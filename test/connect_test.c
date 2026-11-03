/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file connect_test.c
 * @brief ST-C acceptance: duct_io_connect — address
 * parsing, a full connect+echo round-trip, the three pre-session on_error
 * paths (refused, DNS failure, connect timeout), and (T24) the Windows
 * GetAddrInfoExW resolver's own real-NXDOMAIN, localhost-smoke, and
 * shutdown-during-resolve cases — portable cases, but the resolver path
 * they exercise is Windows-only (Linux keeps the detached-thread
 * resolver; both are reached through the same duct_resolve_start).
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>

/** @brief Exposed from os/duct_connect.c for direct unit testing. */
extern bool duct_connect_parse_addr(const char *addr, char *host, size_t host_cap, uint16_t *port);

static atomic_int         g_srv_open      = 0;
static atomic_int         g_cli_open      = 0;
static atomic_int         g_cli_frame_ok  = 0;
static atomic_int         g_cli_err_count = 0;
static _Atomic(int)       g_cli_err_code  = 0;
static _Atomic(void *)    g_cli_err_ctx   = nullptr;
static _Atomic(void *)    g_cli_open_ctx  = nullptr;

static void s_reset(void)
{
    duct_atomic_store(&g_srv_open, 0, relaxed);
    duct_atomic_store(&g_cli_open, 0, relaxed);
    duct_atomic_store(&g_cli_frame_ok, 0, relaxed);
    duct_atomic_store(&g_cli_err_count, 0, relaxed);
    duct_atomic_store(&g_cli_err_code, 0, relaxed);
    duct_atomic_store(&g_cli_err_ctx, nullptr, relaxed);
    duct_atomic_store(&g_cli_open_ctx, nullptr, relaxed);
}

static duct_result_t
srv_on_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_srv_open, 1, release);
    return rc_ok;
}

static duct_result_t
srv_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             const duct_frame_t *frame, duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

static const uint8_t ping_msg[] = "ping";

/** @brief Greets first (out = ping) so the success scenario needs no client
 *  send path; the server echoes it back on the same wire. */
static duct_result_t
cli_on_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
            void *user_ctx, duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_cli_open_ctx, user_ctx, relaxed);
    duct_atomic_fetch(add, &g_cli_open, 1, release);
    duct_response_same(out, duct_view(duct_view_u8, (void *)ping_msg, sizeof ping_msg - 1u),
                        fl_send_static, 0);
    return rc_ok;
}

static duct_result_t
cli_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    if (frame->payload.size == sizeof ping_msg - 1u
        && memcmp(frame->payload.data, ping_msg, frame->payload.size) == 0)
        duct_atomic_fetch(add, &g_cli_frame_ok, 1, release);
    return rc_ok;
}

/** @brief Pre-session connect failure: s == nullptr, proto_state carries the
 *  duct_io_connect user_ctx (duct_error_fn's pre-session semantics). */
static duct_result_t
cli_on_error([[maybe_unused]] duct_session_t *s, duct_result_t error,
             [[maybe_unused]] duct_response_t *out, void *proto_state)
{
    duct_atomic_store(&g_cli_err_code, (int)error, relaxed);
    duct_atomic_store(&g_cli_err_ctx, proto_state, relaxed);
    duct_atomic_fetch(add, &g_cli_err_count, 1, release);
    return rc_ok;
}

/** @brief duct_io_connect requires engine_state_running; the io thread flips
 *  that flag right after pthread_create, so retry past the short window
 *  instead of racing it. */
static duct_result_t
s_connect_retry(duct_engine_t *io, const char *addr, duct_proto_t *proto,
                void *user_ctx, unsigned timeout_ms)
{
    duct_result_t rc = rc_invalid_order;
    for (unsigned waited = 0u; waited < timeout_ms; waited += 5u) {
        rc = duct_io_connect(io, addr, proto, user_ctx, x_tcp);
        if (rc != rc_invalid_order)
            return rc;
        struct timespec ts = { .tv_nsec = 5L * 1000L * 1000L };
        nanosleep(&ts, nullptr);
    }
    return rc;
}

/* ── Scenario 1: address parsing ─────────────────────────────────────── */

typedef struct {
    const char *addr;
    bool        want_ok;
    const char *want_host;
    uint16_t    want_port;
} parse_case_t;

static const parse_case_t parse_cases[] = {
    { "127.0.0.1:8080",       true,  "127.0.0.1",   8080u },
    { "[::1]:9090",           true,  "::1",         9090u },
    { "example.com:80",       true,  "example.com", 80u },
    { "[2001:db8::1]:443",    true,  "2001:db8::1", 443u },
    { "",                     false, nullptr,       0u },
    { "noport",               false, nullptr,       0u },
    { "127.0.0.1:",           false, nullptr,       0u },
    { "127.0.0.1:0",          false, nullptr,       0u },
    { "127.0.0.1:65536",      false, nullptr,       0u },
    { "127.0.0.1:99999",      false, nullptr,       0u },
    { "[::1]",                false, nullptr,       0u },
    { "[::1]:",               false, nullptr,       0u },
    { ":8080",                false, nullptr,       0u },
    { "host:abc",             false, nullptr,       0u },
    { "host:80x",             false, nullptr,       0u },
    { "host:-1",              false, nullptr,       0u },
    { "caf\xC3\xA9.com:80",   false, nullptr,       0u }, /* non-ASCII host (UTF-8 'e' with accent, U+00E9): rejected */
};

static bool sc_parse(void)
{
    bool ok = true;
    for (size_t i = 0u; i < sizeof parse_cases / sizeof parse_cases[0]; ++i) {
        auto c = &parse_cases[i];
        char host[256] = {};
        uint16_t port = 0u;
        bool got = duct_connect_parse_addr(c->addr, host, sizeof host, &port);
        if (got != c->want_ok) {
            fprintf(stderr, "connect: parse[%zu] '%s' ok=%d want=%d\n", i, c->addr, got, c->want_ok);
            ok = false;
            continue;
        }
        if (got && (strcmp(host, c->want_host) != 0 || port != c->want_port)) {
            fprintf(stderr, "connect: parse[%zu] '%s' -> '%s':%u want '%s':%u\n",
                    i, c->addr, host, (unsigned)port, c->want_host, (unsigned)c->want_port);
            ok = false;
        }
    }

    char host[16];
    uint16_t port = 0u;
    ok = ok && !duct_connect_parse_addr(nullptr, host, sizeof host, &port);
    ok = ok && !duct_connect_parse_addr("x:1", nullptr, sizeof host, &port);
    ok = ok && !duct_connect_parse_addr("x:1", host, 0u, &port);
    ok = ok && !duct_connect_parse_addr("x:1", host, sizeof host, nullptr);
    ok = ok && !duct_connect_parse_addr("toolonghostname:80", host, 4u, &port);
    if (!ok)
        fprintf(stderr, "connect: parse guard cases failed\n");
    return ok;
}

/* ── Scenario 2: connect + echo round-trip ───────────────────────────── */

static bool sc_success(void)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto srv_wire = duct_wire_create_length_prefix(0u);
    auto cli_wire = duct_wire_create_length_prefix(0u);
    auto srv = duct_proto_create(&(duct_proto_cfg_t){
        .name = "connect-srv", .wire = srv_wire,
        .on_frame = srv_on_frame, .on_session_open = srv_on_open,
    });
    auto cli = duct_proto_create(&(duct_proto_cfg_t){
        .name = "connect-cli", .wire = cli_wire,
        .on_frame = cli_on_frame, .on_session_open = cli_on_open, .on_error = cli_on_error,
    });
    if (srv) srv->owned_wire = srv_wire; else duct_wire_destroy(srv_wire);
    if (cli) cli->owned_wire = cli_wire; else duct_wire_destroy(cli_wire);
    if (!srv || !cli) {
        duct_proto_destroy(srv); duct_proto_destroy(cli); duct_engine_destroy(io);
        return false;
    }

    uint16_t port = 0u;
    bool ok = duct_io_listen(io, "127.0.0.1", &port, srv) == rc_ok;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        char addr[64];
        snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)port);
        int marker = 0;
        ok = s_connect_retry(io, addr, cli, &marker, 3000u) == rc_ok;
        ok = ok && th_wait_int(&g_cli_frame_ok, 1, 3000u);
        ok = ok && duct_atomic_load(&g_cli_open, acquire) == 1
                && duct_atomic_load(&g_srv_open, acquire) == 1
                && duct_atomic_load(&g_cli_err_count, acquire) == 0
                && duct_atomic_load(&g_cli_open_ctx, relaxed) == &marker;
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(srv);
    duct_proto_destroy(cli);
    return ok;
}

/* ── Scenario 3: connection refused ───────────────────────────────────── */

/** @brief Bind an ephemeral port then close it: nothing listens there, so a
 *  connect gets an immediate RST. */
static uint16_t s_get_closed_port(void)
{
    duct_sock_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == duct_sock_bad) return 0u;
    struct sockaddr_in addr = { .sin_family = AF_INET };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    socklen_t alen = sizeof addr;
    uint16_t port = 0u;
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) == 0
        && getsockname(fd, (struct sockaddr *)&addr, &alen) == 0)
        port = ntohs(addr.sin_port);
    duct_sock_close(fd);
    return port;
}

static bool sc_refused(void)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "connect-refused", .wire = wire,
        .on_frame = cli_on_frame, .on_error = cli_on_error, .connect_timeout_ms = 3000u,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    if (!proto) { duct_engine_destroy(io); return false; }

    uint16_t port = s_get_closed_port();
    bool ok = port != 0u;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        char addr[64];
        snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)port);
        int marker = 0;
        ok = s_connect_retry(io, addr, proto, &marker, 3000u) == rc_ok;
        /* connect_timeout_ms above (3000) is itself already the library's
         * own fallback for a refusal that resolves slower than expected —
         * this wait must clear that with margin, not race it. */
        ok = ok && th_wait_int(&g_cli_err_count, 1, 4000u);
        ok = ok && duct_atomic_load(&g_cli_err_code, relaxed) == (int)rc_conn_refused;
        ok = ok && duct_atomic_load(&g_cli_err_ctx, relaxed) == &marker;
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return ok;
}

/* ── Scenario 4: DNS resolution failure ──────────────────────────────── */

static bool sc_dns_fail(void)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "connect-dns", .wire = wire,
        .on_frame = cli_on_frame, .on_error = cli_on_error,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    if (!proto) { duct_engine_destroy(io); return false; }

    /* A DNS label over 63 octets fails getaddrinfo purely from local
     * validation — deterministic, no network or live resolver needed. */
    char host[96];
    memset(host, 'x', 80u);
    memcpy(host + 80, ".invalid", sizeof ".invalid");
    char addr[112];
    snprintf(addr, sizeof addr, "%s:80", host);

    pthread_t th;
    bool ok = pthread_create(&th, nullptr, th_run, io) == 0;
    if (ok) {
        int marker = 0;
        ok = s_connect_retry(io, addr, proto, &marker, 3000u) == rc_ok;
        ok = ok && th_wait_int(&g_cli_err_count, 1, 10000u);
        ok = ok && duct_atomic_load(&g_cli_err_code, relaxed) == (int)rc_dns_fail;
        ok = ok && duct_atomic_load(&g_cli_err_ctx, relaxed) == &marker;
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }

    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return ok;
}

/* ── Scenario 5: connect timeout ─────────────────────────────────────── */

static bool sc_timeout(void)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    duct_sock_t lfd = socket(AF_INET, SOCK_STREAM, 0);
    bool ok = lfd != duct_sock_bad;
    struct sockaddr_in addr = { .sin_family = AF_INET };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    ok = ok && bind(lfd, (struct sockaddr *)&addr, sizeof addr) == 0
            && listen(lfd, 1) == 0;
    socklen_t alen = sizeof addr;
    ok = ok && getsockname(lfd, (struct sockaddr *)&addr, &alen) == 0;
    uint16_t port = ok ? ntohs(addr.sin_port) : 0u;

    /* Overflow the tiny accept backlog: once it is full, new SYNs black-hole
     * (default tcp_abort_on_overflow=0), so our own connect below never
     * completes until connect_timeout_ms fires it itself. */
    enum { n_fillers = 256 };
    duct_sock_t fillers[n_fillers];
    unsigned n_opened = 0u;
    for (unsigned i = 0u; ok && i < n_fillers; ++i) {
        duct_sock_t fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == duct_sock_bad) break;
        th_set_nonblock(fd);
        int cr = connect(fd, (struct sockaddr *)&addr, sizeof addr);
        (void)cr; /* EINPROGRESS expected; any outcome still adds SYN pressure. */
        fillers[n_opened++] = fd;
    }

    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = ok ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "connect-timeout", .wire = wire,
        .on_frame = cli_on_frame, .on_error = cli_on_error, .connect_timeout_ms = 200u,
    }) : nullptr;
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    ok = ok && proto != nullptr;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        char caddr[64];
        snprintf(caddr, sizeof caddr, "127.0.0.1:%u", (unsigned)port);
        int marker = 0;
        ok = s_connect_retry(io, caddr, proto, &marker, 3000u) == rc_ok;
        ok = ok && th_wait_int(&g_cli_err_count, 1, 5000u);
        ok = ok && duct_atomic_load(&g_cli_err_code, relaxed) == (int)rc_conn_timeout;
        ok = ok && duct_atomic_load(&g_cli_err_ctx, relaxed) == &marker;
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    for (unsigned i = 0u; i < n_opened; ++i) close(fillers[i]);
    if (lfd != duct_sock_bad) close(lfd);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return ok;
}

/* ── Scenario 6 (T24): real NXDOMAIN through the platform resolver ───── */

/** @brief RFC 2606 .invalid is guaranteed never to resolve — unlike
 *  sc_dns_fail's over-long label (rejected by local validation before any
 *  resolver call), this exercises the full async resolve + failure
 *  delivery chain (Windows: GetAddrInfoExW; Linux: the detached thread,
 *  same duct_resolve_start entry either way). Then proves the engine
 *  stays healthy afterward: a normal literal connect on the same engine
 *  must still succeed. */
static bool sc_nxdomain(void)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto srv_wire = duct_wire_create_length_prefix(0u);
    auto cli_wire = duct_wire_create_length_prefix(0u);
    auto srv = duct_proto_create(&(duct_proto_cfg_t){
        .name = "nxdomain-srv", .wire = srv_wire,
        .on_frame = srv_on_frame, .on_session_open = srv_on_open,
    });
    auto cli = duct_proto_create(&(duct_proto_cfg_t){
        .name = "nxdomain-cli", .wire = cli_wire,
        .on_frame = cli_on_frame, .on_session_open = cli_on_open, .on_error = cli_on_error,
    });
    if (srv) srv->owned_wire = srv_wire; else duct_wire_destroy(srv_wire);
    if (cli) cli->owned_wire = cli_wire; else duct_wire_destroy(cli_wire);
    if (!srv || !cli) {
        duct_proto_destroy(srv); duct_proto_destroy(cli); duct_engine_destroy(io);
        return false;
    }

    uint16_t port = 0u;
    bool ok = duct_io_listen(io, "127.0.0.1", &port, srv) == rc_ok;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        int dns_marker = 0;
        ok = s_connect_retry(io, "no-such-host.invalid:9", cli, &dns_marker, 3000u) == rc_ok;
        /* Unlike sc_dns_fail's local-validation-only reject, .invalid still
         * issues a real query that has to actually fail somewhere upstream
         * before the negative response comes back — observed 11-22s in
         * this environment (WSL and native Windows both), not instant;
         * generous margin over that, not the usual few-second bound. */
        ok = ok && th_wait_int(&g_cli_err_count, 1, 40000u);
        ok = ok && duct_atomic_load(&g_cli_err_code, relaxed) == (int)rc_dns_fail;
        ok = ok && duct_atomic_load(&g_cli_err_ctx, relaxed) == &dns_marker;

        char addr[64];
        snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)port);
        int ok_marker = 0;
        ok = ok && s_connect_retry(io, addr, cli, &ok_marker, 3000u) == rc_ok;
        ok = ok && th_wait_int(&g_cli_frame_ok, 1, 3000u);
        ok = ok && duct_atomic_load(&g_cli_open_ctx, relaxed) == &ok_marker;

        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(srv);
    duct_proto_destroy(cli);
    return ok;
}

/* ── Scenario 7 (T24): localhost resolve smoke test ──────────────────── */

/** @brief "localhost" may resolve to ::1 or 127.0.0.1 first depending on
 *  the host's own resolver order; this listener only answers on
 *  127.0.0.1, so either terminal outcome — a session established, or a
 *  refusal when the first result is ::1 and nothing answers there — is a
 *  pass. The only failure is neither ever firing (hang) or a crash. */
static bool sc_localhost_smoke(void)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto srv_wire = duct_wire_create_length_prefix(0u);
    auto cli_wire = duct_wire_create_length_prefix(0u);
    auto srv = duct_proto_create(&(duct_proto_cfg_t){
        .name = "localhost-srv", .wire = srv_wire,
        .on_frame = srv_on_frame, .on_session_open = srv_on_open,
    });
    auto cli = duct_proto_create(&(duct_proto_cfg_t){
        .name = "localhost-cli", .wire = cli_wire,
        .on_frame = cli_on_frame, .on_session_open = cli_on_open, .on_error = cli_on_error,
    });
    if (srv) srv->owned_wire = srv_wire; else duct_wire_destroy(srv_wire);
    if (cli) cli->owned_wire = cli_wire; else duct_wire_destroy(cli_wire);
    if (!srv || !cli) {
        duct_proto_destroy(srv); duct_proto_destroy(cli); duct_engine_destroy(io);
        return false;
    }

    uint16_t port = 0u;
    bool ok = duct_io_listen(io, "127.0.0.1", &port, srv) == rc_ok;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        char addr[64];
        snprintf(addr, sizeof addr, "localhost:%u", (unsigned)port);
        int marker = 0;
        ok = s_connect_retry(io, addr, cli, &marker, 3000u) == rc_ok;
        for (unsigned waited = 0u; ok && waited < 5000u; waited += 10u) {
            if (duct_atomic_load(&g_cli_open, acquire) >= 1
                || duct_atomic_load(&g_cli_err_count, acquire) >= 1)
                break;
            struct timespec ts = { .tv_nsec = 10L * 1000L * 1000L };
            nanosleep(&ts, nullptr);
        }
        ok = ok && (duct_atomic_load(&g_cli_open, acquire) >= 1
                   || duct_atomic_load(&g_cli_err_count, acquire) >= 1);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(srv);
    duct_proto_destroy(cli);
    return ok;
}

/* ── Scenario 8 (T24): engine destroy while a resolve is in flight ───── */

/** @brief Start a resolve of a name that will not resolve quickly, then
 *  destroy the engine at once.
 *  Destroy has to return with no crash and no hang. On Windows it cancels the
 *  lookup and drains its completion; on Linux the lookup runs on and its result
 *  is dropped at the closed gate, so the thread touches no engine state after
 *  destroy. */
static bool sc_shutdown_during_resolve(void)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "connect-shutdown", .wire = wire,
        .on_frame = cli_on_frame, .on_error = cli_on_error,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    if (!proto) { duct_engine_destroy(io); return false; }

    pthread_t th;
    bool ok = pthread_create(&th, nullptr, th_run, io) == 0;
    if (ok) {
        int marker = 0;
        ok = s_connect_retry(io, "slow-nonexistent-host.invalid:9", proto, &marker, 3000u) == rc_ok;
        duct_engine_destroy(io);
        pthread_join(th, nullptr);
    } else {
        duct_engine_destroy(io);
    }
    duct_proto_destroy(proto);
    return ok;
}

/* ── Scenario 9: a peer that accepts and closes at once ──────────────── */

enum { accept_close_n = 32 };

static void *s_accept_and_close(void *arg)
{
    auto lfd = *(const duct_sock_t *)arg;
    for (unsigned i = 0u; i < accept_close_n; ++i) {
        duct_sock_t cfd = accept(lfd, nullptr, nullptr);
        if (cfd == duct_sock_bad)
            break;
        duct_sock_close(cfd);
    }
    return nullptr;
}

static duct_result_t
ac_on_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
           void *user_ctx, [[maybe_unused]] duct_response_t *out,
           [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, (atomic_int *)user_ctx, 1, acq_rel);
    return rc_ok;
}

static duct_result_t
ac_on_error(duct_session_t *s, [[maybe_unused]] duct_result_t error,
            [[maybe_unused]] duct_response_t *out, void *proto_state)
{
    if (!s)
        duct_atomic_fetch(add, (atomic_int *)proto_state, 1, acq_rel);
    return rc_ok;
}

static bool sc_accept_close(void)
{
    duct_sock_t lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd == duct_sock_bad)
        return false;
    struct sockaddr_in addr = { .sin_family = AF_INET };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    socklen_t alen = sizeof addr;
    bool bound = bind(lfd, (struct sockaddr *)&addr, sizeof addr) == 0
              && listen(lfd, accept_close_n) == 0
              && getsockname(lfd, (struct sockaddr *)&addr, &alen) == 0;
    if (!bound) {
        duct_sock_close(lfd);
        return false;
    }
    uint16_t port = ntohs(addr.sin_port);
    pthread_t srv_th;
    if (pthread_create(&srv_th, nullptr, s_accept_and_close, &lfd) != 0) {
        duct_sock_close(lfd);
        return false;
    }

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 4 });
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = io && wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "connect-accept-close", .wire = wire,
        .on_frame = cli_on_frame, .on_session_open = ac_on_open, .on_error = ac_on_error,
    }) : nullptr;
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);

    atomic_int answers[accept_close_n] = {};
    pthread_t th;
    bool ok = io && proto && pthread_create(&th, nullptr, th_run, io) == 0;
    if (ok) {
        char target[64];
        snprintf(target, sizeof target, "127.0.0.1:%u", (unsigned)port);
        for (unsigned i = 0u; ok && i < accept_close_n; ++i)
            ok = s_connect_retry(io, target, proto, &answers[i], 3000u) == rc_ok;
        for (unsigned i = 0u; ok && i < accept_close_n; ++i)
            ok = th_wait_int(&answers[i], 1, 3000u)
              && duct_atomic_load(&answers[i], acquire) == 1;
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }

    duct_sock_close(lfd);
    pthread_join(srv_th, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return ok;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    int pass = 1;

    if (!sc_parse())                   { fprintf(stderr, "connect: parse failed\n");                   pass = 0; }
    if (!sc_success())                 { fprintf(stderr, "connect: success failed\n");                  pass = 0; }
    if (!sc_refused())                 { fprintf(stderr, "connect: refused failed\n");                  pass = 0; }
    if (!sc_dns_fail())                { fprintf(stderr, "connect: dns_fail failed\n");                 pass = 0; }
    if (!sc_timeout())                 { fprintf(stderr, "connect: timeout failed\n");                  pass = 0; }
    if (!sc_nxdomain())                { fprintf(stderr, "connect: nxdomain failed\n");                 pass = 0; }
    if (!sc_localhost_smoke())         { fprintf(stderr, "connect: localhost_smoke failed\n");          pass = 0; }
    if (!sc_shutdown_during_resolve()) { fprintf(stderr, "connect: shutdown_during_resolve failed\n");  pass = 0; }
    if (!sc_accept_close())            { fprintf(stderr, "connect: accept_close failed\n");             pass = 0; }

    if (pass) {
        printf("connect: OK (parse table, connect success, refused, dns-fail, timeout, "
               "nxdomain, localhost smoke, shutdown-during-resolve, accept-close)\n");
        return 0;
    }
    return 1;
}
