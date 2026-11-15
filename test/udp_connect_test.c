/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file udp_connect_test.c
 * @brief UDP client dial: duct_io_connect with x_udp_peer against a
 * reactive listener_dgram server, one engine for both ends. Covers a
 * literal-address round-trip and a hostname ("localhost") round-trip —
 * the latter exercises duct_resolve_start's xport pass-through, not just
 * the literal-address fast path.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>

/* Engine built-in, not declared in the public duct_wire.h — see
 * test_helpers.h's own copy of this declaration for the rationale. */
duct_wire_t *duct_wire_create_dgram_batch(size_t max_dgram, bool framed);

static atomic_int      g_srv_open         = 0;
static atomic_int      g_cli_open         = 0;
static atomic_int      g_cli_frame_ok     = 0;
static atomic_int      g_cli_closed       = 0;
static atomic_int      g_cli_close_reason = -1;
static _Atomic(void *) g_cli_open_ctx     = nullptr;

static void s_reset(void)
{
    duct_atomic_store(&g_srv_open, 0, relaxed);
    duct_atomic_store(&g_cli_open, 0, relaxed);
    duct_atomic_store(&g_cli_frame_ok, 0, relaxed);
    duct_atomic_store(&g_cli_closed, 0, relaxed);
    duct_atomic_store(&g_cli_close_reason, -1, relaxed);
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

static const char ping_msg[] = "udp-ping";

/** @brief Sends first on open, same shape as connect_test.c's TCP
 *  equivalent — the server echoes it straight back. */
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

static void
cli_on_close([[maybe_unused]] duct_session_t *s, duct_close_reason_t reason,
             [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_cli_close_reason, (int)reason, release);
    duct_atomic_store(&g_cli_closed, 1, release);
}

/** @brief duct_io_connect requires engine_state_running; retry past the
 *  short window right after pthread_create instead of racing it — same
 *  pattern as connect_test.c's own s_connect_retry, x_udp_peer fixed.
 */
static duct_result_t
s_connect_retry(duct_engine_t *io, const char *addr, duct_proto_t *proto,
                void *user_ctx, unsigned timeout_ms)
{
    duct_result_t rc = rc_invalid_order;
    for (unsigned waited = 0u; waited < timeout_ms; waited += 5u) {
        rc = duct_io_connect(io, addr, proto, user_ctx, x_udp_peer);
        if (rc != rc_invalid_order)
            return rc;
        struct timespec ts = { .tv_nsec = 5L * 1000L * 1000L };
        nanosleep(&ts, nullptr);
    }
    return rc;
}

static duct_result_t sc_dial(const char *addr_fmt)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return rc_fatal;

    auto srv_wire = duct_wire_create_dgram_batch(0u, false);
    auto cli_wire = duct_wire_create_dgram_batch(0u, false);
    auto srv = duct_proto_create(&(duct_proto_cfg_t){
        .name = "udp-connect-srv", .wire = srv_wire,
        .on_frame = srv_on_frame, .on_session_open = srv_on_open,
    });
    auto cli = duct_proto_create(&(duct_proto_cfg_t){
        .name = "udp-connect-cli", .wire = cli_wire,
        .on_frame = cli_on_frame, .on_session_open = cli_on_open,
    });
    if (srv) srv->owned_wire = srv_wire; else duct_wire_destroy(srv_wire);
    if (cli) cli->owned_wire = cli_wire; else duct_wire_destroy(cli_wire);
    if (!srv || !cli) {
        duct_proto_destroy(srv); duct_proto_destroy(cli); duct_engine_destroy(io);
        return rc_fatal;
    }

    uint16_t port = 0u;
    bool ok = duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
                  .addr = "127.0.0.1", .n_protos = 1, .protos = (const duct_proto_t *[]){ srv },
              }, &port, nullptr, 0u, nullptr) == rc_ok;
    /* "localhost" may resolve to ::1 first (host resolver order) — a UDP
     * connect() to a family nothing listens on black-holes silently
     * instead of refusing, so bind both families. */
    if (ok) {
        uint16_t v6_port = port;
        duct_discard duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
                      .addr = "::1", .n_protos = 1, .protos = (const duct_proto_t *[]){ srv },
                  }, &v6_port, nullptr, 0u, nullptr);
    }

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        char addr[64];
        snprintf(addr, sizeof addr, addr_fmt, (unsigned)port);
        int marker = 0;
        ok = s_connect_retry(io, addr, cli, &marker, 3000u) == rc_ok;
        ok = ok && th_wait_int(&g_cli_frame_ok, 1, 3000u);
        ok = ok && duct_atomic_load(&g_cli_open, acquire) == 1
                && duct_atomic_load(&g_srv_open, acquire) == 1
                && duct_atomic_load(&g_cli_open_ctx, relaxed) == &marker;
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(srv);
    duct_proto_destroy(cli);
    return ok ? rc_ok : rc_fatal;
}

static uint16_t s_closed_udp_port(void)
{
    duct_sock_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == duct_sock_bad)
        return 0u;
    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_addr   = { .s_addr = htonl(INADDR_LOOPBACK) },
    };
    socklen_t len = (socklen_t)sizeof sa;
    uint16_t port = 0u;
    if (bind(fd, (struct sockaddr *)&sa, len) == 0
        && getsockname(fd, (struct sockaddr *)&sa, &len) == 0)
        port = ntohs(sa.sin_port);
    close(fd);
    return port;
}

/** @brief Sending on x_udp_peer to a closed loopback UDP port surfaces ICMP
 *  port unreachable as close_io_error across IOCP, wepoll and epoll alike. */
static duct_result_t sc_refused(void)
{
    s_reset();
    uint16_t port = s_closed_udp_port();
    if (!port)
        return rc_fatal;
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return rc_fatal;

    auto cli_wire = duct_wire_create_dgram_batch(0u, false);
    auto cli = duct_proto_create(&(duct_proto_cfg_t){
        .name = "udp-refused-cli", .wire = cli_wire,
        .on_frame = cli_on_frame, .on_session_open = cli_on_open,
        .on_session_close = cli_on_close,
    });
    if (cli) cli->owned_wire = cli_wire; else duct_wire_destroy(cli_wire);
    if (!cli) {
        duct_engine_destroy(io);
        return rc_fatal;
    }

    bool ok = false;
    pthread_t th;
    if (pthread_create(&th, nullptr, th_run, io) == 0) {
        char addr[64];
        snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)port);
        ok = s_connect_retry(io, addr, cli, nullptr, 3000u) == rc_ok;
        ok = ok && th_wait_int(&g_cli_closed, 1, 2000u);
        ok = ok && duct_atomic_load(&g_cli_close_reason, acquire) == (int)close_io_error;
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }

    duct_engine_destroy(io);
    duct_proto_destroy(cli);
    return ok ? rc_ok : rc_fatal;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    int pass = 1;

    if (sc_dial("127.0.0.1:%u") != rc_ok)
        { fprintf(stderr, "udp_connect: literal-address dial failed\n"); pass = 0; }
    if (sc_dial("localhost:%u") != rc_ok)
        { fprintf(stderr, "udp_connect: hostname (resolver) dial failed\n"); pass = 0; }
    if (sc_refused() != rc_ok)
        { fprintf(stderr, "udp_connect: closed-port ICMP refusal failed\n"); pass = 0; }

    if (pass) {
        printf("udp_connect: OK (literal + hostname x_udp_peer dial, on_session_open "
               "both ends, echo round-trip, closed-port close_io_error)\n");
        return 0;
    }
    return 1;
}
