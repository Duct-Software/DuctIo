/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file host_invoke_test.c
 * @brief ST-HS acceptance: duct_session_invoke / duct_session_close from
 * the host (main) thread, outside any protocol callback — no worker-triggering
 * frame or timer involved.
 *
 * Scenario 1: an async invoke's fn stages a payload with no triggering frame;
 * proves the response gets the same full commit (route + stage + publish) a
 * frame callback's out would. Scenario 2: duct_session_close from the host
 * thread reaches on_session_close with the passed reason and the peer sees
 * EOF; also covers the stale-token case for both invoke and invoke_sync — the
 * host-side resolve is the actual gate, not merely a courtesy check. Scenario
 * 3: duct_session_invoke_sync blocks until fn's commit is visible to the
 * peer and returns fn's own rc, not just rc_ok for "posted".
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>

static constexpr unsigned wait_ms = 3000u;
static constexpr int      eof_timeout_ms = 3000;

static duct_handle_t g_tok;
static atomic_int  g_open_count   = 0;
static atomic_int  g_close_count  = 0;
static atomic_int  g_close_reason = 0;
static atomic_int  g_invoke_ran   = 0;
static atomic_int  g_sync_ran     = 0;

static void s_reset(void)
{
    g_tok = (duct_handle_t){};
    duct_atomic_store(&g_open_count, 0, relaxed);
    duct_atomic_store(&g_close_count, 0, relaxed);
    duct_atomic_store(&g_close_reason, 0, relaxed);
    duct_atomic_store(&g_invoke_ran, 0, relaxed);
    duct_atomic_store(&g_sync_ran, 0, relaxed);
}

/* Bounded EOF probe: true if the peer closed (read <= 0) within the timeout. */
static bool s_read_eof(duct_sock_t fd)
{
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    if (poll(&pfd, 1, eof_timeout_ms) <= 0)
        return false;
    char buf[4];
    return read(fd, buf, sizeof buf) <= 0;
}

static duct_result_t
on_session_open(duct_session_t *s, duct_handle_t tok, [[maybe_unused]] void *user_ctx,
                [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    (void)s;
    g_tok = tok;
    duct_atomic_store(&g_open_count, 1, release);
    return rc_ok;
}

static void
on_session_close(duct_session_t *s, duct_close_reason_t reason, [[maybe_unused]] void *proto_state)
{
    (void)s;
    duct_atomic_store(&g_close_reason, (int)reason, relaxed);
    duct_atomic_fetch(add, &g_close_count, 1, release);
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame, duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

/* ── Scenario 1: async invoke, no triggering frame ───────────────── */

static const char invoke_payload[] = "host-invoked-push";

static duct_result_t
s_invoke_push_fn(duct_session_t *s, duct_response_t *out, void *ctx)
{
    (void)s; (void)ctx;
    duct_atomic_fetch(add, &g_invoke_ran, 1, release);
    *out = (duct_response_t){
        .payload = { .data = (void *)invoke_payload, .size = sizeof invoke_payload - 1u },
        .flags = fl_send_static,
    };
    return rc_ok;
}

static bool sc_invoke(void)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "host-invoke", .wire = wire, .on_frame = on_frame,
        .on_session_open = on_session_open, .on_session_close = on_session_close,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    if (!proto) { duct_engine_destroy(io); return false; }

    uint16_t port = 0u;
    bool ok = duct_io_listen(io, "127.0.0.1", &port, proto) == rc_ok;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        duct_sock_t fd = th_connect(port);
        ok = fd != duct_sock_bad;
        ok = ok && th_wait_int(&g_open_count, 1, wait_ms);

        auto rc = duct_session_invoke(io, g_tok, s_invoke_push_fn, nullptr);
        ok = ok && rc == rc_ok;
        ok = ok && th_recv_eq(fd, invoke_payload, sizeof invoke_payload - 1u) == 0;
        ok = ok && duct_atomic_load(&g_invoke_ran, acquire) == 1;

        if (fd != duct_sock_bad) close(fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return ok;
}

/* ── Scenario 2: host-thread close reaches on_session_close ─────── */

static bool sc_close(void)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "host-close", .wire = wire, .on_frame = on_frame,
        .on_session_open = on_session_open, .on_session_close = on_session_close,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    if (!proto) { duct_engine_destroy(io); return false; }

    uint16_t port = 0u;
    bool ok = duct_io_listen(io, "127.0.0.1", &port, proto) == rc_ok;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        duct_sock_t fd = th_connect(port);
        ok = fd != duct_sock_bad;
        ok = ok && th_wait_int(&g_open_count, 1, wait_ms);

        auto rc = duct_session_close(io, g_tok, close_protocol_error);
        ok = ok && rc == rc_ok;
        ok = ok && th_wait_int(&g_close_count, 1, wait_ms);
        ok = ok && duct_atomic_load(&g_close_reason, relaxed)
                    == (int)close_protocol_error;
        ok = ok && s_read_eof(fd);

        /* Stale token: the session is gone, resolve must fail on the host
         * thread itself — fn never runs, no worker round trip needed. */
        auto stale_rc = duct_session_invoke(io, g_tok, s_invoke_push_fn, nullptr);
        ok = ok && stale_rc == rc_closed;
        auto stale_sync_rc = duct_session_invoke_sync(io, g_tok, s_invoke_push_fn, nullptr);
        ok = ok && stale_sync_rc == rc_closed;
        ok = ok && duct_atomic_load(&g_invoke_ran, acquire) == 0;

        if (fd != duct_sock_bad) close(fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return ok;
}

/* ── Scenario 3: sync invoke blocks until fn's commit lands ─────── */

static const char sync_payload[] = "host-sync-push";

static duct_result_t
s_sync_push_fn(duct_session_t *s, duct_response_t *out, void *ctx)
{
    (void)s; (void)ctx;
    duct_atomic_fetch(add, &g_sync_ran, 1, release);
    *out = (duct_response_t){
        .payload = { .data = (void *)sync_payload, .size = sizeof sync_payload - 1u },
        .flags = fl_send_static,
    };
    return rc_ok;
}

static bool sc_sync(void)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "host-sync", .wire = wire, .on_frame = on_frame,
        .on_session_open = on_session_open, .on_session_close = on_session_close,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    if (!proto) { duct_engine_destroy(io); return false; }

    uint16_t port = 0u;
    bool ok = duct_io_listen(io, "127.0.0.1", &port, proto) == rc_ok;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        duct_sock_t fd = th_connect(port);
        ok = fd != duct_sock_bad;
        ok = ok && th_wait_int(&g_open_count, 1, wait_ms);

        /* No wait_int needed after this returns: rc_ok already means fn ran
         * and its response was committed, unlike the async duct_session_invoke. */
        auto rc = duct_session_invoke_sync(io, g_tok, s_sync_push_fn, nullptr);
        ok = ok && rc == rc_ok;
        ok = ok && duct_atomic_load(&g_sync_ran, acquire) == 1;
        ok = ok && th_recv_eq(fd, sync_payload, sizeof sync_payload - 1u) == 0;

        if (fd != duct_sock_bad) close(fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return ok;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    int pass = 1;

    if (!sc_invoke()) { fprintf(stderr, "host_invoke: invoke failed\n"); pass = 0; }
    if (!sc_close())  { fprintf(stderr, "host_invoke: close failed\n"); pass = 0; }
    if (!sc_sync())   { fprintf(stderr, "host_invoke: sync failed\n"); pass = 0; }

    if (pass) {
        printf("host_invoke: OK (host-thread invoke commits like a frame callback's out, "
               "host-thread close reaches on_session_close, sync invoke blocks for fn's "
               "result, stale token rejected by both)\n");
        return 0;
    }
    return 1;
}
