/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file peer_disconnect_test.c
 * @brief Peer disconnect → on_session_close fires with correct close_reason.
 *
 * Client connects, exchanges a frame, then closes the fd. The server's
 * on_session_close must fire with close_peer (not close_normal).
 * Also tests: multiple sequential disconnects on the same listener — each
 * session opens and closes independently.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>

static uint16_t th_port = 0;

static atomic_int g_open_count  = 0;
static atomic_int g_close_count = 0;
static atomic_int g_frame_count = 0;
static _Atomic(duct_close_reason_t) g_last_reason = close_normal;

static duct_result_t
on_open([[maybe_unused]] duct_session_t *s,
        [[maybe_unused]] duct_handle_t tok,
        [[maybe_unused]] void *user_ctx,
        [[maybe_unused]] duct_response_t *out,
        [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_open_count, 1, relaxed);
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_frame_count, 1, relaxed);
    duct_response_echo(out, frame);
    return rc_ok;
}

static void
on_close([[maybe_unused]] duct_session_t *s,
         duct_close_reason_t reason,
         [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_last_reason, reason, relaxed);
    duct_atomic_fetch(add, &g_close_count, 1, relaxed);
}

static void s_reset(void)
{
    duct_atomic_store(&g_open_count, 0, seq_cst);
    duct_atomic_store(&g_close_count, 0, seq_cst);
    duct_atomic_store(&g_frame_count, 0, seq_cst);
    duct_atomic_store(&g_last_reason, close_normal, seq_cst);
}

/* ── Test 1: single peer disconnect ─────────────────────────────── */

static const char *test_single_disconnect(duct_engine_t *io, duct_proto_t *proto)
{
    (void)io; (void)proto;
    s_reset();

    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    if (th_send(fd, "hello", 5u) != 0) { close(fd); return "send failed"; }
    if (th_recv_eq(fd, "hello", 5u) != 0) { close(fd); return "no echo"; }

    /* Client disconnects. */
    close(fd);

    /* Wait for on_session_close to fire on the worker. */
    if (!th_wait_int(&g_close_count, 1, 2000))
        return "on_session_close did not fire after peer disconnect";

    if (duct_atomic_load(&g_last_reason, seq_cst) != close_peer)
        return "close_reason != close_peer";
    if (duct_atomic_load(&g_open_count, seq_cst) != 1)
        return "open_count != 1";
    if (duct_atomic_load(&g_frame_count, seq_cst) != 1)
        return "frame_count != 1";
    return nullptr;
}

/* ── Test 2: multiple sequential disconnects ────────────────────── */

static const char *test_multi_disconnect(duct_engine_t *io, duct_proto_t *proto)
{
    (void)io; (void)proto;
    s_reset();

    for (unsigned i = 0u; i < 3u; ++i) {
        duct_sock_t fd = th_connect(th_port);
        if (fd == duct_sock_bad) return "connect failed";

        char msg[32];
        int mlen = snprintf(msg, sizeof msg, "round-%u", i);
        if (th_send(fd, msg, (size_t)mlen) != 0) { close(fd); return "send failed"; }
        if (th_recv_eq(fd, msg, (size_t)mlen) != 0) { close(fd); return "echo mismatch"; }
        close(fd);

        /* Wait for close before next connect (same listener, sequential). */
        if (!th_wait_int(&g_close_count, (int)(i + 1), 2000))
            return "on_session_close did not fire";
    }

    if (duct_atomic_load(&g_open_count, seq_cst) != 3)
        return "open_count != 3";
    if (duct_atomic_load(&g_close_count, seq_cst) != 3)
        return "close_count != 3";
    return nullptr;
}

/* ── Main ────────────────────────────────────────────────────────── */

typedef const char *(*test_fn)(duct_engine_t *, duct_proto_t *);

static struct { const char *name; test_fn fn; } s_tests[] = {
    { "single_disconnect", test_single_disconnect },
    { "multi_disconnect",  test_multi_disconnect },
};

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    int pass = 1;

    for (unsigned t = 0u; t < sizeof(s_tests) / sizeof(s_tests[0]); ++t) {
        auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
        if (!io) { fprintf(stderr, "disconnect: %s: io failed\n", s_tests[t].name); pass = 0; continue; }
        auto wire = duct_wire_create_length_prefix(0u);
        if (!wire) { duct_engine_destroy(io); pass = 0; continue; }

        auto proto = duct_proto_create(&(duct_proto_cfg_t){
            .name = "disconnect-test", .wire = wire,
            .on_frame = on_frame,
            .on_session_open = on_open,
            .on_session_close = on_close,
        });
        if (!proto) { duct_engine_destroy(io); duct_wire_destroy(wire); pass = 0; continue; }

        th_port = 0;
        if (duct_io_listen(io, "127.0.0.1", &th_port, proto) != rc_ok) {
            duct_proto_destroy(proto); duct_engine_destroy(io); duct_wire_destroy(wire);
            pass = 0; continue;
        }
        pthread_t th;
        if (pthread_create(&th, nullptr, th_run, io) != 0) {
            duct_proto_destroy(proto); duct_engine_destroy(io); duct_wire_destroy(wire);
            pass = 0; continue;
        }

        const char *err = s_tests[t].fn(io, proto);

        duct_engine_stop(io);
        pthread_join(th, nullptr);
        duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(wire);

        if (err) { fprintf(stderr, "disconnect: %s: FAIL: %s\n", s_tests[t].name, err); pass = 0; }
        else printf("disconnect: %s: OK\n", s_tests[t].name);
    }
    return pass ? 0 : 1;
}
