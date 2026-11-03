/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file close_timeout_test.c
 * @brief A session closed with close_timeout behind a peer that reads nothing.
 *
 * The server streams 64 KB responses into a 1 MB TX ring behind a raw client
 * that never reads, until for 200 ms the ring takes no further response, and
 * then closes the session with close_timeout. The close lands within a second,
 * the ring still over half full and dropped with the conn.
 */

#include "duct.h"
#include "duct_ticks.h"
#include "test_helpers.h"

#include <stdatomic.h>

static constexpr unsigned wait_ms       = 5000u;
static constexpr uint64_t close_by_ns   = 1'000'000'000u;

static constexpr uint64_t full_for_ns  = 200'000'000u;

static uint8_t          g_chunk[65536];
static uint64_t         g_full_since;
static atomic_int       g_closing = 0;
static atomic_int       g_closed  = 0;
static _Atomic uint64_t g_close_at;
static _Atomic uint64_t g_closed_at;
static _Atomic size_t   g_queued_at_close;

static duct_result_t
srv_on_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    out->control.timer.delay_ms = 1u;
    out->control.timer.interval_ms = 1u;
    return rc_ok;
}

static duct_result_t
srv_on_timer(duct_session_t *s, duct_response_t *out, [[maybe_unused]] void *proto_state,
             [[maybe_unused]] uint64_t arg)
{
    if (duct_atomic_load(&g_closing, relaxed))
        return rc_ok;
    if (duct_conn_tx_fits(s, duct_conn_id_primary, sizeof g_chunk)) {
        g_full_since = 0u;
        duct_response_same(out, duct_view(duct_view_u8, g_chunk, sizeof g_chunk),
                           fl_send_static, 0);
        return rc_ok;
    }
    uint64_t now = duct_ticks_mono_ns();
    if (!g_full_since)
        g_full_since = now;
    if (now - g_full_since < full_for_ns)
        return rc_ok;
    duct_tx_pos_t end = {};
    size_t queued = 0u;
    duct_discard duct_conn_tx_end(s, duct_conn_id_primary, &end, &queued);
    duct_atomic_store(&g_queued_at_close, queued, relaxed);
    duct_atomic_store(&g_close_at, now, relaxed);
    duct_atomic_store(&g_closing, 1, release);
    duct_response_close_session(out, close_timeout);
    return rc_ok;
}

static void
srv_on_close([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_close_reason_t reason,
             [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_closed_at, duct_ticks_mono_ns(), relaxed);
    duct_atomic_store(&g_closed, 1, release);
}

static duct_result_t
srv_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             [[maybe_unused]] const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) {
        fprintf(stderr, "close_timeout: io create failed\n");
        return 1;
    }
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "close-timeout-srv", .wire = wire, .on_frame = srv_on_frame,
        .on_session_open = srv_on_open, .on_timer = srv_on_timer,
        .on_session_close = srv_on_close, .max_response = sizeof g_chunk,
        .tx_olb_cap = (size_t)1u << 20u,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!proto) {
        duct_engine_destroy(io);
        fprintf(stderr, "close_timeout: proto create failed\n");
        return 1;
    }

    const char *err = nullptr;
    uint16_t port = 0u;
    pthread_t th;
    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok)
        err = "listen failed";
    else if (pthread_create(&th, nullptr, th_run, io) != 0)
        err = "thread create failed";
    else {
        duct_sock_t fd = th_connect(port);
        if (fd == duct_sock_bad)
            err = "connect failed";
        else if (!th_wait_int(&g_closing, 1, wait_ms))
            err = "the ring never filled behind a peer that reads nothing";
        else if (duct_atomic_load(&g_queued_at_close, relaxed) < ((size_t)1u << 19u))
            err = "the ring held too little at the close to prove a discard";
        else if (!th_wait_int(&g_closed, 1, wait_ms))
            err = "a close on timeout waited for a drain the peer never takes";
        else if (duct_atomic_load(&g_closed_at, relaxed) - duct_atomic_load(&g_close_at, relaxed)
                 >= close_by_ns)
            err = "a close on timeout took over a second";
        if (fd != duct_sock_bad)
            duct_sock_close(fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(proto);

    if (err) {
        fprintf(stderr, "close_timeout: %s\n", err);
        return 1;
    }
    printf("close_timeout: OK (a session closed on timeout discards the ring its silent "
           "peer never drains)\n");
    return 0;
}
