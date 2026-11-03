/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file park_control_test.c
 * @brief A response parked on a full TX ring applies its open_leg and timer in
 * its own callback's turn.
 *
 * A timer fills a 1 MB ring behind a raw client that never reads until a
 * chunk of its own parks and holds its later fires, and host-thread probes see
 * the ring's queued bytes hold still for 200 ms. An invoke then answers a 64 KB payload, which parks, with a
 * dial to a second listener and a timer whose id lands in a global. The id is
 * set once the invoke returns, and the second listener opens a session though
 * the dial's address string is zeroed right after, the payload still parked.
 */

#include "duct.h"
#include "duct_ticks.h"
#include "test_helpers.h"

#include <stdatomic.h>

static constexpr unsigned wait_ms     = 5000u;
static constexpr uint64_t still_for_ns = 200'000'000u;
static constexpr uint64_t idle_ms     = 60'000u;
static constexpr size_t   ring_cap    = (size_t)1u << 20u;
static constexpr size_t   top_up      = 4096u;

static uint8_t          g_chunk[65536];
static atomic_int       g_opened = 0;
static duct_handle_t    g_tok;
static char             g_leg_addr[64];
static duct_timer_id_t  g_timer_id;
static atomic_int       g_leg_opened = 0;

static duct_result_t
srv_on_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    g_tok = tok;
    duct_atomic_store(&g_opened, 1, release);
    out->control.timer.delay_ms = 1u;
    out->control.timer.interval_ms = 1u;
    return rc_ok;
}

static duct_result_t
srv_on_timer(duct_session_t *s, duct_response_t *out, [[maybe_unused]] void *proto_state,
             [[maybe_unused]] uint64_t arg)
{
    size_t n = duct_conn_tx_fits(s, duct_conn_id_primary, sizeof g_chunk) ? sizeof g_chunk
                                                                            : top_up;
    duct_response_same(out, duct_view(duct_view_u8, g_chunk, n), fl_send_static, 0);
    return rc_ok;
}

static duct_result_t
leg_on_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_leg_opened, 1, release);
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
         [[maybe_unused]] const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

static duct_result_t
probe_fn(duct_session_t *s, [[maybe_unused]] duct_response_t *out, void *ctx)
{
    duct_tx_pos_t end = {};
    duct_discard duct_conn_tx_end(s, duct_conn_id_primary, &end, (size_t *)ctx);
    return rc_ok;
}

static duct_result_t
park_fn([[maybe_unused]] duct_session_t *s, duct_response_t *out, [[maybe_unused]] void *ctx)
{
    duct_response_same(out, duct_view(duct_view_u8, g_chunk, sizeof g_chunk),
                       fl_send_static, 0);
    out->control.open_leg.kind = leg_kind_connect;
    out->control.open_leg.conn_id = 1u;
    out->control.open_leg.connect_addr = g_leg_addr;
    out->control.timer.delay_ms = idle_ms;
    out->control.timer.id_out = &g_timer_id;
    return rc_ok;
}

static bool s_ring_still(duct_engine_t *io)
{
    size_t last = SIZE_MAX;
    uint64_t since = 0u;
    for (unsigned waited = 0u; waited < wait_ms; waited += 10u) {
        size_t queued = 0u;
        if (duct_session_invoke_sync(io, g_tok, probe_fn, &queued) != rc_ok)
            return false;
        uint64_t now = duct_ticks_mono_ns();
        if (queued != last) {
            last = queued;
            since = now;
        } else if (queued > ring_cap / 2u && now - since >= still_for_ns)
            return true;
        th_sleep_ms(10u);
    }
    return false;
}

static duct_proto_t *s_proto(const char *name, duct_session_open_fn on_open,
                             duct_timer_fn on_timer)
{
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = name, .wire = wire, .on_frame = on_frame,
        .on_session_open = on_open, .on_timer = on_timer,
        .max_response = sizeof g_chunk, .tx_olb_cap = ring_cap,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    return proto;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) {
        fprintf(stderr, "park_control: io create failed\n");
        return 1;
    }
    auto srv = s_proto("park-control-srv", srv_on_open, srv_on_timer);
    auto leg = s_proto("park-control-leg", leg_on_open, nullptr);
    if (!srv || !leg) {
        duct_proto_destroy(srv);
        duct_proto_destroy(leg);
        duct_engine_destroy(io);
        fprintf(stderr, "park_control: proto create failed\n");
        return 1;
    }

    const char *err = nullptr;
    uint16_t port = 0u, leg_port = 0u;
    pthread_t th;
    if (duct_io_listen(io, "127.0.0.1", &port, srv) != rc_ok
        || duct_io_listen(io, "127.0.0.1", &leg_port, leg) != rc_ok)
        err = "listen failed";
    else if (pthread_create(&th, nullptr, th_run, io) != 0)
        err = "thread create failed";
    else {
        snprintf(g_leg_addr, sizeof g_leg_addr, "127.0.0.1:%u", (unsigned)leg_port);
        duct_sock_t fd = th_connect(port);
        if (fd == duct_sock_bad)
            err = "connect failed";
        else if (!th_wait_int(&g_opened, 1, wait_ms))
            err = "the session never opened";
        else if (!s_ring_still(io))
            err = "the ring never filled behind a peer that reads nothing";
        else if (duct_session_invoke_sync(io, g_tok, park_fn, nullptr) != rc_ok)
            err = "the invoke did not run";
        else {
            memset(g_leg_addr, 0, sizeof g_leg_addr);
            if (g_timer_id == 0u)
                err = "a parked response's timer took no id in its callback's turn";
            else if (!th_wait_int(&g_leg_opened, 1, wait_ms))
                err = "a parked response's dial waited on its payload";
        }
        if (fd != duct_sock_bad)
            duct_sock_close(fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(srv);
    duct_proto_destroy(leg);

    if (err) {
        fprintf(stderr, "park_control: %s\n", err);
        return 1;
    }
    printf("park_control: OK (a response parked on a full ring dials and starts its timer "
           "in its own callback's turn)\n");
    return 0;
}
