/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file tcp_cycle_test.c
 * @brief Two ductio ends of one loopback TCP session keep reading each other
 * while each has more queued for the other than the path holds.
 *
 * One io thread and one worker carry both ends. The accepting end posts its
 * whole run through duct_session_invoke ahead of any echo: frame_count frames
 * of frame_size bytes, 64 MiB. Its socket buffers are pinned small on the
 * listening socket, which the accepted one inherits, so its sends meet a full
 * ring and park almost at once; the dialing end autotunes, and the loop between
 * them still holds a small part of the run. Every frame carries its index, and
 * each end checks the order it arrives in.
 *
 * Shapes: echo, where the dialing end answers each frame with its own bytes and
 * the accepting end answers nothing; sinks, where the dialing end posts the
 * same run back and neither on_frame answers. Before the conn hold both stalled
 * for good: an end deferred its inbound while a send of its own waited parked
 * or a leg lacked room for max_response, whatever its callback would write.
 *
 * Cells: the length-prefix wire with max_response at frame_size and at 0, both
 * shapes; in a TCP_CYCLE_NOISE build the Noise sealed wire the same four ways,
 * where every record is acked at unseal and an echo aliases the cleartext.
 *
 * A cell fails once stall_ms pass with no frame arriving at either end, and
 * prints both ends' counts and the engine's counters.
 */

#include "duct.h"
#include "duct_ticks.h"
#ifdef TCP_CYCLE_NOISE
#include "duct_tls.h"
#include "duct_noise.h"
#endif

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "test_helpers.h"

static constexpr uint32_t frame_count = 4096u;
static constexpr size_t   frame_size  = 16384u;
static constexpr int      sock_buf    = 16384;
static constexpr unsigned stall_ms    = 3000u;
static constexpr unsigned open_ms     = 5000u;

typedef enum : uint8_t { shape_echo, shape_sinks } shape_t;
typedef enum : uint8_t { side_accept, side_dial, side_count } side_t;
typedef enum : uint8_t { wire_lp, wire_noise } wire_kind_t;

typedef struct {
    const char *name;
    wire_kind_t wire;
    size_t      max_response;
    shape_t     shape;
} cell_t;

static const cell_t s_cells[] = {
    { "lp echo",            wire_lp,    frame_size, shape_echo  },
    { "lp echo, cap 0",     wire_lp,    0u,         shape_echo  },
    { "lp sinks",           wire_lp,    frame_size, shape_sinks },
    { "lp sinks, cap 0",    wire_lp,    0u,         shape_sinks },
#ifdef TCP_CYCLE_NOISE
    { "noise echo",         wire_noise, frame_size, shape_echo  },
    { "noise echo, cap 0",  wire_noise, 0u,         shape_echo  },
    { "noise sinks",        wire_noise, frame_size, shape_sinks },
    { "noise sinks, cap 0", wire_noise, 0u,         shape_sinks },
#endif
};
static constexpr unsigned cell_count = sizeof s_cells / sizeof s_cells[0];

static _Atomic shape_t g_shape;
static atomic_int    g_opened;
static atomic_uint   g_got[side_count];
static atomic_uint   g_bad[side_count];
static duct_handle_t g_tok[side_count];
static uint8_t       g_scratch[frame_size];

#ifdef TCP_CYCLE_NOISE
static duct_noise_cfg_t g_accept_cfg,
                        g_dial_cfg;
#endif

static uint8_t s_fill_byte(uint32_t i)
{
    return (uint8_t)(i * 31u + 7u);
}

static bool s_frame_is(const duct_frame_t *frame, uint32_t i)
{
    if (frame->payload.size != frame_size)
        return false;
    auto p = (const uint8_t *)frame->payload.data;
    uint32_t got;
    memcpy(&got, p, sizeof got);
    return got == i && p[sizeof got] == s_fill_byte(i) && p[frame_size - 1u] == s_fill_byte(i);
}

static void s_count(side_t side, const duct_frame_t *frame)
{
    unsigned n = duct_atomic_load(&g_got[side], relaxed);
    if (!s_frame_is(frame, n))
        duct_atomic_fetch(add, &g_bad[side], 1u, relaxed);
    duct_atomic_fetch(add, &g_got[side], 1u, release);
}

/** @brief Accepting end: count, answer nothing. */
static duct_result_t
s_accept_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
               const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
               [[maybe_unused]] void *proto_state)
{
    s_count(side_accept, frame);
    return rc_ok;
}

/** @brief Dialing end: count and, in the echo shape, answer with the frame's
 *  own bytes, which alias the frame where they rest. */
static duct_result_t
s_dial_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             const duct_frame_t *frame, duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    s_count(side_dial, frame);
    if (duct_atomic_load(&g_shape, relaxed) == shape_echo)
        duct_response_same(out, frame->payload, fl_send_copy, 0);
    return rc_ok;
}

static duct_result_t
s_accept_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok,
              [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
              [[maybe_unused]] void *proto_state)
{
    g_tok[side_accept] = tok;
    duct_atomic_fetch(add, &g_opened, 1, release);
    return rc_ok;
}

static duct_result_t
s_dial_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    g_tok[side_dial] = tok;
    duct_atomic_fetch(add, &g_opened, 1, release);
    return rc_ok;
}

/** @brief One frame of the run, its index in @p ctx. The scratch is shared:
 *  invokes run one at a time on the one worker, and the commit copies the
 *  bytes into the ring or into the parked response before the next runs. */
static duct_result_t
s_post([[maybe_unused]] duct_session_t *s, duct_response_t *out, void *ctx)
{
    auto i = (uint32_t)(uintptr_t)ctx;
    memcpy(g_scratch, &i, sizeof i);
    memset(g_scratch + sizeof i, s_fill_byte(i), frame_size - sizeof i);
    duct_response_same(out, duct_view(duct_view_u8, g_scratch, frame_size),
                       fl_send_copy, 0);
    return rc_ok;
}

static duct_wire_t *s_wire(wire_kind_t kind, [[maybe_unused]] side_t side)
{
    switch (kind) {
    case wire_lp:
        return duct_wire_create_length_prefix(0u);
    case wire_noise:
#ifdef TCP_CYCLE_NOISE
        return duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .engine = duct_noise_vtbl(),
            .engine_cfg = side == side_accept ? &g_accept_cfg : &g_dial_cfg,
            .role = side == side_accept ? seal_role_responder : seal_role_initiator,
            .framing = seal_framing_stream });
#else
        return nullptr;
#endif
    }
    return nullptr;
}

static duct_proto_t *s_proto(const cell_t *cell, side_t side)
{
    auto wire = s_wire(cell->wire, side);
    duct_do_if(!wire, return nullptr);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = side == side_accept ? "tcp-cycle-accept" : "tcp-cycle-dial",
        .wire = wire,
        .on_frame = side == side_accept ? s_accept_frame : s_dial_frame,
        .on_session_open = side == side_accept ? s_accept_open : s_dial_open,
        .max_response = cell->max_response,
    });
    if (proto)
        proto->owned_wire = wire;
    else
        duct_wire_destroy(wire);
    return proto;
}

/** @brief Bind @p proto's listener with its socket buffers pinned at
 *  sock_buf, for the accepted socket to inherit. */
static bool s_listen(duct_engine_t *io, duct_proto_t *proto, uint16_t *port)
{
    const duct_proto_t *protos[] = { proto };
    duct_sock_t fd = duct_sock_bad;
    unsigned n = 0u;
    duct_result_t rc = duct_listener_bind(io, &(duct_listener_cfg_t){
        .addr = "127.0.0.1", .n_protos = 1u, .protos = protos }, port, &fd, 1u, &n);
    if (rc != rc_ok || n != 1u)
        return false;
    int size = sock_buf;
    return setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char *)&size, sizeof size) == 0
        && setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&size, sizeof size) == 0;
}

/** @brief Wait for both ends to take frame_count frames, failing once
 *  stall_ms pass with neither count moving. */
static const char *s_drain(duct_engine_t *io, const cell_t *cell)
{
    unsigned last = 0u;
    uint64_t since = duct_ticks_mono_ns();
    for (;;) {
        unsigned acc = duct_atomic_load(&g_got[side_accept], acquire),
                 dial = duct_atomic_load(&g_got[side_dial], acquire);
        if (acc == frame_count && dial == frame_count)
            return nullptr;
        uint64_t now = duct_ticks_mono_ns();
        if (acc + dial != last) {
            last = acc + dial;
            since = now;
        } else if (now - since >= (uint64_t)stall_ms * 1'000'000u) {
            fprintf(stderr, "tcp_cycle: %s: stalled with the accepting end at %u and the "
                    "dialing end at %u of %u frames\n",
                    cell->name, acc, dial, (unsigned)frame_count);
            duct_engine_stats_print(io, stderr, "tcp_cycle");
            return "stalled";
        }
        th_sleep_ms(10u);
    }
}

static const char *s_cell(duct_engine_t *io, const cell_t *cell, duct_proto_t *accept,
                          duct_proto_t *dial)
{
    duct_atomic_store(&g_shape, cell->shape, relaxed);
    duct_atomic_store(&g_opened, 0, relaxed);
    for (unsigned i = 0u; i < side_count; ++i) {
        duct_atomic_store(&g_got[i], 0u, relaxed);
        duct_atomic_store(&g_bad[i], 0u, relaxed);
    }
    uint16_t port = 0u;
    char addr[64];
    if (!s_listen(io, accept, &port))
        return "listen failed";
    snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)port);
    if (th_connect_retry(io, addr, dial, x_tcp) != rc_ok)
        return "connect failed";
    if (!th_wait_int(&g_opened, 2, open_ms))
        return "the sessions never opened";
    for (uint32_t i = 0u; i < frame_count; ++i) {
        auto ctx = (void *)(uintptr_t)i;
        if (duct_session_invoke(io, g_tok[side_accept], s_post, ctx) != rc_ok
            || (cell->shape == shape_sinks
                && duct_session_invoke(io, g_tok[side_dial], s_post, ctx) != rc_ok))
            return "an invoke was refused";
    }
    auto err = s_drain(io, cell);
    if (!err && (duct_atomic_load(&g_bad[side_accept], relaxed)
                 || duct_atomic_load(&g_bad[side_dial], relaxed)))
        err = "a frame arrived out of order or damaged";
    duct_discard duct_session_close(io, g_tok[side_dial], close_normal);
    return err;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

#ifdef TCP_CYCLE_NOISE
    duct_noise_keypair_t accept_kp, dial_kp;
    if (!duct_noise_keypair_generate(&accept_kp) || !duct_noise_keypair_generate(&dial_kp)) {
        fprintf(stderr, "tcp_cycle: keypair generation failed\n");
        return 1;
    }
    g_accept_cfg.local_static = accept_kp;
    g_dial_cfg.local_static = dial_kp;
    memcpy(g_dial_cfg.remote_static_pub, accept_kp.pub, duct_noise_key_size);
#endif

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) {
        fprintf(stderr, "tcp_cycle: engine launch failed\n");
        return 1;
    }
    pthread_t th;
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        duct_engine_destroy(io);
        fprintf(stderr, "tcp_cycle: thread create failed\n");
        return 1;
    }

    duct_proto_t *protos[cell_count][side_count] = {};
    const char *err = nullptr;
    unsigned at = 0u;
    for (; at < cell_count && !err; ++at) {
        auto cell = &s_cells[at];
        protos[at][side_accept] = s_proto(cell, side_accept);
        protos[at][side_dial] = s_proto(cell, side_dial);
        err = protos[at][side_accept] && protos[at][side_dial]
            ? s_cell(io, cell, protos[at][side_accept], protos[at][side_dial])
            : "proto create failed";
        if (!err)
            printf("tcp_cycle: %s: %u frames each way\n", cell->name, (unsigned)frame_count);
    }

    duct_engine_stop(io);
    pthread_join(th, nullptr);
    duct_engine_destroy(io);
    for (unsigned i = 0u; i < cell_count; ++i)
        for (unsigned j = 0u; j < side_count; ++j)
            duct_proto_destroy(protos[i][j]);

    if (err) {
        fprintf(stderr, "tcp_cycle: %s: %s\n", s_cells[at - 1u].name, err);
        return 1;
    }
    printf("tcp_cycle: OK (both ends read on with more queued than the path holds)\n");
    return 0;
}
