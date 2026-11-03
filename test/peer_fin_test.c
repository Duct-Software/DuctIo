/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file peer_fin_test.c
 * @brief A live leg's last frames and the peer's FIN, pending together, all
 *  reach on_frame before the leg closes with close_peer.
 *
 * on_session_open attaches one end of a socketpair at conn_id 1. Its join
 * pauses RX and arms a resume timer; while reads stand paused the test writes
 * frame_count length-prefix frames into the other end and shuts its write side,
 * so the readiness the events model reports carries the data and the FIN at
 * once. Once the timer resumes RX, every frame has to reach on_frame and the
 * leg has to close with close_peer.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>
#include <string.h>

static constexpr unsigned wait_ms = 3000u;
/* The worker applies the join's pause as that callback returns, well inside
 * pause_margin_ms; resume_ms leaves the FIN's readiness that long to reach the
 * io thread while reads stand paused. */
static constexpr unsigned pause_margin_ms = 50u;
static constexpr unsigned resume_ms = 300u;
static constexpr int frame_count = 32;
static constexpr size_t frame_size = 96u;

static atomic_int g_attach_rc = -1;
static atomic_int g_paused = 0;
static atomic_int g_frames = 0;
static atomic_int g_lost_reason = -1;
static _Atomic(duct_sock_t) g_writer = duct_sock_bad;

static duct_result_t
on_session_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_sock_t sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        duct_atomic_store(&g_attach_rc, (int)rc_no_memory, release);
        return rc_ok;
    }
    duct_atomic_store(&g_writer, sv[1], release);
    auto rc = duct_conn_attach_fd(s, 1u, sv[0]);
    duct_atomic_store(&g_attach_rc, (int)rc, release);
    return rc_ok;
}

static duct_result_t
on_conn_join([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
             [[maybe_unused]] const duct_peer_t *peer, duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    if (conn_id != 1u)
        return rc_ok;
    out->control.rx = rx_op_pause;
    out->control.timer.delay_ms = resume_ms;
    duct_atomic_store(&g_paused, 1, release);
    return rc_ok;
}

static duct_result_t
on_timer([[maybe_unused]] duct_session_t *s, duct_response_t *out,
         [[maybe_unused]] void *proto_state, [[maybe_unused]] uint64_t arg)
{
    out->control.rx = rx_op_resume;
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
         const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    if (conn_id == 1u && frame->payload.size == frame_size)
        duct_atomic_fetch(add, &g_frames, 1, release);
    return rc_ok;
}

static void on_conn_lost([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
                         duct_close_reason_t reason, [[maybe_unused]] duct_response_t *out,
                         [[maybe_unused]] void *proto_state)
{
    if (conn_id == 1u)
        duct_atomic_store(&g_lost_reason, (int)reason, release);
}

/* Write the frames and the FIN into the paused leg's peer end. */
static const char *s_fill(duct_sock_t writer)
{
    uint8_t payload[frame_size];
    memset(payload, 0xa5, sizeof payload);
    for (int i = 0; i < frame_count; ++i)
        if (th_send(writer, payload, sizeof payload) != 0)
            return "writing a frame failed";
    return shutdown(writer, SHUT_WR) == 0 ? nullptr : "shutdown of the write side failed";
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) {
        fprintf(stderr, "peer_fin: io create failed\n");
        return 1;
    }
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "peer_fin", .wire = wire, .on_frame = on_frame,
        .on_session_open = on_session_open, .on_conn_join = on_conn_join,
        .on_conn_lost = on_conn_lost, .on_timer = on_timer,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!proto) {
        fprintf(stderr, "peer_fin: proto create failed\n");
        duct_engine_destroy(io);
        return 1;
    }
    uint16_t port = 0u;
    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok) {
        fprintf(stderr, "peer_fin: listen failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }
    pthread_t thread;
    if (pthread_create(&thread, nullptr, th_run, io) != 0) {
        fprintf(stderr, "peer_fin: thread create failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }

    duct_sock_t primary = th_connect(port);
    const char *error = nullptr;
    if (primary == duct_sock_bad)
        error = "primary connect failed";
    else if (!th_wait_int(&g_attach_rc, (int)rc_ok, wait_ms))
        error = "duct_conn_attach_fd did not return rc_ok";
    else if (!th_wait_int(&g_paused, 1, wait_ms))
        error = "the attached leg never joined";
    if (!error) {
        th_sleep_ms(pause_margin_ms);
        error = s_fill(duct_atomic_load(&g_writer, acquire));
    }
    if (!error && !th_wait_int(&g_lost_reason, (int)close_peer, wait_ms))
        error = "the attached leg did not close with close_peer";

    int frames = duct_atomic_load(&g_frames, acquire);
    if (primary != duct_sock_bad)
        close(primary);
    duct_engine_stop(io);
    pthread_join(thread, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    duct_sock_t writer = duct_atomic_load(&g_writer, acquire);
    if (writer != duct_sock_bad)
        close(writer);

    if (!error && frames != frame_count)
        error = "frames pending with the FIN were dropped";
    if (error) {
        fprintf(stderr, "peer_fin: %s (%d of %d frames, close reason %d)\n", error, frames,
                frame_count, duct_atomic_load(&g_lost_reason, acquire));
        return 1;
    }
    printf("peer_fin: OK (%d frames pending with the FIN read before close_peer)\n", frames);
    return 0;
}
