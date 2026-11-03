/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file packet_fd_multi_test.c
 *  @brief Isolation between sessions that each hold their own packet fd.
 *
 *  Several sessions on one engine, each attaching its own descriptor at conn 1
 *  under a wire of its own. A packet written into one descriptor reaches that
 *  session's @c on_frame and no other: nothing routes, because the descriptor
 *  belongs to one conn and that conn to one session.
 *
 *  Every byte of a packet carries its session's index, so a frame delivered to
 *  the wrong session is caught by content — a total that still adds up hides a
 *  swap.
 *
 *  A @c SOCK_DGRAM socketpair stands in for a tun, the shape
 *  @c packet_fd_test.c uses.
 */

#include "duct.h"
#include "test_helpers.h"

#include <sys/socket.h>
#include <unistd.h>
#include <stdatomic.h>

static constexpr unsigned wait_ms      = 15000u;
static constexpr size_t   max_response = 4096u;
static constexpr unsigned n_sessions   = 4u;
static constexpr unsigned packet_len   = 64u;

static duct_wire_t *g_leg_wire;
static duct_sock_t  g_peer[n_sessions];

/* g_opened hands out the session index, g_attach_ok publishes: main waits on
 * the second, so g_peer[] must be stored before the count that admits it. */
static atomic_int g_opened    = 0;
static atomic_int g_attach_ok = 0;
static atomic_int g_frames    = 0;
static atomic_int g_crossed   = 0;

typedef struct { unsigned index; } sess_t;

static duct_result_t
create_state([[maybe_unused]] duct_session_t *s, [[maybe_unused]] void *ctx,
             void **out)
{
    auto st = duct_new(sess_t);
    duct_do_if(!st, return rc_no_memory);
    st->index = n_sessions;
    *out = st;
    return rc_ok;
}

static void
destroy_state([[maybe_unused]] duct_session_t *s, [[maybe_unused]] void *ctx,
              void *value)
{
    auto st = (sess_t *)value;
    duct_del(st);
}

static duct_result_t
on_session_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                [[maybe_unused]] void *user_ctx,
                [[maybe_unused]] duct_response_t *out, void *proto_state)
{
    auto st = (sess_t *)proto_state;
    auto index = (unsigned)duct_atomic_fetch(add, &g_opened, 1, acq_rel);
    if (index >= n_sessions)
        return rc_ok;
    st->index = index;
    duct_sock_t sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0)
        return rc_ok;
    g_peer[index] = sv[0];
    if (duct_conn_attach_packet_fd(s, 1u, sv[1], g_leg_wire) == rc_ok)
        duct_discard duct_atomic_fetch(add, &g_attach_ok, 1, release);
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
         const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
         void *proto_state)
{
    if (conn_id != 1u)
        return rc_ok;
    auto st = (sess_t *)proto_state;
    auto body = (const uint8_t *)frame->payload.data;
    bool mine = frame->payload.size == packet_len;
    for (size_t i = 0u; mine && i < frame->payload.size; ++i)
        mine = body[i] == (uint8_t)st->index;
    if (!mine)
        duct_discard duct_atomic_fetch(add, &g_crossed, 1, release);
    duct_discard duct_atomic_fetch(add, &g_frames, 1, release);
    return rc_ok;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    for (unsigned i = 0u; i < n_sessions; ++i)
        g_peer[i] = duct_sock_bad;
    duct_sock_t driver[n_sessions];
    for (unsigned i = 0u; i < n_sessions; ++i)
        driver[i] = duct_sock_bad;

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) {
        fprintf(stderr, "packet_fd_multi: io create failed\n");
        return 1;
    }
    g_leg_wire = duct_wire_create_dgram_batch(2048u, false);
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = (g_leg_wire && wire) ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "packet-fd-multi", .wire = wire, .on_frame = on_frame,
        .on_session_open = on_session_open,
        .create_state = create_state, .destroy_state = destroy_state,
        .max_response = max_response,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!proto) {
        if (g_leg_wire)
            duct_wire_destroy(g_leg_wire);
        duct_engine_destroy(io);
        fprintf(stderr, "packet_fd_multi: proto create failed\n");
        return 1;
    }

    const char *error = nullptr;
    uint16_t port = 0u;
    pthread_t thread;
    bool running = false;
    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok)
        error = "listen failed";
    if (!error) {
        if (pthread_create(&thread, nullptr, th_run, io) != 0)
            error = "thread create failed";
        else
            running = true;
    }

    for (unsigned i = 0u; !error && i < n_sessions; ++i) {
        driver[i] = th_connect(port);
        if (driver[i] == duct_sock_bad)
            error = "driver connect failed";
    }
    if (!error && !th_wait_int(&g_attach_ok, (int)n_sessions, wait_ms))
        error = "not every session attached its own packet-fd leg";
    if (!error) {
        uint8_t packet[packet_len];
        for (unsigned i = 0u; !error && i < n_sessions; ++i) {
            memset(packet, (int)(uint8_t)i, sizeof packet);
            if (write(g_peer[i], packet, sizeof packet) != (ssize_t)sizeof packet)
                error = "write to a packet fd failed";
        }
    }
    if (!error && !th_wait_int(&g_frames, (int)n_sessions, wait_ms))
        error = "a packet written to one descriptor never reached its session";
    if (!error && duct_atomic_load(&g_crossed, acquire) != 0)
        error = "a packet reached the wrong session";

    for (unsigned i = 0u; i < n_sessions; ++i)
        if (driver[i] != duct_sock_bad)
            close(driver[i]);
    duct_engine_stop(io);
    if (running)
        pthread_join(thread, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    duct_wire_destroy(g_leg_wire);
    for (unsigned i = 0u; i < n_sessions; ++i)
        if (g_peer[i] != duct_sock_bad)
            close(g_peer[i]);
    if (error) {
        fprintf(stderr, "packet_fd_multi: %s\n", error);
        return 1;
    }
    printf("packet_fd_multi: OK (%u sessions, one descriptor each, no crossing)\n",
           n_sessions);
    return 0;
}
