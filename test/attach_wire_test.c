/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file attach_wire_test.c
 *  @brief The wire a packet fd's leg needs: a protocol that carries one.
 *
 *  A session under a protocol with no wire attaches three fds in one turn: a
 *  packet fd with no leg wire, a packet fd on @c duct_wire_packet, and a raw fd
 *  through @c duct_conn_attach_fd. The first two answer @c rc_invalid_arg and
 *  the engine closes both, which their peer ends see as a hangup. The raw fd is
 *  admitted and stays open: a protocol with no wire is a raw one. Every fd is a
 *  socketpair end and every refusal comes ahead of any read, so the test runs
 *  on every platform.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>
#include <stdio.h>

/** @brief Longest wait for an attach result or a hangup, milliseconds. */
static constexpr unsigned wait_ms      = 15000u;
/** @brief Time the admitted fd is watched for a hangup, milliseconds.
 *  The engine closes a refused fd inside the attach call; the watch bounds the
 *  negative. */
static constexpr int      silent_ms    = 100;
/** @brief Response cap of the protocol with no wire, bytes. */
static constexpr size_t   max_response = 1500u;

/** @brief Slot of each attach in the result arrays, and their count.
 *  Packet fd with no leg wire, packet fd on @c duct_wire_packet, raw fd. */
enum : unsigned { no_wire, leg_wire, raw_fd, attaches };

/** @brief Result of each attach, -1 until it runs. */
static atomic_int  g_rc[attaches];
/** @brief Test's end of each attach's socketpair. */
static duct_sock_t g_peer[attaches];

/** @brief Make three socketpairs and attach the engine's end of each, recording the results. */
static duct_result_t on_session_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                                     [[maybe_unused]] void *user_ctx,
                                     [[maybe_unused]] duct_response_t *out,
                                     [[maybe_unused]] void *proto_state)
{
    duct_sock_t engine_end[attaches];
    for (unsigned i = 0u; i < attaches; ++i) {
        duct_sock_t sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
            return rc_ok;
        g_peer[i] = sv[0];
        engine_end[i] = sv[1];
    }
    duct_atomic_store(&g_rc[no_wire],
                      (int)duct_conn_attach_packet_fd(s, 1u, engine_end[no_wire], nullptr), release);
    duct_atomic_store(&g_rc[leg_wire],
                      (int)duct_conn_attach_packet_fd(s, 1u, engine_end[leg_wire], duct_wire_packet()),
                      release);
    duct_atomic_store(&g_rc[raw_fd], (int)duct_conn_attach_fd(s, 2u, engine_end[raw_fd]), release);
    return rc_ok;
}

/** @brief Drop every frame; the test sends none. */
static duct_result_t on_frame([[maybe_unused]] duct_session_t *s,
                              [[maybe_unused]] duct_conn_id_t conn_id,
                              [[maybe_unused]] const duct_frame_t *frame,
                              [[maybe_unused]] duct_response_t *out,
                              [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

/** @brief Check the three attach results, then which fds the engine closed and which it kept.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *check(void)
{
    return !th_wait_int(&g_rc[no_wire], (int)rc_invalid_arg, wait_ms)
               ? "a packet fd was admitted under a protocol with no wire"
         : !th_wait_int(&g_rc[leg_wire], (int)rc_invalid_arg, wait_ms)
               ? "a packet fd with a leg wire was admitted under a protocol with no wire"
         : !th_wait_int(&g_rc[raw_fd], (int)rc_ok, wait_ms)
               ? "duct_conn_attach_fd was refused under a protocol with no wire"
         : !th_peer_closed(g_peer[no_wire], (int)wait_ms) ? "the engine kept a packet fd it refused"
         : !th_peer_closed(g_peer[leg_wire], (int)wait_ms)
               ? "the engine kept a packet fd with a leg wire it refused"
         : th_recv_none(g_peer[raw_fd], silent_ms) != 0 ? "the engine closed the fd it admitted"
         : nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    for (unsigned i = 0u; i < attaches; ++i) {
        duct_atomic_store(&g_rc[i], -1, relaxed);
        g_peer[i] = duct_sock_bad;
    }
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1u, .workers = 1u });
    auto proto = io ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "no-wire", .on_frame = on_frame, .on_session_open = on_session_open,
        .max_response = max_response,
    }) : nullptr;
    uint16_t port = 0u;
    pthread_t th;
    const char *error = !io ? "engine launch failed"
                      : !proto ? "proto create failed"
                      : duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok ? "listen failed"
                      : pthread_create(&th, nullptr, th_run, io) != 0 ? "thread create failed"
                      : nullptr;
    if (!error) {
        auto driver = th_connect(port);
        error = driver == duct_sock_bad ? "driver connect failed" : check();
        duct_sock_close(driver);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    for (unsigned i = 0u; i < attaches; ++i)
        duct_sock_close(g_peer[i]);
    if (error)
        fprintf(stderr, "attach_wire: %s\n", error);
    else
        printf("attach_wire: OK\n");
    return error != nullptr;
}
