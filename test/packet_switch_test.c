/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file packet_switch_test.c
 *  @brief A protocol switch cannot take the wire from a packet fd's leg.
 *
 *  A session under a protocol with a length-prefix wire attaches a packet fd
 *  with no leg wire, so the leg rides the protocol's own, and asks on the leg's
 *  join to switch to a protocol with no wire. The switch is abandoned:
 *  @c on_error carries @c rc_invalid_order, the call itself having answered
 *  @c rc_ok.
 *
 *  A second session of the same kind of protocol, with no packet fd, asks for
 *  that switch from @c on_session_open and the new protocol's @c on_proto_enter
 *  runs: the refusal belongs to the packet leg, not to a protocol with no wire.
 *
 *  The packet fd is a @c SOCK_DGRAM socketpair end, and a packet leg on Windows
 *  closes at its first read, so the test is POSIX only.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

/** @brief Longest wait for a session event, milliseconds. */
static constexpr unsigned wait_ms      = 15000u;
/** @brief Response cap of the protocol with no wire, bytes. */
static constexpr size_t   max_response = 1500u;

/** @brief Result of the packet fd's attach, -1 until it runs. */
static atomic_int g_attach_rc    = -1;
/** @brief Result of the @c duct_proto_switch call, -1 until it runs. */
static atomic_int g_switch_rc    = -1;
/** @brief Last result @c on_error received, -1 until one arrives. */
static atomic_int g_switch_error = -1;
/** @brief Entries into the protocol with no wire. */
static atomic_int g_entered      = 0;

/** @brief Test's end of the packet fd's socketpair, held open so the leg stays up. */
static duct_sock_t  g_peer = duct_sock_bad;
/** @brief Protocol the sessions ask to switch to, the one with no wire. */
static duct_proto_t *g_wireless;

/** @brief Drop every frame; the test sends none. */
static duct_result_t on_frame([[maybe_unused]] duct_session_t *s,
                              [[maybe_unused]] duct_conn_id_t conn_id,
                              [[maybe_unused]] const duct_frame_t *frame,
                              [[maybe_unused]] duct_response_t *out,
                              [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

/** @brief Record the result reported to the author. */
static duct_result_t on_error([[maybe_unused]] duct_session_t *s, duct_result_t error,
                              [[maybe_unused]] duct_response_t *out,
                              [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_switch_error, (int)error, release);
    return rc_ok;
}

/** @brief Count the entries into the protocol with no wire. */
static duct_result_t on_proto_enter([[maybe_unused]] duct_session_t *s,
                                    [[maybe_unused]] void *ctx,
                                    [[maybe_unused]] void *new_state)
{
    duct_atomic_fetch(add, &g_entered, 1, release);
    return rc_ok;
}

/** @brief Attach one end of a datagram socketpair as a packet fd with no leg wire, so the leg rides the protocol's own. */
static duct_result_t packet_on_session_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                                            [[maybe_unused]] void *user_ctx,
                                            [[maybe_unused]] duct_response_t *out,
                                            [[maybe_unused]] void *proto_state)
{
    duct_sock_t sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0)
        return rc_ok;
    g_peer = sv[0];
    duct_atomic_store(&g_attach_rc, (int)duct_conn_attach_packet_fd(s, 1u, sv[1], nullptr), release);
    return rc_ok;
}

/** @brief Ask @p s to switch to the protocol with no wire and record the call's result. */
static void switch_to_wireless(duct_session_t *s)
{
    duct_atomic_store(&g_switch_rc, (int)duct_proto_switch(s, g_wireless, nullptr), release);
}

/** @brief Ask for the switch once the packet leg has joined. */
static duct_result_t packet_on_conn_join(duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                                         [[maybe_unused]] const duct_peer_t *peer,
                                         [[maybe_unused]] duct_response_t *out,
                                         [[maybe_unused]] void *proto_state)
{
    switch_to_wireless(s);
    return rc_ok;
}

/** @brief Ask for the switch as a session with no packet leg opens. */
static duct_result_t alone_on_session_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                                           [[maybe_unused]] void *user_ctx,
                                           [[maybe_unused]] duct_response_t *out,
                                           [[maybe_unused]] void *proto_state)
{
    switch_to_wireless(s);
    return rc_ok;
}

/** @brief Open the session with a packet leg and wait for the abandoned switch to reach @c on_error.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_refused(uint16_t port)
{
    auto driver = th_connect(port);
    auto err = driver == duct_sock_bad ? "driver connect failed"
        : !th_wait_int(&g_attach_rc, (int)rc_ok, wait_ms)
              ? "a packet fd was refused under a protocol with a wire"
        : !th_wait_int(&g_switch_rc, (int)rc_ok, wait_ms) ? "duct_proto_switch refused the call itself"
        : !th_wait_int(&g_switch_error, (int)rc_invalid_order, wait_ms)
              ? "a switch to a protocol with no wire left a packet leg without one"
        : nullptr;
    duct_sock_close(driver);
    return err;
}

/** @brief Open the session with no packet leg and wait for the switch to enter the protocol with no wire.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_taken(uint16_t port)
{
    duct_atomic_store(&g_switch_rc, -1, relaxed);
    auto driver = th_connect(port);
    auto err = driver == duct_sock_bad ? "driver connect failed"
        : !th_wait_int(&g_switch_rc, (int)rc_ok, wait_ms) ? "duct_proto_switch refused the call itself"
        : !th_wait_int(&g_entered, 1, wait_ms)
              ? "a switch to a protocol with no wire was refused where no packet leg stood"
        : nullptr;
    duct_sock_close(driver);
    return err;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1u, .workers = 1u });
    duct_proto_cfg_t packet_cfg = {
        .name = "packet", .on_frame = on_frame, .on_error = on_error,
        .on_session_open = packet_on_session_open, .on_conn_join = packet_on_conn_join,
    };
    duct_proto_cfg_t alone_cfg = {
        .name = "alone", .on_frame = on_frame, .on_error = on_error,
        .on_session_open = alone_on_session_open,
    };
    g_wireless = io ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "wireless", .on_frame = on_frame, .on_proto_enter = on_proto_enter,
        .max_response = max_response,
    }) : nullptr;
    auto packet = io ? duct_proto_create_owning(&packet_cfg, duct_wire_create_length_prefix(0u)) : nullptr;
    auto alone = io ? duct_proto_create_owning(&alone_cfg, duct_wire_create_length_prefix(0u)) : nullptr;
    uint16_t packet_port = 0u,
             alone_port = 0u;
    pthread_t th;
    const char *error = !io ? "engine launch failed"
        : !g_wireless || !packet || !alone ? "proto create failed"
        : duct_io_listen(io, "127.0.0.1", &packet_port, packet) != rc_ok
              || duct_io_listen(io, "127.0.0.1", &alone_port, alone) != rc_ok ? "listen failed"
        : pthread_create(&th, nullptr, th_run, io) != 0 ? "thread create failed"
        : nullptr;
    if (!error) {
        auto refused = sc_refused(packet_port);
        error = refused ? refused : sc_taken(alone_port);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(packet);
    duct_proto_destroy(alone);
    duct_proto_destroy(g_wireless);
    duct_sock_close(g_peer);
    if (error)
        fprintf(stderr, "packet_switch: %s\n", error);
    else
        printf("packet_switch: OK\n");
    return error != nullptr;
}
