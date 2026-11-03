/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file tx_gather_partial_test.c
 * @brief The gather commit's short-write remainder is exactly the unsent tail.
 *
 * s_commit_stream_gather puts header and payload on the wire straight off the
 * pack, never through the TX ring, so a kernel that takes only part of the
 * write leaves a remainder with no staged copy behind it: the commit slices
 * that remainder out of the two spans itself. A wrong boundary duplicates or
 * drops bytes mid-stream, and the length prefix of the frame it happened in
 * still reads correct, so only the bytes themselves show it.
 *
 * The leg is a socketpair attached through duct_conn_attach_fd, which puts the
 * engine's own send buffer under this test's control: shrunk below the
 * payload, the short write happens by construction rather than by timing.
 */

#include "duct.h"

#include <stdatomic.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

#include "test_helpers.h"

static constexpr size_t payload_size = 16384u;
static constexpr int    leg_sndbuf   = 2048;

static uint16_t g_port = 0;
static atomic_int g_attach_rc = -1;
static _Atomic(duct_sock_t) g_attached_fd = duct_sock_bad;
static atomic_int g_join_count = 0;

static uint8_t g_sent[payload_size];

static duct_result_t
on_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
        [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
        [[maybe_unused]] void *proto_state)
{
    duct_sock_t sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        duct_atomic_store(&g_attach_rc, (int)rc_no_memory, release);
        return rc_ok;
    }
    duct_discard setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF,
                            (const char *)&leg_sndbuf, sizeof leg_sndbuf);
    auto rc = duct_conn_attach_fd(s, 1u, sv[0]);
    duct_atomic_store(&g_attach_rc, (int)rc, release);
    if (rc != rc_ok) {
        close(sv[0]);
        close(sv[1]);
        return rc_ok;
    }
    duct_atomic_store(&g_attached_fd, sv[1], release);
    return rc_ok;
}

static duct_result_t
on_join([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
        [[maybe_unused]] const duct_peer_t *peer, [[maybe_unused]] duct_response_t *out,
        [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_join_count, 1, release);
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t cid,
         const duct_frame_t *frame, duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

static const char *s_run_case(void)
{
    for (size_t i = 0u; i < payload_size; ++i)
        g_sent[i] = (uint8_t)(i * 7u + 13u);

    auto fd = th_connect(g_port);
    if (fd == duct_sock_bad)
        return "connect failed";

    const char *err = nullptr;
    static uint8_t back[payload_size];
    uint8_t hdr[4] = {};

    if (!th_wait_int(&g_join_count, 1, 3000u))
        err = "the attached leg never joined";
    else if (duct_atomic_load(&g_attach_rc, acquire) != (int)rc_ok)
        err = "duct_conn_attach_fd refused";
    else {
        auto leg = duct_atomic_load(&g_attached_fd, acquire);
        uint32_t got = 0u;
        if (th_send(leg, g_sent, payload_size) != 0)
            err = "sending the frame into the attached leg failed";
        else if (th_read_exact(leg, hdr, sizeof hdr) != 0)
            err = "no echo header came back off the attached leg";
        else if ((got = ((uint32_t)hdr[0] << 24u) | ((uint32_t)hdr[1] << 16u)
                      | ((uint32_t)hdr[2] <<  8u) |  (uint32_t)hdr[3])
                 != (uint32_t)payload_size)
            err = "the echoed length prefix does not match what was sent";
        else if (th_read_exact(leg, back, payload_size) != 0)
            err = "the echoed payload never arrived in full";
        else if (memcmp(back, g_sent, payload_size) != 0)
            err = "the echoed payload differs from what was sent";
    }

    duct_sock_close(fd);
    return err;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) { fprintf(stderr, "tx_gather_partial: io create failed\n"); return 1; }

    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "gather-partial", .wire = wire,
        .max_response = payload_size + 64u,
        .on_frame = on_frame,
        .on_session_open = on_open, .on_conn_join = on_join,
    }) : nullptr;
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    if (!proto) {
        fprintf(stderr, "tx_gather_partial: proto create failed\n");
        duct_engine_destroy(io);
        return 1;
    }

    const char *err = nullptr;
    pthread_t th;
    bool running = false;

    if (duct_io_listen(io, "127.0.0.1", &g_port, proto) != rc_ok) {
        err = "listen failed";
        goto done;
    }
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        err = "engine thread create failed";
        goto done;
    }
    running = true;
    err = s_run_case();

done:
    if (running) {
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(proto);

    if (err) {
        fprintf(stderr, "tx_gather_partial: %s\n", err);
        return 1;
    }
    printf("tx_gather_partial: OK (a short write's remainder is the exact unsent tail)\n");
    return 0;
}
