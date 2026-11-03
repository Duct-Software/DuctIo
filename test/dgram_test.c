/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file dgram_test.c
 * @brief RW-DG acceptance: connected-per-peer UDP echo end-to-end.
 *
 * duct_listener_bind opens a shared classification socket; the first datagram from
 * each peer spins off a connected per-peer socket (SO_REUSEPORT demux)
 * and a session via on_session_open. on_dgram echoes
 * the payload back. Covers: single round-trip, back-to-back datagrams before
 * the first reply (record-batching through the internal length-prefix
 * framing), and two concurrent peers demultiplexed to distinct sessions.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>
#include <stdio.h>
#include <pthread.h>

#include "dgram_test_helpers.h"

/* Engine built-in, not declared in the public duct_wire.h — see
 * test/test_helpers.h's own copy of this declaration for the rationale. */
duct_wire_t *duct_wire_create_dgram_batch(size_t max_dgram, bool framed);

static uint16_t th_port = 0;
static atomic_int s_open_count = 0;

static duct_result_t
on_session_open([[maybe_unused]] duct_session_t *s,
                [[maybe_unused]] duct_handle_t tok,
                [[maybe_unused]] void *user_ctx,
                [[maybe_unused]] duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &s_open_count, 1, relaxed);
    return rc_ok;
}

static duct_result_t
on_dgram([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    duct_response_same(out, frame->payload, fl_send_copy, 0);
    return rc_ok;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) { fprintf(stderr, "dgram: io create failed\n"); return 1; }

    auto wire = duct_wire_create_dgram_batch(0u, false);
    if (!wire) { fprintf(stderr, "dgram: wire create failed\n"); duct_engine_destroy(io); return 1; }
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "udp-echo", .wire = wire,
        .on_frame = on_dgram, .on_session_open = on_session_open,
        .max_response = 65535u,
    });
    if (proto)
        proto->owned_wire = wire;
    else
        duct_wire_destroy(wire);
    if (!proto) { fprintf(stderr, "dgram: proto create failed\n"); duct_engine_destroy(io); return 1; }

    const duct_proto_t *protos[1] = { proto };
    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
            .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
        }, &th_port, nullptr, 0u, nullptr) != rc_ok) {
        fprintf(stderr, "dgram: bind failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto);
        return 1;
    }
    pthread_t th;
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        fprintf(stderr, "dgram: thread create failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto);
        return 1;
    }

    int pass = 1;
    duct_sock_t fd1 = uc_connect(th_port);
    if (fd1 == duct_sock_bad) { fprintf(stderr, "dgram: client 1 connect failed\n"); pass = 0; goto stop; }

    /* Single round-trip: spins off the per-peer socket + session. */
    static const char m1[] = "hello-ductio-dgram";
    if (uc_send(fd1, m1, sizeof m1 - 1u) != 0 || uc_recv_eq(fd1, m1, sizeof m1 - 1u) != 0) {
        fprintf(stderr, "dgram: client 1 round-trip 1 failed\n");
        pass = 0;
    }

    /* Back-to-back datagrams before either reply lands: exercises the
     * internal record-batching (both queue in one RX OLB post, both echoes
     * flush as separate TX records — see s_handle_conn_write_dgram). */
    static const char m2[] = "burst-one";
    static const char m3[] = "burst-two-longer";
    if (uc_send(fd1, m2, sizeof m2 - 1u) != 0 || uc_send(fd1, m3, sizeof m3 - 1u) != 0) {
        fprintf(stderr, "dgram: client 1 burst send failed\n");
        pass = 0;
    }
    if (uc_recv_eq(fd1, m2, sizeof m2 - 1u) != 0 || uc_recv_eq(fd1, m3, sizeof m3 - 1u) != 0) {
        fprintf(stderr, "dgram: client 1 burst echo mismatch\n");
        pass = 0;
    }

    /* Second peer: distinct per-peer socket (SO_REUSEPORT demux) + session. */
    duct_sock_t fd2 = uc_connect(th_port);
    if (fd2 == duct_sock_bad) { fprintf(stderr, "dgram: client 2 connect failed\n"); pass = 0; goto close_fd1; }

    static const char m4[] = "second-peer";
    if (uc_send(fd2, m4, sizeof m4 - 1u) != 0 || uc_recv_eq(fd2, m4, sizeof m4 - 1u) != 0) {
        fprintf(stderr, "dgram: client 2 round-trip failed\n");
        pass = 0;
    }
    /* Client 1's per-peer socket still answers independently after 2 opened. */
    static const char m5[] = "still-alive-client-1";
    if (uc_send(fd1, m5, sizeof m5 - 1u) != 0 || uc_recv_eq(fd1, m5, sizeof m5 - 1u) != 0) {
        fprintf(stderr, "dgram: client 1 post-second-peer round-trip failed\n");
        pass = 0;
    }
    close(fd2);

close_fd1:
    close(fd1);

stop:
    duct_engine_stop(io);
    pthread_join(th, nullptr);

    if (duct_atomic_load(&s_open_count, acquire) != 2) {
        fprintf(stderr, "dgram: on_session_open fired %d times (expected 2)\n",
                duct_atomic_load(&s_open_count, seq_cst));
        pass = 0;
    }

    duct_engine_destroy(io);
    duct_proto_destroy(proto);

    if (pass) {
        printf("dgram: OK (single + burst round-trips, 2 peers demuxed, on_session_open x2)\n");
        return 0;
    }
    return 1;
}
