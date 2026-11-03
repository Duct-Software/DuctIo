/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file echo_test.c
 * @brief Step 0 acceptance: declarative echo end-to-end on the rev 4.2 contract.
 *
 * accept → on_session_open → on_frame returns duct_response_t (echo) →
 * framework stages into the TX OLB → wakes the io thread → io drains to the
 * socket → client reads the echo back. Exercises the real public API surface
 * (duct_engine_launch/listen/run/stop, duct_proto_create, duct_response_echo).
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>

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
on_frame([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) { fprintf(stderr, "echo: io create failed\n"); return 1; }

    auto wire = duct_wire_create_length_prefix(0u);
    if (!wire) { fprintf(stderr, "echo: wire create failed\n"); duct_engine_destroy(io); return 1; }
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "echo", .wire = wire,
        .on_frame = on_frame, .on_session_open = on_session_open,
    });
    if (!proto) { fprintf(stderr, "echo: proto create failed\n"); duct_engine_destroy(io); duct_wire_destroy(wire); return 1; }

    if (duct_io_listen(io, "127.0.0.1", &th_port, proto) != rc_ok) {
        fprintf(stderr, "echo: listen failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(wire);
        return 1;
    }
    pthread_t th;
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        fprintf(stderr, "echo: thread create failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(wire);
        return 1;
    }

    int pass = 1;
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) { fprintf(stderr, "echo: connect failed\n"); pass = 0; goto stop; }

    /* Three round-trips on the same persistent conn. */
    static const char m1[] = "hello-ductio-echo";
    static const char m2[] = "ping";
    static const char m3[] = "still-alive-on-the-wire";
    if (th_send(fd, m1, sizeof m1 - 1u) != 0 || th_recv_eq(fd, m1, sizeof m1 - 1u) != 0
        || th_send(fd, m2, sizeof m2 - 1u) != 0 || th_recv_eq(fd, m2, sizeof m2 - 1u) != 0
        || th_send(fd, m3, sizeof m3 - 1u) != 0 || th_recv_eq(fd, m3, sizeof m3 - 1u) != 0) {
        pass = 0;
    }
    duct_sock_close(fd);

stop:
    duct_engine_stop(io);
    pthread_join(th, nullptr);

    if (duct_atomic_load(&s_open_count, acquire) != 1) {
        fprintf(stderr, "echo: on_session_open fired %d times (expected 1)\n",
                duct_atomic_load(&s_open_count, seq_cst));
        pass = 0;
    }

    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    duct_wire_destroy(wire);

    if (pass) {
        printf("echo: OK (3 echo round-trips + on_session_open fired once)\n");
        return 0;
    }
    return 1;
}
