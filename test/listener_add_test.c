/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file listener_add_test.c
 * @brief Acceptance test: @ref duct_listener_bind while the engine is
 * already running. Starts with zero listeners, binds one at runtime,
 * confirms it serves, binds a second one and confirms both serve, then
 * mid-life @ref duct_listener_close's the first and confirms the second
 * keeps serving. Exercises the WSAPoll/IOCP races (epoll was
 * never at risk — epoll_ctl is kernel-synchronized regardless of caller
 * thread), so this is most meaningful on the two Windows presets.
 */

#define TH_CONNECT_RETRY_MS 500u

#include "duct.h"
#include "test_helpers.h"

#include <stdio.h>
#include <string.h>

static duct_result_t
on_frame_echo([[maybe_unused]] duct_session_t *s,
              [[maybe_unused]] duct_conn_id_t conn_id,
              const duct_frame_t *frame,
              duct_response_t *out,
              [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

static int s_echo_roundtrip(uint16_t port, const char *tag)
{
    duct_sock_t fd = th_connect(port);
    if (fd == duct_sock_bad) {
        fprintf(stderr, "listener_add: %s: connect failed\n", tag);
        return -1;
    }
    size_t len = strlen(tag);
    int rc = th_send(fd, tag, len) != 0 || th_recv_eq(fd, tag, len) != 0 ? -1 : 0;
    if (rc != 0)
        fprintf(stderr, "listener_add: %s: round-trip failed\n", tag);
    duct_sock_close(fd);
    return rc;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    int pass = 1;

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) { fprintf(stderr, "listener_add: io create failed\n"); return 1; }

    auto wire = duct_wire_create_length_prefix(0u);
    if (!wire) { fprintf(stderr, "listener_add: wire create failed\n"); duct_engine_destroy(io); return 1; }
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "listener-add", .wire = wire, .on_frame = on_frame_echo,
    });
    if (!proto) {
        fprintf(stderr, "listener_add: proto create failed\n");
        duct_engine_destroy(io); duct_wire_destroy(wire);
        return 1;
    }

    /* duct_engine_launch above already confirmed io/worker threads running
     * before returning io, so every duct_listener_bind below unconditionally
     * takes the runtime post+wait path (T36), not the pre-start direct call
     * every other listener test exercises — no timing race to bridge here,
     * unlike the separate blocking start call this test pattern needed
     * before T35's launch/wait consolidation. th_run now just blocks in
     * duct_engine_wait until this test's own duct_engine_stop below. */
    pthread_t th;
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        fprintf(stderr, "listener_add: thread create failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(wire);
        return 1;
    }

    const duct_proto_t *protos[1] = { proto };
    uint16_t port_a = 0u, port_b = 0u;
    duct_sock_t fds_a[4] = {}, fds_b[4] = {};
    unsigned n_a = 0u, n_b = 0u;

    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_stream,
            .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
        }, &port_a, fds_a, 4u, &n_a) != rc_ok || n_a != 1u) {
        fprintf(stderr, "listener_add: runtime bind #1 failed\n");
        pass = 0;
        goto stop;
    }

    if (s_echo_roundtrip(port_a, "listener-a-solo") != 0)
        pass = 0;

    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_stream,
            .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
        }, &port_b, fds_b, 4u, &n_b) != rc_ok || n_b != 1u) {
        fprintf(stderr, "listener_add: runtime bind #2 failed\n");
        pass = 0;
        goto stop;
    }

    if (s_echo_roundtrip(port_a, "listener-a-both") != 0)
        pass = 0;
    if (s_echo_roundtrip(port_b, "listener-b-both") != 0)
        pass = 0;

    if (duct_listener_close(io, fds_a[0]) != rc_ok) {
        fprintf(stderr, "listener_add: mid-life close of listener a failed\n");
        pass = 0;
    }

    if (s_echo_roundtrip(port_b, "listener-b-after-a-closed") != 0)
        pass = 0;

    duct_listener_close(io, fds_b[0]);

    /* Registry cap: duct_runtime_max_listeners live registrations per
     * engine, host-side (previously unenforced on epoll/iocp). Both earlier
     * listeners are closed by this point, so the registry starts empty.
     * Fill every slot, confirm one more is rejected with rc_no_memory,
     * release them all. */
    duct_sock_t cap_fds[duct_runtime_max_listeners];
    unsigned n_cap = 0u;
    for (; n_cap < duct_runtime_max_listeners; ++n_cap) {
        uint16_t p = 0u;
        duct_sock_t f = duct_sock_bad;
        unsigned n = 0u;
        if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_stream,
                .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
            }, &p, &f, 1u, &n) != rc_ok || n != 1u)
            break;
        cap_fds[n_cap] = f;
    }
    if (n_cap != duct_runtime_max_listeners) {
        fprintf(stderr, "listener_add: registry cap: only filled %u/%u slots\n", n_cap, duct_runtime_max_listeners);
        pass = 0;
    } else {
        uint16_t p = 0u;
        duct_sock_t f = duct_sock_bad;
        unsigned n = 0u;
        if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_stream,
                .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
            }, &p, &f, 1u, &n) != rc_no_memory) {
            fprintf(stderr, "listener_add: registry cap: bind past capacity did not return rc_no_memory\n");
            pass = 0;
        }
    }
    for (unsigned i = 0u; i < n_cap; ++i)
        duct_listener_close(io, cap_fds[i]);

stop:
    duct_engine_stop(io);
    pthread_join(th, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    duct_wire_destroy(wire);

    if (pass)
        printf("listener_add: OK (runtime bind while running; second listener unaffected by first's mid-life close)\n");
    else
        fprintf(stderr, "listener_add: FAILED\n");
    return pass ? 0 : 1;
}
