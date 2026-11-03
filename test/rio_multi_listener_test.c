/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file rio_multi_listener_test.c
 * @brief Two x_udp_shared listeners sharing one io thread, both RIO-active
 * where the platform allows it.
 *
 * The regression scenario for the cumulative RIOCreateRequestQueue
 * admission constraint duct_rio_cq_ensure guards: a second RIO-active
 * listener's own RIOCreateRequestQueue can fail WSAENOBUFS once the first
 * has already spent the completion queue's admission budget. Silently
 * degrades to an ordinary two-listener bind, unexercised, wherever RIO is
 * unavailable or unwired into x_udp_shared -- no explicit check gates
 * this file the way rio_probe.c gates its own.
 */

#include "duct.h"
#include "duct_wire.h"

#include <stdio.h>
#include <pthread.h>
#include <string.h>

#include "test_helpers.h"
#include "dgram_test_helpers.h"

static duct_result_t
on_dgram([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame, duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_response_same(out, frame->payload, fl_send_copy, 0);
    return rc_ok;
}

static duct_resolve_disposition_t
preparse([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer,
         [[maybe_unused]] duct_view_u8 peek, [[maybe_unused]] duct_handle_t *out_tok,
         [[maybe_unused]] duct_conn_id_t *out_conn_id, [[maybe_unused]] void **out_user_ctx,
         [[maybe_unused]] size_t *out_lead)
{
    return resolve_new;
}

static bool s_bind(duct_engine_t *io, const duct_proto_t **protos, uint16_t *out_port, const char *tag)
{
    bool ok = duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
                  .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
              }, out_port, nullptr, 0u, nullptr) == rc_ok;
    if (!ok)
        fprintf(stderr, "rio_multi_listener: %s bind failed\n", tag);
    return ok;
}

static bool s_echo(uint16_t port, const char *tag)
{
    duct_sock_t fd = uc_connect(port);
    if (fd == duct_sock_bad) {
        fprintf(stderr, "rio_multi_listener: %s connect failed\n", tag);
        return false;
    }
    size_t len = strlen(tag);
    bool ok = uc_send(fd, tag, len) == 0 && uc_recv_eq(fd, tag, len) == 0;
    if (!ok)
        fprintf(stderr, "rio_multi_listener: %s echo failed\n", tag);
    close(fd);
    return ok;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    int pass = 1;

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) { fprintf(stderr, "rio_multi_listener: io create failed\n"); return 1; }

    auto wire = duct_wire_create_dgram_batch(0u, false);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "rio-multi-listener", .wire = wire, .on_frame = on_dgram,
        .preparse = preparse, .preparse_mode = resolve_sync,
        .max_response = 4096u, .flags = fl_proto_dgram_shared,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    if (!proto) {
        fprintf(stderr, "rio_multi_listener: proto create failed\n");
        duct_engine_destroy(io);
        return 1;
    }

    const duct_proto_t *protos[1] = { proto };
    uint16_t port_a = 0u, port_b = 0u;
    bool bound_a = s_bind(io, protos, &port_a, "listener-a");
    bool bound_b = s_bind(io, protos, &port_b, "listener-b");
    pass = bound_a && bound_b;

    if (pass) {
        pthread_t th;
        if (pthread_create(&th, nullptr, th_run, io) != 0) {
            fprintf(stderr, "rio_multi_listener: thread create failed\n");
            pass = 0;
        } else {
            if (!s_echo(port_a, "listener-a-payload"))
                pass = 0;
            if (!s_echo(port_b, "listener-b-payload"))
                pass = 0;
            duct_engine_stop(io);
            pthread_join(th, nullptr);
        }
    }

    duct_engine_destroy(io);
    duct_proto_destroy(proto);

    if (pass)
        printf("rio_multi_listener: OK (two x_udp_shared listeners on one io thread both bind and serve)\n");
    else
        fprintf(stderr, "rio_multi_listener: FAILED\n");
    return pass ? 0 : 1;
}
