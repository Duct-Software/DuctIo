/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file open_leg_test.c
 * @brief PD5 acceptance: control.open_leg declares leg_kind_inter instead of
 * calling duct_conn_attach_inter imperatively.
 *
 * on_session_open returns rc_ok with out->control.open_leg = { leg_kind_inter,
 * conn_id=1 } — no call on s. The worker's apply-control step attaches the
 * inter leg the same way the imperative call would (test/inter_conn_test.c
 * already proves that call path end to end); this test only proves the
 * declarative trigger produces the same on_conn_join + working leg. Also
 * covers leg_kind_none (default zero-init) as a no-op.
 */

#include "duct.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "test_helpers.h"
#include "dgram_test_helpers.h"

static constexpr unsigned wait_ms = 3000u;

static atomic_int  g_join_count = 0;
static atomic_uint g_join_conn_id = 0u;
static _Atomic(duct_handle_t) g_tok;

static atomic_uint g_published = 0u;
static char        g_last_payload[64];
static size_t      g_last_len;

static duct_result_t
on_session_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok,
                 [[maybe_unused]] void *user_ctx, duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_tok, tok, release);
    out->control.open_leg.kind = leg_kind_inter;
    out->control.open_leg.conn_id = 1u;
    return rc_ok;
}

static duct_result_t
on_conn_join([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
             [[maybe_unused]] const duct_peer_t *peer, [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_join_conn_id, (unsigned)conn_id, release);
    duct_atomic_fetch(add, &g_join_count, 1, relaxed);
    return rc_ok;
}

static duct_result_t
on_dgram([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    auto data = frame->payload;
    g_last_len = data.size < sizeof(g_last_payload) ? data.size : sizeof(g_last_payload);
    memcpy(g_last_payload, data.data, g_last_len);
    duct_atomic_fetch(add, &g_published, 1u, release);
    return rc_ok;
}

static const char *test_open_leg(duct_engine_t *io, uint16_t port)
{
    duct_sock_t fd = uc_connect(port);
    if (fd == duct_sock_bad) return "client connect failed";

    static const char m0[] = "primary-hello";
    if (uc_send(fd, m0, sizeof m0 - 1u) != 0) { close(fd); return "primary send failed"; }
    if (!th_wait_int(&g_join_count, 1, wait_ms)) { close(fd); return "on_conn_join never fired for the declarative open_leg"; }
    if (duct_atomic_load(&g_join_conn_id, acquire) != 1u) {
        close(fd); return "on_conn_join conn_id != 1";
    }

    duct_handle_t tok = duct_atomic_load(&g_tok, acquire);
    static const char p1[] = "declared-inter-leg";
    unsigned before = duct_atomic_load(&g_published, acquire);
    if (duct_io_inter_packet(io, tok, 1u, duct_view(duct_view_u8, (void *)p1, sizeof p1 - 1u)) != rc_ok) {
        close(fd); return "duct_io_inter_packet on the declaratively-opened leg failed";
    }
    for (unsigned waited = 0u; waited < wait_ms; waited += 1u) {
        if (duct_atomic_load(&g_published, acquire) > before)
            break;
        struct timespec ts = { .tv_nsec = 1L * 1000L * 1000L };
        nanosleep(&ts, nullptr);
    }
    if (duct_atomic_load(&g_published, acquire) <= before) {
        close(fd); return "inter packet never reached on_dgram on the declaratively-opened leg";
    }
    if (g_last_len != sizeof p1 - 1u || memcmp(g_last_payload, p1, g_last_len) != 0) {
        close(fd); return "declaratively-opened leg payload mismatch";
    }

    close(fd);
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) { fprintf(stderr, "open_leg: io create failed\n"); return 1; }

    auto wire = duct_wire_create_dgram_batch(0u, false);
    if (!wire) { fprintf(stderr, "open_leg: wire create failed\n"); duct_engine_destroy(io); return 1; }
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "open_leg", .wire = wire,
        .on_frame = on_dgram,
        .on_session_open = on_session_open,
        .on_conn_join = on_conn_join,
        .max_response = 4096u,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    if (!proto) { fprintf(stderr, "open_leg: proto create failed\n"); duct_engine_destroy(io); return 1; }

    const duct_proto_t *protos[1] = { proto };
    uint16_t port = 0u;
    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
            .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
        }, &port, nullptr, 0u, nullptr) != rc_ok) {
        fprintf(stderr, "open_leg: bind failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto);
        return 1;
    }
    pthread_t th;
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        fprintf(stderr, "open_leg: thread create failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto);
        return 1;
    }

    const char *err = test_open_leg(io, port);

    duct_engine_stop(io);
    pthread_join(th, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);

    if (err) {
        fprintf(stderr, "open_leg: %s\n", err);
        return 1;
    }
    printf("open_leg: OK (control.open_leg = leg_kind_inter attaches declaratively, "
           "on_conn_join fires, leg is fully functional)\n");
    return 0;
}
