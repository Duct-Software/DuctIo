/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file dgram_slot_ref_test.c
 * @brief A shared datagram listener echoes whole datagrams of every size class
 * from several peers at once, the datagrams reaching the worker by reference
 * to an RX slot and the replies leaving from a send slot.
 *
 * Six peers on two workers send datagrams from 8 bytes to 60,000 and read each
 * echo back byte for byte. Under @c DUCT_RUNTIME_STATS the io thread's counters
 * add that every datagram was routed by reference and none was copied: the
 * pool is far from dry here, so a copy means the by-reference path never
 * engaged.
 */

#include "duct.h"
#include "duct_wire.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#include "test_helpers.h"
#include "dgram_test_helpers.h"
#include "duct_io.h"
#include "duct_runtime_stats.h"

static constexpr unsigned k_peers  = 6u;
static constexpr unsigned k_rounds = 90u;

static constexpr size_t k_sizes[] = { 8u, 64u, 700u, 1400u, 2040u, 2100u, 9000u, 30000u, 60000u };

static atomic_int g_bad = 0;

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
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

typedef struct {
    uint16_t port;
    unsigned id;
} peer_t;

static void *s_peer(void *arg)
{
    auto p = (peer_t *)arg;
    static thread_local char out[65536], back[65536];
    duct_sock_t fd = uc_connect(p->port);
    if (fd == duct_sock_bad) {
        duct_atomic_fetch(add, &g_bad, 1, relaxed);
        return nullptr;
    }
    for (unsigned r = 0u; r < k_rounds; ++r) {
        size_t size = k_sizes[(r + p->id) % (sizeof k_sizes / sizeof *k_sizes)];
        uint32_t id = p->id, seq = r;
        memcpy(out, &id, sizeof id);
        memcpy(out + 4, &seq, sizeof seq);
        for (size_t i = 8u; i < size; ++i)
            out[i] = (char)(i * 31u + id);
        bool ok = uc_send(fd, out, size) == 0
               && uc_recv(fd, back, sizeof back) == (ssize_t)size
               && memcmp(out, back, size) == 0;
        if (!ok) {
            fprintf(stderr, "dgram_slot_ref: peer %u round %u size %zu failed\n", p->id, r, size);
            duct_atomic_fetch(add, &g_bad, 1, relaxed);
            break;
        }
    }
    close(fd);
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 2 });
    if (!io) { fprintf(stderr, "dgram_slot_ref: io create failed\n"); return 1; }

    auto wire = duct_wire_create_dgram_batch(0u, false);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "dgram-slot-ref", .wire = wire, .on_frame = on_frame,
        .preparse = preparse, .preparse_mode = resolve_sync,
        .max_response = 60000u, .flags = fl_proto_dgram_shared,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    if (!proto) {
        fprintf(stderr, "dgram_slot_ref: proto create failed\n");
        duct_engine_destroy(io);
        return 1;
    }

    const duct_proto_t *protos[1] = { proto };
    uint16_t port = 0u;
    bool ok = duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
                  .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
              }, &port, nullptr, 0u, nullptr) == rc_ok;
    if (!ok)
        fprintf(stderr, "dgram_slot_ref: bind failed\n");

    pthread_t srv;
    if (ok && pthread_create(&srv, nullptr, th_run, io) != 0) {
        fprintf(stderr, "dgram_slot_ref: thread create failed\n");
        ok = false;
    }
    if (ok) {
        pthread_t th[k_peers];
        peer_t peers[k_peers];
        for (unsigned i = 0u; i < k_peers; ++i) {
            peers[i] = (peer_t){ .port = port, .id = i };
            if (pthread_create(&th[i], nullptr, s_peer, &peers[i]) != 0)
                duct_atomic_fetch(add, &g_bad, 1, relaxed);
        }
        for (unsigned i = 0u; i < k_peers; ++i)
            pthread_join(th[i], nullptr);
        duct_engine_stop(io);
        pthread_join(srv, nullptr);
    }
    ok = ok && duct_atomic_load(&g_bad, relaxed) == 0;

#if DUCT_RUNTIME_STATS
    auto st = duct_io_rtstats(0u);
    uint64_t routed = st ? duct_atomic_load(&st->dgram_rx_slot_route, relaxed) : 0u,
             copied = st ? duct_atomic_load(&st->dgram_rx_slot_copy, relaxed) : 0u;
    printf("dgram_slot_ref: routed %llu copied %llu\n", (unsigned long long)routed,
           (unsigned long long)copied);
    ok = ok && routed + copied >= (uint64_t)k_peers * k_rounds;
    if (duct_dgram_rx_slots >= 64u)
        ok = ok && routed >= (uint64_t)k_peers * k_rounds && copied == 0u;
#endif

    duct_engine_destroy(io);
    duct_proto_destroy(proto);

    if (ok)
        printf("dgram_slot_ref: OK (%u peers, %u rounds, every size class echoed whole)\n",
               k_peers, k_rounds);
    else
        fprintf(stderr, "dgram_slot_ref: FAILED\n");
    return ok ? 0 : 1;
}
