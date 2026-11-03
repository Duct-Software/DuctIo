/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file dgram_shared_large_records_test.c
 * @brief Records near the client's RX ring capacity cross from an
 * x_udp_shared leg to an x_udp_peer leg whole, every one of them.
 *
 * One engine, two sessions: a server session holds the x_udp_shared leg
 * (conn 0, real network) and an inter leg (conn 1, host push) whose frames it
 * echoes onto conn 0; a client session dials in via
 * duct_io_connect(x_udp_peer). The host keeps at most @c window records in
 * flight past what the client took, so the client socket's receive buffer
 * never overflows and the kernel drops nothing: every record must arrive, at
 * its full length.
 *
 * record_size (39000 bytes) stays close to the client's own RX ring capacity
 * on purpose: a read offered less room than a whole datagram truncates it, so
 * a record lands whole only where the io thread's reserve waits for room
 * instead of reading short.
 */

#include "duct.h"
#include "duct_wire.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#include "test_helpers.h"

/* Engine built-in, not declared in the public duct_wire.h — see
 * test_helpers.h's own copy of this declaration for the rationale. */
duct_wire_t *duct_wire_create_dgram_batch(size_t max_dgram, bool framed);

static constexpr size_t   record_size   = 39000u;
static constexpr unsigned record_count  = 50u;
static constexpr size_t   max_response  = 40000u;
/** @brief Records the host keeps in flight past what the client took.
 *  Their bytes sit well inside any receive buffer the client socket gets, the
 *  208 KB an unprivileged Linux host caps it at among them. */
static constexpr unsigned window        = 4u;
/** @brief Longest wait for the client to take a record, ms. */
static constexpr unsigned wait_ms       = 3000u;

static _Atomic(duct_handle_t) g_srv_tok;
static atomic_int  g_srv_open    = 0;
static atomic_int  g_srv_join    = 0;
static atomic_int  g_cli_open    = 0;
static atomic_uint g_cli_recv    = 0u;
static atomic_uint g_cli_bad_len = 0u;

static duct_engine_t *g_engine;

/** @brief Wait up to @c wait_ms for the client to have taken @p n records. */
static bool s_wait_recv(unsigned n)
{
    for (unsigned waited = 0u; waited < wait_ms; waited += 5u) {
        if (duct_atomic_load(&g_cli_recv, acquire) >= n)
            return true;
        th_sleep_ms(5u);
    }
    return duct_atomic_load(&g_cli_recv, acquire) >= n;
}

static duct_result_t
srv_on_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok,
           [[maybe_unused]] void *user_ctx, duct_response_t *out,
           [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_srv_tok, tok, release);
    duct_atomic_fetch(add, &g_srv_open, 1, release);
    out->control.open_leg.kind = leg_kind_inter;
    out->control.open_leg.conn_id = 1u;
    return rc_ok;
}

static duct_result_t
srv_on_conn_join([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                 [[maybe_unused]] const duct_peer_t *peer, [[maybe_unused]] duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_srv_join, 1, release);
    return rc_ok;
}

static _Thread_local uint8_t s_srv_out_buf[record_size];

/** @brief Inter-leg packet (conn_id 1) echoes on the real x_udp_shared leg
 *  (conn_id 0). */
static duct_result_t
srv_on_frame([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
            const duct_frame_t *frame, duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    if (conn_id != 1u)
        return rc_drop;
    memcpy(s_srv_out_buf, frame->payload.data, frame->payload.size);
    *out = (duct_response_t){
        .payload = { .data = s_srv_out_buf, .size = frame->payload.size },
        .flags = fl_send_copy,
        .conn_id = 0u,
        .stream_id = duct_stream_id_same,
        .control.stream_op_conn_id = duct_conn_id_same,
    };
    return rc_ok;
}

static duct_result_t
cli_on_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
           [[maybe_unused]] void *user_ctx, duct_response_t *out,
           [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_cli_open, 1, release);
    static const uint8_t hello[4] = { 'h', 'i', 0, 0 };
    duct_response_same(out, duct_view(duct_view_u8, (void *)hello, sizeof hello),
                       fl_send_static, 0);
    return rc_ok;
}

static duct_result_t
cli_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
            const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    if (frame->payload.size != record_size)
        duct_atomic_fetch(add, &g_cli_bad_len, 1, relaxed);
    duct_atomic_fetch(add, &g_cli_recv, 1, release);
    return rc_ok;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    g_engine = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!g_engine) { fprintf(stderr, "dgram_tx_retry_wake: engine create failed\n"); return 1; }

    auto srv_wire = duct_wire_create_dgram_batch(0u, false);
    auto cli_wire = duct_wire_create_dgram_batch(0u, false);
    auto srv = duct_proto_create(&(duct_proto_cfg_t){
        .name = "large-records-srv", .wire = srv_wire,
        .on_frame = srv_on_frame, .on_session_open = srv_on_open,
        .on_conn_join = srv_on_conn_join,
        .flags = fl_proto_dgram_shared, .max_response = max_response,
    });
    auto cli = duct_proto_create(&(duct_proto_cfg_t){
        .name = "large-records-cli", .wire = cli_wire,
        .on_frame = cli_on_frame, .on_session_open = cli_on_open,
    });
    if (srv) srv->owned_wire = srv_wire; else duct_wire_destroy(srv_wire);
    if (cli) cli->owned_wire = cli_wire; else duct_wire_destroy(cli_wire);
    if (!srv || !cli) {
        fprintf(stderr, "dgram_shared_large_records: proto create failed\n");
        duct_proto_destroy(srv); duct_proto_destroy(cli); duct_engine_destroy(g_engine);
        return 1;
    }

    uint16_t port = 0u;
    bool ok = duct_listener_bind(g_engine, &(duct_listener_cfg_t){ .kind = listener_dgram,
                  .addr = "127.0.0.1", .n_protos = 1, .protos = (const duct_proto_t *[]){ srv },
              }, &port, nullptr, 0u, nullptr) == rc_ok;

    char addr[32];
    snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)port);
    for (unsigned waited = 0u; ok && waited < 3000u; waited += 5u) {
        auto rc = duct_io_connect(g_engine, addr, cli, nullptr, x_udp_peer);
        if (rc != rc_invalid_order) { ok = rc == rc_ok; break; }
        th_sleep_ms(5u);
    }
    ok = ok && th_wait_int(&g_srv_join, 1, 3000u) && th_wait_int(&g_cli_open, 1, 3000u);

    if (ok) {
        alignas(8) char buf[duct_inter_batch_bytes(1u)];
        auto batch = (duct_inter_batch_t *)buf;
        auto payload = (uint8_t *)malloc(record_size);
        memset(payload, 0xAB, record_size);
        batch->n = 1u;
        auto srv_tok = duct_atomic_load(&g_srv_tok, acquire);
        for (unsigned i = 0u; i < record_count && ok; ++i) {
            if (i >= window && !s_wait_recv(i - window + 1u)) {
                fprintf(stderr, "dgram_shared_large_records: record %u never arrived\n",
                        i - window);
                ok = false;
                break;
            }
            *duct_inter_batch_pkt(batch, 0u) = (duct_inter_pkt_t){
                .payload = { .data = payload, .size = record_size },
                .stream_id = duct_stream_id_default, .flags = fl_frame_none,
            };
            duct_result_t irc;
            unsigned waited = 0u;
            do {
                irc = duct_io_inter_batch(g_engine, srv_tok, 1u, batch);
                if (irc == rc_defer) {
                    /* A fixed busy-spin count may expire within one Windows
                     * scheduling quantum, before the consumer has run. */
                    if (waited++ >= wait_ms) {
                        fprintf(stderr, "dgram_shared_large_records: ingress stayed full at record %u\n", i);
                        ok = false;
                        break;
                    }
                    th_sleep_ms(1u);
                }
            } while (irc == rc_defer);
            if (irc != rc_ok && irc != rc_defer) {
                fprintf(stderr, "dgram_shared_large_records: inter_batch rc=%d at i=%u\n",
                        (int)irc, i);
                ok = false;
            }
        }
        free(payload);
        ok = ok && s_wait_recv(record_count);
    } else
        fprintf(stderr, "dgram_shared_large_records: setup failed (bind/connect/join)\n");

    /* No corrupted record, ever — the actual correctness property. A
     * record arriving at the wrong length would mean rc_drop's own
     * detection (MSG_TRUNC's real size vs dst.size) failed. */
    if (duct_atomic_load(&g_cli_bad_len, relaxed) != 0u) {
        fprintf(stderr, "dgram_shared_large_records: client received a mis-sized record\n");
        ok = false;
    }
    unsigned recv = duct_atomic_load(&g_cli_recv, acquire);
    if (recv != record_count) {
        fprintf(stderr, "dgram_shared_large_records: recv=%u of %u\n", recv, record_count);
        ok = false;
    }

    duct_engine_destroy(g_engine);
    duct_proto_destroy(srv);
    duct_proto_destroy(cli);

    if (ok)
        printf("dgram_shared_large_records: OK (%u/%u records, %zu bytes each, none corrupted)\n",
               recv, record_count, record_size);
    return ok ? 0 : 1;
}
