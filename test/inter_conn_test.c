/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file inter_conn_test.c
 * @brief ST-AI/ST-IB acceptance: push-mode inter conn ingress + egress end to end.
 *
 * A UDP session's on_session_open declares an inter leg at conn_id=1 via
 * out->control.open_leg = { leg_kind_inter, 1 } (PD4/PD5 — the imperative
 * duct_conn_attach_inter is internal now, see src/include/duct_session.h);
 * on_conn_join confirms it. The host thread then
 * drives ingress purely through duct_io_inter_packet / duct_io_inter_batch
 * (no fd, no reactor poll on that leg, no I/O thread on the path — Stage 0.5
 * pushes straight onto the conn's own dedicated lane) and asserts:
 * single-packet handoff, multi-packet batch handoff with in-order delivery
 * and on_tunnel_resume firing once the worker drains the lane, rc_defer once
 * the lane fills up (backpressure, not a single-slot collision), rc_invalid_arg
 * on a non-inter conn_id, and rc_closed once the session has closed. sc_egress
 * covers the other direction (TX egress): on_dgram echoes
 * a marker payload back on the same (inter) conn_id, and on_packet_out must
 * fire with that exact payload/conn_id/token instead of anything reaching a
 * TX OLB/fd.
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

static uint32_t s_tok_gen(duct_handle_t w)
{
    return (uint32_t)(w >> 32u);
}

typedef struct {
    duct_conn_id_t   conn_id;
    duct_stream_id_t stream_id;
    size_t           len;
    char             data[64];
} record_t;

static constexpr unsigned max_records = 32u;
static record_t g_records[max_records];
static atomic_uint g_next_idx = 0u;
static atomic_uint g_published = 0u;

static atomic_int  g_open_count = 0;
static atomic_int  g_join_count = 0;
static atomic_uint g_join_conn_id = 0u;
static atomic_int  g_close_count = 0;
static atomic_int  g_resume_count = 0;
static _Atomic(duct_handle_t) g_tok;

static const char s_close_sentinel[] = "close-me";
static const char s_egress_marker[]  = "egress-echo-me";

typedef struct {
    duct_handle_t h;
    duct_conn_id_t       conn_id;
    size_t               len;
    char                 data[64];
} packet_out_record_t;

static packet_out_record_t g_packet_out;
static atomic_int          g_packet_out_count = 0;

static duct_result_t
on_session_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok,
                 [[maybe_unused]] void *user_ctx, duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_tok, tok, release);
    duct_atomic_fetch(add, &g_open_count, 1, relaxed);
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

static void
on_session_close([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_close_reason_t reason,
                  [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_close_count, 1, relaxed);
}

static duct_result_t
on_dgram([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id, const duct_frame_t *frame,
         duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    auto data = frame->payload;
    if (data.size == sizeof s_close_sentinel - 1u
        && memcmp(data.data, s_close_sentinel, data.size) == 0) {
        duct_response_close_session(out, close_normal);
        return rc_ok;
    }
    if (data.size == sizeof s_egress_marker - 1u
        && memcmp(data.data, s_egress_marker, data.size) == 0) {
        /* conn_id_same/stream_id_same with no cfg->route resolves to this
         * frame's own in_conn — bounces straight back onto the inter leg,
         * exercising s_commit_response's xport_inter branch. */
        duct_response_echo(out, frame);
        return rc_ok;
    }
    unsigned i = duct_atomic_load(&g_next_idx, relaxed);
    if (i < max_records) {
        g_records[i].conn_id = conn_id;
        g_records[i].stream_id = frame->stream_id;
        g_records[i].len = data.size < sizeof(g_records[i].data) ? data.size : sizeof(g_records[i].data);
        memcpy(g_records[i].data, data.data, g_records[i].len);
    }
    duct_atomic_store(&g_next_idx, i + 1u, relaxed);
    duct_atomic_store(&g_published, i + 1u, release);
    return rc_ok;
}

static void s_on_host(void (*fn)(void *ctx), void *ctx, [[maybe_unused]] void *queue_ctx)
{
    fn(ctx);
}

static void s_on_packet_out([[maybe_unused]] void *app_ctx, duct_handle_t tok,
                            duct_conn_id_t conn_id, duct_view_u8 pkt)
{
    g_packet_out.h = tok;
    g_packet_out.conn_id = conn_id;
    g_packet_out.len = pkt.size < sizeof(g_packet_out.data) ? pkt.size : sizeof(g_packet_out.data);
    memcpy(g_packet_out.data, pkt.data, g_packet_out.len);
    duct_atomic_fetch(add, &g_packet_out_count, 1, release);
}

static void s_on_tunnel_resume([[maybe_unused]] void *app_ctx)
{
    duct_atomic_fetch(add, &g_resume_count, 1, relaxed);
}

static bool s_wait_uint(atomic_uint *p, unsigned target, unsigned timeout_ms)
{
    for (unsigned waited = 0u; waited < timeout_ms; waited += 1u) {
        if (duct_atomic_load(p, acquire) >= target)
            return true;
        struct timespec ts = { .tv_nsec = 1L * 1000L * 1000L };
        nanosleep(&ts, nullptr);
    }
    return duct_atomic_load(p, acquire) >= target;
}

/** @brief Single-packet handoff via duct_io_inter_packet. */
static const char *sc_packet(duct_engine_t *io, duct_handle_t tok)
{
    static const char p1[] = "inter-packet-one";
    unsigned before = duct_atomic_load(&g_published, acquire);
    if (duct_io_inter_packet(io, tok, 1u, duct_view(duct_view_u8, (void *)p1, sizeof p1 - 1u)) != rc_ok)
        return "duct_io_inter_packet failed";
    if (!s_wait_uint(&g_published, before + 1u, wait_ms))
        return "inter packet never reached on_dgram";
    auto rec = &g_records[before];
    if (rec->conn_id != 1u || rec->len != sizeof p1 - 1u || memcmp(rec->data, p1, rec->len) != 0)
        return "inter packet payload/conn_id mismatch";
    return nullptr;
}

/** @brief Multi-packet handoff via duct_io_inter_batch: in-order delivery
 *  and on_tunnel_resume firing once the worker drains the lane. Handoff is
 *  synchronous — every packet is copied onto the lane before the call
 *  returns, no release callback to wait for. */
static const char *sc_batch(duct_engine_t *io, duct_handle_t tok)
{
    static const char b0[] = "batch-0", b1[] = "batch-1-longer", b2[] = "batch-2";
    alignas(8) char buf[duct_inter_batch_bytes(3u)];
    auto batch = (duct_inter_batch_t *)buf;
    batch->n = 3u;
    *duct_inter_batch_pkt(batch, 0u) = (duct_inter_pkt_t){
        .payload = { .data = (void *)b0, .size = sizeof b0 - 1u },
        .stream_id = duct_stream_id_default, .flags = fl_frame_none,
    };
    *duct_inter_batch_pkt(batch, 1u) = (duct_inter_pkt_t){
        .payload = { .data = (void *)b1, .size = sizeof b1 - 1u },
        .stream_id = duct_stream_id_default, .flags = fl_frame_none,
    };
    *duct_inter_batch_pkt(batch, 2u) = (duct_inter_pkt_t){
        .payload = { .data = (void *)b2, .size = sizeof b2 - 1u },
        .stream_id = duct_stream_id_default, .flags = fl_frame_none,
    };

    unsigned before = duct_atomic_load(&g_published, acquire);
    int resume_before = duct_atomic_load(&g_resume_count, acquire);
    if (duct_io_inter_batch(io, tok, 1u, batch) != rc_ok)
        return "duct_io_inter_batch failed";
    if (!s_wait_uint(&g_published, before + 3u, wait_ms))
        return "batch packets never reached on_dgram";
    if (duct_atomic_load(&g_resume_count, acquire) <= resume_before)
        return "on_tunnel_resume did not fire after the batch drained";
    if (g_records[before].conn_id != 1u || memcmp(g_records[before].data, b0, sizeof b0 - 1u) != 0
        || g_records[before + 1u].conn_id != 1u || memcmp(g_records[before + 1u].data, b1, sizeof b1 - 1u) != 0
        || g_records[before + 2u].conn_id != 1u || memcmp(g_records[before + 2u].data, b2, sizeof b2 - 1u) != 0)
        return "batch payload order/content mismatch";
    return nullptr;
}

/** @brief Multiplexing: host-declared stream_id per pushed packet dispatches
 *  straight to on_frame (no wire parse) and routes independently — new
 *  coverage this lane redesign adds; sc_batch above only exercises the
 *  opaque/default-stream_id case. */
static const char *sc_batch_multiplex(duct_engine_t *io, duct_handle_t tok)
{
    static const char m0[] = "mux-a", m1[] = "mux-b";
    alignas(8) char buf[duct_inter_batch_bytes(2u)];
    auto batch = (duct_inter_batch_t *)buf;
    batch->n = 2u;
    *duct_inter_batch_pkt(batch, 0u) = (duct_inter_pkt_t){
        .payload = { .data = (void *)m0, .size = sizeof m0 - 1u },
        .stream_id = 7u, .flags = fl_frame_none,
    };
    *duct_inter_batch_pkt(batch, 1u) = (duct_inter_pkt_t){
        .payload = { .data = (void *)m1, .size = sizeof m1 - 1u },
        .stream_id = 9u, .flags = fl_frame_none,
    };

    unsigned before = duct_atomic_load(&g_published, acquire);
    if (duct_io_inter_batch(io, tok, 1u, batch) != rc_ok)
        return "duct_io_inter_batch (multiplex) failed";
    if (!s_wait_uint(&g_published, before + 2u, wait_ms))
        return "multiplexed batch packets never reached on_dgram";
    if (g_records[before].stream_id != 7u || memcmp(g_records[before].data, m0, sizeof m0 - 1u) != 0
        || g_records[before + 1u].stream_id != 9u || memcmp(g_records[before + 1u].data, m1, sizeof m1 - 1u) != 0)
        return "multiplexed stream_id/payload mismatch";
    return nullptr;
}

/** @brief rc_defer: the dedicated lane is the backpressure signal now, not a
 *  single-slot CAS collision — push fast enough to fill it, then confirm the
 *  worker drains it and the lane accepts pushes again. */
static const char *sc_defer_race(duct_engine_t *io, duct_handle_t tok)
{
    static const char pkt[] = "fill-pkt";
    bool saw_defer = false;
    for (unsigned i = 0u; i < 200000u; ++i) {
        auto rc = duct_io_inter_packet(io, tok, 1u,
            duct_view(duct_view_u8, (void *)pkt, sizeof pkt - 1u));
        if (rc == rc_defer) {
            saw_defer = true;
            break;
        }
        if (rc != rc_ok)
            return "unexpected rc while filling the inter lane";
    }
    if (!saw_defer)
        return "never observed rc_defer while filling the inter lane";
    for (unsigned waited = 0u; waited < wait_ms; ++waited) {
        if (duct_io_inter_packet(io, tok, 1u,
                duct_view(duct_view_u8, (void *)pkt, sizeof pkt - 1u)) == rc_ok)
            return nullptr;
        struct timespec ts = { .tv_nsec = 1L * 1000L * 1000L };
        nanosleep(&ts, nullptr);
    }
    return "inter lane never accepted a push again after draining";
}

/** @brief TX egress (TX egress): a response routed back
 *  onto the inter leg must reach on_packet_out with the exact payload/
 *  conn_id/token, never the TX OLB (there is no fd to write to). */
static const char *sc_egress(duct_engine_t *io, duct_handle_t tok)
{
    int before = duct_atomic_load(&g_packet_out_count, acquire);
    if (duct_io_inter_packet(io, tok, 1u,
            duct_view(duct_view_u8, (void *)s_egress_marker, sizeof s_egress_marker - 1u)) != rc_ok)
        return "duct_io_inter_packet (egress marker) failed";
    if (!th_wait_int(&g_packet_out_count, before + 1, wait_ms))
        return "on_packet_out never fired for the echoed inter response";
    if (g_packet_out.conn_id != 1u)
        return "on_packet_out conn_id != 1";
    if ((uint32_t)g_packet_out.h != (uint32_t)tok
        || s_tok_gen(g_packet_out.h) != s_tok_gen(tok))
        return "on_packet_out token mismatch";
    if (g_packet_out.len != sizeof s_egress_marker - 1u
        || memcmp(g_packet_out.data, s_egress_marker, g_packet_out.len) != 0)
        return "on_packet_out payload mismatch";
    return nullptr;
}

/** @brief rc_invalid_arg: conn_id 0 is the poll leg, not an inter conn. */
static const char *sc_wrong_conn(duct_engine_t *io, duct_handle_t tok)
{
    static const char p[] = "x";
    auto rc = duct_io_inter_packet(io, tok, 0u, duct_view(duct_view_u8, (void *)p, sizeof p - 1u));
    return rc == rc_invalid_arg ? nullptr : "push to the poll leg did not return rc_invalid_arg";
}

/** @brief rc_closed: push after the session has fully closed. */
static const char *sc_stale_token(duct_sock_t fd, duct_engine_t *io, duct_handle_t tok)
{
    static const char p[] = "x";
    if (uc_send(fd, s_close_sentinel, sizeof s_close_sentinel - 1u) != 0)
        return "close sentinel send failed";
    if (!th_wait_int(&g_close_count, 1, wait_ms))
        return "on_session_close did not fire";
    auto rc = duct_io_inter_packet(io, tok, 1u, duct_view(duct_view_u8, (void *)p, sizeof p - 1u));
    return rc == rc_closed ? nullptr : "push after close did not return rc_closed";
}

static const char *test_inter_conn(duct_engine_t *io, uint16_t port)
{
    duct_sock_t fd = uc_connect(port);
    if (fd == duct_sock_bad) return "client connect failed";

    static const char m0[] = "primary-hello";
    if (uc_send(fd, m0, sizeof m0 - 1u) != 0) { close(fd); return "primary send failed"; }
    if (!s_wait_uint(&g_published, 1u, wait_ms)) { close(fd); return "primary dgram not observed"; }
    if (!th_wait_int(&g_join_count, 1, wait_ms)) { close(fd); return "on_conn_join did not fire for the inter leg"; }
    if (duct_atomic_load(&g_join_conn_id, acquire) != 1u) {
        close(fd); return "on_conn_join conn_id != 1";
    }

    duct_handle_t tok = duct_atomic_load(&g_tok, acquire);
    const char *err = sc_packet(io, tok);
    if (!err) err = sc_batch(io, tok);
    if (!err) err = sc_batch_multiplex(io, tok);
    if (!err) err = sc_egress(io, tok);
    if (!err) err = sc_defer_race(io, tok);
    if (!err) err = sc_wrong_conn(io, tok);
    if (!err) err = sc_stale_token(fd, io, tok);
    if (!err && duct_atomic_load(&g_open_count, acquire) != 1)
        err = "on_session_open fired more than once";

    close(fd);
    return err;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){
        .io_threads = 1, .workers = 1,
        .host = {
            .on_packet_out = s_on_packet_out,
            .run = s_on_host,
            .on_inter_resume = s_on_tunnel_resume,
        },
    });
    if (!io) { fprintf(stderr, "inter_conn: io create failed\n"); return 1; }

    auto wire = duct_wire_create_dgram_batch(0u, false);
    if (!wire) { fprintf(stderr, "inter_conn: wire create failed\n"); duct_engine_destroy(io); return 1; }
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "inter", .wire = wire,
        .on_frame = on_dgram,
        .on_session_open = on_session_open,
        .on_conn_join = on_conn_join,
        .on_session_close = on_session_close,
        .max_response = 4096u,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    if (!proto) { fprintf(stderr, "inter_conn: proto create failed\n"); duct_engine_destroy(io); return 1; }

    const duct_proto_t *protos[1] = { proto };
    uint16_t port = 0u;
    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
            .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
        }, &port, nullptr, 0u, nullptr) != rc_ok) {
        fprintf(stderr, "inter_conn: bind failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto);
        return 1;
    }
    pthread_t th;
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        fprintf(stderr, "inter_conn: thread create failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto);
        return 1;
    }

    const char *err = test_inter_conn(io, port);

    duct_engine_stop(io);
    pthread_join(th, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);

    if (err) {
        fprintf(stderr, "inter_conn: %s\n", err);
        return 1;
    }
    printf("inter_conn: OK (attach_inter join, packet + batch ingress, "
           "multiplexed stream_id routing, on_tunnel_resume, TX egress via "
           "on_packet_out, rc_defer lane-full backpressure, rc_invalid_arg, "
           "rc_closed)\n");
    return 0;
}
