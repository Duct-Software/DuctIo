/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file mux_dgram_test.c
 * @brief Multiplexed stream handlers over datagram-classified transports,
 * driven through the real io/worker stack (not the s_dispatch_frame unit
 * harness in handler_dispatch_test.c).
 *
 * The handler-dispatch block in s_dispatch_frame gates purely on
 * frame.stream_id != 0 and never reads conn->xport, so nothing there should
 * care whether the wire runs on a stream or a datagram transport. This binds
 * a custom multiplexed wire (real stream_id header, same shape as
 * tx_full_batch_test.c's mux wire) to a udp_peer conn, and confirms non-zero
 * stream_id frames reach a per-stream handler coroutine while stream_id == 0
 * still reaches on_frame. It also attaches an inter leg on the same session
 * and pushes a stream_id-carrying packet through duct_io_inter_batch — no
 * socket read, no wire, on that leg at all (Stage 0.5): a non-zero stream_id
 * on that leg claims a handler too, exactly like the udp_peer leg above
 *.
 *
 * One of those pushes carries fl_frame_fin with a payload. That frame reaches
 * the handler like any other, so its bytes must be copied out of the VMQ batch
 * first — the batch is free for the producer the moment s_inter_drain returns,
 * and the coroutine runs a duct_coop_cycle later.
 */

#include "duct.h"
#include "duct_wire.h"
#include "duct_stream_ctx.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "test_helpers.h"
#include "dgram_test_helpers.h"

/**
 * Mux wire: [stream_id:4][pad:1][len:4] + payload — the wire format this side
 * packs and a peer sends raw over the socket, same shape as
 * tx_full_batch_test.c's mux wire.
 *
 * On RX, a dgram-classified conn (xport_udp_peer, xport_inter) never hands
 * on_parse this wire format directly: duct_dgram_record_hdr_size bytes of
 * internal record-length framing (duct_wire.h) precede each raw datagram in
 * the RX OLB, to preserve datagram boundaries when several batch into one
 * post. mux_parse consumes that prefix first (its value is redundant with
 * this wire's own len field: reclen == mux_hdr_size + len) and only then
 * decodes its own header from the bytes that follow.
 */

static constexpr size_t mux_hdr_size = 9u;
static constexpr size_t mux_parse_hdr_size = duct_dgram_record_hdr_size + mux_hdr_size;

typedef struct {
    uint8_t  hdr_buf[mux_parse_hdr_size];
    uint32_t partial_len;
    bool     hdr_done;
} mux_parser_t;

typedef struct { duct_wire_t base; } mux_wire_t;

static duct_result_t
mux_parse([[maybe_unused]] const duct_wire_t *self,
          duct_view_u8 input, duct_frame_t *out, duct_wire_parser_t *parser,
          size_t *consumed, size_t *needed)
{
    auto st = (mux_parser_t *)parser;
    *consumed = 0u;
    *needed = 0u;
    uint8_t *p = (uint8_t *)input.data;
    uint8_t *end = p + input.size;

    if (!st->hdr_done) {
        if (st->partial_len > 0u) {
            p += st->partial_len;
            uint32_t want = (uint32_t)mux_parse_hdr_size - st->partial_len;
            uint32_t copy = (uint32_t)(end - p) < want ? (uint32_t)(end - p) : want;
            memcpy(st->hdr_buf + st->partial_len, p, copy);
            st->partial_len += copy;
            p += copy;
            if (st->partial_len < (uint32_t)mux_parse_hdr_size) {
                *needed = mux_parse_hdr_size - st->partial_len;
                return rc_again;
            }
            st->hdr_done = true;
        } else if ((size_t)(end - p) >= mux_parse_hdr_size) {
            memcpy(st->hdr_buf, p, mux_parse_hdr_size);
            p += mux_parse_hdr_size;
            st->hdr_done = true;
        } else {
            memcpy(st->hdr_buf, p, (size_t)(end - p));
            st->partial_len = (uint32_t)(end - p);
            *needed = mux_parse_hdr_size - st->partial_len;
            return rc_again;
        }
    } else {
        p += mux_parse_hdr_size;
    }

    uint32_t sid = ((uint32_t)st->hdr_buf[4] << 24u) | ((uint32_t)st->hdr_buf[5] << 16u)
                 | ((uint32_t)st->hdr_buf[6] <<  8u) |  (uint32_t)st->hdr_buf[7];
    uint32_t len = ((uint32_t)st->hdr_buf[9] << 24u) | ((uint32_t)st->hdr_buf[10] << 16u)
                 | ((uint32_t)st->hdr_buf[11] <<  8u) |  (uint32_t)st->hdr_buf[12];
    st->hdr_done = false;
    st->partial_len = 0u;

    if (len > (1u << 20u)) {
        *consumed = (size_t)(p - (uint8_t *)input.data);
        return rc_invalid_arg;
    }
    if ((size_t)(end - p) < len) {
        st->hdr_done = true;
        *consumed = (size_t)(p - (uint8_t *)input.data);
        *needed = len;
        return rc_again;
    }
    *out = (duct_frame_t){ .stream_id = sid, .payload = { .data = p, .size = len } };
    *consumed = (size_t)((p + len) - (uint8_t *)input.data);
    return rc_ok;
}

static duct_result_t
mux_pack([[maybe_unused]] const duct_wire_t *self, [[maybe_unused]] duct_session_t *s,
         const duct_frame_t *frame, duct_wire_tx_t *stage,
         [[maybe_unused]] duct_wire_codec_t *codec)
{
    uint32_t sid = (uint32_t)frame->stream_id;
    uint32_t len = (uint32_t)frame->payload.size;
    uint8_t hdr[mux_hdr_size] = {
        (uint8_t)(sid >> 24u), (uint8_t)(sid >> 16u),
        (uint8_t)(sid >>  8u), (uint8_t)(sid),
        0u,
        (uint8_t)(len >> 24u), (uint8_t)(len >> 16u),
        (uint8_t)(len >>  8u), (uint8_t)(len),
    };
    return duct_wire_tx_stage(stage,
        duct_view(duct_view_u8, hdr, mux_hdr_size), frame->payload);
}

static duct_wire_parser_t *
mux_create_parser([[maybe_unused]] const duct_wire_t *self)
{
    auto st = duct_new(mux_parser_t);
    duct_do_if(!st, return nullptr);
    *st = (mux_parser_t){};
    return (duct_wire_parser_t *)st;
}

static void mux_destroy_parser([[maybe_unused]] const duct_wire_t *self, duct_wire_parser_t *parser)
{
    auto st = (mux_parser_t *)parser;
    duct_del(st);
}

static void mux_destroy(duct_wire_t *self)
{
    auto w = (mux_wire_t *)self;
    duct_del(w);
}

static duct_wire_t *mux_wire_create(void)
{
    auto w = duct_new(mux_wire_t);
    duct_do_if(!w, return nullptr);
    w->base = (duct_wire_t){
        .name = "test-mux-dgram",
        /* header_size also gates RX frame-payload reconstruction (duct_wire.h);
         * mux_parse_hdr_size folds in duct_dgram_record_hdr_size since
         * on_parse's consumed span includes that prefix but on_pack never
         * emits it. */
        .header_size = mux_parse_hdr_size,
        .max_frame   = 1024u,
        .destroy = mux_destroy, .on_parse = mux_parse, .on_pack = mux_pack,
        .create_parser = mux_create_parser, .destroy_parser = mux_destroy_parser,
    };
    return &w->base;
}

/** @brief Send one mux-framed datagram over a connected UDP socket. */
static int uc_send_mux(duct_sock_t fd, duct_stream_id_t sid, const char *payload, size_t len)
{
    uint8_t hdr[mux_hdr_size] = {
        (uint8_t)(sid >> 24u), (uint8_t)(sid >> 16u),
        (uint8_t)(sid >>  8u), (uint8_t)(sid),
        0u,
        (uint8_t)(len >> 24u), (uint8_t)(len >> 16u),
        (uint8_t)(len >>  8u), (uint8_t)(len),
    };
    uint8_t buf[256];
    memcpy(buf, hdr, mux_hdr_size);
    memcpy(buf + mux_hdr_size, payload, len);
    return uc_send(fd, buf, mux_hdr_size + len);
}

/* ── Protocol callbacks ──────────────────────────────────────────── */

static atomic_int  g_join_count = 0;
static atomic_uint g_join_conn_id = 0u;
static _Atomic(duct_handle_t) g_tok;

typedef struct { duct_stream_id_t stream_id; char data[64]; size_t len; } rec_t;
static constexpr unsigned max_recs = 32u;
static rec_t g_recs[max_recs];
static atomic_uint g_rec_next = 0u;
static atomic_uint g_frame0_count = 0u;

/* Cross-leg busy-race scenario:
 * this stream_id's handler parks on its first call instead of finishing, so
 * a same-stream_id frame can be raced against it from another leg. */
static constexpr duct_stream_id_t parking_sid = 77u;
static atomic_uint g_park_started = 0u;
static atomic_uint g_park_calls = 0u;
static atomic_uint g_err_again_count = 0u;

static duct_result_t
on_frame0([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
          const duct_frame_t *frame, duct_response_t *out,
          [[maybe_unused]] void *proto_state)
{
    /* Handler dispatch in s_dispatch_frame only claims frame.stream_id != 0;
     * this fallback must be the one reached for the primer datagram (sid 0).
     * Index reservation stays relaxed: this proto runs on one worker thread,
     * so on_frame0/s_handler_step never race each other over g_rec_next. The
     * publishing increment below is release, pairing with the main thread's
     * acquire-loads of g_rec_next/g_frame0_count that gate reading g_recs[i]. */
    unsigned i = duct_atomic_load(&g_rec_next, relaxed);
    if (i < max_recs) {
        g_recs[i].stream_id = frame->stream_id;
        g_recs[i].len = frame->payload.size < sizeof(g_recs[i].data)
                       ? frame->payload.size : sizeof(g_recs[i].data);
        memcpy(g_recs[i].data, frame->payload.data, g_recs[i].len);
    }
    duct_atomic_fetch(add, &g_rec_next, 1u, release);
    duct_atomic_fetch(add, &g_frame0_count, 1u, release);
    /* Echo back over this udp_peer conn: exercises s_commit_response's
     * per-record TX reclen wrapper (duct_dgram_rec.h) with this wire's own
     * on_pack header — real protocol data, not a header_internal wire like
     * the engine's built-in dgram-batch one, so it must reach the peer
     * whole (test_mux_dgram's primer-echo check decodes it). */
    duct_response_same(out, frame->payload, fl_send_copy, 0);
    return rc_ok;
}

static duct_result_t
on_error([[maybe_unused]] duct_session_t *s, duct_result_t error,
        [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    if (error == rc_again)
        duct_atomic_fetch(add, &g_err_again_count, 1u, relaxed);
    return rc_ok;
}

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

/** @brief Stackless step: record the frame under its real stream_id, then
 *  tear down (async_done) — each never-before-seen stream_id gets its own
 *  handler + coro, proving frames are not cross-routed between streams.
 *  @c parking_sid's first call parks (async_wait) instead, so a caller can
 *  race a same-stream_id frame from another leg against it; its second
 *  call (the wake this file drives via a follow-up on the same leg)
 *  completes normally. */
static duct_async_rc_t s_handler_step(void *state)
{
    auto hctx = (duct_stream_ctx_t *)state;
    unsigned i = duct_atomic_load(&g_rec_next, relaxed);
    if (i < max_recs) {
        g_recs[i].stream_id = hctx->stream_id;
        g_recs[i].len = hctx->frame.payload.size < sizeof(g_recs[i].data)
                       ? hctx->frame.payload.size : sizeof(g_recs[i].data);
        memcpy(g_recs[i].data, hctx->frame.payload.data, g_recs[i].len);
    }
    duct_atomic_fetch(add, &g_rec_next, 1u, release);
    if (hctx->stream_id == parking_sid
        && duct_atomic_fetch(add, &g_park_calls, 1u, relaxed) == 0u) {
        duct_atomic_fetch(add, &g_park_started, 1u, release);
        return async_wait;
    }
    return async_done;
}

static void s_on_host(void (*fn)(void *ctx), void *ctx, [[maybe_unused]] void *queue_ctx)
{
    fn(ctx);
}

static void s_on_tunnel_resume([[maybe_unused]] void *app_ctx) {}

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

static const rec_t *s_find_rec(unsigned upto, duct_stream_id_t sid)
{
    for (unsigned i = 0u; i < upto && i < max_recs; ++i)
        if (g_recs[i].stream_id == sid)
            return &g_recs[i];
    return nullptr;
}

static const char *test_mux_dgram(duct_engine_t *io, uint16_t port)
{
    duct_sock_t fd = uc_connect(port);
    if (fd == duct_sock_bad) return "client connect failed";

    /* Primer datagram on stream 0: opens the session and must land on
     * on_frame, not the handler path. */
    static const char primer[] = "primer-sid0";
    if (uc_send_mux(fd, 0u, primer, sizeof primer - 1u) != 0) {
        close(fd); return "primer send failed";
    }
    if (!s_wait_uint(&g_frame0_count, 1u, 3000u)) { close(fd); return "on_frame0 never fired"; }
    if (!th_wait_int(&g_join_count, 1, 3000u)) { close(fd); return "on_conn_join did not fire for the inter leg"; }
    if (duct_atomic_load(&g_join_conn_id, acquire) != 1u) {
        close(fd); return "on_conn_join conn_id != 1";
    }
    {
        auto rec = s_find_rec(duct_atomic_load(&g_rec_next, acquire), 0u);
        if (!rec || rec->len != sizeof primer - 1u || memcmp(rec->data, primer, rec->len) != 0) {
            close(fd); return "primer payload mismatch on on_frame0";
        }
    }

    /* on_frame0's echo, staged through s_commit_response's per-record TX
     * reclen wrapper: the mux header must reach the peer intact (RW-DG-TX;
     * unlike the built-in dgram-batch wire's header_internal framing, which
     * a plain socket never sees). */
    {
        uint8_t buf[256];
        ssize_t got = uc_recv(fd, (char *)buf, sizeof buf);
        if (got < (ssize_t)mux_hdr_size) { close(fd); return "primer echo: short or missing reply"; }
        uint32_t rsid = ((uint32_t)buf[0] << 24u) | ((uint32_t)buf[1] << 16u)
                      | ((uint32_t)buf[2] <<  8u) |  (uint32_t)buf[3];
        uint32_t rlen = ((uint32_t)buf[5] << 24u) | ((uint32_t)buf[6] << 16u)
                      | ((uint32_t)buf[7] <<  8u) |  (uint32_t)buf[8];
        if (rsid != 0u || (size_t)got != mux_hdr_size + rlen || rlen != sizeof primer - 1u
            || memcmp(buf + mux_hdr_size, primer, rlen) != 0) {
            close(fd); return "primer echo mismatch";
        }
    }

    /* Two multiplexed datagrams over the udp_peer conn, distinct stream_ids:
     * must reach the handler path (not on_frame0), each with its own payload
     * under its own stream_id — no cross-routing between streams. */
    static const char s7[] = "udp-stream-7", s11[] = "udp-stream-11";
    if (uc_send_mux(fd, 7u, s7, sizeof s7 - 1u) != 0) { close(fd); return "udp sid=7 send failed"; }
    if (uc_send_mux(fd, 11u, s11, sizeof s11 - 1u) != 0) { close(fd); return "udp sid=11 send failed"; }
    if (!s_wait_uint(&g_rec_next, 3u, 3000u)) { close(fd); return "udp mux frames never reached the handler"; }
    {
        unsigned n = duct_atomic_load(&g_rec_next, acquire);
        auto rec7 = s_find_rec(n, 7u);
        auto rec11 = s_find_rec(n, 11u);
        if (!rec7 || rec7->len != sizeof s7 - 1u || memcmp(rec7->data, s7, rec7->len) != 0) {
            close(fd); return "udp sid=7 payload mismatch";
        }
        if (!rec11 || rec11->len != sizeof s11 - 1u || memcmp(rec11->data, s11, rec11->len) != 0) {
            close(fd); return "udp sid=11 payload mismatch";
        }
        if (duct_atomic_load(&g_frame0_count, acquire) != 1u) {
            close(fd); return "a multiplexed udp frame leaked into on_frame0";
        }
    }

    /* One packet pushed through duct_io_inter_batch on the attach_inter leg
     * (conn_id=1, xport_inter) — no socket read on that leg at all, and no
     * wire either (Stage 0.5: inter never binds one). The host declares
     * stream_id directly in the push instead of encoding a mux header into
     * the bytes for a wire to re-parse — framing is the host's own concern
     * for inter. A non-zero stream_id on this leg now
     * claims a handler exactly like the real-socket udp_peer leg above
     * — it must reach s_handler_step, never
     * on_frame0. */
    duct_handle_t tok = duct_atomic_load(&g_tok, acquire);
    static const char s21[] = "inter-stream-21";
    alignas(8) char inter_buf[duct_inter_batch_bytes(1u)];
    auto inter_batch = (duct_inter_batch_t *)inter_buf;
    inter_batch->n = 1u;
    *duct_inter_batch_pkt(inter_batch, 0u) = (duct_inter_pkt_t){
        .payload = { .data = (void *)s21, .size = sizeof s21 - 1u },
        .stream_id = 21u, .flags = fl_frame_none,
    };
    unsigned before = duct_atomic_load(&g_rec_next, acquire);
    int frame0_before = duct_atomic_load(&g_frame0_count, acquire);
    if (duct_io_inter_batch(io, tok, 1u, inter_batch) != rc_ok) {
        close(fd); return "duct_io_inter_batch failed";
    }
    {
        static const char s23[] = "inter-fin-payload";
        unsigned fin_before = duct_atomic_load(&g_rec_next, acquire);
        *duct_inter_batch_pkt(inter_batch, 0u) = (duct_inter_pkt_t){
            .payload = { .data = (void *)s23, .size = sizeof s23 - 1u },
            .stream_id = 23u, .flags = fl_frame_fin,
        };
        if (duct_io_inter_batch(io, tok, 1u, inter_batch) != rc_ok) {
            close(fd); return "duct_io_inter_batch (fin) failed";
        }
        if (!s_wait_uint(&g_rec_next, fin_before + 1u, 3000u)) {
            close(fd); return "a fin-bearing inter frame never reached the handler";
        }
        unsigned n = duct_atomic_load(&g_rec_next, acquire);
        auto rec23 = s_find_rec(n, 23u);
        if (!rec23 || rec23->len != sizeof s23 - 1u
            || memcmp(rec23->data, s23, rec23->len) != 0) {
            close(fd); return "a fin-bearing inter frame lost its payload";
        }
    }
    if (!s_wait_uint(&g_rec_next, before + 1u, 3000u)) {
        close(fd); return "inter-leg frame never reached the handler";
    }
    {
        unsigned n = duct_atomic_load(&g_rec_next, acquire);
        auto rec21 = s_find_rec(n, 21u);
        if (!rec21 || rec21->len != sizeof s21 - 1u || memcmp(rec21->data, s21, rec21->len) != 0) {
            close(fd); return "inter-leg sid=21 payload mismatch";
        }
        if (duct_atomic_load(&g_frame0_count, acquire) != frame0_before) {
            close(fd); return "inter-leg frame leaked into on_frame0";
        }
    }

    /* Cross-leg wake (the deadlock
     * bug): claim parking_sid via the poll leg and park its handler
     * mid-flight, then deliver the same stream_id's next frame from the
     * inter leg. Before this fix that frame bypassed the parked handler
     * entirely and went to on_frame; now s_dispatch_stream_claim must wake
     * the SAME hctx instead, threading the inter-sourced ack_owned copy
     * through hctx->frame/hctx->ack. */
    static const char p1[] = "park-first", p2[] = "park-wake";
    if (uc_send_mux(fd, parking_sid, p1, sizeof p1 - 1u) != 0) {
        close(fd); return "parking sid send failed";
    }
    if (!s_wait_uint(&g_park_started, 1u, 3000u)) { close(fd); return "handler never parked"; }
    unsigned rec_before_wake = duct_atomic_load(&g_rec_next, acquire);
    int frame0_before_wake = duct_atomic_load(&g_frame0_count, acquire);
    *duct_inter_batch_pkt(inter_batch, 0u) = (duct_inter_pkt_t){
        .payload = { .data = (void *)p2, .size = sizeof p2 - 1u },
        .stream_id = parking_sid, .flags = fl_frame_none,
    };
    if (duct_io_inter_batch(io, tok, 1u, inter_batch) != rc_ok) {
        close(fd); return "duct_io_inter_batch (wake) failed";
    }
    if (!s_wait_uint(&g_rec_next, rec_before_wake + 1u, 3000u)) {
        close(fd); return "inter-leg frame never woke the parked handler";
    }
    {
        auto recp = &g_recs[rec_before_wake];
        if (recp->stream_id != parking_sid || recp->len != sizeof p2 - 1u
            || memcmp(recp->data, p2, recp->len) != 0) {
            close(fd); return "woken handler's payload mismatch";
        }
        if (duct_atomic_load(&g_frame0_count, acquire) != frame0_before_wake) {
            close(fd); return "inter-leg wake frame leaked into on_frame0";
        }
    }

    /* claim_busy: two packets for a
     * brand-new stream_id in ONE inter batch. The first claims and spawns
     * the handler (enqueued, not yet stepped — duct_coop_cycle only runs
     * after this whole drain pass returns); the second, dispatched
     * synchronously right behind it within the same s_inter_msg_take loop, must
     * see a handler_ctx that is not parked yet and get claim_busy ->
     * rc_again, dropped rather than delivered or misrouted. */
    static constexpr duct_stream_id_t busy_sid = 88u;
    static const char b1[] = "busy-a", b2[] = "busy-b";
    alignas(8) char busy_buf[duct_inter_batch_bytes(2u)];
    auto busy_batch = (duct_inter_batch_t *)busy_buf;
    busy_batch->n = 2u;
    *duct_inter_batch_pkt(busy_batch, 0u) = (duct_inter_pkt_t){
        .payload = { .data = (void *)b1, .size = sizeof b1 - 1u },
        .stream_id = busy_sid, .flags = fl_frame_none,
    };
    *duct_inter_batch_pkt(busy_batch, 1u) = (duct_inter_pkt_t){
        .payload = { .data = (void *)b2, .size = sizeof b2 - 1u },
        .stream_id = busy_sid, .flags = fl_frame_none,
    };
    unsigned rec_before_race = duct_atomic_load(&g_rec_next, acquire);
    unsigned err_before_race = duct_atomic_load(&g_err_again_count, acquire);
    if (duct_io_inter_batch(io, tok, 1u, busy_batch) != rc_ok) {
        close(fd); return "duct_io_inter_batch (claim_busy race) failed";
    }
    if (!s_wait_uint(&g_err_again_count, err_before_race + 1u, 3000u)) {
        close(fd); return "same-batch race never fired claim_busy/rc_again";
    }
    if (!s_wait_uint(&g_rec_next, rec_before_race + 1u, 3000u)) {
        close(fd); return "claimed handler in the race never ran";
    }
    {
        /* Grace window, then confirm no second record landed: the busy
         * packet must never reach a handler, only the claiming one does. */
        struct timespec ts = { .tv_nsec = 200L * 1000L * 1000L };
        nanosleep(&ts, nullptr);
        if (duct_atomic_load(&g_rec_next, acquire) != rec_before_race + 1u) {
            close(fd); return "busy packet reached a handler instead of dropping";
        }
        auto recb = &g_recs[rec_before_race];
        if (recb->stream_id != busy_sid || recb->len != sizeof b1 - 1u
            || memcmp(recb->data, b1, recb->len) != 0) {
            close(fd); return "claimed handler's payload mismatch in the race";
        }
    }

    close(fd);
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    auto wire = mux_wire_create();
    if (!wire) { fprintf(stderr, "mux_dgram: wire create failed\n"); return 1; }

    auto io = duct_engine_launch(&(duct_engine_cfg_t){
        .io_threads = 1, .workers = 1,
        .host = {
            .run = s_on_host,
            .on_inter_resume = s_on_tunnel_resume,
        },
    });
    if (!io) { fprintf(stderr, "mux_dgram: io create failed\n"); duct_wire_destroy(wire); return 1; }

    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "mux-dgram", .wire = wire,
        .on_frame = on_frame0,
        .on_session_open = on_session_open,
        .on_conn_join = on_conn_join,
        .on_error = on_error,
        .flags = fl_proto_multiplexed,
        .handler_kind = handler_async,
        .handler_async = s_handler_step,
        .max_response = 4096u,
    });
    if (!proto) {
        fprintf(stderr, "mux_dgram: proto create failed\n");
        duct_engine_destroy(io); duct_wire_destroy(wire);
        return 1;
    }

    const duct_proto_t *protos[1] = { proto };
    uint16_t port = 0u;
    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
            .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
        }, &port, nullptr, 0u, nullptr) != rc_ok) {
        fprintf(stderr, "mux_dgram: bind failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(wire);
        return 1;
    }
    pthread_t th;
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        fprintf(stderr, "mux_dgram: thread create failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(wire);
        return 1;
    }

    const char *err = test_mux_dgram(io, port);

    duct_engine_stop(io);
    pthread_join(th, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    duct_wire_destroy(wire);

    if (err) {
        fprintf(stderr, "mux_dgram: %s\n", err);
        return 1;
    }
    printf("mux_dgram: OK (handler dispatch over udp_peer + attach_inter, "
           "stream 0 fallback on_frame, no cross-stream routing)\n");
    return 0;
}
