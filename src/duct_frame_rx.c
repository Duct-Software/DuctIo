/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_frame_rx.c
 *  @brief RX wire-parse → frame-batch → WFQ-post pipeline + WFQ-full retry queue.
 */

#include "duct_frame_rx.h"
#include "duct_io.h"
#include "duct_bits.h"
#include "duct_conn.h"
#include "duct_conn_fence.h"
#include "duct_dgram_rec.h"
#include "duct_olb_rx.h"
#include "duct_relay.h"
#include "duct_wfq.h"
#include "duct_wfq_msg.h"
#include "duct_wire.h"

#include <string.h>

/** @brief Per-batch wire-byte budget: caps cumulative frame length in one
 *  batch message independently of frame count, so a run of large frames
 *  cannot starve the byte-fairness of adjacent lanes. One frame is always
 *  admitted even alone over budget; its length then closes the batch.
 */
static constexpr size_t frame_rx_batch_byte_budget = duct_wfq_byte_quota_norm;

/** @brief WFQ-full batch retry node: inline batch copy + push cursor. */
duct_msg_chain_decl(batch_retry_node_t,
    unsigned worker_id;
    uint32_t from;
    alignas(alignof(duct_conn_handle_t)) duct_msg_frame_batch_t batch;
);

static inline size_t s_batch_retry_node_size(uint32_t n)
{
    return sizeof(batch_retry_node_t) + (size_t)n * sizeof(duct_msg_frame_t);
}

/** @brief Derive the frame ceiling from the NORM lane's actual byte capacity:
 *  the most @c duct_msg_frame_t entries any one batch message can carry
 *  in that lane, capped by the scheduling frame budget. All NORM lanes
 *  share one capacity by construction, per @c duct_wfq_new, so worker 0's
 *  io-0 lane is representative. Returns 0 when the lane cannot carry even
 *  one frame — a misconfiguration the caller must reject.
 */
static unsigned s_compute_frame_ceiling(duct_vmq_mpsc_t *wfq, unsigned n_workers, unsigned n_io)
{
    unsigned lane = duct_wfq_pri_lane(wfq_pri_norm, 0u, n_workers, 0u, n_io);
    size_t cap = duct_mpsc_cap(wfq, lane) & ~(size_t)7u;
    size_t min_msg = duct_vmq_msg_overhead + sizeof(duct_msg_frame_batch_t) + sizeof(duct_msg_frame_t);
    if (cap < min_msg)
        return 0u;
    size_t lane_frame_cap = (cap - duct_vmq_msg_overhead - sizeof(duct_msg_frame_batch_t))
                           / sizeof(duct_msg_frame_t);
    return (unsigned)(lane_frame_cap < duct_wfq_quota_norm ? lane_frame_cap : duct_wfq_quota_norm);
}

bool duct_frame_rx_ctx_init(duct_frame_rx_ctx_t *ctx, duct_vmq_mpsc_t *wfq,
                            unsigned n_workers, unsigned n_io)
{
    *ctx = (duct_frame_rx_ctx_t){};
    ctx->frame_ceiling = s_compute_frame_ceiling(wfq, n_workers, n_io);
    if (ctx->frame_ceiling == 0u)
        return false;
    size_t scratch_bytes = 0u;
    if (duct_ckd_mul(&scratch_bytes, (size_t)ctx->frame_ceiling, sizeof(duct_msg_frame_t))
        || duct_ckd_add(&scratch_bytes, scratch_bytes, sizeof(duct_msg_frame_batch_t)))
        return false;
    ctx->batch_buf = duct_at(duct_new(char, scratch_bytes));
    return ctx->batch_buf != nullptr;
}

void duct_frame_rx_ctx_destroy(duct_frame_rx_ctx_t *ctx)
{
    for (auto m = ctx->retry_q.head; m; ) {
        auto next = duct_msg_next(m);
        duct_del(m);
        m = next;
    }
    ctx->retry_q.head = nullptr;
    ctx->retry_q.tail = nullptr;
    memset(ctx->retry_pending, 0, sizeof ctx->retry_pending);
    duct_del(ctx->batch_buf);
}

/** @brief Push a frame batch to the WFQ. Returns true on success. */
static inline bool
s_batch_push(const duct_wfq_route_t *route, unsigned lane, duct_conn_handle_t handle,
             const duct_msg_frame_t *frames, unsigned n, char *buf)
{
    size_t payload_bytes = n * sizeof(duct_msg_frame_t);
    size_t msg_bytes = sizeof(duct_msg_frame_batch_t) + payload_bytes;
    auto m = (duct_msg_frame_batch_t *)buf;
    m->conn = handle.word;
    m->n = n;
    /* When called with ctx->batch_buf as buf, frames == m->frames (same
     * address) — memcpy with overlapping src/dst is UB; skip explicitly. */
    if (frames != m->frames)
        memcpy(m->frames, frames, payload_bytes);
    return duct_wfq_post(route->wfq, lane, wfq_pri_norm, m, msg_bytes) == vmq_push_ok;
}

/** @brief Push a batch with binary shrink on failure.
 *
 *  Tries the full @p n first. On vmq_push failure, halves @p n until it fits.
 *  Returns the number of frames actually pushed (0 = nothing pushed, lane full).
 */
static inline unsigned
s_batch_push_shrink(const duct_wfq_route_t *route, unsigned lane, duct_conn_handle_t handle,
                    const duct_msg_frame_t *frames, unsigned n, char *buf)
{
    while (n > 0u) {
        if (s_batch_push(route, lane, handle, frames, n, buf))
            return n;
        n /= 2u;
    }
    return 0u;
}

/** @brief True if @p handle already has a pending retry node on this thread. */
static bool s_retry_find(const duct_frame_rx_ctx_t *ctx, duct_conn_handle_t handle)
{
    return duct_bits_test_plain(ctx->retry_pending, (uint32_t)handle.idx);
}

/** @brief Clear @p worker_id's wait bit unless @p kept_head still targets it. */
static void s_retry_maybe_clear(unsigned thread_id,
                                const duct_msg_t *kept_head,
                                unsigned worker_id)
{
    for (auto m = kept_head; m; m = duct_msg_next(m)) {
        auto node = DUCT_CAST(batch_retry_node_t, msg, m);
        if (node->worker_id == worker_id)
            return;
    }
    duct_worker_wfq_wait_clear(worker_id, thread_id);
}

/** @brief Push the remainder of @p node into WFQ.
 *
 *  @return @p node's resulting @c from, absolute — the caller assigns it,
 *  never adds to it.
 *
 *  A still-unsent tail, @c from > 0, is copied into @p stage: the io
 *  thread's reused scratch batch buffer, sized by
 *  @ref duct_frame_rx_ctx_init for the largest batch it allows, so any
 *  node's @c remain fits. @c node->batch.frames and @c node->batch.n stay
 *  untouched for as long as the node exists, so every reader of them —
 *  this function's next call included — keeps seeing the original
 *  numbering. s_batch_push_shrink's shrink retries then see @p stage as a
 *  fresh, unshifted batch, the same @c frames @c == @c m->frames fast path
 *  s_batch_push already takes there.
 */
static uint32_t s_batch_retry_push(const duct_wfq_route_t *route, batch_retry_node_t *node, char *stage)
{
    auto h = (duct_conn_handle_t){ .word = node->batch.conn };
    auto conn = duct_conn_by_handle(h);
    if (!conn)
        return node->from;
    unsigned lane = duct_wfq_pri_lane(wfq_pri_norm, conn->worker_id, route->n_workers,
                                      route->thread_id, route->n_io);
    uint32_t remain = node->batch.n - node->from;
    if (remain == 0u)
        return node->from;
    auto scratch = (duct_msg_frame_batch_t *)stage;
    memcpy(scratch->frames, &node->batch.frames[node->from], (size_t)remain * sizeof(duct_msg_frame_t));
    unsigned pushed = s_batch_push_shrink(route, lane, h, scratch->frames, remain, stage);
    return node->from + pushed;
}

/** @brief Save unpushed frame descriptors for @p handle into the retry queue
 *  and arm the reverse wait. Caller must have already verified no node exists
 *  for this conn (@ref s_retry_find).
 */
static bool
s_retry_save(const duct_wfq_route_t *route, duct_frame_rx_ctx_t *ctx,
             duct_conn_handle_t handle, unsigned worker_id,
             const duct_msg_frame_t *frames, uint32_t n)
{
    auto node = (batch_retry_node_t *)duct_at(duct_new(uint8_t, s_batch_retry_node_size(n),
                                                         alignof(batch_retry_node_t)));
    if (!node)
        return false;
    node->worker_id = worker_id;
    node->from = 0u;
    node->batch.conn = handle.word;
    node->batch.n = n;
    memcpy(node->batch.frames, frames, (size_t)n * sizeof(duct_msg_frame_t));
    duct_msg_queue_push(&ctx->retry_q, &node->msg);
    duct_bits_set_plain(ctx->retry_pending, (uint32_t)handle.idx);
    duct_worker_wfq_wait_arm(worker_id, route->thread_id);
    return true;
}

void duct_frame_rx_retry_drain(const duct_wfq_route_t *route, duct_frame_rx_ctx_t *ctx)
{
    duct_do_if(!ctx->retry_q.head, return);
    duct_msg_t *kept = nullptr,
               *kept_tail = nullptr,
               *done = nullptr,
               *done_tail = nullptr;
    uint64_t freed_workers = 0u;
    for (auto m = ctx->retry_q.head; m; ) {
        auto next = duct_msg_next(m);
        auto node = DUCT_CAST(batch_retry_node_t, msg, m);
        auto h = (duct_conn_handle_t){ .word = node->batch.conn };
        auto conn = duct_conn_by_handle(h);
        if (conn)
            node->from = s_batch_retry_push(route, node, ctx->batch_buf);
        if (!conn) {
            if (node->worker_id < duct_wfq_io_waiters_max)
                freed_workers |= 1ull << node->worker_id;
            duct_bits_clear_plain(ctx->retry_pending, (uint32_t)h.idx);
            duct_del(node);
        } else if (node->from >= node->batch.n) {
            if (node->worker_id < duct_wfq_io_waiters_max)
                freed_workers |= 1ull << node->worker_id;
            duct_bits_clear_plain(ctx->retry_pending, (uint32_t)h.idx);
            duct_msg_next(m) = nullptr;
            if (done_tail)
                duct_msg_next(done_tail) = m;
            else
                done = m;
            done_tail = m;
        } else {
            /* Re-arm: worker wake clears the wait bit unconditionally. */
            duct_worker_wfq_wait_arm(node->worker_id, route->thread_id);
            duct_msg_next(m) = nullptr;
            if (kept_tail)
                duct_msg_next(kept_tail) = m;
            else
                kept = m;
            kept_tail = m;
        }
        m = next;
    }
    ctx->retry_q.head = kept;
    ctx->retry_q.tail = kept_tail;
    while (freed_workers) {
        unsigned wid = duct_ctz_ull(freed_workers);
        freed_workers &= freed_workers - 1u;
        s_retry_maybe_clear(route->thread_id, kept, wid);
    }
    for (auto m = done; m; ) {
        auto next = duct_msg_next(m);
        auto node = DUCT_CAST(batch_retry_node_t, msg, m);
        auto conn = duct_conn_by_handle((duct_conn_handle_t){ .word = node->batch.conn });
        /* A conn whose input ended while this node held its frames posts that
         * end now, behind them; a node carrying the end is its conn's last
         * post. */
        bool ended = duct_has(node->batch.frames[node->batch.n - 1u].flags, duct_frame_end);
        duct_del(node);
        if (conn) {
            duct_frame_rx_post(route, ctx, conn);
            if (!ended)
                duct_frame_rx_end(route, ctx, conn);
        }
        m = next;
    }
}

void duct_frame_rx_retry_discard(duct_frame_rx_ctx_t *ctx, const duct_conn_t *conn)
{
    if (!ctx->retry_q.head)
        return;
    uint32_t idx = duct_conn_idx_get(conn);
    duct_msg_t *kept = nullptr,
               *kept_tail = nullptr;
    bool freed = false;
    for (auto m = ctx->retry_q.head; m; ) {
        auto next = duct_msg_next(m);
        auto node = DUCT_CAST(batch_retry_node_t, msg, m);
        if (((duct_conn_handle_t){ .word = node->batch.conn }).idx == idx) {
            freed = true;
            duct_bits_clear_plain(ctx->retry_pending, idx);
            duct_del(node);
        } else {
            duct_msg_next(m) = nullptr;
            if (kept_tail)
                duct_msg_next(kept_tail) = m;
            else
                kept = m;
            kept_tail = m;
        }
        m = next;
    }
    ctx->retry_q.head = kept;
    ctx->retry_q.tail = kept_tail;
    if (freed)
        s_retry_maybe_clear(conn->io_id, kept, conn->worker_id);
}

/** @brief On WFQ-full, bump the stat, save @p frames into a retry node, and
 *  advance @p rx's post frontier to @p new_posted_off; on save failure,
 *  hard-close @p conn (OOM).
 */
static bool
s_retry_save_or_drop(const duct_wfq_route_t *route, duct_frame_rx_ctx_t *ctx,
                     duct_conn_t *conn, duct_olb_rx_t *rx,
                     duct_conn_handle_t handle,
                     const duct_msg_frame_t *frames, uint32_t n,
                     size_t new_posted_off)
{
#if DUCT_RUNTIME_STATS
    duct_io_rtstat_wfq_push_full_inc();
#endif
    if (s_retry_save(route, ctx, handle, conn->worker_id, frames, n)) {
        rx->posted_off = (uint32_t)new_posted_off;
        return true;
    }
    duct_io_conn_close(conn, close_io_error);
    return false;
}

/** @brief Parse complete frames into scratch and push them, up to @p tail.
 *  The wire path of @ref duct_frame_rx_post, splitting a batch when a push
 *  fails.
 */
static void
s_frame_rx_post_wire(const duct_wfq_route_t *route, duct_frame_rx_ctx_t *ctx, duct_conn_t *conn,
                     duct_olb_rx_t *rx, duct_conn_handle_t handle, unsigned lane,
                     size_t tail, size_t off)
{
    /* wire->max_batch_frames is a protocol preference, not an override of the
     * scheduler/lane-derived ceiling — always clamp to it. */
    unsigned batch_cap = conn->wire->max_batch_frames
                       ? conn->wire->max_batch_frames : ctx->frame_ceiling;
    if (batch_cap > ctx->frame_ceiling)
        batch_cap = ctx->frame_ceiling;
    /* A padded record posts as a frame and a pad, so a peer conn's batch stops
     * one short and the pair still fits scratch. */
    bool padded = conn->xport_type == x_udp_peer;
    if (padded && batch_cap > 1u)
        --batch_cap;
    auto scratch = (duct_msg_frame_batch_t *)ctx->batch_buf;
    scratch->conn = handle.word;
    scratch->n = 0u;
    size_t batch_bytes = 0u;
    /* Pinned once per batch, not re-read from conn->wire at worker dispatch
     * time: a deferred frame can outlive the conn wire rebind, by
     * which point conn->wire->header_size may no longer match what this
     * frame was actually parsed with.
     * sealed_epoch is pinned for the identical reason — see
     * duct_msg_frame_t doc. */
    uint16_t hdr_size = (uint16_t)conn->wire->header_size;
    uint8_t sealed_epoch = conn->wire->unseal ? conn->wire_epoch : 0u;

    for (size_t remain; 0 != (remain = tail > off ? tail - off : 0);) {
        uint32_t raw = padded && remain >= sizeof(duct_dgram_rec_hdr_t)
                     ? (uint32_t)duct_dgram_rec_hdr_decode(rx->data + off) : 0u;
        /* The tail of a coalesced read: staged with no record prefix, so its
         * datagrams are cut directly by segment size;
         * header_size is zero because the only per-datagram header such a wire
         * has is that prefix. The read's first datagram went in ahead of this
         * one as an ordinary record; describing it here instead stages a record
         * prefix that nothing ever acks. */
        if (rx->group_bytes && off == rx->group_off) {
            uint32_t take = duct_min(rx->group_bytes, rx->group_seg);
            scratch->frames[scratch->n++] = (duct_msg_frame_t){
                .offset = (uint32_t)off, .len = take,
                .stream_id = duct_stream_id_default, .flags = fl_frame_none,
                .sealed_epoch = sealed_epoch, .header_size = 0u,
            };
            off += take;
            batch_bytes += take;
            rx->group_off = (uint32_t)off;
            rx->group_bytes -= take;
        } else if (raw == duct_dgram_rec_void) {
            scratch->frames[scratch->n++] = (duct_msg_frame_t){
                .offset = (uint32_t)off, .len = rx->read_unit, .flags = duct_frame_pad,
            };
            off += rx->read_unit;
        } else {
            /* on_parse reads the prefix as a plain length, so a padded one drops
             * its bit in place for the call; a parse that stops puts it back,
             * so the next pass still finds the unit's remainder padded. */
            size_t unit_end = raw & duct_dgram_rec_padded ? off + rx->read_unit : 0u;
            if (unit_end)
                duct_dgram_rec_hdr_encode(rx->data + off, raw & ~duct_dgram_rec_padded);
            duct_view_u8 input = {
                .data = rx->data + off,
                .size = remain,
            };
            duct_frame_t frame = {};
            size_t consumed = 0u,
                   needed = 0u;
            auto rc = conn->wire->on_parse(conn->wire, input, &frame,
                                    conn->wire_parser, &consumed, &needed);
            /* Stop unless a frame actually came out. Every other answer leaves
             * the bytes where they are for a later pass: the wire needing more,
             * a wire that recognized nothing, and any code this loop has no
             * arm for, which @c default catches to prevent advancing progress. */
            bool stop = true;
            switch (rc) {
            case rc_invalid_arg:
            /* The parser state is past trusting, so the error ends the conn's
             * input: reads stop for good, the unparsed remainder goes, and the
             * end follows the frames ahead of it, the leg closing with
             * close_protocol_error behind their answers. */
                /* A batch the lane takes counts as posted, up to off; one it
                 * refuses is dropped with the unparsed remainder. */
                if (scratch->n > 0u
                    && s_batch_push(route, lane, handle, scratch->frames,
                                    scratch->n, ctx->batch_buf))
                    rx->posted_off = (uint32_t)off;
                duct_gen_req_reason_set(conn, close_protocol_error);
                duct_conn_state_set(conn, fl_conn_rx_eof);
                duct_frame_rx_end(route, ctx, conn);
                return;
            case rc_again:
                duct_olb_rx_recv_hint_set(rx, needed);
                break;
            case rc_ok:
                if (consumed) {
                    /* The descriptor's two marks are the engine's alone: only
                     * this parse sets duct_frame_pad, which the worker acks
                     * without dispatching, and only duct_frame_rx_end sets
                     * duct_frame_end. Every other bit a wire sets passes
                     * through. */
                    scratch->frames[scratch->n++] = (duct_msg_frame_t){
                        .offset      = (uint32_t)off,
                        .len         = (uint32_t)consumed,
                        .stream_id   = frame.stream_id,
                        .flags       = duct_and(frame.flags, duct_not(duct_frame_pad),
                                                duct_not(duct_frame_end)),
                        .sealed_epoch = sealed_epoch,
                        .header_size  = hdr_size,
                    };
                    off += consumed;
                    batch_bytes += consumed;
                    stop = false;
                    if (unit_end > off) {
                        scratch->frames[scratch->n++] = (duct_msg_frame_t){
                            .offset = (uint32_t)off, .len = (uint32_t)(unit_end - off),
                            .flags = duct_frame_pad,
                        };
                        off = unit_end;
                    }
                }
                break;
            default:
                break;
            }
            if (stop) {
                if (unit_end)
                    duct_dgram_rec_hdr_encode(rx->data + off, raw);
                break;
            }
        }

        /* Frame-count or wire-byte ceiling reached: one frame is always
         * admitted first, so a single oversized frame still closes its
         * batch and avoids blocking indefinitely. */
        if (scratch->n >= batch_cap || batch_bytes >= frame_rx_batch_byte_budget) {
            /* Full batch — push with binary shrink on failure. n_saved:
             * s_batch_push writes m->n through the same ctx->batch_buf
             * bytes as scratch->n (self-referential push), so a shrunk
             * retry inside s_batch_push_shrink clobbers scratch->n before
             * this line can read it back. */
            unsigned n_saved = scratch->n;
            unsigned pushed = s_batch_push_shrink(
                route, lane, handle, scratch->frames, n_saved, ctx->batch_buf);
            if (pushed > 0u) {
                rx->posted_off = scratch->frames[pushed - 1u].offset
                                     + scratch->frames[pushed - 1u].len;
                unsigned rem = n_saved - pushed;
                if (rem > 0u)
                    memmove(scratch->frames, &scratch->frames[pushed],
                            (size_t)rem * sizeof(duct_msg_frame_t));
                scratch->n = rem;
                batch_bytes = 0u;
                for (unsigned k = 0u; k < rem; ++k)
                    batch_bytes += scratch->frames[k].len;
            } else {
                if (!s_retry_save_or_drop(route, ctx, conn, rx, handle,
                                          scratch->frames, n_saved, off))
                    return;
                scratch->n = 0u;
                batch_bytes = 0u;
                break;
            }
        }
    }
    /* Flush remaining frames. Same n_saved hazard as the mid-loop flush. */
    if (scratch->n > 0u) {
        unsigned n_saved = scratch->n;
        unsigned pushed = s_batch_push_shrink(
            route, lane, handle, scratch->frames, n_saved, ctx->batch_buf);
        if (pushed == n_saved) {
            rx->posted_off = scratch->frames[pushed - 1u].offset
                                + scratch->frames[pushed - 1u].len;
        } else if (!s_retry_save_or_drop(route, ctx, conn, rx, handle,
                                         &scratch->frames[pushed],
                                         n_saved - pushed, off)) {
            return;
        }
    }
    if (off == tail) {
        duct_olb_rx_recv_hint_set(rx, 0u);
        /* A wire-changing switch deferred earlier because this conn was
         * still mid-frame under the old wire (duct_conn_wire_rebind
         * doc) now has nothing left in its way — this is the only place
         * that ever notices the ring just drained, so it is also the only
         * place that can retry. No-op when no rebind is pending. */
        if (duct_atomic_load(&conn->wire_rebind_next, relaxed))
            duct_conn_wire_rebind(route, conn);
    }
}

void duct_frame_rx_post(const duct_wfq_route_t *route, duct_frame_rx_ctx_t *ctx, duct_conn_t *conn)
{
    auto rx = conn->rx_buf;
    auto h = &rx->h;
    size_t tail = duct_atomic_load(&h->tail, relaxed),
           off = rx->posted_off,
           avail = tail > off ? tail - off : 0u;
    if (avail == 0u)
        return;
    /* Quiesced: no new frames past this
     * point. The worker's conn-lost consume sees every frame published before
     * the fence, so this guard cannot drop input the fence promised to deliver. */
    if (duct_atomic_load(&conn->conn_fence, acquire) >= fence_quiescing)
        return;

    auto handle = duct_conn_handle_get(conn);
    /* A pending retry node holds descriptors into this exact byte range;
     * parsing ahead of it double-parses those bytes and desyncs a stateful
     * wire decoder. Parsing resumes only once the node drains. */
    if (ctx->retry_q.head && s_retry_find(ctx, handle))
        return;
    auto lane = duct_wfq_pri_lane(wfq_pri_norm, conn->worker_id, route->n_workers,
                                  route->thread_id, route->n_io);

    if (conn->wire && conn->wire_parser) {
        s_frame_rx_post_wire(route, ctx, conn, rx, handle, lane, tail, off);
        return;
    }

    /* Raw path: one read span posted as a single-frame batch, so a WFQ-full
     * push shares the same retry mechanism as the wire path. */
    duct_msg_frame_t desc = {
        .offset      = (uint32_t)off,
        .len         = (uint32_t)avail,
        .stream_id   = duct_stream_id_default
    };
    if (s_batch_push_shrink(route, lane, handle, &desc, 1u, ctx->batch_buf) > 0u)
        rx->posted_off = tail;
    else
        s_retry_save_or_drop(route, ctx, conn, rx, handle, &desc, 1u, tail);
}

void duct_frame_rx_end(const duct_wfq_route_t *route, duct_frame_rx_ctx_t *ctx, duct_conn_t *conn)
{
    if (!duct_has(duct_conn_state(conn), fl_conn_rx_eof)
        || duct_atomic_load(&conn->conn_fence, acquire) >= fence_quiescing)
        return;
    auto handle = duct_conn_handle_get(conn);
    if (ctx->retry_q.head && s_retry_find(ctx, handle))
        return;
    auto rx = conn->rx_buf;
    duct_olb_rx_discard(rx, duct_atomic_load(&rx->h.tail, relaxed));
    duct_msg_frame_t end = { .offset = rx->posted_off, .flags = duct_frame_end };
    auto lane = duct_wfq_pri_lane(wfq_pri_norm, conn->worker_id, route->n_workers,
                                  route->thread_id, route->n_io);
    if (!s_batch_push(route, lane, handle, &end, 1u, ctx->batch_buf)
        && !s_retry_save_or_drop(route, ctx, conn, rx, handle, &end, 1u, rx->posted_off))
        return;
    duct_conn_wire_rebind(route, conn);
}
