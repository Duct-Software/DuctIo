/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_olb_rx.h
 *  @brief Receive-side buffer: allocation, io read policy, worker drain glue.
 *
 *  The io thread writes incoming bytes into the buffer and publishes them
 *  through @c tail. The worker thread reads frames out of it and
 *  acknowledges them through @ref duct_olb_rx_ack.
 */

#ifndef DUCT_OLB_RX_H
#define DUCT_OLB_RX_H

#include "duct_olb.h"
#include "duct_xsock.h"

#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Divisor giving @c recv_threshold from @c buf_size while no frame
 *  budget is known. */
static constexpr unsigned olb_rx_compact_div = 8u;

/** @brief Multiplier turning a protocol's frame budget into
 *  @c recv_threshold. */
static constexpr unsigned olb_rx_th_factor = 2u;

/** @brief Divisor capping @c recv_threshold against @c buf_size. */
static constexpr unsigned olb_rx_th_div = 2u;

/** @brief Divisor of @c recv_threshold a read settles for once compaction
 *  has been ruled out. */
static constexpr unsigned olb_rx_relax_div = 2u;

/** @brief Outcome of a receive-space request. */
typedef enum duct_olb_rx_result : uint8_t {
    olb_rx_ok,           /**< Enough space was already available. */
    olb_rx_compacted,    /**< Not enough space, but compaction freed enough. */
    olb_rx_full,         /**< Not enough space even after compacting. */

    /** @note Add custom results before this one. */
    olb_rx_result_count  /**< Size sentinel. */
} duct_olb_rx_result_t;

/** @brief The receive-side buffer.
 *
 *  Its leading cache lines hold fields only the io thread touches, the
 *  socket's receive state @c duct_x_sock_rx_fields adds among them. The line
 *  after them holds the fields both threads use to hand bytes and
 *  acknowledgments back and forth, kept on its own line so the worker's
 *  per-frame write to @c acked cannot force the io thread's own fields out
 *  of cache.
 */
duct_olb_decl(duct_olb_rx,
    size_t _Atomic recv_threshold; /**< Free bytes the io thread wants
                                     *  before it tries to compact / expand
                                     *  the buffer. Set once at wire bind.
                                     *  Io-thread only. */

    size_t      recv_hint;   /**< Minimum bytes needed to finish the
                               *  frame the wire is midway through parsing,
                               *  or 0 if the wire has no such requirement.
                               *  Io-thread only. */

    uint32_t    posted_off;  /**< How far into the buffer the io thread has
                               *  already posted frames to the worker.
                               *  Bytes before this offset are never
                               *  re-parsed. Resets to 0 on compaction and
                               *  when a new pass opens. Io-thread only. */

    uint32_t    read_unit;   /**< Largest span one read into this buffer needs,
                               *  bytes: the record prefix plus whichever is
                               *  bigger, the wire's own frame bound or the size
                               *  the socket coalesces to. Fixed at wire bind,
                               *  which is where the kernel's answer about
                               *  coalescing is known. Zero until then, and for
                               *  the whole life of a conn whose protocol
                               *  carries no wire, which leaves its reader
                               *  demanding the whole buffer. */

    uint32_t    group_off,   /**< Ring offset of a coalesced read's first
                               *  undescribed byte. Those bytes are staged with
                               *  no record prefix, so the parse loop cuts them
                               *  into frames itself. */

                group_seg,   /**< Segment size the coalesced read was cut at,
                               *  bytes. Every datagram in that tail is this
                               *  long, the last free to be shorter. */

                group_bytes; /**< Bytes of that tail still undescribed. Zero
                               *  means no coalesced tail is pending, and gates
                               *  every read of @c group_off and
                               *  @c group_seg. */

    uint64_t    pass_base;   /**< Ack total at the start of the oldest live
                               *  pass. Ack totals past it map onto buffer
                               *  offsets from 0 while no held frame breaks
                               *  their order, each short of its offset by
                               *  the bytes @c skip counts before it.
                               *  Io-thread only. */

    uint32_t    pass_end,    /**< End of the older pass while a second one
                               *  runs from offset 0; 0 when one pass is
                               *  live. Io-thread only. */

                pass_free;   /**< Bytes of the older pass the worker has
                               *  released, the bound of the second pass.
                               *  Meaningful only while @c pass_end is
                               *  nonzero. Io-thread only. */

    uint32_t    skip;        /**< Bytes a discard counted as posted without
                               *  handing them to the worker, since the last
                               *  compaction. Every ack total the buffer
                               *  computes leaves them out. Io-thread only. */

    duct_x_sock_rx_fields
#if DUCT_RUNTIME_STATS
    uint64_t    memmove_compacts, /**< Number of compactions that
                                    *  actually moved bytes, because some
                                    *  unparsed tail was still in the
                                    *  buffer. */

                early_compacts;   /**< Number of compactions that ran
                                    * opportunistically, while free
                                    * space was low but not yet
                                    * exhausted. */
#endif
    duct_cacheline_struct(
        /** @brief Total bytes the worker has fully consumed.
         *  Advanced exclusively by the worker after every frame; compaction
         *  rebases @c pass_base while leaving this monotonic total intact.
         *  Folded into @c head in @ref duct_olb_rx_ack_apply.
         */
        uint64_t _Atomic acked;

        /** @brief Number of frames a stream handler still holds a live
         *  pointer into. A frame counts here from dispatch until the
         *  handler parks, finishes, fails, or is cancelled. While this is
         *  above zero neither compaction runs nor a new pass opens.
         */
         uint32_t _Atomic held_frames;

        /** @brief Buffer offset past the frame the worker dispatched last,
         *  in that frame's pass. An earlier frame of the pass is never read
         *  again, even by a deferred retry. Resets to 0 on compaction.
         */
        uint32_t _Atomic dispatch_frontier;

        /** @brief Ack total at which a latched read resumes.
         *  Stored by the io thread from @ref duct_olb_rx_resume_total before
         *  it latches @c fl_conn_rx_full; the worker ack that brings
         *  @c acked to it reposts the read. Read only while that latch is
         *  set.
         */
        uint64_t _Atomic resume_at;

        uint64_t _Atomic roam_at,   /**< Ack total past the datagram that
                                      *  proposed the conn's candidate
                                      *  address. Stored by the io thread
                                      *  before it raises @c fl_conn_roaming,
                                      *  read by the worker under that flag.
                                      *  A rewind, a compaction or a pass
                                      *  change leaves it naming that
                                      *  datagram. */

                         accept_at; /**< @c acked as of the latest frame the
                                      *  protocol accepted with @c acked at or
                                      *  past @c roam_at. Stored by the worker
                                      *  before it posts @c fl_req_peer_roam. */

        /** @brief Answer to one of this conn's frames waiting parked, which
         *  holds the dispatch of the next.
         *  Zero, as a fresh ring holds it, is none. Worker only.
         */
        duct_tx_hold_t tx_hold;
    );
);

static_assert(offsetof(duct_olb_rx_t, acked) % duct_cacheline_size == 0u,
    "duct_olb_rx_t::acked must start on a cache-line boundary");

/** @brief Initialize @c recv_threshold for a freshly allocated buffer.
 *  Uses @c buf_size divided by @ref olb_rx_compact_div, the value that
 *  stands until a protocol's frame budget replaces it.
 */
duct_nonnull(1) static inline void duct_olb_rx_cold_init(duct_olb_rx_t *rx)
{
    duct_atomic_store(&rx->recv_threshold,
                      rx->h.buf_size / olb_rx_compact_div,
                      relaxed);
}

/** @brief Allocate a new receive buffer of the given @p capacity. */
static inline duct_olb_rx_t *duct_olb_rx_new(size_t capacity)
{
    return duct_olb_new(duct_olb_rx_t, capacity, duct_olb_rx_cold_init);
}

/** @brief Current compaction threshold, bytes. */
duct_nonnull(1) static inline size_t
duct_olb_rx_threshold_get(const duct_olb_rx_t *rx)
{
    return duct_atomic_load(&rx->recv_threshold, relaxed);
}

/** @brief Set the largest span one read needs, and the compaction threshold
 *  that has to clear it.
 *
 *  Both come from @p frame_budget, so they cannot disagree: a reserve demanding
 *  more than the threshold admits is a read loop waiting on a compaction
 *  nothing triggers. The threshold is @p frame_budget × @c olb_rx_th_factor,
 *  capped at @c buf_size ÷ @c olb_rx_th_div; a @p frame_budget of 0 falls back
 *  to @c buf_size ÷ @c olb_rx_compact_div and leaves the read span unset.
 */
duct_nonnull(1) static inline void
duct_olb_rx_threshold_set(duct_olb_rx_t *rx, size_t frame_budget)
{
    rx->read_unit = (uint32_t)frame_budget;
    size_t th_max = rx->h.buf_size / olb_rx_th_div,
           th = frame_budget
              ? frame_budget * olb_rx_th_factor
              : rx->h.buf_size / olb_rx_compact_div;
    if (th > th_max)
        th = th_max;
    duct_atomic_store(&rx->recv_threshold, th, relaxed);
}

/** @brief Set how many more bytes the wire parser needs to finish
 *  the frame it is currently midway through. Call with @p hint == 0
 *  to clear the requirement once the wire has caught up.
 */
duct_nonnull(1) static inline void
duct_olb_rx_recv_hint_set(duct_olb_rx_t *rx, size_t hint)
{
    rx->recv_hint = hint;
}

/** @brief Bytes the wire parser still needs to finish its current frame.
 *  @return 0 when the wire has no pending requirement.
 */
duct_nonnull(1) static inline size_t
duct_olb_rx_recv_hint_get(const duct_olb_rx_t *rx)
{
    return rx->recv_hint;
}

/** @brief Abandon the unparsed bytes from @c posted_off up to @p upto.
 *  They count as posted and add to @c skip, which keeps them out of every ack
 *  total, so a latched read waits for no ack of theirs. They stay where they
 *  are: an iocp read in flight past @c stage still lands where it was posted.
 *  The coalesced tail and the parser's pending-frame hint go with them.
 */
duct_nonnull(1) static inline void
duct_olb_rx_discard(duct_olb_rx_t *rx, size_t upto)
{
    rx->skip += (uint32_t)(upto - rx->posted_off);
    rx->posted_off = (uint32_t)upto;
    rx->group_bytes = 0u;
    rx->recv_hint = 0u;
}

/** @brief Move head forward to match the worker's acked count.
 *  @return true if head actually advanced.
 */
duct_nonnull(1) static inline bool
duct_olb_rx_ack_apply(duct_olb_rx_t *rx)
{
    auto h = &rx->h;
    uint64_t ack  = duct_atomic_load(&rx->acked, acquire),
             head = duct_atomic_load(&h->head, relaxed);
    if (ack <= head)
        return false;
    duct_atomic_store(&h->head, ack, relaxed);
    return true;
}

/** @brief Compute the ack total at which every byte before @p off in the
 *  current pass is acked.
 *  @p off lies at or past @c posted_off. The total a staged byte gets stays
 *  the same through a rewind, a compaction, a new pass and the older one
 *  retiring; a discard lowers it by the bytes it skips ahead of that byte.
 */
duct_nonnull(1) static inline uint64_t
duct_olb_rx_total_at(const duct_olb_rx_t *rx, size_t off)
{
    return rx->pass_base + rx->pass_end + off - rx->skip;
}

/** @brief Compute the ack total at which every posted byte is acked.
 *  The older live pass whole, plus the current one up to @c posted_off, less
 *  the bytes @c skip counts. */
duct_nonnull(1) static inline uint64_t
duct_olb_rx_posted_total(const duct_olb_rx_t *rx)
{
    return duct_olb_rx_total_at(rx, rx->posted_off);
}

/** @brief Compact the buffer.
 *  Discards everything before @p boundary and slides the rest down. Every
 *  byte before @p boundary is consumed, as @ref duct_olb_rx_consumed answers,
 *  and @p boundary is at or before @c posted_off, so no relocated byte is
 *  still referenced. The pass accounting restarts as one pass at the current
 *  ack total. @p out_ptr is set to the write position after compaction.
 *
 *  @return Free bytes available at @p out_ptr.
 */
duct_nonnull(1, 3) static inline size_t
duct_olb_rx_compact(duct_olb_rx_t *rx, uint64_t boundary, uint8_t **out_ptr)
{
    auto h = &rx->h;
    size_t partial = h->stage > boundary ? (size_t)(h->stage - boundary) : 0u;
    if (partial && boundary) {
        memmove(rx->data, rx->data + (size_t)boundary, partial);
        duct_rtstat_inc(rx->memmove_compacts, 1u);
    }
    h->stage = partial;
    rx->recv_hint = 0u;
    rx->posted_off = 0u;
    /* group_off slides by boundary distance. */
    if (rx->group_bytes)
        rx->group_off -= (uint32_t)boundary;
    rx->pass_base = duct_atomic_load(&h->head, relaxed);
    rx->pass_end = 0u;
    rx->skip = 0u;
    duct_atomic_store(&rx->dispatch_frontier, 0u, relaxed);
    duct_atomic_store(&h->tail, partial, release);
    *out_ptr = rx->data + partial;
    return h->buf_size - partial; /* partial <= stage <= buf_size always */
}

/** @brief Tell whether the worker is done with every posted frame.
 *  Folds the worker's acks into @c head first, then needs all three: every
 *  posted byte acked; no @c held_frames pin, which @c s_hctx_rx_ack_only
 *  keeps past its ack; and @c dispatch_frontier at @c posted_off less the
 *  bytes @c skip counts, a frontier a handler reading its frame across yields
 *  holds back until it is done. Compaction moves or reuses posted bytes only
 *  then.
 */
duct_nonnull(1) static inline bool
duct_olb_rx_consumed(duct_olb_rx_t *rx)
{
    duct_discard duct_olb_rx_ack_apply(rx);
    return duct_atomic_load(&rx->h.head, relaxed) >= duct_olb_rx_posted_total(rx)
        && duct_atomic_load(&rx->held_frames, acquire) == 0u
        && (size_t)duct_atomic_load(&rx->dispatch_frontier, acquire) + rx->skip >= rx->posted_off;
}

/** @brief Count the bytes of the oldest live pass the worker is done with,
 *  from its start.
 *  The count is of acked bytes, at most the buffer offset it reaches: bytes a
 *  discard skipped behind that point leave it short.
 *  @return false while a held frame pins bytes the ack total already covers,
 *          since acks then stop mapping onto the front of the pass. On true,
 *          the second pass takes over once the count passes the end of the
 *          older one, and @p out_done counts from its start.
 */
duct_nonnull(1, 2) static inline bool
duct_olb_rx_done(duct_olb_rx_t *rx, size_t *out_done)
{
    duct_discard duct_olb_rx_ack_apply(rx);
    uint64_t head = duct_atomic_load(&rx->h.head, relaxed);
    if (duct_atomic_load(&rx->held_frames, acquire) != 0u)
        return false;
    uint64_t done = head - rx->pass_base;
    if (rx->pass_end && done >= rx->pass_end) {
        rx->pass_base += rx->pass_end;
        done -= rx->pass_end;
        rx->pass_end = 0u;
    }
    *out_done = (size_t)done;
    return true;
}

/** @brief Bytes the io thread may stage at the cursor in the current pass.
 *  Bounded by the older pass's released prefix while two passes are live, by
 *  the buffer end otherwise.
 */
duct_nonnull(1) static inline size_t
duct_olb_rx_room(const duct_olb_rx_t *rx)
{
    size_t lim = rx->pass_end ? rx->pass_free : rx->h.buf_size;
    return lim > rx->h.stage ? lim - rx->h.stage : 0u;
}

/** @brief Ack total at which a read latched for want of @p min_avail bytes
 *  resumes.
 *  With @p restart the target is the later of two points: room for the read
 *  released, and the worker down to one read of backlog, so the worker stays
 *  fed through the resume and each resume brings room for more than one
 *  read. The full drain, every posted byte acked, is the target without
 *  @p restart, with a coalesced tail pending, a frame held, or unposted bytes
 *  in a single pass, and caps the target otherwise.
 */
duct_nonnull(1) static inline uint64_t
duct_olb_rx_resume_total(const duct_olb_rx_t *rx, size_t min_avail, bool restart)
{
    uint64_t posted = duct_olb_rx_posted_total(rx);
    if (!restart || rx->group_bytes || duct_atomic_load(&rx->held_frames, relaxed)
        || (!rx->pass_end && rx->h.stage != rx->posted_off))
        return posted;
    uint64_t at = rx->pass_base + (rx->pass_end
                ? duct_min((size_t)rx->pass_end, (size_t)rx->h.stage + min_avail)
                : min_avail),
             low = posted > min_avail ? posted - min_avail : 0u;
    return duct_min(duct_max(at, low), posted);
}

/** @brief Find room in the buffer for the io thread's next read.
 *
 *  Low free space compacts the buffer once every posted frame is
 *  acknowledged, unheld and dispatched, and @p restart otherwise opens a
 *  second pass at offset 0 once the worker has released @p min_avail bytes
 *  from the front and every staged byte is posted; while two passes are live,
 *  only the room below the older pass's release point counts.
 *
 *  @p min_avail is the span the caller cannot proceed without. No success
 *  answer falls below it, the pending-frame hint and the relaxed
 *  half-threshold included.
 *
 *  @return @c olb_rx_ok when the free span sufficed,
 *          @c olb_rx_compacted when compaction or a new pass produced it,
 *          @c olb_rx_full when neither did. @p out_avail is written on every
 *          path; @p out_ptr, the stage cursor, on every path but the early
 *          @c olb_rx_full taken when @c buf_size minus @c stage underflows.
 */
duct_nonnull(1, 4, 5) static inline duct_olb_rx_result_t
duct_olb_rx_try_space(duct_olb_rx_t *rx, size_t min_avail, bool restart,
                      uint8_t **out_ptr, size_t *out_avail)
{
    assert(min_avail);
    auto h = &rx->h;
    size_t done = 0u;
    bool known = duct_olb_rx_done(rx, &done);
    if (rx->pass_end) {
        if (known && done > rx->pass_free)
            rx->pass_free = (uint32_t)done;
        *out_ptr = rx->data + h->stage;
        *out_avail = duct_olb_rx_room(rx);
        return *out_avail >= min_avail ? olb_rx_ok : olb_rx_full;
    }
    size_t threshold = duct_max(duct_olb_rx_threshold_get(rx), min_avail),
           hint = duct_olb_rx_recv_hint_get(rx);
    *out_avail = 0u;
    if (duct_ckd_sub(out_avail, h->buf_size, h->stage))
        return olb_rx_full;
    *out_ptr = rx->data + h->stage;
    if (*out_avail >= threshold)
        return olb_rx_ok;

    if (h->stage && duct_olb_rx_consumed(rx)) {
        *out_avail = duct_olb_rx_compact(rx, rx->posted_off, out_ptr);
        duct_rtstat_inc(rx->early_compacts, 1u);
        return *out_avail >= min_avail ? olb_rx_compacted : olb_rx_full;
    }

    if (hint && *out_avail >= duct_max(hint, min_avail))
        return olb_rx_ok;

    if (*out_avail >= duct_max(threshold / olb_rx_relax_div, min_avail))
        return olb_rx_ok;

    if (restart && known && done >= min_avail && h->stage == rx->posted_off
        && !rx->group_bytes) {
        rx->pass_end = h->stage;
        rx->pass_free = (uint32_t)done;
        h->stage = 0u;
        rx->posted_off = 0u;
        rx->recv_hint = 0u;
        duct_atomic_store(&h->tail, 0u, release);
        *out_ptr = rx->data;
        *out_avail = done;
        return olb_rx_compacted;
    }
    return olb_rx_full;
}

/** @brief Return a fully consumed buffer to offset 0.
 *  Acts only once every staged byte is posted and the worker is done with all
 *  of them, so no byte moves. A record-framed reserve calls it before each
 *  read, which keeps the whole buffer free for the next burst whenever the
 *  worker keeps up.
 */
duct_nonnull(1) static inline void
duct_olb_rx_rewind(duct_olb_rx_t *rx)
{
    auto h = &rx->h;
    if (!h->stage || rx->posted_off != h->stage || !duct_olb_rx_consumed(rx))
        return;
    uint8_t *ptr = nullptr;
    duct_discard duct_olb_rx_compact(rx, rx->posted_off, &ptr);
}

/** @brief Append @p len raw bytes at the stage cursor.
 *
 *  Carries bytes captured during accept-time protocol sniffing, which must
 *  be replayed into the buffer. The caller verifies the space beforehand
 *  through @ref duct_olb_rx_try_space; @ref duct_dgram_rx_append builds on
 *  this to add datagram framing.
 */
duct_nonnull(1) static inline void
duct_olb_rx_append_raw(duct_olb_rx_t *rx, const void *data, size_t len)
{
    if (!len)
        return;
    auto h = &rx->h;
    memcpy(rx->data + h->stage, data, len);
    duct_atomic_store(&h->tail, h->stage + len, release);
    h->stage += len;
}

/** @brief Add @p nbytes to the running total of consumed bytes.
 *
 *  Called by the worker thread as it acks a frame. Stores @c acked with
 *  release ordering, so once @ref duct_olb_rx_ack_apply's acquire-load
 *  observes the new value, the io thread is guaranteed to see everything the
 *  worker did with the frame's bytes before the ack.
 *  @return The new total.
 */
duct_nonnull(1) static inline uint64_t
duct_olb_rx_ack(duct_olb_rx_t *rx, size_t nbytes)
{
    uint64_t ack = duct_atomic_load(&rx->acked, relaxed) + (uint64_t)nbytes;
    duct_atomic_store(&rx->acked, ack, release);
    return ack;
}

#ifdef __cplusplus
}
#endif

#endif /* DUCT_OLB_RX_H */
