/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin П */

/** @file duct_olb_tx.h
 *  @brief Transmit-side descriptor ring: the byte arena is gone, a record is a
 *  32-byte descriptor and the payload rides where its author built it.
 *
 *  The worker stage stages @b descriptors — one @c duct_tx_desc_t per wire
 *  record, its inline header and a @c duct_span_t naming the payload — and
 *  publishes them through @c tail. The io thread gathers iovecs straight from
 *  the sources (@c duct_olb_tx_peek_iov), advances a byte cursor inside the
 *  head record on a short write, and unpins a span only at its record's full
 *  completion (§5.2's stepper: @c duct_olb_tx_advance).
 *
 *  The byte area shrank, it did not vanish (§2.1): a @b materialize arena
 *  beside the descriptors carries what cannot ride a reference — sealed
 *  ciphertext (the encrypt destination), vnet GSO prefixes and sub-threshold
 *  copies. It is a byte ring of its own, freed in record completion order.
 *
 *  Ordering is unchanged: descriptors publish behind the @c tx_seq tickets,
 *  and the public metrics keep counting logical wire bytes — @c stream_end is
 *  the conn's byte-stream end, @c drained the position io has completed up
 *  to, so @c duct_olb_tx_published answers the bytes queued ahead of io
 *  without distortion (§2.2: pacing and AQM estimators read logical wire
 *  bytes, while admission checks @c byte_cap and descriptor occupancy both).
 *
 *  @c head is io's, with one exception: a worker that sent part of its own
 *  staged, still-unpublished records directly settles that with io through
 *  @ref duct_olb_tx_advance_worker — it only ever completes records io has
 *  never seen, past @c tail, so the two writers never touch the same value.
 */

#ifndef DUCT_OLB_TX_H
#define DUCT_OLB_TX_H

#include "duct_olb.h"
#include "duct_span.h"
#include "duct_wire.h"
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

/** @brief Divisor of the byte budget giving the coarse backpressure floor
 *  while no protocol frame budget is known. */
static constexpr unsigned olb_tx_compact_div = 8u;

/** @name The tx region's split, out of the build's TX capacity
 *  The descriptor area and the materialize arena share the bytes the carve's
 *  tx region serves: half the records a 32-byte descriptor each can fill the
 *  ring with, half the §2.1 byte area. The region's placement — where inside
 *  the conn block those bytes sit — is @c duct_conn_block.h's; these two are
 *  the ring's own shape, every cursor arithmetic reading them.
 *  @{
 */
static constexpr uint32_t duct_conn_tx_mat_cap = (uint32_t)(duct_conn_tx_olb_cap / 2u);
static constexpr uint32_t duct_conn_tx_desc_n =
    (uint32_t)((duct_conn_tx_olb_cap - duct_conn_tx_mat_cap)
               / (2u * (uint32_t)sizeof(duct_span_t)));
/** @} */

/** @brief Outcome of a stage request. */
typedef enum duct_olb_tx_result : uint8_t {
    olb_tx_ok = 0,      /**< The record was staged. */
    olb_tx_full,        /**< Not enough room right now: io has not completed
                          *  enough, and the byte budget or the descriptor
                          *  count has no headroom — backpressure, not loss. */
    olb_tx_too_large,   /**< The bytes can never fit; they exceed the byte
                          *  budget or the materialize arena outright. */
    olb_tx_result_count /**< Size sentinel. */
} duct_olb_tx_result_t;

/** @brief One staged wire record: a span naming the payload where its author
 *  built it, plus the inline wire header — 32 bytes whole, two descriptors per
 *  cache line (§2.1). @c hdr_len and the dgram @c gso flag ride the span's own
 *  spare bits, so the record's length is @c duct_span_wire_len and the
 *  datagram record header with its backfilled length dies. */
typedef struct duct_tx_desc {
    duct_span_t span;                      /**< The payload reference. */
    uint8_t     hdr[wire_tx_hdr_max];      /**< The inline wire header. */
} duct_tx_desc_t;

static_assert(sizeof(duct_tx_desc_t) == 2u * sizeof(duct_span_t),
              "a descriptor is exactly 32 bytes: no field may grow it");

/** @brief A snapshot of the staging state.
 *  Taken so a caller can later rewind to it, or measure what happened since. */
typedef struct duct_olb_tx_mark {
    uint64_t tail;    /**< The published tail at the time the mark was taken. */
    uint32_t stage;   /**< The staged-record count then. */
    uint64_t mat_tail;/**< The materialize arena's write position then. */
    uint32_t bytes;   /**< Staged wire bytes then. */
} duct_olb_tx_mark_t;

/** @brief The transmit-side descriptor ring.
 *  The first own line is the staging worker's: the commit tickets, the byte
 *  budget, the staged-bytes accumulator with the materialize cursor, the
 *  stream end, the TX-wait target and the members @c duct_x_sock_stats_fields
 *  adds. The next two are io's: the completion counters the worker's
 *  admission reads (@c drained, @c mat_head, the head record's byte cursor)
 *  with @c write_armed, then the members @c duct_x_sock_tx_fields adds for
 *  the socket's send state, which a worker's direct write reads.
 */
duct_olb_decl(duct_olb_tx,
    uint32_t tx_seq_next;  /**< Next commit ticket to issue on this ring.
                            *  Monotonic, never decremented —
                            *  worker-exclusive. */

    uint32_t tx_seq_serve; /**< Ticket currently allowed to publish.
                            *  A commit whose own ticket does not
                            *  match must wait its turn regardless
                            *  of room, preserving request order on
                            *  this ring's one wire; advances only
                            *  when the ticket ahead of it actually
                            *  resolves (success or terminal
                            *  failure), never on a still-blocked
                            *  retry. */

    uint32_t byte_cap;     /**< The ring's logical wire-byte budget (§2.2's
                            *  tx_byte_cap): the pinned and materialized bytes
                            *  of every unfinished record, staged ones
                            *  included, stay under it. The carve sets it from
                            *  the protocol's per-conn capacity, so admission
                            *  checks it beside the descriptor count and the
                            *  pacing and AQM estimators read the logical wire
                            *  bytes undistorted. */

    uint32_t staged_bytes; /**< Wire bytes staged but not yet published.
                            *  Joins @c stream_end in the budget arithmetic;
                            *  @ref duct_olb_tx_publish folds it into
                            *  @c stream_end. Worker exclusive. */

    uint64_t mat_tail;     /**< The materialize arena's write position, bytes
                            *  from the arena's base, monotonic. Worker
                            *  exclusive; @c duct_olb_tx_mat_open writes it,
                            *  @ref duct_olb_tx_unmark rewinds it. */

    uint64_t stream_end;   /**< End of the conn's byte stream, logical wire
                            *  bytes: every record published and every byte the
                            *  worker wrote to the socket past the ring. Moved
                            *  by @ref duct_olb_tx_publish,
                            *  @ref duct_olb_tx_sent_staged and
                            *  @ref duct_olb_tx_advance_worker alone. */

    duct_x_sock_stats_fields

    /** @brief Drained-position target at which a refused TX room wait
     *  resolves; 0 while unarmed. The worker's single-writer value latch (§6):
     *  a turn the ring refused — admission, an engine park flush, a parked
     *  retry node — stores the monotonic wire position it waits for (release)
     *  ahead of a @c seq_cst fence and then re-checks its room condition. Io,
     *  on each completion advance @c prev → @c new, fences, loads this word
     *  and wakes the conn's worker strictly on the crossing edge @c prev <
     *  T ≤ @c new — no bit, no clear, no RMW, and no disarm write on wake: the
     *  drained position is monotonic, so a spent target can never cross
     *  again. The next arm overwrites with a fresh target computed past the
     *  current position; a lane conn arms here too, its zeroed ring words
     *  yielding the "any signal" form the device wake takes. */
    uint64_t _Atomic resume_at;

    duct_cacheline_struct(
        uint64_t _Atomic drained; /**< Wire bytes fully completed, from the
                                    *  stream's start — whoever completed
                                    *  them: io's stepper over the published
                                    *  records, the worker's over its own
                                    *  still-staged ones, the close paths'
                                    *  purge over what it drops. All through
                                    *  @c duct_olb_tx_complete_one's one
                                    *  fetch-add, so the adds never lose one
                                    *  another; the worker's admission and
                                    *  the public queued metric read it. */

        uint64_t _Atomic mat_head; /**< The materialize arena's free position,
                                    *  bytes from the arena's base, monotonic:
                                    *  what record completions have handed
                                    *  back. Io writes; the worker's arena
                                    *  room reads it. Never past @c mat_tail. */

        uint32_t _Atomic cursor_off; /**< Bytes of the head record already
                                       *  sent, its inline header first —
                                       *  §5.2's stepper cursor inside the
                                       *  record the head names. Zero while
                                       *  the record is untouched; a short
                                       *  write advances it without copying
                                       *  any tail, and the record's
                                       *  completion (its span's unpin with
                                       *  it) waits for the cursor to reach
                                       *  @c duct_span_wire_len. Atomic plain
                                       *  word: io writes it inside published
                                       *  records, the worker inside its own
                                       *  still-staged ones — the tail publish
                                       *  orders the hand-off, and the two
                                       *  writers never touch the same
                                       *  record's cursor. */

        uint8_t _Atomic write_armed; /**< Current write-interest state for
                                       *  reactive backend registration, 1 while
                                       *  the io thread holds the socket armed —
                                       *  same contract as @c
                                       *  duct_listener_t::dgram_tx_write_armed.
                                       *  Io-written (plain store — the one
                                       *  writer) on this its own line; the
                                       *  worker-side TX fast path reads it as a
                                       *  stale-tolerant hint and falls back to
                                       *  the io drain on a stale 1. iocp never
                                       *  touches it. */

        duct_x_sock_tx_fields
    );
);

static_assert(offsetof(duct_olb_tx_t, drained)
                  == sizeof(duct_olb_hdr_t) + duct_cacheline_size,
    "the staging worker's own fields — the platform's sock-stats members"
    " padded within it — fill exactly one line past the common header,"
    " io's completion lines starting CL-aligned behind them");
static_assert(sizeof(duct_olb_tx_t) % duct_cacheline_size == 0u,
    "the TX ring header ends on a cache-line boundary");

/** @brief The ring's logical wire-byte budget (§2.2's tx_byte_cap). */
duct_nonnull(1) static inline uint32_t
duct_olb_tx_byte_cap(const duct_olb_tx_t *tx)
{
    return tx->byte_cap;
}

/** @brief Records a packed cursor stands past, generations included. */
static inline uint64_t
duct_olb_tx_unrolled(uint64_t packed)
{
    return olb_gen(packed) * (uint64_t)duct_conn_tx_desc_n + olb_off(packed);
}

/** @brief Pack an unrolled record position back into cursor form. */
static inline uint64_t
duct_olb_tx_packed(uint64_t unrolled)
{
    return olb_pack((uint32_t)(unrolled / duct_conn_tx_desc_n),
                    (uint32_t)(unrolled % duct_conn_tx_desc_n));
}

/** @brief Bytes queued ahead of io: published but not completed. The logical
 *  wire-byte metric the public queued figures read (§2.2). */
duct_nonnull(1) static inline size_t
duct_olb_tx_published(const duct_olb_tx_t *tx)
{
    return (size_t)(tx->stream_end
                    - duct_atomic_load(&tx->drained, acquire));
}

/** @brief Stream offset io and the worker have handed the socket up to, bytes. */
duct_nonnull(1) static inline uint64_t
duct_olb_tx_drained(const duct_olb_tx_t *tx)
{
    return duct_atomic_load(&tx->drained, acquire);
}

/** @brief Stream offset of the staging cursor, bytes: what a full publish or
 *  worker-side send of everything staged would move @c stream_end to. */
duct_nonnull(1) static inline uint64_t
duct_olb_tx_stream_pos(const duct_olb_tx_t *tx)
{
    return tx->stream_end + tx->staged_bytes;
}

/** @brief Wire bytes the budget holds right now: queued ahead of io plus the
 *  staged-but-unpublished ones. The admission arithmetic's byte limb. */
duct_nonnull(1) static inline size_t
duct_olb_tx_bytes_held(const duct_olb_tx_t *tx)
{
    return (size_t)(duct_olb_tx_stream_pos(tx)
                    - duct_atomic_load(&tx->drained, acquire));
}

/** @brief Descriptors the ring holds right now: published and unfinished plus
 *  the staged-but-unpublished ones. The admission arithmetic's count limb. */
duct_nonnull(1) static inline uint64_t
duct_olb_tx_descs_held(const duct_olb_tx_t *tx)
{
    auto h = &tx->h;
    return duct_olb_tx_unrolled(duct_atomic_load(&h->tail, relaxed))
         + duct_atomic_load(&h->stage, relaxed)
         - duct_olb_tx_unrolled(duct_atomic_load(&h->head, relaxed));
}

/** @brief The coarse backpressure floor the byte budget derives (§2.2:
 *  @c min_room re-derived against the byte budget, no stored field). */
duct_nonnull(1) static inline size_t
duct_olb_tx_min_room(const duct_olb_tx_t *tx)
{
    return tx->byte_cap / olb_tx_compact_div;
}

/** @brief True when the bytes the budget holds have eaten the coarse
 *  backpressure floor's headroom. */
duct_nonnull(1) static inline bool
duct_olb_tx_backpressure(const duct_olb_tx_t *tx)
{
    return duct_olb_tx_bytes_held(tx) + duct_olb_tx_min_room(tx) > tx->byte_cap;
}

/** @brief Room for one more record of @p need wire bytes: a free descriptor
 *  and the byte budget's headroom both (§2.2's admission limbs). */
duct_nonnull(1) static inline bool
duct_olb_tx_room_contig(const duct_olb_tx_t *tx, size_t need)
{
    if (need > tx->byte_cap)
        return false;
    if (duct_olb_tx_descs_held(tx) >= duct_conn_tx_desc_n)
        return false;
    return duct_olb_tx_bytes_held(tx) + need <= tx->byte_cap;
}

/** @brief Take a snapshot of the staging state. */
duct_nonnull(1) static inline duct_olb_tx_mark_t
duct_olb_tx_mark(const duct_olb_tx_t *tx)
{
    return (duct_olb_tx_mark_t){
        .tail = duct_atomic_load(&tx->h.tail, relaxed),
        .stage = duct_atomic_load(&tx->h.stage, relaxed),
        .mat_tail = tx->mat_tail,
        .bytes = tx->staged_bytes,
    };
}

/** @brief Rewind the staging cursors back to @p mark.
 *  Records staged since the mark die unpublished — their spans' references
 *  the caller drops first — and the materialize arena's writes with them. */
duct_nonnull(1) static inline void
duct_olb_tx_unmark(duct_olb_tx_t *tx, duct_olb_tx_mark_t mark)
{
    auto h = &tx->h;
    duct_atomic_store(&h->tail, mark.tail, relaxed);
    duct_atomic_store(&h->stage, mark.stage, relaxed);
    tx->mat_tail = mark.mat_tail;
    tx->staged_bytes = mark.bytes;
}

/** @brief Count @p n wire bytes into the staged records' budget arithmetic. */
duct_nonnull(1) static inline void
duct_olb_tx_staged_bytes_add(duct_olb_tx_t *tx, uint32_t n)
{
    tx->staged_bytes += n;
}

/** @brief Publish the staged records into tail.
 *  Makes them visible to io and moves @c stream_end past their bytes. The
 *  fold runs even over a window the worker already completed itself
 *  (@c duct_olb_tx_advance_worker left nothing to publish): those bytes ride
 *  the completions' drained advance, and the stream end must take them too
 *  or the held metrics underflow. */
duct_nonnull(1) static inline void
duct_olb_tx_publish(duct_olb_tx_t *tx)
{
    auto h = &tx->h;
    tx->stream_end += tx->staged_bytes;
    tx->staged_bytes = 0u;
    uint32_t staged = duct_atomic_load(&h->stage, relaxed);
    if (!staged)
        return;
    uint64_t tail = duct_olb_tx_unrolled(duct_atomic_load(&h->tail, relaxed));
    duct_atomic_store(&h->tail, duct_olb_tx_packed(tail + staged), release);
    duct_atomic_store(&h->stage, 0u, relaxed);
}

/** @brief True while @p tx's io thread holds the socket armed for write
 *  readiness. Worker-side stale-tolerant hint read. */
duct_nonnull(1) static inline bool
duct_olb_tx_write_armed(const duct_olb_tx_t *tx)
{
    return duct_atomic_load(&tx->write_armed, relaxed);
}

/** @brief Record @p tx's write-interest state. Io thread only. */
duct_nonnull(1) static inline void
duct_olb_tx_write_armed_set(duct_olb_tx_t *tx, bool armed)
{
    duct_atomic_store(&tx->write_armed, armed, relaxed);
}

/** @brief True when the completion shift @p prev → @p new crosses the armed
 *  wait target @p target: strictly the edge @c prev < T ≤ @c new, the
 *  unarmed zero never crossing. The one expression both io's completion wake
 *  and the edge tests answer the crossing by. */
static inline bool
duct_olb_tx_wait_crossed(uint64_t prev, uint64_t new, uint64_t target)
{
    return target != 0u && prev < target && new >= target;
}

/** @brief Arm @p tx's TX room wake at @p target.
 *  The store publishes first, the @c seq_cst fence pairs with io's
 *  post-completion load, and the caller re-checks its room condition after
 *  this returns: either that recheck sees the room io freed, or io sees the
 *  target and its next completion crosses it. Staging worker only. */
duct_nonnull(1) static inline void
duct_olb_tx_wait_arm(duct_olb_tx_t *tx, uint64_t target)
{
    duct_atomic_store(&tx->resume_at, target, release);
    atomic_thread_fence(memory_order_seq_cst);
}

/** @brief Drained-position target at which the staging worker's TX room wait
 *  resolves — the value @c resume_at carries while armed.
 *
 *  @p need names the wire bytes a refused @c duct_olb_tx_room_contig check
 *  demanded; 0 falls to the coarse form, the backpressure floor. The target is
 *  the exact flip point of the byte limb, clamped one past the current
 *  drained position, so an armed word always names a position io has not
 *  reached — a target behind it never crosses, and the caller's own post-arm
 *  recheck answers the room io already freed.
 *  Staging worker only. */
duct_nonnull(1) static inline uint64_t
duct_olb_tx_wait_target(duct_olb_tx_t *tx, size_t need)
{
    size_t room = need ? need : duct_olb_tx_min_room(tx);
    uint64_t held = duct_olb_tx_bytes_held(tx),
             drained = duct_atomic_load(&tx->drained, acquire);
    /* The budget frees its headroom once drained reaches held + room - cap;
     * a deficit already covered resolves at the very next completion. */
    uint64_t target = held + room > tx->byte_cap
                    ? drained + (held + room - tx->byte_cap) : drained + 1u;
    return target > drained ? target : drained + 1u;
}

#ifdef __cplusplus
}
#endif

#endif /* DUCT_OLB_TX_H */
