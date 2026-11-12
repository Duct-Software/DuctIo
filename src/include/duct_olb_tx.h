/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_olb_tx.h
 *  @brief Transmit-side buffer: allocation, worker pack glue, io flush.
 *
 *  The worker thread stages outgoing bytes and publishes them through
 *  @c tail. The io thread drains them through @ref duct_olb_tx_readable
 *  and @ref duct_olb_tx_advance.
 *
 *  @c head is io's, with one exception: a worker that sent part of its own
 *  span directly, before publishing it, settles that with io through
 *  @ref duct_olb_tx_advance_worker.
 *
 *  Staging runs in passes over the linear buffer. A pass ends where it stands
 *  once out of room, or once @ref duct_olb_tx_rewind_idle finds io drained up to it;
 *  the next starts at offset 0, bounded by io's head in the one before, which
 *  io drains to its end first. A frame never straddles two passes.
 *
 *  Every byte the worker hands on, published to io or written to the socket
 *  past the ring, lands on one byte stream, the one the socket carries:
 *  @c stream_end is its end and @ref duct_olb_tx_drained the point the socket
 *  has taken up to.
 */

#ifndef DUCT_OLB_TX_H
#define DUCT_OLB_TX_H

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


/** @brief Divisor giving @c min_room from @c buf_size while no frame budget
 *  is known. */
static constexpr unsigned olb_tx_compact_div = 8u;

/** @brief Multiplier turning a protocol's frame budget into @c min_room. */
static constexpr unsigned olb_tx_th_factor = 2u;

/** @brief Divisor capping @c min_room against @c buf_size. */
static constexpr unsigned olb_tx_th_div = 2u;

/** @brief Factor between a pass and the drained one after it that marks a drop
 *  in load.
 *  Passes within it keep their pages, so a steady load makes no system call. */
static constexpr unsigned olb_tx_trim_div = 8u;

/** @brief Outcome of a stage request. */
typedef enum duct_olb_tx_result : uint8_t {
    olb_tx_ok = 0,      /**< The bytes were staged. */
    olb_tx_full,        /**< Not enough room right now: io has not drained
                          *  enough, and no new pass can open either. */
    olb_tx_too_large,   /**< The bytes can never fit; they exceed @c buf_size
                          *  outright. */
    olb_tx_result_count /**< Size sentinel. */
} duct_olb_tx_result_t;

/** @brief A snapshot of the staging cursor.
 *  Taken so a caller can later rewind to it, or measure what happened since.
 */
typedef struct duct_olb_tx_mark {
    uint64_t staged;    /**< The packed staging cursor at the time the mark
                          *  was taken. @ref duct_olb_tx_unmark rewinds
                          *  staging back to this value. */
} duct_olb_tx_mark_t;

/** @brief The transmit-side buffer.
 *  The first line is the staging worker's, @c min_room aside, which io stores
 *  when it binds a wire; the members @c duct_x_sock_stats_fields adds for the
 *  socket's stats reads sit in it. The second holds what io touches besides
 *  @c head and @c tail in the shared header: @c pass_end, and the members
 *  @c duct_x_sock_tx_fields adds for the socket's send state, which a worker's
 *  direct write reads.
 */
duct_olb_decl(duct_olb_tx,
    size_t _Atomic min_room;  /**< The minimum free staging space the
                                *  worker wants, bytes.
                                *  @ref duct_olb_tx_backpressure reports
                                *  true once free space drops below this.
                                *  Zero disables backpressure reporting. */

    uint32_t stage_gen, /**< Pass counter: how many times staging has
                          *  restarted at offset 0. An offset repeats
                          *  every pass, so @c head and @c tail carry
                          *  this beside it.
                          *  Incremented by @ref duct_olb_tx_wrap. */

            tx_seq_next,  /**< Next commit ticket to issue on this
                            *  OLB. Monotonic, never decremented —
                            *  worker-exclusive. */

            tx_seq_serve; /**< Ticket currently allowed to publish.
                            *  A commit whose own ticket does not
                            *  match must wait its turn regardless
                            *  of free space, preserving request
                            *  order on this OLB's one wire; advances
                            *  only when the ticket ahead of it
                            *  actually resolves (success or terminal
                            *  failure), never on a still-blocked
                            *  retry. */

    uint32_t pass_free; /**< End of the span the current pass may stage
                          *  into, bytes. Never above the real bound: io's
                          *  offset while io still drains the previous
                          *  pass, @c buf_size otherwise. Refreshed from
                          *  @c head when a stage outgrows it. */

    uint64_t stream_end; /**< End of the conn's byte stream, bytes: every
                           *  byte published and every byte the worker
                           *  wrote to the socket past the ring. Moved by
                           *  @ref duct_olb_tx_publish,
                           *  @ref duct_olb_tx_sent_staged and
                           *  @ref duct_olb_tx_sent_direct alone. */

    duct_x_sock_stats_fields

    duct_cacheline_struct(
        uint32_t _Atomic pass_end; /**< End of the previous pass, bytes.
                                     *  Stored with release before the
                                     *  @c tail that opens the next pass;
                                     *  io loads it with acquire only while
                                     *  its head is one pass behind @c tail. */
        duct_x_sock_tx_fields
    );
);

static_assert(sizeof(duct_olb_tx_t) == sizeof(duct_olb_hdr_t) + 2u * duct_cacheline_size,
    "the TX ring header is the common header and two lines, the staging worker's and io's");

/** @brief Initialize @c min_room and @c pass_free for a freshly allocated
 *  buffer.
 *  @c min_room takes @c buf_size divided by @ref olb_tx_compact_div, the
 *  value that stands until a protocol's frame budget replaces it.
 */
duct_nonnull(1) static inline void
duct_olb_tx_cold_init(duct_olb_tx_t *tx)
{
    duct_atomic_store(&tx->min_room,
        tx->h.buf_size / olb_tx_compact_div, relaxed);
    tx->pass_free = (uint32_t)tx->h.buf_size;
}

/** @brief Allocate a new transmit buffer with the given byte capacity. */
static inline duct_olb_tx_t *duct_olb_tx_new(size_t capacity)
{
    return duct_olb_new(duct_olb_tx_t, capacity, duct_olb_tx_cold_init);
}

/** @brief Current @c min_room, bytes. */
duct_nonnull(1) static inline size_t
duct_olb_tx_min_room_get(const duct_olb_tx_t *tx)
{
    return duct_atomic_load(&tx->min_room, relaxed);
}

/** @brief Set min_room from the protocol's frame budget.
 *  The value is @c frame_budget × @c olb_tx_th_factor, capped at
 *  @c buf_size ÷ @c olb_tx_th_div. When @c frame_budget is 0,
 *  it falls back to @c buf_size ÷ @c olb_tx_compact_div.
 */
duct_nonnull(1) static inline void
duct_olb_tx_min_room_set(duct_olb_tx_t *tx, size_t frame_budget)
{
    size_t room_max = tx->h.buf_size / olb_tx_th_div,
           room = frame_budget
                ? frame_budget * olb_tx_th_factor
                : tx->h.buf_size / olb_tx_compact_div;
    if (room > room_max)
        room = room_max;
    duct_atomic_store(&tx->min_room, room, relaxed);
}

/** @brief Pack stage_gen and the current stage offset into one word. */
duct_nonnull(1) static inline uint64_t
duct_olb_tx_stage_packed(const duct_olb_tx_t *tx)
{
    auto h = &tx->h;
    return olb_pack(tx->stage_gen, (uint32_t)h->stage);
}

/** @brief Bytes from io's @p head_g up to packed position @p to_g.
 *  A @p to_g one pass ahead counts the older pass's rest through
 *  @c pass_end first. */
duct_nonnull(1) static inline size_t
duct_olb_tx_span_to(const duct_olb_tx_t *tx, uint64_t head_g, uint64_t to_g)
{
    size_t head = olb_off(head_g),
           to = olb_off(to_g);
    if (olb_gen(to_g) != olb_gen(head_g))
        return duct_atomic_load(&tx->pass_end, relaxed) - head + to;
    return to > head ? to - head : 0u;
}

/** @brief Bytes published but not yet drained by io. */
duct_nonnull(1) static inline size_t
duct_olb_tx_published(const duct_olb_tx_t *tx)
{
    auto h = &tx->h;
    uint64_t tail_g = duct_atomic_load(&h->tail, relaxed);
    return duct_olb_tx_span_to(tx, duct_atomic_load(&h->head, acquire), tail_g);
}

/** @brief Stream offset io and the worker have handed the socket up to, bytes.
 *  @c stream_end less the published bytes io has not drained. Staging worker
 *  only. */
duct_nonnull(1) static inline uint64_t
duct_olb_tx_drained(const duct_olb_tx_t *tx)
{
    return tx->stream_end - duct_olb_tx_published(tx);
}

/** @brief Stream offset of the staging cursor, bytes.
 *  @c stream_end plus the span staged and not yet published. Staging worker
 *  only. */
duct_nonnull(1) static inline uint64_t
duct_olb_tx_stream_pos(const duct_olb_tx_t *tx)
{
    uint64_t tail_g = duct_atomic_load(&tx->h.tail, relaxed);
    return tx->stream_end + duct_olb_tx_span_to(tx, tail_g, duct_olb_tx_stage_packed(tx));
}

/** @brief End of the span the current pass may stage into, given io's
 *  @p head_g.
 *  @c buf_size once io is in this pass or done with the previous one; io's
 *  offset in the previous pass while it still drains it.
 */
duct_nonnull(1) static inline size_t
duct_olb_tx_lim(const duct_olb_tx_t *tx, uint64_t head_g)
{
    size_t head = olb_off(head_g);
    return olb_gen(head_g) == tx->stage_gen
        || head >= duct_atomic_load(&tx->pass_end, relaxed)
         ? tx->h.buf_size : head;
}

/** @brief Bytes a new pass may take from offset 0, given io's @p head_g.
 *  Zero while io is still a pass behind, or while bytes are staged but not
 *  published: they open a frame, and a frame stays within one pass. The
 *  whole buffer once io has drained this pass, its head offset otherwise.
 */
duct_nonnull(1) static inline size_t
duct_olb_tx_wrap_room(const duct_olb_tx_t *tx, uint64_t head_g)
{
    auto h = &tx->h;
    if (olb_gen(head_g) != tx->stage_gen
        || h->stage != olb_off(duct_atomic_load(&h->tail, relaxed)))
        return 0u;
    size_t head = olb_off(head_g);
    return head >= h->stage ? h->buf_size : head;
}

/** @brief Open the next pass at offset 0, @p room bytes long.
 *  The pass end goes out before @c tail, so io drains the rest of the
 *  previous pass before it folds into this one. @p room comes from
 *  @ref duct_olb_tx_wrap_room.
 */
duct_nonnull(1) static inline void duct_olb_tx_wrap(duct_olb_tx_t *tx, size_t room)
{
    auto h = &tx->h;
    duct_atomic_store(&tx->pass_end, h->stage, release);
    ++tx->stage_gen;
    h->stage = 0u;
    tx->pass_free = (uint32_t)room;
    duct_atomic_store(&h->tail, olb_pack(tx->stage_gen, 0u), release);
}

/** @brief Bytes ready for io to drain, starting from @p out_head.
 *
 *  While @c head is one pass behind @c tail, the rest of the previous pass up
 *  to @c pass_end comes first, and @c head folds into @c tail's pass once that
 *  is drained. A @c head already past the @c tail this call loaded, a worker
 *  fold that raced it, answers 0. @p out_head is set to the offset io starts
 *  draining from.
 */
duct_nonnull(1, 2) static inline size_t
duct_olb_tx_readable(duct_olb_tx_t *tx, uint64_t *out_head)
{
    auto h = &tx->h;
    uint64_t tail_g = duct_atomic_load(&h->tail, acquire),
             head_g = duct_atomic_load(&h->head, relaxed);
    uint32_t gen = olb_gen(tail_g);
    for (;;) {
        size_t head = olb_off(head_g);
        *out_head = (uint64_t)head;
        if (olb_gen(head_g) == gen) {
            size_t tail = olb_off(tail_g);
            return tail > head ? tail - head : 0u;
        }
        if (olb_gen(head_g) != gen - 1u)
            return 0u;
        /* pass_end belongs to head's pass only while head has not moved: a
         * worker fold and a second pass in between store the next one's. */
        size_t end = duct_atomic_load(&tx->pass_end, acquire);
        uint64_t now = duct_atomic_load(&h->head, relaxed);
        if (now != head_g)
            head_g = now;
        else if (head < end)
            return end - head;
        /* Compare-exchange, not a plain store: this is the one write
         * @ref duct_olb_tx_advance_worker also makes, and whichever lands
         * second must not undo the other. Landing offset 0 over a worker
         * that already sent the front of the span replays those bytes. */
        else if (duct_atomic_cas(weak, &h->head, &head_g,
                                 olb_pack(gen, 0u), acq_rel, acquire))
            head_g = olb_pack(gen, 0u);
    }
}

/** @brief Mark @p nbytes as drained after a successful send. */
duct_nonnull(1) static inline void
duct_olb_tx_advance(duct_olb_tx_t *tx, size_t nbytes)
{
    auto h = &tx->h;
    uint64_t head_g = duct_atomic_load(&h->head, relaxed);
    duct_atomic_store(&h->head,
                      olb_pack(olb_gen(head_g), olb_off(head_g) + nbytes),
                      release);
}

/** @brief Account for @p sent bytes the worker sent itself off the front of
 *  its own staged, still-unpublished span.
 *
 *  The worker-side counterpart of @ref duct_olb_tx_advance.
 *  Folds @c head into @c stage_gen when io has not folded it yet,
 *  otherwise advances it in place. Only the fold can collide with io, and
 *  it compare-exchanges against the same expected value io's own fold in
 *  @ref duct_olb_tx_readable uses: exactly one lands, and the loser reads
 *  back a @c head already in @c stage_gen, which io then never rewrites.
 *
 *  Caller must hold: every published byte drained when its commit began, so
 *  io has no readable span, and no other advance can interleave.
 */
duct_nonnull(1) static inline void
duct_olb_tx_advance_worker(duct_olb_tx_t *tx, size_t sent)
{
    auto h = &tx->h;
    uint64_t head_g = duct_atomic_load(&h->head, acquire);
    while (olb_gen(head_g) != tx->stage_gen)
        if (duct_atomic_cas(weak, &h->head, &head_g,
                            olb_pack(tx->stage_gen, sent), acq_rel, acquire))
            return;
    duct_atomic_store(&h->head,
                      olb_pack(olb_gen(head_g), olb_off(head_g) + sent),
                      release);
}

/** @brief Buffer bytes io has nothing left to drain in.
 *  One stage takes only what @ref duct_olb_tx_align finds at the cursor, which
 *  the split between the end of a pass and the start of the next can make
 *  smaller.
 */
duct_nonnull(1) static inline size_t
duct_olb_tx_space(const duct_olb_tx_t *tx)
{
    return tx->h.buf_size - duct_olb_tx_published(tx);
}

/** @brief True when free staging space has dropped below @c min_room. */
duct_nonnull(1) static inline bool
duct_olb_tx_backpressure(const duct_olb_tx_t *tx)
{
    size_t min_room = duct_olb_tx_min_room_get(tx);
    return min_room && duct_olb_tx_space(tx) < min_room;
}

/** @brief Take a snapshot of the staging cursor. */
duct_nonnull(1) static inline duct_olb_tx_mark_t
duct_olb_tx_mark(const duct_olb_tx_t *tx)
{
    return (duct_olb_tx_mark_t){ .staged = duct_olb_tx_stage_packed(tx) };
}

/** @brief Make @p need bytes stageable at the cursor, opening the next pass
 *  when this one has no room left.
 *  @return false when @p need exceeds the buffer, or when this pass lacks
 *          the room and no new pass can take it: io still a pass behind,
 *          bytes staged but unpublished, or io's head too near offset 0.
 */
duct_nonnull(1) static inline bool
duct_olb_tx_align(duct_olb_tx_t *tx, size_t need)
{
    auto h = &tx->h;
    if (need > h->buf_size)
        return false;
    if (h->stage + need <= tx->pass_free)
        return true;
    uint64_t head_g = duct_atomic_load(&h->head, acquire);
    tx->pass_free = (uint32_t)duct_olb_tx_lim(tx, head_g);
    if (h->stage + need <= tx->pass_free)
        return true;
    size_t room = duct_olb_tx_wrap_room(tx, head_g);
    if (need > room)
        return false;
    duct_olb_tx_wrap(tx, room);
    return true;
}

/** @brief True when @p need bytes can be staged now.
 *  The answer @ref duct_olb_tx_align gives, without opening a pass.
 */
duct_nonnull(1) static inline bool
duct_olb_tx_room_contig(const duct_olb_tx_t *tx, size_t need)
{
    auto h = &tx->h;
    if (need > h->buf_size)
        return false;
    if (h->stage + need <= tx->pass_free)
        return true;
    uint64_t head_g = duct_atomic_load(&h->head, acquire);
    return h->stage + need <= duct_olb_tx_lim(tx, head_g)
        || need <= duct_olb_tx_wrap_room(tx, head_g);
}

/** @brief Stage bytes, opening the next pass first when this one is out of
 *  room.
 *
 *  Copies @p hdr (if non-null) immediately followed by @p data (if
 *  @p len is nonzero) as one all-or-nothing span.
 */
duct_nonnull(1) static inline duct_olb_tx_result_t
duct_olb_tx_stage(duct_olb_tx_t *tx, const uint8_t *hdr,
                  size_t hdr_size, const void *data, size_t len)
{
    auto h = &tx->h;
    size_t total = (hdr ? hdr_size : 0u) + len;
    if (total > h->buf_size)
        return olb_tx_too_large;
    if (!duct_olb_tx_align(tx, total))
        return olb_tx_full;
    auto off = tx->data + h->stage;
    if (hdr) {
        memcpy(off, hdr, hdr_size);
        off += hdr_size;
    }
    if (len)
        memcpy(off, data, len);
    h->stage += total;
    return olb_tx_ok;
}

/** @brief Reserve writable space at the staging cursor.
 *
 *  The caller writes directly into the returned span. Space must fit within
 *  the current pass without advancing past boundaries (@ref duct_olb_tx_align
 *  handles pass rollover).
 *
 *  @return Pointer to the reserved space;
 *          nullptr if @p len does not fit.
 */
duct_nonnull(1) static inline void *
duct_olb_tx_span_open(duct_olb_tx_t *tx, size_t len)
{
    auto h = &tx->h;
    if (len > h->buf_size)
        return nullptr;
    if (h->stage + len > tx->pass_free) {
        tx->pass_free = (uint32_t)duct_olb_tx_lim(tx, duct_atomic_load(&h->head, acquire));
        if (h->stage + len > tx->pass_free)
            return nullptr;
    }
    auto ptr = tx->data + h->stage;
    h->stage += len;
    return ptr;
}

/** @brief Publish the staging cursor into tail.
 *  Makes staged bytes visible to io and moves @c stream_end past them.
 */
duct_nonnull(1) static inline void
duct_olb_tx_publish(duct_olb_tx_t *tx)
{
    auto h = &tx->h;
    uint64_t stage_g = duct_olb_tx_stage_packed(tx);
    tx->stream_end += duct_olb_tx_span_to(tx, duct_atomic_load(&h->tail, relaxed), stage_g);
    duct_atomic_store(&h->tail, stage_g, release);
}

/** @brief Account for @p sent bytes the worker wrote to the socket past the ring.
 *  Moves @c stream_end alone. */
duct_nonnull(1) static inline void
duct_olb_tx_sent_direct(duct_olb_tx_t *tx, size_t sent)
{
    tx->stream_end += sent;
}

/** @brief Rewind the staging cursors back to mark.
 *  Does not touch the published tail. @p mark has to be taken in the current
 *  pass: one taken before @ref duct_olb_tx_align opened a new pass lies in a
 *  pass io may already be draining.
 */
duct_nonnull(1) static inline void
duct_olb_tx_unmark(duct_olb_tx_t *tx, duct_olb_tx_mark_t mark)
{
    auto h = &tx->h;
    tx->stage_gen = olb_gen(mark.staged);
    h->stage = olb_off(mark.staged);
}

/** @brief Bytes staged since @p mark was taken.
 *
 *  Assumes at most one wrap happened in between, which holds for one
 *  bounded @c on_pack call.
 */
duct_nonnull(1) static inline size_t
duct_olb_tx_staged_since(const duct_olb_tx_t *tx, duct_olb_tx_mark_t mark)
{
    auto now = duct_olb_tx_stage_packed(tx);
    return olb_gen(now) == olb_gen(mark.staged)
         ? olb_off(now) - olb_off(mark.staged)
         : olb_off(now);
}

/** @brief Overwrite @p size bytes ending at @p mark's position with
 *  @p data.
 *
 *  For writing a value that is only known after more data has already
 *  been staged, such as a length prefix: stage a placeholder, take a
 *  mark right after it, stage the payload, then call this once
 *  @ref duct_olb_tx_staged_since reports the payload's length.
 */
duct_nonnull(1, 3) static inline void
duct_olb_tx_backfill(duct_olb_tx_t *tx, duct_olb_tx_mark_t mark,
                     const void *data, size_t size)
{
    memcpy(tx->data + olb_off(mark.staged) - size, data, size);
}

/** @brief Account for the worker sending its whole staged, unpublished span
 *  itself, and rewind staging onto tail.
 *  @c stream_end moves past the span; the buffer's bytes stay as they are. */
duct_nonnull(1) static inline void
duct_olb_tx_sent_staged(duct_olb_tx_t *tx)
{
    auto h = &tx->h;
    uint64_t tail_g = duct_atomic_load(&h->tail, acquire);
    tx->stream_end += duct_olb_tx_span_to(tx, tail_g, duct_olb_tx_stage_packed(tx));
    tx->stage_gen = olb_gen(tail_g);
    h->stage = olb_off(tail_g);
}

/** @brief Report whether io has drained every published byte, and start a
 *  drained ring's next pass at offset 0.
 *  Bytes staged but not published keep their pass. A drained pass the one
 *  before outran by more than @c olb_tx_trim_div times gives the pages past
 *  its end, or past @c min_room where that lies further, back to the system.
 *  Staging worker only. */
duct_nonnull(1) static inline bool duct_olb_tx_rewind_idle(duct_olb_tx_t *tx)
{
    if (duct_olb_tx_published(tx))
        return false;
    auto h = &tx->h;
    size_t end = h->stage;
    if (!end || end != olb_off(duct_atomic_load(&h->tail, relaxed)))
        return true;
    size_t prev = duct_atomic_load(&tx->pass_end, relaxed),
           keep = duct_max(end, duct_olb_tx_min_room_get(tx));
    duct_olb_tx_wrap(tx, h->buf_size);
    size_t from_off = duct_align_up(offsetof(duct_olb_tx_t, data) + keep, duct_page_size());
    char *from = (char *)tx + from_off,
         *last = (char *)tx + h->total_size;
    if (prev > keep * olb_tx_trim_div)
        duct_vm_discard(from, (size_t)(last - from));
    return true;
}

#ifdef __cplusplus
}
#endif

#endif /* DUCT_OLB_TX_H */
