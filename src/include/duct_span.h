/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_span.h
 *  @brief The pin-able payload reference: one idiom for a ring span, a
 *  pooled buffer or an owned block on both sides of the engine.
 *
 *  A @c duct_span_t is what a TX descriptor carries instead of staged bytes
 *  (duct-zerocopy-payload.md §2): the payload stays where its author built
 *  it and the descriptor holds a reference the send path pins for its
 *  lifetime. The substrate rides @c tagged_base's low two bits — every
 *  substrate's base pointer is at least 4-aligned, a conn block by its
 *  512 KB block size, a @c duct_new block and a mat-arena base by 8 — and
 *  the whole span is 16 bytes, so span plus the 16-byte inline wire header
 *  is exactly one 32-byte descriptor, two per cache line.
 *
 *  The pin half of the §5.1 matrix is the header's second job: the shared
 *  invariant @c duct_span_pin / @c duct_span_unpin every staging site calls,
 *  with the cross-leg lifetime of an rx span (@c span_rx) riding
 *  @c rx->pins on its own line C and one unit of @c conn->refs — the §2.3
 *  invariant: while a conn's live rx spans ride descriptors anywhere, the
 *  conn holds one refs unit, taken on the worker strictly before the
 *  descriptor is published into the foreign leg's ring, dropped by any
 *  thread at delivery with the resume re-check ahead of the release, so a
 *  pinned block never re-enters the free bitmap at all.
 */

#ifndef DUCT_SPAN_H
#define DUCT_SPAN_H

#include "duct_conn.h"
#include "duct_olb_rx.h"
#include "duct_relay.h"
#include "duct_x_slot.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief The substrate of a span, in @c tagged_base's low two bits. */
typedef enum duct_span_kind : uint8_t {
    span_mat,    /**< 00: materialized bytes — a sub-threshold copy, sealed
                   *  ciphertext or a foreign buffer staged into the TX ring's
                   *  materialize arena. No pin, no RMW. */
    span_ptr,    /**< 01: a @c duct_new-backed block (ct_buf chunk, x_slot,
                   *  fl_send_owned without a release hook) the descriptor
                   *  holds through its alloc-header holder count. */
    span_rx,     /**< 10: a byte range of the conn's own RX OLB, held by
                   *  @c rx->pins — the cross-leg relay substrate. */
    span_static, /**< 11: @c fl_send_static bytes, valid forever, held by
                   *  nothing. */
} duct_span_kind_t;

/** @brief One pin-able payload reference, 16 bytes. */
typedef struct duct_span {
    uintptr_t tagged_base; /**< Substrate pointer, its [1:0] the kind. The
                             *  bases are 4-aligned by construction: a conn
                             *  block by its power-of-two block size, a heap
                             *  block and a mat-arena base by eight. */
    uint32_t  off;         /**< [31:27] hdr_len (0..16, the inline wire
                             *  header's bytes); [26:0] the span's byte
                             *  offset into its substrate — a mat-arena or
                             *  ring offset. */
    uint32_t  len;         /**< [31] the dgram gso flag; [30:0] span bytes.
                             *  The wire record's length is hdr_len + len. */
} duct_span_t;

static_assert(sizeof(duct_span_t) == 16u,
              "a span is 16 bytes: two descriptors per cache line");

/** @brief Bits of @c tagged_base the substrate kind rides. */
static constexpr uintptr_t duct_span_tag_mask = 3u;

/** @brief Mask of @c off's hdr_len field. */
static constexpr uint32_t duct_span_hdr_mask = (uint32_t)31u << 27;

/** @brief The dgram gso flag's bit in @c len. */
static constexpr uint32_t duct_span_gso_bit = (uint32_t)1u << 31;

/** @brief A span's substrate. */
duct_nonnull(1) static inline duct_span_kind_t
duct_span_kind_of(const duct_span_t *s)
{
    return (duct_span_kind_t)(s->tagged_base & duct_span_tag_mask);
}

/** @brief The span's substrate base, tag bits clear. */
duct_nonnull(1) static inline void *
duct_span_base(const duct_span_t *s)
{
    return (void *)(s->tagged_base & ~duct_span_tag_mask);
}

/** @brief The span's byte offset into its substrate. */
duct_nonnull(1) static inline uint32_t
duct_span_off(const duct_span_t *s)
{
    return s->off & ~duct_span_hdr_mask;
}

/** @brief The span's payload bytes. */
duct_nonnull(1) static inline uint32_t
duct_span_len(const duct_span_t *s)
{
    return s->len & ~duct_span_gso_bit;
}

/** @brief Bytes of the inline wire header this span's descriptor carries. */
duct_nonnull(1) static inline uint32_t
duct_span_hdr_len(const duct_span_t *s)
{
    return (s->off & duct_span_hdr_mask) >> 27;
}

/** @brief True when the descriptor's record is a gso one. */
duct_nonnull(1) static inline bool
duct_span_gso(const duct_span_t *s)
{
    return (s->len & duct_span_gso_bit) != 0u;
}

/** @brief The wire record's whole length: inline header plus span. */
duct_nonnull(1) static inline uint32_t
duct_span_wire_len(const duct_span_t *s)
{
    return duct_span_hdr_len(s) + duct_span_len(s);
}

/** @brief Pack @p hdr_len (0..16) and the gso flag into @p s's spare bits. */
duct_nonnull(1) static inline void
duct_span_meta_set(duct_span_t *s, uint32_t hdr_len, bool gso)
{
    assert(hdr_len <= 16u);
    s->off = (s->off & ~duct_span_hdr_mask) | (hdr_len << 27);
    s->len = (s->len & ~duct_span_gso_bit) | (gso ? duct_span_gso_bit : 0u);
}

/** @brief A span of @p len bytes at @p off of the mat arena at @p base. */
static inline duct_span_t
duct_span_of_mat(void *base, uint32_t off, uint32_t len)
{
    return (duct_span_t){
        .tagged_base = (uintptr_t)base | (uintptr_t)span_mat,
        .off = off, .len = len,
    };
}

/** @brief A span of @p len bytes at @p off of the block at @p base. */
static inline duct_span_t
duct_span_of_ptr(void *base, uint32_t off, uint32_t len)
{
    return (duct_span_t){
        .tagged_base = (uintptr_t)base | (uintptr_t)span_ptr,
        .off = off, .len = len,
    };
}

/** @brief A span of @p len ring bytes at @p off of @p conn's RX OLB. */
static inline duct_span_t
duct_span_of_rx(duct_conn_t *conn, uint32_t off, uint32_t len)
{
    return (duct_span_t){
        .tagged_base = (uintptr_t)conn | (uintptr_t)span_rx,
        .off = off, .len = len,
    };
}

/** @brief A span of static bytes — @p off stays 0, the base a raw pointer. */
static inline duct_span_t
duct_span_of_static(const void *at, uint32_t len)
{
    return (duct_span_t){
        .tagged_base = (uintptr_t)at | (uintptr_t)span_static,
        .off = 0u, .len = len,
    };
}

/** @brief The §2.3 pin: raise @p rx's span count, its 0 → 1 edge taking one
 *  unit of @p conn's release count.
 *
 *  Worker thread only, and strictly before the descriptor referencing the
 *  span is published into a foreign leg's ring: past the publication a
 *  foreign io thread — or the kernel inside its async post — reads the
 *  conn's bytes, and the refs unit is what keeps the block out of the free
 *  bitmap while it does. The relaxed add pairs with the unpin's acq_rel
 *  drop; the descriptor's own publication orders the raise.
 */
duct_nonnull(1, 2) static inline void
duct_span_rx_pin(duct_conn_t *conn, duct_olb_rx_t *rx)
{
    if (duct_atomic_fetch(add, &rx->pins, 1u, relaxed) == 0u)
        duct_conn_ref_take(conn);
}

/** @brief The §2.3 unpin step, any thread at delivery or discard: the last
 *  pin out re-checks the armed resume level and posts the read, then drops
 *  the conn's refs unit last — the release may free the block, so @p conn
 *  and @p rx are dead past this call.
 *
 *  The seq_cst fence pairs with io's arm (s_rx_latch): either the arm's
 *  recheck saw the last ack, or this drop sees the armed target and its
 *  level check posts the read the park waits on — the crossing edge the
 *  worker's ack post answers may already be in the past by the time the
 *  last pin drops, which a level check, not an edge, covers. Outside a
 *  pause the target reads 0 and a drop never posts spuriously.
 */
duct_nonnull(1, 2) static inline void
duct_span_rx_unpin(duct_conn_t *conn, duct_olb_rx_t *rx)
{
    if (duct_atomic_fetch(sub, &rx->pins, 1u, acq_rel) != 1u)
        return;
    atomic_thread_fence(memory_order_seq_cst);
    uint64_t target = duct_atomic_load(&rx->resume_at, relaxed);
    if (target && duct_atomic_load(&rx->acked, relaxed) >= target) {
        auto handle = duct_conn_handle_get(conn);
        duct_io_post_rx_read(&handle);
    }
    duct_conn_release(conn);
}

/** @brief The §5.1 matrix pin for a whole span.
 *
 *  Only @c span_ptr claims a holder — through @c duct_try_share, whose
 *  255-holder ceiling answers nullptr; the caller degrades that answer to a
 *  copy (a @c span_mat), never sends unheld. @c span_rx raises @c rx->pins,
 *  its conn named by the span's own base; @p rx is that leg's ring header,
 *  the one word the span cannot derive for itself — null where the caller
 *  knows the span is no rx one, which every other substrate leaves unread.
 *  The other substrates pin nothing.
 *
 *  @return true with the span's reference held; false only for the ptr
 *          ceiling, the caller's copy signal.
 */
duct_nonnull(1) static inline bool
duct_span_pin(duct_span_t *span, duct_olb_rx_t *rx)
{
    switch (duct_span_kind_of(span)) {
    case span_ptr:
        /* duct_try_share answers nullptr at the 255-holder ceiling and adds
         * no holder on that path — the copy degradation stays exact. */
        return duct_try_share(duct_span_base(span)) != nullptr;
    case span_rx:
        duct_span_rx_pin((duct_conn_t *)duct_span_base(span), rx);
        return true;
    case span_mat:
    case span_static:
        return true;
    }
    duct_unreachable();
}

/** @brief The §5.1 matrix unpin for a whole span, any thread at delivery or
 *  discard — each substrate's reference drops exactly once.
 *
 *  @c span_ptr drops its holder (@c duct_del); @c span_rx runs the §2.3
 *  step above — @p rx is the span's own leg's ring header
 *  (@c duct_conn_rx_hdr of the span's base conn at a foreign completion
 *  site), null only where the caller knows the span is no rx one, which
 *  every other substrate leaves unread. The materialize arena's cursor
 *  advance rides the descriptor ring's completion order, not this call.
 */
duct_nonnull(1) static inline void
duct_span_unpin(duct_span_t *span, duct_olb_rx_t *rx)
{
    switch (duct_span_kind_of(span)) {
    case span_ptr: {
        void *held = duct_span_base(span);
        duct_del(held);
        break;
    }
    case span_rx:
        duct_span_rx_unpin((duct_conn_t *)duct_span_base(span), rx);
        break;
    case span_mat:
    case span_static:
        break;
    }
}

#ifdef __cplusplus
}
#endif

#endif /* DUCT_SPAN_H */
