/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_olb.h
 *  @brief Shared header and constructor macros for the oversized linear
 *  buffer variants.
 *
 *  @ref duct_olb_hdr_t holds the cursors, allocation metadata, and backend
 *  scratch every variant embeds first. It spans three cache lines, kept
 *  separate so the producer's and consumer's cursors do not false-share.
 *
 *  @ref duct_olb_rx_t and @ref duct_olb_tx_t are the two built-in variants;
 *  include a variant header, and this file only to add a new one.
 */

#ifndef DUCT_OLB_H
#define DUCT_OLB_H

#include "duct_core.h"
#include "duct_types.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct duct_conn duct_conn_t;
void duct_conn_release(duct_conn_t *conn);

/** @brief Parked output that an inbound conn's frames or a session's timers
 *  wait on.
 *  It stands while @c leg's @c tx_seq_serve has not passed @c ticket. The
 *  owning worker alone writes and reads it. */
typedef struct duct_tx_hold {
    duct_handle_t leg;    /**< Handle word of the TX leg the output waits on,
                            *  @c handle_null for none. */
    uint32_t      ticket; /**< The output's commit ticket on @c leg. */
} duct_tx_hold_t;

/** @brief Bit position of the generation inside a packed cursor.
 *  A cursor carries the generation in the upper 32 bits, the offset in the
 *  lower.
 */
static constexpr unsigned olb_gen_shift = 32u;

/** @brief Mask selecting the offset out of a packed cursor. */
static constexpr uint64_t olb_off_mask = (uint64_t)(uint32_t)-1;

/** @brief Pack generation @p gen and offset @p off into one cursor word. */
#define olb_pack(gen, off) (((uint64_t)(gen) << olb_gen_shift) | (off))

/** @brief Generation half of packed cursor @p val. */
#define olb_gen(val) ((uint32_t)((val) >> olb_gen_shift))

/** @brief Offset half of packed cursor @p val, bytes. */
#define olb_off(val) ((size_t)((val) & olb_off_mask))

/** @brief Bits for @c duct_olb_hdr_t::lifecycle — the io thread's
 *  single-flight marker for the backend op embedded in @c ext. The
 *  operation's lifetime borrow is a unit of the owning conn's @c refs, not
 *  this byte. See @ref duct_olb_io_begin, @ref duct_olb_io_done.
 */
typedef enum duct_olb_flags : uint8_t {
    fl_olb_none    = 0u,      /**< No flags set. */
    fl_olb_io_busy = 1u << 0, /**< An io operation is in flight. */
} duct_olb_flags_t;

/** @brief Cursors, allocation metadata, and backend scratch shared by
 *  every OLB variant.
 */
typedef struct duct_olb_hdr {
    duct_cacheline_struct(
        uint64_t _Atomic head; /**< Consumer cursor. Bytes before this
                                  *  offset have been fully handled and may
                                  *  be reclaimed. RX: advanced by
                                  *  @ref duct_olb_rx_ack_apply as the
                                  *  worker acknowledges frames. TX:
                                  *  advanced by @ref duct_olb_tx_advance
                                  *  as io drains sent bytes, and by
                                  *  @ref duct_olb_tx_advance_worker for
                                  *  bytes the producer sent itself ahead of
                                  *  publishing — those two settle their one
                                  *  overlapping write by compare-exchange. */
        /* Io-thread-bound opaque extension sharing @c head's cache line. */
        alignas(alignof(void *))
        union {
            char    ext[duct_cacheline_size - sizeof(uint64_t)];
                              /**< Inline storage the events backend casts to
                                *  its own per-operation state. */
            void   *ext_ptr;  /**< The same storage read as one pointer. */
        };
    );  /* CL-0 */

    duct_cacheline_struct(
        uint32_t _Atomic stage; /**< Staging cursor, ahead of tail until
                                  *  published. RX: io-exclusive. TX: the
                                  *  staging worker's own counter, one plain
                                  *  word the io thread also reads — the
                                  *  close claim's ring-draining check and
                                  *  the public queued metric — while the
                                  *  same worker's release-finish purge
                                  *  rewrites it (the slot's gen word, not
                                  *  this field, orders that hand-off), so
                                  *  every access goes through the duct
                                  *  atomics, relaxed both ways. */
        uint64_t _Atomic tail;  /**< Producer cursor. RX: written by the io
                                  *  thread. TX: written by the worker
                                  *  thread. */
    );  /* CL-1 */

    duct_cacheline_struct(
        duct_olb_flags_t _Atomic lifecycle; /**< io_busy/delete_req rendezvous. */
        size_t buf_size;    /**< @c data[] capacity, bytes. */
    );  /* CL-2 */
} duct_olb_hdr_t;

static_assert(offsetof(duct_olb_hdr_t, stage) % duct_cacheline_size == 0u,
    "duct_olb_hdr_t CL-1 line");
static_assert(offsetof(duct_olb_hdr_t, lifecycle) % duct_cacheline_size == 0u,
    "duct_olb_hdr_t lifecycle line");
static_assert(sizeof(duct_olb_hdr_t) % duct_cacheline_size == 0u,
    "duct_olb_hdr_t must end on a cache-line boundary");

/** @brief Declare one OLB variant. @p tag is the struct name.
 *
 *  The struct starts with @ref duct_olb_hdr_t, then the variant's own
 *  fields from @c __VA_ARGS__; the buffer region lives outside the struct,
 *  a carved region of the owning conn block, whose fixed page-0 placement
 *  lets the writing entries of @c duct_conn_block.h resolve its base from
 *  the header's own address. @c __VA_ARGS__ gets one cache line by default;
 *  nest @ref duct_cacheline_struct, or @ref duct_cacheline_struct_ext for a
 *  named remainder, around each group if the variant needs more than one.
 */
#define duct_olb_decl(tag, ...)                         \
    typedef struct tag {                                \
        duct_olb_hdr_t h;                               \
        duct_cacheline_struct(__VA_ARGS__);             \
    } tag##_t

/** @brief Mark @p hdr as having a live in-flight io operation.
 *
 *  Every call pairs with a later @ref duct_olb_io_done. The marker is a flag,
 *  not a count: at most one operation may be in flight per @p hdr — the
 *  single @c iocp_op_t embedded in @c ext is the reason.
 *
 *  @retval true   @p hdr was already busy; the caller must not post.
 *  @retval false  The marker now stands for this caller's operation.
 */
[[nodiscard]] duct_nonnull(1) static inline bool
duct_olb_io_begin(duct_olb_hdr_t *hdr)
{
    auto prev = duct_atomic_fetch(or, &hdr->lifecycle, fl_olb_io_busy, relaxed);
    return duct_has(prev, fl_olb_io_busy);
}

/** @brief Clear the in-flight marker and drop the operation's borrow of
 *  @p conn's release count.
 *  Pairs with @ref duct_olb_io_begin and the @c refs unit its caller took
 *  ahead of the submission. The marker clears first, while the header's
 *  block is certainly live; the release may be the count's last unit, which
 *  finalizes the slot — @p conn and @p hdr must not be touched again after
 *  this returns.
 */
duct_nonnull(1, 2) static inline void
duct_olb_io_done(duct_olb_hdr_t *hdr, duct_conn_t *conn)
{
    duct_atomic_fetch(and, &hdr->lifecycle, duct_not(fl_olb_io_busy), acq_rel);
    duct_conn_release(conn);
}

#ifdef __cplusplus
}
#endif

#endif /* DUCT_OLB_H */
