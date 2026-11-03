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

/** @brief Bits for @c duct_olb_hdr_t::lifecycle, the rendezvous between an
 *  in-flight io operation and a delete request. See @ref duct_olb_io_begin,
 *  @ref duct_olb_io_done, @ref duct_olb_del.
 */
typedef enum duct_olb_flags : uint8_t {
    fl_olb_none       = 0u,      /**< No flags set. */
    fl_olb_io_busy    = 1u << 0, /**< An io operation is in flight. */
    fl_olb_delete_req = 1u << 1, /**< Deletion was requested while busy. */
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
        uint32_t         stage; /**< Staging cursor, ahead of tail until
                                  *  published. */
        uint64_t _Atomic tail;  /**< Producer cursor. RX: written by the io
                                  *  thread. TX: written by the worker
                                  *  thread. */
    );  /* CL-1 */

    duct_cacheline_struct(
        duct_olb_flags_t _Atomic lifecycle; /**< io_busy/delete_req rendezvous. */
        size_t buf_size,    /**< @c data[] capacity, bytes. */
               total_size;  /**< Full VM mapping size for @c duct_vm_del. */
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
 *  fields from @c __VA_ARGS__, then a flexible array member @c data[] for
 *  the buffer itself. @c __VA_ARGS__ gets one cache line by default; nest
 *  @ref duct_cacheline_struct, or @ref duct_cacheline_struct_ext for a
 *  named remainder, around each group if the variant needs more than one.
 */
#define duct_olb_decl(tag, ...)                         \
    typedef struct tag {                                \
        duct_olb_hdr_t h;                               \
        duct_cacheline_struct(__VA_ARGS__);             \
        uint8_t data[];                                    \
    } tag##_t

/** @brief Allocate one variant in a single mapping and run @p initializer.
 *
 *  The mapping covers the header declared by @ref duct_olb_decl, the variant's
 *  own fields, and the flexible array member. @p capacity is the logical byte
 *  capacity; 0 defaults to 1 MiB, and the mapping is rounded up to a whole
 *  page. The ceiling is 4 GiB, set by @c duct_olb_hdr_t::stage being a 32-bit
 *  cursor.
 */
#define duct_olb_new(type, capacity, initializer)                   \
    ((type *)({                                                     \
        uint32_t _cap = (uint32_t)(capacity),                       \
                 _total = 0u;                                       \
        if (!_cap)                                                  \
            _cap = mbytes(1u);                                      \
        type *_out = nullptr;                                       \
        if (!duct_ckd_add(&_total, sizeof(type), _cap)) {           \
            duct_vm_handle_t _vm = duct_vm_new(_total);             \
            if (_vm.base) {                                         \
                auto _o = (type *)_vm.base;                         \
                *_o = (type){};                                     \
                _o->h.total_size = _vm.size;                        \
                _o->h.buf_size = _vm.size - offsetof(type, data);   \
                initializer(_o);                                    \
                _out = _o;                                          \
            }                                                       \
        }                                                           \
        _out;                                                       \
    }))

/** @brief Mark @p hdr as having a live in-flight io operation.
 *
 *  Every call pairs with a later @ref duct_olb_io_done. The marker is a flag,
 *  not a count: at most one operation may be in flight per @p hdr.
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

/** @brief Clear the in-flight marker.
 *  Pairs with @ref duct_olb_io_begin.
 *
 *  @retval true   @p hdr had a pending delete request; this call freed it,
 *                 and @p hdr must not be touched again.
 *  @retval false  Nothing was pending; @p hdr stays live.
 */
[[nodiscard]] duct_nonnull(1) static inline bool
duct_olb_io_done(duct_olb_hdr_t *hdr)
{
    auto prev = duct_atomic_fetch(and, &hdr->lifecycle, duct_not(fl_olb_io_busy), acq_rel);
    if (!duct_has(prev, fl_olb_delete_req))
        return false;
    duct_vm_del(&(duct_vm_handle_t){ .base = hdr, .size = hdr->total_size });
    return true;
}

/** @brief Request deletion of @p hdr.
 *
 *  Deletes it immediately if no io operation is in flight. Otherwise
 *  defers the deletion to the matching @ref duct_olb_io_done.
 *
 *  @retval true   This call freed @p hdr itself.
 *  @retval false  Deferred.
 */
duct_nonnull(1) static inline bool duct_olb_del(duct_olb_hdr_t *hdr)
{
    auto prev = duct_atomic_fetch(or, &hdr->lifecycle, fl_olb_delete_req, acq_rel);
    if (duct_has(prev, fl_olb_io_busy))
        return false;
    duct_vm_del(&(duct_vm_handle_t){ .base = hdr, .size = hdr->total_size });
    return true;
}

#ifdef __cplusplus
}
#endif

#endif /* DUCT_OLB_H */
