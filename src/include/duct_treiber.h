/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_treiber.h
 *  @brief Lock-free free-list of slot indices: a Treiber stack with a
 *  versioned head over a fixed slot array.
 *
 *  Usage: embed a @c uint32_t _Atomic next-link in the slot type, keep one
 *  @c uint64_t _Atomic head word per pool, instantiate typed pop/push/seed
 *  via @ref DUCT_TREIBER_DECLARE. Consumers: conn, session and resolver
 *  slot pools.
 *
 *  The head word holds the version in its high half, the top slot idx in
 *  the low. Every CAS bumps the version to avoid ABA-problem. Pop acquire
 *  pairs with push release.
 *
 *  Stale-handle invalidation stays outside — each pool keeps its own
 *  per-slot generation word, bumped around these calls.
 */

#ifndef DUCT_TREIBER_H
#define DUCT_TREIBER_H

#include "duct_core.h"

#include <stdatomic.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Sentinel: stack empty / slot has no successor. */
static constexpr uint32_t treiber_empty = UINT32_MAX;

/** @brief ABA version, head bits [32:63]. */
static constexpr unsigned treiber_ver_shift = 32u;

/** @brief Top slot idx, head bits [0:31]. */
static constexpr uint64_t treiber_idx_mask = 0xFFFFFFFFull;

/** @brief Pack version + slot idx into a 64-bit head value. */
static inline uint64_t treiber_head_pack(unsigned ver, uint32_t idx)
{
    return ((uint64_t)ver << treiber_ver_shift) | (uint64_t)idx;
}

/** @brief Extract slot idx from a head value. */
static inline uint32_t treiber_head_idx(uint64_t head)
{
    return (uint32_t)(head & treiber_idx_mask);
}

/** @brief Extract version from a head value. */
static inline unsigned treiber_head_ver(uint64_t head)
{
    return (unsigned)(head >> treiber_ver_shift);
}

/** @name Treiber pop / push / seed generator
 *  Emits @c prefix##_pop / @c _push / @c _seed over @p slot_type slots
 *  linked through their own @p next_field.
 *
 *  @c _pop returns the winning slot idx, or @ref treiber_empty when the
 *  stack is empty — acquire on the head load and on CAS success, so the
 *  winner's later reads of the slot see whatever the releasing pusher
 *  wrote. The caller does its own post-pop init (generation bump, field
 *  resets); this function only owns the free-list unlink.
 *
 *  @c _push links @p idx back onto the stack — relaxed head load and
 *  next-field store, release on CAS success, so a later popper's acquire
 *  pairs with this release.
 *
 *  @c _seed links every slot @c 0 .. @p count-1 in reverse (pop yields
 *  idx 0 first) and publishes the head, via @c atomic_init — constructor
 *  context, single-threaded, no CAS needed.
 *  @{
 */
#define DUCT_TREIBER_DECLARE(prefix, slot_type, next_field)                         \
duct_nonnull(1, 2) static inline uint32_t                                           \
prefix##_pop(uint64_t _Atomic *head_word, slot_type *slots)                         \
{                                                                                   \
    uint64_t head = duct_atomic_load(head_word, acquire);                           \
    for (;; duct_cpu_relax()) {                                                     \
        uint32_t top = treiber_head_idx(head);                                      \
        if (top == treiber_empty)                                                   \
            return treiber_empty;                                                   \
        uint32_t next = duct_atomic_load(&slots[top].next_field, relaxed);          \
        uint64_t new_head = treiber_head_pack(treiber_head_ver(head) + 1u, next);   \
        if (duct_atomic_cas(weak, head_word, &head, new_head, acquire, relaxed))    \
            return top;                                                             \
    }                                                                               \
}                                                                                   \
duct_nonnull(1, 2) static inline void                                               \
prefix##_push(uint64_t _Atomic *head_word, slot_type *slots, uint32_t idx)          \
{                                                                                   \
    uint64_t head = duct_atomic_load(head_word, relaxed);                           \
    for (;; duct_cpu_relax()) {                                                     \
        duct_atomic_store(&slots[idx].next_field, treiber_head_idx(head), relaxed); \
        uint64_t new_head = treiber_head_pack(treiber_head_ver(head) + 1u, idx);    \
        if (duct_atomic_cas(weak, head_word, &head, new_head, release, relaxed))    \
            return;                                                                 \
    }                                                                               \
}                                                                                   \
duct_nonnull(1, 2) static inline void                                               \
prefix##_seed(uint64_t _Atomic *head_word, slot_type *slots, uint32_t count)        \
{                                                                                   \
    uint32_t prev = treiber_empty;                                                  \
    for (uint32_t i = count; i-- > 0u;) {                                           \
        atomic_init(&slots[i].next_field, prev);                                    \
        prev = i;                                                                   \
    }                                                                               \
    atomic_init(head_word, treiber_head_pack(count, prev));                         \
}
/** @} */

#ifdef __cplusplus
}
#endif

#endif /* DUCT_TREIBER_H */
