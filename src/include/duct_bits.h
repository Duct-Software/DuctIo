/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_bits.h
 *  @brief Runtime-internal atomic slot bitmap.
 *
 *  One bit per slot index, packed 64 per @c uint64_t word (@c idx >> 6
 *  selects the word, @c idx & 63 the bit within it). Caller owns sizing the
 *  backing array to the max slot count.
 */

#ifndef DUCT_BITS_H
#define DUCT_BITS_H

#include "duct_core.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Bits to shift @c idx right to select its word. */
static constexpr unsigned bits_word_shift = 6u;

/** @brief Mask to extract @c idx's bit position within its word. */
static constexpr unsigned bits_index_mask = 63u;

/** @brief @c 1 as @c uint64_t, for shifting into a bit position. */
static constexpr uint64_t bits_word_one   = 1ull;

/** @brief Test bit by slot index. */
duct_nonnull(1) static inline bool
duct_bits_test(const uint64_t _Atomic *bits, unsigned idx)
{
    return duct_atomic_load(&bits[idx >> bits_word_shift], relaxed)
        & (bits_word_one << (idx & bits_index_mask));
}

/** @brief Set bit by slot index. */
duct_nonnull(1) static inline void
duct_bits_set(uint64_t _Atomic *bits, unsigned idx)
{
    duct_atomic_fetch(or, &bits[idx >> bits_word_shift],
                      bits_word_one << (idx & bits_index_mask),
                      release);
}

/** @brief Set bit; returns true on 0->1 transition, for callers tracking
 *  actual state changes (such as @c inter_pending in @c duct_worker_inter_arm).
 */
duct_nonnull(1) static inline bool
duct_bits_set_if_new(uint64_t _Atomic *bits, unsigned idx)
{
    auto mask = bits_word_one << (idx & bits_index_mask);
    return !(duct_atomic_fetch(or, &bits[idx >> bits_word_shift], mask, release)
             & mask);
}

/** @brief Clear bit by slot index. */
duct_nonnull(1) static inline void
duct_bits_clear(uint64_t _Atomic *bits, unsigned idx)
{
    duct_atomic_fetch(and, &bits[idx >> bits_word_shift],
                      ~(bits_word_one << (idx & bits_index_mask)),
                      relaxed);
}

/** @brief Atomically grab and clear all bits in one word. */
duct_nonnull(1) static inline uint64_t
duct_bits_grab(uint64_t _Atomic *bits, unsigned word)
{
    return duct_atomic_exchange(&bits[word], 0, acquire);
}

/** @brief Test bit by slot index, plain (no atomics) — thread-private
 *  bitmaps only, where the caller already knows no concurrent writer can
 *  touch @p bits.
 */
duct_nonnull(1) static inline bool
duct_bits_test_plain(const uint64_t *bits, unsigned idx)
{
    return (bits[idx >> bits_word_shift] >> (idx & bits_index_mask)) & 1u;
}

/** @brief Set bit by slot index, plain (no atomics). */
duct_nonnull(1) static inline void
duct_bits_set_plain(uint64_t *bits, unsigned idx)
{
    bits[idx >> bits_word_shift] |= bits_word_one << (idx & bits_index_mask);
}

/** @brief Clear bit by slot index, plain (no atomics). */
duct_nonnull(1) static inline void
duct_bits_clear_plain(uint64_t *bits, unsigned idx)
{
    bits[idx >> bits_word_shift] &= ~(bits_word_one << (idx & bits_index_mask));
}

#ifdef __cplusplus
}
#endif

#endif /* DUCT_BITS_H */
