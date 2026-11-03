/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_coro_switch.c
 *  @brief AArch64 stack switch and initial SP for stackful coroutines.
 *
 *  The frame carries AAPCS64's callee-saved set — x19-x28, the frame
 *  pointer x29, the link register x30, the low 64 bits of v8-v15
 *  (d8-d15) — plus FPCR, whose control bits a callee must preserve and
 *  which is per-context here: a coroutine may legally hold a custom
 *  rounding mode across its own yield. FPCR's hardware default is 0, so
 *  the zeroed synthetic frame from @ref duct_coro_init_sp seeds it
 *  correctly as-is.
 */

#include "duct_coro.h"

#include <stdint.h>
#include <string.h>

/** @brief stp/ldp pairs saving/restoring d8-d15. */
static constexpr unsigned d_pairs = 4u;

/** @brief stp/ldp pairs saving/restoring x19-x28 plus x29/x30. */
static constexpr unsigned x_pairs = 6u;

/** @brief Bytes per stp/ldp pair: two 8-byte registers. */
static constexpr unsigned pair_size = 16u;

/** @brief FPCR's own slot: 8 bytes of value + 8 bytes padding
 *  to keep SP 16-byte aligned.
 */
static constexpr unsigned fpcr_slot = 16u;

/** @brief FPCR slot's byte offset, right above every register pair. */
static constexpr unsigned fpcr_off = (d_pairs + x_pairs) * pair_size;

/** @brief Total switch-frame size in bytes. */
static constexpr unsigned sp_frame_size = fpcr_off + fpcr_slot;

/** @brief Frame size in pointer-sized slots. */
static constexpr unsigned nregs = sp_frame_size / sizeof(void *);

/** @brief x30's link register (LR) slot index in the synthetic frame
 *  built by @c duct_coro_init_sp.
 */
static constexpr unsigned slot_x30 =
    ((x_pairs - 1u) * pair_size + sizeof(void *)) / sizeof(void *);

static_assert(d_pairs == 4u && x_pairs == 6u,
              "asm stp/ldp list matches AArch64 callee-saved map");
static_assert(nregs * sizeof(void *) == sp_frame_size,
              "initial-sp slots match switch frame bytes");
static_assert(slot_x30 < nregs,
              "x30 slot inside synthetic frame");

/** @brief Save the callee-saved frame + FPCR on the current stack, publish
 *  SP into @p from_sp, adopt @p to_sp, restore its frame, ret via the
 *  restored x30.
 */
__attribute__((naked, used, noinline))
void duct_coro_switch([[maybe_unused]] void **from_sp,
                      [[maybe_unused]] void *to_sp)
{
    __asm__ volatile(
        "stp x19, x20, [sp, %0]!\n\t"
        "stp x21, x22, [sp, %c1]\n\t"
        "stp x23, x24, [sp, %c2]\n\t"
        "stp x25, x26, [sp, %c3]\n\t"
        "stp x27, x28, [sp, %c4]\n\t"
        "stp x29, x30, [sp, %c5]\n\t"
        "stp d8,  d9,  [sp, %c6]\n\t"
        "stp d10, d11, [sp, %c7]\n\t"
        "stp d12, d13, [sp, %c8]\n\t"
        "stp d14, d15, [sp, %c9]\n\t"
        "mrs x2, fpcr\n\t"
        "str x2, [sp, %c10]\n\t"
        "mov x2, sp\n\t"
        "str x2, [x0]\n\t"
        "mov sp, x1\n\t"
        "ldr x2, [sp, %c10]\n\t"
        "msr fpcr, x2\n\t"
        "ldp d14, d15, [sp, %c9]\n\t"
        "ldp d12, d13, [sp, %c8]\n\t"
        "ldp d10, d11, [sp, %c7]\n\t"
        "ldp d8,  d9,  [sp, %c6]\n\t"
        "ldp x29, x30, [sp, %c5]\n\t"
        "ldp x27, x28, [sp, %c4]\n\t"
        "ldp x25, x26, [sp, %c3]\n\t"
        "ldp x23, x24, [sp, %c2]\n\t"
        "ldp x21, x22, [sp, %c1]\n\t"
        "ldp x19, x20, [sp], %11\n\t"
        "ret\n\t"
        :
        :
        "i" (-(int)sp_frame_size),
        "i" (1u * pair_size),
        "i" (2u * pair_size),
        "i" (3u * pair_size),
        "i" (4u * pair_size),
        "i" (5u * pair_size),
        "i" (6u * pair_size),
        "i" (7u * pair_size),
        "i" (8u * pair_size),
        "i" (9u * pair_size),
        "i" (fpcr_off),
        "i" (sp_frame_size)
        : "memory");
}

/* All nregs slots start zeroed, which is FPCR's correct hardware default,
 * except x30's LR slot, planted with entry: duct_coro_switch's restore
 * sequence ends in a ret that lands there. */
void *duct_coro_init_sp(char *stack_top, void *entry)
{
    void **sp = (void **)((uintptr_t)stack_top & ~(uintptr_t)15u);
    sp -= nregs;
    memset(sp, 0, nregs * sizeof(void *));
    sp[slot_x30] = entry;
    return sp;
}
