/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_coro_switch.c
 *  @brief x86_64 stack switch and initial SP for stackful coroutines,
 *  one branch per calling convention: GCC/Clang's @c ms_abi (Windows x64)
 *  and @c sysv_abi — every other x86_64 target, Linux, the BSDs and macOS
 *  alike. The latter's spec carries the historical title "System V AMD64
 *  psABI"; a document name those systems adopted, with no OS lineage
 *  implied.
 *
 *  Each branch saves its convention's callee-saved set. A switch always
 *  runs inside an ordinary call — duct_coro_yield / duct_coro_wait /
 *  duct_coro_resume — so the compiler has already spilled live
 *  caller-saved values onto the switching context's own stack; the frame
 *  carries what a callee is obliged to preserve:
 *  - sysv_abi: rbx, rbp, r12-r15, with @c from_sp/@c to_sp arriving in
 *   rdi/rsi;
 *  - ms_abi: rdi and rsi on top of that set, arguments in rcx/rdx, and
 *   the low 128 bits of xmm6-xmm15;
 *  - both conventions: MXCSR control bits and the x87 control word,
 *   per-context state here since a coroutine may legally hold a custom
 *   rounding mode across its own yield. They live at the base of every
 *   frame, and @ref duct_coro_init_sp seeds their hardware defaults; a
 *   zeroed MXCSR or control word unmasks every FP exception.
 */

#include "duct_coro.h"

#include <stdint.h>
#include <string.h>

/** @brief Control-word block size at the frame base.
 *  @c stmxcsr(4) + @c fnstcw(2) + pad(2).
 */
static constexpr unsigned ctl_size = 8u;

/** @brief MXCSR hardware default.
 *  Every FP exception masked, round-to-nearest.
 */
static constexpr uint32_t mxcsr_default = 0x1F80u;

/** @brief x87 control-word hardware default.
 *  64-bit extended precision.
 */
static constexpr uint16_t x87cw_default = 0x037Fu;

#ifdef _WIN32

/** @brief ms_abi callee-saved GP registers: rbx, rbp, rdi, rsi, r12-r15. */
static constexpr unsigned gp_slots = 8u;

/** @brief Bytes per XMM register's saved low 128 bits. */
static constexpr unsigned xmm_reg_size = 16u;

/** @brief ms_abi callee-saved XMM registers: xmm6-xmm15, low halves only. */
static constexpr unsigned xmm_count = 10u;

/** @brief Bytes reserved below the GP-register pushes.
 *  Control words + the whole XMM save area — ms_abi has callee-saved XMM
 *  registers, unlike sysv_abi, which has none.
 */
static constexpr unsigned save_size = ctl_size + xmm_count * xmm_reg_size;

/** @brief Save the callee-saved frame + control words on the current stack,
 *  publish rsp into @p from_sp, adopt @p to_sp, restore its frame, ret via
 *  the restored return address.
 */
__attribute__((naked, used, noinline))
void duct_coro_switch([[maybe_unused]] void **from_sp,
                      [[maybe_unused]] void *to_sp)
{
    __asm__ volatile(
        "pushq %%rdi\n\t"
        "pushq %%rsi\n\t"
        "pushq %%rbx\n\t"
        "pushq %%rbp\n\t"
        "pushq %%r12\n\t"
        "pushq %%r13\n\t"
        "pushq %%r14\n\t"
        "pushq %%r15\n\t"
        "subq  %0, %%rsp\n\t"
        "stmxcsr (%%rsp)\n\t"
        "fnstcw  4(%%rsp)\n\t"
        "movups %%xmm6,  %c1(%%rsp)\n\t"
        "movups %%xmm7,  %c2(%%rsp)\n\t"
        "movups %%xmm8,  %c3(%%rsp)\n\t"
        "movups %%xmm9,  %c4(%%rsp)\n\t"
        "movups %%xmm10, %c5(%%rsp)\n\t"
        "movups %%xmm11, %c6(%%rsp)\n\t"
        "movups %%xmm12, %c7(%%rsp)\n\t"
        "movups %%xmm13, %c8(%%rsp)\n\t"
        "movups %%xmm14, %c9(%%rsp)\n\t"
        "movups %%xmm15, %c10(%%rsp)\n\t"
        "movq  %%rsp, (%%rcx)\n\t"
        "movq  %%rdx, %%rsp\n\t"
        "movups %c10(%%rsp), %%xmm15\n\t"
        "movups %c9(%%rsp),  %%xmm14\n\t"
        "movups %c8(%%rsp),  %%xmm13\n\t"
        "movups %c7(%%rsp),  %%xmm12\n\t"
        "movups %c6(%%rsp),  %%xmm11\n\t"
        "movups %c5(%%rsp),  %%xmm10\n\t"
        "movups %c4(%%rsp),  %%xmm9\n\t"
        "movups %c3(%%rsp),  %%xmm8\n\t"
        "movups %c2(%%rsp),  %%xmm7\n\t"
        "movups %c1(%%rsp),  %%xmm6\n\t"
        "fldcw   4(%%rsp)\n\t"
        "ldmxcsr (%%rsp)\n\t"
        "addq  %0, %%rsp\n\t"
        "popq  %%r15\n\t"
        "popq  %%r14\n\t"
        "popq  %%r13\n\t"
        "popq  %%r12\n\t"
        "popq  %%rbp\n\t"
        "popq  %%rbx\n\t"
        "popq  %%rsi\n\t"
        "popq  %%rdi\n\t"
        "ret\n\t"
        :
        :
        "i" (save_size),
        "i" (ctl_size + 0u * xmm_reg_size),
        "i" (ctl_size + 1u * xmm_reg_size),
        "i" (ctl_size + 2u * xmm_reg_size),
        "i" (ctl_size + 3u * xmm_reg_size),
        "i" (ctl_size + 4u * xmm_reg_size),
        "i" (ctl_size + 5u * xmm_reg_size),
        "i" (ctl_size + 6u * xmm_reg_size),
        "i" (ctl_size + 7u * xmm_reg_size),
        "i" (ctl_size + 8u * xmm_reg_size),
        "i" (ctl_size + 9u * xmm_reg_size)
        : "memory");
}

#else /* sysv_abi — every other x86_64 target */

/** @brief sysv_abi callee-saved GP registers: rbx, rbp, r12-r15. */
static constexpr unsigned gp_slots  = 6u;

/** @brief Bytes reserved below the GP-register pushes: just the control
 *  words — sysv_abi has no callee-saved XMM registers at all, unlike
 *  ms_abi.
 */
static constexpr unsigned save_size = ctl_size;

/** @brief Save the callee-saved frame + control words on the current stack,
 *  publish rsp into @p from_sp, adopt @p to_sp, restore its frame, ret via
 *  the restored return address.
 */
__attribute__((naked, used, noinline))
void duct_coro_switch([[maybe_unused]] void **from_sp,
                      [[maybe_unused]] void *to_sp)
{
    __asm__ volatile(
        "pushq %%rbx\n\t"
        "pushq %%rbp\n\t"
        "pushq %%r12\n\t"
        "pushq %%r13\n\t"
        "pushq %%r14\n\t"
        "pushq %%r15\n\t"
        "subq  %0, %%rsp\n\t"
        "stmxcsr (%%rsp)\n\t"
        "fnstcw  4(%%rsp)\n\t"
        "movq  %%rsp, (%%rdi)\n\t"
        "movq  %%rsi, %%rsp\n\t"
        "fldcw   4(%%rsp)\n\t"
        "ldmxcsr (%%rsp)\n\t"
        "addq  %0, %%rsp\n\t"
        "popq  %%r15\n\t"
        "popq  %%r14\n\t"
        "popq  %%r13\n\t"
        "popq  %%r12\n\t"
        "popq  %%rbp\n\t"
        "popq  %%rbx\n\t"
        "ret\n\t"
        :
        :
        "i" (save_size)
        : "memory");
}

#endif

/* Low to high: a zeroed register area sized for this ABI's switch frame,
 * then entry, then a null slot terminating the synthetic call chain if entry
 * ever returns. duct_coro_switch's restore pops through the register area
 * and its final ret consumes entry's slot as a real return address, so entry
 * is never popped into a register. The stack pointer lands 8 mod 16, the
 * at-function-entry state both conventions prescribe; only frame_size
 * differs. The control-word slots at the frame base hold hardware defaults,
 * a zeroed slot unmasking every FP exception. */
void *duct_coro_init_sp(char *stack_top, void *entry)
{
    static constexpr unsigned frame_size = save_size + gp_slots * sizeof(void *);
    void **sp = (void **)((uintptr_t)stack_top & ~(uintptr_t)15u);
    *(--sp) = nullptr;
    *(--sp) = entry;
    sp = (void **)((uintptr_t)sp - frame_size);
    memset(sp, 0, frame_size);
    *(uint32_t *)sp = mxcsr_default;
    *((uint16_t *)sp + 2) = x87cw_default;
    return sp;
}
