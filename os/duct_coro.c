/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_coro.c
 *  @brief Stackful coroutine backend: stack pool, per-thread scheduler
 *  state, resume/yield/wait around the per-ISA context switch.
 *
 *  @par Scope
 *  - Owns: stack pool allocation, guard-page protection, resume/yield/wait.
 *  - Run and wait queues live with the coroutine runtime.
 *
 *  Windows adds one platform step: @ref duct_coro_resume patches the NT_TIB
 *  stack bounds around each switch, via the s_teb_* accessors below.
 */

#include "duct_coro.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

static thread_local void        *s_sched_sp;        /* scheduler SP, switch-back target */
static thread_local duct_coro_t *s_coro_current;    /* coro running on this thread */

#ifdef _WIN32

/* pool->stack_usable, cached for the TIB patch: duct_coro_resume's portable
 * signature has no pool parameter, and each worker thread owns exactly one
 * pool, so one thread_local carries the value. */
static thread_local size_t s_coro_stack_usable;

/* NT_TIB.StackBase/StackLimit sitting at gs:0x08/0x10. Compiler stack probes
 * (_chkstk on large frames) and SEH unwinding read them to judge whether the
 * current rsp is in bounds, so running on a coroutine stack requires
 * patching both. MinGW-w64 headers expose no named TEB field path to the
 * NT_TIB, hence raw gs accesses: each asm template takes
 * offsetof(NT_TIB, ...) as an "i" operand printed with %c — a bare
 * constant, the form a segment displacement needs. */
static_assert(offsetof(NT_TIB, StackBase) == 0x08 && offsetof(NT_TIB, StackLimit) == 0x10,
    "NT_TIB layout changed — s_teb_* accessors assume gs:0x08/0x10");

/** @brief Current thread's NT_TIB.StackBase. */
static inline void *s_teb_stack_base(void)
{
    void *v;
    __asm__ ("movq %%gs:%c1, %0" : "=r" (v) : "i" (offsetof(NT_TIB, StackBase)));
    return v;
}

/** @brief Set current thread's NT_TIB.StackBase. */
static inline void s_teb_set_stack_base(void *v)
{
    __asm__ volatile ("movq %0, %%gs:%c1" :: "r" (v), "i" (offsetof(NT_TIB, StackBase)) : "memory");
}

/** @brief Current thread's NT_TIB.StackLimit. */
static inline void *s_teb_stack_limit(void)
{
    void *v;
    __asm__ ("movq %%gs:%c1, %0" : "=r" (v) : "i" (offsetof(NT_TIB, StackLimit)));
    return v;
}

/** @brief Set current thread's NT_TIB.StackLimit. */
static inline void s_teb_set_stack_limit(void *v)
{
    __asm__ volatile ("movq %0, %%gs:%c1" :: "r" (v), "i" (offsetof(NT_TIB, StackLimit)) : "memory");
}

#endif

/** @brief Entry trampoline: run func(arg), mark done, switch back to the scheduler. */
static void s_coro_entry(void)
{
    auto co = s_coro_current;
    co->func(co->arg);
    co->state = coro_state_done;
    /* Final switch-out: duct_coop_cycle sees coro_state_done and releases the slot. */
    duct_coro_switch(&co->saved_sp, s_sched_sp);
    duct_unreachable();
}

duct_result_t duct_coro_pool_new(duct_coro_pool_t *pool,
                                 unsigned max_slots,
                                 size_t stack_bytes)
{
    *pool = (duct_coro_pool_t){};
    size_t guard = duct_page_size(),
           stack = stack_bytes ? stack_bytes : coro_stack_default;
    stack = duct_align_up(stack, guard);
    duct_do_if(stack == 0u, return rc_invalid_arg);
    size_t slot = guard + stack,
           zone = 0u;
    duct_do_if(duct_ckd_mul(&zone, (size_t)max_slots, slot), return rc_invalid_arg);
    duct_vm_handle_t vm = duct_vm_new(zone);
    duct_do_if(!vm.base || !vm.size, return rc_no_memory);
    unsigned cap = (unsigned)(vm.size / slot);
    duct_do_if(!cap, duct_vm_del(&vm); return rc_no_memory);
    pool->base = (char *)vm.base;
    pool->zone_size = vm.size;
    pool->slot_size = slot;
    pool->guard_size = guard;
    duct_do_if(duct_ckd_sub(&pool->stack_usable, stack, coro_meta_size),
        duct_vm_del(&vm); return rc_invalid_arg
    );
#ifdef _WIN32
    s_coro_stack_usable = pool->stack_usable;
#endif
    return rc_ok;
}

void duct_coro_pool_del(duct_coro_pool_t *pool)
{
    duct_vm_handle_t vm = { .base = pool->base, .size = pool->zone_size };
    duct_vm_del(&vm);
    *pool = (duct_coro_pool_t){};
}

duct_coro_t *duct_coro_acquire(duct_coro_pool_t *pool,
                               duct_coro_func_t func, void *arg)
{
    /* Unbuilt pool — duct_coro_pool_new failed or never ran. */
    duct_do_if(!pool->base, return nullptr);
    auto co = pool->free_list;
    if (co) {
        pool->free_list = co->next;
        co->next = nullptr;
    } else {
        if (pool->n_committed >= (unsigned)(pool->zone_size / pool->slot_size))
            return nullptr;
        /* Commit the next slot: arm its guard page, park zeroed meta at the top. */
        auto slot = pool->base + (size_t)pool->n_committed * pool->slot_size;
        bool prot = true;
#ifdef _WIN32
        prot = VirtualProtect(slot, pool->guard_size, PAGE_NOACCESS, &(DWORD){ 0u });
#else
        prot = !mprotect(slot, pool->guard_size, PROT_NONE);
#endif
        duct_do_if(!prot, return nullptr);
        auto stack = slot + pool->guard_size;
        co = (duct_coro_t *)(stack + pool->stack_usable);
        *co = (duct_coro_t){};
        co->stack_base = stack;
        ++pool->n_committed;
    }
    ++pool->n_alive;
    co->func = func;
    co->arg = arg;
    co->state = coro_state_ready;
    auto top = co->stack_base + pool->stack_usable;
    void (*entry)(void) = s_coro_entry;
    void *entry_ptr = nullptr;
    /* memcpy is the conforming way to pass a function pointer through void *. */
    memcpy(&entry_ptr, &entry, sizeof(entry_ptr));
    co->saved_sp = duct_coro_init_sp(top, entry_ptr);
    return co;
}

void duct_coro_resume(duct_coro_t *coro)
{
    coro->state = coro_state_running;
    /* Entry trampoline reads current coroutine from TLS before first switch. */
    s_coro_current = coro;
#ifdef _WIN32
    /* Point the TIB at the coroutine stack for _chkstk/SEH (see s_teb_* above). */
    void *saved_base  = s_teb_stack_base(),
         *saved_limit = s_teb_stack_limit();
    s_teb_set_stack_base(coro->stack_base + s_coro_stack_usable);
    s_teb_set_stack_limit(coro->stack_base);
#endif
    duct_coro_switch(&s_sched_sp, coro->saved_sp);
#ifdef _WIN32
    /* Back on the scheduler stack — restore its bounds; every switch into a
     * coroutine goes through the patch above. */
    s_teb_set_stack_base(saved_base);
    s_teb_set_stack_limit(saved_limit);
#endif
}

void duct_coro_yield(void)
{
    auto co = s_coro_current;
    co->state = coro_state_suspended;
    duct_coro_switch(&co->saved_sp, s_sched_sp);
}

void duct_coro_wait(void)
{
    auto co = s_coro_current;
    co->state = coro_state_waiting;
    duct_coro_switch(&co->saved_sp, s_sched_sp);
}

void duct_coro_release(duct_coro_pool_t *pool, duct_coro_t *coro)
{
    coro->state = coro_state_done;
    coro->func = nullptr;
    coro->arg = nullptr;
    coro->on_resume = nullptr;
    coro->on_resume_ctx = nullptr;
    --pool->n_alive;
    /* Reclaim span, truncated to whole pages: duct_vm_discard takes them alone,
     * and the top page also carries the coro meta. */
    duct_vm_discard(coro->stack_base, pool->stack_usable & ~(pool->guard_size - 1u));
    coro->next = pool->free_list;
    pool->free_list = coro;
}
