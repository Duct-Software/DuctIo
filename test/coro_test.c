/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file coro_smoke.c
 * @brief Regression smoke for ported coro primitives (stackful switch + stackless step).
 */

#include "duct_coro.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define CHECK(expr, msg) \
    do { if (!(expr)) { fprintf(stderr, "FAIL: %s\n", msg); return 1; } } while (0)

static int s_order[8];
static unsigned s_n;

static void s_fiber(void *arg)
{
    uintptr_t v = (uintptr_t)arg;
    s_order[s_n++] = (int)v + 1;
    duct_coro_yield();
    s_order[s_n++] = (int)v + 2;
    duct_coro_yield();
    s_order[s_n++] = (int)v + 3;
}

static duct_async_rc_t s_async_step(void *state)
{
    int *p = (int *)state;
    *p += 1;
    return (*p < 3) ? async_yield : async_done;
}

/* R5: a stackful coro parked in duct_coro_wait can be cancelled (queue_remove +
 * destroy) mid-wait without corrupting the queue or leaking the slot. */
static void s_fiber_wait([[maybe_unused]] void *arg)
{
    s_order[s_n++] = 100;
    duct_coro_wait();
    s_order[s_n++] = 101; /* unreached: cancelled before re-resume */
}

#if defined(__x86_64__) || defined(_M_X64)

static const float s_ymm6_pattern[8] = {
    1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f,
};

/* always_inline is load-bearing, not a style choice: Clang emits its own
 * vzeroupper before any call site to this function, even one marked
 * target("avx") like the caller — inlining removes the call site (and that
 * vzeroupper) entirely, so the capture below runs before any upper-half
 * clobber instead of after one. GCC does not insert that call-site
 * vzeroupper, so this only bites under Clang. */
__attribute__((target("avx"), always_inline)) static inline bool s_ymm6_matches(void)
{
    float buf[8];
    __asm__ volatile("vmovupd %%ymm6, %0" : "=m"(buf[0]) :: "memory");
    for (unsigned i = 0u; i < 8u; ++i)
        if (buf[i] != s_ymm6_pattern[i])
            return false;
    return true;
}

__attribute__((target("avx"))) static void s_fiber_ymm([[maybe_unused]] void *arg)
{
    /* Save/restore YMM6 around yield via asm memory store/load.
     * GCC inserts vzeroupper before any non-AVX call (including duct_coro_yield),
     * clobbering upper 128 bits. The store captures all 256 bits before vzeroupper;
     * the load restores them after the yield returns. */
    float buf[8] __attribute__((aligned(32)));
    __asm__ volatile("vmovupd %0, %%ymm6" :: "m"(s_ymm6_pattern[0]) : "ymm6");
    __asm__ volatile("vmovupd %%ymm6, %0" : "=m"(buf[0]) :: "memory");
    duct_coro_yield();
    __asm__ volatile("vmovupd %0, %%ymm6" :: "m"(buf[0]) : "ymm6");
    if (!s_ymm6_matches()) { fprintf(stderr, "FAIL: ymm6 after yield 1\n"); return; }
    __asm__ volatile("vmovupd %%ymm6, %0" : "=m"(buf[0]) :: "memory");
    duct_coro_yield();
    __asm__ volatile("vmovupd %0, %%ymm6" :: "m"(buf[0]) : "ymm6");
    if (!s_ymm6_matches()) { fprintf(stderr, "FAIL: ymm6 after yield 2\n"); return; }
}

#endif /* __x86_64__ */

int main(void)
{
    /* stackful: create one coro, resume until done, observe order 1,2,3 */
    duct_coro_pool_t pool;
    CHECK(duct_coro_pool_new(&pool, 4u, 64u * 1024u) == rc_ok, "pool_new");
    duct_coro_t *co = duct_coro_acquire(&pool, s_fiber, (void *)(uintptr_t)0);
    CHECK(co, "coro_create");
    CHECK(co->state == coro_state_ready, "initial state");
    duct_coro_resume(co);
    CHECK(co->state == coro_state_suspended, "state after yield 1");
    CHECK(s_n == 1u && s_order[0] == 1, "order[0]");
    duct_coro_resume(co);
    CHECK(co->state == coro_state_suspended, "state after yield 2");
    CHECK(s_n == 2u && s_order[1] == 2, "order[1]");
    duct_coro_resume(co);
    CHECK(co->state == coro_state_done, "state after done");
    CHECK(s_n == 3u && s_order[2] == 3, "order[2]");
    duct_coro_release(&pool, co);

    /* stackless: step yields twice then done; counter lives in the state buffer */
    duct_async_pool_t apool;
    CHECK(duct_async_pool_init(&apool, 4u) == rc_ok, "async_pool_init");
    duct_async_t *au = duct_async_acquire(&apool, s_async_step);
    CHECK(au, "async_acquire");
    CHECK(au->step == s_async_step, "au step fn");
    int *ctr = (int *)au->state;
    *ctr = 0;
    CHECK(au->step(au->state) == async_yield && *ctr == 1, "au step 1");
    CHECK(au->step(au->state) == async_yield && *ctr == 2, "au step 2");
    CHECK(au->step(au->state) == async_done && *ctr == 3, "au step 3");
    duct_async_release(&apool, au);
    duct_async_pool_fini(&apool);

    /* queue round-trip: put runnable, pop it */
    duct_coro_queue_t queue;
    duct_coro_queue_init(&queue);
    CHECK(queue.n_run == 0u, "queue empty");
    duct_coro_t *co2 = duct_coro_acquire(&pool, s_fiber, (void *)(uintptr_t)10);
    CHECK(co2, "coro_create co2");
    co2->state = coro_state_ready;
    duct_coro_queue_put(&queue, co2);
    CHECK(queue.n_run == 1u, "queue n_run");
    CHECK(duct_coro_queue_next(&queue) == co2, "queue next");
    CHECK(queue.n_run == 0u, "queue drained");
    duct_coro_release(&pool, co2);

    /* R5: cancel a stackful coro parked in coro_wait — queue_remove + destroy. */
    s_n = 0u;
    duct_coro_t *cw = duct_coro_acquire(&pool, s_fiber_wait, nullptr);
    CHECK(cw, "coro_create cw");
    CHECK(pool.n_alive == 1u, "n_alive");
    duct_coro_resume(cw);
    CHECK(cw->state == coro_state_waiting, "cw waiting");
    CHECK(s_n == 1u && s_order[0] == 100, "wait order");
    duct_coro_queue_put(&queue, cw);
    CHECK(queue.n_wait == 1u, "queue n_wait");
    duct_coro_queue_remove(&queue, cw);
    CHECK(queue.n_wait == 0u, "queue wait cleared");
    duct_coro_release(&pool, cw);
    CHECK(pool.n_alive == 0u, "n_alive zero");

#if defined(__x86_64__) || defined(_M_X64)
    duct_coro_t *cy = duct_coro_acquire(&pool, s_fiber_ymm, nullptr);
    CHECK(cy, "coro_create cy");
    duct_coro_resume(cy);
    CHECK(cy->state == coro_state_suspended, "ymm suspended 1");
    duct_coro_resume(cy);
    CHECK(cy->state == coro_state_suspended, "ymm suspended 2");
    duct_coro_resume(cy);
    CHECK(cy->state == coro_state_done, "ymm done");
    duct_coro_release(&pool, cy);
#endif

    duct_coro_pool_del(&pool);

    printf("coro_smoke OK\n");
    return 0;
}
