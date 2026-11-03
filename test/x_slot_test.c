/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file x_slot_test.c
 * @brief The elastic transfer-slot pool: growth by chunk, addressing, registration hooks, the sweep at
 * rest, the size-class pair the TX side takes slots from, and many threads taking, filling and returning
 * slots while the pool grows and is swept under them.
 */

#include "duct_x_slot.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond)                                                                           \
    do {                                                                                      \
        if (!(cond)) {                                                                        \
            fprintf(stderr, "x_slot: %s:%d: %s\n", __FILE__, __LINE__, #cond);                \
            exit(1);                                                                          \
        }                                                                                     \
    } while (0)

static constexpr uint32_t k_lead = 4u;

static constexpr duct_x_slot_hooks_t k_no_hooks = {};

typedef struct {
    unsigned _Atomic ups,
                     downs,
                     calls;
    unsigned         fail_at;
    duct_result_t    fail_rc;
    bool             record;
    void            *base_of[16];
    size_t           bytes_of[16];
} hook_log_t;

static duct_result_t s_up(void *ctx, void *base, size_t bytes, uintptr_t *cookie)
{
    auto log = (hook_log_t *)ctx;
    unsigned n = atomic_load(&log->ups);
    atomic_fetch_add(&log->calls, 1u);
    if (log->fail_at && n + 1u == log->fail_at)
        return log->fail_rc;
    if (log->record && n < 16u) {
        log->base_of[n] = base;
        log->bytes_of[n] = bytes;
    }
    *cookie = (uintptr_t)base | 1u;
    atomic_fetch_add(&log->ups, 1u);
    return rc_ok;
}

static void s_down(void *ctx, [[maybe_unused]] uintptr_t cookie)
{
    atomic_fetch_add(&((hook_log_t *)ctx)->downs, 1u);
}

static duct_x_slot_hooks_t s_hooks_of(hook_log_t *log)
{
    return (duct_x_slot_hooks_t){ .up = s_up, .down = s_down, .ctx = log };
}

static void check_empty_pool(void)
{
    duct_x_slot_pool_t pool;
    CHECK(duct_x_slot_pool_init(&pool, 0u, 256u, k_lead, 4u, k_no_hooks));
    CHECK(duct_x_slot_acquire(&pool) == treiber_empty);
    duct_x_slot_release(&pool, treiber_empty);
    CHECK(!duct_x_slot_pool_avail(&pool));
    CHECK(!duct_x_slot_pool_owns(&pool, &pool));
    CHECK(!duct_x_slot_pool_sweep(&pool));
    duct_x_slot_pool_free(&pool);

    CHECK(duct_x_slot_pool_init(&pool, 8u, 0u, k_lead, 4u, k_no_hooks));
    CHECK(duct_x_slot_acquire(&pool) == treiber_empty);
    duct_x_slot_pool_free(&pool);
    CHECK(!duct_x_slot_pool_init(&pool, 8u, 4u, 8u, 4u, k_no_hooks));
    printf("  empty_pool OK\n");
}

static void check_growth_by_chunk(void)
{
    duct_x_slot_pool_t pool;
    CHECK(duct_x_slot_pool_init(&pool, 10u, 256u, k_lead, 4u, k_no_hooks));
    CHECK(pool.n_chunks == 3u && pool.chunk_slots == 4u);
    CHECK(duct_atomic_load(&pool.live, relaxed) == 0u);
    CHECK(duct_x_slot_pool_dry(&pool));
    CHECK(duct_x_slot_pool_avail(&pool));

    bool seen[10] = {};
    uint32_t got[10];
    for (unsigned i = 0u; i < 10u; ++i) {
        got[i] = duct_x_slot_acquire(&pool);
        CHECK(got[i] < 10u && !seen[got[i]]);
        seen[got[i]] = true;
        CHECK(duct_atomic_load(&pool.live, relaxed) == i / 4u + 1u);
    }
    CHECK(duct_x_slot_acquire(&pool) == treiber_empty);
    CHECK(duct_atomic_load(&pool.live, relaxed) == 3u);
    CHECK(!duct_x_slot_pool_avail(&pool));
    duct_x_slot_release(&pool, treiber_empty);
    CHECK(!duct_x_slot_pool_avail(&pool) && duct_x_slot_acquire(&pool) == treiber_empty);

    CHECK(duct_x_slot_chunk_of(&pool, 3u) == 0u && duct_x_slot_chunk_of(&pool, 4u) == 1u
          && duct_x_slot_chunk_of(&pool, 9u) == 2u);
    CHECK(duct_x_slot_chunk_off(&pool, 5u) == 256u);

    duct_x_slot_release(&pool, got[6]);
    CHECK(duct_x_slot_pool_avail(&pool));
    CHECK(duct_x_slot_acquire(&pool) == got[6]);
    for (unsigned i = 0u; i < 10u; ++i)
        duct_x_slot_release(&pool, got[i]);
    duct_x_slot_pool_free(&pool);
    printf("  growth_by_chunk OK\n");
}

static void check_addressing(void)
{
    duct_x_slot_pool_t pool;
    CHECK(duct_x_slot_pool_init(&pool, 6u, 200u, k_lead, 3u, k_no_hooks));
    uint32_t a = duct_x_slot_acquire(&pool),
             b = duct_x_slot_acquire(&pool);
    CHECK(a != b);
    CHECK(duct_x_slot_data(&pool, b) == duct_x_slot_data(&pool, a) + ((ptrdiff_t)b - (ptrdiff_t)a) * 200);
    CHECK(duct_x_slot_payload(&pool, a) == duct_x_slot_data(&pool, a) + k_lead);
    CHECK(duct_x_slot_cap(&pool) == 200u - k_lead);
    CHECK(duct_x_slot_holds(&pool, a, duct_x_slot_data(&pool, a) + 199));
    CHECK(!duct_x_slot_holds(&pool, a, duct_x_slot_data(&pool, a) + 200));
    CHECK(duct_x_slot_pool_owns(&pool, duct_x_slot_data(&pool, 5u) + 199));
    CHECK(!duct_x_slot_pool_owns(&pool, duct_x_slot_data(&pool, 5u) + 200));
    CHECK(!duct_x_slot_pool_owns(&pool, (const char *)pool.range.base - 1));
    memset(duct_x_slot_data(&pool, a), 0x5a, 200u);
    memset(duct_x_slot_data(&pool, b), 0xa5, 200u);
    CHECK(((uint8_t *)duct_x_slot_data(&pool, a))[199] == 0x5au);
    duct_x_slot_release(&pool, a);
    duct_x_slot_release(&pool, b);
    duct_x_slot_pool_free(&pool);
    printf("  addressing OK\n");
}

static void check_claims(void)
{
    duct_x_slot_pool_t pool;
    uint32_t n = duct_dgram_rx_batch + 2u;
    CHECK(duct_x_slot_pool_init(&pool, n, 64u, k_lead, n, k_no_hooks));
    uint32_t idx[2];
    for (unsigned i = 0u; i < 2u; ++i)
        idx[i] = duct_x_slot_acquire(&pool);
    CHECK(duct_x_slot_drop(&pool, idx[1], false));
    CHECK(duct_x_slot_claim(&pool, idx[0]));
    CHECK(duct_x_slot_claim(&pool, idx[0]));
    CHECK(duct_atomic_load(&pool.claims, relaxed) == 2u);
    CHECK(!duct_x_slot_claim(&pool, idx[0]));
    CHECK(duct_atomic_load(&pool.claims, relaxed) == 2u);
    CHECK(!duct_x_slot_drop(&pool, idx[0], false));
    CHECK(!duct_x_slot_drop(&pool, idx[0], true));
    CHECK(duct_x_slot_drop(&pool, idx[0], true));
    CHECK(duct_atomic_load(&pool.claims, relaxed) == 0u);
    duct_x_slot_pool_free(&pool);
    printf("  claims OK\n");
}

/* A batch take gives the slots n single takes would, grows the pool through its chunks as they run short,
 * answers what the pool has left at its ceiling, and a batch return puts the first slot on top. */
static void check_batch(void)
{
    duct_x_slot_pool_t one, many;
    CHECK(duct_x_slot_pool_init(&one, 10u, 256u, k_lead, 4u, k_no_hooks));
    CHECK(duct_x_slot_pool_init(&many, 10u, 256u, k_lead, 4u, k_no_hooks));
    uint32_t single[6], batch[6];
    for (unsigned i = 0u; i < 6u; ++i)
        single[i] = duct_x_slot_acquire(&one);
    CHECK(duct_x_slot_acquire_n(&many, batch, 6u) == 6u);
    CHECK(memcmp(single, batch, sizeof single) == 0);
    CHECK(duct_atomic_load(&many.live, relaxed) == 2u);

    uint32_t rest[8];
    CHECK(duct_x_slot_acquire_n(&many, rest, 8u) == 4u);
    CHECK(duct_atomic_load(&many.live, relaxed) == 3u);
    CHECK(duct_x_slot_acquire_n(&many, rest, 3u) == 0u);
    CHECK(duct_x_slot_acquire_n(&many, rest, 0u) == 0u);

    uint32_t back[3] = { batch[4], batch[1], batch[5] },
             again[3];
    duct_x_slot_release_n(&many, back, 3u);
    duct_x_slot_release_n(&many, back, 0u);
    CHECK(duct_x_slot_acquire_n(&many, again, 3u) == 3u);
    CHECK(memcmp(back, again, sizeof back) == 0);
    CHECK(duct_x_slot_acquire_n(&many, again, 1u) == 0u);

    duct_x_slot_pool_t none;
    CHECK(duct_x_slot_pool_init(&none, 0u, 256u, k_lead, 4u, k_no_hooks));
    CHECK(duct_x_slot_acquire_n(&none, again, 3u) == 0u);
    duct_x_slot_pool_free(&none);
    duct_x_slot_pool_free(&many);
    duct_x_slot_pool_free(&one);
    printf("  batch OK\n");
}

static void check_hooks(void)
{
    hook_log_t log = { .record = true };
    duct_x_slot_pool_t pool;
    CHECK(duct_x_slot_pool_init(&pool, 8u, 128u, k_lead, 2u, s_hooks_of(&log)));

    uint32_t got[8];
    for (unsigned i = 0u; i < 8u; ++i) {
        got[i] = duct_x_slot_acquire(&pool);
        CHECK(got[i] != treiber_empty);
        unsigned c = i / 2u;
        CHECK(atomic_load(&log.ups) == c + 1u);
        CHECK(log.base_of[c] == (char *)pool.range.base + (size_t)c * 2u * 128u);
        CHECK(log.bytes_of[c] == 2u * 128u);
        CHECK(duct_x_slot_cookie(&pool, got[i]) == ((uintptr_t)log.base_of[c] | 1u));
    }
    for (unsigned i = 0u; i < 8u; ++i)
        duct_x_slot_release(&pool, got[i]);
    duct_x_slot_pool_free(&pool);
    CHECK(atomic_load(&log.downs) == 4u);

    /* A refused registration leaves the chunk absent: the take fails, and the next one retries it. */
    hook_log_t flaky = { .fail_at = 3u, .fail_rc = rc_again };
    CHECK(duct_x_slot_pool_init(&pool, 8u, 128u, k_lead, 2u, s_hooks_of(&flaky)));
    for (unsigned i = 0u; i < 4u; ++i)
        got[i] = duct_x_slot_acquire(&pool);
    CHECK(got[0] != treiber_empty && got[3] != treiber_empty);
    CHECK(duct_x_slot_acquire(&pool) == treiber_empty);
    CHECK(duct_atomic_load(&pool.live, relaxed) == 2u);
    CHECK(duct_x_slot_pool_dry(&pool));
    flaky.fail_at = 0u;
    uint32_t more = duct_x_slot_acquire(&pool);
    CHECK(more >= 4u && duct_atomic_load(&pool.live, relaxed) == 3u);
    duct_x_slot_release(&pool, more);
    for (unsigned i = 0u; i < 4u; ++i)
        duct_x_slot_release(&pool, got[i]);
    duct_x_slot_pool_free(&pool);
    CHECK(atomic_load(&flaky.downs) == 3u);

    /* A refusal that is final ends the growth: the hook is not asked again, and the slots out still serve. */
    hook_log_t spent = { .fail_at = 2u, .fail_rc = rc_no_memory };
    CHECK(duct_x_slot_pool_init(&pool, 8u, 128u, k_lead, 2u, s_hooks_of(&spent)));
    for (unsigned i = 0u; i < 2u; ++i)
        got[i] = duct_x_slot_acquire(&pool);
    CHECK(got[0] != treiber_empty && got[1] != treiber_empty);
    CHECK(duct_x_slot_acquire(&pool) == treiber_empty);
    CHECK(atomic_load(&spent.calls) == 2u);
    CHECK(duct_x_slot_acquire(&pool) == treiber_empty && atomic_load(&spent.calls) == 2u);
    duct_x_slot_release(&pool, got[0]);
    CHECK(duct_x_slot_acquire(&pool) == got[0]);
    duct_x_slot_release(&pool, got[0]);
    duct_x_slot_release(&pool, got[1]);
    duct_x_slot_pool_free(&pool);
    printf("  hooks OK\n");
}

static void check_sweep(void)
{
    hook_log_t log = {};
    size_t page = duct_page_size();
    duct_x_slot_pool_t pool;
    CHECK(duct_x_slot_pool_init(&pool, 8u, (uint32_t)(2u * page), k_lead, 2u, s_hooks_of(&log)));

    uint32_t got[8];
    for (unsigned i = 0u; i < 8u; ++i)
        got[i] = duct_x_slot_acquire(&pool);
    CHECK(duct_atomic_load(&pool.live, relaxed) == 4u && atomic_load(&log.ups) == 4u);
    for (unsigned i = 0u; i < 8u; ++i)
        memset(duct_x_slot_payload(&pool, got[i]), 0xcc, 64u);

    /* Growth makes the pool busy for one sweep, which only notes it. */
    CHECK(!duct_x_slot_pool_sweep(&pool));

    /* Slots still held in the top chunk keep that chunk; the free ones under it above the floor go. */
    for (unsigned i = 0u; i < 8u; ++i)
        if (got[i] / 2u != 3u)
            duct_x_slot_release(&pool, got[i]);
    CHECK(duct_x_slot_pool_sweep(&pool));
    CHECK(duct_atomic_load(&pool.live, relaxed) == 2u && atomic_load(&log.downs) == 2u);

    /* The held chunk back, a calm pool keeps its floor of one chunk. */
    for (unsigned i = 0u; i < 8u; ++i)
        if (got[i] / 2u == 3u)
            duct_x_slot_release(&pool, got[i]);
    CHECK(duct_x_slot_pool_sweep(&pool));
    CHECK(duct_atomic_load(&pool.live, relaxed) == 1u && atomic_load(&log.downs) == 3u);
#ifdef __linux__
    CHECK(*(uint8_t *)duct_x_slot_payload(&pool, 6u) == 0u);
    CHECK(*(uint8_t *)duct_x_slot_payload(&pool, 0u) == 0xccu);
#endif
    CHECK(!duct_x_slot_pool_sweep(&pool));

    /* What is left is chunk 0 alone, and the pool grows again on demand, into the lowest absent chunk. */
    uint32_t again[2];
    for (unsigned i = 0u; i < 2u; ++i)
        again[i] = duct_x_slot_acquire(&pool);
    CHECK(again[0] < 2u && again[1] < 2u && again[0] != again[1]);
    CHECK(duct_atomic_load(&pool.live, relaxed) == 1u);
    uint32_t next = duct_x_slot_acquire(&pool);
    CHECK(next >= 2u && next < 4u);
    CHECK(duct_atomic_load(&pool.live, relaxed) == 2u && atomic_load(&log.ups) == 5u);

    /* Hitting the ceiling is pressure, and the sweep that follows it leaves the chunks alone. */
    uint32_t rest[5];
    for (unsigned i = 0u; i < 5u; ++i)
        rest[i] = duct_x_slot_acquire(&pool);
    CHECK(duct_x_slot_acquire(&pool) == treiber_empty);
    for (unsigned i = 0u; i < 5u; ++i)
        duct_x_slot_release(&pool, rest[i]);
    duct_x_slot_release(&pool, next);
    for (unsigned i = 0u; i < 2u; ++i)
        duct_x_slot_release(&pool, again[i]);
    CHECK(!duct_x_slot_pool_sweep(&pool));

    /* A sweep that finds another one running does not wait for it, and leaves the chunks alone. */
    duct_atomic_store(&pool.sweeping, true, relaxed);
    CHECK(!duct_x_slot_pool_sweep(&pool));
    CHECK(duct_atomic_load(&pool.live, relaxed) == 4u);
    duct_atomic_store(&pool.sweeping, false, relaxed);

    CHECK(duct_x_slot_pool_sweep(&pool));
    CHECK(duct_atomic_load(&pool.live, relaxed) == 1u);

    duct_x_slot_pool_free(&pool);
    CHECK(atomic_load(&log.downs) == atomic_load(&log.ups));
    printf("  sweep OK\n");
}

static void check_class_pair(void)
{
    duct_x_slot_pool_t pools[2];
    CHECK(duct_x_slot_pool_init(&pools[0], 6u, 64u, 8u, 3u, k_no_hooks));
    CHECK(duct_x_slot_pool_init(&pools[1], 2u, 512u, 8u, 1u, k_no_hooks));
    CHECK(duct_x_slot_fits(pools, 504u) && !duct_x_slot_fits(pools, 505u));
    CHECK(duct_x_slot_class_for(pools, 56u) == 0u && duct_x_slot_class_for(pools, 57u) == 1u);

    uint32_t small = duct_x_slot_take(pools, 56u),
             large = duct_x_slot_take(pools, 57u);
    CHECK(small != treiber_empty && !(small & duct_x_slot_ref_large));
    CHECK(large != treiber_empty && (large & duct_x_slot_ref_large));
    CHECK(duct_x_slot_span(pools, small).size == 56u && duct_x_slot_span(pools, large).size == 504u);
    CHECK(duct_x_slot_span(pools, small).data == duct_x_slot_payload(&pools[0], small));
    CHECK(duct_x_slot_span(pools, large).data
          == duct_x_slot_payload(&pools[1], large & ~duct_x_slot_ref_large));

    uint32_t other = duct_x_slot_take(pools, 500u);
    CHECK(other != treiber_empty && (other & duct_x_slot_ref_large));
    CHECK(!duct_x_slot_has(pools, 500u));
    CHECK(duct_x_slot_take(pools, 500u) == treiber_empty);
    CHECK(duct_x_slot_has(pools, 56u));
    duct_x_slot_put(pools, large);
    CHECK(duct_x_slot_has(pools, 500u) && duct_x_slot_take(pools, 500u) == large);
    duct_x_slot_put(pools, large);
    duct_x_slot_put(pools, other);
    duct_x_slot_put(pools, small);
    for (unsigned c = 0u; c < 2u; ++c)
        duct_x_slot_pool_free(&pools[c]);
    printf("  class_pair OK\n");
}

static duct_result_t s_lock_up(void *ctx, void *base, size_t bytes, uintptr_t *cookie)
{
    auto log = (hook_log_t *)ctx;
    atomic_fetch_add(&log->calls, 1u);
    duct_result_t rc = duct_vm_lock(base, bytes);
    if (rc != rc_ok)
        return rc;
    *cookie = (uintptr_t)base | 1u;
    atomic_fetch_add(&log->ups, 1u);
    return rc_ok;
}

static void check_reserve(void)
{
    hook_log_t log = {};
    size_t page = duct_page_size();
    duct_x_slot_pool_t pool;
    duct_x_slot_hooks_t hooks = { .up = s_lock_up, .ctx = &log, .reserve = true };
    CHECK(duct_x_slot_pool_init(&pool, 4u, (uint32_t)page, 0u, 1u, hooks));
    CHECK(pool.range.base && duct_atomic_load(&pool.live, relaxed) == 0u);

    uint32_t first = duct_x_slot_acquire(&pool);
    if (first == treiber_empty) {
        /* The system refused the lock for good: the chunk stays absent and no later try asks again. */
        CHECK(atomic_load(&log.ups) == 0u && duct_atomic_load(&pool.live, relaxed) == 0u);
        CHECK(duct_x_slot_acquire(&pool) == treiber_empty && duct_x_slot_acquire(&pool) == treiber_empty);
        CHECK(atomic_load(&log.calls) == 1u);
        duct_x_slot_pool_free(&pool);
        printf("  reserve OK (no lock)\n");
        return;
    }
    /* A chunk is usable only once its hook ran: it reads zero, takes a write, and the next chunk is a page on. */
    auto p = (uint8_t *)duct_x_slot_payload(&pool, first);
    CHECK(p[0] == 0u && p[page - 1u] == 0u);
    p[0] = p[page - 1u] = 0x5au;
    CHECK(duct_atomic_load(&pool.live, relaxed) == 1u && atomic_load(&log.ups) == 1u);
    uint32_t more[3];
    for (unsigned i = 0u; i < 3u; ++i) {
        more[i] = duct_x_slot_acquire(&pool);
        CHECK(more[i] != treiber_empty && more[i] != first);
        CHECK(*(uint8_t *)duct_x_slot_payload(&pool, more[i]) == 0u);
    }
    CHECK(duct_atomic_load(&pool.live, relaxed) == 4u && atomic_load(&log.ups) == 4u);
    CHECK(duct_x_slot_acquire(&pool) == treiber_empty);

    /* Slots go back with their pages locked, and come out again the way the secret arena needs them. */
    duct_x_slot_release(&pool, more[2]);
    CHECK(duct_x_slot_acquire(&pool) == more[2] && atomic_load(&log.ups) == 4u);
    duct_x_slot_pool_free(&pool);
    printf("  reserve OK\n");
}

enum { k_threads = 4, k_sweepers = 2, k_rounds = 40000, k_slots = 24 };

typedef struct {
    duct_x_slot_pool_t *pool;
    uint32_t _Atomic   *owner;
    unsigned            id;
    unsigned            took;
    bool _Atomic       *stop;
} worker_t;

static void *s_worker(void *arg)
{
    auto w = (worker_t *)arg;
    uint32_t held[3];
    for (unsigned round = 0u; round < k_rounds; ++round) {
        unsigned n = 1u + round % 3u;
        unsigned got = 0u;
        /* Odd rounds take their slots in one batch, even rounds one at a time. */
        unsigned taken = round & 1u ? duct_x_slot_acquire_n(w->pool, held, n) : 0u;
        for (; got < n; ++got) {
            uint32_t idx = round & 1u ? (got < taken ? held[got] : treiber_empty) : duct_x_slot_acquire(w->pool);
            if (idx == treiber_empty)
                break;
            uint32_t was = 0u;
            if (!atomic_compare_exchange_strong(&w->owner[idx], &was, w->id + 1u)) {
                fprintf(stderr, "x_slot: slot %u handed to %u while %u holds it\n", idx, w->id, was);
                exit(1);
            }
            /* The registration of the slot's chunk stands whenever the slot is held. */
            uint32_t c = duct_x_slot_chunk_of(w->pool, idx);
            uintptr_t want = ((uintptr_t)w->pool->range.base
                              + (size_t)c * w->pool->chunk_slots * w->pool->slot_bytes) | 1u;
            if (duct_x_slot_cookie(w->pool, idx) != want) {
                fprintf(stderr, "x_slot: slot %u of chunk %u holds cookie %zx, not %zx\n", idx, c,
                        (size_t)duct_x_slot_cookie(w->pool, idx), (size_t)want);
                exit(1);
            }
            auto p = (volatile uint8_t *)duct_x_slot_payload(w->pool, idx);
            uint8_t stamp = (uint8_t)(w->id * 61u + round);
            for (unsigned b = 0u; b < 32u; ++b)
                p[b] = stamp;
            held[got] = idx;
        }
        for (unsigned i = 0u; i < got; ++i) {
            auto p = (volatile uint8_t *)duct_x_slot_payload(w->pool, held[i]);
            uint8_t stamp = (uint8_t)(w->id * 61u + round);
            for (unsigned b = 0u; b < 32u; ++b)
                if (p[b] != stamp) {
                    fprintf(stderr, "x_slot: slot %u was written under its holder\n", held[i]);
                    exit(1);
                }
            uint32_t mine = w->id + 1u;
            if (!atomic_compare_exchange_strong(&w->owner[held[i]], &mine, 0u)) {
                fprintf(stderr, "x_slot: slot %u changed owner while held\n", held[i]);
                exit(1);
            }
            if (!(round & 1u))
                duct_x_slot_release(w->pool, held[i]);
        }
        if (round & 1u)
            duct_x_slot_release_n(w->pool, held, got);
        w->took += got;
    }
    return nullptr;
}

static void *s_sweeper(void *arg)
{
    auto w = (worker_t *)arg;
    while (!atomic_load(w->stop)) {
        duct_discard duct_x_slot_pool_sweep(w->pool);
        for (volatile unsigned spin = 0u; spin < 2000u; ++spin)
            ;
    }
    return nullptr;
}

static void check_concurrent(void)
{
    hook_log_t log = {};
    duct_x_slot_pool_t pool;
    CHECK(duct_x_slot_pool_init(&pool, k_slots, 4u * (uint32_t)duct_page_size(), k_lead, 3u,
                                s_hooks_of(&log)));

    static uint32_t _Atomic owner[k_slots];
    bool _Atomic stop = false;
    worker_t w[k_threads];
    pthread_t th[k_threads],
              sw[k_sweepers];
    for (unsigned i = 0u; i < k_threads; ++i) {
        w[i] = (worker_t){ .pool = &pool, .owner = owner, .id = i, .stop = &stop };
        CHECK(pthread_create(&th[i], nullptr, s_worker, &w[i]) == 0);
    }
    /* Two sweepers: one at a time takes the pool, the other skips. */
    worker_t sweeper = { .pool = &pool, .stop = &stop };
    for (unsigned i = 0u; i < k_sweepers; ++i)
        CHECK(pthread_create(&sw[i], nullptr, s_sweeper, &sweeper) == 0);
    for (unsigned i = 0u; i < k_threads; ++i)
        pthread_join(th[i], nullptr);
    atomic_store(&stop, true);
    for (unsigned i = 0u; i < k_sweepers; ++i)
        pthread_join(sw[i], nullptr);

    unsigned took = 0u;
    for (unsigned i = 0u; i < k_threads; ++i)
        took += w[i].took;
    CHECK(took > 0u);
    for (unsigned i = 0u; i < k_slots; ++i)
        CHECK(atomic_load(&owner[i]) == 0u);

    /* Every slot of the pool is back: they all come out once. */
    bool seen[k_slots] = {};
    unsigned count = 0u;
    for (uint32_t idx; (idx = duct_x_slot_acquire(&pool)) != treiber_empty; ++count) {
        CHECK(idx < k_slots && !seen[idx]);
        seen[idx] = true;
    }
    CHECK(count == k_slots);
    CHECK(duct_atomic_load(&pool.live, relaxed) == pool.n_chunks);
    for (unsigned i = 0u; i < k_slots; ++i)
        duct_x_slot_release(&pool, i);
    duct_x_slot_pool_free(&pool);
    CHECK(atomic_load(&log.ups) == atomic_load(&log.downs));
    printf("  concurrent OK (%u slots taken, %u chunk registrations)\n", took, atomic_load(&log.ups));
}

int main(void)
{
    printf("x_slot_test\n");
    check_empty_pool();
    check_growth_by_chunk();
    check_addressing();
    check_claims();
    check_batch();
    check_hooks();
    check_sweep();
    check_class_pair();
    check_reserve();
    check_concurrent();
    printf("x_slot: OK\n");
    return 0;
}
