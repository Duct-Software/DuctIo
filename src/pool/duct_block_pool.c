/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_block_pool.c
 *  @brief The block state machine of the block pools.
 *
 *  Implements the acquire, release and sweep contract of
 *  @ref duct_block_pool.h over the three bitmaps. The process-global
 *  slot-return table with its pool ids is gone: a slot names its pool by
 *  the owner word its pool stamps, resolved where the slot is released.
 */

#include "duct_block_pool.h"
#include "duct_x_slot.h"

#include <assert.h>

/** @brief Lower the acquire hint to word @p w when it sat higher. */
static void s_hint_lower(duct_block_pool_t *pool, uint32_t w)
{
    uint32_t hint = duct_atomic_load(&pool->acquire_hint, relaxed);
    while (hint > w) {
        if (duct_atomic_cas(weak, &pool->acquire_hint, &hint, w, relaxed, relaxed))
            break;
    }
}

/** @brief Claim the whole free word @p w for the sweeper: the bits to zero
 *  by compare-exchange, the word's own run bit set. */
static void s_run_claim(duct_block_pool_t *pool, uint32_t w)
{
    uint64_t full = UINT64_MAX;
    if (!duct_atomic_cas(strong, &duct_at(pool->free_bits)[w], &full, 0ull, acq_rel, relaxed))
        return;
    duct_atomic_fetch(or, &duct_at(pool->run_bits)[w >> 6], 1ull << (w & 63u), release);
}

/** @brief Take block @p idx back from the dirty set at its reuse: the dirty
 *  bit off and its pages moving from dirty to live accounting. */
static void s_dirty_revive(duct_block_pool_t *pool, uint32_t idx)
{
    auto m = &duct_at(pool->meta)[idx];
    uint64_t bit = 1ull << (idx % block_run_drop);
    uint64_t was = duct_atomic_fetch(and, &duct_at(pool->dirty_bits)[idx / block_run_drop],
                                     ~bit, relaxed);
    if ((was & bit) && m->touched) {
        uint64_t pages = (uint64_t)m->touched * duct_page_size();
        duct_atomic_fetch(sub, &pool->dirty_bytes, pages, relaxed);
        duct_atomic_fetch(add, &pool->live_bytes, pages, relaxed);
    }
}

/** @brief Move block @p idx, its free bit already cleared, to @c blk_active.
 *  A never-committed block commits once in its life; a warm free block
 *  flips; a discarded one flips and makes its tail reusable.
 *  @return false when the one commit was refused, the block back to
 *  @c blk_uncommitted.
 */
static bool s_blk_open(duct_block_pool_t *pool, uint32_t idx)
{
    auto m = &duct_at(pool->meta)[idx];
    auto state = duct_atomic_load(&m->state, acquire);
    switch (state) {
    case blk_uncommitted:
        duct_blk_state_t from = blk_uncommitted;
        duct_discard duct_atomic_cas(strong, &m->state, &from, blk_committing, acq_rel, relaxed);
        auto rc = duct_vm_commit(duct_block_pool_at(pool, idx), pool->block_size);
        if (rc != rc_ok) {
            duct_atomic_store(&m->state, blk_uncommitted, relaxed);
            return false;
        }
        duct_atomic_store(&m->state, blk_active, release);
        return true;
    case blk_warm_free:
        from = blk_warm_free;
        duct_discard duct_atomic_cas(strong, &m->state, &from, blk_active, acq_rel, relaxed);
        s_dirty_revive(pool, idx);
        return true;
    case blk_discarded:
        from = blk_discarded;
        duct_discard duct_atomic_cas(strong, &m->state, &from, blk_active, acq_rel, relaxed);
        duct_vm_reuse((uint8_t *)duct_block_pool_at(pool, idx) + pool->page0,
                      pool->block_size - pool->page0);
        return true;
    default:
        duct_unreachable();
    }
}

bool duct_block_pool_init(duct_block_pool_t *pool, uint32_t n_blocks, uint32_t block_size,
                          uint32_t page0, size_t floor)
{
    *pool = (duct_block_pool_t){};
    duct_do_if(!n_blocks || !block_size || !page0 || page0 > block_size
               || block_size % duct_page_size() != 0u || page0 % duct_page_size() != 0u,
               return false);
    auto vm = duct_vm_reserve_lazy((size_t)n_blocks * block_size);
    duct_do_if(!vm.base, return false);
    uint32_t words = duct_blk_words(n_blocks);
    auto free_bits = duct_new(_Atomic uint64_t, words);
    auto dirty_bits = duct_new(_Atomic uint64_t, words);
    auto run_bits = duct_new(_Atomic uint64_t, duct_blk_words(words));
    auto meta = duct_new(duct_blk_meta_t, n_blocks);
    duct_do_if(!free_bits || !dirty_bits || !run_bits || !meta,
               duct_del(free_bits); duct_del(dirty_bits); duct_del(run_bits); duct_del(meta);
               duct_vm_del(&vm); return false);
    pool->vm = vm;
    pool->free_bits = free_bits;
    pool->dirty_bits = dirty_bits;
    pool->run_bits = run_bits;
    pool->meta = meta;
    pool->n_blocks = n_blocks;
    pool->block_size = block_size;
    pool->page0 = page0;
    pool->floor = floor;
    pool->floor_words = (uint32_t)(floor / ((size_t)block_run_drop * block_size));
    for (uint32_t w = 0u; w < words; ++w)
        duct_atomic_store(&duct_at(pool->free_bits)[w], duct_blk_word_mask(pool, w), relaxed);
    return true;
}

uint32_t duct_block_pool_acquire(duct_block_pool_t *pool)
{
    uint32_t words = duct_blk_words(pool->n_blocks);
    for (uint32_t w = duct_atomic_load(&pool->acquire_hint, relaxed); w < words; ++w) {
        uint64_t word = duct_atomic_load(&duct_at(pool->free_bits)[w], acquire);
        for (; word; duct_cpu_relax()) {
            uint32_t idx = (w << 6) + duct_ctz_ull(word);
            if (duct_atomic_cas(weak, &duct_at(pool->free_bits)[w], &word,
                                word & ~(1ull << (idx & 63u)), acquire, relaxed)) {
                if (s_blk_open(pool, idx))
                    return idx;
                duct_atomic_fetch(or, &duct_at(pool->free_bits)[idx >> 6],
                                  1ull << (idx & 63u), release);
                return duct_blk_none;
            }
        }
    }
    return duct_blk_none;
}

void duct_block_pool_release(duct_block_pool_t *pool, uint32_t idx, uint16_t touched)
{
    auto m = &duct_at(pool->meta)[idx];
    uint32_t w = idx / block_run_drop;
    uint64_t bit = 1ull << (idx % block_run_drop);
    uint16_t was = m->touched;
    m->touched = touched;
    duct_atomic_store(&m->state, blk_warm_free, relaxed);
    if (touched) {
        duct_atomic_fetch(or, &duct_at(pool->dirty_bits)[w], bit, relaxed);
        duct_atomic_fetch(add, &pool->dirty_bytes, (uint64_t)touched * duct_page_size(), relaxed);
    }
    if (was)
        duct_atomic_fetch(sub, &pool->live_bytes, (uint64_t)was * duct_page_size(), relaxed);
    uint64_t word = duct_atomic_fetch(or, &duct_at(pool->free_bits)[w], bit, release);
    s_hint_lower(pool, w);
    if ((word | bit) == UINT64_MAX && w >= pool->floor_words)
        s_run_claim(pool, w);
}

void *duct_block_pool_block(const duct_block_pool_t *pool, uint32_t idx)
{
    duct_do_if(idx >= pool->n_blocks, return nullptr);
    return duct_atomic_load(&duct_at(pool->meta)[idx].state, acquire) < blk_active
        ? nullptr : duct_block_pool_at(pool, idx);
}

/** @brief Drop the tail of block @p idx, page 0 untouched: the dirty bit
 *  off with its pages out of @c dirty_bytes, @c duct_vm_discard over the
 *  touched pages past @c page0, and the high-water back to zero. */
static void s_blk_tail_drop(duct_block_pool_t *pool, uint32_t idx)
{
    auto m = &duct_at(pool->meta)[idx];
    uint64_t bit = 1ull << (idx % block_run_drop);
    uint16_t touched = m->touched;
    if (touched) {
        uint64_t was = duct_atomic_fetch(and, &duct_at(pool->dirty_bits)[idx / block_run_drop],
                                         ~bit, relaxed);
        if (was & bit)
            duct_atomic_fetch(sub, &pool->dirty_bytes,
                              (uint64_t)touched * duct_page_size(), relaxed);
    }
    size_t resident = duct_min((size_t)touched * duct_page_size(), (size_t)pool->block_size);
    if (resident > pool->page0)
        duct_vm_discard((uint8_t *)duct_block_pool_at(pool, idx) + pool->page0,
                        resident - pool->page0);
    m->touched = 0u;
}

/** @brief First word from @p forward whose run bit stands, @c duct_blk_none. */
static uint32_t s_run_next(duct_block_pool_t *pool, uint32_t from)
{
    uint32_t words = duct_blk_words(pool->n_blocks);
    for (uint32_t w = from; w < words; ++w)
        if (duct_atomic_load(&duct_at(pool->run_bits)[w >> 6], relaxed) & 1ull << (w & 63u))
            return w;
    return duct_blk_none;
}

/** @brief Take the run bit of word @p w for this stepper alone. */
static bool s_run_grab(duct_block_pool_t *pool, uint32_t w)
{
    uint64_t word = duct_atomic_load(&duct_at(pool->run_bits)[w >> 6], acquire);
    for (; word & 1ull << (w & 63u); duct_cpu_relax()) {
        if (duct_atomic_cas(weak, &duct_at(pool->run_bits)[w >> 6], &word,
                            word & ~(1ull << (w & 63u)), acq_rel, relaxed))
            return true;
    }
    return false;
}

/** @brief Drop the tails of the claimed word @c cur->run_word holds and
 *  restore its bits whole.
 *  The unit costs one @p quota ahead of the walk; a never-committed or
 *  already-discarded member is skipped.
 *  @return false when @p quota is empty, the word left claimed for the next
 *  step.
 */
static bool s_run_drop(duct_block_pool_t *pool, duct_sweep_cursor_t *cur, uint32_t *quota)
{
    uint32_t w = cur->run_word;
    duct_do_if(!*quota, return false);
    --*quota;
    for (; cur->run_off < block_run_drop; ++cur->run_off) {
        uint32_t idx = w * block_run_drop + cur->run_off;
        auto m = &duct_at(pool->meta)[idx];
        auto state = duct_atomic_load(&m->state, acquire);
        if (state == blk_uncommitted)
            continue;
        assert(state == blk_warm_free || state == blk_discarded);
        if (state != blk_warm_free)
            continue;
        duct_atomic_store(&m->state, blk_discarding, relaxed);
        s_blk_tail_drop(pool, idx);
        duct_atomic_store(&m->state, blk_discarded, relaxed);
    }
    duct_atomic_store(&duct_at(pool->free_bits)[w], UINT64_MAX, release);
    cur->run_scan = w + 1u;
    cur->run_word = duct_blk_none;
    cur->run_off = 0u;
    return true;
}

/** @brief Drop the dirtiest free block of word @c cur->dirty_word, one unit
 *  of @p quota.
 *  The block's bit is cleared first and restored after its tail drop, so it
 *  hides from an acquire for exactly the drop; a bit the run claim holds or
 *  a live word leaves the dirty accounting instead of dropping.
 *  @return true when a block was dropped, false when the words ran out.
 */
static bool s_dirty_drop(duct_block_pool_t *pool, duct_sweep_cursor_t *cur, uint32_t *quota)
{
    uint32_t words = duct_blk_words(pool->n_blocks);
    while (cur->dirty_word < words) {
        uint32_t w = cur->dirty_word;
        uint64_t dirty = duct_atomic_load(&duct_at(pool->dirty_bits)[w], acquire);
        if (!dirty) {
            ++cur->dirty_word;
            continue;
        }
        if (duct_atomic_load(&duct_at(pool->run_bits)[w >> 6], acquire) & 1ull << (w & 63u)) {
            ++cur->dirty_word;
            continue;
        }
        uint32_t best = UINT32_MAX;
        for (uint32_t b = 0u; b < block_run_drop; ++b)
            if (dirty & 1ull << b
                && (best == UINT32_MAX
                    || duct_at(pool->meta)[w * block_run_drop + b].touched
                       > duct_at(pool->meta)[w * block_run_drop + best].touched))
                best = b;
        uint64_t bit = 1ull << best;
        bool grabbed = false;
        uint64_t word = duct_atomic_load(&duct_at(pool->free_bits)[w], acquire);
        for (; word & bit; duct_cpu_relax()) {
            grabbed = duct_atomic_cas(weak, &duct_at(pool->free_bits)[w], &word,
                                      word & ~bit, acquire, relaxed);
            if (grabbed)
                break;
        }
        if (!grabbed) {
            if (!word
                || duct_atomic_load(&duct_at(pool->run_bits)[w >> 6], acquire)
                   & 1ull << (w & 63u)) {
                ++cur->dirty_word;
                continue;
            }
            uint64_t was = duct_atomic_fetch(and, &duct_at(pool->dirty_bits)[w], ~bit, relaxed);
            if ((was & bit) && duct_at(pool->meta)[w * block_run_drop + best].touched) {
                uint64_t pages = (uint64_t)duct_at(pool->meta)[w * block_run_drop + best].touched
                                 * duct_page_size();
                duct_atomic_fetch(sub, &pool->dirty_bytes, pages, relaxed);
                duct_atomic_fetch(add, &pool->live_bytes, pages, relaxed);
            }
            continue;
        }
        uint32_t idx = w * block_run_drop + best;
        auto m = &duct_at(pool->meta)[idx];
        duct_atomic_store(&m->state, blk_discarding, relaxed);
        s_blk_tail_drop(pool, idx);
        duct_atomic_store(&m->state, blk_discarded, relaxed);
        duct_atomic_fetch(or, &duct_at(pool->free_bits)[w], bit, release);
        --*quota;
        return true;
    }
    return false;
}

/** @brief The watermark test: dirty past the larger of live and the floor. */
static bool s_dirty_over(duct_block_pool_t *pool)
{
    return duct_atomic_load(&pool->dirty_bytes, relaxed)
         > duct_max(duct_atomic_load(&pool->live_bytes, relaxed), pool->floor);
}

bool duct_block_pool_sweep_step(duct_block_pool_t *pool, duct_sweep_cursor_t *cur,
                                uint32_t budget)
{
    uint32_t quota = budget;
    switch (cur->phase) {
    case sweep_idle:
        cur->run_scan = 0u;
        cur->run_word = duct_blk_none;
        cur->run_off = 0u;
        cur->phase = sweep_scan_runs;
        [[fallthrough]];
    case sweep_scan_runs:
        if (cur->run_word != duct_blk_none && !s_run_drop(pool, cur, &quota))
            return true;
        for (;;) {
            duct_do_if(!quota, return true);
            uint32_t w = s_run_next(pool, cur->run_scan);
            if (w == duct_blk_none)
                break;
            cur->run_scan = w;
            if (!s_run_grab(pool, w))
                continue;
            if (duct_atomic_load(&duct_at(pool->free_bits)[w], acquire) == UINT64_MAX)
                continue;
            cur->run_word = w;
            cur->run_off = 0u;
            if (!s_run_drop(pool, cur, &quota))
                return true;
        }
        cur->phase = sweep_scan_dirty;
        cur->dirty_word = 0u;
        [[fallthrough]];
    case sweep_scan_dirty:
        while (quota && s_dirty_over(pool) && s_dirty_drop(pool, cur, &quota))
            ;
        cur->phase = sweep_idle;
        break;
    default:
        duct_unreachable();
    }
    if (s_run_next(pool, cur->run_scan) != duct_blk_none)
        return true;
    if (s_dirty_over(pool)) {
        uint32_t words = duct_blk_words(pool->n_blocks);
        for (uint32_t w = 0u; w < words; ++w)
            if (duct_atomic_load(&duct_at(pool->dirty_bits)[w], relaxed))
                return true;
    }
    return false;
}

void duct_block_pool_shutdown(duct_block_pool_t *pool)
{
    duct_do_if(!pool->vm.base, return);
    uint32_t words = duct_blk_words(pool->n_blocks);
    for (uint32_t w = 0u; w < words; ++w) {
        uint64_t live = ~duct_atomic_load(&duct_at(pool->free_bits)[w], acquire) & duct_blk_word_mask(pool, w);
        bool claimed = duct_atomic_load(&duct_at(pool->run_bits)[w >> 6], acquire)
                       & 1ull << (w & 63u);
        for (; live; live &= live - 1u) {
            uint32_t idx = (w << 6) + duct_ctz_ull(live);
            duct_blk_state_t state = duct_atomic_load(&duct_at(pool->meta)[idx].state, acquire);
            assert(state == blk_active || claimed || state == blk_uncommitted);
        }
    }
    duct_vm_del(&pool->vm);
    duct_del(pool->free_bits);
    duct_del(pool->dirty_bits);
    duct_del(pool->run_bits);
    duct_del(pool->meta);
    *pool = (duct_block_pool_t){};
}
