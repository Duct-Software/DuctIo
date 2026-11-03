/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_x_slot.c
 *  @brief Growth, sweep and publication of the elastic slot pool.
 *
 *  The contract of each entry is in duct_x_slot.h. A chunk moves absent, growing, live, retiring,
 *  absent: the thread that claims an absent chunk by compare-exchange advances it to live, and the
 *  one sweep that holds the pool advances it from live to retiring and back to absent.
 */

#include "duct_x_slot.h"

#include <assert.h>

/** @brief Slots of chunk @p chunk, the last chunk taking the remainder. */
static uint32_t s_chunk_count(const duct_x_slot_pool_t *pool, uint32_t chunk)
{
    uint32_t n = (uint32_t)duct_len(pool->slots);
    return duct_min(pool->chunk_slots, n - chunk * pool->chunk_slots);
}

/** @brief First byte of chunk @p chunk. */
static void *s_chunk_base(const duct_x_slot_pool_t *pool, uint32_t chunk)
{
    return duct_x_slot_data(pool, chunk * pool->chunk_slots);
}

/** @brief Bytes of chunk @p chunk. */
static size_t s_chunk_bytes(const duct_x_slot_pool_t *pool, uint32_t chunk)
{
    return (size_t)s_chunk_count(pool, chunk) * pool->slot_bytes;
}

/** @brief Grow @p pool by the first absent chunk, scanning round the ring from @c grow_at.
 *  Runs the up hook on the chunk, then makes it live and pushes its slots in reverse index order, so
 *  a pop yields the lowest first. A refusal leaves the chunk absent, and one other than @c rc_again
 *  ends the pool's growth.
 *  @return true when a chunk went live.
 */
static bool s_grow(duct_x_slot_pool_t *pool)
{
    auto chunks = duct_at(pool->chunks);
    uint32_t from = duct_atomic_load(&pool->grow_at, relaxed);
    if (from == duct_x_slot_grow_ended)
        return false;
    for (uint32_t i = 0u; i < pool->n_chunks; ++i) {
        uint32_t c = from + i >= pool->n_chunks ? from + i - pool->n_chunks : from + i;
        uint32_t absent = chunk_absent;
        if (!duct_atomic_cas(strong, &chunks[c].state, &absent, chunk_growing, acquire, relaxed))
            continue;
        auto rc = pool->hooks.up ? pool->hooks.up(pool->hooks.ctx, s_chunk_base(pool, c),
                                                  s_chunk_bytes(pool, c), &chunks[c].cookie)
                                 : rc_ok;
        if (rc != rc_ok) {
            duct_atomic_store(&chunks[c].state, chunk_absent, release);
            if (rc != rc_again)
                duct_atomic_store(&pool->grow_at, duct_x_slot_grow_ended, relaxed);
            return false;
        }
        duct_atomic_store(&chunks[c].state, chunk_live, release);
        duct_atomic_store(&pool->grow_at, c + 1u, relaxed);
        duct_atomic_fetch(add, &pool->live, 1u, relaxed);
        for (uint32_t k = s_chunk_count(pool, c); k-- > 0u;)
            duct_x_slot_free_push(&pool->free_head, duct_at(pool->slots), c * pool->chunk_slots + k);
        return true;
    }
    return false;
}

/** @brief Give chunk @p chunk back to the system.
 *  Withdraws it from the backend, then discards the whole pages inside its bytes, so a page shared
 *  with a neighbouring chunk stays. The chunk reads absent, and a grower may claim it, from the final
 *  store.
 */
static void s_retire(duct_x_slot_pool_t *pool, uint32_t chunk)
{
    auto info = &duct_at(pool->chunks)[chunk];
    if (pool->hooks.down && info->cookie)
        pool->hooks.down(pool->hooks.ctx, info->cookie);
    info->cookie = 0u;
    size_t page = duct_page_size();
    uintptr_t lo = (uintptr_t)s_chunk_base(pool, chunk),
              hi = lo + s_chunk_bytes(pool, chunk);
    lo = (lo + page - 1u) & ~(page - 1u);
    hi &= ~(page - 1u);
    if (hi > lo)
        duct_vm_discard((void *)lo, hi - lo);
    duct_atomic_fetch(sub, &pool->live, 1u, relaxed);
    if (chunk < duct_atomic_load(&pool->grow_at, relaxed))
        duct_atomic_store(&pool->grow_at, chunk, relaxed);
    duct_atomic_store(&info->state, chunk_absent, release);
}

uint32_t duct_x_slot_refill(duct_x_slot_pool_t *pool)
{
    duct_atomic_fetch(add, &pool->pressure, 1u, relaxed);
    uint32_t idx = duct_x_slot_free_pop(&pool->free_head, duct_at(pool->slots));
    if (idx == treiber_empty && s_grow(pool))
        idx = duct_x_slot_free_pop(&pool->free_head, duct_at(pool->slots));
    return idx;
}

bool duct_x_slot_pool_sweep(duct_x_slot_pool_t *pool)
{
    uint32_t pressure = duct_atomic_load(&pool->pressure, relaxed);
    if (duct_atomic_exchange(&pool->seen, pressure, relaxed) != pressure)
        return false;
    if (duct_atomic_load(&pool->live, relaxed) <= duct_x_slot_floor_chunks)
        return false;
    bool idle = false;
    if (!duct_atomic_cas(strong, &pool->sweeping, &idle, true, acquire, relaxed))
        return false;
    auto chunks = duct_at(pool->chunks);
    auto links = duct_at(pool->slots);
    for (uint32_t c = 0u; c < pool->n_chunks; ++c)
        chunks[c].freed = 0u;
    /* A chunk is idle when every one of its slots comes out of the list here, held by no one. */
    uint32_t chain = treiber_empty;
    for (uint32_t idx; (idx = duct_x_slot_free_pop(&pool->free_head, links)) != treiber_empty;) {
        ++chunks[duct_x_slot_chunk_of(pool, idx)].freed;
        duct_atomic_store(&links[idx].next, chain, relaxed);
        chain = idx;
    }
    for (uint32_t c = pool->n_chunks; c-- > duct_x_slot_floor_chunks;)
        if (duct_atomic_load(&chunks[c].state, relaxed) == chunk_live
            && chunks[c].freed == s_chunk_count(pool, c))
            duct_atomic_store(&chunks[c].state, chunk_retiring, relaxed);
    for (uint32_t idx = chain; idx != treiber_empty;) {
        uint32_t next = duct_atomic_load(&links[idx].next, relaxed);
        if (duct_atomic_load(&chunks[duct_x_slot_chunk_of(pool, idx)].state, relaxed) != chunk_retiring)
            duct_x_slot_free_push(&pool->free_head, links, idx);
        idx = next;
    }
    /* After the walk above, not inside it: a retired chunk is open to a grower, whose pushes
     * rewrite the links of its slots, and the chain still reads them until the walk is done. */
    for (uint32_t c = pool->n_chunks; c-- > duct_x_slot_floor_chunks;)
        if (duct_atomic_load(&chunks[c].state, relaxed) == chunk_retiring)
            s_retire(pool, c);
    duct_atomic_store(&pool->sweeping, false, release);
    return true;
}

bool duct_x_slot_pool_init(duct_x_slot_pool_t *pool, uint32_t n, uint32_t slot_bytes,
                           uint32_t lead, uint32_t chunk_slots, duct_x_slot_hooks_t hooks)
{
    *pool = (duct_x_slot_pool_t){};
    atomic_init(&pool->free_head, treiber_head_pack(0u, treiber_empty));
    duct_do_if(!n || !slot_bytes, return true);
    duct_do_if(lead > slot_bytes, return false);
    size_t bytes = 0u;
    bool of = duct_ckd_mul(&bytes, (size_t)n, (size_t)slot_bytes);
    duct_do_if(of, return false);
    uint32_t per = duct_min(chunk_slots ? chunk_slots : n, n),
             chunks = (n + per - 1u) / per;
    /* The links start on a cache line, so the allocation header that duct_len reads shares none with
     * the first links, the slots a LIFO list reuses first. */
    auto slots = duct_new(duct_x_slot_t, n, duct_cacheline_size);
    auto info = slots ? duct_new(duct_x_slot_chunk_t, chunks) : nullptr;
    assert(!hooks.reserve || hooks.up);
    auto range = !info ? (duct_vm_handle_t){} : hooks.reserve ? duct_vm_reserve(bytes) : duct_vm_new(bytes);
    duct_do_if(!range.base, duct_del(info); duct_del(slots); return false);
    pool->slots = slots;
    pool->chunks = info;
    pool->range = range;
    pool->hooks = hooks;
    pool->slot_bytes = slot_bytes;
    pool->lead = lead;
    pool->chunk_slots = per;
    pool->n_chunks = chunks;
    return true;
}

duct_x_slot_pool_t *
duct_x_slot_pool_publish(duct_x_slot_pool_t *_Atomic *slot, duct_x_slot_pool_t *fresh)
{
    duct_x_slot_pool_t *held = nullptr;
    if (duct_atomic_cas(strong, slot, &held, fresh, acq_rel, acquire))
        return fresh;
    duct_x_slot_pool_free(fresh);
    duct_del(fresh);
    return held;
}

void duct_x_slot_pool_free(duct_x_slot_pool_t *pool)
{
    if (pool->range.base && pool->hooks.down)
        for (uint32_t c = 0u; c < pool->n_chunks; ++c)
            if (duct_at(pool->chunks)[c].cookie)
                pool->hooks.down(pool->hooks.ctx, duct_at(pool->chunks)[c].cookie);
    duct_vm_del(&pool->range);
    duct_del(pool->chunks);
    duct_del(pool->slots);
    *pool = (duct_x_slot_pool_t){};
}
