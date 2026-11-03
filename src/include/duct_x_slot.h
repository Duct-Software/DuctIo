/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_x_slot.h
 *  @brief Elastic pool of equal transfer slots for datagram receive and send, device legs and the secret arena.
 *
 *  A pool owns one address range of @c n slots behind a lock-free free list, cut into chunks. A chunk
 *  becomes usable when demand reaches it and goes back to the system when a sweep finds it idle, so
 *  memory follows load. The pool's hooks hand each chunk to a backend that must know it, such as a
 *  registered-I/O buffer or a page lock. Slot @c i lies at @c range.base + i * slot_bytes and its payload
 *  @c lead bytes in; its free-list link sits in an array of its own, so a pop reads a link while another
 *  thread writes the slot.
 *
 *  Any thread takes and returns slots, one at a time or several with one exchange of the list head. One
 *  growing thread claims one absent chunk by compare-exchange, and at most one sweep per pool runs, on
 *  an io thread; nothing here locks, spins or waits. The fields of a pool sit on four cache lines by
 *  who writes them: the list head, the fields fixed at init, the consumer's counters, and the grow and
 *  sweep state.
 *
 *  Invariants:
 *  - a chunk retires only when a sweep has popped every one of its slots, and after that sweep has
 *    walked the chain of slots it popped, since a chunk reads absent, and is open to a grower, as soon
 *    as it retires;
 *  - a return to the list is a seq_cst compare-exchange of the head, so the stall test after it needs no fence
 *    of its own: it pairs with the fence a reader takes between setting @c stalled and re-checking the
 *    list;
 *  - the bytes of a retired chunk are undefined, so a user writes a slot before it reads it; a pool made
 *    with @c hooks.reserve is never swept and its slots read zero;
 *  - the send side takes slots from a pair of pools, the small one at index 0 and the large at index 1,
 *    named by a reference that carries @ref duct_x_slot_ref_large for the large one.
 */

#ifndef DUCT_X_SLOT_H
#define DUCT_X_SLOT_H

#include "duct_core.h"
#include "duct_treiber.h"
#include "duct_types.h"

#include <assert.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Per-slot record of a pool: free-list link and claim count.
 *  The two words sit in an array beside the slot range, never in a slot.
 */
typedef struct duct_x_slot {
    uint32_t _Atomic next;    /**< Index of the next free slot while this one is on the free list or in a sweep's chain. */
    uint32_t _Atomic holders; /**< Holds on a taken slot: 0 while the lane alone holds it, 2 from the first claim, one more for each further claim. */
} duct_x_slot_t;

/** @brief Chunks a sweep never retires, the lowest indices.
 *  A pool at rest keeps one, so the first read after a lull finds slots with no grow and no registration.
 */
static constexpr uint32_t duct_x_slot_floor_chunks = 1u;

/** @brief Value of @c grow_at that ends the growth of a pool.
 *  An up hook's refusal other than @c rc_again stores it; a store of a grower or a retire that
 *  races the refusal undoes it, and the next refusal ends the growth again.
 */
static constexpr uint32_t duct_x_slot_grow_ended = UINT32_MAX;

/** @brief Backend hooks of a pool, fixed when the pool is made.
 *  A chunk is announced to the backend by @c up when it grows and withdrawn by @c down when it retires.
 */
typedef struct duct_x_slot_hooks {
    /** @brief Make a grown chunk usable to the backend and store its handle in @p cookie.
     *  Runs on the growing thread, under no lock. Answers @c rc_ok for a taken chunk, @c rc_again for a
     *  refusal that the next take on a dry pool retries, and any other code for a refusal that ends the
     *  pool's growth. A null hook takes every chunk.
     */
    duct_result_t (*up)(void *ctx, void *base, size_t bytes, uintptr_t *cookie);
    /** @brief Withdraw a chunk from the backend, @p cookie being the handle @c up stored.
     *  Runs for a chunk with a cookie when a sweep retires it, on the sweeping thread, and when the pool is freed.
     */
    void (*down)(void *ctx, uintptr_t cookie);
    void *ctx;     /**< Argument of both hooks. */
    bool  reserve; /**< Range kind: the range is reserved and stays inaccessible until @c up makes a chunk usable, so @c up is required. */
} duct_x_slot_hooks_t;

/** @brief Life of a chunk, held in its @c state word. */
enum : uint32_t {
    chunk_absent,   /**< No memory in use; the first grower to claim it takes it. */
    chunk_growing,  /**< A grower holds it and runs the up hook. */
    chunk_live,     /**< Its slots circulate. */
    chunk_retiring, /**< A sweep holds every slot of it and gives it back. */
};

/** @brief Record of one chunk of a pool. */
typedef struct duct_x_slot_chunk {
    uint32_t _Atomic state;  /**< Chunk life: absent, growing, live or retiring. */
    uint32_t         freed;  /**< Slots of the chunk the running sweep has popped, read and written under that sweep's claim alone. */
    uintptr_t        cookie; /**< Handle the up hook stored for the chunk, 0 for none. */
} duct_x_slot_chunk_t;

/** @brief Elastic pool of equal slots over one address range.
 *  Made by @ref duct_x_slot_pool_init and freed by @ref duct_x_slot_pool_free; a pool of no slots
 *  answers every take empty. Each group of fields below owns a cache line.
 */
typedef struct duct_x_slot_pool {
    /* Written by every taker and returner, so nothing else shares the line. */
    duct_cacheline_struct(
        uint64_t _Atomic  free_head; /**< Versioned head of the free-slot stack. */
    );
    /* Fixed at init and read by both sides of the list: no write reaches the line. */
    duct_cacheline_struct(
        duct_ptr_t(duct_x_slot_t)       slots;  /**< Record of each slot, @c n of them. */
        duct_ptr_t(duct_x_slot_chunk_t) chunks; /**< Record of each chunk, @c n_chunks of them. */
        duct_vm_handle_t  range;     /**< Address range of the @c n slots, null for a pool of none. */
        uint32_t          slot_bytes,  /**< Bytes of one slot, @c lead included. */
                          lead,        /**< Bytes ahead of a slot's payload, where the caller writes a header. */
                          chunk_slots, /**< Slots of a chunk, the last chunk taking the remainder. */
                          n_chunks;    /**< Chunks the range divides into, the most that go live. */
        unsigned          reader;    /**< Io id of the thread that reads the socket, the target of a resume. */
    );
    /* The consumer's: its worker moves claims and pins, and reads stalled at every return. */
    duct_cacheline_struct(
        uint32_t _Atomic  claims;    /**< Claims standing on taken slots, bounded by the slot count less one read batch. */
        uint32_t _Atomic  pins;      /**< Conns whose lane a worker holds behind a parked answer. */
        bool _Atomic      stalled;   /**< The reader parked its socket for want of a slot; set on receive pools alone. */
    );
    /* Written at a grow, a retire, a dry take and a sweep, none on the path of a datagram. */
    duct_cacheline_struct(
        duct_x_slot_hooks_t hooks;   /**< Backend hooks. */
        uint32_t _Atomic  live;      /**< Chunks live. */
        uint32_t _Atomic  grow_at;   /**< Chunk where the next grow's scan starts, or the value @c duct_x_slot_grow_ended. */
        uint32_t _Atomic  pressure;  /**< Takes that found the free list empty, wrapping. */
        uint32_t _Atomic  seen;      /**< Value of @c pressure the last sweep read. */
        bool _Atomic      sweeping;  /**< A sweep holds the pool. */
    );
} duct_x_slot_pool_t;

static_assert(sizeof(duct_x_slot_pool_t) == 4u * duct_cacheline_size,
              "a pool is four cache lines: the list head, the fields fixed at init, the consumer's, the grow and sweep state");
static_assert(offsetof(duct_x_slot_pool_t, slots) == duct_cacheline_size
              && offsetof(duct_x_slot_pool_t, claims) == 2u * duct_cacheline_size
              && offsetof(duct_x_slot_pool_t, hooks) == 3u * duct_cacheline_size,
              "each group of a pool starts a cache line");

/** @name Treiber pop, push and seed over @c duct_x_slot_t::next
 *  Instantiated as @c duct_x_slot_free_pop, @c _push and @c _seed.
 *  @{
 */
DUCT_TREIBER_DECLARE(duct_x_slot_free, duct_x_slot_t, next)
/** @} */

/** @brief Address of slot @p idx. */
duct_nonnull(1) static inline uint8_t *
duct_x_slot_data(const duct_x_slot_pool_t *pool, uint32_t idx)
{
    return (uint8_t *)pool->range.base + (size_t)idx * pool->slot_bytes;
}

/** @brief Address of slot @p idx's payload, @c lead bytes in. */
duct_nonnull(1) static inline uint8_t *
duct_x_slot_payload(const duct_x_slot_pool_t *pool, uint32_t idx)
{
    return duct_x_slot_data(pool, idx) + pool->lead;
}

/** @brief Payload bytes of one slot. */
duct_nonnull(1) static inline size_t duct_x_slot_cap(const duct_x_slot_pool_t *pool)
{
    return pool->slot_bytes - pool->lead;
}

/** @brief Test whether @p ptr lies inside slot @p idx. */
duct_nonnull(1) static inline bool
duct_x_slot_holds(const duct_x_slot_pool_t *pool, uint32_t idx, const void *ptr)
{
    auto base = (const uint8_t *)duct_x_slot_data(pool, idx);
    return (const void *)ptr >= (const void *)base && (const void *)ptr < (const void *)base + pool->slot_bytes;
}

/** @brief Test whether @p ptr lies inside the pool's range of slots, live chunks or not.
 *  False for a pool with no range.
 */
duct_nonnull(1) static inline bool
duct_x_slot_pool_owns(const duct_x_slot_pool_t *pool, const void *ptr)
{
    if (!pool->range.base)
        return false;
    auto base = (const char *)pool->range.base;
    return (const char *)ptr >= base
        && (const char *)ptr < base + (size_t)duct_len(pool->slots) * pool->slot_bytes;
}

/** @brief Index of the slot whose bytes @p ptr falls in.
 *  @p ptr lies inside the range, as @ref duct_x_slot_pool_owns tests.
 */
duct_nonnull(1) static inline uint32_t
duct_x_slot_index(const duct_x_slot_pool_t *pool, const void *ptr)
{
    return (uint32_t)((size_t)((const char *)ptr - (const char *)pool->range.base) / pool->slot_bytes);
}

/** @brief Chunk that holds slot @p idx. */
duct_nonnull(1) static inline uint32_t
duct_x_slot_chunk_of(const duct_x_slot_pool_t *pool, uint32_t idx)
{
    return idx / pool->chunk_slots;
}

/** @brief Byte offset of slot @p idx from the base of its chunk. */
duct_nonnull(1) static inline size_t
duct_x_slot_chunk_off(const duct_x_slot_pool_t *pool, uint32_t idx)
{
    return (size_t)(idx % pool->chunk_slots) * pool->slot_bytes;
}

/** @brief Handle the up hook stored for the chunk of slot @p idx.
 *  The caller holds the slot, so its chunk stays live.
 */
duct_nonnull(1) static inline uintptr_t
duct_x_slot_cookie(const duct_x_slot_pool_t *pool, uint32_t idx)
{
    return duct_at(pool->chunks)[duct_x_slot_chunk_of(pool, idx)].cookie;
}

/** @brief Take a slot from a free list found empty, growing the pool by one chunk where one can.
 *  Counts the take in @c pressure. Declared for @ref duct_x_slot_acquire and @ref duct_x_slot_acquire_n
 *  alone.
 *  @return The slot, or @c treiber_empty when the list is still empty.
 */
duct_nonnull(1) uint32_t duct_x_slot_refill(duct_x_slot_pool_t *pool);

/** @brief Take a free slot of @p pool, from any thread.
 *  @return The slot, or @c treiber_empty for a pool with no range, a pool whose chunks are all
 *          live and every slot out, a refused or ended grow, and a list a sweep holds.
 */
duct_nonnull(1) static inline uint32_t duct_x_slot_acquire(duct_x_slot_pool_t *pool)
{
    duct_do_if(!pool->range.base, return treiber_empty);
    uint32_t idx = duct_x_slot_free_pop(&pool->free_head, duct_at(pool->slots));
    return idx != treiber_empty ? idx : duct_x_slot_refill(pool);
}

/** @brief Take up to @p n slots off the top of the free list with one compare-exchange.
 *  Reads the links of the first @p n slots under the head's version, so a push or pop by any other
 *  thread fails the exchange and the walk starts again from the head it found. Grows nothing.
 *  @return How many slots came off, 0 for an empty list.
 */
duct_nonnull(1, 2) static inline uint32_t
duct_x_slot_free_pop_n(duct_x_slot_pool_t *pool, uint32_t *out, uint32_t n)
{
    auto links = duct_at(pool->slots);
    uint64_t head = duct_atomic_load(&pool->free_head, acquire);
    for (;; duct_cpu_relax()) {
        uint32_t got = 0u,
                 at = treiber_head_idx(head);
        for (; at != treiber_empty && got < n; ++got) {
            out[got] = at;
            at = duct_atomic_load(&links[at].next, relaxed);
        }
        if (!got)
            return 0u;
        uint64_t next = treiber_head_pack(treiber_head_ver(head) + 1u, at);
        if (duct_atomic_cas(weak, &pool->free_head, &head, next, acquire, relaxed))
            return got;
    }
}

/** @brief Take up to @p n free slots of @p pool into @p out in one step, from any thread.
 *  The slots come in the order of @p n single takes. A list that runs short grows the pool by one
 *  chunk, as @ref duct_x_slot_acquire does, and the rest of @p n comes from it.
 *  @param out  Room for @p n indices.
 *  @return How many slots were taken: fewer than @p n when the pool is at its ceiling with the rest out,
 *          and 0 where @ref duct_x_slot_acquire answers @c treiber_empty.
 */
duct_nonnull(1, 2) static inline uint32_t
duct_x_slot_acquire_n(duct_x_slot_pool_t *pool, uint32_t *out, uint32_t n)
{
    duct_do_if(!pool->range.base, return 0u);
    uint32_t got = duct_x_slot_free_pop_n(pool, out, n);
    while (got < n) {
        uint32_t idx = duct_x_slot_refill(pool);
        duct_do_if(idx == treiber_empty, break);
        out[got++] = idx;
        got += duct_x_slot_free_pop_n(pool, out + got, n - got);
    }
    return got;
}

/** @brief Return the @p n taken slots in @p idx to the free list with one compare-exchange, from any thread.
 *  The first of @p idx ends on top. Each index names a slot the caller holds, none twice. The exchange is
 *  seq_cst, which the stall test after a return relies on.
 */
duct_nonnull(1, 2) static inline void
duct_x_slot_release_n(duct_x_slot_pool_t *pool, const uint32_t *idx, uint32_t n)
{
    duct_do_if(!n, return);
    auto links = duct_at(pool->slots);
    for (uint32_t k = 1u; k < n; ++k)
        duct_atomic_store(&links[idx[k - 1u]].next, idx[k], relaxed);
    uint64_t head = duct_atomic_load(&pool->free_head, relaxed);
    for (;; duct_cpu_relax()) {
        duct_atomic_store(&links[idx[n - 1u]].next, treiber_head_idx(head), relaxed);
        uint64_t next = treiber_head_pack(treiber_head_ver(head) + 1u, idx[0]);
        if (duct_atomic_cas(weak, &pool->free_head, &head, next, seq_cst, relaxed))
            return;
    }
}

/** @brief Return slot @p idx to the free list, from any thread.
 *  @p idx names a slot the caller holds, or is @c treiber_empty, which a take on a pool of none answers and which
 *  returns nothing. The return is seq_cst, as that of @ref duct_x_slot_release_n.
 */
duct_nonnull(1) static inline void
duct_x_slot_release(duct_x_slot_pool_t *pool, uint32_t idx)
{
    duct_do_if(idx == treiber_empty, return);
    assert(idx < duct_len(pool->slots));
    duct_x_slot_release_n(pool, &idx, 1u);
}

/** @brief Test whether the free list holds no slot. */
duct_nonnull(1) static inline bool duct_x_slot_pool_dry(const duct_x_slot_pool_t *pool)
{
    return treiber_head_idx(duct_atomic_load(&pool->free_head, acquire)) == treiber_empty;
}

/** @brief Test whether a take can find a slot: the list holds one, or a chunk is not yet live. */
duct_nonnull(1) static inline bool duct_x_slot_pool_avail(const duct_x_slot_pool_t *pool)
{
    return pool->range.base
        && (!duct_x_slot_pool_dry(pool)
            || duct_atomic_load(&pool->live, relaxed) < pool->n_chunks);
}

/** @brief Take back the stall of @p pool.
 *  The caller's last step before the call is a seq_cst step on the pool, a return to the free list or
 *  a pin, which pairs with the fence the reader takes between setting @c stalled and its re-check.
 *  @return true for the caller that cleared it, who owes the reader a resume.
 */
duct_nonnull(1) static inline bool duct_x_slot_unstall(duct_x_slot_pool_t *pool)
{
    return duct_atomic_load(&pool->stalled, seq_cst)
        && duct_atomic_exchange(&pool->stalled, false, acq_rel);
}

/** @brief Take a claim on the taken slot @p idx, so that it outlives the lane's hold.
 *  @return false past the bound of the slot count less @c duct_dgram_rx_batch, which leaves the
 *          reader one read batch.
 */
duct_nonnull(1) static inline bool
duct_x_slot_claim(duct_x_slot_pool_t *pool, uint32_t idx)
{
    size_t n = pool->slots ? duct_len(pool->slots) : 0u;
    uint32_t room = n > duct_dgram_rx_batch ? (uint32_t)n - duct_dgram_rx_batch : 0u;
    if (duct_atomic_fetch(add, &pool->claims, 1u, relaxed) >= room) {
        duct_atomic_fetch(sub, &pool->claims, 1u, relaxed);
        return false;
    }
    auto holders = &duct_at(pool->slots)[idx].holders;
    if (duct_atomic_load(holders, relaxed))
        duct_atomic_fetch(add, holders, 1u, relaxed);
    else
        duct_atomic_store(holders, 2u, relaxed);
    return true;
}

/** @brief Drop one hold on slot @p idx: a claim's with @p claim, else the lane's.
 *  @return true for the drop that leaves no holder, whose caller releases the slot.
 */
duct_nonnull(1) static inline bool
duct_x_slot_drop(duct_x_slot_pool_t *pool, uint32_t idx, bool claim)
{
    auto holders = &duct_at(pool->slots)[idx].holders;
    if (claim)
        duct_atomic_fetch(sub, &pool->claims, 1u, relaxed);
    else if (!duct_atomic_load(holders, relaxed))
        return true;
    return duct_atomic_fetch(sub, holders, 1u, acq_rel) == 1u;
}

/** @brief Set up @p pool for @p n slots of @p slot_bytes each, @p lead of them ahead of the payload.
 *  Chunks of @p chunk_slots slots, @p n when it is 0; the range is mapped usable at once, or reserved
 *  when @p hooks.reserve is set. No chunk is live yet. A pool of no slots is valid and answers
 *  every take empty.
 *  @return false when @p lead exceeds @p slot_bytes, the size overflows or memory is short.
 */
[[nodiscard]] duct_nonnull(1) bool
duct_x_slot_pool_init(duct_x_slot_pool_t *pool, uint32_t n, uint32_t slot_bytes, uint32_t lead,
                      uint32_t chunk_slots, duct_x_slot_hooks_t hooks);

/** @brief Free @p pool: withdraw every chunk that has a cookie, unmap the range and drop the records.
 *  Every slot is back, and no other thread uses the pool.
 */
duct_nonnull(1) void duct_x_slot_pool_free(duct_x_slot_pool_t *pool);

/** @brief Store @p fresh in the shared @p slot unless another thread stored a pool there first.
 *  The loser frees its own pool.
 *  @return The pool that @p slot holds.
 */
duct_nonnull(1, 2) duct_x_slot_pool_t *
duct_x_slot_pool_publish(duct_x_slot_pool_t *_Atomic *slot, duct_x_slot_pool_t *fresh);

/** @brief Give the idle chunks of @p pool back, above the floor.
 *  Goes on only for a pool that met no empty free list since the last sweep and holds more than
 *  @ref duct_x_slot_floor_chunks live chunks, and only when no other sweep holds it; a sweep that
 *  finds another running returns at once. The free list is empty while the sweep runs, so a taker
 *  meets a dry pool.
 *  @return true when the sweep ran, and the caller wakes whoever waited on the pool.
 */
duct_nonnull(1) bool duct_x_slot_pool_sweep(duct_x_slot_pool_t *pool);

/** @brief Bit of a send reference that names the large pool of the pair. */
static constexpr uint32_t duct_x_slot_ref_large = 1u << 31;

/** @brief Pool of the pair @p pools that reference @p ref names. */
duct_nonnull(1) static inline duct_x_slot_pool_t *
duct_x_slot_ref_pool(duct_x_slot_pool_t *pools, uint32_t ref)
{
    return &pools[ref >> 31];
}

/** @brief Test whether the large pool of @p pools holds @p need payload bytes in a slot. */
duct_nonnull(1) static inline bool duct_x_slot_fits(const duct_x_slot_pool_t *pools, size_t need)
{
    return need <= duct_x_slot_cap(&pools[1]);
}

/** @brief Index of the pool of @p pools that serves @p need payload bytes: 0, the small one, where it fits. */
duct_nonnull(1) static inline unsigned
duct_x_slot_class_for(const duct_x_slot_pool_t *pools, size_t need)
{
    return need <= duct_x_slot_cap(&pools[0]) ? 0u : 1u;
}

/** @brief Take a slot that holds @p need payload bytes from the pair @p pools.
 *  @return A reference, the slot index with @ref duct_x_slot_ref_large set for the large pool, or
 *          @c treiber_empty as @ref duct_x_slot_acquire answers.
 */
duct_nonnull(1) static inline uint32_t duct_x_slot_take(duct_x_slot_pool_t *pools, size_t need)
{
    unsigned c = duct_x_slot_class_for(pools, need);
    uint32_t idx = duct_x_slot_acquire(&pools[c]);
    return idx == treiber_empty ? idx : idx | (c ? duct_x_slot_ref_large : 0u);
}

/** @brief Test whether a take of @p need payload bytes can find a slot.
 *  Answers as @ref duct_x_slot_pool_avail does for the pool of the pair that serves @p need.
 */
duct_nonnull(1) static inline bool duct_x_slot_has(const duct_x_slot_pool_t *pools, size_t need)
{
    return duct_x_slot_pool_avail(&pools[duct_x_slot_class_for(pools, need)]);
}

/** @brief Return the slot that reference @p ref names to its pool of the pair. */
duct_nonnull(1) static inline void duct_x_slot_put(duct_x_slot_pool_t *pools, uint32_t ref)
{
    duct_x_slot_release(duct_x_slot_ref_pool(pools, ref), ref & ~duct_x_slot_ref_large);
}

/** @brief Payload span of the slot that reference @p ref names, its capacity as the size. */
duct_nonnull(1) static inline duct_view_u8 duct_x_slot_span(duct_x_slot_pool_t *pools, uint32_t ref)
{
    auto pool = duct_x_slot_ref_pool(pools, ref);
    return (duct_view_u8){ .data = duct_x_slot_payload(pool, ref & ~duct_x_slot_ref_large),
                         .size = duct_x_slot_cap(pool) };
}

#ifdef __cplusplus
}
#endif

#endif
