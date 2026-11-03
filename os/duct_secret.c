/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_secret.c
 *  @brief Secret arena: the locked pages that @c duct_new_secret blocks live in.
 *
 *  Seven slot classes, 64 to 4096 bytes, each a pool of the shared slot type over a reservation of
 *  address space of its own, built by the first secret of its class. A page of a class is locked in
 *  RAM, and kept out of core files where the system offers it, when the pool grows into it, and stays
 *  locked to the end of the process: nothing sweeps these pools. A class's free slots are the pool's
 *  free list, whose links sit in an array of their own, since a pop reads the top slot's link while
 *  another thread may already own that slot and write its object over it. A lock the system refuses
 *  ends the growth of its class.
 *
 *  A slot holds the 8-byte @c duct_alloc_hdr_t at its first byte and the object behind it, and
 *  comes out zeroed: a fresh page reads zero, and @c duct_secret_release wipes the header and the
 *  object before the slot goes back. A secret the arena does not take stays on the heap, marked
 *  secret and wiped at its release: a block aligned past 8 or over 4088 bytes, a class whose pages
 *  are spent or whose lock the system refused, a pool whose build failed, any block of an
 *  AddressSanitizer build.
 */

#include "duct_core.h"
#include "duct_x_slot.h"

/** @brief Slot classes, numbered 1 to 7; class 0 marks a block on the heap. */
enum : unsigned { s_classes = 7u };
static_assert(s_classes < 1u << alloc_arena_bits, "a class number fits the arena field of the header");

/** @brief Set in a build with AddressSanitizer, which keeps every secret on the heap.
 *  The sanitizer tracks a heap block and reports its use after the release; a slot goes back to
 *  its class at once, inside a mapping the sanitizer does not track.
 */
#ifdef __SANITIZE_ADDRESS__
static constexpr bool s_sanitized = true;
#else
static constexpr bool s_sanitized = false;
#endif

/** @brief Pool of each slot class, nullptr until the first secret of that class builds it.
 *  Index 0 is unused.
 */
static duct_x_slot_pool_t *_Atomic s_pools[s_classes + 1u];

/** @brief Bytes of a slot of class @p c, 64 for class 1 to 4096 for class 7. */
static size_t s_slot_size(unsigned c)
{
    return (size_t)1u << (c + 5u);
}

/** @brief Slots of class @p c on one page. */
static uint32_t s_per_page(unsigned c)
{
    return (uint32_t)(duct_page_size() / s_slot_size(c));
}

/** @brief Pages of the run of class @p c: @c duct_runtime_max_conns slots rounded up to a page, and one more. */
static uint32_t s_run_pages(unsigned c)
{
    size_t page = duct_page_size();
    return (uint32_t)(((size_t)duct_runtime_max_conns * s_slot_size(c) + page - 1u) / page + 1u);
}

/** @brief Smallest class whose slot holds @p total bytes, 0 for more than 4096. */
static unsigned s_class(size_t total)
{
    unsigned c = 1u;
    while (c <= s_classes && s_slot_size(c) < total)
        ++c;
    return c <= s_classes ? c : 0u;
}

/** @brief Up hook of a class pool: lock one page of its reserved range.
 *  Answers what @c duct_vm_lock answers, @c rc_ok for a page now usable, zeroed and locked and
 *  @c rc_no_memory for a refused commit or lock, which ends the growth of the class.
 */
static duct_result_t
s_lock([[maybe_unused]] void *ctx, void *base, size_t bytes, [[maybe_unused]] uintptr_t *cookie)
{
    return duct_vm_lock(base, bytes);
}

/** @brief Pool of class @p c, built and published by the first caller.
 *  A chunk is one page of @c s_per_page slots, the range @c s_run_pages pages, and the hooks reserve
 *  the range for @c s_lock to open a page at a time.
 *  @return The pool, nullptr where it cannot be built.
 */
static duct_x_slot_pool_t *s_pool_of(unsigned c)
{
    auto pool = duct_atomic_load(&s_pools[c], acquire);
    if (pool)
        return pool;
    auto fresh = duct_new(duct_x_slot_pool_t);
    duct_do_if(!fresh, return nullptr);
    uint32_t per = s_per_page(c);
    bool ok = duct_x_slot_pool_init(fresh, s_run_pages(c) * per, (uint32_t)s_slot_size(c), 0u, per,
                                    (duct_x_slot_hooks_t){ .up = s_lock, .reserve = true });
    duct_do_if(!ok, duct_del(fresh); return nullptr);
    return duct_x_slot_pool_publish(&s_pools[c], fresh);
}

/** @brief Pop a free slot of class @p c, the pool growing a page when none is free.
 *  @return The slot, nullptr when the pool or the class has none to give.
 */
static unsigned char *s_slot(unsigned c)
{
    auto pool = s_pool_of(c);
    duct_do_if(!pool, return nullptr);
    uint32_t i = duct_x_slot_acquire(pool);
    return i == treiber_empty ? nullptr : (unsigned char *)duct_x_slot_data(pool, i);
}

void *duct_secret_adopt(void *obj)
{
    auto h = (duct_alloc_hdr_t *)((unsigned char *)obj - sizeof(duct_alloc_hdr_t));
    /* Set ahead of every exit: a block left on the heap is wiped by its release. */
    h->secret = 1;
    /* A slot starts on a multiple of 64, so its object sits on 8 modulo 16: a block aligned wider stays. */
    unsigned c = s_sanitized || ((uintptr_t)obj & 15u) != 8u ? 0u : s_class(sizeof *h + h->size);
    auto slot = c ? s_slot(c) : nullptr;
    duct_do_if(!slot, return obj);
    /* Nothing is copied: duct_new zeroed the object and the caller has written none of it. */
    auto moved = (duct_alloc_hdr_t *)slot;
    moved->arena = c;
    moved->back = 1u;
    moved->secret = 1;
    moved->size = h->size;
    free((unsigned char *)obj - (size_t)h->back * sizeof *h);
    return slot + sizeof *h;
}

bool duct_secret_release(void *obj)
{
    auto h = (duct_alloc_hdr_t *)((unsigned char *)obj - sizeof(duct_alloc_hdr_t));
    unsigned c = h->arena;
    size_t size = h->size;
    if (!c) {
        /* A heap block keeps its header: duct_del reads back from it for the free. */
        duct_secure_zero(obj, size);
        return true;
    }
    /* A slot is wiped whole, header included, so that the next secret finds it zero. */
    duct_secure_zero(h, sizeof *h + size);
    auto pool = duct_atomic_load(&s_pools[c], acquire);
    duct_x_slot_release(pool, duct_x_slot_index(pool, h));
    return false;
}
