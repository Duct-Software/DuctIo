/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */
/* AI-generated test code. */

/** @file block_pool_test.c
 *  @brief Unit test for the block pool machine: states, free bitmap, runs, the sweep stepper.
 *
 *  @c t_fresh_ctor expects a reserve of nothing committed, every block uncommitted, a stale
 *  @c duct_block_pool_block answered nullptr, and the acquire path handing out lowest indices
 *  until the pool is dry. @c t_open_active expects the first open to commit, to leave the block
 *  writable and the by-handle answer live. @c t_warm_reuse expects a release to warm the block,
 *  the bitmap to hand the lowest hole back first, and the touched watermark to move between the
 *  live and dirty sums as blocks cycle. @c t_watermark_drain expects the stepper, past its
 *  watermark, to drop the dirtiest free blocks first, to return their bits, and a reacquire to
 *  take a discarded block through the reuse path. @c t_run_claim expects a full 64-bit word to
 *  claim as one run, the quota to split the 64 tails across ticks, the bits to return whole, and
 *  a floor that covers the pool to keep runs from claiming. @c t_slot_pool expects the pool id
 *  table and the slot stamp: a stamped slot releases through the pool, keeps its holders, and
 *  answers its byte length behind the header.
 */

#include "../src/pool/duct_block_pool.h"
#include "duct_x_slot.h"

#include <stdio.h>
#include <string.h>

#define CHECK(expr, msg) \
    do { if (!(expr)) { fprintf(stderr, "FAIL: %s\n", msg); return 1; } } while (0)

static duct_blk_state_t s_state(const duct_block_pool_t *pool, uint32_t idx)
{
    return duct_atomic_load(&duct_at(pool->meta)[idx].state, acquire);
}

static uint64_t s_free_word(const duct_block_pool_t *pool, uint32_t w)
{
    return duct_atomic_load(&duct_at(pool->free_bits)[w], acquire);
}

static int t_fresh_ctor(void)
{
    duct_block_pool_t pool;
    size_t pg = duct_page_size();
    CHECK(duct_block_pool_init(&pool, 8u, 4u * pg, pg, 0u), "a pool reserves its range");
    CHECK(pool.vm.base && pool.vm.size == 8u * 4u * pg, "the reservation covers every block");
    for (uint32_t i = 0u; i < 8u; ++i) {
        CHECK(s_state(&pool, i) == blk_uncommitted, "a fresh block is uncommitted");
        CHECK(!duct_block_pool_block(&pool, i), "a stale lookup of an unopened block answers nullptr");
    }
    CHECK(!duct_block_pool_block(&pool, 8u), "an index past the pool answers nullptr");
    for (uint32_t i = 0u; i < 8u; ++i)
        CHECK(duct_block_pool_acquire(&pool) == i, "acquire hands out the lowest index first");
    CHECK(duct_block_pool_acquire(&pool) == duct_blk_none, "a dry pool answers none");
    duct_block_pool_shutdown(&pool);
    CHECK(!pool.vm.base, "shutdown drops the mapping");
    return 0;
}

static int t_open_active(void)
{
    duct_block_pool_t pool;
    size_t pg = duct_page_size();
    CHECK(duct_block_pool_init(&pool, 4u, 4u * pg, pg, 0u), "a pool comes up");
    uint32_t idx = duct_block_pool_acquire(&pool);
    CHECK(idx == 0u, "the first open takes the lowest block");
    auto at = (uint8_t *)duct_block_pool_block(&pool, idx);
    CHECK(at && at == (uint8_t *)pool.vm.base, "an open block answers its address");
    memset(at, 0xa5, 4u * pg);
    CHECK(at[0] == 0xa5u && at[4u * pg - 1u] == 0xa5u, "page 0 and the tail stay writable");
    CHECK(s_state(&pool, idx) == blk_active, "an open block is active");
    CHECK(!duct_block_pool_block(&pool, 1u), "an unopened neighbour still answers nullptr");
    duct_block_pool_release(&pool, idx, 4u);
    duct_block_pool_shutdown(&pool);
    return 0;
}

static int t_warm_reuse(void)
{
    duct_block_pool_t pool;
    size_t pg = duct_page_size();
    CHECK(duct_block_pool_init(&pool, 8u, 4u * pg, pg, 0u), "a pool comes up");
    for (uint32_t i = 0u; i < 8u; ++i)
        duct_discard duct_block_pool_acquire(&pool);
    duct_block_pool_release(&pool, 5u, 2u);
    duct_block_pool_release(&pool, 2u, 0u);
    CHECK(s_state(&pool, 5u) == blk_warm_free && s_state(&pool, 2u) == blk_warm_free,
          "a release warms the block");
    CHECK(duct_atomic_load(&duct_at(pool.dirty_bits)[0], relaxed) == 1ull << 5u,
          "a touched release marks its block dirty alone");
    CHECK(duct_atomic_load(&pool.dirty_bytes, relaxed) == 2u * pg,
          "the dirty sum holds the touched pages");
    CHECK(duct_block_pool_acquire(&pool) == 2u, "a clean warm block is the lowest hole");
    CHECK(duct_block_pool_acquire(&pool) == 5u, "a dirty warm block revives next");
    CHECK(duct_atomic_load(&duct_at(pool.dirty_bits)[0], relaxed) == 0u,
          "a revive clears the dirty mark");
    CHECK(duct_atomic_load(&pool.dirty_bytes, relaxed) == 0u
          && duct_atomic_load(&pool.live_bytes, relaxed) == 2u * pg,
          "the revived dirt moves to the live sum");
    duct_block_pool_release(&pool, 5u, 1u);
    CHECK(duct_atomic_load(&pool.live_bytes, relaxed) == 0u
          && duct_atomic_load(&pool.dirty_bytes, relaxed) == 1u * pg,
          "a release with a new watermark swaps the sums");
    duct_block_pool_shutdown(&pool);
    return 0;
}

static int t_watermark_drain(void)
{
    duct_block_pool_t pool;
    duct_sweep_cursor_t cursor = {};
    size_t pg = duct_page_size();
    CHECK(duct_block_pool_init(&pool, 8u, 4u * pg, pg, 0u), "a pool comes up");
    uint16_t touched[8] = {1u, 2u, 3u, 4u, 1u, 2u, 3u, 4u};
    for (uint32_t i = 0u; i < 8u; ++i) {
        CHECK(duct_block_pool_acquire(&pool) == i, "acquire stays dense");
        auto at = (uint8_t *)duct_block_pool_block(&pool, i);
        memset(at, 0x5a, (size_t)touched[i] * pg);
    }
    for (uint32_t i = 0u; i < 8u; ++i)
        duct_block_pool_release(&pool, i, touched[i]);
    CHECK(duct_atomic_load(&pool.dirty_bytes, relaxed) == 20u * pg, "the dirty sum holds the dirt");
    CHECK(duct_block_pool_sweep_step(&pool, &cursor, 2u), "the first tick drops the quota");
    CHECK(s_state(&pool, 3u) == blk_discarded && s_state(&pool, 7u) == blk_discarded,
          "the dirtiest blocks drop first");
    CHECK(s_state(&pool, 0u) == blk_warm_free, "a cleaner block stays warm");
    CHECK(duct_atomic_load(&duct_at(pool.free_bits)[0], relaxed) == 0xffu,
          "a dropped block's bit returns");
    unsigned ticks = 1u;
    while (duct_block_pool_sweep_step(&pool, &cursor, 2u))
        ++ticks;
    CHECK(duct_atomic_load(&pool.dirty_bytes, relaxed) == 0u, "the drain empties the dirt");
    for (uint32_t i = 0u; i < 8u; ++i)
        CHECK(s_state(&pool, i) == blk_discarded, "every dirty block dropped");
    CHECK(ticks >= 3u, "the quota split the drain over ticks");
    CHECK(duct_block_pool_acquire(&pool) == 0u, "a dropped block reopens through reuse");
    auto at = (uint8_t *)duct_block_pool_block(&pool, 0u);
    memset(at, 0xa5, 4u * pg);
    CHECK(at[pg] == 0xa5u, "a reused tail is writable again");
#ifdef __linux__
    for (uint32_t i = 1u; i < 8u; ++i) {
        auto dropped = (const uint8_t *)duct_block_pool_block(&pool, i);
        for (uint32_t p = 1u; p < touched[i]; ++p)
            CHECK(dropped && dropped[p * pg] == 0u,
                  "a dropped tail page reads zero on Linux");
    }
#endif
    duct_block_pool_shutdown(&pool);
    return 0;
}

static int t_run_claim(void)
{
    duct_block_pool_t pool;
    duct_sweep_cursor_t cursor = {};
    size_t pg = duct_page_size();
    CHECK(duct_block_pool_init(&pool, 128u, 4u * pg, pg, 0u), "a two-word pool comes up");
    for (uint32_t i = 0u; i < 128u; ++i) {
        CHECK(duct_block_pool_acquire(&pool) == i, "acquire walks every block");
        memset(duct_block_pool_block(&pool, i), 0x5a, pg);
    }
    for (uint32_t i = 0u; i < 128u; ++i)
        duct_block_pool_release(&pool, i, 1u);
    CHECK(s_free_word(&pool, 0u) == 0u && s_free_word(&pool, 1u) == 0u,
          "a full word claims as a run and leaves no free bits");
    CHECK(duct_atomic_load(&duct_at(pool.run_bits)[0], relaxed) == 3u,
          "both words wait in the run bitmap");
    CHECK(duct_block_pool_sweep_step(&pool, &cursor, 1u), "the first tick takes its quota");
    CHECK(s_state(&pool, 0u) == blk_discarded && s_state(&pool, 63u) == blk_discarded,
          "the tick drops its whole run word");
    CHECK(s_state(&pool, 64u) == blk_warm_free && s_free_word(&pool, 1u) == 0u,
          "the second word waits claimed");
    CHECK(s_free_word(&pool, 0u) == UINT64_MAX, "a finished run returns its bits whole");
    CHECK(duct_block_pool_sweep_step(&pool, &cursor, 1u), "the run drains over ticks");
    CHECK(!duct_block_pool_sweep_step(&pool, &cursor, 1u), "the drained pool settles");
    CHECK(s_free_word(&pool, 1u) == UINT64_MAX && s_state(&pool, 127u) == blk_discarded,
          "the second run finishes too");
    CHECK(duct_block_pool_acquire(&pool) == 0u, "a run-dropped block reopens");

    duct_block_pool_t floored;
    CHECK(duct_block_pool_init(&floored, 128u, 4u * pg, pg, 2u * block_run_drop * 4u * pg),
          "a floored pool comes up");
    for (uint32_t i = 0u; i < 128u; ++i)
        CHECK(duct_block_pool_acquire(&floored) == i, "acquire walks every block of the floored pool");
    for (uint32_t i = 0u; i < 128u; ++i)
        duct_block_pool_release(&floored, i, 0u);
    CHECK(s_free_word(&floored, 0u) == UINT64_MAX && s_free_word(&floored, 1u) == UINT64_MAX,
          "a floor past the words keeps a full word warm");
    duct_sweep_cursor_t none = {};
    CHECK(!duct_block_pool_sweep_step(&floored, &none, 8u), "a warm clean pool answers no work");
    CHECK(s_state(&floored, 0u) == blk_warm_free, "the floor keeps the block warm");
    duct_block_pool_shutdown(&floored);
    duct_block_pool_shutdown(&pool);
    return 0;
}

static int t_slot_pool(void)
{
    duct_x_slot_pool_t xpool;
    CHECK(duct_x_slot_pool_init(&xpool, 16u, 256u, 0u, 0u, 16u, (duct_x_slot_hooks_t){}),
          "a slot pool comes up");
    duct_x_slot_pool_engage(&xpool);
    uint32_t idx = duct_x_slot_acquire(&xpool);
    CHECK(idx != treiber_empty, "a slot comes");
    uint8_t *obj_at = duct_x_slot_obj(&xpool, idx);
    CHECK(duct_x_slot_obj_is(obj_at), "the owner word reads as a pool's");
    CHECK(duct_x_slot_pool_of(obj_at) == &xpool, "the word names its own pool");
    CHECK(duct_x_slot_obj_cap(obj_at) == duct_x_slot_cap(&xpool),
          "the object answers its capacity through the word");
    CHECK(duct_x_slot_index(&xpool, obj_at) == idx, "the slot reads back by address");
    uint32_t other = duct_x_slot_acquire(&xpool);
    CHECK(other != idx, "an out slot stays out of its pool");
    duct_x_slot_release_obj(obj_at);
    CHECK(duct_x_slot_acquire(&xpool) == idx, "the object return puts the slot back");
    duct_x_slot_release(&xpool, idx);
    duct_x_slot_release(&xpool, other);
    duct_x_slot_pool_free(&xpool);
    return 0;
}

int main(void)
{
    static int (*const tests[])(void) = {
        t_fresh_ctor, t_open_active, t_warm_reuse, t_watermark_drain, t_run_claim, t_slot_pool,
    };
    for (size_t i = 0u; i < sizeof tests / sizeof tests[0]; ++i)
        if (tests[i]())
            return 1;
    printf("block_pool: OK\n");
    return 0;
}
