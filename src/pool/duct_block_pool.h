/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_block_pool.h
 *  @brief Fixed-size blocks over one lazy VM reserve, a hierarchical bitmap
 *  1-based free list, and a budgeted tail-discard stepper.
 *
 *  One pool owns one address range of @c n_blocks equal blocks, a block a
 *  power of two; the block number is the slot index, so every substructure
 *  of a slot sits at a fixed offset of its block. Free blocks are bits: one
 *  @c uint64_t word holds @c block_run_drop of them, and an acquire clears
 *  the lowest set bit a word offers, so live blocks stay dense under churn.
 *  Each block's life is a state word in resident per-block metadata, and the
 *  first @c page0 bytes of a block stay resident from its first opening —
 *  the tail alone is ever returned to the system, by @c duct_vm_discard.
 *
 *  A release that names the touched pages of its block marks it dirty; dirty
 *  bytes past @c max(live bytes, floor) and a free word that fills whole
 *  past the floor words become the work of @ref duct_block_pool_sweep_step,
 *  which spends a caller-given budget one run word or one dirty block at a
 *  time. The pool carries no generation or lifecycle words of the conns and
 *  sessions above it; page 0 is theirs to keep.
 */

#ifndef DUCT_BLOCK_POOL_H
#define DUCT_BLOCK_POOL_H

#include "duct_core.h"
#include "duct_conn.h"

#include <stdatomic.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

static_assert(alloc_slot_bits == hconn_idx_bits,
              "the header's slot word and the handle word are one index width");

/** @brief Life of one block, held in its @c meta word.
 *  Transitions run by compare-exchange from an acquire or the sweeper, and
 *  by the owner's release store; a stale reader that finds a state below
 *  @c blk_active leaves the block's memory untouched.
 */
typedef enum duct_blk_state : uint8_t {
    blk_uncommitted, /**< Range reserved, memory committed nowhere and touched never. */
    blk_committing,  /**< An acquire holds it: the one commit of its life runs. */
    blk_active,      /**< Owned by a slot user. */
    blk_warm_free,   /**< Free with its tail resident: reuse costs no syscall. */
    blk_discarding,  /**< The sweeper holds it and is dropping its tail. */
    blk_discarded,   /**< Tail given back, page 0 resident; reuse runs @c duct_vm_reuse. */
} duct_blk_state_t;

/** @brief Phases of a sweep cursor: whole run words first, then dirty blocks. */
typedef enum duct_sweep_phase {
    sweep_idle,        /**< Between passes; the next step resets the cursor. */
    sweep_scan_runs,   /**< Dropping claimed whole words of free blocks. */
    sweep_scan_dirty,  /**< Dropping the dirtiest free blocks past the watermark. */
} duct_sweep_phase_t;

/** @brief Position of a sweep between steps, private to its caller.
 *  Words past @c run_scan are searched for the next claimed run;
 *  @c run_word with @c run_off walks the run being dropped, and
 *  @c dirty_word is the word the dirty scan resumes at.
 */
typedef struct duct_sweep_cursor {
    duct_sweep_phase_t phase;
    uint32_t run_scan,
             run_word,
             run_off,
             dirty_word;
} duct_sweep_cursor_t;

/** @brief Resident per-block record: the state word and the touched high-water.
 *  @c touched counts pages, zero once a sweep has dropped the tail.
 */
typedef struct duct_blk_meta {
    duct_blk_state_t _Atomic state;
    uint16_t touched;
} duct_blk_meta_t;

/** @brief One pool's blocks: the fixed line and the acquire/release line.
 *  The first line holds what init fixed — the range, the three bitmaps, the
 *  metadata and the sizes; the second the words every acquire and release
 *  touches, on a cache line of their own.
 */
typedef struct duct_block_pool {
    duct_cacheline_struct_ext(_fixed_pad,
        duct_vm_handle_t vm;
        duct_ptr_t(_Atomic uint64_t) free_bits;
        duct_ptr_t(_Atomic uint64_t) dirty_bits;
        duct_ptr_t(_Atomic uint64_t) run_bits;
        duct_ptr_t(duct_blk_meta_t)  meta;
        uint32_t n_blocks,
                 block_size,
                 page0,
                 floor_words;
        size_t   floor;
    );
    duct_cacheline_struct_ext(_hot_pad,
        uint32_t _Atomic acquire_hint;
        uint64_t _Atomic live_bytes,
                          dirty_bytes;
    );
} duct_block_pool_t;

static_assert(offsetof(duct_block_pool_t, acquire_hint) % duct_cacheline_size == 0u
              && offsetof(duct_block_pool_t, acquire_hint) >= duct_cacheline_size,
              "the acquire and release line stands on its own cache line");

/** @brief Acquire answer when the pool holds no free block it can open. */
static constexpr uint32_t duct_blk_none = UINT32_MAX;

/** @brief Blocks one bitmap word covers; the run a whole word's drop takes. */
static constexpr uint32_t block_run_drop = 64u;

/** @brief Bitmap words @p n_blocks divide into. */
static inline uint32_t duct_blk_words(uint32_t n_blocks)
{
    return (n_blocks + block_run_drop - 1u) / block_run_drop;
}

/** @brief Mask of the valid bits of word @p w: the whole word, or the low
 *  @c n_blocks modulo the run where the last word runs short. */
duct_nonnull(1) static inline uint64_t
duct_blk_word_mask(const duct_block_pool_t *pool, uint32_t w)
{
    uint32_t tail = pool->n_blocks % block_run_drop;
    return tail && w + 1u == duct_blk_words(pool->n_blocks)
        ? (1ull << tail) - 1u : UINT64_MAX;
}

/** @brief Address of block @p idx, unchecked: @p idx is below @c n_blocks. */
duct_nonnull(1) static inline void *duct_block_pool_at(const duct_block_pool_t *pool, uint32_t idx)
{
    return (uint8_t *)pool->vm.base + (size_t)idx * pool->block_size;
}

/** @brief Set @p pool up over @c n_blocks blocks of @p block_size bytes, the
 *  first @p page0 of each resident for its life and @p floor bytes of dirt
 *  below the watermark always.
 *  The range is reserved lazily: no RAM and no commit at return, every block
 *  @c blk_uncommitted, every bitmap bit free. @p block_size and @p page0 are
 *  whole pages of the running system.
 *  @return false when an argument is zero, @p page0 passes @p block_size, a
 *          size is off the page grid, or the reserve or the arrays fail.
 */
[[nodiscard]] duct_nonnull(1) bool
duct_block_pool_init(duct_block_pool_t *pool, uint32_t n_blocks, uint32_t block_size,
                     uint32_t page0, size_t floor);

/** @brief Take the whole range down and free the arrays; a zeroed pool is left.
 *  Walks the complement of the free bitmap first — exactly the ever-opened
 *  blocks — and asserts each live, run-claimed or never committed, so a leak
 *  past shutdown names itself.
 */
duct_nonnull(1) void duct_block_pool_shutdown(duct_block_pool_t *pool);

/** @brief Take the lowest free block and open it, from any thread.
 *  Opening follows the block's state: a never-committed block commits once in
 *  its life and answers @c duct_blk_none when the commit is refused; a warm
 *  free block reuses at no syscall; a discarded one runs @c duct_vm_reuse on
 *  its tail. A word a run claim holds reads empty until the sweeper restores
 *  its bits — the caller that meets one steps @ref duct_block_pool_sweep_step
 *  itself and retries.
 *  @return The block index, or @ref duct_blk_none.
 */
duct_nonnull(1) uint32_t duct_block_pool_acquire(duct_block_pool_t *pool);

/** @brief Give block @p idx back and record @p touched pages of high-water.
 *  The block turns warm free and its bit returns to the bitmap at once; a
 *  nonzero @p touched marks it dirty and adds its pages to @c dirty_bytes,
 *  and the pages the block held leave @c live_bytes. A release that fills a
 *  bitmap word whole, in a word past the floor, claims the word for the
 *  sweeper by compare-exchange — its blocks hide from an acquire until the
 *  run restores them.
 */
duct_nonnull(1) void duct_block_pool_release(duct_block_pool_t *pool, uint32_t idx, uint16_t touched);

/** @brief Resolve block @p idx to its address, @c nullptr unless it is live.
 *  A stale index or a block below @c blk_active answers @c nullptr without
 *  touching the block's memory; raw page-0 readers that hold their own
 *  liveness proof use @ref duct_block_pool_at.
 */
duct_nonnull(1) void *duct_block_pool_block(const duct_block_pool_t *pool, uint32_t idx);

/** @brief Spend one @p budget of sweep work: claimed run words first, then
 *  the dirtiest free blocks while the watermark stands.
 *  A unit of work is a whole run word or one dirty block, charged ahead of
 *  the grab, so a step leaves no half-dropped word behind. The cursor
 *  carries the position; a @c sweep_idle cursor starts a fresh pass.
 *  @return true when work a next step would take remains.
 */
duct_nonnull(1, 2) bool
duct_block_pool_sweep_step(duct_block_pool_t *pool, duct_sweep_cursor_t *cursor,
                           uint32_t budget);

#ifdef __cplusplus
}
#endif

#endif
