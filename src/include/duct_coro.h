/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_coro.h
 *  @brief Stackful + stackless coroutine primitives and worker runtime.
 *
 *  @par Scope
 *  - Owns: stackful pool/queue, stackless pool/queue, runtime cycle.
 *  - Platform-specific pieces: the per-ISA stack switch, and the stack
 *   pool's own mmap.
 *
 *  @par Entry points
 *  @ref duct_coop_init, @ref duct_coop_cycle,
 *  @ref duct_coro_acquire, @ref duct_coro_resume, @ref duct_async_acquire.
 */

#ifndef DUCT_CORO_H
#define DUCT_CORO_H

#include "duct_build_config.h"
#include "duct_core.h"
#include "duct_types.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

static constexpr size_t coro_stack_default  = kbytes(64u);
static constexpr size_t coro_meta_size      = 128u;

/** @brief Stackful coro lifecycle dispatched by the scheduler. */
typedef enum duct_coro_state : uint8_t {
    coro_state_ready = 0u,  /**< Acquired, first resume still pending; on the run queue. */
    coro_state_running,     /**< Executing now, between switch-in and switch-out. */
    coro_state_suspended,   /**< Yielded, still runnable — rescheduled on the next cycle. */
    coro_state_waiting,     /**< Parked by duct_coro_wait; skipped until
                              * @c duct_coro_queue_wake moves it back to running. */
    coro_state_done,        /**< Entry returned; the drain releases the slot. */

    /** @note Additional states must be placed here. */
    coro_state_count        /**< States count; not a valid state. */
} duct_coro_state_t;

/** @brief Stackful coroutine meta; lives at the top of its own slot's stack,
 *  inside reserved @c coro_meta_size bytes.
 */
typedef struct duct_coro {
    void *saved_sp;             /**< SP saved at switch-out; the next resume switches into it. */
    char *stack_base;           /**< Usable stack bottom above the guard page. */
    duct_coro_state_t state;    /**< Lifecycle state. */
    duct_coro_func_t  func;     /**< Entry function, invoked on the first resume. */
    void             *arg;      /**< Opaque argument handed to @c func. */
    duct_coro_resume_fn on_resume;      /**< Handler post-resume hook; nullptr for "raw" coros. */
    void               *on_resume_ctx;  /**< Handler ctx passed to @c on_resume. */
    struct duct_coro   *next,   /**< Queue link; doubles as the pool free-list link. */
                      **pprev;  /**< Address of whichever link points at this node
                                  * (run_head/wait_head or a sibling's next) 
                                  * — O(1) unlink; NULL when not enqueued. */
} duct_coro_t;

static_assert(sizeof(duct_coro_t) <= coro_meta_size,
    "duct_coro_t exceeds coro_meta_size");

/** @brief Stackful coro pool over one reserved VM zone; guard pages arm
 *  lazily, slot by slot, on first acquire past the committed count.
 */
typedef struct duct_coro_pool {
    char   *base;           /**< One reserved VM zone all slots are carved from. */
    size_t  zone_size,      /**< Whole mapping, page-rounded by @c duct_vm_new. */
            slot_size,      /**< Per slot: guard page + stack. */
            guard_size,     /**< Protected bytes at each slot's bottom. */
            stack_usable;   /**< Stack bytes per slot below the @c duct_coro_t meta
                              * parked at the slot top (@c coro_meta_size). */
    unsigned n_committed,   /**< Slots whose guard page is armed; grows lazily. */
             n_alive;       /**< Acquired and unreleased coros. */
    duct_coro_t *free_list; /**< Released slots, linked via @c duct_coro_t::next. */
} duct_coro_pool_t;

/** @brief Reserve and map stack pool for up to @p max_slots coroutines. */
duct_nonnull(1) duct_result_t
duct_coro_pool_new(duct_coro_pool_t *pool, unsigned max_slots, size_t stack_bytes);

/** @brief Unmap coroutine pool and free all associated resources. */
duct_nonnull(1) void duct_coro_pool_del(duct_coro_pool_t *pool);

/** @brief Fetch a coroutine in ready state from pool. */
duct_nonnull(1) duct_coro_t *
duct_coro_acquire(duct_coro_pool_t *pool, duct_coro_func_t func, void *arg);

/** @brief Resume coroutine until yield/wait/done transition. */
duct_nonnull(1) void duct_coro_resume(duct_coro_t *coro);

/** @brief Yield from currently running coroutine back to scheduler context. */
void duct_coro_yield(void);

/** @brief Park currently running coroutine into waiting state. */
void duct_coro_wait(void);

/** @brief Finalize coroutine and return slot to pool free-list. */
duct_nonnull(1, 2) void duct_coro_release(duct_coro_pool_t *pool, duct_coro_t *coro);

/** @brief Save current stack pointer to @p from_sp and switch to @p to_sp. */
void duct_coro_switch(void **from_sp, void *to_sp);

/** @brief Build the initial synthetic stack pointer.
 *  Read by the first @ref duct_coro_resume.
 *  @p entry must follow void(void) ABI expected by platform trampolines.
 */
void *duct_coro_init_sp(char *stack_top, void *entry);

/** @brief Which side of a coop run/wait queue a node belongs to. */
typedef enum duct_coop_side : uint8_t {
    coop_run,   /**< Runnable FIFO; @c _next pops from here on each cycle. */
    coop_wait,  /**< Parked until @c _requeue returns the node to run side. */
} duct_coop_side_t;

/** @brief One generator for both coroutine flavors' scheduling queues: given a
 *  node type linked through its own next/pprev pair, it emits the queue
 *  struct plus _init/_enqueue/_next/_requeue/_remove. Two sides: run is a
 *  FIFO of runnables, wait holds parked nodes until _requeue puts them
 *  back. @p is_waiting_expr (candidate visible as @c node) tells _remove
 *  which side's counter to drop; the optional trailing argument names a
 *  bool field _enqueue keeps in sync — async's @c in_wait, while stackful
 *  passes none: @c state alone decides it.
 */
#define DUCT_COOP_QUEUE_DECLARE(queue_type,                                 \
                                prefix,                                     \
                                node_type,                                  \
                                is_waiting_expr,                            \
                                ...)                                        \
typedef struct queue_type {                                                 \
    node_type *run_head,  /* FIFO head — the next runnable to pop */        \
              *run_tail,  /* FIFO tail — where _enqueue appends */          \
              *wait_head; /* parked nodes; unordered, prepend-only */       \
    unsigned n_run,       /* nodes on the run side */                       \
             n_wait;      /* nodes on the wait side */                      \
} queue_type;                                                               \
                                                                            \
static duct_nonnull(1) inline void prefix##_init(queue_type *q)             \
{                                                                           \
    *q = (queue_type){};                                                    \
}                                                                           \
                                                                            \
/** @brief Link a node into the run (append) or wait (prepend) side. */     \
static duct_nonnull(1, 2) inline void                                       \
prefix##_enqueue(queue_type *q, node_type *node, duct_coop_side_t side)     \
{                                                                           \
    switch (side) {                                                         \
    case coop_run:                                                          \
        node->next = nullptr;                                               \
        node->pprev = q->run_tail ? &q->run_tail->next : &q->run_head;      \
        *node->pprev = node;                                                \
        q->run_tail = node;                                                 \
        ++q->n_run;                                                         \
        __VA_OPT__(node->__VA_ARGS__ = false;)                              \
        break;                                                              \
    case coop_wait:                                                         \
        node->next = q->wait_head;                                          \
        if (q->wait_head)                                                   \
            q->wait_head->pprev = &node->next;                              \
        node->pprev = &q->wait_head;                                        \
        q->wait_head = node;                                                \
        ++q->n_wait;                                                        \
        __VA_OPT__(node->__VA_ARGS__ = true;)                               \
        break;                                                              \
    }                                                                       \
}                                                                           \
                                                                            \
/** @brief Pop the next runnable node. */                                   \
static duct_nonnull(1) inline node_type *prefix##_next(queue_type *q)       \
{                                                                           \
    auto node = q->run_head;                                                \
    if (!node)                                                              \
        return nullptr;                                                     \
    q->run_head = node->next;                                               \
    if (q->run_head)                                                        \
        q->run_head->pprev = &q->run_head;                                  \
    else                                                                    \
        q->run_tail = nullptr;                                              \
    node->next = nullptr;                                                   \
    node->pprev = nullptr;                                                  \
    --q->n_run;                                                             \
    return node;                                                            \
}                                                                           \
                                                                            \
/** @brief Move a waiting node from the wait side back to run. */           \
static duct_nonnull(1, 2) inline void                                       \
prefix##_requeue(queue_type *q, node_type *node)                            \
{                                                                           \
    *node->pprev = node->next;                                              \
    if (node->next)                                                         \
        node->next->pprev = node->pprev;                                    \
    --q->n_wait;                                                            \
    prefix##_enqueue(q, node, coop_run);                                    \
}                                                                           \
                                                                            \
/** @brief Remove a node from whichever queue contains it. */               \
static duct_nonnull(1, 2) inline void                                       \
prefix##_remove(queue_type *q, node_type *node)                             \
{                                                                           \
    if (!node->pprev)                                                       \
        return;                                                             \
    *node->pprev = node->next;                                              \
    if (node->next)                                                         \
        node->next->pprev = node->pprev;                                    \
    if (is_waiting_expr)                                                    \
        --q->n_wait;                                                        \
    else {                                                                  \
        --q->n_run;                                                         \
        if (q->run_tail == node) {                                          \
            q->run_tail = q->run_head;                                      \
            if (q->run_tail)                                                \
                while (q->run_tail->next)                                   \
                    q->run_tail = q->run_tail->next;                        \
        }                                                                   \
    }                                                                       \
    node->next = nullptr;                                                   \
    node->pprev = nullptr;                                                  \
    __VA_OPT__(node->__VA_ARGS__ = false;)                                  \
}

/** @brief Stackful scheduling queue.
 *  Emits @c duct_coro_queue_t plus
 *  @c duct_coro_queue_init/_enqueue/_next/_requeue/_remove over
 *  @ref duct_coro_t nodes. Wait-side membership is read straight off
 *  @c state == coro_state_waiting — no extra flag field to maintain.
 */
DUCT_COOP_QUEUE_DECLARE(duct_coro_queue_t,
                        duct_coro_queue,
                        duct_coro_t,
                        node->state == coro_state_waiting)

/** @brief Enqueue coroutine into run/wait queue by current state. */
static duct_nonnull(1, 2) inline void
duct_coro_queue_put(duct_coro_queue_t *queue, duct_coro_t *coro)
{
    switch (coro->state) {
    case coro_state_waiting:
        duct_coro_queue_enqueue(queue, coro, coop_wait);
        break;
    case coro_state_suspended:
    case coro_state_ready:
        duct_coro_queue_enqueue(queue, coro, coop_run);
        break;
    default:
        duct_log(stderr, "duct_coro_queue_put: invalid coro state %u, dropping coro %p",
                 (unsigned)coro->state, (void *)coro);
        break;
    }
}

/** @brief Move a waiting stackful coroutine back to the run queue. */
static duct_nonnull(1, 2) inline void
duct_coro_queue_wake(duct_coro_queue_t *queue, duct_coro_t *coro)
{
    if (coro->state == coro_state_waiting) {
        coro->state = coro_state_suspended;
        duct_coro_queue_requeue(queue, coro);
    }
}

/** @brief Stackless coroutine.
 *  A step function @ref duct_coop_cycle
 *  re-invokes until it returns @c async_done, plus one inline cacheline of private state —
 *  no own stack, all persistence lives in @c priv or the handler ctx.
 */
typedef struct duct_async {
    duct_async_step_t  step;    /**< Step function; called with @c state each resume. */
    void *state;                /**< Handed to @c step: @c &priv for "raw" coros, or
                                  * the external handler ctx. */
    duct_async_done_fn on_done; /**< NULL for raw coros; handler post-step hook. */
    void *on_done_ctx;          /**< Handler ctx (same as state for handlers). */
    bool in_wait;               /**< True while on the wait side; maintained by
                                  * @c duct_async_queue_enqueue/_requeue alone. */
    struct duct_async *next,    /**< Queue link; doubles as the pool free-list link. */
                     **pprev;   /**< Address of whichever link points at this
                                 * node (run_head/wait_head or a sibling's next) 
                                 * — O(1) unlink; NULL when not enqueued. */
    duct_cacheline_struct_ext(priv); /**< Opaque per-coro state, zeroed on acquire. */
} duct_async_t;

/** @brief Stackless coro pool: one zeroed slab, all slots are free-listed at init. */
typedef struct duct_async_pool {
    duct_ptr_t(duct_async_t) slots; /**< Slab of coros, one per slot; @c duct_len gives the slot count. */
    duct_async_t *free_list;        /**< Released slots linked via @c duct_async_t::next. */
    unsigned n_alive;               /**< Acquired and unreleased coros. */
} duct_async_pool_t;

/** @brief Allocate the slab and seed the free list: every slot is threaded
 *  on via its @c next, head-first, so acquire hands them out from the last
 *  index down. Async slots don't need per-slot arming, so the stackful pool's
 *  lazy guard-page commit has no counterpart here.
 */
static duct_nonnull(1) inline duct_result_t
duct_async_pool_init(duct_async_pool_t *pool, unsigned n_slots)
{
    *pool = (duct_async_pool_t){};
    pool->slots = duct_new(duct_async_t, n_slots);
    duct_do_if(!pool->slots, return rc_no_memory);
    auto slots = duct_at(pool->slots);
    for (unsigned i = 0u; i < n_slots; ++i) {
        slots[i].next = pool->free_list;
        pool->free_list = &slots[i];
    }
    return rc_ok;
}

/** @brief Free the slab and zero the pool; all live coros must be done by now. */
static duct_nonnull(1) inline void
duct_async_pool_fini(duct_async_pool_t *pool)
{
    duct_del(pool->slots);
    *pool = (duct_async_pool_t){};
}

/** @brief Pop a free slot and arm it; hooks cleared, @c priv zeroed,
 *  @c state pointed at @c priv.
 *  @return An armed coro, or @c nullptr if pool is exhausted.
 */
static duct_nonnull(1, 2) inline duct_async_t *
duct_async_acquire(duct_async_pool_t *pool, duct_async_step_t step)
{
    auto coro = pool->free_list;
    duct_do_if(!coro, return nullptr);
    pool->free_list = coro->next;
    coro->next = nullptr;
    coro->pprev = nullptr;
    coro->on_done = nullptr;
    coro->on_done_ctx = nullptr;
    coro->in_wait = false;
    coro->step = step;
    memset(coro->priv, 0, duct_cacheline_size);
    coro->state = coro->priv;
    ++pool->n_alive;
    return coro;
}

/** @brief Disarm a coro and push it back onto the free list. */
static duct_nonnull(1, 2) inline void
duct_async_release(duct_async_pool_t *pool, duct_async_t *coro)
{
    --pool->n_alive;
    coro->step = nullptr;
    coro->state = nullptr;
    coro->on_done = nullptr;
    coro->on_done_ctx = nullptr;
    coro->in_wait = false;
    coro->pprev = nullptr;
    coro->next = pool->free_list;
    pool->free_list = coro;
}

/** @brief Stackless scheduling queue.
 *  Emits @c duct_async_queue_t plus
 *  @c duct_async_queue_init/_enqueue/_next/_requeue/_remove over
 *  @ref duct_async_t nodes. Wait-side membership rides the node's own
 *  @c in_wait flag, kept in sync by @c _enqueue/@c _requeue.
 */
DUCT_COOP_QUEUE_DECLARE(duct_async_queue_t, duct_async_queue, duct_async_t,
                        node->in_wait, in_wait)

/** @brief Wake a specific stackless coro; wait → run. */
static duct_nonnull(1, 2) inline void
duct_async_queue_wake_coro(duct_async_queue_t *queue, duct_async_t *coro)
{
    if (coro->in_wait)
        duct_async_queue_requeue(queue, coro);
}

/** @brief Per-worker coroutine queues and pools; inert until opened. */
typedef struct duct_coop {
    duct_coro_pool_t   pool;        /**< Stackful stack pool. */
    duct_coro_queue_t  queue;       /**< Stackful run/wait queue. */
    duct_async_pool_t  async_pool;  /**< Stackless slab pool. */
    duct_async_queue_t async_queue; /**< Stackless run/wait queue. */
    unsigned stack_slots,           /**< Configured stackful capacity; 0 if flavor unused. */
             async_slots;           /**< Configured stackless capacity; 0 if flavor unused. */
    bool open;                      /**< Armed latch for the open path.
                                      * Set by @ref duct_coop_init before the pools
                                      * are built, so a failed open's own rollback close
                                      * still tears them down; makes @c open / @c close idempotent
                                      * and gates @c cycle / @c wake on an inert coop. */
} duct_coop_t;

/** @brief Initialize coroutine runtime pools on the calling thread.
 *  Host-agnostic: operates on caller-owned @p cp directly on the calling thread.
 */
duct_nonnull(1) duct_result_t duct_coop_init(duct_coop_t *cp,
                                             unsigned stack_slots,
                                             unsigned async_slots,
                                             size_t stack_bytes);

/** @brief Destroy coroutine runtime pools and pending queues. */
duct_nonnull(1) void duct_coop_fini(duct_coop_t *cp);

/** @brief Execute one bounded coroutine scheduling cycle on the calling thread.
 *  @return Coroutine steps run; the worker counts these as progress so a
 *          self-driving handler holds the busy-poll ramp.
 */
duct_nonnull(1) size_t duct_coop_cycle(duct_coop_t *cp);

/** @brief Wake one stackful coroutine previously moved to waiting state. */
duct_nonnull(1, 2) void duct_coop_wake(duct_coop_t *cp, duct_coro_t *coro);

#ifdef __cplusplus
}
#endif

#endif /* DUCT_CORO_H */
