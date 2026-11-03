/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_timer.h
 *  @brief Per-worker timers: deadline-sorted list + id hash for
 *  O(1) cancel, with a coalescing drain horizon. Worker-local,
 *  single-thread use.
 *
 *  Timer subsystem shares the universal @c duct_exec_fn callback
 *  with the message system through that leaf primitive; the drain
 *  ignores the returned @c duct_exec_rc_t.
 */

#ifndef DUCT_TIMER_H
#define DUCT_TIMER_H

#include "duct_core.h"
#include "duct_exec.h"
#include "duct_time.h"
#include "duct_ticks.h"
#include "duct_hash.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Coalescing horizon as a timespec; window itself is @c duct_timer_coalesce_us. */
#define timer_coalesce() duct_time_from_us(duct_timer_coalesce_us)

typedef uint64_t duct_timer_handle_t;

static constexpr duct_timer_handle_t timer_handle_null = 0; /**< Invalid/absent handle. */
static constexpr unsigned timer_id_bits = 48u;   /**< Handle bits [0:47] — local id;
                                                  *   [48:55] worker slot, [56:63] proc. */
static constexpr uint64_t timer_id_mask = (1ULL << timer_id_bits) - 1ULL;
static constexpr uint8_t timer_slot_proc = 0xFFu; /**< Unused — no reader in-tree. */

/** @brief Pack proc/worker/local_id into self-routing handle. */
static inline duct_timer_handle_t
duct_timer_make_handle(uint8_t proc_idx, uint8_t worker_slot, uint64_t local_id)
{
    return ((uint64_t)proc_idx << 56)
         | ((uint64_t)worker_slot << timer_id_bits)
         | (local_id & timer_id_mask);
}

/** @brief Extract the owning processor index from a handle. */
static inline uint8_t duct_timer_handle_proc(duct_timer_handle_t handle)
{
    return (uint8_t)(handle >> 56);
}

/** @brief Extract the local timer id from a handle. */
static inline uint64_t duct_timer_handle_id(duct_timer_handle_t handle)
{
    return handle & timer_id_mask;
}

/** @brief Process-wide source of the ids @c duct_timer_new_id hands out. */
extern uint64_t _Atomic duct_timer_global_id;

/* DUCT_TIMER_NO_HIRES gates all of this, forced 1 off-Windows by the
 * generated build config. */
#if !DUCT_TIMER_NO_HIRES

/** @c timeBeginPeriod(1)/timeEndPeriod(1); defined by the Windows backend.
 *  Call only through @ref duct_timer_hires_ref / @ref duct_timer_hires_unref.
 *  @{
 */
void duct_timer_hires_on(void);
void duct_timer_hires_off(void);
/** @} */

/** Count of armed fine timers (@ref duct_timer_is_fine); process-wide,
 *  defined by the Windows backend.
 */
extern uint32_t _Atomic duct_timer_hires_refcount;

/** @brief True if @p delay_us or a repeating @p interval_us is finer than
 *  @c duct_timer_coarse_granularity_us.
 */
static inline bool duct_timer_is_fine(uint64_t delay_us, uint64_t interval_us)
{
    return delay_us < duct_timer_coarse_granularity_us
        || (interval_us != 0u && interval_us < duct_timer_coarse_granularity_us);
}

/** @brief True if a fine timer is armed somewhere in the process. */
static inline bool duct_timer_hires_active(void)
{
    return duct_atomic_load(&duct_timer_hires_refcount, relaxed) != 0u;
}

/** @brief Ref a newly-armed fine timer. */
static inline void duct_timer_hires_ref(void)
{
    if (duct_atomic_fetch(add, &duct_timer_hires_refcount, 1u, relaxed) == 0u)
        duct_timer_hires_on();
}

/** @brief Unref a retiring fine timer. */
static inline void duct_timer_hires_unref(void)
{
    if (duct_atomic_fetch(sub, &duct_timer_hires_refcount, 1u, relaxed) == 1u)
        duct_timer_hires_off();
}

#else /* DUCT_TIMER_NO_HIRES */

/** @brief Always false: this build arms no hi-res timing. */
static inline bool duct_timer_is_fine([[maybe_unused]] uint64_t delay_us,
                                      [[maybe_unused]] uint64_t interval_us)
{
    return false;
}

static inline bool duct_timer_hires_active(void) { return false; }
static inline void duct_timer_hires_ref(void) {}
static inline void duct_timer_hires_unref(void) {}

#endif /* !DUCT_TIMER_NO_HIRES */

/** @brief Next local id.
 *
 *  @return always nonzero — 0 is reserved for @ref timer_handle_null.
 */
static inline uint64_t duct_timer_new_id(void)
{
    uint64_t id = duct_atomic_fetch(add, &duct_timer_global_id, 1, relaxed);
    if (!id)
        id = duct_atomic_fetch(add, &duct_timer_global_id, 1, relaxed);
    return id & timer_id_mask;
}

static constexpr unsigned timer_hash_size = 1u << duct_timer_hash_bits;

typedef struct duct_timer duct_timer_t;

/** @brief Timer node linked into a deadline-sorted list and an id hash chain. */
struct duct_timer {
    duct_timer_t      *next, *prev;     /**< Deadline-sorted list links. */
    duct_hash_handle_t hh;              /**< Id hash-chain link. */
    uint64_t        id;                 /**< Local timer id. */
    struct timespec deadline,           /**< Absolute next-fire time. */
                    interval;           /**< Repeat period; zero for one-shot. */
    void           *arg,                /**< Opaque argument passed to @c exec. */
                  (*arg_free)(void*);   /**< Releases @c arg at retirement; nullptr for a static arg. */
    duct_exec_fn    exec;               /**< Heap-level callback fired on expiry. */
    uint32_t        iterations;         /**< Remaining fires; zero means unbounded. */
    bool            fine;               /**< Counted toward
                                          *   @c duct_timer_hires_refcount;
                                          *   cleared once unreffed. */
};

/** @brief Unref @p t once, however it retires — @c fine guards a cancelled
 *  node later swept by the drain against being unreffed twice.
 */
static inline void duct_timer_hires_unref_once(duct_timer_t *t)
{
    if (t->fine) {
        t->fine = false;
        duct_timer_hires_unref();
    }
}

/** @brief Worker-local timer set: sorted list, id hash and a node free chain. */
typedef struct {
    duct_timer_t        sentinel,                   /**< Ring sentinel for the sorted list. */
                       *free_head;                  /**< Reusable node free chain. */
    duct_hash_handle_t *buckets[timer_hash_size];   /**< Id hash buckets for O(1) cancel. */
    unsigned            free_count;                 /**< Nodes currently on the free chain. */
} duct_timers_t;

/** @name Find / insert a timer by local id within its own hash bucket.
 *  @{
 */
DUCT_HASH_DECLARE(duct_timer_hash_find, duct_timer_hash_insert,
                  duct_timers_t, buckets, duct_timer_t, uint64_t,
                  node->id == key, timer_hash_size - 1u)
/** @} */

/** @brief Zero the set and close the sentinel ring. */
duct_nonnull(1) static inline void duct_timers_init(duct_timers_t *tl)
{
    *tl = (duct_timers_t){};
    tl->sentinel.next = tl->sentinel.prev = &tl->sentinel;
}

/** @brief Free every pending node, releasing unfired args, then the free
 *  chain; leaves the set re-initialized. Safe on a never-initialized set.
 */
duct_nonnull(1) static inline void duct_timers_destroy(duct_timers_t *tl)
{
    duct_do_if(!tl->sentinel.next && !tl->sentinel.prev, return);
    auto sen = &tl->sentinel;
    auto t = sen->next;
    while (t != sen) {
        auto n = t->next;
        if (t->arg_free)
            t->arg_free(t->arg); /* unfired or cancelled-before-fire */
        duct_timer_hires_unref_once(t);
        duct_del(t);
        t = n;
    }
    t = tl->free_head;
    while (t) {
        auto n = t->next;
        duct_del(t); /* arg already released by drain or cancel */
        t = n;
    }
    duct_timers_init(tl);
}

/** @brief Allocate node from free chain or heap. */
duct_nonnull(1) static inline duct_timer_t *duct_timer_new(duct_timers_t *tl)
{
    auto t = tl->free_head;
    if (t) {
        tl->free_head = t->next;
        if (tl->free_count)
            tl->free_count--;
    } else
        t = duct_new(duct_timer_t);
    return t;
}

/** @brief Unlink from the id hash and return the node to the free chain. */
duct_nonnull(1, 2) static inline void
duct_timer_del(duct_timers_t *tl, duct_timer_t *t)
{
    duct_hash_remove(&t->hh);
    t->next = tl->free_head;
    t->prev = nullptr;
    tl->free_head = t;
    tl->free_count++;
}

/** @brief Release free chain back to heap. */
duct_nonnull(1) static inline void duct_timers_trim(duct_timers_t *tl)
{
    auto t = tl->free_head;
    while (t) {
        auto n = t->next;
        duct_del(t);
        t = n;
    }
    tl->free_head  = nullptr;
    tl->free_count = 0;
}

/** @brief Trim if free chain exceeds threshold. */
duct_nonnull(1) static inline void duct_timers_maybe_trim(duct_timers_t *tl)
{
    if (tl->free_count >= duct_timer_trim_threshold)
        duct_timers_trim(tl);
}

/** @brief Unlink from sorted list. No-op if not linked. */
duct_nonnull(1) static inline void duct_timer_unlink(duct_timer_t *t)
{
    if (!t->prev) return;
    t->prev->next = t->next;
    t->next->prev = t->prev;
    t->next = t->prev = nullptr;
}

/** @brief Insert into sorted list by ascending deadline.
 *
 *  Tail-first O(1) for typical reschedule.
 */
duct_nonnull(1, 2) static inline void
duct_timer_insert(duct_timers_t *tl, duct_timer_t *t)
{
    duct_timer_t *sen = &tl->sentinel,
                 *p;
    if (sen->prev == sen || !duct_time_le(t->deadline, sen->prev->deadline)) {
        p = sen;
    } else {
        p = sen->prev;
        while (p != sen && !duct_time_le(p->deadline, t->deadline))
            p = p->prev;
        p = p->next;
    }
    t->next = p;
    t->prev = p->prev;
    p->prev->next = t;
    p->prev = t;
}

/** @brief Add a timer.
 *
 *  @param delay_us    Delay before the first fire.
 *  @param interval_us Re-arm period for a repeating timer (@p iterations != 1);
 *                     irrelevant for a one-shot timer.
 *  @param arg         Opaque value passed to @c exec on each fire.
 *  @param arg_free    Arg destructor called once at retirement — final fire,
 *                     cancel or destroy. When set, the timer owns @p arg;
 *                     nullptr for a caller-owned or static arg.
 *
 *  @return Self-routing handle or @ref timer_handle_null on OOM.
 */
duct_nonnull(1) static inline duct_timer_handle_t
duct_timer_add(duct_timers_t *tl, uint8_t proc_idx,
               uint8_t worker_slot, uint64_t delay_us, uint64_t interval_us,
               uint32_t iterations, duct_exec_fn exec, void *arg,
               void (*arg_free)(void *))
{
    auto t = duct_timer_new(tl);
    duct_do_if(!t, return timer_handle_null);
    uint64_t lid = duct_timer_new_id();
    t->id         = lid;
    t->deadline   = duct_time_add(duct_time_from_ns(duct_ticks_mono_ns()), duct_time_from_us(delay_us));
    t->interval   = duct_time_from_us(interval_us);
    t->exec       = exec;
    t->arg        = arg;
    t->arg_free   = arg_free;
    t->iterations = iterations;
    t->fine       = duct_timer_is_fine(delay_us, interval_us);
    if (t->fine)
        duct_timer_hires_ref();
    duct_timer_hash_insert(tl, t->id, &t->hh);
    duct_timer_insert(tl, t);
    return duct_timer_make_handle(proc_idx, worker_slot, lid);
}

/** @brief Cancel a timer by handle: release its arg and remove the id-hash
 *  link, so the handle no longer resolves.
 *
 *  @note The node stays on the sorted list — the drain frees it once its
 *  deadline comes around, detecting the removed hash link; failing that,
 *  @c duct_timers_destroy does.
 *
 *  @return false if @p handle no longer resolves — already retired, or
 *          never existed.
 */
duct_nonnull(1) static inline bool
duct_timer_cancel(duct_timers_t *tl, duct_timer_handle_t handle)
{
    auto t = duct_timer_hash_find(tl, duct_timer_handle_id(handle));
    if (!t)
        return false;
    if (t->arg_free)
        t->arg_free(t->arg);
    t->arg      = nullptr;
    t->arg_free = nullptr;
    duct_timer_hires_unref_once(t);
    duct_hash_remove(&t->hh);
    return true;
}

/** @brief Deadline of the soonest timer; zero timespec if empty. */
static inline struct timespec duct_timers_nearest(const duct_timers_t *tl)
{
    auto sen = &tl->sentinel;
    return (sen->next == sen) ? (struct timespec){} : sen->next->deadline;
}

/** @brief Ms from @p now to @p deadline, minimum 1. A zero @p deadline —
 *  the "no timer armed" sentinel — maps to @c DUCT_TIMEOUT_INFINITE.
 */
static inline uint32_t
duct_deadline_to_ms_at(struct timespec deadline, struct timespec now)
{
    if (!deadline.tv_sec && !deadline.tv_nsec)
        return DUCT_TIMEOUT_INFINITE;
    if (duct_time_le(deadline, now))
        return 1;
    struct timespec d = duct_time_sub(deadline, now);
    uint32_t ms = (uint32_t)(d.tv_sec * 1000 + d.tv_nsec / 1000000);
    return ms < 1 ? 1 : ms;
}

/** Smallest nonzero ms @ref duct_deadline_to_ms_at can return — its own
 *  return-unit floor, not a granularity guess.
 */
static constexpr uint64_t duct_timer_ms_floor_us = 1000u;

/** @brief True if the nearest armed timer is due within a
 *  wait-primitive-safe window, one already overdue included.
 *
 *  The window is @ref duct_timer_ms_floor_us under hi-res timing, else
 *  @ref duct_timer_coarse_granularity_us. Callers evaluate this window to
 *  avoid blocking when sub-millisecond timers are due.
 */
static inline bool duct_timers_due_soon(const duct_timers_t *tl, struct timespec now)
{
    auto nearest = duct_timers_nearest(tl);
    if (!nearest.tv_sec && !nearest.tv_nsec)
        return false;
#if !DUCT_TIMER_NO_HIRES
    uint64_t window_us = duct_timer_hires_active()
        ? duct_timer_ms_floor_us : duct_timer_coarse_granularity_us;
#else
    uint64_t window_us = duct_timer_ms_floor_us;
#endif
    return duct_time_diff_ns(nearest, now) < (int64_t)window_us * 1000;
}

/** @brief One bounded deadline-limited wait step on a futex address.
 *
 *  @retval false  @p deadline is exhausted — already passed at entry, or the
 *                 wait timed out.
 *  @retval true   Woken, or the condition changed.
 */
duct_nonnull(1) static inline bool
duct_deadline_wait(uint32_t _Atomic *addr, uint32_t expected, struct timespec deadline)
{
    auto now = duct_time_now();
    return duct_time_le(deadline, now)
        ? false
        : duct_futex_wait(addr, expected, duct_deadline_to_ms_at(deadline, now));
}

/** @brief Wait until the counter @p count reads 0, for at most @p bound_ms.
 *  A futex wait on the counter itself, so the decrement that brings it to zero
 *  has to wake it. Returns with the count still non-zero once the bound passes. */
duct_nonnull(1) static inline void
duct_drain_wait(uint32_t _Atomic *count, uint32_t bound_ms)
{
    auto deadline = duct_time_add(duct_time_now(),
                                  duct_time_from_us((uint64_t)bound_ms * 1000ull));
    for (;;) {
        auto n = duct_atomic_load(count, acquire);
        if (n == 0u || !duct_deadline_wait(count, n, deadline))
            return;
    }
}

/** @brief Default budget for a cross-thread confirmation wait. */
static constexpr uint32_t duct_sync_bound_ms = 5000u;

/** @brief Fire every timer due by @p now plus the coalescing horizon.
 *
 *  A node cancelled before its deadline is freed here without a fire.
 *  @return Number of due nodes taken off the list, the cancelled ones included.
 */
duct_nonnull(1) static inline uint32_t
duct_timers_drain_at(duct_timers_t *tl, struct timespec now)
{
    auto horizon = duct_time_add(now, timer_coalesce());
    auto sen = &tl->sentinel;
    uint32_t fired = 0;
    while (sen->next != sen) {
        auto t = sen->next;
        if (!duct_time_le(t->deadline, horizon))
            break;
        duct_timer_unlink(t);
        /* A cancelled node has released its arg and its hash link: exec is
         * skipped for it. */
        if (t->exec && t->hh.pprev)
            duct_discard t->exec(t->arg);
        fired++;
        /* A cancel during exec removes the hash link and frees arg —
         * the orphaned node is ours to free here. */
        bool cancelled = !t->hh.pprev,
             alive = !cancelled
                     && (t->interval.tv_sec || t->interval.tv_nsec)
                     && t->iterations != 1;
        if (alive) {
            if (t->iterations > 1)
                t->iterations--;
            do {
                t->deadline = duct_time_add(t->deadline, t->interval);
            } while (duct_time_le(t->deadline, now));
            duct_timer_insert(tl, t);
        } else {
            if (t->arg_free)
                t->arg_free(t->arg);
            t->arg      = nullptr;
            t->arg_free = nullptr;
            duct_timer_hires_unref_once(t);
            duct_timer_del(tl, t);
        }
    }
    return fired;
}

#ifdef __cplusplus
}
#endif

#endif /* DUCT_TIMER_H */
