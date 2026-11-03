/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_time.h
 *  @brief Spin-before-park policy of the event loops, monotonic time as a timespec and
 *  time-unit conversions.
 */

#ifndef DUCT_TIME_H
#define DUCT_TIME_H

#include "duct_core.h"
#include "duct_ticks.h"

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Spin-before-park policy of the engine's event loops.
 *  Each figure comes from the environment's nanosecond override first, then
 *  @c duct_engine_cfg_t, then the build's microsecond default. A host with one
 *  cpu online takes no window, overrides included. */
typedef struct duct_spin_policy {
    uint64_t window_ns, /**< Longest spin on one idle stretch, nanoseconds; cut to
                          *   @c cutoff_ns, past which a spin costs more than the
                          *   park it saves. */
             cutoff_ns; /**< Price of one park and wake, in spin nanoseconds. */
} duct_spin_policy_t;

/** @brief Spin policy in force.
 *  Written by @c duct_engine_launch before its threads start, which read it
 *  unsynchronized. */
extern duct_spin_policy_t duct_spin_policy;

/** @brief Number of candidate spin windows, spaced evenly from zero up to the
 *  capped window. */
static constexpr unsigned duct_spin_cands = 4u;

/** @brief Spin-before-park state of one event loop thread.
 *  All zero is the start: no idle stretch running, every candidate at cost 0,
 *  so the loop parks until its first stretch is scored. */
typedef struct duct_spin_state {
    uint64_t idle_since_ns,            /**< Start of the idle stretch in progress,
                                         *  0 while the loop has work. */
             cost_ns[duct_spin_cands]; /**< Decayed average cost of each candidate
                                         *  window, 1/16 weight per stretch. */
} duct_spin_state_t;

/** @brief Record one poll's outcome and choose the next wait.
 *  A poll that @p found work ends the stretch in progress, if any, and scores
 *  it against every candidate: a window covering the stretch costs the stretch,
 *  a shorter one costs itself plus @c cutoff_ns. A poll that found nothing
 *  starts a stretch at @p now_ns unless one runs.
 *  @return true to poll again without blocking: always after work, so a stretch
 *  starts only at a poll that came back empty, and while the running stretch is
 *  shorter than the candidate of least cost.
 */
static inline bool duct_spin_next(duct_spin_state_t *ss, bool found, uint64_t now_ns)
{
    uint64_t step = duct_min(duct_spin_policy.window_ns, duct_spin_policy.cutoff_ns)
                  / (duct_spin_cands - 1u);
    if (found) {
        if (ss->idle_since_ns) {
            uint64_t idle = now_ns - ss->idle_since_ns;
            for (unsigned k = 0u; k < duct_spin_cands; ++k) {
                uint64_t cost = idle <= step * k ? idle : step * k + duct_spin_policy.cutoff_ns;
                ss->cost_ns[k] = ss->cost_ns[k] - (ss->cost_ns[k] >> 4) + (cost >> 4);
            }
            ss->idle_since_ns = 0u;
        }
        return true;
    }
    if (!ss->idle_since_ns)
        ss->idle_since_ns = now_ns;
    unsigned best = 0u;
    for (unsigned k = 1u; k < duct_spin_cands; ++k)
        if (ss->cost_ns[k] < ss->cost_ns[best])
            best = k;
    return now_ns - ss->idle_since_ns < step * best;
}

/** @brief Split an already-read nanosecond stamp into a timespec, so a caller
 *  needing both forms pays for one clock read.
 */
static inline struct timespec duct_time_from_ns(uint64_t ns)
{
    return (struct timespec){
        .tv_sec = (time_t)(ns / 1000000000ULL),
        .tv_nsec = (long)(ns % 1000000000ULL)
    };
}

/** @brief Current monotonic time as a timespec. */
static inline struct timespec duct_time_now(void)
{
    return duct_time_from_ns(duct_ticks_mono_ns());
}

/** @brief Tell if @p a is at or before @p b. */
static inline bool duct_time_le(struct timespec a, struct timespec b)
{
    return a.tv_sec < b.tv_sec || (a.tv_sec == b.tv_sec && a.tv_nsec <= b.tv_nsec);
}

/** @brief Sum of two timespecs with nanosecond carry. */
static inline struct timespec duct_time_add(struct timespec a, struct timespec b)
{
    struct timespec r = { a.tv_sec + b.tv_sec, a.tv_nsec + b.tv_nsec };
    if (r.tv_nsec >= 1000000000L) { r.tv_sec++; r.tv_nsec -= 1000000000L; }
    return r;
}

/** @brief Difference @p a - @p b as a timespec with nanosecond borrow. */
static inline struct timespec duct_time_sub(struct timespec a, struct timespec b)
{
    struct timespec r = { a.tv_sec - b.tv_sec, a.tv_nsec - b.tv_nsec };
    if (r.tv_nsec < 0) { r.tv_sec--; r.tv_nsec += 1000000000L; }
    return r;
}

/** @brief Signed @p a - @p b in nanoseconds; negative when @p a precedes @p b. */
static inline int64_t duct_time_diff_ns(struct timespec a, struct timespec b)
{
    return ((int64_t)a.tv_sec - b.tv_sec) * 1000000000LL
         + ((int64_t)a.tv_nsec - b.tv_nsec);
}

/** @brief Convert microseconds to a timespec. */
static inline struct timespec duct_time_from_us(uint64_t us)
{
    return (struct timespec){
        .tv_sec = (time_t)(us / 1000000ULL),
        .tv_nsec = (long)((us % 1000000ULL) * 1000L)
    };
}

/** @brief Milliseconds to nanoseconds. Saturates on overflow. */
static inline uint64_t duct_time_ms_to_ns(uint64_t ms)
{
    uint64_t ns = 0;
    duct_do_if(duct_ckd_mul(&ns, ms, 1000000ULL), return UINT64_MAX);
    return ns;
}

/** @brief Microseconds to milliseconds. */
static inline uint64_t duct_time_us_to_ms(uint64_t us)
{
    return us == 0 ? 0 : (us + 999) / 1000;
}

#ifdef __cplusplus
}
#endif

#endif /* DUCT_TIME_H */
