/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/**
 * @file duct_ticks.h
 * @brief Calibrated-TSC clock: rdtsc plus a fixed-point scale in place of a
 * clock_gettime per reading, for long-lived threads whose call rate makes a
 * vDSO call per reading measurable. Init is non-blocking: it only anchors, the
 * first readings fall through to CLOCK_MONOTONIC, and the first one with a
 * ~2ms baseline computes the scale from that genuinely elapsed window.
 * Re-anchors against CLOCK_MONOTONIC whenever the tick delta exceeds the
 * recalibration window (~4ms) and returns that reading, so no error
 * accumulates; a sleep across the window lands on the re-anchor path. Returns
 * are clamped monotone per instance, and an instance serves one thread. The
 * wall clock rides the monotonic one plus the offset of CLOCK_REALTIME from it.
 * Non-x86 builds read CLOCK_MONOTONIC on every reading.
 */

#ifndef DUCT_TICKS_H
#define DUCT_TICKS_H

#include "duct_core.h"

#include <stdint.h>
#include <time.h>

#if defined(__x86_64__)
#include <x86intrin.h>
#endif

/** @brief Monotonic tick clock of one thread. */
typedef struct {
    uint64_t  base_ns,         /**< CLOCK_MONOTONIC at the anchor, 0 before init. */
              base_ticks,      /**< rdtsc at the anchor. */
              ns_per_tick_q32, /**< Scale, Q32 fixed point; 0 while still
                                 *  bootstrapping (readings fall through to
                                 *  the real clock until the baseline is
                                 *  wide enough to calibrate from). */
              recal_ticks,     /**< Tick delta past which the next reading
                                 *  re-anchors, ~4ms worth. */
              last_ns;         /**< Largest reading handed out. A re-anchor
                                 *  whose real reading lands under an
                                 *  extrapolation that overshot hands it again:
                                 *  callers' unsigned now-minus-stamp
                                 *  arithmetic wraps on a backward step. */
} duct_tickclock_t;

/** @brief Baseline the scale calibration needs before it trusts itself. */
static constexpr uint64_t duct_tickclock_calib_ns = 2000000u;
/** @brief Recalibration window, ns.
 *  A reading this long past the anchor re-anchors, and @ref duct_ticks_wall_ns re-reads its
 *  offset as often. */
static constexpr uint64_t duct_tickclock_window_ns = 2u * duct_tickclock_calib_ns;

static inline uint64_t duct_tickclock_raw_ns(clockid_t clk)
{
    struct timespec ts;
    clock_gettime(clk, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/** @brief Anchor @p tc against CLOCK_MONOTONIC. Non-blocking; the instance calibrates
 *  itself over its first ~2ms of readings. */
static inline void duct_tickclock_init(duct_tickclock_t *tc)
{
    *tc = (duct_tickclock_t){ .base_ns = duct_tickclock_raw_ns(CLOCK_MONOTONIC) };
#if defined(__x86_64__)
    tc->base_ticks = __rdtsc();
#endif
}

/** @brief Read @p tc's CLOCK_MONOTONIC time, ns.
 *  Tick-extrapolated from the anchor; a reading past the recalibration window,
 *  any sleep included, re-anchors from the real clock and refines the scale. */
static inline uint64_t duct_tickclock_ns(duct_tickclock_t *tc)
{
    uint64_t ret;
#if defined(__x86_64__)
    if (tc->ns_per_tick_q32 != 0u) {
        uint64_t d = __rdtsc() - tc->base_ticks;
        if (d < tc->recal_ticks) {
            /* d < recal_ticks (~2^24) and scale < 2^32: the product stays
             * under 2^56, no wider intermediate needed. */
            ret = tc->base_ns + ((d * tc->ns_per_tick_q32) >> 32);
        } else {
            uint64_t ns = duct_tickclock_raw_ns(CLOCK_MONOTONIC),
                     t  = __rdtsc();
            uint64_t dns = ns - tc->base_ns,
                     dt  = t - tc->base_ticks;
            if (dt && dns && dns < (1ull << 31))
                tc->ns_per_tick_q32 = (dns << 32) / dt; /* refine: tracks NTP slew */
            tc->base_ns = ns;
            tc->base_ticks = t;
            ret = ns;
        }
    } else {
        /* Bootstrapping: real clock per reading until the window since
         * init spans the calibration baseline, then derive the scale from
         * that genuinely elapsed window -- no blocking calibration sleep
         * anywhere. recal is normalized to ~4ms of ticks even when the
         * first qualifying reading arrives much later. */
        uint64_t ns = duct_tickclock_raw_ns(CLOCK_MONOTONIC),
                 t  = __rdtsc();
        uint64_t dns = ns - tc->base_ns,
                 dt  = t - tc->base_ticks;
        if (dns >= duct_tickclock_calib_ns && dt) {
            /* If elapsed window exceeds 2^31 ns, restarts calibration baseline. */
            if (dns < (1ull << 31)) {
                tc->ns_per_tick_q32 = (dns << 32) / dt;
                tc->recal_ticks = dt * duct_tickclock_window_ns / dns;
            }
            tc->base_ns = ns;
            tc->base_ticks = t;
        }
        ret = ns;
    }
#else
    ret = duct_tickclock_raw_ns(CLOCK_MONOTONIC);
#endif
    if (ret < tc->last_ns)
        return tc->last_ns; /* see last_ns's own doc */
    tc->last_ns = ret;
    return ret;
}

/** @brief Read this thread's monotonic tick clock, ns.
 *  For long-lived loop threads whose pass rate makes a vDSO call per reading
 *  measurable. One instance per thread and translation unit, inited at its first
 *  reading. Each tracks CLOCK_MONOTONIC to well under a microsecond; a stall
 *  between the clock read and the rdtsc of a re-anchor, a preempted virtual CPU
 *  for one, shows as an error up to its length until the following re-anchors. */
static inline uint64_t duct_ticks_mono_ns(void)
{
    static thread_local duct_tickclock_t tc;
    if (!tc.base_ns)
        duct_tickclock_init(&tc);
    return duct_tickclock_ns(&tc);
}

/** @brief Offset of CLOCK_REALTIME from one thread's monotonic tick clock. */
typedef struct {
    uint64_t at_ns,     /**< Monotonic tick reading the offset was taken at, 0 before the first. */
             offset_ns; /**< CLOCK_REALTIME less that reading, modulo 2^64. */
} duct_tickwall_t;

/** @brief Read the wall clock riding @p w's offset, ns since the epoch.
 *  The monotonic tick clock plus the offset of CLOCK_REALTIME from it, re-read once per
 *  @p window_ns: a step of the wall clock moves the offset alone and shows within one
 *  window, forward or back. Costs a monotonic tick reading and one CLOCK_REALTIME read per
 *  window. @p w belongs to one thread.
 */
static inline uint64_t duct_tickwall_read_ns(duct_tickwall_t *w, uint64_t window_ns)
{
    uint64_t mono = duct_ticks_mono_ns();
    if (!w->at_ns || mono - w->at_ns >= window_ns) {
        w->offset_ns = duct_tickclock_raw_ns(CLOCK_REALTIME) - mono;
        w->at_ns = mono;
    }
    return mono + w->offset_ns;
}

/** @brief Read this thread's wall clock, ns since the epoch.
 *  The reading of @ref duct_tickwall_read_ns over @c duct_tickclock_window_ns, and a step
 *  back holds it until the wall clock passes it. One instance per thread and translation
 *  unit. */
static inline uint64_t duct_ticks_wall_ns(void)
{
    static thread_local duct_tickwall_t w;
    static thread_local uint64_t last_ns;
    last_ns = duct_max(last_ns, duct_tickwall_read_ns(&w, duct_tickclock_window_ns));
    return last_ns;
}

#endif /* DUCT_TICKS_H */
