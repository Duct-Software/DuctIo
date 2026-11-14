/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_pmtu.h
 *  @brief Path-MTU burst search over a connection's wire size.
 *
 *  A bracketing search sends a burst of distinct candidate sizes per round-trip
 *  between a floor (@ref duct_pmtu_base_min) and an upper ceiling, narrowing the
 *  bracket in parallel rather than probing one failing size at a time.
 */

#ifndef DUCT_PMTU_H
#define DUCT_PMTU_H

#include "duct_protocol.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** @brief Wire floor (bytes): 1280 IPv6 minimum link MTU minus 40 IPv6 and 8 UDP bytes
 *  for stateless IPv4-to-IPv6 header synthesis on transitional paths. */
static constexpr uint16_t duct_pmtu_base_min         = 1232u;
/** @brief Bracket width at which refinement stops and the proven bound is final, bytes. */
static constexpr uint16_t duct_pmtu_stop_gap         = 16u;
/** @brief Consecutive silent bursts with lower echoes required before sealing @c failed. */
static constexpr uint8_t  duct_pmtu_fail_strikes_max = 2u;
/** @brief Capacity of a burst rung list: 4 coarse/refine rungs with headroom. */
static constexpr uint8_t  duct_pmtu_burst_max        = 8u;

/** @brief Bracket search state over wire datagram sizes in bytes. */
typedef struct {
    uint16_t base,   /**< Lower floor of the bracket, bytes. */
             max,    /**< Path ceiling in bytes; at least @c base. */
             good,   /**< Highest size confirmed echoed in this search cycle. */
             failed; /**< Tentative upper ceiling from a silent rung, or 0 when unprobed. */
    uint8_t  failed_strikes; /**< Silent bursts at @c failed while a lower rung echoed. */
} duct_pmtu_t;

/** @brief Return true once @c good reaches @c max or the bracket narrows within @ref duct_pmtu_stop_gap. */
static inline bool duct_pmtu_done(const duct_pmtu_t *p)
{
    return p->good >= p->max
        || (p->failed != 0u && p->failed <= p->good + duct_pmtu_stop_gap);
}

/** @brief Reset @p p for a search between @p base (clamped to @ref duct_pmtu_base_min) and @p max. */
static inline void duct_pmtu_init(duct_pmtu_t *p, uint16_t base, uint16_t max)
{
    if (base < duct_pmtu_base_min)
        base = duct_pmtu_base_min;
    if (max < base)
        max = base;
    *p = (duct_pmtu_t){ .base = base, .max = max, .good = base };
}

/** @brief Drop proven gains above @c base and clear @c failed to start a fresh search cycle. */
static inline void duct_pmtu_restart(duct_pmtu_t *p)
{
    p->good = p->base;
    p->failed = 0u;
    p->failed_strikes = 0u;
}

/** @brief Highest wire size proven so far in the current cycle. */
static inline uint16_t duct_pmtu_mtu(const duct_pmtu_t *p)
{
    return p->good;
}

/** @brief Append unique @p val to @p out up to @ref duct_pmtu_burst_max entries.
 *  @return Updated rung count. */
static inline uint8_t duct_pmtu_push_rung(uint16_t out[static duct_pmtu_burst_max],
                                          uint8_t n, uint16_t val)
{
    for (uint8_t i = 0u; i < n; ++i)
        if (out[i] == val)
            return n;
    if (n < duct_pmtu_burst_max)
        out[n++] = val;
    return n;
}

/** @brief Populate @p out with unique wire candidate rungs for the next burst.
 *  Coarse probes span [@c good, @c max] when @c failed is 0; refinement probes
 *  subdivide [@c good, @c failed] and retest @c failed until confirmed twice.
 *  @return Number of rungs written (0 once @ref duct_pmtu_done holds). */
static inline uint8_t duct_pmtu_burst(const duct_pmtu_t *p,
                                      uint16_t out[static duct_pmtu_burst_max])
{
    if (duct_pmtu_done(p))
        return 0u;
    uint8_t n = 0u;
    if (p->failed == 0u) {
        uint16_t span = (uint16_t)(p->max - p->good);
        uint16_t cand[] = {
            p->max,
            (uint16_t)(p->good + span * 3u / 4u),
            (uint16_t)(p->good + span / 2u),
            p->base
        };
        for (size_t i = 0u; i < sizeof cand / sizeof cand[0]; ++i)
            if (cand[i] != p->good || cand[i] == p->base)
                n = duct_pmtu_push_rung(out, n, cand[i]);
        return n;
    }
    uint16_t gap   = (uint16_t)(p->failed - p->good),
             mid   = (uint16_t)(p->good + gap / 2u),
             upper = (uint16_t)(mid + (p->failed - mid) / 2u),
             lower = (uint16_t)(p->good + (mid - p->good) / 2u);
    uint16_t cand[] = { mid, upper, lower, p->failed };
    size_t limit = p->failed_strikes < duct_pmtu_fail_strikes_max ? 4u : 3u;
    for (size_t i = 0u; i < limit; ++i)
        n = duct_pmtu_push_rung(out, n, cand[i]);
    return n;
}

/** @brief Record an echoed @p size; rehabilitates @c failed if a tentative ceiling echoes. */
static inline void duct_pmtu_ack(duct_pmtu_t *p, uint16_t size)
{
    if (size < p->base || size > p->max)
        return;
    if (p->failed && size >= p->failed) {
        if (p->failed_strikes < duct_pmtu_fail_strikes_max) {
            p->good = (uint16_t)duct_max(p->good, size);
            p->failed = 0u;
            p->failed_strikes = 0u;
        }
        return;
    }
    if (size > p->good)
        p->good = size;
}

/** @brief Default path assumption before kernel or search refinement, bytes. */
static constexpr uint16_t duct_pmtu_path_default = 1500u;
/** @brief RTT multiplier for a single burst wait window. */
static constexpr uint64_t duct_pmtu_rto_rtts     = 4u;
/** @brief Minimum wait window for a burst or report timeout, nanoseconds. */
static constexpr uint64_t duct_pmtu_rto_min_ns   = 50'000'000u;
/** @brief Upper cap on wait window for a burst or report timeout, nanoseconds. */
static constexpr uint64_t duct_pmtu_rto_max_ns   = 2'000'000'000u;

/** @brief Outcome of matching an incoming probe echo against the active burst. */
typedef enum : uint8_t {
    pmtu_echo_none = 0, /**< Unmatched or duplicate rung. */
    pmtu_echo_rung,     /**< Matched rung; burst stays open awaiting remaining rungs. */
    pmtu_echo_closed,   /**< Final pending rung or search convergence closed the burst. */
    pmtu_echo_count     /**< Sentinel count of echo outcomes. */
} duct_pmtu_echo_t;

/** @brief Session-level burst driver binding @ref duct_pmtu_t to RTT timing and OS path cuts. */
typedef struct duct_pmtu_drive {
    duct_pmtu_t search;
    uint16_t    floor,
                /* Bounded at duct_pmtu_burst_max (8); coarse and refine emit at most 4 rungs. */
                rungs[duct_pmtu_burst_max];
    uint8_t     burst_count,
                burst_acked;
    uint64_t    burst_at,
                rtt;
} duct_pmtu_drive_t;

/** @brief Initialise @p d against connection @p conn_id of @p s, clamped to [floor, top]. */
duct_nonnull(1, 2) void duct_pmtu_drive_open(duct_pmtu_drive_t *d, duct_session_t *s,
                                             duct_conn_id_t conn_id, uint16_t base, uint16_t top,
                                             uint64_t rtt);

/** @brief Compute the burst timeout in milliseconds from the current RTT estimate. */
duct_nonnull(1) uint64_t duct_pmtu_drive_wait_ms(const duct_pmtu_drive_t *d);

/** @brief Begin the next burst at @p now, returning the count of rungs staged in @c d->rungs. */
duct_nonnull(1) uint8_t duct_pmtu_drive_burst(duct_pmtu_drive_t *d, uint64_t now);

/** @brief Score an echoed rung of wire size @p wire at @p now and update clean RTT. */
duct_nonnull(1) duct_pmtu_echo_t duct_pmtu_drive_echo(duct_pmtu_drive_t *d, uint16_t wire,
                                                      uint64_t now);

/** @brief Close an expired burst, fold kernel path-MTU cuts, and score silent upper bounds.
 *  @return true when @c d->search has reached convergence. */
duct_nonnull(1, 2) bool duct_pmtu_drive_settle(duct_pmtu_drive_t *d, duct_session_t *s,
                                               duct_conn_id_t conn_id);

#endif
