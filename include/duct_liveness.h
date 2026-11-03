/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_liveness.h
 *  @brief Silence check and rest detection for a link to one peer.
 *
 *  A @c duct_liveness_t holds the stamps of one link: the last traffic in either
 *  direction, the last frame heard from the peer and the deadline of the open
 *  check. The caller feeds it events and times; it sends no probe and arms no
 *  timer.
 *
 *  A check opens once the peer has been quiet for a span. Each deadline asks
 *  the caller for another probe with a wait twice the last, and the check ends
 *  dead after @c duct_liveness_tries deadlines passed unanswered. A frame heard
 *  closes it.
 *
 *  One instance serves one link on one thread; every time comes from one
 *  monotonic clock, nanoseconds.
 */

#ifndef DUCT_LIVENESS_H
#define DUCT_LIVENESS_H

#include "duct_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Deadlines an open check passes before the peer counts as silent. */
static constexpr uint8_t duct_liveness_tries = 3u;

/** @brief Liveness stamps of one link, all-zero before it moves a packet. */
typedef struct duct_liveness {
    uint64_t active_at, /**< Time traffic last crossed in either direction, 0 before the first. */
             heard_at,  /**< Time a frame last arrived from the peer, 0 before the first. */
             due_at;    /**< Deadline of the open check, 0 while none is open. */
    uint8_t  passed;    /**< Deadlines the open check has passed, the shift of its next wait. */
} duct_liveness_t;

/** @brief Verdict of a deadline. */
typedef enum : uint8_t {
    live_quiet, /**< Nothing is due: no check is open, or its deadline has not come. */
    live_ping,  /**< A deadline passed with tries left; the caller sends another probe. */
    live_dead,  /**< Every try passed unanswered; the check is closed. */
} duct_live_t;

/** @brief Note traffic crossing the link in either direction at @p now. */
static inline void duct_liveness_active(duct_liveness_t *l, uint64_t now)
{
    l->active_at = now;
}

/** @brief Note a frame heard from the peer at @p now, which closes the open check. */
static inline void duct_liveness_heard(duct_liveness_t *l, uint64_t now)
{
    l->heard_at = now;
    l->due_at = 0u;
}

/** @brief Close the open check without a verdict. */
static inline void duct_liveness_close(duct_liveness_t *l)
{
    l->due_at = 0u;
}

/** @brief Test whether the link has moved no traffic for @p rest_ns.
 *  False before the first traffic.
 */
static inline bool duct_liveness_resting(const duct_liveness_t *l, uint64_t now, uint64_t rest_ns)
{
    return l->active_at && now - l->active_at >= rest_ns;
}

/** @brief Open a check when the peer has been quiet for @p quiet_ns.
 *  @return true when a check opened: the caller sends the first probe, and its
 *          deadline is @p rto_ns on. False while a check is open or the peer
 *          spoke inside the span.
 */
static inline bool duct_liveness_check(duct_liveness_t *l, uint64_t now, uint64_t quiet_ns,
                                       uint64_t rto_ns)
{
    if (l->due_at || now - l->heard_at < quiet_ns)
        return false;
    l->passed = 0u;
    l->due_at = now + rto_ns;
    return true;
}

/** @brief Judge the open check at @p now.
 *  @p rto_ns is the caller's current base wait; each deadline passed doubles it
 *  for the next one. @retval live_ping carries the next deadline already set.
 */
static inline duct_live_t duct_liveness_due(duct_liveness_t *l, uint64_t now, uint64_t rto_ns)
{
    if (!l->due_at || now < l->due_at)
        return live_quiet;
    if (++l->passed >= duct_liveness_tries) {
        l->due_at = 0u;
        return live_dead;
    }
    l->due_at = now + (rto_ns << l->passed);
    return live_ping;
}

#ifdef __cplusplus
}
#endif

#endif
