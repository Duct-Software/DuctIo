/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_pmtu.h
 *  @brief Path-MTU search driven by the caller's own probes, and the probe
 *  bookkeeping that runs it.
 *
 *  A datagram protocol asks @ref duct_pmtu_probe what size to try, sends a
 *  packet that size itself, and reports back through @ref duct_pmtu_ack or
 *  @ref duct_pmtu_lost. The search touches no socket and knows nothing of what
 *  a probe looks like: only the protocol knows what its peer echoes, so only
 *  the protocol can say whether one arrived.
 *
 *  @ref duct_pmtu_mtu answers from the first call, at @c base, and rises as
 *  probes confirm. The ceiling is tried first, so a path at its full width
 *  settles in one probe and a narrower one is halved down to.
 *
 *  Probing requires datagrams to be dropped without IP fragmentation.
 *  Dialed datagram sockets enable the don't-fragment option for that reason;
 *  a shared listener socket does not.
 *
 *  @ref duct_pmtu_drive_t keeps the probe out, its send time and the round trip
 *  beside a search, and cuts the search to the path MTU the kernel holds for
 *  the leg. The drive builds, sends and times nothing: the protocol sends the
 *  probe, arms its timer with the wait the drive answers, and feeds echoes and
 *  losses back. The drive reads the kernel's figure through the session, so
 *  its calls belong to the session's own callbacks.
 */

#ifndef DUCT_PMTU_H
#define DUCT_PMTU_H

#include "duct_protocol.h"

#include <stdbool.h>
#include <stdint.h>

/** @brief Smallest MTU a search may be based on, IPv6's own link minimum.
 *  Every IPv6 path carries it, which makes a search usable before one probe
 *  has answered. */
static constexpr uint16_t duct_pmtu_base_min = 1280u;

/** @brief Consecutive unanswered probes that fail the size under probe, RFC
 *  8899's MAX_PROBES.
 *  A failed size bounds the search until a restart, and a probe goes
 *  unanswered to ordinary loss as well as to a path too narrow for it. */
static constexpr uint8_t duct_pmtu_unanswered_max = 3u;

/** @brief One path's search state: its bounds, and what probes have proven.
 *
 *  Single-thread use, one instance per path under search. The next probe size
 *  is computed dynamically from @c good and @c failed bounds.
 */
typedef struct {
    uint16_t base,   /**< Floor the search never reports below. */
             max,    /**< Ceiling the search never probes above. */
             good,   /**< Largest size a probe has confirmed. */
             failed; /**< Smallest size a probe has failed at; 0 while none
                       *  has. */
    uint8_t  unanswered; /**< Probes of the size under probe unanswered in a
                           *  row. Every call moving @c good or @c failed
                           *  clears it. */
} duct_pmtu_t;

/** @brief Open a search over @p base to @p max.
 *  A @p base under @ref duct_pmtu_base_min is raised to it, and a @p max under
 *  @p base is raised to @p base, so any pair yields a usable search. */
static inline void duct_pmtu_init(duct_pmtu_t *p, uint16_t base, uint16_t max)
{
    if (base < duct_pmtu_base_min)
        base = duct_pmtu_base_min;
    if (max < base)
        max = base;
    *p = (duct_pmtu_t){ .base = base, .max = max, .good = base };
}

/** @brief Reopen the search over the bounds it already has.
 *  The usable MTU drops back to @c base: a path that changed under a settled
 *  search no longer proves what it did. */
static inline void duct_pmtu_restart(duct_pmtu_t *p)
{
    p->good = p->base;
    p->failed = 0u;
    p->unanswered = 0u;
}

/** @brief Largest size probes have confirmed, answerable from the first call. */
static inline uint16_t duct_pmtu_mtu(const duct_pmtu_t *p)
{
    return p->good;
}

/** @brief Size to probe next, 0 once the search has nothing left to try.
 *  The ceiling comes first, then the midpoint between what is confirmed and
 *  what has failed; a window one size wide ends the search. */
static inline uint16_t duct_pmtu_probe(const duct_pmtu_t *p)
{
    if (p->good >= p->max)
        return 0u;
    if (p->failed == 0u)
        return p->max;
    if (p->failed <= p->good + 1u)
        return 0u;
    return (uint16_t)(p->good + (uint16_t)((p->failed - p->good) / 2u));
}

/** @brief Record that a probe of @p size arrived.
 *  A size at or below what is confirmed, or at or above what has failed, moves
 *  nothing, which keeps a late echo from reopening settled ground. */
static inline void duct_pmtu_ack(duct_pmtu_t *p, uint16_t size)
{
    if (size > p->good && (p->failed == 0u || size < p->failed)) {
        p->good = size;
        p->unanswered = 0u;
    }
}

/** @brief Record that a probe of @p size went unanswered.
 *  @p size is what the caller sent. Only the size still under probe counts;
 *  any other, 0 for no probe out included, records nothing.
 *  @return true when this loss fails @p size, the last of
 *          @ref duct_pmtu_unanswered_max in a row; false otherwise. */
static inline bool duct_pmtu_lost(duct_pmtu_t *p, uint16_t size)
{
    uint16_t want = duct_pmtu_probe(p);
    if (!want || size != want || ++p->unanswered < duct_pmtu_unanswered_max)
        return false;
    p->unanswered = 0u;
    p->failed = size;
    return true;
}

/** @brief Path MTU a search assumes where the kernel names none, Ethernet's. */
static constexpr uint16_t duct_pmtu_path_default = 1500u;
/** @brief Round trips of the last clean sample a probe is given before it counts as unanswered. */
static constexpr uint64_t duct_pmtu_rto_rtts     = 4u;
/** @brief Floor of a probe's wait, nanoseconds.
 *  It keeps a queue building behind a loaded leg from failing a size the path carries.
 */
static constexpr uint64_t duct_pmtu_rto_min_ns   = 50'000'000u;
/** @brief Ceiling of a probe's wait, nanoseconds. */
static constexpr uint64_t duct_pmtu_rto_max_ns   = 2'000'000'000u;

/** @brief A search with the bookkeeping of its probe.
 *  Filled by @ref duct_pmtu_drive_open.
 */
typedef struct duct_pmtu_drive {
    duct_pmtu_t search;  /**< Search the drive feeds. */
    uint16_t    floor,   /**< Base the search reopens from once the kernel's figure falls under a confirmed size. */
                probing; /**< Wire size of the probe awaiting its echo, 0 when none is out. */
    uint64_t    probe_at, /**< Time the probe out was sent. */
                rtt;      /**< Round trip of the last probe answered on its first try, nanoseconds; the seed from open until then. */
} duct_pmtu_drive_t;

/** @brief Open a search over @p base up to @p top on leg @p conn_id, cut to the kernel's path MTU.
 *  The ceiling is the smaller of @p top and the path MTU the kernel holds for
 *  the leg, @c duct_pmtu_path_default where it names none, and never under
 *  @p base. @p rtt seeds the probe waits. Clears the probe out.
 */
duct_nonnull(1, 2) void duct_pmtu_drive_open(duct_pmtu_drive_t *d, duct_session_t *s,
                                             duct_conn_id_t conn_id, uint16_t base, uint16_t top,
                                             uint64_t rtt);

/** @brief Wait before a probe sent after @p tries unanswered tries counts as lost, milliseconds.
 *  Four round trips and at least @c duct_pmtu_rto_min_ns, doubled once per try,
 *  at most @c duct_pmtu_rto_max_ns. A message of the protocol's own that
 *  retries on the same schedule takes its wait here too.
 */
duct_nonnull(1) uint64_t duct_pmtu_drive_wait_ms(const duct_pmtu_drive_t *d, unsigned tries);

/** @brief Record the probe of @p wire bytes sent at @p now.
 *  @return the wait before it counts as lost, milliseconds, for the try the
 *          search is on; the caller arms its timer with it.
 */
duct_nonnull(1) uint64_t duct_pmtu_drive_sent(duct_pmtu_drive_t *d, uint16_t wire, uint64_t now);

/** @brief Match an echo of @p wire bytes arriving at @p now against the probe out.
 *  A probe answered on its first try sets the round trip.
 *  @return true when the echo is the probe out: the search confirms the size
 *          and the probe clears. False for any other echo, which changes nothing.
 */
duct_nonnull(1) bool duct_pmtu_drive_echo(duct_pmtu_drive_t *d, uint16_t wire, uint64_t now);

/** @brief Count the probe out as unanswered and clear it.
 *  A kernel path MTU under the probe's size reopens the search under that
 *  figure, keeping a confirmed size that fits it and falling to the floor
 *  otherwise. Without one the loss counts against the size, which fails on its
 *  last try. A call with no probe out counts nothing.
 *  @return true when the search changed under the caller: it applies
 *          @ref duct_pmtu_mtu again.
 */
duct_nonnull(1, 2) bool duct_pmtu_drive_lost(duct_pmtu_drive_t *d, duct_session_t *s,
                                             duct_conn_id_t conn_id);

#endif
