/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_redial.h
 *  @brief Redial pacing for a protocol that reconnects its own legs.
 *
 *  A @c duct_redial_t counts the attempts since the last success and names the
 *  transport its dials take. The delay before the next dial doubles per attempt up
 *  to a cap, and an attempt's deadline follows the same count and the transport.
 *  The functions here do arithmetic and fill a
 *  response; the engine starts no redial, so whether, when and with what prefix
 *  a leg redials stays with the protocol.
 *
 *  One instance serves one dial sequence on one thread.
 */

#ifndef DUCT_REDIAL_H
#define DUCT_REDIAL_H

#include "duct_core.h"
#include "duct_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief First redial delay, milliseconds. */
static constexpr uint64_t duct_redial_base_ms    = 250u;
/** @brief Doublings after which the redial delay stops growing. */
static constexpr uint8_t  duct_redial_cap        = 5u;
/** @brief First deadline of a datagram attempt, milliseconds. */
static constexpr uint64_t duct_redial_rto_ms     = 1000u;
/** @brief Longest attempt deadline, and every stream attempt's, milliseconds. */
static constexpr uint64_t duct_redial_rto_max_ms = 4000u;

/** @brief Attempt counter of one redial sequence and the transport of its dials. */
typedef struct duct_redial {
    uint8_t      attempts; /**< Delays handed out since the last reset, held at @c duct_redial_cap. */
    duct_xport_t xport;    /**< Transport of the dials. It picks the deadline curve, and a reset keeps it. */
} duct_redial_t;

/** @brief Take the delay before the next redial, milliseconds.
 *  The delay is @c duct_redial_base_ms doubled once per attempt counted so far;
 *  counting stops at @c duct_redial_cap, which holds the delay level.
 */
static inline uint64_t duct_redial_next_ms(duct_redial_t *r)
{
    uint64_t delay = duct_redial_base_ms << r->attempts;
    if (r->attempts < duct_redial_cap)
        ++r->attempts;
    return delay;
}

/** @brief Restart the curve once the peer has answered. */
static inline void duct_redial_reset(duct_redial_t *r)
{
    r->attempts = 0u;
}

/** @brief Deadline of the dial attempt in progress, milliseconds.
 *  An attempt over a delimited @c xport gets @c duct_redial_rto_ms doubled per
 *  attempt counted, up to @c duct_redial_rto_max_ms; any other attempt gets
 *  @c duct_redial_rto_max_ms.
 */
static inline uint64_t duct_redial_deadline_ms(const duct_redial_t *r)
{
    return duct_xport_delimited(r->xport)
         ? duct_min(duct_redial_rto_ms << r->attempts, duct_redial_rto_max_ms)
         : duct_redial_rto_max_ms;
}

/** @brief Fill @p out's timer with the next redial delay and the token @p timer_arg.
 *  Counts the attempt in @p r. The protocol's @c on_timer receives @p timer_arg
 *  when the delay ends.
 */
static inline void duct_response_redial(duct_response_t *out, duct_redial_t *r, uintptr_t timer_arg)
{
    out->control.timer.delay_ms = duct_redial_next_ms(r);
    out->control.timer.arg = timer_arg;
}

/** @brief Fill @p out's open_leg with a dial of @p addr at slot @p conn_id.
 *  @p kind is a connect kind. @p addr and @p prefix name storage that outlives
 *  the callback's return; @p prefix leads the new leg's wire.
 */
static inline void duct_response_dial(duct_response_t *out, duct_leg_kind_t kind,
                                      duct_conn_id_t conn_id, const char *addr, duct_view_u8 prefix)
{
    out->control.open_leg.kind = kind;
    out->control.open_leg.conn_id = conn_id;
    out->control.open_leg.connect_addr = addr;
    out->control.open_leg.tx_prefix = prefix;
}

#ifdef __cplusplus
}
#endif

#endif
