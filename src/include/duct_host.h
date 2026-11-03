/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_host.h
 *  @brief io/worker → host egress relay.
 *
 *  "Host" is the embedding application: code running on any thread
 *  the engine does not own — neither an io thread, nor a worker.
 */

#ifndef DUCT_HOST_H
#define DUCT_HOST_H

#include "duct.h"
#include "duct_vmq.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef union duct_session_handle duct_session_handle_t;

/** @brief Copy @p cfg into the host-bridge singleton.
 *
 *  Called once from @ref duct_engine_launch.
 */
duct_nonnull(1) void duct_host_init(const duct_host_cfg_t *cfg);

/** @brief TX egress for a push-mode inter conn.
 *
 *  The leg kind @ref duct_conn_attach_inter opens. Enqueues @p pkt for host
 *  delivery via @c on_packet_out. Copies @p pkt into the worker egress lane
 *  for asynchronous batch dispatch via @c run. Worker-thread only.
 *
 *  @retval rc_ok             Queued, or the no-bridge case alike — @ref
 *                            duct_host_init left @c on_packet_out / @c run
 *                            unset, a silent no-op by design.
 *  @retval rc_again          Lane full: backpressure signal to retry.
 *  @retval rc_invalid_arg    @p pkt outgrows an empty lane, or its size
 *                            overflows the message header.
 *  @retval rc_invalid_order  Called off a worker thread.
 */
duct_nonnull(1) duct_result_t
duct_host_packet_out(const duct_session_handle_t *tok,
                     duct_conn_id_t conn_id, duct_view_u8 pkt);

/** @brief One egress slot carved and not yet resolved.
 *  Opaque to the holder: filled by @ref duct_host_egress_reserve, handed back
 *  to exactly one of @ref duct_host_egress_publish or
 *  @ref duct_host_egress_abandon.
 */
typedef struct duct_host_egress_hold {
    duct_vmq_lane_t        ln;        /**< Calling worker's egress lane view. */
    duct_vmq_reserve_pos_t pos;       /**< Carved slot, header included. */
    void                  *pkt;       /**< Message header the payload trails. */
    unsigned               worker_id; /**< Lane owner, re-resolved at drain. */
} duct_host_egress_hold_t;

/** @brief Carve @p size payload bytes on the calling worker's egress lane,
 *  addressed to @p conn_id of @p tok, and hand them back to write into.
 *
 *  The zero-copy half of @ref duct_host_packet_out: the bytes are written
 *  where they will be delivered from, so nothing copies them a second time.
 *  Producer work continues behind the hold and stays invisible until it
 *  resolves, so one is open at a time and only across the callback that fills
 *  it. Worker-thread only, same as @ref duct_host_packet_out.
 *
 *  @return Payload span, @p out filled; @c nullptr with @p out untouched when
 *          no bridge is configured, the lane has no room, or @p size outgrows
 *          an empty lane.
 */
duct_nonnull(1, 4) void *
duct_host_egress_reserve(const duct_session_handle_t *tok,
                         duct_conn_id_t conn_id, size_t size,
                         duct_host_egress_hold_t *out);

/** @brief Deliver @p len bytes of @p hold's span, and everything queued behind
 *  it, to @c on_packet_out.
 *  @p len at most the @c size the reserve was given; the rest of the span
 *  returns to the lane.
 */
duct_nonnull(1) void
duct_host_egress_publish(duct_host_egress_hold_t *hold, size_t len);

/** @brief Close @p hold without delivering its span.
 *  Whatever was queued behind it while it was open becomes visible here, so a
 *  response that took the copy path still reaches @c on_packet_out.
 */
duct_nonnull(1) void
duct_host_egress_abandon(duct_host_egress_hold_t *hold);

/** @brief True once the bridge has both a packet sink and a queue to run on.
 *  Decides whether the worker pool allocates egress lanes at all, so an engine
 *  with no inter conns carries none of this.
 */
bool duct_host_egress_enabled(void);

/** @brief True when a response of @p max_response bytes fits an empty egress lane.
 *  Evaluated at leg creation to reject protocols whose response caps exceed
 *  lane capacity. True when no bridge or lane exists.
 */
bool duct_host_egress_fits(size_t max_response);

/** @brief Stop egress drains from being scheduled, and wait out any already
 *  in flight.
 *
 *  A scheduled drain reads lane memory, so it must complete before lanes are
 *  freed. Runs after worker join (no producers remain) and before lanes are
 *  freed. A callback already queued still runs and delivers what it holds.
 *
 *  Bounded by @p timeout_ms, because a host that tore its queue down first
 *  leaves a drain that never runs: on expiry the lane is abandoned through
 *  @ref duct_worker_egress_abandon, its memory left allocated while a
 *  pending callback still points at it.
 */
void duct_host_egress_quiesce(unsigned n_workers, uint32_t timeout_ms);

/** @brief Fire the host's @c on_inter_resume hint through @c run,
 *  once a worker's drain pass moved any inter-conn traffic.
 *
 *  A coarse "retry a deferred push" signal untied to one push or
 *  one conn. No-op when @c run or @c on_inter_resume is not configured.
 */
void duct_host_inter_resume_fire(void);

#ifdef __cplusplus
}
#endif

#endif /* DUCT_HOST_H */
