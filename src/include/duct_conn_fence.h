/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_conn_fence.h
 *  @brief Conn close-fence orchestration — WFQ-ordered lifecycle handoff
 *  markers bridging the I/O thread to the owning worker.
 *
 *  Bridge module above @c duct_conn: posts wire-rebind / conn-lost fence
 *  markers onto the conn's own WFQ lane so they drain in frame-batch order,
 *  retries them on WFQ-full, and dispatches the io-side retire once the
 *  worker confirms no further access.
 */

#ifndef DUCT_CONN_FENCE_H
#define DUCT_CONN_FENCE_H

#include "duct_core.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct duct_conn duct_conn_t;
typedef struct duct_wfq_route duct_wfq_route_t;

/** @brief Rebind @p conn's wire for a wire-changing @c duct_proto_switch.
 *
 *  A peer unaware of the switch may still be mid-frame under the old wire,
 *  so the rebind waits for the unparsed leftover to drain or prove discardable
 *  before swapping. On drain, swaps @c conn->wire / @c wire_parser to
 *  @c wire_rebind_next's and posts the completion fence.
 *  No-op if @c wire_rebind_next is already clear, and for a conn at
 *  @c fence_quiescing or past: it keeps its sentinel and posts no fence, its
 *  @c conn_lost paying the leg's share of the switch.
 */
duct_nonnull(1, 2) void
duct_conn_wire_rebind(const duct_wfq_route_t *route, duct_conn_t *conn);

/** @brief Tell @p conn's owner worker its transport is gone, so it detaches
 *  the session-side leg.
 *
 *  Called once the io thread has torn down the fd/poll registration for a
 *  conn that was bound to a live session — pushes the conn_lost message onto
 *  the worker's normal WFQ lane, where @ref duct_session_exec_conn_lost runs
 *  it, so it drains after every frame batch already accepted for this conn.
 *  Advances @c conn_fence quiescing → posted once the lane slot is reserved
 *  and before the message is published, so the worker never sees the fence
 *  ahead of the state; a lane with no room leaves the conn quiescing and arms
 *  @c fl_req_fence_retry instead.
 */
duct_nonnull(1, 2) void
duct_conn_fence_lost_publish(const duct_wfq_route_t *route, duct_conn_t *conn);

/** @brief Retry a fence-retry request for @p conn.
 *
 *  Independent things it may be retrying:
 *  — a close fence still at @c fence_quiescing,
 *  — a wire-rebind fence whose sentinel is still set, on a conn short of
 *  @c fence_quiescing.
 */
duct_nonnull(1, 2) void
duct_conn_fence_retry(const duct_wfq_route_t *route, duct_conn_t *conn);

/** @brief Retire-request dispatch entry: the worker already confirmed no
 *  further worker-side access remains.
 *
 *  The confirmation is @ref duct_conn_fence_confirm_retire. CASes
 *  @c fence_retire_ready → @c fence_retired, then immediately tears down and
 *  releases the slot — the fence ordering proves no worker / io reference
 *  remains.
 */
duct_nonnull(1) void duct_conn_fence_retire(duct_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif /* DUCT_CONN_FENCE_H */
