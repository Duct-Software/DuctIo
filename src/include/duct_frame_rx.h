/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_frame_rx.h
 *  @brief RX wire-parse → frame-batch → WFQ-post pipeline, and its
 *  WFQ-full retry queue.
 *
 *  One @ref duct_frame_rx_ctx_t per I/O thread, embedded in the executor
 *  and reached by sibling modules through
 *  @ref duct_wfq_route_t::frame_rx. @ref duct_frame_rx_post is the single
 *  entry point every RX producer (stream/datagram read, listener
 *  classification, pending-create injection) calls once new bytes land in
 *  a conn's RX OLB.
 */

#ifndef DUCT_FRAME_RX_H
#define DUCT_FRAME_RX_H

#include "duct_core.h"
#include "duct_msg.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct duct_conn duct_conn_t;
typedef struct duct_wfq_route duct_wfq_route_t;
typedef struct duct_vmq_mpsc duct_vmq_mpsc_t;

/** @brief Words in the per-conn retry bitmap: one bit per conn slot. */
static constexpr size_t frame_rx_retry_words = (duct_runtime_max_conns + 63u) / 64u;

/** @brief Per-I/O-thread wire-parse batching scratch + WFQ-full retry queue.
 *
 *  @c batch_buf is sized from @c frame_ceiling at @ref
 *  duct_frame_rx_ctx_init and reused across every @ref duct_frame_rx_post
 *  call on this thread — never touched by another thread.
 */
typedef struct duct_frame_rx_ctx {
    unsigned         frame_ceiling; /**< Max frames per batch; derived from NORM-lane bytes. */
    char            *batch_buf;     /**< Heap; sized from frame_ceiling. */
    duct_msg_queue_t retry_q;       /**< Queued WFQ-full retry nodes.
                                      *  Drained by
                                      *  @ref duct_frame_rx_retry_drain. */
    uint64_t         retry_pending[frame_rx_retry_words]; /**< Bit per conn
                                      *  idx, set while that conn has a node
                                      *  queued in @c retry_q. Gates
                                      *  @ref duct_frame_rx_post from parsing
                                      *  ahead of it. */
} duct_frame_rx_ctx_t;

/** @brief Derive the frame ceiling from the NORM lane's byte capacity and
 *  size @c batch_buf from it.
 *
 *  @return false on a degenerate lane capacity (cannot carry even one
 *  frame) or allocation failure.
 */
duct_nonnull(1, 2) bool
duct_frame_rx_ctx_init(duct_frame_rx_ctx_t *ctx,
                       duct_vmq_mpsc_t *wfq,
                       unsigned n_workers,
                       unsigned n_io);

/** @brief Free @c batch_buf + drop every pending retry node. */
duct_nonnull(1) void duct_frame_rx_ctx_destroy(duct_frame_rx_ctx_t *ctx);

/** @brief Post complete wire frames in [posted_off, tail) of @p conn's RX
 *  OLB as WFQ batch messages.
 *
 *  When a wire is bound on @p conn, parses complete frames and groups them
 *  into one or more @c msg_frame_batch messages, bounded by @c
 *  ctx->frame_ceiling and the per-batch wire-byte budget. A WFQ-full push
 *  saves the unposted suffix into a retry node (drained by
 *  @ref duct_frame_rx_retry_drain); a partial tail from an incomplete frame
 *  remains unposted in the OLB.
 *
 *  On a parse error records @c close_protocol_error via @ref
 *  duct_gen_req_reason_set and ends the conn's input through
 *  @ref duct_frame_rx_end — RX is permanently desynced past this point. On a
 *  WFQ-full retry-save allocation failure, hard-closes @p conn via
 *  @ref duct_io_conn_close.
 *
 *  Without a wire, posts the entire unposted span as one single-frame batch
 *  (raw path).
 */
duct_nonnull(1, 2, 3) void
duct_frame_rx_post(const duct_wfq_route_t *route,
                   duct_frame_rx_ctx_t *ctx,
                   duct_conn_t *conn);

/** @brief Post the end of @p conn's input behind every frame it posted.
 *
 *  Runs once @c fl_conn_rx_eof is set: on the read or the parse error that set
 *  it or, while a retry node holds frames ahead of it, on that node's drain.
 *  Drops the bytes no frame took, posts a @c duct_frame_end descriptor through
 *  the lane and retry queue the frames took, and lets a wire rebind waiting on
 *  those bytes go through. A no-op on a conn whose input has not ended and on
 *  one already quiesced.
 */
duct_nonnull(1, 2, 3) void
duct_frame_rx_end(const duct_wfq_route_t *route,
                  duct_frame_rx_ctx_t *ctx,
                  duct_conn_t *conn);

/** @brief Retry every pending WFQ-full node. */
duct_nonnull(1, 2) void
duct_frame_rx_retry_drain(const duct_wfq_route_t *route,
                          duct_frame_rx_ctx_t *ctx);

/** @brief Drop @p conn's retry node, if any — teardown path. */
duct_nonnull(1, 2) void
duct_frame_rx_retry_discard(duct_frame_rx_ctx_t *ctx,
                            const duct_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif /* DUCT_FRAME_RX_H */
