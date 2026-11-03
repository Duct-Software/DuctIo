/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_worker.h
 *  @brief Worker module — lifecycle API and cross-module calls.
 *
 *  Also declares the worker-context calls the session modules make in-thread
 *  — admission, timer cancel, defer and retry discard — plus the declarative
 *  committer.
 */

#ifndef DUCT_WORKER_H
#define DUCT_WORKER_H

#include "duct_types.h"
#include "duct_core.h"
#include "duct_protocol.h"

#include <assert.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct duct_vmq_mpsc    duct_vmq_mpsc_t;
typedef struct duct_stream_ctx  duct_stream_ctx_t;

typedef union duct_conn_handle    duct_conn_handle_t;
typedef union duct_session_handle duct_session_handle_t;

/** @brief Initialize the worker module.
 *
 *  @param n_workers     Worker pthread count.
 *  @param n_io          I/O thread count: routes the WFQ lanes and, under
 *                       io-first pinning, offsets each worker's pin slot.
 *  @param wfq           Shared WFQ; stored per-slot at init.
 *  @param seal_key_lifetime_ms  Key lifetime armed on every sealed conn;
 *                       0 arms none.
 */
bool duct_worker_module_init(unsigned n_workers, unsigned n_io,
                             duct_vmq_mpsc_t *wfq,
                             uint64_t seal_key_lifetime_ms);

/** @brief Spawn worker threads + rendezvous on @c started flag. */
bool duct_worker_module_start_threads(void);

/** @brief Signal shutdown on all workers + wake each. */
void duct_worker_module_request_shutdown(void);

/** @brief Join all worker threads. */
void duct_worker_module_join(void);

/** @brief Cleanup.
 *  Destroys timers, deferred queues and ctrl stacks. A message left on a ctrl
 *  stack does not run, but a stranded invoke's @c on_done and a dialed open's
 *  @c on_error are called with @c rc_closed on the calling thread first.
 */
void duct_worker_module_cleanup(void);

/** @brief Per-worker thread entry point.
 *
 *  Places the calling thread on its pin slot, n_io + worker_id with io-first
 *  pinning and worker_id without, then runs the worker's main loop until
 *  shutdown.
 *
 *  Each pthread @ref duct_worker_module_start_threads spawns runs this,
 *  through a thin wrapper that unpacks the thread's @c void*
 *  argument into @p worker_id.
 */
void duct_worker_thread_entry(unsigned worker_id);

/** @brief Report the logical cpu worker @p worker_id placed itself on.
 *  @return -1 for an unpinned worker or a @p worker_id past the worker count.
 */
int duct_worker_thread_cpu(unsigned worker_id);

/** @brief Check if the conn has TX room for @p need bytes. */
bool duct_worker_admit_leg(duct_conn_handle_t conn, size_t need);

/** @brief How many encoded-response slots a callback transaction needs. */
typedef enum duct_admit_reserve : uint8_t {
    admit_reserve_response  = 1u, /**< Just the data response. */
    admit_reserve_with_push = 2u, /**< The data response, plus a possible
                                     *  stream-open push riding along. */
} duct_admit_reserve_t;

/** @brief Reservation size for the next callback transaction.
 *
 *  Scaled by @p reserve.
 *  @retval 0         No explicit cap — fall back to
 *                    @c duct_worker_admit_leg's coarse backpressure check.
 *  @retval SIZE_MAX  The reservation size overflowed at
 *                    @c duct_proto_create; treat as blocked.
 */
duct_nonnull(1) static inline size_t
duct_worker_admit_need(const duct_proto_t *proto,
                       duct_admit_reserve_t reserve)
{
    return proto->admit_need[reserve - 1u];
}

/** @brief Close one leg of a session, on the session's worker.
 *
 *  A @c close_normal, @c close_peer or @c close_protocol_error close of a leg
 *  with a TX ring follows the leg's output: while an earlier ticket waits, the
 *  engine park holds bytes or the ring has no room for the engine's
 *  @c close_notify, the close takes a ticket and waits parked. In
 *  its turn it stages the @c close_notify of a sealed wire, for a
 *  @c close_normal or @c close_peer close alone, and posts the close request,
 *  which io carries out once the ring drains. Any other reason, and a leg
 *  without a ring, posts at once.
 */
void duct_worker_conn_close(duct_conn_handle_t handle,
                            duct_close_reason_t reason);

/** @brief Client-first-flight hook.
 *
 *  Lazily creates @p handle conn's sealed-wire codec if missing, then
 *  — on that fresh creation — runs the engine's @c start, so a client-role
 *  engine can emit its first flight. No-op for a stale handle, a plain wire,
 *  an unbound conn, or a codec that already exists. Idempotent.
 *
 *  A fresh codec takes @p tx_prefix, the one its dial declared: over the
 *  codec prefix at the wire's width, or on an @c x_tcp conn as the stream's lead ahead
 *  of @c start.
 *  @return false only for a nonempty @p tx_prefix no codec of the conn takes:
 *          a plain wire, a failed build or a width fitting neither form.
 */
bool duct_worker_tls_ensure_started(duct_conn_handle_t handle, duct_view_u8 tx_prefix);

/** @brief Bound the handshake of leg @p handle of @p s.
 *  A sealed leg whose engine names peers and has not named this one by
 *  @c join_auth_timeout_ms is closed with @c close_timeout, the session
 *  standing while another leg does. Runs as a leg joins and as a session's
 *  first leg opens. Arms nothing for a plain wire or an engine naming no
 *  peer. */
duct_nonnull(1) void duct_worker_join_deadline_arm(duct_session_t *s, duct_conn_handle_t handle);

/** @brief Start the idle bound of @p s from its protocol's @c idle_timeout_ms.
 *  Arms nothing for a protocol without a bound or a session whose timer is
 *  pending. Runs on the session's worker, at session open and when a protocol
 *  switch completes. */
duct_nonnull(1) void duct_worker_idle_arm(duct_session_t *s);

/** @brief Encoded-response slot count for the next callback transaction.
 *
 *  @retval admit_reserve_with_push  @p cfg's stream-open push may ride along
 *                                   with the data response, multiplexed +
 *                                   @c on_stream_open.
 *  @retval admit_reserve_response   Otherwise.
 */
duct_nonnull(1) static inline duct_admit_reserve_t
duct_admit_slots(const duct_proto_cfg_t *cfg)
{
    return duct_has(cfg->flags, fl_proto_multiplexed)
        && cfg->on_stream_open
            ? admit_reserve_with_push : admit_reserve_response;
}

/** @brief Session timer cancellation.
 *
 *  Cancels every timer owned by @p h's session. Called from last-detach
 *  session teardown before @c destroy_state. No-op off the worker
 *  thread.
 */
duct_nonnull(1) void
duct_worker_session_timers_cancel(const duct_session_handle_t *h);

/** @brief Deferred-frame discard for one conn.
 *
 *  Acks @p conn's remaining unprocessed frames (no callback invoked) and
 *  clears its defer mask bit. Called from
 *  @ref duct_session_exec_conn_lost before leg detach, while @p conn's
 *  rx_buf is still valid to ack against.
 */
duct_nonnull(1) void
duct_worker_conn_defer_discard(const duct_conn_handle_t *conn);

/** @brief Stream handler cancellation.
 *
 *  Removes the coroutine from its run queue, releases its slot if
 *  stackless or destroys it if stackful, then frees the context.
 */
void duct_stream_cancel(duct_stream_ctx_t *hctx);

/** @brief Retry-list discard for one conn.
 *
 *  Drops every parked output that leaves on @p conn, its ticket going with
 *  the conn's TX ring, and lands the carried ack and drops the pin of every
 *  answer read on @p conn that leaves on another leg, its payload copied off
 *  @p conn's buffers first, or voided where no copy is to be had. Called from
 *  @ref duct_session_exec_conn_lost ahead of the retire confirm, past which
 *  io frees @p conn's rings while its handle still resolves.
 */
duct_nonnull(1) void
duct_worker_conn_retry_discard(const duct_conn_handle_t *conn);

/** @brief Response commit: route, TX stage, io wake, control effects.
 *
 *  Called by the worker's on_frame/on_batch path and by the session
 *  ctrl executors, which also run in worker context.
 */
void duct_response_commit(duct_session_t *s, duct_conn_id_t in_conn,
                          duct_stream_id_t in_stream,
                          duct_response_t *out);

/** @brief Release the owned payload of @p out.
 *  Nothing without @c fl_send_owned. With it, a set @c release is called on @c release_arg; with
 *  none, @c duct_del frees @c release_arg, or @c payload.data where that is nullptr. It clears
 *  nothing in @p out: a second call releases a second time.
 */
static inline void duct_response_release_owned(duct_response_t *out)
{
    if (!duct_has(out->flags, fl_send_owned))
        return;
    if (out->release) {
        out->release(out->release_arg);
        return;
    }
    void *block = out->release_arg ? out->release_arg : out->payload.data;
    duct_del(block);
}

#if DUCT_RUNTIME_STATS
typedef struct duct_worker_rt duct_worker_rt_t;

/** @brief Read-only pointer to worker telemetry counters;
 *  @return nullptr if bad id or stats off.
 */
const duct_worker_rt_t *duct_worker_rtstats(unsigned worker_id);

/** @brief Count one @c x_tcp direct send against the calling worker.
 *  @p cap is the write cap in force, 0 for none, and @p total the bytes
 *  offered: a send under a cap counts in @c tcp_eor_writes, one past it in
 *  @c tcp_cut_writes too. Call it on a worker thread.
 */
void duct_worker_rtstat_tcp_write(size_t cap, size_t total);

/** @brief Count one worker direct send that did not go whole against the
 *  calling worker.
 *  @p armed counts a send skipped on a write-armed conn in
 *  @c fastpath_armed_skip; otherwise the socket took less than it was
 *  offered, counted in @c fastpath_eagain. Call it on a worker thread.
 */
void duct_worker_rtstat_fast_miss(bool armed);
#endif

#ifdef __cplusplus
}
#endif

#endif /* DUCT_WORKER_H */
