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

#include "duct.h"
#include "duct_types.h"
#include "duct_core.h"
#include "duct_protocol.h"
#include "duct_relay.h"

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

bool duct_worker_module_alive(void);

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

bool duct_proto_hold_root(duct_proto_t *p);
void duct_proto_release(duct_proto_t *p);

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
