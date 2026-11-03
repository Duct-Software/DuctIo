/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_io.h
 *  @brief Transport executor — lifecycle contract + cross-module routing.
 *
 *  @ref duct_io_t is the per-thread event-loop executor, opaque: accept,
 *  connect and join dispatch, and admission, all live behind it. A sibling
 *  module acting on a conn from outside the executor — wire and fence
 *  orchestration, wire-parse batching — receives a @ref duct_wfq_route_t
 *  as an opaque dispatch token.
 *
 *  Callers reach the module through the lifecycle API below.
 */

#ifndef DUCT_IO_H
#define DUCT_IO_H

#include "duct_conn.h"
#include "duct_core.h"

#include <stdatomic.h>
#include <stdbool.h>

typedef struct duct_listener duct_listener_t;

#ifdef __cplusplus
extern "C" {
#endif

typedef struct duct_vmq_mpsc     duct_vmq_mpsc_t;
typedef struct duct_frame_rx_ctx duct_frame_rx_ctx_t;
typedef struct duct_io           duct_io_t;
typedef struct duct_listener     duct_listener_t;
typedef struct duct_io_trunk     duct_io_trunk_t;

/** @brief Shared WFQ-routing context, one per io thread.
 *
 *  What the fence and frame-rx modules are handed:
 *  enough to compute a WFQ lane, arm the reverse wait, or self-repost via
 *  @c trunk, without exposing executor timers, pre-connections, or scratch space.
 *  @c trunk provides the post-and-kick surface @ref duct_io_trunk_req_post
 *  while events backend state remains encapsulated.
 *
 *  Valid on the originating thread; functions requiring the executor read
 *  thread-local state.
 */
typedef struct duct_wfq_route {
    duct_vmq_mpsc_t     *wfq;
    unsigned             n_workers,
                         n_io,
                         thread_id;
    duct_io_trunk_t     *trunk;
} duct_wfq_route_t;

/* Module lifecycle — called on the main / setup thread */

/** @brief Initialize the transport module.
 *
 *  @param n_io          Number of I/O threads (1 typical, max 2).
 *  @param wfq           Shared WFQ; posts to a worker's lane.
 *  @param n_workers     Worker count for lane routing.
 */
bool duct_io_init(unsigned n_io, duct_vmq_mpsc_t *wfq, unsigned n_workers);

/** @brief Copy the outgoing socket policy, after init and before starting threads. */
void duct_io_configure_sockets(duct_socket_prepare_fn prepare, void *ctx);

/** @brief Spawn I/O pthreads + rendezvous on @c started flag. Returns false on failure. */
bool duct_io_start_threads(void);

/** @brief Signal shutdown on all I/O threads. */
void duct_io_request_shutdown(void);

/** @brief Join all I/O threads. */
void duct_io_join(void);

/** @brief Cleanup: release connections, drain unhandled messages, and close descriptors.
 *  Teardown runs unhandled message destructors on the calling thread: invokes
 *  device @c release and packet-fd @c on_error with @c rc_closed.
 */
void duct_io_cleanup(void);

/** @brief Detach and return listener lists across all I/O threads as a single chain.
 *  Sets each thread's list pointer to null. Call before @ref duct_io_cleanup,
 *  threads already joined.
 */
duct_listener_t *duct_io_listeners_detach(void);

/** @brief Run io thread @p io_id until shutdown.
 *  Places the thread on its pin slot, @p io_id with io-first pinning and past
 *  every worker's without, then runs its event loop.
 */
void duct_io_thread_entry(unsigned io_id);

/** @brief Report the logical cpu io thread @p io_id placed itself on.
 *  @return -1 for an unpinned thread or an @p io_id past the io thread count.
 */
int duct_io_thread_cpu(unsigned io_id);

/** @brief CAS @p bit into @p handle's conn's gen_req, generation-checked; on
 *  a 0→nonzero req_flags transition, post + kick @p trunk's coalesced
 *  request message. Rejected outright once @p handle's generation no longer
 *  matches (@ref duct_conn_reclaim already won this conn's retire race).
 *  @return the 0→nonzero transition.
 */
duct_nonnull(1) bool
duct_io_trunk_req_post(duct_io_trunk_t *trunk, duct_conn_handle_t handle, duct_conn_req_flags_t bit);

/** @brief Unified close: I/O-side quiesce for both the unbound, pre-open and
 *  bound close-fence paths.
 *
 *  Resolves the executor from thread-local state on the calling I/O thread;
 *  connections are closed exclusively by their assigned I/O thread.
 */
duct_nonnull(1) void
duct_io_conn_close(duct_conn_t *conn, duct_close_reason_t reason);

/** @brief Free @p listener's datagram peer map.
 *
 *  Frees the internal hash table mapping datagram peers for @p listener
 *  during listener teardown.
 *  A no-op for a stream listener or one with no peers recorded.
 */
duct_nonnull(1) void duct_io_listener_dgram_peers_free(duct_listener_t *listener);

/** @brief Hand device leg @p conn's lent packets back to its device and free
 *  its RX slots.
 *
 *  When @c duct_device_ops_t::release_read is set, read memory is lent directly
 *  to the inter lane. Teardown calls this after draining the connection lane
 *  (releasing all lent slots) and before @c ops.release.
 *  A no-op on any other conn.
 */
duct_nonnull(1) void duct_io_device_teardown(duct_conn_t *conn);

/** @brief Close connections in @p listener's datagram peer table when the listener
 *  socket is revoked.
 *
 *  Closes @c x_udp_shared conns on all platforms. Closes @c x_udp_peer conns on
 *  Windows (TX-only sockets) and retains them on Linux (independent @c SO_REUSEPORT
 *  sockets). A no-op on a stream listener or one with no peers recorded.
 *  Closing is idempotent.
 */
duct_nonnull(1) void duct_io_listener_dgram_peers_close_all(duct_listener_t *listener);

/** @brief Resume the stream listeners parked for want of a descriptor, right after a socket closed.
 *  From any thread: posts every io thread its resume while any listener is parked, and
 *  nothing otherwise.
 */
void duct_io_accept_resume(void);

#if DUCT_RUNTIME_STATS
typedef struct duct_io_rt duct_io_rt_t;
/** @brief Read-only pointer to io-thread telemetry counters; nullptr if bad id or stats off. */
const duct_io_rt_t *duct_io_rtstats(unsigned io_id);

/** @brief Increment thread-local @c wfq_push_full counter.
 *  Single-writer from the assigned I/O thread; non-atomic.
 */
void duct_io_rtstat_wfq_push_full_inc(void);

/** @brief Increment thread-local @c fence_push_full counter.
 *
 *  Incremented when a fence publisher finds the @c wfq_pri_norm lane full
 *  and falls back to @c fl_req_fence_retry.
 *  Single-writer; non-atomic.
 */
void duct_io_rtstat_fence_push_full_inc(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* DUCT_IO_H */
