/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct.h
 *  @brief Single public include and runtime entry points.
 *
 *  One include pulls the core surface: types, core, wire, protocol, stream
 *  handlers and the TX staging pool. Sealing, crypto and the tick clock are
 *  opt-in headers of their own.
 *
 *  Protocol logic is callbacks returning a @ref duct_response_t — its top
 *  level is the outbound frame, its @c control subsection declares the side
 *  effects the framework applies after the callback returns. A few operations
 *  stay imperative on the opaque @ref duct_session_t handle.
 *  @c duct_engine_launch starts a running engine
 *  in one call; @c duct_engine_wait blocks until a stop is requested, by
 *  @ref duct_engine_request_stop or a stop signal among others, and then stops.
 *  Internal buffer sizes, the session table, conn slab, WFQ and OLB are not
 *  part of this contract.
 */

#ifndef DUCT_H
#define DUCT_H

#include "duct_types.h"
#include "duct_str.h"
#include "duct_file.h"
#include "duct_wire.h"
#include "duct_protocol.h"
#include "duct_stream.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Runtime configuration */

/** @brief Runtime configuration for one engine.
 *
 *  @c host matters only for inter conns; leave it zero-initialized when every
 *  conn is polled from an fd.
 */
typedef struct duct_engine_cfg {
    unsigned         io_threads; /**< Reactor pthread count; must be at least 1. */
    unsigned         workers;    /**< Worker pthread count for protocol logic. */
    duct_host_cfg_t  host;       /**< Inter-conn host bridge. */
    duct_socket_prepare_fn socket_prepare; /**< Prepares every outgoing IP socket before connect; null for normal sockets. */
    void            *socket_ctx; /**< Argument of @c socket_prepare; lives until engine destruction returns. */
    uint64_t         seal_key_lifetime_ms; /**< Lifetime of a sealed conn's key
                                             *   set, milliseconds. Once it
                                             *   passes, up to a quarter early,
                                             *   the engine's @c rekey runs with
                                             *   the conn's next PDU either way,
                                             *   so an idle conn sends nothing
                                             *   for its keys. 0 leaves a conn
                                             *   the keys it opened with. An
                                             *   engine whose vtbl sets no
                                             *   @c rekey ignores it. */
    uint32_t         spin_window_us; /**< Longest spin of an io or worker thread
                                       *   on one idle stretch, microseconds.
                                       *   Cut to @c spin_gap_cutoff_us; within
                                       *   it each thread picks its spin from
                                       *   the gaps it has seen. 0 takes the
                                       *   build's @c DUCT_BUSY_SPIN_US, and
                                       *   @c DUCT_BUSY_SPIN_NS in the
                                       *   environment overrides both. On a
                                       *   host with one cpu online no thread
                                       *   spins, whatever the three say. */
    uint32_t         spin_gap_cutoff_us; /**< Price of one park and wake of an
                                           *   io or worker thread, microseconds
                                           *   of spin. A thread weighs every
                                           *   spin against it and spins no
                                           *   longer. 0 takes the build's
                                           *   @c DUCT_SPIN_GAP_CUTOFF_US, and
                                           *   @c DUCT_SPIN_GAP_CUTOFF_NS in the
                                           *   environment overrides both; a
                                           *   price of 0 there parks at once. */
} duct_engine_cfg_t;

/* Lifecycle */

/** @brief Validate @p cfg, allocate the runtime, and spawn its I/O and
 *  worker threads — @p e is already running by the time this returns.
 *
 *  @param cfg  Borrowed for the call only; copied internally.
 *  @return A running engine, or @c nullptr on invalid config, allocation
 *         failure, or a thread-spawn failure (torn down before returning,
 *         same as any other constructor failure — nothing to clean up).
 */
duct_engine_t *duct_engine_launch(const duct_engine_cfg_t *cfg);

/** @brief Stop if running, then destroy the runtime and release all resources.
 *  A dial or a packet-fd open not yet resolved reaches its protocol's @c on_error before this
 *  returns, on the calling thread, with @c rc_closed or the failure it already has, so the
 *  @c user_ctx it carries stays valid until then. A POSIX name lookup still running reports nothing.
 */
void duct_engine_destroy(duct_engine_t *e);

/** @brief Block the calling thread until a stop is requested, then stop the engine.
 *  A request is @ref duct_engine_request_stop, a stop signal armed by
 *  @ref duct_engine_stop_on_signals, or a @ref duct_engine_stop or
 *  @ref duct_engine_destroy on another thread; one made before the call ends the
 *  wait at once. The stop that follows is @ref duct_engine_stop's.
 *  @return @c rc_ok, or @c rc_invalid_arg for a null @p e.
 */
duct_result_t duct_engine_wait(duct_engine_t *e);

/** @brief Signal shutdown and join the I/O and worker threads.
 *  @return @c rc_ok once all threads have joined.
 */
duct_result_t duct_engine_stop(duct_engine_t *e);

/** @brief Ask for a stop without stopping.
 *  Sets the request that @ref duct_engine_wait_request and @ref duct_engine_wait
 *  sleep on and wakes them. Callable from any thread, a signal handler included.
 *  Requests do not add up, and the next @ref duct_engine_launch starts with none.
 *  @return @c rc_ok, or @c rc_invalid_arg for a null @p e.
 */
duct_result_t duct_engine_request_stop(duct_engine_t *e);

/** @brief Block the calling thread until a stop is requested.
 *  A request is @ref duct_engine_request_stop, a stop signal armed by
 *  @ref duct_engine_stop_on_signals, or a @ref duct_engine_stop or
 *  @ref duct_engine_destroy on another thread; one made before the call ends the
 *  wait at once, and any number of threads may wait. The engine keeps running:
 *  the caller does its own teardown, then calls @ref duct_engine_stop.
 *  @return @c rc_ok, or @c rc_invalid_arg for a null @p e.
 */
duct_result_t duct_engine_wait_request(duct_engine_t *e);

/** @brief Make the process's stop signals request a stop of @p e until it is
 *  destroyed.
 *  SIGINT, SIGTERM and SIGHUP on POSIX; Ctrl-C, Ctrl-Break and a closed console on
 *  Windows. @ref duct_engine_destroy puts back the handlers the process had, and a
 *  second call arms nothing more. A closed console on Windows keeps its handler
 *  waiting for four seconds, within which the process ends when @c main returns.
 *  @return @c rc_ok, or @c rc_invalid_arg for a null @p e.
 */
duct_result_t duct_engine_stop_on_signals(duct_engine_t *e);

/** @brief Kind of engine-owned thread a placement query names. */
typedef enum duct_thread_role : uint8_t {
    thread_io,     /**< I/O reactor thread, indexed below @c io_threads. */
    thread_worker, /**< Worker thread, indexed below @c workers. */
} duct_thread_role_t;

/** @brief Report the logical cpu engine thread @p index of @p role was placed on.
 *  Each thread places itself once as it starts, before @ref duct_engine_launch
 *  returns, so the answer holds for the engine's lifetime. How strongly the
 *  placement holds is the platform implementation's.
 *  @return the cpu, or -1 for a null @p e, an unknown @p role, an @p index past
 *          that role's threads, a build with pinning off, or a placement the
 *          system refused.
 */
int duct_engine_thread_cpu(const duct_engine_t *e, duct_thread_role_t role, unsigned index);

/** @brief The engine's actual worker count; 0 for a null @p e. */
unsigned duct_engine_workers(const duct_engine_t *e);

/* Network binding */

/** @brief Listen for inbound stream connections; one session per accepted conn.
 *
 *  Sugar over @ref duct_listener_bind with a one-protocol array. Accepted
 *  sessions receive @c proto_cfg.user_ctx as their @c on_session_open
 *  @c user_ctx. Does not report the listening socket(s) back — revoke via
 *  @ref duct_listener_bind directly when the caller needs @ref duct_listener_close.
 *
 *  @param e         Runtime instance.
 *  @param host      Bind host as a bare name/IP, e.g. @c "127.0.0.1", @c "::1",
 *                  @c "0.0.0.0", @c "::" (no port, no brackets).
 *  @param port      In/out: pass @c 0 to bind an OS-assigned ephemeral port; on
 *                  @c rc_ok receives the actual bound port. Required (non-NULL).
 *  @param proto     Protocol bound to every accepted session.
 *  @return @c rc_ok once the listener is registered.
 */
duct_result_t duct_io_listen(duct_engine_t *e, const char *host, uint16_t *port,
                              duct_proto_t *proto);

/** @brief Bind a listener with an explicit protocol array and pre-parse
 *        configuration; stream or datagram, selected by @c cfg->kind.
 *
 *  Callable at any point in @p e's life, from any thread.
 *
 *  @param e         Runtime instance.
 *  @param cfg       Borrowed for the call; @c cfg->addr is the bind host, no port, or @c cfg->local_path names a path listener's socket file.
 *  @param port      In/out, required: @c 0 asks for an ephemeral port, @c rc_ok writes back the one bound, 0 for a path listener.
 *  @param out_fds   Optional; takes up to @p max_fds of the sockets opened, one per I/O thread, in registration order.
 *  @param max_fds   Capacity of @p out_fds; ignored when that is @c nullptr.
 *  @param out_n_fds Optional; takes how many sockets opened, which may exceed @p max_fds — the excess are live, just unreported.
 *  @retval rc_ok           Listener registered.
 *  @retval rc_invalid_arg  A required argument is missing, a protocol does not fit @c cfg->kind (a @c listener_dgram
 *                          wire absent, or sealed without @c fl_seal_dgram_ok), @c cfg->peek_min cannot be met, or
 *                          the path fields do not fit the listener, see @c duct_listener_cfg_t::local_path.
 *  @retval rc_not_supported  A path listener in a build targeting Windows before 10 1803.
 *  @retval rc_fatal        A socket or path was refused, or the I/O thread did not take the node.
 *  @retval rc_no_memory    @p e is already at @c duct_runtime_max_listeners, or an allocation failed.
 */
duct_result_t duct_listener_bind(duct_engine_t *e, const duct_listener_cfg_t *cfg,
                                  uint16_t *port,
                                  duct_sock_t *out_fds, unsigned max_fds,
                                  unsigned *out_n_fds);

/** @brief Open an outbound connection; one session for the link.
 *
 *  A call returning @c rc_ok ends in @c on_session_open, or with a null session
 *  and @p user_ctx in @c on_error, a destroy of @p e before the dial resolves
 *  included; an error that finds no memory reports nothing.
 *
 *  @param e         Runtime instance.
 *  @param addr      Peer address as @c "host:port" or @c "[::]:port", pure
 *                  ASCII for a symbolic host; @c x_local takes the path.
 *  @param proto     Protocol bound to the session.
 *  @param user_ctx  Borrowed; stored on the session and delivered to
 *                  @c on_session_open. May be @c nullptr.
 *  @param xport     x_tcp for a stream dial, x_udp_peer for a connected-UDP
 *                  dial, x_local for an AF_UNIX one; any other is rejected.
 *  @retval rc_ok             Connect initiated.
 *  @retval rc_invalid_arg    @p addr does not parse (a non-ASCII host, or for
 *                            @c x_local a path empty or too long for
 *                            @c sun_path), or @p xport is none of the three.
 *  @retval rc_not_supported  @c x_local on a Windows build older than 10 1803.
 */
duct_result_t duct_io_connect(duct_engine_t *e, const char *addr,
                               duct_proto_t *proto,
                               void *user_ctx, duct_xport_t xport);

/** @brief Open an outbound connection from a socket bound to interface @p egress_if,
 *  led by @p tx_prefix.
 *
 *  Takes @ref duct_io_connect's arguments and returns its codes. The socket is
 *  bound to the interface of that index before it connects; @c 0 binds none.
 *  An index no interface holds, and a bind the host refuses, fail the dial
 *  through @c on_error with @c rc_fatal. On Linux the socket also receives
 *  from that interface alone.
 *
 *  @param egress_if  Interface index: @c if_nametoindex on POSIX, the adapter's
 *                    interface index on Windows. @c x_local takes none: @c rc_invalid_arg.
 *  @param tx_prefix  Cleartext bytes ahead of everything else the conn sends, at
 *                    most @c duct_seal_prefix_max, copied during the call; empty
 *                    for none. More bytes, or a size with no data, return
 *                    @c rc_invalid_arg. A stream dial writes them once, a datagram
 *                    dial leads its PDUs with them in place of the wire's prefix.
 *                    A wire whose codec cannot take them closes the conn at the
 *                    session's open and fails the dial through @c on_error with
 *                    @c rc_invalid_arg.
 */
duct_result_t duct_io_connect_via(duct_engine_t *e, const char *addr,
                                   duct_proto_t *proto,
                                   void *user_ctx, duct_xport_t xport,
                                   uint32_t egress_if, duct_view_u8 tx_prefix);

duct_result_t duct_io_connect_worker(duct_engine_t *e, const char *addr,
                                     duct_proto_t *proto,
                                     void *user_ctx, duct_xport_t xport,
                                     uint32_t egress_if, duct_view_u8 tx_prefix,
                                     unsigned worker);

/** @brief Open a session whose leg 0 is the caller's packet-delimited fd.
 *
 *  The session-opening sibling of @ref duct_conn_attach_packet_fd, callable from
 *  any thread while @p e runs. The conn is @c x_raw_packet, bound to @p proto's
 *  own wire, which must exist and fit a packet leg: @ref duct_wire_packet gives
 *  one frame per packet. @p fd belongs to the engine from this call on, whatever
 *  it returns. The session opens on a worker and delivers @p user_ctx to
 *  @c on_session_open, as a dial does; a conn the I/O thread cannot set up
 *  reaches @c on_error with @c rc_no_memory, a null session and @p user_ctx,
 *  and an engine destroyed before the open ran reaches it with @c rc_closed.
 *
 *  @retval rc_ok             Posted to an I/O thread.
 *  @retval rc_invalid_arg    Null @p e or @p proto, @c duct_sock_bad as @p fd, a
 *                            protocol with no wire, or a wire whose framing does
 *                            not fit a packet leg.
 *  @retval rc_invalid_order  @p e is not running.
 *  @retval rc_not_supported  Windows, whose packet leg refuses its first read.
 *  @retval rc_no_memory      The message allocation failed.
 */
duct_result_t duct_io_attach_packet_fd(duct_engine_t *e, duct_sock_t fd, duct_proto_t *proto,
                                       void *user_ctx);

/** @brief Start a one-shot timer that belongs to no session.
 *
 *  After @p delay_ms, 0 meaning the worker's next turn, @p proto's @c on_timer
 *  runs once on a worker with a null session, @p user_ctx as its
 *  @c proto_state and @p arg as its token. The response @c on_timer fills is not
 *  applied. A timer still pending when the engine stops is freed without
 *  firing, and one the worker finds no memory for is dropped without a report.
 *  Callable from any thread, an @c on_timer included. @p proto and @p user_ctx
 *  stay the caller's and must live until the engine is destroyed.
 *
 *  @retval rc_ok             Timer posted.
 *  @retval rc_invalid_arg    Null @p e or @p proto, a protocol with no
 *                            @c on_timer, or a @p delay_ms that overflows
 *                            microseconds.
 *  @retval rc_invalid_order  The engine is not running.
 *  @retval rc_no_memory      Allocation failed.
 */
duct_result_t duct_timer_start(duct_engine_t *e, duct_proto_t *proto, void *user_ctx,
                               uint64_t delay_ms, uintptr_t arg);

/** @brief Worker index wildcards. @c duct_worker_any picks a worker round-robin;
 *  @c duct_worker_none is what @ref duct_worker_self answers off a worker thread.
 */
static constexpr unsigned duct_worker_any  = UINT32_MAX;
static constexpr unsigned duct_worker_none = UINT32_MAX;

/** @brief The calling thread's worker id, or @c duct_worker_none off a worker. */
unsigned duct_worker_self(void);

/** @brief Out-of-session work: runs on the addressed worker, outside any session. */
typedef void (*duct_worker_fn)(duct_engine_t *e, unsigned worker, void *ctx);

duct_nonnull(2, 3) duct_result_t
duct_worker_post_work(unsigned worker_id, duct_engine_t *e, duct_worker_fn fn, void *ctx);

duct_nonnull(2, 3) duct_result_t
duct_worker_post_proto(unsigned worker_id, duct_engine_t *e, duct_proto_t *proto,
                       void *user_ctx, uintptr_t arg);

/** @brief Post @p fn onto one worker's ctrl stack and return immediately.
 *
 *  The worker runs @c fn(e, its id, ctx) during its next drain. @p ctx stays
 *  the caller's: a node still queued at engine stop is freed without execution
 *  and the runtime runs no callback for it. @p fn must not block — a blocking
 *  @p fn stalls every machine parked on that worker; work that waits unbounded
 *  or on events unrelated to @p fn runs on its own context and posts its
 *  completion back with @ref duct_worker_post. A host machine keeps one home
 *  worker for its whole life and re-posts when it finds itself elsewhere.
 *
 *  @param e       Runtime instance.
 *  @param worker  Worker index, or @c duct_worker_any for round-robin.
 *  @param fn      Work to run on the worker.
 *  @param ctx     Argument forwarded to @p fn.
 *  @retval rc_ok             Posted.
 *  @retval rc_invalid_arg    Null @p e or @p fn, or an index past the worker
 *                            count other than @c duct_worker_any.
 *  @retval rc_invalid_order  The engine is not running.
 */
duct_result_t duct_worker_post(duct_engine_t *e, unsigned worker,
                               duct_worker_fn fn, void *ctx);

/** @brief Post one @c on_work tour of @p proto onto a worker's ctrl stack.
 *
 *  The worker runs @c cfg.on_work with @c user_ctx falling back to
 *  @c cfg.user_ctx when null; the message carries a root hold on @p proto from
 *  post to execution or cleanup, so a tour cannot outlive its protocol. A tour
 *  may call the OS boundary synchronously — adapter close, netlink, a guard
 *  transaction — when the result gates the tour's own next state and the call
 *  is bounded; it suspends instead, a coroutine wait or a machine state, when
 *  the wait is unbounded, when other cargo on that worker would actually
 *  progress meanwhile, or when it waits on work unrelated to the tour's next
 *  state.
 *
 *  @param e         Runtime instance.
 *  @param worker    Worker index, or @c duct_worker_any for round-robin.
 *  @param proto     Protocol whose @c on_work runs; must stay alive until the
 *                   engine is destroyed.
 *  @param user_ctx  Argument for the tour; null falls back to @c cfg.user_ctx.
 *  @param arg       Tag forwarded to @c on_work.
 *  @retval rc_ok             Posted.
 *  @retval rc_invalid_arg    Null @p e or @p proto, a protocol without
 *                            @c on_work, or an index past the worker count.
 *  @retval rc_invalid_order  The engine is not running, or the hold count on
 *                            @p proto is exhausted.
 */
duct_result_t duct_proto_post(duct_engine_t *e, unsigned worker,
                              duct_proto_t *proto, void *user_ctx, uintptr_t arg);

/** @brief Revoke one listener by its socket, from any thread.
 *
 *  Deregisters exactly the node whose listening socket equals @p fd — one of
 *  the values @ref duct_listener_bind reported through its @c out_fds
 *  parameter — and closes that socket; a path listener first removes its socket
 *  file while the file is still its own. Sessions already accepted through it
 *  are unaffected; other listeners (including sibling I/O-thread sockets from
 *  the same @c duct_listener_bind call) keep running. Blocks the caller until
 *  the deregistration is confirmed on the owning I/O thread, or a bounded wait
 *  elapses first.
 *
 *  @param e   Runtime instance.
 *  @param fd  Listening socket to revoke, as reported via @c out_fds.
 *  @retval rc_ok           Listener closed.
 *  @retval rc_invalid_arg  @p fd does not name a live listener.
 *  @retval rc_timeout      The bound elapsed first (the close may still
 *                          complete afterward).
 *  @retval rc_no_memory    Allocation failure.
 */
duct_result_t duct_listener_close(duct_engine_t *e, duct_sock_t fd);

/* Host-thread session control */

/** @brief Post @p fn to the session's worker and return immediately.
 *
 *  The worker runs @c fn(s, out, ctx) during its next drain and processes @p out
 *  (route + stage + publish + notify) after @p fn returns. @p ctx must stay valid
 *  until the worker finishes @c fn, not merely until this call returns.
 *
 *  @param e    Runtime instance.
 *  @param tok  Session token.
 *  @param fn   Work to run on the worker.
 *  @param ctx  Argument forwarded to @p fn.
 *  @retval rc_ok      Posted successfully.
 *  @retval rc_closed  @p tok is stale.
 */
duct_result_t duct_session_invoke(duct_engine_t *e,
                                   duct_handle_t tok,
                                   duct_session_fn fn,
                                   void *ctx);

/** @brief Invoke completion; runs exactly once per accepted call — see
 *  @ref duct_session_invoke_done.
 */
typedef void (*duct_session_invoke_done_fn)(duct_result_t rc, void *done_ctx);

/** @brief Post @p fn to the session's worker and report its outcome to
 *  @p on_done exactly once.
 *
 *  @p on_done runs with @p fn's return code on the worker after a normal
 *  commit, with @c rc_closed on the worker when @p tok no longer resolves by
 *  the time the message executes, with @c rc_no_memory synchronously on this
 *  thread when the message allocation fails, and with @c rc_closed
 *  synchronously when the engine is not running or @p tok is already stale.
 *  Releasing @p done_ctx is @p on_done's job — the runtime never frees it.
 *
 *  @param e         Runtime instance.
 *  @param tok       Session token.
 *  @param fn        Work to run on the worker.
 *  @param ctx       Argument forwarded to @p fn.
 *  @param on_done   Completion callback; runs exactly once.
 *  @param done_ctx  Argument forwarded to @p on_done.
 *  @retval rc_ok           Posted; @p on_done still runs exactly once.
 *  @retval rc_invalid_arg  Null @p e or @p fn; @p on_done does not run.
 *  @retval rc_closed       The engine is not running or @p tok is stale;
 *                          @p on_done has run with @c rc_closed.
 */
duct_result_t duct_session_invoke_done(duct_engine_t *e,
                                        duct_handle_t tok,
                                        duct_session_fn fn,
                                        void *ctx,
                                        duct_session_invoke_done_fn on_done,
                                        void *done_ctx);

/** @brief Post @p fn and block the caller until @c fn and its flush complete,
 *  or a 5-second timeout elapses first.
 *
 *  For tests, shutdown, and host threads that do not serve the worker. Never call
 *  it from a thread the worker may wait on — deadlock risk. Here @p ctx need only
 *  outlive the call. The bound exists so a pathological @p fn that never returns
 *  cannot hang the caller (or, symmetrically, an in-progress call cannot hang
 *  @c duct_engine_stop / @c duct_engine_destroy)
 *  forever. On @c rc_timeout, @p fn may still run (or
 *  may already have run) after this call returns; it is not safe to assume
 *  either outcome.
 *
 *  @param e    Runtime instance.
 *  @param tok  Session token.
 *  @param fn   Work to run on the worker.
 *  @param ctx  Argument forwarded to @p fn.
 *  @return The result @c fn returned, on success.
 *  @retval rc_closed   @p tok is stale or the engine is not running.
 *  @retval rc_timeout  The bound elapsed first.
 */
duct_result_t duct_session_invoke_sync(duct_engine_t *e,
                                        duct_handle_t tok,
                                        duct_session_fn fn,
                                        void *ctx);

/** @brief Function that @c duct_session_dispatch runs on a session's worker. */
typedef void (*duct_session_dispatch_fn)(void *ctx);

/** @brief Run @p fn on the worker that serves the session of @p tok, at once when the caller is that worker.
 *
 *  A call made on that worker's thread runs @c fn(ctx) nested in the callback that made it, ahead of every call
 *  already posted to the worker, and returns after it. A call from any other thread posts @p fn and returns
 *  without waiting. Either way @p fn never runs beside a callback of a session the worker serves. The call in
 *  place commits nothing and a posted one commits an empty response, so work that must answer goes through
 *  @c duct_session_invoke.
 *
 *  @p ctx must stay valid until @p fn has run. A posted call whose session ends before the worker reaches it is
 *  dropped without notice: @p fn does not run and @p ctx stays the caller's.
 *
 *  @retval rc_ok           @p fn ran, or is posted and runs unless the session ends or the engine stops first.
 *  @retval rc_closed       @p tok is stale; @p fn does not run.
 *  @retval rc_no_memory    Allocation failed; @p fn does not run.
 *  @retval rc_invalid_arg  @p e or @p fn is null.
 */
duct_result_t duct_session_dispatch(duct_engine_t *e,
                                    duct_handle_t tok,
                                    duct_session_dispatch_fn fn,
                                    void *ctx);

/** @brief Close a session from a host thread; returns after posting.
 *
 *  Equivalent to an invoke whose @c fn calls the worker-thread session close.
 *  The protocol's @c on_session_close runs on the worker.
 *
 *  @param e       Runtime instance.
 *  @param tok     Session token.
 *  @param reason  Close reason recorded for the session.
 *  @retval rc_ok      Posted successfully.
 *  @retval rc_closed  @p tok is stale.
 */
duct_result_t duct_session_close(duct_engine_t *e,
                                  duct_handle_t tok,
                                  duct_close_reason_t reason);

/** @brief Push one packet into an inter conn.
 *        A thin wrapper over @ref duct_io_inter_batch for a single packet.
 *
 *  @p pkt is non-owning; copied onto the lane before this call returns.
 *  @p conn_id must name a conn attached with @c duct_conn_attach_inter.
 *  Prefer @ref duct_io_inter_batch for throughput.
 *
 *  @param e        Runtime instance.
 *  @param tok      Session token.
 *  @param conn_id  Target inter conn.
 *  @param pkt      Non-owning packet view.
 *  @retval rc_ok      Handed off.
 *  @retval rc_closed  @p tok is stale.
 */
duct_result_t duct_io_inter_packet(duct_engine_t *e,
                                   duct_handle_t tok,
                                   duct_conn_id_t conn_id,
                                   duct_view_u8 pkt);

/** @brief Push a batch of packets into an inter conn, the primary push-ingress path.
 *
 *  Synchronous: the packets are copied onto the conn's lane before this
 *  returns. Allocate the batch with @ref duct_inter_batch_bytes.
 *
 *  @warning Single-producer: the lane is an SPSC ring whose one legitimate
 *  consumer is the owning worker. Serialize calls onto one @p conn_id —
 *  concurrent calls for the *same* conn from several host threads corrupt the
 *  ring. Different conns are independent.
 *
 *  @param e        Runtime instance.
 *  @param tok      Session token.
 *  @param conn_id  Target inter conn.
 *  @param batch    Packet batch; only referenced for the duration of this call.
 *  @retval rc_ok           Handed off.
 *  @retval rc_defer        The lane is momentarily full.
 *  @retval rc_invalid_arg  The batch never fits the lane.
 *  @retval rc_closed       @p tok is stale.
 */
duct_result_t duct_io_inter_batch(duct_engine_t *e,
                                  duct_handle_t tok,
                                  duct_conn_id_t conn_id,
                                  const duct_inter_batch_t *batch);

/** @brief Runtime telemetry, summed across every worker and I/O thread.
 *        All fields read 0 when the library was built with
 *        runtime stats off — check the return value of @ref
 *        duct_engine_stats, not individual fields, to tell "disabled" apart
 *        from "genuinely zero so far".
 */
typedef struct duct_rt_stats {
    uint64_t wfq_drain,          /**< WFQ work units drained: one per plain message,
                                      one per frame of a batch; all workers. */
             futex_wait,         /**< Times a worker parked on its wake_latch futex, all workers. */
             rx_resume_post,     /**< RX-full latches cleared + reposted. */
             batch_partial_defer, /**< Partial batch defers (batch_defer_idx > 0). */
             defer_oom_drop,     /**< Frames ack+dropped: a defer-node alloc failed. */
             commit_internal,    /**< Commits that hit transient TX backpressure. */
             retry_saved,        /**< Successful emit/frame/timer retry saves. */
             fastpath_armed_skip, /**< x_udp_peer/x_tcp/x_raw/x_raw_packet worker
                                    *  fast-path sends skipped without a syscall,
                                    *  write_armed already set, all workers. An
                                    *  x_udp_shared response is counted by
                                    *  dgram_fast_sent and dgram_lane_staged
                                    *  instead. */
             fastpath_eagain,    /**< ...vs attempted and the socket took less than it
                                   *  was offered, all workers; a write cut to the
                                   *  cap and taken whole counts in tcp_cut_writes
                                   *  alone. */
             dgram_shared_tx_drop, /**< x_udp_shared responses dropped: their listener's
                                        dgram_tx_outbox lane was full, all workers. */
             tx_drain_posts,     /**< TX drain posts that actually posted, all io threads. */
             tx_drain_deduped,   /**< TX drain posts skipped by dedup, all io threads. */
             wfq_push_full,      /**< WFQ push failures (lane full), all io threads. */
             fence_push_full,    /**< Close-fence posts that found their lane full and retried, all io threads. */
             rx_full_latch,      /**< RX-full stalls latched, all io threads. */
             io_loop_pass,       /**< duct_events_run_loop iterations, all io threads. */
             io_busy_spin,       /**< Passes posted with wait-timeout 0 (event-recency spin
                                      budget still unspent), all io threads. */
             io_busy_enter,      /**< Spin-budget window entered, all io threads. */
             io_busy_exit,       /**< Spin-budget window exited, all io threads. */
             dgram_tx_real_kick,      /**< Worker->io dgram_tx_outbox kick messages executed,
                                            all io threads. */
             dgram_tx_real_kick_idle, /**< ...of those, found nothing queued -- the kick
                                            round-tripped through trunk.stack for nothing
                                            because an earlier drain already emptied the
                                            lane, all io threads. */
             dgram_shared_rx_drop,    /**< Classified datagrams for an x_udp_shared conn
                                            dropped: their inter_lane refused the
                                            reservation, or the descriptor size for their
                                            frame count overflowed; all io threads. */
             dgram_rx_slot_route,     /**< Datagrams an inter lane took by
                                            reference to the RX slot they were
                                            read into, all io threads. */
             dgram_rx_slot_copy,      /**< ...vs copied into the lane, no slot
                                            free to hand over. The two together
                                            tell a live zero-copy RX path from
                                            one never engaging. */
             dgram_tx_batch_calls,    /**< Batches sent for x_udp_shared TX, summed across the
                                            worker fast path and the io thread's outbox-lane
                                            drain. */
             dgram_tx_batch_msgs,     /**< Datagrams those batches offered -- submissions, so
                                            an EAGAIN-retried entry recounts; divide by calls
                                            for the average batch. */
             dgram_tx_batch_max,      /**< Most datagrams one batch offered, max across all
                                            workers and io threads. */
             dgram_fast_sent,         /**< Datagrams the worker fast path resolved (kernel
                                            accepted), each counted once, all workers. */
             dgram_lane_staged,       /**< Datagrams the fast path could not send and deferred
                                            into the io outbox lane, all workers. */
             dgram_lane_sent,         /**< Datagrams the io thread resolved from the outbox
                                            lane, each counted once, all io threads -- the
                                            slow path's real output. */
             dgram_tx_gso_writes,     /**< Segmented writes, each one peer's group of equal-sized
                                            datagrams handed to the stack as one send, all
                                            workers and io threads. */
             dgram_tx_gso_dgrams,     /**< Datagrams those writes carried; divide by
                                            dgram_tx_gso_writes for the average group. */
             dgram_rx_gro_reads,      /**< Reads that returned several same-source
                                            datagrams as one coalesced group, all io
                                            threads. */
             dgram_rx_gro_dgrams,     /**< Datagrams those groups held; divide by
                                            dgram_rx_gro_reads for the average
                                            group. */
             vnet_rx_tso_reads,       /**< Reads from tun legs with
                                            IFF_VNET_HDR that cut into two or
                                            more packets, all io threads. */
             vnet_rx_tso_pkts,        /**< Packets those reads cut into; divide
                                            by vnet_rx_tso_reads for the
                                            average. */
             vnet_rx_drop,            /**< Reads from those legs lost whole to
                                            a refused cut, all io threads. */
             vnet_tx_gro_writes,      /**< Segmented writes to those legs,
                                            each merged from two or more
                                            packets, all workers. */
             vnet_tx_gro_pkts,        /**< Packets those writes carried; divide
                                            by vnet_tx_gro_writes for the
                                            average. */
             vnet_tx_drop,            /**< Writes to those legs the fd refused,
                                            each lost whole, all workers. */
             vnet_tx_gro_single,      /**< Writes to those legs of a single
                                            packet a merge was checked for, all
                                            workers. */
             tx_train_flush_full,     /**< x_udp_peer and x_tcp trains sent at
                                            their frame limit, all workers. */
             tx_train_flush_end,      /**< Trains sent with no frame of the
                                            dispatch left to join them, all
                                            workers. */
             tx_train_flush_wait,     /**< Trains sent once their wait budget
                                            ran out, all workers. */
             inter_held,              /**< Inter-lane messages left on their
                                            lane while an answer of their conn
                                            waited parked, all workers. A held
                                            message stays at the lane head and
                                            counts again on each later drain
                                            that finds the hold standing, so
                                            this is holds met, not distinct
                                            messages. The lane then fills
                                            toward its producer, and what a
                                            shared datagram listener discards
                                            is reported as dgram_shared_rx_drop. */
             tcp_writes,              /**< x_tcp writes: worker direct sends and
                                            io drain writes, all workers and io
                                            threads. */
             tcp_eor_writes,          /**< ...of those, under the socket's write
                                            cap, each ending its skb with
                                            MSG_EOR. */
             tcp_cut_writes,          /**< Worker direct sends cut to the write
                                            cap, the rest left to io, all
                                            workers. */
             tcp_lowat_reads,         /**< Pacing-rate reads of sockets following
                                            their lowat, all io threads. */
             tcp_lowat_sets,          /**< Lowat changes those reads applied, all
                                            io threads. */
             tcp_rcvbuf_reads,        /**< Steps of TCP sockets whose receive
                                            buffer follows what their conn
                                            consumes, all io threads. */
             tcp_rcvbuf_sets;         /**< Window or buffer changes those steps
                                            applied, all io threads. */
} duct_rt_stats_t;

/** @brief Member names of @c duct_rt_stats_t, each passed to @p apply in member order.
 *  A table of the engine's counters by name builds from this list; the engine's build
 *  fails when it names a member the struct lacks, names one twice or leaves one out.
 */
#define duct_rt_stats_members(apply)                                                               \
    apply(wfq_drain) apply(futex_wait) apply(rx_resume_post) apply(batch_partial_defer)            \
    apply(defer_oom_drop) apply(commit_internal) apply(retry_saved) apply(fastpath_armed_skip)     \
    apply(fastpath_eagain) apply(dgram_shared_tx_drop) apply(tx_drain_posts)                       \
    apply(tx_drain_deduped) apply(wfq_push_full) apply(fence_push_full) apply(rx_full_latch)       \
    apply(io_loop_pass) apply(io_busy_spin) apply(io_busy_enter) apply(io_busy_exit)               \
    apply(dgram_tx_real_kick) apply(dgram_tx_real_kick_idle) apply(dgram_shared_rx_drop)           \
    apply(dgram_rx_slot_route) apply(dgram_rx_slot_copy) apply(dgram_tx_batch_calls)              \
    apply(dgram_tx_batch_msgs) apply(dgram_tx_batch_max) apply(dgram_fast_sent)                    \
    apply(dgram_lane_staged) apply(dgram_lane_sent) apply(dgram_tx_gso_writes)                     \
    apply(dgram_tx_gso_dgrams) apply(dgram_rx_gro_reads) apply(dgram_rx_gro_dgrams)                \
    apply(vnet_rx_tso_reads) apply(vnet_rx_tso_pkts) apply(vnet_rx_drop) apply(vnet_tx_gro_writes) \
    apply(vnet_tx_gro_pkts) apply(vnet_tx_drop) apply(vnet_tx_gro_single)                          \
    apply(tx_train_flush_full) apply(tx_train_flush_end) apply(tx_train_flush_wait)                \
    apply(inter_held) apply(tcp_writes) apply(tcp_eor_writes)          \
    apply(tcp_cut_writes) apply(tcp_lowat_reads) apply(tcp_lowat_sets) apply(tcp_rcvbuf_reads)     \
    apply(tcp_rcvbuf_sets)

/** @brief Snapshot aggregated runtime counters across all worker and I/O
 *        threads.
 *
 *  @param e    Runtime instance.
 *  @param out  Filled with the current totals; zeroed first.
 *  @retval true   The library was built with runtime stats on; @c out holds
 *                 real counters.
 *  @retval false  Stats are compiled out; @c out is all-zero.
 */
bool duct_engine_stats(duct_engine_t *e, duct_rt_stats_t *out);

/** @brief Print the runtime counters to @p out as log lines, each led by @p tag after its stamp.
 *  The figures are the ones @ref duct_engine_stats sums. The first line is the
 *  conn pool's refusals. A build with counters compiled out adds one line saying
 *  so and stops; any other adds six, led @c fastpath, @c offload,
 *  @c train flush, @c tcp, @c drops and @c backpressure. A null argument prints
 *  nothing. The totals are final once @ref duct_engine_stop has returned.
 */
void duct_engine_stats_print(duct_engine_t *e, FILE *out, const char *tag);

/** @brief Declare a statistics section on a running engine.
 *  The table and its names are copied, and the engine keeps a shard of @c shard_size
 *  bytes, zero at the start and aligned to a cache line, for each I/O thread and each
 *  worker. The section lives until @ref duct_engine_destroy.
 *  Any host thread, returning before @ref duct_engine_destroy starts.
 *  @return the section; nullptr for a null argument, an engine that is not running, an
 *          empty name, no fields or a shard of no bytes, a field with no name, one off an
 *          8-byte boundary or too near the shard's end for a counter, and for want of memory.
 */
duct_stats_t *duct_stats_create(duct_engine_t *e, const duct_stats_cfg_t *cfg);

/** @brief Take the calling thread's shard of the section @p st.
 *  The shard is the struct the table describes, written by this thread alone with
 *  @ref duct_stat_add.
 *  @return the shard; nullptr on a thread that is no I/O thread or worker of the engine,
 *          which is every host thread, the one calling @ref duct_engine_destroy included,
 *          where session-close callbacks run.
 */
duct_nonnull(1) void *duct_stats_shard(duct_stats_t *st);

/** @brief Visit every counter of the engine and of its statistics sections.
 *  The engine's own section, named @c engine, comes first: @c conns_free,
 *  @c conns_refused and @c stats_enabled, which is 1 in a build with runtime stats and
 *  then adds each counter of @ref duct_rt_stats_t under its member name, in the order of
 *  @ref duct_rt_stats_members. The created
 *  sections follow, newest first, each with its fields in table order. A section's
 *  value is the sum over its shards, stopped at @c UINT64_MAX, read with relaxed loads:
 *  no thread waits on another, two counters are not read at one instant, and a counter
 *  only ever added to never falls.
 *  Any thread while the engine stands. Does nothing for a null @p e or @p visit.
 */
void duct_stats_read(duct_engine_t *e, duct_stats_visit_fn visit, void *ctx);

/** @brief Conn slots the runtime can still hand out.
 *
 *  The pool is built once for the process, @c DUCT_RUNTIME_MAX_CONNS slots, and
 *  every leg of every session takes one: an accepted or dialed socket, a shared
 *  datagram peer, a tun, a device. A reading, not a reservation: other threads
 *  take and return slots while it is read, so it says where the pool stands and a
 *  claim made on it can still find the pool empty.
 *  Any thread, always on.
 */
unsigned duct_conns_free(void);

/** @brief Acquires the pool refused for want of a free slot since the process
 *  began.
 *
 *  Each leaves a datagram from a new peer dropped, a socket closed or an inter
 *  attach undone, with no callback to say so; the runtime prints it on stderr as
 *  well, at most once a second. Any thread, always on.
 */
uint64_t duct_conns_refused(void);

#ifdef __cplusplus
}
#endif

#endif /* DUCT_H */
