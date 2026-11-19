/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_relay.h
 *  @brief Cross-module relay — the single L1.5 convergence point.
 *
 *  Declarations whose callers cross a thread boundary: I/O ⟷
 *  worker, I/O ⟷ session, the outbound resolver handoff, and listener-close
 *  sync. In-thread module APIs live in their respective module headers;
 *  no L2 module includes another L2 module's header for relay operations.
 */

#ifndef DUCT_RELAY_H
#define DUCT_RELAY_H

#include "duct_types.h"
#include "duct_exec.h"
#include "duct_msg.h"
#include "duct_protocol.h"
#include "duct_seal_engine.h"
#include "duct_vmq.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct duct_device_ops    duct_device_ops_t;
typedef union duct_conn_handle    duct_conn_handle_t;
typedef union duct_session_handle duct_session_handle_t;
typedef struct duct_conn          duct_conn_t;
typedef struct duct_listener      duct_listener_t;
typedef struct duct_listener_sync duct_listener_sync_t;
typedef struct duct_vmq_mpsc      duct_vmq_mpsc_t;
typedef struct duct_dgram_out     duct_dgram_out_t;
typedef struct duct_x_gso_tally   duct_x_gso_tally_t;
typedef struct duct_x_slot_pool   duct_x_slot_pool_t;
typedef struct duct_stream_ctx    duct_stream_ctx_t;
typedef struct duct_span          duct_span_t;

/** @name Message lists
 *  Each list is called with a macro @c X(name), where @c name completes the type @c duct_msg_NAME.
 *  The sweep lists hold the kinds whose messages give something back when the engine is destroyed
 *  with them still on a stack, one list per stack that sweeps them; the post lists hold the types a
 *  stack accepts.
 *  @{
 */

/** @brief Kinds the io sweep gives back, each also the kind @c msg_kind_NAME. */
#define duct_msg_sweep_io(X)                                              \
    X(attach_device) X(attach_fd) X(open_packet_fd) X(io_connect)         \
    X(pre_parse) X(listener_register) X(listener_close)

/** @brief Kinds the worker sweep gives back, each also the kind @c msg_kind_NAME. */
#define duct_msg_sweep_ctrl(X) X(session_open) X(session_invoke) X(proto_post)

/** @brief Types an io trunk accepts: its sweep kinds, the plain @c attach_inter and the embedded
 *  @c dgram_tx_kick and @c rx_resume.
 */
#define duct_msg_post_io(X) duct_msg_sweep_io(X) X(attach_inter) X(dgram_tx_kick) X(rx_resume)

/** @brief Types a worker ctrl stack accepts: its sweep kinds, @c pre_parse, which the worker returns
 *  to the trunk, and the plain @c conn_join, @c connect_error, @c connect_leg_error and @c timer_start.
 */
#define duct_msg_post_ctrl(X)                                             \
    duct_msg_sweep_ctrl(X) X(pre_parse) X(conn_join) X(connect_error)     \
    X(connect_leg_error) X(timer_start) X(worker_post)
/** @} */

/** @brief Kind of a message on an io trunk or worker ctrl stack, stored in @c duct_msg_t::arg.
 *  Engine teardown sweeps switch on this kind to release resources of unprocessed messages.
 *  @c msg_kind_plain releases only message allocation; @c msg_kind_embedded marks an embedded
 *  message held by the parent structure that teardown sweeps skip; other kinds are generated
 *  from the sweep lists.
 */
typedef enum : uintptr_t {
    msg_kind_plain,
    msg_kind_embedded,
#define duct_msg_kind_enumerator(name) msg_kind_##name,
    duct_msg_sweep_io(duct_msg_kind_enumerator)
    duct_msg_sweep_ctrl(duct_msg_kind_enumerator)
#undef duct_msg_kind_enumerator
} duct_msg_kind_t;

#define duct_msg_kind_one(name) + 1u
/** @brief Number of kinds, the plain and the embedded among them.
 *  A sweep aborts on an arg at or past it.
 */
static constexpr uintptr_t msg_kind_count = 2u duct_msg_sweep_io(duct_msg_kind_one)
                                                duct_msg_sweep_ctrl(duct_msg_kind_one);
#undef duct_msg_kind_one

static_assert(sizeof(duct_msg_kind_t) == sizeof(void *), "duct_msg_kind_t must fit duct_msg_t::arg");
static_assert(msg_kind_plain == 0, "the nullptr arg of duct_msg_new is the plain kind");

/* Each postable type, declared ahead of its definition so that the checks of the post macros see it
 * in every file; the file that makes the message defines it. */
#define duct_msg_forward(name) typedef struct duct_msg_##name duct_msg_##name;
duct_msg_post_io(duct_msg_forward)
duct_msg_post_ctrl(duct_msg_forward)
#undef duct_msg_forward

/** @brief Allocate a heap message of type @c duct_msg_NAME with @c arg set to @c msg_kind_NAME.
 *  The kind follows the type's name, so a message cannot carry another type's kind.
 */
#define duct_msg_new_kind(name, exec, ...) \
    duct_msg_new(duct_msg_##name, exec, msg_kind_##name __VA_OPT__(,) __VA_ARGS__)

/** @brief Initializer of a @c duct_msg_t embedded in a parent structure, with executor @p exec and the
 *  embedded kind.
 *  Teardown sweeps skip messages of this kind; lifetime is managed by the enclosing object.
 */
#define duct_msg_init_embedded(exec) \
    ((duct_msg_t){ .exec_fn = (exec), .arg = (void *)msg_kind_embedded })

/** @brief Association of a @c _Generic that accepts a pointer to @c duct_msg_NAME.
 *  The post macros read their type lists through it.
 */
#define duct_msg_arm(name) duct_msg_##name *: true,

/** @name I/O → worker calls
 *  @{
 */

/** @brief Push @p msg onto worker @p worker_id's ctrl_stack and wake it.
 *  The untyped form behind @ref duct_worker_post_ctrl.
 *
 *  Thread-safe — multiple producers can push concurrently.
 *
 *  @retval true   Posted.
 *  @retval false  @p worker_id is out of range; caller must then release
 *                 @p msg + all resources inside.
 */
duct_nonnull(2) bool
duct_worker_post_ctrl_msg(unsigned worker_id, duct_msg_t *msg);

/** @brief Root of the ctrl message @p m, a pointer to a type of @c duct_msg_post_ctrl.
 *  Any other type stops the build. @p m is evaluated once.
 */
#define duct_msg_ctrl_root(m)                                                            \
    ({                                                                                   \
        static_assert(_Generic((m), duct_msg_post_ctrl(duct_msg_arm) default: false),    \
                      "duct_msg_ctrl_root: not a message type of a ctrl stack");         \
        &(m)->msg;                                                                       \
    })

/** @brief Post the ctrl message @p m to worker @p worker_id.
 *  @p m points at a message type of @c duct_msg_post_ctrl; any other type stops the build.
 *  Answers as @ref duct_worker_post_ctrl_msg, @p m and @p worker_id evaluated once.
 */
#define duct_worker_post_ctrl(worker_id, m) \
    duct_worker_post_ctrl_msg((worker_id), duct_msg_ctrl_root(m))

/** @brief Post a pre-session connect failure. */
duct_nonnull(2) void
duct_worker_post_connect_error(unsigned worker_id, const duct_proto_t *proto,
                               void *user_ctx, duct_result_t err);

/** @brief Post the start of a session-less one-shot timer to worker @p worker_id.
 *  The worker arms @p delay_us and then runs @p proto's @c on_timer with a null
 *  session, @p user_ctx and @p arg. Backs @ref duct_timer_start.
 *  @retval rc_ok             Posted.
 *  @retval rc_no_memory      The message allocation failed.
 *  @retval rc_invalid_order  @p worker_id is out of range.
 */
duct_nonnull(2) duct_result_t
duct_worker_post_timer_start(unsigned worker_id, const duct_proto_t *proto, void *user_ctx,
                             uint64_t delay_us, uintptr_t arg);

/** @brief Post a leg-dial failure on an already-live session —
 *  @c control.open_leg == @c leg_kind_connect.
 *
 *  Resolves @p h on @p worker_id and fires @c cfg->on_error(s, err, ...).
 *  No-op if @p h no longer resolves, e.g. session is closing/closed.
 */
duct_nonnull(2) void
duct_worker_post_connect_leg_error(unsigned worker_id,
                                   const duct_session_handle_t *h,
                                   duct_result_t err);

/** @brief Subscribe I/O thread @p io_id to a wake after its push to
 *  @p worker_id's normal WFQ lane hit lane-full.
 *
 *  The worker's drain pass kicks every armed @p io_id via @ref duct_io_wake
 *  once it frees normal-lane space. Arming also wakes the worker itself.
 */
void duct_worker_wfq_wait_arm(unsigned worker_id, unsigned io_id);

/** @brief Clear @p io_id's wait bit on @p worker_id.
 *
 *  Called once a WFQ-full retry batch for @p worker_id fully drained and no
 *  other node in @p io_id's retry queue still targets it. The worker's kick
 *  clears armed bits in bulk regardless, so a partially-drained retry re-arms.
 */
void duct_worker_wfq_wait_clear(unsigned worker_id, unsigned io_id);

/** @brief Edge-latched wake of @p worker_id's futex-parked main loop.
 *
 *  Idempotent — no-op if already armed and not yet consumed.
 */
void duct_worker_wake_id(unsigned worker_id);

/** @brief Arm @p conn_idx's bit in @p worker_id's @c inter_armed bitmap,
 *  so the worker's next drain cycle fully drains that conn's inter_lane.
 *
 *  Called by whichever producer pushed onto @p conn_idx's inter_lane. The
 *  drain takes the bit only for a conn bound to @p worker_id and drops it
 *  otherwise, @c duct_session_exec_open and @c duct_session_exec_conn_join
 *  re-arming a conn once they bind it.
 *  @note Bit before wake: the caller notifies the lane's bound consumer
 *  via @ref duct_vmq_notify once after this call. @p conn_idx must come
 *  from a live resolved conn, @ref duct_conn_idx_get.
 */
void duct_worker_inter_arm(unsigned worker_id, unsigned conn_idx);

/** @brief Arm @p conn_idx's bit in @p worker_id's drain-completion frontier bitmap. */
void duct_worker_done_arm(unsigned worker_id, unsigned conn_idx);

/** @brief Flush the calling worker's @c x_udp_peer and vnet trains bound for
 *  @p conn.
 *  A close request runs it first, so the close finds those records published
 *  or sent. Conn-lost runs it before confirming retire, where the closed fence
 *  turns the flush into a drop: io reclaims a bound conn only after that
 *  confirm. No-op off a worker thread.
 */
duct_nonnull(1) void duct_worker_conn_train_flush(const duct_conn_handle_t *conn);

/** @brief Address of @p worker_id's wake latch.
 *  A VMQ lane binds @c wake_latch to this address via @ref duct_vmq_bind_wake.
 *  Returns nullptr if @p worker_id is out of range.
 */
uint32_t _Atomic *duct_worker_wake_latch(unsigned worker_id);

/** @name Host-egress lane, worker side
 *  One lane per worker, allocated at pool start only where
 *  @ref duct_host_egress_enabled holds and freed at worker-module cleanup.
 *  The assigned worker is the sole producer; the host module consumes from
 *  the host queue. Nullptr if @p worker_id is out of range, or on an engine
 *  with no bridge.
 *  @{
 */

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

duct_nonnull(1, 3) duct_result_t
duct_host_packet_out_span(const duct_session_handle_t *tok,
                          duct_conn_id_t conn_id, const duct_span_t *span);

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

/** @brief Fire the host's @c on_inter_resume hint through @c run,
 *  once a worker's drain pass moved any inter-conn traffic.
 *
 *  A coarse "retry a deferred push" signal untied to one push or
 *  one conn. No-op when @c run or @c on_inter_resume is not configured.
 */
void duct_host_inter_resume_fire(void);

duct_vmq_mpsc_t *duct_worker_egress_lane(unsigned worker_id);

/** @brief The calling worker's id, or @c conn_worker_none off a worker thread
 *  and on a worker with no lane. */
unsigned duct_worker_egress_self(void);

/** @brief Drop @p worker_id's lane pointer, leaving the allocation.
 *  The deliberate leak @ref duct_host_egress_quiesce falls back on when a
 *  drain it cannot wait out is still scheduled against that memory. */
void duct_worker_egress_abandon(unsigned worker_id);
/** @} */

/** @name Session → worker calls
 *  The session module's entries into the worker's data plane, kept beside the
 *  crossing posts they ride with.
 *  @{
 */

/** @brief Check if the conn has TX room for @p need bytes. */
bool duct_worker_admit_leg(duct_conn_handle_t conn, size_t need);

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

/** @brief Wire-rebind fence node executor.
 *
 *  Decrements @c switch_pending, finishes the switch once every leg
 *  has confirmed. @p self is a byte-copied VMQ payload (@ref
 *  duct_msg_wire_fence is a plain @c duct_msg_decl, not chainable) — it is
 *  never heap-owned and must not be freed here. No-op if the session is
 *  gone or the switch was already abandoned (session close clears
 *  @c switch_next first). Runs ahead of its conn's conn_lost: io posts no
 *  fence for a conn it has quiesced.
 */
duct_exec_rc_t duct_session_exec_wire_fence(void *self);

/** @brief Start the idle bound of @p s from its protocol's @c idle_timeout_ms.
 *  Arms nothing for a protocol without a bound or a session whose timer is
 *  pending. Runs on the session's worker, at session open and when a protocol
 *  switch completes. */
duct_nonnull(1) void duct_worker_idle_arm(duct_session_t *s);

/** @brief Session timer cancellation.
 *
 *  Cancels every timer owned by @p h's session and drops every retry node
 *  its parked timer fires hold, ahead of the session block's return. Called
 *  from last-detach session teardown before @c destroy_state. No-op off the
 *  worker thread.
 */
duct_nonnull(1) void
duct_worker_session_timers_cancel(const duct_session_handle_t *h);

duct_nonnull(1) void duct_worker_session_defer_discard(const duct_session_t *s);

duct_nonnull(1) void duct_worker_reclaim_add(duct_session_t *s);

void duct_worker_reclaim_reset_all(void);

/** @brief Deferred-frame discard for one conn.
 *
 *  Acks @p conn's remaining unprocessed frames (no callback invoked) and
 *  clears its defer mask bit. Called from
 *  @ref duct_session_exec_conn_lost before leg detach, while @p conn's
 *  rx_buf is still valid to ack against.
 */
duct_nonnull(1) void
duct_worker_conn_defer_discard(const duct_conn_handle_t *conn);

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

/** @brief Idempotently force-settle unfinished @c fl_send_done responses on closing @p conn. */
duct_nonnull(1, 3) void
duct_worker_conn_done_close(duct_session_t *s, duct_conn_id_t conn_id, duct_conn_t *conn);

duct_nonnull(1) bool duct_worker_session_tx_parked(const duct_session_t *s);

/** @brief Stream handler cancellation.
 *
 *  Removes the coroutine from its run queue, releases its slot if
 *  stackless or destroys it if stackful, then frees the context.
 */
void duct_stream_cancel(duct_stream_ctx_t *hctx);

/** @brief Response commit: route, TX stage, io wake, control effects.
 *
 *  Called by the worker's on_frame/on_batch path and by the session
 *  ctrl executors, which also run in worker context.
 */
void duct_response_commit(duct_session_t *s, duct_conn_id_t in_conn,
                          duct_stream_id_t in_stream,
                          duct_response_t *out);
/** @} */

/** @} */

/** @name Worker → I/O calls
 *  @{
 */

/** @brief Request conn close.
 *
 *  The I/O thread quiesces the conn on the next wake if the conn's
 *  TX OLB is already empty, or once @ref duct_io_post_tx_drain
 *  empties it — respond-then-close.
 *  @p reason is carried by @c conn_lost fence message for a bound leg.
 *  The calling worker's trains for @p conn go out first: the close counts
 *  published bytes only.
 */
duct_nonnull(1) void
duct_io_post_close_request(const duct_conn_handle_t *conn,
                           duct_close_reason_t reason);

/** @brief Wake I/O thread @p io_id's event loop.
 *  Through @ref duct_events_kick.
 *
 *  The woken I/O thread runs @ref duct_io_on_wake — lane-message dispatch,
 *  frame-rx retry drain.
 */
void duct_io_wake(unsigned io_id);

/** @brief Post TX OLB drain for @p conn.
 *
 *  The assigned I/O thread runs one TX drive @ref duct_events_drive_tx —
 *  send until TX OLB empties or the socket reports would-block.
 *
 *  @note Coalesced via @c fl_req_tx_drain. Posts for any conn — the xport is
 *  read on the far side, where @c s_req_do_tx_drain returns without work for
 *  @c x_inter: a host-driven leg's egress goes to the host, a device leg's
 *  into device memory on the worker that commits.
 */
duct_nonnull(1) void duct_io_post_tx_drain(const duct_conn_handle_t *conn);

/** @brief Report whether the I/O thread assigned to @p conn is parked.
 *  A relaxed read of the flag @ref duct_io_work_pending sets ahead of a wait
 *  that can block, cleared at that thread's next pass: a hint for choosing
 *  between a direct send and a handoff, which the thread stays free to
 *  outdate at once. False when no I/O thread is assigned.
 */
duct_nonnull(1) bool duct_io_parked(const duct_conn_t *conn);

/** @brief Read @p conn's path MTU off its socket, on the calling worker.
 *  @c conn->fd stays open for the call: a bound conn is reclaimed, and its fd
 *  closed, only once its worker confirms retire, which it cannot do while it
 *  sits inside the dispatch making this call.
 *  @return false for a conn already closing or a socket the kernel names no
 *          path for, @p out untouched.
 */
duct_nonnull(1, 2) bool duct_io_path_mtu(const duct_conn_t *conn, uint16_t *out);

/** @brief Read the local and remote addresses of @p conn's socket, on the
 *  calling worker.
 *  @c conn->fd stays open for the call on the footing @ref duct_io_path_mtu
 *  states. A shared datagram leg reads its listener's socket, open until the
 *  leg's reclaim drops its listener ref, and the peer its worker last migrated
 *  it to. A null output skips that side.
 *  @return @c rc_invalid_order for a conn already closing or a socket the
 *          kernel names no address for, the outputs untouched.
 */
duct_nonnull(1) duct_result_t duct_io_addrs(const duct_conn_t *conn, duct_peer_t *local,
                                            duct_peer_t *remote);

/** @brief Read the congestion control @p conn's socket runs, on the calling
 *  worker.
 *  @c conn->fd stays open for the call on the footing @ref duct_io_path_mtu
 *  states.
 *  @return @c rc_invalid_order for a conn already closing, @c rc_not_supported
 *          on a build that reads no name, @p out untouched in both.
 */
duct_nonnull(1, 2) duct_result_t duct_io_tcp_congestion(const duct_conn_t *conn,
                                                        char out[duct_tcp_cc_name_max]);

/** @brief Read the congestion figures of @p conn's socket, on the calling worker.
 *  @c conn->fd stays open for the call on the footing @ref duct_io_path_mtu
 *  states. A platform that counts timeouts itself keeps that count in
 *  per-socket state written here, so one worker, the session's, makes every
 *  call for a conn.
 *  @return @c rc_invalid_order for a conn already closing, @c rc_not_supported
 *          for a stack that reports no figures, @p out untouched in both.
 */
duct_nonnull(1, 2) duct_result_t duct_io_tcp_stats(const duct_conn_t *conn,
                                                   duct_tcp_stats_t *out);

/** @brief Read the bytes @p conn's socket holds unsent, on the calling worker.
 *  @c conn->fd stays open for the call on the footing @ref duct_io_path_mtu
 *  states.
 *  @return the figure, or @c duct_tx_unsent_unread for a conn already closing
 *          and wherever the platform has none to read.
 */
duct_nonnull(1) uint64_t duct_io_tx_unsent(const duct_conn_t *conn);

/** @brief Set the acknowledgment bound of @p conn's socket, on the calling
 *  worker.
 *  @c conn->fd stays open for the call on the footing @ref duct_io_path_mtu
 *  states.
 *  @return @c rc_ok once set, @c rc_invalid_order for a conn already closing,
 *          @c rc_not_supported for a stack refusing @p ms.
 */
duct_nonnull(1) duct_result_t duct_io_tcp_ack_timeout(const duct_conn_t *conn, uint32_t ms);

/** @brief Wake @p listener's I/O thread to drain its @c dgram_tx_outbox.
 *  The @c x_udp_shared counterpart of @ref duct_io_post_tx_drain.
 *
 *  Edge-latched — no-op if another post is already pending.
 *
 *  @note Fire-and-forget — no confirmation rc; @p listener must be kept
 *  alive across this call by the caller's @c pre_conn_refs contribution.
 */
duct_nonnull(1) void duct_io_post_dgram_tx(duct_listener_t *listener);

/** @brief One-time init of @p listener's embedded @c dgram_tx_kick —
 *  binds its @c exec_fn, the embedded kind and its back-pointer. Called once at registration,
 *  before the listener is reachable from any worker; the executor it binds
 *  stays private to the io module, same ownership split as @c dgram_tx_outbox.
 */
duct_nonnull(1) void duct_io_dgram_tx_kick_init(duct_listener_t *listener);

/** @brief Drop one hold on RX slot @p idx of @p pool, a claim's with @p claim, else the lane's.
 *  Callable from any thread. The drop that leaves no holder returns the slot to the pool, and a
 *  pool stalled on the slot it lacked gets its stall taken back and its reader io thread the resume.
 */
duct_nonnull(1) void duct_io_rx_slot_drop(duct_x_slot_pool_t *pool, uint32_t idx, bool claim);

/** @brief The request-exec function a conn pool slot binds to.
 *  The I/O request executor bound across each slot's embedded @c req_msg
 *  in @c duct_conn_pool_ctor.
 */
duct_exec_fn duct_io_conn_req_exec_fn(void);

/** @brief Rebind @p conn's wire for a wire-changing @c duct_proto_switch.
 *
 *  Arms @c conn->wire_rebind_next + the coalesced @c fl_req_wire_rebind
 *  bit. The assigned I/O thread swaps @c conn->wire / @c wire_parser to
 *  @p next's and posts a completion fence onto the conn's WFQ lane.
 *
 *  @note Swap timing depends on the unparsed RX leftover: a complete
 *  old-wire header means a real in-flight frame — parse it first, swap after;
 *  anything shorter is considered "dead bytes" — discard them and swap now.
 */
duct_nonnull(1) void
duct_io_post_wire_rebind(const duct_conn_handle_t *conn,
                         const duct_proto_t *next);

/** @brief Post @p conn's device holds and @c ops->release to its owning io
 *  thread, one unit of @c conn->refs borrowed for the posted finish.
 *  The conn-lost consume calls this past its lane drain: a host callback
 *  keeps its io thread contract, and the borrow keeps the slot resolvable
 *  until the finish drops it.
 */
duct_nonnull(1) void duct_io_conn_device_release_post(duct_conn_t *conn);

/** @brief Post RX resume for @p conn.
 *
 *  Restarts reading after RX-full or suspend backpressure. The assigned I/O
 *  thread disarms the rx header's value latch and runs
 *  @ref duct_events_drive_rx. Coalesced via @c fl_req_rx_resume.
 */
duct_nonnull(1) void duct_io_post_rx_read(const duct_conn_handle_t *conn);

/** @brief Post listener registration to @p listener->io_id.
 *  On successful post, lifecycle of @p listener passes to the target I/O thread.
 *  @c sync->ok is the result, signaled via @c sync->done.
 *  A successful post increments the reference count on @p sync with @c duct_share.
 *
 *  @return false on error — caller retains @p listener and sole hold on @p sync.
 */
duct_nonnull(1, 2) bool
duct_io_post_listener_register(duct_listener_t *listener, duct_listener_sync_t *sync);

/** @brief Post a listener revocation by socket to @p io_id.
 *  @c sync->ok reports whether a matching node was found, signaled via
 *  @c sync->done. A successful post increments the reference count on @p sync
 *  with @c duct_share.
 *
 *  @return false on error — caller retains sole hold on @p sync.
 */
duct_nonnull(3) bool
duct_io_post_listener_close(unsigned io_id, duct_sock_t fd, duct_listener_sync_t *sync);

/** @brief Send @p n already wire-packed @c x_udp_shared datagrams to
 *  @p listener's socket in as few syscalls as the platform allows.
 *
 *  Each @ref duct_dgram_out_t carries its destination and its bytes as a
 *  header span and a payload span, which reach the wire as one datagram
 *  without the payload being copied to join them. Every platform-specific
 *  batch type stays behind that descriptor.
 *
 *  Queues nothing itself, and is callable from any worker thread on the same
 *  cross-thread safety terms described by @ref duct_io_udp_peer_send_staged.
 *
 *  @param tally gains each segmented write this call makes and the datagrams
 *         it carried.
 *  @return How many of the first @p n the caller may move past: the stack took
 *  them, or no send will ever carry them. The rest are the caller's to park or
 *  retry.
 */
duct_nonnull(1, 2, 4) uint32_t
duct_io_dgram_shared_send_batch(duct_listener_t *listener,
                                const duct_dgram_out_t *msgs, uint32_t n,
                                duct_x_gso_tally_t *tally);

/** @brief Send the records staged but unpublished on an @c x_udp_peer conn's
 *  TX ring, from the calling worker thread.
 *  The span runs from the published tail to the staging cursor. A run of
 *  equal-length records leaves as one segmented write where the stack cuts
 *  datagrams, a lone record through a plain send. Callable only while io has
 *  no published byte of that ring left to drain. The TX header's
 *  @c write_armed is io's, read relaxed, and @c conn->fd stays open until
 *  @ref duct_conn_teardown_worker, which for a bound conn runs at its
 *  worker's conn_lost consume.
 *  @param out_sent bytes of whole records taken, or refused as too large for
 *         the path, the prefix the caller settles with
 *         @ref duct_olb_tx_advance_worker.
 *  @param tally gains each segmented write and the datagrams it carried.
 *  Counts send declines and refusals in internal statistics.
 *  @return @c rc_ok with every record gone; @c rc_again once the socket
 *          fills or io holds it write-armed; @c rc_fatal on a failed send.
 */
duct_nonnull(1, 2, 3) duct_result_t
duct_io_udp_peer_send_staged(duct_conn_t *conn, size_t *out_sent,
                             duct_x_gso_tally_t *tally);

/** @brief Attempt one immediate direct send of @p n spans on an @c x_tcp,
 *  @c x_raw, or @c x_raw_packet conn socket.
 *
 *  Bypasses the conn's TX OLB and the worker→io drain-post whenever every
 *  byte lands in one call. A caller owes its conn's TX OLB proven idle
 *  beforehand, nothing else queued ahead of these spans in program order, and
 *  on a stream, whose write can fall short, the unsent tail staged there itself
 *  on a @c false return. An @c x_tcp socket under a write cap takes at most the
 *  cap, under the flags the cap names, and a request past it answers @c false.
 *  It counts its misses in @c fastpath_armed_skip and @c fastpath_eagain
 *  itself. Same cross-thread safety as @ref duct_io_udp_peer_send_staged.
 *
 *  @param out_written  Bytes that actually went, summed across the spans.
 *          Zero for would-block, for a socket the io thread already knows is
 *          write-blocked, and for a real send failure alike.
 *  @return true once every byte of every span reached the kernel, which
 *          finishes the caller's commit. false on a short write or on any of
 *          the three zero cases above; the next drive_tx pass on the I/O thread
 *          resolves genuine failures through the standard close path.
 */
duct_nonnull(1, 2, 4) bool
duct_io_stream_send_fast(duct_conn_t *conn, const duct_view_u8 *bufs,
                         unsigned n, size_t *out_written);

/** @brief Ask @p conn's io thread to move its connected datagram socket to the
 *  candidate address recorded for it.
 *
 *  Posted for a conn raising @ref fl_conn_roaming, once the worker has stored
 *  the accepted frame's ack total into the RX ring's @c accept_at. io moves the
 *  socket only while @c accept_at reaches @c roam_at, the total at the end of
 *  the proposing datagram; short of it the post resolves to nothing, the flag
 *  stays raised and the next accepted frame posts again.
 */
duct_nonnull(1) void duct_io_post_peer_roam(const duct_conn_handle_t *conn);

/** @brief @p listener's @c dgram_tx_outbox, opaque to every caller outside
 *  the io module.
 *
 *  Callers resolve the worker lane via @ref duct_mpsc_lane; this accessor
 *  keeps listener layout private to the I/O module.
 */
duct_nonnull(1) duct_vmq_mpsc_t *
duct_io_dgram_shared_outbox(duct_listener_t *listener);

/** @brief Resolve @p listener's RX slot pool, the one its socket reads into.
 *  Keeps the listener's layout private to the io module. */
duct_nonnull(1) duct_x_slot_pool_t *
duct_io_dgram_shared_rx_slots(duct_listener_t *listener);

/** @brief Test whether @p listener stages its datagram sends through its outbox lane.
 *  True when the listener has TX slot pools: iocp builds them for every listener with an outbox,
 *  wsaevent only once RIO is active. A worker then fills a slot of @ref duct_io_dgram_shared_tx_slots
 *  and publishes a lane entry that carries its reference, and the io thread's drain posts the send.
 *  False indicates the worker uses the direct batch send path.
 */
duct_nonnull(1) bool
duct_io_dgram_shared_needs_lane_tx(duct_listener_t *listener);

/** @brief Resolve @p listener's TX slot pools, the pair a worker stages its sends into.
 *  Index 0 is the small class and index 1 the large one, @c duct_x_slot_take choosing by size. Keeps
 *  the listener's layout private to the io module.
 *  @return The pair, @c nullptr for a listener without TX slot pools.
 */
duct_nonnull(1) duct_x_slot_pool_t *
duct_io_dgram_shared_tx_slots(duct_listener_t *listener);

/** @brief Test whether @p listener's socket is registered for RIO sends.
 *  True once its io backend armed the RIO send state: the socket then serves RIO
 *  calls alone, a worker's direct grouped send on it would report the bytes taken
 *  and lose them, and every entry stages into the lane for the io thread's
 *  registered-slot send instead.
 */
duct_nonnull(1) bool
duct_io_dgram_shared_rio_tx(duct_listener_t *listener);

/** @} */

/** @name Outbound connect entry point and calls
 *  @{
 */

/** @brief Terminal action taken by a resolved dial. */
typedef enum : uint8_t {
    intent_session, /**< Opens a brand-new session. */
    intent_leg      /**< Attaches onto an already-live session's @c conn_id slot. */
} duct_conn_intent_kind_t;

/** @brief Outbound-dial intent carried across the async connecting window.
 *
 *  Describes which terminal action a resolved dial takes and its payload.
 *  Held directly on the @c duct_pre_conn_t while fd is in flight; read by
 *  the io thread's connect-finish tail on resolution. A session intent still
 *  unresolved when the engine is destroyed reaches its protocol's @c on_error
 *  with @c rc_closed, a leg intent nothing: its session closes with the engine.
 */
typedef struct {
    duct_conn_intent_kind_t kind;
    const duct_proto_t     *proto;    /**< Wire bound on success; error-routing
                                        *  proto for a session dial. */
    duct_xport_t             xport;   /**< Dial target kind: x_tcp, x_udp_peer
                                        *  or x_local. */
    uint32_t                 egress_if; /**< Index of the interface the dial's
                                        *  socket is bound to before it
                                        *  connects, 0 for none. */
    uint32_t                 worker;
    duct_seal_prefix_t       tx_prefix; /**< Leading bytes of the opened conn's first
                                        *  send: a session dial's @c duct_io_connect_via
                                        *  prefix, a leg's @c open_leg.tx_prefix. The
                                        *  conn's codec takes them as it is built. */
    union {
        void               *user_ctx;  /**< @c on_session_open ctx, doubles as
                                        *  pre-session @c on_error identity. */
        struct {
            duct_handle_t   hsession;  /**< leg: target live session. */
            duct_conn_id_t  conn_id;   /**< leg: target slot in that session. */
            char            tcp_congestion[duct_tcp_cc_name_max]; /**< leg: the dial's
                                        *  @c open_leg.tcp_congestion, NUL-terminated;
                                        *  empty takes the protocol's. */
        } leg;
    };
} duct_conn_intent_t;

/** @brief Create @p seed's dial socket on the caller's thread, prepare it through the launch
 *  policy, and post its connect toward the IP @p peer on I/O thread @p io_id.
 *  Callable from any thread, the resolver's completion thread included; @p seed
 *  is copied.
 *  @return false for an @p io_id out of range or a failed allocation, the socket
 *  closed; a refused preparation posts the dial failure. */
duct_nonnull(2, 3) bool
duct_io_post_connect(unsigned io_id, const duct_peer_t *peer, const duct_conn_intent_t *seed,
                     uint32_t connect_timeout_ms);

/** @brief Create @p seed's x_local socket on the caller's thread and post its connect toward
 *  the socket file @p path on I/O thread @p io_id.
 *  Callable from any thread; @p seed and @p path are copied. @p seed names
 *  @c x_local and @p path fits @c sun_path, which @c duct_local_path_fits has
 *  answered for it.
 *  @return false for an @p io_id out of range or a failed allocation, the socket
 *  closed. */
duct_nonnull(2, 3) bool
duct_io_post_connect_local(unsigned io_id, const char *path, const duct_conn_intent_t *seed,
                           uint32_t connect_timeout_ms);

/** @brief Deliver @p seed's connect failure @p err through I/O thread @p io_id.
 *  That thread forwards it to the session an @c intent_leg seed names, else to
 *  @ref duct_worker_post_connect_error.
 *  @return false for an @p io_id out of range or a failed allocation. */
duct_nonnull(2) bool
duct_io_post_connect_failed(unsigned io_id, const duct_conn_intent_t *seed, duct_result_t err);

/** @brief Start the outbound dial @p seed describes toward @p addr.
 *
 *  A literal IPv4/IPv6 address posts through @ref duct_io_post_connect at once,
 *  and the socket path of an @c x_local dial through
 *  @ref duct_io_post_connect_local; a hostname goes to @ref duct_resolve_start,
 *  which posts on completion. Nothing reads @p addr or @p seed past the return.
 *
 *  @retval rc_ok             The dial is posted, or its resolve is in flight.
 *  @retval rc_invalid_arg    Unparseable @p addr, a @c seed->xport other than
 *                            @c x_tcp, @c x_udp_peer and @c x_local, a wire
 *                            framing the xport does not fit, or an @c x_local
 *                            @c egress_if or path that does not fit @c sun_path.
 *  @retval rc_not_supported  An @c x_local dial below @c duct_x_local_floor.
 *  @retval rc_fatal          A literal's or a path's post failed.
 *
 *  Any other code is @ref duct_resolve_start's.
 */
duct_nonnull(2, 3) duct_result_t
duct_connect_start(unsigned io_id, const char *addr, const duct_conn_intent_t *seed,
                   uint32_t connect_timeout_ms);

/** @brief Hand a non-literal hostname to the platform resolver.
 *
 *  Calls overlapped @c GetAddrInfoExW on Windows; spawns a detached
 *  thread calling @c getaddrinfo on other OSes.
 *
 *  @note @p host and @p seed are valid only for the duration of the call —
 *  the resolver copies what it needs. @p host must already be pure ASCII,
 *  guaranteed by @c duct_connect_parse_addr; not re-validated here.
 *
 *  @retval rc_ok         The resolve is in flight.
 *  @retval rc_no_memory  Allocation failure.
 *  @retval rc_dns_fail   Resolver failure.
 */
duct_nonnull(2, 5) duct_result_t
duct_resolve_start(unsigned io_id, const char *host, uint16_t port,
                   uint32_t connect_timeout_ms,
                   const duct_conn_intent_t *seed);

/** @brief Cancel all in-flight DNS resolves and wait for the completions they
 *  are delivering.
 *
 *  Called at engine teardown while I/O and worker threads are still alive, so on
 *  Windows a cancelled resolve's @c rc_dns_fail delivers through the ordinary
 *  error path. On Linux, the call closes the post gate and waits for active
 *  resolver threads; completions returning later drop their results.
 */
void duct_resolve_cancel_all(void);

/** @brief Attach a push-mode inter conn on @p io_id's thread.
 *  The io half of @ref duct_conn_attach_inter.
 *
 *  I/O thread acquires a bare pool slot and creates the conn's
 *  @c inter_lane, binds its wake to the session worker's latch,
 *  then joins it to the session @p h at @p conn_id through the same
 *  @ref duct_session_exec_conn_join path as other legs. No wire is bound
 *  at this stage.
 *
 *  @return false if @p io_id is out of range or allocation failed; nothing
 *  is committed — @p conn_id's slot stays empty, the attach may be retried.
 */
duct_nonnull(2) bool
duct_io_post_attach_inter(unsigned io_id, const duct_session_handle_t *h,
                          duct_conn_id_t conn_id, const duct_proto_t *proto);

/** @brief Attach file descriptor on @p io_id's thread.
 *  The io half of @ref duct_conn_attach_fd.
 *
 *  I/O thread registers @p fd with the events backend as @p xport, binds
 *  @p leg_wire — or @p proto->wire when it is null — then joins it to
 *  the session @p h at @p conn_id through
 *  the same @ref duct_session_exec_conn_join path as other legs. @p xport is
 *  @c x_raw for a byte stream and @c x_raw_packet for a packet-delimited
 *  descriptor, which decides whether the rings carry a record header.
 *
 *  @return false if @p io_id is out of range or allocation failed.
 *  Descriptor ownership transfers unconditionally: closed on failure,
 *  managed by conn on success.
 */
duct_nonnull(2) bool
duct_io_post_attach_fd(unsigned io_id, const duct_session_handle_t *h,
                       duct_conn_id_t conn_id, duct_sock_t fd,
                       duct_xport_t xport, const duct_proto_t *proto,
                       const duct_wire_t *leg_wire);

/** @brief Open session over packet socket descriptor on @p io_id's thread.
 *  The io half of @ref duct_io_attach_packet_fd.
 *
 *  I/O thread registers @p fd as an @c x_raw_packet conn bound to @p proto->wire
 *  and posts the session open to a worker. A conn it cannot set up reaches
 *  @p proto's @c on_error with @c rc_no_memory, a null session and @p user_ctx.
 *
 *  @return false if the message allocation failed. Descriptor ownership
 *  transfers unconditionally: closed on failure, managed by conn on success.
 */
duct_nonnull(3) bool
duct_io_post_open_packet_fd(unsigned io_id, duct_sock_t fd, duct_proto_t *proto, void *user_ctx);

/** @brief Attach device callbacks on @p io_id's I/O thread.
 *  @c ops is copied into the message; device context lifetime moves to the I/O
 *  side, and any failure from here on releases it via @c ops->destroy.
 *  The wait handle itself is borrowed and never closed.
 */
duct_nonnull(2, 4) bool
duct_io_post_attach_device(unsigned io_id, const duct_session_handle_t *h,
                           duct_conn_id_t conn_id,
                           const duct_device_ops_t *ops,
                           const duct_proto_t *proto);
/** @} */
#ifdef __cplusplus
}
#endif

#endif /* DUCT_RELAY_H */
