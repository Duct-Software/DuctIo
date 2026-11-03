/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_events.h
 *  @brief Event-notification downcall/upcall contract, shared by every
 *  @c DUCT_EVENTS_MODEL flavor. The engine calls the downcalls and defines
 *  the upcalls; each flavor's backend does the reverse.
 */

#ifndef DUCT_EVENTS_H
#define DUCT_EVENTS_H

#include "duct_core.h"
#include "duct_ticks.h"
#include "duct_types.h"
#include "duct_time.h"
#include "duct_x_slot.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Event tag kind. */
typedef enum : uint8_t {
    io_tag_wake,      /**< Cross-thread wake slot;
                        * @c tag unused. */
    io_tag_listener,  /**< Listener;
                        * @c tag is a @c duct_listener_t *. */
    io_tag_pre_conn,  /**< Still-dialing or probe-waiting;
                        * @c tag is a @c duct_pre_conn_t *. */
    io_tag_conn,      /**< Conn;
                        * @c tag is an opaque conn handle. */
    io_tag_rio_cq     /**< RIO completion-queue notify slot, wsaevent only;
                        * @c tag unused. */
} duct_io_tag_t;

/** @brief Decoded readiness bits, and the interest bitmask.
 *
 *  Delivered with @ref duct_io_on_event; @ref duct_events_watch takes the
 *  same bits as interest.
 */
typedef enum : uint8_t {
    io_ev_read     = 1u << 0,  /**< Read ready. */
    io_ev_write    = 1u << 1,  /**< Write ready. */
    io_ev_error    = 1u << 2,  /**< Error. */
    io_ev_hup      = 1u << 3,  /**< Hang up. */
} duct_io_ev_flags_t;

/** @brief Decoded I/O event. */
typedef struct {
    duct_io_tag_t kind; /**< Tag kind. */
    void         *ptr;  /**< Opaque payload. */
    duct_io_ev_flags_t flags; /**< Readiness. */
} duct_io_event_t;

typedef struct duct_olb_hdr duct_olb_hdr_t;

/** @brief Bytes a record-framed RX read leaves free past its span for the
 *  backend's per-read state.
 *  iocp lays an overlapped @c WSARecvMsg's message and control area there, and
 *  the read owns those bytes until its completion; the readiness models need
 *  none. */
#if DUCT_EVENTS_MODEL_IOCP
static constexpr size_t duct_events_rx_scratch = 128u;
#else
static constexpr size_t duct_events_rx_scratch = 0u;
#endif

/** @brief Ephemeral transfer context for a single RX / TX drive.
 *  Filled by @ref duct_io_rx_reserve and @ref duct_io_tx_peek.
 */
typedef struct {
    duct_sock_t fd;     /**< Conn socket. */
    duct_xport_t xport_type; /**< Transport type. */
    uint16_t units;     /**< Read units of one batched datagram read, 1 for a
                          *  single read. Past 1, @c buf and @c size are the
                          *  first unit's span, and each further span starts one
                          *  record header past the previous one's end. */
    uint8_t *buf;       /**< Buffer. */
    size_t  size;       /**< Buffer size. */
    void   *ctx,        /**< Read argument for @c duct_xread, keyed by @c xport_type.
                          *  A vnet leg's reserve sets its header span; every other
                          *  transfer holds nullptr. */
           *io_priv;    /**< Owning conn's backend registration cache. */
    duct_olb_hdr_t *olb_hdr; /**< RX/TX OLB header for duct_olb_io_begin/_done. */
} duct_io_xfer_t;

typedef struct duct_listener duct_listener_t;
typedef struct duct_pre_conn duct_pre_conn_t;

/** @brief Opaque per-I/O-thread events environment. */
typedef struct duct_events_env duct_events_env_t;

/** @brief Allocate and setup this I/O thread's events environment.
 *  @return nullptr on any step failure.
 */
[[nodiscard]] duct_events_env_t *duct_events_init(void);

/** @brief Release and free @p env resources. */
duct_nonnull(1) void duct_events_fini(duct_events_env_t *env);

/** @brief Register @p fd for events.
 *
 *  @p tag is dispatched internally by @p kind.
 *  @return false on failure.
 */
[[nodiscard]] duct_nonnull(1, 4) bool
duct_events_watch(duct_events_env_t *env, duct_sock_t fd,
                  duct_io_tag_t kind, void *tag,
                  duct_xport_t xport_type);

/** @brief Elevate an already-watched, still-dialing @p fd from
 *  pre_conn to conn tag once the dial resolves.
 *
 *  @return false on failure.
 */
[[nodiscard]] duct_nonnull(1, 3) bool
duct_events_promote(duct_events_env_t *env, duct_sock_t fd, void *tag);

/** @brief Stop watching @p fd. @p rx_io_priv is owned by conn's RX OLB. */
duct_nonnull(1) void
duct_events_unwatch(duct_events_env_t *env, duct_sock_t fd, void *rx_io_priv);

/** @brief Watch @p device for readiness.
 *  The one entry the portable side calls, so what a device *is* stays here:
 *  a waitable handle on the Windows models, an ordinary descriptor under
 *  epoll and under poll off Windows. @p device is @c
 *  duct_device_ops_t::wait_handle verbatim, reinterpreted by whichever model
 *  takes it, and readiness arrives as @ref duct_io_on_device carrying
 *  @p tag_ptr.
 *
 *  @return @c false on a device this env already watches, when the model's
 *          own resource runs out — a full wait set on wsaevent, a wait
 *          completion packet iocp cannot get from ntdll, create or bind — and
 *          on poll under Windows, which has no way to wait a handle at all.
 */
[[nodiscard]] duct_nonnull(1, 2) bool
duct_events_watch_device(duct_events_env_t *env, void *device, void *tag_ptr);

/** @brief Stop watching @p device.
 *  It stays open either way: the device owns it, no model closes it.
 *  Tolerates a device that was never watched.
 */
duct_nonnull(1, 2) void
duct_events_unwatch_device(duct_events_env_t *env, void *device);

/** @brief Set whether @p device's readiness still reaches this loop.
 *  Real only where readiness repeats until something consumes it, which among
 *  the four models is poll alone — epoll takes a device edge-triggered, and
 *  both Windows models wait an auto-reset handle, so a signal already
 *  delivered never comes back on its own. Clearing it keeps a device the io
 *  thread holds unread with @c fl_conn_rx_full latched from returning poll()
 *  every turn. The same io thread sets it again ahead of its next read:
 *  a device lacks a drive tail to re-arm from.
 */
duct_nonnull(1, 2) void
duct_events_device_rx_interest(duct_events_env_t *env, void *device, bool want);

/** @brief Cancel every outstanding op on @p fd without closing it — the
 *  caller decides @p fd's fate relying on the return value.
 *
 *  @retval true   No expected arrivals for @p fd, safe to resolve.
 *  @retval false  The cancelled op still owes at least one completion.
 */
[[nodiscard]] duct_nonnull(1) bool
duct_events_cancel_io(duct_events_env_t *env, duct_sock_t fd);

/** @brief Cross-thread wake for a parked event loop.
 *  Signals @p env's wake slot; @see duct_events_run_loop for the park side. */
duct_nonnull(1) void duct_events_kick(duct_events_env_t *env);

/** @brief Run this thread's event loop until @p shutdown is set. */
duct_nonnull(1, 2) void
duct_events_run_loop(duct_events_env_t *env, bool _Atomic *shutdown);

/** @brief Drive @p tag's conn RX forward — read everything to would-block
 *  or post an async read.
 */
duct_nonnull(1) void duct_events_drive_rx(void *tag);

/** @brief Sit @p fd out of further RX drives.
 *
 *  Clears the per-fd read-interest bit so @ref duct_events_drive_rx skips
 *  it, until the caller posts @c fl_req_rx_resume.
 *
 *  @note For level-triggered polling only.
 *  @note Synchronized with @c fl_conn_rx_full / @c fl_conn_suspended —
 *  whoever clears either one also posts @c fl_req_rx_resume,
 *  @ref duct_io_post_rx_read, which kicks this thread's poll and restores
 *  read interest on this conn.
 */
void duct_events_rx_stall(duct_sock_t fd, void *rx_io_priv);

/** @brief Drive @p tag's conn TX forward — send everything until
 *  would-block or post an async send.
 */
duct_nonnull(1) void duct_events_drive_tx(void *tag);

/** @brief Arm or disarm write interest on @p listener's dgram TX socket.
 *  Called on a genuine armed/disarmed transition alone: a level-triggered
 *  backend left armed spins @c epoll_wait/@c poll on an always-writable UDP
 *  socket whatever is queued. epoll and poll keep the read interest
 *  @c rx_parked leaves.
 *
 *  @note No-op on wsaevent, whose write readiness is already edge-triggered,
 *  and on iocp, which drives dgram TX through @ref duct_events_dgram_tx_kick.
 */
duct_nonnull(1, 2) void
duct_events_dgram_tx_interest(duct_events_env_t *env, duct_listener_t *listener, bool armed);

/** @brief Set whether @p listener's socket stays on this loop's read readiness.
 *  A datagram listener leaves it while its RX slot pool is dry, the datagrams waiting
 *  in the socket's kernel queue; a path listener leaves it for the pause of its accept
 *  pace, and a stream listener while parked for want of a descriptor, the clients
 *  waiting in the socket's accept queue. epoll rebuilds the whole mask, taking write
 *  interest from @c dgram_tx_write_armed; poll sets or clears @c POLLIN; kqueue adds or
 *  deletes @c EVFILT_READ; wsaevent toggles @c FD_READ, or @c FD_ACCEPT for a stream
 *  listener, whose return sets its event as well.
 *
 *  @note On iocp a stream listener's read interest is its outstanding @c AcceptEx:
 *  @p want true posts the one an idle listener lacks, parking the listener again when no
 *  accept socket can be made, and false does nothing, the pause being the re-post its
 *  completion leaves out. A datagram listener's reads complete into its own buffers and
 *  never reach @ref duct_io_dgram_rx_drain, so the call does nothing there.
 */
duct_nonnull(1, 2) void
duct_events_listener_rx_interest(duct_events_env_t *env, duct_listener_t *listener, bool want);

/** @brief Build @p listener's TX slot pools and the send state that posts from them, if this backend needs them.
 *  iocp builds the pools for every listener with an outbox, and without RIO the overlapped send state
 *  too, stored at @c listener->dgram_tx_pool; wsaevent builds the pools once RIO is loaded. A no-op,
 *  always true, on the readiness-driven backends and for a listener with no outbox. Called once, when
 *  the listener is made.
 *
 *  @return false only on genuine allocation failure.
 */
duct_nonnull(1) bool
duct_events_dgram_tx_pool_alloc(duct_listener_t *listener);

/** @brief Release @p listener's TX slot pools and send state.
 *  A send still in flight keeps both until it settles. No-op wherever
 *  @ref duct_events_dgram_tx_pool_alloc was a no-op.
 */
duct_nonnull(1) void
duct_events_dgram_tx_pool_free(duct_listener_t *listener);

/** @brief Post the queued sends of @p listener's @c dgram_tx_outbox from their TX slots, on a backend whose TX is
 *  completion-based (iocp, and wsaevent with RIO).
 *  A lane entry names the slot a worker filled. The send is posted from that slot, the peer address written ahead
 *  of the payload, and the entry is committed without waiting for the send: the slot goes back to its pool when
 *  the send completes. A call posts while a send descriptor is free; the rest of the lane waits for the drain a
 *  completion runs.
 *
 *  @return true if this backend owns dgram TX for @p listener and handled the kick —
 *  the caller must not also run portable drain/reconcile.
 *  @c false on epoll/poll/kqueue and on wsaevent without RIO, meaning
 *  "not mine, use the portable fallback."
 */
duct_nonnull(1, 2) bool
duct_events_dgram_tx_kick(duct_events_env_t *env, duct_listener_t *listener);

/** @brief Hooks that make a grown chunk of a slot pool usable by this backend's I/O.
 *  With RIO loaded (iocp, wsaevent), the hooks register each chunk as a RIO buffer and deregister it
 *  when the chunk is retired. Every other case answers none, a chunk then needing no step.
 */
duct_x_slot_hooks_t duct_events_x_slot_hooks(void);

/**
 *  @name Upcalls
 *  Called by events backend to report meaningful I/O observations.
 *  Portably defined by the engine; each backend calls only the
 *  flavor-relevant subset.
 *  @{
 */

/** @brief One decoded poll event. */
duct_nonnull(1) void duct_io_on_event(duct_io_event_t *ev);

/** @brief Device readiness for the conn @p tag names.
 *  The models that wait a handle call this directly. A model whose device is
 *  a descriptor reports it as ordinary readiness instead, and @ref
 *  duct_io_on_event routes it here. */
duct_nonnull(1) void duct_io_on_device(void *tag);

/** @brief Update @p tag's conn's cached @c io_priv value — called whenever
 *  a poll-style backend's own bookkeeping for it changes: initial
 *  registration, promotion, or a swap-compacting unwatch.
 *
 *  @note Poll-style array-based backends only.
 */
duct_nonnull(2) void
duct_io_on_relocate(duct_io_tag_t kind, void *tag, void *io_priv);

/** @brief This thread's wake key fired: dispatch lane messages,
 *  then drain the frame-rx retry queue.
 */
void duct_io_on_wake(void);

/** @brief Take the outcome of the outbound dial @p pre_conn.
 *  @p rc is the connect's own: @c rc_ok for a connection made, @c rc_conn_refused,
 *  or another code for any other failure. A deadline already fired reports
 *  @c rc_conn_timeout whatever @p rc says. @p pre_conn is gone after the call, and
 *  its fd is a conn's or closed.
 */
duct_nonnull(1) void
duct_io_on_pre_conn_dialed(duct_pre_conn_t *pre_conn, duct_result_t rc);

/** @brief Take the outcome of one probe-wait read for @p pre_conn.
 *  @p rc is the read's own code: @c rc_ok with @p n bytes landed where
 *  @c duct_pre_conn_probe_room named, @p n 0 for a read the deadline cancelled;
 *  @c rc_again for a read that found nothing; @c rc_closed for the peer's FIN; any
 *  other code for a broken connection. A broken connection, and a FIN ahead of the
 *  first byte, close the fd unclassified.
 *
 *  @return true while @p pre_conn waits for more of its first read: the deadline
 *  stands, nothing is freed and a proactive backend posts the next read. false
 *  once the wait resolved and @p pre_conn is gone, so the caller reads nothing of it.
 */
duct_nonnull(1) bool
duct_io_on_pre_conn_probed(duct_pre_conn_t *pre_conn, duct_result_t rc, size_t n);

/** @brief Read probe-wait @p pre_conn's readable fd until a read answers would-block or the wait ends.
 *  The entry of the backends whose readiness is the signal. Each read lands in
 *  @c duct_pre_conn_probe_room and goes to @ref duct_io_on_pre_conn_probed, so a FIN
 *  right behind the last bytes resolves in the same pass. The caller reads nothing of
 *  @p pre_conn after the call.
 */
duct_nonnull(1) void
duct_io_on_pre_conn_readable(duct_pre_conn_t *pre_conn);

/** @brief Fill a @c duct_peer_t from a resolved Berkeley @c sockaddr.
 *
 *  @return filled peer data;
 *          zeroed @ref duct_peer_t if @p sa is @c nullptr.
 */
duct_peer_t duct_io_peer_from_sockaddr(const struct sockaddr *sa);

/** @brief Fill a Berkeley socket address from a @c duct_peer_t.
 *  The inverse of @ref duct_io_peer_from_sockaddr.
 *
 *  @return address length.
 */
duct_nonnull(1, 2) int
duct_io_sockaddr_from_peer(const duct_peer_t *peer,
                           struct sockaddr_storage *out);

/** @brief Fill a Berkeley @c AF_UNIX address from the socket file @p path.
 *  @p path fits the platform's @c sun_path, which @c duct_local_path_fits has
 *  answered for it.
 *
 *  @return address length.
 */
duct_nonnull(1, 2) int
duct_io_sockaddr_from_path(const char *path, struct sockaddr_storage *out);

/** @brief Classify and dispatch one accepted stream @p fd on @p listener.
 *  @p fd arrives non-blocking: the first read and a probe wait's reads stop at
 *  would-block. It ends as a conn, a probe-wait pre_conn, an async pre-parse
 *  hand-off or a close.
 */
duct_nonnull(1, 3) void
duct_io_on_accept(duct_listener_t *listener,
                  duct_sock_t fd, const duct_peer_t *peer);

/** @brief Classify and dispatch one received datagram on @p listener;
 *  @p data points to ephemeral, non-owning storage valid for the call only.
 *
 *  @param seg  Segment size of a coalesced read: @p data then holds several
 *              datagrams of that size from one source, the last free to be
 *              shorter. 0 for one datagram.
 */
duct_nonnull(1, 2, 3) void
duct_io_on_dgram(duct_listener_t *listener,
                 const duct_peer_t *peer, duct_view_u8 *data, uint32_t seg);

/** @brief Classify and dispatch one received datagram that sits in RX slot @p slot of @p listener's pool.
 *  The completion-driven counterpart of @ref duct_io_on_dgram for a read posted into a pooled slot:
 *  @p bytes is the datagram's length and @p seg is as there. @p lend says the caller holds a replacement
 *  for the slot, so a route may hand @p slot to a worker lane by reference; without it the datagram is
 *  copied wherever it is kept. Called on the listener's io thread.
 *
 *  @return true when the slot was handed away and the caller must not release it.
 */
duct_nonnull(1, 2) bool
duct_io_on_dgram_slot(duct_listener_t *listener, const duct_peer_t *peer, uint32_t slot,
                      size_t bytes, uint32_t seg, bool lend);

typedef struct duct_dgram_tx_entry duct_dgram_tx_entry_t;

/** @brief Post one queued send.
 *  The callback of @ref duct_io_dgram_send_drain.
 *  @return false when the backend can take no more now, which leaves @p entry queued; true once
 *          @p entry is spent, posted or not.
 */
typedef bool (*duct_dgram_send_fn)(void *arg, const duct_dgram_tx_entry_t *entry);

/** @brief Hand the entries queued in @p listener's @c dgram_tx_outbox to @p send, lane by lane.
 *  A lane drains in order and stops at the first entry @p send refuses; the entries it took are
 *  committed, and a producer parked on a full lane is woken. The first lane served moves on at each
 *  call. On the listener's io thread.
 */
duct_nonnull(1, 2) void
duct_io_dgram_send_drain(duct_listener_t *listener, duct_dgram_send_fn send, void *arg);

/** @brief Length standing for a datagram too large for the buffer offered it.
 *
 *  Reported per entry by @c duct_xrecv_peers, which keeps the entry so the
 *  exhaustion check still counts what the kernel handed back.
 *  Such a datagram is unusable — its tail is gone and
 *  the wire has no way to tell a short one from a cut one — so the drain skips
 *  it and a batched conn read voids its unit, avoiding fragment delivery.
 */
static constexpr uint32_t duct_dgram_len_truncated = UINT32_MAX;

/** @brief Check out @p listener's free datagram RX slots, up to
 *  @c duct_dgram_rx_batch, as read spans in @p out.
 *
 *  Each span starts one record header past its slot's base, so the io side
 *  writes that header into the gap and the wire sees @c [record][payload]
 *  contiguous — the same shape @c duct_dgram_rx_header_commit gives a conn's
 *  ring. Ownership of a slot moves to the lane when its datagram is routed by
 *  reference; @ref duct_io_rx_slots_release takes back the rest.
 *
 *  @param out  Room for @c duct_dgram_rx_batch spans; only the returned count
 *              is written.
 *  @return How many spans were filled, 0 when the pool is empty or slots from
 *          a previous batch are still checked out. On 0 the caller asks
 *          @ref duct_io_dgram_rx_stall first, and reads into the block of
 *          @ref duct_io_dgram_rx_scratch, the datagram then copied, only where
 *          that declines.
 */
duct_nonnull(1, 2) uint32_t duct_io_rx_slots_acquire(duct_listener_t *listener, duct_view_u8 *out);

/** @brief Return every slot still checked out; those the lane took are already
 *  cleared and skipped. Leaves the pool ready for the next batch. */
void duct_io_rx_slots_release(void);

/** @brief Take this io thread's scratch block for one datagram read, @c DUCT_LISTENER_DGRAM_DEFAULT bytes.
 *  Made at the first call and kept until @c duct_io_cleanup. The drain reads into it where
 *  @ref duct_io_rx_slots_acquire finds no slot and @ref duct_io_dgram_rx_stall declines, and the
 *  route copies out of it. Called on the io thread; any other gets an empty span.
 *  @return The block; an empty span, @c data null, where it cannot be made.
 */
duct_view_u8 duct_io_dgram_rx_scratch(void);

/** @brief Park @p listener on its dry RX slot pool.
 *  Withdraws its read interest and sets the pool's @c stalled; the slot return
 *  or pin that takes the stall back posts this thread a resume, which puts the
 *  listener back.
 *  @return true with the listener parked; false where reading goes on: a pool
 *          with no live chunk, one a held lane pins, or one a slot or a pin
 *          came back to during the call.
 */
duct_nonnull(1) bool duct_io_dgram_rx_stall(duct_listener_t *listener);

/** @brief Accept one client on stream @p listener, parking it when the process has no descriptor left.
 *  The accept loops of the reactive backends call this in place of @c duct_xaccept. An
 *  @c rc_defer parks @p listener through @ref duct_io_accept_park, and the accept is tried
 *  once more past that park, so a descriptor closed in between is taken; a later close
 *  resumes the listener through @c duct_io_accept_resume.
 *  @return what @c duct_xaccept answers to the last try; @c rc_defer leaves @p listener parked.
 */
duct_nonnull(1, 2, 3) duct_result_t
duct_io_accept(duct_listener_t *listener, duct_sock_t *fd, struct sockaddr_storage *addr);

/** @brief Park stream @p listener for want of a descriptor.
 *  Withdraws its read interest, as a dry datagram pool does, and counts it among the parks
 *  @c duct_io_accept_resume reads. On @p listener's own io thread.
 */
duct_nonnull(1) void duct_io_accept_park(duct_listener_t *listener);

/** @brief Put parked stream @p listener back on its read readiness and off the count.
 *  On iocp that readiness is a re-posted @c AcceptEx, which parks @p listener again when no
 *  accept socket can be made. On @p listener's own io thread.
 */
duct_nonnull(1) void duct_io_accept_unpark(duct_listener_t *listener);

/** @brief Read @p listener's pending datagrams, at most
 *  @c duct_dgram_rx_max_passes batches of @c duct_dgram_rx_batch each.
 *
 *  The readiness-driven backends share this: proactive ones complete into
 *  their own buffers and call @ref duct_io_on_dgram directly instead.
 *
 *  Stopping short of an empty socket is safe because a listener is registered
 *  level-triggered, so whatever is left re-notifies. The bound keeps one
 *  flooded listener from holding the io thread past its timers and past the
 *  trunk of posts its workers are waiting on. A dry slot pool stops it through
 *  @ref duct_io_dgram_rx_stall, the rest waiting in the socket's kernel queue.
 */
duct_nonnull(1) void duct_io_dgram_rx_drain(duct_listener_t *listener);

/** @brief Receive up to @c r->units datagrams into the read units @p r
 *  describes, in one call, and commit them to @p tag's conn.
 *
 *  @return @c rc_ok when every unit filled; @c rc_again when fewer arrived, the
 *          socket having run dry, and each later datagram raises readiness
 *          again; the receive call's own failure otherwise.
 */
[[nodiscard]] duct_nonnull(1, 2) duct_result_t
duct_io_dgram_rx_units(void *tag, const duct_io_xfer_t *r);

/** @brief @p listener's socket is writable again — retry whatever
 *  @c dgram_tx_outbox drain last stopped on EAGAIN. No-op if nothing is
 *  queued; safe to call speculatively.
 *  @return true if any lane actually had data to send this call, false if
 *          every lane was already empty (a pure no-op call).
 */
duct_nonnull(1) bool duct_io_on_dgram_tx_writable(duct_listener_t *listener);

/** @brief Dispatch an undrained trunk request, then drain due timers.
 *
 *  Withdraws the park announcement @ref duct_io_work_pending made on the
 *  previous pass first, so posters stop kicking a thread that is awake. The
 *  dispatch runs ahead of the clock read, so a timer it arms reaches the
 *  answer and the milliseconds returned are measured past it. A pass past
 *  the sweep period also sweeps this thread's slot pools and hands their
 *  idle chunks back; the sweep arms no timer and bounds no park.
 *
 *  @return milliseconds until the next deadline,
 *          @c DUCT_TIMEOUT_INFINITE if none armed.
 */
[[nodiscard]] uint32_t duct_io_on_tick(void);

/** @brief True if a timer is due within the millisecond after this thread's
 *  own tick drain.
 *
 *  @ref duct_io_on_tick floors such a deadline to 1 ms, since 0 collides
 *  with @c DUCT_TIMEOUT_INFINITE in that return channel. A backend whose
 *  wait call treats a literal 0 timeout as "don't block" calls this and
 *  passes its own native 0.
 */
[[nodiscard]] bool duct_io_timer_due_soon(void);

/** @brief Announce that this thread's next event wait may block, and report
 *  whether its trunk still holds an undrained request.
 *
 *  Posters kick only an announced thread. The seq_cst fence here pairs with
 *  theirs: a request pushed before it is either seen by this check or
 *  answered with a kick, so a backend calls this right before every wait that
 *  can block, beside @ref duct_io_timer_due_soon, and passes its own native 0
 *  timeout on true. A request the io thread posts onto its own trunk carries
 *  no kick at all.
 */
[[nodiscard]] bool duct_io_work_pending(void);

#if DUCT_RUNTIME_STATS
/** @brief Count one duct_events_run_loop pass into this io thread's stats.
 *  Bumps loop_pass, and busy_spin on a pass @p in_window posts with timeout 0;
 *  busy_enter and busy_exit count its changes. @p in_window is the loop's last
 *  duct_spin_next answer. The worker loop keeps the same three counters in
 *  duct_worker_rt_t.
 */
void duct_io_rtstat_busy_track(bool in_window);
#endif

/** @brief Reserve RX buffer space for @p tag's conn. */
[[nodiscard]] duct_nonnull(1, 2) bool
duct_io_rx_reserve(void *tag, duct_io_xfer_t *out);

/** @brief Commit @p n bytes just read into reserved RX space.
 *  The reservation comes from @ref duct_io_rx_reserve.
 *
 *  @param seg  Segment size @c duct_xread reported for a coalesced read: the
 *              @p n bytes are then several datagrams of that size, the last
 *              free to be shorter, and each becomes a record of its own. 0 for
 *              one datagram, and on every stream transport.
 */
void duct_io_rx_commit(void *tag, size_t n, size_t seg);

/** @brief Commit a batched read of @p n datagrams into @p tag's reserved read
 *  units and post them for parsing.
 *
 *  @p lens holds each datagram's length, or @ref duct_dgram_len_truncated. A
 *  datagram outside its wire's bounds voids its unit, and the ring stops at the
 *  end of the last one inside them; nothing is staged when none is.
 */
duct_nonnull(1, 2) void duct_io_rx_commit_units(void *tag, const uint32_t *lens, uint32_t n);

/** @brief End one RX-drive step for @p tag's conn.
 *
 *  Post arrived data for parsing, and close the conn on @c rc_fatal or
 *  @c rc_invalid_arg. @c rc_closed on a transport whose zero-length read carries
 *  the peer's FIN ends the conn's input: reads stop for good, and the end
 *  follows every frame posted ahead of it to the worker, which closes the leg
 *  with @c close_peer behind the answers ahead of it. A transport delivering
 *  whole packets has no such signal and reads on.
 */
duct_nonnull(1) void duct_io_rx_done(void *tag, duct_result_t rc);

/** @brief Peek TX buffer content for @p tag's conn. */
[[nodiscard]] duct_nonnull(1, 2) bool
duct_io_tx_peek(void *tag, duct_io_xfer_t *out);

/** @brief Send one TX-drive step's worth of @p tag's conn and advance its ring.
 *
 *  Takes @p p from a @ref duct_io_tx_peek that answered true. A record-framed
 *  datagram leg may resolve several queued records in one call, so a single
 *  call can consume more of the ring than @p p describes; peek again for
 *  remaining bytes.
 *
 *  @param out_rc what @ref duct_io_tx_done is to be given once the drive ends.
 *  @return true to keep draining. False stops the drive, and @p out_rc
 *          separates the reasons: @c rc_ok is a stream short write, @c rc_again
 *          a socket out of room, @c rc_closed a stale @p tag, @c rc_fatal a
 *          conn to close.
 */
duct_nonnull(1, 2, 3) bool
duct_io_tx_send(void *tag, const duct_io_xfer_t *p, duct_result_t *out_rc);

/** @brief Advance TX OLB by @p n bytes just sent.
 *  The span they were sent from comes from @ref duct_io_tx_peek. Only iocp
 *  calls this directly; a reactive backend advances through
 *  @ref duct_io_tx_send.
 */
duct_nonnull(1) bool
duct_io_tx_advance(void *tag, size_t offered, size_t n);

/** @brief Address up to @p max whole records at the head of @p tag's TX ring.
 *  Payload spans only, each record's length prefix stepped over; the walk stops
 *  at the first record the readable run does not hold entirely.
 *  @return records addressed; 0 for a stale @p tag or a ring without record
 *  boundaries.
 */
duct_nonnull(1, 2) unsigned
duct_io_tx_peek_bufs(void *tag, duct_view_u8 *bufs, unsigned max);

/** @brief Advance @p tag's TX ring past its first @p n records.
 *  Completes a send that carried @p n records at once. They are the ring's
 *  head records while one send per conn is in flight; @p n is at most
 *  @c duct_dgram_tx_batch.
 */
duct_nonnull(1) void
duct_io_tx_advance_records(void *tag, unsigned n);

/** @brief End one TX-drive step for @p tag. */
duct_nonnull(1) void duct_io_tx_done(void *tag, duct_result_t rc);

/** @brief Record @p tag's conn write-interest state, @c fl_conn_write_armed
 *  — @p armed true when this drive step still had readable TX data left
 *  after the socket stopped taking more (reactive backends only; never
 *  called by iocp). No-op for a stale tag, or a conn whose live union arm
 *  is not the ring pair.
 */
duct_nonnull(1) void duct_io_tx_write_armed_set(void *tag, bool armed);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* DUCT_EVENTS_H */
