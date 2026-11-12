/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_listener.h
 *  @brief Listener node: one bound listen socket plus its protocol array.
 *
 *  One logical @ref duct_listener_bind yields @c n_io nodes where
 *  @c duct_x_port_sharing spreads a port across sockets — one SO_REUSEPORT
 *  socket per I/O thread, so the kernel spreads accepts — and one node
 *  elsewhere. A bind carrying @c fl_proto_dgram_shared yields one node per
 *  worker there instead: node k is read by io thread k % @c n_io and opens
 *  its sessions on worker k. A path bind, @c x_local, is one node whatever the
 *  platform spreads, and its node keeps the bound file's state in a
 *  @c duct_local_bind_t. A datagram node reads into its worker's RX slot
 *  pool, which the engine holds for its whole life. Each node lives on its
 *  owning io thread's list, io-thread-exclusive from registration to free; the
 *  host only ever holds a pointer-free @c {fd, io_id} registry entry. Each node
 *  owns its @c protos array, the @c duct_proto_t elements stay borrowed from
 *  the caller until @c duct_engine_destroy.
 *
 *  One definition serves every backend. A backend that needs private
 *  per-listener state (IOCP's accept/recv ops) keeps a side context in its
 *  events TU, back-pointing here.
 */

#ifndef DUCT_LISTENER_H
#define DUCT_LISTENER_H

#include "duct_core.h"
#include "duct_msg.h"
#include "duct_timer.h"
#include "duct_types.h"
#include "duct_vmq.h"
#include "duct_wfq_msg.h"
#include "duct_wire.h"
#include "duct_x_slot.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Largest @c max_response a @c fl_proto_dgram_shared proto may
 *  declare: one @c dgram_tx_outbox reserve must fit the VMQ header, the
 *  entry header, and the payload in one message. Checked once at bind
 *  time and reused as the worst-case reservation size on the worker's
 *  commit path — single
 *  source of truth for both.
 */
static constexpr size_t duct_dgram_lane_max_response =
    duct_dgram_tx_outbox_cap - duct_vmq_msg_overhead - sizeof(duct_dgram_tx_entry_t);

static constexpr size_t duct_dgram_shared_max_response =
    duct_dgram_lane_max_response < duct_udp4_payload_max ? duct_dgram_lane_max_response
                                                         : duct_udp4_payload_max;

/** @brief Forward declaration for @c duct_listener_cfg_t.
 *  The public @ref duct_listener_bind config; @ref duct_listener_route_bind
 *  only ever passes a pointer through.
 */
typedef struct duct_listener_cfg duct_listener_cfg_t;

/** @brief Host/io rendezvous for one posted register or close op; not
 *  reused across ops.
 *  Two holders: the poster, which drops its own after its wait or, with none, at once, and the
 *  posted message, whose hold the post takes with @c duct_share and
 *  @ref duct_listener_sync_signal drops.
 */
typedef struct duct_listener_sync {
    uint32_t _Atomic  done;  /**< Signalled flag, 1 once @c ok is stored.
                               *  The signal's release store pairs with the waiter's acquire load. */
    bool              ok;    /**< Outcome of the op, written ahead of @c done: registered, or a
                               *  node found to close. */
} duct_listener_sync_t;

/** @brief Report the outcome of a posted register or close op to the host thread waiting on @p sync.
 *  Stores @p ok, raises @c done, wakes every listener sync waiter and drops the message's hold
 *  with @c duct_del; @p sync is not used after the call. The io thread that ran the op calls it,
 *  and so does the teardown that abandons an op no io thread will run, with @p ok false.
 */
void duct_listener_sync_signal(duct_listener_sync_t *sync, bool ok);

/** @brief Host-side {fd, io_id} registry entry, @c duct_runtime_max_listeners
 *  of them per engine.
 *  A bind claims a free slot by CAS on @c fd, so binds from several threads
 *  never share one, and writes @c io_id after the claim: only a close of that
 *  fd reads it, which follows the bind that returned the fd.
 */
typedef struct duct_listener_reg {
    duct_sock_t _Atomic fd;    /**< Registered node's socket, @c duct_sock_bad
                                 *  while the slot is free. */
    unsigned            io_id; /**< Registered node's io thread. */
} duct_listener_reg_t;

/** @brief Default classification-read cap when @c duct_listener_cfg_t::peek_cap is 0. */
#ifndef DUCT_LISTENER_PEEK_DEFAULT
#define DUCT_LISTENER_PEEK_DEFAULT 128u
#endif

/** @brief Largest stream probe read a listener takes, however large a @c peek_cap
 *  names: the probe buffers size to it, so an explicit cap past it is clamped. */
#ifndef DUCT_LISTENER_PEEK_MAX
#define DUCT_LISTENER_PEEK_MAX 2048u
#endif

/** @brief Most probe-wait parks one listener holds at once.
 *  A stranger spends nothing to occupy a park — an fd, a peek buffer and a
 *  timer for @c probe_wait_ms — so the park count is bounded per listener: a
 *  wait past the bound is refused and the bytes classify as they stand. */
#ifndef DUCT_LISTENER_PROBE_PARK_MAX
#define DUCT_LISTENER_PROBE_PARK_MAX 128u
#endif

/** @brief Largest stream probe read a listener offers, bytes: @p peek_cap, or
 *  @c DUCT_LISTENER_PEEK_DEFAULT when that is 0, clamped to @c DUCT_LISTENER_PEEK_MAX.
 *  Bounds the accept-time read, the bytes a probe-wait pre_conn accumulates and
 *  the @c peek_min a bind accepts, so a pre-parse never sees more than it. */
static inline size_t duct_listener_peek_span(size_t peek_cap)
{
    size_t cap = peek_cap ? peek_cap : DUCT_LISTENER_PEEK_DEFAULT;
    return duct_min(cap, (size_t)DUCT_LISTENER_PEEK_MAX);
}

/** @brief Default datagram classification buffer when @c peek_cap is 0 for a
 *  @c listener_dgram listener. The datagram is read whole either way, see
 *  @c duct_listener::xport_type.
 */
#ifndef DUCT_LISTENER_DGRAM_DEFAULT
#define DUCT_LISTENER_DGRAM_DEFAULT duct_udp4_payload_max
#endif

/** @brief Capacity of a local bind's path, bytes, NUL included.
 *  The widest @c sun_path any supported platform has. */
static constexpr size_t duct_local_path_max = 108u;

/** @brief Socket file, session count and accept pace of one path listener, owned by its node. */
typedef struct duct_local_bind {
    char     path[duct_local_path_max]; /**< Path of the socket file this listener placed; empty
                                          *  once the unlink has run. */
    uint64_t dev,                       /**< Device of the placed file, read after the bind; the
                                          *  volume serial on Windows. */
             ino;                       /**< Inode of the placed file; the file index on Windows. */
    unsigned live;                      /**< Sessions accepted and not yet torn down. */
    uint16_t cap;                       /**< Most live sessions admitted; 0 = no cap. */
    uint16_t rate;                      /**< Most accepts a second, spaced 1/@c rate s apart; 0 = unpaced. */
    duct_timer_handle_t pace;           /**< Handle of the one-shot timer that ends the pause after an
                                          *  accept; @c timer_handle_null while the listener accepts. */
} duct_local_bind_t;

/** @brief One registered listener: listen socket + protocol array.
 *
 *  @c protos order is dispatch priority: sync pre-parses run first, then
 *  async ones, then @c preparse==NULL fallbacks — the first
 *  non-@c resolve_not_me answer claims the accept. With no pre-parse
 *  configured anywhere, @c protos[0] claims everything.
 */
typedef struct duct_listener duct_listener_t;

/** @brief Worker→io wake for one listener's @c dgram_tx_outbox, embedded
 *  in @c duct_listener_t.
 *  @c wake_latch already guarantees at most one in flight per listener. */
duct_msg_chain_decl(duct_msg_dgram_tx_kick, duct_listener_t *listener);

typedef struct duct_listener {
    duct_sock_t           listen_fd; /**< Bound, non-blocking; @c duct_sock_bad once a path
                                       *  listener has retired. */
    const duct_proto_t  **protos;    /**< Owned array of borrowed proto pointers; order = priority. */
    unsigned              n_protos;  /**< Entries in @c protos; at least 1. */
    size_t       peek_cap;  /**< Stream: probe read cap — a real read,
                               *  re-injected into the conn's RX later; dgram: max accepted
                               *  probe payload. 0 = default for either. */
    uint32_t     probe_wait_ms; /**< Copied from the cfg at registration; 0 = disabled. */
    uint16_t     bound_port;    /**< Actual port, OS-assigned if @c addr used @c :0. */
    uint16_t     peek_min;      /**< Copied from the cfg at registration: bytes a stream first read
                                  *  has to reach before a pre-parse is asked, 0 = none. A bind
                                  *  keeps it within the probe read span and refuses it without
                                  *  @c probe_wait_ms. */
    unsigned     io_id,         /**< Owning I/O thread index. */
                 worker;        /**< Worker for @c resolve_async pre-parse, the
                                  *  one whose RX slot pool a datagram node
                                  *  reads into, and, for a shared bind where
                                  *  the port spreads, the one its sessions
                                  *  run on. */
    duct_xport_t xport_type;    /**< @c x_tcp; @c x_udp for the shared classification
                                  *  socket per-peer conns spin off from; @c x_local for a
                                  *  path listener. The conns a stream node accepts take it
                                  *  as their own. */
    duct_local_bind_t *local;   /**< Path-listener state, freed with the node; nullptr unless
                                  *  @c xport_type is @c x_local. */
    void       *dgram_peers; /**< @c listener_dgram only: peer-address → conn map, owned
                                *  and typed by the io module,
                                *  lazily allocated on the first entry. Freed via @ref
                                *  duct_io_listener_dgram_peers_free at teardown; nullptr
                                *  for a stream listener. */
    void       *dgram_tx_outbox; /**< Outbox of @c x_udp_shared datagrams, an opaque
                                    *  @c duct_vmq_mpsc_t* with one lane per worker.
                                    *  @c fl_proto_dgram_shared only, allocated at
                                    *  registration. A worker stages there every datagram
                                    *  its fast path does not send and wakes this listener's
                                    *  I/O thread, the lane's only drainer. Freed at
                                    *  teardown; nullptr without a shared proto bound. */
    duct_msg_dgram_tx_kick dgram_tx_kick; /**< @c fl_proto_dgram_shared only: embedded kick
                                            *  message. Posted via @ref duct_io_post_dgram_tx;
                                            *  fields set once at registration. */
    void       *dgram_tx_pool; /**< @c fl_proto_dgram_shared only, iocp without RIO: opaque
                                  *  send state, owned and typed by the IOCP backend. One
                                  *  overlapped @c WSASendMsg descriptor per send in flight,
                                  *  each posting from a slot of @c tx_slots. Allocated by
                                  *  @ref duct_events_dgram_tx_pool_alloc, freed by @ref
                                  *  duct_events_dgram_tx_pool_free once its last send
                                  *  settles; nullptr on every other backend and wherever
                                  *  RIO is in use. */
    void       *dgram_tx_rio; /**< @c fl_proto_dgram_shared only, iocp and wsaevent where RIO
                                 *  is in use: opaque @c duct_rio_tx_t pointer, owned by the
                                 *  RIO module. Made when the listener registers on its io
                                 *  thread (@c s_rio_dgram_init), since its request queue
                                 *  needs a completion queue only that thread's env owns.
                                 *  Freed by @ref duct_events_dgram_tx_pool_free; nullptr
                                 *  wherever RIO is not in use for this listener. */
    uint32_t _Atomic wake_latch;    /**< Kick dedup for @c duct_io_post_dgram_tx: only the
                                      *  0→1 transition posts, a kick already in
                                      *  flight covers every lane anyway. The I/O thread
                                      *  clears it right before draining, so a commit racing
                                      *  in mid-drain still gets a fresh kick. */
    bool _Atomic dgram_tx_write_armed; /**< Current write-interest state for @c
                                          *  duct_events_dgram_tx_interest. Written only by
                                          *  the io thread (relaxed), which also reads it
                                          *  back itself so the reconcile only calls the
                                          *  backend on a genuine transition. */
    unsigned    pre_conn_refs;  /**< "Something outside still points at this listener" count:
                                   *  probe-wait @c duct_pre_conn_t holders, live
                                   *  @c x_udp_shared and @c x_local conns, and in-flight async
                                   *  pre-parse round trips. io-thread-private. */
    unsigned    probe_parks;    /**< Probe-wait @c duct_pre_conn_t parks this node holds,
                                   *  bounded by @c DUCT_LISTENER_PROBE_PARK_MAX because a
                                   *  stranger spends nothing to occupy one. io-thread-private. */
    bool        closing;        /**< Close requested while @c pre_conn_refs was still
                                   *  nonzero — the node stays until the last ref drops, and
                                   *  @c listen_fd with it unless a path listener retired it
                                   *  (@c duct_listener_release_pre_conn_ref finishes the close
                                   *  then). io-thread-private, false otherwise. */
    bool        rx_parked;      /**< Read interest withdrawn on a dry @c rx_slots,
                                   *  until that pool's resume puts it back.
                                   *  io-thread-private. */
    duct_x_slot_pool_t *rx_slots; /**< RX slot pool of this node's worker, held
                                     *  and freed by the engine; null on a
                                     *  stream node. */
    duct_x_slot_pool_t  *tx_slots; /**< The pair of TX slot pools workers stage sends into, small
                                     *  class first. Made by @ref duct_listener_tx_slots_new;
                                     *  nullptr where the listener's TX is not posted from slots. */
    unsigned             tx_lane;  /**< Lane the next drain of the outbox starts from, rotating so
                                     *  that no lane is always served first. io-thread-private. */
    struct duct_listener *next; /**< Owning io thread's singly-linked list. */
} duct_listener_t;

/** @brief Largest datagram read @p l offers, bytes: its @c peek_cap, or
 *  @c DUCT_LISTENER_DGRAM_DEFAULT when that is unset or larger.
 *  Every listener read path offers at least this much, and coalescing on the
 *  listener fd is capped at it, so a coalesced group always fits. */
duct_nonnull(1) static inline size_t duct_listener_dgram_span(const duct_listener_t *l)
{
    size_t cap = l->peek_cap ? l->peek_cap : DUCT_LISTENER_DGRAM_DEFAULT;
    return duct_min(cap, (size_t)DUCT_LISTENER_DGRAM_DEFAULT);
}

/** @brief Span a read into RX slot @p idx of @p pool offers for @p l.
 *  The slot's payload area, no larger than @p l's datagram span.
 */
duct_nonnull(1, 2) static inline duct_view_u8
duct_listener_rx_span(const duct_listener_t *l, const duct_x_slot_pool_t *pool, uint32_t idx)
{
    return (duct_view_u8){ .data = duct_x_slot_payload(pool, idx),
                         .size = duct_min(duct_x_slot_cap(pool), duct_listener_dgram_span(l)) };
}

/** @brief Build the pair of TX slot pools of @p l and store it in @c tx_slots.
 *  The small class serves path-MTU datagrams, the large one full UDP payloads. Each slot has @p lead
 *  bytes ahead of its payload, and the small class grows @p chunk slots at a time. The counts follow
 *  the outbox of @p l, which is made already.
 *  @return false with nothing stored when a pool cannot be built.
 */
[[nodiscard]] duct_nonnull(1) bool
duct_listener_tx_slots_new(duct_listener_t *l, uint32_t lead, uint32_t chunk);

/** @brief Free the pair @p pools: both pools and the array that holds them.
 *  Every slot is back, and no other thread uses the pools.
 */
duct_nonnull(1) void duct_listener_tx_slots_free(duct_x_slot_pool_t *pools);

/** @brief Test whether @p l is a path listener with a rate set. */
duct_nonnull(1) static inline bool duct_listener_paced(const duct_listener_t *l)
{
    return l->local && l->local->rate;
}

/** @brief Test whether @p l's accepts are paused until its pace timer fires. */
duct_nonnull(1) static inline bool duct_listener_held(const duct_listener_t *l)
{
    return l->local && l->local->pace != timer_handle_null;
}

/** @brief Narrow view of the engine's listener state.
 *
 *  Lets the listener module work on the listener list and thread topology
 *  while @c duct_engine_t stays private to the engine module. Built fresh on
 *  the stack at each call site.
 */
typedef struct duct_listener_route {
    duct_listener_reg_t *regs;          /**< e->listener_regs, duct_runtime_max_listeners entries. */
    unsigned            n_workers,      /**< e->n_workers; a new node's .worker assignment,
                                          *  and the fan-out of an @c fl_proto_dgram_shared
                                          *  bind. */
                        n_io;          /**< e->n_io; the fan-out of every other bind, and
                                         *  the modulus giving a node its io thread. */
    duct_x_slot_pool_t *_Atomic *rx_pools; /**< e->rx_pools, each worker's RX slot
                                             *  pool by worker index, null until
                                             *  that worker's first datagram node. */
} duct_listener_route_t;

/** @brief Output span for registered listener fds, mirroring
 *  @c duct_listener_bind's @c out_fds/@c max_fds/@c out_n_fds triplet:
 *  @c fds may be nullptr, @c cap bounds how many entries it can hold, @c n
 *  is set to the full registered count on return regardless of @c cap.
 */
typedef struct duct_listener_out_fds {
    duct_sock_t *fds;
    unsigned    cap,
                n;
} duct_listener_out_fds_t;

/** @brief Register one logical bind as one or more listener nodes.
 *  The first socket becomes node 0, and one more SO_REUSEPORT socket on the
 *  same resolved @p port is opened per further node: @c route->n_io nodes, or
 *  @c route->n_workers for @c fl_proto_dgram_shared, node k on io thread
 *  k % @c n_io; a platform whose @c duct_x_port_sharing spreads nothing takes
 *  one node. A path bind, @c cfg->local_path set, is one node on every platform
 *  and writes 0 to @p port. On any failure every node this call
 *  added is unwound; earlier binds stay untouched.
 *
 *  @return @c rc_ok; @c rc_invalid_arg for a malformed @p cfg or a proto set its
 *          kind cannot carry, @c fl_proto_dgram_shared on @c listener_stream
 *          among them; @c rc_not_supported for a path bind below
 *          @c duct_x_local_floor; @c rc_fatal where a socket cannot be opened,
 *          a path is refused or its io thread does not take the node;
 *          @c rc_no_memory on an allocation failure or a full registry.
 */
duct_result_t duct_listener_route_bind(duct_listener_route_t *route, const duct_listener_cfg_t *cfg,
                                       uint16_t *port, duct_listener_out_fds_t *out);

/** @brief Revoke one listener by socket.
 *  The body of @ref duct_listener_close; cross-thread confirmation is a
 *  bounded wait on a posted-op sync block.
 */
duct_result_t duct_listener_route_close(duct_listener_route_t *route, duct_sock_t fd);

/** @brief Tear down and free every node on @p head. Whole-engine teardown
 *  only (@c s_engine_destroy, after @ref duct_io_listeners_detach).
 */
void duct_listener_destroy_chain(duct_listener_t *head);

/** @brief Tear down and free one listener node. Exported for the owning
 *  io thread's register/close execs.
 */
void duct_listener_destroy(duct_listener_t *l);

/* Async pre-parse — internal ctrl + reverse-kick, one round-trip message */

/** @brief I/O↔worker async pre-parse round trip: one object, one allocation,
 *  both directions. The I/O thread fills @c listener/fd/peer/payload and
 *  posts; the worker-side classifier fills @c decision, @c lead, @c proto,
 *  @c join_tok, @c join_conn_id and @c user_ctx in place, repoints
 *  @c msg.exec_fn at the I/O-side result handler, and posts the *same*
 *  object back on every disposition, reject and not_me included, so the I/O
 *  side always learns the outcome and can clear its dgram_peers pending marker.
 *
 *  @c listener stays alive for the whole trip via a @c pre_conn_refs
 *  reference taken by the poster and released when the trip ends.
 *
 *  @c payload is the classification bytes, copied behind the message by the
 *  poster and freed with it; @c payload_len counts them, 0 when
 *  classification needed no bytes. Injected later as the new conn's first RX
 *  content, a stream's from past @c lead.
 *
 *  @c fd_registered: stream fd still watched as @c io_tag_pre_conn; the
 *  result handler then promotes in place. Stream classify detaches before
 *  posting, so that path always passes false.
 */
duct_msg_chain_decl(duct_msg_pre_parse,
    duct_listener_t              *listener;
    duct_sock_t                   fd;
    duct_peer_t                   peer;
    bool                           fd_registered;
    duct_resolve_disposition_t    decision;    /**< resolve_new / resolve_join / resolve_reject / resolve_not_me. */
    uint16_t                      lead;        /**< Leading bytes of @c payload the preparse consumed. */
    uint32_t                      payload_len; /**< Bytes of @c payload. */
    const duct_proto_t           *proto;       /**< Matched protocol, if any. */
    duct_handle_t                  join_tok;    /**< Valid if @c resolve_join. */
    duct_conn_id_t                join_conn_id; /**< Valid if @c resolve_join. */
    void                         *user_ctx;   /**< Valid if @c resolve_new. */
    uint8_t                       payload[]);  /**< Classification bytes, @c payload_len of them. */

/** @brief Drop one @c pre_conn_refs reference.
 *  Destroys @p listener, its socket included while still open, when the count
 *  reaches 0 with @c closing set. io-thread-only.
 */
void duct_listener_release_pre_conn_ref(duct_listener_t *listener);

/** @brief Test whether a path listener is under its cap of live sessions.
 *  The session is counted once its conn is registered. A cap of 0 turns the limit off.
 *  @p listener is an @c x_local node.
 */
duct_nonnull(1) bool duct_local_listener_admits(duct_listener_t *listener);

/* Platform socket primitives, shared by every backend */

/** @brief Open, bind, and listen a non-blocking SO_REUSEPORT TCP socket on
 *  @p host:*port; an ephemeral bind writes the OS-assigned port back.
 *  @return @c duct_sock_bad on failure.
 */
duct_sock_t duct_listener_open(const char *host, uint16_t *port);

/** @brief Open and bind the non-blocking SO_REUSEPORT UDP classification
 *  socket for @c listener_dgram; no @c listen(). Ephemeral bind writes the
 *  OS-assigned port back. @return @c duct_sock_bad on failure.
 */
duct_sock_t duct_dgram_socket_open(const char *host, uint16_t *port, bool shared);

/** @brief Test whether @p path is non-empty and fits @c sockaddr_un's @c sun_path with its NUL. */
duct_nonnull(1) bool duct_local_path_fits(const char *path);

/** @brief Bind and listen a non-blocking AF_UNIX stream socket on @c cfg->local_path.
 *  The path has passed @ref duct_local_path_fits. A path held by a socket nobody
 *  serves is unlinked and bound over; a served socket, a regular file, a symlink
 *  and a path that cannot be examined refuse the bind. The mode and group are
 *  applied between bind and listen, which takes backlog 0 under a nonzero
 *  @c cfg->max_conns_per_s. On success @p local holds the path, the placed
 *  file's identity, @c cfg->max_sessions as its cap and @c cfg->max_conns_per_s as its rate.
 *  @return The listening socket. @c duct_sock_bad on any refusal, the reason on
 *          stderr and no file this call placed left behind; a mode or group is a
 *          refusal on Windows.
 */
duct_nonnull(1, 2) duct_sock_t duct_local_listener_open(const duct_listener_cfg_t *cfg,
                                                        duct_local_bind_t *local);

/** @brief Remove the placed socket file while it is still this listener's own.
 *  The file is own while its device and inode match the ones read after the bind.
 *  @c local->path is empty on return either way.
 */
duct_nonnull(1) void duct_local_listener_unlink(duct_local_bind_t *local);

/** @brief Unlink a path listener's file when still its own, then close its socket.
 *  Leaves @c listen_fd at @c duct_sock_bad. A second call finds both done.
 */
duct_nonnull(1) void duct_local_listener_retire(duct_listener_t *listener);

#ifdef __cplusplus
}
#endif

#endif /* DUCT_LISTENER_H */
