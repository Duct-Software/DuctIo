/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_io.c
 *  @brief Transport executor: accepts, connects, and joins conns, drains
 *  RX into the OLB, drains TX out of it, and decides when a conn or
 *  listener drives.
 *
 *  A worker asking the I/O thread to act on a conn posts one message onto
 *  that thread's own stack; repeated requests for the same conn coalesce
 *  into one pending bit. Each accepted conn lands on a worker chosen by
 *  its pool index modulo the worker count.
 */

#include "duct_io.h"
#include "duct_xport.h"
#include "duct_conn_fence.h"
#include "duct_dgram_rec.h"
#include "duct_events.h"
#include "duct_frame_rx.h"
#include "duct_x_slot.h"
#include "duct_hash.h"
#include "duct_join.h"
#include "duct_listener.h"
#include "duct_olb_rx.h"
#include "duct_olb_tx.h"
#include "duct_pre_conn.h"
#include "duct_protocol.h"
#include "duct_relay.h"
#include "duct_session.h"
#include "duct_stats.h"
#include "duct_timer.h"
#include "duct_vmq.h"
#include "duct_vnet.h"
#include "duct_wfq_msg.h"

#if DUCT_RUNTIME_STATS
#include "duct_runtime_stats.h"
#include "duct_worker.h"
#endif

#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> /* duct_sock_close is a macro alias for close(). */

/* Berkeley socket shapes mirrored by Winsock, so the peer and
 * sockaddr conversions below stay portable across both; only the header
 * differs. */
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <afunix.h>
    #include "duct_rio.h"
#else
    #include <netinet/in.h>
    #include <sys/socket.h>
    #include <sys/un.h>
#endif

/** @brief One I/O thread's post target: any thread pushes a message onto
 *  its stack and kicks its events handle when the thread may be parked. The
 *  events handle is opaque backend state the thread allocates for itself.
 */
typedef struct duct_io_trunk {
    duct_msg_stack_t    stack;
    bool _Atomic        parked;  /**< Park announcement: true while the
                                   *  thread's next event wait can block. Set
                                   *  by @ref duct_io_work_pending ahead of
                                   *  that wait, cleared by
                                   *  @ref duct_io_on_tick on the next pass. */
    duct_events_env_t  *events;
} duct_io_trunk_t;

/** @brief Message that puts an io thread's parked listeners back on its
 *  readiness set.
 *  One is embedded per io thread. @c latch keeps it at most once in flight: a
 *  poster's exchange from 0 to 1 pushes it, and its exec takes the latch back
 *  first.
 */
duct_msg_chain_decl(duct_msg_rx_resume, uint32_t _Atomic latch);

/** @brief Transport executor state. */
typedef struct duct_io {
    bool _Atomic           shutdown;
    unsigned _Atomic       started;       /**< Start rendezvous: 0 pending, 1
                                           *  running, 2 the events backend
                                           *  failed to start. */
    int                    cpu;           /**< Logical cpu this thread placed
                                           *  itself on, -1 unpinned. Written
                                           *  once ahead of the release store
                                           *  of @c started, which
                                           *  @ref duct_engine_thread_cpu
                                           *  relies on. */
    duct_io_trunk_t     trunk;
    duct_frame_rx_ctx_t    frame_rx;
    duct_wfq_route_t     route;
    pthread_t              thread;
    duct_timers_t          timers;
    duct_pre_conn_t       *pre_conns;       /**< Pending dial and
                                              *  probe-wait admissions. */
    duct_listener_t        *listeners;
    struct device_leg      *devices;      /**< Device legs this thread carries,
                                           *  linked through their @c prev and
                                           *  @c next. */
    duct_x_slot_pool_t    *held_pool;    /**< Pool the slots in @c held come
                                           *  from, the drained listener's; null
                                           *  while none are held. */
    duct_msg_rx_resume     rx_resume;    /**< Resume a stalled pool's slot
                                           *  return posts this thread. */
    struct timespec        sweep_at;     /**< Earliest time of the next sweep of this
                                           *  thread's slot pools. The tick tests it on
                                           *  each pass; no timer holds it. */
    uint32_t               held[duct_dgram_rx_batch], /**< Slots checked out for
                                           *  the batch in flight; an entry goes
                                           *  @c treiber_empty once the lane
                                           *  owns that slot. */
                           n_held;       /**< Entries of @c held in use. Zero
                                           *  between batches;
                                           *  @ref duct_io_rx_slots_acquire
                                           *  refuses to start on top of a
                                           *  non-zero one. */
    duct_ptr_t(uint8_t)    vnet_hdr;     /**< Owner of a vnet leg's header scratch.
                                           *  @ref duct_vnet_hdr_max bytes on the
                                           *  owner cacheline, released with the
                                           *  trunk. */
    duct_view_u8           vnet_hdr_span; /**< The scratch lent to a read: the
                                           *  reading conn's @c vnet_hdr_len at
                                           *  each reserve. The kernel writes the
                                           *  @c virtio_net_hdr here, the packet
                                           *  into the leg's ring. */
    duct_ptr_t(uint8_t)    dgram_scratch; /**< Read buffer of a datagram read that finds
                                           *  no RX slot. Null until the first such
                                           *  read, made by @ref duct_io_dgram_rx_scratch
                                           *  and freed by @ref duct_io_cleanup. */
#if DUCT_RUNTIME_STATS
    duct_io_rt_t           rtstats;
    bool                    spinning;       /**< True while the last pass
                                              *  was busy-spinning. */
#endif
} duct_io_t;

/** @brief State of the io module, one per process. */
typedef struct {
    duct_io_t *xports; /**< The io objects, one for each io thread; nullptr before the engine's init and after its cleanup. */
    unsigned   n_io;   /**< Entries in @c xports; 0 outside an engine's life. */
    unsigned _Atomic accept_parked; /**< Count of stream listeners parked for want of a
                                      *  descriptor, across io threads. A closing socket
                                      *  posts the resume while it is not 0. */
} duct_io_module_state_t;

static duct_io_module_state_t s_imod;

static thread_local duct_io_t *s_io_this;

#if DUCT_RUNTIME_STATS
const duct_io_rt_t *duct_io_rtstats(unsigned io_id)
{
    if (io_id >= s_imod.n_io)
        return nullptr;
    return &s_imod.xports[io_id].rtstats;
}

void duct_io_rtstat_wfq_push_full_inc(void)
{
    duct_rtstat_obj_inc(s_io_this, rtstats.wfq_push_full, 1);
}

void duct_io_rtstat_fence_push_full_inc(void)
{
    duct_rtstat_obj_inc(s_io_this, rtstats.fence_push_full, 1);
}

void duct_io_rtstat_busy_track(bool in_window)
{
    auto t = s_io_this;
    duct_rtstat_obj_inc(t, rtstats.loop_pass, 1);
    if (in_window != t->spinning) {
        if (in_window)
            duct_rtstat_obj_inc(t, rtstats.busy_enter, 1);
        else
            duct_rtstat_obj_inc(t, rtstats.busy_exit, 1);
        t->spinning = in_window;
    }
    if (in_window)
        duct_rtstat_obj_inc(t, rtstats.busy_spin, 1);
}
#endif

/** @brief Add @p tally to this io thread's segmented-write counters. */
static inline void s_rtstat_gso([[maybe_unused]] duct_x_gso_tally_t tally)
{
    duct_rtstat_obj_inc(s_io_this, rtstats.dgram_tx_gso_writes, tally.writes);
    duct_rtstat_obj_inc(s_io_this, rtstats.dgram_tx_gso_dgrams, tally.dgrams);
}

/** @brief Count one coalesced read of @p n bytes cut at @p seg on this io thread. */
static inline void s_rtstat_gro([[maybe_unused]] size_t n, [[maybe_unused]] size_t seg)
{
    duct_rtstat_obj_inc(s_io_this, rtstats.dgram_rx_gro_reads, 1);
    duct_rtstat_obj_inc(s_io_this, rtstats.dgram_rx_gro_dgrams, (n + seg - 1u) / seg);
}

/** A conn's tag encodes its pool index with a truncated generation above
 *  it as one plain integer. A slot that closes and is reused right away
 *  gets a fresh generation, so a stale tag left over from the same
 *  readiness batch resolves to nothing. The truncated generation
 *  outlasts any realistic recycle count for one slot.
 */
static constexpr unsigned xport_conn_tag_shift = 2u;
static constexpr unsigned xport_conn_gen_bits = 60u - hconn_idx_bits;
static constexpr uint64_t xport_conn_gen_mask = (1ull << xport_conn_gen_bits) - 1;
static constexpr uint64_t xport_conn_idx_mask = (1ull << hconn_idx_bits) - 1;

static inline uint64_t s_conn_tag_word(duct_conn_t *conn)
{
    uint64_t gen = duct_gen_req_gen(duct_atomic_load(duct_conn_gen_req(conn), relaxed)) & xport_conn_gen_mask;
    return (gen << (hconn_idx_bits + xport_conn_tag_shift))
         | ((uint64_t)duct_conn_idx_get(conn) << xport_conn_tag_shift);
}

/** @brief Resolves a packed idx+generation word back to its conn.
 *  @return nullptr if the slot was torn down and reissued since the
 *  word was minted.
 */
static inline duct_conn_t *s_conn_from_tag(void *tag)
{
    uint64_t word = (uint64_t)(uintptr_t)tag;
    auto conn = duct_conn_by_idx(
        (unsigned)((word >> xport_conn_tag_shift) & xport_conn_idx_mask));
    uint64_t gen = (word >> (hconn_idx_bits + xport_conn_tag_shift)) & xport_conn_gen_mask;
    uint64_t cur = duct_gen_req_gen(duct_atomic_load(duct_conn_gen_req(conn), acquire));
    return (cur & xport_conn_gen_mask) == gen ? conn : nullptr;
}

static bool s_conn_close(duct_io_t *t, duct_conn_t *conn, duct_close_reason_t reason);
static bool s_conn_register(duct_io_t *t, duct_conn_t *conn, bool promote);
static void s_close_fd(duct_sock_t fd, bool abort);
static duct_conn_t *
s_conn_prepare(duct_listener_t *listener, const duct_peer_t *peer,
               duct_view_u8 payload, const duct_proto_t *proto,
               duct_xport_t xport, duct_sock_t fd, bool promote,
               uint32_t worker_id, const duct_wire_t *leg_wire);
static void s_rx_start(duct_conn_t *conn);
static void s_tx_start(duct_conn_t *conn);
static void s_pre_conn_free(duct_io_t *t, duct_pre_conn_t *pre_conn);
static duct_exec_rc_t s_pre_conn_timeout_fire(void *arg);
static bool s_dgram_peer_find(duct_listener_t *listener, const duct_peer_t *peer,
                              duct_conn_t **out_conn, bool *out_candidate);
static void s_dgram_peer_candidate_clear(duct_conn_t *conn);
static void s_dgram_peer_add(duct_listener_t *listener, const duct_peer_t *peer, duct_conn_t *conn);
static void s_dgram_peer_add_at(duct_listener_t *listener, const duct_peer_t *peer,
                                duct_conn_t *conn, bool candidate);
static void s_dgram_peer_add_pending(duct_listener_t *listener, const duct_peer_t *peer);
static void s_dgram_peer_clear_pending(duct_listener_t *listener, const duct_peer_t *peer);
static duct_exec_rc_t s_preparse_exec_result(void *self);
static void s_io_abandon_listener_register(duct_msg_listener_register *m);
static inline void s_msg_push(unsigned io_id, duct_msg_t *msg);

/** @brief Post the message @p m to io thread @p io_id's trunk and kick it.
 *  @p m points at a message type of @c duct_msg_post_io; any other type stops the build.
 */
#define s_msg_post(io_id, m)                                                             \
    ({                                                                                   \
        static_assert(_Generic((m), duct_msg_post_io(duct_msg_arm) default: false),      \
                      "s_msg_post: not a message type of an io trunk");                  \
        s_msg_push((io_id), &(m)->msg);                                                  \
    })

static void s_req_do_tx_drain(duct_conn_t *conn);
static void s_req_do_rx_read(duct_conn_t *conn);
static void s_device_drive(duct_conn_t *conn);
static duct_device_ops_t *s_device_leg_new(const duct_device_ops_t *ops);
static struct device_leg *s_device_find(const duct_io_t *t, const void *handle);
static void s_device_link(duct_io_t *t, duct_conn_t *conn);
static void s_device_unlink(duct_io_t *t, duct_conn_t *conn);
static bool s_req_do_close(duct_io_t *t, duct_conn_t *conn);

int duct_io_sockaddr_from_peer(const duct_peer_t *peer, struct sockaddr_storage *out)
{
    if (peer->family == AF_INET6) {
        auto a6 = (struct sockaddr_in6 *)out;
        *a6 = (struct sockaddr_in6){ .sin6_family = AF_INET6, .sin6_port = htons(peer->port) };
        memcpy(&a6->sin6_addr, peer->addr.v6, sizeof a6->sin6_addr);
        return sizeof *a6;
    }
    auto a4 = (struct sockaddr_in *)out;
    *a4 = (struct sockaddr_in){ .sin_family = AF_INET, .sin_port = htons(peer->port) };
    memcpy(&a4->sin_addr, peer->addr.v4, sizeof a4->sin_addr);
    return sizeof *a4;
}

int duct_io_sockaddr_from_path(const char *path, struct sockaddr_storage *out)
{
    auto un = (struct sockaddr_un *)out;
    *un = (struct sockaddr_un){ .sun_family = AF_UNIX };
    memcpy(un->sun_path, path, strlen(path) + 1u);
    return sizeof *un;
}

duct_peer_t duct_io_peer_from_sockaddr(const struct sockaddr *sa)
{
    duct_peer_t peer = {};
    if (!sa)
        return peer;
    if (sa->sa_family == AF_INET6) {
        auto a6 = (const struct sockaddr_in6 *)sa;
        peer = (duct_peer_t){ .family = AF_INET6, .port = ntohs(a6->sin6_port) };
        memcpy(peer.addr.v6, &a6->sin6_addr, sizeof peer.addr.v6);
    } else if (sa->sa_family == AF_INET) {
        auto a4 = (const struct sockaddr_in *)sa;
        peer = (duct_peer_t){ .family = AF_INET, .port = ntohs(a4->sin_port) };
        memcpy(peer.addr.v4, &a4->sin_addr, sizeof peer.addr.v4);
    }
    return peer;
}

/** @brief Connected per-peer datagram socket, SO_REUSEPORT-bound to
 *  @p listen_fd's local address, connected to @p peer.
 *  @return duct_sock_bad on failure, with the fd already closed.
 */
static duct_sock_t s_dgram_peer_socket_open(duct_sock_t listen_fd, const duct_peer_t *peer)
{
    struct sockaddr_storage ss;
    socklen_t slen = (socklen_t)duct_io_sockaddr_from_peer(peer, &ss);
    duct_sock_t fd = duct_sock_bad;
    if (duct_xopen_dgram_peer(listen_fd, (struct sockaddr *)&ss, slen, &fd) != rc_ok)
        return duct_sock_bad;
    return fd;
}

/** @brief Wake @p trunk's thread for a message just pushed, if it may be
 *  parked.
 *  The seq_cst fence pairs with @ref duct_io_work_pending's: either that park
 *  check sees the push and the thread stays awake, or this sees the
 *  announcement and kicks. A kick lands in the events handle's own wake
 *  state, so one sent to a thread already awake costs a spurious wake only.
 */
static void s_kick(duct_io_trunk_t *trunk)
{
    atomic_thread_fence(memory_order_seq_cst);
    if (duct_atomic_load(&trunk->parked, relaxed))
        duct_events_kick(trunk->events);
}

/** @brief Acquire a conn slot and set it up on @p fd, its worker picked by slot
 *  index among this io thread's route.
 *  Its TX OLB takes @p proto's @c tx_olb_cap, raised to @c duct_conn_tx_olb_cap,
 *  which a conn without a protocol takes as is. Its socket takes @p proto's
 *  send options and @p tcp_congestion through @c duct_xset_sock_tx, once, and
 *  a TCP socket's receive buffer goes to the follow through
 *  @c duct_xset_sock_rx.
 *  @return nullptr with @p fd unwatched and closed when no slot or no ring is to be had. */
static duct_conn_t *s_conn_new(duct_sock_t fd, duct_xport_t xport, const duct_proto_t *proto,
                               const char *tcp_congestion)
{
    auto t = s_io_this;
    auto conn = duct_conn_acquire();
    if (!conn) {
        s_close_fd(fd, false);
        return nullptr;
    }
    auto cfg = proto ? duct_proto_cfg_of(proto) : nullptr;
    size_t tx_cap = cfg ? duct_max(cfg->tx_olb_cap, duct_conn_tx_olb_cap) : duct_conn_tx_olb_cap;
    if (duct_conn_setup(conn, fd, xport, tx_cap) != rc_ok) {
        s_close_fd(fd, false);
        duct_conn_release(conn);
        return nullptr;
    }
    duct_xset_sock_tx(duct_x_sock_tx_of(conn->tx_buf), fd, xport,
                      cfg ? cfg->tcp_notsent_lowat : 0u,
                      cfg ? cfg->tcp_notsent_lowat_us : 0u, tcp_congestion);
    duct_xset_sock_rx(duct_x_sock_rx_of(conn->rx_buf), fd, xport);
    conn->worker_id = duct_conn_idx_get(conn) % t->route.n_workers;
    return conn;
}

static bool s_listener_register(duct_io_t *t, duct_listener_t *listener)
{
    if (!listener || listener->listen_fd == duct_sock_bad)
        return false;
    return duct_events_watch(t->trunk.events, listener->listen_fd, io_tag_listener, listener,
                             x_tcp /* unused for io_tag_listener */);
}

/** @brief Arm @p conn's fd with the events backend and put it on this thread's
 *  live-conn list.
 *
 *  @p promote takes an fd already watched as @c io_tag_pre_conn — a resolved
 *  dial, a probe-wait retry, or an async pre-parse that left it registered —
 *  and replaces that narrower interest in place. A fresh watch is the other
 *  case, and an @c x_inter conn never reaches it: that leg has no fd and
 *  attaches through a separate path.
 *
 *  @return @c false with nothing linked and no stat counted.
 */
static bool s_conn_register(duct_io_t *t, duct_conn_t *conn, bool promote)
{
    if (!conn || conn->fd == duct_sock_bad)
        return false;
    assert(conn->worker_id != conn_worker_none);
    auto tag = (void *)(uintptr_t)s_conn_tag_word(conn);
    bool armed;
    if (promote)
        armed = duct_events_promote(t->trunk.events, conn->fd, tag);
    else {
        assert(conn->xport_type != x_inter);
        armed = duct_events_watch(t->trunk.events, conn->fd, io_tag_conn, tag,
                                  conn->xport_type);
    }
    if (!armed)
        return false;
    conn->io_id = t->route.thread_id;
    duct_conn_io_list_link(conn, t->route.thread_id);
    duct_rtstat_obj_inc(t, rtstats.conns_added, 1);
    return true;
}

/** @brief Reclaim @p conn that failed before going live, its fd's watch dropped first.
 *  A promoted fd still carries the io_tag_pre_conn watch, which the close in
 *  @c duct_conn_teardown leaves behind. */
static void s_conn_unwatch_reclaim(duct_io_t *t, duct_conn_t *conn)
{
    duct_events_unwatch(t->trunk.events, conn->fd, nullptr);
    duct_conn_reclaim(conn);
}

/** @brief Propagate a failed outbound dial to whichever worker owns
 *  @p seed's target — a leg's session, or a fresh session's own protocol.
 */
static void s_connect_error(const duct_wfq_route_t *route,
                            duct_conn_intent_t seed, duct_result_t err)
{
    if (seed.kind == intent_leg) {
        auto leg_tok = (duct_session_handle_t){ .word = seed.leg.hsession };
        auto target = duct_session_by_handle(leg_tok);
        if (!target)
            return;
        auto worker_id = duct_atomic_load(&target->worker_id, acquire);
        duct_worker_post_connect_leg_error(worker_id, DUCT_CAST(duct_session_handle_t, word, &seed.leg.hsession), err);
        return;
    }
    duct_worker_post_connect_error(route->thread_id % route->n_workers,
                                   seed.proto, seed.user_ctx, err);
}

/** @brief Bind @p conn's wire and join it to @p seed's target — a leg's
 *  session, or open a fresh one.
 *  Both posts carry @p seed's prefix to the worker, whose codec takes it as it
 *  is built.
 */
static bool s_connect_ok(duct_conn_t *conn, duct_conn_intent_t seed)
{
    conn->ctx = nullptr;
    if (duct_conn_bind_wire(conn, seed.proto, nullptr) != rc_ok) {
        duct_io_conn_close(conn, close_internal_error);
        return false;
    }
    if (seed.kind == intent_leg) {
        auto leg_tok = (duct_session_handle_t){ .word = seed.leg.hsession };
        auto target = duct_session_by_handle(leg_tok);
        if (!target) {
            duct_io_conn_close(conn, close_internal_error);
            return false;
        }
        conn->worker_id = duct_atomic_load(&target->worker_id, acquire);
        if (duct_sessions_post_conn_join(conn, leg_tok, seed.leg.conn_id, &(duct_peer_t){},
                                         seed.tx_prefix))
            return true;
        duct_io_conn_close(conn, close_internal_error);
        return false;
    }
    if (duct_sessions_post_session_open(conn, seed.proto, seed.user_ctx, seed.tx_prefix, true))
        return true;
    duct_io_conn_close(conn, close_internal_error);
    return false;
}

/* Ingress lane capacity for one x_inter or x_udp_shared conn. A reservation
 * this refuses drops the datagram outright, counted as dgram_shared_rx_drop,
 * so the size bounds how far the io thread may run ahead of its worker. */
static constexpr size_t inter_lane_cap = kbytes(144u);

/** @brief Give @p conn its ingress lane, bound to its worker's wake latch.
 *  @c conn->worker_id is read here, so it must already be final.
 *  @return @c false with the lane left null and nothing else touched.
 */
static bool s_inter_lane_attach(duct_conn_t *conn)
{
    conn->inter_lane = duct_vmq_mpsc_new(1u, (size_t[]){ inter_lane_cap });
    if (!conn->inter_lane)
        return false;
    duct_vmq_bind_wake(duct_mpsc_ctrl(conn->inter_lane, 0u),
                       duct_worker_wake_latch(conn->worker_id));
    return true;
}

/** @brief Acquire an @c x_inter conn and give it the lane its worker wakes on.
 *
 *  What both attach paths share and nothing more: no @c duct_conn_setup (no
 *  OLBs — TX egresses through the host, RX lands inline on the lane), no wire
 *  bind, no events registration. Whatever a caller owns beyond the conn —
 *  the device path's @c duct_device_ops_t and its release discipline — stays
 *  with that caller.
 *
 *  @return the conn, or @c nullptr with nothing left allocated.
 */
static duct_conn_t *
s_inter_conn_create(const duct_wfq_route_t *route, duct_session_t *target)
{
    auto conn = duct_conn_acquire();
    duct_do_if(!conn, return nullptr);
    conn->xport_type = x_inter;
    conn->io_id = route->thread_id;
    conn->worker_id = duct_atomic_load(&target->worker_id, acquire);
    if (!s_inter_lane_attach(conn)) {
        duct_conn_release(conn);
        return nullptr;
    }
    return conn;
}

/** @brief Create an @c x_inter conn (no fd, no OLBs) and join it to
 *  @p tok's session at @p conn_id.
 */
static void s_attach_inter(const duct_wfq_route_t *route, const duct_session_handle_t *tok,
                           duct_conn_id_t conn_id, [[maybe_unused]] const duct_proto_t *proto)
{
    auto stok = *tok;
    auto target = duct_session_by_handle(stok);
    duct_do_if(!target, return);
    auto conn = s_inter_conn_create(route, target);
    duct_do_if(!conn, return);
    if (!duct_sessions_post_conn_join(conn, stok, conn_id, &(duct_peer_t){}, (duct_seal_prefix_t){}))
        duct_io_conn_close(conn, close_internal_error);
}

/** @brief Create a device-backed x_inter conn on the io thread and join it to
 *  @p tok's session at @p conn_id.
 *
 *  A handle one of this thread's device legs already holds is refused before
 *  any conn exists. Releases @p ops's ctx on every failure that leaves no conn
 *  behind, and hands it to @c conn->ctx otherwise — from there
 *  duct_conn_teardown is the one release site, which is why the watch failure
 *  reclaims without releasing. @c conn->ctx doubles as the device
 *  discriminator: a host-driven x_inter conn leaves it null.
 */
static void s_attach_device(const duct_wfq_route_t *route,
                            const duct_session_handle_t *tok,
                            duct_conn_id_t conn_id,
                            const duct_device_ops_t *ops,
                            [[maybe_unused]] const duct_proto_t *proto)
{
    auto stok = *tok;
    auto target = duct_session_by_handle(stok);
    duct_do_if(!target, ops->release(ops->ctx); return);
    bool occupied = duct_session_conn_at(target, conn_id).word != 0u;
    duct_do_if(occupied, ops->release(ops->ctx); return);
    auto dup = s_device_find(s_io_this, ops->wait_handle);
    duct_do_if(dup, ops->release(ops->ctx); return);
    auto conn = s_inter_conn_create(route, target);
    duct_do_if(!conn, ops->release(ops->ctx); return);
    conn->ctx = s_device_leg_new(ops);
    duct_do_if(!conn->ctx,
               duct_conn_reclaim(conn); ops->release(ops->ctx); return);
    if (!duct_events_watch_device(s_io_this->trunk.events, ops->wait_handle,
                                  (void *)(uintptr_t)s_conn_tag_word(conn))) {
        duct_conn_reclaim(conn);
        return;
    }
    s_device_link(s_io_this, conn);
    duct_conn_io_list_link(conn, route->thread_id);
    if (!duct_sessions_post_conn_join(conn, stok, conn_id, &(duct_peer_t){}, (duct_seal_prefix_t){}))
        duct_io_conn_close(conn, close_internal_error);
}

/** @brief Create an x_udp_shared conn on a pool slot alone.
 *  No fd and no OLBs: the wire is bound and the ctx points back at
 *  @p listener, whose TX outbox it sends through. @p worker_id comes from the
 *  joining leg's session when given; a new session runs on the listener's
 *  worker where the port spreads, a shared bind then holding one node per
 *  worker, and by conn slot otherwise. Posting the session open or join is the
 *  caller's job.
 */
static duct_conn_t *
s_dgram_shared_conn_new(const duct_wfq_route_t *route, duct_listener_t *listener,
                        const duct_peer_t *peer, const duct_proto_t *proto,
                        uint32_t worker_id)
{
    auto conn = duct_conn_acquire();
    duct_do_if(!conn, return nullptr);
    conn->xport_type = x_udp_shared;
    conn->io_id = route->thread_id;
    conn->worker_id = worker_id != conn_worker_none ? worker_id
                    : duct_x_port_sharing == x_port_share_spread ? listener->worker
                    : duct_conn_idx_get(conn) % route->n_workers;
    if (!s_inter_lane_attach(conn)) {
        duct_conn_release(conn);
        return nullptr;
    }
    if (duct_conn_bind_wire(conn, proto, nullptr) != rc_ok) {
        duct_conn_reclaim(conn);
        return nullptr;
    }
    conn->ctx = duct_new(duct_dgram_shared_ctx_t);
    if (!conn->ctx) {
        duct_conn_reclaim(conn);
        return nullptr;
    }
    auto dctx = (duct_dgram_shared_ctx_t *)conn->ctx;
    *dctx = (duct_dgram_shared_ctx_t){
        .listener = listener, .peer = *peer,
    };
    ++listener->pre_conn_refs;
    return conn;
}

/** @brief One frame parsed directly inside the reserved inter_lane message.
 *
 *  @c s_dgram_shared_route reserves that message, and @c payload aliases its
 *  memory, per the @c on_parse contract.
 */
typedef struct s_dgram_shared_frame {
    duct_view_u8         payload;
    duct_stream_id_t   stream_id;
    duct_frame_flags_t flags;
} dgram_shared_frame_t;

/** @brief Parse-loop cap, sized for a jumbo-MTU datagram packed with the
 *  smallest realistic sub-frame: about 98 in the worst case, with
 *  headroom to 160. A datagram carrying more sub-frames than this
 *  silently drops the remainder.
 */
static constexpr unsigned s_dgram_shared_frame_cap = 160u;

/** @brief Parse every frame out of the record-header-prefixed @p scratch,
 *  in place. @return frame count, @p frames filled that many.
 */
static unsigned s_dgram_shared_parse(duct_conn_t *conn, uint8_t *scratch, size_t scratch_bytes,
                                     dgram_shared_frame_t *frames)
{
    unsigned n = 0u;
    size_t off = 0u;
    while (off < scratch_bytes && n < s_dgram_shared_frame_cap) {
        duct_view_u8 input = { .data = scratch + off, .size = scratch_bytes - off };
        duct_frame_t frame = {};
        size_t consumed = 0u,
               needed = 0u;
        /* A datagram is atomic, so rc_again here always means truncated or
         * malformed input. Stop, keep what already parsed cleanly, drop
         * the remainder. */
        auto rc = conn->wire->on_parse(conn->wire, input, &frame, conn->wire_parser, &consumed, &needed);
        if (rc != rc_ok || consumed == 0u)
            break;
        frames[n++] = (dgram_shared_frame_t){
            .payload = frame.payload, .stream_id = frame.stream_id, .flags = frame.flags,
        };
        off += consumed;
    }
    return n;
}

/** @brief Fill @p stage's descriptors from @p frames, offsets set to where
 *  each payload actually landed, and publish.
 *  Those offsets count from @p base: the batch itself when the bytes ride
 *  inline, the slot when @c stage->rx_pool carries them.
 */
static void s_dgram_shared_publish(duct_conn_t *conn, const duct_peer_t *peer,
                                   duct_msg_inter_batch_t *stage, const duct_vmq_lane_t *ln,
                                   duct_vmq_reserve_pos_t *pos, const dgram_shared_frame_t *frames,
                                   unsigned n_frames, const uint8_t *base)
{
    auto ch = duct_conn_handle_get(conn);
    stage->conn = ch.word;
    stage->n = n_frames;
    stage->peer = *peer;
    auto pkts = duct_msg_inter_pkts(stage);
    for (unsigned i = 0u; i < n_frames; ++i)
        pkts[i] = (duct_msg_inter_pkt_t){
            .offset = (uint32_t)((const uint8_t *)frames[i].payload.data - base),
            .len = (uint32_t)frames[i].payload.size,
            .stream_id = frames[i].stream_id, .flags = frames[i].flags,
        };
    duct_vmq_publish(ln, pos);
    duct_worker_inter_arm(conn->worker_id, duct_conn_idx_get(conn));
    duct_vmq_notify(ln->ctrl);
}

/** @brief Reserve @p total bytes on @p ln as an inter_msg_batch.
 *  Counts the drop here, so a caller adds no counting of its own.
 *  @return the batch, unpublished, or nullptr on a refused reservation.
 */
static duct_msg_inter_batch_t *
s_dgram_shared_reserve(const duct_vmq_lane_t *ln, size_t total, duct_vmq_reserve_pos_t *pos)
{
    duct_vmq_push_rc_t rc;
    auto stage = (duct_msg_inter_batch_t *)
        duct_vmq_reserve(ln, inter_msg_batch, 0u, total, pos, &rc);
    if (!stage) {
        duct_rtstat_obj_inc(s_io_this, rtstats.dgram_shared_rx_drop, 1);
        return nullptr;
    }
    stage->rx_pool = nullptr;
    stage->pkts_off = (uint32_t)sizeof(duct_msg_inter_batch_t);
    stage->holds_off = 0u;
    return stage;
}

/** @brief Descriptor bytes for an @p n_frames inter batch, header included.
 *  @return true on overflow, @p out then unusable. */
static bool s_inter_desc_bytes(unsigned n_frames, size_t *out)
{
    *out = 0u;
    return duct_ckd_mul(out, (size_t)n_frames, sizeof(duct_msg_inter_pkt_t))
        || duct_ckd_add(out, *out, sizeof(duct_msg_inter_batch_t));
}

/** @brief Find the slot of @p pool whose payload starts at @p ptr.
 *  The read spans a pass hands out are slices of one allocation, so the index
 *  falls out of the offset, and the exact-payload test rejects an interior
 *  pointer the division alone maps to a real slot. @c treiber_empty for any
 *  other pointer, and for a null @p pool, outside a pass that holds slots.
 */
static uint32_t
s_rx_slot_of_payload(const duct_x_slot_pool_t *pool, const void *ptr)
{
    if (!pool || !duct_x_slot_pool_owns(pool, ptr))
        return treiber_empty;
    uint32_t idx = duct_x_slot_index(pool, ptr);
    return ptr == duct_x_slot_payload(pool, idx) ? idx : treiber_empty;
}

/** @brief Hand @p slot to @p stage: the batch resolves its packets through the
 *  pool, and @p t stops counting the slot as checked out so the pass-end
 *  release leaves it with the lane.
 */
static void s_dgram_slot_lend(duct_io_t *t, duct_msg_inter_batch_t *stage, uint32_t slot)
{
    stage->rx_pool = t->held_pool;
    stage->rx_slot = slot;
    for (uint32_t i = 0u; i < t->n_held; ++i)
        if (t->held[i] == slot)
            t->held[i] = treiber_empty;
    duct_rtstat_obj_inc(t, rtstats.dgram_rx_slot_route, 1);
}

/** @brief Route @p data by reference when it was read into one of this
 *  thread's checked-out slots, publishing descriptors alone and moving that
 *  slot to the lane.
 *
 *  Pointer identity decides: a datagram read through other paths
 *  takes the copying path instead. The record header fills the gap preceding
 *  the payload, allowing in-place parsing over the slot.
 *
 *  @return true once this datagram is accounted for, dropped included; false
 *          leaves it entirely to the caller.
 */
static bool
s_dgram_shared_route_slot(duct_conn_t *conn, const duct_peer_t *peer, const duct_view_u8 *data)
{
    auto t = s_io_this;
    uint32_t slot = s_rx_slot_of_payload(t->held_pool, data->data);
    if (slot == treiber_empty)
        return false;
    auto base = (uint8_t *)duct_x_slot_data(t->held_pool, slot);

    duct_dgram_rec_hdr_encode(base, data->size);
    size_t scratch_bytes = duct_dgram_record_hdr_size + data->size;

    dgram_shared_frame_t frames[s_dgram_shared_frame_cap];
    unsigned n_frames = s_dgram_shared_parse(conn, base, scratch_bytes, frames);
    duct_do_if(!n_frames, return true);

    size_t desc_bytes;
    bool of = s_inter_desc_bytes(n_frames, &desc_bytes);
    duct_do_if(of, duct_rtstat_obj_inc(t, rtstats.dgram_shared_rx_drop, 1); return true);

    auto ln = duct_mpsc_lane(conn->inter_lane, 0u);
    duct_vmq_reserve_pos_t pos;
    auto stage = s_dgram_shared_reserve(&ln, desc_bytes, &pos);
    duct_do_if(!stage, return true);

    s_dgram_slot_lend(t, stage, slot);
    s_dgram_shared_publish(conn, peer, stage, &ln, &pos, frames, n_frames, base);
    return true;
}

/** @brief Check a datagram of @p size against @p conn's wire @c max_frame,
 *  counting the drop when it is past it.
 *  A wire declaring @c max_frame 0, or no wire at all, bounds nothing.
 *  @c on_parse cannot be the one to refuse such a datagram: @c rc_invalid_arg
 *  there is a read-wire protocol error, which ends the conn, where a datagram
 *  costs only itself.
 *  @return true for a datagram past the bound; the caller drops it. */
static bool s_dgram_rx_oversize(const duct_conn_t *conn, size_t size)
{
    if (!conn->wire || !conn->wire->max_frame || size <= conn->wire->max_frame)
        return false;
    duct_rtstat_obj_inc(s_io_this, rtstats.dgram_rx_oversize, 1);
    return true;
}

/** @brief Check a datagram of @p len against @p conn's wire bounds.
 *  @return false for @ref duct_dgram_len_truncated, under
 *          @ref duct_wire_dgram_min, and past @c max_frame, which
 *          @ref s_dgram_rx_oversize counts. */
static bool s_dgram_rx_admits(const duct_conn_t *conn, size_t len)
{
    return len != duct_dgram_len_truncated && len >= duct_wire_dgram_min(conn->wire)
        && !s_dgram_rx_oversize(conn, len);
}

/** @brief Wire-parses one already-classified datagram on the io thread
 *  and pushes it onto its conn's inter_lane as one inter batch. Every
 *  path that already knows which x_udp_shared conn a datagram belongs
 *  to converges here to route it in.
 */
static void s_dgram_shared_route(duct_conn_t *conn, const duct_peer_t *peer, const duct_view_u8 *data)
{
    duct_do_if(!conn->wire || !conn->wire_parser, return);
    /* Bound before anything is spent on it: past this line a datagram takes a
     * lane reservation of its own size, or an RX slot held until the worker
     * drains, so oversize garbage occupies either at the sender's choosing. */
    if (s_dgram_rx_oversize(conn, data->size))
        return;

    if (s_dgram_shared_route_slot(conn, peer, data))
        return;

    uint8_t rhdr[duct_dgram_record_hdr_size];
    duct_dgram_rec_hdr_encode(rhdr, data->size);
    size_t scratch_bytes = 0u;
    bool scratch_of = duct_ckd_add(&scratch_bytes, sizeof rhdr, data->size);
    duct_do_if(scratch_of, return);

    /* Reserve for one frame initially and parse directly into the reservation.
     * Multiplexed datagrams expand the slot in place to preserve parser replay
     * state. Descriptors follow payload data. */
    static constexpr size_t payload_off = sizeof(duct_msg_inter_batch_t);
    size_t desc_off = 0u;
    bool of = duct_ckd_add(&desc_off, payload_off, scratch_bytes);
    duct_do_if(of, return);
    desc_off = duct_align_up(desc_off, 8u);
    size_t total_1 = 0u;
    bool total_of = duct_ckd_add(&total_1, desc_off, sizeof(duct_msg_inter_pkt_t));
    duct_do_if(total_of, return);

    auto ln = duct_mpsc_lane(conn->inter_lane, 0u);
    duct_vmq_reserve_pos_t pos;
    auto stage = s_dgram_shared_reserve(&ln, total_1, &pos);
    /* A refused reservation drops the datagram: this path carries the loss
     * the way UDP does, with nothing queued for a later attempt. */
    duct_do_if(!stage, return);

    duct_rtstat_obj_inc(s_io_this, rtstats.dgram_rx_slot_copy, 1);
    auto scratch = (uint8_t *)stage + payload_off;
    memcpy(scratch, rhdr, sizeof rhdr);
    if (data->size)
        memcpy(scratch + sizeof rhdr, data->data, data->size);

    dgram_shared_frame_t frames[s_dgram_shared_frame_cap];
    unsigned n_frames = s_dgram_shared_parse(conn, scratch, scratch_bytes, frames);
    if (n_frames == 0u)
        return;

    if (n_frames > 1u) {
        size_t desc_bytes = 0u,
               total = 0u;
        of = duct_ckd_mul(&desc_bytes, (size_t)n_frames, sizeof(duct_msg_inter_pkt_t))
          || duct_ckd_add(&total, desc_off, desc_bytes);
        duct_do_if(of, duct_rtstat_obj_inc(s_io_this, rtstats.dgram_shared_rx_drop, 1); return);
        auto grown = s_dgram_shared_reserve(&ln, total, &pos);
        duct_do_if(!grown, return);
        if (grown != stage) {
            auto moved = (uint8_t *)grown + payload_off;
            memmove(moved, scratch, scratch_bytes);
            ptrdiff_t shift = moved - scratch;
            for (unsigned i = 0u; i < n_frames; ++i)
                frames[i].payload.data = (uint8_t *)frames[i].payload.data + shift;
            stage = grown;
        }
    }
    stage->pkts_off = (uint32_t)desc_off;
    stage->holds_off = 0u;
    s_dgram_shared_publish(conn, peer, stage, &ln, &pos, frames, n_frames,
                           (const uint8_t *)stage);
}

/** @brief Route a whole coalesced read by reference: @p seg-sized datagrams
 *  packed back to back in one slot become one inter batch of @p seg-sized
 *  descriptors, its tail descriptor short whenever the last datagram is.
 *
 *  A slot is the unit of ownership the lane takes, so splitting the read and
 *  routing each datagram on its own leaves every one behind the first with an
 *  interior pointer and a copy. The batch message already addresses several
 *  frames of one slot by offset, which lets all of them ride the one slot
 *  instead.
 *
 *  The wire gate buys that: no record header is written and @c on_parse
 *  never runs, so this is exact only where the record prefix is the wire's
 *  whole per-datagram header and a record therefore parses to its own body.
 *  Every other wire falls back to the caller's split, the same shape
 *  @c s_dgram_pack_header answering 0 gives the TX side.
 *
 *  @return true once the read is accounted for, dropped included; false leaves
 *          it entirely to the caller.
 */
static bool
s_dgram_shared_route_group(duct_listener_t *listener, const duct_peer_t *peer,
                           duct_view_u8 *data, uint32_t seg)
{
    duct_conn_t *conn = nullptr;
    bool known = s_dgram_peer_find(listener, peer, &conn, nullptr);
    if (!known || !conn || conn->xport_type != x_udp_shared)
        return false;
    if (!conn->wire || !conn->wire_parser)
        return false;
    bool records = duct_wire_records(conn->wire);
    if (!records)
        return false;
    if (conn->wire->max_frame && seg > conn->wire->max_frame)
        return false;

    unsigned n_frames = (unsigned)((data->size + seg - 1u) / seg);
    if (n_frames > s_dgram_shared_frame_cap)
        return false;

    auto t = s_io_this;
    uint32_t slot = s_rx_slot_of_payload(t->held_pool, data->data);
    if (slot == treiber_empty)
        return false;

    size_t desc_bytes;
    bool of = s_inter_desc_bytes(n_frames, &desc_bytes);
    duct_do_if(of, return false);

    auto ln = duct_mpsc_lane(conn->inter_lane, 0u);
    duct_vmq_reserve_pos_t pos;
    auto stage = s_dgram_shared_reserve(&ln, desc_bytes, &pos);
    /* One reservation carries the whole read, so a refusal loses every datagram
     * in it; the reserve counted one, the rest are counted here. */
    duct_do_if(!stage, duct_rtstat_obj_inc(t, rtstats.dgram_shared_rx_drop,
                                           n_frames - 1u); return true);

    dgram_shared_frame_t frames[s_dgram_shared_frame_cap];
    for (unsigned i = 0u; i < n_frames; ++i) {
        size_t off = (size_t)i * seg;
        size_t take = duct_min(data->size - off, (size_t)seg);
        frames[i] = (dgram_shared_frame_t){
            .payload = { .data = data->data + off, .size = take },
            .stream_id = duct_stream_id_default, .flags = fl_frame_none,
        };
    }
    s_dgram_slot_lend(t, stage, slot);
    s_dgram_shared_publish(conn, peer, stage, &ln, &pos, frames, n_frames,
                           (const uint8_t *)duct_x_slot_data(t->held_pool, slot));
    return true;
}

/** @brief Light-attach done: route the first datagram and alias the peer in
 *  dgram_peers.
 *
 *  Shared by @c s_dgram_shared_admit_join and @c s_dgram_shared_admit_open
 *  once each has posted its own way.
 */
static void
s_dgram_shared_admit_tail(duct_listener_t *listener, const duct_peer_t *peer,
                          const duct_view_u8 *data, duct_conn_t *conn)
{
    s_dgram_shared_route(conn, peer, data);
    s_dgram_peer_add(listener, peer, conn);
}

/** @brief resolve_join(empty-slot) tail for fl_proto_dgram_shared. */
static void
s_dgram_shared_admit_join(const duct_wfq_route_t *route, duct_listener_t *listener,
                          const duct_peer_t *peer, const duct_view_u8 *data, const duct_proto_t *proto,
                          uint32_t worker_id, duct_session_handle_t tok, duct_conn_id_t conn_id)
{
    auto conn = s_dgram_shared_conn_new(route, listener, peer, proto, worker_id);
    if (!conn)
        return;
    if (!duct_sessions_post_conn_join(conn, tok, conn_id, peer, (duct_seal_prefix_t){})) {
        duct_io_conn_close(conn, close_internal_error);
        return;
    }
    s_dgram_shared_admit_tail(listener, peer, data, conn);
}

/** @brief resolve_new tail for fl_proto_dgram_shared. */
static void
s_dgram_shared_admit_open(const duct_wfq_route_t *route, duct_listener_t *listener,
                          const duct_peer_t *peer, const duct_view_u8 *data, const duct_proto_t *proto,
                          uint32_t worker_id, void *user_ctx)
{
    auto conn = s_dgram_shared_conn_new(route, listener, peer, proto, worker_id);
    if (!conn)
        return;
    if (!duct_sessions_post_session_open(conn, proto, user_ctx, (duct_seal_prefix_t){}, false)) {
        duct_io_conn_close(conn, close_internal_error);
        return;
    }
    s_dgram_shared_admit_tail(listener, peer, data, conn);
}

/** @brief Create an @p xport conn atop a caller-owned @p fd and join it
 *  to @p tok's session at @p conn_id.
 */
static void s_attach_fd(const duct_session_handle_t *tok,
                        duct_conn_id_t conn_id, duct_sock_t fd,
                        duct_xport_t xport, const duct_proto_t *proto,
                        const duct_wire_t *leg_wire)
{
    auto stok = *tok;
    auto target = duct_session_by_handle(stok);
    if (!target) {
        duct_sock_close(fd);
        return;
    }
    /* A reactive backend's drive loop needs a would-block signal to detect
     * exhaustion, so this forces non-blocking regardless of what the
     * caller already set. */
    duct_xset_nonblock(fd);
    duct_peer_t none = {};
    auto conn = s_conn_prepare(nullptr, &none, (duct_view_u8){}, proto,
                               xport, fd, false,
                               duct_atomic_load(&target->worker_id, acquire),
                               leg_wire);
    duct_do_if(!conn, return);
    if (!duct_sessions_post_conn_join(conn, stok, conn_id, &none, (duct_seal_prefix_t){}))
        duct_io_conn_close(conn, close_internal_error);
}

/** @brief Create an @c x_raw_packet conn atop a caller-owned @p fd and open a session on it.
 *  @p user_ctx goes to @c on_session_open; a conn that cannot be set up reaches
 *  @p proto's @c on_error with @c rc_no_memory.
 */
static void s_open_packet_fd(duct_io_t *t, duct_sock_t fd, duct_proto_t *proto, void *user_ctx)
{
    /* The events backend reads the fd to would-block, so it is made non-blocking
     * whatever the caller set. */
    duct_xset_nonblock(fd);
    duct_peer_t none = {};
    auto conn = s_conn_prepare(nullptr, &none, (duct_view_u8){}, proto, x_raw_packet, fd, false,
                               conn_worker_none, nullptr);
    if (conn && duct_sessions_post_session_open(conn, proto, user_ctx, (duct_seal_prefix_t){}, true))
        return;
    if (conn)
        duct_io_conn_close(conn, close_internal_error);
    s_connect_error(&t->route, (duct_conn_intent_t){ .kind = intent_session, .proto = proto,
                                                     .xport = x_raw_packet, .user_ctx = user_ctx },
                    rc_no_memory);
}

/** @brief Ask @p cfg's preparse, and answer with what the engine will act on.
 *
 *  A @c resolve_join naming a leg past @c duct_session_max_legs comes back
 *  @c resolve_reject, and so does a lead past @p data. The bounds belong here
 *  because this is where an author's answer enters: @ref duct_session_conn_at
 *  indexes @c conns with no bound of its own, the io-side readers of that slot
 *  take the leg id straight from this return, and a seed starts past the lead.
 *  @p out_lead takes the lead of a @c resolve_new or @c resolve_join alone, so
 *  a fallback match after this call inherits none.
 */
static duct_resolve_disposition_t
s_preparse_call(const duct_proto_cfg_t *cfg, const duct_peer_t *peer, duct_view_u8 data,
                duct_handle_t *out_tok, duct_conn_id_t *out_conn_id, void **out_user_ctx,
                size_t *out_lead)
{
    size_t lead = 0u;
    auto disp = cfg->preparse(cfg->preparse_ctx, peer, data,
                              out_tok, out_conn_id, out_user_ctx, &lead);
    if (disp != resolve_join && disp != resolve_new)
        return disp;
    if (lead > data.size || (disp == resolve_join && *out_conn_id >= duct_session_max_legs))
        return resolve_reject;
    *out_lead = lead;
    return disp;
}

/** @brief Classification bytes of @p m as a buffer.
 *  A message that carries none answers a null @c data.
 */
static duct_view_u8 s_preparse_payload(duct_msg_pre_parse *m)
{
    return m->payload_len ? (duct_view_u8){ .data = m->payload, .size = m->payload_len } : (duct_view_u8){};
}

/** @brief Worker-side classification for one async pre-parse round trip.
 *
 *  Reposts @p self back to its listener's I/O thread on every outcome,
 *  including a reject or no-match, so the I/O side can clear the pending
 *  marker it set on that peer before posting this job.
 *
 *  @c listener stays valid here: a reference taken on it before this job
 *  was posted keeps it alive for the round trip's whole duration.
 */
static duct_exec_rc_t s_preparse_exec(void *self)
{
    auto msg = (duct_msg_pre_parse *)self;
    auto listener = msg->listener;

    const duct_proto_t *matched = nullptr;
    duct_resolve_disposition_t disp = resolve_not_me;
    duct_handle_t out_tok = {};
    duct_conn_id_t out_conn_id = duct_conn_id_primary;
    void *out_user_ctx = nullptr;
    size_t lead = 0u;

    for (unsigned i = 0u; i < listener->n_protos; ++i) {
        auto proto = listener->protos[i];
        auto cfg = &proto->cfg;
        if (!cfg->preparse || cfg->preparse_mode != resolve_async)
            continue;
        disp = s_preparse_call(cfg, &msg->peer, s_preparse_payload(msg),
                               &out_tok, &out_conn_id, &out_user_ctx, &lead);
        if (disp == resolve_hold)
            disp = resolve_not_me;
        if (disp != resolve_not_me) {
            matched = proto;
            break;
        }
    }

    /* No async match: fall back to the first preparse==NULL proto (always new). */
    if (disp == resolve_not_me) {
        for (unsigned i = 0u; i < listener->n_protos; ++i) {
            auto proto = listener->protos[i];
            if (!proto->cfg.preparse) {
                matched = proto;
                disp = resolve_new;
                out_user_ctx = proto->cfg.user_ctx;
                break;
            }
        }
    }

    msg->decision = disp;
    msg->lead = (uint16_t)lead;
    msg->proto = matched;
    msg->join_tok = out_tok;
    msg->join_conn_id = out_conn_id;
    msg->user_ctx = out_user_ctx;
    msg->msg.exec_fn = s_preparse_exec_result;
    s_msg_post(listener->io_id, msg);
    return exec_done;
}

/** @brief One async pre-parse job, posted to @p listener's home worker.
 *  Takes a reference on @p listener for the round trip's whole duration:
 *  neither the probe fd nor the datagram listener socket keeps it
 *  referenced while the job travels from I/O to worker and back. @p peek is
 *  copied behind the message and the caller keeps its own bytes.
 */
static bool s_preparse_post(duct_listener_t *listener, duct_sock_t fd,
                                       const duct_peer_t *peer, duct_view_u8 peek,
                                       bool fd_registered)
{
    auto msg = duct_msg_new_kind(pre_parse, s_preparse_exec, peek.size);
    if (!msg)
        return false;
    msg->listener = listener;
    msg->fd = fd;
    msg->peer = peer ? *peer : (duct_peer_t){};
    msg->payload_len = (uint32_t)peek.size;
    if (peek.size)
        memcpy(msg->payload, peek.data, peek.size);
    msg->fd_registered = fd_registered;
    if (!duct_worker_post_ctrl(listener->worker, msg)) {
        /* Drop: the caller still owns fd and must release it. */
        duct_msg_done(msg);
        return false;
    }
    ++listener->pre_conn_refs;
    /* Datagram only: marks this peer pending so a retransmit arriving
     * during this round trip is not classified again as a brand-new peer.
     * Cleared once the decision lands, whatever it turns out to be. */
    if (listener->xport_type == x_udp)
        s_dgram_peer_add_pending(listener, peer);
    return true;
}

/** @brief Close @p fd after taking it off this thread's readiness set.
 *
 *  @p abort takes the abortive close: the peer reads a reset instead of a
 *  FIN. It fits the deadline cut of a held park — the reference server's
 *  idle bound leaves its own reset behind at sixty seconds — and nothing
 *  else; a reply just written closes gently so its delivery survives.
 *
 *  On a probe-wait retry, @p fd still carries its pre-conn watch, and the
 *  caller frees that pre_conn the instant classification returns; a
 *  backend whose interest set is a plain userspace array keeps a dangling
 *  entry pointing at freed memory if close() runs first. The unwatch does
 *  nothing for an @p fd never registered. A stream listener parked for want
 *  of a descriptor is resumed once @p fd is gone.
 */
static void s_close_fd(duct_sock_t fd, bool abort)
{
    duct_events_unwatch(s_io_this->trunk.events, fd, nullptr);
    if (abort)
        duct_sock_rst_close(fd);
    else
        duct_sock_close(fd);
    duct_io_accept_resume();
}

/** @brief Shared sync-preparse resolution result.
 *
 *  Either a match, or still @c resolve_not_me pending the has-async and
 *  fallback tail, @c s_resolve_tail. @c want_async is set only by that tail,
 *  when no sync proto matched and at least one async-preparse proto is
 *  registered; the caller performs the handoff, this struct only reports it.
 */
typedef struct {
    duct_resolve_disposition_t disp;
    const duct_proto_t        *proto;
    duct_handle_t              tok;
    duct_conn_id_t             conn_id;
    void                      *user_ctx;
    size_t                     lead;
    bool                       want_async;
} resolve_result_t;

/** @brief Resolve a join lead the engine built, ahead of every preparse.
 *  Only a first read of at least @c duct_join_lead_size bytes is asked; a
 *  lead this listener's protocols do not take leaves the read to them. */
static resolve_result_t
s_resolve_lead(const duct_listener_t *listener, const uint8_t *peek, size_t n)
{
    resolve_result_t r = { .disp = resolve_not_me, .conn_id = duct_conn_id_primary };
    duct_session_handle_t tok;
    duct_conn_id_t cid;
    const duct_proto_t *proto;
    bool joins = n >= duct_join_lead_size
              && duct_join_match(peek, listener->protos, listener->n_protos,
                                 &tok, &cid, &proto);
    if (joins)
        r = (resolve_result_t){ .disp = resolve_join, .proto = proto, .tok = tok.word,
                                  .conn_id = cid, .lead = duct_join_lead_size };
    return r;
}

/** @brief Resolve a datagram whose wire leads it with a join lead, ahead of
 *  every preparse.
 *  Each protocol of @p listener on a wire that raises @c fl_wire_join_lead is
 *  asked in turn, and the first naming a session takes the datagram as a join
 *  on the primary conn id. */
static resolve_result_t
s_resolve_dgram_lead(const duct_listener_t *listener, const duct_view_u8 *data)
{
    for (unsigned i = 0u; i < listener->n_protos; ++i) {
        auto proto = listener->protos[i];
        auto wire = proto->cfg.wire;
        if (!wire || !duct_has(wire->flags, fl_wire_join_lead))
            continue;
        auto tok = duct_join_dgram_match(data->data, data->size, proto);
        if (tok.word != handle_null)
            return (resolve_result_t){ .disp = resolve_join, .proto = proto,
                                         .tok = tok.word, .conn_id = duct_conn_id_primary };
    }
    return (resolve_result_t){ .disp = resolve_not_me };
}

/** @brief Sync-preparse loop only, shared verbatim by the accept and
 *  datagram classification paths. Kept separate from the has-async
 *  check and preparse==NULL fallback that follow it: those two ignore
 *  the read entirely and, run together, resolve a listener with a fallback
 *  proto on the very first, still-empty read, before probe-wait arms.
 */
static resolve_result_t
s_resolve_sync(duct_listener_t *listener, const duct_peer_t *peer, const duct_view_u8 *data)
{
    resolve_result_t r = { .disp = resolve_not_me, .conn_id = duct_conn_id_primary };
    for (unsigned i = 0u; i < listener->n_protos; ++i) {
        auto proto = listener->protos[i];
        auto cfg = &proto->cfg;
        if (!cfg->preparse || cfg->preparse_mode != resolve_sync)
            continue;
        r.disp = s_preparse_call(cfg, peer, *data, &r.tok, &r.conn_id, &r.user_ctx, &r.lead);
        if (r.disp != resolve_not_me) {
            r.proto = proto;
            break;
        }
    }
    return r;
}

/** @brief Second stage: has-async check, then preparse==NULL fallback —
 *  a no-op passthrough unless @p r is still @c resolve_not_me.
 *
 *  Has-async wins outright where both apply, so @c want_async and a
 *  fallback match are mutually exclusive on return.
 */
static resolve_result_t
s_resolve_tail(duct_listener_t *listener, resolve_result_t r)
{
    if (r.disp != resolve_not_me)
        return r;
    for (unsigned i = 0u; i < listener->n_protos; ++i) {
        auto cfg = &listener->protos[i]->cfg;
        if (cfg->preparse && cfg->preparse_mode == resolve_async) {
            r.want_async = true;
            return r;
        }
    }
    for (unsigned i = 0u; i < listener->n_protos; ++i) {
        auto proto = listener->protos[i];
        if (!proto->cfg.preparse) {
            r.proto = proto;
            r.disp = resolve_new;
            r.user_ctx = proto->cfg.user_ctx;
            break;
        }
    }
    return r;
}

/** @brief Park @p fd as a probe-wait pre_conn that holds the bytes @p held.
 *  Arms the listener's @c probe_wait_ms deadline once; the reads that follow fill the
 *  pre_conn's own buffer and leave it where it was. Without a timer the wait has no
 *  deadline and ends at the next read.
 *  @return false, with nothing left behind, on an allocation or watch failure, and
 *          with the listener already holding @c DUCT_LISTENER_PROBE_PARK_MAX parks:
 *          the caller classifies the bytes it read as a listener that never waited
 *          does.
 */
static bool s_probe_wait_begin(duct_listener_t *listener, duct_sock_t fd, const duct_peer_t *peer,
                               duct_view_u8 held)
{
    auto t = s_io_this;
    if (listener->probe_parks >= DUCT_LISTENER_PROBE_PARK_MAX)
        return false;
    auto pre_conn = duct_new(duct_pre_conn_t);
    if (pre_conn) {
        *pre_conn = (duct_pre_conn_t){
            .fd = fd, .kind = pre_conn_probe,
            .probe = { .listener = listener, .peer = *peer },
        };
        pre_conn->probe.peek = duct_new(uint8_t, duct_listener_peek_span(listener->peek_cap));
        if (pre_conn->probe.peek) {
            pre_conn->probe.peek_len = (uint16_t)held.size;
            if (held.size)
                memcpy(duct_at(pre_conn->probe.peek), held.data, held.size);
            pre_conn->next = t->pre_conns;
            t->pre_conns = pre_conn;
            if (duct_events_watch(t->trunk.events, fd, io_tag_pre_conn, pre_conn,
                                  x_tcp /* unused for io_tag_pre_conn */)) {
                ++listener->pre_conn_refs;
                ++listener->probe_parks;
                auto h = duct_timer_add(&t->timers, (uint8_t)t->route.thread_id, 0u,
                                        (uint64_t)listener->probe_wait_ms * 1000u, 0u, 1u,
                                        s_pre_conn_timeout_fire, pre_conn, nullptr);
                if (h != timer_handle_null)
                    pre_conn->timeout = h;
                return true;
            }
            s_pre_conn_free(t, pre_conn);
        } else
            duct_del(pre_conn);
    }
    return false;
}

/** @brief Write on @p fd the reply @p proto's preparse staged, where it staged one.
 *  Every stream answer goes out through here: ahead of the close a retry takes,
 *  ahead of the session's first byte or a joined leg's, ahead of the wait a
 *  hold holds. @p proto null, or an answer of no bytes, sends nothing. */
static void s_preparse_reply_write(const duct_proto_t *proto, duct_sock_t fd, duct_xport_t xport,
                                   const duct_peer_t *peer)
{
    duct_view_u8 reply = {};
    auto cfg = proto ? duct_proto_cfg_of(proto) : nullptr;
    if (cfg && cfg->preparse_reply
        && cfg->preparse_reply(cfg->preparse_ctx, peer, &reply) && reply.size)
        duct_discard duct_xwrite(fd, xport, reply, &(size_t){0u}, nullptr, 0);
}

/** @brief Classify and dispatch one accepted stream @p fd from the @p n bytes of @p peek already read.
 *
 *  A read under @c listener->peek_min waits first, ahead of the join lead and every
 *  pre-parse. A longer one resolves the engine join lead, then the sync pre-parses,
 *  and an empty read still unmatched waits too. Then the fd closes on reject, retry
 *  or no match, goes to the async pre-parse hand-off, or becomes a conn through
 *  resolve_join or resolve_new.
 *
 *  A wait parks the fd as a probe-wait pre_conn, whose resolution calls this again
 *  with @p allow_wait false: an fd waits once, and a read still short is classified
 *  as it stands. A pre-parse's @c resolve_hold asks the same machinery for more
 *  bytes: parked with the deadline still armed the answer is more waiting, the
 *  caller keeping its pre_conn; past the deadline, the read span, a closed peer or
 *  an accept path with no wait to give, the connection closes, beyond any fallback.
 *
 *  @param probe    The pre_conn this resolution serves, null from the accept path.
 *  @param more     Whether more bytes can still arrive on @p fd; a FIN-ended read holds nothing.
 *  @return true with @p fd consumed or parked; false only for a probe-resolution
 *          still waiting on more bytes, its pre_conn left armed and held.
 */
static bool s_classify_stream(const duct_wfq_route_t *route, duct_listener_t *listener,
                                 duct_sock_t fd, const duct_peer_t *peer,
                                 uint8_t *peek, size_t n, bool allow_wait,
                                 duct_pre_conn_t *probe, bool more)
{
    duct_view_u8 peek_buf = { .data = (void *)peek, .size = n };
    if (allow_wait && n < listener->peek_min && s_probe_wait_begin(listener, fd, peer, peek_buf))
        return true;

    auto r = s_resolve_lead(listener, peek, n);
    if (r.disp == resolve_not_me)
        r = s_resolve_sync(listener, peer, &peek_buf);
    if (r.disp == resolve_hold) {
        /* A wait is granted only while more bytes can still arrive and the probe
         * read span still has room for them: the span's last byte ends the hold,
         * and so does a peer whose FIN sent its last. A deadline cuts the rest.
         * A hold that can wait no longer closes: its bytes belong to the holding
         * protocol, never to a fallback or async pre-parse. The deadline's own
         * cut closes abortively — the peer reads a reset, as a reference server's
         * idle bound leaves one — while a peer's finished stream closes gently.
         * A hold answers where its protocol staged one and the listener still
         * grants the wait, from the accept path or a probe retry alike, and the
         * peer's next bytes re-classify the connection; an empty reply holds
         * silently. */
        bool room = more && n < duct_listener_peek_span(listener->peek_cap);
        if (room && probe && probe->timeout != timer_handle_null) {
            s_preparse_reply_write(r.proto, fd, listener->xport_type, peer);
            return false;
        }
        if (room && allow_wait && listener->probe_wait_ms
            && s_probe_wait_begin(listener, fd, peer, peek_buf)) {
            s_preparse_reply_write(r.proto, fd, listener->xport_type, peer);
            return true;
        }
        /* @p more rides the deadline's own fire: its cut closes abortively,
         * the peer reading a reset as a reference idle bound leaves one. A
         * peer whose FIN ended the hold closes gently, its side already gone. */
        s_close_fd(fd, more);
        return true;
    }

    if (r.disp == resolve_reject || r.disp == resolve_retry) {
        if (r.disp == resolve_retry) {
            /* A stranger's stream is answered on its own connection, as a datagram
             * one is off the listener: the reply the protocol's preparse_reply builds
             * goes out ahead of the close, costing no conn and no session. */
            s_preparse_reply_write(r.proto, fd, listener->xport_type, peer);
        }
        s_close_fd(fd, false);
        return true;
    }

    /* On empty reads, waits once for initial peer bytes when @p allow_wait is
     * set before falling back to async/fallback/reject. */
    if (r.disp == resolve_not_me && n == 0u && allow_wait && listener->probe_wait_ms
        && s_probe_wait_begin(listener, fd, peer, peek_buf))
        return true;

    r = s_resolve_tail(listener, r);

    /* No sync match, an async proto exists: hand the fd + peek to the
     * listener's home worker for classification. A probe-wait retry
     * drops its io_tag_pre_conn watch outright first, since the caller
     * frees that pre_conn the instant this function returns. */
    if (r.disp == resolve_not_me && r.want_async) {
        if (!allow_wait)
            duct_events_unwatch(s_io_this->trunk.events, fd, nullptr);
        duct_view_u8 pk = { .data = peek, .size = n };
        if (!s_preparse_post(listener, fd, peer, pk, false))
            s_close_fd(fd, false);
        return true;
    }

    if (r.disp == resolve_not_me || !r.proto) {
        s_close_fd(fd, false);
        return true;
    }

    peek_buf = n > r.lead
        ? (duct_view_u8){ .data = (void *)(peek + r.lead), .size = n - r.lead }
        : (duct_view_u8){};
    if (r.disp == resolve_join) {
        auto tok = (duct_session_handle_t){ .word = r.tok };
        auto target = duct_session_by_handle(tok);
        /* Occupancy is authoritative on the worker, which refuses an occupied
         * slot for good. Reading it here keeps a stale conn_id from
         * spending a socket, a conn slot and a reactor registration on its
         * way to that refusal. */
        if (!target || duct_session_conn_at(target, r.conn_id).word) {
            s_close_fd(fd, false);
            return true;
        }
        if (r.proto) {
            /* resolve_new's shape: the joined leg's reply leaves ahead of its first byte. */
            s_preparse_reply_write(r.proto, fd, listener->xport_type, peer);
        }
        /* Occupancy is authoritative on the worker; the I/O thread only
         * routes, so a stale conn_id here creates and tears down a conn.
         * A probe-wait retry arrives with its fd already watched, which
         * !allow_wait hands over as the promotion. */
        auto conn = s_conn_prepare(listener, peer, peek_buf, r.proto, listener->xport_type, fd,
                                   !allow_wait,
                                   duct_atomic_load(&target->worker_id, acquire),
                                   nullptr);
        if (!conn)
            return true;
        /* Join ctrl runs before any frame reaches the WFQ lane. */
        if (!duct_sessions_post_conn_join(conn, tok, r.conn_id, peer, (duct_seal_prefix_t){}))
            duct_io_conn_close(conn, close_internal_error);
        else if (peek_buf.size)
            duct_frame_rx_post(route, &s_io_this->frame_rx, conn);
        return true;
    }

    /* resolve_new — resolve_join's shape without a session to join. The reply
     * leaves ahead of the conn's first egress, so the peer reads it exactly
     * where a retry's answer stands: before any session byte. */
    s_preparse_reply_write(r.proto, fd, listener->xport_type, peer);
    auto conn = s_conn_prepare(listener, peer, peek_buf, r.proto, listener->xport_type, fd,
                               !allow_wait, conn_worker_none, nullptr);
    if (!conn)
        return true;
    /* session_open runs before any frame. */
    if (!duct_sessions_post_session_open(conn, r.proto, r.user_ctx, (duct_seal_prefix_t){}, false))
        duct_io_conn_close(conn, close_internal_error);
    else if (peek_buf.size)
        duct_frame_rx_post(route, &s_io_this->frame_rx, conn);
    return true;
}

/** @brief End the pause of the path listener @p arg: clear its pace and put its read interest back. */
static duct_exec_rc_t s_listener_pace_fire(void *arg)
{
    auto listener = (duct_listener_t *)arg;
    listener->local->pace = timer_handle_null;
    duct_events_listener_rx_interest(s_io_this->trunk.events, listener, true);
    return exec_done;
}

/** @brief Pause @p listener's accepts for 1/rate s: arm its pace timer and withdraw its read interest.
 *  A timer that cannot be armed keeps the listener accepting. */
static void s_listener_pace_begin(duct_io_t *t, duct_listener_t *listener)
{
    auto local = listener->local;
    auto h = duct_timer_add(&t->timers, (uint8_t)t->route.thread_id, 0u,
                            1'000'000u / local->rate, 0u, 1u,
                            s_listener_pace_fire, listener, nullptr);
    if (h == timer_handle_null)
        return;
    local->pace = h;
    duct_events_listener_rx_interest(t->trunk.events, listener, false);
}

/** @brief Cancel @p listener's pace timer when one is armed. */
static void s_listener_pace_end(duct_io_t *t, duct_listener_t *listener)
{
    if (!duct_listener_held(listener))
        return;
    auto local = listener->local;
    duct_timer_cancel(&t->timers, local->pace);
    local->pace = timer_handle_null;
}

/* Owns only the fast path — a single proto with no pre-parse and no probe
 * wait, so nothing to read before deciding — and the first, synchronous probe
 * read; everything past that
 * shares one model-agnostic tail with a probe-wait's retry. The route comes
 * from the calling thread's own I/O context, that thread's event or
 * completion loop always being the caller. */
void duct_io_on_accept(duct_listener_t *listener, duct_sock_t fd, const duct_peer_t *peer)
{
    auto route = &s_io_this->route;
    /* Every accept of a paced listener starts the pause, whatever becomes of the client. */
    if (duct_listener_paced(listener))
        s_listener_pace_begin(s_io_this, listener);

    /* Fast path: single proto, no pre-parse, no probe wait. A declared probe
     * wait takes the first bytes, where a join lead travels. */
    if (listener->n_protos == 1u && !listener->protos[0]->cfg.preparse
        && !listener->probe_wait_ms) {
        auto conn = s_conn_prepare(listener, peer, (duct_view_u8){},
                                   listener->protos[0], listener->xport_type, fd, false,
                                   conn_worker_none, nullptr);
        if (conn && !duct_sessions_post_session_open(conn, listener->protos[0],
                                                     listener->protos[0]->cfg.user_ctx,
                                                     (duct_seal_prefix_t){}, false))
            duct_io_conn_close(conn, close_internal_error);
        return;
    }

    /* Sync dispatch: read, iterate sync pre-parses, then fallback. The read is
     * destructive, peek-then-reread being unreliable on some targets' socket
     * APIs, so every classification path here consumes the bytes for good and
     * re-injects them, less the lead a preparse consumed, into the conn's own
     * RX OLB once one exists. */
    uint8_t peek[DUCT_LISTENER_PEEK_MAX];
    size_t n = 0;
    duct_view_u8 peek_buf = { .data = peek, .size = duct_listener_peek_span(listener->peek_cap) };
    /* rc_again is a would-block signal, nothing arrived yet: proceed with
     * n==0 so a preparse that needs no bytes can still classify. Any other
     * code, a FIN among them, means the peer is gone, so drop the fd. */
    auto peek_rc = duct_xread(fd, listener->xport_type, peek_buf, &n, nullptr, 0, nullptr);
    duct_do_if(peek_rc != rc_ok && peek_rc != rc_again,
        duct_sock_close(fd);
        return;
    );
    s_classify_stream(route, listener, fd, peer, peek, n, /* allow_wait */ true, nullptr,
                      /* more */ true);
}

/** @brief Open, create, bind, seed and register one conn for the session layer.
 *
 *  @p fd is @c duct_sock_bad for a datagram peer, which has no per-peer socket
 *  yet — classification ran on the shared socket, where TCP had @c accept4 — so
 *  one opens from @p listener's socket, @c nullptr where no listener backs
 *  this conn. @p promote re-tags an existing @c io_tag_pre_conn descriptor in place.
 *  @p worker_id of @c conn_worker_none keeps whatever @ref s_conn_new chose.
 *
 *  The wire binds for a joined leg exactly as for a new session: two legs of
 *  one session on different wires frame one and leave the other raw. First
 *  bytes land before registration, since a proactive backend posts its first
 *  read there, sized off the ring's stage as it stands; appending after that
 *  leaves the posted read stale. A live @p payload pointer seeds even at size
 *  zero — an empty datagram is a record of its own — unless it falls outside
 *  @ref duct_wire_dgram_min to @c max_frame, and is dropped whole.
 *
 *  @return The conn, the protocol ctrl post still owed and due before any frame
 *          reaches the WFQ lane; @c nullptr with socket and slot released.
 */
static duct_conn_t *
s_conn_prepare(duct_listener_t *listener, const duct_peer_t *peer,
               duct_view_u8 payload, const duct_proto_t *proto,
               duct_xport_t xport, duct_sock_t fd, bool promote,
               uint32_t worker_id, const duct_wire_t *leg_wire)
{
    switch (xport) {
    case x_udp_peer:
        if (fd == duct_sock_bad)
            fd = s_dgram_peer_socket_open(listener->listen_fd, peer);
        break;
    case x_local:
        /* Checked ahead of s_conn_new: a client past the session cap takes no pool slot. */
        if (!duct_local_listener_admits(listener)) {
            if (promote)
                s_close_fd(fd, false);
            else
                duct_sock_close(fd);
            return nullptr;
        }
        break;
    default:
        break;
    }
    if (fd == duct_sock_bad)
        return nullptr;
    auto conn = s_conn_new(fd, xport, proto,
                           proto ? duct_proto_cfg_of(proto)->tcp_congestion : nullptr);
    if (!conn)
        return nullptr;
    auto rx = duct_conn_rx_olb(conn);
    if (rx)
        rx->peer = *peer;
    if (worker_id != conn_worker_none)
        conn->worker_id = worker_id;
    if (duct_conn_bind_wire(conn, proto, leg_wire) != rc_ok) {
        s_conn_unwatch_reclaim(s_io_this, conn);
        return nullptr;
    }
    if (payload.data) {
        if (!duct_conn_record_framed(conn))
            duct_olb_rx_append_raw(conn->rx_buf, payload.data, payload.size);
        else if (s_dgram_rx_admits(conn, payload.size))
            duct_dgram_rx_append(conn->rx_buf, payload.data, payload.size);
    }
    if (!s_conn_register(s_io_this, conn, promote)) {
        s_conn_unwatch_reclaim(s_io_this, conn);
        return nullptr;
    }
    switch (xport) {
    case x_local:
        /* Counted once registered, so every conn that counts has a teardown to drop it. */
        duct_local_listener_take(listener, conn);
        break;
    default:
        break;
    }
    return conn;
}

/** @brief Append one listener-classified datagram to @p conn's own RX ring.
 *
 *  The worker post stays the caller's, which lets the roam branch put its
 *  candidate and its flag between the two.
 *
 *  Enforces datagram bounds checks for peer datagrams arriving on shared
 *  listener sockets. The other checks are @ref s_conn_prepare's seed,
 *  @ref duct_io_rx_commit, and @ref duct_io_rx_commit_units.
 *
 *  Connections assigned to other I/O threads are rejected immediately.
 *
 *  @return false for a missing conn or ring, a conn owned elsewhere, a datagram
 *          outside the wire's bounds, and a ring with no room; nothing appended
 *          in any of them.
 */
static bool s_dgram_rx_append_checked(duct_conn_t *conn, const duct_view_u8 *data)
{
    size_t avail = 0u;
    auto rx = conn ? duct_conn_rx_olb(conn) : nullptr;
    if (!rx
        || conn->io_id != s_io_this->route.thread_id
        || !s_dgram_rx_admits(conn, data->size)
        || duct_olb_rx_try_space(rx, sizeof(duct_dgram_rec_hdr_t) + data->size, true,
                                 &(uint8_t *){nullptr}, &avail) == olb_rx_full)
        return false;
    duct_dgram_rx_append(rx, data->data, data->size);
    return true;
}

/** @brief Answer @p peer with whatever @p proto offers, for a @c resolve_retry.
 *  Sends straight off the listener's own socket: a retry exists to cost no conn
 *  and no session, so nothing is looked up and nothing is allocated. A listener
 *  holding an RIO send state answers through it — a socket registered for RIO
 *  serves RIO calls alone, and a raw sendto on it would report the bytes taken
 *  and lose them. */
static void s_preparse_retry_reply(const duct_listener_t *listener,
                                   const duct_proto_t *proto,
                                   const duct_peer_t *peer)
{
    if (!proto)
        return;
    auto cfg = duct_proto_cfg_of(proto);
    duct_view_u8 reply = {};
    if (!cfg->preparse_reply
        || !cfg->preparse_reply(cfg->preparse_ctx, peer, &reply)
        || !reply.size)
        return;
#ifdef _WIN32
    if (listener->dgram_tx_rio) {
        duct_discard duct_rio_tx_send(listener, peer, reply);
        return;
    }
#endif
    struct sockaddr_storage ss;
    socklen_t slen = (socklen_t)duct_io_sockaddr_from_peer(peer, &ss);
    duct_discard duct_xsend_dgram(listener->listen_fd, (struct sockaddr *)&ss, slen, reply);
}

/** @brief Classification and dispatch for one already-received datagram
 *  on the listener's shared classification socket: dedup against
 *  in-flight spun-off peers, then fast-path, join-lead, sync-preparse, or
 *  async-preparse resolution, then session-open or conn-join for a
 *  fresh peer. Called from a reactive backend's own readiness-driven
 *  datagram loop or a proactive one's own completion handler.
 */
static void s_classify_dgram(const duct_wfq_route_t *route, duct_listener_t *listener,
                                         const duct_peer_t *peer, const duct_view_u8 *data)
{
    duct_conn_t *existing = nullptr;
    bool is_candidate = false;
    if (s_dgram_peer_find(listener, peer, &existing, &is_candidate)) {
        /* Dispatches datagrams from known peer addresses without re-evaluating
         * new connection classification. */
        if (existing && existing->xport_type == x_udp_shared) {
            s_dgram_shared_route(existing, peer, data);
            return;
        }
        /* A datagram from an address this leg is already reachable at retires
         * any candidate standing for it: the client is still where it was, and
         * a surviving candidate is one this frame's own acceptance confirms,
         * for an address nobody accepted anything from. */
        if (existing && !is_candidate)
            s_dgram_peer_candidate_clear(existing);
        if (!s_dgram_rx_append_checked(existing, data))
            return;
        duct_frame_rx_post(route, &s_io_this->frame_rx, existing);
        return;
    }

    /* No probe-wait analog for dgram (a datagram is always a complete
     * read), so this runs the join-lead check, the sync loop and the
     * has-async/fallback tail back to back with nothing between them. A
     * single-proto-no-preparse listener needs no special fast path: the
     * tail's own fallback loop already resolves to the same result (sync
     * loop skips the proto, fallback loop matches it: resolve_new +
     * user_ctx = cfg->user_ctx). */
    auto r = s_resolve_dgram_lead(listener, data);
    if (r.disp == resolve_not_me)
        r = s_resolve_sync(listener, peer, data);
    if (r.disp == resolve_hold)
        r.disp = resolve_not_me;
    r = s_resolve_tail(listener, r);

    if (r.disp == resolve_not_me && r.want_async) {
        duct_discard s_preparse_post(listener, duct_sock_bad, peer, *data, false);
        return;
    }

    if (r.disp == resolve_retry) {
        s_preparse_retry_reply(listener, r.proto, peer);
        return;
    }

    if (r.disp == resolve_not_me || r.disp == resolve_reject || !r.proto)
        return;

    if (r.disp == resolve_join) {
        auto tok = (duct_session_handle_t){ .word = r.tok };
        auto target = duct_session_by_handle(tok);
        if (!target)
            return;
        if (duct_has(duct_proto_cfg_of(r.proto)->flags, fl_proto_dgram_shared)) {
            /* Occupied slot: this leg's client roamed, its address changing
             * under preparse's own CID map. Routes to the existing conn and
             * aliases the new address, a conn-join post here being what
             * refuses an occupied slot. Empty slot: a genuine new leg,
             * light-attach and join as usual. conn->ctx->peer is written
             * only by the owning worker, off the inter_lane message this
             * route carries, to avoid racing a read here. */
            auto slot = duct_session_conn_at(target, r.conn_id);
            if (slot.word) {
                auto conn = duct_conn_by_handle(slot);
                if (!conn || conn->xport_type != x_udp_shared)
                    return;
                s_dgram_shared_route(conn, peer, data);
                s_dgram_peer_add(listener, peer, conn);
                return;
            }
            s_dgram_shared_admit_join(route, listener, peer, data, r.proto,
                                      duct_atomic_load(&target->worker_id, acquire), tok, r.conn_id);
            return;
        }
        auto held = duct_session_conn_at(target, r.conn_id);
        if (held.word) {
            /* This leg's client changed address. The new one routes inbound
             * now, off preparse alone, the same way the shared branch above
             * aliases its own; the socket replies leave on moves later, once
             * the protocol accepts a frame. Splitting the two keeps a
             * guessed session handle from redirecting a session's replies,
             * which a connect() doing both at once cannot. */
            auto roamed = duct_conn_by_handle(held);
            /* Cross-thread SO_REUSEPORT datagrams targeting legs assigned to
             * other I/O threads are dropped. */
            if (!roamed || roamed->xport_type != x_udp_peer
                || roamed->io_id != s_io_this->route.thread_id)
                return;
            /* Append, candidate, ack total, flag, post: the worker learns of
             * this frame only from that post and reads roam_at only under the
             * flag, so it never sees either half-set. A refused append leaves
             * the leg the candidate it already had. */
            if (!s_dgram_rx_append_checked(roamed, data))
                return;
            auto rx = roamed->rx_buf;
            s_dgram_peer_candidate_clear(roamed);
            s_dgram_peer_add_at(listener, peer, roamed, true);
            duct_atomic_store(&rx->roam_at, duct_olb_rx_total_at(rx, rx->h.stage), release);
            duct_conn_state_set(roamed, fl_conn_roaming);
            duct_frame_rx_post(route, &s_io_this->frame_rx, roamed);
            return;
        }
        auto conn = s_conn_prepare(listener, peer, *data, r.proto, x_udp_peer,
                                      duct_sock_bad, false,
                                      duct_atomic_load(&target->worker_id, acquire),
                                      nullptr);
        if (!conn)
            return;
        if (!duct_sessions_post_conn_join(conn, tok, r.conn_id, peer, (duct_seal_prefix_t){})) {
            duct_io_conn_close(conn, close_internal_error);
            return;
        }
        duct_frame_rx_post(route, &s_io_this->frame_rx, conn);
        s_dgram_peer_add(listener, peer, conn);
        return;
    }

    /* resolve_new */
    if (duct_has(duct_proto_cfg_of(r.proto)->flags, fl_proto_dgram_shared)) {
        s_dgram_shared_admit_open(route, listener, peer, data, r.proto, conn_worker_none, r.user_ctx);
        return;
    }
    auto conn = s_conn_prepare(listener, peer, *data, r.proto, x_udp_peer,
                               duct_sock_bad, false, conn_worker_none, nullptr);
    if (!conn)
        return;
    if (!duct_sessions_post_session_open(conn, r.proto, r.user_ctx, (duct_seal_prefix_t){}, false)) {
        duct_io_conn_close(conn, close_internal_error);
        return;
    }
    duct_frame_rx_post(route, &s_io_this->frame_rx, conn);
    s_dgram_peer_add(listener, peer, conn);
}

/* Reached from a reactive backend's readiness-driven read loop, or from a
 * proactive one's completion handler. */
void duct_io_on_dgram(duct_listener_t *listener, const duct_peer_t *peer,
                      duct_view_u8 *data, uint32_t seg)
{
    /* A zero-length datagram is a datagram, and the single-unit path carries
     * it: the split loop's condition is false at once for an empty read. */
    if (!seg || seg >= data->size) {
        s_classify_dgram(&s_io_this->route, listener, peer, data);
        return;
    }
    s_rtstat_gro(data->size, seg);
    if (s_dgram_shared_route_group(listener, peer, data, seg))
        return;
    /* Walked apart one datagram at a time, so nothing past here learns they
     * arrived together. */
    for (size_t off = 0u; off < data->size; off += seg) {
        size_t take = duct_min(data->size - off, (size_t)seg);
        s_classify_dgram(&s_io_this->route, listener, peer,
                         &(duct_view_u8){ .data = data->data + off, .size = take });
    }
}

bool duct_io_on_dgram_slot(duct_listener_t *listener, const duct_peer_t *peer, uint32_t slot,
                           size_t bytes, uint32_t seg, bool lend)
{
    auto t = s_io_this;
    auto pool = listener->rx_slots;
    if (lend) {
        t->held[0] = slot;
        t->n_held = 1u;
        t->held_pool = pool;
    }
    auto span = duct_listener_rx_span(listener, pool, slot);
    duct_io_on_dgram(listener, peer, &(duct_view_u8){ .data = span.data, .size = bytes }, seg);
    bool lent = lend && t->held[0] == treiber_empty;
    t->n_held = 0u;
    t->held_pool = nullptr;
    return lent;
}

uint32_t duct_io_rx_slots_acquire(duct_listener_t *listener, duct_view_u8 *out)
{
    auto t = s_io_this;
    duct_do_if(!t || t->n_held, return 0u);
    auto pool = listener->rx_slots;
    t->n_held = duct_x_slot_acquire_n(pool, t->held, duct_dgram_rx_batch);
    for (uint32_t i = 0u; i < t->n_held; ++i)
        out[i] = duct_listener_rx_span(listener, pool, t->held[i]);
    if (t->n_held)
        t->held_pool = pool;
    return t->n_held;
}

void duct_io_rx_slots_release(void)
{
    auto t = s_io_this;
    duct_do_if(!t || !t->held_pool, return);
    uint32_t back = 0u;
    for (uint32_t i = 0u; i < t->n_held; ++i)
        if (t->held[i] != treiber_empty)
            t->held[back++] = t->held[i];
    duct_x_slot_release_n(t->held_pool, t->held, back);
    t->n_held = 0u;
    t->held_pool = nullptr;
}

duct_view_u8 duct_io_dgram_rx_scratch(void)
{
    auto t = s_io_this;
    duct_do_if(!t, return (duct_view_u8){});
    if (!t->dgram_scratch)
        t->dgram_scratch = duct_new(uint8_t, DUCT_LISTENER_DGRAM_DEFAULT);
    duct_do_if(!t->dgram_scratch, return (duct_view_u8){});
    return (duct_view_u8){ .data = duct_at(t->dgram_scratch), .size = duct_len(t->dgram_scratch) };
}

/** @brief Take @p listener's socket off @p t's readiness set, or put it back. */
static void s_listener_rx_park(duct_io_t *t, duct_listener_t *listener, bool parked)
{
    listener->rx_parked = parked;
    duct_events_listener_rx_interest(t->trunk.events, listener, !parked);
}

/* The re-check runs past a seq_cst fence that pairs with the seq_cst step ahead of
 * s_rx_unstall, the slot return of duct_io_rx_slot_drop or the pin of
 * duct_io_rx_pin: either it sees their slot or pin, or they see stalled and post
 * the resume. */
bool duct_io_dgram_rx_stall(duct_listener_t *listener)
{
    auto t = s_io_this;
    auto pool = listener->rx_slots;
    if (!pool->range.base || !duct_atomic_load(&pool->live, acquire)
        || duct_atomic_load(&pool->pins, acquire))
        return false;
    s_listener_rx_park(t, listener, true);
    duct_atomic_store(&pool->stalled, true, relaxed);
    atomic_thread_fence(memory_order_seq_cst);
    if ((!duct_x_slot_pool_dry(pool) || duct_atomic_load(&pool->pins, relaxed))
        && duct_atomic_exchange(&pool->stalled, false, acq_rel)) {
        s_listener_rx_park(t, listener, false);
        return false;
    }
    return true;
}

/** @brief Put back every parked listener of this thread: a stream listener at once, a
 *  datagram listener whose pool is no longer stalled.
 *  The latch goes back by exchange, so a poster that found it still up has its
 *  stall clear published to this walk.
 */
static duct_exec_rc_t s_msg_exec_rx_resume(void *self)
{
    auto m = (duct_msg_rx_resume *)self;
    duct_discard duct_atomic_exchange(&m->latch, 0u, acq_rel);
    auto t = s_io_this;
    for (auto l = t->listeners; l; l = l->next) {
        if (!l->rx_parked)
            continue;
        if (!l->rx_slots)
            duct_io_accept_unpark(l);
        else if (!duct_atomic_load(&l->rx_slots->stalled, acquire))
            s_listener_rx_park(t, l, false);
    }
    return exec_done;
}

/** @brief Post io thread @p io_id its resume, unless one is already in flight.
 *  Posts nothing to a thread whose events duct_io_cleanup has already closed, nor
 *  once the cleanup is done: a slot returned or a socket closed during engine
 *  teardown finds that thread's @c trunk.events null or @c s_imod.n_io 0.
 */
static void s_rx_resume_post(unsigned io_id)
{
    if (io_id >= s_imod.n_io || !s_imod.xports[io_id].trunk.events)
        return;
    auto t = &s_imod.xports[io_id];
    if (duct_atomic_exchange(&t->rx_resume.latch, 1u, acq_rel) != 0u)
        return;
    s_msg_post(io_id, &t->rx_resume);
}

/** @brief Take @p pool's stall back, where it is stalled, and post its reader
 *  the resume.
 *  The caller's seq_cst return or pin ahead of the test pairs with the fence
 *  @ref duct_io_dgram_rx_stall takes between setting @c stalled and its re-check. */
static void s_rx_unstall(duct_x_slot_pool_t *pool)
{
    if (duct_x_slot_unstall(pool))
        s_rx_resume_post(pool->reader);
}

void duct_io_rx_slot_drop(duct_x_slot_pool_t *pool, uint32_t idx, bool claim)
{
    bool last = duct_x_slot_drop(pool, idx, claim);
    duct_do_if(!last, return);
    duct_x_slot_release(pool, idx);
    s_rx_unstall(pool);
}

void duct_io_accept_park(duct_listener_t *listener)
{
    s_listener_rx_park(s_io_this, listener, true);
    duct_atomic_fetch(add, &s_imod.accept_parked, 1u, seq_cst);
}

void duct_io_accept_unpark(duct_listener_t *listener)
{
    s_listener_rx_park(s_io_this, listener, false);
    duct_atomic_fetch(sub, &s_imod.accept_parked, 1u, relaxed);
}

duct_result_t duct_io_accept(duct_listener_t *listener, duct_sock_t *fd, struct sockaddr_storage *addr)
{
    auto rc = duct_xaccept(listener->listen_fd, fd, addr);
    if (rc != rc_defer)
        return rc;
    duct_io_accept_park(listener);
    rc = duct_xaccept(listener->listen_fd, fd, addr);
    if (rc != rc_defer)
        duct_io_accept_unpark(listener);
    return rc;
}

/* The fence pairs with the seq_cst raise of duct_io_accept_park: either this read sees
 * the park, or the accept duct_io_accept retries past that park sees the descriptor the
 * caller has just closed. */
void duct_io_accept_resume(void)
{
    atomic_thread_fence(memory_order_seq_cst);
    if (!duct_atomic_load(&s_imod.accept_parked, relaxed))
        return;
    for (unsigned i = 0u; i < s_imod.n_io; ++i)
        s_rx_resume_post(i);
}

void duct_io_rx_pin(duct_x_slot_pool_t *pool)
{
    duct_atomic_fetch(add, &pool->pins, 1u, seq_cst);
    s_rx_unstall(pool);
}

void duct_io_rx_unpin(duct_x_slot_pool_t *pool)
{
    duct_atomic_fetch(sub, &pool->pins, 1u, release);
}

/** @brief Scope-exit end of the async pre-parse message @p r points at.
 *  Gives back the listener reference taken when the job was posted, then frees the message. The
 *  release is the last use of @c listener: it frees the listener when @c duct_listener_close
 *  already ran and this was the last outstanding reference.
 */
static void s_preparse_end(duct_msg_pre_parse **r)
{
    duct_listener_release_pre_conn_ref((*r)->listener);
    duct_del(*r);
}

/** @brief I/O-side tail of the async pre-parse round trip, run on
 *  whichever I/O thread posted the original job once the worker-side
 *  classifier has filled in its decision and reposted the same object
 *  back.
 *
 *  Clears the pending peer marker to unblock future classifications.
 *  Successful branches re-add the active connection to @c dgram_peers for
 *  subsequent fast-path routing.
 */
static duct_exec_rc_t s_preparse_exec_result(void *self)
{
    [[gnu::cleanup(s_preparse_end)]] duct_msg_pre_parse *result = self;
    auto payload = s_preparse_payload(result);
    auto route = &s_io_this->route;
    bool is_dgram = result->listener && result->listener->xport_type == x_udp;
    if (is_dgram)
        s_dgram_peer_clear_pending(result->listener, &result->peer);

    if (result->decision == resolve_retry && is_dgram)
        s_preparse_retry_reply(result->listener, result->proto, &result->peer);

    if (result->decision == resolve_reject || result->decision == resolve_not_me
        || result->decision == resolve_retry || !result->proto) {
        if (!is_dgram && result->fd != duct_sock_bad)
            s_close_fd(result->fd, false);
        return exec_done;
    }

    duct_session_t *target = nullptr;
    duct_session_handle_t join_tok = {};
    if (result->decision == resolve_join) {
        join_tok = (duct_session_handle_t){ .word = result->join_tok };
        target = duct_session_by_handle(join_tok);
        if (!target) {
            if (!is_dgram && result->fd != duct_sock_bad)
                s_close_fd(result->fd, false);
            return exec_done;
        }
    }

    /* Shared-socket protocols classify here exactly as the sync path does: an
     * occupied slot is a migration, an empty one a new leg. A per-peer
     * connected socket therefore only ever opens for a proto without the
     * flag. */
    if (is_dgram && duct_has(duct_proto_cfg_of(result->proto)->flags, fl_proto_dgram_shared)) {
        if (!target) {
            s_dgram_shared_admit_open(route, result->listener, &result->peer, &payload,
                                      result->proto, conn_worker_none, result->user_ctx);
            return exec_done;
        }
        auto slot = duct_session_conn_at(target, result->join_conn_id);
        if (slot.word) {
            auto held = duct_conn_by_handle(slot);
            if (held && held->xport_type == x_udp_shared) {
                s_dgram_shared_route(held, &result->peer, &payload);
                s_dgram_peer_add(result->listener, &result->peer, held);
            }
            return exec_done;
        }
        s_dgram_shared_admit_join(route, result->listener, &result->peer, &payload,
                                  result->proto, duct_atomic_load(&target->worker_id, acquire),
                                  join_tok, result->join_conn_id);
        return exec_done;
    }

    /* A stream conn's seed starts past the lead its preparse consumed. */
    auto seed = payload;
    if (!is_dgram && result->lead)
        seed = result->lead < seed.size
             ? (duct_view_u8){ .data = (uint8_t *)seed.data + result->lead,
                             .size = seed.size - result->lead }
             : (duct_view_u8){};
    auto conn = s_conn_prepare(result->listener,
                               &result->peer, seed, result->proto,
                               is_dgram ? x_udp_peer : result->listener->xport_type,
                               is_dgram ? duct_sock_bad : result->fd,
                               result->fd_registered,
                               target ? duct_atomic_load(&target->worker_id, acquire)
                                      : conn_worker_none,
                               nullptr);
    if (!conn)
        return exec_done;
    bool posted = target
        ? duct_sessions_post_conn_join(conn, join_tok, result->join_conn_id, &result->peer,
                                       (duct_seal_prefix_t){})
        : duct_sessions_post_session_open(conn, result->proto, result->user_ctx,
                                          (duct_seal_prefix_t){}, false);
    if (!posted) {
        duct_io_conn_close(conn, close_internal_error);
        return exec_done;
    }
    if (seed.data)
        duct_frame_rx_post(route, &s_io_this->frame_rx, conn);
    if (is_dgram)
        s_dgram_peer_add(result->listener, &result->peer, conn);
    return exec_done;
}

/** @brief Tracks active datagram peers in @c dgram_peers to route packets
 *  from the shared listener to existing connections.
 */
typedef struct s_dgram_peer_node {
    duct_hash_handle_t  hh;
    duct_peer_t         peer;
    duct_conn_handle_t  conn;
    bool                candidate;
} dgram_peer_node_t;

/** @brief Bucket count for dgram_peers: internal dispatch-path sizing.
 *  Power of two so the mask-and index stays one instruction.
 */
static constexpr unsigned s_dgram_peer_buckets = 128u;
static constexpr unsigned s_dgram_peer_mask = s_dgram_peer_buckets - 1u;

/* Folds the family-and-port word and all 16 bytes of addr.v6 through the splitmix64 finalizer,
 * whatever the family: an IPv4 peer's unused tail is zero, as duct_x_same_peer, which compares the
 * same bytes, requires. */
uint64_t duct_peer_hash(const duct_peer_t *peer)
{
    uint32_t family_port;
    memcpy(&family_port, &peer->family, sizeof family_port);
    uint64_t lo, hi;
    memcpy(&lo, peer->addr.v6, sizeof lo);
    memcpy(&hi, peer->addr.v6 + sizeof lo, sizeof hi);
    uint64_t h = duct_splitmix64(family_port);
    h = duct_splitmix64(h ^ lo);
    return duct_splitmix64(h ^ hi);
}

/** @brief Lookup for @p peer among in-flight entries.
 *
 *  @retval false  No entry was ever recorded for @p peer: a fresh peer,
 *                 safe to resolve as new.
 *  @retval true   A matching entry exists, even if its conn has since been
 *                 reclaimed, @p out_conn left null then — that peer identity
 *                 was just torn down, and admission must not re-admit it as
 *                 new on losing a race with the conn's own reclaim.
 *  @param out_candidate  True when the match is an address @p out_conn routes
 *                 from but does not yet reply to. Null to ignore.
 *
 *  A dead match is pruned here, safe because dgram_peers is io-thread-owned
 *  for a listener's whole live span. A node whose conn is the null handle is
 *  a pending entry, an async pre-parse in flight with no conn yet: a live
 *  match, never pruned, since a null handle resolves to no conn either way.
 */
static bool
s_dgram_peer_find(duct_listener_t *listener, const duct_peer_t *peer,
                  duct_conn_t **out_conn, bool *out_candidate)
{
    *out_conn = nullptr;
    if (out_candidate)
        *out_candidate = false;
    auto buckets = (duct_hash_handle_t **)listener->dgram_peers;
    if (!buckets)
        return false;
    unsigned idx = duct_hash_idx(duct_peer_hash(peer), s_dgram_peer_mask);
    for (auto h = buckets[idx]; h; h = h->next) {
        auto node = duct_hash_entry(h, dgram_peer_node_t, hh);
        if (!duct_x_same_peer(&node->peer, peer))
            continue;
        if (!node->conn.word)
            return true;
        auto conn = duct_conn_by_handle(node->conn);
        if (!conn) {
            duct_hash_remove(&node->hh);
            duct_del(node);
            return true;
        }
        *out_conn = conn;
        if (out_candidate)
            *out_candidate = node->candidate;
        return true;
    }
    return false;
}

/** @brief Lazily allocates @p listener's bucket array, with no sweep —
 *  just what every insert needs. A pending insert carries no conn to
 *  check, so it never benefits from reclaiming dead entries, and a full
 *  128-bucket walk for it on every fresh peer under an initiation flood
 *  buys nothing. Returns nullptr on allocation failure.
 */
static duct_hash_handle_t **s_dgram_peer_ensure_buckets(duct_listener_t *listener)
{
    auto buckets = (duct_hash_handle_t **)listener->dgram_peers;
    if (!buckets) {
        buckets = duct_at(duct_new(duct_hash_handle_t *, s_dgram_peer_buckets));
        if (!buckets)
            return nullptr;
        listener->dgram_peers = buckets;
    }
    return buckets;
}

/** @brief Shared prefix for a real-conn dgram_peers insert: the lazy
 *  bucket array plus a sweep of every entry whose conn has since been
 *  reclaimed. A lookup already prunes its own single dead match inline,
 *  so this sweep's remaining job is the entries no lookup has touched
 *  since. A pending entry, with conn.word == 0, is never live by the
 *  conn check and must not be swept as if it were a dead conn. Still a
 *  full-table walk; only the per-datagram lookup needed to stop being
 *  one. Returns nullptr on allocation failure.
 */
static duct_hash_handle_t **s_dgram_peer_prepare(duct_listener_t *listener)
{
    auto buckets = s_dgram_peer_ensure_buckets(listener);
    if (!buckets)
        return nullptr;
    for (unsigned i = 0u; i < s_dgram_peer_buckets; ++i) {
        auto h = buckets[i];
        while (h) {
            auto next = h->next;
            auto node = duct_hash_entry(h, dgram_peer_node_t, hh);
            if (node->conn.word && !duct_conn_by_handle(node->conn)) {
                duct_hash_remove(&node->hh);
                duct_del(node);
            }
            h = next;
        }
    }
    return buckets;
}

/** @brief Record @p conn reachability at @p peer.
 *  @p candidate marks roaming candidate addresses awaiting protocol verification.
 */
static void s_dgram_peer_add_at(duct_listener_t *listener, const duct_peer_t *peer,
                                duct_conn_t *conn, bool candidate)
{
    auto buckets = s_dgram_peer_prepare(listener);
    if (!buckets)
        return;
    auto node = duct_new(dgram_peer_node_t);
    if (!node)
        return;
    *node = (dgram_peer_node_t){ .peer = *peer, .conn = duct_conn_handle_get(conn),
                                   .candidate = candidate };
    duct_hash_insert(&buckets[duct_hash_idx(duct_peer_hash(peer), s_dgram_peer_mask)], &node->hh);
}

/** @brief @p conn recorded as freshly spun off for @p peer. */
static void s_dgram_peer_add(duct_listener_t *listener, const duct_peer_t *peer, duct_conn_t *conn)
{
    s_dgram_peer_add_at(listener, peer, conn, false);
}

/** @brief @p conn's candidate node, and in @p out_listener the listener holding
 *  it.
 *  A full walk of every listener this io thread owns, which keeps the address
 *  off the conn itself; it runs once per roam, against a table
 *  @ref s_dgram_peer_prepare already walks whole on every insert.
 */
static dgram_peer_node_t *
s_dgram_peer_candidate_find(duct_conn_t *conn, duct_listener_t **out_listener)
{
    auto handle = duct_conn_handle_get(conn);
    for (auto l = s_io_this->listeners; l; l = l->next) {
        auto buckets = (duct_hash_handle_t **)l->dgram_peers;
        if (!buckets)
            continue;
        for (unsigned i = 0u; i < s_dgram_peer_buckets; ++i)
            for (auto h = buckets[i]; h; h = h->next) {
                auto node = duct_hash_entry(h, dgram_peer_node_t, hh);
                if (node->candidate && node->conn.word == handle.word) {
                    *out_listener = l;
                    return node;
                }
            }
    }
    return nullptr;
}

/** @brief Unmap every address @p keep's conn answered at before @p keep.
 *  A retired address left mapped routes into this session whoever the kernel
 *  hands that 4-tuple to next.
 */
static void s_dgram_peer_drop_others(duct_listener_t *listener,
                                     const dgram_peer_node_t *keep)
{
    auto buckets = (duct_hash_handle_t **)listener->dgram_peers;
    if (!buckets)
        return;
    for (unsigned i = 0u; i < s_dgram_peer_buckets; ++i) {
        auto h = buckets[i];
        while (h) {
            auto next = h->next;
            auto node = duct_hash_entry(h, dgram_peer_node_t, hh);
            if (node != keep && node->conn.word == keep->conn.word) {
                duct_hash_remove(&node->hh);
                duct_del(node);
            }
            h = next;
        }
    }
}

/** @brief Drop @p conn's candidate address and lower its roaming flag.
 *  The flag test leads so every other conn pays one relaxed load for this.
 */
static void s_dgram_peer_candidate_clear(duct_conn_t *conn)
{
    if (!duct_has(duct_conn_state(conn), fl_conn_roaming))
        return;
    duct_listener_t *listener = nullptr;
    auto node = s_dgram_peer_candidate_find(conn, &listener);
    if (node) {
        duct_hash_remove(&node->hh);
        duct_del(node);
    }
    duct_conn_state_clear(conn, fl_conn_roaming);
}

/** @brief Move @p conn's connected socket to its candidate address.
 *
 *  The move runs only while the ring's @c accept_at reaches its @c roam_at: a
 *  candidate replaced since the worker's post carries a later @c roam_at, and
 *  an ack of a rejected frame never raises @c accept_at. A refused move leaves
 *  the flag raised, and the next accepted frame asks again.
 */
static void s_req_do_peer_roam(duct_conn_t *conn)
{
    duct_listener_t *listener = nullptr;
    auto node = s_dgram_peer_candidate_find(conn, &listener);
    if (!node) {
        duct_conn_state_clear(conn, fl_conn_roaming);
        return;
    }
    auto rx = conn->rx_buf;
    if (duct_atomic_load(&rx->accept_at, acquire) < duct_atomic_load(&rx->roam_at, relaxed))
        return;
    struct sockaddr_storage ss;
    socklen_t slen = (socklen_t)duct_io_sockaddr_from_peer(&node->peer, &ss);
    if (duct_xconnect_dgram_peer(conn->fd, (struct sockaddr *)&ss, slen) != rc_ok)
        return;
    s_dgram_peer_drop_others(listener, node);
    node->candidate = false;
    duct_conn_state_clear(conn, fl_conn_roaming);
}

/** @brief In-flight marker for @p peer's async pre-parse decision,
 *  before any conn exists. Blocks a retransmit from resolving as a
 *  brand-new peer while classification is still on a worker. Cleared
 *  once the decision lands, whatever it turns out to be.
 */
static void s_dgram_peer_add_pending(duct_listener_t *listener, const duct_peer_t *peer)
{
    auto buckets = s_dgram_peer_ensure_buckets(listener);
    if (!buckets)
        return;
    auto node = duct_new(dgram_peer_node_t);
    if (!node)
        return;
    *node = (dgram_peer_node_t){ .peer = *peer, .conn = conn_handle_null };
    duct_hash_insert(&buckets[duct_hash_idx(duct_peer_hash(peer), s_dgram_peer_mask)], &node->hh);
}

/** @brief Removes @p peer's pending marker if one is still there.
 *  A no-op if none: every caller clears unconditionally regardless of
 *  whether a marker was actually set.
 */
static void s_dgram_peer_clear_pending(duct_listener_t *listener, const duct_peer_t *peer)
{
    auto buckets = (duct_hash_handle_t **)listener->dgram_peers;
    if (!buckets)
        return;
    unsigned idx = duct_hash_idx(duct_peer_hash(peer), s_dgram_peer_mask);
    for (auto h = buckets[idx]; h; h = h->next) {
        auto node = duct_hash_entry(h, dgram_peer_node_t, hh);
        if (!node->conn.word && duct_x_same_peer(&node->peer, peer)) {
            duct_hash_remove(&node->hh);
            duct_del(node);
            return;
        }
    }
}

void duct_io_listener_dgram_peers_free(duct_listener_t *listener)
{
    auto buckets = (duct_hash_handle_t **)listener->dgram_peers;
    if (!buckets)
        return;
    for (unsigned i = 0u; i < s_dgram_peer_buckets; ++i)
        for (auto h = buckets[i]; h; ) {
            auto next = h->next;
            auto node = duct_hash_entry(h, dgram_peer_node_t, hh);
            duct_del(node);
            h = next;
        }
    duct_del(buckets);
    listener->dgram_peers = nullptr;
}

/* Read-only over the table; the entries themselves are torn down afterward. */
void duct_io_listener_dgram_peers_close_all(duct_listener_t *listener)
{
    auto buckets = (duct_hash_handle_t **)listener->dgram_peers;
    if (!buckets)
        return;
    for (unsigned i = 0u; i < s_dgram_peer_buckets; ++i)
        for (auto h = buckets[i]; h; h = h->next) {
            auto node = duct_hash_entry(h, dgram_peer_node_t, hh);
            auto conn = duct_conn_by_handle(node->conn);
            if (!conn)
                continue;
            /* A connected socket that takes its own peer's datagrams keeps
             * receiving with the listener gone. */
            if (conn->xport_type == x_udp_peer && duct_x_port_sharing >= x_port_share_connected)
                continue;
            duct_io_conn_close(conn, close_io_error);
        }
}

/** @brief Congestion control a dial's socket asks for: a leg dial's own, else
 *  its protocol's. */
static const char *s_dial_cc(const duct_conn_intent_t *seed)
{
    return seed->kind == intent_leg && seed->leg.tcp_congestion[0]
         ? seed->leg.tcp_congestion : duct_proto_cfg_of(seed->proto)->tcp_congestion;
}

/** @brief Promotes successfully dialed @p fd into a connection.
 *  Acquires slot, re-tags pending dial descriptor in place, dispatches
 *  session-open or leg-attach, and starts TX.
 *
 *  Registers before the wire binds and before @c worker_id, the one admitted
 *  path that skips @ref s_conn_prepare. An outbound dial carries nothing
 *  buffered, so the seed-before-register rule that helper keeps has no case
 *  here; a dial that ever carries a payload to seed turns this into the defect
 *  the rule prevents. @p peer is the dialed address, the conn's own from here
 *  on; an @c x_local dial names a path, so its @c duct_peer_t stays empty.
 *
 *  @return false only if the acquire or register step failed. The
 *  caller still owns reporting that; this only decides whether to.
 */
static bool s_dial_promote(duct_io_t *t, duct_sock_t fd, duct_conn_intent_t seed,
                           const duct_peer_t *peer)
{
    auto conn = s_conn_new(fd, seed.xport, seed.proto, s_dial_cc(&seed));
    if (!conn)
        return false;
    auto rx = duct_conn_rx_olb(conn);
    if (rx)
        rx->peer = *peer;
    if (!s_conn_register(t, conn, true)) {
        s_conn_unwatch_reclaim(t, conn);
        return false;
    }
    if (!s_connect_ok(conn, seed))
        return false;
    /* TX kick only: promoting the fd already armed its read interest, and
     * a proactive backend forbids re-posting RX mid-flight. A
     * level-triggered backend still needs write-interest reconciled once,
     * harmless elsewhere. */
    s_tx_start(conn);
    return true;
}

/** @brief Outbound connect start on the reactor.
 *  Connects prepared descriptor and registers a pending dial to defer connection
 *  slot acquisition until resolution. @p seed specifies dial variant; xport
 *  reads @p target as peer address or socket path.
 *
 *  On proactive backends, datagram connects post synthetic completions since
 *  ConnectEx does not support datagram sockets.
 */
static void s_dial_begin(duct_io_t *t, const duct_dial_target_t *target,
                            duct_conn_intent_t seed, uint32_t connect_timeout_ms, duct_sock_t fd)
{
    struct sockaddr_storage ss;
    socklen_t slen;
    switch (seed.xport) {
    case x_local:
        slen = (socklen_t)duct_io_sockaddr_from_path(target->path, &ss);
        break;
    default:
        slen = (socklen_t)duct_io_sockaddr_from_peer(&target->peer, &ss);
        break;
    }
    auto err = duct_xconnect(seed.xport, fd, (struct sockaddr *)&ss, slen);
    if (err != rc_ok) {
        s_connect_error(&t->route, seed, err);
        return;
    }
    auto pre_conn = duct_new(duct_pre_conn_t);
    if (!pre_conn) {
        duct_sock_close(fd);
        s_connect_error(&t->route, seed, rc_no_memory);
        return;
    }
    *pre_conn = (duct_pre_conn_t){ .fd = fd, .kind = pre_conn_dial,
                                   .dial = { .seed = seed, .target = *target } };
    pre_conn->next = t->pre_conns;
    t->pre_conns = pre_conn;
    if (!duct_events_watch(t->trunk.events, fd, io_tag_pre_conn, pre_conn, seed.xport)) {
        /* Nothing was ever posted to the OS on a registration failure, so
         * there is no completion to defer to on any backend — a plain
         * free is correct here. */
        s_pre_conn_free(t, pre_conn);
        duct_sock_close(fd);
        s_connect_error(&t->route, seed, rc_no_memory);
        return;
    }
    if (connect_timeout_ms == 0u)
        return;
    uint64_t delay_us = 0u;
    if (duct_ckd_mul(&delay_us, connect_timeout_ms, 1000u))
        return;
    auto h = duct_timer_add(&t->timers, (uint8_t)t->route.thread_id, 0u,
                            delay_us, 0u, 1u, s_pre_conn_timeout_fire, pre_conn, nullptr);
    if (h != timer_handle_null)
        pre_conn->timeout = h;
}

/** @brief Releases @p pre_conn: cancels armed timer, unlinks from
 *  @p t->pre_conns, and deallocates memory. Does not modify descriptor
 *  lifecycle.
 */
static void s_pre_conn_free(duct_io_t *t, duct_pre_conn_t *pre_conn)
{
    if (pre_conn->timeout != timer_handle_null)
        duct_timer_cancel(&t->timers, pre_conn->timeout);
    for (duct_pre_conn_t **pp = &t->pre_conns; *pp; pp = &(*pp)->next) {
        if (*pp != pre_conn)
            continue;
        *pp = pre_conn->next;
        break;
    }
    if (pre_conn->kind == pre_conn_probe)
        duct_del(pre_conn->probe.peek);
    duct_del(pre_conn);
}

/** @brief @p pre_conn timeout report to its caller, then free. Sole
 *  resolver for a timeout, on either backend: called directly on
 *  reactive backends, where the fire is the only signal that will ever
 *  arrive, or by the guaranteed-later completion upcall a proactive
 *  backend owes, once it observes @p pre_conn->timed_out already set.
 *  Does not touch the fd, already closed by whichever path set
 *  @c timed_out.
 */
static void s_pre_conn_resolve_timeout(duct_io_t *t, duct_pre_conn_t *pre_conn)
{
    if (pre_conn->kind == pre_conn_dial)
        s_connect_error(&t->route, pre_conn->dial.seed, rc_conn_timeout);
    s_pre_conn_free(t, pre_conn);
}

/** @brief Resolve a probe-wait @p pre_conn with the bytes it holds.
 *  Classifies @c probe.peek with @c allow_wait false, then frees @p pre_conn with its
 *  deadline and drops the listener's reference.
 *
 *  A reactive backend reaches it from the deadline fire or from the upcall, a
 *  proactive one from the upcall alone, its fire only cancelling the read.
 *  Whichever comes first resolves and the other can no longer occur, so no flag
 *  arbitrates as it does for a dial.
 *
 *  @return true when the classification held the wait for more bytes: @p pre_conn
 *          stays armed and held, unresolved. false once it resolved and
 *          @p pre_conn is gone.
 */
static bool s_pre_conn_resolve_probe(duct_io_t *t, duct_pre_conn_t *pre_conn, bool more)
{
    auto listener = pre_conn->probe.listener;
    auto fd = pre_conn->fd;
    auto peer = pre_conn->probe.peer;
    if (!s_classify_stream(&t->route, listener, fd, &peer, duct_at(pre_conn->probe.peek),
                           pre_conn->probe.peek_len,
                           /* allow_wait */ false, pre_conn, more))
        return true;
    /* The park's slot goes back here, where the park's reference keeps the
     * listener alive: whole-engine teardown frees probe parks without their
     * listeners, so s_pre_conn_free itself cannot touch one. */
    --listener->probe_parks;
    s_pre_conn_free(t, pre_conn);
    duct_listener_release_pre_conn_ref(listener);
    return false;
}

/** @brief Dispatch dial or probe-wait timeout fire.
 *  A null @p arg indicates the timer was cancelled; retiring the node at its
 *  deadline is a no-op.
 *
 *  Cancelling the fd's I/O gates resolution: true, on reactive backends
 *  always, means this fire is the only signal ever coming, so it
 *  resolves directly. False, on a proactive backend only, means the
 *  cancelled op still owes one guaranteed-later completion, which resolves
 *  it instead; resolving here as well double-resolves the same @p pre_conn.
 *
 *  Probe-wait resolves through the probe path, whose classification owns
 *  the fd's fate — a hold cut by the deadline closes it there. Dial closes
 *  it unconditionally and resolves through the timeout path, gated on the
 *  guaranteed-later path by @c timed_out.
 */
static duct_exec_rc_t s_pre_conn_timeout_fire(void *arg)
{
    if (!arg)
        return exec_done;
    auto pre_conn = (duct_pre_conn_t *)arg;
    pre_conn->timeout = timer_handle_null; /* just fired — not armed anymore */
    auto cancel = duct_events_cancel_io_of(s_io_this->trunk.events);
    if (cancel)
        cancel(pre_conn->fd);
    if (pre_conn->kind != pre_conn_probe) {
        pre_conn->timed_out = true;
        s_close_fd(pre_conn->fd, false);
        if (!cancel)
            s_pre_conn_resolve_timeout(s_io_this, pre_conn);
        return exec_done;
    }
    if (cancel)
        return exec_done;
    /* The deadline nulls the timer before this, so a hold can wait no
     * longer: it closes the connection, never holds again. */
    duct_discard s_pre_conn_resolve_probe(s_io_this, pre_conn, true);
    return exec_done;
}

/* When pre_conn->timed_out is raised on proactive backends, reports
 * timeout directly. */
void duct_io_on_pre_conn_dialed(duct_pre_conn_t *pre_conn, duct_result_t rc)
{
    auto t = s_io_this;
    if (pre_conn->timed_out) {
        s_pre_conn_resolve_timeout(t, pre_conn);
        return;
    }
    auto fd = pre_conn->fd;
    auto seed = pre_conn->dial.seed;
    auto peer = pre_conn->dial.target.peer;
    s_pre_conn_free(t, pre_conn);
    if (rc == rc_ok) {
        if (!s_dial_promote(t, fd, seed, &peer))
            s_connect_error(&t->route, seed, rc_no_memory);
        return;
    }
        s_close_fd(fd, false);
    s_connect_error(&t->route, seed, rc);
}

/* A read that leaves peek.size under peek_min keeps the wait with its deadline
 * as armed, so a peer dripping bytes is cut when a silent one is. Past peek_min
 * a resolution may still hold for a pre-parse that wants more bytes, reported as
 * this function's true with the pre_conn kept, which a proactive backend posts
 * its next read off. A read at the peer's FIN resolves as its last: no hold asks
 * a closed stream for bytes. An iocp read the deadline cancelled comes as rc_ok
 * with no bytes and resolves on the nulled timer's fire, a hold closing there.
 * A peer gone before its first byte closes, as for duct_io_on_accept's own reads. */
bool duct_io_on_pre_conn_probed(duct_pre_conn_t *pre_conn, duct_result_t rc, size_t n)
{
    auto p = &pre_conn->probe;
    switch (rc) {
    case rc_again:
        return true;
    case rc_ok:
        p->peek_len = (uint16_t)(p->peek_len + n);
        if (pre_conn->timeout != timer_handle_null && p->peek_len < p->listener->peek_min)
            return true;
        break;
    case rc_closed:
        if (p->peek_len)
            break;
        [[fallthrough]];
    default:
        auto listener = p->listener;
        s_close_fd(pre_conn->fd, false);
        /* The park's slot goes back beside its reference, as in
         * s_pre_conn_resolve_probe. */
        --listener->probe_parks;
        s_pre_conn_free(s_io_this, pre_conn);
        duct_listener_release_pre_conn_ref(listener);
        return false;
    }
    return s_pre_conn_resolve_probe(s_io_this, pre_conn, rc == rc_ok);
}

void duct_io_on_pre_conn_readable(duct_pre_conn_t *pre_conn)
{
    for (;;) {
        size_t n = 0u;
        auto rc = duct_xread(pre_conn->fd, pre_conn->probe.listener->xport_type,
                             duct_pre_conn_probe_room(pre_conn), &n, nullptr, 0, nullptr);
        if (!duct_io_on_pre_conn_probed(pre_conn, rc, n) || rc != rc_ok)
            return;
    }
}

/** @brief Entry guard and kick-off for one conn's RX drive; the actual
 *  recv()-to-EAGAIN loop runs in the events backend, calling back into
 *  this file's own reserve, commit, and done steps. This function only
 *  decides whether a drive should start at all.
 */
static void s_rx_start(duct_conn_t *conn)
{
    if (!conn || !duct_conn_rx_olb(conn))
        return;
    if (duct_conn_state(conn) & (fl_conn_closed | fl_conn_suspended | fl_conn_rx_full | fl_conn_rx_eof)) {
        duct_events_rx_stall(conn->fd, conn->rx_buf->h.ext_ptr);
        return;
    }
    /* A protocol error leaves the wire's parser state untrustworthy, so
     * reading on desynced state risks misparsed frame boundaries — RX
     * stops for good while TX still drains gracefully. Checked alone:
     * fl_conn_closing only lands once the close fence has run, but RX
     * must stop the instant the error is detected. duct_conn_acquire
     * resets this field per generation, so a stale value cannot leak
     * into a reused slot. */
    if (duct_gen_req_reason(duct_atomic_load(duct_conn_gen_req(conn), relaxed)) == close_protocol_error) {
        duct_events_rx_stall(conn->fd, conn->rx_buf->h.ext_ptr);
        return;
    }
    duct_events_drive_rx((void *)(uintptr_t)s_conn_tag_word(conn));
}

/** @brief Latch @p conn's RX as stalled until the worker's acks reach its
 *  resume target.
 *  Publishes @ref duct_olb_rx_resume_total for @p min_avail and @p restart as
 *  @c resume_at ahead of the latch, so the ack reaching it reposts the read.
 *  The @c seq_cst fence pairs with @ref s_rx_ack_check's: that check either
 *  sees the latch and reposts, or its ack is visible to whatever the caller
 *  checks after this.
 */
static void s_rx_latch([[maybe_unused]] duct_io_t *t, duct_conn_t *conn,
                       size_t min_avail, bool restart)
{
    duct_atomic_store(&conn->rx_buf->resume_at,
                      duct_olb_rx_resume_total(conn->rx_buf, min_avail, restart), relaxed);
    duct_conn_state_set(conn, fl_conn_rx_full);
    atomic_thread_fence(memory_order_seq_cst);
    duct_rtstat_obj_inc(t, rtstats.rx_full_latch, 1);
}

/** @brief Repost @p conn's read when no worker ack is left to clear the latch.
 *  A posted byte still unacked means an ack is coming and carries the repost
 *  with it; past that, nothing else wakes this conn, so the repost chains on
 *  itself until the stall lifts.
 */
static void s_rx_latch_repost(duct_conn_t *conn)
{
    uint64_t head = duct_atomic_load(&conn->rx_buf->h.head, relaxed);
    if (head < duct_olb_rx_posted_total(conn->rx_buf))
        return;
    auto ch = duct_conn_handle_get(conn);
    duct_io_post_rx_read(&ch);
}

/** @brief Shared OLB-space-with-latch dance: tries the OLB's own space check
 *  and, when it answers @c olb_rx_full, latches the stall and rechecks.
 *
 *  @p min_avail is 1 for a stream conn. A record-framed one demands
 *  @c duct_olb_rx_t::read_unit plus the backend's read scratch, clamped to the
 *  buffer, or @c duct_vnet_cut_max on a vnet leg, and may open a second pass;
 *  a stream conn waits for compaction.
 *
 *  The latch synchronizes with worker acknowledgments to avoid polling for
 *  buffer space.
 *
 *  @retval false  No room after the recheck; the latch is set, and either the
 *                 worker's owed ack or the self-repost retries.
 *  @retval true   The output pointer and length hold the raw OLB reservation.
 */
static bool s_rx_reserve_space([[maybe_unused]] duct_io_t *t, duct_conn_t *conn, size_t min_avail,
                               uint8_t **out_ptr, size_t *out_avail)
{
    bool restart = duct_conn_record_framed(conn);
    auto space = duct_olb_rx_try_space(conn->rx_buf, min_avail, restart, out_ptr, out_avail);
    if (space != olb_rx_full)
        return true;
    /* A stalled reactive backend will not re-fire for backlog already
     * signaled, so a worker ack reposts against the latch. */
    s_rx_latch(t, conn, min_avail, restart);
    space = duct_olb_rx_try_space(conn->rx_buf, min_avail, restart, out_ptr, out_avail);
    if (space == olb_rx_full) {
        s_rx_latch_repost(conn);
        return false;
    }
    duct_conn_state_clear(conn, fl_conn_rx_full);
    return true;
}

/** @brief Fill @p out's reconciliation fields and refuse the read.
 *  @c fd and @c io_priv are set even on this false return: a level-triggered
 *  backend reads them off its drive loop's exit to reconcile its own
 *  read-interest bit on a "not driving this turn" outcome.
 */
static bool s_rx_reserve_stall(const duct_conn_t *conn, duct_io_xfer_t *out)
{
    assert(duct_conn_has_olb(conn));
    out->fd = conn->fd;
    out->io_priv = conn->rx_buf->h.ext_ptr;
    out->olb_hdr = &conn->rx_buf->h;
    return false;
}

/** @brief Most ring bytes one batched read lays out, the span one coalesced read
 *  takes.
 *  Every unit but the last staged one fills a whole read unit however short its
 *  datagram, so a wire with a large @c max_frame stays on single reads, which
 *  pack its ring. */
static constexpr size_t rx_units_span = kbytes(64u);
static_assert(duct_x_recv_batch_max <= UINT16_MAX, "duct_io_xfer_t::units must hold a whole batch");

/* Supplies the stream-vs-record minimum, and on a record-framed xport hands
 * back a pointer one header past the reservation, leaving the gap
 * duct_io_rx_commit fills. There the span also stops duct_events_rx_scratch
 * short of the reservation's end, room the backend keeps its per-read state
 * in until the read completes. A vnet leg's span holds the packet alone; its
 * header span rides out->ctx. */
bool duct_io_rx_reserve(void *tag, duct_io_xfer_t *out)
{
    auto conn = s_conn_from_tag(tag);
    duct_do_if(!conn, return false);
    /* Closed/suspended/ended gate: a reactive backend already checked this
     * before reaching here, so it is redundant there. A proactive
     * backend's own completion chain reposts unconditionally without
     * touching duct_conn_t, so only this check stops its next read after an
     * rx_op_pause or the end of the conn's input. */
    if (duct_conn_state(conn) & (fl_conn_closed | fl_conn_suspended | fl_conn_rx_eof))
        return s_rx_reserve_stall(conn, out);
    auto t = s_io_this;
    uint8_t *ptr = nullptr;
    size_t avail = 0u;
    size_t rec = duct_conn_record_framed(conn) ? sizeof(duct_dgram_rec_hdr_t) : 0u,
           scratch = rec ? duct_events_rx_scratch : 0u;
    size_t min_avail = 1u;
    if (rec) {
        /* The OLB describes one coalesced group at a time, so a read landing
         * on top of an undescribed one has nowhere to go: committed as a single
         * record it fails the first datagram and drops the rest with it.
         * Refusing the read leaves those datagrams in the kernel socket buffer,
         * and the group is described without a read at all — by the post
         * duct_frame_rx_retry_drain makes once the node blocking it drains. */
        if (conn->rx_buf->group_bytes) {
            s_rx_latch(t, conn, 1u, false);
            s_rx_latch_repost(conn);
            return s_rx_reserve_stall(conn, out);
        }
        duct_olb_rx_rewind(conn->rx_buf);
        /* Demands room for the largest span one read can answer with, so recv()
         * is never offered less: a token minimum lets a nearly-full OLB hand it
         * a smaller one, and MSG_TRUNC then costs the whole arriving datagram,
         * or every datagram of an arriving group. Latching parks that backlog
         * in the kernel socket buffer intact instead. The clamp covers a wire
         * declaring max_frame past the whole OLB, and a read span no larger
         * than the record header, which a conn carrying no wire keeps for
         * its whole life. */
        min_avail = conn->rx_buf->read_unit + scratch;
        if (min_avail <= rec + scratch || min_avail > conn->rx_buf->h.buf_size)
            min_avail = conn->rx_buf->h.buf_size;
        /* A vnet read lands in the ring and is cut there, so the room to demand
         * is the largest cut, which keeps the span above duct_vnet_gso_max: a
         * tun clips a longer read to its span with no sign. */
        if (conn->vnet_hdr_len)
            min_avail = duct_vnet_cut_max;
    }
    if (!s_rx_reserve_space(t, conn, min_avail, &ptr, &avail))
        return s_rx_reserve_stall(conn, out);
    uint8_t *buf = ptr + rec;
    size_t size = avail - rec - scratch,
           unit = conn->rx_buf->read_unit;
    uint16_t units = 1u;
    void *ctx = nullptr;
    if (conn->vnet_hdr_len) {
        t->vnet_hdr_span = (duct_view_u8){ duct_at(t->vnet_hdr), conn->vnet_hdr_len };
        ctx = &t->vnet_hdr_span;
    } else if (conn->xport_type == x_udp_peer && conn->wire_parser && unit > rec
               && t->frame_rx.frame_ceiling > 1u) {
        /* One datagram per read unit, a record header gap ahead of each span.
         * Only the wire parse walks that layout, and a frame posts together
         * with the pad after it, which a frame_ceiling of 1 has no room for. */
        size_t fit = duct_min(duct_min((size_t)duct_x_recv_batch_max, rx_units_span / unit),
                              (avail - scratch) / unit);
        if (fit > 1u) {
            units = (uint16_t)fit;
            size = unit - rec;
        }
    }
    /* ctx is the read argument duct_xread takes on x_raw_packet, the vnet
     * header span, and null on every other xport that has a ring. It is never
     * conn->ctx, which holds the xport's own conn state. */
    *out = (duct_io_xfer_t){
        .buf = buf, .size = size,
        .fd = conn->fd, .xport_type = conn->xport_type,
        .ctx = ctx,
        .io_priv = conn->rx_buf->h.ext_ptr, .olb_hdr = &conn->rx_buf->h,
        .units = units,
    };
    return true;
}

/** @brief Stage a coalesced read of @p seg-sized datagrams: the first as an
 *  ordinary record, the rest as the OLB's coalesced tail.
 *
 *  A record prefix delimits one datagram for @c on_parse, and the read landed
 *  packed with room for exactly one — the gap @ref duct_io_rx_reserve leaves in
 *  front of it. The first datagram takes that gap. The rest carry their length
 *  in the descriptor the worker actually reads, so they need no prefix and
 *  nothing moves to make room for one.
 *
 *  Cutting from @p seg alone holds only where a record parses to its own body,
 *  @ref duct_wire_records. Coalescing is asked for at wire bind and only for
 *  such a wire, so @p seg reaches here set on no other.
 *
 *  @return false while the OLB's previous coalesced tail is still undescribed;
 *          the caller then commits nothing and the read is lost.
 */
static bool s_dgram_rx_commit_group(duct_olb_rx_t *rx, size_t n, size_t seg)
{
    duct_do_if(rx->group_bytes, return false);
    duct_dgram_rx_header_commit(rx, seg);
    auto h = &rx->h;
    rx->group_off = (uint32_t)h->stage;
    rx->group_seg = (uint32_t)seg;
    rx->group_bytes = (uint32_t)(n - seg);
    duct_atomic_store(&h->tail, h->stage += n - seg, release);
    return true;
}

/** @brief Cut a vnet leg's read of @p n bytes, header span and packet, in
 *  place in @p conn's ring under the leg's GSO record bound, and publish it.
 *  @return false when the cut refused the read, which is then lost. */
static bool s_vnet_rx_commit(duct_conn_t *conn, size_t n)
{
    auto h = &conn->rx_buf->h;
    unsigned pkts = 0u;
    size_t out = duct_vnet_cut(duct_at(s_io_this->vnet_hdr),
                               conn->rx_buf->data + h->stage,
                               n - conn->vnet_hdr_len,
                               duct_atomic_load(&conn->vnet_gso, relaxed),
                               duct_olb_rx_room(conn->rx_buf), &pkts);
    if (!out) {
        duct_rtstat_obj_inc(s_io_this, rtstats.vnet_rx_drop, 1);
        return false;
    }
    if (pkts > 1u) {
        duct_rtstat_obj_inc(s_io_this, rtstats.vnet_rx_tso_reads, 1);
        duct_rtstat_obj_inc(s_io_this, rtstats.vnet_rx_tso_pkts, pkts);
    }
    duct_atomic_store(&h->tail, h->stage += out, release);
    return true;
}

void duct_io_rx_commit(void *tag, size_t n, size_t seg)
{
    auto conn = s_conn_from_tag(tag);
    duct_do_if(!conn, return);
    if (duct_conn_record_framed(conn)) {
        /* A datagram outside its wire's bounds is dropped whole, nothing
         * committed, a coalesced read held to max_frame by its segment. A vnet
         * read carries its virtio_net_hdr on top of the minimum and skips the
         * max_frame bound: it holds a whole offloaded packet train. */
        size_t min = duct_wire_dgram_min(conn->wire) + conn->vnet_hdr_len;
        duct_do_if(n < min, return);
        if (!conn->vnet_hdr_len && s_dgram_rx_oversize(conn, seg && seg < n ? seg : n))
            return;
        /* Read off this conn's own connected socket, so the source is the
         * address it already replies to: any candidate standing for this leg
         * is stale from here. */
        s_dgram_peer_candidate_clear(conn);
        /* A coalesced read is described or lost, never committed as one record:
         * its bytes are several datagrams, and a wire handed them as one fails
         * the first and drops the rest with it. A vnet read likewise becomes one
         * record per packet, or is lost whole. Both post at once, so the worker
         * starts on a burst while this thread reads the rest, and the OLB's one
         * coalesced tail clears before the next reserve. A single record waits
         * for read_unit unposted bytes, which hands small datagrams over in
         * read-unit batches; duct_io_rx_done posts the rest. */
        if (conn->vnet_hdr_len) {
            if (!s_vnet_rx_commit(conn, n))
                return;
        } else if (seg && seg < n) {
            s_rtstat_gro(n, seg);
            if (!s_dgram_rx_commit_group(conn->rx_buf, n, seg))
                return;
        } else {
            auto rx = conn->rx_buf;
            duct_dgram_rx_header_commit(rx, n);
            if (rx->h.stage - rx->posted_off < rx->read_unit)
                return;
        }
        auto t = s_io_this;
        duct_frame_rx_post(&t->route, &t->frame_rx, conn);
        return;
    }
    auto h = &conn->rx_buf->h;
    duct_atomic_store(&h->tail, h->stage += n, release);
}

void duct_io_rx_commit_units(void *tag, const uint32_t *lens, uint32_t n)
{
    auto conn = s_conn_from_tag(tag);
    duct_do_if(!conn, return);
    auto rx = conn->rx_buf;
    size_t rec = sizeof(duct_dgram_rec_hdr_t),
           unit = rx->read_unit;
    auto base = rx->data + rx->h.stage;
    uint32_t last = n;
    for (uint32_t i = 0u; i < n; ++i) {
        uint32_t hdr = duct_dgram_rec_void;
        if (s_dgram_rx_admits(conn, lens[i])) {
            hdr = rec + lens[i] < unit ? lens[i] | duct_dgram_rec_padded : lens[i];
            last = i;
        }
        duct_dgram_rec_hdr_encode(base + (size_t)i * unit, hdr);
    }
    if (last == n)
        return;
    /* The ring stops at the last datagram's end, so its record carries no
     * padded bit: every pad acks staged bytes only. */
    duct_dgram_rec_hdr_encode(base + (size_t)last * unit, lens[last]);
    s_dgram_peer_candidate_clear(conn);
    auto h = &rx->h;
    duct_atomic_store(&h->tail, h->stage += (size_t)last * unit + rec + lens[last], release);
    auto t = s_io_this;
    duct_frame_rx_post(&t->route, &t->frame_rx, conn);
}

void duct_io_rx_done(void *tag, duct_result_t rc)
{
    auto conn = s_conn_from_tag(tag);
    duct_do_if(!conn, return);
    auto t = s_io_this;
    /* Unconditional: duct_frame_rx_post's own tail-vs-posted_off check
     * already no-ops when nothing new arrived, so there is no cheaper
     * gate to duplicate here. */
    duct_frame_rx_post(&t->route, &t->frame_rx, conn);
    /* The receive follow steps only on a drive that read the socket dry. A
     * drive the full ring latched ends on the backend's initial rc_again too,
     * its kernel queue still full, and a buffer shrunk under that queue has the
     * kernel prune it. */
    if (rc == rc_again && conn->xport_type == x_tcp
        && !(duct_conn_state(conn) & (fl_conn_rx_full | fl_conn_suspended | fl_conn_closed)))
        switch (duct_x_sock_rx_follow(duct_x_sock_rx_of(conn->rx_buf), conn->fd,
                                      duct_atomic_load(&conn->rx_buf->acked, relaxed))) {
        case x_follow_set:
            duct_rtstat_obj_inc(t, rtstats.tcp_rcvbuf_sets, 1);
            [[fallthrough]];
        case x_follow_read:
            duct_rtstat_obj_inc(t, rtstats.tcp_rcvbuf_reads, 1);
            break;
        case x_follow_none:
            break;
        }
    if (rc == rc_closed && duct_conn_reads_eof(conn)) {
        /* The input ends once: a parse error in this same drive ends it first. */
        if (!duct_has(duct_conn_state(conn), fl_conn_rx_eof)) {
            duct_conn_state_set(conn, fl_conn_rx_eof);
            duct_frame_rx_end(&t->route, &t->frame_rx, conn);
        }
    } else if (rc == rc_fatal || rc == rc_invalid_arg) {
        /* rc_invalid_arg is duct_xread refusing this conn's transport on this
         * build, a permanent condition: the close carries it to the protocol
         * as on_conn_lost with close_io_error. */
        s_conn_close(t, conn, close_io_error);
    }
}

/** @brief Entry guard and kick-off for one conn's TX drive; the actual
 *  send()-until-drained-or-blocked loop runs in the events backend,
 *  calling back into this file's own peek, advance, and done steps.
 */
static void s_tx_start(duct_conn_t *conn)
{
    if (!conn || !duct_conn_tx_olb(conn) || duct_has(duct_conn_state(conn), fl_conn_closed))
        return;
    duct_events_drive_tx((void *)(uintptr_t)s_conn_tag_word(conn));
}

/** @brief Fill @p out's reconciliation fields, settle a pending close, refuse
 *  the send.
 *  Same write-interest reconciliation as @ref s_rx_reserve_stall, and the
 *  fields are captured ahead of the close because that close can reclaim
 *  @p conn outright. A close this call wins leaves @c out->fd at
 *  @c duct_sock_bad: the conn's reactor entry is gone, its poll slot free to
 *  hold another entry by then, and nothing is left to reconcile.
 *  @param readable bytes offered by the ring; only zero transitions
 *                  @c fl_conn_closing.
 */
static bool s_tx_peek_idle(duct_conn_t *conn, size_t readable, duct_io_xfer_t *out)
{
    assert(duct_conn_has_olb(conn));
    out->fd = conn->fd;
    out->io_priv = conn->tx_buf->h.ext_ptr;
    out->olb_hdr = &conn->tx_buf->h;
    if (readable == 0u && duct_has(duct_conn_state(conn), fl_conn_closing)
        && s_conn_close(s_io_this, conn,
                        duct_gen_req_reason(duct_atomic_load(duct_conn_gen_req(conn), relaxed))))
        out->fd = duct_sock_bad;
    return false;
}

/* Record-framed: one record's payload, positioned past the internal
 * record-length prefix the worker staged ahead of the wire's own bytes,
 * independent of whatever shape on_pack itself writes, and stripped before the
 * peer sees it; the prefix's duct_dgram_rec_gso bit stays out of the length.
 * Stream: the whole readable region, an x_tcp one cut to the opening's piece.
 * Nothing readable resolves a pending respond-then-close right here:
 * fl_conn_closing was set while this conn still had unflushed TX, and this is
 * the drain that finally empties it. */
bool duct_io_tx_peek(void *tag, duct_io_xfer_t *out)
{
    auto conn = s_conn_from_tag(tag);
    duct_do_if(!conn, return false);
    size_t rec = duct_conn_record_framed(conn) ? sizeof(duct_dgram_rec_hdr_t) : 0u;
    uint64_t head = 0u;
    size_t n = duct_olb_tx_readable(conn->tx_buf, &head);
    /* n == rec is a record header with no payload, which a zero-length
     * datagram legitimately stages: only a short header or an empty ring
     * is idle. */
    if (n == 0u || n < rec)
        return s_tx_peek_idle(conn, n, out);
    auto base = conn->tx_buf->data + (size_t)head;
    size_t len = n;
    if (rec) {
        len = duct_dgram_rec_hdr_decode((const uint8_t *)base) & ~duct_dgram_rec_gso;
        assert(n >= rec + len); /* worker staged reclen + wire bytes together as one indivisible transaction */
    }
    /* The bound lives here because iocp posts this span as it stands. */
    if (conn->xport_type == x_tcp) {
        size_t piece = duct_x_sock_tx_piece(duct_x_sock_tx_of(conn->tx_buf));
        len = piece && piece < len ? piece : len;
    }
    /* No .ctx: only a shared, unconnected socket needs the peer
     * address for duct_xwrite. */
    *out = (duct_io_xfer_t){
        .buf = base + rec, .size = len,
        .fd = conn->fd, .xport_type = conn->xport_type,
        .io_priv = conn->tx_buf->h.ext_ptr, .olb_hdr = &conn->tx_buf->h,
    };
    return true;
}

/** @brief Wake @p conn's worker if a turn armed @c fl_conn_tx_wait on it.
 *  Called after every TX head advance and on every device signal. The fence
 *  pairs with the worker's arm, so either its room check after arming sees
 *  what io freed or this sees the flag, and with the fence the worker runs
 *  after clearing its wake latch. Nothing re-polls a missed wake. The flag
 *  spares a worker with nothing blocked a futex round trip per drained message.
 */
static void s_tx_wake_waiter(duct_conn_t *conn)
{
    atomic_thread_fence(memory_order_seq_cst);
    if (!duct_has(duct_conn_state(conn), fl_conn_tx_wait))
        return;
    duct_conn_state_clear(conn, fl_conn_tx_wait);
    duct_worker_wake_id(conn->worker_id);
}

/** @brief Release @p offered bytes of @p conn's TX ring, @p n of them sent.
 *  @p offered is a snapshot the peek call already captured this same drive
 *  iteration; re-reading the OLB's readable length here races a
 *  concurrently-staging worker.
 *  @return true while the drive may continue.
 */
static bool s_tx_advance(duct_conn_t *conn, size_t offered, size_t n)
{
    if (duct_conn_record_framed(conn)) {
        assert(n == offered || n == 0u); /* a record-framed transport ships a
                                           * packet whole or not at all, with
                                           * no short-write retry concept. */
        duct_olb_tx_advance(conn->tx_buf, sizeof(duct_dgram_rec_hdr_t) + offered);
        s_tx_wake_waiter(conn);
        return true;
    }
    duct_olb_tx_advance(conn->tx_buf, n);
    /* Counted here, where an iocp completion lands as well as a write's return. */
    if (conn->xport_type == x_tcp)
        duct_x_sock_tx_sent(duct_x_sock_tx_of(conn->tx_buf), n);
    s_tx_wake_waiter(conn);
    return n == offered; /* short write: socket buffer full, caller stops */
}

bool duct_io_tx_advance(void *tag, size_t offered, size_t n)
{
    auto conn = s_conn_from_tag(tag);
    duct_do_if(!conn, return false);
    return s_tx_advance(conn, offered, n);
}

/** @brief Address up to @p max whole records in the @p n ring bytes at
 *  @p base, payload spans only. */
static unsigned s_tx_rec_bufs(uint8_t *base, size_t n, duct_view_u8 *bufs, unsigned max)
{
    size_t rec = sizeof(duct_dgram_rec_hdr_t),
           off = 0u;
    unsigned count = 0u;
    while (count < max && n - off >= rec) {
        size_t len = duct_dgram_rec_hdr_decode((const uint8_t *)base + off);
        if (n - off < rec + len)
            break;
        bufs[count++] = (duct_view_u8){ .data = base + off + rec, .size = len };
        off += rec + len;
    }
    return count;
}

/** @brief Address up to @p max whole records queued at @p conn's ring head.
 *  Payload spans only: each record's internal length prefix is stepped over,
 *  the way @ref duct_io_tx_peek strips the single one it reports. The walk
 *  stops at the first record the readable run does not hold entirely, so a
 *  worker staging concurrently never contributes a half record.
 *  @return records addressed; 0 on a leg with no record boundaries to find.
 */
static unsigned s_tx_peek_bufs(duct_conn_t *conn, duct_view_u8 *bufs, unsigned max)
{
    if (!duct_conn_record_framed(conn))
        return 0u;
    uint64_t head = 0u;
    size_t n = duct_olb_tx_readable(conn->tx_buf, &head);
    return s_tx_rec_bufs(conn->tx_buf->data + (size_t)head, n, bufs, max);
}

unsigned duct_io_tx_peek_bufs(void *tag, duct_view_u8 *bufs, unsigned max)
{
    auto conn = s_conn_from_tag(tag);
    duct_do_if(!conn, return 0u);
    return s_tx_peek_bufs(conn, bufs, max);
}

void duct_io_tx_advance_records(void *tag, unsigned n)
{
    auto conn = s_conn_from_tag(tag);
    duct_do_if(!conn, return);
    assert(n <= duct_dgram_tx_batch);
    if (n > 1u)
        s_rtstat_gso((duct_x_gso_tally_t){ .writes = 1u, .dgrams = n });
    duct_view_u8 bufs[duct_dgram_tx_batch];
    n = s_tx_peek_bufs(conn, bufs, n);
    for (unsigned i = 0u; i < n; ++i)
        duct_discard s_tx_advance(conn, bufs[i].size, bufs[i].size);
}

DUCT_XSEND_GROUPED_DECLARE(s_tx_send_grouped, duct_view_u8)
DUCT_XSEND_GROUPED_DECLARE(s_peer_send_grouped, duct_dgram_out_t)

/** @brief Ship the records queued behind @p conn's head in one pass.
 *
 *  Only a connected per-peer socket qualifies: the batch carries no
 *  destination per entry, and a leg whose ring holds a byte stream has no
 *  record boundaries to send on. A single record declines too, leaving the
 *  caller's one-record path to handle it without a second ring walk.
 *
 *  @param out_rc untouched unless this call took the batch. @c rc_drop from the
 *         send names the head record as one the path never carries: it is
 *         stepped over here and reported as @c rc_ok, matching what the
 *         one-record path does with the same verdict.
 *  @return true once this call took the batch, whatever the send answered.
 */
static bool s_tx_send_batch(duct_conn_t *conn, const duct_io_xfer_t *p,
                            duct_result_t *out_rc)
{
    switch (p->xport_type) {
    case x_udp_peer:
        break;
    case x_raw: case x_raw_packet: case x_tcp: case x_udp:
    case x_udp_shared: case x_bt: case x_can: case x_inter: case x_local:
        return false;
    }
    duct_view_u8 bufs[duct_dgram_tx_batch];
    unsigned n = s_tx_peek_bufs(conn, bufs, duct_dgram_tx_batch);
    if (n < 2u)
        return false;
    unsigned sent = 0u;
    duct_x_gso_tally_t tally = {};
    *out_rc = s_tx_send_grouped(p->fd, bufs, n, &sent, &tally);
    s_rtstat_gso(tally);
    for (unsigned i = 0u; i < sent; ++i)
        duct_discard s_tx_advance(conn, bufs[i].size, bufs[i].size);
    switch (*out_rc) {
    case rc_ok:
        if (sent < n)
            *out_rc = rc_again;
        break;
    case rc_drop:
        duct_discard s_tx_advance(conn, bufs[0].size, 0u);
        *out_rc = rc_ok;
        break;
    default:
        break;
    }
    return true;
}

/* Resolves connection tag once for batch send and cursor advance. */
bool duct_io_tx_send(void *tag, const duct_io_xfer_t *p, duct_result_t *out_rc)
{
    auto conn = s_conn_from_tag(tag);
    duct_do_if(!conn,
        *out_rc = rc_closed;
        return false
    );
    if (s_tx_send_batch(conn, p, out_rc))
        return *out_rc == rc_ok;
    size_t nwritten = 0u,
           offered = p->size;
    /* A vnet leg's ring holds bare packets and GSO records, the prefix bit
     * telling them apart. A packet leaves under a zero header; a record leaves
     * as its packet under the header duct_vnet_gso_open builds, its segment
     * size counted as written since a record advances whole, and one that
     * fails to open is dropped. No header's bytes count toward the advance. */
    if (conn->vnet_hdr_len) {
        duct_view_u8 pkt = { .data = p->buf, .size = p->size };
        bool gso = duct_dgram_rec_hdr_decode((const uint8_t *)p->buf - duct_dgram_record_hdr_size)
                 & duct_dgram_rec_gso;
        uint8_t vh[duct_vnet_hdr_max];
        bool bad = gso && !duct_vnet_gso_open(&pkt, vh);
        duct_view_u8 spans[2] = {
            { .data = gso ? vh : (uint8_t *)&duct_vnet_zero[0], .size = conn->vnet_hdr_len },
            pkt,
        };
        *out_rc = bad ? rc_drop : duct_xwritev(p->fd, p->xport_type, spans, 2u, &nwritten, 0);
        nwritten = nwritten > conn->vnet_hdr_len
                 ? nwritten - conn->vnet_hdr_len + (p->size - pkt.size) : 0u;
    } else {
        /* Under the platform's cap a write takes at most the cap, with the
         * flags the cap names. A capped write counts whole, so the drive goes
         * on until the socket refuses. */
        int flags = 0;
        if (p->xport_type == x_tcp) {
            size_t cap = duct_x_sock_tx_cap(duct_x_sock_tx_of(conn->tx_buf), &flags);
            duct_rtstat_obj_inc(s_io_this, rtstats.tcp_writes, 1);
            duct_rtstat_obj_inc(s_io_this, rtstats.tcp_eor_writes, cap != 0u);
            if (cap)
                offered = duct_min(offered, cap);
        }
        *out_rc = duct_xwrite(p->fd, p->xport_type,
                              (duct_view_u8){ .data = p->buf, .size = offered },
                              &nwritten, p->ctx, flags);
    }
    switch (*out_rc) {
    case rc_ok:
        return s_tx_advance(conn, offered, nwritten);
    case rc_drop:
        return s_tx_advance(conn, p->size, 0u);
    default:
        return false;
    }
}

void duct_io_tx_done(void *tag, duct_result_t rc)
{
    if (rc != rc_fatal)
        return;
    auto conn = s_conn_from_tag(tag);
    duct_do_if(!conn, return);
    s_conn_close(s_io_this, conn, close_io_error);
}

void duct_io_tx_write_armed_set(void *tag, bool armed)
{
    auto conn = s_conn_from_tag(tag);
    duct_do_if(!conn, return);
    if (!duct_conn_has_olb(conn))
        return;
    if (armed)
        duct_conn_state_set(conn, fl_conn_write_armed);
    else
        duct_conn_state_clear(conn, fl_conn_write_armed);
    /* Only a drive the socket refused with bytes still readable steps the
     * platform's lowat follow: a leg that never backs up keeps the bound it
     * was created with. */
    if (armed && conn->xport_type == x_tcp)
        switch (duct_x_sock_tx_follow(duct_x_sock_tx_of(conn->tx_buf), conn->fd)) {
        case x_follow_set:
            duct_rtstat_obj_inc(s_io_this, rtstats.tcp_lowat_sets, 1);
            [[fallthrough]];
        case x_follow_read:
            duct_rtstat_obj_inc(s_io_this, rtstats.tcp_lowat_reads, 1);
            break;
        case x_follow_none:
            break;
        }
}

/** @brief Push @p conn's staged TX out, unless nothing here owns its egress.
 *  No @c x_inter leg has one this thread drives: a device leg is written into
 *  by the worker that commits, a host-driven one by the host. The guard earns
 *  its place on the union — @c tx_buf is the word an inter lane spans, so
 *  @ref s_tx_start reads a lane pointer as an OLB without it.
 */
static void s_req_do_tx_drain(duct_conn_t *conn)
{
    duct_do_if(conn->xport_type == x_inter, return);
    s_tx_start(conn);
}

static void s_req_do_rx_read(duct_conn_t *conn)
{
    /* Clear fl_conn_rx_full to enable buffer space re-check in s_rx_start. */
    duct_conn_state_clear(conn, fl_conn_rx_full);
    /* conn->ctx, not the xport alone: a host-driven x_inter leg has no device
     * to read and belongs on the socket path below. Clearing the latch first
     * lets this drive get past s_device_drive's own entry guard. */
    if (conn->xport_type == x_inter && conn->ctx) {
        s_device_drive(conn);
        return;
    }
    s_rx_start(conn);
}

/** @brief Claim a posted close request on @p conn.
 *  An empty TX ring, or a @c close_timeout reason, which drops what the ring
 *  holds, closes now; a ring still draining leaves @c fl_conn_closing set for
 *  @ref s_tx_peek_idle to close on once a drive finds it empty. A cleared flag
 *  means a slot recycle or a race already resolved this close, a no-op.
 *  @return true once this call wins the close; a caller dispatching
 *  further bits against @p conn must stop there.
 */
static bool s_req_do_close(duct_io_t *t, duct_conn_t *conn)
{
    if (!duct_has(duct_conn_state(conn), fl_conn_closing))
        return false;
    auto reason = duct_gen_req_reason(duct_atomic_load(duct_conn_gen_req(conn), relaxed));
    if (reason != close_timeout && duct_conn_tx_olb(conn)) {
        uint64_t head = 0u;
        if (duct_olb_tx_readable(conn->tx_buf, &head) != 0u)
            return false;
    }
    return s_conn_close(t, conn, reason);
}

/** @brief Coalesced per-conn I/O request resolved by handle to drop stale
 *  requests across slot reclaims.
 *
 *  Dispatches every req_flags bit live at execution time in the fixed order
 *  wire_rebind -> tx_drain -> close_req -> rx_resume -> fence_retry -> retire. wire_rebind runs first so a
 *  same-pass rx_resume sees the already-rebound wire. tx_drain runs before
 *  close_req so a respond-then-close turn gets its best chance at closing
 *  in the same wake. retire runs last because close_req and retire can
 *  both reclaim @p conn synchronously, making the slot visible to a
 *  concurrent @ref duct_conn_acquire immediately — close_req short-circuits
 *  subsequent dispatch on connection close.
 *  A reclaim held for this node runs ahead of all of it and ends the pass;
 *  on a closed conn only fence_retry and retire run.
 *  Cross-conn order is unspecified; only this per-conn ordering is a
 *  correctness requirement.
 */
static duct_exec_rc_t s_req_exec(void *self)
{
    auto m = (duct_msg_conn_req *)self;
    auto conn = duct_conn_by_handle(m->handle);
    if (!conn)
        return exec_done;
    auto t = s_io_this;
    /* fetch_and, not exchange: gen_req's generation, and between close posts
     * its reason, must survive this clear — only the flags bits get zeroed.
     * Returns the pre-clear word, so bits set after an earlier racing post
     * but before this AND still land in it. acq_rel, not acquire: this clear
     * re-opens the coalescing gate in s_req_post_ex, so its store must
     * publish what duct_io_on_wake already did to &m->msg — the reverse-pass
     * write to its own next pointer — before a winning racer there writes
     * that same pointer again. */
    duct_conn_req_flags_t flags = duct_gen_req_flags(
        duct_atomic_fetch(and, duct_conn_gen_req(conn), ~(uint64_t)gen_req_flags_mask, acq_rel));
    auto state = duct_conn_state(conn);
    /* duct_io_on_wake read this node's next before running it, so the slot
     * can go now. */
    if (duct_has(state, fl_conn_reclaim_held)) {
        duct_conn_state_clear(conn, fl_conn_reclaim_held);
        duct_conn_reclaim(conn);
        return exec_done;
    }
    if (duct_has(state, fl_conn_closed))
        flags &= fl_req_fence_retry | fl_req_retire;
    /* Rebind first: nothing else in this function touches the wire, but
     * running it first keeps any rx_resume in the same pass reading the
     * already-rebound wire. */
    if (duct_has(flags, fl_req_wire_rebind))
        duct_conn_wire_rebind(&t->route, conn);
    if (duct_has(flags, fl_req_tx_drain))
        s_req_do_tx_drain(conn);
    if (duct_has(flags, fl_req_close)) {
        /* I/O-thread-local now: the worker's post only packs fl_req_close
         * and reason into gen_req — this dispatch actually arms the
         * persistent pending flag, single-threaded, with no race
         * against s_tx_start's own later read of it. */
        duct_conn_state_set(conn, fl_conn_closing);
        if (s_req_do_close(t, conn))
            return exec_done; /* conn may already be a different occupant's past this point */
    }
    if (duct_has(flags, fl_req_peer_roam))
        s_req_do_peer_roam(conn);
    if (duct_has(flags, fl_req_rx_resume))
        s_req_do_rx_read(conn);
    if (duct_has(flags, fl_req_fence_retry))
        duct_conn_fence_retry(&t->route, conn);
    if (duct_has(flags, fl_req_retire))
        duct_conn_fence_retire(conn);
    return exec_done;
}

duct_exec_fn duct_io_conn_req_exec_fn(void)
{
    return s_req_exec;
}

/** @brief Generation-checked CAS of @p bit into @p handle's conn's
 *  gen_req. On a 0->nonzero req_flags transition, posts conn's own
 *  embedded request message onto @p trunk's stack. Any other flags bit
 *  already set means a message for this conn is already posted and not
 *  yet drained, so the CAS alone is enough — that message resolves
 *  whatever bits are live when it runs.
 *
 *  A generation mismatch means a reclaim already won this conn's retire
 *  race, so the post is rejected outright. The generation check and the
 *  flags CAS run as one atomic operation on the same word, so a racing
 *  post and a racing reclaim order through gen_req's own modification
 *  order, with no gap between them.
 *
 *  The kick that returns a blocked wait is skipped when the posting thread
 *  owns @p trunk: the message already sits on that thread's own stack, and
 *  @ref duct_io_on_tick dispatches it before the next wait.
 *
 *  @return The 0->nonzero transition.
 */
static bool
s_req_post_ex(duct_io_trunk_t *trunk, duct_conn_handle_t handle,
                         duct_conn_req_flags_t bit, bool set_reason, duct_close_reason_t reason)
{
    auto conn = duct_conn_by_idx(handle.idx);
    uint64_t old = duct_atomic_load(duct_conn_gen_req(conn), relaxed);
    for (;; duct_cpu_relax()) {
        if (duct_gen_req_gen(old) != handle.gen)
            return false; /* slot already retired/reused under us: reject outright */
        uint64_t want = set_reason
            ? (old & ~(gen_req_reason_mask << gen_req_reason_shift))
              | ((uint64_t)reason << gen_req_reason_shift) | (uint64_t)bit
            : old | (uint64_t)bit;
        /* acq_rel and acquire, not release and relaxed: the flags read
         * this loop settles on must acquire the acq_rel clear of this
         * same word on the dispatch side, or a winning 0->nonzero
         * transition here can push the message while the io thread's
         * own reverse pass is still writing that same node's next
         * pointer. */
        if (duct_atomic_cas(weak, duct_conn_gen_req(conn), &old, want, acq_rel, acquire))
            break;
    }
    if (duct_gen_req_flags(old))
        return false; /* coalesced: a message for conn is already posted */
    auto m = duct_conn_req_msg(conn);
    m->handle = handle;
    duct_msg_stack_push(&trunk->stack, &m->msg);
    auto t = s_io_this;
    if (!t || trunk != &t->trunk)
        s_kick(trunk);
    return true;
}

bool duct_io_trunk_req_post(duct_io_trunk_t *trunk, duct_conn_handle_t handle,
                              duct_conn_req_flags_t bit)
{
    return s_req_post_ex(trunk, handle, bit, false, close_normal);
}

/** @brief Close-request post: packs @p reason into gen_req atomically
 *  with fl_req_close, in the same CAS, so a losing race can never leave
 *  a stale reason for a winning one.
 */
static bool
s_req_post_close(duct_io_trunk_t *trunk, duct_conn_handle_t handle, duct_close_reason_t reason)
{
    return s_req_post_ex(trunk, handle, fl_req_close, true, reason);
}

/** @brief @p handle resolve, an out-of-range io_id rejected in the same step. */
static inline duct_conn_t *s_conn_ranged(duct_conn_handle_t handle)
{
    auto c = duct_conn_by_handle(handle);
    return (c && c->io_id < s_imod.n_io) ? c : nullptr;
}

/** @brief One duct_io_post_* function @p fn: resolves the conn, then
 *  posts @p bit through the trunk.
 */
#define s_io_post_bit(fn, bit) \
    void fn(const duct_conn_handle_t *conn) \
    { \
        auto _c = s_conn_ranged(*conn); \
        if (!_c) \
            return; \
        duct_io_trunk_req_post(&s_imod.xports[_c->io_id].trunk, *conn, (bit)); \
    }

/** @brief Shared push+kick tail for every msg-poster below. */
static inline void s_msg_push(unsigned io_id, duct_msg_t *msg)
{
    duct_msg_stack_push(&s_imod.xports[io_id].trunk.stack, msg);
    s_kick(&s_imod.xports[io_id].trunk);
}

/** @brief Any-thread to io outbound connect request: dns_err == rc_ok
 *  carries a resolved target, its prepared socket and a peer or, for
 *  x_local, a socket path; any other value is a DNS failure delivered
 *  straight to whichever on_error channel seed.kind selects.
 */
duct_msg_chain_decl(duct_msg_io_connect,
    duct_dial_target_t   target;
    uint32_t             connect_timeout_ms;
    duct_result_t        dns_err;
    duct_sock_t          fd;
    duct_conn_intent_t  seed;
);

static duct_exec_rc_t s_msg_exec_connect(void *self)
{
    auto m = (duct_msg_io_connect *)self;
    auto t = s_io_this;
    if (m->dns_err != rc_ok)
        s_connect_error(&t->route, m->seed, m->dns_err);
    else
        s_dial_begin(t, &m->target, m->seed, m->connect_timeout_ms, m->fd);
    return duct_msg_done(m);
}

void duct_io_post_close_request(const duct_conn_handle_t *conn, duct_close_reason_t reason)
{
    duct_worker_conn_train_flush(conn);
    auto c = s_conn_ranged(*conn);
    if (!c)
        return;
    s_req_post_close(&s_imod.xports[c->io_id].trunk, *conn, reason);
}

bool duct_io_parked(const duct_conn_t *conn)
{
    return conn->io_id < s_imod.n_io && duct_atomic_load(&s_imod.xports[conn->io_id].trunk.parked, relaxed);
}

bool duct_io_path_mtu(const duct_conn_t *conn, uint16_t *out)
{
    return !duct_has(duct_conn_state(conn), fl_conn_closed) && duct_xget_path_mtu(conn->fd, out);
}

duct_result_t duct_io_addrs(const duct_conn_t *conn, duct_peer_t *local, duct_peer_t *remote)
{
    if (duct_has(duct_conn_state(conn), fl_conn_closed))
        return rc_invalid_order;
    auto shared = conn->xport_type == x_udp_shared
                ? (const duct_dgram_shared_ctx_t *)conn->ctx : nullptr;
    struct sockaddr_storage mine, theirs;
    socklen_t len = sizeof mine;
    if (local && getsockname(shared ? shared->listener->listen_fd : conn->fd,
                             (struct sockaddr *)&mine, &len) != 0)
        return rc_invalid_order;
    len = sizeof theirs;
    if (remote && !shared && getpeername(conn->fd, (struct sockaddr *)&theirs, &len) != 0)
        return rc_invalid_order;
    if (local)
        *local = duct_io_peer_from_sockaddr((struct sockaddr *)&mine);
    if (remote)
        *remote = shared ? shared->peer : duct_io_peer_from_sockaddr((struct sockaddr *)&theirs);
    return rc_ok;
}

duct_result_t duct_io_tcp_congestion(const duct_conn_t *conn, char out[duct_tcp_cc_name_max])
{
    if (duct_has(duct_conn_state(conn), fl_conn_closed))
        return rc_invalid_order;
    return duct_xget_tcp_congestion(conn->fd, out) ? rc_ok : rc_not_supported;
}

duct_result_t duct_io_tcp_stats(const duct_conn_t *conn, duct_tcp_stats_t *out)
{
    if (duct_has(duct_conn_state(conn), fl_conn_closed))
        return rc_invalid_order;
    return duct_xget_tcp_stats(duct_x_sock_stats_of(conn->tx_buf), conn->fd, out)
         ? rc_ok : rc_not_supported;
}

uint64_t duct_io_tx_unsent(const duct_conn_t *conn)
{
    if (duct_has(duct_conn_state(conn), fl_conn_closed))
        return duct_tx_unsent_unread;
    return duct_xget_tx_unsent(conn->fd);
}

duct_result_t duct_io_tcp_ack_timeout(const duct_conn_t *conn, uint32_t ms)
{
    if (duct_has(duct_conn_state(conn), fl_conn_closed))
        return rc_invalid_order;
    return duct_xset_tcp_ack_timeout(conn->fd, ms) ? rc_ok : rc_not_supported;
}

void duct_io_post_tx_drain(const duct_conn_handle_t *conn)
{
    auto c = s_conn_ranged(*conn);
    if (!c)
        return;
    auto t = &s_imod.xports[c->io_id];
    if (!duct_io_trunk_req_post(&t->trunk, *conn, fl_req_tx_drain)) {
        duct_rtstat_atomic_inc(&t->rtstats.tx_drain_deduped, 1);
        return;
    }
    duct_rtstat_atomic_inc(&t->rtstats.tx_drain_posts, 1);
}

s_io_post_bit(duct_io_post_rx_read, fl_req_rx_resume)
s_io_post_bit(duct_io_post_peer_roam, fl_req_peer_roam)

void duct_io_post_wire_rebind(const duct_conn_handle_t *conn, const duct_proto_t *next)
{
    auto c = s_conn_ranged(*conn);
    if (!c)
        return;
    duct_atomic_store(&c->wire_rebind_next, next, relaxed);
    duct_io_trunk_req_post(&s_imod.xports[c->io_id].trunk, *conn, fl_req_wire_rebind);
}

s_io_post_bit(duct_io_retire_request, fl_req_retire)

/* Kicks without the park check: what it wakes the thread for, the frame-rx
 * retry drain, pushes nothing onto the trunk for that check to see. */
void duct_io_wake(unsigned io_id)
{
    if (io_id >= s_imod.n_io)
        return;
    duct_events_kick(s_imod.xports[io_id].trunk.events);
}

/** @brief Sends one queued datagram. @p arg is the owning listener. A
 *  closed listener, with listen_fd already duct_sock_bad, is terminal,
 *  treated as sent — nothing left to retry it against.
 *  @return false only on EAGAIN or EWOULDBLOCK; the drain loop stops
 *  there and leaves this entry, and the rest of the lane, queued.
 */
static bool s_dgram_tx_send(duct_vmq_hdr_t *hdr, void *arg)
{
    auto listener = (duct_listener_t *)arg;
    duct_do_if(listener->listen_fd == duct_sock_bad, return true);
    auto entry = (duct_dgram_tx_entry_t *)&hdr->payload[0];
    struct sockaddr_storage ss;
    auto ss_len = duct_io_sockaddr_from_peer(&entry->peer, &ss);
    return duct_xsend_dgram(listener->listen_fd, (struct sockaddr *)&ss, ss_len,
                            (duct_view_u8){ .data = entry->data, .size = entry->len });
}

/* The batch goes through s_peer_send_grouped: each group of one peer's equal-sized
 * datagrams leaves as one segmented write, each stretch between groups through
 * duct_xsend_peers. A refused segmentation falls back to those plain sends,
 * which count an undeliverable datagram resolved, so no answer here closes the
 * shared socket. */
uint32_t duct_io_dgram_shared_send_batch(duct_listener_t *listener,
                                         const duct_dgram_out_t *msgs, uint32_t n,
                                         duct_x_gso_tally_t *tally)
{
    /* listen_fd is provably valid here: the caller's own conn is alive, and
     * that conn's own pre_conn_refs contribution alone keeps this listener
     * from ever reaching duct_listener_destroy while it is. */
    assert(listener->listen_fd != duct_sock_bad);
    unsigned sent = 0u;
    duct_discard s_peer_send_grouped(listener->listen_fd, msgs, n, &sent, tally);
    return sent;
}

duct_vmq_mpsc_t *duct_io_dgram_shared_outbox(duct_listener_t *listener)
{
    return (duct_vmq_mpsc_t *)listener->dgram_tx_outbox;
}

duct_x_slot_pool_t *duct_io_dgram_shared_rx_slots(duct_listener_t *listener)
{
    return listener->rx_slots;
}

bool duct_io_dgram_shared_needs_lane_tx(duct_listener_t *listener)
{
    return listener->tx_slots != nullptr;
}

bool duct_io_dgram_shared_rio_tx(duct_listener_t *listener)
{
    return listener->dgram_tx_rio != nullptr;
}

duct_x_slot_pool_t *duct_io_dgram_shared_tx_slots(duct_listener_t *listener)
{
    return listener->tx_slots;
}

duct_result_t duct_io_udp_peer_send_staged(duct_conn_t *conn, size_t *out_sent,
                                           duct_x_gso_tally_t *tally)
{
    *out_sent = 0u;
    if (duct_has(duct_conn_state(conn), fl_conn_write_armed)) {
#if DUCT_RUNTIME_STATS
        duct_worker_rtstat_fast_miss(true);
#endif
        return rc_again;
    }
    assert(conn->fd != duct_sock_bad);
    auto tx = conn->tx_buf;
    size_t base = olb_off(duct_atomic_load(&tx->h.tail, relaxed)),
           off = base,
           end = tx->h.stage;
    while (off < end) {
        duct_view_u8 bufs[duct_dgram_tx_batch];
        unsigned n = s_tx_rec_bufs(tx->data + off, end - off, bufs, duct_dgram_tx_batch),
                 sent = 0u;
        assert(n);
        duct_result_t rc;
        /* A lone record takes the plain send io's own one-record drain makes. */
        if (n == 1u) {
            size_t written = 0u;
            rc = duct_xwrite(conn->fd, x_udp_peer, bufs[0], &written, nullptr, 0);
            sent = rc == rc_ok;
        } else
            rc = s_tx_send_grouped(conn->fd, bufs, n, &sent, tally);
        /* rc_drop names the first record, too large for the path: step over it. */
        if (rc == rc_drop)
            sent = 1u;
        for (unsigned i = 0u; i < sent; ++i)
            off += duct_dgram_record_hdr_size + bufs[i].size;
        *out_sent = off - base;
        if (rc == rc_drop || (rc == rc_ok && sent == n))
            continue;
#if DUCT_RUNTIME_STATS
        duct_worker_rtstat_fast_miss(false);
#endif
        return rc == rc_ok ? rc_again : rc;
    }
    return rc_ok;
}

bool duct_io_stream_send_fast(duct_conn_t *conn, const duct_view_u8 *bufs,
                              unsigned n, size_t *out_written)
{
    if (duct_has(duct_conn_state(conn), fl_conn_write_armed)) {
#if DUCT_RUNTIME_STATS
        duct_worker_rtstat_fast_miss(true);
#endif
        *out_written = 0u;
        return false;
    }
    /* conn->fd is provably valid here: the calling worker is still
     * dispatching this conn's own commit. */
    assert(conn->fd != duct_sock_bad);
    size_t total = 0u;
    for (unsigned i = 0u; i < n; ++i)
        total += bufs[i].size;
    /* Under the platform's cap only the cap goes, with its flags, and the rest
     * is the caller's to publish for io, the answer a short write gets. A TCP
     * conn alone reads the cap, so a packet-fd leg's direct write here loads
     * nothing of its TX ring. */
    int flags = 0;
    size_t cap = 0u;
    if (conn->xport_type == x_tcp) {
        cap = duct_x_sock_tx_cap(duct_x_sock_tx_of(conn->tx_buf), &flags);
#if DUCT_RUNTIME_STATS
        duct_worker_rtstat_tcp_write(cap, total);
#endif
    }
    size_t offered = total;
    duct_result_t rc;
    if (cap && total > cap) {
        duct_view_u8 cut[n];
        unsigned m = 0u;
        for (size_t left = cap; m < n && left; ++m) {
            cut[m] = (duct_view_u8){ .data = bufs[m].data, .size = duct_min(bufs[m].size, left) };
            left -= cut[m].size;
        }
        offered = cap;
        rc = duct_xwritev(conn->fd, conn->xport_type, cut, m, out_written, flags);
    } else
        rc = duct_xwritev(conn->fd, conn->xport_type, bufs, n, out_written, flags);
    /* Every byte the socket took counts toward the opening's packets, a short
     * write's too. */
    if (conn->xport_type == x_tcp)
        duct_x_sock_tx_sent(duct_x_sock_tx_of(conn->tx_buf), *out_written);
    bool took = rc == rc_ok && *out_written == offered;
#if DUCT_RUNTIME_STATS
    if (!took)
        duct_worker_rtstat_fast_miss(false);
#endif
    return took && offered == total;
}

/** @brief Walk one outbox lane of a listener whose socket is closed.
 *  s_dgram_tx_send answers a closed socket as sent, so every entry commits
 *  unsent and the lane drains clean. */
static bool s_dgram_tx_lane_drain_single(duct_vmq_lane_t *ln, duct_listener_t *listener,
                                         size_t *out_peeked)
{
    auto pos = duct_vmq_drain_begin(ln);
    duct_vmq_hdr_t *hdr;
    size_t sent = 0u;
    bool clean = true;
    while ((hdr = duct_vmq_drain_peek(ln, &pos)) != nullptr) {
        ++*out_peeked;
        if (!s_dgram_tx_send(hdr, listener)) {
            clean = false;
            break;
        }
        pos.head += pos.step;
        ++sent;
    }
    if (sent)
        duct_vmq_commit_head(ln, pos.gen, pos.head);
    return clean;
}

/** @brief Send one outbox lane's snapshot in stack-held chunks.
 *  A chunk is @ref duct_x_gso_segs_max entries: it bounds the stack arrays Linux
 *  @c duct_xsend_peers sizes by its count, and still holds the longest group one
 *  segmented write takes. The lane head commits once, past the last entry
 *  sent; a chunk sent short or answered @c rc_again stops the lane with the
 *  rest queued.
 *  @return true once the snapshot drained whole.
 */
static bool s_dgram_tx_lane_drain_batch(duct_vmq_lane_t *ln, duct_listener_t *listener,
                                        size_t *out_peeked)
{
    auto pos = duct_vmq_drain_begin(ln);
    size_t head = pos.head;
    unsigned offered = 0u,
             resolved = 0u;
    duct_x_gso_tally_t tally = {};
    bool clean = true;
    for (;;) {
        duct_dgram_out_t outs[duct_x_gso_segs_max];
        size_t heads[duct_x_gso_segs_max];
        unsigned n = 0u;
        duct_vmq_hdr_t *hdr;
        while (n < duct_x_gso_segs_max && (hdr = duct_vmq_drain_peek(ln, &pos)) != nullptr) {
            auto entry = (duct_dgram_tx_entry_t *)&hdr->payload[0];
            outs[n] = (duct_dgram_out_t){
                .peer = entry->peer,
                .body = { .data = entry->data, .size = entry->len },
            };
            pos.head += pos.step;
            heads[n++] = pos.head;
        }
        if (!n)
            break;
        *out_peeked += n;
        offered += n;
        unsigned sent = 0u;
        auto rc = s_peer_send_grouped(listener->listen_fd, outs, n, &sent, &tally);
        resolved += sent;
        if (sent)
            head = heads[sent - 1u];
        if (rc != rc_ok || sent < n) {
            clean = false;
            break;
        }
    }
    if (offered) {
        duct_rtstat_obj_inc(s_io_this, rtstats.dgram_tx_batch_calls, 1);
        duct_rtstat_obj_inc(s_io_this, rtstats.dgram_tx_batch_msgs, offered);
        duct_rtstat_obj_max(s_io_this, rtstats.dgram_tx_batch_max, (uint64_t)offered);
    }
    duct_rtstat_obj_inc(s_io_this, rtstats.dgram_tx_lane_sent, resolved);
    s_rtstat_gso(tally);
    if (resolved)
        duct_vmq_commit_head(ln, pos.gen, head);
    return clean;
}

/** @brief Drain every worker lane of @p listener's dgram_tx_outbox.
 *  An open socket drains through s_dgram_tx_lane_drain_batch, a closed one
 *  through s_dgram_tx_lane_drain_single.
 *
 *  @return true once every lane drained clean this pass;
 *          false if any lane stopped early and still has work queued.
 *  @param out_peeked incremented by the number of lane entries actually
 *         looked at this call, across every lane. 0 on return means the
 *         call was a pure no-op, with no syscall issued anywhere.
 */
static bool s_dgram_tx_outbox_drain(duct_listener_t *listener, size_t *out_peeked)
{
    auto outbox = (duct_vmq_mpsc_t *)listener->dgram_tx_outbox;
    duct_do_if(!outbox, return true);
    bool all_drained = true;
    bool open = listener->listen_fd != duct_sock_bad;
    for (unsigned i = 0u; i < outbox->n_lanes; ++i) {
        auto ln = duct_mpsc_lane(outbox, i);
        bool lane_drained = open ? s_dgram_tx_lane_drain_batch(&ln, listener, out_peeked)
                                 : s_dgram_tx_lane_drain_single(&ln, listener, out_peeked);
        if (!lane_drained)
            all_drained = false;
        /* Claims and clears worker wait_latch armed on failed reservations;
         * wakes the worker by ID on success. */
        if (duct_vmq_ack_waiter(ln.ctrl))
            duct_worker_wake_id(i);
    }
    return all_drained;
}

void duct_io_dgram_send_drain(duct_listener_t *listener, duct_dgram_send_fn send, void *arg)
{
    auto outbox = (duct_vmq_mpsc_t *)listener->dgram_tx_outbox;
    bool full = false;
    for (unsigned k = 0u; k < outbox->n_lanes; ++k) {
        unsigned i = (listener->tx_lane + k) % outbox->n_lanes;
        auto ln = duct_mpsc_lane(outbox, i);
        auto pos = duct_vmq_drain_begin(&ln);
        duct_vmq_hdr_t *hdr;
        bool any = false;
        while (!full && (hdr = duct_vmq_drain_peek(&ln, &pos)) != nullptr) {
            full = !send(arg, (const duct_dgram_tx_entry_t *)&hdr->payload[0]);
            duct_do_if(full, break);
            pos.head += pos.step;
            any = true;
        }
        if (any)
            duct_vmq_commit_head(&ln, pos.gen, pos.head);
        if (duct_vmq_ack_waiter(ln.ctrl))
            duct_worker_wake_id(i);
    }
    listener->tx_lane = (listener->tx_lane + 1u) % outbox->n_lanes;
}

/* Arms write interest only while a lane is EAGAIN-blocked and
 * disarms the instant it clears: a level-triggered backend left armed spins
 * on an always-writable UDP socket whatever is queued. A proactive backend
 * owns dgram TX through its own kick path and returns early below, which is
 * why that early return answers true with nothing measured. */
bool duct_io_on_dgram_tx_writable(duct_listener_t *listener)
{
    if (duct_events_dgram_tx_kick(s_io_this->trunk.events, listener))
        return true;
    size_t peeked = 0u;
    bool want_armed = !s_dgram_tx_outbox_drain(listener, &peeked);
    if (want_armed != duct_atomic_load(&listener->dgram_tx_write_armed, relaxed)) {
        duct_events_dgram_tx_interest(s_io_this->trunk.events, listener, want_armed);
        duct_atomic_store(&listener->dgram_tx_write_armed, want_armed, relaxed);
    }
    return peeked > 0u;
}

/** @brief Worker to io wake for one listener's dgram_tx_outbox: drains
 *  every worker lane and sends. @c m is @p listener's own embedded
 *  dgram_tx_kick, never heap-owned — nothing to free on return.
 */
static duct_exec_rc_t s_msg_exec_dgram_tx_kick(void *self)
{
    auto m = (duct_msg_dgram_tx_kick *)self;
    /* The same Dekker gap as a plain wake-latch clear: a release store
     * alone lets this sit in the store buffer past the outbox drain
     * below, so a worker's post-dgram-tx exchange can still observe the
     * pre-clear 1 and skip re-posting, a lost kick. */
    duct_atomic_store(&m->listener->wake_latch, 0u, release);
    atomic_thread_fence(memory_order_seq_cst);
    duct_rtstat_obj_inc(s_io_this, rtstats.dgram_tx_real_kick, 1);
    if (!duct_io_on_dgram_tx_writable(m->listener))
        duct_rtstat_obj_inc(s_io_this, rtstats.dgram_tx_real_kick_idle, 1);
    return exec_done;
}

void duct_io_dgram_tx_kick_init(duct_listener_t *listener)
{
    listener->dgram_tx_kick.msg = duct_msg_init_embedded(s_msg_exec_dgram_tx_kick);
    listener->dgram_tx_kick.listener = listener;
}

void duct_io_post_dgram_tx(duct_listener_t *listener)
{
    /* acq_rel: the acquire pairs with the kick exec's release clear, so the io
     * thread's reverse pass over this node's next pointer is over before the
     * push below reuses the node. */
    if (duct_atomic_exchange(&listener->wake_latch, 1u, acq_rel) != 0u)
        return;
    s_msg_post(listener->io_id, &listener->dgram_tx_kick);
}

/** @brief Shared builder for every connect-request poster: @p target
 *  nullptr means the DNS-failure variant, where dns_err carries the
 *  failure and the target is left zeroed and unused.
 */
static duct_socket_prepare_fn s_socket_prepare;
static void *s_socket_ctx;

static bool s_msg_post_connect(unsigned io_id, const duct_dial_target_t *target,
                                  duct_conn_intent_t seed, uint32_t connect_timeout_ms,
                                  duct_result_t dns_err, duct_sock_t fd)
{
    if (io_id >= s_imod.n_io)
        return false;
    auto m = duct_msg_new_kind(io_connect, s_msg_exec_connect);
    if (!m)
        return false;
    if (target)
        m->target = *target;
    m->connect_timeout_ms = connect_timeout_ms;
    m->dns_err = dns_err;
    m->fd = fd;
    m->seed = seed;
    s_msg_post(io_id, m);
    return true;
}

bool duct_io_post_connect(unsigned io_id, const duct_peer_t *peer, const duct_conn_intent_t *seed,
                          uint32_t connect_timeout_ms)
{
    duct_sock_t fd = duct_xsocket(peer->family, seed->xport, seed->egress_if, s_dial_cc(seed));
    if (fd != duct_sock_bad && s_socket_prepare && !s_socket_prepare(s_socket_ctx, fd, peer->family)) {
        duct_sock_close(fd);
        fd = duct_sock_bad;
    }
    if (fd == duct_sock_bad)
        return duct_io_post_connect_failed(io_id, seed, rc_fatal);
    if (!s_msg_post_connect(io_id, &(duct_dial_target_t){ .peer = *peer }, *seed,
                            connect_timeout_ms, rc_ok, fd)) {
        duct_sock_close(fd);
        return false;
    }
    return true;
}

bool duct_io_post_connect_local(unsigned io_id, const char *path, const duct_conn_intent_t *seed,
                                uint32_t connect_timeout_ms)
{
    duct_sock_t fd = duct_xsocket(AF_UNIX, x_local, 0u, nullptr);
    if (fd == duct_sock_bad)
        return duct_io_post_connect_failed(io_id, seed, rc_fatal);
    duct_dial_target_t target = {};
    memcpy(target.path, path, strlen(path) + 1u);
    if (!s_msg_post_connect(io_id, &target, *seed, connect_timeout_ms, rc_ok, fd)) {
        duct_sock_close(fd);
        return false;
    }
    return true;
}

bool duct_io_post_connect_failed(unsigned io_id, const duct_conn_intent_t *seed, duct_result_t err)
{
    return s_msg_post_connect(io_id, nullptr, *seed, 0u, err, duct_sock_bad);
}

/** @brief Worker to io attach-inter request: creates the conn on
 *  @p io_id, then joins it to the session already attached on the
 *  worker. proto is the worker's own s->proto, read on the worker, the
 *  same thread as the session, not re-derived here from a cross-thread
 *  session read.
 */
duct_msg_chain_decl(duct_msg_attach_inter,
    duct_handle_t      tok;
    duct_conn_id_t     conn_id;
    const duct_proto_t *proto;
);

static duct_exec_rc_t s_msg_exec_attach_inter(void *self)
{
    auto m = (duct_msg_attach_inter *)self;
    s_attach_inter(&s_io_this->route, DUCT_CAST(duct_session_handle_t, word, &m->tok), m->conn_id, m->proto);
    return duct_msg_done(m);
}

bool duct_io_post_attach_inter(unsigned io_id, const duct_session_handle_t *tok,
                               duct_conn_id_t conn_id, const duct_proto_t *proto)
{
    if (io_id >= s_imod.n_io)
        return false;
    auto m = duct_msg_new(duct_msg_attach_inter, s_msg_exec_attach_inter, nullptr);
    if (!m)
        return false;
    m->tok = tok->word;
    m->conn_id = conn_id;
    m->proto = proto;
    s_msg_post(io_id, m);
    return true;
}

/** @brief Worker to io attach-fd request: registers m->fd, already open
 *  and caller-owned until this point, on @p io_id, then joins it to the
 *  session already attached on the worker. Same shape as the
 *  attach-inter request, minus the inter-lane creation.
 */
duct_msg_chain_decl(duct_msg_attach_device,
    duct_handle_t      tok;
    duct_conn_id_t     conn_id;
    duct_device_ops_t  ops;
    const duct_proto_t *proto;
);

static duct_exec_rc_t s_msg_exec_attach_device(void *self)
{
    auto m = (duct_msg_attach_device *)self;
    s_attach_device(&s_io_this->route, DUCT_CAST(duct_session_handle_t, word, &m->tok),
                    m->conn_id, &m->ops, m->proto);
    return duct_msg_done(m);
}

bool duct_io_post_attach_device(unsigned io_id, const duct_session_handle_t *tok,
                                duct_conn_id_t conn_id,
                                const duct_device_ops_t *ops,
                                const duct_proto_t *proto)
{
    duct_do_if(io_id >= s_imod.n_io, ops->release(ops->ctx); return false);
    auto m = duct_msg_new_kind(attach_device, s_msg_exec_attach_device);
    duct_do_if(!m, ops->release(ops->ctx); return false);
    m->tok = tok->word;
    m->conn_id = conn_id;
    m->ops = *ops;
    m->proto = proto;
    s_msg_post(io_id, m);
    return true;
}

duct_msg_chain_decl(duct_msg_attach_fd,
    duct_handle_t      tok;
    duct_conn_id_t     conn_id;
    duct_xport_t       xport;
    duct_sock_t        fd;
    const duct_proto_t *proto;
    const duct_wire_t  *leg_wire;
);

static duct_exec_rc_t s_msg_exec_attach_fd(void *self)
{
    auto m = (duct_msg_attach_fd *)self;
    s_attach_fd(DUCT_CAST(duct_session_handle_t, word, &m->tok), m->conn_id, m->fd, m->xport,
                m->proto, m->leg_wire);
    return duct_msg_done(m);
}

bool duct_io_post_attach_fd(unsigned io_id, const duct_session_handle_t *tok,
                            duct_conn_id_t conn_id, duct_sock_t fd,
                            duct_xport_t xport, const duct_proto_t *proto,
                            const duct_wire_t *leg_wire)
{
    if (io_id >= s_imod.n_io) {
        duct_sock_close(fd);
        return false;
    }
    auto m = duct_msg_new_kind(attach_fd, s_msg_exec_attach_fd);
    if (!m) {
        duct_sock_close(fd);
        return false;
    }
    m->tok = tok->word;
    m->conn_id = conn_id;
    m->fd = fd;
    m->xport = xport;
    m->proto = proto;
    m->leg_wire = leg_wire;
    s_msg_post(io_id, m);
    return true;
}

duct_msg_chain_decl(duct_msg_open_packet_fd,
    duct_sock_t   fd;
    duct_proto_t *proto;
    void         *user_ctx;
);

static duct_exec_rc_t s_msg_exec_open_packet_fd(void *self)
{
    auto m = (duct_msg_open_packet_fd *)self;
    s_open_packet_fd(s_io_this, m->fd, m->proto, m->user_ctx);
    return duct_msg_done(m);
}

bool duct_io_post_open_packet_fd(unsigned io_id, duct_sock_t fd, duct_proto_t *proto, void *user_ctx)
{
    auto m = duct_msg_new_kind(open_packet_fd, s_msg_exec_open_packet_fd);
    duct_do_if(!m, duct_sock_close(fd); return false);
    m->fd = fd;
    m->proto = proto;
    m->user_ctx = user_ctx;
    s_msg_post(io_id, m);
    return true;
}

/** @brief Host to io listener revocation: unlinks fd's node from this
 *  thread's own list, deregisters, then either closes the socket and
 *  frees the node right away, when there are no outstanding
 *  pre_conn_refs, or defers both to the last reference's release — a
 *  worker committing a response for an x_udp_shared conn may still be
 *  reserving into this listener's own dgram_tx_outbox lane. A path
 *  listener unlinks its file and closes its socket at once, whatever
 *  is outstanding, and defers the free alone. Signals sync either way.
 */
duct_msg_chain_decl(duct_msg_listener_close,
    duct_sock_t                  fd;
    duct_listener_sync_t        *sync;
);

static duct_exec_rc_t s_msg_exec_listener_close(void *self)
{
    auto m = (duct_msg_listener_close *)self;
    duct_listener_t *prev = nullptr,
                     *l = s_io_this->listeners;
    while (l && l->listen_fd != m->fd) {
        prev = l;
        l = l->next;
    }
    if (l) {
        if (prev)
            prev->next = l->next;
        else
            s_io_this->listeners = l->next;
        duct_events_unwatch(s_io_this->trunk.events, l->listen_fd, nullptr);
        /* Unconditional on every platform: the callee itself decides
         * per-xport, per-platform, which conns actually need it. */
        duct_io_listener_dgram_peers_close_all(l);
        /* A held node is the arg of its pace timer, which must not outlive it. */
        s_listener_pace_end(s_io_this, l);
        /* A node parked for want of a descriptor leaves the count with the list. */
        if (l->rx_parked && !l->rx_slots)
            duct_atomic_fetch(sub, &s_imod.accept_parked, 1u, relaxed);
        if (l->pre_conn_refs == 0u)
            duct_listener_destroy(l); /* closes listen_fd itself */
        else {
            l->closing = true;
            if (l->xport_type == x_local)
                duct_local_listener_retire(l);
        }
    }
    duct_listener_sync_signal(m->sync, l != nullptr);
    return duct_msg_done(m);
}

bool duct_io_post_listener_close(unsigned io_id, duct_sock_t fd, duct_listener_sync_t *sync)
{
    if (io_id >= s_imod.n_io)
        return false;
    auto m = duct_msg_new_kind(listener_close, s_msg_exec_listener_close);
    if (!m)
        return false;
    m->fd = fd;
    m->sync = duct_share(sync);
    s_msg_post(io_id, m);
    return true;
}

/** @brief Host to io listener registration, the sole registration path
 *  a listener bind takes: registers on this thread, links the node
 *  into this thread's own list on success or frees it on failure, then
 *  signals sync.
 */
duct_msg_chain_decl(duct_msg_listener_register,
    duct_listener_t             *listener;
    duct_listener_sync_t        *sync;
);

static duct_exec_rc_t s_msg_exec_listener_register(void *self)
{
    auto m = (duct_msg_listener_register *)self;
    auto listener = m->listener;
    if (s_listener_register(s_io_this, listener)) {
        listener->next = s_io_this->listeners;
        s_io_this->listeners = listener;
        duct_listener_sync_signal(m->sync, true);
    } else {
        s_io_abandon_listener_register(m);
    }
    return duct_msg_done(m);
}

bool duct_io_post_listener_register(duct_listener_t *listener, duct_listener_sync_t *sync)
{
    if (listener->io_id >= s_imod.n_io)
        return false;
    auto m = duct_msg_new_kind(listener_register, s_msg_exec_listener_register);
    if (!m)
        return false;
    m->listener = listener;
    m->sync = duct_share(sync);
    s_msg_post(listener->io_id, m);
    return true;
}

void duct_io_on_wake(void)
{
    auto t = s_io_this;
    auto head = duct_msg_reverse(duct_msg_stack_detach(&t->trunk.stack));
    for (auto n = head; n; ) {
        auto next = duct_msg_next(n);
        duct_discard n->exec_fn(n);
        n = next;
    }
    if (t->frame_rx.retry_q.head)
        duct_frame_rx_retry_drain(&t->route, &t->frame_rx);
}

/** @brief Packets one @c ops.read call may hand back. */
static constexpr unsigned device_rx_batch = 32u;

static_assert(sizeof(duct_msg_inter_batch_t)
              + device_rx_batch * sizeof(duct_msg_inter_pkt_t) < inter_lane_cap,
              "a descriptor-only device batch must always fit its lane");

/** @brief Packets a lending device leg may have out on the lane at once.
 *
 *  One drive's worth, which is also the most that can ever be outstanding:
 *  @ref s_device_drive reads only on a lane @c duct_vmq_room reports whole, so
 *  its first pass hands back everything held from before, and each of its
 *  @c duct_dgram_rx_max_passes passes adds at most one clamped batch. Sized to
 *  that, the capacity test in the drive never refuses a lending device, and
 *  only what @ref s_device_split cannot address still copies. The test
 *  stays as the guard: a drive that reads more falls back to copying rather
 *  than running past @c held[].
 *
 *  The bound comes from the engine's own two RX constants, so raising
 *  @c duct_dgram_rx_max_passes grows every lending leg's array with it. The
 *  size of that array is all this decides: a device left holding none of its
 *  own read memory is still read again, since the resume comes from the
 *  worker emptying the lane.
 */
static constexpr unsigned device_hold_cap =
    device_rx_batch * duct_dgram_rx_max_passes;

/** @brief Packets a leg driving @p ops may hold lent at once.
 *  @c device_hold_cap for a device that answers @c release_read, none for one that does not. It sizes the
 *  leg's @c held[] and bounds the lending gate of @ref s_device_drive, so the two agree.
 */
static unsigned s_device_hold_cap(const duct_device_ops_t *ops)
{
    return ops->release_read ? device_hold_cap : 0u;
}

/** @brief A device leg's @c conn->ctx: the caller's op table, the RX slots its
 *  reads land in and what the engine holds lent from that device.
 *  @c ops leads the struct, so a reader wanting the table alone casts
 *  @c conn->ctx straight to @ref duct_device_ops_t.
 */
typedef struct device_leg {
    duct_device_ops_t ops;
    struct device_leg *prev,   /**< Previous leg on the io thread's device list. */
                      *next;   /**< Next leg on the io thread's device list. */
    unsigned          n_held;  /**< Entries of @c held in use, at most @c device_hold_cap. */
    duct_x_slot_pool_t  rx_slots; /**< Slots this leg's reads land in,
                                    *  @c duct_dgram_rx_max_passes of them, one
                                    *  per drive pass, and none for a device
                                    *  whose @c ops.rx_span is 0. A slot is a
                                    *  chunk, so the tick's sweep gives idle ones
                                    *  back. A drive reads only on a drained lane,
                                    *  which has handed every earlier slot back,
                                    *  so the pool never runs dry. */
    duct_view_u8        held[];  /**< Packets read out of the device and not yet
                                 *  handed back through @c ops.release_read. */
} device_leg_t;

/** @brief Allocate a device leg's @c conn->ctx around a copy of @p ops.
 *  Room for @c device_hold_cap packets trails it when @p ops answers
 *  @c release_read, and none when it does not; its RX pool, whose slots each hold
 *  @c device_rx_batch buffers of @c rx_span bytes, is set up beside it with no
 *  chunk live, and has no slot for an @c rx_span of 0.
 *  @return the copy, @c nullptr when an allocation fails.
 */
static duct_device_ops_t *s_device_leg_new(const duct_device_ops_t *ops)
{
    duct_auto_del auto leg = (device_leg_t *)duct_at(
        duct_new(uint8_t, sizeof(device_leg_t) + (size_t)s_device_hold_cap(ops) * sizeof(duct_view_u8),
                 alignof(device_leg_t)));
    duct_do_if(!leg, return nullptr);
    uint32_t passes = ops->rx_span ? duct_dgram_rx_max_passes : 0u;
    bool pooled = duct_x_slot_pool_init(&leg->rx_slots, passes,
                                        (uint32_t)(ops->rx_span * device_rx_batch
                                                   + duct_dgram_record_hdr_size),
                                        duct_dgram_record_hdr_size, 1u, (duct_x_slot_hooks_t){});
    duct_do_if(!pooled, return nullptr);
    leg->ops = *ops;
    leg->n_held = 0u;
    return &duct_move(leg)->ops;
}

/** @brief Find the device leg of @p t holding @p handle, @c nullptr when none does. */
static device_leg_t *s_device_find(const duct_io_t *t, const void *handle)
{
    auto leg = t->devices;
    while (leg && leg->ops.wait_handle != handle)
        leg = leg->next;
    return leg;
}

/** @brief Put @p conn's device leg at the head of @p t's device list. */
static void s_device_link(duct_io_t *t, duct_conn_t *conn)
{
    auto leg = (device_leg_t *)conn->ctx;
    leg->next = t->devices;
    if (t->devices)
        t->devices->prev = leg;
    t->devices = leg;
}

/** @brief Take @p conn's device leg off @p t's device list. */
static void s_device_unlink(duct_io_t *t, duct_conn_t *conn)
{
    auto leg = (device_leg_t *)conn->ctx;
    if (leg->prev)
        leg->prev->next = leg->next;
    else
        t->devices = leg->next;
    if (leg->next)
        leg->next->prev = leg->prev;
    leg->prev = leg->next = nullptr;
}

/** @brief Hand every held packet back to @p leg's device. */
static void s_device_holds_release(device_leg_t *leg)
{
    for (unsigned i = 0u; i < leg->n_held; ++i)
        leg->ops.release_read(leg->ops.ctx, leg->held[i]);
    leg->n_held = 0u;
}

void duct_io_device_teardown(duct_conn_t *conn)
{
    duct_do_if(conn->xport_type != x_inter || !conn->ctx, return);
    auto leg = (device_leg_t *)conn->ctx;
    s_device_holds_release(leg);
    duct_x_slot_pool_free(&leg->rx_slots);
}

/** @brief Copy @p n packets from @p bufs onto @p conn's inter lane and arm
 *  its worker.
 *  The io thread that owns @p conn runs this, so it needs none of the
 *  @c host_pins dance @ref duct_io_inter_batch does for a host caller.
 *
 *  Places the longest fitting prefix of @p bufs onto the lane.
 *
 *  @retval rc_ok          all @p n placed, with room left for another batch
 *                         that size.
 *  @retval rc_again       all @p n placed, and the next one no longer fits.
 *  @retval rc_defer       a tail was dropped, or nothing fit at all.
 *  @retval rc_invalid_arg the first packet outgrows a whole empty lane — a
 *                         permanent drop, never backpressure: latching on it
 *                         wedges the device for good.
 */
static duct_result_t
s_device_push(duct_conn_t *conn, const duct_view_u8 *bufs, unsigned n)
{
    assert(n);
    auto ln = duct_mpsc_lane(conn->inter_lane, 0u);
    size_t room = duct_vmq_room(&ln);

    size_t need = sizeof(duct_msg_inter_batch_t);
    unsigned fit = 0u;
    for (unsigned i = 0u; i < n; ++i) {
        if (bufs[i].size > ln.capacity)
            break;
        size_t next = need + sizeof(duct_msg_inter_pkt_t) + bufs[i].size;
        if (vmq_msg_aligned(next) > room)
            break;
        need = next;
        fit = i + 1u;
    }
    if (!fit)
        return vmq_msg_aligned(sizeof(duct_msg_inter_batch_t)
                               + sizeof(duct_msg_inter_pkt_t) + bufs[0].size)
             > ln.capacity ? rc_invalid_arg : rc_defer;

    duct_vmq_reserve_pos_t pos;
    auto stage = (duct_msg_inter_batch_t *)
        duct_vmq_reserve(&ln, inter_msg_batch, 0u, need, &pos,
                         &(duct_vmq_push_rc_t){});
    assert(stage);

    auto h = duct_conn_handle_get(conn);
    stage->conn = h.word;
    stage->n = fit;
    stage->peer = (duct_peer_t){};
    stage->rx_pool = nullptr;
    stage->pkts_off = (uint32_t)sizeof(duct_msg_inter_batch_t);
    stage->holds_off = 0u;
    auto pkts = duct_msg_inter_pkts(stage);
    size_t cursor = sizeof(duct_msg_inter_batch_t)
                  + (size_t)fit * sizeof(duct_msg_inter_pkt_t);
    for (unsigned i = 0u; i < fit; ++i) {
        pkts[i] = (duct_msg_inter_pkt_t){
            .offset = (uint32_t)cursor,
            .len = (uint32_t)bufs[i].size,
            .stream_id = duct_stream_id_default,
        };
        if (bufs[i].size)
            memcpy((char *)stage + cursor, bufs[i].data, bufs[i].size);
        cursor += bufs[i].size;
    }
    duct_vmq_publish(&ln, &pos);
    duct_worker_inter_arm(conn->worker_id, duct_conn_idx_get(conn));
    duct_vmq_notify(ln.ctrl);
    if (fit < n)
        return rc_defer;
    return ln.capacity - (pos.off + pos.aligned) >= pos.aligned ? rc_ok : rc_again;
}

/** @brief Offer @p slot's payload area to one device read, cut into
 *  @c device_rx_batch buffers of @p span bytes.
 *
 *  Carves slot payload into descriptor spans. For @c treiber_empty,
 *  buffers are initialized to empty.
 */
static void s_device_carve(const duct_x_slot_pool_t *pool, uint32_t slot, size_t span,
                           duct_view_u8 *bufs)
{
    if (slot == treiber_empty) {
        for (unsigned i = 0u; i < device_rx_batch; ++i)
            bufs[i] = (duct_view_u8){};
        return;
    }
    auto base = duct_x_slot_payload(pool, slot);
    for (unsigned i = 0u; i < device_rx_batch; ++i)
        bufs[i] = (duct_view_u8){ .data = base + i * span, .size = span };
}

static_assert(device_rx_batch <= 32u,
              "one buffer per bit of the mask s_device_split fills");

/** @brief Sort the @p n buffers a device returned into the two kinds a
 *  descriptor batch can address.
 *
 *  @param out_slot_mask  Bit @c i set when @p bufs[i] and its whole span lie
 *                        inside @p slot, so an offset reaches it.
 *  @param out_lent       Buffers outside @p pool altogether, which the batch
 *                        carries as pointers into the device's own memory.
 *  @return false when some buffer is neither: a span running past the slot's
 *          end, a null pointer, or pool bytes belonging to another slot.
 *          Lending any of those hands engine memory to @c ops.release_read,
 *          and a null one collides with the hold array's own "resolve by
 *          offset" entry, so the batch is copied instead. @c treiber_empty
 *          offered no slot and puts every buffer in the second kind.
 *  @note The mask is filled as far as the refusal, which leaves every bit it
 *        does set true.
 */
static bool s_device_split(const duct_x_slot_pool_t *pool, uint32_t slot,
                           const duct_view_u8 *bufs, unsigned n,
                           uint32_t *out_slot_mask, unsigned *out_lent)
{
    *out_slot_mask = 0u;
    *out_lent = 0u;
    auto base = slot == treiber_empty
              ? nullptr : (const char *)duct_x_slot_data(pool, slot);
    for (unsigned i = 0u; i < n; ++i) {
        auto p = (const char *)bufs[i].data;
        duct_do_if(!p, return false);
        if (base && duct_x_slot_holds(pool, slot, p)) {
            size_t off = (size_t)(p - base);
            duct_do_if(bufs[i].size > pool->slot_bytes - off, return false);
            *out_slot_mask |= 1u << i;
            continue;
        }
        bool ours = duct_x_slot_pool_owns(pool, p);
        duct_do_if(ours, return false);
        ++*out_lent;
    }
    return true;
}

/** @brief Publish @p n device packets onto @p conn's inter lane as
 *  descriptors, whole or not at all.
 *
 *  Each packet is addressed the way @ref s_device_split classified it: a bit
 *  of @p slot_mask means an offset into @p slot, the @p lent others a pointer
 *  in the hold array behind the descriptors, where a null entry marks the
 *  ones addressed by offset. Both kinds live in one message, so a batch
 *  answered from both memories needs no copy. A message carries descriptors
 *  alone, so its size is independent of what the packets hold.
 *
 *  Ownership divides on the publish. @p slot passes to the batch whenever any
 *  packet resolves through it, and the worker's batch handler returns it;
 *  every other exit leaves the slot with the caller. A lent packet is
 *  recorded in @p leg instead and goes back to the device at
 *  @ref s_device_holds_release, which every drive pass runs once the lane
 *  reads empty — @ref duct_vmq_drain commits its head after the whole pass,
 *  so an empty lane means every callback that saw those bytes has returned.
 *  @return @c rc_ok published, @c rc_defer the lane has no room this pass,
 *          @c rc_invalid_arg the descriptor block overflowed @c size_t.
 */
static duct_result_t
s_device_push_desc(duct_conn_t *conn, device_leg_t *leg,
                   duct_x_slot_pool_t *pool, uint32_t slot,
                   const duct_view_u8 *bufs, unsigned n,
                   uint32_t slot_mask, unsigned lent)
{
    auto ln = duct_mpsc_lane(conn->inter_lane, 0u);
    size_t need = 0u, holds = 0u;
    bool of = s_inter_desc_bytes(n, &need);
    if (lent)
        of = of || duct_ckd_mul(&holds, (size_t)n, sizeof(void *))
                || duct_ckd_add(&need, need, holds);
    duct_do_if(of, return rc_invalid_arg);
    size_t want = vmq_msg_aligned(need);
    size_t room = duct_vmq_room(&ln);
    duct_do_if(want > room, return rc_defer);

    duct_vmq_reserve_pos_t pos;
    auto stage = (duct_msg_inter_batch_t *)
        duct_vmq_reserve(&ln, inter_msg_batch, 0u, need, &pos,
                         &(duct_vmq_push_rc_t){});
    assert(stage);

    auto h = duct_conn_handle_get(conn);
    stage->conn = h.word;
    stage->n = n;
    stage->peer = (duct_peer_t){};
    stage->rx_pool = slot_mask ? pool : nullptr;
    stage->rx_slot = slot;
    stage->pkts_off = (uint32_t)sizeof(duct_msg_inter_batch_t);
    stage->holds_off = lent ? (uint32_t)(sizeof(duct_msg_inter_batch_t)
                              + (size_t)n * sizeof(duct_msg_inter_pkt_t)) : 0u;
    auto pkts = duct_msg_inter_pkts(stage);
    auto held = duct_msg_inter_holds(stage);
    auto base = slot_mask ? (const char *)duct_x_slot_data(pool, slot) : nullptr;
    for (unsigned i = 0u; i < n; ++i) {
        bool ours = (slot_mask >> i) & 1u;
        pkts[i] = (duct_msg_inter_pkt_t){
            .offset = ours ? (uint32_t)((const char *)bufs[i].data - base) : 0u,
            .len = (uint32_t)bufs[i].size,
            .stream_id = duct_stream_id_default,
        };
        if (!held)
            continue;
        held[i] = ours ? nullptr : bufs[i].data;
        if (!ours)
            leg->held[leg->n_held++] = bufs[i];
    }
    duct_vmq_publish(&ln, &pos);
    duct_worker_inter_arm(conn->worker_id, duct_conn_idx_get(conn));
    duct_vmq_notify(ln.ctrl);
    return rc_ok;
}

/** @brief Latch RX-full on @p conn and take its device off the readiness set. */
static void s_device_stall(duct_conn_t *conn)
{
    duct_conn_state_set(conn, fl_conn_rx_full);
    duct_events_device_rx_interest(s_io_this->trunk.events,
        ((const duct_device_ops_t *)conn->ctx)->wait_handle, false);
}

/** @brief Read @p conn's device until it runs dry, the lane stops taking a
 *  whole batch, or the pass budget is spent.
 *  Bounded at @c duct_dgram_rx_max_passes for the reason @ref
 *  duct_io_dgram_rx_drain is: a device at line rate must not hold this io
 *  thread past its timers and past the trunk of worker posts every other conn
 *  it owns is waiting on.
 *
 *  Runs only on a drained lane, so a read meets the whole capacity, and what
 *  that buys splits by how the batch is addressed. Reaching
 *  @ref s_device_push_desc it is descriptors alone and lands whole whatever
 *  the packets hold. Falling to @ref s_device_push it lands whole only while
 *  @c device_rx_batch packets at the device's MTU stay under
 *  @c inter_lane_cap — 32 at an Ethernet 1500 against 144 KB — that copy
 *  dropping the tail a jumbo frame leaves no room for.
 *  Releases lent packets on fully drained lanes. If unread bytes remain,
 *  latches @c fl_conn_rx_full until worker drain resumes.
 */
static void s_device_drive(duct_conn_t *conn)
{
    if (duct_conn_state(conn) & (fl_conn_closed | fl_conn_suspended | fl_conn_rx_full))
        return;
    auto ln = duct_mpsc_lane(conn->inter_lane, 0u);
    if (duct_vmq_room(&ln) != ln.capacity) {
        s_device_stall(conn);
        return;
    }
    auto t = s_io_this;
    auto leg = (device_leg_t *)conn->ctx;
    auto dev = &leg->ops;
    auto pool = &leg->rx_slots;
    /* A device signals one handle, and a device whose send ring just freed
     * room raises it too. Answering every wake with the TX nudge makes such
     * a device prompt without a second handle or a capability
     * flag; one that never signals writability costs a flag test here, and
     * its parked response waits for the worker's next event. */
    s_tx_wake_waiter(conn);
    duct_events_device_rx_interest(t->trunk.events, dev->wait_handle, true);
    for (unsigned pass = 0u; pass < duct_dgram_rx_max_passes; ++pass) {
        if (leg->n_held && duct_vmq_room(&ln) == ln.capacity)
            s_device_holds_release(leg);
        duct_view_u8 views[device_rx_batch];
        uint32_t slot = duct_x_slot_acquire(pool);
        s_device_carve(pool, slot, dev->rx_span, views);
        unsigned n = 0u;
        auto rc = dev->read(dev->ctx, views, device_rx_batch, &n);
        duct_do_if(rc == rc_closed,
                   duct_x_slot_release(pool, slot);
                   duct_io_conn_close(conn, close_io_error); return);
        if (n == 0u) {
            duct_x_slot_release(pool, slot);
            return;
        }
        /* Clamped, not trusted: bufs holds exactly this many. */
        if (n > device_rx_batch)
            n = device_rx_batch;
        uint32_t slot_mask = 0u;
        unsigned lent = 0u;
        bool desc = s_device_split(pool, slot, views, n, &slot_mask, &lent)
                 && s_device_hold_cap(dev) - leg->n_held >= lent;
        auto push = desc
                  ? s_device_push_desc(conn, leg, pool, slot, views, n, slot_mask, lent)
                  : s_device_push(conn, views, n);
        /* Device memory the hold list did not take is done with the moment the
         * batch is placed or refused: the copy path has the bytes, and a
         * refusal drops them. Only a recorded packet outlives this loop. */
        if (dev->release_read && !(desc && lent && push == rc_ok))
            for (unsigned i = 0u; i < n; ++i)
                if (!duct_x_slot_pool_owns(pool, views[i].data))
                    dev->release_read(dev->ctx, views[i]);
        if (!desc || !slot_mask || push != rc_ok)
            duct_x_slot_release(pool, slot);
        if (push == rc_defer || push == rc_again) {
            s_device_stall(conn);
            return;
        }
        if (n < device_rx_batch)
            return;
    }
    auto ch = duct_conn_handle_get(conn);
    duct_io_post_rx_read(&ch);
}

void duct_io_on_device(void *tag)
{
    auto conn = s_conn_from_tag(tag);
    duct_do_if(!conn || !conn->ctx, return);
    s_device_drive(conn);
}

void duct_io_on_event(duct_io_event_t *ev)
{
    auto t = s_io_this;
    auto conn = s_conn_from_tag(ev->ptr);
    duct_do_if(!conn, return);
    if (duct_has(ev->flags, duct_or(io_ev_error, io_ev_hup))) {
        s_conn_close(t, conn, close_io_error);
        return;
    }
    if (conn->xport_type == x_inter && conn->ctx) {
        s_device_drive(conn);
        return;
    }
    if (duct_has(ev->flags, io_ev_read))
        s_rx_start(conn);
    if (duct_has(duct_conn_state(conn), fl_conn_closed))
        return;
    if (duct_has(ev->flags, io_ev_write))
        s_tx_start(conn);
}

/* Uses duct_conn_rx_olb because rx_buf aliases inter_lane: on an x_inter or
 * x_udp_shared conn, checking rx_buf alone treats a lane pointer as an OLB.
 * The predicate checks xport_type instead and never reads the union. */
void duct_io_on_relocate(duct_io_tag_t kind, void *tag, void *io_priv)
{
    if (kind != io_tag_conn)
        return;
    auto conn = s_conn_from_tag(tag);
    duct_do_if(!conn, return);
    if (!duct_conn_rx_olb(conn))
        return;
    conn->rx_buf->h.ext_ptr = conn->tx_buf->h.ext_ptr = io_priv;
}

/** @brief Test whether a listener of @p t ahead of @p upto reads into RX pool @p pool.
 *  A pool shared by several listeners is swept once, at the first.
 */
static bool s_pool_listed_before(const duct_io_t *t, const duct_listener_t *upto,
                                 const duct_x_slot_pool_t *pool)
{
    for (auto p = t->listeners; p != upto; p = p->next)
        if (p->rx_slots == pool)
            return true;
    return false;
}

/** @brief Least time between the sweeps of an io thread's slot pools, nanoseconds.
 *  A sweep pops every free slot of a pool and so leaves its list empty for a moment, and a grow costs a
 *  registration on a proactive backend; the pause keeps a bursty sender from growing and trimming a
 *  pool in step with it. The tick tests it on the clock read it already takes: nothing is armed and no
 *  park is shortened for it.
 */
static constexpr uint64_t s_slot_sweep_ns = 1'000'000'000u;

/** @brief Sweep every slot pool @p t holds: the RX pool of each listener, the two TX pools of each
 *  listener and the read slots of each device leg.
 *  A swept RX pool resumes its stalled reader, and swept TX pools drain their listener's lanes
 *  again, since the sweep leaves a pool dry for a moment.
 */
static void s_pools_sweep(duct_io_t *t)
{
    for (auto l = t->listeners; l; l = l->next) {
        auto rx = l->rx_slots;
        if (rx && !s_pool_listed_before(t, l, rx) && duct_x_slot_pool_sweep(rx))
            s_rx_unstall(rx);
        auto tx = l->tx_slots;
        if (!tx)
            continue;
        bool taken = false;
        for (unsigned c = 0u; c < 2u; ++c)
            taken = duct_x_slot_pool_sweep(&tx[c]) || taken;
        if (taken)
            duct_discard duct_events_dgram_tx_kick(t->trunk.events, l);
    }
    for (auto leg = t->devices; leg; leg = leg->next)
        duct_discard duct_x_slot_pool_sweep(&leg->rx_slots);
}

uint32_t duct_io_on_tick(void)
{
    auto t = s_io_this;
    /* Reuses a single monotonic clock reading across the I/O pass. */
    duct_atomic_store(&t->trunk.parked, false, relaxed);
    if (duct_atomic_load(&t->trunk.stack.top, relaxed))
        duct_io_on_wake();
    auto now = duct_time_from_ns(duct_ticks_mono_ns());
    duct_timers_drain_at(&t->timers, now);
    duct_timers_maybe_trim(&t->timers);
    if (duct_time_le(t->sweep_at, now)) {
        t->sweep_at = duct_time_add(now, duct_time_from_ns(s_slot_sweep_ns));
        s_pools_sweep(t);
    }
    return duct_deadline_to_ms_at(duct_timers_nearest(&t->timers), now);
}

bool duct_io_work_pending(void)
{
    auto t = s_io_this;
    duct_atomic_store(&t->trunk.parked, true, relaxed);
    atomic_thread_fence(memory_order_seq_cst);
    return duct_atomic_load(&t->trunk.stack.top, relaxed) != nullptr;
}

bool duct_io_timer_due_soon(void)
{
    auto t = s_io_this;
    return duct_timers_due_soon(&t->timers, duct_time_from_ns(duct_ticks_mono_ns()));
}

/** @brief Raise @p t's shutdown flag and kick its trunk.
 *  The kick returns a blocked event wait right away, so shutdown
 *  needs no timeout watchdog to notice it. It skips the park check: the
 *  flag is no trunk message, and that check reads nothing else. */
static duct_nonnull(1) void s_request_shutdown(duct_io_t *t)
{
    duct_atomic_store(&t->shutdown, true, release);
    duct_events_kick(t->trunk.events);
}

/** @brief Drop @p conn from the events backend, by wait handle for a
 *  device-backed x_inter conn and by fd for everything else.
 *  A device leg leaves its thread's device list first. */
static void s_conn_deregister(duct_io_t *t, duct_conn_t *conn)
{
    if (conn->xport_type == x_inter && conn->ctx) {
        s_device_unlink(t, conn);
        duct_events_unwatch_device(t->trunk.events,
            ((const duct_device_ops_t *)conn->ctx)->wait_handle);
        return;
    }
    auto rx = duct_conn_rx_olb(conn);
    duct_events_unwatch(t->trunk.events, conn->fd, rx ? rx->h.ext_ptr : nullptr);
}

/** @brief Take @p conn off this io thread: its queued retry frames, its reactor
 *  watch and the live-conn list.
 *
 *  Its request flags stay: only its request node's run reopens the request
 *  gate, and that run keeps just the fence's own requests on a closed conn.
 *
 *  @c fl_conn_closed is set before deregistration; in-flight completions
 *  stall on that flag in @ref duct_io_rx_reserve.
 *  @ref duct_conn_io_list_unlink excludes host-driven @c x_inter internally; a
 *  device-backed one was linked at attach and is unlinked here.
 */
static void s_conn_detach(duct_io_t *t, duct_conn_t *conn)
{
    duct_frame_rx_retry_discard(&t->frame_rx, conn);
    duct_conn_state_set(conn, fl_conn_closed);
    s_conn_deregister(t, conn);
    duct_conn_io_list_unlink(conn, t->route.thread_id);
}

/** @brief Unified close: I/O-side quiesce, unbound and bound fence paths.
 *
 *  CASes conn_fence to fence_quiescing; any other state means a concurrent or
 *  earlier close already ran, or a lost bind race already self-retired —
 *  idempotent either way. Deregisters from the events backend only; the fd
 *  stays open until teardown's own close at reclaim, since a worker's TX fast
 *  path may still be using it for a commit queued before this quiesce won.
 *
 *  fence_unbound, with fl_conn_in_wfq unset: fast-releases now, since
 *  the generation bump invalidates any pending session_open or
 *  conn_join handle before its ctrl runs. Set: leaves teardown to that
 *  ctrl's own fence check and the later fence retire. fence_open:
 *  publishes conn_lost onto the owner worker's WFQ lane; reclaim, and
 *  the fd close, wait behind every already-queued commit there,
 *  same-lane FIFO.
 *
 *  @retval true   Won the quiesce CAS — callers still dispatching work
 *                 against @p conn must stop.
 *  @retval false  Close already claimed elsewhere; @p conn untouched.
 */
static bool s_conn_close(duct_io_t *t, duct_conn_t *conn, duct_close_reason_t reason)
{
    assert(conn);
    auto pre = duct_conn_fence_quiesce(conn);
    if (pre != fence_unbound && pre != fence_open)
        return false; /* already claimed by a concurrent/earlier close — no-op */
    s_conn_detach(t, conn);
    if (pre == fence_unbound) {
        if (!duct_has(duct_conn_state(conn), fl_conn_in_wfq))
            duct_conn_reclaim(conn);
        return true;
    }
    conn->close_reason = reason;
    duct_conn_fence_lost_publish(&t->route, conn);
    return true;
}

/** @brief Non-graceful teardown for process shutdown: no conn_lost, no fence
 *  dance — workers may already be gone. Releases every resource directly,
 *  the conn's pending requests dropped first, since no request node runs
 *  past shutdown to release a held reclaim.
 */
static void s_conn_shutdown(duct_io_t *t, duct_conn_t *conn)
{
    s_conn_detach(t, conn);
    duct_atomic_fetch(and, duct_conn_gen_req(conn), ~(uint64_t)gen_req_flags_mask, relaxed);
    duct_conn_reclaim(conn);
}

void duct_io_conn_close(duct_conn_t *conn, duct_close_reason_t reason)
{
    s_conn_close(s_io_this, conn, reason);
}

bool duct_io_init(unsigned n_io, duct_vmq_mpsc_t *wfq, unsigned n_workers)
{
    /* duct_engine_launch is this function's sole caller and already
     * rejects cfg->io_threads > duct_runtime_max_io_threads before n_io
     * ever reaches here. */
    assert(n_io <= duct_runtime_max_io_threads);

    s_imod.xports = duct_at(duct_new(duct_io_t, n_io));
    if (!s_imod.xports)
        return false;
    /* After the array: duct_io_cleanup walks n_io entries of it. */
    s_imod.n_io = n_io;

    for (unsigned i = 0u; i < n_io; ++i) {
        auto t = &s_imod.xports[i];
        atomic_init(&t->shutdown, false);
        atomic_init(&t->started, 0u);
        atomic_init(&t->trunk.stack.top, nullptr);
        atomic_init(&t->trunk.parked, false);
        atomic_init(&t->rx_resume.latch, 0u);
        t->route = (duct_wfq_route_t){
            .wfq = wfq,
            .n_workers = n_workers,
            .n_io = n_io,
            .thread_id = i,
            .trunk = &t->trunk,
        };
        duct_timers_init(&t->timers);
        if (!duct_frame_rx_ctx_init(&t->frame_rx, wfq, n_workers, n_io))
            return false;
        t->rx_resume.msg = duct_msg_init_embedded(s_msg_exec_rx_resume);
        /* A cache line of its own: the kernel writes this block on every vnet read of
         * its thread, and the threads' blocks are allocated back to back. */
        t->vnet_hdr = duct_new(uint8_t, duct_vnet_hdr_max, duct_cacheline_size);
        if (!t->vnet_hdr)
            return false;
    }
    return true;
}

void duct_io_configure_sockets(duct_socket_prepare_fn prepare, void *ctx)
{
    s_socket_prepare = prepare;
    s_socket_ctx = ctx;
}

static void *s_pthread_proc(void *arg)
{
    auto id = (unsigned)(uintptr_t)arg;
    duct_io_thread_entry(id);
    return nullptr;
}

void duct_io_thread_entry(unsigned io_id)
{
    if (io_id >= s_imod.n_io)
        return;
    auto t = &s_imod.xports[io_id];
    char dbg_name[16];
    duct_discard snprintf(dbg_name, sizeof dbg_name, "duct-io-%hu", (unsigned short)io_id);
    duct_thread_set_name(dbg_name);
    duct_thread_block_stop_signals();
    /* With io-first pinning off, io still claims a slot -- after every
     * worker, so the clean cores go to the bottleneck first and io gets
     * its own core only when the table is deep enough. A too-small table
     * leaves this thread unpinned and shows as one pin_fail. */
    unsigned pin_slot = duct_thread_pin_io_first ? io_id : t->route.n_workers + io_id;
    t->cpu = duct_thread_pinning ? duct_thread_bind_cpu(pin_slot) : -1;
    if (duct_thread_pinning && t->cpu < 0)
        duct_rtstat_obj_inc(t, rtstats.pin_fail, 1);
    t->trunk.events = duct_events_init();
    if (!t->trunk.events) {
        duct_atomic_store(&t->started, 2u, release);
        duct_futex_wake(&t->started, 1);
        return;
    }
    s_io_this = t;
    /* The statistics shards number the I/O threads first, then the workers. */
    duct_stats_bind(io_id);
    duct_atomic_store(&t->started, 1u, release);
    duct_futex_wake(&t->started, 1);
    duct_events_run_loop(t->trunk.events, &t->shutdown);
    s_io_this = nullptr;
    duct_stats_unbind();
}

int duct_io_thread_cpu(unsigned io_id)
{
    return io_id < s_imod.n_io ? s_imod.xports[io_id].cpu : -1;
}

static constexpr unsigned xport_start_rendezvous_timeout_ms = 1000u;

bool duct_io_start_threads(void)
{
    for (unsigned i = 0u; i < s_imod.n_io; ++i) {
        if (pthread_create(&s_imod.xports[i].thread, nullptr,
                           s_pthread_proc, (void *)(uintptr_t)i) != 0) {
            /* Rollback already-started threads. */
            for (unsigned j = 0u; j < i; ++j) {
                s_request_shutdown(&s_imod.xports[j]);
                pthread_join(s_imod.xports[j].thread, nullptr);
            }
            return false;
        }
        /* Rendezvous: waits for the thread to init its own events
         * backend and start — pinning is best-effort and cannot fail
         * startup — or to fail that init. Either way, shutdown and join
         * tear it down before rollback continues: an already-failed
         * thread has already returned on its own, so the extra shutdown
         * store and kick land on a dead thread as a harmless no-op. */
        if (!duct_thread_started_wait(&s_imod.xports[i].started, xport_start_rendezvous_timeout_ms)) {
            s_request_shutdown(&s_imod.xports[i]);
            pthread_join(s_imod.xports[i].thread, nullptr);
            goto rollback;
        }
    }
    return true;

rollback:
    for (unsigned j = 0u; j < s_imod.n_io; ++j) {
        if (duct_atomic_load(&s_imod.xports[j].started, acquire) == 1u) {
            s_request_shutdown(&s_imod.xports[j]);
            pthread_join(s_imod.xports[j].thread, nullptr);
        }
    }
    return false;
}

void duct_io_request_shutdown(void)
{
    for (unsigned i = 0u; i < s_imod.n_io; ++i)
        s_request_shutdown(&s_imod.xports[i]);
}

void duct_io_join(void)
{
    for (unsigned i = 0u; i < s_imod.n_io; ++i)
        pthread_join(s_imod.xports[i].thread, nullptr);
}

duct_listener_t *duct_io_listeners_detach(void)
{
    duct_listener_t *head = nullptr;
    for (unsigned i = 0u; i < s_imod.n_io; ++i) {
        auto l = s_imod.xports[i].listeners;
        while (l) {
            auto next = l->next;
            l->next = head;
            head = l;
            l = next;
        }
        s_imod.xports[i].listeners = nullptr;
    }
    /* The parks leave with the listeners: the closes of duct_io_cleanup then post no
     * resume to a thread already stopped. */
    duct_atomic_store(&s_imod.accept_parked, 0u, relaxed);
    return head;
}

/** @brief Report a dial the engine ends before it resolves to the protocol that made it.
 *  Only a fresh session's seed reports, with @p rc; a leg's session closes with the engine.
 */
static void s_dial_abandon(const duct_conn_intent_t *seed, duct_result_t rc)
{
    if (seed->kind == intent_session)
        duct_session_dial_lost(duct_proto_cfg_of(seed->proto), seed->user_ctx, rc);
}

/** @brief Call the release of the device an unrun attach carries.
 *  No leg has taken the device, so its release is due here.
 */
static void s_io_abandon_attach_device(duct_msg_attach_device *m)
{
    m->ops.release(m->ops.ctx);
}

/** @brief Close the fd an unrun attach carries. */
static void s_io_abandon_attach_fd(duct_msg_attach_fd *m)
{
    duct_sock_close(m->fd);
}

/** @brief Close the fd of an unrun packet-fd open and report the open lost with @c rc_closed. */
static void s_io_abandon_open_packet_fd(duct_msg_open_packet_fd *m)
{
    duct_sock_close(m->fd);
    duct_session_dial_lost(duct_proto_cfg_of(m->proto), m->user_ctx, rc_closed);
}

/** @brief Report a dial that never ran as lost, a session dial only.
 *  The code is the lookup failure's, else @c rc_closed.
 */
static void s_io_abandon_io_connect(duct_msg_io_connect *m)
{
    if (m->fd != duct_sock_bad)
        duct_sock_close(m->fd);
    s_dial_abandon(&m->seed, m->dns_err != rc_ok ? m->dns_err : rc_closed);
}

/** @brief Drop what an unrun pre-parse job holds: a stream's probe fd and the listener reference.
 *  The peek bytes are the message's tail and go with it.
 */
static void s_io_abandon_pre_parse(duct_msg_pre_parse *m)
{
    if (m->listener->xport_type != x_udp && m->fd != duct_sock_bad)
        duct_sock_close(m->fd);
    duct_listener_release_pre_conn_ref(m->listener);
}

/** @brief Destroy the listener an unrun registration carries and signal its sync failed.
 *  A registration the io thread refuses ends the same way.
 */
static void s_io_abandon_listener_register(duct_msg_listener_register *m)
{
    duct_listener_destroy(m->listener);
    duct_listener_sync_signal(m->sync, false);
}

/** @brief Signal failed the sync an unrun listener close carries. */
static void s_io_abandon_listener_close(duct_msg_listener_close *m)
{
    duct_listener_sync_signal(m->sync, false);
}

/* One case per kind of the io list, calling its handler on the message cast to the kind's type; the
 * kinds of the ctrl list stand as bare cases with nothing to give back. */
#define s_io_abandon_case(name) \
    case msg_kind_##name: s_io_abandon_##name((duct_msg_##name *)msg); break;
#define s_io_abandon_other(name) case msg_kind_##name:

/** @brief Give back what a trunk-stack message no io thread ran still owns, by its kind.
 *  Runs on the thread that destroys the engine, the io threads joined: no case
 *  may reach @c s_io_this, and a device's @c release and the @c on_error of a
 *  packet-fd open or a dial land on this thread.
 */
static void s_trunk_msg_abandon(duct_msg_t *msg)
{
    duct_fatal((uintptr_t)msg->arg >= msg_kind_count);
    switch ((duct_msg_kind_t)(uintptr_t)msg->arg) {
    case msg_kind_plain:
    case msg_kind_embedded:
    duct_msg_sweep_ctrl(s_io_abandon_other)
        break;
    duct_msg_sweep_io(s_io_abandon_case)
    }
}
#undef s_io_abandon_case
#undef s_io_abandon_other

void duct_io_cleanup(void)
{
    for (unsigned i = 0u; i < s_imod.n_io; ++i) {
        auto t = &s_imod.xports[i];
        /* Drop all conns still owned by this io thread — s_conn_shutdown
         * unlinks each as it goes, so the next pointer is captured first. */
        for (auto conn = duct_conn_io_list_head(i); conn; ) {
            auto next = conn->io_next;
            s_conn_shutdown(t, conn);
            conn = next;
        }
        /* Drain orphan messages from trunk stack. Embedded messages
         * (msg_kind_embedded) are skipped as their lifetimes are managed
         * by parent objects; other messages release associated resources
         * and are freed. */
        auto head = duct_msg_stack_detach(&t->trunk.stack);
        while (head) {
            auto next = duct_msg_next(head);
            if ((duct_msg_kind_t)(uintptr_t)head->arg != msg_kind_embedded) {
                s_trunk_msg_abandon(head);
                duct_msg_done(head);
            }
            head = next;
        }
        /* Drops all still-pending dial and probe-wait admissions,
         * mirroring the conn loop above. This is whole-engine teardown
         * with this thread already joined: no concurrent resolver, no
         * deferred-completion dance needed, a direct free is enough. A
         * dial reports through s_dial_abandon first; a probe's park count
         * goes back nowhere here — its listener may already be gone, and
         * the count dies with it. */
        for (auto pre_conn = t->pre_conns; pre_conn; ) {
            auto next = pre_conn->next;
            if (pre_conn->kind == pre_conn_dial)
                s_dial_abandon(&pre_conn->dial.seed, rc_closed);
            duct_events_unwatch(t->trunk.events, pre_conn->fd, nullptr);
            duct_sock_close(pre_conn->fd);
            s_pre_conn_free(t, pre_conn);
            pre_conn = next;
        }
        /* Every conn drop above already discarded its own retry node; this
         * also frees batch_buf — belt-and-suspenders for anything the
         * loop missed. */
        duct_frame_rx_ctx_destroy(&t->frame_rx);
        duct_del(t->vnet_hdr);
        duct_del(t->dgram_scratch);
        duct_timers_destroy(&t->timers);
        duct_events_fini(t->trunk.events);
        t->trunk.events = nullptr;
    }
    duct_del(s_imod.xports);
    s_imod.n_io = 0u;
}
