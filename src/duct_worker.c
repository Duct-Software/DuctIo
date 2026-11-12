/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_worker.c
 *  @brief Worker: WFQ drain, defer retry, timers, declarative dispatch.
 *
 *  The protocol's on_frame/on_dgram callback runs with a duct_response_t
 *  out-parameter; s_commit_response does the TX path (route, stage,
 *  publish, release, io wake), and s_ctl_apply applies the declarative
 *  side effects (stream fin/reset, open leg, timer start/cancel, RX
 *  pause/resume, close). Session lifecycle composition and
 *  on_session_open/on_session_close firing live in the session TU; this
 *  file binds conns and tears io legs down.
 *
 *  Frame dispatch covers both a plain wire's RX ring span
 *  (s_dispatch_frame) and a sealed wire's decrypted cleartext
 *  (s_dispatch_sealed_frame); a multiplexed protocol's stream handler runs
 *  as a stackless async or stackful coroutine through the worker's own
 *  coop scheduler. Transient TX backpressure across every retry class
 *  (emit, frame, timer, fin) parks on one unified retry list, drained
 *  each cycle by s_retry_drain.
 */

#include "duct_worker.h"
#include "duct_build_config.h"
#include "duct_relay.h"
#include "duct_dgram_out.h"
#include "duct_host.h"
#include "duct_protocol.h"
#include "duct_session.h"
#include "duct_stats.h"
#include "duct_tx_pool.h"
#include "duct_vmq.h"
#include "duct_vnet.h"
#include "duct_wfq.h"
#include "duct_timer.h"
#include "duct_bits.h"
#include "duct_core.h"
#include "duct_hash.h"
#include "duct_join.h"
#include "duct_coro.h"
#include "duct_stream_ctx.h"
#include "duct_dgram_rec.h"
#include "duct_x_slot.h"
#include "duct_ticks.h"
#include "duct_olb_rx.h"
#include "duct_olb_tx.h"
#include "duct_wire_codec.h"
#include "duct_wire_tx.h"
#include "duct_tls.h"
#if DUCT_RUNTIME_STATS
#include "duct_runtime_stats.h"
#endif

#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


/** @brief Sentinel for the ticket parameter of @c s_commit_response: take a
 *  fresh ticket from the target OLB.
 *  Reaching UINT32_MAX takes 2^32 commits on one OLB.
 */
static constexpr uint32_t duct_tx_ticket_fresh = UINT32_MAX;

/** @brief Advance a tx_seq counter, skipping @c duct_tx_ticket_fresh so the
 *  sentinel never collides with a real ticket after a wrap. */
static inline uint32_t s_tx_seq_advance(uint32_t v)
{
    return v + 1u == duct_tx_ticket_fresh ? v + 2u : v + 1u;
}

/** @brief One conn's commit-ticket counters, wherever its xport keeps them. */
typedef struct { uint32_t *next,
                          *serve; } tx_seq_ref_t;

/** @brief Resolve @p conn's ticket counters: its TX OLB's pair when it has
 *  one, @c duct_conn_t::tx_seq when it has no OLB at all.
 *  Both members are null together, which is the answer for an OLB xport whose
 *  buffer is not wired up yet — @ref duct_conn_setup fills it, and it never
 *  runs for @c x_inter or @c x_udp_shared.
 */
static inline tx_seq_ref_t s_tx_seq_of(duct_conn_t *conn)
{
    if (!duct_conn_has_olb(conn))
        return (tx_seq_ref_t){ &conn->tx_seq.next, &conn->tx_seq.serve };
    auto tx = conn->tx_buf;
    duct_do_if(!tx, return (tx_seq_ref_t){});
    return (tx_seq_ref_t){ &tx->tx_seq_next, &tx->tx_seq_serve };
}

/** @brief Claim @p seq's next commit ticket, or re-present @p *ticket from an
 *  earlier blocked attempt.
 *
 *  @return false while an older ticket has not published yet: the caller must
 *  not stage, and must carry @p *ticket into its own retry. Order, not space —
 *  a false here says nothing about how much room is free.
 */
duct_nonnull(2) static inline bool
s_tx_ticket_take(tx_seq_ref_t seq, uint32_t *ticket)
{
    if (*ticket == duct_tx_ticket_fresh) {
        *ticket = *seq.next;
        *seq.next = s_tx_seq_advance(*seq.next);
    }
    return *ticket == *seq.serve;
}

/** @brief Let the ticket behind the one just resolved through. Exactly one
 *  call per @ref s_tx_ticket_take that reached a definitive outcome; a still-
 *  blocked attempt leaves its ticket outstanding for the retry instead.
 */
static inline void s_tx_ticket_resolve(tx_seq_ref_t seq)
{
    *seq.serve = s_tx_seq_advance(*seq.serve);
}

/** @brief Resolve @p ticket on @p conn in its turn, for an output that stages
 *  nothing.
 *  @return false while an older ticket of @p conn waits; true once this one
 *  resolved, and for a gone @p conn or one without counters. */
static bool s_tx_ticket_pass(duct_conn_t *conn, uint32_t ticket)
{
    auto seq = conn ? s_tx_seq_of(conn) : (tx_seq_ref_t){};
    if (seq.serve && *seq.serve != ticket)
        return false;
    if (seq.serve)
        s_tx_ticket_resolve(seq);
    return true;
}

static bool s_hold_adopt(const duct_session_t *s, duct_tx_hold_t *h, const duct_conn_t *owner);

/** @brief Test whether @p ticket on @p leg is still ahead of the leg's serve counter.
 *  A leg that is gone, or no longer one of @p s's, reads as served.
 */
static bool s_tx_pending(const duct_session_t *s, duct_handle_t leg, uint32_t ticket)
{
    auto handle = (duct_conn_handle_t){ .word = leg };
    auto conn = s && duct_session_conn_id_by_handle(s, handle) < duct_session_max_legs
              ? duct_conn_by_handle(handle) : nullptr;
    auto seq = conn ? s_tx_seq_of(conn) : (tx_seq_ref_t){};
    return seq.serve && (int32_t)(*seq.serve - ticket) <= 0;
}

/** @brief Test whether the parked output @p h names still waits for its turn.
 *  It waits while its leg, still one of @p s's, has not served its ticket; a
 *  published or abandoned ticket and a leg gone or detached clear @p h. A
 *  detached leg is never read: the conn-lost consume detaches it before the
 *  retire confirm that hands its rings to io's teardown. When @p h clears and
 *  @p owner, the conn whose dispatch @p h belongs to and null for the session's
 *  timer hold, is set, a parked answer of that dispatch still waiting takes
 *  @p h over: the hold stands until the last of them is served, on whichever
 *  leg it parked. */
static bool s_tx_held(const duct_session_t *s, duct_tx_hold_t *h, const duct_conn_t *owner)
{
    if (h->leg == handle_null)
        return false;
    if (s_tx_pending(s, h->leg, h->ticket))
        return true;
    h->leg = handle_null;
    return owner && s_hold_adopt(s, h, owner);
}

/** @brief Resolve the hold @p conn's inbound waits on: its RX ring's, or its
 *  inter lane's on a conn without a ring. */
static duct_tx_hold_t *s_conn_tx_hold(const duct_conn_t *conn)
{
    auto rx = duct_conn_rx_olb(conn);
    if (rx)
        return &rx->tx_hold;
    auto lane = duct_conn_lane(conn);
    assert(lane);
    return &duct_mpsc_ctrl(lane, 0u)->tx_hold;
}

/** @brief Unbounded drain quota sentinel. */
static constexpr size_t   wfq_quota_none          = SIZE_MAX;
static constexpr unsigned worker_ext_drain_quota  = 16u;
static constexpr size_t   egress_lane_cap = kbytes(256u);

/** @brief Fraction of the key lifetime each arm pulls its fire forward within. */
static constexpr unsigned rekey_spread_div = 4u;

/** @brief Internal result of a synchronous response commit. */
typedef enum duct_commit_rc : uint8_t {
    commit_ok,      /**< Handed off for delivery -- staged, reserved, or
                      *  sent; never wire-confirmed. */
    commit_closed,
    commit_invalid,
    commit_internal,
} duct_commit_rc_t;

/** @brief Handler coroutine step outcome, runtime-agnostic: async_yield /
 *  coro_state_suspended -> emit, async_wait / coro_state_waiting -> wait, async_done /
 *  coro_state_done -> done.
 */
typedef enum duct_handler_event : uint8_t {
    handler_event_emit,
    handler_event_wait,
    handler_event_done,
} duct_handler_event_t;

/** @brief What the runtime-specific caller must do with the coroutine next. */
typedef enum duct_handler_outcome : uint8_t {
    handler_outcome_run,
    handler_outcome_park,
    handler_outcome_release,
    /** Commit hit transient TX backpressure; context is queued in the worker
     *  retry list (@ref s_retry_emit_save), with subsequent dispatch handled
     *  by @ref s_retry_drain.
     */
    handler_outcome_retry,
} duct_handler_outcome_t;

#ifndef DUCT_BITMAP_WORDS
#define DUCT_BITMAP_WORDS ((duct_max_conns + 63u) / 64u)
#endif

typedef struct retry_node retry_node_t;

typedef struct duct_deferred_queue {
    duct_msg_queue_t    q;
    uint64_t _Atomic    mask[DUCT_BITMAP_WORDS];
} duct_deferred_queue_t;

/** @brief Arena bytes of a worker's region ring, one @c dgram_tx_outbox lane's
 *  capacity.
 *  The TX pool's arena holds a pass's @c x_udp_shared batch entries and every
 *  region an author takes through @ref duct_tx_pool_acquire, several at once;
 *  the cleartext ring's holds the datagram being decrypted and the payloads a
 *  vnet train still references.
 */
static constexpr size_t duct_worker_tx_pool_cap = duct_dgram_tx_outbox_cap;

/** @brief In-arena header preceding every acquired region, immediately
 *  followed by @c len bytes of payload.
 *
 *  @ref duct_tx_pool_acquire hands the region out, and
 *  @c s_tx_pool_region_bytes rounds the whole footprint up to keep the
 *  next header 8-byte aligned too.
 *
 *  @c refs counts live @c duct_worker_dgram_batch_entry_t entries still
 *  referencing this region, resolved back down at every flush, retry-save or
 *  terminal-drop point; in the cleartext ring it counts the spans of the vnet
 *  train that point into the region.
 *  @c hold is the claim of whoever took the region, set by @c s_pool_acquire.
 *  @c s_tx_pool_pass_end clears a TX region's unless @c keep carries it one pass
 *  on, @c s_tx_pool_drop_hold a cleartext region's. A region frees only once
 *  both are zero.
 *
 *  @c refs and @c hold share one 32-bit word: the ring is worker-owned and
 *  single-threaded, so neither is atomic and the header stays 8 in-arena bytes.
 */
typedef struct {
    uint32_t len;
    uint32_t refs : 30;
    uint32_t hold : 1;
    uint32_t keep : 1;
} duct_tx_pool_hdr_t;

/** @brief Arena grid, in bytes.
 *  Header and payload both round up to it and the arena starts on it, so
 *  regions bump-allocate with no inter-region padding and every header and
 *  payload lands aligned to it. */
static constexpr uint32_t duct_tx_pool_align = 8u;

/** @brief Region header size, rounded up to the arena grid.
 *  @ref duct_tx_pool_hdr_t padded to @ref duct_tx_pool_align keeps the
 *  payload (and hence the next region's own header) on that grid. Plain
 *  arithmetic, not @ref duct_align_up: that macro's statement-expression form
 *  is not a constant expression a file-scope @c constexpr initializer
 *  accepts. */

static constexpr uint32_t duct_tx_pool_hdr_bytes =
    ((uint32_t)sizeof(duct_tx_pool_hdr_t) + duct_tx_pool_align - 1u)
    & ~(duct_tx_pool_align - 1u);

/** @brief Offset @c s_tx_pool_place answers when no room is left for a region.
 *  No offset of the arena equals it. */
static constexpr uint32_t duct_tx_pool_no_room = UINT32_MAX;

/** @brief Total in-arena footprint of a region holding @p len payload
 *  bytes: header plus 8-aligned payload, so consecutive regions bump-
 *  allocate cleanly without any inter-region padding logic. */
static inline uint32_t s_tx_pool_region_bytes(uint32_t len)
{
    return duct_tx_pool_hdr_bytes + (uint32_t)duct_align_up(len, duct_tx_pool_align);
}

/** @brief Single-threaded, variable-region ring over @c arena, the type of a
 *  worker's TX staging pool and of its cleartext ring.
 *  The owning worker alone touches it, so every field is a plain counter.
 */
typedef struct {
    uint32_t head,       /**< Start of the oldest not-yet-reclaimed region. */
             tail,       /**< Next bump-allocate offset. */
             high_water; /**< Where the skipped fragment's own tail end was,
                           *  read by reclaim while @c wrapped; meaningless
                           *  otherwise. */
    bool     wrapped;    /**< A pending wrap: a region that did not fit in
                           *  @c [tail, cap) skipped that leftover fragment and
                           *  continued at offset 0. Set, live data spans
                           *  @c [head, high_water) from the lap before the wrap
                           *  plus @c [0, tail) from the new one, and a fresh
                           *  allocation may grow @c tail only up to @c head --
                           *  never past it, never a second wrap ahead of the
                           *  first one draining. Unset, live data is the plain
                           *  span @c [head, tail). */
    alignas(duct_tx_pool_align) uint8_t arena[duct_worker_tx_pool_cap];
} duct_tx_pool_t;

/** @brief One @c x_udp_shared send this drain pass has staged but not yet
 *  handed to the kernel. @c ptr is either a pool region's own payload
 *  (zero-copy: the author's response payload already lived there) or a
 *  region this same commit call packed the wire's bytes into (the
 *  fallback: a foreign buffer, or a wire whose @c on_pack writes a real
 *  header) — either way @c region (that region's header, @c ptr minus
 *  @ref duct_tx_pool_hdr_bytes) owns one reference this entry is
 *  responsible for releasing exactly once, at whichever point (send,
 *  lane-copy, retry-save, or terminal drop) resolves this entry — see
 *  @ref s_worker_dgram_flush. @c handle is re-resolved at flush time; callback
 *  state for @ref s_fire_send_done is copied into this entry to outlive
 *  transient handler context.
 */
typedef struct {
    duct_conn_handle_t handle;
    duct_peer_t         peer;
    duct_conn_id_t      conn_id;
    duct_stream_id_t    stream_id;
    duct_send_flags_t   flags;
    uintptr_t           send_token;
    uint8_t             *ptr;
    union {
        duct_tx_pool_hdr_t *region;
        void               *block;
    };
    uint32_t            len;
    uint8_t             hdr[wire_tx_hdr_max];
    uint8_t             hdr_len;
} duct_worker_dgram_batch_entry_t;

/** @brief One worker drain pass's @c x_udp_shared batching state -- the
 *  entry array is allocated once per worker thread (@c s_run_loop),
 *  sized to @c duct_async_cycle_quota, the ceiling on how many responses
 *  one @c duct_coop_cycle call can produce. The kick array has the same size, and @c n and
 *  @c kick_n stay under it. This struct only borrows those arrays and is
 *  handed to @c s_commit_response's @c x_udp_shared case through @ref
 *  duct_worker_t::dgram_pass, reset per pass. Entry bytes live in the
 *  worker's persistent @ref duct_tx_pool_t; this struct carries no byte
 *  storage of its own.
 */
typedef struct {
    duct_worker_dgram_batch_entry_t *entries;
    uint32_t                        n;
    uint64_t                        first_ns; /**< Monotonic stamp of the entry
                                     *  that opened this batch; the latency
                                     *  budget runs from it. Meaningless while
                                     *  @c n is zero. */
    duct_listener_t                 *listener; /**< This batch's listener;
                                     *  nullptr when empty. A commit for a
                                     *  different listener flushes first --
                                     *  one send-batch call targets exactly
                                     *  one socket. */
    duct_listener_t                 **kick_listeners; /**< Distinct listeners
                                     *  using lane reservations during this
                                     *  pass, batched for notification at
                                     *  flush. */
    uint32_t                        kick_n;
} dgram_pass_t;

/** @brief This worker's train of TCP segments or UDP datagrams bound for one vnet tun leg.
 *  No pass ends with a train open; @c gro.segs of 0 marks it empty. Each payload
 *  span points into a region of the worker's cleartext ring, which the train
 *  holds by a reference until the write. */
typedef struct {
    duct_conn_handle_t conn; /**< Leg the train is bound for; a handle, so a leg
                               *  gone by the flush resolves to nothing. */
    duct_vnet_gro_t    gro;  /**< Segments merged so far. */
    duct_tx_pool_hdr_t *regions[duct_vnet_gro_span_max]; /**< Region behind each
                               *  payload span of @c gro, by span. The span of a
                               *  payload the ring had no room to copy has none:
                               *  nullptr, its train written at once. */
} vnet_train_t;

/** @brief This worker's train of frames staged, unpublished, on one
 *  @c x_udp_peer or @c x_tcp leg's TX ring.
 *  No frame batch or inter lane drain ends with a train open, and a commit
 *  outside them sends its frame at once. */
typedef struct {
    duct_conn_handle_t conn;     /**< Leg the frames are bound for; a handle,
                                   *  so a leg gone by the flush resolves to
                                   *  nothing. */
    uint32_t           frames;   /**< Frames staged since the train opened;
                                   *  0 marks it empty. */
    bool               more;     /**< More frames of the dispatch in flight
                                   *  still to come after the current one. Set
                                   *  per frame of a frame batch and across an
                                   *  inter lane drain, each of which flushes
                                   *  the train when it ends. */
    uint64_t           first_ns; /**< Tick stamp of the train's opening, which
                                   *  @c duct_dgram_batch_wait_ns runs from. */
} tx_train_t;

/** @brief State of one worker thread.
 *  The leading group holds the fields producer threads write: the wake
 *  latch, the control stack, the WFQ waiter bits and the inter-lane arm
 *  bitmap with its count. It fills whole cache lines, so a producer's write
 *  never invalidates a field only this worker writes. The fields behind it
 *  are written by this worker, set at init, or set once at start or stop.
 *  The worker array is allocated with @c duct_new, which honours the line
 *  alignment of the struct.
 */
typedef struct duct_worker {
    duct_cacheline_struct(
        /* A declaration of its own: the group's alignas aligns every declarator
         * of the first declaration to a line. */
        uint32_t _Atomic        inter_pending; /**< Count of @c inter_armed bits set.
                                                 *  An arm adds 1 where it finds the
                                                 *  bit clear, and the scan subtracts
                                                 *  1 per bit it grabs. Zero lets
                                                 *  s_inter_drain skip its scan of
                                                 *  the DUCT_BITMAP_WORDS words. */
        uint32_t _Atomic        wake_latch;    /**< Wake flag of this worker's park.
                                                 *  A producer exchanges it to 1 and
                                                 *  wakes the futex when it read 0.
                                                 *  The worker clears it ahead of its
                                                 *  last re-check and waits on it
                                                 *  while it reads 0. */
        uint32_t _Atomic        retry_epoch;   /**< Lap counter of the retry list.
                                                 *  Each TX-room wake through
                                                 *  @c duct_worker_wake_id adds 1, as
                                                 *  does a retry pass that resolved a
                                                 *  node; @c s_retry_drain attempts
                                                 *  every parked node once per value. */
        duct_msg_stack_t        ctrl_stack;    /**< Control messages posted by any
                                                 *  thread through
                                                 *  @c duct_worker_post_ctrl. The
                                                 *  worker detaches the whole stack
                                                 *  in its drain. */
        duct_wfq_io_waiters_t   wfq_io_waiters; /**< Bit per io thread waiting for room
                                                 *  in this worker's WFQ lanes.
                                                 *  @c s_drain_kick_io_waiters takes
                                                 *  the word and wakes each io thread
                                                 *  whose bit it held. */
        uint64_t _Atomic        inter_armed[DUCT_BITMAP_WORDS]; /**< Bit per conn
                                                 *  index with an unconsumed
                                                 *  inter_lane push. Producers arm it
                                                 *  through @c duct_worker_inter_arm,
                                                 *  and this worker's drain grabs
                                                 *  every word, dropping the bit of a
                                                 *  conn not bound to it. */
    );
    duct_timers_t           timers;
    duct_deferred_queue_t   defer_q;
    duct_vmq_mpsc_t        *host_egress; /**< Host-bridge egress, this worker's
                                    * alone to produce on; null without a
                                    * bridge. */
    duct_msg_queue_t       ext_pending;
    duct_coop_t     coop;
    /** Unified TX-backpressure retry queue (emit/frame/timer/fin/dgram/engine), FIFO —
     *  see retry_node_t and s_retry_drain. retry_tail is nullptr
     *  exactly when retry_head is.
     */
    retry_node_t         *retry_head,
                           *retry_tail;
    /** @brief Runtime-wide WFQ; this worker drains its assigned lanes. */
    duct_vmq_mpsc_t        *wfq;
    unsigned                worker_id;
    unsigned                n_workers;
    unsigned                n_io;
    int                     cpu;           /**< Logical cpu this worker placed
                                             *  itself on, -1 unpinned. Written
                                             *  once ahead of the release store
                                             *  of @c started, which
                                             *  @ref duct_engine_thread_cpu
                                             *  relies on. */
    duct_spin_state_t       spin;
    uint64_t                pass_ns;       /**< Monotonic reading taken at the top of
                                             *  this worker's current loop pass,
                                             *  nanoseconds. It does not move inside the
                                             *  pass, so the idle stamps and the idle
                                             *  expiries of one pass read one value. */
    bool                    spinning;      /**< Spin decision of the last idle pass;
                                             *  its changes feed busy_enter/exit. */
    bool _Atomic            shutdown;
    unsigned _Atomic        started;
    duct_tx_pool_t          tx_pool; /**< Worker TX staging pool. */
    duct_tx_pool_t          ct_pool; /**< Region ring for the cleartext of the
                               *  sealed datagrams this worker decrypts off the
                               *  inter lane. */
    /** @brief This worker's @c x_udp_shared batching state, null outside its
     *  run loop.
     *  Bound once at loop entry and cleared at exit, so a null here tells
     *  @ref s_worker_dgram_flush there is no loop to flush for. The counters
     *  inside reset per pass, not this pointer.
     *  @c s_commit_response accumulates datagrams into this batch;
     *  @ref s_worker_dgram_flush sends them at pass completion.
     */
    dgram_pass_t           *dgram_pass;
    uint32_t                  dgram_parked; /**< Datagram retry nodes this worker
                                              *  holds parked. While any is, a
                                              *  datagram commit waits and the
                                              *  flush parks what it cannot send. */
    vnet_train_t           *vnet_train; /**< This worker's vnet train, null
                                            *  outside its run loop. */
    duct_tx_hold_t           *hold_into;  /**< Hold an output parked now
                                            *  writes: the dispatched conn's
                                            *  around a frame's or an inter
                                            *  message's dispatch, the
                                            *  session's around a timer's
                                            *  invoke, null elsewhere. */
    const duct_conn_t        *hold_conn;  /**< Conn whose dispatch @c hold_into
                                            *  belongs to, null around a timer's
                                            *  invoke and elsewhere. A frame or
                                            *  fin parked meanwhile records its
                                            *  handle. */
    duct_frame_ack_t         *rx_ack;    /**< Ack of the frame whose answer is
                                            *  being taken, null elsewhere; a
                                            *  park aliasing the frame takes it
                                            *  over and clears this. */
    const duct_frame_ack_t   *slot_now;   /**< RX slot of the inter batch in dispatch,
                                            *  null for a batch that carries none and
                                            *  outside a dispatch. @ref s_slot_pin pins
                                            *  an answer that lies in it. */
    tx_train_t             tx_train;    /**< This worker's @c x_udp_peer or
                                            *  @c x_tcp train. */
#if DUCT_RUNTIME_STATS
    duct_worker_rt_t        rtstats;
#endif
} duct_worker_t;

static_assert(alignof(duct_worker_t) == duct_cacheline_size,
    "a worker starts on a cacheline");
static_assert(offsetof(duct_worker_t, wake_latch) < offsetof(duct_worker_t, timers)
              && offsetof(duct_worker_t, timers) % duct_cacheline_size == 0u,
    "the fields other threads write fill cachelines of their own");

/** @brief Argument of a timer node: the worker, timer handle, and exec fields.
 *
 *  The node's @c exec picks the variant. A session timer holds the owning
 *  session's handle, a word @c token and the @c key it was started under, 0 for
 *  none: @c token is the protocol's argument under @ref s_timer_fire, the conn
 *  handle under @ref s_rekey_fire, @ref s_join_deadline_fire and
 *  @ref s_hs_retry_fire, and 0 under
 *  @ref s_idle_fire. @ref duct_worker_session_timers_cancel matches on
 *  @c session_tok, so every session kind retires with its session. A free timer,
 *  armed for @ref s_timer_fire_free, belongs to no session and holds the
 *  protocol, its @c user_ctx and the token.
 *
 *  Handles throughout, never a raw @c duct_session_t* or @c duct_conn_t*: the
 *  target is resolved again on each fire, and one reclaimed between arm and
 *  fire is a safe drop. Allocated via @c duct_new, released by the timer module
 *  through @c duct_del_fn on fire-done, cancel or destroy.
 */
typedef struct {
    duct_worker_t *w;
    union {
        struct {
            duct_handle_t  session_tok;
            uint64_t       token;
            uint32_t       key;
        };
        struct {
            const duct_proto_t *proto;
            void               *user_ctx;
            uintptr_t           arg;
        };
    };
    duct_timer_handle_t   self;     /* Own handle, for self-cancel on stale
                                      * resolve or a closing session — the
                                      * only way to stop a recurring timer;
                                      * the heap ignores exec's return value.
                                      * s_rekey_fire matches it against its
                                      * codec's rekey_timer; a keyed timer's slot
                                      * and its parked fire name it too. */
} timer_ctx_t;

typedef struct {
    duct_worker_t   *workers;
    pthread_t       *threads;
    unsigned         n_workers;
    uint64_t         seal_key_lifetime_ms;
} duct_worker_module_state_t;

static duct_worker_module_state_t s_wmod;

#if DUCT_RUNTIME_STATS
const duct_worker_rt_t *duct_worker_rtstats(unsigned worker_id)
{
    if (worker_id >= s_wmod.n_workers)
        return nullptr;
    return &s_wmod.workers[worker_id].rtstats;
}
#endif

/** @brief TLS pointer to the currently running worker; file-static only. */
static thread_local duct_worker_t *s_this_worker;

#if DUCT_RUNTIME_STATS
void duct_worker_rtstat_tcp_write(size_t cap, size_t total)
{
    duct_rtstat_obj_inc(s_this_worker, rtstats.tcp_writes, 1);
    duct_rtstat_obj_inc(s_this_worker, rtstats.tcp_eor_writes, cap != 0u);
    duct_rtstat_obj_inc(s_this_worker, rtstats.tcp_cut_writes, cap && total > cap);
}

void duct_worker_rtstat_fast_miss(bool armed)
{
    duct_rtstat_obj_inc(s_this_worker, rtstats.fastpath_armed_skip, armed);
    duct_rtstat_obj_inc(s_this_worker, rtstats.fastpath_eagain, !armed);
}
#endif

/** @brief Reclaim @p pool head past every fully dead region.
 *  Dead regions (@c refs == 0 && !hold) are reclaimed in ring order. An
 *  out-of-order-dead region (a live successor already resolved while this one
 *  is still held/referenced) waits for its predecessors; the only long-holder
 *  is one retried chunk against a pool sized for many. Crossing @c high_water
 *  while wrapped flips back to the plain single-lap regime and the walk
 *  continues from offset 0.
 */
static void s_tx_pool_reclaim(duct_tx_pool_t *pool)
{
    for (;;) {
        if (pool->wrapped && pool->head == pool->high_water) {
            pool->head = 0u;
            pool->wrapped = false;
        }
        if (pool->head == pool->tail) {
            /* Unambiguously empty -- a wrapped tail never catches head
             * exactly (s_tx_pool_place). Rewind to offset 0 so a
             * following large acquire never fails on the cursor's
             * parking spot alone: head == tail mid-arena otherwise
             * splits the free space in two. */
            assert(!pool->wrapped);
            pool->head = 0u;
            pool->tail = 0u;
            return;
        }
        auto hdr = (duct_tx_pool_hdr_t *)(pool->arena + pool->head);
        if (hdr->refs != 0u || hdr->hold)
            return;
        pool->head += s_tx_pool_region_bytes(hdr->len);
    }
}

/** @brief End a worker pass: release the hold of every region not marked
 *  @c keep.
 *  A region marked @c keep spends the mark here and survives into the next
 *  pass instead, so cross-pass reuse is re-declared every pass. An author who
 *  acquires and never emits cannot wedge the ring this way — @ref
 *  s_tx_pool_reclaim frees in ring order, so one region left held blocks every
 *  region behind it.
 *  @return true when a region was still held: released here, or at the next
 *  pass end for one that carried @c keep.
 */
static bool s_tx_pool_pass_end(duct_tx_pool_t *pool)
{
    uint32_t off = pool->head;
    uint32_t end = pool->wrapped ? pool->high_water : pool->tail;
    bool held = false;
    for (;;) {
        if (off >= end) {
            if (!pool->wrapped || end == pool->tail)
                break;
            off = 0u;
            end = pool->tail;
            continue;
        }
        auto hdr = (duct_tx_pool_hdr_t *)(pool->arena + off);
        held |= hdr->hold;
        if (hdr->keep)
            hdr->keep = 0u;
        else
            hdr->hold = 0u;
        off += s_tx_pool_region_bytes(hdr->len);
    }
    return held;
}

/** @brief True if @p ptr falls inside @p pool arena.
 *
 *  The range check @c s_commit_dgram_shared uses to tell a pool-backed
 *  response payload from an ordinary author buffer. Two compares: a pointer
 *  outside this worker arena cannot alias into it.
 */
static inline bool s_tx_pool_owns(const duct_tx_pool_t *pool, const uint8_t *ptr)
{
    return ptr >= pool->arena
        && ptr < pool->arena + duct_worker_tx_pool_cap;
}

/** @brief Bump-allocate @p need bytes at @p pool tail, wrapping once behind @c head.
 *  @p limit is how far @c tail may grow this call without touching live data:
 *  @c head once already wrapped (nothing past it is reusable until reclaim
 *  proves otherwise), the arena end otherwise. A not-yet-wrapped pool that
 *  does not fit before the end wraps once; an already-wrapped pool that does
 *  not fit before @c head fails with @ref duct_tx_pool_no_room.
 *  @return Offset where the region header starts, or @ref duct_tx_pool_no_room.
 */
static uint32_t s_tx_pool_place(duct_tx_pool_t *pool, uint32_t need)
{
    uint32_t tail = pool->tail;
    uint32_t limit = pool->wrapped ? pool->head : duct_worker_tx_pool_cap;
    assert(tail <= limit);
    /* While wrapped, tail must never catch head exactly: head == tail is
     * the ring's one "empty" sentinel (s_tx_pool_reclaim's rewind), so a
     * full-to-the-byte wrapped pool reads as a drained one and reclaim
     * deadlocks on it. One byte of the
     * wrapped gap stays unusable by design; same for entering a wrap. */
    bool fits = pool->wrapped ? need < limit - tail : need <= limit - tail;
    if (!fits) {
        if (pool->wrapped || need >= pool->head)
            return duct_tx_pool_no_room;
        pool->high_water = tail;
        pool->wrapped = true;
        tail = 0u;
    }
    uint32_t placed_at = tail;
    tail += need;
    if (tail == duct_worker_tx_pool_cap && pool->head != 0u) {
        /* Landed exactly on the boundary -- zero-waste wrap, no dead
         * space to skip. head == 0 keeps the unwrapped tail == cap form
         * instead: wrapping there recreates the ambiguous
         * head == tail == 0 full state. */
        pool->high_water = duct_worker_tx_pool_cap;
        pool->wrapped = true;
        tail = 0u;
    }
    pool->tail = tail;
    return placed_at;
}

/** @brief Take a region of @p size payload bytes from @p pool, held for its taker.
 *  Reclaims the dead regions at the head first.
 *  @return The payload, 8-byte aligned; nullptr when @p size can never fit or the
 *  ring has no room now. */
static void *s_pool_acquire(duct_tx_pool_t *pool, size_t size)
{
    duct_do_if(size > UINT32_MAX, return nullptr);
    s_tx_pool_reclaim(pool);
    uint32_t need = s_tx_pool_region_bytes((uint32_t)size);
    duct_do_if(need > duct_worker_tx_pool_cap, return nullptr); /* can never fit, ever */

    uint32_t off = s_tx_pool_place(pool, need);
    duct_do_if(off == duct_tx_pool_no_room, return nullptr);
    auto hdr = (duct_tx_pool_hdr_t *)(pool->arena + off);
    *hdr = (duct_tx_pool_hdr_t){ .len = (uint32_t)size, .refs = 0u, .hold = true };
    return (char *)hdr + duct_tx_pool_hdr_bytes;
}

void *duct_tx_pool_acquire(size_t size)
{
    auto w = s_this_worker;
    duct_do_if(!w, return nullptr);
    void *region = s_pool_acquire(&w->tx_pool, size);
    duct_rtstat_obj_inc(w, rtstats.tx_pool_acquire_fail, !region);
    return region;
}

/** @brief The region header behind a payload pointer.
 *  Valid only for a pointer @c s_pool_acquire handed out, never an interior
 *  one. */
static inline duct_tx_pool_hdr_t *s_tx_pool_hdr_of(void *ptr)
{
    return (duct_tx_pool_hdr_t *)((char *)ptr - duct_tx_pool_hdr_bytes);
}

/** @brief Drop the hold on the region behind @p ptr, leaving @c refs to govern it.
 *  Its callers are the packing of @c x_udp_shared responses into the TX pool, a
 *  branch the iocp build compiles out in favour of the outbox lane, and the
 *  cleartext ring: a packet's end and a vnet train's copy of a payload. */
static void s_tx_pool_drop_hold(void *ptr)
{
    s_tx_pool_hdr_of(ptr)->hold = 0u;
}

static duct_exec_rc_t s_dispatch_msg(duct_vmq_hdr_t *hdr);
static duct_exec_rc_t s_dispatch_batch(duct_vmq_hdr_t *hdr, duct_worker_t *w,
                                       uint32_t *out_defer_idx);
static bool s_defer_batch_from_vmq(duct_deferred_queue_t *q,
                                   const duct_vmq_hdr_t *hdr, uint32_t from);
static duct_exec_rc_t
s_dispatch_batch_frames(duct_worker_t *w, const duct_msg_frame_batch_t *b,
                        uint32_t from, uint32_t *out_defer_idx);

/** @brief Where an inbound sealed packet's cleartext lands: a destination
 *  reservation taken before the decrypt, so the cleartext lands where it will be
 *  sent from, else a region of the worker's cleartext ring.
 *
 *  Lives on @ref s_inter_pkt's stack for one packet and doubles as that
 *  packet's unseal context: @c base leads the struct, which lets
 *  @ref s_redirect_reserve and @ref s_redirect_commit cast back to it. @c at is
 *  the frame payload the protocol then sees; where that is @c span, a response
 *  that is the whole of it, written whole, is recognised at the commit by
 *  pointer and published in place.
 *
 *  @c span and @c ct are the only fields the declaration initialises, and the
 *  only ones any path reads before @ref redirect_take has run; @c take writes
 *  the rest ahead of the reservation it may fail to get. A field added here that
 *  some path reads before then has to be initialised at the declaration too.
 */
typedef struct {
    duct_unseal_ctx_t        base;
    void                    *span;      /**< Reserved bytes, null while no
                                          *  reservation is open. Whoever
                                          *  consumes it clears it, leaving
                                          *  @ref s_redirect_release only what
                                          *  nothing took. */
    size_t                   cap;       /**< Length of the unseal target: the
                                          *  cleartext count @c unseal_size
                                          *  reported for @c span, the region's
                                          *  size for @c ct. */
    size_t                   len;       /**< Bytes committed into the target so
                                          *  far. */
    duct_conn_id_t           conn_id;   /**< Leg @c route answered for this
                                          *  packet, carried into the commit so
                                          *  the callback runs once. */
    duct_stream_id_t         stream_id; /**< Stream from that same answer. */
    const duct_device_ops_t *dev;       /**< Set when the destination is a
                                          *  device leg, null when @c host
                                          *  carries the reservation instead. */
    duct_host_egress_hold_t  host;
    void                    *ct;        /**< Cleartext-ring region the packet
                                          *  decrypts into, null where a
                                          *  reservation or a plain wire is in
                                          *  play. @ref s_redirect_release drops
                                          *  its hold; a vnet train that took a
                                          *  reference keeps the region. */
    void                    *at;        /**< Where the unseal writes, @c span or
                                          *  @c ct, set ahead of the unseal. */
} redirect_t;

static duct_nonnull(1, 4, 5) duct_commit_rc_t s_commit_response(duct_session_t *s,
                                                                duct_conn_id_t in_conn,
                                                                duct_stream_id_t in_stream,
                                                                duct_response_t *out,
                                                                uint32_t *ticket, bool is_replay,
                                                                redirect_t *redirect);
static duct_commit_rc_t s_response_put(duct_session_t *s, duct_response_t *out,
                                       duct_conn_id_t conn_id, duct_stream_id_t stream_id,
                                       duct_frame_flags_t flags, redirect_t *redirect,
                                       duct_stream_ctx_t *hctx);
static duct_commit_rc_t s_response_take(duct_session_t *s, duct_response_t *out,
                                        duct_conn_id_t conn_id, duct_stream_id_t stream_id,
                                        duct_frame_flags_t flags, redirect_t *redirect,
                                        duct_stream_ctx_t *hctx);
static void s_response_switch(duct_session_t *s);
static void s_vnet_train_flush(duct_worker_t *w);
static void s_response_drop(duct_session_t *s, duct_response_t *out);
static void s_response_take_control(duct_session_t *s, const duct_response_t *out);
static duct_commit_rc_t s_response_retry(duct_session_t *s, duct_response_t *out,
                                         duct_conn_id_t conn_id, duct_stream_id_t stream_id,
                                         duct_frame_flags_t flags, uint32_t *ticket);
static void s_response_settle(duct_session_t *s, const duct_response_t *out,
                              duct_stream_id_t stream_id, duct_frame_flags_t flags);
static void s_commit_ticket_abandon(duct_conn_t *conn, uint32_t ticket, duct_response_t *out);
static duct_dgram_tx_entry_t *
s_dgram_tx_lane_reserve(const duct_vmq_lane_t *ln, size_t entry_bytes,
                        duct_vmq_reserve_pos_t *out_pos, duct_vmq_push_rc_t *out_rc);

/** @brief One staged send on a shared datagram listener, from the reservation of its lane entry to its publication. */
typedef struct {
    duct_vmq_lane_t        ln;    /**< This worker's lane of the listener's outbox. */
    duct_vmq_reserve_pos_t pos;   /**< Position of the reserved entry in the lane. */
    duct_dgram_tx_entry_t *entry; /**< The reserved entry, carrying the peer and the slot reference. */
    duct_x_slot_pool_t    *pools; /**< The listener's TX slot pools, null where the entry carries the bytes itself. */
    uint32_t               ref;   /**< Reference of the TX slot taken, @c treiber_empty without one. */
    duct_view_u8             span;  /**< Writable payload: the slot's bytes, or the entry's own. */
} dgram_out_t;

/** @brief Open a staged send of @p need payload bytes to @p peer on @p listener, on this worker's lane.
 *  A listener with TX slot pools stages into a slot of the class @p need asks for, and the lane entry
 *  carries its reference alone; without pools the entry carries the bytes. A class found empty arms the
 *  lane's wait latch and is tried once more, which closes the race with the io thread's drain wake.
 *  @return true with @p o set and its span writable for @p need bytes; false with @p rc the cause,
 *          @c vmq_push_too_large for a size past the large class, @c vmq_push_full for a dry class,
 *          or the lane's own refusal.
 */
static bool s_dgram_out_open(duct_listener_t *listener, const duct_peer_t *peer, size_t need,
                             dgram_out_t *o, duct_vmq_push_rc_t *rc)
{
    o->ln = duct_mpsc_lane(duct_io_dgram_shared_outbox(listener), s_this_worker->worker_id);
    o->pools = duct_io_dgram_shared_tx_slots(listener);
    o->ref = treiber_empty;
    size_t entry_bytes = sizeof(duct_dgram_tx_entry_t);
    if (!o->pools)
        entry_bytes += need;
    else {
        if (!duct_x_slot_fits(o->pools, need)) {
            *rc = vmq_push_too_large;
            return false;
        }
        o->ref = duct_x_slot_take(o->pools, need);
        if (o->ref == treiber_empty) {
            duct_atomic_store(&o->ln.ctrl->wait_latch, 1, relaxed);
            atomic_thread_fence(memory_order_seq_cst);
            o->ref = duct_x_slot_take(o->pools, need);
            if (o->ref == treiber_empty) {
                *rc = vmq_push_full;
                return false;
            }
            duct_atomic_store(&o->ln.ctrl->wait_latch, 0, relaxed);
        }
        o->span = duct_x_slot_span(o->pools, o->ref);
    }
    o->entry = s_dgram_tx_lane_reserve(&o->ln, entry_bytes, &o->pos, rc);
    if (!o->entry) {
        if (o->pools)
            duct_x_slot_put(o->pools, o->ref);
        return false;
    }
    o->entry->peer = *peer;
    o->entry->slot = o->ref;
    if (!o->pools)
        o->span = (duct_view_u8){ .data = o->entry->data, .size = need };
    return true;
}

/** @brief Give back the slot of a staged send that is not published. */
static void s_dgram_out_abort(const dgram_out_t *o)
{
    if (o->pools)
        duct_x_slot_put(o->pools, o->ref);
}

/** @brief Publish the staged send as @p len payload bytes.
 *  An entry that carries its bytes shrinks to them; a slot's entry stays one record.
 */
static void s_dgram_out_publish(dgram_out_t *o, size_t len)
{
    o->entry->len = (uint32_t)len;
    duct_vmq_publish_shrink(&o->ln, &o->pos, sizeof(duct_dgram_tx_entry_t) + (o->pools ? 0u : len));
}

/** @brief Test whether this worker's lane and the TX pools of @p listener take a send of @p need payload bytes now. */
static bool s_dgram_out_fits(duct_listener_t *listener, size_t need)
{
    auto ln = duct_mpsc_lane(duct_io_dgram_shared_outbox(listener), s_this_worker->worker_id);
    auto pools = duct_io_dgram_shared_tx_slots(listener);
    size_t entry_bytes = sizeof(duct_dgram_tx_entry_t) + (pools ? 0u : need);
    return duct_vmq_room(&ln) >= vmq_msg_aligned(entry_bytes) && (!pools || duct_x_slot_has(pools, need));
}

static void s_ctl_apply_now(duct_session_t *s, const duct_response_t *out);
static void s_ctl_apply_after(duct_session_t *s, const duct_response_t *out);
static void s_ctl_send_fin(duct_session_t *s, duct_conn_id_t target,
                                     duct_stream_id_t stream_id, duct_frame_flags_t flg,
                                     duct_stream_error_t err);
static duct_olb_tx_result_t s_ctl_fin_stage(duct_conn_t *conn, duct_session_t *s,
                                            duct_stream_id_t stream_id,
                                            duct_frame_flags_t flg,
                                            duct_stream_error_t err, uint32_t *ticket);

static bool s_retry_frame_save(duct_worker_t *w, duct_session_t *s, duct_conn_id_t conn_id,
                               duct_stream_id_t stream_id, duct_frame_flags_t frame_flags,
                               duct_response_t *out, uint32_t ticket);
static duct_wire_codec_t *s_tls_codec(duct_conn_t *conn);
/** @brief Outcome of the copy a parked response takes of its payload. */
typedef enum : uint8_t {
    own_kept,   /**< Owned or static already and not pooled, left as it is. */
    own_copied, /**< Copied into a buffer the response owns. */
    own_failed, /**< The copy found no memory, the payload staying where it was. */
} own_t;
static own_t s_retry_payload_own(duct_response_t *out);
static bool s_retry_emit_save(duct_worker_t *w, duct_stream_ctx_t *hctx, uint32_t ticket);
static void s_retry_emit_discard(duct_worker_t *w, duct_stream_ctx_t *target);

static void s_timer_invoke(duct_session_t *s, const duct_proto_cfg_t *cfg, uint64_t token);
static duct_exec_rc_t s_timer_fire(void *arg);
static void s_ctrl_msg_abandon(duct_msg_t *msg);

static void s_hctx_async_done(duct_async_t *co, duct_async_rc_t rc, void *ctx);
static void s_hctx_sf_resume(duct_coro_t *co, void *ctx);
static void s_tx_train_flush(duct_worker_t *w);
static void s_tx_train_flush_for(duct_conn_handle_t conn);
static void s_worker_dgram_flush(void);

/** @brief s_rx_ack's @c end_off sentinel: nothing to advance
 *  dispatch_frontier to. Defensive re-entry only — see s_hctx_rx_ack.
 */
static constexpr uint32_t s_dispatch_frontier_skip = UINT32_MAX;

/** @brief The frame batch in flight on this worker.
 *  @c conn is its leg while the batch dispatches; @c owed records that an ack
 *  of that leg left its read-latch check to the batch end.
 */
static thread_local struct {
    const duct_conn_t *conn;
    bool               owed;
} s_rx_ack_batch;

/** @brief Repost @p conn's read when @p acked reaches its latched resume
 *  target.
 *  The @c seq_cst fence pairs with @ref s_rx_latch's: either this sees the
 *  latch, or the io thread's recheck after latching sees @p acked. A stalled
 *  reactive backend never re-signals backlog already signaled, so this repost
 *  is what resumes the read.
 */
static void s_rx_ack_check(duct_conn_t *conn, uint64_t acked)
{
    atomic_thread_fence(memory_order_seq_cst);
    if (duct_has(duct_conn_state(conn), fl_conn_rx_full)
        && acked >= duct_atomic_load(&conn->rx_buf->resume_at, relaxed)) {
        duct_conn_state_clear(conn, fl_conn_rx_full);
        auto ch = duct_conn_handle_get(conn);
        duct_io_post_rx_read(&ch);
        duct_rtstat_obj_inc(s_this_worker, rtstats.rx_resume_post, 1);
    }
}

/** @brief Ack @p len ring bytes of @p conn and advance its dispatch_frontier to @p end_off.
 *  @p end_off is the ring offset past the acked frame's last byte,
 *  @c s_dispatch_frontier_skip when nothing advances; the frontier moves in
 *  the same call as its ack. The read-latch check runs right away, except
 *  for the leg a batch is dispatching: @ref s_dispatch_batch_frames runs it
 *  once at the batch end, so a batch pays one fence.
 */
static inline void s_rx_ack(duct_conn_t *conn, size_t len, uint32_t end_off)
{
    uint64_t acked = duct_olb_rx_ack(conn->rx_buf, len);
    if (end_off != s_dispatch_frontier_skip)
        duct_atomic_store(&conn->rx_buf->dispatch_frontier, end_off, release);
    if (s_rx_ack_batch.conn == conn)
        s_rx_ack_batch.owed = true;
    else
        s_rx_ack_check(conn, acked);
}

/** @brief Sealed-codec cleartext-buffer compaction.
 *
 *  Moves the unparsed tail @c [ct_parse_off, ct_len) to base, once nothing
 *  can still reference the consumed prefix. Safe only while the codec is the
 *  buffer's one holder and @c ct_ack_off == ct_parse_off, every parsed frame
 *  fully acked — short of that, a pinned frame's payload still points
 *  somewhere in @c [ct_ack_off, ct_parse_off) and a memmove dangles it.
 */
static void s_codec_compact(duct_wire_codec_t *codec)
{
    /* One holder reads 0 until the buffer is first shared and 1 once its pins have
     * dropped back; a pin beside the codec makes it 2 and up. */
    if (duct_atomic_load(&duct_block_hdr(codec->ct_buf)->holders, relaxed) > 1u
        || codec->ct_ack_off != codec->ct_parse_off)
        return;
    size_t tail = codec->ct_len - codec->ct_parse_off;
    auto ct = duct_at(codec->ct_buf);
    if (tail)
        memmove(ct, ct + codec->ct_parse_off, tail);
    codec->ct_len = (uint32_t)tail;
    codec->ct_parse_off = 0u;
    codec->ct_ack_off = 0u;
}

/** @brief The codec of @p conn, if it is still the one that owns cleartext buffer @p block.
 *  A conn rebound or lost since a pin was taken answers nullptr: the pin's ack and
 *  compaction have no codec left to reach. */
static duct_wire_codec_t *s_ct_codec_of(duct_conn_t *conn, const void *block)
{
    auto sc = conn ? duct_conn_sealed_ctx(conn) : nullptr;
    return sc && sc->codec && duct_at(sc->codec->ct_buf) == block ? sc->codec : nullptr;
}

/** @brief Drop one pin on cleartext buffer @p block, compacting the buffer where
 *  @p conn's codec still owns it.
 *  The last holder frees the block, which can be this pin once the codec is gone. */
static void s_ct_pin_release(duct_conn_t *conn, void *block)
{
    auto codec = s_ct_codec_of(conn, block);
    duct_del(block);
    if (codec)
        s_codec_compact(codec);
}

/** @brief One frame's ack, ring or sealed.
 *
 *  Acks ring bytes via @ref s_rx_ack, or a sealed record's cleartext span
 *  via @c ct_ack_off of @p conn's codec, which counts only while that codec
 *  still owns the span's buffer, opportunistically compacting @c ct_buf now
 *  that this ack may have just made it possible. Replaces every direct @c
 *  s_rx_ack(conn, task->len, ...) call in @ref s_dispatch_one_frame and
 *  the deferred-handler completion path.
 */
static void s_frame_ack_apply(duct_conn_t *conn, duct_frame_ack_t ack)
{
    switch (ack.kind) {
    case ack_ring:
        s_rx_ack(conn, ack.ring.task_len, ack.ring.end_off);
        break;
    case ack_ct:
        auto codec = s_ct_codec_of(conn, ack.ct.data);
        if (codec) {
            codec->ct_ack_off += (uint32_t)ack.ct.size;
            s_codec_compact(codec);
        }
        break;
    case ack_owned:
        duct_del(ack.owned.ptr);
        break;
    case ack_slot:
        duct_io_rx_slot_drop(ack.slot.pool, ack.slot.idx, true);
        break;
    default:
        duct_unreachable();
    }
}

static_assert(duct_session_max_streams + 3u <= UINT8_MAX,
              "a codec's buffer holds one pin per parked stream handler and per answer it parks");

/** @brief Held-frame source pin against compaction.
 *
 *  Pins @c rx->held_frames (RX ring, cross-thread with the io thread's own
 *  compaction check, so atomic) or the codec's cleartext buffer, one more
 *  holder of its block, while a multiplexed handler owns the frame.
 *  @ref s_hctx_hold_release is the release of both.
 */
static void s_frame_hold_pin(duct_conn_t *conn, duct_frame_ack_t ack)
{
    switch (ack.kind) {
    case ack_ring:
        duct_discard duct_atomic_fetch(add, &conn->rx_buf->held_frames, 1u, release);
        break;
    case ack_ct:
        duct_discard duct_share(ack.ct.data);
        break;
    case ack_owned:
    case ack_slot:
        break;
    default:
        duct_unreachable();
    }
}

/** @brief Conditional on_error fire, control-only.
 *  Fires @c cfg->on_error if set, applies its control-only out on rc_ok;
 *  out->payload/flags/release/send_token are not read — see duct_error_fn.
 */
static void s_fire_error(duct_session_t *s,
                                const duct_proto_cfg_t *cfg, duct_result_t err)
{
    if (!cfg->on_error)
        return;
    duct_response_t out;
    duct_response_reset(&out);
    if (cfg->on_error(s, err, &out, s->proto_state) == rc_ok)
        s_response_take_control(s, &out);
}

static void s_fire_send_done(duct_session_t *s,
                                    const duct_proto_cfg_t *cfg,
                                    duct_conn_id_t cid, duct_stream_id_t sid,
                                    const duct_response_t *out,
                                    duct_result_t result)
{
    if (!duct_has(out->flags, fl_send_done) || !cfg->on_send_done)
        return;
    duct_send_done_info_t info = {
        .conn_id = cid, .stream_id = sid,
        .send_token = out->send_token, .result = result,
    };
    duct_response_t done_out;
    duct_response_reset(&done_out);
    if (cfg->on_send_done(s, &info, &done_out, s->proto_state) == rc_ok)
        s_response_take_control(s, &done_out);
}

/** @brief Stage @p frame onto @p stage through @p wire @c on_pack.
 *
 *  A null @p wire stages the payload by itself, which carries a leg with no
 *  wire at all. @p codec is the caller's to resolve, this function
 *  holding no @c conn to read one from: null for a plain wire, and for a
 *  sealed wire whose codec does not exist yet, before its first RX task.
 */
static duct_olb_tx_result_t
s_wire_pack_into(const duct_wire_t *wire, duct_session_t *s,
                const duct_frame_t *frame, duct_wire_tx_t *stage,
                duct_wire_codec_t *codec)
{
    if (!wire) {
        auto rc = duct_wire_tx_stage(stage, (duct_view_u8){}, frame->payload);
        return rc == rc_ok ? olb_tx_ok : rc == rc_invalid_arg ? olb_tx_too_large : olb_tx_full;
    }
    assert(wire->on_pack);
    auto wrc = wire->on_pack(wire, s, frame, stage, codec);
    return wrc == rc_ok ? olb_tx_ok : wrc == rc_invalid_arg ? olb_tx_too_large : olb_tx_full;
}

/** @brief Record-header bytes @p conn TX ring carries per packet.
 *
 *  Nonzero on a record-framed conn, whose ring holds several packets at once
 *  and needs each boundary written down for @ref duct_io_tx_peek. The engine's
 *  handshake egress and the TX reservation taken ahead of an unseal size
 *  themselves from here; @ref s_tx_stage_frame writes the same header off the
 *  same predicate, so a transport reaching one path and not the other stages a
 *  boundary the drain never finds.
 */
static size_t s_tx_rec_size(const duct_conn_t *conn)
{
    return duct_conn_record_framed(conn) ? duct_dgram_record_hdr_size : 0u;
}

/** @brief Bytes @p conn's wire packs @p payload_size into, its header
 *  included.
 *  @return false when the size overflows or the wire @c tx_bound
 *  refuses it; @p out_need carries an answer only on true.
 */
static bool s_tx_wire_need(const duct_conn_t *conn, size_t payload_size, size_t *out_need)
{
    if (conn->wire && conn->wire->tx_bound) {
        *out_need = conn->wire->tx_bound(conn->wire, payload_size);
        return *out_need != SIZE_MAX;
    }
    *out_need = 0u;
    return !duct_ckd_add(out_need, payload_size,
                         conn->wire ? conn->wire->header_size : 0u);
}

/** @brief Bytes @p conn TX ring needs to hold a @p payload_size frame,
 *  the record header on a framed leg included.
 *  @return false on the same terms as @ref s_tx_wire_need.
 */
static bool s_tx_frame_need(const duct_conn_t *conn, size_t payload_size, size_t *out_need)
{
    return s_tx_wire_need(conn, payload_size, out_need)
        && !duct_ckd_add(out_need, *out_need, s_tx_rec_size(conn));
}

/** @brief Transactional frame stage onto @p conn's TX OLB.
 *
 *  On a record-framed conn, wraps the frame in the datagram record header:
 *  placeholder reclen → wire pack → backfill with the measured length. On any
 *  other transport, stages the wire-packed, or raw wireless, bytes directly.
 *  All-or-nothing: on failure (@c olb_tx_full or @c olb_tx_too_large), the
 *  TX cursor is preserved and placeholders are rewound via
 *  @ref duct_olb_tx_unmark. Callers publish after @c olb_tx_ok.
 */
static duct_olb_tx_result_t
s_tx_stage_frame(duct_conn_t *conn, duct_session_t *s, const duct_frame_t *frame)
{
    bool dgram_framed = duct_conn_record_framed(conn);
    size_t need = 0u;
    if (!s_tx_frame_need(conn, frame->payload.size, &need))
        return olb_tx_too_large;
    /* align answers for the whole frame, opening the next pass when this one
     * is out of room, so the placeholder and every span on_pack stages below
     * land in one pass and the unmark rewinds within it. */
    if (!duct_olb_tx_align(conn->tx_buf, need))
        return olb_tx_full;

    /* conn->wire->unseal gates the sealed-only s_tls_codec call: guards a
     * client-first protocol reaching TX before session bind or a wire-fence
     * finish runs. wire->unseal is already resident (read for tx_bound/
     * on_pack above/below), so a plain wire never touches ctx's cold cache
     * line to rule this out. */
    auto codec = conn->wire && conn->wire->unseal ? s_tls_codec(conn) : nullptr;
    auto mark = duct_olb_tx_mark(conn->tx_buf);
    auto rec_mark = mark;
    duct_olb_tx_result_t st = olb_tx_ok;
    if (dgram_framed) {
        uint8_t placeholder[duct_dgram_record_hdr_size] = {};
        st = duct_olb_tx_stage(conn->tx_buf, placeholder, sizeof(placeholder), nullptr, 0u);
        if (st == olb_tx_ok)
            rec_mark = duct_olb_tx_mark(conn->tx_buf);
    }
    if (st == olb_tx_ok) {
        auto stage = (duct_wire_tx_t){ .kind = wire_tx_olb, .olb = conn->tx_buf };
        st = s_wire_pack_into(conn->wire, s, frame, &stage, codec);
        if (st != olb_tx_ok)
            /* Rewinds the header placeholder above too, on dgram_framed --
             * a partial stage (e.g. just the wire header) must never leak
             * the cursor forward: stage left past tail holds
             * duct_olb_tx_wrap_room at zero, and no new pass opens for this
             * conn again. */
            duct_olb_tx_unmark(conn->tx_buf, mark);
        else if (dgram_framed) {
            /* A vnet leg's GSO record carries its flag in the prefix, where
             * duct_io_tx_send reads it back to build the record's header. */
            uint8_t rec[duct_dgram_record_hdr_size];
            bool gso = conn->vnet_hdr_len && duct_has(frame->flags, fl_frame_gso);
            duct_dgram_rec_hdr_encode(rec, duct_olb_tx_staged_since(conn->tx_buf, rec_mark)
                                           | (gso ? duct_dgram_rec_gso : 0u));
            duct_olb_tx_backfill(conn->tx_buf, rec_mark, rec, sizeof(rec));
        }
    }
    return st;
}

static void s_wake(unsigned worker_id)
{
    if (worker_id >= s_wmod.n_workers)
        return;
    auto w = &s_wmod.workers[worker_id];
    if (duct_atomic_exchange(&w->wake_latch, 1u, release) == 0u)
        duct_futex_wake((void *)&w->wake_latch, 1);
}

void duct_worker_wake_id(unsigned worker_id)
{
    if (worker_id >= s_wmod.n_workers)
        return;
    duct_atomic_fetch(add, &s_wmod.workers[worker_id].retry_epoch, 1u, release);
    s_wake(worker_id);
}

duct_vmq_mpsc_t *duct_worker_egress_lane(unsigned worker_id)
{
    return worker_id < s_wmod.n_workers ? s_wmod.workers[worker_id].host_egress
                                        : nullptr;
}

unsigned duct_worker_egress_self(void)
{
    auto w = s_this_worker;
    return w && w->host_egress ? w->worker_id : conn_worker_none;
}

unsigned duct_worker_self(void)
{
    auto w = s_this_worker;
    return w ? w->worker_id : conn_worker_none;
}

void duct_worker_egress_abandon(unsigned worker_id)
{
    duct_do_if(worker_id >= s_wmod.n_workers, return);
    s_wmod.workers[worker_id].host_egress = nullptr;
}

uint32_t _Atomic *duct_worker_wake_latch(unsigned worker_id)
{
    if (worker_id >= s_wmod.n_workers)
        return nullptr;
    return &s_wmod.workers[worker_id].wake_latch;
}

void duct_worker_inter_arm(unsigned worker_id, unsigned conn_idx)
{
    if (worker_id >= s_wmod.n_workers)
        return;
    auto w = &s_wmod.workers[worker_id];
    /* set_if_new, not a bare duct_bits_set: a redundant arm on an
     * already-set bit must not double-count inter_pending, or the counter
     * drifts upward forever and s_inter_drain's zero-skip never fires
     * again once it happens once (grab clears the bit exactly once
     * regardless of how many times it was armed). */
    if (duct_bits_set_if_new(w->inter_armed, conn_idx))
        duct_atomic_fetch(add, &w->inter_pending, 1u, relaxed);
}

/** @brief Per-response payload cap; 0 indicates no explicit cap (coarse
 *  backpressure check applies). Raw (wire-less) protocols cannot reach 0
 *  here — @c duct_proto_create rejects that combo.
 *  The wire's @c max_frame is a parse-time legality bound and no fallback
 *  here: it can exceed the TX OLB capacity, the length-prefix wire's 1 MiB
 *  default among such values, which makes admission block forever.
 */
static inline size_t s_admit_eff_max(const duct_proto_cfg_t *cfg)
{
    return cfg->max_response;
}

/** @brief True if the target TX OLB has room for @p need.
 *
 *  @p need 0 (no explicit cap) falls back to the OLB's coarse backpressure
 *  signal. A null or closing conn is not a backpressure signal; real closure
 *  is reported by the commit path as @c commit_closed.
 */
static inline bool s_admit_leg_room(const duct_conn_t *conn, size_t need)
{
    duct_do_if(!conn, return true);
    auto tx = duct_conn_tx_olb(conn);
    if (!tx)
        return true;
    return need != 0u ? duct_olb_tx_room_contig(tx, need)
                      : !duct_olb_tx_backpressure(tx);
}

/** @brief Arm @p conn's TX-room wake ahead of the caller's last room check.
 *  The fence pairs with the one io runs after freeing room: either that check
 *  sees the room, or io sees @c fl_conn_tx_wait and wakes this worker. An arm
 *  placed after a failed check lets io free the room unseen.
 */
static void s_tx_wait_arm(duct_conn_t *conn)
{
    duct_conn_state_set(conn, fl_conn_tx_wait);
    atomic_thread_fence(memory_order_seq_cst);
}

/** @brief Test @p conn's TX room for @p need, and on a refusal flush this
 *  worker's train and test again. */
static bool s_admit_leg_room_flushed(duct_conn_handle_t handle, const duct_conn_t *conn,
                                     size_t need)
{
    if (s_admit_leg_room(conn, need))
        return true;
    /* Frames on this worker's train hold room without being published, so no
     * io drain frees it and no tx_advance wake follows; the flush does. */
    s_tx_train_flush_for(handle);
    return s_admit_leg_room(conn, need);
}

bool duct_worker_admit_leg(duct_conn_handle_t handle, size_t need)
{
    auto conn = duct_conn_by_handle(handle);
    if (s_admit_leg_room_flushed(handle, conn, need))
        return true;
    s_tx_wait_arm(conn);
    return s_admit_leg_room(conn, need);
}

/** @brief External ctrl_stack harvest into the local FIFO. */
static duct_nonnull(1) void s_drain_harvest_ext(duct_worker_t *w)
{
    auto chain = duct_msg_stack_detach(&w->ctrl_stack);
    if (!chain)
        return;
    auto fifo = duct_msg_reverse(chain);
    if (w->ext_pending.head)
        duct_msg_next(w->ext_pending.tail) = fifo;
    else
        w->ext_pending.head = fifo;
    w->ext_pending.tail = chain;
}

/** @brief Bounded quota execution from the ext-pending FIFO; deferral stops the pass. */
static duct_nonnull(1) size_t s_drain_ext(duct_worker_t *w)
{
    if (!w->ext_pending.head)
        return 0u;
    auto cur = w->ext_pending.head;
    auto saved_tail = w->ext_pending.tail;
    size_t count = 0u;
    w->ext_pending.head = nullptr;
    w->ext_pending.tail = nullptr;
    while (cur && count < worker_ext_drain_quota) {
        auto next = duct_msg_next(cur);
        auto rc = exec_done;
        duct_msg_next(cur) = nullptr;
        if (cur->exec_fn)
            rc = cur->exec_fn(cur);
        switch (rc) {
        case exec_done:
            break;
        case exec_defer:
            duct_msg_next(cur) = next;
            w->ext_pending.head = cur;
            w->ext_pending.tail = saved_tail;
            return count;
        case exec_drop:
            duct_del(cur);
            break;
        }
        cur = next;
        ++count;
    }
    if (cur) {
        w->ext_pending.head = cur;
        w->ext_pending.tail = saved_tail;
    }
    return count;
}

static duct_nonnull(1, 2) size_t s_drain_lane(const duct_vmq_lane_t *ln,
                                              duct_worker_t *w,
                                              size_t max_frames,
                                              size_t max_bytes)
{
    duct_vmq_drain_pos_t pos = duct_vmq_drain_begin(ln);
    size_t slots = 0u,          /* VMQ slots consumed; gates commit_head */
           frames_used = 0u,    /* frames charged against quota */
           bytes_used = 0u;     /* wire bytes charged against quota */
    for (duct_vmq_hdr_t *hdr = nullptr;
         frames_used < max_frames && bytes_used < max_bytes
         && (hdr = duct_vmq_drain_peek(ln, &pos)) != nullptr; ) {
        duct_exec_rc_t rc;
        size_t quota,
               charge_bytes = 0u;
        uint32_t batch_defer_idx = 0u;
        if (hdr->type == msg_frame_batch) {
            rc = s_dispatch_batch(hdr, w, &batch_defer_idx);
            auto b = (const duct_msg_frame_batch_t *)&hdr->payload[0];
            /* On partial defer, only acked frames [0..i) count against quota,
             * a pad charging neither frames nor bytes; deferred frames [i..n)
             * are replayed via the defer queue. A defer at index zero charges
             * one frame unit to ensure loop progress. */
            uint32_t done_n = rc == exec_defer ? batch_defer_idx : b->n,
                     frames_n = 0u;
            for (uint32_t k = 0u; k < done_n; ++k)
                if (!(b->frames[k].flags & duct_frame_pad)) {
                    charge_bytes += b->frames[k].len;
                    ++frames_n;
                }
            quota = rc == exec_defer && batch_defer_idx == 0u ? 1u : frames_n;
        } else {
            rc = s_dispatch_msg(hdr);
            quota = 1u;
        }
        pos.head += pos.step;
        ++slots;
        frames_used += quota;
        bytes_used += charge_bytes;
        duct_rtstat_obj_inc(w, rtstats.wfq_drain, quota);
        if (rc != exec_defer)
            continue;
        /* Only msg_frame_batch's own dispatch ever returns exec_defer —
         * msg_callback always runs to completion. Batch defer
         * (partial or full): one heap node, cursor = batch_defer_idx. */
        assert(hdr->type == msg_frame_batch);
        if (batch_defer_idx > 0u)
            duct_rtstat_obj_inc(w, rtstats.batch_partial_defer, 1);
        if (!s_defer_batch_from_vmq(&w->defer_q, hdr, batch_defer_idx)) {
            /* Defer node OOM is terminal for the undeferred suffix:
             * drops the suffix and notifies the protocol via on_error with
             * rc_no_memory. */
            auto b = (const duct_msg_frame_batch_t *)&hdr->payload[0];
            auto c = duct_conn_by_handle((duct_conn_handle_t){ .word = b->conn });
            if (c && duct_conn_rx_olb(c))
                for (uint32_t j = batch_defer_idx; j < b->n; ++j)
                    s_rx_ack(c, b->frames[j].len, b->frames[j].offset + b->frames[j].len);
            duct_rtstat_obj_inc(w, rtstats.defer_oom_drop, b->n - batch_defer_idx);
            auto s = c ? duct_session_by_conn(c) : nullptr;
            if (s && s->proto)
                s_fire_error(s, duct_proto_cfg_of(s->proto), rc_no_memory);
        }
    }
    if (slots != 0u)
        duct_vmq_commit_head(ln, pos.gen, pos.head);
    return slots;
}

/** @brief WFQ-lane range drain, [from, to), per-lane frame + byte quota. */
static duct_nonnull(4) size_t s_drain_range(duct_vmq_mpsc_t *wfq,
                                                    unsigned from, unsigned to,
                                                    duct_worker_t *w,
                                                    size_t max_per_lane,
                                                    size_t byte_quota)
{
    size_t total = 0u;
    for (unsigned i = from; i < to; ++i) {
        auto ln = duct_mpsc_lane(wfq, i);
        total += s_drain_lane(&ln, w, max_per_lane, byte_quota);
    }
    return total;
}

void duct_worker_wfq_wait_arm(unsigned worker_id, unsigned io_id)
{
    if (worker_id >= s_wmod.n_workers || io_id >= duct_wfq_io_waiters_max)
        return;
    duct_atomic_fetch(or, &s_wmod.workers[worker_id].wfq_io_waiters,
                      1ull << io_id, release);
    /* Also wakes worker_id through the same wake_latch/futex pair its
     * sleep path checks: setting wfq_io_waiters alone does not unblock a
     * worker already past its pre-sleep drain and about to call
     * duct_futex_wait, and nothing else re-arms that wait later — the
     * retry stalls forever. */
    s_wake(worker_id);
}

void duct_worker_wfq_wait_clear(unsigned worker_id, unsigned io_id)
{
    if (worker_id >= s_wmod.n_workers || io_id >= duct_wfq_io_waiters_max)
        return;
    duct_atomic_fetch(and, &s_wmod.workers[worker_id].wfq_io_waiters,
                      ~(1ull << io_id), relaxed);
}

/** @brief Armed-waiter kick, every bit, once.
 *  Called after the normal lane is drained, where frame batches are
 *  published.
 */
static void s_drain_kick_io_waiters(duct_worker_t *w)
{
    uint64_t bits = duct_atomic_exchange(&w->wfq_io_waiters, 0u, acq_rel);
    while (bits) {
        unsigned io_id = duct_ctz_ull(bits);
        bits &= bits - 1u;
        duct_io_wake(io_id);
    }
}

/** @brief Drain one fair pass across ext, HI, NORM, and LO lane ranges.
 *
 *  @ref duct_wfq_pri_lane maps each (priority, worker_id, io_id) to exactly
 *  one lane; @p hi_lane / @p norm_lane / @p lo_lane are the base (io_id 0) of
 *  @p w three @c n_io-wide ranges — one lane per producer I/O thread keeps
 *  every ring single-producer/single-consumer. A base index @c >= wfq->n_lanes
 *  is treated as an empty range without indexing past @c lane_off[].
 */
static duct_nonnull(1) size_t s_drain_pass(duct_worker_t *w,
                                                   unsigned hi_lane,
                                                   unsigned norm_lane,
                                                   unsigned lo_lane)
{
    auto wfq = w->wfq;
    size_t drained = 0u;
    drained += s_drain_ext(w);
    /* Frame batches are published only to the NORM lane; HI and LO never
     * carry wire bytes, so their byte quota stays unbounded. */
    if (hi_lane < wfq->n_lanes)
        drained += s_drain_range(wfq, hi_lane, hi_lane + w->n_io, w,
                                        duct_wfq_quota_fast, wfq_quota_none);
    if (norm_lane < wfq->n_lanes)
        drained += s_drain_range(wfq, norm_lane, norm_lane + w->n_io, w,
                                        duct_wfq_quota_norm, duct_wfq_byte_quota_norm);
    s_drain_kick_io_waiters(w);
    if (lo_lane < wfq->n_lanes)
        drained += s_drain_range(wfq, lo_lane, lo_lane + w->n_io, w,
                                        duct_wfq_quota_bg, wfq_quota_none);
    return drained;
}

/** @brief Deferred batch node: inline batch copy + cursor. One heap alloc
 *  per deferred batch lifetime — cursor moves, node stays in FIFO.
 */
duct_msg_chain_decl(batch_defer_node_t,
    uint32_t from;  /**< Cursor: first unprocessed frame index. */
    alignas(alignof(duct_conn_handle_t)) duct_msg_frame_batch_t batch;
);

/** @brief Size of a defer node for a batch of @p n frames. */
static inline size_t s_defer_node_size(unsigned n)
{
    return sizeof(batch_defer_node_t) + (size_t)n * sizeof(duct_msg_frame_t);
}

static void s_defer_clear(duct_deferred_queue_t *q)
{
    for (auto m = q->q.head; m; ) {
        auto next = duct_msg_next(m);
        auto node = DUCT_CAST(batch_defer_node_t, msg, m);
        duct_del(node);
        m = next;
    }
    q->q.head = nullptr;
    q->q.tail = nullptr;
    for (unsigned i = 0u; i < DUCT_BITMAP_WORDS; ++i)
        duct_atomic_store(&q->mask[i], 0u, relaxed);
}

static inline bool
s_defer_mask_test(const uint64_t _Atomic *mask, duct_conn_handle_t h)
{
    return h.gen != 0u && duct_bits_test(mask, (unsigned)h.idx);
}

static inline void
s_defer_mask_set(uint64_t _Atomic *mask, duct_conn_handle_t h)
{
    if (h.gen != 0u)
        duct_bits_set(mask, (unsigned)h.idx);
}

/** @brief Ready-node enqueue into the defer FIFO; mask bit from @c batch.conn. */
static void
s_defer_node_push(duct_deferred_queue_t *q, batch_defer_node_t *node)
{
    duct_msg_queue_push(&q->q, &node->msg);
    auto h = (duct_conn_handle_t){ .word = node->batch.conn };
    if (h.gen != 0u && duct_conn_by_handle(h))
        duct_bits_set(q->mask, (unsigned)h.idx);
}

/** @brief Defer-node allocation from a VMQ batch, payload copied, cursor set.
 *  @retval true   Success.
 *  @retval false  Allocation failed.
 */
static bool
s_defer_batch_from_vmq(duct_deferred_queue_t *q,
                       const duct_vmq_hdr_t *hdr,
                       uint32_t from)
{
    auto batch = (const duct_msg_frame_batch_t *)&hdr->payload[0];
    size_t node_sz = s_defer_node_size(batch->n);
    auto node = (batch_defer_node_t *)duct_at(duct_new(uint8_t, node_sz, alignof(batch_defer_node_t)));
    if (!node)
        return false;
    node->from = from;
    memcpy(&node->batch, hdr->payload,
           sizeof(duct_msg_frame_batch_t) + (size_t)batch->n * sizeof(duct_msg_frame_t));
    s_defer_node_push(q, node);
    return true;
}

/** @brief Deferred-batch replay from node->from.
 *  Returns exec_done when all frames processed, exec_defer if re-deferred
 *  (node->from updated).
 */
static duct_exec_rc_t s_defer_replay_node(batch_defer_node_t *node)
{
    auto w = s_this_worker;
    assert(w);
    auto b = &node->batch;
    auto conn = duct_conn_by_handle((duct_conn_handle_t){ .word = b->conn });
    if (!conn)
        return exec_done;
    return s_dispatch_batch_frames(w, b, node->from, &node->from);
}

/** @brief One defer-FIFO retry pass; re-deferral keeps the same node.
 *
 *  Only batch_defer_node nodes live in the queue. s_defer_replay_node uses
 *  node->from as cursor; on re-defer the cursor advances, the node stays.
 */
static duct_nonnull(1) bool s_defer_drain(duct_worker_t *w)
{
    auto q = &w->defer_q;
    if (!q->q.head)
        return false;
    duct_msg_t *kept = nullptr,
               *kept_tail = nullptr;
    bool progress = false;
    uint64_t _Atomic mask[DUCT_BITMAP_WORDS] = {};
    for (auto m = q->q.head; m; ) {
        auto next = duct_msg_next(m);
        auto node = DUCT_CAST(batch_defer_node_t, msg, m);
        auto h = (duct_conn_handle_t){ .word = node->batch.conn };
        if (s_defer_mask_test(mask, h)) {
            duct_msg_next(m) = nullptr;
            if (kept_tail)
                duct_msg_next(kept_tail) = m;
            else
                kept = m;
            kept_tail = m;
        } else {
            auto rc = s_defer_replay_node(node);
            if (rc == exec_defer) {
                s_defer_mask_set(mask, h);
                duct_msg_next(m) = nullptr;
                if (kept_tail)
                    duct_msg_next(kept_tail) = m;
                else
                    kept = m;
                kept_tail = m;
            } else {
                progress = true;
                duct_del(node);
            }
        }
        m = next;
    }
    q->q.head = kept;
    q->q.tail = kept_tail;
    memcpy(q->mask, mask, sizeof(mask));
    return progress;
}

void duct_worker_conn_defer_discard(const duct_conn_handle_t *conn)
{
    auto w = s_this_worker;
    assert(w);
    auto ch = *conn;
    duct_do_if(ch.gen == 0u, return);
    auto q = &w->defer_q;
    auto c = duct_conn_by_handle(ch);
    duct_msg_t *kept = nullptr,
               *kept_tail = nullptr;
    for (auto m = q->q.head; m; ) {
        auto next = duct_msg_next(m);
        auto node = DUCT_CAST(batch_defer_node_t, msg, m);
        if (node->batch.conn == conn->word) {
            if (c && duct_conn_rx_olb(c))
                for (uint32_t k = node->from; k < node->batch.n; ++k) {
                    auto f = &node->batch.frames[k];
                    s_rx_ack(c, f->len, f->offset + f->len);
                }
            duct_del(node);
        } else {
            duct_msg_next(m) = nullptr;
            if (kept_tail)
                duct_msg_next(kept_tail) = m;
            else
                kept = m;
            kept_tail = m;
        }
        m = next;
    }
    q->q.head = kept;
    q->q.tail = kept_tail;
    duct_bits_clear(q->mask, (unsigned)ch.idx);
}

static duct_exec_rc_t s_dispatch_msg(duct_vmq_hdr_t *hdr)
{
    auto m = (duct_msg_t *)&hdr->payload[0];
    return m->exec_fn ? m->exec_fn(m) : exec_done;
}

/** @brief Resolve outcome for @c s_dispatch_resolve. */
typedef enum : uint8_t { res_ok, res_gone, res_no_proto, res_unbound, res_retired } resolve_rc_t;

/** @brief Shared handle → conn → session → proto resolution for frame/inter-pkt
 *  dispatch and frame retry. @c res_unbound is a live conn with no session yet
 *  and @c conn_fence == fence_unbound — its own ctrl (session_open/conn_join)
 *  is still queued behind the ext_pending backlog while this handle's WFQ
 *  traffic already drained, not a torn-down conn. @c res_retired is a live conn
 *  with no session at or past @c fence_retire_ready: its worker has confirmed
 *  no further access and io tears the rings down at any moment, so a caller
 *  reads and acks none of them. Centralizes resolution only, not policy:
 *  callers apply their own distinct outcome per state (defer/drop/ack), and
 *  anything beyond conn+session+proto — @c rx_buf, @c wire_rebind_next —
 *  stays a per-site check outside this helper.
 */
static resolve_rc_t
s_dispatch_resolve(duct_conn_handle_t h, duct_conn_t **out_conn, duct_session_t **out_s)
{
    auto conn = duct_conn_by_handle(h);
    auto s = conn ? duct_session_by_conn(conn) : nullptr;
    *out_conn = conn;
    *out_s = s;
    if (!conn)
        return res_gone;
    if (!s) {
        auto fence = duct_atomic_load(&conn->conn_fence, acquire);
        return fence == fence_unbound ? res_unbound
             : fence >= fence_retire_ready ? res_retired : res_gone;
    }
    return s->proto ? res_ok : res_no_proto;
}

static inline bool s_hctx_parked(const duct_stream_ctx_t *h);
static inline void s_hctx_wake(duct_coop_t *cp, duct_stream_ctx_t *h);

static size_t s_engine_park_cap(const duct_conn_t *conn, const duct_wire_codec_t *codec);
static bool s_engine_park_flush(duct_conn_t *conn);
static uint8_t *s_engine_park_span(duct_conn_t *conn, duct_wire_codec_t *codec, size_t len);

static duct_exec_rc_t s_dispatch_one_frame(duct_worker_t *w, duct_conn_t *conn,
    duct_session_t *s, duct_conn_id_t cid,
    duct_frame_t frame, duct_frame_ack_t ack);

static duct_exec_rc_t s_dispatch_sealed_frame(duct_worker_t *w, duct_conn_t *conn,
    duct_session_t *s, duct_conn_handle_t handle, const duct_msg_frame_t *task);

static duct_exec_rc_t s_dispatch_frame(duct_worker_t *w, duct_conn_handle_t handle,
                                        const duct_msg_frame_t *task)
{
    duct_conn_t *conn;
    duct_session_t *s;
    auto rr = s_dispatch_resolve(handle, &conn, &s);
    /* A frame queued or deferred ahead of the retire confirm reaches here after it: the ext queue
     * drains ahead of the lanes, and the defer queue replays in a pass of its own. io frees the rings
     * once it takes the retire request, so none is read or acked. */
    if (rr == res_retired)
        return exec_done;
    if (rr == res_gone) {
        /* A closing session is a sink until its outbound ring drains. Leaving
         * these bytes unacked can close both peers' windows permanently. */
        if (conn && duct_conn_rx_olb(conn)) {
            auto sc = duct_conn_sealed_ctx(conn);
            if (task->sealed_epoch && sc && sc->head_unsealed)
                sc->head_unsealed = false;
            else
                s_rx_ack(conn, task->len, task->offset + task->len);
        }
        return exec_done;
    }
    if (!duct_conn_rx_olb(conn))
        /* Checked ahead of res_unbound on purpose: rx_buf is set at accept,
         * before any ctrl post, so a live conn with a pending bind (the
         * res_unbound case below) should already have it — this only drops
         * (not defers) whatever state manages to reach here without one. */
        return exec_done;
    if (rr == res_unbound)
        /* Retry once the session bind completes. */
        return exec_defer;
    if (rr == res_no_proto) {
        /* Session torn down by another worker — ack and drop. */
        s_rx_ack(conn, task->len, task->offset + task->len);
        return exec_done;
    }
    if (s->wire_rebind_next)
        return exec_defer; /* wire-changing switch in flight; replayed once every leg's fence lands, no ack */
    if (task->flags & duct_frame_pad) {
        s_rx_ack(conn, task->len, task->offset + task->len);
        return exec_done;
    }
    if (task->flags & duct_frame_end) {
        /* A parse error records close_protocol_error before posting the end;
         * any other end is the peer's FIN. */
        auto reason = duct_gen_req_reason(duct_atomic_load(duct_conn_gen_req(conn), relaxed));
        duct_worker_conn_close(handle, reason == close_protocol_error ? reason : close_peer);
        return exec_done;
    }
    /* task->sealed_epoch, not conn->wire->unseal: a deferred task can
     * outlive its own conn's wire rebind (same reasoning as
     * task->header_size just below, duct_msg_frame_t's own doc) —
     * re-deriving sealed-ness from conn->wire on every replay reroutes a
     * stale task through whatever dispatch path the current wire implies.
     * Zero means "parsed under a plain wire";
     * s_dispatch_sealed_frame itself compares the nonzero generation
     * against the conn's current one to catch a stale replay. */
    if (task->sealed_epoch)
        return s_dispatch_sealed_frame(w, conn, s, handle, task);
    auto cid = duct_session_conn_id_by_handle(s, handle);
    /* A refused join detaches its leg and leaves the conn bound until the
     * close fence lands, so frames already posted for it resolve here with no
     * leg in the session: ack and drop. */
    if (cid == duct_session_max_legs) {
        s_rx_ack(conn, task->len, task->offset + task->len);
        return exec_done;
    }
    /* task->header_size, pinned at parse time — not conn->wire->header_size,
     * which may already be the *next* wire's for a frame replayed past its
     * own conn's rebind. */
    size_t hdr = task->header_size;
    duct_frame_t frame = {
        .stream_id = task->stream_id,
        .flags = task->flags,
        .payload = { .data = conn->rx_buf->data + task->offset + hdr,
                     .size = task->len - hdr },
    };
    return s_dispatch_one_frame(w, conn, s, cid, frame,
        (duct_frame_ack_t){ .kind = ack_ring, .ring = { task->len, task->offset + task->len } });
}

typedef enum duct_stream_claim_rc : uint8_t {
    claim_fallthrough, /**< stream_id == 0 or handler_kind == handler_none: caller runs on_frame. */
    claim_handled,      /**< Claimed, errored, or handed to a handler coroutine. */
    claim_busy,         /**< Existing handler_ctx not parked; caller decides defer vs drop. */
    claim_count,        /**< Not a valid outcome — array sizing, loop bounds. */
} duct_stream_claim_rc_t;

/** @brief Close @p sid on fl_frame_rst as close_peer, on a bare fl_frame_fin
 *  as close_normal. Flags carrying neither are a no-op. */
static void s_stream_close_on_flags(duct_session_t *s, duct_stream_id_t sid,
                                    duct_frame_flags_t flags)
{
    if (duct_has(flags, duct_or(fl_frame_fin, fl_frame_rst)))
        duct_session_stream_close(s, sid,
            duct_has(flags, fl_frame_rst) ? close_peer : close_normal);
}

/** @brief Stream claim, server-push, and handler-coroutine dispatch for one
 *  frame.
 *
 *  Shared by @c s_dispatch_frame_body and @c s_inter_pkt, which differ in what
 *  a failed claim or a busy stream should do — replay versus drop — so that
 *  decision, and the hold ahead of it, stay with each caller.
 *  @p ack is only read from, or handed off into the handler ctx; the caller
 *  still owns applying it on every returned path.
 */
static duct_stream_claim_rc_t s_dispatch_stream_claim(duct_worker_t *w, duct_conn_t *conn,
    duct_session_t *s, const duct_proto_cfg_t *cfg, duct_conn_id_t cid,
    duct_frame_t frame, duct_frame_ack_t ack)
{
    /* An RST names a stream to end, so it opens none: a refusal below answers
     * the peer's RST with an RST, and two ends doing that never stop. The term
     * is on rst alone — a fin arrives with the final data of a one-frame
     * exchange and has to open the stream it ends. The last term asks whether
     * the slot is taken; duct_stream_state answers slot->proto_state instead,
     * null on a claimed stream whenever the proto sets no create_stream_state,
     * and costs a second hash lookup per frame. */
    if (duct_has(cfg->flags, fl_proto_multiplexed) && frame.stream_id != 0u && s->streams
        && !duct_has(frame.flags, fl_frame_rst)
        && !duct_session_stream_slot(s, frame.stream_id)) {
        duct_response_t open_out = {};
        duct_stream_admit_t admit;
        /* The RST needs no wire-capability check: a non-zero stream_id reaches
         * here only from a wire that parses one, and every such wire carries
         * the flags too. rc_again, not rc_no_memory — nothing allocated and
         * failed, and the peer may retry this stream once a slot frees. */
        if (!duct_session_stream_claim(s, frame.stream_id, &open_out, &admit)) {
            if (admit == stream_admit_full) {
                s_ctl_send_fin(s, cid, frame.stream_id, fl_frame_rst, stream_err_refused);
                s_fire_error(s, cfg, rc_again);
            } else if (admit == stream_admit_rejected) {
                s_ctl_send_fin(s, cid, frame.stream_id, fl_frame_rst, stream_err_rejected);
                s_fire_error(s, cfg, rc_invalid_arg);
            } else {
                s_fire_error(s, cfg, rc_invalid_arg);
            }
            s_frame_ack_apply(conn, ack);
            return claim_handled;
        }
        if (cfg->on_stream_open)
            duct_discard s_response_put(s, &open_out, cid, frame.stream_id, fl_frame_none,
                                        nullptr, nullptr);
    }
    if (cfg->handler_kind == handler_none || frame.stream_id == 0u)
        return claim_fallthrough;
    auto cp = &w->coop;
    auto slot = duct_session_stream_slot(s, frame.stream_id);
    /* An abort ends both halves at once, so the handler is cancelled rather
     * than handed a frame whose reply nobody is left to read. A fin ends only
     * the peer's half and falls through: the handler runs on, and the stream
     * closes when it returns (@ref s_hctx_stream_done). */
    if (duct_has(frame.flags, fl_frame_rst)) {
        s_stream_close_on_flags(s, frame.stream_id, frame.flags);
        s_frame_ack_apply(conn, ack);
        return claim_handled;
    }
    /* Past its own end: the peer already said it was done. */
    if (slot && duct_has(slot->flags, fl_stream_peer_done)) {
        s_ctl_send_fin(s, cid, frame.stream_id, fl_frame_rst, stream_err_rejected);
        s_fire_error(s, cfg, rc_invalid_arg);
        s_frame_ack_apply(conn, ack);
        return claim_handled;
    }
    if (slot && slot->handler_ctx && !s_hctx_parked(slot->handler_ctx))
        return claim_busy;
    /* Recorded here, past the busy check and before either delivery branch:
     * a deferred frame has not reached the handler yet, and marking it early
     * leaves its own replay to meet the refusal above. */
    if (slot && duct_has(frame.flags, fl_frame_fin))
        slot->flags = duct_or(slot->flags, fl_stream_peer_done);
    if (slot && slot->handler_ctx) {
        auto hctx = slot->handler_ctx;
        /* dispatch_frontier does NOT advance here: the handler may hold
         * frame.payload well past this call (async_yield turns), so
         * advancing marks this offset reached before it is actually read.
         * the frame's pin already covers that window; s_hctx_rx_ack advances
         * dispatch_frontier once the handler is truly done. */
        hctx->frame = frame;
        hctx->conn_id = cid;
        hctx->ack = ack;
        s_frame_hold_pin(conn, ack);
        duct_response_reset(&hctx->out);
        s_hctx_wake(cp, hctx);
        return claim_handled;
    }
    /* First frame: create handler coro + ctx. RX not acked — handler owns it.
     * slot is non-NULL here: claim above succeeded (fl_proto_multiplexed +
     * handler_kind != none is validated by duct_proto_create, which also
     * guarantees s->streams is allocated). */
    assert(slot);
    /* dispatch_frontier does not advance here either — same reasoning as
     * the existing-hctx branch above; s_hctx_rx_ack advances it once the
     * handler is truly done with frame.payload. handler_oom below is the
     * one exit from this branch that never reads it, so it advances
     * frontier itself. */
    duct_auto_del auto hctx = duct_new(duct_stream_ctx_t);
    if (!hctx)
        goto handler_oom;
    *hctx = (duct_stream_ctx_t){
        .s = s, .stream_id = frame.stream_id, .conn_id = cid,
        .frame = frame, .ack = ack,
        .out = { .control.stream_op_conn_id = duct_conn_id_same },
        .stream_state = slot->proto_state,
    };
    s_frame_hold_pin(conn, ack);
    slot->handler_ctx = hctx;
    if (cfg->handler_kind == handler_async) {
        auto co = duct_async_acquire(&cp->async_pool, cfg->handler_async);
        if (!co) {
            slot->handler_ctx = nullptr;
            goto handler_oom;
        }
        co->state = hctx;
        co->on_done = s_hctx_async_done;
        co->on_done_ctx = hctx;
        co->in_wait = false;
        hctx->au = co;
        duct_async_queue_enqueue(&cp->async_queue, co, coop_run);
    } else if (cfg->handler_kind == handler_coro) {
        auto co = duct_coro_acquire(&cp->pool, cfg->handler_coro, hctx);
        if (!co) {
            slot->handler_ctx = nullptr;
            goto handler_oom;
        }
        co->on_resume = s_hctx_sf_resume;
        co->on_resume_ctx = hctx;
        hctx->co = co;
        duct_coro_queue_put(&cp->queue, co);
    } else {
        /* handler_kind == handler_none is rejected by duct_proto_create for
         * multiplexed protos with a stream_handler; reaching here means a
         * bypass. Roll back the ctx — no coro to cancel. */
        slot->handler_ctx = nullptr;
        goto handler_oom;
    }
    duct_discard duct_move(hctx);
    return claim_handled;

handler_oom:
    s_fire_error(s, cfg, rc_no_memory);
    duct_session_stream_close(s, frame.stream_id, close_internal_error);
    s_frame_ack_apply(conn, ack);
    return claim_handled;
}

/** @brief Stamp @p s's idle clock for a frame accepted on @p conn.
 *  Only a session with an idle timer pending takes a stamp, and only from a
 *  socket leg: a frame off an attached fd or a device says nothing of the peer.
 */
static inline void s_idle_heard(const duct_worker_t *w, const duct_conn_t *conn,
                                duct_session_t *s)
{
    if (s->idle_at != session_idle_unarmed && duct_conn_peer_socket(conn))
        s->idle_at = w->pass_ns;
}

/** @brief Count one frame of @p bytes payload in leg @p cid's rx tally. */
static inline void s_count_rx(const duct_session_t *s, duct_conn_id_t cid, size_t bytes)
{
    assert(cid < duct_session_max_legs);
    auto tally = &duct_session_counters(s)[cid];
    tally->rx_frames += 1u;
    tally->rx_bytes += bytes;
}

/** @brief Claim, handler or @c on_frame, and answer for one already resolved
 *  frame, wherever its bytes came from.
 *
 *  The RX ring through @c s_dispatch_frame, or a sealed wire's decrypted
 *  cleartext through @c s_dispatch_sealed_frame. @p ack tells every ack site
 *  in this body — and the multiplexed-handler completion path, which can
 *  finish long after this call returns — which sink to advance. An answer
 *  parked aliasing the frame carries @p ack, which lands as the answer
 *  resolves.
 *
 *  A frame counts in its leg's rx tally once a stream handler claims it or
 *  @c on_frame answers with anything but @c rc_defer; a deferred frame counts
 *  at its replay.
 *
 *  @p cid stays a parameter because @ref duct_session_conn_id_by_handle is a
 *  real per-session-leg lookup, and the sealed drain loop below calls this
 *  once per inner frame in one record; hoisting that lookup out to once per
 *  task is load-bearing.
 */
static duct_exec_rc_t s_dispatch_frame_body(duct_worker_t *w, duct_conn_t *conn,
    duct_session_t *s, const duct_proto_cfg_t *cfg, duct_conn_id_t cid,
    duct_frame_t frame, duct_frame_ack_t ack)
{
    switch (s_dispatch_stream_claim(w, conn, s, cfg, cid, frame, ack)) {
    case claim_handled:
        s_count_rx(s, cid, frame.payload.size);
        s_idle_heard(w, conn, s);
        return exec_done;
    case claim_busy:    return exec_defer;
    case claim_fallthrough: break;
    default: duct_unreachable();
    }
    duct_response_t out;
    duct_response_reset(&out);
    auto rc = cfg->on_frame(s, cid, &frame, &out, s->proto_state);
    if (rc == rc_defer) {
        duct_response_release_owned(&out);
        return exec_defer;
    }
    s_count_rx(s, cid, frame.payload.size);
    if (rc != rc_ok) {
        /* Discard: ack the bytes, no response / control / stream close. A
         * proto_switch recorded during the callback still applies. */
        s_frame_ack_apply(conn, ack);
        s_response_drop(s, &out);
        return exec_done;
    }
    s_idle_heard(w, conn, s);
    w->rx_ack = &ack;
    auto c_rc = s_response_take(s, &out, cid, frame.stream_id, frame.flags, nullptr, nullptr);
    if (w->rx_ack)
        s_frame_ack_apply(conn, ack);
    w->rx_ack = nullptr;
    if (c_rc == commit_internal)
        return exec_done;
    /* Adoption takes on_frame's rc_ok on a frame whose ack total reaches
     * roam_at. No byte past this frame's datagram is acked yet, a sealed
     * record's ring bytes going at its unseal, so reaching roam_at places the
     * frame at or past the datagram that proposed the address. A frame a
     * stream handler still holds only keeps acked short, deferring the move
     * to a later accept. */
    if (duct_has(duct_conn_state(conn), fl_conn_roaming)) {
        auto rx = conn->rx_buf;
        uint64_t at = duct_atomic_load(&rx->acked, relaxed);
        if (at >= duct_atomic_load(&rx->roam_at, acquire)) {
            duct_atomic_store(&rx->accept_at, at, release);
            auto rh = duct_conn_handle_get(conn);
            /* io re-points the socket on this post: records committed ahead
             * of it leave through the current peer. */
            s_tx_train_flush_for(rh);
            duct_io_post_peer_roam(&rh);
        }
    }
    return exec_done;
}

/** @brief Dispatch one frame of @p conn unless an answer to an earlier one still
 *  waits parked.
 *  The wait is @p conn's RX ring hold, which every output parked during the
 *  dispatch writes and which stands until the last of them is served, on
 *  whichever leg it parked; @c exec_defer leaves the frame for its replay once
 *  those outputs publish, fail or lose their legs. */
static duct_exec_rc_t s_dispatch_one_frame(duct_worker_t *w, duct_conn_t *conn,
    duct_session_t *s, duct_conn_id_t cid,
    duct_frame_t frame, duct_frame_ack_t ack)
{
    auto cfg = duct_proto_cfg_of(s->proto);
    duct_do_if(!cfg->on_frame, return exec_done);
    auto hold = s_conn_tx_hold(conn);
    if (s_tx_held(s, hold, conn))
        return exec_defer;
    w->hold_into = hold;
    w->hold_conn = conn;
    auto rc = s_dispatch_frame_body(w, conn, s, cfg, cid, frame, ack);
    w->hold_into = nullptr;
    w->hold_conn = nullptr;
    return rc;
}

/** @brief Engine decrypt-in-place target: @p self's codec cleartext buffer
 *  at its current write cursor, with the room left there.
 *
 *  Never fails, and its one driver reaches it holding at least @c pdu_ct_max:
 *  @ref s_dispatch_sealed_frame defers until the room left in @c ct_buf clears
 *  that bar. Reporting the room lets an engine size its write against the
 *  span it was handed; @ref s_unseal_commit catches one that does not. No
 *  copy from an engine-owned buffer — the engine decrypts straight
 *  into codec state.
 */
static void *s_unseal_reserve(duct_unseal_ctx_t *self, size_t *out_cap)
{
    auto codec = self->codec;
    *out_cap = duct_byte_len(codec->ct_buf) - codec->ct_len;
    return duct_at(codec->ct_buf) + codec->ct_len;
}

/** @brief Cleartext-cursor advance for @p len just-decrypted bytes.
 *  Makes them visible to the RX drain, out of @ref s_unseal_reserve's span.
 *
 *  Bytes written but never committed this way (an aborted or
 *  still-buffering decrypt) stay invisible — the next reservation starts
 *  at the same, un-advanced cursor and overwrites them.
 *
 *  Returns false if @p len exceeds available buffer capacity without
 *  advancing the cursor.
 */
static bool s_unseal_commit(duct_unseal_ctx_t *self, size_t len)
{
    auto codec = self->codec;
    size_t room = duct_byte_len(codec->ct_buf) - codec->ct_len;
    duct_do_if(len > room, return false);
    codec->ct_len += (uint32_t)len;
    return true;
}

/** @brief Engine decrypt-in-place target: what is left of @p self's destination
 *  reservation or cleartext-ring region.
 *  Cursor-shaped as @ref s_unseal_reserve over the codec buffer; appends
 *  subsequent chunks sequentially for engines splitting cleartext across
 *  multiple commits.
 */
static void *s_redirect_reserve(duct_unseal_ctx_t *self, size_t *out_cap)
{
    auto r = DUCT_CAST(redirect_t, base, self);
    *out_cap = r->cap - r->len;
    return (char *)r->at + r->len;
}

/** @brief Advance the target's write cursor by @p len decrypted bytes.
 *  Nothing is published here: a destination sees a reserved span only once the
 *  response commit resolves it. A @p len past what is left is refused, the same
 *  bound @ref s_unseal_commit enforces on the codec buffer.
 */
static bool s_redirect_commit(duct_unseal_ctx_t *self, size_t len)
{
    auto r = DUCT_CAST(redirect_t, base, self);
    duct_do_if(len > r->cap - r->len, return false);
    r->len += len;
    return true;
}

/** @brief Stage engine egress, a handshake reply or an alert, into @p self's TX
 *  OLB or its codec's engine park.
 *  The codec's PDU prefix goes out ahead of @p bytes, counted with them into the
 *  record header a record-framed conn takes: handshake bytes never pass the
 *  packer, so the prefix is added here. A codec with a join lead leads the
 *  record once the bytes behind its prefix are written. The ring takes the
 *  record only while the park is empty, and publishes it and posts io's drain;
 *  otherwise the park keeps it, ahead of every later byte of the conn. @p bare
 *  sends one opening packet alone and never parks: an @c x_udp_peer conn stages
 *  it as a record, an @c x_tcp conn also writes the packet's end into the
 *  socket's opening, for io to cut its writes at.
 *  @return @c false once the conn is gone, for a @p bare the conn refuses or
 *  finds no room for in the ring or the opening, and when the park has no room
 *  or no memory.
 */
static bool s_unseal_tx_stage(duct_unseal_ctx_t *self, duct_view_u8 bytes, bool bare)
{
    assert(self->tx_buf->kind == wire_tx_olb);
    auto olb = self->tx_buf->olb;
    auto h = (duct_conn_handle_t){ .word = self->handle };
    auto conn = duct_conn_by_handle(h);
    if (!conn || (bare && conn->xport_type != x_udp_peer && conn->xport_type != x_tcp))
        return false;
    /* Train records staged in this pass take its room, and the span below
     * never opens the next pass: they go out first. */
    s_tx_train_flush_for(h);
    /* The opening's cuts count from the stream's first byte, so its first
     * packet stages ahead of every byte published or written, a lead apart. */
    auto opening = bare && conn->xport_type == x_tcp ? &duct_x_sock_tx_of(olb)->opening : nullptr;
    uint64_t ahead = opening ? duct_olb_tx_stream_pos(olb) : 0u;
    if (opening && (!duct_x_opening_room(opening, ahead, bytes.size)
                    || (!duct_x_opening_count(opening) && olb->stream_end != 0u)))
        return false;
    size_t rec = s_tx_rec_size(conn),
           pre = bare ? 0u : self->codec->tx_prefix_len,
           len = rec + pre + bytes.size;
    auto span = self->codec->engine_park_len ? nullptr
              : (uint8_t *)duct_olb_tx_span_open(olb, len);
    bool ring = span != nullptr;
    if (!ring && !bare)
        span = s_engine_park_span(conn, self->codec, len);
    if (!span)
        return false;
    if (opening)
        duct_x_opening_push(opening, ahead, bytes.size);
    if (rec)
        duct_dgram_rec_hdr_encode(span, pre + bytes.size);
    if (pre)
        memcpy(span + rec, self->codec->prefix, pre);
    if (bytes.size)
        memcpy(span + rec + pre, bytes.data, bytes.size);
    if (pre)
        duct_wire_codec_lead(self->codec, span + rec, pre + bytes.size);
    if (ring) {
        duct_olb_tx_publish(olb);
        duct_io_post_tx_drain(DUCT_CAST(duct_conn_handle_t, word, &self->handle));
    }
    return true;
}

/** @brief Stage engine egress behind the codec's PDU prefix. */
static bool s_unseal_tx_append(duct_unseal_ctx_t *self, duct_view_u8 bytes)
{
    return s_unseal_tx_stage(self, bytes, false);
}

/** @brief Stage one opening packet without the codec's PDU prefix. */
static bool s_unseal_tx_append_bare(duct_unseal_ctx_t *self, duct_view_u8 bytes)
{
    return s_unseal_tx_stage(self, bytes, true);
}

/** @brief Engine egress on a datagram conn, staged into the listener
 *  dgram outbox addressed to the peer.
 *  Returns false on outbox reservation failure. Carries the codec's PDU prefix
 *  and join lead.
 */
static bool s_unseal_tx_append_dgram(duct_unseal_ctx_t *self, duct_view_u8 bytes)
{
    auto h = (duct_conn_handle_t){ .word = self->handle };
    auto conn = duct_conn_by_handle(h);
    if (!conn || conn->xport_type != x_udp_shared || !conn->ctx)
        return false;
    auto dctx = (duct_dgram_shared_ctx_t *)conn->ctx;
    auto listener = dctx->listener;
    size_t pre = self->codec->tx_prefix_len;
    duct_io_post_dgram_tx(listener);
    dgram_out_t dout;
    duct_vmq_push_rc_t push_rc;
    if (!s_dgram_out_open(listener, &dctx->peer, pre + bytes.size, &dout, &push_rc))
        return false;
    auto at = (uint8_t *)dout.span.data;
    if (pre)
        memcpy(at, self->codec->prefix, pre);
    if (bytes.size)
        memcpy(at + pre, bytes.data, bytes.size);
    if (pre)
        duct_wire_codec_lead(self->codec, at, pre + bytes.size);
    s_dgram_out_publish(&dout, pre + bytes.size);
    duct_io_post_dgram_tx(listener);
    return true;
}

static duct_result_t s_hs_arm(duct_unseal_ctx_t *self, uint32_t delay_ms);

/** @brief The conn's peer address: the RX ring's own for a socket conn, the
 *  shared ctx's for a shared leg, none for a conn that names no address.
 *  Read into every engine context the worker builds. */
static duct_peer_t s_conn_peer(const duct_conn_t *conn)
{
    auto rx = duct_conn_rx_olb(conn);
    if (rx)
        return rx->peer;
    if (conn->xport_type == x_udp_shared && conn->ctx)
        return ((const duct_dgram_shared_ctx_t *)conn->ctx)->peer;
    return (duct_peer_t){};
}

/** @brief Build the context an engine emits through outside any inbound PDU.
 *  @p tx_stage is the caller's own storage, borrowed by the returned context.
 *  The append is picked by xport: an @c x_udp_shared conn owns no ring and
 *  stages into its listener's dgram outbox. The bare append is the ring's for
 *  every xport and takes an @c x_udp_peer or @c x_tcp conn alone. The context
 *  carries the codec's opening ceiling, and arms the engine's @c retry through
 *  @c s_hs_arm. */

static duct_unseal_ctx_t s_engine_ctx(duct_conn_t *conn,
                                      duct_wire_codec_t *codec,
                                      duct_wire_tx_t *tx_stage)
{
    auto handle = duct_conn_handle_get(conn);
    *tx_stage = (duct_wire_tx_t){ .kind = wire_tx_olb, .olb = conn->tx_buf };
    return (duct_unseal_ctx_t){
        .handle = handle.word,
        .codec = codec, .tx_buf = tx_stage,
        .peer = s_conn_peer(conn),
        .tx_append = conn->xport_type == x_udp_shared
                   ? s_unseal_tx_append_dgram : s_unseal_tx_append,
        .tx_append_bare = s_unseal_tx_append_bare,
        .opening_ceiling = codec->opening_ceiling,
        .arm = s_hs_arm,
    };
}

/** @brief Find the codec whose engine sends @p conn's @c close_notify for a
 *  close of @p reason.
 *  Null for a plain wire, a conn without its codec yet, an engine that sends
 *  none, and a @c close_protocol_error close: @c close_notify announces a
 *  graceful end. */
static duct_wire_codec_t *s_notify_codec(duct_conn_t *conn, duct_close_reason_t reason)
{
    auto sc = reason != close_protocol_error && conn->wire && conn->wire->unseal
            ? duct_conn_sealed_ctx(conn) : nullptr;
    auto codec = sc ? sc->codec : nullptr;
    return codec && codec->engine->vtbl->close_notify ? codec : nullptr;
}

/** @brief Stage @p conn's engine @c close_notify for a close of @p reason into
 *  its TX ring or engine park.
 *  Nothing is staged where @ref s_notify_codec answers null. */
static void s_close_notify(duct_conn_t *conn, duct_close_reason_t reason)
{
    auto codec = s_notify_codec(conn, reason);
    if (!codec)
        return;
    duct_wire_tx_t tx_stage;
    auto ctx = s_engine_ctx(conn, codec, &tx_stage);
    codec->engine->vtbl->close_notify(codec->engine, &ctx);
}

/** @brief Mark the codec this timer was armed for as past its key lifetime.
 *  The conn is resolved from @c token afresh, so one reclaimed since the arm is
 *  passed over, and a codec rebuilt since carries another @c rekey_timer. Nothing
 *  is sent here: the conn's next PDU either way takes the rekey. */
static duct_exec_rc_t s_rekey_fire(void *arg)
{
    auto ctx = (timer_ctx_t *)arg;
    duct_do_if(!ctx, return exec_done);
    duct_conn_handle_t handle = { .word = ctx->token };
    auto conn = duct_conn_by_handle(handle);
    auto sc = conn ? duct_conn_sealed_ctx(conn) : nullptr;
    if (sc && sc->codec && sc->codec->rekey_timer == ctx->self)
        sc->codec->rekey_due = true;
    return exec_done;
}

/** @brief Add @p ctx as a timer node running @p exec after @p delay_us, again
 *  every @p interval_us unless that is 0.
 *  Sets the context's worker and own handle.
 *  @return the timer's handle, @c timer_handle_null when no timer node is to be
 *  had; the context is released then, and otherwise by the timer.
 */
static duct_timer_handle_t
s_timer_start(duct_worker_t *w, timer_ctx_t *ctx, uint64_t delay_us, uint64_t interval_us,
              duct_exec_fn exec)
{
    ctx->w = w;
    auto h = duct_timer_add(&w->timers, w->worker_id, 0u, delay_us, interval_us,
                            interval_us ? 0u : 1u, exec, ctx, duct_del_fn);
    if (h == timer_handle_null)
        duct_del(ctx);
    else
        ctx->self = h;
    return h;
}

/** @brief Arm a one-shot timer running @p exec after @p delay_us, its argument a
 *  fresh @c timer_ctx_t holding @p session_tok and @p token.
 *  @return the timer's handle, @c timer_handle_null when no context or timer
 *  node is to be had.
 */
static duct_timer_handle_t
s_timer_arm_once(duct_worker_t *w, duct_handle_t session_tok, uint64_t token, uint64_t delay_us,
                 duct_exec_fn exec)
{
    auto ctx = duct_new(timer_ctx_t);
    duct_do_if(!ctx, return timer_handle_null);
    ctx->session_tok = session_tok;
    ctx->token = token;
    return s_timer_start(w, ctx, delay_us, 0u, exec);
}

/** @brief Find the slot of @p tk holding @p key, @c session_timer_keys for none.
 *  Key 0 finds a free slot.
 */
static unsigned s_timer_key_find(const duct_session_timer_key_t *tk, uint32_t key)
{
    for (unsigned i = 0u; i < session_timer_keys; ++i)
        if (tk[i].key == key)
            return i;
    return session_timer_keys;
}

/** @brief Find the slot of @p s holding @p timer under @p key, nullptr for none.
 *  A timer replaced or cancelled under its key is not held.
 */
static duct_session_timer_key_t *
s_timer_key_held(const duct_session_t *s, uint32_t key, duct_timer_handle_t timer)
{
    auto tk = duct_session_timer_keys(s);
    unsigned at = s_timer_key_find(tk, key);
    return at < session_timer_keys && tk[at].timer == timer ? &tk[at] : nullptr;
}

/** @brief Test whether @p timer's node in @p w's set carries an interval.
 *  A session timer with one runs unbounded, so the answer is whether it arms
 *  again after this fire. */
static bool s_timer_repeats(duct_worker_t *w, duct_timer_handle_t timer)
{
    auto t = duct_timer_hash_find(&w->timers, duct_timer_handle_id(timer));
    return t && (t->interval.tv_sec || t->interval.tv_nsec);
}

/** @brief Free the slot of the fire of @p timer under @p key unless the timer repeats.
 *  The timer set says which: a node with an interval stays armed and keeps its
 *  slot until it is cancelled or replaced, while a one-shot's node is retired
 *  after this fire.
 */
static void s_timer_key_spend(duct_worker_t *w, const duct_session_t *s, uint32_t key,
                               duct_timer_handle_t timer)
{
    auto held = key && !s_timer_repeats(w, timer) ? s_timer_key_held(s, key, timer) : nullptr;
    if (held)
        *held = (duct_session_timer_key_t){};
}

/** @brief Arm @p codec's one-shot key-lifetime timer, its handle kept in
 *  @c rekey_timer.
 *
 *  Each fire is pulled forward by up to a @c rekey_spread_div'th of the
 *  lifetime, so conns opened in one burst stop coming due together — on a
 *  single worker that is one stall of their handshakes added together. The
 *  shift only ever subtracts: the lifetime bounds how long a key carries
 *  traffic.
 *
 *  A zero lifetime, an engine declining @c rekey and a failed allocation all
 *  leave the conn with the key set it has. */
static void s_rekey_arm(duct_conn_t *conn, duct_wire_codec_t *codec)
{
    auto w = s_this_worker;
    uint64_t lifetime_ms = s_wmod.seal_key_lifetime_ms;
    duct_do_if(!w, return);
    if (!lifetime_ms || !codec->engine->vtbl->rekey)
        return;
    uint64_t delay_us = 0u;
    bool overflow = duct_ckd_mul(&delay_us, lifetime_ms, 1000u);
    duct_do_if(overflow, return);
    uint64_t token = duct_conn_handle_get(conn).word;
    /* The handle is the spread's only input: it differs across live conns by
     * construction, and hashing it costs the worker no generator state and no
     * call out. */
    uint64_t spread = delay_us / rekey_spread_div;
    uint64_t first = delay_us - duct_splitmix64(token) % (spread + 1u);
    auto h = s_timer_arm_once(w, conn->session_token, token, first, s_rekey_fire);
    if (h != timer_handle_null)
        codec->rekey_timer = h;
}

/** @brief Run the engine's @c retry for the conn @p arg names.
 *  The conn is resolved from @c token afresh, so one gone or reused is left
 *  alone, as is a conn whose codec is gone or whose engine declines @c retry. The
 *  timer retires with this fire; @c retry arms the next. */
static duct_exec_rc_t s_hs_retry_fire(void *arg)
{
    auto ctx = (timer_ctx_t *)arg;
    assert(ctx);
    duct_conn_handle_t handle = { .word = ctx->token };
    auto conn = duct_conn_by_handle(handle);
    auto sc = conn ? duct_conn_sealed_ctx(conn) : nullptr;
    auto codec = sc ? sc->codec : nullptr;
    if (!codec || !codec->engine->vtbl->retry)
        return exec_done;
    duct_wire_tx_t tx_stage;
    auto ectx = s_engine_ctx(conn, codec, &tx_stage);
    codec->engine->vtbl->retry(codec->engine, &ectx);
    return exec_done;
}

/** @brief Arm a one-shot timer that runs @c s_hs_retry_fire for the conn @p self
 *  names, @p delay_ms milliseconds from now.
 *  The timer rides the conn's session, so the session's end retires it.
 *  @return rc_ok when armed, rc_closed for a conn that is gone, rc_no_memory when
 *  no timer context or node is to be had. */
static duct_result_t s_hs_arm(duct_unseal_ctx_t *self, uint32_t delay_ms)
{
    auto w = s_this_worker;
    assert(w);
    auto h = (duct_conn_handle_t){ .word = self->handle };
    auto conn = duct_conn_by_handle(h);
    duct_do_if(!conn, return rc_closed);
    return s_timer_arm_once(w, conn->session_token, h.word, (uint64_t)delay_ms * 1000u,
                            s_hs_retry_fire) == timer_handle_null ? rc_no_memory : rc_ok;
}

/** @brief Bytes one engine message takes on @p conn's egress: the engine's
 *  budget, the codec's PDU prefix and a record-framed ring's record header. */
static size_t s_hs_need(const duct_conn_t *conn, const duct_wire_codec_t *codec)
{
    return codec->engine->vtbl->engine_hs_budget + codec->tx_prefix_len + s_tx_rec_size(conn);
}

/** @brief Test whether one engine message fits @p conn's egress now.
 *  The engine's budget counts its own bytes alone, and @c tx_append adds the
 *  codec's PDU prefix to each message, plus a record header on a ring. An
 *  @c x_udp_shared conn's message takes an entry on this worker's lane of its
 *  listener's outbox. Only this worker fills either, so a true answer holds
 *  until it writes again; a conn with neither answers true. */
static bool s_hs_fits(const duct_conn_t *conn, const duct_wire_codec_t *codec)
{
    size_t need = s_hs_need(conn, codec);
    if (conn->xport_type == x_udp_shared)
        return s_dgram_out_fits(((const duct_dgram_shared_ctx_t *)conn->ctx)->listener, need);
    auto tx = duct_conn_tx_olb(conn);
    return !tx || duct_olb_tx_space(tx) >= need;
}

/** @brief Run @p codec's due rekey through @p ctx and arm its next lifetime.
 *  A conn short of room for one engine message leaves it due, as do
 *  @c rc_again and @c rc_no_memory, for the conn's next PDU; @c rc_fatal arms
 *  nothing more. */
static void s_rekey_take(duct_conn_t *conn, duct_wire_codec_t *codec, duct_unseal_ctx_t *ctx)
{
    if (!codec->rekey_due || !s_hs_fits(conn, codec))
        return;
    auto rc = codec->engine->vtbl->rekey(codec->engine, ctx);
    if (rc == rc_again || rc == rc_no_memory)
        return;
    codec->rekey_due = false;
    if (rc != rc_fatal)
        s_rekey_arm(conn, codec);
}

/** @brief Take @p conn's due rekey after a committed send.
 *  The flag is read ahead of building the engine context, so a send with no
 *  rekey due builds none. */
static void s_rekey_on_send(duct_conn_t *conn)
{
    auto sc = duct_conn_sealed_ctx(conn);
    auto codec = sc ? sc->codec : nullptr;
    if (!codec || !codec->rekey_due)
        return;
    duct_wire_tx_t tx_stage;
    auto ectx = s_engine_ctx(conn, codec, &tx_stage);
    s_rekey_take(conn, codec, &ectx);
}

/** @brief Close the joined leg @p arg names unless its codec has named its
 *  peer.
 *  The conn is resolved from @c token afresh, so one gone or reused is left
 *  alone. */
static duct_exec_rc_t s_join_deadline_fire(void *arg)
{
    auto ctx = (timer_ctx_t *)arg;
    duct_do_if(!ctx, return exec_done);
    duct_conn_handle_t handle = { .word = ctx->token };
    auto conn = duct_conn_by_handle(handle);
    auto sc = conn ? duct_conn_sealed_ctx(conn) : nullptr;
    if (!sc || (sc->codec && sc->codec->peer_announced))
        return exec_done;
    duct_io_post_close_request(&handle, close_timeout);
    return exec_done;
}

void duct_worker_join_deadline_arm(duct_session_t *s, duct_conn_handle_t handle)
{
    auto w = s_this_worker;
    assert(w);
    auto conn = duct_conn_by_handle(handle);
    auto sc = conn ? duct_conn_sealed_ctx(conn) : nullptr;
    if (!s->proto || !sc || !sc->codec || !sc->codec->engine->vtbl->peer_identity)
        return;
    auto cfg = duct_proto_cfg_of(s->proto);
    uint64_t ms = cfg->join_auth_timeout_ms ? cfg->join_auth_timeout_ms
                                            : duct_join_auth_default_ms;
    duct_discard s_timer_arm_once(w, duct_session_handle_from_live(s).word, handle.word,
                                  ms * 1000u, s_join_deadline_fire);
}

/** @brief Coalescing window of the timer wheel, nanoseconds: a drain fires a
 *  timer due that far ahead of the pass time.
 *  The pass time does not move inside a drain, so an idle remainder under the
 *  window falls due again at once; the expiry counts it as elapsed. */
static constexpr uint64_t idle_coalesce_ns = duct_timer_coalesce_us * 1000u;

static duct_exec_rc_t s_idle_fire(void *arg);

/** @brief Arm @p s's idle timer to fire in @p delay_ns, rounded up to the
 *  wheel's microsecond, leaving the session unarmed when no timer is to be had. */
static void s_idle_timer(duct_worker_t *w, duct_session_t *s, uint64_t delay_ns)
{
    if (s_timer_arm_once(w, duct_session_handle_from_live(s).word, 0u, (delay_ns + 999u) / 1000u,
                         s_idle_fire) == timer_handle_null)
        s->idle_at = session_idle_unarmed;
}

/** @brief Idle span of @p s's protocol of the moment, nanoseconds; 0 for a
 *  protocol with no bound. */
static uint64_t s_idle_span_ns(const duct_session_t *s)
{
    return (uint64_t)duct_proto_cfg_of(s->proto)->idle_timeout_ms * 1'000'000u;
}

/** @brief Close the session @p arg names if it accepted no frame from a socket
 *  leg for its protocol's span, else re-arm for what remains of it.
 *  The span is read afresh at each expiry, so a protocol switch changes it from
 *  the next one on, and a protocol with none retires the timer and leaves the
 *  session unarmed. */
static duct_exec_rc_t s_idle_fire(void *arg)
{
    auto ctx = (timer_ctx_t *)arg;
    assert(ctx);
    auto w = ctx->w;
    auto s = duct_session_attached_by_handle((duct_session_handle_t){ .word = ctx->session_tok });
    if (!s)
        return exec_done;
    assert(s->idle_at != session_idle_unarmed);
    uint64_t span_ns = s_idle_span_ns(s),
             quiet_ns = w->pass_ns - s->idle_at;
    if (span_ns && quiet_ns + idle_coalesce_ns < span_ns) {
        s_idle_timer(w, s, span_ns - quiet_ns);
        return exec_done;
    }
    s->idle_at = session_idle_unarmed;
    if (span_ns)
        duct_session_close_walk(s, close_timeout);
    return exec_done;
}

void duct_worker_idle_arm(duct_session_t *s)
{
    uint64_t span_ns = s_idle_span_ns(s);
    if (s->idle_at != session_idle_unarmed || !span_ns)
        return;
    auto w = s_this_worker;
    assert(w);
    s->idle_at = w->pass_ns;
    s_idle_timer(w, s, span_ns);
}

/** @brief Resolve @p conn's sealed-wire codec, building it on first use with
 *  @p tx_prefix.
 *
 *  A fresh codec takes @p tx_prefix, arms its key-lifetime timer and
 *  fires the engine's own start(). Nullptr for a plain wire, an ineligible
 *  xport, a failed build, or a prefix the codec cannot take, that codec
 *  destroyed unarmed. It tests the wire itself: s_tx_stage_frame's hot path
 *  proves it first, duct_worker_tls_ensure_started does not.
 */
static duct_wire_codec_t *s_tls_codec_open(duct_conn_t *conn, duct_view_u8 tx_prefix)
{
    if (!conn->wire || !conn->wire->unseal)
        return nullptr;
    auto sc = duct_conn_sealed_ctx(conn);
    if (!sc)
        return nullptr;
    if (sc->codec)
        return sc->codec;
    auto codec = conn->wire->create_codec(conn->wire, conn->xport_type);
    if (!codec)
        return nullptr;
    /* A dial's prefix lands here and nowhere else: the codec exists from here
     * and start() emits below, the one point a first flight can still carry
     * it. A stream codec takes no per-PDU prefix, so an x_tcp or x_local conn
     * writes the bytes once instead, as the stream's lead. */
    duct_view_u8 lead = {};
    if (tx_prefix.size) {
        if (tx_prefix.size == codec->tx_prefix_len)
            memcpy(codec->prefix, tx_prefix.data, tx_prefix.size);
        else if (!codec->tx_prefix_len
                 && (conn->xport_type == x_tcp || conn->xport_type == x_local))
            lead = tx_prefix;
        else {
            codec->destroy(codec);
            return nullptr;
        }
    }
    sc->codec = codec;
    s_rekey_arm(conn, codec);
    auto tx = duct_conn_tx_olb(conn);
    if (!tx)
        return codec;
    /* The lead leaves in the first flight's own publish, so io never drains it
     * alone; with no start, or one emitting nothing, the publish below hands it
     * to the next drain. A dialed conn builds its codec at its join, its ring
     * still empty, so a lead of at most duct_seal_prefix_max bytes stages. */
    if (lead.size)
        duct_discard duct_olb_tx_stage(tx, nullptr, 0u, lead.data, lead.size);
    if (codec->engine->vtbl->start) {
        duct_wire_tx_t tx_stage;
        auto ctx = s_engine_ctx(conn, codec, &tx_stage);
        codec->engine->vtbl->start(codec->engine, &ctx);
    }
    if (lead.size)
        duct_olb_tx_publish(tx);
    return codec;
}

/** @brief Resolve @p conn's sealed-wire codec, building it on first use with no
 *  prefix. */
static duct_wire_codec_t *s_tls_codec(duct_conn_t *conn)
{
    return s_tls_codec_open(conn, (duct_view_u8){});
}

bool duct_worker_tls_ensure_started(duct_conn_handle_t handle, duct_view_u8 tx_prefix)
{
    auto conn = duct_conn_by_handle(handle);
    return !conn || s_tls_codec_open(conn, tx_prefix) || !tx_prefix.size;
}

/** @brief Unrecoverable sealed-path failure handling: close, never
 *  drop-and-continue.
 *
 *  A dropped or rejected record desyncs the AEAD sequence, so every later
 *  record fails authentication anyway. Fires the protocol's on_error, then
 *  posts a @c close_protocol_error close request at once, which io carries
 *  out once the TX ring drains.
 */
static void s_sealed_fatal(duct_conn_handle_t handle, duct_session_t *s,
                           const duct_proto_cfg_t *cfg, duct_result_t rc)
{
    s_fire_error(s, cfg, rc);
    duct_io_post_close_request(&handle, close_protocol_error);
}

/** @brief Whether a leg of @p s other than @p cid has a codec that named the
 *  peer. */
static bool s_leg_named_besides(duct_session_t *s, duct_conn_id_t cid)
{
    duct_conn_handle_t h;
    duct_session_for_each_leg(s, i, h) {
        auto conn = i != cid ? duct_conn_by_handle(h) : nullptr;
        auto sc = conn ? duct_conn_sealed_ctx(conn) : nullptr;
        if (sc && sc->codec && sc->codec->peer_announced)
            return true;
    }
    return false;
}

/** @brief Act on @p codec's first identity: hold it to the session's, key the
 *  session where no other leg of it has named the peer, then hand it to the
 *  protocol.
 *
 *  Keying covers the first naming and a later one with every other naming leg
 *  gone, a fresh dial that stands on a new relation at the far end.
 *
 *  Asked after every accepted unseal; an engine answers an identity only once
 *  the peer has proven it holds the leg's keys, and @c peer_announced holds
 *  every PDU after an accepted naming off. A naming under an identity other
 *  than the session's closes the leg unless @c fl_proto_join_any_peer, and
 *  answers false for the caller to drop that PDU's cleartext; the leg keeps
 *  @c peer_announced clear, so each PDU it unseals before the close lands is
 *  refused alike.
 *
 *  The datagram call site sits inside @ref s_inter_pkt's redirect scope:
 *  @c unseal_size answers 0 until the identity does, so no destination leg
 *  holds a reservation for the one PDU this commits a response under.
 */
static bool s_peer_auth_fire(duct_session_t *s, const duct_proto_cfg_t *cfg,
                             duct_conn_id_t cid, duct_wire_codec_t *codec)
{
    auto vt = codec->engine->vtbl;
    if (codec->peer_announced || !vt->peer_identity)
        return true;
    auto id = vt->peer_identity(codec->engine);
    if (id.size == 0u)
        return true;
    bool named = s->join.id != nullptr;
    if (named) {
        bool stranger = !duct_has(cfg->flags, fl_proto_join_any_peer)
                     && !duct_join_same_peer(s, id);
        duct_do_if(stranger, duct_discard duct_conn_close(s, cid, close_protocol_error);
                             return false);
    }
    bool stored = named && s_leg_named_besides(s, cid);
    if (!stored)
        stored = duct_join_install(s, id, vt, codec->engine);
    /* A leg that goes on with no identity stored leaves the session unnamed, and the next naming leg keys it
     * without the same-peer rule. */
    duct_do_if(!stored, duct_discard duct_conn_close(s, cid, close_internal_error);
                        return false);
    codec->peer_announced = true;
    if (!cfg->on_peer_auth)
        return true;
    duct_response_t out;
    duct_response_reset(&out);
    cfg->on_peer_auth(s, cid, id, &out, s->proto_state);
    duct_response_commit(s, cid, duct_stream_id_default, &out);
    return true;
}

/** @brief Unseal one already-parsed sealed record and dispatch the frames
 *  inside it.
 *
 *  @p task's whole RX-ring span, header included, is unsealed into @p conn's
 *  codec, then 0 or more complete inner frames drain out of its cleartext
 *  buffer through the same hold, claim, handler and answer pipeline the plain
 *  path uses; the sealed path forks only the frame source. The unseal waits
 *  only while the codec's engine park has no room for one more engine message
 *  and cannot flush whole into the ring.
 *
 *  @p task->sealed_epoch snapshots the wire-binding generation that parsed
 *  it, which is no longer @p conn's current one once a deferred task replays
 *  across a protocol switch away from, or between, sealed wires. The leading
 *  generation check keeps that safe, uniformly for a task deferred
 *  before its own ack-at-unseal ran and one deferred after. A task of a leg
 *  the session no longer holds, a refused join's leg awaiting its close
 *  fence, is disposed of by the same check.
 */
static duct_exec_rc_t s_dispatch_sealed_frame(duct_worker_t *w, duct_conn_t *conn,
    duct_session_t *s, duct_conn_handle_t handle, const duct_msg_frame_t *task)
{
    auto cfg = duct_proto_cfg_of(s->proto);
    auto cid = duct_session_conn_id_by_handle(s, handle);
    if (task->sealed_epoch != conn->wire_epoch || cid == duct_session_max_legs) {
        /* Stale: wire_epoch bumps on every rebind, so any mismatch proves
         * this task predates conn's current generation. If ack-at-unseal
         * already ran for it, its ring bytes are already accounted for:
         * clears the bit without double-acknowledgement; otherwise acknowledges
         * immediately. */
        auto sc = duct_conn_sealed_ctx(conn);
        if (sc && sc->head_unsealed)
            sc->head_unsealed = false;
        else
            s_rx_ack(conn, task->len, task->offset + task->len);
        return exec_done;
    }
    auto sc = duct_conn_sealed_ctx(conn);
    if (!sc) {
        s_sealed_fatal(handle, s, cfg, rc_invalid_arg);
        return exec_done;
    }
    auto codec = sc->codec;
    if (!codec) {
        codec = conn->wire->create_codec(conn->wire, conn->xport_type);
        if (!codec) {
            s_sealed_fatal(handle, s, cfg, rc_no_memory);
            return exec_done;
        }
        sc->codec = codec;
    }
    if (!sc->head_unsealed) {
        auto vt = codec->engine->vtbl;
        if (duct_byte_len(codec->ct_buf) - codec->ct_len < vt->pdu_ct_max)
            return exec_defer;
        if (codec->engine_park_len
            && duct_byte_len(codec->engine_park) - codec->engine_park_len < s_hs_need(conn, codec)
            && !s_engine_park_flush(conn))
            return exec_defer;
        auto tx_stage = (duct_wire_tx_t){ .kind = wire_tx_olb, .olb = conn->tx_buf };
        duct_unseal_ctx_t ctx = {
            .handle = handle.word,
            .codec = codec, .tx_buf = &tx_stage,
            .peer = s_conn_peer(conn),
            .reserve = s_unseal_reserve, .commit = s_unseal_commit,
            .tx_append = s_unseal_tx_append,
        };
        /* task->header_size specifies the frame slice for rebind-replay
         * safety. Zero indicates datagram transports that carry no record
         * header. */
        size_t hdr = task->header_size;
        duct_view_u8 pdu = { .data = conn->rx_buf->data + task->offset + hdr,
                           .size = task->len - hdr };
        auto ct_was = codec->ct_len;
        s_rekey_take(conn, codec, &ctx);
        auto rc = conn->wire->unseal(conn->wire, codec, pdu, &ctx);
        /* rc_again leaves the PDU to replay whole, as the deferred task replays
         * it; the run after the arm is the room check the arm pairs with. */
        if (rc == rc_again) {
            s_tx_wait_arm(conn);
            rc = conn->wire->unseal(conn->wire, codec, pdu, &ctx);
            if (rc == rc_again)
                return exec_defer;
        }
        /* On datagram transports with independent records, unseal failures are
         * acknowledged and dropped while preserving the session. On stream
         * transports, unseal failures terminate the connection. */
        if (rc != rc_ok) {
            if (duct_conn_record_framed(conn)) {
                s_fire_error(s, cfg, rc);
                s_rx_ack(conn, task->len, task->offset + task->len);
            } else {
                s_sealed_fatal(handle, s, cfg, rc);
            }
            return exec_done;
        }
        sc->head_unsealed = true;
        s_rx_ack(conn, task->len, task->offset + task->len); /* ack-at-unseal */
        if (!s_peer_auth_fire(s, cfg, cid, codec)) {
            /* The refused PDU's cleartext alone goes: a leg commits none
             * before its peer is named. */
            codec->ct_len = ct_was;
            sc->head_unsealed = false;
            return exec_done;
        }
    }
    if (!codec->inner) {
        /* inner == nullptr: "raw bytes over TLS" — the whole
         * record's cleartext is one frame; no inner wire to drain through,
         * so no loop, no on_parse call. A record that yields no cleartext
         * at all (a handshake-only record — the null engine's own hello
         * exchange never calls commit) has nothing to dispatch: a
         * zero-size phantom frame is not a real application message. */
        uint32_t consumed = codec->ct_len - codec->ct_parse_off;
        if (consumed == 0u) {
            sc->head_unsealed = false;
            s_codec_compact(codec);
            return exec_done;
        }
        duct_frame_t frame = { .payload = {
            .data = duct_at(codec->ct_buf) + codec->ct_parse_off, .size = consumed } };
        auto ack = (duct_frame_ack_t){ .kind = ack_ct,
            .ct = { .data = duct_at(codec->ct_buf), .size = consumed } };
        if (s_dispatch_one_frame(w, conn, s, cid, frame, ack) == exec_defer)
            return exec_defer; /* ct_parse_off not advanced: replayed next pass */
        codec->ct_parse_off += consumed;
        sc->head_unsealed = false;
        s_codec_compact(codec);
        return exec_done;
    }
    for (;;) {
        duct_frame_t frame = {};
        size_t consumed = 0u;
        [[maybe_unused]] size_t needed = 0u;
        duct_view_u8 avail = { .data = duct_at(codec->ct_buf) + codec->ct_parse_off,
                             .size = codec->ct_len - codec->ct_parse_off };
        auto rc = codec->inner->on_parse(codec->inner, avail, &frame,
                                         codec->inner_parser, &consumed, &needed);
        if (rc == rc_again) {
            sc->head_unsealed = false;
            s_codec_compact(codec);
            return exec_done;
        }
        /* Zero consumption with rc_ok violates the parser contract;
         * terminates the connection with rc_invalid_arg. */
        if (rc != rc_ok || consumed == 0u) {
            s_sealed_fatal(handle, s, cfg, rc == rc_ok ? rc_invalid_arg : rc);
            return exec_done;
        }
        auto ack = (duct_frame_ack_t){ .kind = ack_ct,
            .ct = { .data = duct_at(codec->ct_buf), .size = consumed } };
        if (s_dispatch_one_frame(w, conn, s, cid, frame, ack) == exec_defer)
            return exec_defer; /* ct_parse_off not advanced: replayed next pass */
        codec->ct_parse_off += (uint32_t)consumed;
    }
}

/** @brief Batch frame iteration [from..n), one s_dispatch_frame call each.
 *  Returns exec_done when all processed, exec_defer at the first defer.
 */
static duct_exec_rc_t
s_dispatch_batch_run(duct_worker_t *w, duct_conn_handle_t h, const duct_msg_frame_batch_t *b,
                     uint32_t from, uint32_t *out_defer_idx)
{
    for (uint32_t i = from; i < b->n; ++i) {
        w->tx_train.more = i + 1u < b->n;
        auto rc = s_dispatch_frame(w, h, &b->frames[i]);
        if (rc == exec_defer) {
            if (out_defer_idx)
                *out_defer_idx = i;
            return exec_defer;
        }
        /* A multiplexed handler stream's frame dispatch only wakes its
         * coroutine (duct_async_queue_wake_coro/duct_coop_wake) — the step
         * that actually parks it again (in_wait) runs from duct_coop_cycle,
         * not the wake itself. Without a cycle here, the next same-stream
         * frame later in this same batch sees the handler still
         * not-yet-parked and defers the whole remainder, even though
         * nothing is actually blocked — just not yet scheduled. */
        duct_coop_cycle(&w->coop);
    }
    return exec_done;
}

/** @brief Dispatch batch @p b from frame @p from, checking its leg's read
 *  latch once at the end.
 *  The end check runs only after an ack of that leg, so it reads a conn its
 *  worker has not retired: @c s_dispatch_frame drops a retired conn's frames
 *  unacked, and a retire is confirmed by a message of its own, never inside a
 *  batch; io reclaims a conn after that confirm. An unbound conn io may
 *  reclaim mid-batch; its frames defer unacked. What the batch committed goes
 *  out at its end: this worker's train and its @c x_udp_shared pass.
 */
static duct_exec_rc_t
s_dispatch_batch_frames(duct_worker_t *w, const duct_msg_frame_batch_t *b,
                        uint32_t from, uint32_t *out_defer_idx)
{
    auto h = (duct_conn_handle_t){ .word = b->conn };
    auto conn = duct_conn_by_handle(h);
    s_rx_ack_batch.conn = conn;
    auto rc = s_dispatch_batch_run(w, h, b, from, out_defer_idx);
    bool owed = s_rx_ack_batch.owed;
    s_rx_ack_batch.conn = nullptr;
    s_rx_ack_batch.owed = false;
    if (owed)
        s_rx_ack_check(conn, duct_atomic_load(&conn->rx_buf->acked, relaxed));
    w->tx_train.more = false;
    s_tx_train_flush(w);
    s_worker_dgram_flush();
    return rc;
}

duct_exec_rc_t duct_msg_exec_frame_batch(void *self)
{
    auto batch = (duct_msg_frame_batch_t *)self;
    auto w = s_this_worker;
    assert(w);
    auto conn = duct_conn_by_handle((duct_conn_handle_t){ .word = batch->conn });
    if (!conn)
        return exec_done;
    uint32_t defer_idx = 0u;
    return s_dispatch_batch_frames(w, batch, 0u, &defer_idx);
}

static duct_exec_rc_t s_dispatch_batch(duct_vmq_hdr_t *hdr, duct_worker_t *w,
                                              uint32_t *out_defer_idx)
{
    auto batch = (const duct_msg_frame_batch_t *)&hdr->payload[0];
    auto h = (duct_conn_handle_t){ .word = batch->conn };
    auto conn = duct_conn_by_handle(h);
    if (!conn)
        return exec_done;

    /* Defer guard: if the conn's defer bit is set, defer the whole batch. */
    if (duct_bits_test(w->defer_q.mask, (unsigned)h.idx)) {
        *out_defer_idx = 0u;
        return exec_defer;
    }

    return s_dispatch_batch_frames(w, batch, 0u, out_defer_idx);
}

/** @brief Where @p pkt's bytes live: device memory the batch borrowed, an RX
 *  slot, or the batch's own tail.
 *  The choice is per packet, so one batch holds both borrowed and slot-resident
 *  ones. A null hold entry says this packet takes an offset instead,
 *  which is why a producer never lends a null pointer.
 */
static void *s_inter_payload(const duct_msg_inter_batch_t *b,
                             const duct_msg_inter_pkt_t *pkt)
{
    auto held = duct_msg_inter_holds((duct_msg_inter_batch_t *)b);
    if (held) {
        auto lent = held[pkt - duct_msg_inter_pkts((duct_msg_inter_batch_t *)b)];
        if (lent)
            return lent;
    }
    if (b->rx_pool)
        return duct_x_slot_data(b->rx_pool, b->rx_slot) + pkt->offset;
    return (char *)b + pkt->offset;
}

/** @brief Reserve @p size bytes on the leg @c route sends this packet to, for
 *  the unseal to decrypt straight into.
 *
 *  The caller has checked that @p cfg routes. @p out's @c span stays null, and
 *  the packet takes the copy path, for a @p size of 0 and for a destination that
 *  is no live @c x_inter leg, has no room, or is a read-only device.
 *
 *  @c route is evaluated here before @c on_frame using pre-frame protocol state.
 */
static void redirect_take(duct_session_t *s, const duct_proto_cfg_t *cfg,
                            duct_conn_id_t cid, duct_stream_id_t sid,
                            size_t size, redirect_t *out)
{
    if (size == 0u)
        return;
    duct_conn_id_t   rconn = cid;
    duct_stream_id_t rstream = sid;
    cfg->route(cid, sid, s->proto_state, &rconn, &rstream);
    duct_do_if(rconn >= duct_session_max_legs, return);
    auto conn = duct_conn_by_handle(duct_session_conn_at(s, rconn));
    duct_do_if(!conn || conn->xport_type != x_inter, return);
    out->conn_id = rconn;
    out->stream_id = rstream;
    out->cap = size;
    out->len = 0u;
    auto dev = (const duct_device_ops_t *)conn->ctx;
    out->dev = dev;
    if (dev) {
        /* A read-only device has no send memory to lend. */
        duct_do_if(!dev->write_reserve, return);
        auto span = dev->write_reserve(dev->ctx, size);
        duct_do_if(!span, return);
        out->span = span;
        return;
    }
    auto stok = duct_session_handle_from_live(s);
    out->span = duct_host_egress_reserve(&stok, rconn, size, &out->host);
}

/** @brief Close whatever reservation @p r still holds, delivering nothing.
 *
 *  Releases active reservations at scope exit. Commits zero bytes for unused
 *  device reservations or abandons host egress reservations.
 */
static void s_redirect_release(redirect_t *r)
{
    if (r->ct)
        s_tx_pool_drop_hold(r->ct);
    if (!r->span)
        return;
    if (r->dev)
        duct_discard r->dev->write_commit(r->dev->ctx, r->span, 0u);
    else
        duct_host_egress_abandon(&r->host);
}

/** @brief Per-packet dispatch for one inter frame.
 *
 *  Mirrors s_dispatch_frame's "plain path" tail — on_frame, response commit,
 *  control apply, proto switch — and takes the multiplexed stream-claim branch
 *  as well, handing it a copy of the payload since a parked handler outlives
 *  the batch. The @c inter_lane head advance releases packet memory.
 *
 *  rc_defer from on_frame has no replay path here: the lane consumed the
 *  message once @ref s_inter_msg_take took it, so the packet drops and says so
 *  through @c on_error with @c rc_again. @c rc_drop is the deliberate discard
 *  and reports nothing; a proto_switch on_frame recorded applies on either of
 *  its exits.
 *
 *  A sealed packet decrypts into the destination leg's own egress memory when
 *  the protocol routes and @ref redirect_take reserves it there, else into a cleartext-ring region
 *  sized to the datagram and the inner header; @ref s_redirect_release closes
 *  either on every return.
 */
static void s_inter_pkt(duct_conn_handle_t handle,
                                  const duct_msg_inter_batch_t *b, const duct_msg_inter_pkt_t *pkt)
{
    duct_conn_t *conn;
    duct_session_t *s;
    if (s_dispatch_resolve(handle, &conn, &s) != res_ok)
        return;
    if (s->wire_rebind_next)
        return; /* wire-changing switch in flight elsewhere in the session; no replay path here */
    auto cfg = duct_proto_cfg_of(s->proto);
    duct_do_if(!cfg->on_frame, return);
    auto w = s_this_worker;
    auto cid = duct_session_conn_id_by_handle(s, handle);
    /* A refused join's leg awaiting its close fence: dropped with no callback
     * and no report. */
    if (cid == duct_session_max_legs)
        return;
    duct_frame_t frame = {
        .stream_id = pkt->stream_id,
        .flags = pkt->flags,
        .payload = { .data = s_inter_payload(b, pkt), .size = pkt->len },
    };
    /* Each datagram constitutes a complete PDU, allocated in a discrete
     * cleartext region. */
    [[gnu::cleanup(s_redirect_release)]] redirect_t redirect;
    redirect.span = nullptr;
    redirect.ct = nullptr;
    bool sealed = conn->wire && conn->wire->unseal;
    if (sealed) {
        auto codec = s_tls_codec(conn);
        if (!codec)
            return;
        /* The strip runs before the question, not after: unseal_size answers
         * about the engine's own PDU, and counting the conn's prefix into it
         * over-reserves on the destination leg, while a datagram too short to
         * hold an engine PDU at all answers nonzero and takes cfg->route plus a
         * reservation on forged bytes. */
        if (cfg->route) {
            auto vt = codec->engine->vtbl;
            duct_view_u8 sized = frame.payload;
            size_t want = 0u;
            if (vt->unseal_size && duct_wire_codec_rx_strip(codec, &sized))
                want = vt->unseal_size(codec->engine, sized);
            redirect_take(s, cfg, cid, frame.stream_id, want, &redirect);
        }
        if (!redirect.span) {
            /* The cleartext is the datagram at most, plus the inner wire's header a
             * control datagram gets ahead of its payload. A full ring is full of the
             * train's references: writing the train frees them for one more ask. */
            size_t room = frame.payload.size + (codec->inner ? codec->inner->header_size : 0u);
            redirect.ct = s_pool_acquire(&w->ct_pool, room);
            if (!redirect.ct) {
                s_vnet_train_flush(w);
                redirect.ct = s_pool_acquire(&w->ct_pool, room);
            }
            if (!redirect.ct) {
                s_fire_error(s, cfg, rc_again);
                return;
            }
            redirect.cap = room;
            redirect.len = 0u;
        }
        redirect.at = redirect.span ? redirect.span : redirect.ct;
        redirect.base = (duct_unseal_ctx_t){
            .handle = handle.word,
            .codec = codec,
            .peer = s_conn_peer(conn),
            .reserve = s_redirect_reserve,
            .commit = s_redirect_commit,
            .tx_append = s_unseal_tx_append_dgram,
        };
        s_rekey_take(conn, codec, &redirect.base);
        auto urc = conn->wire->unseal(conn->wire, codec, frame.payload, &redirect.base);
        if (urc != rc_ok) {
            s_fire_error(s, cfg, urc);
            return;
        }
        if (!s_peer_auth_fire(s, cfg, cid, codec))
            return;
        frame.payload = duct_view(duct_view_u8, (void *)redirect.at, redirect.len);
        if (frame.payload.size == 0u)
            return;
        /* A datagram PDU holds exactly one inner frame, datagram framing
         * sealing one per PDU; a cleartext that frame does not fill exactly
         * costs only this datagram. */
        if (codec->inner) {
            duct_frame_t inner = {};
            size_t consumed = 0u,
                   needed = 0u;
            bool whole = frame.payload.size >= codec->inner->header_size
                      && codec->inner->on_parse(codec->inner, frame.payload, &inner,
                                                codec->inner_parser, &consumed,
                                                &needed) == rc_ok
                      && consumed == frame.payload.size;
            if (!whole) {
                s_fire_error(s, cfg, rc_invalid_arg);
                return;
            }
            frame = inner;
        }
    }
    bool shared = conn->xport_type == x_udp_shared;
    /* A sealed wire authenticates the datagram itself, so its source is adopted
     * here, ahead of every dispatch path below — the handler claim among them,
     * which returns before the plain-wire gate further down. Sound while the
     * engine carries the replay window @c fl_wire_dgram_ok stands for: without
     * one, a captured datagram replayed from a foreign address moves the
     * endpoint. */
    if (sealed && shared)
        ((duct_dgram_shared_ctx_t *)conn->ctx)->peer = b->peer;
    if (duct_has(cfg->flags, fl_proto_multiplexed) && frame.stream_id != 0u
        && cfg->handler_kind != handler_none) {
        /* Claim-eligible: the VMQ batch this frame lives in commits — frees
         * for producer reuse — the instant s_inter_drain's loop returns, but
         * handler dispatch is always queued to a later duct_coop_cycle pass,
         * so the payload needs a hold of its own before the coroutine is
         * queued: a claim on the RX slot it lies in, else a copy. An RST
         * takes neither, still closing the stream before any handler reads
         * its bytes; a fin takes one like any other. An empty payload takes
         * neither: a count of 0 makes duct_new answer nullptr, not out-of-memory. */
        bool is_rst = duct_has(frame.flags, fl_frame_rst);
        void *copy = nullptr;
        bool pinned = frame.payload.size && !is_rst && !sealed && b->rx_pool
                   && duct_x_slot_holds(b->rx_pool, b->rx_slot, frame.payload.data)
                   && duct_x_slot_claim(b->rx_pool, b->rx_slot);
        if (!pinned && frame.payload.size && !is_rst) {
            copy = duct_new(uint8_t, frame.payload.size);
            if (!copy) {
                s_fire_error(s, cfg, rc_no_memory);
                return;
            }
            memcpy(copy, frame.payload.data, frame.payload.size);
        }
        /* An RST never reaches a handler (s_dispatch_stream_claim closes the
         * stream first) — payload.data stays whatever it was, unread. Every
         * other path lands frame.payload.data on the copy, nullptr for a
         * zero-size payload, ensuring handlers never retain pointers into the
         * freed inter batch. */
        if (!is_rst && !pinned)
            frame.payload.data = copy;
        duct_frame_ack_t ack = pinned
            ? (duct_frame_ack_t){ .kind = ack_slot,
                                  .slot = { .pool = b->rx_pool, .idx = b->rx_slot } }
            : (duct_frame_ack_t){ .kind = ack_owned, .owned = { .ptr = copy } };
        switch (s_dispatch_stream_claim(w, conn, s, cfg, cid, frame, ack)) {
        case claim_handled:
            s_count_rx(s, cid, frame.payload.size);
            s_idle_heard(w, conn, s);
            return;
        case claim_busy:
            /* No replay path here: the frame is already off the lane. */
            s_frame_ack_apply(conn, ack);
            s_fire_error(s, cfg, rc_again);
            return;
        case claim_fallthrough:
            break; /* unreachable: gated above by the same condition */
        default:
            duct_unreachable();
        }
    }
    duct_response_t out;
    duct_response_reset(&out);
    auto rc = cfg->on_frame(s, cid, &frame, &out, s->proto_state);
    /* Every answer counts: rc_defer drops the packet below, so no replay
     * counts it. */
    s_count_rx(s, cid, frame.payload.size);
    if (rc != rc_ok) {
        if (rc == rc_defer)
            s_fire_error(s, cfg, rc_again);
        s_response_drop(s, &out);
        return;
    }
    s_idle_heard(w, conn, s);
    /* A plain wire authenticates nothing, so this return is the only affirmative
     * available: a protocol routing by its own preparse key accepts datagrams
     * from any source, and an unauthenticated one must not redirect the
     * session's replies. Sits ahead of the commit below, which sends to this
     * field, so the migrated datagram is answered at its new address. Past conn
     * creation this worker both writes and reads the field, so the plain write
     * races nothing. */
    if (!sealed && shared)
        ((duct_dgram_shared_ctx_t *)conn->ctx)->peer = b->peer;
    duct_discard s_response_take(s, &out, cid, frame.stream_id, frame.flags, &redirect, nullptr);
}

/** @brief Pin RX slot pool for @p conn during parked responses.
 *  Applicable to @c x_udp_shared conns; readers copy unslotted packets while
 *  pinned to prevent socket stalling.
 */
static void s_rx_pin(duct_conn_t *conn, duct_x_slot_pool_t *pool)
{
    if (conn->xport_type != x_udp_shared)
        return;
    auto dctx = (duct_dgram_shared_ctx_t *)conn->ctx;
    if (!pool)
        pool = dctx->rx_pin ? dctx->rx_pin : duct_io_dgram_shared_rx_slots(dctx->listener);
    if (dctx->rx_pin == pool)
        return;
    if (dctx->rx_pin)
        duct_io_rx_unpin(dctx->rx_pin);
    dctx->rx_pin = pool;
    duct_io_rx_pin(pool);
}

/** @brief Take @p conn's pin back, where it holds one. */
static void s_rx_unpin(duct_conn_t *conn)
{
    if (conn->xport_type != x_udp_shared)
        return;
    auto dctx = (duct_dgram_shared_ctx_t *)conn->ctx;
    if (!dctx->rx_pin)
        return;
    duct_io_rx_unpin(dctx->rx_pin);
    dctx->rx_pin = nullptr;
}

/** @brief Dispatch every packet of one message on the inter lane of @p arg, a
 *  @c duct_conn_t, unless an answer of that conn still waits parked.
 *  The lane's hold is read once per message and written by every output the
 *  message's packets park, and stands until the last is served on whichever leg
 *  it parked, so a conn parks at most one message's answers.
 *  @return false to leave this message, and the lane behind it, unread: a
 *  producer then meets a full lane, and a shared datagram conn pins its slot's
 *  pool so the socket reads on for other conns. */
static bool s_inter_msg_take(duct_vmq_hdr_t *hdr, void *arg)
{
    auto conn = (duct_conn_t *)arg;
    auto b = (duct_msg_inter_batch_t *)&hdr->payload[0];
    auto hold = s_conn_tx_hold(conn);
    auto w = s_this_worker;
    if (s_tx_held(duct_session_by_conn(conn), hold, conn)) {
        duct_rtstat_obj_inc(w, rtstats.inter_held, 1);
        s_rx_pin(conn, b->rx_pool);
        return false;
    }
    auto h = (duct_conn_handle_t){ .word = b->conn };
    auto pkts = duct_msg_inter_pkts(b);
    duct_frame_ack_t slot = { .kind = ack_slot, .slot = { .pool = b->rx_pool, .idx = b->rx_slot } };
    w->hold_into = hold;
    w->hold_conn = conn;
    w->slot_now = b->rx_pool ? &slot : nullptr;
    for (uint32_t i = 0u; i < b->n; ++i)
        s_inter_pkt(h, b, &pkts[i]);
    w->slot_now = nullptr;
    w->hold_into = nullptr;
    w->hold_conn = nullptr;
    /* After the loop: every packet in the batch reads the same slot, and this
     * drop ends the lane's hold on it. A path that outlives the call holds a
     * claim of its own or an owned copy: a claiming multiplexed handler (s_inter_pkt)
     * and a parked answer lying in the slot (s_slot_pin) take a claim, a sealed
     * frame or a claim past the bound takes a copy. Anything else that starts
     * retaining the payload needs a claim here, since a released slot is handed
     * straight out again. */
    if (b->rx_pool)
        duct_io_rx_slot_drop(b->rx_pool, b->rx_slot, false);
    return true;
}

/** @brief Inter-armed bitmap scan, one full drain of each armed conn's
 *  inter_lane.
 *  No quota applies: a lane is bounded by its own capacity. A bit whose conn
 *  is not bound to this worker is dropped, its lane unread: it was armed
 *  behind the retire confirm or left by the slot's earlier conn, and io frees
 *  or reuses what it names.
 *  @return Messages drained.
 */
static size_t s_inter_drain(duct_worker_t *w)
{
    if (!duct_atomic_load(&w->inter_pending, relaxed))
        return 0u;
    size_t total = 0u;
    for (unsigned word = 0u; word < DUCT_BITMAP_WORDS; ++word) {
        uint64_t bits = duct_bits_grab(w->inter_armed, word);
        while (bits) {
            unsigned bit = duct_ctz_ull(bits);
            bits &= bits - 1u;
            duct_atomic_fetch(sub, &w->inter_pending, 1u, relaxed);
            unsigned idx = (word << bits_word_shift) | bit;
            auto conn = duct_conn_by_idx(idx);
            /* A bit outlives its conn and names a slot io has retired or handed
             * to another worker, so this is the one field read before the match. */
            if (duct_atomic_load(&conn->bound_worker, relaxed) != w->worker_id + 1u)
                continue;
            auto lane = duct_conn_lane(conn);
            if (!lane)
                continue;
            assert(duct_atomic_load(&conn->conn_fence, relaxed) < fence_retire_ready);
            bool stopped = false;
            /* Handle taken before the drain: dispatching a packet can close
             * this conn, and the resume is addressed to the leg that was
             * read, not to whatever the slot holds afterwards. Null for
             * anything but a device leg, which the post below tests —
             * a live conn's handle never carries a zero generation. */
            auto ch = conn->xport_type == x_inter && conn->ctx
                    ? duct_conn_handle_get(conn) : conn_handle_null;
            /* The hold is read per message: the first one it stops stays on
             * the lane with every message behind it, and the conn is re-armed
             * so the pass after the parked answer leaves finds it again. */
            w->tx_train.more = true;
            total += duct_vmq_mpsc_drain_while(lane, s_inter_msg_take, conn, &stopped);
            w->tx_train.more = false;
            s_tx_train_flush(w);
            s_worker_dgram_flush();
            if (stopped) {
                if (duct_bits_set_if_new(w->inter_armed, idx))
                    duct_atomic_fetch(add, &w->inter_pending, 1u, relaxed);
                continue;
            }
            s_rx_unpin(conn);
            /* Only a lane this pass emptied resumes the device: an io thread
             * woken over a partly full lane has to stop again without reading,
             * and a lane still holding bytes is still armed, so the pass that
             * does empty it carries the resume instead. */
            if (ch.word) {
                auto ln = duct_mpsc_lane(lane, 0u);
                if (!duct_vmq_unread(ln.ctrl))
                    duct_io_post_rx_read(&ch);
            }
        }
    }
    /* on_inter_resume is a coarse "a lane made room, maybe retry a
     * deferred push" hint, not a per-push guarantee. */
    if (total)
        duct_host_inter_resume_fire();
    return total;
}

/** @brief True if @p h's active coro is parked, for whichever runtime it
 *  uses — au: in_wait; co: state == coro_state_waiting.
 */
static inline bool s_hctx_parked(const duct_stream_ctx_t *h)
{
    if (h->au)
        return h->au->in_wait;
    if (h->co)
        return h->co->state == coro_state_waiting;
    return true;
}

/** @brief Parked-coro wake, on whichever runtime @p h uses. */
static inline void s_hctx_wake(duct_coop_t *cp, duct_stream_ctx_t *h)
{
    if (h->au)
        duct_async_queue_wake_coro(&cp->async_queue, h->au);
    else if (h->co)
        duct_coop_wake(cp, h->co);
}

/** @brief Coro enqueue, to run (@p run true) or park (false).
 *
 *  @c au only: @c duct_coro_queue_put derives run-vs-park from @c
 *  co->state itself, so @p run is inert on the co path — callers merging
 *  both outcomes into one co call site (@ref s_hctx_sf_resume) may pass
 *  either.
 */
static inline void s_hctx_enqueue(duct_coop_t *cp, duct_stream_ctx_t *h, bool run)
{
    if (h->au)
        duct_async_queue_enqueue(&cp->async_queue, h->au, run ? coop_run : coop_wait);
    else if (h->co)
        duct_coro_queue_put(&cp->queue, h->co);
}

/** @brief Coro removal from its queue, release to its pool. */
static inline void s_hctx_remove_release(duct_coop_t *cp, duct_stream_ctx_t *h)
{
    if (h->au) {
        duct_async_queue_remove(&cp->async_queue, h->au);
        duct_async_release(&cp->async_pool, h->au);
    } else if (h->co) {
        duct_coro_queue_remove(&cp->queue, h->co);
        duct_coro_release(&cp->pool, h->co);
    }
}

/** @brief Held-frame ack (RX byte count + dispatch_frontier) without pin
 *  release.
 *
 *  Idempotent through @c frame_acked: a frame acked at a TX-backpressure park
 *  is acked once, and the handler's own later @c async_wait or @c async_done
 *  adds nothing — @ref duct_olb_rx_ack sums, so a second call moves @c head
 *  past bytes nobody read.
 *
 *  Leaves the pin up and @c frame in place, which lets a
 *  handler read @c duct_stream_frame again after the park.
 *  @ref s_hctx_hold_release is the other half, run when the handler's turn
 *  truly ends.
 */
static void s_hctx_rx_ack_only(duct_stream_ctx_t *hctx)
{
    if (hctx->frame_acked)
        return;
    auto c = duct_conn_by_handle(duct_session_conn_at(hctx->s, hctx->conn_id));
    switch (hctx->ack.kind) {
    case ack_ring:
        auto rx = c ? duct_conn_rx_olb(c) : nullptr;
        if (rx) {
            uint32_t end_off = s_dispatch_frontier_skip;
            if (hctx->frame.payload.data)
                /* End offset of the held frame, derived the same way
                 * s_dispatch_frame computed its start (rx->data + task->offset +
                 * hdr, size = task->len - hdr) — hdr cancels out, so this always
                 * equals task->offset + task->len exactly. */
                end_off = (uint32_t)((const uint8_t *)hctx->frame.payload.data
                         - rx->data + (ptrdiff_t)hctx->frame.payload.size);
            s_rx_ack(c, hctx->ack.ring.task_len, end_off);
        }
        break;
    case ack_ct:
        /* No ring, no dispatch_frontier — the sealed record this frame came
         * from was already s_rx_ack'd at unseal time. The conn only finds the
         * codec that owns the acked buffer, and c is nullptr once the leg is
         * gone. */
        s_frame_ack_apply(c, hctx->ack);
        break;
    case ack_owned:
    case ack_slot:
        break;
    default:
        duct_unreachable();
    }
    hctx->frame_acked = true;
}

/** @brief Held-frame pin release, @c frame cleared.
 *
 *  Idempotent — a no-op if the frame was never held or the pin was
 *  already released. The ring decrement is release-ordered, so it, and
 *  everything this handler step did with the frame's bytes before it, is
 *  visible to a racing compaction check the instant it observes either.
 *
 *  Sealed case: the pin is a hold on the codec's cleartext buffer. A codec a
 *  @c proto_switch fence destroyed while this handler was parked on it leaves
 *  the buffer to this release, which frees it as the last holder.
 */
static void s_hctx_hold_release(duct_stream_ctx_t *hctx)
{
    if (hctx->frame.payload.data) {
        switch (hctx->ack.kind) {
        case ack_ring:
            auto c = duct_conn_by_handle(duct_session_conn_at(hctx->s, hctx->conn_id));
            auto rx = c ? duct_conn_rx_olb(c) : nullptr;
            if (rx)
                duct_discard duct_atomic_fetch(sub, &rx->held_frames, 1u, release);
            break;
        case ack_ct:
            s_ct_pin_release(duct_conn_by_handle(duct_session_conn_at(hctx->s, hctx->conn_id)),
                             hctx->ack.ct.data);
            break;
        case ack_owned:
            duct_del(hctx->ack.owned.ptr);
            break;
        case ack_slot:
            duct_io_rx_slot_drop(hctx->ack.slot.pool, hctx->ack.slot.idx, true);
            break;
        default:
            duct_unreachable();
        }
    }
    hctx->frame = (duct_frame_t){};
    hctx->frame_acked = false;
}

/** @brief Full release: ack then drop the pin in one step —
 *  the normal (non-retry) disposition once a handler step is truly done
 *  with its held frame (wait / done / immediate terminal failure).
 */
static void s_hctx_rx_ack(duct_stream_ctx_t *hctx)
{
    s_hctx_rx_ack_only(hctx);
    s_hctx_hold_release(hctx);
}

/** @brief True when @p conn's leg round-trips fl_frame_fin and fl_frame_rst.
 *  A null @p conn and a leg with no wire both answer false. */
static bool s_conn_carries_frame_flags(const duct_conn_t *conn)
{
    return conn && conn->wire && duct_has(conn->wire->flags, fl_wire_frame_flags);
}

/** @brief True when @p conn's leg can carry a control frame naming @p sid.
 *  Stream 0 is connection-level and needs no id on the wire, so a
 *  length-prefix leg stays a valid target for it. */
static bool s_conn_can_send_fin(const duct_conn_t *conn, duct_stream_id_t sid)
{
    return s_conn_carries_frame_flags(conn)
        && (sid == 0u || duct_has(conn->wire->flags, fl_wire_stream_ids));
}

/** @brief True when @p conn has somewhere to stage a standalone control frame.
 *  A per-conn TX ring on the shapes that own one, and for @c x_udp_shared the
 *  listener's outbox its data already rides. @c x_inter has neither: a device
 *  leg carries no peer and no framing.
 */
static bool s_conn_ctl_stageable(const duct_conn_t *conn)
{
    return duct_conn_tx_olb(conn) || conn->xport_type == x_udp_shared;
}

/** @brief Terminal-failure stream disposition: close_internal_error if the
 *  session's proto is still live, otherwise just drop the slot's handler_ctx
 *  link (the session already tore down around this handler). Tells the peer
 *  before tearing down locally: an RST where the leg can carry one for this
 *  stream, otherwise the whole conn closes — a leg that cannot say "this
 *  stream only" leaves nothing between silence and taking the rest of the
 *  conn's streams down with it.
 *
 *  Checks @ref s_conn_can_send_fin directly; sends RST if supported, or
 *  closes the connection.
 */
static void s_hctx_stream_fail(duct_session_t *s, duct_stream_ctx_t *hctx)
{
    auto slot = duct_session_stream_slot(s, hctx->stream_id);
    if (slot && s->proto) {
        auto conn = duct_conn_by_handle(duct_session_conn_at(s, hctx->conn_id));
        if (s_conn_can_send_fin(conn, hctx->stream_id))
            s_ctl_send_fin(s, hctx->conn_id, hctx->stream_id, fl_frame_rst,
                           stream_err_internal);
        else
            duct_discard duct_conn_close(s, hctx->conn_id, close_internal_error);
        duct_session_stream_teardown(s, slot, close_internal_error);
    } else if (slot)
        slot->handler_ctx = nullptr;
}

/** @brief Normal-completion stream disposition. */
static void s_hctx_stream_done(duct_session_t *s, duct_stream_ctx_t *hctx)
{
    auto slot = duct_session_stream_slot(s, hctx->stream_id);
    if (slot)
        duct_session_stream_teardown(s, slot, close_normal);
}

/* Word-wise compare against duct_response_reset's own state: a step that
 * yielded without writing out leaves it byte-identical to the template, and
 * the whole emit turn (commit preamble, control walk, re-reset) is then a
 * no-op -- a polling ingest step yields empty at spin rates, where that
 * walk sits on every pass. A false "dirty" verdict
 * (e.g. a compiler leaving compound-literal padding unzeroed) only takes
 * the ordinary path. */
static const duct_response_t s_response_clean = { .control.stream_op_conn_id = duct_conn_id_same };

static_assert(sizeof(duct_response_t) % sizeof(uint64_t) == 0u, "word-wise response compare");

static inline bool s_response_is_clean(const duct_response_t *out)
{
    auto a = (const unsigned char *)out;
    auto b = (const unsigned char *)&s_response_clean;
    uint64_t diff = 0u;
    for (size_t i = 0u; i < sizeof *out; i += sizeof(uint64_t)) {
        uint64_t x,
                 y;
        memcpy(&x, a + i, sizeof x);
        memcpy(&y, b + i, sizeof y);
        diff |= x ^ y;
    }
    return diff == 0u;
}

/** @brief Runtime-agnostic handler step completion: takes a yielded response,
 *  running on once it commits or parks and tearing the stream down when it
 *  fails, acks + parks a wait, or acks + tears down the stream on done. Shared by @ref
 *  s_hctx_async_done and @ref s_hctx_sf_resume, which only translate their
 *  own rc/state into a @ref duct_handler_event_t and act on the returned
 *  @ref duct_handler_outcome_t — rescheduling for run/park, releasing the
 *  coroutine for their own runtime on release.
 */
static duct_handler_outcome_t s_hctx_complete(duct_stream_ctx_t *hctx,
                                                 duct_handler_event_t event)
{
    auto s = hctx->s;
    switch (event) {
    case handler_event_emit:
        if (s_response_is_clean(&hctx->out)) {
            /* Empty yield: nothing to commit, apply, or reset. A pending
             * duct_proto_switch is imperative state outside out, so its
             * apply still runs. */
            s_response_drop(s, &hctx->out);
            return handler_outcome_run;
        }
        switch (s_response_take(s, &hctx->out, hctx->conn_id, hctx->stream_id, fl_frame_none,
                                nullptr, hctx)) {
        case commit_ok:
            duct_response_reset(&hctx->out);
            return handler_outcome_run;
        case commit_internal:
            duct_response_reset(&hctx->out);
            return handler_outcome_retry;
        default:
            s_hctx_rx_ack(hctx);
            s_hctx_stream_fail(s, hctx);
            duct_del(hctx);
            return handler_outcome_release;
        }
    case handler_event_wait:
        /* Ack deferred until handler parks — OLB won't compact past un-acked offset. */
        s_hctx_rx_ack(hctx);
        hctx->frame = (duct_frame_t){};
        return handler_outcome_park;
    default: /* handler_event_done */
        s_hctx_rx_ack(hctx);
        s_hctx_stream_done(s, hctx);
        duct_del(hctx);
        return handler_outcome_release;
    }
}

static void s_hctx_async_done(duct_async_t *co, duct_async_rc_t rc, void *ctx)
{
    auto hctx = (duct_stream_ctx_t *)ctx;
    auto w = s_this_worker;
    assert(w);
    auto cp = &w->coop;
    duct_handler_event_t event = rc == async_yield ? handler_event_emit :
                                 rc == async_wait  ? handler_event_wait :
                                                  handler_event_done;

    switch (s_hctx_complete(hctx, event)) {
    case handler_outcome_run:
        s_hctx_enqueue(cp, hctx, true);
        break;
    case handler_outcome_park:
        s_hctx_enqueue(cp, hctx, false);
        break;
    case handler_outcome_retry:
        /* Left unenqueued while tracked in w->retry_head until s_retry_drain
         * resumes it. */
        break;
    case handler_outcome_release:
        /* async_done: duct_coop_cycle releases after this callback returns.
         * emit-turned-failure: the step returned async_yield, not async_done, so
         * the drain loop will not release it — do it here. */
        if (event == handler_event_emit) {
            duct_async_queue_remove(&cp->async_queue, co);
            duct_async_release(&cp->async_pool, co);
        }
        break;
    }
}

static void s_hctx_sf_resume(duct_coro_t *co, void *ctx)
{
    auto hctx = (duct_stream_ctx_t *)ctx;
    auto w = s_this_worker;
    assert(w);
    auto cp = &w->coop;
    duct_handler_event_t event = co->state == coro_state_suspended ? handler_event_emit :
                                 co->state == coro_state_waiting  ? handler_event_wait :
                                                               handler_event_done;

    switch (s_hctx_complete(hctx, event)) {
    case handler_outcome_run:
    case handler_outcome_park:
        s_hctx_enqueue(cp, hctx, true); /* run inert on the co path, see s_hctx_enqueue's own doc */
        break;
    case handler_outcome_retry:
        /* Left unenqueued while tracked in w->retry_head until s_retry_drain
         * resumes it; co->state remains coro_state_suspended. */
        break;
    case handler_outcome_release:
        /* duct_coop_cycle destroys on coro_state_done; it already popped co off
         * the run queue before calling on_resume, so no queue_remove here. */
        co->state = coro_state_done;
        break;
    }
}

void duct_stream_cancel(duct_stream_ctx_t *hctx)
{
    duct_do_if(!hctx, return);
    /* Null off a worker thread: engine teardown reaches here from whichever
     * thread called duct_engine_destroy, through duct_sessions_reclaim_shutdown,
     * which forces conn_count to 0 and the state to closing so its own
     * s_session_maybe_fire_close runs the teardown that calls
     * duct_session_streams_destroy. The worker-owned retry list and coop queues
     * are already quiesced by then, so only the ctx needs releasing -- which is
     * why s_retry_clear drops a parked node without touching its hctx. */
    auto w = s_this_worker;
    /* Releases any pending RX frame hold retained by this handler context. */
    if (hctx->frame.payload.data && hctx->s)
        s_hctx_rx_ack(hctx);
    if (w) {
        s_retry_emit_discard(w, hctx);
        s_hctx_remove_release(&w->coop, hctx);
    }
    duct_del(hctx);
}

/** @brief Which TX-backpressure class an @c retry_node_t holds. */
typedef enum : uint8_t { retry_emit, retry_frame, retry_timer, retry_fin,
                         retry_dgram_tx, retry_engine, retry_close } retry_kind_t;

/** @brief Inbound buffer a parked payload points into: none, the inbound conn's
 *  RX ring, or the inbound sealed conn's cleartext buffer. */
typedef enum : uint8_t { alias_none, alias_ring, alias_ct } alias_t;

/** @brief Unified TX-backpressure retry node: one list and one drain for
 *  every class that parks work on a transient failure.
 *
 *  @c s_retry_drain is that drain, in list order; the classes are emit, frame
 *  and fin on a commit_internal failure, timer behind its session's parked
 *  timer output, dgram_tx on a full lane, engine for a codec's parked engine
 *  egress, and close for a close that follows its leg's parked
 *  output. emit re-resolves nothing at retry time, @c emit.hctx being a
 *  direct, still-live pointer, safe only under the lifetime invariant below.
 *  The rest carry a handle or token and re-resolve fresh each pass, since none
 *  has a per-stream owner to discard its node on teardown.
 *
 *  Lifetime invariant: every path that frees a @c duct_stream_ctx_t must
 *  first remove its emit node from this list, or @c s_retry_drain
 *  dereferences a dangling @c emit.hctx. Exactly two paths do:
 *  @ref duct_stream_cancel through @c s_retry_emit_discard, and this drain's
 *  own terminal branch, which consumes the node in place.
 */
typedef struct retry_node {
    struct retry_node *next;
    retry_kind_t       kind;
    uint32_t             attempt_epoch; /* s_retry_lap of the epoch of its last
                                         * attempt, 0 before the first. */
    union {
        /* A copy-mode payload is the node's own copy; a static or owned one
         * keeps pointing where it did. hctx's pin stays live until this node
         * resolves. See s_retry_emit_save. */
        struct { duct_stream_ctx_t *hctx;
                 duct_response_t out;
                 uint32_t ticket; } emit;
        /* pin: the inbound buffer the payload, uncopied, points into, for an
         * answer carrying its frame's ack or one s_retry_payload_own left in
         * place. ack_len is a carried ack's length, 0 for none; ack_end is its
         * ring end under alias_ring, ct_block the pinned buffer under alias_ct.
         * handle is the ticket-owning routed leg, re-resolve target and
         * fl_conn_tx_wait owner; rx_handle is the inbound leg the payload was
         * read from, meaningful only while pinned or carrying an ack. hold_of
         * is the conn whose dispatch parked the node, 0 for none. */
        struct { duct_conn_handle_t handle, rx_handle, hold_of; duct_stream_id_t sid;
                 duct_frame_flags_t flags; duct_response_t out; alias_t pin;
                 uint32_t ack_len,
                          ticket;
                 union { uint32_t ack_end; void *ct_block; }; } frame;
        struct { duct_handle_t tok; uint64_t token; duct_timer_handle_t self; uint32_t key; } timer;
        /* Bare control frame: no payload, so no ring pin and no ownership
         * to settle. Carries a handle and re-resolves like frame does, for
         * the same reason — no per-stream owner discards it on teardown —
         * and a hold_of as frame's. */
        struct { duct_conn_handle_t handle, hold_of; duct_stream_id_t sid;
                 duct_frame_flags_t flags; duct_stream_error_t err;
                 uint32_t ticket; } fin;
        /* Heap-allocated copy of datagram payload to outlive the pass arena.
         * listener is used after handle re-resolution. No subsequent worker
         * datagram leaves ahead of a parked one; dgram_parked gates flush and
         * commits while any is parked. */
        struct { duct_conn_handle_t handle; duct_listener_t *listener;
                 duct_peer_t peer; void *block; duct_view_u8 bytes;
                 duct_conn_id_t conn_id; duct_stream_id_t stream_id;
                 duct_send_flags_t flags; uintptr_t send_token; } dgram_tx;
        /* The conn whose codec's engine park holds bytes, and the wire
         * binding they were staged under: a rebind since drops the node. */
        struct { duct_conn_handle_t handle; uint8_t wire_epoch; } engine;
        /* A close of the leg that follows its output, its ticket taken behind
         * the leg's parked output: posted with its reason in that ticket's
         * turn, once the engine park flushed and the ring has room for the
         * close_notify the reason stages. */
        struct { duct_conn_handle_t handle; uint32_t ticket; duct_close_reason_t reason; } close;
    };
} retry_node_t;

static void s_retry_enqueue(duct_worker_t *w, retry_node_t *node);

/** @brief Hand @p h to a parked answer of @p owner's dispatch that still waits on its ticket.
 *  A frame or fin node matches by its @c hold_of, an emit node by the inbound
 *  conn of its stream; the first match in list order takes @p h.
 *  @return false when no answer of the dispatch is left waiting.
 */
static bool s_hold_adopt(const duct_session_t *s, duct_tx_hold_t *h, const duct_conn_t *owner)
{
    auto of = duct_conn_handle_get(owner);
    for (auto n = s_this_worker->retry_head; n; n = n->next) {
        duct_tx_hold_t waits = {};
        switch (n->kind) {
        case retry_frame:
            if (n->frame.hold_of.word == of.word)
                waits = (duct_tx_hold_t){ n->frame.handle.word, n->frame.ticket };
            break;
        case retry_fin:
            if (n->fin.hold_of.word == of.word)
                waits = (duct_tx_hold_t){ n->fin.handle.word, n->fin.ticket };
            break;
        case retry_emit:
            if (n->emit.hctx->s == s
                && duct_session_conn_at(s, n->emit.hctx->conn_id).word == of.word)
                waits = (duct_tx_hold_t){ duct_session_conn_at(s, n->emit.out.conn_id).word,
                                          n->emit.ticket };
            break;
        case retry_timer:
        case retry_dgram_tx:
        case retry_engine:
        case retry_close:
            break;
        }
        if (waits.leg != handle_null && s_tx_pending(s, waits.leg, waits.ticket)) {
            *h = waits;
            return true;
        }
    }
    return false;
}

/** @brief Capacity of @p codec's engine park on @p conn, bytes: two engine
 *  messages.
 *  One reply parked leaves room for a second in flight, and the unseal waits
 *  while the park has no room for one more. A sealed wire refuses a budget
 *  whose park the smallest TX ring cannot take whole. */
static size_t s_engine_park_cap(const duct_conn_t *conn, const duct_wire_codec_t *codec)
{
    return 2u * s_hs_need(conn, codec);
}

/** @brief Stage @p conn's parked engine bytes whole into its TX ring, ahead of
 *  every later byte.
 *  @return true once the park is empty; false while the ring has no room for
 *  all of it, the conn's TX-room wake armed. */
static bool s_engine_park_flush(duct_conn_t *conn)
{
    auto sc = duct_conn_sealed_ctx(conn);
    auto codec = sc ? sc->codec : nullptr;
    if (!codec || !codec->engine_park_len)
        return true;
    auto tx = duct_conn_tx_olb(conn);
    size_t n = codec->engine_park_len;
    if (!tx || duct_olb_tx_stage(tx, nullptr, 0u, duct_at(codec->engine_park), n) != olb_tx_ok) {
        s_tx_wait_arm(conn);
        return false;
    }
    codec->engine_park_len = 0u;
    duct_olb_tx_publish(tx);
    auto handle = duct_conn_handle_get(conn);
    duct_io_post_tx_drain(&handle);
    return true;
}

/** @brief Reserve @p len bytes at the end of @p codec's engine park.
 *  The park allocates at its first use, and bytes into an empty park queue a
 *  @c retry_engine node that flushes them once the ring frees; the conn's
 *  TX-room wake is armed.
 *  @return the span, nullptr when the park has no room or no memory. */
static uint8_t *s_engine_park_span(duct_conn_t *conn, duct_wire_codec_t *codec, size_t len)
{
    size_t cap = codec->engine_park ? duct_byte_len(codec->engine_park)
                                    : s_engine_park_cap(conn, codec);
    if (len > cap - codec->engine_park_len)
        return nullptr;
    if (!codec->engine_park) {
        codec->engine_park = duct_new(uint8_t, cap);
        if (!codec->engine_park)
            return nullptr;
    }
    if (!codec->engine_park_len) {
        auto node = duct_new(retry_node_t);
        if (!node)
            return nullptr;
        *node = (retry_node_t){
            .kind = retry_engine,
            .engine = { .handle = duct_conn_handle_get(conn), .wire_epoch = conn->wire_epoch },
        };
        s_retry_enqueue(s_this_worker, node);
    }
    auto span = duct_at(codec->engine_park) + codec->engine_park_len;
    codec->engine_park_len += (uint32_t)len;
    s_tx_wait_arm(conn);
    return span;
}

/** @brief Drop the pin a parked @c retry_frame node holds on its inbound buffer.
 *  A ring pin resolves @c node->frame.rx_handle, not its @c handle: the pin was
 *  taken against the leg the payload was read from, which routing can make a
 *  different one from the leg that owns the ticket. A cleartext pin drops its
 *  hold on the buffer whether that leg resolves or not. Resets @c pin, so a
 *  second call on a node kept voided does nothing.
 */
static void s_retry_frame_pins_release(retry_node_t *node)
{
    switch (node->frame.pin) {
    case alias_ring:
        auto rx_conn = duct_conn_by_handle(node->frame.rx_handle);
        auto rx = rx_conn ? duct_conn_rx_olb(rx_conn) : nullptr;
        if (rx)
            duct_discard duct_atomic_fetch(sub, &rx->held_frames, 1u, release);
        break;
    case alias_ct:
        s_ct_pin_release(duct_conn_by_handle(node->frame.rx_handle), node->frame.ct_block);
        break;
    case alias_none:
        break;
    }
    node->frame.pin = alias_none;
}

/** @brief End a parked @c retry_frame node: land the frame ack it carries, then
 *  drop its pin.
 *  The ack lands whether the answer published, failed or lost its leg; an
 *  inbound leg gone since took its ring with it. */
static void s_retry_frame_done(retry_node_t *node)
{
    if (node->frame.ack_len) {
        auto rx = duct_conn_by_handle(node->frame.rx_handle);
        if (rx && duct_conn_rx_olb(rx))
            s_frame_ack_apply(rx, node->frame.pin == alias_ring
                ? (duct_frame_ack_t){ .kind = ack_ring,
                                      .ring = { node->frame.ack_len, node->frame.ack_end } }
                : (duct_frame_ack_t){ .kind = ack_ct,
                                      .ct = { node->frame.ct_block, node->frame.ack_len } });
        node->frame.ack_len = 0u;
    }
    s_retry_frame_pins_release(node);
}

/** @brief Release @p out's owned payload and leave it holding none: no owner flag, no release hook.
 *  The send-done flag and token stay.
 */
static void s_response_void_payload(duct_response_t *out)
{
    duct_response_release_owned(out);
    out->payload = (duct_view_u8){};
    out->flags = duct_and(out->flags, duct_not(fl_send_owned));
    out->release = nullptr;
    out->release_arg = nullptr;
}

/** @brief Empty a parked @c retry_frame node in place: land its carried ack,
 *  drop its pin and release its payload.
 *  Its ticket stays for the drain to resolve in turn, and its frame flags
 *  clear, so no fin or rst follows; a second call does nothing. */
static void s_retry_frame_void(retry_node_t *node)
{
    s_retry_frame_done(node);
    s_response_void_payload(&node->frame.out);
    node->frame.out.flags = (duct_send_flags_t)0;
    node->frame.flags = fl_frame_none;
}

/** @brief Debug-only: true if @p hctx already has an emit node parked in
 *  @p w's retry list. Backs the single-membership assert in @ref
 *  s_retry_emit_save; compiled away with NDEBUG, so the O(n) scan costs
 *  nothing in release builds.
 */
[[maybe_unused]] static bool s_retry_has_emit(const duct_worker_t *w, const duct_stream_ctx_t *hctx)
{
    for (auto n = w->retry_head; n; n = n->next)
        if (n->kind == retry_emit && n->emit.hctx == hctx)
            return true;
    return false;
}

/** @brief Append @p node to @p w's retry FIFO tail — O(1), the rest of
 *  the queue untouched. Oldest-first drain order, matching insertion.
 */
static void s_retry_enqueue(duct_worker_t *w, retry_node_t *node)
{
    node->next = nullptr;
    if (w->retry_tail)
        w->retry_tail->next = node;
    else
        w->retry_head = node;
    w->retry_tail = node;
}

/** @brief Park one packed @c x_udp_shared datagram whose outbox-lane reserve
 *  failed at flush time.
 *
 *  The bytes are copied out of the dying pass arena into an owned buffer and
 *  retried by @c s_retry_drain until the lane has room again; send_done and
 *  on_error for the entry are deferred to the node's own resolution.
 *  @return false only when the copy allocation itself fails; the caller keeps
 *  its terminal-drop accounting for that. */
static bool s_retry_dgram_tx_save(duct_worker_t *w, const duct_worker_dgram_batch_entry_t *e,
                                  duct_listener_t *listener, uint8_t *bytes)
{
    auto node = duct_new(retry_node_t);
    duct_do_if(!node, return false);
    if (!e->hdr_len && !s_tx_pool_owns(&w->tx_pool, bytes)) {
        node->dgram_tx.block = duct_share(e->block);
        node->dgram_tx.bytes = (duct_view_u8){ .data = bytes, .size = e->len };
    } else {
        size_t total = (size_t)e->hdr_len + e->len;
        auto data = duct_new(uint8_t, total);
        duct_do_if(!data, duct_del(node); return false);
        auto copy = duct_at(data);
        if (e->hdr_len)
            memcpy(copy, e->hdr, e->hdr_len);
        memcpy(copy + e->hdr_len, bytes, e->len);
        node->dgram_tx.block = copy;
        node->dgram_tx.bytes = (duct_view_u8){ .data = copy, .size = total };
    }
    node->kind = retry_dgram_tx;
    node->dgram_tx.handle = e->handle;
    node->dgram_tx.listener = listener;
    node->dgram_tx.peer = e->peer;
    node->dgram_tx.conn_id = e->conn_id;
    node->dgram_tx.stream_id = e->stream_id;
    node->dgram_tx.flags = e->flags;
    node->dgram_tx.send_token = e->send_token;
    s_retry_enqueue(w, node);
    ++w->dgram_parked;
    duct_rtstat_obj_inc(w, rtstats.retry_saved, 1);
    return true;
}

/** @brief Reserve @p entry_bytes on @p ln, this worker's @c dgram_tx_outbox
 *  lane, armed for the drain's wake on a refusal.
 *  @ref duct_vmq_reserve_armed carries the protocol.
 *  @return null with @p *out_rc carrying the failing attempt's cause.
 */
static duct_dgram_tx_entry_t *
s_dgram_tx_lane_reserve(const duct_vmq_lane_t *ln, size_t entry_bytes,
                        duct_vmq_reserve_pos_t *out_pos, duct_vmq_push_rc_t *out_rc)
{
    return (duct_dgram_tx_entry_t *)
        duct_vmq_reserve_armed(ln, dgram_tx_msg, 0u, entry_bytes, out_pos, out_rc);
}

/** @brief Release of a pinned answer: drop its claim on the RX slot and free the pin. */
static void s_slot_pin_drop(void *arg)
{
    auto pin = (duct_frame_ack_t *)arg;
    duct_io_rx_slot_drop(pin->slot.pool, pin->slot.idx, true);
    duct_del(pin);
}

/** @brief Pin the payload of a parked answer that lies in the RX slot @p slot, in place of a copy.
 *  Takes a claim on the slot and hands it to the answer as its release, so the slot stays out of the
 *  pool until the answer resolves. The copy path stays for a null slot, a payload that is empty, owned
 *  or static, one that does not lie wholly inside the slot, a failed allocation and a claim past the
 *  pool's bound.
 *  @return true when the answer is pinned.
 */
static bool s_slot_pin(duct_response_t *out, const duct_frame_ack_t *slot)
{
    if (!slot || !out->payload.data
        || duct_has(out->flags, duct_or(fl_send_owned, fl_send_static)))
        return false;
    auto pool = slot->slot.pool;
    auto at = (const char *)out->payload.data;
    auto end = (const char *)duct_x_slot_data(pool, slot->slot.idx) + pool->slot_bytes;
    if (!duct_x_slot_holds(pool, slot->slot.idx, at) || out->payload.size > (size_t)(end - at))
        return false;
    auto pin = duct_new(duct_frame_ack_t);
    if (!pin)
        return false;
    if (!duct_x_slot_claim(pool, slot->slot.idx)) {
        duct_del(pin);
        return false;
    }
    *pin = *slot;
    out->flags = duct_or(out->flags, fl_send_owned);
    out->release = s_slot_pin_drop;
    out->release_arg = pin;
    return true;
}

/** @brief Backpressure-hit commit save, as a retry_emit node in @p w's
 *  unified retry list.
 *
 *  Acks @p hctx's frame for flow control and leaves its pin up: the
 *  park comes from an @c async_yield, and the resumed handler reads the same
 *  frame through @ref duct_stream_frame until it answers @c async_wait or
 *  @c async_done, which drop it; @ref s_retry_drain drops it only where the
 *  retry fails outright. A payload inside the frame's owned copy rides a share
 *  of it and one inside its claimed RX slot is pinned by @ref s_slot_pin; any
 *  other copy-mode payload is copied through @ref s_retry_payload_own, a failed
 *  copy leaving it in place, valid while the handler is suspended, and a TX-pool
 *  payload is abandoned instead. The park holds the stream's inbound conn: its
 *  hold takes the emit's ticket on the routed leg.
 *  @p hctx->out parks as the handler left it otherwise: @ref s_commit_response
 *  skips releasing an @c fl_send_owned buffer on @c commit_internal, and an
 *  early release here leaves the deferred retry staging freed bytes.
 *
 *  @return false when the node or a TX-pool payload's copy finds no memory:
 *          ticket abandoned, owned payload released, @c rc_again through on_send_done.
 */
static bool s_retry_emit_save(duct_worker_t *w, duct_stream_ctx_t *hctx, uint32_t ticket)
{
    assert(!s_retry_has_emit(w, hctx)); /* single-membership: a parked coro cannot step again */
    auto s = hctx->s;
    auto at = (const char *)hctx->out.payload.data;
    auto base = (const char *)hctx->ack.owned.ptr;
    if (hctx->ack.kind == ack_owned && base && at
        && !duct_has(hctx->out.flags, duct_or(fl_send_owned, fl_send_static))
        && at >= base && (size_t)(at - base) <= hctx->frame.payload.size
        && hctx->out.payload.size <= hctx->frame.payload.size - (size_t)(at - base)) {
        hctx->out.release_arg = duct_share(hctx->ack.owned.ptr);
        hctx->out.release = nullptr;
        hctx->out.flags = duct_or(hctx->out.flags, fl_send_owned);
    } else if (hctx->ack.kind == ack_slot)
        duct_discard s_slot_pin(&hctx->out, &hctx->ack);
    auto owned = hctx->out.payload.data ? s_retry_payload_own(&hctx->out) : own_kept;
    auto node = owned == own_failed && s_tx_pool_owns(&w->tx_pool, hctx->out.payload.data)
              ? nullptr : duct_new(retry_node_t);
    if (!node) {
        s_commit_ticket_abandon(duct_conn_by_handle(duct_session_conn_at(s, hctx->out.conn_id)),
                                ticket, &hctx->out);
        s_fire_send_done(s, duct_proto_cfg_of(s->proto), hctx->out.conn_id, hctx->stream_id,
                         &hctx->out, rc_again);
        return false;
    }
    *node = (retry_node_t){
        .kind = retry_emit,
        .emit = { .hctx = hctx, .out = hctx->out, .ticket = ticket },
    };
    s_retry_enqueue(w, node);
    auto rx_conn = duct_conn_by_handle(duct_session_conn_at(s, hctx->conn_id));
    if (rx_conn)
        *s_conn_tx_hold(rx_conn) = (duct_tx_hold_t){
            duct_session_conn_at(s, hctx->out.conn_id).word, ticket };
    s_hctx_rx_ack_only(hctx);
    duct_rtstat_obj_inc(w, rtstats.retry_saved, 1);
    return true;
}

/** @brief Copy a copy-mode payload into a buffer the response itself owns.
 *
 *  A parked response waits on TX room with no bound, so a payload left
 *  aliasing a receive buffer holds that buffer for the same stretch — which
 *  on the RX ring blocks compaction and stops the conn reading for every
 *  other stream — and one left aliasing author memory outlives the callback
 *  that lent it. Re-flagged @c fl_send_owned with @c release and @c release_arg
 *  cleared, so the default release frees the copy exactly once, on whichever
 *  terminal outcome the retry resolves to. Both savers and the conn-lost
 *  discard take it.
 *
 *  @p out carries a payload — the caller tests that to decide whether the
 *  alias question arises at all.
 *  @return @c own_copied once the response owns the copy, @c own_kept for a
 *  payload it already owns or declares static, @c own_failed when the
 *  allocation fails, the payload then staying where it was.
 */
static own_t s_retry_payload_own(duct_response_t *out)
{
    assert(out->payload.data);
    /* A pooled payload copies whatever its flags say: the region's own hold
     * ends with the pass that took it, and a parked node outlives that. */
    bool pooled = s_this_worker
               && s_tx_pool_owns(&s_this_worker->tx_pool, out->payload.data);
    if (!pooled && duct_has(out->flags, duct_or(fl_send_owned, fl_send_static)))
        return own_kept;
    auto copy = duct_new(uint8_t, out->payload.size);
    duct_do_if(!copy, return own_failed);
    memcpy(copy, out->payload.data, out->payload.size);
    out->payload.data = duct_at(copy);
    out->flags = duct_or(out->flags, fl_send_owned);
    out->release = nullptr;
    out->release_arg = nullptr;
    return own_copied;
}

/** @brief Classify @p p against RX ring @p rx and @p codec's cleartext buffer,
 *  either of them null for none, as is a codec that has no buffer. */
static alias_t s_rx_alias(const duct_olb_rx_t *rx, const duct_wire_codec_t *codec,
                            const void *p)
{
    ptrdiff_t delta = rx ? (const uint8_t *)p - rx->data : -1;
    if (delta >= 0 && (size_t)delta < rx->h.buf_size)
        return alias_ring;
    delta = codec && codec->ct_buf ? (const uint8_t *)p - duct_at(codec->ct_buf) : -1;
    return delta >= 0 && (size_t)delta < duct_byte_len(codec->ct_buf) ? alias_ct : alias_none;
}

/** @brief Backpressure-hit response save, as a retry_frame node in @p w's
 *  unified retry list.
 *
 *  @p frame_flags replays the inbound frame's flags into a post-retry fin or
 *  rst, none where no frame came in. The ticket's leg comes from
 *  @c out->conn_id, routing being free to answer a leg other than the inbound
 *  one at @p conn_id the payload was read on, which it stands in for out of
 *  range or gone. The node writes @c w->hold_into's hold and records
 *  @c w->hold_conn's handle as its @c hold_of. An answer lying in the RX slot of
 *  the batch in dispatch, @c w->slot_now, is pinned by @ref s_slot_pin. One
 *  aliasing the frame in dispatch stays uncopied
 *  and takes over its ack from @c w->rx_ack, landing it as the answer resolves;
 *  any other payload @ref s_retry_payload_own copies, an alias staying where it
 *  declines or the copy fails. An alias pins the inbound rx ring's held_frames
 *  or the sealed codec's cleartext buffer, released by @ref s_retry_frame_done.
 *  A torn-down conn drops the node at retry: a ring pin stays unreleased, a
 *  cleartext pin is released and the last release frees the buffer.
 *  @return false on allocation failure, of the node or of a copy no pin covers:
 *          ticket abandoned, owned payload released, @c rc_again reported.
 */
static bool s_retry_frame_save(duct_worker_t *w, duct_session_t *s, duct_conn_id_t conn_id,
                               duct_stream_id_t stream_id, duct_frame_flags_t frame_flags,
                               duct_response_t *out, uint32_t ticket)
{
    auto conn = duct_conn_by_handle(duct_session_conn_at(s, out->conn_id));
    assert(conn);
    auto rx_conn = conn_id < duct_session_max_legs
                 ? duct_conn_by_handle(duct_session_conn_at(s, conn_id)) : nullptr;
    if (!rx_conn)
        rx_conn = conn;
    auto handle = duct_conn_handle_get(conn);
    auto rx = duct_conn_rx_olb(rx_conn);
    auto sc = duct_conn_sealed_ctx(rx_conn);
    auto codec = sc ? sc->codec : nullptr;
    alias_t alias = out->payload.data ? s_rx_alias(rx, codec, out->payload.data) : alias_none;
    if (alias == alias_none)
        duct_discard s_slot_pin(out, w->slot_now);
    auto ack = w->rx_ack;
    bool carry = ack && !duct_has(out->flags, duct_or(fl_send_owned, fl_send_static))
              && (alias == alias_ring ? ack->kind == ack_ring
                  : alias == alias_ct && ack->kind == ack_ct && ack->ct.data == duct_at(codec->ct_buf));
    auto owned = out->payload.data && !carry ? s_retry_payload_own(out) : own_kept;
    auto node = owned == own_failed && alias == alias_none ? nullptr : duct_new(retry_node_t);
    if (!node) {
        s_commit_ticket_abandon(conn, ticket, out);
        s_fire_send_done(s, duct_proto_cfg_of(s->proto), out->conn_id, stream_id, out, rc_again);
        return false;
    }
    alias_t pin = owned == own_copied ? alias_none : alias;
    *node = (retry_node_t){
        .kind = retry_frame,
        .frame = { .handle = handle, .rx_handle = duct_conn_handle_get(rx_conn),
                   .hold_of = w->hold_conn ? duct_conn_handle_get(w->hold_conn) : conn_handle_null,
                   .sid = stream_id, .flags = frame_flags,
                   .out = *out, .pin = pin, .ticket = ticket },
    };
    switch (pin) {
    case alias_ring:
        duct_discard duct_atomic_fetch(add, &rx->held_frames, 1u, release);
        node->frame.ack_len = carry ? (uint32_t)ack->ring.task_len : 0u;
        node->frame.ack_end = carry ? ack->ring.end_off : 0u;
        break;
    case alias_ct:
        node->frame.ct_block = duct_share(codec->ct_buf);
        node->frame.ack_len = carry ? (uint32_t)ack->ct.size : 0u;
        break;
    case alias_none:
        break;
    }
    if (carry)
        w->rx_ack = nullptr;
    s_retry_enqueue(w, node);
    if (w->hold_into)
        *w->hold_into = (duct_tx_hold_t){ handle.word, ticket };
    duct_rtstat_obj_inc(w, rtstats.retry_saved, 1);
    return true;
}

/** @brief Blocked FIN/RST save, as a retry_fin node in @p w's unified retry
 *  list.
 *
 *  Re-resolved fresh via @c handle at retry time, like @ref
 *  s_retry_frame_save; a conn gone by then drops the node, its ticket dying
 *  with the OLB that issued it. The node writes @c w->hold_into's hold and
 *  records @c w->hold_conn's handle as its @c hold_of.
 *
 *  @return false on allocation failure — @p ticket is then still outstanding
 *  and the caller must resolve it, or every later commit on this OLB waits
 *  on one that never publishes.
 */
static bool s_retry_fin_save(duct_worker_t *w, duct_conn_t *conn,
                             duct_stream_id_t stream_id,
                             duct_frame_flags_t flags, duct_stream_error_t err,
                             uint32_t ticket)
{
    auto node = duct_new(retry_node_t);
    if (!node)
        return false;
    *node = (retry_node_t){
        .kind = retry_fin,
        .fin = { .handle = duct_conn_handle_get(conn),
                 .hold_of = w->hold_conn ? duct_conn_handle_get(w->hold_conn) : conn_handle_null,
                 .sid = stream_id, .flags = flags, .err = err, .ticket = ticket },
    };
    s_retry_enqueue(w, node);
    if (w->hold_into)
        *w->hold_into = (duct_tx_hold_t){ node->fin.handle.word, ticket };
    duct_rtstat_obj_inc(w, rtstats.retry_saved, 1);
    return true;
}

/** @brief Blocked on_timer-fire save, as a retry_timer node in @p w's
 *  unified retry list.
 *
 *  Re-resolved fresh via @c session_tok at retry time (@ref s_retry_drain),
 *  same rationale as @ref s_retry_frame_save. The node carries the fire's key
 *  and timer handle, so a fire whose key slot no longer holds that timer drops
 *  at retry. The fire waits on its session's @c timer_hold: the parked output
 *  it names arms the leg's TX-room wake at each attempt, and resolving it is
 *  progress that brings this node another one.
 *  @return false on node-OOM: the fire is lost.
 */
static bool s_retry_timer_save(duct_worker_t *w, const timer_ctx_t *ctx)
{
    auto node = duct_new(retry_node_t);
    if (!node)
        return false;
    *node = (retry_node_t){
        .kind = retry_timer,
        .timer = { .tok = ctx->session_tok, .token = ctx->token, .self = ctx->self,
                   .key = ctx->key },
    };
    s_retry_enqueue(w, node);
    duct_rtstat_obj_inc(w, rtstats.retry_saved, 1);
    return true;
}

/** @brief Test whether @p conn's ring takes its close for @p reason behind
 *  every byte staged before it.
 *  Flushes the engine park first and wants room for one engine message where
 *  @ref s_notify_codec names a @c close_notify; a false answer has the conn's
 *  TX-room wake armed. */
static bool s_close_ready(duct_conn_t *conn, duct_close_reason_t reason)
{
    if (!s_engine_park_flush(conn))
        return false;
    auto codec = s_notify_codec(conn, reason);
    return !codec || duct_worker_admit_leg(duct_conn_handle_get(conn), s_hs_need(conn, codec));
}

/** @brief Park @p conn's close for @p reason as a @c retry_close node on a
 *  ticket of its own, behind every ticket the conn has issued.
 *  @return false when no node is to be had, nothing taken. */
static bool s_retry_close_save(duct_worker_t *w, duct_conn_t *conn, duct_close_reason_t reason)
{
    auto node = duct_new(retry_node_t);
    if (!node)
        return false;
    uint32_t ticket = duct_tx_ticket_fresh;
    duct_discard s_tx_ticket_take(s_tx_seq_of(conn), &ticket);
    *node = (retry_node_t){
        .kind = retry_close,
        .close = { .handle = duct_conn_handle_get(conn), .ticket = ticket, .reason = reason },
    };
    s_retry_enqueue(w, node);
    duct_rtstat_obj_inc(w, rtstats.retry_saved, 1);
    return true;
}

/* Reused from WFQ's own per-pass frame quota, same idiom as the frame-rx
 * batch byte budget. */
static constexpr unsigned retry_drain_quota = 64u;

/** @brief Mark of an attempt in retry epoch @p epoch.
 *  Always odd, so a node never attempted, its mark 0, never matches one. */
static inline uint32_t s_retry_lap(uint32_t epoch)
{
    return epoch << 1u | 1u;
}

/** @brief Unified TX-backpressure retry pass, every node kind.
 *
 *  @c retry_node_t carries the node shape and the cross-class invariants.
 *  retry_emit keeps its live hctx: success resumes the coroutine, a terminal
 *  failure tears down as the immediate path does, minus the RX ack its save
 *  made. retry_frame and retry_fin re-resolve conn and session fresh: a frame
 *  replays through @ref s_response_retry, and one an RST voided, or either
 *  kind whose session is gone, resolves its ticket in turn and ends there, a
 *  gone conn taking its ticket with it; every frame's end lands the ack it
 *  carries. A retry_timer drops with its session or its key slot's timer and
 *  waits while the session's @c timer_hold stands. retry_engine flushes its
 *  conn's park whole, and retry_close posts its close in its ticket's turn.
 *
 *  A frame, fin or emit attempt arms its leg's TX-room wake first, see
 *  @ref s_tx_wait_arm, and a park flush or a close's room check on failing; a
 *  save arms nothing, the attempt later in the same pass does.
 *
 *  @return true if any node resolved, success or terminal, or the quota ended
 *  the lap with nodes untried; either way another pass has work.
 */
static duct_nonnull(1) bool s_retry_drain(duct_worker_t *w)
{
    if (!w->retry_head)
        return false;
    bool progress = false;
    uint32_t epoch = duct_atomic_load(&w->retry_epoch, acquire);
    /* One attempt per node already queued at entry up to budget; re-enqueued
     * nodes yield to subsequent passes. */
    auto stop_after = w->retry_tail;
    /* A datagram the lane refuses keeps every later one of this lap parked. */
    bool dgram_blocked = false;
    for (unsigned budget = retry_drain_quota; budget && w->retry_head; --budget) {
        auto node = w->retry_head;
        bool last_of_lap = node == stop_after;
        w->retry_head = node->next;
        if (!w->retry_head)
            w->retry_tail = nullptr;
        node->next = nullptr;
        node->attempt_epoch = s_retry_lap(epoch);
        bool keep = false;
        switch (node->kind) {
        case retry_engine: {
            auto conn = duct_conn_by_handle(node->engine.handle);
            auto session = conn ? duct_session_by_conn(conn) : nullptr;
            if (conn && conn->wire_epoch != node->engine.wire_epoch)
                conn = nullptr;
            if (conn && !s_engine_park_flush(conn)) {
                keep = true;
                break;
            }
            duct_del(node);
            /* This engine output may have been the switch's last barrier. */
            if (session)
                s_response_switch(session);
            progress = true;
            break;
        }
        case retry_close:
            auto close_conn = duct_conn_by_handle(node->close.handle);
            if (close_conn) {
                auto cseq = s_tx_seq_of(close_conn);
                if (*cseq.serve != node->close.ticket || !s_close_ready(close_conn, node->close.reason)) {
                    keep = true;
                    break;
                }
                s_close_notify(close_conn, node->close.reason);
                s_tx_ticket_resolve(cseq);
                duct_io_post_close_request(&node->close.handle, node->close.reason);
            }
            auto close_s = close_conn ? duct_session_by_conn(close_conn) : nullptr;
            progress = true;
            duct_del(node);
            if (close_s)
                s_response_switch(close_s);
            break;
        case retry_emit:
            auto hctx = node->emit.hctx;
            auto s = hctx->s;
            auto emit_ticket = node->emit.ticket;
            /* node->emit.out.conn_id, not hctx->conn_id: s_commit_response
             * already route-resolved the real target leg, which a multiplexed
             * emit's round-robin routing can differ from. */
            auto emit_conn = duct_conn_by_handle(duct_session_conn_at(s, node->emit.out.conn_id));
            if (emit_conn)
                s_tx_wait_arm(emit_conn);
            auto c_rc = s_response_retry(s, &node->emit.out, hctx->conn_id, hctx->stream_id,
                                         fl_frame_none, &emit_ticket);
            if (c_rc == commit_internal) {
                keep = true;
                break;
            }
            progress = true;
            if (c_rc == commit_ok) {
                /* Frame and pin survive: the handler parked on an async_yield
                 * and reads duct_stream_frame again on the step this queues.
                 * Its own async_wait or async_done drops them. */
                s_hctx_enqueue(&w->coop, hctx, true);
            } else {
                s_hctx_hold_release(hctx);
                s_hctx_stream_fail(s, hctx);
                duct_del(hctx);
            }
            duct_del(node);
            break;
        case retry_frame:
            duct_conn_t *conn;
            bool live = s_dispatch_resolve(node->frame.handle, &conn, &s) == res_ok;
            if (!live)
                s_retry_frame_void(node);
            if (!live || node->frame.out.payload.size == 0u) {
                if (!s_tx_ticket_pass(conn, node->frame.ticket)) {
                    keep = true;
                    break;
                }
                progress = true;
                if (live) {
                    s_response_settle(s, &node->frame.out, node->frame.sid, node->frame.flags);
                    s_response_switch(s);
                }
                duct_del(node);
                break;
            }
            auto cid = duct_session_conn_id_by_handle(s, node->frame.handle);
            auto frame_ticket = node->frame.ticket;
            s_tx_wait_arm(conn);
            c_rc = s_response_retry(s, &node->frame.out, cid, node->frame.sid, node->frame.flags,
                                    &frame_ticket);
            if (c_rc == commit_internal) {
                keep = true;
                break;
            }
            progress = true;
            /* Resolved (success or terminal) — s_commit_response's own
             * cleanup already advanced conn->tx_buf->tx_seq_serve past this
             * ticket; nothing to clear here explicitly. */
            s_retry_frame_done(node);
            duct_del(node);
            break;
        case retry_fin:
            duct_conn_t *fin_conn;
            if (s_dispatch_resolve(node->fin.handle, &fin_conn, &s) != res_ok) {
                if (!s_tx_ticket_pass(fin_conn, node->fin.ticket)) {
                    keep = true;
                    break;
                }
                progress = true;
                duct_del(node);
                break;
            }
            uint32_t fin_ticket = node->fin.ticket;
            s_tx_wait_arm(fin_conn);
            auto fin_st = s_ctl_fin_stage(fin_conn, s, node->fin.sid, node->fin.flags,
                                          node->fin.err, &fin_ticket);
            if (fin_st == olb_tx_full) {
                /* The ticket is unchanged: only a fresh one is ever minted,
                 * and this node's was minted at save. */
                keep = true;
                break;
            }
            progress = true;
            if (fin_st != olb_tx_ok && s->proto)
                s_fire_error(s, duct_proto_cfg_of(s->proto), rc_invalid_arg);
            s_response_switch(s);
            duct_del(node);
            break;
        case retry_timer:
            auto stok = (duct_session_handle_t){ .word = node->timer.tok };
            s = duct_session_attached_by_handle(stok);
            auto cfg = s && s->proto ? duct_proto_cfg_of(s->proto) : nullptr;
            bool fresh = s && (!node->timer.key || s_timer_key_held(s, node->timer.key, node->timer.self)),
                 due = fresh && cfg && cfg->on_timer;
            if (due && s_tx_held(s, &s->timer_hold, nullptr)) {
                keep = true;
                break;
            }
            progress = true;
            if (fresh)
                s_timer_key_spend(w, s, node->timer.key, node->timer.self);
            if (due)
                s_timer_invoke(s, cfg, node->timer.token);
            duct_del(node);
            break;
        case retry_dgram_tx: {
            auto dconn = duct_conn_by_handle(node->dgram_tx.handle);
            if (!dconn) {
                /* Conn/session closed while parked -- same silent-drop
                 * discipline as the flush's own dead-handle case. */
                duct_del(node->dgram_tx.block);
                duct_del(node);
                --w->dgram_parked;
                progress = true;
                break;
            }
            if (dgram_blocked) {
                keep = true;
                break;
            }
            /* Pre-arm ahead of the reserve below; the post-write kick
             * after publish stays the race backstop. */
            duct_io_post_dgram_tx(node->dgram_tx.listener);
            size_t parked = node->dgram_tx.bytes.size;
            duct_vmq_push_rc_t drc;
            dgram_out_t dout;
            bool staged = s_dgram_out_open(node->dgram_tx.listener, &node->dgram_tx.peer,
                                           parked, &dout, &drc);
            if (!staged && drc == vmq_push_too_large) {
                /* Terminal: this entry can never fit the lane at all --
                 * unreachable for any datagram a commit already staged
                 * once. The drop accounting stays, and the send-done
                 * still fires: same open-token rule as the flush drop path. */
                duct_rtstat_obj_inc(w, rtstats.dgram_shared_tx_drop, 1);
                auto ds = duct_session_by_conn(dconn);
                if (ds)
                    s_fire_send_done(ds, duct_proto_cfg_of(ds->proto),
                                     node->dgram_tx.conn_id, node->dgram_tx.stream_id,
                                     &(duct_response_t){ .flags = node->dgram_tx.flags,
                                                         .send_token = node->dgram_tx.send_token },
                                     rc_no_memory);
                duct_del(node->dgram_tx.block);
                duct_del(node);
                --w->dgram_parked;
                progress = true;
                break;
            }
            if (!staged) {
                dgram_blocked = true;
                keep = true; /* lane still full -- next pass, wait_latch armed */
                break;
            }
            memcpy(dout.span.data, node->dgram_tx.bytes.data, parked);
            s_dgram_out_publish(&dout, parked);
            duct_rtstat_obj_inc(w, rtstats.dgram_lane_staged, 1);
            duct_io_post_dgram_tx(node->dgram_tx.listener);
            auto ds = duct_session_by_conn(dconn);
            if (ds)
                s_fire_send_done(ds, duct_proto_cfg_of(ds->proto), node->dgram_tx.conn_id,
                                 node->dgram_tx.stream_id,
                                 &(duct_response_t){ .flags = node->dgram_tx.flags,
                                                     .send_token = node->dgram_tx.send_token }, rc_ok);
            duct_del(node->dgram_tx.block);
            duct_del(node);
            --w->dgram_parked;
            progress = true;
            break;
        }
        }
        if (keep)
            s_retry_enqueue(w, node);
        if (last_of_lap) {
            if (progress)
                duct_discard duct_atomic_fetch(add, &w->retry_epoch, 1u, release);
            return progress || epoch != duct_atomic_load(&w->retry_epoch, acquire);
        }
    }
    /* A room wake must reach every queued ticket, including a serving ticket
     * beyond this quota. Stop after one blocked lap in the current epoch. */
    /* Resolving a ticket can unblock a node already attempted earlier in
     * this lap, even without a subsequent IO wake. */
    if (progress)
        duct_discard duct_atomic_fetch(add, &w->retry_epoch, 1u, release);
    epoch = duct_atomic_load(&w->retry_epoch, acquire);
    for (auto node = w->retry_head; node; node = node->next)
        if (node->attempt_epoch != s_retry_lap(epoch))
            return true;
    return progress;
}

/** @brief Drop every node still parked on @p w's retry list.
 *  Each kind releases what it owns, through the same calls @ref s_retry_drain
 *  makes when it gives a node up, with one exception: an emit node's hctx is
 *  left to @ref duct_stream_cancel. Enumerating all seven with no @c default
 *  makes an eighth kind warn here as well as there.
 */
static void s_retry_clear(duct_worker_t *w)
{
    for (auto node = w->retry_head; node; ) {
        auto next = node->next;
        switch (node->kind) {
        case retry_emit:
            duct_response_release_owned(&node->emit.out);
            break;
        case retry_frame:
            s_retry_frame_pins_release(node);
            duct_response_release_owned(&node->frame.out);
            break;
        case retry_dgram_tx:
            duct_del(node->dgram_tx.block);
            break;
        case retry_engine: /* Codec teardown owns the bounded buffer. */
        case retry_timer:
        case retry_fin:
        case retry_close:
            break;
        }
        duct_del(node);
        node = next;
    }
    w->retry_head = nullptr;
    w->retry_tail = nullptr;
    w->dgram_parked = 0u;
}

/** @brief Unlink @p target's emit node from @p w's unified retry list.
 *
 *  Releases the node payload and resolves its ticket via
 *  @ref s_commit_ticket_abandon. The caller handles RX hold release.
 */
static void s_retry_emit_discard(duct_worker_t *w, duct_stream_ctx_t *target)
{
    retry_node_t *prev = nullptr;
    for (auto node = w->retry_head; node; prev = node, node = node->next) {
        if (node->kind != retry_emit || node->emit.hctx != target)
            continue;
        if (prev)
            prev->next = node->next;
        else
            w->retry_head = node->next;
        if (node == w->retry_tail)
            w->retry_tail = prev;
        /* node->emit.out.conn_id, not target->conn_id -- see
         * s_retry_emit_save's own note. */
        auto conn = duct_conn_by_handle(duct_session_conn_at(target->s, node->emit.out.conn_id));
        s_commit_ticket_abandon(conn, node->emit.ticket, &node->emit.out);
        duct_del(node);
        return;
    }
}

/** @brief Empty out every parked retry_frame node whose response goes out on
 *  leg @p handle's stream @p sid, landing its carried ack and releasing its
 *  payload and ring pins now.
 *  Run by @ref s_ctl_send_fin ahead of an RST: the peer discards that queued
 *  tail on arrival anyway.
 *
 *  Emptied, not unlinked, because the node's ticket still has to resolve in
 *  order — tx_seq_serve advances one step at a time, so dropping a node
 *  that is not at the front of the sequence leaves a hole no later commit
 *  on this OLB can get past. @ref s_retry_drain still takes each node in its
 *  turn, resolving the ticket itself and settling the response's control.
 *
 *  That control stays: an author's close riding along with the discarded
 *  payload is not part of the reset stream, and its timer ran at intake.
 */
static void s_retry_frame_void_stream(duct_worker_t *w, duct_conn_handle_t handle,
                                      duct_stream_id_t sid)
{
    for (auto node = w->retry_head; node; node = node->next) {
        if (node->kind != retry_frame || node->frame.out.stream_id != sid
            || node->frame.handle.word != handle.word)
            continue;
        s_retry_frame_void(node);
    }
}

void duct_worker_conn_retry_discard(const duct_conn_handle_t *conn)
{
    auto w = s_this_worker;
    assert(w);
    auto h = *conn;
    retry_node_t *prev = nullptr;
    for (retry_node_t *node = w->retry_head, *next; node; node = next) {
        next = node->next;
        bool drop = false;
        switch (node->kind) {
        case retry_frame:
            if (node->frame.handle.word == h.word) {
                s_retry_frame_done(node);
                duct_response_release_owned(&node->frame.out);
                drop = true;
            } else if (node->frame.rx_handle.word == h.word && node->frame.pin != alias_none) {
                if (s_retry_payload_own(&node->frame.out) == own_copied)
                    s_retry_frame_done(node);
                else
                    s_retry_frame_void(node);
            }
            break;
        case retry_fin:
            drop = node->fin.handle.word == h.word;
            break;
        case retry_engine:
            drop = node->engine.handle.word == h.word;
            break;
        case retry_close:
            drop = node->close.handle.word == h.word;
            break;
        case retry_dgram_tx:
            drop = node->dgram_tx.handle.word == h.word;
            if (drop) {
                duct_del(node->dgram_tx.block);
                --w->dgram_parked;
            }
            break;
        case retry_emit:
        case retry_timer:
            break;
        }
        if (!drop) {
            prev = node;
            continue;
        }
        if (prev)
            prev->next = next;
        else
            w->retry_head = next;
        if (w->retry_tail == node)
            w->retry_tail = prev;
        duct_del(node);
    }
}

/** @brief Release a response whose ticket was issued but never reaches @c s_commit_response.
 *
 *  Reached from a failed @c s_retry_frame_save or @c s_retry_emit_save
 *  allocation, from @c s_retry_emit_discard unlinking a still-parked node out
 *  from under a cancelled stream, and from @c s_ctl_send_fin when a fin cannot
 *  be parked. The response is left holding no payload. The serve counter
 *  advances once for each ticket that reaches an outcome, so a ticket left
 *  unresolved wedges every later commit on this conn, not just this one
 *  response.
 *
 *  @p ticket at the front of its queue, tx_seq_serve == ticket, advances serve
 *  as a normal resolution does, through @ref s_tx_ticket_pass. Off the front,
 *  another ticket still queued ahead of it, as an answer queued behind parked
 *  host sends is, serve cannot skip just this one without a hole the later
 *  commits cannot pass, so the conn closes. A conn without counters, an OLB
 *  xport whose buffer was never wired up, takes the release alone.
 */
static void
s_commit_ticket_abandon(duct_conn_t *conn, uint32_t ticket, duct_response_t *out)
{
    s_response_void_payload(out);
    if (!conn || s_tx_ticket_pass(conn, ticket))
        return;
    auto handle = duct_conn_handle_get(conn);
    duct_io_post_close_request(&handle, close_internal_error);
}

/** @brief Commit failure tail: fire send-done and on_error, and hand back the
 *  commit outcome.
 *  @c commit_closed skips on_error, nothing protocol-level having gone wrong
 *  with the peer just gone; every other failure, a malformed request or
 *  exhausted TX room, is the protocol's to hear about. Every outcome but
 *  @c commit_internal counts in the addressed leg's @c tx_refused, after both
 *  callbacks.
 */
static duct_commit_rc_t
s_commit_fail(duct_session_t *s, const duct_proto_cfg_t *cfg,
              duct_conn_id_t conn_id, duct_stream_id_t stream_id, duct_response_t *out,
              duct_result_t done_rc, duct_commit_rc_t commit_rc, bool is_replay)
{
    /* fl_send_done promises exactly one completion per response. A
     * commit_internal is not this response's resolution -- a retry node takes
     * (or already holds) the token, and the completion fires when that node
     * resolves: inside the replayed commit on success, at the terminal-failure
     * sites otherwise. */
    if (commit_rc != commit_internal)
        s_fire_send_done(s, cfg, conn_id, stream_id, out, done_rc);
    if (commit_rc != commit_closed && !(commit_rc == commit_internal && is_replay))
        s_fire_error(s, cfg, done_rc);
    if (commit_rc == commit_internal && s_this_worker)
        duct_rtstat_obj_inc(s_this_worker, rtstats.commit_internal, 1);
    if (commit_rc != commit_internal && conn_id < duct_session_max_legs)
        duct_session_counters(s)[conn_id].tx_refused += 1u;
    return commit_rc;
}

/** @brief Get this pass's queued @c x_udp_shared entries onto the wire.
 *
 *  Runs at each frame batch, inter lane drain and drain pass end, and inline
 *  wherever a commit or control stage needs the pass out or the pool relieved.
 *
 *  Takes the pass -- entry count and listener read, then cleared -- before the
 *  batch goes out, and the batch precedes any callback: a send-done re-entering
 *  here finds nothing to resend, and a fin it stages lands behind its own data.
 *
 *  An entry the batch does not resolve retries once through the per-worker
 *  @c dgram_tx_outbox lane, then parks via @ref s_retry_dgram_tx_save, the rest
 *  of the pass parking behind it; only a failed park is terminal, counted via
 *  @c dgram_shared_tx_drop. The batch runs only while that lane is empty and
 *  nothing of this worker is parked, so no pass sends past what an earlier one
 *  left in either and reorders one conn's datagrams. A listener holding an RIO
 *  send state takes the lane alone: its socket serves RIO calls only, so the
 *  worker's own grouped send never runs on it and every entry stages into the
 *  lane for the io thread's registered-slot send.
 *
 *  @ref s_fire_send_done fires exactly once per entry -- here for sent,
 *  lane-staged or terminal-dropped, later when a parked entry resolves. A
 *  session already closed resolves to no conn, and that entry drops silently.
 */
static void
s_worker_dgram_flush(void)
{
    auto w = s_this_worker;
    auto pass = w ? w->dgram_pass : nullptr;
    duct_do_if(!pass, goto kick);
    if (!pass->n)
        goto kick;
    {
    uint32_t n = pass->n;
    auto listener = pass->listener;
    pass->n = 0u;
    pass->listener = nullptr;
    auto ln = duct_mpsc_lane(duct_io_dgram_shared_outbox(listener), w->worker_id);
    uint32_t resolved = 0u;
    if (!w->dgram_parked && !duct_io_dgram_shared_rio_tx(listener)
        && duct_vmq_room(&ln) == ln.capacity) {
        duct_dgram_out_t msgs[n];
        for (uint32_t i = 0u; i < n; ++i)
            msgs[i] = (duct_dgram_out_t){
                .peer = pass->entries[i].peer,
                .hdr  = { .data = pass->entries[i].hdr, .size = pass->entries[i].hdr_len },
                .body = { .data = pass->entries[i].ptr, .size = pass->entries[i].len },
            };
        duct_x_gso_tally_t tally = {};
        resolved = duct_io_dgram_shared_send_batch(listener, msgs, n, &tally);
        duct_rtstat_obj_inc(w, rtstats.dgram_batch_calls, 1);
        duct_rtstat_obj_inc(w, rtstats.dgram_batch_msgs, n);
        duct_rtstat_obj_max(w, rtstats.dgram_batch_max, (uint64_t)n);
        duct_rtstat_obj_inc(w, rtstats.dgram_tx_gso_writes, tally.writes);
        duct_rtstat_obj_inc(w, rtstats.dgram_tx_gso_dgrams, tally.dgrams);
    }
    if (resolved < n)
        /* Pre-arm ahead of the fallback loop below, which may reserve
         * into the lane per entry; the pass's coalesced kick_listeners
         * kick still lands once at the very end. */
        duct_io_post_dgram_tx(listener);
    duct_rtstat_obj_inc(w, rtstats.dgram_fast_sent, resolved);

    bool need_kick = false;
    for (uint32_t i = 0u; i < n; ++i) {
        auto e = &pass->entries[i];
        bool ok = i < resolved;
        bool parked = false;
        if (!ok) {
            duct_vmq_push_rc_t push_rc;
            dgram_out_t o;
            size_t bytes = (size_t)e->hdr_len + e->len;
            bool staged = !w->dgram_parked
                       && s_dgram_out_open(listener, &e->peer, bytes, &o, &push_rc);
            if (staged) {
                if (e->hdr_len)
                    memcpy(o.span.data, e->hdr, e->hdr_len);
                memcpy(o.span.data + e->hdr_len, e->ptr, e->len);
                s_dgram_out_publish(&o, bytes);
                duct_rtstat_obj_inc(w, rtstats.dgram_lane_staged, 1);
                need_kick = true;
                ok = true;
            } else if (s_retry_dgram_tx_save(w, e, listener, e->ptr))
                parked = true; /* send_done/on_error fire when the node resolves */
            else
                duct_rtstat_obj_inc(w, rtstats.dgram_shared_tx_drop, 1);
        }
        /* Every path above -- sent, lane-copied, retry-copied, terminal-
         * dropped -- is done reading e->ptr here, so this entry's own
         * reference on its pool region drops now. Every x_udp_shared entry
         * carries exactly one, set in s_commit_response's x_udp_shared case,
         * never null. */
        if (s_tx_pool_owns(&w->tx_pool, e->ptr))
            --e->region->refs;
        else
            duct_del(e->block);
        if (parked)
            continue;
        auto conn = duct_conn_by_handle(e->handle);
        auto s = conn ? duct_session_by_conn(conn) : nullptr;
        if (!s)
            continue;
        auto cfg = duct_proto_cfg_of(s->proto);
        if (ok)
            s_fire_send_done(s, cfg, e->conn_id, e->stream_id,
                             &(duct_response_t){ .flags = e->flags, .send_token = e->send_token }, rc_ok);
        else {
            /* Terminal drop still owes the send-done: fl_send_done promises
             * exactly one completion per response, and a token left open
             * leaks whatever the protocol gates on it (a leg wedged at its
             * inflight cap for ever). info.result carries the failure. */
            s_fire_send_done(s, cfg, e->conn_id, e->stream_id,
                             &(duct_response_t){ .flags = e->flags, .send_token = e->send_token },
                             rc_no_memory);
            s_fire_error(s, cfg, rc_again);
        }
    }
    if (need_kick && pass->kick_n < duct_async_cycle_quota)
        pass->kick_listeners[pass->kick_n++] = listener;
    else if (need_kick)
        duct_io_post_dgram_tx(listener); /* pending-kick set full: kick now, don't lose it */
    /* The callbacks above invoke close, attach, timer, and rx operations,
     * which post messages without committing to this batch. */
    assert(pass->n == 0u);
    s_tx_pool_reclaim(&w->tx_pool);
    }
kick:
    duct_do_if(!pass, return);
    for (uint32_t i = 0u; i < pass->kick_n; ++i)
        duct_io_post_dgram_tx(pass->kick_listeners[i]);
    pass->kick_n = 0u;
}

#if !DUCT_EVENTS_MODEL_IOCP
/** @brief Acquire @p need bytes from the shared TX pool, retrying once after a dgram-batch flush. */
static void *s_dgram_acquire_or_flush(size_t need)
{
    auto acquired = duct_tx_pool_acquire(need);
    if (!acquired) {
        s_worker_dgram_flush();
        acquired = duct_tx_pool_acquire(need);
    }
    return acquired;
}
#endif

/** @brief Context for response commit helpers. */
typedef struct {
    duct_session_t         *s;
    duct_conn_id_t           out_conn;
    duct_stream_id_t         out_stream;
    duct_response_t        *out;
    duct_conn_t             *conn;
    duct_conn_handle_t       handle;
    bool                     is_replay;
    /** @brief Destination reservation or cleartext-ring region of the packet in
     *  dispatch, open across this commit.
     *  Nullptr from every caller but @ref s_inter_pkt. */
    redirect_t            *redirect;
} commit_ctx_t;

/** @brief Route a commit failure to @c s_commit_fail with @p ctx's saved identity. */
static duct_commit_rc_t
s_commit_ctx_fail(const commit_ctx_t *ctx, duct_result_t err, duct_commit_rc_t crc)
{
    return s_commit_fail(ctx->s, duct_proto_cfg_of(ctx->s->proto), ctx->out_conn, ctx->out_stream, ctx->out,
                         err, crc, ctx->is_replay);
}

/** @brief Publish a successful stage and fire the response's completion.
 *  The shared tail for every xport that stages into a real per-conn TX OLB.
 */
static duct_commit_rc_t
s_commit_ctx_ok(const commit_ctx_t *ctx)
{
    duct_olb_tx_publish(ctx->conn->tx_buf);
    duct_io_post_tx_drain(&ctx->handle);
    s_fire_send_done(ctx->s, duct_proto_cfg_of(ctx->s->proto), ctx->out_conn, ctx->out_stream, ctx->out, rc_ok);
    return commit_ok;
}

/** @brief Map an OLB stage result to a commit outcome.
 *  Routes pack failures uniformly; @c olb_tx_full maps to retryable @c rc_again
 *  while other failures map to terminal @c rc_invalid_arg.
 */
static duct_commit_rc_t
s_commit_stage_result(const commit_ctx_t *ctx, duct_olb_tx_result_t st)
{
    switch (st) {
    case olb_tx_ok:   return s_commit_ctx_ok(ctx);
    case olb_tx_full: return s_commit_ctx_fail(ctx, rc_again, commit_internal);
    default:          return s_commit_ctx_fail(ctx, rc_invalid_arg, commit_invalid);
    }
}

/** @brief Commit an @c x_inter response to device memory or host queue.
 *  Transports without write callbacks reject commits with @c commit_invalid.
 *  The device's @c write_commit answers @c rc_ok for a packet taken and
 *  @c rc_closed to close the leg; @c rc_drop and other answers fail with
 *  @c commit_invalid.
 *
 *  A ring with no room and the host's own @c rc_again both park the response on the retry list. Nothing
 *  overtakes it there: a leg with no TX OLB keeps its ticket sequence in @c duct_conn_t::tx_seq, so a later
 *  commit on this conn waits its turn the same way an OLB leg's does.
 *
 *  A payload that is the whole reservation @c ctx->redirect already holds on this same leg, written whole, is
 *  sent from where it lies, and the reservation is marked consumed so the caller's release finds none. Every
 *  other payload, the head of the reservation included, is copied into a fresh one of its own size, and the
 *  untouched hold closes at that release.
 */
static duct_commit_rc_t
s_commit_inter(const commit_ctx_t *ctx)
{
    auto s = ctx->s; auto cfg = duct_proto_cfg_of(s->proto); auto out = ctx->out;
    auto out_conn = ctx->out_conn; auto out_stream = ctx->out_stream;
    auto r = ctx->redirect;
    bool direct = r && r->span && r->conn_id == out_conn
               && out->payload.data == r->span && out->payload.size == r->len && r->len == r->cap;
    auto dev = (const duct_device_ops_t *)ctx->conn->ctx;
    if (dev) {
        /* A response routed to a read-only device is refused. */
        duct_do_if(!dev->write_reserve, return s_commit_ctx_fail(ctx, rc_invalid_arg, commit_invalid));
        size_t len = out->payload.size;
        void *buf;
        if (direct) {
            buf = r->span;
            r->span = nullptr;
        } else {
            buf = dev->write_reserve(dev->ctx, len);
            if (!buf)
                return s_commit_ctx_fail(ctx, rc_again, commit_internal);
            memcpy(buf, out->payload.data, len);
        }
        auto wrc = dev->write_commit(dev->ctx, buf, len);
        if (wrc == rc_closed) {
            duct_io_post_close_request(&ctx->handle, close_io_error);
            return s_commit_ctx_fail(ctx, rc_closed, commit_closed);
        }
        if (wrc != rc_ok)
            return s_commit_ctx_fail(ctx, wrc == rc_drop ? rc_drop : rc_invalid_arg, commit_invalid);
        s_fire_send_done(s, cfg, out_conn, out_stream, out, rc_ok);
        return commit_ok;
    }
    if (direct) {
        r->span = nullptr;
        duct_host_egress_publish(&r->host, out->payload.size);
        s_fire_send_done(s, cfg, out_conn, out_stream, out, rc_ok);
        return commit_ok;
    }
    auto stok = duct_session_handle_from_live(s);
    auto hrc = duct_host_packet_out(&stok, out_conn, out->payload);
    if (hrc == rc_again)
        return s_commit_ctx_fail(ctx, rc_again, commit_internal);
    if (hrc != rc_ok)
        return s_commit_ctx_fail(ctx, rc_invalid_arg, commit_invalid);
    s_fire_send_done(s, cfg, out_conn, out_stream, out, rc_ok);
    return commit_ok;
}

/** @brief Commit an @c x_udp_shared response using listener-configured TX dispatch.
 *  For reactive backends without RIO, queues entries into the worker batch
 *  array for transmission by @ref s_worker_dgram_flush. On IOCP or RIO
 *  backends, reserves slots in the listener @c dgram_tx_outbox.
 */
static duct_commit_rc_t
s_commit_dgram_shared(const commit_ctx_t *ctx)
{
    auto s = ctx->s; auto cfg = duct_proto_cfg_of(s->proto); auto out = ctx->out;
    auto conn = ctx->conn;
    auto out_conn = ctx->out_conn; auto out_stream = ctx->out_stream;
    auto dctx = (const duct_dgram_shared_ctx_t *)conn->ctx;
    auto listener = dctx->listener;
    size_t need = 0u;
    if (!s_tx_wire_need(conn, out->payload.size, &need))
        return s_commit_ctx_fail(ctx, rc_invalid_arg, commit_invalid);
    auto codec = conn->wire && conn->wire->unseal ? s_tls_codec(conn) : nullptr;
    duct_frame_t frame = {
        .stream_id = out_stream, .payload = out->payload, .flags = out->frame_flags,
    };
#if !DUCT_EVENTS_MODEL_IOCP
    if (!duct_io_dgram_shared_needs_lane_tx(listener)) {
        if (s_this_worker->dgram_parked)
            return s_commit_ctx_fail(ctx, rc_again, commit_internal);
        auto pass = s_this_worker->dgram_pass;
        /* duct_dgram_batch_wait_ns bounds how long the batch's first entry
         * waits, measured from its enqueue timestamp. */
        uint64_t now = duct_ticks_mono_ns();
        bool no_room = pass->n >= duct_async_cycle_quota
                     || (pass->listener && pass->listener != listener)
                     || (pass->n && now - pass->first_ns >= duct_dgram_batch_wait_ns);
        if (no_room)
            s_worker_dgram_flush();

        duct_worker_dgram_batch_entry_t *entry;
        /* fl_wire_gather is the wire declaring it packs into a span pair, so
         * on_pack writes its header straight into the entry and leaves the
         * payload where its author built it; the send puts the two on the wire
         * as one datagram. The pool term is the lifetime: only a pool region
         * outlives this commit, held by the refs bump below until the flush
         * resolves the entry. */
        bool pooled = s_tx_pool_owns(&s_this_worker->tx_pool, out->payload.data);
        bool owned = !pooled && duct_has(out->flags, fl_send_owned) && !out->release;
        if (duct_has(conn->wire->flags, fl_wire_gather) && (pooled || owned)) {
            entry = &pass->entries[pass->n];
            duct_view_u8 bufs[2] = { { .data = entry->hdr } };
            auto stage = (duct_wire_tx_t){ .kind = wire_tx_gather, .gather = bufs };
            auto prc = s_wire_pack_into(conn->wire, s, &frame, &stage, codec);
            if (prc != olb_tx_ok)
                return s_commit_stage_result(ctx, prc);
            entry->hdr_len = (uint8_t)bufs[0].size;
            auto region = pooled ? s_tx_pool_hdr_of(out->payload.data) : nullptr;
            /* Contract: payload.data is exactly duct_tx_pool_acquire's own
             * returned pointer, still held. An interior pointer lands this
             * header read inside payload bytes -- both asserts catch that
             * in debug. */
            assert(!region || region->hold);
            assert(!region || out->payload.size <= region->len);
            if (region)
                ++region->refs;
            /* The entry carries the buffer refs above pinned, not the span
             * on_pack echoed into bufs[1]: the two agree by the gather
             * contract, and only this one is held for the send. */
            if (region)
                entry->region = region;
            else
                entry->block = duct_share(out->release_arg ? out->release_arg : out->payload.data);
            entry->ptr = out->payload.data;
            entry->len = (uint32_t)out->payload.size;
        } else {
            auto acquired = s_dgram_acquire_or_flush(need);
            if (!acquired)
                return s_commit_ctx_fail(ctx, rc_again, commit_internal);
            auto view = (duct_vmq_tx_view_t){ .data = acquired, .stage = 0u, .capacity = need };
            auto stage = (duct_wire_tx_t){ .kind = wire_tx_vmq_view, .vmq_view = view };
            auto prc = s_wire_pack_into(conn->wire, s, &frame, &stage, codec);
            if (prc != olb_tx_ok) {
                s_tx_pool_drop_hold(acquired);
                return s_commit_stage_result(ctx, prc);
            }
            auto region = s_tx_pool_hdr_of(acquired);
            region->refs = 1u;
            s_tx_pool_drop_hold(acquired);
            entry = &pass->entries[pass->n];
            entry->hdr_len = 0u;
            entry->region = region;
            entry->ptr = acquired;
            entry->len = (uint32_t)stage.vmq_view.stage;
        }
        pass->listener = listener;
        /* Each branch takes its slot past its own last chance to flush --
         * nothing reaches the pass from on_pack, while s_dgram_acquire_or_flush
         * empties it and renumbers from zero on an exhausted pool. */
        assert(entry == &pass->entries[pass->n]);
        entry->handle = ctx->handle;
        entry->peer = dctx->peer;
        entry->conn_id = out_conn;
        entry->stream_id = out_stream;
        entry->flags = out->flags;
        entry->send_token = out->send_token;
        if (!pass->n)
            pass->first_ns = now;
        ++pass->n;
        return commit_ok;
    }
#endif
    /* Pre-arm ahead of the reserve below; the post-write kick after publish
     * is the race backstop. */
    duct_io_post_dgram_tx(listener);
    dgram_out_t dout;
    duct_vmq_push_rc_t push_rc;
    if (!s_dgram_out_open(listener, &dctx->peer, need, &dout, &push_rc)) {
        duct_rtstat_obj_inc(s_this_worker, rtstats.dgram_shared_tx_drop, 1);
        return push_rc == vmq_push_too_large
             ? s_commit_ctx_fail(ctx, rc_invalid_arg, commit_invalid)
             : s_commit_ctx_fail(ctx, rc_again, commit_internal);
    }
    duct_rtstat_obj_inc(s_this_worker, rtstats.dgram_lane_staged, 1);
    auto view = (duct_vmq_tx_view_t){ .data = dout.span.data, .stage = 0u, .capacity = need };
    auto tx_stage = (duct_wire_tx_t){ .kind = wire_tx_vmq_view, .vmq_view = view };
    auto prc = s_wire_pack_into(conn->wire, s, &frame, &tx_stage, codec);
    if (prc != olb_tx_ok) {
        s_dgram_out_abort(&dout);
        return s_commit_stage_result(ctx, prc);
    }
    s_dgram_out_publish(&dout, tx_stage.vmq_view.stage);
    duct_io_post_dgram_tx(listener);
    s_fire_send_done(s, cfg, out_conn, out_stream, out, rc_ok);
    return commit_ok;
}

/** @brief Send @p w's train from its ring, or hand it to io.
 *  While io has nothing published on the ring, the worker sends the frames
 *  itself and publishes only what the socket refused: an @c x_udp_peer train
 *  in segmented or batched calls, an @c x_tcp one as one write, and that only
 *  while @ref duct_io_parked reports its io thread parked. Otherwise the frames
 *  are published for io's drain. A leg gone or fenced for close drops the
 *  train. */
static void s_tx_train_flush(duct_worker_t *w)
{
    auto t = &w->tx_train;
    if (!t->frames)
        return;
    t->frames = 0u;
    auto conn = duct_conn_by_handle(t->conn);
    auto tx = conn ? duct_conn_tx_olb(conn) : nullptr;
    if (!tx || duct_atomic_load(&conn->conn_fence, acquire) >= fence_quiescing)
        return;
    if (!duct_olb_tx_published(tx) && (conn->xport_type != x_tcp || duct_io_parked(conn))) {
        size_t sent = 0u;
        duct_result_t rc;
        if (conn->xport_type == x_tcp) {
            size_t base = olb_off(duct_atomic_load(&tx->h.tail, relaxed));
            auto span = (duct_view_u8){ .data = tx->data + base, .size = tx->h.stage - base };
            rc = duct_io_stream_send_fast(conn, &span, 1u, &sent) ? rc_ok : rc_again;
        } else {
            duct_x_gso_tally_t tally = {};
            rc = duct_io_udp_peer_send_staged(conn, &sent, &tally);
            duct_rtstat_obj_inc(w, rtstats.dgram_tx_gso_writes, tally.writes);
            duct_rtstat_obj_inc(w, rtstats.dgram_tx_gso_dgrams, tally.dgrams);
        }
        if (rc == rc_ok) {
            duct_olb_tx_sent_staged(tx);
            return;
        }
        if (sent)
            duct_olb_tx_advance_worker(tx, sent);
    }
    duct_olb_tx_publish(tx);
    duct_io_post_tx_drain(&t->conn);
}

/** @brief Flush this worker's train when it is bound for @p conn. */
static void s_tx_train_flush_for(duct_conn_handle_t conn)
{
    auto w = s_this_worker;
    if (w && w->tx_train.frames && w->tx_train.conn.word == conn.word)
        s_tx_train_flush(w);
}

#if !DUCT_EVENTS_MODEL_IOCP
/** @brief Put @p ctx's commit on this worker's train, opening one for its leg
 *  where none is.
 *  A train bound for another leg is flushed first. False off a worker thread,
 *  and while io holds published bytes or a write-armed socket on the leg: a
 *  direct send starts only where io has nothing left to drain, so that commit
 *  stages and publishes behind them. */
static bool s_tx_train_board(const commit_ctx_t *ctx)
{
    auto w = s_this_worker;
    if (!w)
        return false;
    auto t = &w->tx_train;
    if (t->frames && t->conn.word == ctx->handle.word)
        return true;
    s_tx_train_flush(w);
    auto conn = ctx->conn;
    if (!duct_olb_tx_rewind_idle(conn->tx_buf) || duct_has(duct_conn_state(conn), fl_conn_write_armed))
        return false;
    t->conn = ctx->handle;
    t->first_ns = duct_ticks_mono_ns();
    return true;
}

/** @brief Stage @p frame onto this worker's open train and flush the train once
 *  it is due.
 *  The train goes out once no frame of the dispatch in flight follows, at
 *  @c duct_dgram_tx_batch frames, or once @c duct_dgram_batch_wait_ns has
 *  passed since it opened, so a lone frame leaves at once; both limits bound an
 *  @c x_tcp train too. A full ring behind a loaded train sends the train, then
 *  stages @p frame again and publishes it.
 */
static duct_commit_rc_t s_commit_train(const commit_ctx_t *ctx, const duct_frame_t *frame)
{
    auto w = s_this_worker;
    auto t = &w->tx_train;
    auto st = s_tx_stage_frame(ctx->conn, ctx->s, frame);
    if (st == olb_tx_full && t->frames) {
        s_tx_train_flush(w);
        return s_commit_stage_result(ctx, s_tx_stage_frame(ctx->conn, ctx->s, frame));
    }
    if (st != olb_tx_ok)
        return s_commit_stage_result(ctx, st);
    if (++t->frames >= duct_dgram_tx_batch || !t->more
        || duct_ticks_mono_ns() - t->first_ns >= duct_dgram_batch_wait_ns) {
        duct_rtstat_obj_inc(w, rtstats.tx_train_flush_full, t->frames >= duct_dgram_tx_batch);
        duct_rtstat_obj_inc(w, rtstats.tx_train_flush_end,
                            t->frames < duct_dgram_tx_batch && !t->more);
        duct_rtstat_obj_inc(w, rtstats.tx_train_flush_wait,
                            t->frames < duct_dgram_tx_batch && t->more);
        s_tx_train_flush(w);
    }
    s_fire_send_done(ctx->s, duct_proto_cfg_of(ctx->s->proto), ctx->out_conn,
                     ctx->out_stream, ctx->out, rc_ok);
    return commit_ok;
}
#endif

/** @brief Commit an @c x_udp_peer response onto this worker's train, or stage
 *  and publish it. */
static duct_commit_rc_t
s_commit_udp_peer(const commit_ctx_t *ctx)
{
    auto conn = ctx->conn;
    if (!duct_conn_tx_olb(conn))
        return s_commit_ctx_fail(ctx, rc_closed, commit_closed);
    duct_frame_t wire_frame = {
        .stream_id = ctx->out_stream, .payload = ctx->out->payload,
        .flags = ctx->out->frame_flags,
    };
#if !DUCT_EVENTS_MODEL_IOCP
    if (s_tx_train_board(ctx))
        return s_commit_train(ctx, &wire_frame);
#endif
    return s_commit_stage_result(ctx, s_tx_stage_frame(conn, ctx->s, &wire_frame));
}

#if !DUCT_EVENTS_MODEL_IOCP
/** @brief Commit a response by sending the pack's own header and payload
 *  spans, neither of them passing through the TX ring.
 *
 *  Room for the whole frame is claimed in the ring before a byte goes out: a
 *  short write leaves no staged copy behind it, so the remainder has to be
 *  known to fit first. That remainder is the only thing this path ever
 *  stages, and the payload reaches the socket from wherever its author built
 *  it.
 *
 *  Transports without framing headers supply a single payload span to
 *  @ref duct_xwritev.
 */
static duct_commit_rc_t
s_commit_stream_gather(const commit_ctx_t *ctx, const duct_frame_t *frame)
{
    auto conn = ctx->conn;
    size_t need = 0u;
    if (!s_tx_frame_need(conn, frame->payload.size, &need))
        return s_commit_stage_result(ctx, olb_tx_too_large);
    if (!duct_olb_tx_align(conn->tx_buf, need))
        return s_commit_stage_result(ctx, olb_tx_full);

    uint8_t hdr[wire_tx_hdr_max];
    duct_view_u8 bufs[2] = { { .data = hdr } };
    auto stage = (duct_wire_tx_t){ .kind = wire_tx_gather, .gather = bufs };
    auto st = s_wire_pack_into(conn->wire, ctx->s, frame, &stage, nullptr);
    if (st != olb_tx_ok)
        return s_commit_stage_result(ctx, st);

    size_t written = 0u;
    bool hdr_span = bufs[0].size != 0u;
    duct_discard duct_io_stream_send_fast(conn, hdr_span ? bufs : &bufs[1],
                                          hdr_span ? 2u : 1u, &written);
    duct_olb_tx_sent_direct(conn->tx_buf, written);
    size_t hdr_sent = written < bufs[0].size ? written : bufs[0].size,
           pl_sent  = written - hdr_sent,
           hdr_left = bufs[0].size - hdr_sent,
           pl_left  = bufs[1].size - pl_sent;
    if (!hdr_left && !pl_left) {
        s_fire_send_done(ctx->s, duct_proto_cfg_of(ctx->s->proto), ctx->out_conn,
                         ctx->out_stream, ctx->out, rc_ok);
        return commit_ok;
    }
    return s_commit_stage_result(ctx,
        duct_olb_tx_stage(conn->tx_buf,
                          hdr_left ? hdr + hdr_sent : nullptr, hdr_left,
                          pl_left ? (const uint8_t *)bufs[1].data + pl_sent : nullptr,
                          pl_left));
}
#endif

/** @brief Commit an @c x_tcp, @c x_raw or @c x_local response, trying one direct
 *  send whenever the TX ring was idle before staging.
 *
 *  An idle ring makes an immediate send safe: @c write and @c send
 *  can fall short, so this path runs only with nothing else queued ahead of
 *  these bytes. The wire picks between two shapes. One raising
 *  @ref fl_wire_gather, and a leg carrying no wire at all, send the spans through
 *  @ref s_commit_stream_gather and touch the ring only for what the kernel
 *  refused. Every other wire stages through @ref s_tx_stage_frame first and
 *  sends from the ring, a short or failed attempt then publishing what is
 *  already sitting there. An @c x_tcp frame on such a wire boards this
 *  worker's train instead, @ref s_commit_train; only one the train turns away
 *  takes the send here. A gather wire's frame never boards: the frames of a
 *  train are staged and unpublished, which an idle ring does not count, and a
 *  direct send passes them to the socket.
 */
static duct_commit_rc_t
s_commit_stream(const commit_ctx_t *ctx)
{
    auto s = ctx->s; auto out = ctx->out; auto conn = ctx->conn;
    auto out_stream = ctx->out_stream;
    if (!duct_conn_tx_olb(conn))
        return s_commit_ctx_fail(ctx, rc_closed, commit_closed);
    duct_frame_t wire_frame = {
        .stream_id = out_stream, .payload = out->payload, .flags = out->frame_flags,
    };
#if !DUCT_EVENTS_MODEL_IOCP
    bool olb_was_idle = duct_olb_tx_rewind_idle(conn->tx_buf);
    bool gathers = !conn->wire || duct_has(conn->wire->flags, fl_wire_gather);
    if (olb_was_idle && gathers)
        return s_commit_stream_gather(ctx, &wire_frame);
    if (!gathers && conn->xport_type == x_tcp && s_tx_train_board(ctx))
        return s_commit_train(ctx, &wire_frame);
    auto mark = duct_olb_tx_mark(conn->tx_buf);
#endif
    auto st = s_tx_stage_frame(conn, s, &wire_frame);
    if (st != olb_tx_ok)
        return s_commit_stage_result(ctx, st);
#if !DUCT_EVENTS_MODEL_IOCP
    if (olb_was_idle) {
        size_t off_now = olb_off(duct_olb_tx_stage_packed(conn->tx_buf)),
               staged = duct_olb_tx_staged_since(conn->tx_buf, mark),
               off = off_now - staged,
               written = 0u;
        auto span = (duct_view_u8){ .data = conn->tx_buf->data + off, .size = staged };
        if (duct_io_stream_send_fast(conn, &span, 1u, &written)) {
            /* Every byte reached the kernel -- nothing to publish, the span
             * counting on the stream past the ring. Staging resyncs from
             * tail's current value: s_tx_stage_frame's own align may have
             * opened a new pass since mark, which leaves mark in a pass io
             * may still drain, and stage rewound there desyncs from tail for
             * good. */
            duct_olb_tx_sent_staged(conn->tx_buf);
            s_fire_send_done(s, duct_proto_cfg_of(s->proto), ctx->out_conn, out_stream, out, rc_ok);
            return commit_ok;
        }
        if (written > 0u)
            duct_olb_tx_advance_worker(conn->tx_buf, written);
    }
#endif
    return s_commit_ctx_ok(ctx);
}

/** @brief Write @p w's open train to its leg as one segmented write, then return
 *  every reference its spans hold.
 *  A leg gone or fenced for close drops the train unwritten; a write the fd
 *  refuses counts in @c vnet_tx_drop. */
static void s_vnet_train_flush(duct_worker_t *w)
{
    auto t = w->vnet_train;
    unsigned segs = t->gro.segs;
    if (!segs)
        return;
    auto conn = duct_conn_by_handle(t->conn);
    uint8_t vh[duct_vnet_hdr_max];
    duct_vnet_gro_finish(&t->gro, vh);
    if (conn && duct_atomic_load(&conn->conn_fence, acquire) < fence_quiescing) {
        t->gro.bufs[0] = (duct_view_u8){ .data = vh, .size = conn->vnet_hdr_len };
        size_t written = 0u;
        if (!duct_io_stream_send_fast(conn, t->gro.bufs, duct_vnet_gro_front + t->gro.nspans,
                                      &written) && !written)
            duct_rtstat_obj_inc(w, rtstats.vnet_tx_drop, 1);
        else if (segs > 1u) {
            duct_rtstat_obj_inc(w, rtstats.vnet_tx_gro_writes, 1);
            duct_rtstat_obj_inc(w, rtstats.vnet_tx_gro_pkts, segs);
        } else
            duct_rtstat_obj_inc(w, rtstats.vnet_tx_gro_single, 1);
    }
    for (unsigned i = 0u; i < t->gro.nspans; ++i)
        if (t->regions[i])
            --t->regions[i]->refs;
}

/** @brief Flush this worker's train when it is bound for @p conn. */
static void s_vnet_train_flush_for(duct_conn_handle_t conn)
{
    auto w = s_this_worker;
    auto t = w ? w->vnet_train : nullptr;
    if (t && t->gro.segs && t->conn.word == conn.word)
        s_vnet_train_flush(w);
}

void duct_worker_conn_train_flush(const duct_conn_handle_t *conn)
{
    s_tx_train_flush_for(*conn);
    s_vnet_train_flush_for(*conn);
}

#if !DUCT_EVENTS_MODEL_IOCP
/** @brief Offer packet @p pkt, bound for @p conn, to this worker's train.
 *  @p mss is a GSO record's segment size, 0 for a plain packet. A UDP datagram
 *  joins only where @p conn carries @c fl_conn_vnet_uso.
 *  A payload inside @p redirect's region stays where it lies, the train taking a
 *  reference on the region; any other is copied into a region of its own before
 *  this returns. A copy the ring has no room for writes the train at once, this
 *  payload in it.
 *  @return true once the train holds it; false hands it back, this worker's
 *          train already written. */
static bool s_vnet_train_take(const duct_conn_t *conn, duct_view_u8 pkt, size_t mss,
                              const redirect_t *redirect)
{
    auto w = s_this_worker;
    if (!w)
        return false;
    auto t = w->vnet_train;
    auto h = duct_conn_handle_get(conn);
    if (t->gro.segs && t->conn.word != h.word)
        s_vnet_train_flush(w);
    auto merge = duct_has(duct_conn_state(conn), fl_conn_vnet_uso) ? vnet_merge_tcp_udp
                                                                    : vnet_merge_tcp;
    for (;;) {
        auto rc = duct_vnet_gro_offer(&t->gro, (const uint8_t *)pkt.data, pkt.size, mss, merge);
        if (rc == vnet_gro_flush_first) {
            s_vnet_train_flush(w);
            continue;
        }
        if (rc == vnet_gro_alone) {
            s_vnet_train_flush(w);
            return false;
        }
        t->conn = h;
        unsigned k = t->gro.nspans - 1u;
        auto span = &t->gro.bufs[duct_vnet_gro_front + k];
        auto at = (const char *)span->data;
        auto home = redirect ? (const char *)redirect->ct : nullptr;
        duct_tx_pool_hdr_t *region;
        if (home && at >= home && at + span->size <= home + redirect->cap)
            region = s_tx_pool_hdr_of(redirect->ct);
        else {
            void *copy = s_pool_acquire(&w->ct_pool, span->size);
            if (!copy) {
                t->regions[k] = nullptr;
                s_vnet_train_flush(w);
                return true;
            }
            memcpy(copy, span->data, span->size);
            span->data = copy;
            region = s_tx_pool_hdr_of(copy);
            s_tx_pool_drop_hold(copy);
        }
        ++region->refs;
        t->regions[k] = region;
        if (rc == vnet_gro_taken_last)
            s_vnet_train_flush(w);
        return true;
    }
}
#endif

/** @brief Commit a response on a packet-fd leg, reaching the device ahead of
 *  the ring where there is nothing queued.
 *
 *  @ref s_commit_stream cannot serve this xport. Its second fast path sends a
 *  span read back out of the ring, and on a record-framed leg that span opens
 *  with the internal record header delimiting packets there — bytes a device
 *  must never receive. Packing into gather buffers sends what the wire
 *  produced, and the fallback goes through @ref s_tx_stage_frame, so the ring
 *  still gets the header its reader expects.
 *
 *  A write that moved anything counts as sent: a packet fd takes a datagram
 *  whole, leaving no remainder to resume, and staging the frame again puts the
 *  packet's head on the wire a second time.
 *
 *  On a vnet leg a packet goes to this worker's train first, and the direct
 *  write and the stage below both flush that train before they touch the conn,
 *  which keeps the leg's packets in order. A GSO record's header is built
 *  before either path, so one no segmentation takes fails with
 *  @c rc_invalid_arg, and the direct write sends its packet under that header.
 */
static duct_commit_rc_t
s_commit_packet_fd(const commit_ctx_t *ctx)
{
    auto conn = ctx->conn;
    if (!duct_conn_tx_olb(conn))
        return s_commit_ctx_fail(ctx, rc_closed, commit_closed);
    duct_frame_t wire_frame = {
        .stream_id = ctx->out_stream,
        .payload = ctx->out->payload,
        .flags = ctx->out->frame_flags,
    };
    duct_view_u8 pkt = wire_frame.payload;
    bool gso = conn->vnet_hdr_len && duct_has(wire_frame.flags, fl_frame_gso);
    uint8_t vh[duct_vnet_hdr_max];
    size_t mss = gso ? duct_vnet_gso_open(&pkt, vh) : 0u;
    duct_do_if(gso && !mss, return s_commit_ctx_fail(ctx, rc_invalid_arg, commit_invalid));
#if !DUCT_EVENTS_MODEL_IOCP
    if (duct_olb_tx_rewind_idle(conn->tx_buf)
        && (!conn->wire || duct_has(conn->wire->flags, fl_wire_gather))) {
        uint8_t hdr[wire_tx_hdr_max];
        duct_view_u8 bufs[2] = { { .data = hdr } };
        auto stage = (duct_wire_tx_t){ .kind = wire_tx_gather, .gather = bufs };
        auto st = s_wire_pack_into(conn->wire, ctx->s, &wire_frame, &stage, nullptr);
        if (st != olb_tx_ok)
            return s_commit_stage_result(ctx, st);
        if (!mss)
            pkt = bufs[1];
        if (conn->vnet_hdr_len && !bufs[0].size
            && s_vnet_train_take(conn, pkt, mss, ctx->redirect)) {
            s_fire_send_done(ctx->s, duct_proto_cfg_of(ctx->s->proto),
                             ctx->out_conn, ctx->out_stream, ctx->out, rc_ok);
            return commit_ok;
        }
        s_vnet_train_flush_for(ctx->handle);
        size_t written = 0u;
        duct_view_u8 spans[3];
        unsigned ns = 0u;
        if (conn->vnet_hdr_len)
            spans[ns++] = (duct_view_u8){ .data = mss ? vh : (uint8_t *)&duct_vnet_zero[0],
                                        .size = conn->vnet_hdr_len };
        if (bufs[0].size)
            spans[ns++] = bufs[0];
        spans[ns++] = pkt;
        bool sent = duct_io_stream_send_fast(conn, spans, ns, &written);
        if (sent || written != 0u) {
            s_fire_send_done(ctx->s, duct_proto_cfg_of(ctx->s->proto),
                             ctx->out_conn, ctx->out_stream, ctx->out, rc_ok);
            return commit_ok;
        }
    }
#endif
    s_vnet_train_flush_for(ctx->handle);
    return s_commit_stage_result(ctx, s_tx_stage_frame(conn, ctx->s, &wire_frame));
}

/** @brief Commit a response for any xport without its own s_commit_* case.
 *  Plain stage-then-publish through @ref s_tx_stage_frame.
 */
static duct_commit_rc_t
s_commit_generic(const commit_ctx_t *ctx)
{
    auto conn = ctx->conn;
    if (!duct_conn_tx_olb(conn))
        return s_commit_ctx_fail(ctx, rc_closed, commit_closed);
    duct_frame_t wire_frame = {
        .stream_id = ctx->out_stream,
        .payload = ctx->out->payload,
        .flags = ctx->out->frame_flags,
    };
    return s_commit_stage_result(ctx, s_tx_stage_frame(conn, ctx->s, &wire_frame));
}

/** @brief Validate and dispatch one response commit to its xport's own
 *  s_commit_* handler.
 *  @p is_replay marks @ref s_response_retry's replay of a parked
 *  retry_emit/retry_frame node -- s_commit_fail's on_error suppression
 *  reads it, since the node's owner already heard about this same
 *  commit_internal condition on the attempt that first saved it.
 *  @ref s_response_put passes false for every fresh response, a server push
 *  taken inside this very commit included. @p ticket is a fresh one from
 *  @ref s_response_put or the node's own from @ref s_response_retry.
 *
 *  @p redirect carries open destination reservations or cleartext regions
 *  from @ref s_inter_pkt, caching pre-resolved routes. Nullptr for other
 *  callers.
 *
 *  A @c commit_ok for a payload counts in the addressed leg's tx tally, after
 *  the callbacks its xport's commit fired.
 */
static duct_commit_rc_t s_commit_response(duct_session_t *s,
                                          duct_conn_id_t in_conn,
                                          duct_stream_id_t in_stream,
                                          duct_response_t *out,
                                          uint32_t *ticket, bool is_replay,
                                          redirect_t *redirect)
{
    duct_do_if(!s->proto, return commit_closed);
    if (duct_has(out->flags, fl_send_pool_keep) && out->payload.data && s_this_worker
        && s_tx_pool_owns(&s_this_worker->tx_pool, out->payload.data))
        s_tx_pool_hdr_of(out->payload.data)->keep = 1u;
    duct_commit_rc_t rc = commit_ok;
    /* Early declare: assigned once resolved below, read at cleanup's own
     * ticket bookkeeping -- several earlier guards goto cleanup before that
     * resolution runs. */
    duct_conn_t *conn = nullptr;
    tx_seq_ref_t seq = {};
    auto cfg = duct_proto_cfg_of(s->proto);
    /* route() runs only when a field is `same`, seeing the inbound frame's
     * own in_conn/in_stream; its output overwrites only the `same` field(s)
     * -- an explicit author value stays. */
    duct_conn_id_t out_conn = out->conn_id;
    duct_stream_id_t out_stream = out->stream_id;
    /* Author's raw stream_id before route resolution: a server-push claim
     * fires only on an explicit non-zero, non-same override — a route-resolved
     * target is not an author push and must not trigger on_stream_open. */
    duct_stream_id_t out_stream_pre = out_stream;
    if (out_conn == duct_conn_id_same || out_stream == duct_stream_id_same) {
        duct_conn_id_t   rconn = in_conn;
        duct_stream_id_t rstream = in_stream;
        if (redirect && redirect->span) {
            rconn = redirect->conn_id;
            rstream = redirect->stream_id;
        } else if (cfg->route)
            cfg->route(in_conn, in_stream, s->proto_state, &rconn, &rstream);
        if (out_conn == duct_conn_id_same)   out_conn = rconn;
        if (out_stream == duct_stream_id_same) out_stream = rstream;
    }
    out->conn_id   = out_conn;
    out->stream_id = out_stream;
    commit_ctx_t ctx = {
        .s = s, .out_conn = out_conn, .out_stream = out_stream,
        .out = out, .is_replay = is_replay,
        .redirect = redirect,
    };
    /* Server push: an explicit non-zero override on an unclaimed stream
     * claims it and fires on_stream_open, whose response goes through
     * s_response_put ahead of this one's payload. Its code stays out of this
     * call's: morphing commit_ok into commit_internal here lets the caller
     * re-consume — a retry-save use-after-free — or double-release an
     * already-published payload; the push reports its own failure. */
    if (duct_has(cfg->flags, fl_proto_multiplexed)
        && out_stream_pre != 0u && out_stream_pre != duct_stream_id_same
        && s->streams && !duct_session_stream_slot(s, out_stream))
    {
        duct_response_t open_out = {};
        duct_stream_admit_t admit;
        if (duct_session_stream_claim(s, out_stream, &open_out, &admit)) {
            if (cfg->on_stream_open)
                duct_discard s_response_put(s, &open_out, out_conn, out_stream, fl_frame_none,
                                            nullptr, nullptr);
        } else
            s_fire_error(s, cfg, admit == stream_admit_full ? rc_again : rc_invalid_arg);
    }
    if (out->payload.size == 0u) {
        s_fire_send_done(s, cfg, out_conn, out_stream, out, rc_ok);
        goto cleanup;
    }
    size_t eff_max = s_admit_eff_max(cfg);
    duct_do_if(eff_max != 0u && out->payload.size > eff_max,
        rc = s_commit_ctx_fail(&ctx, rc_invalid_arg, commit_invalid);
        goto cleanup;
    );
    duct_do_if(out_conn >= duct_session_max_legs,
        rc = s_commit_ctx_fail(&ctx, rc_invalid_arg, commit_invalid);
        goto cleanup;
    );
    auto handle = duct_session_conn_at(s, out_conn);
    conn = duct_conn_by_handle(handle);
    duct_do_if(!conn,
        rc = s_commit_ctx_fail(&ctx, rc_closed, commit_closed);
        goto cleanup;
    );
    ctx.conn = conn;
    ctx.handle = handle;
    /* A GSO record rides a vnet leg's record prefix or a wire's flags. Staged
     * raw on any other leg it reaches the peer as a malformed packet, so the
     * commit fails and stages nothing. */
    bool flags_ride = s_conn_carries_frame_flags(conn);
    bool gso_blind = duct_has(out->frame_flags, fl_frame_gso) && !flags_ride
                  && !conn->vnet_hdr_len;
    duct_do_if(gso_blind,
        rc = s_commit_ctx_fail(&ctx, rc_not_supported, commit_invalid);
        goto cleanup;
    );
    /* The payload still goes; only the flags have nowhere to ride. The first
     * attempt reports, a replay of the same response stays quiet. */
    if (duct_has(out->frame_flags, duct_or(fl_frame_fin, fl_frame_rst)) && !is_replay
        && !flags_ride)
        s_fire_error(s, cfg, rc_not_supported);
    /* Ticket: this conn's own request-order sequencer, kept in its TX OLB or,
     * for a leg without one, in duct_conn_t::tx_seq -- both park on
     * commit_internal, so both need the order. A replay passes its ticket
     * back in, a fresh caller gets the next one, and a mismatch means an
     * earlier response has not published yet -- order, not space, is
     * enforced. */
    seq = s_tx_seq_of(conn);
    if (seq.next && !s_tx_ticket_take(seq, ticket)) {
        rc = s_commit_ctx_fail(&ctx, rc_again, commit_internal);
        goto cleanup;
    }

    if (!s_engine_park_flush(conn)) {
        rc = s_commit_ctx_fail(&ctx, rc_again, commit_internal);
        goto cleanup;
    }

    switch (conn->xport_type) {
    case x_inter:
        rc = s_commit_inter(&ctx);
        break;
    case x_udp_shared:
        rc = s_commit_dgram_shared(&ctx);
        break;
    case x_udp_peer:
        rc = s_commit_udp_peer(&ctx);
        break;
    case x_tcp:
    case x_raw:
    case x_local:
        rc = s_commit_stream(&ctx);
        break;
    case x_raw_packet:
        rc = s_commit_packet_fd(&ctx);
        break;
    default:
        rc = s_commit_generic(&ctx);
        break;
    }
    if (rc == commit_ok) {
        auto tally = &duct_session_counters(s)[out_conn];
        tally->tx_frames += 1u;
        tally->tx_bytes += out->payload.size;
        s_rekey_on_send(conn);
    }

cleanup:
    /* Resolves the ticket taken at the gate above, exactly once, from
     * whichever exit got here. Skipped when rc is commit_internal. */
    if (seq.serve && rc != commit_internal)
        s_tx_ticket_resolve(seq);
    /* commit_internal is the one exception: ownership passes back to the
     * caller for a possible retry-save read before release -- releasing
     * here too double-releases, and reading after is a use-after-free.
     * Every other outcome releases unconditionally. */
    if (rc != commit_internal)
        duct_response_release_owned(out);
    return rc;
}

/** @brief Log @p out's open_leg declaration when @p rc says the session refused
 *  it. */
static void s_leg_refused(const duct_response_t *out, duct_result_t rc)
{
    if (rc == rc_ok)
        return;
    auto leg = &out->control.open_leg;
    const char *what = leg->kind == leg_kind_inter ? "inter attach"
                     : leg->kind == leg_kind_join  ? "join dial" : "dial";
    const char *why = rc == rc_invalid_arg   ? "bad argument"
                    : rc == rc_invalid_order ? "slot taken, no live leg to take an io thread from, or no join key"
                    : rc == rc_no_memory     ? "out of memory" : "refused";
    duct_diag("%s%s%s at conn %u refused: %s", what, leg->connect_addr ? " " : "",
              leg->connect_addr ? leg->connect_addr : "", (unsigned)leg->conn_id, why);
}

/** @brief Apply @p out's open_leg, timer and rx, the control effects that wait
 *  on no payload.
 *  Runs once per response as it is taken, in the callback's own turn: open_leg's
 *  pointers and timer's id_out name author memory valid through that turn. */
static void s_ctl_apply_now(duct_session_t *s, const duct_response_t *out)
{
    auto w = s_this_worker;
    /* Open leg — leg_kind_accept is a declarative no-op here; leg_kind_inter
     * attaches now. Every effect this pass applies is best-effort and reports
     * nothing to the author: a declaration the session cannot honour is logged
     * by s_leg_refused and absorbed, the author having no move to make on it.
     * A dial already in flight is the exception, reaching on_error through
     * s_msg_exec_connect_leg_error — that failure is the peer's, and retry or
     * fallback is the author's. */
    auto leg = &out->control.open_leg;
    duct_result_t rc = rc_ok;
    if (leg->kind == leg_kind_inter)
        rc = duct_conn_attach_inter(s, leg->conn_id);
    else if (leg->kind == leg_kind_connect || leg->kind == leg_kind_connect_dgram)
        rc = duct_conn_attach_connect(
            s, leg->conn_id, leg->connect_addr,
            leg->kind == leg_kind_connect_dgram ? x_udp_peer : x_tcp,
            leg->tx_prefix, leg->tcp_congestion, leg->egress_if);
    else if (leg->kind == leg_kind_join) {
        uint8_t lead[duct_join_lead_size];
        rc = duct_join_lead(s, leg->conn_id, lead)
           ? duct_conn_attach_connect(
                 s, leg->conn_id, leg->connect_addr, x_tcp,
                 (duct_view_u8){ .data = lead, .size = sizeof lead }, leg->tcp_congestion,
                 leg->egress_if)
           : rc_invalid_order;
    }
    s_leg_refused(out, rc);
    /* A key names one timer of the session: its holder is cancelled and the
     * slot freed before anything starts, so a replaced timer never fires and a
     * zero delay_ms ends at the cancel. A new key takes a free slot; with none
     * free the start is refused. */
    auto tm = &out->control.timer;
    auto tk = duct_session_timer_keys(s);
    unsigned at = tm->key ? s_timer_key_find(tk, tm->key) : session_timer_keys;
    if (at < session_timer_keys) {
        duct_timer_cancel(&w->timers, tk[at].timer);
        tk[at] = (duct_session_timer_key_t){};
    } else if (tm->key)
        at = s_timer_key_find(tk, 0u);
    if (tm->delay_ms != 0u && tm->key && at == session_timer_keys)
        duct_diag("timer key %u refused: every key slot is live", (unsigned)tm->key);
    else if (tm->delay_ms != 0u) {
        uint64_t delay_us = 0u,
                 interval_us = 0u;
        bool of = duct_ckd_mul(&delay_us, tm->delay_ms, 1000u)
               || duct_ckd_mul(&interval_us, tm->interval_ms, 1000u);
        auto ctx = duct_new(timer_ctx_t);
        duct_timer_handle_t h = timer_handle_null;
        if (!of && ctx) {
            auto live = duct_session_handle_from_live(s);
            ctx->session_tok = live.word;
            ctx->token = tm->arg;
            ctx->key = tm->key;
            h = s_timer_start(w, ctx, delay_us, interval_us, s_timer_fire);
        } else
            duct_del(ctx);
        if (tm->id_out)
            *tm->id_out = h != timer_handle_null ? duct_timer_handle_id(h) : 0u;
        if (tm->key && h != timer_handle_null)
            tk[at] = (duct_session_timer_key_t){ .timer = h, .key = tm->key };
    }
    if (tm->cancel_id != 0u) {
        auto gone = duct_timer_make_handle(w->worker_id, 0u, tm->cancel_id);
        duct_timer_cancel(&w->timers, gone);
        for (unsigned i = 0u; i < session_timer_keys; ++i)
            if (tk[i].timer == gone)
                tk[i] = (duct_session_timer_key_t){};
    }
    /* RX pause/resume — per live leg. */
    if (out->control.rx != rx_op_none) {
        duct_conn_handle_t handle;
        duct_session_for_each_leg(s, i, handle) {
            auto conn = duct_conn_by_handle(handle);
            if (!conn)
                continue;
            if (out->control.rx == rx_op_pause)
                duct_conn_state_set(conn, fl_conn_suspended);
            else {
                duct_conn_state_clear(conn, fl_conn_suspended);
                /* A reactive backend's readiness signal may not re-fire for
                 * data that arrived while suspended; post an rx_read so the
                 * io thread reads explicitly on resume. */
                duct_io_post_rx_read(&handle);
            }
        }
    }
}

/** @brief Apply @p out's stream_op and close_target, the control effects that
 *  follow its payload onto the wire. */
static void s_ctl_apply_after(duct_session_t *s, const duct_response_t *out)
{
    /* Stream fin/reset, staged ahead of the close below so a close that drains
     * carries the frame; the imperative calls also tear down the local stream
     * slot. */
    if (out->control.stream_op == stream_op_fin)
        duct_discard duct_stream_close(s, out->control.stream_op_conn_id,
                                       out->control.stream_op_stream_id);
    else if (out->control.stream_op == stream_op_reset)
        duct_discard duct_stream_reset(s, out->control.stream_op_conn_id,
                                       out->control.stream_op_stream_id,
                                       out->control.stream_op_error);
    /* Close intent, after the response is on the wire. */
    if (out->control.close_target == close_target_session)
        duct_session_close_walk(s, out->control.close_reason);
    else if (out->control.close_target == close_target_conn)
        duct_discard duct_conn_close(s, out->control.close_conn_id, out->control.close_reason);
}

/** @brief Apply what follows a response's staged payload: its stream_op and
 *  close, and the close of inbound stream @p stream_id where @p flags carry a
 *  FIN or RST. */
static void s_response_settle(duct_session_t *s, const duct_response_t *out,
                              duct_stream_id_t stream_id, duct_frame_flags_t flags)
{
    s_ctl_apply_after(s, out);
    s_stream_close_on_flags(s, stream_id, flags);
}

/** @brief Take a response of control alone, on_error's or on_send_done's, both
 *  halves at once. */
static void s_response_take_control(duct_session_t *s, const duct_response_t *out)
{
    s_ctl_apply_now(s, out);
    s_ctl_apply_after(s, out);
}

/** @brief Apply @p s's pending protocol switch once no response of it waits
 *  parked.
 *  A parked emit, frame, engine output or FIN/RST stages under its original
 *  wire, so the switch waits for the last of them. Refused switches across
 *  incompatible legs deliver @c rc_invalid_order via @c on_error. */
static void s_response_switch(duct_session_t *s)
{
    if (!s->pending_switch_next)
        return;
    for (auto n = s_this_worker->retry_head; n; n = n->next) {
        duct_conn_handle_t leg;
        switch (n->kind) {
        case retry_emit:
            if (n->emit.hctx->s == s)
                return;
            continue;
        case retry_frame:
            leg = n->frame.handle;
            break;
        case retry_engine:
            leg = n->engine.handle;
            break;
        case retry_fin:
            leg = n->fin.handle;
            break;
        case retry_close:
            leg = n->close.handle;
            break;
        case retry_timer:
        case retry_dgram_tx:
            continue;
        }
        if (duct_session_conn_id_by_handle(s, leg) < duct_session_max_legs)
            return;
    }
    if (duct_session_apply_switch(s) == rc_invalid_order)
        s_fire_error(s, duct_proto_cfg_of(s->proto), rc_invalid_order);
}

/** @brief Release a response its callback declined, and let the turn's switch
 *  through. */
static void s_response_drop(duct_session_t *s, duct_response_t *out)
{
    duct_response_release_owned(out);
    s_response_switch(s);
}

/** @brief Take one response through intake, commit and settle, leaving the
 *  turn's switch pending.
 *  open_leg, timer and rx apply first, whatever the payload does. A committed
 *  payload settles at once; one the ring cannot take parks, as a handler's emit
 *  where @p hctx is set, and settles at its replay. A failed commit has reported
 *  itself. A stream-open push calls this directly: it lands ahead of its
 *  frame's on_frame or inside the pushing response's commit, where a switch is
 *  early.
 *  @return the commit's code, commit_invalid where the park found no memory.
 */
static duct_commit_rc_t s_response_put(duct_session_t *s, duct_response_t *out,
                                       duct_conn_id_t conn_id, duct_stream_id_t stream_id,
                                       duct_frame_flags_t flags, redirect_t *redirect,
                                       duct_stream_ctx_t *hctx)
{
    assert(!duct_has_all(out->flags, duct_or(fl_send_static, fl_send_owned)));
    if (!s->proto) {
        duct_response_release_owned(out);
        return commit_closed;
    }
    s_ctl_apply_now(s, out);
    uint32_t ticket = duct_tx_ticket_fresh;
    auto rc = s_commit_response(s, conn_id, stream_id, out, &ticket, false, redirect);
    if (rc == commit_ok)
        s_response_settle(s, out, stream_id, flags);
    else if (rc == commit_internal
             && !(hctx ? s_retry_emit_save(s_this_worker, hctx, ticket)
                       : s_retry_frame_save(s_this_worker, s, conn_id, stream_id, flags, out,
                                            ticket)))
        rc = commit_invalid;
    return rc;
}

/** @brief Take a turn's own response, then the turn's pending switch unless its
 *  payload parked. */
static duct_commit_rc_t s_response_take(duct_session_t *s, duct_response_t *out,
                                        duct_conn_id_t conn_id, duct_stream_id_t stream_id,
                                        duct_frame_flags_t flags, redirect_t *redirect,
                                        duct_stream_ctx_t *hctx)
{
    auto rc = s_response_put(s, out, conn_id, stream_id, flags, redirect, hctx);
    if (rc != commit_internal)
        s_response_switch(s);
    return rc;
}

/** @brief Replay a parked response's commit on its @p ticket, then settle it
 *  and let the switch through unless it parks again. */
static duct_commit_rc_t s_response_retry(duct_session_t *s, duct_response_t *out,
                                         duct_conn_id_t conn_id, duct_stream_id_t stream_id,
                                         duct_frame_flags_t flags, uint32_t *ticket)
{
    auto rc = s_commit_response(s, conn_id, stream_id, out, ticket, true, nullptr);
    if (rc == commit_ok)
        s_response_settle(s, out, stream_id, flags);
    if (rc != commit_internal)
        s_response_switch(s);
    return rc;
}

/** @brief Stage @p wf onto the listener outbox an @c x_udp_shared leg sends
 *  through, where any other shape has a ring of its own.
 *
 *  Takes the lane slot even on a backend whose data path batches instead:
 *  a stream of responses earns batching, and a control frame is one per
 *  stream close. @ref s_worker_dgram_flush runs first for the ordering that
 *  buys — batched data and a lane entry drain on different schedules, so a fin
 *  published while its own stream's bytes still sit in the batch reaches the
 *  peer ahead of them.
 *
 *  @return The same three outcomes @ref s_ctl_fin_stage maps, a full lane
 *          being @c olb_tx_full.
 */
static duct_olb_tx_result_t
s_ctl_fin_stage_dgram(duct_conn_t *conn, duct_session_t *s, const duct_frame_t *wf)
{
    auto w = s_this_worker;
    duct_do_if(!w || !conn->wire, return olb_tx_too_large);
    size_t need = 0u;
    bool sized = s_tx_wire_need(conn, wf->payload.size, &need);
    duct_do_if(!sized, return olb_tx_too_large);
    auto dctx = (const duct_dgram_shared_ctx_t *)conn->ctx;
    auto listener = dctx->listener;

    s_worker_dgram_flush();
    dgram_out_t dout;
    duct_vmq_push_rc_t push_rc;
    if (!s_dgram_out_open(listener, &dctx->peer, need, &dout, &push_rc)) {
        duct_rtstat_obj_inc(w, rtstats.dgram_shared_tx_drop, 1);
        return push_rc == vmq_push_too_large ? olb_tx_too_large : olb_tx_full;
    }
    auto view = (duct_vmq_tx_view_t){ .data = dout.span.data, .stage = 0u, .capacity = need };
    auto tx_stage = (duct_wire_tx_t){ .kind = wire_tx_vmq_view, .vmq_view = view };
    auto prc = s_wire_pack_into(conn->wire, s, wf, &tx_stage, s_tls_codec(conn));
    if (prc != olb_tx_ok) {
        s_dgram_out_abort(&dout);
        return prc;
    }
    duct_rtstat_obj_inc(w, rtstats.dgram_lane_staged, 1);
    s_dgram_out_publish(&dout, tx_stage.vmq_view.stage);
    duct_io_post_dgram_tx(listener);
    return olb_tx_ok;
}

/** @brief One ticket-ordered FIN/RST staging attempt on @p conn.
 *
 *  Shared by the first attempt (@ref s_ctl_send_fin) and every replay of a
 *  parked one (@ref s_retry_drain). A FIN stages empty; an RST stages @p err
 *  as its four payload bytes, rebuilt from the scalar on each attempt, so a
 *  parked node owns no buffer. Either way the frame carries position: released
 *  ahead of a response still waiting its turn on this leg, it tells the peer
 *  the stream ended before the data that ends it.
 *
 *  Where it stages follows the leg: a ring for the shapes that own one,
 *  @ref s_ctl_fin_stage_dgram's listener outbox for @c x_udp_shared. The ticket
 *  is taken the same way either side of that fork, @ref s_tx_seq_of answering
 *  for a leg with no ring out of @c duct_conn_t::tx_seq.
 *
 *  @retval olb_tx_ok         Published, io woken.
 *  @retval olb_tx_full       Blocked, by an older ticket or by room;
 *                            @p ticket stays outstanding for the retry.
 *  @retval olb_tx_too_large  Terminal; the ticket is resolved here.
 */
static duct_olb_tx_result_t s_ctl_fin_stage(duct_conn_t *conn, duct_session_t *s,
                                            duct_stream_id_t stream_id,
                                            duct_frame_flags_t flg,
                                            duct_stream_error_t err, uint32_t *ticket)
{
    /* duct_conn_tx_olb, never conn->tx_buf: on a leg without a ring that word
     * carries duct_conn_t::tx_seq, which as a pointer looks live once the
     * counters advance. Null from it is the fork below, not a refusal — only a
     * leg with neither ring nor outbox stops here, and every entry filters on
     * s_conn_ctl_stageable first, so this catches the next one that forgets. */
    auto tx = duct_conn_tx_olb(conn);
    bool stageable = s_conn_ctl_stageable(conn);
    duct_do_if(!stageable, return olb_tx_full);
    auto seq = s_tx_seq_of(conn);
    if (!s_tx_ticket_take(seq, ticket) || !s_engine_park_flush(conn))
        return olb_tx_full;
    uint8_t code[4];
    duct_store_be32(code, (uint32_t)err);
    duct_frame_t wf = { .stream_id = stream_id, .flags = flg };
    if (duct_has(flg, fl_frame_rst))
        wf.payload = duct_view(duct_view_u8, (void *)code, sizeof code);
    auto st = tx ? s_tx_stage_frame(conn, s, &wf)
                 : s_ctl_fin_stage_dgram(conn, s, &wf);
    if (st == olb_tx_full)
        return olb_tx_full;
    if (st == olb_tx_ok && tx) {
        duct_olb_tx_publish(tx);
        auto handle = duct_conn_handle_get(conn);
        duct_io_post_tx_drain(&handle);
    }
    s_tx_ticket_resolve(seq);
    return st;
}

/** @brief Stage a FIN or RST control frame on a leg that can carry it, its io
 *  thread woken.
 *
 *  @c duct_conn_id_same takes the first leg that can, searching past those that
 *  cannot; any other value pins the frame to exactly that leg and stops there,
 *  retargeting a named leg being how an author's own mistake goes unseen.
 *  Either way a search ending empty answers @c rc_not_supported through
 *  @c on_error. Invalid configurations (missing wire, unsupported stream
 *  flags, nonexistent leg, or unstageable device) report errors via @c on_error.
 *  The local stream closes regardless; this only answers whether the peer was told.
 *
 *  Ordered behind whatever is already queued on that leg, parking on the
 *  unified retry list when its turn has not come. An RST first voids the
 *  queued tail of its own stream (@ref s_retry_frame_void_stream) — that
 *  tail is bytes the peer discards on arrival. A FIN keeps its tail: it
 *  means "everything before this is the whole stream", so arriving without
 *  that data hands the peer a cleanly truncated stream.
 */
static void s_ctl_send_fin(duct_session_t *s, duct_conn_id_t target,
                                     duct_stream_id_t stream_id, duct_frame_flags_t flg,
                                     duct_stream_error_t err)
{
    duct_conn_handle_t handle;
    duct_session_for_each_leg(s, i, handle) {
        if (target != duct_conn_id_same && i != target)
            continue;
        auto conn = duct_conn_by_handle(handle);
        /* Verifies wire support for FIN frames and staging availability on the
         * target connection. */
        if (!conn || !s_conn_ctl_stageable(conn)
            || !s_conn_can_send_fin(conn, stream_id)) {
            if (target != duct_conn_id_same)
                break;
            continue;
        }
        auto w = s_this_worker;
        if (duct_has(flg, fl_frame_rst) && w)
            s_retry_frame_void_stream(w, handle, stream_id);
        uint32_t ticket = duct_tx_ticket_fresh;
        auto st = s_ctl_fin_stage(conn, s, stream_id, flg, err, &ticket);
        if (st == olb_tx_full
            && !(w && s_retry_fin_save(w, conn, stream_id, flg, err, ticket))) {
            /* Nowhere to park it, so this ticket has no replay left to
             * resolve it — hand it to the same abandon path a failed
             * retry-save uses, and report the frame as dropped below. */
            duct_response_t none;
            duct_response_reset(&none);
            s_commit_ticket_abandon(conn, ticket, &none);
            st = olb_tx_too_large;
        }
        if (st == olb_tx_too_large && s->proto)
            /* Notifies protocol of dropped control frame via rc_invalid_arg. */
            s_fire_error(s, duct_proto_cfg_of(s->proto), rc_invalid_arg);
        return; /* target resolved to this leg */
    }
    if (s->proto)
        s_fire_error(s, duct_proto_cfg_of(s->proto), rc_not_supported);
}

/** @brief Invoke on_timer and take its response.
 *  Shared by s_timer_fire's own fire and s_retry_drain's retry_timer case, the
 *  two places on_timer runs once @p s's @c timer_hold has cleared; an output
 *  that parks here sets that hold.
 */
static void s_timer_invoke(duct_session_t *s, const duct_proto_cfg_t *cfg, uint64_t token)
{
    auto w = s_this_worker;
    assert(!w->hold_conn);
    w->hold_into = &s->timer_hold;
    duct_response_t out;
    duct_response_reset(&out);
    duct_discard cfg->on_timer(s, &out, s->proto_state, token);
    duct_conn_id_t in_conn = duct_conn_id_same;
    duct_conn_handle_t h;
    duct_session_for_each_leg(s, i, h) { in_conn = i; break; }
    duct_discard s_response_take(s, &out, in_conn, duct_stream_id_default, fl_frame_none,
                                 nullptr, nullptr);
    w->hold_into = nullptr;
}

/** @brief Run a free timer's @c on_timer with a null session and release the
 *  response it fills.
 */
static duct_exec_rc_t s_timer_fire_free(void *arg)
{
    auto ctx = (const timer_ctx_t *)arg;
    duct_do_if(!ctx, return exec_done);
    duct_response_t out;
    duct_response_reset(&out);
    duct_discard duct_proto_cfg_of(ctx->proto)->on_timer(nullptr, &out, ctx->user_ctx, ctx->arg);
    duct_response_release_owned(&out);
    return exec_done;
}

static duct_exec_rc_t s_timer_fire(void *arg)
{
    auto ctx = (timer_ctx_t *)arg;
    duct_do_if(!ctx, return exec_done);
    auto w = ctx->w;
    auto stok = (duct_session_handle_t){ .word = ctx->session_tok };
    auto s = duct_session_attached_by_handle(stok);
    if (!s) {
        /* Reclaimed or closing: cancel this (possibly recurring) timer now —
         * resolve will keep failing every future fire otherwise. */
        duct_timer_cancel(&w->timers, ctx->self);
        return exec_done;
    }
    auto cfg = s->proto ? duct_proto_cfg_of(s->proto) : nullptr;
    bool runs = cfg && cfg->on_timer;
    if (runs && s_tx_held(s, &s->timer_hold, nullptr)) {
        /* The session's last timer output waits parked. A repeating timer's
         * tick is dropped, its next one taking its place as the timer set
         * folds overdue ticks; a one-shot fire parks as a retry_timer node,
         * run once that output resolves, its key keeping its slot meanwhile.
         * The timer node itself is left as-is either way. */
        if (s_timer_repeats(w, ctx->self) || s_retry_timer_save(w, ctx))
            return exec_done;
        runs = false;
    }
    s_timer_key_spend(w, s, ctx->key, ctx->self);
    if (runs)
        s_timer_invoke(s, cfg, ctx->token);
    /* Retirement (drain/cancel/destroy) calls t->arg_free(ctx) — here duct_del_fn.
     * exec must not free ctx: drain needs arg alive during exec, and cancel/
     * destroy release it for unfired timers. */
    return exec_done;
}

void duct_worker_session_timers_cancel(const duct_session_handle_t *h)
{
    auto w = s_this_worker;
    if (!w)
        return;
    auto sen = &w->timers.sentinel;
    for (auto t = sen->next; t != sen; t = t->next) {
        /* A free timer holds no session handle to match. */
        if (!t->arg || t->exec == s_timer_fire_free)
            continue;
        auto ctx = (timer_ctx_t *)t->arg;
        if (ctx->session_tok != h->word)
            continue;
        if (t->arg_free)
            t->arg_free(t->arg);
        t->arg = nullptr;
        t->arg_free = nullptr;
        duct_hash_remove(&t->hh);
    }
}

/** @brief Shutdown drain: flush the defer queue and this worker's own lanes,
 *  then cleanup. Every worker runs its own shutdown drain concurrently as it
 *  exits, so — same as the main loop — only @p w's own three lanes are
 *  touched; together all workers still cover every lane exactly once. A ctrl
 *  message that defers on its last attempt completes what it owes and is freed.
 */
static duct_nonnull(1) void s_shutdown_drain(duct_worker_t *w)
{
    duct_do_if(!w->wfq, return);
    auto wfq = w->wfq;
    unsigned lanes[3] = {
        duct_wfq_pri_lane(wfq_pri_hi, w->worker_id, w->n_workers, 0u, w->n_io),
        duct_wfq_pri_lane(wfq_pri_norm, w->worker_id, w->n_workers, 0u, w->n_io),
        duct_wfq_pri_lane(wfq_pri_lo, w->worker_id, w->n_workers, 0u, w->n_io),
    };
    s_defer_drain(w);
    for (;;) {
        s_drain_harvest_ext(w);
        size_t drained = s_drain_ext(w);
        for (unsigned i = 0u; i < 3u; ++i)
            if (lanes[i] < wfq->n_lanes)
                drained += s_drain_range(wfq, lanes[i], lanes[i] + w->n_io, w,
                                                wfq_quota_none, wfq_quota_none);
        drained += s_inter_drain(w);
        if (!drained)
            break;
    }
    while (w->ext_pending.head) {
        auto node = w->ext_pending.head;
        auto next = duct_msg_next(node);
        switch (node->exec_fn ? node->exec_fn(node) : exec_drop) {
        case exec_done:
            break;
        case exec_defer:
        case exec_drop:
            s_ctrl_msg_abandon(node);
            duct_del(node);
            break;
        }
        w->ext_pending.head = next;
    }
    w->ext_pending.tail = nullptr;
    /* Both clears run past the loop above, not before it: an ext_pending
     * exec_fn dispatches, and a dispatch can defer a batch or park a
     * response. Clearing first empties the two lists and lets that same loop
     * refill them. */
    s_defer_clear(&w->defer_q);
    s_retry_clear(w);
}

/** @brief Run one worker sub-pass over every source of worker work.
 *  The run loop makes one busy and one idle pass per iteration.
 *  @return nonzero when the pass moved anything or left work only another
 *  pass reaches: the units drained, else 1 for defer or retry progress, a
 *  retry lap its quota cut short, or a retry node waiting on held pool regions.
 */
static size_t s_run_pass(duct_worker_t *w, unsigned hi_lane, unsigned norm_lane,
                         unsigned lo_lane, struct timespec now)
{
    bool progress = s_defer_drain(w);
    s_drain_harvest_ext(w);
    size_t drained = s_drain_pass(w, hi_lane, norm_lane, lo_lane);
    drained += s_inter_drain(w);
    /* The loop iteration's `now`: timers fire at millisecond coalescing, which
     * the microseconds since its read cannot move. */
    duct_timers_drain_at(&w->timers, now);
    drained += duct_coop_cycle(&w->coop);
    /* After every drain that saves a retry node, so a node saved this pass
     * gets its armed attempt before the worker can park. */
    progress |= s_retry_drain(w);
    /* x_udp_shared responses this sub-pass committed outside a frame
     * batch or an inter lane drain, which send their own: control and
     * host messages, timers, the coop cycle, the retry drain. */
    s_worker_dgram_flush();
    s_vnet_train_flush(w);
    assert(!w->tx_train.frames);
    /* Nothing wakes a retry node blocked on the pool; the pass that frees the
     * held regions has to run on its own. */
    if (s_tx_pool_pass_end(&w->tx_pool) && w->retry_head)
        progress = true;
    return drained ? drained : progress;
}

static void s_run_loop(duct_worker_t *w)
{
    duct_do_if(!w || !w->wfq, return);
    unsigned hi_lane = duct_wfq_pri_lane(wfq_pri_hi, w->worker_id, w->n_workers, 0u, w->n_io),
             norm_lane = duct_wfq_pri_lane(wfq_pri_norm, w->worker_id, w->n_workers, 0u, w->n_io),
             lo_lane = duct_wfq_pri_lane(wfq_pri_lo, w->worker_id, w->n_workers, 0u, w->n_io);
    /* Per-pass timestamps via duct_ticks_mono_ns, cheap enough to read at
     * spin-loop pass rates. Timer deadlines are stamped from the same tick
     * clock, so a deadline and the pass comparing it share one timeline;
     * a park that spans the recalibration window lands on the re-anchor
     * path and returns the real clock on its own. */

    /* x_udp_shared batching scratch, allocated once per worker thread
     * lifetime. Entry bytes live in w->tx_pool; these arrays carry only entry
     * and kick bookkeeping. */
    auto dgram_entries = duct_at(duct_new(duct_worker_dgram_batch_entry_t, duct_async_cycle_quota));
    auto dgram_kick_listeners = duct_at(duct_new(duct_listener_t *, duct_async_cycle_quota));
    auto dgram_pass = duct_new(dgram_pass_t);
    auto vnet_train = duct_new(vnet_train_t);
    duct_do_if(!dgram_entries || !dgram_kick_listeners || !dgram_pass || !vnet_train,
        duct_del(dgram_entries); duct_del(dgram_kick_listeners);
        duct_del(dgram_pass); duct_del(vnet_train); return);
    *dgram_pass = (dgram_pass_t){
        .entries = dgram_entries,
        .kick_listeners = dgram_kick_listeners,
    };

    s_this_worker = w;
    w->dgram_pass = dgram_pass;
    w->vnet_train = vnet_train;
    while (!duct_atomic_load(&w->shutdown, relaxed)) {
        dgram_pass->n = 0u;
        dgram_pass->kick_n = 0u;
        dgram_pass->listener = nullptr;
        duct_rtstat_obj_inc(w, rtstats.loop_pass, 1);
        uint64_t now_ns = duct_ticks_mono_ns();
        w->pass_ns = now_ns;
        auto now = duct_time_from_ns(now_ns);
        duct_timers_drain_at(&w->timers, now);
        size_t drained = s_run_pass(w, hi_lane, norm_lane, lo_lane, now);
        if (drained != 0u) {
            duct_spin_next(&w->spin, true, now_ns);
            continue;
        }
        /* Idle: reclaim quarantined session slots. The close callback fires
         * at the detach/close-request transition, not here — this only
         * reclaims slots, safe with a non-empty defer_q since conn-lost
         * consume discards a conn's defer node before its leg detaches. Conn
         * slots need no idle drain of their own: duct_conn_fence_retire
         * tears one down synchronously the instant no reference remains. */
        duct_sessions_reclaim_idle();
        if (duct_atomic_load(&w->shutdown, acquire))
            break;
        duct_timers_maybe_trim(&w->timers);
        /* Re-check before sleeping: a producer may have posted during dispatch,
         * and a TX-room wake landing after the pass above is erased by this
         * store, so the rerun covers every source, defer and retry included.
         * The seq_cst fence closes the Dekker gap against duct_vmq_notify's
         * publish-then-exchange and io's room release: a plain release store
         * lets this clear sit in the store buffer past the recheck loads, the
         * producer's exchange sees the pre-clear 1 and skips the wake while the
         * rerun sees nothing: lost wakeup, park forever. */
        duct_atomic_store(&w->wake_latch, 0u, release);
        atomic_thread_fence(memory_order_seq_cst);
        drained = s_run_pass(w, hi_lane, norm_lane, lo_lane, now);
        if (drained != 0u) {
            duct_spin_next(&w->spin, true, now_ns);
            continue;
        }
        if (duct_atomic_load(&w->shutdown, acquire))
            break;
        now_ns = duct_ticks_mono_ns();
        now = duct_time_from_ns(now_ns);
        uint32_t timeout_ms = duct_deadline_to_ms_at(duct_timers_nearest(&w->timers), now);
        if (!duct_atomic_load(&w->wake_latch, acquire)) {
            /* Both passes came back empty with no wake latched: this is the
             * worker's empty poll, where its idle stretch starts. */
            bool in_window = duct_spin_next(&w->spin, false, now_ns);
            if (in_window != w->spinning) {
                if (in_window)
                    duct_rtstat_obj_inc(w, rtstats.busy_enter, 1);
                else
                    duct_rtstat_obj_inc(w, rtstats.busy_exit, 1);
                w->spinning = in_window;
            }
            if (in_window) {
                duct_rtstat_obj_inc(w, rtstats.busy_spin, 1);
                duct_cpu_relax();
            } else if (duct_timers_due_soon(&w->timers, now)) {
                /* Sub-millisecond timer deadline pending: relax CPU without
                 * entering blocking wait. */
                duct_cpu_relax();
            } else {
                duct_rtstat_obj_inc(w, rtstats.futex_wait, 1);
                duct_discard duct_futex_wait((void *)&w->wake_latch, 0u, timeout_ms);
            }
        }
    }
    s_shutdown_drain(w);
    /* The drain commits into the train as a pass does. */
    s_vnet_train_flush(w);
    assert(!w->tx_train.frames);
    w->dgram_pass = nullptr;
    w->vnet_train = nullptr;
    duct_del(dgram_pass);
    duct_del(vnet_train);
    duct_del(dgram_entries);
    duct_del(dgram_kick_listeners);
    s_this_worker = nullptr;
}

bool duct_worker_module_init(unsigned n_workers,
                             unsigned n_io,
                             duct_vmq_mpsc_t *wfq,
                             uint64_t seal_key_lifetime_ms)
{
    s_wmod.seal_key_lifetime_ms = seal_key_lifetime_ms;

    s_wmod.workers = duct_at(duct_new(duct_worker_t, n_workers));
    if (!s_wmod.workers)
        return false;
    /* After the array: duct_worker_module_cleanup walks n_workers entries of it. */
    s_wmod.n_workers = n_workers;
    s_wmod.threads = duct_at(duct_new(pthread_t, n_workers));
    if (!s_wmod.threads)
        return false;

    for (unsigned i = 0u; i < n_workers; ++i) {
        auto w = &s_wmod.workers[i];
        w->worker_id = i;
        w->n_workers = n_workers;
        w->n_io = n_io;
        w->wfq = wfq;
        atomic_init(&w->shutdown, false);
        atomic_init(&w->wake_latch, 0u);
        atomic_init(&w->retry_epoch, 0u);
        atomic_init(&w->started, 0u);
        atomic_init(&w->wfq_io_waiters, 0u);
        if (duct_host_egress_enabled()) {
            w->host_egress = duct_vmq_mpsc_new(1u, (size_t[]){ egress_lane_cap });
            if (!w->host_egress)
                return false;
        }
        duct_timers_init(&w->timers);
    }
    for (unsigned lane = 0u; lane < wfq->n_lanes; ++lane)
        duct_vmq_bind_wake(duct_mpsc_ctrl(wfq, lane),
                           &s_wmod.workers[(lane / n_io) % n_workers].wake_latch);
    return true;
}

static void *s_pthread_proc(void *arg)
{
    auto id = (unsigned)(uintptr_t)arg;
    duct_worker_thread_entry(id);
    return nullptr;
}

static constexpr unsigned start_rendezvous_timeout_ms = 1000u;

void duct_worker_thread_entry(unsigned worker_id)
{
    if (worker_id >= s_wmod.n_workers)
        return;
    auto w = &s_wmod.workers[worker_id];
    char dbg_name[16];
    duct_discard snprintf(dbg_name, sizeof dbg_name, "duct-wrk-%hu", (unsigned short)worker_id);
    duct_thread_set_name(dbg_name);
    duct_thread_block_stop_signals();
    /* Workers take the slots after every io thread's with io-first pinning, and
     * the table from slot 0 without it. */
    unsigned pin_slot = (duct_thread_pin_io_first ? w->n_io : 0u) + worker_id;
    w->cpu = duct_thread_pinning ? duct_thread_bind_cpu(pin_slot) : -1;
    if (duct_thread_pinning && w->cpu < 0)
        duct_rtstat_obj_inc(w, rtstats.pin_fail, 1);
    s_this_worker = w;
    /* The statistics shards number the I/O threads first, then the workers. */
    duct_stats_bind(w->n_io + worker_id);
    /* Stackful coro pools use mmap guard pages; TSAN cannot instrument mmap
     * regions ("unexpected memory mapping"). Under TSAN, disable the stackful
     * pool — stackless coros (calloc-backed) remain available. */
    unsigned stack_slots = duct_coro_stack_slots;
#ifdef __SANITIZE_THREAD__
    stack_slots = 0u;
#endif
    if (stack_slots != 0u || duct_coro_sl_slots != 0u)
        duct_coop_init(&w->coop,
                               stack_slots, duct_coro_sl_slots,
                               duct_coro_stack_bytes);
    duct_atomic_store(&w->started, 1u, release);
    duct_futex_wake(&w->started, 1);
    s_run_loop(w);
    duct_coop_fini(&w->coop);
    s_this_worker = nullptr;
    duct_stats_unbind();
}

int duct_worker_thread_cpu(unsigned worker_id)
{
    return worker_id < s_wmod.n_workers ? s_wmod.workers[worker_id].cpu : -1;
}

bool duct_worker_module_start_threads(void)
{
    for (unsigned i = 0u; i < s_wmod.n_workers; ++i) {
        if (pthread_create(&s_wmod.threads[i], nullptr,
                           s_pthread_proc, (void *)(uintptr_t)i) != 0) {
            for (unsigned j = 0u; j < i; ++j) {
                duct_atomic_store(&s_wmod.workers[j].shutdown, true, release);
                s_wake(j);
                pthread_join(s_wmod.threads[j], nullptr);
            }
            return false;
        }
        /* Rendezvous: wait for the thread to init + start (or fail); either
         * way, shutdown+wake+join tears it down before rollback continues —
         * an init-failed thread has already returned on its own, so the
         * extra shutdown store/wake lands on a dead thread and is a
         * harmless no-op. */
        if (!duct_thread_started_wait(&s_wmod.workers[i].started, start_rendezvous_timeout_ms)) {
            duct_atomic_store(&s_wmod.workers[i].shutdown, true, release);
            s_wake(i);
            pthread_join(s_wmod.threads[i], nullptr);
            goto rollback;
        }
    }
    return true;

rollback:
    for (unsigned j = 0u; j < s_wmod.n_workers; ++j) {
        if (duct_atomic_load(&s_wmod.workers[j].started, acquire) == 1u) {
            duct_atomic_store(&s_wmod.workers[j].shutdown, true, release);
            s_wake(j);
            pthread_join(s_wmod.threads[j], nullptr);
        }
    }
    return false;
}

void duct_worker_module_request_shutdown(void)
{
    for (unsigned i = 0u; i < s_wmod.n_workers; ++i) {
        duct_atomic_store(&s_wmod.workers[i].shutdown, true, release);
        s_wake(i);
    }
}

void duct_worker_module_join(void)
{
    for (unsigned i = 0u; i < s_wmod.n_workers; ++i)
        pthread_join(s_wmod.threads[i], nullptr);
}

void duct_worker_module_cleanup(void)
{
    for (unsigned i = 0u; i < s_wmod.n_workers; ++i) {
        duct_timers_destroy(&s_wmod.workers[i].timers);
        s_defer_clear(&s_wmod.workers[i].defer_q);
        /* Late-arrival ctrl nodes (posted after this worker's s_shutdown_drain
         * harvested): workers are joined, so no new producers. They are not
         * executed — sessions are being torn down, so conn-lost and open
         * callbacks have no observable sink — but a stranded invoke or dialed
         * open still reports rc_closed to its completion, then the node is
         * freed. */
        auto head = duct_msg_stack_detach(&s_wmod.workers[i].ctrl_stack);
        while (head) {
            auto next = duct_msg_next(head);
            s_ctrl_msg_abandon(head);
            duct_msg_done(head);
            head = next;
        }
        if (s_wmod.workers[i].host_egress) {
            duct_vmq_mpsc_del(s_wmod.workers[i].host_egress);
            s_wmod.workers[i].host_egress = nullptr;
        }
    }
    /* Clear worker count prior to deallocating worker arrays to safeguard
     * boundary checks. */
    s_wmod.n_workers = 0u;
    duct_del(s_wmod.workers);
    duct_del(s_wmod.threads);
}

bool duct_worker_post_ctrl_msg(unsigned worker_id, duct_msg_t *msg)
{
    if (worker_id >= s_wmod.n_workers)
        return false;
    auto w = &s_wmod.workers[worker_id];
    duct_msg_stack_push(&w->ctrl_stack, msg);
    s_wake(worker_id);
    return true;
}

/** @brief Pre-session connect failure payload — no conn or session exists
 *  yet, see @c duct_error_fn's pre-session semantics.
 */
duct_msg_chain_decl(duct_msg_connect_error,
    const duct_proto_t *proto;
    void               *user_ctx;
    duct_result_t       err;
);

/** @brief Deliver a dial's failure to its protocol.
 *  Answers @c exec_done on every path: the io threads that post it are joined before a
 *  worker's last harvest, so the shutdown drain runs it and its message needs no kind.
 */
static duct_exec_rc_t s_msg_exec_connect_error(void *self)
{
    auto m = (duct_msg_connect_error *)self;
    duct_session_dial_lost(duct_proto_cfg_of(m->proto), m->user_ctx, m->err);
    return duct_msg_done(m);
}

void duct_worker_post_connect_error(unsigned worker_id, const duct_proto_t *proto,
                                    void *user_ctx, duct_result_t err)
{
    auto m = duct_msg_new(duct_msg_connect_error, s_msg_exec_connect_error, nullptr);
    if (!m)
        return;
    m->proto = proto;
    m->user_ctx = user_ctx;
    m->err = err;
    if (!duct_worker_post_ctrl(worker_id, m))
        duct_msg_done(m);
}

/** @brief Live-session leg-dial failure payload.
 *  The session already exists and is resolved by token, same as any other
 *  cross-thread session ctrl message; @see duct_msg_connect_error for the
 *  shape carrying a dial that never reached one.
 */
duct_msg_chain_decl(duct_msg_connect_leg_error,
    duct_handle_t tok;
    duct_result_t err;
);

static duct_exec_rc_t s_msg_exec_connect_leg_error(void *self)
{
    auto m = (duct_msg_connect_leg_error *)self;
    auto stok = (duct_session_handle_t){ .word = m->tok };
    auto s = duct_session_attached_by_handle(stok);
    if (s && s->proto)
        s_fire_error(s, duct_proto_cfg_of(s->proto), m->err);
    return duct_msg_done(m);
}

void duct_worker_post_connect_leg_error(unsigned worker_id, 
                                        const duct_session_handle_t *h,
                                        duct_result_t err)
{
    auto m = duct_msg_new(duct_msg_connect_leg_error,
                                                        s_msg_exec_connect_leg_error,
                                                        nullptr);
    duct_do_if(!m, return);
    m->tok = h->word;
    m->err = err;
    if (!duct_worker_post_ctrl(worker_id, m))
        duct_msg_done(m);
}

/** @brief Session-less timer start payload: the protocol whose @c on_timer runs,
 *  its context, the delay in microseconds and the token.
 */
duct_msg_chain_decl(duct_msg_timer_start,
    const duct_proto_t *proto;
    void               *user_ctx;
    uint64_t            delay_us;
    uintptr_t           arg;
);

/** @brief Arm the timer a start message carries on this worker.
 *  A start that finds no memory for its timer is dropped without a report.
 */
static duct_exec_rc_t s_msg_exec_timer_start(void *self)
{
    auto m = (duct_msg_timer_start *)self;
    auto ctx = duct_new(timer_ctx_t);
    if (ctx) {
        ctx->proto = m->proto;
        ctx->user_ctx = m->user_ctx;
        ctx->arg = m->arg;
        duct_discard s_timer_start(s_this_worker, ctx, m->delay_us, 0u, s_timer_fire_free);
    }
    return duct_msg_done(m);
}

duct_result_t duct_worker_post_timer_start(unsigned worker_id, const duct_proto_t *proto,
                                           void *user_ctx, uint64_t delay_us, uintptr_t arg)
{
    auto m = duct_msg_new(duct_msg_timer_start, s_msg_exec_timer_start, nullptr);
    duct_do_if(!m, return rc_no_memory);
    m->proto = proto;
    m->user_ctx = user_ctx;
    m->delay_us = delay_us;
    m->arg = arg;
    if (duct_worker_post_ctrl(worker_id, m))
        return rc_ok;
    duct_msg_done(m);
    return rc_invalid_order;
}

/** @brief Host-driven invoke payload: @c fn
 *  gets the same full-commit treatment as any response-producing callback,
 *  not on_error/on_send_done's control-only one.
 */
duct_msg_chain_decl(duct_msg_session_invoke,
    duct_handle_t                tok;
    duct_session_fn             fn;
    void                        *ctx;
    duct_session_invoke_done_fn on_done;
    void                        *done_ctx;
);

static duct_exec_rc_t s_msg_exec_session_invoke(void *self)
{
    auto m = (duct_msg_session_invoke *)self;
    auto stok = (duct_session_handle_t){ .word = m->tok };
    auto s = duct_session_attached_by_handle(stok);
    duct_result_t rc = rc_closed;
    if (s) {
        duct_response_t out;
        duct_response_reset(&out);
        rc = m->fn(s, &out, m->ctx);
        duct_response_commit(s, duct_conn_id_primary, duct_stream_id_default, &out);
    }
    if (m->on_done)
        m->on_done(rc, m->done_ctx);
    return duct_msg_done(m);
}

/** @brief Report a dialed open that never ran as lost with @c rc_closed. */
static void s_ctrl_abandon_session_open(duct_msg_session_open *m)
{
    if (m->dialed)
        duct_session_dial_lost(duct_proto_cfg_of(m->proto), m->user_ctx, rc_closed);
}

/** @brief Complete an invoke that never ran with @c rc_closed. */
static void s_ctrl_abandon_session_invoke(duct_msg_session_invoke *m)
{
    if (m->on_done)
        m->on_done(rc_closed, m->done_ctx);
}

/* One case per kind of the ctrl list, calling its handler on the message cast to the kind's type; the
 * kinds of the io list stand as bare cases with nothing to give back. */
#define s_ctrl_abandon_case(name) \
    case msg_kind_##name: s_ctrl_abandon_##name((duct_msg_##name *)msg); break;
#define s_ctrl_abandon_other(name) case msg_kind_##name:

/** @brief Complete what a ctrl message that will never run still owes, by its kind.
 *  A dialed open reaches its protocol's @c on_error and an invoke its @c on_done,
 *  both with @c rc_closed, without running the author's @c fn or opening a
 *  session. The io kinds owe nothing here: the io threads are joined before any
 *  worker shuts down, so none is posted after a worker's last harvest.
 */
static void s_ctrl_msg_abandon(duct_msg_t *msg)
{
    duct_fatal((uintptr_t)msg->arg >= msg_kind_count);
    switch ((duct_msg_kind_t)(uintptr_t)msg->arg) {
    case msg_kind_plain:
    case msg_kind_embedded:
    duct_msg_sweep_io(s_ctrl_abandon_other)
        break;
    duct_msg_sweep_ctrl(s_ctrl_abandon_case)
    }
}
#undef s_ctrl_abandon_case
#undef s_ctrl_abandon_other

bool duct_worker_post_session_invoke(unsigned worker_id, const duct_session_handle_t *tok,
                                        duct_session_fn fn, void *ctx,
                                        duct_session_invoke_done_fn on_done, void *done_ctx)
{
    auto m = duct_msg_new_kind(session_invoke, s_msg_exec_session_invoke);
    if (!m) {
        if (on_done)
            on_done(rc_no_memory, done_ctx);
        return false;
    }
    m->tok = tok->word;
    m->fn = fn;
    m->ctx = ctx;
    m->on_done = on_done;
    m->done_ctx = done_ctx;
    if (!duct_worker_post_ctrl(worker_id, m)) {
        s_ctrl_abandon_session_invoke(m);
        duct_msg_done(m);
        return false;
    }
    return true;
}

duct_result_t duct_stream_close(duct_session_t *s, duct_conn_id_t conn_id,
                                duct_stream_id_t stream_id)
{
    duct_do_if(!s, return rc_invalid_arg);
    s_ctl_send_fin(s, conn_id, stream_id, fl_frame_fin, stream_err_none);
    duct_session_stream_close(s, stream_id, close_normal);
    return rc_ok;
}

duct_result_t duct_stream_reset(duct_session_t *s, duct_conn_id_t conn_id,
                                duct_stream_id_t stream_id, duct_stream_error_t err)
{
    duct_do_if(!s, return rc_invalid_arg);
    s_ctl_send_fin(s, conn_id, stream_id, fl_frame_rst, err);
    duct_session_stream_close(s, stream_id, close_peer);
    return rc_ok;
}

/* A close with nothing parked ahead of it and room for its close_notify posts
 * at once, and so does one whose node finds no memory, its alert staged where
 * the ring or the park takes it. */
void duct_worker_conn_close(duct_conn_handle_t handle, duct_close_reason_t reason)
{
    auto conn = duct_conn_by_handle(handle);
    auto seq = conn && duct_conn_tx_olb(conn)
                    && (reason == close_normal || reason == close_peer || reason == close_protocol_error)
             ? s_tx_seq_of(conn) : (tx_seq_ref_t){};
    if (seq.next) {
        if ((*seq.next != *seq.serve || !s_close_ready(conn, reason))
            && s_retry_close_save(s_this_worker, conn, reason))
            return;
        s_close_notify(conn, reason);
    }
    duct_io_post_close_request(&handle, reason);
}

duct_result_t duct_conn_close(duct_session_t *s, duct_conn_id_t conn_id,
                              duct_close_reason_t reason)
{
    duct_do_if(conn_id >= duct_session_max_legs, return rc_invalid_arg);
    auto handle = duct_session_conn_at(s, conn_id);
    if (!handle.word)
        return rc_ok;
    duct_worker_conn_close(handle, reason);
    return rc_ok;
}

/** @brief I/O thread owning this session's legs; @c conn_io_none when none is live.
 *  Every attach posts to the io_id of a leg already attached, so one session's
 *  legs share one thread and any live leg answers for it.
 */
static unsigned s_session_io_id(const duct_session_t *s)
{
    duct_conn_handle_t handle;
    duct_session_for_each_leg(s, i, handle) {
        auto conn = duct_conn_by_handle(handle);
        if (conn)
            return conn->io_id;
    }
    return conn_io_none;
}

duct_result_t duct_conn_attach_inter(duct_session_t *s, duct_conn_id_t conn_id)
{
    duct_do_if(conn_id >= duct_session_max_legs, return rc_invalid_arg);
    bool occupied = duct_session_conn_at(s, conn_id).word != 0u;
    duct_do_if(occupied, return rc_invalid_order);
    auto io_id = s_session_io_id(s);
    duct_do_if(io_id == conn_io_none, return rc_invalid_order);
    auto cap = duct_proto_cfg_of(s->proto)->max_response;
    bool fits = cap == 0u || duct_host_egress_fits(cap);
    duct_do_if(!fits, return rc_invalid_arg);
    auto stok = duct_session_handle_from_live(s);
    return duct_io_post_attach_inter(io_id, &stok, conn_id, s->proto)
         ? rc_ok : rc_no_memory;
}

/** @brief Attach caller-owned @p fd as an @p xport leg at @p conn_id.
 *  Closes @p fd on every rejection, so ownership transfers whatever the answer.
 *  A packet fd needs a protocol that carries a wire, and the wire the leg binds,
 *  @p leg_wire or the protocol's own, has to fit @p xport's framing: either
 *  failure answers @c rc_invalid_arg.
 */
static duct_result_t s_attach_fd_as(duct_session_t *s, duct_conn_id_t conn_id,
                                    duct_sock_t fd, duct_xport_t xport,
                                    const duct_wire_t *leg_wire)
{
    if (conn_id >= duct_session_max_legs || fd == duct_sock_bad) {
        duct_sock_close(fd);
        return rc_invalid_arg;
    }
    auto cfg = s->proto ? duct_proto_cfg_of(s->proto) : nullptr;
    if (!cfg) {
        duct_sock_close(fd);
        return rc_invalid_order;
    }
    if ((duct_xport_needs_wire(xport) && !cfg->wire)
        || !duct_wire_framing_fits_xport(leg_wire ? leg_wire : cfg->wire, xport)) {
        duct_sock_close(fd);
        return rc_invalid_arg;
    }
    if (duct_session_conn_at(s, conn_id).word) {
        duct_sock_close(fd);
        return rc_invalid_order;
    }
    auto io_id = s_session_io_id(s);
    if (io_id == conn_io_none) {
        duct_sock_close(fd);
        return rc_invalid_order;
    }
    auto stok = duct_session_handle_from_live(s);
    return duct_io_post_attach_fd(io_id, &stok, conn_id, fd, xport, s->proto,
                                  leg_wire)
         ? rc_ok : rc_no_memory;
}

duct_result_t duct_conn_attach_fd(duct_session_t *s, duct_conn_id_t conn_id, duct_sock_t fd)
{
    return s_attach_fd_as(s, conn_id, fd, x_raw, nullptr);
}

duct_result_t duct_conn_attach_packet_fd(duct_session_t *s, duct_conn_id_t conn_id,
                                          duct_sock_t fd, const duct_wire_t *leg_wire)
{
    return s_attach_fd_as(s, conn_id, fd, x_raw_packet, leg_wire);
}

duct_result_t duct_conn_set_tx_prefix(duct_session_t *s, duct_conn_id_t conn_id,
                                      duct_view_u8 prefix)
{
    duct_do_if(conn_id >= duct_session_max_legs, return rc_invalid_arg);
    auto conn = duct_conn_by_handle(duct_session_conn_at(s, conn_id));
    duct_do_if(!conn, return rc_invalid_order);
    auto sc = duct_conn_sealed_ctx(conn);
    duct_do_if(!sc || !sc->codec, return rc_invalid_order);
    auto codec = sc->codec;
    duct_do_if(codec->tx_prefix_len == 0u || !prefix.data
              || prefix.size != codec->tx_prefix_len, return rc_invalid_arg);
    memcpy(codec->prefix, prefix.data, prefix.size);
    return rc_ok;
}

duct_result_t duct_conn_path_mtu(duct_session_t *s, duct_conn_id_t conn_id, uint16_t *out)
{
    duct_do_if(conn_id >= duct_session_max_legs, return rc_invalid_arg);
    auto conn = duct_conn_by_handle(duct_session_conn_at(s, conn_id));
    duct_do_if(!conn, return rc_invalid_order);
    if (conn->xport_type != x_tcp && conn->xport_type != x_udp_peer)
        return rc_not_supported;
    return duct_io_path_mtu(conn, out) ? rc_ok : rc_invalid_order;
}

duct_result_t duct_conn_addrs(duct_session_t *s, duct_conn_id_t conn_id,
                              duct_peer_t *local, duct_peer_t *remote)
{
    duct_do_if(conn_id >= duct_session_max_legs, return rc_invalid_arg);
    auto conn = duct_conn_by_handle(duct_session_conn_at(s, conn_id));
    duct_do_if(!conn, return rc_invalid_order);
    if (conn->xport_type != x_tcp && conn->xport_type != x_udp_peer
        && conn->xport_type != x_udp_shared)
        return rc_not_supported;
    return duct_io_addrs(conn, local, remote);
}

duct_result_t duct_conn_tcp_congestion(duct_session_t *s, duct_conn_id_t conn_id,
                                       char out[duct_tcp_cc_name_max])
{
    duct_do_if(conn_id >= duct_session_max_legs, return rc_invalid_arg);
    auto conn = duct_conn_by_handle(duct_session_conn_at(s, conn_id));
    duct_do_if(!conn, return rc_invalid_order);
    if (conn->xport_type != x_tcp)
        return rc_not_supported;
    return duct_io_tcp_congestion(conn, out);
}

duct_result_t duct_conn_tcp_stats(duct_session_t *s, duct_conn_id_t conn_id, duct_tcp_stats_t *out)
{
    duct_do_if(conn_id >= duct_session_max_legs, return rc_invalid_arg);
    auto conn = duct_conn_by_handle(duct_session_conn_at(s, conn_id));
    duct_do_if(!conn, return rc_invalid_order);
    if (conn->xport_type != x_tcp)
        return rc_not_supported;
    return duct_io_tcp_stats(conn, out);
}

duct_result_t duct_conn_set_ack_timeout(duct_session_t *s, duct_conn_id_t conn_id, uint32_t ms)
{
    duct_do_if(conn_id >= duct_session_max_legs || ms > (uint32_t)INT32_MAX,
               return rc_invalid_arg);
    auto conn = duct_conn_by_handle(duct_session_conn_at(s, conn_id));
    duct_do_if(!conn, return rc_invalid_order);
    if (conn->xport_type != x_tcp)
        return rc_not_supported;
    return duct_io_tcp_ack_timeout(conn, ms);
}

/** @brief Return the GSO record ceiling of vnet leg @p conn: its wire's @c max_frame capped at 65535, bytes. */
static uint16_t s_gso_ceiling(const duct_conn_t *conn)
{
    return (uint16_t)duct_min(conn->wire->max_frame, (size_t)UINT16_MAX);
}

duct_result_t duct_conn_set_gso(duct_session_t *s, duct_conn_id_t conn_id, uint16_t max)
{
    duct_do_if(conn_id >= duct_session_max_legs, return rc_invalid_arg);
    auto conn = duct_conn_by_handle(duct_session_conn_at(s, conn_id));
    duct_do_if(!conn, return rc_invalid_order);
    duct_do_if(!conn->vnet_hdr_len, return rc_not_supported);
    uint16_t ceiling = s_gso_ceiling(conn);
    duct_do_if(max > ceiling, return rc_invalid_arg);
    duct_atomic_store(&conn->vnet_gso, max, relaxed);
    return rc_ok;
}

uint16_t duct_conn_gso_max(const duct_session_t *s, duct_conn_id_t conn_id)
{
    auto conn = conn_id < duct_session_max_legs ? duct_conn_by_handle(duct_session_conn_at(s, conn_id))
                                                : nullptr;
    return conn && conn->vnet_hdr_len ? s_gso_ceiling(conn) : 0u;
}

duct_result_t duct_conn_tx_end(duct_session_t *s, duct_conn_id_t conn_id,
                               duct_tx_pos_t *out, size_t *queued)
{
    duct_do_if(conn_id >= duct_session_max_legs, return rc_invalid_arg);
    auto h = duct_session_conn_at(s, conn_id);
    auto conn = duct_conn_by_handle(h);
    if (!conn)
        return rc_invalid_order;
    auto tx = duct_conn_tx_olb(conn);
    if (!tx)
        return rc_not_supported;
    *out = (duct_tx_pos_t){ .at = tx->stream_end, .leg = h.word };
    *queued = duct_olb_tx_published(tx);
    return rc_ok;
}

bool duct_conn_tx_sent(duct_session_t *s, duct_conn_id_t conn_id, duct_tx_pos_t pos)
{
    if (conn_id >= duct_session_max_legs)
        return true;
    auto h = duct_session_conn_at(s, conn_id);
    auto conn = h.word == pos.leg ? duct_conn_by_handle(h) : nullptr;
    auto tx = conn ? duct_conn_tx_olb(conn) : nullptr;
    return !tx || duct_olb_tx_drained(tx) >= pos.at;
}

bool duct_conn_tx_fits(duct_session_t *s, duct_conn_id_t conn_id, size_t size)
{
    if (conn_id >= duct_session_max_legs)
        return true;
    auto handle = duct_session_conn_at(s, conn_id);
    auto conn = duct_conn_by_handle(handle);
    if (!conn || !duct_conn_tx_olb(conn))
        return true;
    auto cfg = duct_proto_cfg_of(s->proto);
    size_t need = 0u;
    if (!s_tx_frame_need(conn, size, &need)
        || duct_ckd_add(&need, need, duct_worker_admit_need(s->proto, duct_admit_slots(cfg))))
        return false;
    return s_admit_leg_room_flushed(handle, conn, need);
}

size_t duct_conn_tx_quantum(duct_session_t *s, duct_conn_id_t conn_id)
{
    if (conn_id >= duct_session_max_legs)
        return 0u;
    auto conn = duct_conn_by_handle(duct_session_conn_at(s, conn_id));
    auto tx = conn ? duct_conn_tx_olb(conn) : nullptr;
    return tx ? duct_x_sock_tx_quantum(duct_x_sock_tx_of(tx)) : 0u;
}

uint64_t duct_conn_tx_unsent(duct_session_t *s, duct_conn_id_t conn_id)
{
    if (conn_id >= duct_session_max_legs)
        return duct_tx_unsent_unread;
    auto conn = duct_conn_by_handle(duct_session_conn_at(s, conn_id));
    if (!conn || conn->xport_type != x_tcp)
        return duct_tx_unsent_unread;
    return duct_io_tx_unsent(conn);
}

size_t duct_conn_tx_cap(duct_session_t *s, duct_conn_id_t conn_id)
{
    if (conn_id >= duct_session_max_legs)
        return 0u;
    auto conn = duct_conn_by_handle(duct_session_conn_at(s, conn_id));
    auto tx = conn ? duct_conn_tx_olb(conn) : nullptr;
    return tx ? tx->h.buf_size : 0u;
}

duct_conn_counters_t duct_conn_counters(const duct_session_t *s, duct_conn_id_t conn_id)
{
    return conn_id < duct_session_max_legs ? duct_session_counters(s)[conn_id]
                                           : (duct_conn_counters_t){};
}

bool duct_session_closing(const duct_session_t *s)
{
    return duct_atomic_load(&s->state, acquire) != session_state_attached;
}

duct_result_t duct_conn_attach_device(duct_session_t *s, duct_conn_id_t conn_id,
                                      const duct_device_ops_t *ops)
{
    duct_do_if(!ops->release, return rc_invalid_arg);
    bool usable = ops->wait_handle && ops->read
               && (ops->write_reserve != nullptr) == (ops->write_commit != nullptr);
    duct_do_if(!usable, ops->release(ops->ctx); return rc_invalid_arg);
    duct_do_if(ops->rx_span > duct_ipv4_len_max,
               ops->release(ops->ctx); return rc_invalid_arg);
    duct_do_if(conn_id >= duct_session_max_legs,
               ops->release(ops->ctx); return rc_invalid_arg);
    bool occupied = duct_session_conn_at(s, conn_id).word != 0u;
    duct_do_if(occupied, ops->release(ops->ctx); return rc_invalid_order);
    auto io_id = s_session_io_id(s);
    duct_do_if(io_id == conn_io_none, ops->release(ops->ctx); return rc_invalid_order);
    auto stok = duct_session_handle_from_live(s);
    return duct_io_post_attach_device(io_id, &stok, conn_id, ops, s->proto)
         ? rc_ok : rc_no_memory;
}

duct_result_t duct_conn_attach_connect(duct_session_t *s, duct_conn_id_t conn_id,
                                        const char *addr, duct_xport_t xport,
                                        duct_view_u8 tx_prefix, const char *tcp_congestion,
                                        uint32_t egress_if)
{
    duct_do_if(conn_id >= duct_session_max_legs || !addr, return rc_invalid_arg);
    bool occupied = duct_session_conn_at(s, conn_id).word != 0u;
    duct_do_if(occupied, return rc_invalid_order);
    auto io_id = s_session_io_id(s);
    duct_do_if(io_id == conn_io_none, return rc_invalid_order);
    auto live = duct_session_handle_from_live(s);
    auto seed = (duct_conn_intent_t){
        .kind = intent_leg, .proto = s->proto, .xport = xport, .egress_if = egress_if,
        .leg = { .hsession = live.word, .conn_id = conn_id },
    };
    size_t cc_len = tcp_congestion ? strnlen(tcp_congestion, sizeof seed.leg.tcp_congestion) : 0u;
    duct_do_if(cc_len == sizeof seed.leg.tcp_congestion, return rc_invalid_arg);
    if (!duct_seal_prefix_set(&seed.tx_prefix, tx_prefix))
        return rc_invalid_arg;
    if (cc_len)
        memcpy(seed.leg.tcp_congestion, tcp_congestion, cc_len);
    return duct_connect_start(io_id, addr, &seed, duct_proto_cfg_of(s->proto)->connect_timeout_ms);
}

void duct_response_commit(duct_session_t *s,
                          duct_conn_id_t in_conn,
                          duct_stream_id_t in_stream,
                          duct_response_t *out)
{
    duct_do_if(!s, return);
    duct_do_if(!s_this_worker, return);
    duct_discard s_response_take(s, out, in_conn, in_stream, fl_frame_none, nullptr, nullptr);
}

