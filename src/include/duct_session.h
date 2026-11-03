/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_session.h
 *  @brief L5 session — identity, protocol state, dynamic conn array.
 *
 *  A session binds one or more connections to a protocol and its per-session
 *  state. The session closes when its last conn closes (terminal teardown via
 *  @ref duct_session_detach_leg). Allocated from a session pool with
 *  generation-checked handles.
 */

#ifndef DUCT_SESSION_H
#define DUCT_SESSION_H

#include "duct_core.h"
#include "duct_types.h"
#include "duct_conn.h"
#include "duct_hash.h"
#include "duct_olb.h"
#include "duct_protocol.h"
#include "duct_seal_engine.h"
#include "duct_msg.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Slot index component of session handles.
 *  Bounded by @c duct_runtime_max_conns.
 */
typedef uint32_t duct_session_id_t;

/** @brief Generation-checked session token for cross-thread access.
 *
 *  A copyable ticket obtained from @c on_session_open and handed back to
 *  invoke or push-ingress calls; unresolvable once its generation no
 *  longer matches the slot. Public API exposes this as a plain
 *  @c duct_handle_t — internal code casts to this union for @c id / @c gen
 *  access.
 */
typedef union duct_session_handle {
    duct_handle_t word;
    struct {
        duct_session_id_t id;
        uint32_t          gen;
    };
} duct_session_handle_t;

static_assert(sizeof(duct_session_handle_t) == sizeof(duct_handle_t),
    "duct_session_handle_t must be 64 bits");

/** @brief Session lifecycle states. */
typedef enum duct_session_state : uint8_t {
    session_state_free = 0,    /**< Slot is unused. */
    session_state_attached,    /**< Live with at least one attached conn. */
    session_state_closing,     /**< Teardown started; draining pending work. */
    session_state_quarantine,  /**< Closed; held until the drain epoch passes. */
    session_state_count        /**< State count sentinel. */
} duct_session_state_t;

/** @brief Session flags. */
typedef enum duct_session_flags : uint8_t {
    /** @brief Guards session teardown from running more than once. */
    fl_session_teardown_claimed = 1u << 0,

    /** @brief Teardown has finished; the session's memory may be freed. */
    fl_session_teardown_done    = 1u << 1,
} duct_session_flags_t;

static_assert(sizeof(duct_session_flags_t) == sizeof(uint8_t),
    "duct_session_flags_t width must be 8 bits");

static_assert(duct_session_max_streams >= 1u,
    "duct_session_max_streams must be >= 1");

static_assert(duct_session_max_legs >= 1u,
    "duct_session_max_legs must be >= 1");

static_assert((duct_session_max_streams & (duct_session_max_streams - 1u)) == 0u,
    "duct_session_max_streams must be a power of two");
    
/** @brief Epoch-based reclamation grace window.
 *  A freed session slot is not reused for this number of session-pool epochs
 *  after close, so resolve-then-use references captured before the generation
 *  bump have drained.
 */
static constexpr unsigned session_quarantine_epochs = 2u;

/** @brief @c idle_at of a session with no idle timer pending.
 *  Zero; stamps are monotonic-clock readings, which are never zero. */
static constexpr uint64_t session_idle_unarmed = 0u;

typedef struct duct_stream duct_stream_t;
typedef struct duct_stream_ctx duct_stream_ctx_t;

/** @brief A session's join state: the identity its legs are held to and the
 *  key its join leads carry.
 *  The owner worker writes every field; io reads @c key, @c name and @c proto
 *  once the index lists the session, and advances @c window. */
typedef struct duct_session_join {
    uint8_t             key[duct_siphash_key_size]; /**< SipHash key a lead's
                                                       *  MAC runs under. */
    duct_ptr_t(uint8_t) id;                         /**< Identity the
                                                       *  session's first leg
                                                       *  named, an allocation
                                                       *  of its own size;
                                                       *  nullptr until a leg
                                                       *  names its peer. */
    uint16_t            name;    /**< Index name both ends derive. */
    uint32_t            sent;    /**< Counter of the next lead this side
                                   *  builds; 0 while the session holds no
                                   *  key. */
    const duct_proto_t *proto;   /**< Protocol the session had when keyed,
                                   *  which a lead's listener must serve. */
    uint64_t _Atomic    window;  /**< Lead counters taken: the top one in the
                                   *  high half, a mask of the 32 below it in
                                   *  the low. */
} duct_session_join_t;

/** @brief Per-stream state a slot carries beyond its identity. */
typedef enum duct_stream_flags : uint8_t {
    fl_stream_none      = 0u,
    fl_stream_peer_done = 1u << 0, /**< The peer sent @c fl_frame_fin and this
                                     *  side has not finished: the slot stays
                                     *  claimed and its handler runs on, but a
                                     *  further frame from that peer is a
                                     *  protocol error. Raised only where a
                                     *  handler exists — a callback protocol's
                                     *  slot is torn down on the fin frame
                                     *  itself, so it has no half to be in, and
                                     *  a later frame reusing that id claims a
                                     *  fresh stream, firing @c on_stream_open
                                     *  a second time. */
} duct_stream_flags_t;

static_assert(sizeof(duct_stream_flags_t) == sizeof(uint8_t),
    "duct_stream_flags_t must be 8 bits wide");

/** @brief One multiplexed stream within a session.
 *
 *  Intrusive hash-chain link @c hh over the session's @c stream_buckets.
 *  Free slots reuse @c hh.next as the free-list link.
 */
struct duct_stream {
    duct_stream_id_t _Atomic id;    /**< Stream identifier; 0 == free slot. */

    duct_stream_flags_t flags;      /**< Cleared when the slot returns to the
                                      *  free list, so a recycled slot starts
                                      *  where a fresh one does. */

    duct_hash_handle_t hh;          /**< Id hash-chain link. */

    duct_stream_ctx_t *handler_ctx; /**< Live handler coroutine context;
                                      *  non-null only while a multiplexed handler
                                      *  is running or parked between frames.
                                      *  Set on first dispatch, cleared on
                                      *  completion or cancel. */

    void *proto_state;              /**< Per-stream state.
                                      *  From @ref
                                      *  duct_proto_cfg::create_stream_state,
                                      *  or nullptr if unset. */
};

/** @brief L5 session identity.
 *
 *  Fields sit by who touches them and when. The first cacheline holds identity,
 *  lifecycle and protocol binding, written only when a session opens, attaches
 *  or detaches a leg, switches protocol, closes or is reclaimed, so no write to
 *  it falls on the frame path. The second holds what the owner worker touches
 *  per frame: the activity stamp, which each accepted frame writes, the
 *  pending-switch pointers and the first legs, which other threads read only
 *  when a leg attaches, joins or migrates and at a host batch. The rest is cold
 *  or private to one kind of session: the remaining legs, the join state, the
 *  stream table and the payload of a pending switch.
 */
typedef struct duct_session {

    duct_cacheline_struct(
        duct_session_id_t    session_id;  /**< Slot identifier. */

        /** @brief Per-slot monotonic generation. 0 means never issued.
         *  Bumped on acquire and on invalidate, never cleared on free.
         */
        uint32_t _Atomic generation;

        /** @brief Free-list Treiber stack link. */
        uint32_t _Atomic next_free;

        /** @brief Pending-reclaim Treiber stack link.
         *  @see duct_sessions_reclaim
         */
        uint32_t _Atomic reclaim_next;

        /** @brief On the pending-reclaim stack or a reclaim call's local
         *  chain right now. A second push while set folds the chain
         *  into a cycle (push writes @c reclaim_next), leaving
         *  @ref duct_sessions_reclaim walking it forever -- every push
         *  claims this first and skips when already claimed. */
        bool _Atomic     reclaim_queued;

        /** @brief Session's current lifecycle state.
         *  @see duct_session_state_t for the state machine.
         */
        duct_session_state_t _Atomic state;

        /** @brief Session flag bits. */
        duct_session_flags_t _Atomic flags;

        /** @brief Reason recorded at close. */
        duct_close_reason_t  _Atomic close_reason;

        /** @brief Drain epoch before the slot may be reused.
         *
         *  Set to @c drain_epoch + session_quarantine_epochs at the
         *  closing→quarantine transition — a fixed grace, independent of
         *  which conn triggered the close. Written before that state CAS
         *  so concurrent drainers observe the real window.
         */
        uint64_t             _Atomic quarantine_after;

        /** @brief Worker thread that owns this session's protocol logic.
         *
         *  Assigned once, at first leg attach, and immutable after — a
         *  later join leg always routes to this same worker.
         */
        uint32_t _Atomic worker_id;

        /** @brief Attached leg count. Sole writers: the owner worker, on
         *  attach and detach. Never zeroed by the idle drainer.
         */
        uint32_t _Atomic conn_count;

        const duct_proto_t *proto;     /**< Bound protocol descriptor. */

        /** @brief Protocol-owned per-session state, opaque to the runtime.
         *
         *  Lifetime matches the session's own: created at open, released
         *  at close.
         */
        void *proto_state;

        /** @brief Application context pointer, opaque to the runtime. */
        void *user_ctx;
    );

    /** @brief Pass-clock reading of the session's last activity, nanoseconds:
     *  the idle timer's arming, then each frame accepted from a socket leg.
     *  @c session_idle_unarmed while no idle timer is pending. After acquire
     *  only the owner worker writes it.
     */
    uint64_t             idle_at;

    /** @brief Protocol this session is switching to, once the in-flight
     *  response finishes sending; nullptr when no switch is pending.
     *
     *  Worker-private: only the owning worker ever reads or writes it.
     */
    const duct_proto_t *pending_switch_next;

    /** @brief Protocol switch still waiting on every leg's wire rebind.
     *  The async counterpart of @ref pending_switch_next for a
     *  switch whose new protocol's wire differs from the old one.
     *
     *  Nullptr once no such switch is in flight; worker-private, same as
     *  @ref pending_switch_next.
     */
    const duct_proto_t *wire_rebind_next;

    /** @brief Per-leg conn handle, indexed by conn_id; 0 when that leg
     *  is unattached.
     *
     *  Stored as the raw 64-bit word, not the decoded union: an atomic
     *  read through the union's bitfield view is undefined, so every
     *  access loads the scalar first and decodes after — see @ref
     *  duct_session_conn_at. Backed by the pool's own inline slab, alive
     *  for the process's whole life, so a stale read here is never a
     *  dangling pointer, only a stale generation.
     */
    duct_handle_t _Atomic conns[duct_session_max_legs];

    duct_session_join_t  join;             /**< Join key, peer identity and
                                              *  lead window. */

    alignas(duct_cacheline_size) duct_stream_t *streams; /**< Stream table for
                                              *  multiplexed protocols. */
    duct_hash_handle_t **stream_buckets;   /**< Hash bucket heads for the
                                              *  stream table; lazily
                                              *  allocated on first use. */
    duct_hash_handle_t  *stream_free_head; /**< Free-list head via
                                              *  @c hh.next; NULL when the
                                              *  table is full. */
    uint32_t             stream_count;     /**< Number of live streams. */

    /** @brief Legs still to confirm before the wire-changing switch
     *  commits.
     *  A leg leaves once: by its wire fence or, closing first, by its
     *  conn_lost.
     */
    uint32_t             wire_rebind_pending;

    /** @brief Opaque context for the pending protocol switch, passed
     *  unchanged to both the leave and the enter callback of that switch.
     */
    void                *pending_switch_ctx;

    /** @brief Opaque context for the pending wire-changing switch.
     *  The @ref wire_rebind_next counterpart of @ref pending_switch_ctx.
     */
    void                *wire_rebind_ctx;

    /** @brief The session's last timer output while it waits parked, which
     *  holds the next timer fire.
     *  Reset with the slot; worker only.
     */
    duct_tx_hold_t       timer_hold;
} duct_session_t;

static_assert(offsetof(duct_session_t, idle_at) == duct_cacheline_size,
    "the first group must fill exactly one line");
static_assert(offsetof(duct_session_t, conns) + sizeof(duct_handle_t) <= 2 * duct_cacheline_size,
    "the first leg must share the frame path's line");
static_assert(offsetof(duct_session_t, streams) % duct_cacheline_size == 0u,
    "the owner's tail starts on a line of its own, apart from the join window io advances");

/** @brief Reclaim pass for epoch-expired sessions: closing → quarantine → free.
 *
 *  Drains the pending-reclaim stack (pushed onto by @ref duct_session_release,
 *  @ref duct_session_request_close, and the last @ref duct_session_detach_leg —
 *  every site that moves a slot into @c session_state_closing / quarantine),
 *  not a full pool scan; anything not yet ready for this @p drain_epoch is
 *  requeued for the next call. Called from the worker idle path;
 *  @c on_session_close has already fired (in @ref duct_session_detach_leg /
 *  @ref duct_session_request_close) before the slot reaches closing→quarantine
 *  here.
 */
void duct_sessions_reclaim(uint64_t drain_epoch);

/** @brief Idle-driven reclaim pass: closing → quarantine → free.
 *
 *  Bumps the pool's own epoch and drains the session quarantine against it.
 */
void duct_sessions_reclaim_idle(void);

/** @brief Shutdown reclaim: every live session straight to free.
 *
 *  Full pool scan, not a pending-reclaim drain — catches sessions the normal
 *  close path never pushed there (still attached with live conns). For
 *  @ref duct_engine_destroy only, after every I/O and worker thread of the
 *  dying engine has joined: the pool is process-global and outlives one
 *  engine, and a session left live here never reaches any other reclaim.
 */
void duct_sessions_reclaim_shutdown(void);

/** @brief Session slot acquisition from the pool's free stack.
 *  Nullptr if the pool is exhausted.
 */
duct_session_t *duct_session_acquire(void);

/** @brief Resolve the per-leg traffic tallies of @p s, one entry per @c conn_id.
 *
 *  The block is pool storage beside the session slot, outside
 *  @ref duct_session_t, and @ref duct_session_acquire zeroes it. Only the
 *  owner worker writes it.
 */
duct_nonnull(1) duct_conn_counters_t *duct_session_counters(const duct_session_t *s);

/** @brief Keyed timers a session holds live at once.
 *  The public contract of @c duct_response_t's timer key states this figure.
 */
static constexpr unsigned session_timer_keys = 8u;

/** @brief One slot of a session's keyed timers. */
typedef struct duct_session_timer_key {
    uint64_t timer; /**< Handle of the timer started under @c key, as the owner worker's timer set made it. */
    uint32_t key;   /**< Key the timer was started under, 0 for a free slot.
                      *  A one-shot's slot frees as its fire runs, so a fire parked
                      *  for TX room keeps it until the retry resolves. */
} duct_session_timer_key_t;

/** @brief Resolve the keyed-timer slots of @p s, @c session_timer_keys entries.
 *
 *  The block is pool storage beside the session slot, outside
 *  @ref duct_session_t, and @ref duct_session_acquire zeroes it. Only the
 *  owner worker reads or writes it.
 */
duct_nonnull(1) duct_session_timer_key_t *duct_session_timer_keys(const duct_session_t *s);

/** @brief Slots of the join index, four per session slot.
 *  The index lists at most one handle word per session, so it fills to a quarter.
 */
static constexpr unsigned duct_session_join_index_slots = 4u * duct_max_conns;

/** @brief Resolve the join index, @c duct_session_join_index_slots handle words in pool storage.
 *  A zero word, or one that no longer resolves attached, is a free slot. A worker lists its
 *  session by CAS under the name of its lead, and an io thread reads the slots with acquire loads.
 */
duct_handle_t _Atomic *duct_session_join_index(void);

/** @brief Session slot release: quarantine + per-slot generation bump. */
duct_nonnull(1) void duct_session_release(duct_session_t *session);

/** @brief Handle-based session resolve, either @c session_state_attached or
 *  @c session_state_closing.
 *
 *  Nullptr if the generation is stale (slot recycled) or the slot was
 *  never attached. Use @ref duct_session_attached_by_handle to reject a
 *  closing session (join, frame dispatch).
 */
duct_session_t *duct_session_by_handle(duct_session_handle_t h);

/** @brief Handle-based session resolve, strictly @c session_state_attached.
 *  One atomic state read covers both the resolve and the state check.
 */
duct_session_t *duct_session_attached_by_handle(duct_session_handle_t h);

/** @brief Leg attach at @p conn_id.
 *
 *  Stores @p handle at @c conns[conn_id] and sets
 *  @c session_state_attached. Session-side only: the caller binds the conn's
 *  fence separately via @ref duct_conn_session_bind.
 *
 *  @param session   Live session from @ref duct_session_acquire.
 *  @param conn_id   Logical leg index; @c duct_conn_id_primary on first attach.
 *                  Must be < @ref duct_session_max_legs.
 *  @param handle    Generation-checked pool handle for the leg.
 *  @retval rc_ok           Attached.
 *  @retval rc_invalid_arg  Null session or @p conn_id over cap.
 */
duct_result_t
duct_session_attach_conn(duct_session_t *session,
                         duct_conn_id_t conn_id,
                         duct_conn_handle_t handle);

/**
 *  @name Composed lifecycle entry points
 *  Session state-machine composition + lifecycle-callback firing. Production
 *  opens a session only through @ref duct_session_exec_open, which cannot
 *  compose through @ref duct_session_open below — the fence bind and
 *  @c s_conn_start must land ahead of @c create_state and @c on_session_open,
 *  steps this function has no conn to perform. @c destroy_state / io teardown
 *  stay on the worker.
 */
/**@{*/

/** @brief Test-scaffold session open, without a conn fence.
 *
 *  Allocates a session, attaches the first leg, binds @p proto, and fires
 *  @c on_session_open into @p out. Composes @ref duct_session_acquire +
 *  @ref duct_session_attach_conn + @c create_state + @c on_session_open. Not
 *  part of the production open path (see this group's own doc above) — a
 *  direct-session test harness instead. @p out reaches @c on_session_open
 *  verbatim — the caller zero-init's it; a nullptr @p out uses a zero-init
 *  scratch. The caller processes it for TX + control. @p user_ctx is the
 *  value passed to @c on_session_open.
 *
 *  @return The new live session, or nullptr on alloc/attach failure. A
 *  @c create_state failure does not roll back — @c proto_state stays null
 *  and the session still opens, same as @ref duct_session_exec_open.
 */
duct_nonnull(1) duct_session_t *
duct_session_open(const duct_proto_t *proto,
                  duct_conn_id_t conn_id,
                  duct_conn_handle_t handle,
                  void *user_ctx,
                  uint32_t worker_id,
                  duct_response_t *out);

/** @brief Leg detach, with once-guarded session close.
 *
 *  Removes a leg; if it was the last, fires @c on_session_close once and
 *  destroys @c proto_state. Composes the internal leg-removal step with the
 *  once-guarded close fire, which runs only when the removal transitions
 *  the session to closing AND no live legs remain. Idempotent via the
 *  @c fl_session_teardown_claimed once-guard.
 *
 *  @return true if @c on_session_close fired on this call.
 */
duct_nonnull(1) bool
duct_session_detach_leg(duct_session_t *session,
                        duct_conn_id_t conn_id,
                        duct_close_reason_t reason);

/** @brief Session close request.
 *
 *  Marks the session closing and fires @c on_session_close now if no live
 *  legs remain, otherwise defers the fire to the last
 *  @ref duct_session_detach_leg. Sets @c close_reason and
 *  @c session_state_closing. The worker follows this with io teardown +
 *  @ref duct_session_detach_leg per live leg; the last detach fires the
 *  close callback.
 */
duct_nonnull(1) void
duct_session_request_close(duct_session_t *session,
                           duct_close_reason_t reason);

/** @brief Token snapshot from a live session.
 *  A @c nullptr @p s yields a zero token.
 */
static inline duct_session_handle_t
duct_session_handle_from_live(const duct_session_t *s)
{
    return s ? (duct_session_handle_t) {
        .id = s->session_id,
        .gen = duct_atomic_load(&s->generation, acquire)
    } : (duct_session_handle_t){};
}

/** @brief Atomic load of one connection handle from slot @p conn_id.
 *  Decoded with acquire semantics; pairs with release store in
 *  @ref duct_session_attach_conn and detach clear.
 */
static inline duct_conn_handle_t
duct_session_conn_at(const duct_session_t *s, duct_conn_id_t conn_id)
{
    return (duct_conn_handle_t){ .word = duct_atomic_load(&s->conns[conn_id], acquire) };
}

/** @brief Live-leg iteration macro.
 *
 *  @p i (declared by this macro) becomes the conn_id, @p h (pre-declared
 *  by the caller) the resolved handle — the guarded body runs only for a
 *  live leg (@c h.word set).
 */
#define duct_session_for_each_leg(s, i, h) \
    for (duct_conn_id_t i = 0u; i < duct_session_max_legs; ++i) \
        if (((h) = duct_session_conn_at((s), i)).word)

/** @brief Atomic OR into session flags. */
duct_nonnull(1) static inline void
duct_session_state_set(duct_session_t *session, duct_session_flags_t flags)
{
    duct_atomic_fetch(or, &session->flags, flags, release);
}

/** @brief Atomic AND-NOT clear of session flags. */
duct_nonnull(1) static inline void
duct_session_state_clear(duct_session_t *session, duct_session_flags_t flags)
{
    duct_atomic_fetch(and, &session->flags, duct_not(flags),
                      release);
}

/** @brief Atomic session-flags load. */
duct_nonnull(1) static inline duct_session_flags_t
duct_session_state(const duct_session_t *session)
{
    return duct_atomic_load(&session->flags, acquire);
}

/** @brief Bound-session resolve for a conn; nullptr if unbound or freed. */
duct_nonnull(1) duct_session_t *
duct_session_by_conn(const duct_conn_t *conn);

/** @brief Conn_id lookup by pool handle.
 *
 *  @c duct_session_max_legs if absent — a sentinel outside any valid conn_id.
 *  @c conn_count tracks active legs and does not bound the index: an attached
 *  leg id can exceed the count when a lower-numbered sibling has detached.
 */
duct_nonnull(1) duct_conn_id_t
duct_session_conn_id_by_handle(const duct_session_t *s,
                               duct_conn_handle_t h);

/** @brief Close walk: mark closing, post an I/O close per live leg.
 *
 *  Detach happens only when each leg's own conn_lost fence arrives (@ref
 *  duct_session_exec_conn_lost) — this walk must not touch @c s->conns[]
 *  itself, or a leg's deferred frames/streams miss that discard. The last
 *  detach fires on_session_close.
 */
duct_nonnull(1) void
duct_session_close_walk(duct_session_t *s, duct_close_reason_t reason);

/** @brief Session-open node executor.
 *  Runs on the worker; frees @p self via @ref duct_msg_done.
 */
duct_exec_rc_t duct_session_exec_open(void *self);

/** @brief Conn-join node executor.
 *  Frees @p self via @ref duct_msg_done.
 */
duct_exec_rc_t duct_session_exec_conn_join(void *self);

/** @brief Conn-lost node executor.
 *
 *  @p self is a byte-copied VMQ payload (@ref duct_msg_conn_lost is a plain
 *  @c duct_msg_decl, not chainable) — it is never heap-owned and must not
 *  be freed here. A lost leg whose wire fence is still owed leaves the count
 *  of a pending wire-changing switch.
 */
duct_exec_rc_t duct_session_exec_conn_lost(void *self);

/** @brief Wire-rebind fence node executor.
 *
 *  Decrements @c wire_rebind_pending, finishes the switch once every leg
 *  has confirmed. @p self is a byte-copied VMQ payload (@ref
 *  duct_msg_wire_fence is a plain @c duct_msg_decl, not chainable) — it is
 *  never heap-owned and must not be freed here. No-op if the session is
 *  gone or the switch was already abandoned (session close clears
 *  @c wire_rebind_next first). Runs ahead of its conn's conn_lost: io posts no
 *  fence for a conn it has quiesced.
 */
duct_exec_rc_t duct_session_exec_wire_fence(void *self);

/** @brief Report a dial that ended before @c on_session_open to @p cfg's @c on_error.
 *  The callback gets a null session, @p rc and @p user_ctx as its state, and the
 *  response it fills is ignored. Reached by a dialed open that fails, by a
 *  pre-session connect failure, and with @c rc_closed by a packet-fd open or
 *  dialed open that engine teardown drops unrun.
 */
void duct_session_dial_lost(const duct_proto_cfg_t *cfg, void *user_ctx, duct_result_t rc);

/** @brief Session-open ctrl post to the conn's worker.
 *
 *  @p tx_prefix is the prefix a dial declared, empty for an accepted conn;
 *  @p dialed marks an outbound dial or @ref duct_io_attach_packet_fd, whose
 *  pre-open failures report to @c on_error.
 *
 *  @retval true   Posted.
 *  @retval false  Message-alloc failure — the conn stays watched by the
 *                 events backend; the caller must drop it.
 */
bool duct_sessions_post_session_open(duct_conn_t *conn,
                                     const duct_proto_t *proto,
                                     void *user_ctx,
                                     duct_seal_prefix_t tx_prefix,
                                     bool dialed);

/** @brief Conn-join ctrl post to the target session's worker.
 *
 *  @p tx_prefix is a dialed leg's @c open_leg.tx_prefix, empty for any other join.
 *
 *  @retval true   Posted.
 *  @retval false  Message-alloc failure; the caller drops the conn.
 */
bool duct_sessions_post_conn_join(duct_conn_t *conn,
                                  duct_session_handle_t tok,
                                  duct_conn_id_t conn_id,
                                  const duct_peer_t *peer,
                                  duct_seal_prefix_t tx_prefix);

/* Direct control — internal backing for the declarative control.* fields
 * the worker's ctl-apply step executes. */

/** @brief Close leg @p conn_id of @p s.
 *
 *  The session and its other legs stay live. The close goes through
 *  @ref duct_worker_conn_close; the leg detaches once io has closed it and its
 *  fence quiesces.
 *  @retval rc_invalid_arg  @p conn_id past the session's legs.
 *  @retval rc_ok           Requested, or no leg at @p conn_id.
 */
duct_nonnull(1) duct_result_t duct_conn_close(duct_session_t *s,
                                              duct_conn_id_t conn_id,
                                              duct_close_reason_t reason);

/** @brief Push-mode inter-conn attach (multi-conn).
 *
 *  The conn has no fd: the host pushes ingress with @c duct_io_inter_batch and
 *  the runtime emits egress through @c on_packet_out. Backs
 *  @c control.open_leg = { leg_kind_inter, conn_id }; declarative-only, with
 *  no direct author call site.
 */
duct_nonnull(1) duct_result_t duct_conn_attach_inter(duct_session_t *s,
                                                     duct_conn_id_t conn_id);

/** @brief Dial-and-attach leg (multi-conn).
 *
 *  Dials @p addr and attaches the resulting leg at @p conn_id once connected.
 *  Backs the connect, connect_dgram and join kinds of @c control.open_leg.
 *  Starts the dial through @c duct_connect_start under the protocol's
 *  @c connect_timeout_ms, its intent holding copies of @p tx_prefix and
 *  @p tcp_congestion: nothing reads the three pointers past the return.
 *  @p xport is @c x_tcp, @c x_udp_peer or @c x_local, @p addr then a socket path,
 *  and the session wire's framing must fit it; any other value is @c rc_invalid_arg.
 *  @p conn_id must be free and the session must still hold a live leg, which is
 *  where the dial takes its I/O thread: reopening @c duct_conn_id_primary works
 *  while another leg holds the session. Those rejections, an unparsable @p addr,
 *  a @p tx_prefix past @c duct_seal_prefix_max and a @p tcp_congestion of
 *  @c duct_tcp_cc_name_max bytes or more return synchronously with no
 *  @c on_error; a failure once the dial is in flight reaches @c cfg->on_error.
 *  @p tx_prefix travels with this dial alone to the codec of the conn it opens,
 *  a leg whose codec cannot take it refused at its join; @p tcp_congestion,
 *  @c nullptr or empty for the protocol's, names this leg socket's controller.
 *  @p egress_if is the interface index the socket binds to, 0 for none.
 */
duct_nonnull(1) duct_result_t duct_conn_attach_connect(duct_session_t *s,
                                                       duct_conn_id_t conn_id,
                                                       const char *addr,
                                                       duct_xport_t xport,
                                                       duct_view_u8 tx_prefix,
                                                       const char *tcp_congestion,
                                                       uint32_t egress_if);

/** @brief Local FIN close for a stream, no data.
 *
 *  Backs @c control.stream_op = stream_op_fin. For "final data + FIN" the
 *  declarative path uses @ref duct_response_t with @c fl_frame_fin instead —
 *  one response, one wire frame with END_STREAM. @p conn_id is the multi-conn
 *  leg target: @c duct_conn_id_same picks the first live leg with a wire,
 *  the single-conn behavior; any other value pins the FIN to exactly that leg.
 */
duct_result_t duct_stream_close(duct_session_t *s, duct_conn_id_t conn_id,
                                duct_stream_id_t stream_id);

/** @brief Stream abort via RST frame.
 *  Backs @c control.stream_op = stream_op_reset. @p conn_id: see @ref
 *  duct_stream_close. @p err becomes the frame's four payload bytes, which is
 *  how the peer tells a refusal it may retry from one it may not.
 */
duct_result_t duct_stream_reset(duct_session_t *s, duct_conn_id_t conn_id,
                                duct_stream_id_t stream_id,
                                duct_stream_error_t err);

/** @brief Stream-table allocation for a multiplexed session.
 *
 *  Called from both open paths (@ref duct_session_open, @ref
 *  duct_session_exec_open) after the proto is bound, only when
 *  @c fl_proto_multiplexed is set. Non-multiplexed sessions keep @c streams
 *  NULL (zero overhead). Returns @c false on OOM (caller rolls back the open).
 */
bool duct_session_streams_alloc(duct_session_t *s);

/** @brief Live-stream teardown, every slot.
 *  Fires @c on_stream_close + @c destroy_stream_state per slot. Called at
 *  terminal session close, before @c proto is cleared. No-op when
 *  @c streams is NULL.
 */
void duct_session_streams_destroy(duct_session_t *s);

/** @brief Stream-handler cancellation for one conn's legs.
 *
 *  Cancels every stream handler last associated with @p conn_id and tears
 *  down its stream slot; streams owned by other legs are untouched.
 *  Called from @ref duct_session_exec_conn_lost before leg detach, while
 *  @c s->conns[conn_id] still resolves. No-op when @c streams is NULL.
 */
void duct_session_streams_cancel_conn(duct_session_t *s, duct_conn_id_t conn_id,
                                      duct_close_reason_t reason);

/** @brief Stream-table array free, no callbacks.
 *  Called at slot reclaim and pool teardown.
 */
void duct_session_streams_free(duct_session_t *s);

/** @brief Outcome of a stream claim attempt.
 *  Separates admission outcomes for peer responses: a full table is transient,
 *  whereas a protocol rejection is final. None of them is an allocation
 *  failure — the table is built once at @ref duct_session_streams_alloc and
 *  claims pop from its free list.
 */
typedef enum duct_stream_admit : uint8_t {
    stream_admit_ok = 0,     /**< Slot claimed, or already live. */
    stream_admit_full,       /**< No free slot; the protocol never saw the id. */
    stream_admit_rejected,   /**< @c create_stream_state declined the id. */
    stream_admit_unusable,   /**< No stream table, or stream 0. */
} duct_stream_admit_t;

/** @brief Stream claim, with @c create_stream_state + @c on_stream_open.
 *
 *  Idempotent: a second claim of the same id returns the existing slot without
 *  re-firing the hooks. Stream 0 (control) never claims → returns nullptr.
 *  Returns nullptr if @c streams is NULL, @p stream_id is 0, the table is full,
 *  or @c create_stream_state fails; @p admit takes which of those it was, and
 *  may be null. @p out is zero-init'd before @c on_stream_open;
 *  the caller processes it for TX + control only on a non-nullptr return.
 *
 *  @return The claimed slot on success (non-nullptr); the per-stream state is
 *         @c slot->proto_state (may be nullptr when @c create_stream_state is
 *         unset — that is still a successful claim).
 */
duct_stream_t *duct_session_stream_claim(duct_session_t *s,
                                         duct_stream_id_t stream_id,
                                         duct_response_t *out,
                                         duct_stream_admit_t *admit);

/** @brief Stream close, with @c on_stream_close + @c destroy_stream_state.
 *
 *  Idempotent: a no-op if the stream is not claimed. Stream 0 never claims.
 *  Cancels a live handler coro on the owner worker — worker-thread only.
 */
void duct_session_stream_close(duct_session_t *s,
                               duct_stream_id_t stream_id,
                               duct_close_reason_t reason);

/** @brief One stream-slot teardown.
 *
 *  Fires @c on_stream_close + @c destroy_stream_state, returns the slot to
 *  the free list; a live handler stays untouched. Internal: called from
 *  on_done (async_done path) via the worker TU, and as a subroutine of
 *  @ref duct_session_stream_close.
 */
void duct_session_stream_teardown(duct_session_t *s, duct_stream_t *slot,
                                  duct_close_reason_t reason);

/** @brief Live stream-slot lookup for @p stream_id, or NULL. */
duct_stream_t *duct_session_stream_slot(duct_session_t *s,
                                        duct_stream_id_t stream_id);

/** @brief Pending proto-switch execution (recorded by @c duct_proto_switch).
 *
 *  Runs on the worker once the triggering turn's response has staged and no
 *  response of the session waits parked. When the new proto's wire equals the
 *  old one, finishes synchronously: creates the new @c proto_state, fires
 *  @c on_proto_leave (old, with live streams), tears down old live streams,
 *  fires @c on_proto_enter (new), disposes of the old @c proto_state per the
 *  leave disposition, commits @c s->proto + state. When the wire differs, fans
 *  a wire-rebind request out to every leg but an @c x_inter one (@ref
 *  duct_io_post_wire_rebind) and returns; that tail runs from @ref
 *  duct_session_exec_wire_fence once every leg's rebind fence has landed.
 *
 *  @retval rc_ok             Applied, deferred to the fences, or none pending.
 *  @retval rc_closed         A session no longer attached; the switch is dropped.
 *  @retval rc_invalid_order  Refused before any rebind posts: a leg carries a
 *                            wire of its own, or the incoming proto carries none
 *                            while a leg needs one. The caller reports it to
 *                            on_error.
 *  @retval rc_invalid_arg    @p s null.
 */
duct_result_t duct_session_apply_switch(duct_session_t *s);

/** @brief Session-open node, io→session.
 *  Binds a session to an accepted or dialed conn. A dial that named a prefix
 *  carries it in @c tx_prefix, which the conn's codec takes as it is built;
 *  every other open carries none. @c dialed marks a session opened by a dial or
 *  @ref duct_io_attach_packet_fd, so an exit before @c on_session_open reports
 *  to @c on_error.
 */
duct_msg_chain_decl(duct_msg_session_open,
    duct_conn_handle_t  conn;
    duct_conn_id_t      conn_id;
    const duct_proto_t *proto;
    void               *user_ctx;
    duct_seal_prefix_t  tx_prefix;
    bool                dialed);

/** @brief Conn-join node.
 *  Attaches a new leg to an existing session. A dialed leg's node carries the
 *  prefix its dial declared in @c tx_prefix, which the joined conn's codec takes
 *  as it is built; every other join carries none.
 */
duct_msg_chain_decl(duct_msg_conn_join,
    duct_conn_handle_t    conn;
    duct_conn_id_t        conn_id;
    duct_session_handle_t tok;
    duct_peer_t           peer;
    duct_seal_prefix_t      tx_prefix);

/** @brief Conn-lost fence node.
 *
 *  Pushed by the I/O thread directly onto the owner worker's normal WFQ lane
 *  (not the ctrl_stack) so it drains after every frame batch already
 *  accepted for this conn. @c session is the token captured at bind time;
 *  the worker finds the leg via @ref duct_session_conn_id_by_handle, a
 *  stale/absent leg is idempotent.
 */
duct_msg_decl(duct_msg_conn_lost,
    duct_conn_handle_t  conn;
    duct_handle_t       session;
    duct_close_reason_t reason);

/** @brief Wire-rebind fence node.
 *
 *  Pushed by the I/O thread directly onto the owner worker's normal WFQ lane
 *  (not the ctrl_stack) so it drains after every frame batch this conn
 *  already posted under the old wire. @c session is the token captured at
 *  post time; the worker finds the leg via
 *  @ref duct_session_conn_id_by_handle, a stale/absent leg is idempotent.
 */
duct_msg_decl(duct_msg_wire_fence,
    duct_conn_handle_t conn;
    duct_handle_t      session);

#ifdef __cplusplus
}
#endif

#endif /* DUCT_SESSION_H */
