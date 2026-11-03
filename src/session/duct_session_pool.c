/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_session_pool.c
 *  @brief Session pool: Treiber-stack free-list, generation, resolve, quarantine.
 *
 *  O(1) alloc (pop) and free-list reclaim (push), generation tracking, resolve,
 *  and epoch-based-reclamation quarantine drain. Mirrors the conn-pool
 *  Treiber-stack pattern.
 */

#include "duct_core.h"
#include "duct_join.h"
#include "duct_relay.h"
#include "duct_session.h"
#include "duct_treiber.h"
#include "duct_types.h"
#include "duct_worker.h"

#include <string.h>

/** @brief Generation value @c gen_fetch_bump never hands out. */
static constexpr uint32_t gen_sentinel = UINT32_MAX;

/** @brief Session pool: one VM mapping, Treiber-stack free-list + sessions.
 *
 *  @c free_head is a versioned-head Treiber stack (ver|idx, @ref treiber_empty
 *  when empty). @c sessions is the backing session array. @c size is the OS
 *  mapping length for munmap.
 */
typedef struct duct_session_pool {
    uint64_t _Atomic free_head,    /**< Treiber stack head: ver|idx;
                                    * @c treiber_empty when empty. */
                     reclaim_head, /**< Treiber stack head of sessions pending
                                    * @c duct_sessions_reclaim, closing or
                                    * quarantine, not yet free; same ver|idx
                                    * shape as @c free_head. */
                     epoch;        /**< Drain epoch, bumped once per
                                    * @c duct_sessions_reclaim_idle call;
                                    * independent of the conn pool's epoch. */
    size_t           size;
    alignas(duct_cacheline_size)
    duct_conn_counters_t counters[duct_max_conns][duct_session_max_legs]; /**< Per-leg
                                    * traffic tallies, one block per session slot,
                                    * indexed like @c sessions[]. */
    alignas(duct_cacheline_size)
    duct_session_timer_key_t timer_keys[duct_max_conns][session_timer_keys]; /**< Keyed
                                    * timer slots, one block per session slot, indexed
                                    * like @c sessions[]. */
    alignas(duct_cacheline_size)
    duct_handle_t _Atomic join_index[duct_session_join_index_slots]; /**< Name index of
                                    * session join leads, one handle word a slot.
                                    * Reached through @ref duct_session_join_index. */
    alignas(duct_cacheline_size)
    duct_session_t   sessions[];
} duct_session_pool_t;

/** @brief Pop/push/seed over @c sessions[]::next_free. */
DUCT_TREIBER_DECLARE(s_sess_stack, duct_session_t, next_free)
/** @brief Pop/push over @c sessions[]::reclaim_next.
 *
 *  The pending-reclaim stack, scoped to sessions actually mid-close and
 *  drained by @ref duct_sessions_reclaim. No @c _seed call: the stack starts
 *  empty, since no session is mid-close at boot — see
 *  @ref duct_session_pool_ctor.
 */
DUCT_TREIBER_DECLARE(s_reclaim_stack, duct_session_t, reclaim_next)

static duct_session_pool_t *s_pool;

/** @brief Pending-reclaim push, at most once while the session is anywhere
 *  in the reclaim machinery.
 *
 *  That machinery is the shared stack, a reclaim call's local chain, or its
 *  requeue. A duplicate push writes @c reclaim_next on a node already linked
 *  and folds the chain into a cycle @ref duct_sessions_reclaim then walks
 *  forever. @c reclaim_queued is claimed here and released only when the slot
 *  leaves the machinery — freed, or dropped by the reclaim loop default
 *  arm. The requeue path bypasses this wrapper on purpose: its nodes are
 *  still legitimately claimed. */
static void s_reclaim_push_once(duct_session_t *s)
{
    bool was = duct_atomic_exchange(&s->reclaim_queued, true, acq_rel);
    assert(!was);
    if (was)
        return;
    s_reclaim_stack_push(&s_pool->reclaim_head, s_pool->sessions, (uint32_t)s->session_id);
}

/** @brief Per-slot generation +1; skip 0 (never issued) and UINT32_MAX. */
static inline uint32_t gen_fetch_bump(uint32_t _Atomic *g)
{
    uint32_t next;
    do {
        next = duct_atomic_fetch(add, g, 1u, relaxed) + 1u;
    } while (next == 0 || next == gen_sentinel);
    return next;
}

static void duct_session_pool_ctor(void) __attribute__((constructor(DUCT_CTOR_PRI_STATE)));
static void duct_session_pool_ctor(void)
{
    duct_vm_handle_t vm = duct_vm_new(sizeof(duct_session_pool_t) + duct_max_conns * sizeof(duct_session_t));
    duct_fatal(!vm.base || !vm.size);
    s_pool = (duct_session_pool_t *)vm.base;
    s_pool->size = vm.size;
    /* Seed free stack with all session slots; push in reverse so pop
     * yields idx 0 first. mmap is zero-init, but a bare 0|0 head
     * self-loops on slot 0, whose next_free is 0 too, so seed
     * explicitly. */
    s_sess_stack_seed(&s_pool->free_head, s_pool->sessions, duct_max_conns);
    /* Pending-reclaim stack starts empty: no session is mid-close at boot. */
    s_reclaim_stack_seed(&s_pool->reclaim_head, s_pool->sessions, 0u);
    atomic_init(&s_pool->epoch, 0u);
}

static void duct_session_pool_dtor(void) __attribute__((destructor(DUCT_CTOR_PRI_STATE)));
static void duct_session_pool_dtor(void)
{
    for (unsigned i = 0u; i < duct_max_conns; ++i) {
        auto s = &s_pool->sessions[i];
        duct_session_streams_free(s);
    }
    auto vmh = (duct_vm_handle_t){ .base = s_pool, .size = s_pool->size };
    duct_vm_del(&vmh);
    s_pool = nullptr;
}

void duct_sessions_reclaim_idle(void)
{
    duct_sessions_reclaim(duct_atomic_fetch(add, &s_pool->epoch, 1u, relaxed) + 1u);
}

duct_session_t *duct_session_acquire(void)
{
    uint32_t top = s_sess_stack_pop(&s_pool->free_head, s_pool->sessions);
    duct_do_if(top == treiber_empty, return nullptr);
    auto s = &s_pool->sessions[top];
    /* Invalidate any prior life before publishing a new attached session. */
    duct_discard gen_fetch_bump(&s->generation);
    /* Inline conns[]: clear the previous occupant's handles — the
     * slab itself is never freed between reuses. */
    memset(s->conns, 0, sizeof s->conns);
    s->session_id = (duct_session_id_t)top;
    memset(duct_session_counters(s), 0, sizeof s_pool->counters[0]);
    memset(duct_session_timer_keys(s), 0, sizeof s_pool->timer_keys[0]);
    duct_atomic_store(&s->flags, 0u, relaxed);
    duct_atomic_store(&s->close_reason, close_normal, relaxed);
    duct_atomic_store(&s->quarantine_after, 0u, relaxed);
    duct_atomic_store(&s->worker_id, 0u, relaxed);
    s->proto = nullptr;
    s->proto_state = nullptr;
    s->user_ctx = nullptr;
    s->pending_switch_next = nullptr;
    s->pending_switch_ctx = nullptr;
    s->wire_rebind_next = nullptr;
    s->wire_rebind_ctx = nullptr;
    s->wire_rebind_pending = 0u;
    s->timer_hold = (duct_tx_hold_t){};
    s->idle_at = session_idle_unarmed;
    duct_atomic_store(&s->conn_count, 0u, relaxed);
    s->streams = nullptr;
    s->stream_buckets = nullptr;
    s->stream_free_head = nullptr;
    s->stream_count = 0u;
    s->join.id = nullptr;
    s->join.name = 0u;
    s->join.sent = 0u;
    s->join.proto = nullptr;
    duct_atomic_store(&s->join.window, 0u, relaxed);
    duct_atomic_store(&s->state, session_state_attached, release);
    return s;
}

duct_conn_counters_t *duct_session_counters(const duct_session_t *s)
{
    return s_pool->counters[s->session_id];
}

duct_session_timer_key_t *duct_session_timer_keys(const duct_session_t *s)
{
    return s_pool->timer_keys[s->session_id];
}

duct_handle_t _Atomic *duct_session_join_index(void)
{
    return s_pool->join_index;
}

void duct_session_release(duct_session_t *session)
{
    duct_join_forget(session);
    duct_discard gen_fetch_bump(&session->generation);
    duct_atomic_store(&session->conn_count, 0u, relaxed);
    /* No close callback to fire (this is the rollback / pre-open release
     * path — on_session_open never ran), so claim the teardown, which keeps
     * the shutdown walk from firing one, and publish teardown_done now:
     * the drainer's quarantine→free waits for it before reclaiming. */
    duct_atomic_store(&session->flags, 0u, relaxed);
    duct_atomic_fetch(or, &session->flags,
                      duct_or(fl_session_teardown_claimed, fl_session_teardown_done), release);
    /* until before state: rollback reclaims on the next drain (grace = 0),
     * so publish the 0 timer before quarantine. Slot is exclusively owned
     * here (just alloced, never published), so plain store, not the
     * monotonic max used on the closing path. */
    duct_atomic_store(&session->quarantine_after, 0u, relaxed);
    duct_atomic_store(&session->state, session_state_quarantine, release);
    s_reclaim_push_once(session);
}

/** @brief Release-store into one conn slot.
 *
 *  Writes @c conns[conn_id]; the host thread's @ref duct_session_conn_at
 *  races this write via @c duct_io_inter_batch.
 */
static void s_conn_slot_store(duct_session_t *s, duct_conn_id_t conn_id, duct_conn_handle_t handle)
{
    duct_atomic_store(&s->conns[conn_id], handle.word, release);
}

duct_result_t duct_session_attach_conn(duct_session_t *session,
                                       duct_conn_id_t conn_id,
                                       duct_conn_handle_t handle)
{
    duct_do_if(!session, return rc_invalid_arg);
    duct_do_if(conn_id >= duct_session_max_legs, return rc_invalid_arg);
    if (!duct_session_conn_at(session, conn_id).word)
        duct_atomic_fetch(add, &session->conn_count, 1u, relaxed);
    s_conn_slot_store(session, conn_id, handle);
    duct_atomic_store(&session->state, session_state_attached, release);
    return rc_ok;
}

/** @brief CAS attached->closing, pushing onto the pending-reclaim stack on
 *  the winning transition. Idempotent: a session already past attached
 *  loses the CAS and is a no-op — whichever caller won the race already
 *  pushed it.
 */
static void s_session_transition_closing(duct_session_t *s, duct_close_reason_t reason)
{
    duct_atomic_store(&s->close_reason, reason, release);
    duct_session_state_t expected = session_state_attached;
    if (duct_atomic_cas(strong, &s->state, &expected, session_state_closing, acq_rel, relaxed))
        s_reclaim_push_once(s);
}

static duct_result_t s_session_remove_conn(duct_session_t *s,
                                           duct_conn_id_t conn_id,
                                           duct_close_reason_t reason)
{
    duct_do_if(!s, return rc_invalid_arg);
    if (conn_id < duct_session_max_legs && duct_session_conn_at(s, conn_id).word) {
        s_conn_slot_store(s, conn_id, conn_handle_null);
        if (duct_atomic_load(&s->conn_count, relaxed) != 0u)
            duct_atomic_fetch(sub, &s->conn_count, 1u, relaxed);
    }
    if (duct_atomic_load(&s->conn_count, relaxed) == 0u) {
        /* Last leg removed — session → closing. Grace is a fixed session-pool
         * epoch offset; conn-lost teardown already discarded every deferred
         * frame for this session's conns before detach, so no conn-derived
         * epoch input is needed here. */
        s_session_transition_closing(s, reason);
    }
    return rc_ok;
}

/** @brief Once-guarded on_session_close fire.
 *
 *  Fires @c on_session_close + destroys @c proto_state, once, when closing
 *  and no legs remain. Fires on @c session_state_closing or
 *  @c session_state_quarantine (the drainer may have CASed closing→quarantine
 *  before the owner reaches here — the fire still runs, once-guarded).
 *  @c fl_session_teardown_claimed is the once-guard (claim at entry);
 *  @c fl_session_teardown_done is published release @e after the teardown writes
 *  so the drainer's quarantine→free (acquire-load of teardown_done) sees the
 *  teardown happen-before it frees @c conns / streams table. @c conn_count
 *  is atomic: any idle worker zeroes it in quarantine→free, so the read here
 *  is a relaxed load (state already excludes concurrent attach; the count is
 *  only a "no legs" witness).
 */
static bool s_session_maybe_fire_close(duct_session_t *s)
{
    auto st = duct_atomic_load(&s->state, acquire);
    if ((st != session_state_closing && st != session_state_quarantine)
        || duct_atomic_load(&s->conn_count, relaxed) != 0u)
        return false;
    /* Claim the fire once: CAS teardown_claimed 0→1. A concurrent caller (or
     * the drainer reaching quarantine→free after a prior fire) loses and bails. */
    auto exp = duct_atomic_load(&s->flags, relaxed);
    exp = duct_and(exp, duct_not(fl_session_teardown_claimed));
    if (!duct_atomic_cas(strong, &s->flags,
                                &exp,
                                duct_or(exp, fl_session_teardown_claimed),
                                acq_rel,
                                relaxed))
        return false;
    /* No session-owned timer may fire (even a stale-resolve no-op) once
     * teardown starts. */
    auto tok = duct_session_handle_from_live(s);
    duct_worker_session_timers_cancel(&tok);
    auto cfg = s->proto ? duct_proto_cfg_of(s->proto) : nullptr;
    if (cfg) {
        if (cfg->on_session_close)
            cfg->on_session_close(s,
                                  duct_atomic_load(&s->close_reason, relaxed),
                                  s->proto_state);
        if (cfg->destroy_state && s->proto_state)
            cfg->destroy_state(s, cfg->create_state_ctx, s->proto_state);
    }
    s->proto_state = nullptr;
    /* Tear down live streams while the proto callbacks are still resolvable. */
    duct_session_streams_destroy(s);
    s->proto = nullptr;
    /* Zeroed only once the state has left attached. A lead that io matches against the key in
     * the window of that move is MACed under zeroes, and duct_session_exec_conn_join refuses
     * its join on the attached check. */
    duct_secure_zero(s->join.key, sizeof s->join.key);
    /* Freed ahead of teardown_done: the slot is reusable once that is published, and acquire clears the pointer. */
    duct_join_forget(s);
    /* Publish teardown_done: release so the drainer's acquire-load in quarantine→free
     * observes the writes above before it frees @c conns / streams table. */
    duct_atomic_fetch(or, &s->flags, fl_session_teardown_done, release);
    return true;
}

duct_session_t *duct_session_open(const duct_proto_t *proto,
                                  duct_conn_id_t conn_id,
                                  duct_conn_handle_t handle,
                                  void *user_ctx,
                                  uint32_t worker_id,
                                  duct_response_t *out)
{
    auto s = duct_session_acquire();
    duct_do_if(!s, return nullptr);
    auto rc = duct_session_attach_conn(s, conn_id, handle);
    duct_do_if(rc != rc_ok, duct_session_release(s); return nullptr);
    s->proto = proto;
    s->user_ctx = user_ctx;
    /* worker_id before on_session_open: a later join resolves the token the
     * protocol stashes in on_session_open, and the I/O thread's acquire load
     * reads the release store here to route the join post. */
    duct_atomic_store(&s->worker_id, worker_id, release);
    auto cfg = duct_proto_cfg_of(proto);
    if (duct_has(cfg->flags, fl_proto_multiplexed))
        duct_do_if(!duct_session_streams_alloc(s), duct_session_release(s); return nullptr);
    if (cfg->create_state
        && cfg->create_state(s, cfg->create_state_ctx, &s->proto_state) != rc_ok)
        s->proto_state = nullptr;
    if (cfg->on_session_open) {
        auto tok = duct_session_handle_from_live(s);
        cfg->on_session_open(s,
                             *(const duct_handle_t *)&tok,
                             user_ctx,
                             out ? out : &(duct_response_t){},
                             s->proto_state);
    }
    return s;
}

bool duct_session_detach_leg(duct_session_t *session,
                             duct_conn_id_t conn_id,
                             duct_close_reason_t reason)
{
    duct_discard s_session_remove_conn(session, conn_id, reason);
    return s_session_maybe_fire_close(session);
}

void duct_session_request_close(duct_session_t *session,
                                duct_close_reason_t reason)
{
    /* No resurrection: a stale @p session whose slot the drainer already moved
     * past closing (quarantine/free) must not rewind the state machine. */
    auto st = duct_atomic_load(&session->state, acquire);
    if (st == session_state_quarantine || st == session_state_free)
        return;
    /* CAS inside the helper, not a plain store: only the winner of
     * attached→closing has never been pushed onto the pending-reclaim stack
     * yet. A redundant call that finds the session already closing loses
     * the CAS and skips the push — it was already pushed by whichever call
     * (this function or the last duct_session_detach_leg) won the
     * transition first. */
    s_session_transition_closing(session, reason);
    s_session_maybe_fire_close(session);
}

/** @brief Slot lookup + generation check shared by both resolve variants
 *  below. @p out_state reports the session's state on a generation match, so
 *  a strict caller does not re-read the atomic after this returns.
 */
static duct_session_t *s_session_resolve_slot(duct_session_id_t sid,
                                              uint32_t generation,
                                              duct_session_state_t *out_state)
{
    duct_do_if(sid >= duct_max_conns, return nullptr);
    duct_session_t *s = &s_pool->sessions[sid];
    uint32_t gen = duct_atomic_load(&s->generation, acquire);
    if (gen == 0u || gen != generation)
        return nullptr;
    *out_state = duct_atomic_load(&s->state, acquire);
    return s;
}

duct_session_t *duct_session_by_handle(duct_session_handle_t h)
{
    duct_session_state_t st = session_state_free;
    /* Generation is the only staleness check: it does not bump until the
     * closing → quarantine transition (gated on conn_count == 0 and the
     * close-fire teardown completing), so a token captured while attached
     * still matches through the whole closing window. The conn_lost
     * detach and a residual timer fire both need the live pointer during
     * that window to run their closing-specific policy; callers that must
     * reject a closing session (join, frame dispatch) use @ref
     * duct_session_attached_by_handle instead. */
    auto s = s_session_resolve_slot(h.id, h.gen, &st);
    return (s && (st == session_state_attached || st == session_state_closing)) ? s : nullptr;
}

duct_session_t *duct_session_attached_by_handle(duct_session_handle_t h)
{
    duct_session_state_t st = session_state_free;
    auto s = s_session_resolve_slot(h.id, h.gen, &st);
    return (s && st == session_state_attached) ? s : nullptr;
}

/** @brief Monotonic max store.
 *
 *  Stores @p val into @c *ap only if it exceeds the current value. Lets
 *  concurrent closing→quarantine CAS-losers with different drain epochs
 *  only lengthen the grace window, never shorten it. Portable CAS loop
 *  (GCC 13 lacks C23 @c atomic_fetch_max_explicit).
 */
static void s_u64_fetch_max(uint64_t _Atomic *ap, uint64_t val)
{
    for (auto cur = duct_atomic_load(ap, relaxed); val > cur; duct_cpu_relax())
    {
        if (duct_atomic_cas(weak, ap, &cur, val, relaxed, relaxed))
            break;
    }
}

void duct_sessions_reclaim(uint64_t drain_epoch)
{
    /* Phase 1: drain the shared pending-reclaim stack into a local chain
     * (reusing reclaim_next, now exclusively ours per popped slot) instead
     * of scanning all duct_max_conns slots — scopes this call's work to
     * sessions actually mid-close. Grabbing the whole chain up front, before
     * any processing, also means a same-round requeue (phase 3) can never be
     * re-popped by this same loop. */
    uint32_t local = treiber_empty;
    for (uint32_t idx; (idx = s_reclaim_stack_pop(&s_pool->reclaim_head, s_pool->sessions)) != treiber_empty; ) {
        duct_atomic_store(&s_pool->sessions[idx].reclaim_next, local, relaxed);
        local = idx;
    }
    /* Phase 2: process; anything not reaching session_state_free this round is
     * chained onto requeue instead, for phase 3 to push back. */
    uint32_t requeue = treiber_empty;
    while (local != treiber_empty) {
        uint32_t idx = local;
        duct_session_t *s = &s_pool->sessions[idx];
        local = duct_atomic_load(&s->reclaim_next, relaxed);
        bool done = false;
        switch (duct_atomic_load(&s->state, acquire)) {
        case session_state_closing:
            /* closing → quarantine: only once every leg has detached, since
             * that leg's conn_lost fence otherwise resolves a stale token,
             * and teardown has published fl_session_teardown_done. Grace
             * timer is a monotonic max, published before the CAS so its
             * release orders it ahead of quarantine for any concurrent
             * drainer. Exactly one winner bumps gen. */
            if (duct_atomic_load(&s->conn_count, relaxed) != 0u
                || !(duct_atomic_load(&s->flags, acquire) & fl_session_teardown_done))
                break;
            s_u64_fetch_max(&s->quarantine_after, drain_epoch + session_quarantine_epochs);
            duct_session_state_t expected = session_state_closing;
            if (duct_atomic_cas(strong, &s->state, &expected, session_state_quarantine, acq_rel, acquire))
                duct_discard gen_fetch_bump(&s->generation);
            break;
        case session_state_quarantine:
            if (duct_atomic_load(&s->quarantine_after, relaxed) > drain_epoch)
                break;
            /* quarantine → free: conn_count confirms no attached leg, and
             * teardown_done confirms maybe_fire_close's on_session_close /
             * destroy_state / streams_destroy already ran — freeing the
             * streams table before that races the owner still walking
             * it. conns[] is inline, nothing to free there. Not
             * yet done: skip this round, retry on a later drain.
             * Generation stays non-zero on reuse (conn-pool style). */
            if (duct_atomic_load(&s->conn_count, relaxed) != 0u
                || !(duct_atomic_load(&s->flags, acquire) & fl_session_teardown_done))
                break;
            expected = session_state_quarantine;
            if (duct_atomic_cas(strong, &s->state, &expected, session_state_free, acq_rel, acquire)) {
                duct_session_streams_free(s);
                duct_atomic_store(&s->flags, 0u, relaxed);
                duct_atomic_store(&s->quarantine_after, 0u, relaxed);
                /* Leaving the reclaim machinery: release the push claim
                 * before the slot becomes acquirable again. */
                duct_atomic_store(&s->reclaim_queued, false, release);
                s_sess_stack_push(&s_pool->free_head, s_pool->sessions, (uint32_t)s->session_id);
                done = true;
            }
            break;
        default:
            /* Unreachable by construction — every push site moves a slot to
             * closing or quarantine before pushing. A slot that shows up here
             * in a state this loop cannot advance is dropped; this surfaces an
             * invariant break as a leak to chase, avoiding a silent infinite requeue. */
            duct_atomic_store(&s->reclaim_queued, false, release);
            done = true;
            break;
        }
        if (!done) {
            duct_atomic_store(&s->reclaim_next, requeue, relaxed);
            requeue = idx;
        }
    }
    /* Phase 3: publish not-yet-ready sessions back for the next call. */
    while (requeue != treiber_empty) {
        uint32_t idx = requeue;
        requeue = duct_atomic_load(&s_pool->sessions[idx].reclaim_next, relaxed);
        s_reclaim_stack_push(&s_pool->reclaim_head, s_pool->sessions, idx);
    }
}

/* Single-threaded by construction, same as duct_io_cleanup conn walk —
 * plain stores throughout, no CAS needed. The s_session_maybe_fire_close
 * firing-flag guard makes it safe to call unconditionally here, even on a
 * session the graceful path already fired. */
void duct_sessions_reclaim_shutdown(void)
{
    for (uint32_t idx = 0u; idx < duct_max_conns; ++idx) {
        auto s = &s_pool->sessions[idx];
        if (duct_atomic_load(&s->state, relaxed) == session_state_free)
            continue;
        duct_atomic_store(&s->conn_count, 0u, relaxed);
        if (duct_atomic_load(&s->state, relaxed) == session_state_attached)
            duct_atomic_store(&s->state, session_state_closing, relaxed);
        s_session_maybe_fire_close(s);
        duct_session_streams_free(s);
        duct_atomic_store(&s->flags, 0u, relaxed);
        duct_atomic_store(&s->quarantine_after, 0u, relaxed);
        /* The pool outlives the engine: a claim left set here makes the
         * next engine instance skip this slot's first reclaim push. */
        duct_atomic_store(&s->reclaim_queued, false, relaxed);
        duct_discard gen_fetch_bump(&s->generation);
        duct_atomic_store(&s->state, session_state_free, relaxed);
        s_sess_stack_push(&s_pool->free_head, s_pool->sessions, idx);
    }
    /* The pending-reclaim stack may still hold entries for slots just
     * force-freed above. Left in place they outlive this engine, and a
     * next instance's fresh push for a reused slot then coexists with
     * the stale entry -- the same slot on the stack twice, which a
     * single reclaim pass pops twice and folds into a self-cycle its
     * chain walk never exits. Single-threaded here: reset outright. */
    s_reclaim_stack_seed(&s_pool->reclaim_head, s_pool->sessions, 0u);
}
