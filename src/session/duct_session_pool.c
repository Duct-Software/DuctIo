/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_session_pool.c
 *  @brief Session pool: 64 KB blocks over duct_block_pool, owner-run reclaim.
 *
 *  One block per session slot; the slot index is the block number. Page 0
 *  carries the body, the per-leg counters, the keyed-timer slots, the timer
 *  hold and the session-owned retry maps, and stays resident for the
 *  process's whole life. The owner worker runs every transition past
 *  @c sess_attached and drains its own reclaim list on its idle pass.
 */

#include "duct_core.h"
#include "duct_join.h"
#include "duct_relay.h"
#include "duct_session.h"
#include "duct_session_block.h"
#include "duct_types.h"
#include "../pool/duct_block_pool.h"

#include <assert.h>
#include <string.h>

/** @brief Generation value @c gen_fetch_bump never hands out. */
static constexpr uint32_t gen_sentinel = UINT32_MAX;

/** @brief Grace ticks a dead session owes before its block returns. */
static constexpr uint8_t session_grace_ticks = 2u;

/** @brief Blocks the watermark keeps warm below its floor. */
static constexpr uint32_t session_pool_floor_blocks = 8u;

/** @brief The process-global session pool: the block pool and the join
 *  index beside it, made by the state constructor. */
typedef struct duct_session_pool {
    duct_block_pool_t                blocks;
    duct_ptr_t(_Atomic duct_handle_t) join_index;
} duct_session_pool_t;

static duct_session_pool_t *s_pool;

static void duct_session_pool_ctor(void) __attribute__((constructor(DUCT_CTOR_PRI_STATE)));
static void duct_session_pool_ctor(void)
{
    s_pool = duct_new(duct_session_pool_t);
    duct_fatal(!s_pool);
    duct_fatal(!duct_block_pool_init(&s_pool->blocks, duct_max_conns, session_block_size,
                                     duct_session_page0(),
                                     (size_t)session_pool_floor_blocks * session_block_size));
    s_pool->join_index = duct_new(_Atomic duct_handle_t, duct_session_join_index_slots);
    duct_fatal(!s_pool->join_index);
}

static void duct_session_pool_dtor(void) __attribute__((destructor(DUCT_CTOR_PRI_STATE)));
static void duct_session_pool_dtor(void)
{
    duct_sessions_reclaim_shutdown();
    duct_block_pool_shutdown(&s_pool->blocks);
    duct_del(s_pool->join_index);
    duct_del(s_pool);
    s_pool = nullptr;
}

/** @brief Per-slot generation +1; skip 0 (never issued) and UINT32_MAX. */
static inline uint32_t gen_fetch_bump(uint32_t _Atomic *g)
{
    uint32_t next;
    do {
        next = duct_atomic_fetch(add, g, 1u, relaxed) + 1u;
    } while (next == 0u || next == gen_sentinel);
    return next;
}

uint32_t duct_session_idx_get(const duct_session_t *s)
{
    return (uint32_t)(((uintptr_t)s - (uintptr_t)s_pool->blocks.vm.base)
                      / session_block_size);
}

duct_session_t *duct_session_block_at(uint32_t idx)
{
    return (duct_session_t *)duct_block_pool_at(&s_pool->blocks, idx);
}

bool duct_session_block_live(uint32_t idx)
{
    if (idx >= s_pool->blocks.n_blocks)
        return false;
    return duct_atomic_load(&duct_at(s_pool->blocks.meta)[idx].state, acquire)
        == blk_active;
}

struct duct_block_pool *duct_session_pool_blocks(void)
{
    return &s_pool->blocks;
}

duct_conn_counters_t *duct_session_counters(const duct_session_t *s)
{
    return (duct_conn_counters_t *)((uintptr_t)s + session_off_counters);
}

duct_session_timer_key_t *duct_session_timer_keys(const duct_session_t *s)
{
    return (duct_session_timer_key_t *)((uintptr_t)s + session_off_timer_keys);
}

duct_handle_t _Atomic *duct_session_join_index(void)
{
    return duct_at(s_pool->join_index);
}

duct_session_handle_t duct_session_handle_from_live(const duct_session_t *s)
{
    return s ? (duct_session_handle_t) {
        .id = duct_session_idx_get(s),
        .gen = duct_atomic_load(&s->generation, acquire)
    } : (duct_session_handle_t){};
}

duct_session_t *duct_session_acquire(uint32_t worker_id)
{
    assert(worker_id < duct_runtime_max_workers);
    uint32_t idx = duct_block_pool_acquire(&s_pool->blocks);
    if (idx == duct_blk_none) {
        duct_sweep_cursor_t help = {};
        bool pending = true;
        while (pending && idx == duct_blk_none) {
            pending = duct_block_pool_sweep_step(&s_pool->blocks, &help, 1u);
            idx = duct_block_pool_acquire(&s_pool->blocks);
        }
        if (idx == duct_blk_none)
            return nullptr;
    }
    auto s = duct_session_block_at(idx);
    duct_discard gen_fetch_bump(&s->generation);
    memset(s->conns, 0, sizeof s->conns);
    s->flags = fl_session_none;
    s->close_reason = close_normal;
    s->grace_left = 0u;
    s->reclaim_next = duct_blk_none;
    s->worker_id = (uint8_t)worker_id;
    s->conn_count = 0u;
    s->proto = nullptr;
    s->proto_state = nullptr;
    s->user_ctx = nullptr;
    s->switch_next = nullptr;
    s->switch_stage = switch_none;
    s->switch_ctx = nullptr;
    s->switch_pending = 0u;
    s->idle_at = session_idle_unarmed;
    s->stream_free_head = nullptr;
    s->stream_count = 0u;
    s->join.id = nullptr;
    s->join.name = 0u;
    s->join.sent = 0u;
    s->join.proto = nullptr;
    duct_atomic_store(&s->join.window, 0u, relaxed);
    memset((uint8_t *)s + session_off_counters, 0,
           (size_t)duct_session_page0() - session_off_counters);
    duct_atomic_store(&s->state, sess_attached, release);
    return s;
}

/** @brief Idempotent cold reset of every session-owned word the block
 *  carries: the join identity and its key, the streams region, the per-leg
 *  counters and the keyed-timer slots. Shared by the rollback release and
 *  the last-detach teardown; the pool's acquire reset covers the rest.
 *  Runs while @c s->proto still names the protocol of the live streams —
 *  the teardown clears it right after.
 */
static void s_session_cold_free(duct_session_t *s)
{
    duct_join_forget(s);
    /* Zeroed only once the state has left attached. A lead that io matches against the key in
     * the window of that move is MACed under zeroes, and duct_session_exec_conn_join refuses
     * its join on the attached check. */
    duct_secure_zero(s->join.key, sizeof s->join.key);
    duct_session_streams_destroy(s);
    s->stream_free_head = nullptr;
    s->stream_count = 0u;
    s->flags = fl_session_none;
    memset(duct_session_counters(s), 0,
           duct_session_max_legs * sizeof(duct_conn_counters_t));
    memset(duct_session_timer_keys(s), 0,
           session_timer_keys * sizeof(duct_session_timer_key_t));
}

static void s_session_free_push(duct_session_t *s)
{
    duct_discard gen_fetch_bump(&s->generation);
    duct_atomic_store(&s->state, sess_free, relaxed);
    duct_block_pool_release(&s_pool->blocks, duct_session_idx_get(s),
                            duct_session_stats(s)->touched);
}

void duct_session_release(duct_session_t *session)
{
    s_session_cold_free(session);
    s_session_free_push(session);
}

bool duct_session_dead_tick(duct_session_t *s)
{
    if (s->grace_left) {
        --s->grace_left;
        return false;
    }
    s_session_free_push(s);
    return true;
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
        ++session->conn_count;
    s_conn_slot_store(session, conn_id, handle);
    duct_atomic_store(&session->state, sess_attached, release);
    return rc_ok;
}

/** @brief Owner-side attached→closing publication.
 *
 *  Owner-only by the §1 invariant, so a guarded plain pair carries it; a
 *  session already past @c sess_attached is left alone — no resurrection of
 *  a closing, dead or freed slot.
 */
static void s_session_transition_closing(duct_session_t *s, duct_close_reason_t reason)
{
    if (duct_atomic_load(&s->state, acquire) != sess_attached)
        return;
    s->close_reason = reason;
    duct_atomic_store(&s->state, sess_closing, release);
}

/** @brief Once-guarded on_session_close fire, straight into @c sess_dead.
 *
 *  Fires @c on_session_close + destroys @c proto_state, once, when closing
 *  and no legs remain: the state word itself is the once-guard — only the
 *  owner runs this, and a session already in @c sess_dead has had its
 *  teardown. The cold free folds in, the grace arms, and the owner's
 *  reclaim list takes the slot; off a worker thread (the shutdown walk)
 *  the push is a no-op and the walker itself returns the block.
 */
static bool s_session_maybe_fire_close(duct_session_t *s)
{
    if (duct_atomic_load(&s->state, acquire) != sess_closing || s->conn_count != 0u)
        return false;
    auto tok = duct_session_handle_from_live(s);
    duct_worker_session_timers_cancel(&tok);
    duct_worker_session_defer_discard(s);
    auto cfg = s->proto ? duct_proto_cfg_of(s->proto) : nullptr;
    if (cfg) {
        if (cfg->on_session_close)
            cfg->on_session_close(s, s->close_reason, s->proto_state);
        if (cfg->destroy_state && s->proto_state)
            cfg->destroy_state(s, cfg->create_state_ctx, s->proto_state);
    }
    s->proto_state = nullptr;
    s_session_cold_free(s);
    s->proto = nullptr;
    s->grace_left = session_grace_ticks;
    duct_atomic_store(&s->state, sess_dead, release);
    duct_worker_reclaim_add(s);
    return true;
}

static bool s_session_remove_conn(duct_session_t *s,
                                  duct_conn_id_t conn_id,
                                  duct_close_reason_t reason)
{
    duct_do_if(!s, return false);
    if (conn_id < duct_session_max_legs && duct_session_conn_at(s, conn_id).word) {
        s_conn_slot_store(s, conn_id, conn_handle_null);
        if (s->conn_count)
            --s->conn_count;
    }
    if (s->conn_count != 0u)
        return false;
    s_session_transition_closing(s, reason);
    return s_session_maybe_fire_close(s);
}

duct_session_t *duct_session_open(const duct_proto_t *proto,
                                  duct_conn_id_t conn_id,
                                  duct_conn_handle_t handle,
                                  void *user_ctx,
                                  uint32_t worker_id,
                                  duct_response_t *out)
{
    auto s = duct_session_acquire(worker_id);
    duct_do_if(!s, return nullptr);
    auto rc = duct_session_attach_conn(s, conn_id, handle);
    duct_do_if(rc != rc_ok, duct_session_release(s); return nullptr);
    s->proto = proto;
    s->user_ctx = user_ctx;
    auto cfg = duct_proto_cfg_of(proto);
    if (duct_has(cfg->flags, fl_proto_multiplexed))
        duct_session_streams_alloc(s);
    if (cfg->create_state
        && cfg->create_state(s, cfg->create_state_ctx, &s->proto_state) != rc_ok)
        s->proto_state = nullptr;
    if (cfg->on_session_open) {
        auto tok = duct_session_handle_from_live(s);
        cfg->on_session_open(s,
                             tok.word,
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
    return s_session_remove_conn(session, conn_id, reason);
}

void duct_session_request_close(duct_session_t *session,
                                duct_close_reason_t reason)
{
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
    duct_do_if(!duct_session_block_live(sid), return nullptr);
    duct_session_t *s = duct_session_block_at(sid);
    uint32_t gen = duct_atomic_load(&s->generation, acquire);
    if (gen == 0u || gen != generation)
        return nullptr;
    *out_state = duct_atomic_load(&s->state, acquire);
    return s;
}

duct_session_t *duct_session_by_handle(duct_session_handle_t h)
{
    duct_session_state_t st = sess_free;
    /* Generation is the only staleness check: it does not bump until the
     * slot's block returns to the pool (gated on conn_count == 0 and the
     * close-fire teardown completing), so a token captured while attached
     * still matches through the whole closing and dead window. The
     * conn_lost detach and a residual timer fire both need the live pointer
     * during that window to run their closing-specific policy; callers that
     * must reject a closing session (join, frame dispatch) use @ref
     * duct_session_attached_by_handle instead.
     */
    auto s = s_session_resolve_slot(h.id, h.gen, &st);
    return (s && (st == sess_attached || st == sess_closing)) ? s : nullptr;
}

duct_session_t *duct_session_attached_by_handle(duct_session_handle_t h)
{
    duct_session_state_t st = sess_free;
    auto s = s_session_resolve_slot(h.id, h.gen, &st);
    return (s && st == sess_attached) ? s : nullptr;
}

/* Single-threaded by construction — every worker joined ahead of the engine
 * destroy that runs this. The walk covers exactly the ever-opened blocks:
 * the complement of the free bitmap, never the whole slot space. */
void duct_sessions_reclaim_shutdown(void)
{
    auto blocks = &s_pool->blocks;
    uint32_t words = duct_blk_words(blocks->n_blocks);
    for (uint32_t w = 0u; w < words; ++w) {
        uint64_t live = ~duct_atomic_load(&duct_at(blocks->free_bits)[w], acquire)
                        & duct_blk_word_mask(blocks, w);
        for (; live; live &= live - 1u) {
            uint32_t idx = (w << 6) + duct_ctz_ull(live);
            if (duct_atomic_load(&duct_at(blocks->meta)[idx].state, acquire) != blk_active)
                continue;
            auto s = duct_session_block_at(idx);
            if (duct_atomic_load(&s->generation, relaxed) == 0u)
                continue;
            s->conn_count = 0u;
            s_session_transition_closing(s, close_normal);
            duct_discard s_session_maybe_fire_close(s);
            s_session_free_push(s);
        }
    }
    duct_worker_reclaim_reset_all();
}
