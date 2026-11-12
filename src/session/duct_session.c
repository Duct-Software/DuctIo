/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_session.c
 *  @brief Session lifecycle — executors, helpers, and io→session post wrappers.
 *
 *  Owns the session state machine + ctrl ingress. The worker TU keeps the data
 *  plane (WFQ drain, defer, timers, on_frame/on_batch dispatch, response route+TX,
 *  control application) and the declarative committer.
 */

#include "duct_session.h"
#include "duct_dgram_rec.h"
#include "duct_relay.h"
#include "duct_worker.h"
#include "duct_protocol.h"
#include "duct_stream_ctx.h"
#include "duct_hash.h"
#include "duct_core.h"

#include <assert.h>

duct_session_t *duct_session_by_conn(const duct_conn_t *conn)
{
    return duct_session_attached_by_handle(
        (duct_session_handle_t){ .word = conn->session_token });
}

duct_conn_id_t duct_session_conn_id_by_handle(const duct_session_t *s,
                                              duct_conn_handle_t h)
{
    for (duct_conn_id_t i = 0u; i < duct_session_max_legs; ++i) {
        auto ch = duct_session_conn_at(s, i);
        if (ch.gen && ch.idx == h.idx && ch.gen == h.gen)
            return i;
    }
    return duct_session_max_legs;
}

void duct_session_close_walk(duct_session_t *s, duct_close_reason_t reason)
{
    duct_session_request_close(s, reason);
    /* Abandon any wire-rebind fan-out in flight: a fence landing after this
     * point sees wire_rebind_next == nullptr and abandons finishing
     * the switch on a session that is already tearing down. */
    s->wire_rebind_next = nullptr;
    s->wire_rebind_ctx = nullptr;
    /* Close requests only: detach runs from duct_session_exec_conn_lost once
     * each leg's fence quiesces, so its discard and cancel steps see the leg
     * still attached. A close_normal leg's request waits behind the leg's
     * parked output, the closing session's parked answers ending voided in
     * their turn. */
    duct_conn_handle_t handle;
    duct_session_for_each_leg(s, i, handle)
        duct_worker_conn_close(handle, reason);
}

/** @brief Pre-open retire.
 *
 *  No session was ever (or is still) bound to @p conn — DOA close, join
 *  rejection before bind, or a bind race lost to I/O. Quiesces (idempotent
 *  if I/O already won that CAS), then asks the owning I/O thread to retire
 *  the conn once no further access remains, which is one posted request bit.
 *  No @c conn_lost is ever posted for an unbound conn.
 */
static void s_worker_retire_pre_open(duct_conn_t *conn)
{
    duct_discard duct_conn_fence_quiesce(conn);
    if (duct_conn_fence_confirm_retire(conn)) {
        auto ch = duct_conn_handle_get(conn);
        duct_io_retire_request(&ch);
    }
}

void duct_session_dial_lost(const duct_proto_cfg_t *cfg, void *user_ctx, duct_result_t rc)
{
    if (!cfg->on_error)
        return;
    duct_response_t out = {};
    duct_discard cfg->on_error(nullptr, rc, &out, user_ctx);
}

/** @brief Bring a leg just bound to @p s into service: its lane armed, its codec
 *  started with the dial's @p prefix, its handshake bounded.
 *  @return false when no codec of the conn takes @p prefix; the bound is then
 *  unarmed. */
static bool s_conn_start(duct_session_t *s, duct_conn_t *conn, duct_seal_prefix_t *prefix)
{
    /* A datagram push can already have lost its race against
     * s_inter_drain, which drops the bit of a conn not yet bound to its worker,
     * and the lane then waits for its next push to arm. The bind has bound this
     * conn, so arming here has the next drain pass take that frame. */
    if (duct_conn_lane(conn))
        duct_worker_inter_arm(conn->worker_id, duct_conn_idx_get(conn));
    auto handle = duct_conn_handle_get(conn);
    /* A client-role sealed wire needs its engine's start to emit a first flight
     * before the open or join callback commits anything over the conn; a plain
     * wire has no codec to start and a server-role engine's start is nullptr.
     * A codec that cannot take the dial's prefix fails here. */
    auto pr = duct_seal_prefix_view(prefix);
    if (!duct_worker_tls_ensure_started(handle, duct_view(duct_view_u8, pr.data, pr.size)))
        return false;
    /* The bound reads the codec the start just built. */
    duct_worker_join_deadline_arm(s, handle);
    return true;
}

/** @brief Resolve @p handle to its conn while no session has bound it.
 *  A stale handle answers nullptr, and so does a conn io quiesced first, which
 *  is retired here: no session is prepared for it and no author callback runs. */
static duct_conn_t *s_unbound_conn(duct_conn_handle_t handle)
{
    auto conn = duct_conn_by_handle(handle);
    duct_do_if(!conn, return nullptr);
    if (duct_atomic_load(&conn->conn_fence, acquire) == fence_unbound)
        return conn;
    s_worker_retire_pre_open(conn);
    return nullptr;
}

/** @brief Detach the leg of @p s at @p conn_id and ask io to close its bound @p conn.
 *  The bound close fence retires the conn, and the conn_lost it posts finds no
 *  leg left. A session's last leg detaching fires on_session_close and
 *  destroy_state, which release proto_state and the streams. */
static void s_refuse_leg(duct_session_t *s, duct_conn_id_t conn_id, const duct_conn_handle_t *conn)
{
    duct_discard duct_session_detach_leg(s, conn_id, close_protocol_error);
    duct_io_post_close_request(conn, close_protocol_error);
}

duct_exec_rc_t duct_session_exec_open(void *self)
{
    auto msg = (duct_msg_session_open *)self;
    auto cfg = duct_proto_cfg_of(msg->proto);
    auto conn = s_unbound_conn(msg->conn);
    if (!conn) {
        if (msg->dialed)
            duct_session_dial_lost(cfg, msg->user_ctx, rc_closed);
        return duct_msg_done(msg);
    }
    size_t need = duct_worker_admit_need(msg->proto, duct_admit_slots(cfg));
    if (need == SIZE_MAX)
        return exec_defer;
    if (!duct_worker_admit_leg(msg->conn, need))
        return exec_defer;

    duct_result_t rc = rc_no_memory;
    auto s = duct_session_acquire();
    if (!s)
        goto fail_retire;
    if (duct_session_attach_conn(s, msg->conn_id, msg->conn) != rc_ok)
        goto fail_release;
    s->proto = msg->proto;
    s->user_ctx = msg->user_ctx;
    duct_atomic_store(&s->worker_id, conn->worker_id, release);
    if (duct_has(cfg->flags, fl_proto_multiplexed) && !duct_session_streams_alloc(s))
        goto fail_release;

    auto tok = duct_session_handle_from_live(s);
    if (!duct_conn_session_bind(conn, tok.word)) {
        rc = rc_closed;
        goto fail_release;
    }
    if (!s_conn_start(s, conn, &msg->tx_prefix)) {
        /* The open never ran, so the session rolls back with no session
         * callback; the conn, already bound, closes by request and its
         * conn_lost fence finds no session. */
        duct_session_streams_free(s);
        duct_session_release(s);
        duct_io_post_close_request(&msg->conn, close_protocol_error);
        if (msg->dialed)
            duct_session_dial_lost(cfg, msg->user_ctx, rc_invalid_arg);
        return duct_msg_done(msg);
    }
    if (cfg->create_state) {
        auto crc = cfg->create_state(s, cfg->create_state_ctx, &s->proto_state);
        if (crc != rc_ok)
            s->proto_state = nullptr;
    }
    duct_response_t out;
    duct_response_reset(&out);
    duct_result_t orc = cfg->on_session_open
                      ? cfg->on_session_open(s, tok.word,
                                             msg->user_ctx, &out, s->proto_state)
                      : rc_ok;
    if (orc != rc_ok) {
        duct_response_release_owned(&out);
        s_refuse_leg(s, msg->conn_id, &msg->conn);
        return duct_msg_done(msg);
    }
    duct_response_commit(s, msg->conn_id, duct_stream_id_default, &out);
    duct_worker_idle_arm(s);
    return duct_msg_done(msg);

fail_release:
    duct_session_streams_free(s);
    duct_session_release(s);
fail_retire:
    s_worker_retire_pre_open(conn);
    if (msg->dialed)
        duct_session_dial_lost(cfg, msg->user_ctx, rc);
    return duct_msg_done(msg);
}

duct_exec_rc_t duct_session_exec_conn_join(void *self)
{
    auto msg = (duct_msg_conn_join *)self;
    auto conn = s_unbound_conn(msg->conn);
    if (!conn)
        return duct_msg_done(msg);
    auto s = duct_session_attached_by_handle(msg->tok);
    if (!s || msg->conn_id >= duct_session_max_legs || duct_session_conn_at(s, msg->conn_id).word) {
        /* Stale/closing token or occupied slot: no leg was ever prepared for
         * this conn. */
        s_worker_retire_pre_open(conn);
        return duct_msg_done(msg);
    }
    auto cfg = s->proto ? duct_proto_cfg_of(s->proto) : nullptr;
    /* A join without a protocol callback emits no application response.
     * The fresh leg carries a separate handshake budget; unrelated full legs must
     * not block independent listener admissions behind this control message. */
    if (cfg && cfg->on_conn_join) {
        size_t need = duct_worker_admit_need(s->proto, duct_admit_slots(cfg));
        if (need == SIZE_MAX)
            return exec_defer;
        duct_conn_handle_t handle;
        duct_session_for_each_leg(s, i, handle)
            if (!duct_worker_admit_leg(handle, need))
                return exec_defer;
        if (!duct_worker_admit_leg(msg->conn, need))
            return exec_defer;
    }
    if (duct_session_attach_conn(s, msg->conn_id, msg->conn) != rc_ok) {
        s_worker_retire_pre_open(conn);
        return duct_msg_done(msg);
    }
    auto tok = duct_session_handle_from_live(s);
    if (!duct_conn_session_bind(conn, tok.word)) {
        duct_discard duct_session_detach_leg(s, msg->conn_id, close_internal_error);
        s_worker_retire_pre_open(conn);
        return duct_msg_done(msg);
    }
    if (!s_conn_start(s, conn, &msg->tx_prefix)) {
        s_refuse_leg(s, msg->conn_id, &msg->conn);
        return duct_msg_done(msg);
    }

    duct_response_t out;
    duct_response_reset(&out);
    duct_result_t jrc = cfg && cfg->on_conn_join
                       ? cfg->on_conn_join(s, msg->conn_id, &msg->peer, &out, s->proto_state)
                       : rc_ok;
    if (jrc != rc_ok) {
        duct_response_release_owned(&out);
        s_refuse_leg(s, msg->conn_id, &msg->conn);
        return duct_msg_done(msg);
    }
    duct_response_commit(s, msg->conn_id, duct_stream_id_default, &out);
    return duct_msg_done(msg);
}

static void s_wire_rebind_settle(duct_session_handle_t handle);

duct_exec_rc_t duct_session_exec_conn_lost(void *self)
{
    auto msg = (duct_msg_conn_lost *)self;
    auto conn = duct_conn_by_handle(msg->conn);
    duct_do_if(!conn, return exec_done); /* already retired */
    auto handle = (duct_session_handle_t){ .word = msg->session };
    auto s = duct_session_by_handle(handle);
    if (s) {
        auto cid = duct_session_conn_id_by_handle(s, msg->conn);
        if (cid < duct_session_max_legs) {
            /* Cancel handlers and discard deferred frames for this leg
             * before detach: both may still reference conn->rx_buf, which
             * retire can tear down once this executor finishes. */
            duct_session_streams_cancel_conn(s, cid, msg->reason);
            duct_worker_conn_defer_discard(&msg->conn);
            /* err_out is discarded. on_conn_lost's out below is this
             * executor's only committed response. */
            auto cfg = s->proto ? duct_proto_cfg_of(s->proto) : nullptr;
            if (msg->reason == close_protocol_error && cfg && cfg->on_error) {
                duct_response_t err_out = {};
                duct_discard cfg->on_error(s, rc_invalid_arg, &err_out, s->proto_state);
            }
            /* on_conn_lost fires before the detach so it still runs for a
             * session's last leg, whose detach tears the session down inline
             * and nulls s->proto. Its control applies after, once conn_id's
             * slot is free for an open_leg redial into it. */
            duct_response_t out;
            duct_response_reset(&out);
            bool notify = cfg && cfg->on_conn_lost;
            if (notify)
                cfg->on_conn_lost(s, cid, msg->reason, &out, s->proto_state);
            duct_session_detach_leg(s, cid, msg->reason);
            /* A leg that closed owing its wire fence leaves the switch's count
             * here, ahead of the control below: a dial staged there takes
             * s->proto, which the last leg out finishes switching. */
            if (duct_atomic_load(&conn->wire_rebind_next, relaxed))
                s_wire_rebind_settle(handle);
            if (notify) {
                duct_response_release_owned(&out);
                duct_response_t ctl = { .control = out.control };
                duct_response_commit(s, cid, duct_stream_id_default, &ctl);
            }
        }
        /* else: s_refuse_leg detached the leg ahead of this fence, which finds
         * no leg of the conn left. */
    }
    /* Every parked output naming this leg lets go of it ahead of the retire
     * confirm: past it io frees the leg's rings while its handle still
     * resolves, until the slot is reclaimed. */
    duct_worker_conn_retry_discard(&msg->conn);
    /* Sealed-wire codec, if any. A handler or answer still pinning its cleartext
     * buffer keeps the buffer alive past this destroy. */
    duct_conn_sealed_codec_detach(conn);
    duct_conn_session_unbind(conn);
    /* Every train bound for this conn is gone before the confirm: past it io
     * reclaims the slot, and a later flush lands on its next occupant. */
    duct_worker_conn_train_flush(&msg->conn);
    if (duct_conn_fence_confirm_retire(conn))
        duct_io_retire_request(&msg->conn);
    return exec_done;
}

/** @brief Post @p msg to @p conn's worker, the conn flagged as holding a ctrl
 *  message in flight.
 *  Callers pass @c duct_msg_ctrl_root of the message, which checks its type.
 *  @return false when no worker takes it; the flag is cleared and @p msg freed. */
static bool s_post_ctrl(duct_conn_t *conn, duct_msg_t *msg)
{
    duct_conn_state_set(conn, fl_conn_in_wfq);
    if (duct_worker_post_ctrl_msg(conn->worker_id, msg))
        return true;
    /* duct_worker_post_ctrl_msg fails only for a worker_id past the workers, which
     * a conn's never is; the flag still clears, since a set one blocks
     * s_conn_close's fence_unbound fast-reclaim. */
    duct_conn_state_clear(conn, fl_conn_in_wfq);
    duct_msg_done(msg);
    return false;
}

bool duct_sessions_post_session_open(duct_conn_t *conn,
                                     const duct_proto_t *proto,
                                     void *user_ctx,
                                     duct_seal_prefix_t tx_prefix,
                                     bool dialed)
{
    auto msg = duct_msg_new_kind(session_open, duct_session_exec_open);
    if (!msg)
        return false;
    msg->conn = duct_conn_handle_get(conn);
    msg->conn_id = duct_conn_id_primary;
    msg->proto = proto;
    msg->user_ctx = user_ctx;
    msg->tx_prefix = tx_prefix;
    msg->dialed = dialed;
    return s_post_ctrl(conn, duct_msg_ctrl_root(msg));
}

bool duct_sessions_post_conn_join(duct_conn_t *conn,
                                  duct_session_handle_t tok,
                                  duct_conn_id_t conn_id,
                                  const duct_peer_t *peer,
                                  duct_seal_prefix_t tx_prefix)
{
    auto msg = duct_msg_new(duct_msg_conn_join, duct_session_exec_conn_join, nullptr);
    if (!msg)
        return false;
    msg->conn = duct_conn_handle_get(conn);
    msg->conn_id = conn_id;
    msg->tok = tok;
    msg->peer = peer ? *peer : (duct_peer_t){};
    msg->tx_prefix = tx_prefix;
    return s_post_ctrl(conn, duct_msg_ctrl_root(msg));
}

/** @brief Stream-slot find/insert by id within the matching hash bucket. */
DUCT_HASH_DECLARE(s_stream_hash_find, s_stream_hash_insert,
                   duct_session_t, stream_buckets, duct_stream_t,
                   duct_stream_id_t, duct_atomic_load(&node->id, relaxed) == key,
                   duct_session_max_streams - 1u)

/** @brief Live stream-slot lookup via hash bucket, or NULL. */
static duct_nonnull(1) duct_stream_t *
s_stream_find(const duct_session_t *s, duct_stream_id_t stream_id)
{
    return s_stream_hash_find(s, stream_id);
}

bool duct_session_streams_alloc(duct_session_t *s)
{
    duct_do_if(!s, return false);
    if (s->streams)
        return true;
    s->streams = duct_at(duct_new(duct_stream_t, duct_session_max_streams));
    duct_do_if(!s->streams, return false);
    s->stream_buckets = duct_at(duct_new(duct_hash_handle_t *, duct_session_max_streams));
    if (!s->stream_buckets) {
        duct_del(s->streams);
        return false;
    }
    /* duct_new zeroes: id/proto_state/hh.pprev zero. Build the free
     * list as slot[i].hh.next = &slot[i+1].hh, last → NULL. */
    for (uint32_t i = 0u; i + 1u < duct_session_max_streams; ++i)
        s->streams[i].hh.next = &s->streams[i + 1u].hh;
    s->streams[duct_session_max_streams - 1u].hh.next = nullptr;
    s->stream_free_head = &s->streams[0u].hh;
    s->stream_count = 0u;
    return true;
}

void duct_session_streams_free(duct_session_t *s)
{
    duct_do_if(!s, return);
    duct_del(s->streams);
    duct_del(s->stream_buckets);
    s->stream_free_head = nullptr;
    s->stream_count = 0u;
}

duct_stream_t *duct_session_stream_claim(duct_session_t *s, duct_stream_id_t stream_id,
                                duct_response_t *out, duct_stream_admit_t *admit)
{
    duct_stream_admit_t admit_scratch;
    duct_stream_admit_t *w = admit ? admit : &admit_scratch;
    *w = stream_admit_unusable;
    duct_do_if(!s || !s->streams || !s->proto, return nullptr);
    duct_do_if(stream_id == 0u, return nullptr); /* stream 0 = control, never claims */
    /* Idempotent: return the existing slot without re-firing hooks. */
    auto hit = s_stream_find(s, stream_id);
    if (hit) {
        *w = stream_admit_ok;
        return hit;
    }
    *w = stream_admit_full;
    duct_do_if(!s->stream_free_head, return nullptr); /* table full */
    auto cfg = duct_proto_cfg_of(s->proto);
    void *state = nullptr;
    *w = stream_admit_rejected;
    if (cfg->create_stream_state) {
        auto rc = cfg->create_stream_state(s, stream_id, cfg->create_state_ctx, &state);
        duct_do_if(rc != rc_ok, return nullptr); /* no slot consumed */
    }
    *w = stream_admit_ok;
    /* Commit: pop a free slot and link it at the bucket head. */
    auto slot = duct_hash_entry(s->stream_free_head, duct_stream_t, hh);
    s->stream_free_head = slot->hh.next;
    s_stream_hash_insert(s, stream_id, &slot->hh);
    slot->proto_state = state;
    duct_atomic_store(&slot->id, stream_id, relaxed);
    ++s->stream_count;
    duct_response_t scratch;
    duct_response_t *o = out ? out : &scratch;
    duct_response_reset(o);
    if (cfg->on_stream_open)
        duct_discard cfg->on_stream_open(s, stream_id, o, state);
    return slot;
}

void duct_session_stream_teardown(duct_session_t *s, duct_stream_t *slot,
                                  duct_close_reason_t reason)
{
    duct_stream_id_t sid = duct_atomic_load(&slot->id, relaxed);
    if (sid == 0u)
        return; /* already torn down (recursive close from on_stream_close) */
    duct_atomic_store(&slot->id, 0u, relaxed);
    duct_hash_remove(&slot->hh);
    auto cfg = duct_proto_cfg_of(s->proto);
    auto state = slot->proto_state;
    if (cfg->on_stream_close)
        cfg->on_stream_close(s, sid, reason, state);
    if (cfg->destroy_stream_state && state)
        cfg->destroy_stream_state(s, sid, cfg->create_state_ctx, state);
    slot->proto_state = nullptr;
    slot->handler_ctx = nullptr;
    slot->flags = fl_stream_none;
    slot->hh.next = s->stream_free_head;
    s->stream_free_head = &slot->hh;
    if (s->stream_count)
        --s->stream_count;
}

void duct_session_stream_close(duct_session_t *s, duct_stream_id_t stream_id,
                               duct_close_reason_t reason)
{
    duct_do_if(!s || !s->proto, return);
    if (!s->streams || stream_id == 0u)
        return;
    auto slot = s_stream_find(s, stream_id);
    if (!slot)
        return; /* not claimed: idempotent */
    if (slot->handler_ctx) {
        duct_stream_cancel(slot->handler_ctx);
        slot->handler_ctx = nullptr;
    }
    duct_session_stream_teardown(s, slot, reason);
}

duct_stream_t *duct_session_stream_slot(duct_session_t *s,
                                        duct_stream_id_t stream_id)
{
    duct_do_if(!s || !s->streams || stream_id == 0u, return nullptr);
    return s_stream_find(s, stream_id);
}

void duct_session_streams_destroy(duct_session_t *s)
{
    duct_do_if(!s, return);
    if (!s->streams)
        return;
    auto reason = duct_atomic_load(&s->close_reason, relaxed);
    for (uint32_t i = 0u; i < duct_session_max_streams; ++i) {
        auto slot = &s->streams[i];
        duct_stream_id_t sid = duct_atomic_load(&slot->id, relaxed);
        if (sid == 0u)
            continue;
        if (slot->handler_ctx) {
            duct_stream_cancel(slot->handler_ctx);
            slot->handler_ctx = nullptr;
        }
        duct_session_stream_teardown(s, slot, reason);
    }
    s->stream_count = 0u;
}

void duct_session_streams_cancel_conn(duct_session_t *s, duct_conn_id_t conn_id,
                                      duct_close_reason_t reason)
{
    duct_do_if(!s, return);
    if (!s->streams)
        return;
    for (uint32_t i = 0u; i < duct_session_max_streams; ++i) {
        auto slot = &s->streams[i];
        duct_stream_id_t sid = duct_atomic_load(&slot->id, relaxed);
        if (sid == 0u || !slot->handler_ctx)
            continue;
        auto hctx = (duct_stream_ctx_t *)slot->handler_ctx;
        if (hctx->conn_id != conn_id)
            continue;
        duct_stream_cancel(slot->handler_ctx);
        slot->handler_ctx = nullptr;
        duct_session_stream_teardown(s, slot, reason);
    }
}

void *duct_stream_state(duct_session_t *s, duct_stream_id_t stream_id)
{
    duct_do_if(!s || !s->streams || stream_id == 0u, return nullptr);
    auto slot = s_stream_find(s, stream_id);
    return slot ? slot->proto_state : nullptr;
}

uint32_t duct_session_conn_count(const duct_session_t *s)
{
    return duct_atomic_load(&s->conn_count, acquire);
}

duct_conn_id_t duct_session_nth_live_leg(const duct_session_t *s, uint32_t ordinal)
{
    duct_conn_handle_t h;
    uint32_t seen = 0u;
    duct_session_for_each_leg(s, i, h) {
        if (seen == ordinal)
            return i;
        ++seen;
    }
    return duct_session_max_legs;
}

void *duct_session_user_ctx(const duct_session_t *s)
{
    return s->user_ctx;
}

/* duct_stream_close / duct_stream_reset live on the worker side — they stage a
 * wire FIN/RST frame on the conn's TX OLB, which requires the worker's TX
 * plumbing (wire->on_pack + duct_olb_tx_publish + duct_io_post_tx_drain). */

duct_result_t duct_proto_switch(duct_session_t *s, const duct_proto_t *next,
                                void *migration_ctx)
{
    duct_do_if(!s || !next, return rc_invalid_arg);
    /* Already pending: either the synchronous record window (pending_switch_next,
     * cleared by duct_session_apply_switch before it returns) or a wire-changing
     * switch's rebind fan-out still draining (wire_rebind_next, cleared only once
     * every leg's fence lands) — one switch in flight at a time either way. */
    duct_do_if(s->pending_switch_next || s->wire_rebind_next, return rc_again);
    s->pending_switch_next = next;
    s->pending_switch_ctx = migration_ctx;
    return rc_ok;
}

/** @brief Proto-switch tail.
 *
 *  New-state creation, leave phase, stream teardown, stream-table allocation
 *  for the new proto, enter phase, old-state disposal, @c s->proto commit.
 *  Shared by the same-wire synchronous path
 *  and the wire-changing path's post-fence continuation (@ref
 *  duct_session_exec_wire_fence) — identical either way, since by the time
 *  this runs every leg already parses/packs the new wire.
 */
static void s_session_finish_switch(duct_session_t *s, const duct_proto_t *next, void *ctx)
{
    auto old = s->proto;
    auto old_cfg = duct_proto_cfg_of(old);
    auto next_cfg = duct_proto_cfg_of(next);
    /* Create the new proto_state first so a failure aborts before leave. */
    void *new_state = nullptr;
    if (next_cfg->create_state) {
        auto rc = next_cfg->create_state(s, next_cfg->create_state_ctx, &new_state);
        duct_do_if(rc != rc_ok, return); /* abort, stay on old proto */
    }
    /* Leave phase: old proto sees its live streams. */
    duct_leave_t disp = leave_destroy;
    if (old_cfg->on_proto_leave)
        disp = old_cfg->on_proto_leave(s, ctx, s->proto_state);
    if (disp == leave_reject) {
        if (next_cfg->destroy_state && new_state)
            next_cfg->destroy_state(s, next_cfg->create_state_ctx, new_state);
        return; /* abort, stay on old proto */
    }
    /* Teardown old live streams (on_stream_close fires on the old proto). */
    duct_session_streams_destroy(s);
    /* A switch is the third way a session reaches a multiplexed proto, and the
     * only one that finds the table already decided: the two open paths size it
     * from the proto they open with. Without this a session upgrading into a
     * multiplexed proto keeps a null table, so every stream id it then receives
     * claims no slot — multiplexing on, silently doing nothing. Idempotent, so
     * a multiplexed-to-multiplexed switch reuses the table the teardown above
     * just emptied. */
    bool ready = !duct_has(next_cfg->flags, fl_proto_multiplexed)
              || duct_session_streams_alloc(s);
    /* Enter phase (old proto_state still valid for a close on failure). */
    duct_result_t erc = rc_ok;
    if (ready && next_cfg->on_proto_enter)
        erc = next_cfg->on_proto_enter(s, ctx, new_state);
    if (!ready || erc != rc_ok) {
        /* No table, or enter refused: old streams are torn down, proto_state
         * intact; close the session on the old proto, then free the orphaned
         * new_state. Both causes leave exactly that state, which is why they
         * share one disposition. */
        if (next_cfg->destroy_state && new_state)
            next_cfg->destroy_state(s, next_cfg->create_state_ctx, new_state);
        duct_session_close_walk(s, close_protocol_error);
        return;
    }
    /* Dispose of the old proto_state per the leave disposition. */
    if (disp == leave_destroy && old_cfg->destroy_state && s->proto_state)
        old_cfg->destroy_state(s, old_cfg->create_state_ctx, s->proto_state);
    s->proto = next;
    s->proto_state = new_state;
    duct_worker_idle_arm(s);
}

duct_result_t duct_session_apply_switch(duct_session_t *s)
{
    duct_do_if(!s, return rc_invalid_arg);
    auto next = s->pending_switch_next;
    if (!next)
        return rc_ok;
    auto ctx = s->pending_switch_ctx;
    s->pending_switch_next = nullptr;
    s->pending_switch_ctx = nullptr;
    /* Abandon the switch if the session is no longer live (e.g. the same
     * callback also declared close_target=session). */
    auto st = duct_atomic_load(&s->state, acquire);
    duct_do_if(st != session_state_attached, return rc_closed);

    auto cur_cfg = duct_proto_cfg_of(s->proto);
    auto next_cfg = duct_proto_cfg_of(next);
    if (cur_cfg->wire == next_cfg->wire) {
        s_session_finish_switch(s, next, ctx);
        return rc_ok;
    }
    /* Wire changes: fan out a rebind to every leg that can have a wire.
     * x_inter never does — framing is the host's concern there; every
     * other transport does once a wire is configured, even one whose
     * *old* proto happened to be wireless (conn->wire == NULL is then
     * indistinguishable from an inter leg by that field alone, hence checking
     * the transport type). Defer the finish until
     * every counted leg confirms. */
    uint32_t pending = 0u;
    duct_conn_handle_t handle;
    duct_session_for_each_leg(s, i, handle) {
        auto conn = duct_conn_by_handle(handle);
        if (!conn || conn->xport_type == x_inter)
            continue;
        /* Refused: a leg wire that the rebind replaces with the incoming proto's,
         * and a leg that needs a wire, left by the rebind with none. */
        if ((conn->wire && conn->wire != cur_cfg->wire)
            || (duct_xport_needs_wire(conn->xport_type) && !next_cfg->wire))
            return rc_invalid_order;
        ++pending;
    }
    if (pending == 0u) {
        s_session_finish_switch(s, next, ctx);
        return rc_ok;
    }
    s->wire_rebind_next = next;
    s->wire_rebind_ctx = ctx;
    s->wire_rebind_pending = pending;
    duct_session_for_each_leg(s, i, handle) {
        auto conn = duct_conn_by_handle(handle);
        if (!conn || conn->xport_type == x_inter)
            continue;
        duct_io_post_wire_rebind(&handle, next);
    }
    return rc_ok;
}

/** @brief Count one leg out of a session's wire-changing switch.
 *  The leg that brings the count to zero finishes the switch. A session that is
 *  gone or no longer attached, and one whose switch was abandoned
 *  (@c duct_session_close_walk clears @c wire_rebind_next), is left alone.
 */
static void s_wire_rebind_settle(duct_session_handle_t handle)
{
    auto s = duct_session_attached_by_handle(handle);
    if (!s || !s->wire_rebind_next || --s->wire_rebind_pending != 0u)
        return;
    auto next = s->wire_rebind_next;
    auto ctx = s->wire_rebind_ctx;
    s->wire_rebind_next = nullptr;
    s->wire_rebind_ctx = nullptr;
    s_session_finish_switch(s, next, ctx);
}

duct_exec_rc_t duct_session_exec_wire_fence(void *self)
{
    auto msg = (duct_msg_wire_fence *)self;
    /* By the time this fence lands, duct_conn_wire_rebind already rebound
     * conn->wire away from the old wire, so a leftover sealed codec is
     * reached through the conn's sealed ctx, not conn->wire. Nothing
     * upstream cancels a handler still parked on this codec's cleartext
     * buffer: the detach destroys the codec so no new task reaches it, and the
     * handler's pin keeps the buffer its frame points into. */
    auto conn = duct_conn_by_handle(msg->conn);
    /* io posts no fence for a conn it has quiesced, so this one runs ahead of its
     * conn_lost, while the worker still holds the conn. */
    assert(!conn || duct_atomic_load(&conn->conn_fence, relaxed) < fence_retire_ready);
    if (conn) {
        duct_conn_sealed_codec_detach(conn);
        /* conn->wire is the *new* wire by this point (same rebind-before-
         * fence ordering the old-codec detach above already relies on) —
         * a client-role engine on the new sealed wire (STARTTLS on the
         * client side) needs this exact hook to speak, the same
         * as a fresh accept/connect. msg->conn is already the handle conn
         * was resolved from above. */
        duct_discard duct_worker_tls_ensure_started(msg->conn, (duct_view_u8){});
    }
    auto handle = (duct_session_handle_t){ .word = msg->session };
    s_wire_rebind_settle(handle);
    return exec_done;
}

