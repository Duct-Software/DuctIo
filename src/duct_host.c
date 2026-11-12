/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_host.c
 *  @brief Host bridge — inter-conn egress/ingress to the embedding application.
 *
 *  "Host" is the embedding application: code running on any thread the engine
 *  does not own — not an io thread, not a worker. This layer owns the
 *  @c duct_host_cfg_t singleton copied at @ref duct_engine_launch, the egress
 *  path (@ref duct_host_packet_out queues onto the calling worker's lane and
 *  a scheduled drain fires @c on_packet_out per packet,
 *  @ref duct_host_inter_resume_fire fires @c on_inter_resume through @c run),
 *  and the ingress path (@ref duct_io_inter_batch / @ref duct_io_inter_packet
 *  push into a conn's inter_lane).
 */

#include "duct_relay.h"
#include "duct_host.h"
#include "duct_ticks.h"
#include "duct_session.h"
#include "duct_vmq.h"
#include "duct_wfq.h"
#include "duct.h"

#include <string.h>

/* Host bridge singleton:
 * copied once from duct_host_cfg_t at duct_engine_launch, read by workers through
 * duct_host_packet_out and duct_host_inter_resume_fire and by the host's executor
 * through s_host_egress_run, and never mutated while those run, so a plain
 * cross-thread read needs no atomics. Workers reach the bridge with no engine
 * pointer in scope, so it is module state like s_wmod and s_imod. nullptr fields
 * when the engine has no inter conns. */
static duct_host_cfg_t s_host_cfg;

static bool _Atomic s_egress_stopping;

void duct_host_init(const duct_host_cfg_t *cfg)
{
    s_host_cfg = *cfg;
    duct_atomic_store(&s_egress_stopping, false, release);
}

void duct_host_inter_resume_fire(void)
{
    if (s_host_cfg.run && s_host_cfg.on_inter_resume)
        s_host_cfg.run(s_host_cfg.on_inter_resume, s_host_cfg.ctx, s_host_cfg.queue_ctx);
}

/** @brief One packet queued on a worker's egress lane.
 *  Identity travels as values, not as a resolved conn: a message for a leg
 *  that died before the drain still reaches @c on_packet_out, since nothing
 *  re-validates the handle.
 */
typedef struct {
    duct_handle_t  h;
    duct_conn_id_t conn_id;
    uint32_t       len;
    alignas(8)
    uint8_t        data[];
} egress_pkt_t;

/** @brief Lane-local @c duct_vmq_hdr_t::type tag, outside the
 *  shared WFQ tag space this lane's messages never reach. */
static constexpr uint8_t s_egress_msg = 0u;

bool duct_host_egress_enabled(void)
{
    return s_host_cfg.on_packet_out && s_host_cfg.run;
}

bool duct_host_egress_fits(size_t max_response)
{
    if (!duct_host_egress_enabled())
        return true;
    unsigned wid = duct_worker_egress_self();
    duct_do_if(wid == conn_worker_none, return true);
    auto q = duct_worker_egress_lane(wid);
    duct_do_if(!q, return true);
    size_t need = 0u;
    if (duct_ckd_add(&need, sizeof(egress_pkt_t), max_response))
        return false;
    auto ln = duct_mpsc_lane(q, 0u);
    return vmq_msg_aligned(need) <= ln.capacity;
}

static void s_egress_dispatch(duct_vmq_hdr_t *hdr, [[maybe_unused]] void *arg)
{
    auto p = (const egress_pkt_t *)&hdr->payload[0];
    s_host_cfg.on_packet_out(s_host_cfg.ctx, p->h, p->conn_id,
                             duct_view(duct_view_u8, (void *)p->data, p->len));
}

static void s_host_egress_run(void *ctx)
{
    /* ctx is the worker index, not its lane pointer: the lookup answers null
     * once teardown has cleared the pool, which makes a callback the host
     * delivers late harmless. A pointer here is dereferenced blind. */
    unsigned worker_id = (unsigned)(uintptr_t)ctx;
    auto q = duct_worker_egress_lane(worker_id);
    duct_do_if(!q, return);
    auto ln = duct_mpsc_lane(q, 0u);
    duct_vmq_drain_enter(ln.ctrl);
    duct_discard duct_vmq_mpsc_drain(q, s_egress_dispatch, nullptr);
    /* A worker the full lane refused armed the latch and parked its response;
     * this drain made the room it waits for. */
    if (duct_vmq_ack_waiter(ln.ctrl))
        duct_worker_wake_id(worker_id);
    duct_vmq_drain_disarm(ln.ctrl);
    if (duct_atomic_load(&s_egress_stopping, acquire)) {
        duct_vmq_drain_leave(ln.ctrl);
        return;
    }
    /* Disarm, then look again: a packet published between the drain above and
     * that disarm found the flag still claimed and scheduled nothing, so this
     * re-check is the only thing left to carry it. One published after the
     * disarm arms the flag itself; subsequent arming here returns false. */
    if (duct_vmq_unread(ln.ctrl) && duct_vmq_drain_arm(ln.ctrl))
        s_host_cfg.run(s_host_egress_run, (void *)(uintptr_t)worker_id,
                       s_host_cfg.queue_ctx);
    duct_vmq_drain_leave(ln.ctrl);
}

/** @brief Wait for @p worker_id egress drains to complete before freeing its lane.
 *  The armed flag marks a pending callback; the in-drain count tracks active
 *  execution. Both must clear: the first loop claims the armed flag to prevent
 *  new callbacks, and the second waits for any running callback to exit.
 */
static void s_egress_quiesce_one(unsigned worker_id, uint64_t deadline)
{
    auto q = duct_worker_egress_lane(worker_id);
    duct_do_if(!q, return);
    auto ctrl = duct_mpsc_ctrl(q, 0u);
    while (!duct_vmq_drain_arm(ctrl)) {
        if (duct_ticks_mono_ns() >= deadline) {
            duct_worker_egress_abandon(worker_id);
            return;
        }
        duct_cpu_relax();
    }
    while (!duct_vmq_drain_idle(ctrl)) {
        if (duct_ticks_mono_ns() >= deadline) {
            duct_worker_egress_abandon(worker_id);
            return;
        }
        duct_cpu_relax();
    }
}

void duct_host_egress_quiesce(unsigned n_workers, uint32_t timeout_ms)
{
    if (!duct_host_egress_enabled())
        return;
    duct_atomic_store(&s_egress_stopping, true, release);
    auto deadline = duct_ticks_mono_ns() + (uint64_t)timeout_ms * 1000000ull;
    for (unsigned i = 0u; i < n_workers; ++i)
        s_egress_quiesce_one(i, deadline);
}

duct_result_t duct_host_packet_out(const duct_session_handle_t *tok,
                                   duct_conn_id_t conn_id, duct_view_u8 pkt)
{
    /* No host bridge configured: drop the packet and return rc_ok. */
    if (!duct_host_egress_enabled())
        return rc_ok;
    unsigned wid = duct_worker_egress_self();
    duct_do_if(wid == conn_worker_none, return rc_invalid_order);
    auto q = duct_worker_egress_lane(wid);
    auto ln = duct_mpsc_lane(q, 0u);
    size_t need = 0u;
    if (duct_ckd_add(&need, sizeof(egress_pkt_t), pkt.size))
        return rc_invalid_arg;
    duct_vmq_reserve_pos_t pos;
    duct_vmq_push_rc_t push_rc;
    auto stage = (egress_pkt_t *)
        duct_vmq_reserve_armed(&ln, s_egress_msg, 0u, need, &pos, &push_rc);
    if (!stage)
        return push_rc == vmq_push_too_large ? rc_invalid_arg : rc_again;
    *stage = (egress_pkt_t){ .h = tok->word,
                               .conn_id = conn_id, .len = (uint32_t)pkt.size };
    memcpy(stage->data, pkt.data, pkt.size);
    duct_vmq_publish(&ln, &pos);
    if (duct_vmq_drain_arm(ln.ctrl))
        s_host_cfg.run(s_host_egress_run, (void *)(uintptr_t)wid, s_host_cfg.queue_ctx);
    return rc_ok;
}

void *duct_host_egress_reserve(const duct_session_handle_t *tok,
                               duct_conn_id_t conn_id, size_t size,
                               duct_host_egress_hold_t *out)
{
    bool bridged = duct_host_egress_enabled();
    duct_do_if(!bridged, return nullptr);
    unsigned wid = duct_worker_egress_self();
    duct_do_if(wid == conn_worker_none, return nullptr);
    auto q = duct_worker_egress_lane(wid);
    duct_do_if(!q, return nullptr);
    size_t need = 0u;
    if (duct_ckd_add(&need, sizeof(egress_pkt_t), size))
        return nullptr;
    auto ln = duct_mpsc_lane(q, 0u);
    duct_vmq_push_rc_t push_rc;
    duct_vmq_reserve_pos_t pos;
    auto stage = (egress_pkt_t *)
        duct_vmq_reserve_held(&ln, s_egress_msg, 0u, need, &pos, &push_rc);
    duct_do_if(!stage, return nullptr);
    *stage = (egress_pkt_t){ .h = tok->word,
                               .conn_id = conn_id };
    *out = (duct_host_egress_hold_t){ .ln = ln, .pos = pos, .pkt = stage,
                                      .worker_id = wid };
    return stage->data;
}

void duct_host_egress_publish(duct_host_egress_hold_t *hold, size_t len)
{
    auto p = (egress_pkt_t *)hold->pkt;
    p->len = (uint32_t)len;
    duct_vmq_publish_held(&hold->ln, &hold->pos, sizeof(egress_pkt_t) + len);
    if (duct_vmq_drain_arm(hold->ln.ctrl))
        s_host_cfg.run(s_host_egress_run, (void *)(uintptr_t)hold->worker_id,
                       s_host_cfg.queue_ctx);
}

void duct_host_egress_abandon(duct_host_egress_hold_t *hold)
{
    duct_vmq_abandon_held(&hold->ln, &hold->pos);
    /* A push made while the hold was open published behind it, invisible to the
     * consumer, so the drain that push armed has already run and found nothing.
     * Moving the tail here exposes those bytes, and the schedule rides
     * with it. */
    if (duct_vmq_unread(hold->ln.ctrl) && duct_vmq_drain_arm(hold->ln.ctrl))
        s_host_cfg.run(s_host_egress_run, (void *)(uintptr_t)hold->worker_id,
                       s_host_cfg.queue_ctx);
}

duct_result_t duct_io_inter_batch(duct_engine_t *e, duct_handle_t tok,
                                  duct_conn_id_t conn_id,
                                  const duct_inter_batch_t *batch)
{
    duct_do_if(!e || !batch, return rc_invalid_arg);
    duct_do_if(conn_id >= duct_session_max_legs, return rc_invalid_arg);
    auto stok = (duct_session_handle_t){ .word = tok };
    auto s = duct_session_attached_by_handle(stok);
    duct_do_if(!s, return rc_closed);
    auto h = duct_session_conn_at(s, conn_id);
    /* Cross-session misdirection guard: s is a fixed pool slot, by session
     * id, never unmapped, so a full close and reuse by a brand-new session
     * between the resolve above and this conns[] read silently repoints
     * conn_id at the new session's leg. generation advances only on that
     * exact closing -> quarantine -> free -> re-acquire transition, so
     * re-checking it against the token's snapshot proves the read did not
     * race a reuse; a mismatch means it did, and h must be discarded. */
    duct_do_if(duct_atomic_load(&s->generation, acquire) != stok.gen, return rc_closed);
    auto conn = duct_conn_by_handle(h);
    duct_do_if(!conn || conn->xport_type != x_inter, return rc_invalid_arg);

    size_t desc_bytes = 0u;
    duct_do_if(duct_ckd_mul(&desc_bytes, (size_t)batch->n, sizeof(duct_msg_inter_pkt_t))
               || duct_ckd_add(&desc_bytes, desc_bytes, sizeof(duct_msg_inter_batch_t)),
        return rc_invalid_arg);
    size_t total = desc_bytes;
    for (unsigned i = 0u; i < batch->n; ++i)
        duct_do_if(duct_ckd_add(&total, total, batch->pkts[i].payload.size), return rc_invalid_arg);
    duct_do_if(total > (size_t)UINT32_MAX, return rc_invalid_arg);

    /* Re-resolve by handle right before the mutate: conn above was captured
     * before the size math, and a close racing that window reclaims and
     * reissues the slot. This re-check is the safety step — the initial
     * resolve is fail-fast validation only. */
    auto live = duct_conn_by_handle(h);
    duct_do_if(!live, return rc_closed);
    /* host_pins: this thread is an unregistered reader the close-fence
     * protocol never enumerates — that protocol proves no worker/io
     * reference remains, nothing about host threads. Pin before touching
     * inter_lane, then re-check below. A mismatch means duct_conn_reclaim's
     * generation bump already landed, so its host_pins spin either passed
     * this conn before the pin or waits for the decrement below; either way
     * inter_lane stays untouched past this point. */
    duct_atomic_fetch(add, &live->host_pins, 1u, relaxed);
    /* Dekker-shaped store-then-load across two different atomics: host_pins
     * here, gen_req in duct_conn_reclaim. Acquire/release gives no StoreLoad
     * barrier, so a weakly-ordered arch reorders the later load ahead of
     * this store — AArch64 pre-LSE ldaxr/stlxr among them. The full fence
     * closes that window. */
    atomic_thread_fence(memory_order_seq_cst);
    if (!duct_conn_by_handle(h)) {
        duct_atomic_fetch(sub, &live->host_pins, 1u, release);
        return rc_closed;
    }
    auto lane = live->inter_lane;
    auto ln = duct_mpsc_lane(lane, 0u);
    duct_vmq_reserve_pos_t pos;
    duct_vmq_push_rc_t push_rc;
    /* Reserve space directly in the lane: payload bytes copy once from host
     * buffers into ring memory. */
    auto stage = (duct_msg_inter_batch_t *)
        duct_vmq_reserve(&ln, inter_msg_batch, 0u, total, &pos, &push_rc);
    if (!stage) {
        duct_atomic_fetch(sub, &live->host_pins, 1u, release);
        return push_rc == vmq_push_too_large ? rc_invalid_arg : rc_defer;
    }
    stage->conn = h.word;
    stage->n = batch->n;
    stage->peer = (duct_peer_t){}; /* x_udp_shared-only field; unused here */
    stage->rx_pool = nullptr;
    stage->pkts_off = (uint32_t)sizeof(duct_msg_inter_batch_t);
    stage->holds_off = 0u;
    auto stage_pkts = duct_msg_inter_pkts(stage);
    size_t cursor = desc_bytes;
    for (unsigned i = 0u; i < batch->n; ++i) {
        auto pkt = &batch->pkts[i];
        stage_pkts[i] = (duct_msg_inter_pkt_t){
            .offset = (uint32_t)cursor,
            .len = (uint32_t)pkt->payload.size,
            .stream_id = pkt->stream_id,
            .flags = pkt->flags,
        };
        if (pkt->payload.size)
            memcpy((char *)stage + cursor, pkt->payload.data, pkt->payload.size);
        cursor += pkt->payload.size;
    }
    duct_vmq_publish(&ln, &pos);
    /* Mark then notify, both still pinned: duct_vmq_notify derefs ln.ctrl,
     * which lives inside the inter_lane allocation, and duct_conn_reclaim
     * frees that once host_pins hits zero. Bit before wake, and
     * live->worker_id read here while the pin holds. s_inter_drain worker_id
     * check stays as backstop. */
    duct_worker_inter_arm(live->worker_id, duct_conn_idx_get(live));
    duct_vmq_notify(ln.ctrl);
    duct_atomic_fetch(sub, &live->host_pins, 1u, release);
    return rc_ok;
}

duct_result_t duct_io_inter_packet(duct_engine_t *e, duct_handle_t tok,
                                   duct_conn_id_t conn_id, duct_view_u8 pkt)
{
    alignas(8) char buf[duct_inter_batch_bytes(1u)];
    auto b = (duct_inter_batch_t *)&buf[0];
    b->n = 1u;
    *duct_inter_batch_pkt(b, 0u) = (duct_inter_pkt_t){
        .payload = pkt, .stream_id = duct_stream_id_default, .flags = fl_frame_none,
    };
    return duct_io_inter_batch(e, tok, conn_id, b);
}
