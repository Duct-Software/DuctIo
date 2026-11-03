/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_conn_fence.c
 *  @brief Close-fence orchestration: wire-rebind / conn-lost fence posting,
 *  fence-retry dispatch, retire.
 */

#include "duct_conn_fence.h"
#include "duct_conn.h"
#include "duct_core.h"
#include "duct_frame_rx.h"
#include "duct_olb_rx.h"
#include "duct_protocol.h"
#include "duct_relay.h"
#include "duct_session.h"
#include "duct_vmq.h"
#include "duct_wfq_msg.h"
#include "duct_wire.h"
#include "duct_io.h"

/** @brief Arm @p conn's fence retry once its lane refused a fence.
 *  Counts the refusal, posts @c fl_req_fence_retry and arms the worker's
 *  reverse wake for this io thread. */
static duct_nonnull(1, 2) void
s_fence_retry_arm(const duct_wfq_route_t *route, duct_conn_t *conn)
{
#if DUCT_RUNTIME_STATS
    duct_io_rtstat_fence_push_full_inc();
#endif
    duct_io_trunk_req_post(route->trunk, duct_conn_handle_get(conn), fl_req_fence_retry);
    duct_worker_wfq_wait_arm(conn->worker_id, route->thread_id);
}

/** @brief Push a wire-rebind completion fence onto @p conn.
 *  It goes onto the conn's own @c wfq_pri_norm lane, behind every frame batch
 *  already posted; landing clears the retry sentinel @c conn->wire_rebind_next,
 *  and a full lane arms the retry instead.
 */
static duct_nonnull(1, 2) void
s_conn_post_wire_fence(const duct_wfq_route_t *route, duct_conn_t *conn)
{
    duct_msg_wire_fence m = {
        .msg = { .exec_fn = duct_session_exec_wire_fence, .arg = nullptr },
        .conn = duct_conn_handle_get(conn),
        .session = conn->session_token,
    };
    auto lane_id = duct_wfq_pri_lane(wfq_pri_norm, conn->worker_id, route->n_workers,
                                     route->thread_id, route->n_io);
    auto lane = duct_mpsc_lane(route->wfq, lane_id);
    if (vmq_push_ok != duct_vmq_push(&lane, msg_callback, wfq_pri_norm, &m, sizeof m)) {
        s_fence_retry_arm(route, conn);
        return;
    }
    duct_vmq_notify(lane.ctrl);
    duct_atomic_store(&conn->wire_rebind_next, nullptr, relaxed);
}

void duct_conn_wire_rebind(const duct_wfq_route_t *route, duct_conn_t *conn)
{
    auto next = duct_atomic_load(&conn->wire_rebind_next, relaxed);
    duct_do_if(!next, return); /* fence already landed on an earlier attempt */
    auto fence = duct_atomic_load(&conn->conn_fence, acquire);
    /* A quiesced conn keeps its sentinel and posts no fence: its conn_lost pays
     * the leg's share of the switch, and a fence queued behind that message
     * runs past the worker's confirm. */
    duct_do_if(fence >= fence_quiescing, return);
    auto next_cfg = duct_proto_cfg_of(next);
    if (conn->wire != next_cfg->wire) {
        auto rx = duct_conn_rx_olb(conn);
        if (rx) {
            size_t tail = duct_atomic_load(&rx->h.tail, relaxed),
                   avail = tail - rx->posted_off;

            /* Wait only for a pending full old-wire header — peer committed to a
             * known length, a real in-flight tail; duct_frame_rx_post retries
             * once the buffer drains. Anything shorter, or no old wire, is
             * indistinguishable from dead — discard it.
             * avail > 0u guards sealed wires (header_size == 0).
             */
            if (conn->wire && avail > 0u && avail >= conn->wire->header_size)
                return;
            /* Everything past posted_off is unparsed: frames a retry node
             * holds count in posted_off from the moment they are saved. */
            duct_olb_rx_discard(rx, tail);
        }
        if (conn->wire && conn->wire_parser)
            conn->wire->destroy_parser(conn->wire, conn->wire_parser);
        conn->wire = nullptr;
        conn->wire_parser = nullptr;
        if (duct_conn_bind_wire(conn, next, nullptr) != rc_ok) {
            duct_io_conn_close(conn, close_internal_error);
            return;
        }
    }
    s_conn_post_wire_fence(route, conn);
}

void duct_conn_fence_lost_publish(const duct_wfq_route_t *route, duct_conn_t *conn)
{
    /* conn_fence must reach fence_posted before this message is visible to
     * the worker: duct_conn_fence_confirm_retire also accepts a still-
     * fence_quiescing conn (the unrelated pre-open-reject path), so an
     * early-visible message lets the worker advance to fence_retire_ready
     * before this store lands, and the store then clobbers it back to
     * fence_posted with the message already consumed, stranding the conn.
     * Reserve then publish keeps the store strictly before the message's
     * own release-visibility. */
    auto lane_id = duct_wfq_pri_lane(wfq_pri_norm, conn->worker_id, route->n_workers,
                                     route->thread_id, route->n_io);
    auto lane = duct_mpsc_lane(route->wfq, lane_id);
    duct_vmq_reserve_pos_t pos;
    duct_vmq_push_rc_t rc;
    auto dst = duct_vmq_reserve(&lane, msg_callback, wfq_pri_norm,
                                sizeof(duct_msg_conn_lost), &pos, &rc);
    if (!dst) {
        s_fence_retry_arm(route, conn);
        return;
    }
    duct_msg_conn_lost m = {
        .msg = { .exec_fn = duct_session_exec_conn_lost, .arg = nullptr },
        .conn = duct_conn_handle_get(conn),
        .session = conn->session_token,
        .reason = conn->close_reason,
    };
    memcpy(dst, &m, sizeof m);
    duct_atomic_store(&conn->conn_fence, fence_posted, release);
    duct_vmq_publish(&lane, &pos);
    duct_vmq_notify(lane.ctrl);
}

void duct_conn_fence_retry(const duct_wfq_route_t *route, duct_conn_t *conn)
{
    if (duct_atomic_load(&conn->conn_fence, acquire) == fence_quiescing)
        duct_conn_fence_lost_publish(route, conn);
    if (duct_atomic_load(&conn->wire_rebind_next, relaxed))
        duct_conn_wire_rebind(route, conn); /* rebind already done or buf still not drained */
}

void duct_conn_fence_retire(duct_conn_t *conn)
{
    duct_conn_fence_t expected = fence_retire_ready;
    if (duct_atomic_cas(strong, &conn->conn_fence, &expected, fence_retired, acq_rel, acquire)) {
        assert(!duct_atomic_load(&conn->bound_worker, relaxed));
        duct_conn_io_list_unlink(conn, conn->io_id);
        duct_conn_reclaim(conn);
    }
}
