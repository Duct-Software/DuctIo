/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_listener.c
 *  @brief Listener lifecycle — bind, revoke, whole-engine teardown.
 *
 *  Everything here operates through @ref duct_listener_route_t
 *  never @c duct_engine_t itself — that struct stays private to the engine
 *  module, whose three thin public wrappers
 *  (@ref duct_listener_bind, @ref duct_listener_close, @ref duct_io_listen)
 *  assemble a route from their own @c e and call into
 *  @ref duct_listener_route_bind / @ref duct_listener_route_close here.
 *  Whole-engine teardown (@c s_engine_destroy) detaches every io thread's own
 *  list via @ref duct_io_listeners_detach and frees the chain with
 *  @ref duct_listener_destroy_chain.
 *
 *  A path listener's live-session count is kept here too, through
 *  @c duct_local_listener_admits, @c duct_local_listener_take and
 *  @c duct_local_listener_drop.
 */

#include "duct_listener.h"

#include "duct.h"
#include "duct_dgram_rec.h"
#include "duct_events.h"
#include "duct_io.h"
#include "duct_pmtu.h"
#include "duct_relay.h"
#include "duct_timer.h"
#include "duct_vmq.h"
#include "duct_xport.h"

#include <assert.h>

static uint32_t _Atomic s_sync_seq;

/** @brief Wake every host thread blocked in a listener sync wait. */
static void s_sync_wake(void)
{
    duct_atomic_fetch(add, &s_sync_seq, 1u, release);
    duct_futex_wake(&s_sync_seq, duct_futex_wake_all);
}

/* ok is written ahead of the release store of done, which the waiter's acquire
 * load of done pairs with; the duct_del goes last, since it may free the block. */
void duct_listener_sync_signal(duct_listener_sync_t *sync, bool ok)
{
    sync->ok = ok;
    duct_atomic_store(&sync->done, 1u, release);
    s_sync_wake();
    duct_del(sync);
}

static bool s_listener_sync_wait(duct_listener_sync_t *sync)
{
    auto deadline = duct_time_add(duct_time_now(),
                                  duct_time_from_us((uint64_t)duct_sync_bound_ms * 1000ull));
    for (;;) {
        /* seq read before done: a wake landing between the two loads changes
         * seq, so the wait below returns instantly and the next iteration
         * sees the signal — no lost-wake window. */
        uint32_t seq = duct_atomic_load(&s_sync_seq, acquire);
        if (duct_atomic_load(&sync->done, acquire))
            return true;
        if (!duct_deadline_wait(&s_sync_seq, seq, deadline))
            return false;
    }
}

/** @brief Wait on @p sync and report both outcomes.
 *  The caller's hold ends with its own @c duct_auto_del. @p *ok true implies
 *  this also returns true — a caller that only cares about success can check
 *  @p *ok alone. */
static bool s_sync_finish(duct_listener_sync_t *sync, bool *ok)
{
    bool signaled = s_listener_sync_wait(sync);
    *ok = signaled && sync->ok;
    return signaled;
}

void duct_listener_destroy(duct_listener_t *l)
{
    if (l->local) {
        duct_local_listener_retire(l);
        duct_del(l->local);
    }
    if (l->listen_fd != duct_sock_bad)
        duct_sock_close(l->listen_fd);
    duct_io_listener_dgram_peers_free(l);
    if (l->dgram_tx_outbox)
        duct_vmq_mpsc_del((duct_vmq_mpsc_t *)l->dgram_tx_outbox);
    duct_events_dgram_tx_pool_free(l);
    duct_del(l->protos);
    duct_del(l);
}

void duct_listener_release_pre_conn_ref(duct_listener_t *listener)
{
    assert(listener->pre_conn_refs > 0u);
    if (--listener->pre_conn_refs == 0u && listener->closing)
        duct_listener_destroy(listener); /* closes listen_fd itself if still open */
}

void duct_listener_destroy_chain(duct_listener_t *head)
{
    while (head) {
        auto next = head->next;
        duct_listener_destroy(head);
        head = next;
    }
}

bool duct_local_listener_admits(duct_listener_t *listener)
{
    auto local = listener->local;
    return !local->cap || local->live < local->cap;
}

void duct_local_listener_take(duct_listener_t *listener, duct_conn_t *conn)
{
    ++listener->local->live;
    ++listener->pre_conn_refs;
    conn->ctx = listener;
}

void duct_local_listener_drop(duct_conn_t *conn)
{
    auto listener = (duct_listener_t *)conn->ctx;
    conn->ctx = nullptr;
    --listener->local->live;
    duct_listener_release_pre_conn_ref(listener);
}

/** @brief Claim a free registry slot for @p fd and record @p io_id in it.
 *  @return false with every slot taken. */
static bool s_reg_add(duct_listener_reg_t *regs, duct_sock_t fd, unsigned io_id)
{
    for (unsigned i = 0u; i < duct_runtime_max_listeners; ++i) {
        duct_sock_t vacant = duct_sock_bad;
        if (duct_atomic_cas(strong, &regs[i].fd, &vacant, fd, acq_rel, relaxed)) {
            regs[i].io_id = io_id;
            return true;
        }
    }
    return false;
}

/** @brief Find the registry slot holding @p fd, @c nullptr for none. */
static duct_listener_reg_t *s_reg_find(duct_listener_reg_t *regs, duct_sock_t fd)
{
    for (unsigned i = 0u; i < duct_runtime_max_listeners; ++i)
        if (duct_atomic_load(&regs[i].fd, acquire) == fd)
            return &regs[i];
    return nullptr;
}

/** @brief Post @p fd's listener close with no wait.
 *  The registry slot is found ahead of the post: once the io thread's close
 *  runs, the OS stays free to hand the same fd number to a concurrent bind,
 *  and a lookup after that finds that bind's slot. The slot is freed once the
 *  post lands, the fd being the io thread's business from then. On an alloc
 *  or post failure the entry stays: the listener remains io-owned and live,
 *  unreachable from here, but never a stale registry hit either.
 */
static void s_close_fire_and_forget(duct_listener_route_t *route, duct_sock_t fd, unsigned io_id)
{
    duct_auto_del auto sync = duct_new(duct_listener_sync_t);
    if (!sync)
        return;
    auto reg = s_reg_find(route->regs, fd);
    if (!duct_io_post_listener_close(io_id, fd, sync))
        return;
    if (reg)
        duct_atomic_store(&reg->fd, duct_sock_bad, release);
}

/** @brief Resolve the RX slot pool of @p l's worker, creating it on first use.
 *  Every datagram node of that worker reads into it, all of them on io thread
 *  worker % @c n_io. Binds racing on a fresh worker publish one pool through
 *  the CAS, the loser freeing its own.
 *  @return @c nullptr on an allocation failure. */
static duct_x_slot_pool_t *s_rx_pool_of(duct_listener_route_t *route, const duct_listener_t *l)
{
    auto slot = &route->rx_pools[l->worker];
    auto pool = duct_atomic_load(slot, acquire);
    if (pool)
        return pool;
    auto fresh = duct_new(duct_x_slot_pool_t);
    duct_do_if(!fresh, return nullptr);
    /* A slot stays checked out until the worker consumes the lane entry
     * holding it, so one duct_io_dgram_rx_drain holds up to
     * duct_dgram_rx_batch * duct_dgram_rx_max_passes; a pool short of that
     * stalls the socket mid-drain. The record header rides on top of a
     * whole datagram, so a slot's payload area matches the fallback read.
     * The slots are the pool's ceiling: a read batch of them goes live at a
     * time, as a drain needs them, and goes back at rest. */
    bool ok = duct_x_slot_pool_init(fresh, duct_dgram_rx_slots,
                                    DUCT_LISTENER_DGRAM_DEFAULT + duct_dgram_record_hdr_size,
                                    duct_dgram_record_hdr_size, duct_dgram_rx_batch,
                                    duct_events_x_slot_hooks());
    duct_do_if(!ok, duct_del(fresh); return nullptr);
    fresh->reader = l->io_id;
    return duct_x_slot_pool_publish(slot, fresh);
}

/* The counts follow the outbox the slots stand behind. The small class holds the lanes' capacity in
 * path-MTU datagrams, never fewer than one chunk, and grows a send depth of slots at a time; the large
 * class holds each lane's capacity in full UDP payloads, at least one, and grows a slot per lane. The
 * lane capacity is read back from the made outbox, so the build's override and the queue's clamp are
 * both in it. */
bool duct_listener_tx_slots_new(duct_listener_t *l, uint32_t lead, uint32_t chunk)
{
    auto outbox = (duct_vmq_mpsc_t *)l->dgram_tx_outbox;
    uint32_t lanes = outbox->n_lanes;
    size_t lane_bytes = duct_mpsc_cap(outbox, 0u);
    uint32_t slot_bytes[2] = {
        (uint32_t)duct_align_up(lead + duct_pmtu_path_default, duct_cacheline_size),
        (uint32_t)duct_align_up(lead + duct_udp4_payload_max, duct_cacheline_size),
    };
    uint32_t count[2] = {
        (uint32_t)duct_max((size_t)lanes * lane_bytes / slot_bytes[0], (size_t)chunk),
        lanes * (uint32_t)duct_max(lane_bytes / slot_bytes[1], (size_t)1u),
    };
    uint32_t grain[2] = { chunk, lanes };
    auto pools = duct_new(duct_x_slot_pool_t, 2);
    duct_do_if(!pools, return false);
    for (unsigned c = 0u; c < 2u; ++c) {
        bool ok = duct_x_slot_pool_init(&duct_at(pools)[c], count[c], slot_bytes[c], lead, grain[c],
                                        duct_events_x_slot_hooks());
        duct_do_if(!ok, duct_listener_tx_slots_free(duct_at(pools)); return false);
    }
    l->tx_slots = duct_at(pools);
    return true;
}

void duct_listener_tx_slots_free(duct_x_slot_pool_t *pools)
{
    for (unsigned c = 0u; c < 2u; ++c)
        duct_x_slot_pool_free(&pools[c]);
    duct_del(pools);
}

/** @brief Build node @p node of one bind and register it on its io thread.
 *  @p node picks both the io thread, node % @c n_io, and the worker,
 *  node % @c n_workers. @p fd, and @p local when set, belong to the node on
 *  every path: on a failure the path is unlinked while @p fd still pins the file's
 *  identity, then @p fd is closed and both are freed.
 */
static duct_result_t
s_listener_make_node(duct_listener_route_t *route, const duct_listener_cfg_t *cfg,
                     duct_sock_t fd, duct_xport_t xport_type, uint16_t port, unsigned node,
                     bool shared, duct_local_bind_t *local)
{
    unsigned io_id = node % route->n_io;
    duct_result_t rc = rc_no_memory;
    duct_auto_del auto protos = duct_at(duct_new(const duct_proto_t *, cfg->n_protos));
    duct_auto_del auto sync = duct_new(duct_listener_sync_t);
    if (!protos || !sync)
        goto cleanup;
    for (unsigned i = 0u; i < cfg->n_protos; ++i)
        protos[i] = cfg->protos[i];

    auto l = duct_new(duct_listener_t);
    if (!l)
        goto cleanup;
    *l = (duct_listener_t){
        .listen_fd = fd,
        .protos = duct_move(protos),
        .n_protos = cfg->n_protos,
        .peek_cap = cfg->peek_cap,
        .probe_wait_ms = cfg->probe_wait_ms,
        .peek_min = cfg->peek_min,
        .bound_port = port,
        .io_id = io_id,
        .worker = node % route->n_workers,
        .xport_type = xport_type,
        .local = local,
    };
    /* Several same-source datagrams of one size come back as one read, the
     * per-packet work done once for the group. Every listener read path reports
     * the segment size the split runs on, and the cap keeps a group inside the
     * span each of them offers. */
    if (xport_type == x_udp) {
        duct_discard duct_xset_dgram_gro(fd, duct_listener_dgram_span(l));
        l->rx_slots = s_rx_pool_of(route, l);
        if (!l->rx_slots) {
            duct_listener_destroy(l);
            return rc_no_memory;
        }
    }
    if (shared) {
        duct_auto_del auto caps = duct_at(duct_new(size_t, route->n_workers));
        if (!caps) {
            duct_listener_destroy(l);
            return rc_no_memory;
        }
        /* DUCT_DGRAM_TX_LANE_CAP env override, same knob class as
         * DUCT_DGRAM_RCVBUF: the lane is a standing queue invisible to
         * application send flow control (send_done fires at staging),
         * and its depth bounds worst-case delivery age.
         * Floor guards vmq per-entry overhead. */
        size_t lane_cap = duct_dgram_tx_outbox_cap;
        {
            const char *env = getenv("DUCT_DGRAM_TX_LANE_CAP");
            long long v = env ? atoll(env) : 0;
            if (v >= 64 * 1024)
                lane_cap = (size_t)v;
        }
        for (unsigned i = 0u; i < route->n_workers; ++i)
            caps[i] = lane_cap;
        l->dgram_tx_outbox = duct_vmq_mpsc_create(route->n_workers, caps, 0u);
        if (!l->dgram_tx_outbox) {
            duct_listener_destroy(l);
            return rc_no_memory;
        }
        if (!duct_events_dgram_tx_pool_alloc(l)) {
            duct_listener_destroy(l);
            return rc_no_memory;
        }
        duct_io_dgram_tx_kick_init(l);
    }
    /* duct_engine_launch always starts every io thread before returning an
     * engine handle at all, so a listener never binds before its owning io
     * thread exists — post plus bounded wait is always valid. */
    if (!duct_io_post_listener_register(l, sync)) {
        duct_listener_destroy(l);
        return rc_fatal;
    }
    bool ok;
    duct_discard s_sync_finish(sync, &ok);
    if (!ok)
        return rc_fatal;
    if (!s_reg_add(route->regs, fd, io_id)) {
        s_close_fire_and_forget(route, fd, io_id);
        return rc_no_memory;
    }
    return rc_ok;

cleanup:
    if (local) {
        duct_local_listener_unlink(local);
        duct_del(local);
    }
    duct_sock_close(fd);
    return rc;
}

static duct_result_t
s_listener_register(duct_listener_route_t *route, const duct_listener_cfg_t *cfg,
                    duct_sock_t fd, duct_xport_t xport_type, uint16_t port,
                    bool shared, duct_listener_out_fds_t *out, duct_local_bind_t *local)
{
    duct_sock_t added[duct_runtime_max_workers];
    unsigned n_fds = 0u;

    /* Where the port spreads across sockets, a shared bind takes one socket per
     * worker, its sessions opened on that worker, so a worker behind on its
     * lanes stalls only the socket its own sessions read through; any other
     * bind takes one per io thread. Elsewhere a bind is one socket. A path
     * bind is one node on every platform, node 0 owning the bound file. */
    unsigned fanout;
    switch (xport_type) {
    case x_local:
        fanout = 1u;
        break;
    default:
        fanout = duct_x_port_sharing < x_port_share_spread ? 1u
               : shared ? route->n_workers : route->n_io;
        break;
    }

    duct_result_t rc = s_listener_make_node(route, cfg, fd, xport_type, port, 0u, shared, local);
    duct_do_if(rc != rc_ok, goto fail);
    added[n_fds++] = fd;
    if (out->fds && out->cap)
        out->fds[0] = fd;

    for (unsigned node = 1u; node < fanout; ++node) {
        uint16_t bound_port = port;
        duct_sock_t extra_fd = xport_type == x_udp
            ? duct_dgram_socket_open(cfg->addr, &bound_port, shared)
            : duct_listener_open(cfg->addr, &bound_port);
        duct_do_if(extra_fd == duct_sock_bad,
            rc = rc_fatal;
            goto fail;
        );
        rc = s_listener_make_node(route, cfg, extra_fd, xport_type, bound_port, node, shared, nullptr);
        duct_do_if(rc != rc_ok, goto fail);
        added[n_fds++] = extra_fd;
        if (out->fds && n_fds - 1u < out->cap)
            out->fds[n_fds - 1u] = extra_fd;
    }
    out->n = n_fds;
    return rc_ok;

fail:
    /* added[i] is node i's socket, read by io thread i % n_io. */
    for (unsigned i = 0u; i < n_fds; ++i)
        s_close_fire_and_forget(route, added[i], i % route->n_io);
    out->n = 0u;
    return rc;
}

duct_result_t duct_listener_route_bind(duct_listener_route_t *route, const duct_listener_cfg_t *cfg,
                                       uint16_t *port, duct_listener_out_fds_t *out)
{
    duct_do_if(!cfg || cfg->n_protos == 0u || !cfg->protos || !port || !out, return rc_invalid_arg);
    /* A path bind names no host, has a path that fits and is a stream; an
     * address bind names a host and sets none of the path-side fields. */
    bool local = cfg->local_path != nullptr,
         named = cfg->addr && *cfg->addr,
         fits = local && duct_local_path_fits(cfg->local_path);
    duct_do_if(local ? named || !fits || cfg->kind != listener_stream
                     : !named || cfg->local_mode || cfg->local_group || cfg->max_sessions
                           || cfg->max_conns_per_s,
               return rc_invalid_arg);
    duct_do_if(local && !duct_x_local_floor, return rc_not_supported);
    /* The probe wait holds peek_min, so it needs probe_wait_ms, a stream listener and a value
     * one read can reach: the wait then always has room for the read that completes it. */
    auto span = duct_listener_peek_span(cfg->peek_cap);
    duct_do_if(cfg->peek_min && (cfg->peek_min > span || !cfg->probe_wait_ms || cfg->kind == listener_dgram),
               return rc_invalid_arg);

    /* fl_proto_dgram_shared is meaningless outside
     * listener_dgram: it says "never open a per-peer connected socket," and
     * listener_stream has no per-peer socket. A sealed
     * wire framed for datagrams is refused alongside it: this listener's conns
     * are x_tcp or x_local, whose ring carries no record for that framing to
     * strip. */
    auto stream_xport = local ? x_local : x_tcp;
    if (cfg->kind != listener_dgram)
        for (unsigned i = 0u; i < cfg->n_protos; ++i)
            if (duct_has(cfg->protos[i]->cfg.flags, fl_proto_dgram_shared)
                || !duct_wire_framing_fits_xport(cfg->protos[i]->cfg.wire, stream_xport))
                return rc_invalid_arg;

    if (cfg->kind == listener_dgram) {
        /* Every bound proto needs a wire that strips the internal
         * [len][payload] record framing (duct_proto_create_udp sets one up).
         * A sealed wire passes on two separate answers: fl_wire_dgram_ok, where
         * TLS sequences records by position and needs gapless ordered delivery
         * while Noise numbers every PDU and carries a replay window; and
         * datagram framing, which consumes the record. One
         * check here covers all three x_udp conn kinds. */
        for (unsigned i = 0u; i < cfg->n_protos; ++i) {
            auto wire = cfg->protos[i]->cfg.wire;
            if (!wire
                || (wire->unseal && !duct_has(wire->flags, fl_wire_dgram_ok))
                || !duct_wire_framing_fits_xport(wire, x_udp_shared))
                return rc_invalid_arg;
        }

        /* A shared proto's every response reserves whole into a fixed-cap
         * outbox lane, so an unset or oversized max_response is a guaranteed
         * vmq_push_too_large on first use — caught once here instead.
         * wire->header_size is folded in because the lane holds the packed
         * bytes, and on_pack may add that much on top of max_response. */
        for (unsigned i = 0u; i < cfg->n_protos; ++i) {
            auto pcfg = &cfg->protos[i]->cfg;
            if (!duct_has(pcfg->flags, fl_proto_dgram_shared))
                continue;
            size_t need = 0u;
            if (pcfg->max_response == 0u
                || duct_ckd_add(&need, pcfg->max_response, pcfg->wire->header_size)
                || need > duct_dgram_shared_max_response)
                return rc_invalid_arg;
        }

        bool shared = false;
        for (unsigned i = 0u; i < cfg->n_protos && !shared; ++i)
            shared = duct_has(cfg->protos[i]->cfg.flags, fl_proto_dgram_shared);

        duct_sock_t fd = duct_dgram_socket_open(cfg->addr, port, shared);
        if (fd == duct_sock_bad)
            return rc_fatal;
        return s_listener_register(route, cfg, fd, x_udp, *port, shared, out, nullptr);
    }

    if (local) {
        duct_auto_del auto bound = duct_new(duct_local_bind_t);
        duct_do_if(!bound, return rc_no_memory);
        duct_sock_t local_fd = duct_local_listener_open(cfg, bound);
        duct_do_if(local_fd == duct_sock_bad, return rc_fatal);
        *port = 0u;
        return s_listener_register(route, cfg, local_fd, x_local, 0u, false, out, duct_move(bound));
    }

    /* cfg->addr is the bind host; *port is in/out (0 = ephemeral, OS assigns). */
    duct_sock_t fd = duct_listener_open(cfg->addr, port);
    if (fd == duct_sock_bad)
        return rc_fatal;
    return s_listener_register(route, cfg, fd, x_tcp, *port, false, out, nullptr);
}

duct_result_t duct_listener_route_close(duct_listener_route_t *route, duct_sock_t fd)
{
    duct_do_if(fd == duct_sock_bad, return rc_invalid_arg);

    auto reg = s_reg_find(route->regs, fd);
    duct_do_if(!reg, return rc_invalid_arg);
    auto io_id = reg->io_id;

    duct_auto_del auto sync = duct_new(duct_listener_sync_t);
    duct_do_if(!sync, return rc_no_memory);
    if (!duct_io_post_listener_close(io_id, fd, sync))
        return rc_fatal;
    /* Post landed: the fd's fate is now the io thread's business, and the
     * OS cannot hand this exact fd number to a new socket before that
     * thread's own close runs — freeing the slot now, not after
     * confirmation, cannot collide with a later bind, and avoids leaving a
     * stale entry behind on rc_timeout below. */
    duct_atomic_store(&reg->fd, duct_sock_bad, release);

    bool ok;
    bool signaled = s_sync_finish(sync, &ok);
    return signaled ? (ok ? rc_ok : rc_invalid_arg) : rc_timeout;
}
