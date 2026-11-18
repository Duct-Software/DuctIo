/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

#include "duct_bits.h"
#include "duct_conn.h"
#include "duct_conn_block.h"
#include "duct_core.h"
#include "duct_dgram_rec.h"
#include "duct_io.h"
#include "duct_olb_rx.h"
#include "duct_wfq_msg.h"
#include "duct_olb_tx.h"
#include "duct_protocol.h"
#include "duct_relay.h"
#include "duct_ticks.h"
#include "duct_vmq.h"
#include "duct_vnet.h"
#include "duct_wire.h"
#include "duct_xport.h"
#include "../pool/duct_block_pool.h"

#if DUCT_RUNTIME_STATS
#include "duct_runtime_stats.h"
#endif

#include <string.h>
#include <unistd.h>

typedef struct duct_conn_pool {
    duct_block_pool_t blocks;
    unsigned _Atomic free_n;
    uint64_t _Atomic refused,
                     said_at;
    duct_conn_t *io_head[duct_runtime_max_io_threads];
} duct_conn_pool_t;

static constexpr uint32_t conn_pool_floor_blocks = 8u;

static duct_conn_pool_t *s_pool;

static duct_sweep_cursor_t s_sweep;

static void duct_conn_pool_ctor(void) __attribute__((constructor(DUCT_CTOR_PRI_STATE)));
static void duct_conn_pool_ctor(void)
{
    s_pool = duct_new(duct_conn_pool_t);
    duct_fatal(!s_pool);
    duct_fatal(!duct_block_pool_init(&s_pool->blocks, duct_max_conns, conn_block_size,
                                     duct_conn_page0(),
                                     (size_t)conn_pool_floor_blocks * conn_block_size));
    duct_atomic_store(&s_pool->free_n, duct_max_conns, relaxed);
}

void duct_conn_pool_reclaim(void);

static void duct_conn_pool_dtor(void) __attribute__((destructor(DUCT_CTOR_PRI_STATE)));
static void duct_conn_pool_dtor(void)
{
    duct_conn_pool_reclaim();
    duct_block_pool_shutdown(&s_pool->blocks);
    duct_del(s_pool);
    s_pool = nullptr;
}

uint32_t duct_conn_idx_get(const duct_conn_t *conn)
{
    return duct_conn_block_idx(conn);
}

duct_conn_t *duct_conn_by_idx(unsigned idx)
{
    /* The guarded resolver: a slot that is not active — never committed,
     * warm-free or dropped — answers nullptr, and only an active conn's
     * whole block is dereferenceable. Page 0 stays mapped for any slot
     * that was ever live, so raw page-0 readers use duct_conn_block_at. */
    return duct_conn_block_live(idx) ? duct_conn_block_at(idx) : nullptr;
}

uint32_t duct_conn_block_idx(const duct_conn_t *conn)
{
    return (uint32_t)(((uintptr_t)conn - (uintptr_t)s_pool->blocks.vm.base)
                      / conn_block_size);
}

duct_conn_t *duct_conn_block_at(uint32_t idx)
{
    return (duct_conn_t *)duct_block_pool_at(&s_pool->blocks, idx);
}

bool duct_conn_block_live(uint32_t idx)
{
    if (idx >= s_pool->blocks.n_blocks)
        return false;
    return duct_atomic_load(&duct_at(s_pool->blocks.meta)[idx].state, acquire)
        == blk_active;
}

uint64_t _Atomic *duct_conn_gen_req(const duct_conn_t *conn)
{
    return (uint64_t _Atomic *)((uintptr_t)conn + conn_off_gen);
}

duct_msg_conn_req *duct_conn_req_msg(const duct_conn_t *conn)
{
    return (duct_msg_conn_req *)((uintptr_t)conn + conn_off_req);
}

duct_block_pool_t *duct_conn_pool_blocks(void)
{
    return &s_pool->blocks;
}

void duct_conn_io_list_link(duct_conn_t *conn, unsigned io_id)
{
    assert(io_id < duct_runtime_max_io_threads);
    /* Host-driven x_inter conns stay out: no fd, never registered via
     * s_conn_register. A device-backed one carries a duct_device_ops_t copy
     * in the ctx region and holds a watched wait handle, so it belongs here —
     * this list is how duct_io_cleanup reaches it at engine teardown. */
    if (conn->xport_type == x_inter && !duct_conn_device_ops(conn))
        return;
    conn->io_prev = nullptr;
    conn->io_next = s_pool->io_head[io_id];
    if (s_pool->io_head[io_id])
        s_pool->io_head[io_id]->io_prev = conn;
    s_pool->io_head[io_id] = conn;
}

void duct_conn_io_list_unlink(duct_conn_t *conn, unsigned io_id)
{
    assert(io_id < duct_runtime_max_io_threads);
    /* Host-driven x_inter was never linked, and duct_conn_acquire doesn't
     * reset io_next/io_prev on a fresh slot — unlinking anyway splices
     * garbage pointers into the live list. */
    if (conn->xport_type == x_inter && !duct_conn_device_ops(conn))
        return;
    /* Idempotent: may run against a conn, unlinked by s_conn_close.
     * Not-head-and-no-neighbors only happens for an already-removed
     * or never-linked node — a sole linked node is still the head. */
    if (s_pool->io_head[io_id] != conn && !conn->io_prev && !conn->io_next)
        return;
    if (conn->io_prev)
        conn->io_prev->io_next = conn->io_next;
    else
        s_pool->io_head[io_id] = conn->io_next;
    if (conn->io_next)
        conn->io_next->io_prev = conn->io_prev;
    conn->io_next = conn->io_prev = nullptr;
}

duct_conn_t *duct_conn_io_list_head(unsigned io_id)
{
    assert(io_id < duct_runtime_max_io_threads);
    return s_pool->io_head[io_id];
}

duct_conn_t *duct_conn_by_handle(duct_conn_handle_t handle)
{
    if (!handle.gen)
        return nullptr;
    duct_do_if(handle.idx >= duct_max_conns, return nullptr);
    duct_do_if(!duct_conn_block_live(handle.idx), return nullptr);
    auto conn = duct_conn_block_at(handle.idx);
    uint64_t gen = duct_gen_req_gen(duct_atomic_load(duct_conn_gen_req(conn), acquire));
    return (gen != 0u && gen == handle.gen) ? conn : nullptr;
}

/** @brief True if @p g can still take @p bumps more generation bumps.
 *  The ceiling is @ref hconn_gen_mask.
 */
static inline bool s_gen_ceiling_ok(uint64_t g, unsigned bumps)
{
    return g + bumps <= hconn_gen_mask;
}

/** @brief Bump @c gen_req's generation by one, packing req_flags/reason
 *  back to zero in the same store.
 *
 *  A single publishing point — nobody ever observes "generation bumped,
 *  flags still stale". Caller must already know no concurrent writer can
 *  touch @c gen_req.
 *  @return false at the per-conn generation ceiling — slot retires for good.
 */
static bool s_gen_advance(duct_conn_t *conn)
{
    auto slot = duct_conn_gen_req(conn);
    uint64_t old_word = duct_atomic_load(slot, relaxed),
             new_gen = duct_gen_req_gen(old_word) + 1u;
    if (!s_gen_ceiling_ok(duct_gen_req_gen(old_word), 1u))
        return false;
    duct_atomic_store(slot, duct_gen_req_pack(new_gen, 0u, close_normal), release);
    return true;
}

/** @brief Least gap between two pool-exhaustion log lines, nanoseconds. */
static constexpr uint64_t s_refusal_gap_ns = 1'000'000'000u;

/** @brief Count one refused acquire and log the exhaustion once per
 *  @c s_refusal_gap_ns, whichever thread arrives first. */
static void s_pool_refused(void)
{
    uint64_t n = duct_atomic_fetch(add, &s_pool->refused, 1u, relaxed) + 1u,
             now = duct_ticks_mono_ns(),
             then = duct_atomic_load(&s_pool->said_at, relaxed);
    if (now - then >= s_refusal_gap_ns
        && duct_atomic_cas(strong, &s_pool->said_at, &then, now, relaxed, relaxed))
        duct_diag("conn pool exhausted: all %u slots in use, %llu acquires refused so far",
                  duct_max_conns, (unsigned long long)n);
}

unsigned duct_conns_free(void)
{
    return duct_atomic_load(&s_pool->free_n, relaxed);
}

uint64_t duct_conns_refused(void)
{
    return duct_atomic_load(&s_pool->refused, relaxed);
}

static void s_page0_reset(duct_conn_t *conn)
{
    memset((void *)((uintptr_t)conn + conn_off_req), 0,
           (size_t)duct_conn_page0() - conn_off_req);
    duct_conn_req_msg(conn)->msg = duct_msg_init_embedded(duct_io_conn_req_exec_fn());
}

duct_conn_t *duct_conn_acquire(void)
{
    uint32_t idx = duct_block_pool_acquire(&s_pool->blocks);
    if (idx == duct_blk_none) {
        /* Every word either holds a live conn or waits on its run drop:
         * stepping a private cursor hands claimed words back before this
         * thread reports exhaustion. A step takes its quota per word upfront
         * and finishes the word in one go, so no cursor can inherit a
         * half-dropped word; the pool's own CASes make the concurrent step
         * safe; the io tick's cursor is never touched. */
        duct_sweep_cursor_t help = {};
        bool pending = true;
        while (pending && idx == duct_blk_none) {
            pending = duct_block_pool_sweep_step(&s_pool->blocks, &help, 1u);
            idx = duct_block_pool_acquire(&s_pool->blocks);
        }
        if (idx == duct_blk_none) {
            s_pool_refused();
            return nullptr; /* no free blocks */
        }
    }
    duct_atomic_fetch(sub, &s_pool->free_n, 1u, relaxed);
    auto conn = duct_conn_block_at(idx);
    duct_atomic_store(&conn->session_token, handle_null, release);
    bool advanced = s_gen_advance(conn);
    duct_do_if(!advanced, return nullptr); /* per-conn gen overflow */
    /* Resetting the fields below after the generation bump is safe only
     * because a fresh generation is not itself a publication channel: no
     * thread resolves this conn by handle until a later message hands the
     * handle out with its own release/acquire edge. Do not reorder.
     * Every teardown path runs ahead of the release that drains @c refs,
     * and the page-0 reset below zeroes both lane words and the ctx for
     * the next occupant.
     */
    duct_atomic_store(&conn->state, 0u, relaxed);
    duct_atomic_store(&conn->refs, 1u, relaxed);
    conn->fd = duct_sock_bad;
    conn->wire = nullptr;
    conn->wire_parser = nullptr;
    conn->vnet_hdr_len = 0u;
    duct_atomic_store(&conn->vnet_gso, 0u, relaxed);
    /* head_unsealed survives teardown — duct_conn_sealed_codec_detach clears
     * the codec alone — so this reset stops a recycled slot from skipping
     * its first unseal. */
    conn->seal = (duct_sealed_conn_ctx_t){};
    duct_atomic_store(&conn->wire_rebind_next, nullptr, relaxed);
    conn->io_id = conn_io_none;
    conn->worker_id = conn_worker_none;
    s_page0_reset(conn);
    return conn;
}

static void s_conn_free_push(duct_conn_t *conn)
{
    duct_atomic_fetch(add, &s_pool->free_n, 1u, relaxed);
    duct_conn_touched_update(conn);
    duct_block_pool_release(&s_pool->blocks, duct_conn_idx_get(conn),
                            duct_conn_stats(conn)->touched);
}

/** @brief Finish a release at @c refs == 0: arm @c rel_pend over live
 *  request flags, hand a pinned word to the last unpin as @c conn_spent,
 *  or clear the bit, bump the generation and push the slot.
 *  The bump and the flags test are one whole-word CAS: a post landing first
 *  holds the finish for its node's run, and one landing after finds a
 *  generation nothing matches. The bump is guarded because generation
 *  shares that word, where an add at the ceiling wraps it to 0. The push
 *  asks for two bumps: the next acquire needs its own, and without it that
 *  acquire fails having already popped the slot, leaking it.
 *  A pin nibble still holding units (§5) is the spent handoff: no new pin
 *  can land past the quiesce claim, so the count only waits out the decay,
 *  and the unpin that takes @c pins 1 → 0 re-enters here on a word nothing
 *  else can move — both races closed by the CAS: an unpin landing between
 *  this loop's read and its spent-CAS fails that CAS and the re-loop sees
 *  @c pins == 0, a spent mark landing before the last unpin hands the
 *  completion to that unpin's own finish.
 *  @p gen, when nonzero, must still match the word — a recycled slot
 *  belongs to its next occupant's cycle.
 */
static void s_release_finish(duct_conn_t *conn, uint64_t gen)
{
    auto slot = duct_conn_gen_req(conn);
    uint64_t old_word = duct_atomic_load(slot, relaxed);
    for (;;) {
        if (gen && duct_gen_req_gen(old_word) != gen)
            return;
        if (duct_gen_req_flags(old_word)) {
            if (old_word & gen_req_rel_pend)
                return;
            if (duct_atomic_cas(weak, slot, &old_word,
                                old_word | gen_req_rel_pend, release, relaxed))
                return;
            continue;
        }
        if (old_word & gen_req_pins_mask) {
            if (duct_gen_req_phase(old_word) == conn_spent)
                return; /* the last unpin's completion, already handed off */
            uint64_t want = (old_word & ~gen_req_phase_mask)
                          | ((uint64_t)conn_spent << gen_req_phase_shift);
            if (duct_atomic_cas(weak, slot, &old_word, want, release, relaxed))
                return;
            continue;
        }
        if (!s_gen_ceiling_ok(duct_gen_req_gen(old_word), 1u))
            return; /* per-conn gen overflow, slot retired for good */
        uint64_t want = (old_word & ~gen_req_rel_pend)
                      + (1ull << gen_req_gen_shift);
        if (duct_atomic_cas(weak, slot, &old_word, want, release, relaxed)) {
            if (s_gen_ceiling_ok(duct_gen_req_gen(old_word), 2u)) {
                /* The slot's last unit is spent: nobody's commit, completion
                 * or purge-side walk can hold the ring open now, and the
                 * records it still carries — a timeout's unsent bytes, a
                 * lost conn's staged train — complete here, each payload
                 * reference dropped before the block takes its next
                 * occupant. */
                duct_do_if(duct_conn_tx_olb(conn),
                           duct_olb_tx_purge(duct_conn_tx_olb(conn)));
                s_conn_free_push(conn);
            }
            return;
        }
    }
}

void duct_conn_release(duct_conn_t *conn)
{
    if (duct_atomic_fetch(sub, &conn->refs, 1u, acq_rel) != 1u)
        return;
    s_release_finish(conn, 0u);
}

void duct_conn_unpin(duct_conn_t *conn)
{
    uint64_t prev = duct_atomic_fetch(sub, duct_conn_gen_req(conn),
                                      1ull << gen_req_pins_shift, acq_rel);
    if ((prev & gen_req_pins_mask) != (1ull << gen_req_pins_shift))
        return;
    /* Only a word already marked spent owes this unpin a finish: anything
     * else still holds @c refs > 0, whose own 0-crossing re-enters the
     * finish loop and observes pins == 0 there. */
    if (duct_conn_phase(conn) == conn_spent)
        s_release_finish(conn, 0u);
}

void duct_conn_release_finish(duct_conn_t *conn, uint64_t gen)
{
    s_release_finish(conn, gen);
}

void duct_conn_discard(duct_conn_t *conn)
{
    duct_conn_teardown_io(conn);
    duct_conn_teardown_worker(conn);
    duct_conn_teardown_ctx(conn);
    duct_conn_release(conn);
}

duct_result_t duct_conn_setup(duct_conn_t *conn, duct_sock_t fd, duct_xport_t xport,
                              size_t tx_cap)
{
    duct_do_if(fd == duct_sock_bad, return rc_invalid_arg);
    duct_do_if(((duct_olb_rx_t *)((uintptr_t)conn + conn_off_rx))->h.buf_size,
               return rc_invalid_order);
    duct_do_if(tx_cap > duct_conn_tx_olb_cap || !tx_cap, return rc_invalid_arg);
    /* A coalescing datagram socket answers one whole group per read, and its
     * reserve demands room for the worst case plus the backend's per-read
     * scratch; a vnet tun leg's reserve demands a whole cut. That room rides
     * on top of the working area: taken out of the same bytes, the last read's
     * worth of stage never satisfies a reserve and the read loop stalls on a
     * compaction the worker is never caught up enough to allow. Sized from the
     * build's own ceiling: coalescing is asked for at wire bind, past this
     * carve, and a region cannot grow afterwards. */
    size_t vnet = xport == x_raw_packet ? duct_x_vnet_hdr_len(fd) : 0u;
    duct_do_if(vnet > duct_vnet_hdr_max, return rc_not_supported);
    size_t rx_cap = duct_conn_rx_olb_cap
                  + (xport == x_udp_peer
                         ? sizeof(duct_dgram_rec_hdr_t) + duct_x_gro_max + duct_events_rx_scratch
                         : 0u)
                  + (vnet ? duct_vnet_cut_max : 0u);
    duct_do_if(rx_cap > conn_rx_region_max, return rc_invalid_arg);
    conn->fd = fd;
    conn->xport_type = xport;
    conn->vnet_hdr_len = (uint8_t)vnet;
    duct_conn_carve_olb(conn, rx_cap, tx_cap);
    /* A tun takes its offloads as the engine takes the fd: from here the cut
     * and merge stand behind every read and write. A type 5 write goes only to a
     * tun that took the USO flags, which fl_conn_vnet_uso records. */
    if (vnet && duct_x_vnet_offload(fd) == rc_ok)
        duct_conn_state_set(conn, fl_conn_vnet_uso);
    return rc_ok;
}

/* The codec goes at once, whatever pins its cleartext buffer: a parked handler or
 * answer holds the buffer block, not the codec, and the last pin to drop frees the
 * block. */
void duct_conn_sealed_codec_detach(duct_conn_t *conn)
{
    auto sc = duct_conn_sealed_ctx(conn);
    if (sc && sc->codec) {
        auto codec = sc->codec;
        sc->codec = nullptr;
        duct_wire_codec_destroy(codec);
    }
}

void duct_conn_inter_slot_release(duct_vmq_hdr_t *hdr, [[maybe_unused]] void *arg)
{
    duct_do_if(hdr->type != inter_msg_batch, return);
    auto b = (const duct_msg_inter_batch_t *)&hdr->payload[0];
    if (b->rx_pool)
        duct_io_rx_slot_drop(b->rx_pool, b->rx_slot, false);
}

static void s_conn_transport_fini_lane(duct_conn_t *conn)
{
    auto lane = duct_conn_lane(conn);
    duct_discard duct_vmq_mpsc_drain(lane, duct_conn_inter_slot_release, nullptr);
    /* wake_latch stays bound: the latch is its worker's, outliving the conn,
     * and a host thread pinned in §5's word may still notify it after this
     * drain — an empty wake, harmless. Clearing the pointer here would race
     * that notify's read of it; the next occupant's page-0 reset clears it
     * with no pins left to observe the write. */
}

void duct_conn_teardown_io(duct_conn_t *conn)
{
    /* Runs before the physical half, while the ctx region still points
     * at what the xport put there — and holds only the parts no queued
     * worker work can still reference: the x_local drop is admission
     * accounting and a listener reference the worker's egress never
     * touches. */
    switch (conn->xport_type) {
    case x_local:
        if (*duct_conn_listener_ref(conn))
            duct_local_listener_drop(conn);
        break;
    default:
        break;
    }
}

void duct_conn_teardown_ctx(duct_conn_t *conn)
{
    /* Runs after the physical half drained the lane: batches queued ahead of
     * the consume could still carry device-lent payloads and reserve into
     * the listener outbox, so the releases below wait the lane out. */
    switch (conn->xport_type) {
    case x_udp_shared: {
        auto dctx = duct_conn_dgram_ctx(conn);
        if (dctx->listener) {
            duct_io_listener_pre_conn_ref_release(dctx->listener);
            dctx->listener = nullptr;
        }
        break;
    }
    case x_inter: {
        /* Holds before release: past ops.release the device belongs to the
         * application again and may be closed, so nothing of ours may still
         * reference it. */
        auto ops = duct_conn_device_ops(conn);
        if (ops) {
            duct_io_device_teardown(conn);
            if (ops->release)
                ops->release(ops->ctx);
            duct_conn_ctx(conn)->link = nullptr;
        }
        break;
    }
    default:
        break;
    }
}

void duct_conn_teardown_worker(duct_conn_t *conn)
{
    conn->wire_parser = nullptr;
    conn->wire = nullptr;
    duct_conn_sealed_codec_detach(conn);
    /* One arm resolves, never both: the xport that shaped this block decides
     * which page-0 substructures were live. */
    auto lane = duct_conn_lane(conn);
    if (lane) {
        /* A host reader still pinned in the word (§5) is one more MPSC
         * producer this drain pairs with, and the pinned word keeps the
         * slot out of every reuse path — no spin and no fence needed: the
         * generation bump cannot land until the last unpin's finish. */
        s_conn_transport_fini_lane(conn);
    }
    if (conn->fd != duct_sock_bad) {
        duct_sock_close(conn->fd);
        conn->fd = duct_sock_bad;
        /* The descriptor just freed may be the one a parked listener waits for. */
        duct_io_accept_resume();
    }
    /* ::session_token retained — conn-lost consume reads it ahead of its
     * teardown half. ::generation and ::io_id are owned by pool. */
}

void duct_conn_pool_reclaim(void)
{
    auto blocks = &s_pool->blocks;
    uint32_t words = duct_blk_words(blocks->n_blocks);
    for (uint32_t w = 0u; w < words; ++w) {
        uint64_t live = ~duct_atomic_load(&duct_at(blocks->free_bits)[w], acquire)
                        & duct_blk_word_mask(blocks, w);
        for (; live; live &= live - 1u) {
            uint32_t idx = (w << 6) + duct_ctz_ull(live);
            /* A run-claimed word reads all-live with most blocks never
             * committed: only an active block's page 0 is safe to touch,
             * and only an active conn owes teardown. */
            if (duct_atomic_load(&duct_at(blocks->meta)[idx].state, acquire) != blk_active)
                continue;
            auto conn = duct_conn_block_at(idx);
            if (duct_gen_req_gen(duct_atomic_load(duct_conn_gen_req(conn), relaxed)) == 0u)
                continue;
            /* Mirrors io's s_conn_shutdown, except for the events/io-list
             * walk, with the threads already joined: every ctx release runs
             * inline, past the lane drain, and the slot is pushed regardless
             * of @c refs. */
            duct_atomic_fetch(and, duct_conn_gen_req(conn),
                              ~((uint64_t)gen_req_flags_mask | gen_req_rel_pend),
                              relaxed);
            duct_atomic_store(&conn->refs, 0u, relaxed);
            duct_conn_teardown_io(conn);
            duct_conn_teardown_worker(conn);
            if (conn->xport_type == x_udp_shared) {
                auto dctx = duct_conn_dgram_ctx(conn);
                if (dctx->listener) {
                    duct_listener_release_pre_conn_ref(dctx->listener);
                    dctx->listener = nullptr;
                }
            } else if (conn->xport_type == x_inter && duct_conn_device_ops(conn)) {
                auto ops = duct_conn_device_ops(conn);
                duct_io_device_teardown(conn);
                if (ops->release)
                    ops->release(ops->ctx);
                duct_conn_ctx(conn)->link = nullptr;
            }
            s_release_finish(conn, 0u);
        }
    }
}

bool duct_conn_pool_sweep(uint32_t budget)
{
    return duct_block_pool_sweep_step(&s_pool->blocks, &s_sweep, budget);
}

duct_result_t duct_conn_bind_wire(duct_conn_t *conn, const duct_proto_t *proto,
                                  const duct_wire_t *leg_wire)
{
    duct_do_if(conn->wire || conn->wire_parser, return rc_invalid_order);
    /* Bumped on every bind. A sealed task's duct_msg_frame_t::sealed_epoch
     * proves stale only by comparing against this conn's current generation,
     * so it must advance on every rebind, even a conn not sealed-eligible yet,
     * in case a later proto_switch makes it so. */
    if (++conn->wire_epoch == 0u)
        conn->wire_epoch = 1u;
    auto cfg = duct_proto_cfg_of(proto);
    auto wire = leg_wire ? leg_wire : cfg->wire;
    if (!wire)
        return rc_ok;
    if (!duct_wire_framing_fits_xport(wire, conn->xport_type))
        return rc_invalid_arg;
    duct_fatal(wire->parser_max > duct_wire_parser_slot);
    duct_fatal(wire->codec_max > duct_wire_codec_slot);
    auto parser = duct_conn_wire_parser_slot(conn, 0u);
    memset(parser, 0, duct_wire_parser_slot);
    duct_wire_parser_init(wire, parser);
    conn->wire = wire;
    conn->wire_parser = parser;
    size_t budget = conn->wire->max_frame;
    /* Coalescing is asked for only once the wire is known to be one whose
     * whole per-datagram header is the record prefix: a group reaches the
     * parse described by its segment size, and nothing else describes it. */
    size_t coalesced = 0u;
    if (conn->xport_type == x_udp_peer && duct_wire_records(wire))
        coalesced = duct_xset_dgram_gro(conn->fd, duct_x_gro_max);
    if (coalesced > 0u)
        duct_conn_state_set(conn, fl_conn_dgram_gro);
    else
        duct_conn_state_clear(conn, fl_conn_dgram_gro);
    auto rx = duct_conn_rx_olb(conn);
    if (rx)
        /* One argument fixes both the span a reserve demands and the threshold
         * that has to clear it: the threshold is sized to the kernel response
         * for coalescing options or falls back to single-frame bounds. */
        duct_olb_rx_threshold_set(rx,
            (duct_conn_record_framed(conn) ? sizeof(duct_dgram_rec_hdr_t) : 0u)
                + duct_max(budget, coalesced));
    return rc_ok;
}

static duct_nonnull(1, 2) void
s_fence_retry_arm(const duct_wfq_route_t *route, duct_conn_t *conn)
{
#if DUCT_RUNTIME_STATS
    duct_io_rtstat_fence_push_full_inc();
#endif
    duct_io_trunk_req_post(route->trunk, duct_conn_handle_get(conn), fl_req_fence_retry);
    duct_worker_wfq_wait_arm(conn->worker_id, route->thread_id);
}

static duct_nonnull(1, 2) void
s_conn_post_wire_fence(const duct_wfq_route_t *route, duct_conn_t *conn)
{
    duct_msg_wire_fence m = {
        .msg = { .exec_fn = duct_session_exec_wire_fence, .arg = nullptr },
        .conn = duct_conn_handle_get(conn).word,
        .session = duct_atomic_load(&conn->session_token, acquire),
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
    /* A quiesced conn keeps its sentinel and posts no fence: its conn_lost pays
     * the leg's share of the switch, and a fence queued behind that message
     * runs past the worker's confirm. */
    duct_do_if(duct_conn_phase(conn) >= conn_quiesced, return);
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
        conn->wire = nullptr;
        conn->wire_parser = nullptr;
        if (duct_conn_bind_wire(conn, next, nullptr) != rc_ok) {
            duct_io_conn_close(conn, close_internal_error);
            return;
        }
    }
    s_conn_post_wire_fence(route, conn);
}
