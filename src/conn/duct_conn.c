/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_conn.c
 *  @brief Conn setup / teardown, pool lifecycle.
 */

#include "duct.h"
#include "duct_bits.h"
#include "duct_conn.h"
#include "duct_core.h"
#include "duct_dgram_rec.h"
#include "duct_io.h"
#include "duct_olb_rx.h"
#include "duct_wfq_msg.h"
#include "duct_olb_tx.h"
#include "duct_protocol.h"
#include "duct_relay.h"
#include "duct_ticks.h"
#include "duct_treiber.h"
#include "duct_vnet.h"
#include "duct_wire.h"
#include "duct_wire_codec.h"
#include "duct_xport.h"

#include <string.h>
#include <unistd.h>

/** @brief Fixed-layout connection pool.
 *
 *  A Treiber free-list over a fixed-size conn slab, every slot is either
 *  free (on the stack) or in-use (acquired, referenced by pointer).
 *  A slot returns to free only via @ref duct_conn_release, called once the
 *  close-fence, @ref duct_conn_fence_retire, has already proved no worker
 *  or io reference remains — release is therefore immediate.
 *
 *  Live conns are @c conns[] with @c generation != 0.
 */
typedef struct duct_conn_pool {
    uint64_t _Atomic free_head; /**< Treiber stack head word for free conns. 
                                  *  Higher 32 bits for version,
                                  *  lower for idx; @ref treiber_empty if empty. */
    unsigned _Atomic free_n;    /**< Free slots, as @c duct_conns_free reads them.
                                  *  Raised ahead of a push and lowered after a
                                  *  pop, so it never wraps below zero and runs
                                  *  ahead of the stack by the pushes in flight. */
    uint64_t _Atomic refused,   /**< Acquires refused for an empty stack, as
                                  *  @c duct_conns_refused reads them. */
                     said_at;   /**< Monotonic nanoseconds of the last
                                  *  exhaustion line @c s_pool_refused logged. */

    size_t size;                /**< Backing allocation size. */

    /** @brief Per-io-thread live-conn list heads @c duct_conn_t::io_next/io_prev. */
    duct_conn_t *io_head[duct_runtime_max_io_threads];

    /** @brief Resident array of packed gen + req_flags + close_reason words.
     *  See @ref duct_gen_req_pack for the layout.
     *  Indexed 1:1 with conns[]; resolved via @ref duct_conn_gen_req.
     */
    uint64_t _Atomic gen_req[duct_max_conns];

    /** @brief Resident array of embedded req wake messages, one per slot.
     *  Indexed 1:1 with conns[]; resolved via @ref duct_conn_req_msg.
     *  @c exec_fn and the embedded kind set once for the whole array at pool construction.
     */
    duct_msg_conn_req req_msg[duct_max_conns];

    /** @brief Resident array of conn slots. */
    duct_cacheline_struct(duct_conn_t conns[duct_max_conns]);
} duct_conn_pool_t;

/** @name Pop/push/seed over @c conns[]::next_free.
 *  @{
 */
DUCT_TREIBER_DECLARE(s_conn_stack, duct_conn_t, next_free)
/** @} */

static duct_conn_pool_t *s_pool;

static void duct_conn_pool_ctor(void) __attribute__((constructor(DUCT_CTOR_PRI_STATE)));
static void duct_conn_pool_ctor(void)
{
    duct_vm_handle_t vm = duct_vm_new(sizeof(duct_conn_pool_t));
    duct_fatal(!vm.base || !vm.size);
    s_pool = (duct_conn_pool_t *)vm.base;
    s_pool->size = vm.size;
    /* Seed free with all conn slots; push in reverse so pop yields idx 0 first. */
    s_conn_stack_seed(&s_pool->free_head, s_pool->conns, duct_max_conns);
    duct_atomic_store(&s_pool->free_n, duct_max_conns, relaxed);
    auto req_exec = duct_io_conn_req_exec_fn();
    for (unsigned i = 0u; i < duct_max_conns; ++i)
        s_pool->req_msg[i].msg = duct_msg_init_embedded(req_exec);
}

#ifndef DUCT_BITMAP_WORDS
#define DUCT_BITMAP_WORDS ((duct_max_conns + 63u) / 64u)
#endif

void duct_conn_pool_reclaim(void)
{
    /* generation != 0 can't tell live from already-free — generation never
     * resets to 0 — snapshot free first, so the force pass below only touches
     slots no path has released. */
    
    uint64_t on_free[DUCT_BITMAP_WORDS] = {},
             head = duct_atomic_load(&s_pool->free_head, relaxed);
    for (uint32_t cur = treiber_head_idx(head);
        cur != treiber_empty && !duct_bits_test_plain(on_free, cur);
        cur = duct_atomic_load(&s_pool->conns[cur].next_free, relaxed))
    {
        duct_bits_set_plain(on_free, cur);
    }

    for (unsigned i = 0u; i < duct_max_conns; ++i) {
        if (duct_bits_test_plain(on_free, i))
            continue;
        auto conn = &s_pool->conns[i];
        if (duct_gen_req_gen(duct_atomic_load(&s_pool->gen_req[i], relaxed)) != 0u) {
            /* Mirrors io's s_conn_shutdown, except
             * for poll/io-list and the retry-node discard. */
            duct_atomic_fetch(and, &s_pool->gen_req[i], ~(uint64_t)gen_req_flags_mask, relaxed);
            duct_conn_reclaim(conn);
        }
    }
}

static void duct_conn_pool_dtor(void) __attribute__((destructor(DUCT_CTOR_PRI_STATE)));
static void duct_conn_pool_dtor(void)
{
    duct_conn_pool_reclaim();
    duct_vm_del(&(duct_vm_handle_t){ .base = s_pool, .size = s_pool->size });
    s_pool = nullptr;
}

uint32_t duct_conn_idx_get(const duct_conn_t *conn)
{
    return (uint32_t)(conn - s_pool->conns);
}

duct_conn_t *duct_conn_by_idx(unsigned idx)
{
    return &s_pool->conns[idx];
}

uint64_t _Atomic *duct_conn_gen_req(const duct_conn_t *conn)
{
    return &s_pool->gen_req[duct_conn_idx_get(conn)];
}

duct_msg_conn_req *duct_conn_req_msg(const duct_conn_t *conn)
{
    return &s_pool->req_msg[duct_conn_idx_get(conn)];
}

void duct_conn_io_list_link(duct_conn_t *conn, unsigned io_id)
{
    assert(io_id < duct_runtime_max_io_threads);
    /* Host-driven x_inter conns stay out: no fd, never registered via
     * s_conn_register. A device-backed one carries its duct_device_ops_t copy
     * in ctx and holds a watched wait handle, so it belongs here — this list
     * is how duct_io_cleanup reaches it at engine teardown. */
    if (conn->xport_type == x_inter && !conn->ctx)
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
    /* Host-driven x_inter was never linked, and duct_conn_acquire doesn't reset
     * io_next/io_prev on a fresh slot — unlinking anyway splices garbage
     * pointers into the live list. */
    if (conn->xport_type == x_inter && !conn->ctx)
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
    auto conn = &s_pool->conns[handle.idx];
    uint64_t gen = duct_gen_req_gen(duct_atomic_load(&s_pool->gen_req[handle.idx], acquire));
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

duct_conn_t *duct_conn_acquire(void)
{
    uint32_t top = s_conn_stack_pop(&s_pool->free_head, s_pool->conns);
    if (top == treiber_empty) {
        s_pool_refused();
        return nullptr; /* no free slots */
    }
    duct_atomic_fetch(sub, &s_pool->free_n, 1u, relaxed);
    auto conn = &s_pool->conns[top];
    bool advanced = s_gen_advance(conn);
    duct_do_if(!advanced, return nullptr); /* per-conn gen overflow */
    duct_atomic_store(&conn->state, 0, relaxed);
    /* Resetting the fields below after the generation bump is safe only
     * because a fresh generation is not itself a publication channel: no
     * thread resolves this conn by handle until a later message hands the
     * handle out with its own release/acquire edge. Do not reorder.
     * duct_conn_reclaim always tears down before release — both lane words
     * and ctx are freed and nulled there and are not live for the next
     * occupant.
     */
    assert(!conn->inter_lane);
    assert(!conn->ctx);
    conn->fd = duct_sock_bad;
    conn->rx_buf = nullptr;
    conn->tx_buf = nullptr;
    conn->wire = nullptr;
    conn->wire_parser = nullptr;
    conn->vnet_hdr_len = 0u;
    duct_atomic_store(&conn->vnet_gso, 0u, relaxed);
    /* head_unsealed survives teardown — duct_conn_sealed_codec_detach clears
     * the codec alone — so this reset stops a recycled slot from skipping
     * its first unseal. */
    conn->seal = (duct_sealed_conn_ctx_t){};
    duct_atomic_store(&conn->wire_rebind_next, nullptr, relaxed);
    conn->session_token = handle_null;
    duct_atomic_store(&conn->conn_fence, fence_unbound, relaxed);
    conn->io_id = conn_io_none;
    conn->worker_id = conn_worker_none;
    /* Shutdown reclaims a bound conn with no unbind, and its slot returns bound. */
    duct_atomic_store(&conn->bound_worker, 0u, relaxed);
    return conn;
}

static void s_conn_free_push(duct_conn_t *conn)
{
    uint32_t idx = duct_conn_idx_get(conn);
    duct_conn_state_clear(conn, fl_conn_in_wfq);
    duct_atomic_fetch(add, &s_pool->free_n, 1u, relaxed);
    s_conn_stack_push(&s_pool->free_head, s_pool->conns, idx);
}

void duct_conn_release(duct_conn_t *conn)
{
    /* Same exclusivity as duct_conn_acquire: by now this generation's
     * handle is unreachable — it was never handed out (io's s_conn_new
     * setup-failure path). duct_conn_reclaim advances slot generation
     * ahead of teardown. */
    bool advanced = s_gen_advance(conn);
    duct_do_if(!advanced, return); /* per-conn gen overflow, slot retired for good */
    s_conn_free_push(conn);
}

void duct_conn_reclaim(duct_conn_t *conn)
{
    /* The bump and the test for a posted request are one CAS: a post landing
     * first holds the reclaim for its node's run, and one landing after finds
     * a generation nothing matches. The bump is guarded because generation
     * shares that word, where an add at the ceiling wraps it to 0. The test
     * asks for two bumps: the next acquire needs its own, and without it that
     * acquire fails having already popped the slot, leaking it. */
    auto gen_slot = duct_conn_gen_req(conn);
    uint64_t old_word = duct_atomic_load(gen_slot, relaxed),
             g = 0u;
    for (;;) {
        if (duct_gen_req_flags(old_word)) {
            duct_conn_state_set(conn, fl_conn_reclaim_held);
            return;
        }
        g = duct_gen_req_gen(old_word);
        if (!s_gen_ceiling_ok(g, 1u)
            || duct_atomic_cas(weak, gen_slot, &old_word,
                               old_word + (1ull << gen_req_gen_shift), release, relaxed))
            break;
    }
    bool retiring = !s_gen_ceiling_ok(g, 2u);

    /* host_pins counts an unregistered reader — duct_io_inter_batch,
     * called from a host thread the close-fence protocol never sees
     * (it only tracks worker/io references). The bump above already
     * shut the door on new pins, so a nonzero count here is just one
     * already in flight, about to finish. Spin here so duct_vmq_mpsc_del
     * below can't race a still-running push. The fence matters because
     * acquire/release alone won't pair this spin-load with the other
     * thread's own pin-then-recheck on a weak-ordered CPU. */
    atomic_thread_fence(memory_order_seq_cst);
    for( ; duct_atomic_load(&conn->host_pins, relaxed); duct_cpu_relax()){}
    duct_conn_teardown(conn);
    if (!retiring)
        s_conn_free_push(conn);
}

duct_result_t duct_conn_setup(duct_conn_t *conn, duct_sock_t fd, duct_xport_t xport,
                              size_t tx_cap)
{
    duct_do_if(fd == duct_sock_bad, return rc_invalid_arg);
    /* Both union words directly: xport_type is assigned further down, so the
     * arm accessors have no answer to give yet. */
    duct_do_if(conn->rx_buf || conn->tx_buf, return rc_invalid_order);
    /* A coalescing datagram socket answers one whole group per read, and its
     * reserve demands room for the worst case plus the backend's per-read
     * scratch; a vnet tun leg's reserve demands a whole cut. That room rides on
     * top of the working area: taken out of the same bytes, the last read's
     * worth of stage never satisfies a reserve and the read loop stalls on a
     * compaction the worker is never caught up enough to allow. Sized from the
     * build's own ceiling: coalescing is asked for at wire bind, past this
     * allocation, and a buffer cannot grow afterwards. */
    size_t vnet = xport == x_raw_packet ? duct_x_vnet_hdr_len(fd) : 0u;
    duct_do_if(vnet > duct_vnet_hdr_max, return rc_not_supported);
    size_t rx_cap = duct_conn_rx_olb_cap
                  + (xport == x_udp_peer
                         ? sizeof(duct_dgram_rec_hdr_t) + duct_x_gro_max + duct_events_rx_scratch
                         : 0u)
                  + (vnet ? duct_vnet_cut_max : 0u);
    auto rx = duct_olb_rx_new(rx_cap);
    duct_do_if(!rx, return rc_no_memory);
    auto tx = duct_olb_tx_new(tx_cap);
    duct_do_if(!tx, duct_olb_del(&rx->h); return rc_no_memory);
    conn->fd = fd;
    conn->xport_type = xport;
    conn->vnet_hdr_len = (uint8_t)vnet;
    conn->rx_buf = rx;
    conn->tx_buf = tx;
    conn->ctx = nullptr;
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
        codec->destroy(codec);
    }
}

void duct_conn_inter_slot_release(duct_vmq_hdr_t *hdr, [[maybe_unused]] void *arg)
{
    duct_do_if(hdr->type != inter_msg_batch, return);
    auto b = (const duct_msg_inter_batch_t *)hdr->payload;
    if (b->rx_pool)
        duct_io_rx_slot_drop(b->rx_pool, b->rx_slot, false);
}

void duct_conn_teardown(duct_conn_t *conn)
{
    if (conn->wire && conn->wire_parser) {
        duct_wire_parser_destroy(conn->wire, conn->wire_parser);
        conn->wire_parser = nullptr;
    }
    conn->wire = nullptr;
    duct_conn_sealed_codec_detach(conn);
    /* One arm resolves, never both: each null below writes a union word the
     * opposite arm spans too. */
    auto lane = duct_conn_lane(conn);
    if (lane) {
        duct_discard duct_vmq_mpsc_drain(lane, duct_conn_inter_slot_release, nullptr);
        duct_vmq_mpsc_del(lane);
        conn->inter_lane = nullptr;
    }
    auto rx = duct_conn_rx_olb(conn);
    if (rx) {
        duct_olb_del(&rx->h);
        conn->rx_buf = nullptr;
    }
    auto tx = duct_conn_tx_olb(conn);
    if (tx) {
        duct_olb_del(&tx->h);
        conn->tx_buf = nullptr;
    }
    /* This function is the actual choke point every teardown path
     * funnels through: duct_conn_reclaim: both the fence-driven retire
     * and s_conn_close's direct fence_unbound branch.
     * Runs before the ctx free below, while conn->ctx still points
     * at what the xport put there. */
    /* ctx tested: s_dgram_shared_conn_new reaches reclaim twice before
     * allocating it, and takes the listener ref later still, so those paths
     * arrive here with nothing to release. A standing pin is taken back ahead
     * of the ref. */
    if (conn->ctx)
        switch (conn->xport_type) {
        case x_udp_shared: {
            auto dctx = (duct_dgram_shared_ctx_t *)conn->ctx;
            if (dctx->rx_pin)
                duct_io_rx_unpin(dctx->rx_pin);
            duct_listener_release_pre_conn_ref(dctx->listener);
            break;
        }
        /* Lane before release: past ops.release the device belongs to the
         * application again and may be closed, so nothing of ours may still
         * reference it. */
        case x_inter: {
            auto ops = (duct_device_ops_t *)conn->ctx;
            duct_io_device_teardown(conn);
            if (ops->release)
                ops->release(ops->ctx);
            break;
        }
        /* The ctx borrows the listener: drop clears it, so the free below
         * never reaches the listener. */
        case x_local:
            duct_local_listener_drop(conn);
            break;
        default:
            break;
        }
    if (conn->ctx) {
        duct_del(conn->ctx);
        conn->ctx = nullptr;
    }
    if (conn->fd != duct_sock_bad) {
        duct_sock_close(conn->fd);
        conn->fd = duct_sock_bad;
        /* The descriptor just freed may be the one a parked listener waits for. */
        duct_io_accept_resume();
    }
    /* ::session_token and ::conn_fence retained — conn-lost consume
     * reads them before the fence confirms retire-ready.
     * ::generation and ::owner_io are owned by pool. */
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
    auto parser = duct_wire_parser_create(wire);
    duct_do_if(wire->create_parser && !parser, return rc_no_memory);
    conn->wire = wire;
    conn->wire_parser = parser;
    size_t budget = conn->wire->max_frame;
    /* Coalescing is asked for only once the wire is known to be one whose
     * whole per-datagram header is the record prefix: a group reaches the
     * parse described by its segment size, and nothing else describes it. */
    size_t coalesced = 0u;
    if (conn->xport_type == x_udp_peer && duct_wire_records(wire))
        coalesced = duct_xset_dgram_gro(conn->fd, duct_x_gro_max);
    auto rx = duct_conn_rx_olb(conn);
    if (rx)
        /* One argument fixes both the span a reserve demands and the threshold
         * that has to clear it: the threshold is sized to the kernel response
         * for coalescing options or falls back to single-frame bounds. */
        duct_olb_rx_threshold_set(rx,
            (duct_conn_record_framed(conn) ? sizeof(duct_dgram_rec_hdr_t) : 0u)
                + duct_max(budget, coalesced));
    auto tx = duct_conn_tx_olb(conn);
    if (tx) {
        size_t resp = cfg->max_response ? cfg->max_response : budget;
        if (conn->wire->tx_bound)
            resp = conn->wire->tx_bound(conn->wire, resp);
        duct_olb_tx_min_room_set(tx, resp);
    }
    return rc_ok;
}
