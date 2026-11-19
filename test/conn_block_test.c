/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file conn_block_test.c
 * @brief The conn pool carved over @c duct_block_pool: page-0 identity,
 *  the union tail's life, and the touched watermark's arithmetic.
 *
 * No engine, no io thread: the pool's own constructor has already run in
 * every binary that links the library. Each section leaves the pool with
 * every block released, so the sections compose in any order.
 */

/* AI-generated test code. */

#define _GNU_SOURCE

#include "duct_conn_block.h"
#include "duct_vmq.h"
#include "../src/pool/duct_block_pool.h"

#include "duct_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void s_fail(const char *what)
{
    fprintf(stderr, "conn_block: %s\n", what);
    exit(1);
}

static void s_expect(bool ok, const char *what)
{
    if (!ok)
        s_fail(what);
}

static duct_blk_meta_t *s_meta(void)
{
    return duct_at(duct_conn_pool_blocks()->meta);
}

static void s_stage_rx(duct_olb_rx_t *rx, size_t len)
{
    char chunk[4096];
    memset(chunk, 'r', sizeof chunk);
    s_expect(len <= rx->h.buf_size - duct_atomic_load(&rx->h.stage, relaxed),
             "rx stage overflows the carved cap");
    for (size_t left = len; left;) {
        size_t take = left < sizeof chunk ? left : sizeof chunk;
        duct_olb_rx_append_raw(rx, chunk, take);
        left -= take;
    }
}

static void t_carve_shapes(void)
{
    auto conn = duct_conn_acquire();
    s_expect(conn != nullptr, "acquire refused an empty pool");
    conn->xport_type = x_tcp;
    duct_conn_carve_olb(conn, duct_conn_rx_olb_cap, duct_conn_tx_olb_cap);
    uint8_t *base = (uint8_t *)conn;
    auto rx = duct_conn_rx_olb(conn);
    auto tx = duct_conn_tx_olb(conn);
    s_expect((uint8_t *)rx == base + conn_off_rx, "rx header off its page-0 offset");
    s_expect((uint8_t *)tx == base + conn_off_tx, "tx header off its page-0 offset");
    s_expect(duct_conn_rx_data(conn) == base + duct_conn_page0(),
             "rx data off the page-0 boundary");
    s_expect(duct_conn_tx_data(conn) == base + duct_conn_page0() + conn_rx_region_max,
             "tx data off the rx region ceiling");
    s_expect((uint8_t *)duct_conn_wire_parser_slot(conn, 0u)
                 == base + duct_conn_page0() + conn_rx_region_max + conn_tx_region_max
             && (uint8_t *)duct_conn_wire_parser_slot(conn, 1u)
                 == (uint8_t *)duct_conn_wire_parser_slot(conn, 0u) + duct_wire_parser_slot
             && (uint8_t *)duct_conn_codec_slot(conn)
                 == (uint8_t *)duct_conn_wire_parser_slot(conn, 1u) + duct_wire_parser_slot,
             "the wire slots sit past the tx region, parser pair then codec");
    s_expect(duct_olb_rx_data(rx) == duct_conn_rx_data(conn)
                 && duct_olb_tx_data(tx) == duct_conn_tx_data(conn),
             "an OLB header resolves its data off its own address");
    s_expect(rx->h.buf_size == duct_conn_rx_olb_cap && tx->h.buf_size == duct_conn_tx_olb_cap,
             "carved caps not stamped");
    s_expect(duct_conn_lane(conn) == nullptr, "an OLB conn resolved a lane");
    s_stage_rx(rx, duct_conn_rx_olb_cap);
    s_expect(duct_atomic_load(&rx->h.stage, relaxed) == duct_conn_rx_olb_cap,
             "the full rx ceiling is writable");
    memset(duct_conn_tx_data(conn), 't', duct_conn_tx_olb_cap);
    duct_conn_rx_staged(conn, duct_atomic_load(&rx->h.stage, relaxed));
    duct_conn_tx_staged(conn, duct_conn_tx_olb_cap);
    duct_conn_touched_update(conn);
    size_t want = (duct_conn_rx_olb_cap + duct_conn_tx_olb_cap) / duct_page_size();
    s_expect(duct_conn_stats(conn)->touched == want, "touched pages miscounted");

    auto lane_conn = duct_conn_acquire();
    s_expect(lane_conn != nullptr, "second acquire refused the pool");
    lane_conn->xport_type = x_inter;
    duct_conn_carve_lane(lane_conn);
    uint8_t *lbase = (uint8_t *)lane_conn;
    auto q = duct_conn_lane(lane_conn);
    s_expect((uint8_t *)q == lbase + conn_off_lane,
             "lane header off its page-0 offset");
    s_expect(duct_mpsc_cap(q, 0u) == duct_inter_lane_cap, "lane carve lost its capacity");
    s_expect((uint8_t *)duct_mpsc_ctrl(q, 0u) == (uint8_t *)q + conn_off_lane_ctrl - conn_off_lane,
             "lane ctrl off its page-0 offset");
    s_expect((uint8_t *)duct_mpsc_data(q, 0u)
                 == (uint8_t *)q + duct_conn_page0() - conn_off_lane,
             "lane data off the page-0 boundary");
    duct_conn_lane_staged(lane_conn, 8u);
    auto ln = duct_mpsc_lane(q, 0u);
    duct_vmq_reserve_pos_t pos = {};
    duct_vmq_push_rc_t rc = vmq_push_ok;
    auto payload = duct_vmq_reserve(&ln, 1u, 0u, 16u, &pos, &rc);
    s_expect(payload != nullptr, "a reserve refused the carved lane");
    memset(payload, 'l', 16u);
    duct_vmq_publish(&ln, &pos);
    duct_vmq_notify(ln.ctrl);
    s_expect(duct_mpsc_lane_unread(q, 0u) == duct_vmq_msg_overhead + 16u,
             "a published lane message is not unread");
    duct_conn_touched_update(lane_conn);
    s_expect(duct_conn_stats(lane_conn)->touched == 0u,
             "a lane below one page of traffic touched a page");
    duct_conn_release(lane_conn);
    duct_conn_release(conn);
}

static void t_page0_aba(void)
{
    /* The second conn pins the run word incomplete: a release completing a
     * whole sixty-four claims it for the batch drop, and the freed slot only
     * returns with that drop's sweep. Warm lowest-first reuse is observable
     * solely inside a word another conn still holds. */
    auto anchor = duct_conn_acquire();
    s_expect(anchor != nullptr, "anchor acquire refused the pool");
    auto conn = duct_conn_acquire();
    s_expect(conn != nullptr, "acquire refused the pool");
    uint32_t idx = duct_conn_idx_get(conn);
    s_expect(idx == duct_conn_idx_get(anchor) + 1u, "acquire skipped the anchor's neighbor");
    duct_conn_handle_t h = duct_conn_handle_get(conn);
    memset(duct_conn_dgram_ctx(conn), 0xa5, sizeof(duct_dgram_shared_ctx_t));
    duct_conn_release(conn);
    s_expect(!duct_conn_block_live(idx), "a released block still resolves as live");
    s_expect(duct_conn_by_handle(h) == nullptr, "a stale handle resolved after release");

    auto again = duct_conn_acquire();
    s_expect(again != nullptr, "re-acquire refused the pool");
    s_expect(again == conn, "the freed block was not reused lowest-first");
    s_expect(duct_conn_idx_get(again) == idx, "the recycled block changed slots");
    duct_conn_handle_t h2 = duct_conn_handle_get(again);
    s_expect(h2.gen != h.gen, "the recycle did not advance the generation");
    s_expect(duct_conn_by_handle(h) == nullptr, "the pre-recycle handle still resolves");
    s_expect(duct_conn_by_handle(h2) == again, "the post-recycle handle does not resolve");
    for (size_t i = 0u; i < sizeof(duct_dgram_shared_ctx_t); ++i)
        s_expect(((uint8_t *)duct_conn_dgram_ctx(again))[i] == 0u,
                 "the small ctx survived a recycle un-zeroed");
    duct_conn_release(again);
    duct_conn_release(anchor);
}

static void t_churn_watermark(void)
{
    constexpr uint32_t churn_n = 24u;
    s_expect(duct_max_conns >= churn_n, "preset too small for the churn set");
    duct_conn_handle_t handles[churn_n];
    uint32_t idxs[churn_n];
    for (uint32_t i = 0u; i < churn_n; ++i) {
        auto conn = duct_conn_acquire();
        s_expect(conn != nullptr, "churn acquire refused");
        conn->xport_type = x_tcp;
        duct_conn_carve_olb(conn, duct_conn_rx_olb_cap, duct_conn_tx_olb_cap);
        s_stage_rx(duct_conn_rx_olb(conn), duct_conn_rx_olb_cap);
        memset(duct_conn_tx_data(conn), 't', duct_conn_tx_olb_cap);
        duct_conn_rx_staged(conn, duct_conn_rx_olb_cap);
        duct_conn_tx_staged(conn, duct_conn_tx_olb_cap);
        handles[i] = duct_conn_handle_get(conn);
        idxs[i] = duct_conn_idx_get(conn);
    }
    size_t per = (duct_conn_rx_olb_cap + duct_conn_tx_olb_cap) / duct_page_size();
    auto pool = duct_conn_pool_blocks();
    uint64_t dirty0 = duct_atomic_load(&pool->dirty_bytes, relaxed);
    for (uint32_t i = 0u; i < churn_n; ++i) {
        auto conn = duct_conn_block_at(idxs[i]);
        duct_conn_release(conn);
    }
    size_t floor = pool->floor;
    uint64_t dirty = duct_atomic_load(&pool->dirty_bytes, relaxed);
    s_expect(dirty - dirty0 == (uint64_t)churn_n * per * duct_page_size(),
             "the churn did not land in the dirty sum");
    s_expect(dirty > floor, "the churn stayed under the watermark floor");

    for (unsigned rounds = 0u; duct_conn_pool_sweep(4u); ++rounds)
        s_expect(rounds < 1000u, "the watermark sweep never drained");
    dirty = duct_atomic_load(&pool->dirty_bytes, relaxed);
    s_expect(dirty <= floor, "the sweep left dirty above the floor");
    s_expect(dirty < dirty0 + (uint64_t)churn_n * per * duct_page_size(),
             "resident bytes did not fall after close-all");

    uint32_t dropped = 0u;
    for (uint32_t i = 0u; i < churn_n; ++i) {
        s_expect(duct_conn_by_handle(handles[i]) == nullptr,
                 "a stale handle resolved into a dropped tail");
        duct_blk_state_t state = duct_atomic_load(&s_meta()[idxs[i]].state, relaxed);
        dropped += state == blk_discarded;
        if (state == blk_discarded) {
            auto conn = (duct_conn_t *)((uint8_t *)pool->vm.base
                                        + (size_t)idxs[i] * conn_block_size);
            uint64_t gen = duct_gen_req_gen(
                duct_atomic_load(duct_conn_gen_req(conn), relaxed));
            s_expect(gen == (uint64_t)handles[i].gen + 1u,
                     "page 0 did not survive the tail drop with its generation");
        }
    }
    s_expect(dropped > 0u, "the watermark dropped no tails");

    auto revived = duct_conn_acquire();
    s_expect(revived != nullptr, "re-acquire after the sweep refused the pool");
    revived->xport_type = x_tcp;
    duct_conn_carve_olb(revived, duct_conn_rx_olb_cap, duct_conn_tx_olb_cap);
    s_stage_rx(duct_conn_rx_olb(revived), duct_conn_tx_olb_cap);
    s_expect(revived->fd == duct_sock_bad, "a recycled conn kept an fd");
    duct_conn_release(revived);
}

static void t_tx_retry_region(void)
{
    /* Geometry and acquire-reset of the TX retry region: the node and copy
     *  slots sit inside the block behind the batch retry node, the maps land
     *  in page 0's zeroed fixed part, and a recycled block starts all-free —
     *  the maps are the region's whole init. Hold every block so the one
     *  released is the one the next acquire hands back. */
    auto held = (duct_conn_t **)calloc(duct_max_conns, sizeof(duct_conn_t *));
    s_expect(held != nullptr, "region test scratch alloc failed");
    unsigned n_held = 0u;
    for (;;) {
        duct_conn_t *c = duct_conn_acquire();
        if (!c)
            break;
        held[n_held++] = c;
    }
    s_expect(n_held >= 2u, "the pool held fewer than two blocks");
    auto conn = held[n_held - 1u];
    auto maps = duct_conn_tx_retry_maps(conn);
    s_expect((uintptr_t)maps == (uintptr_t)conn + conn_off_retry_maps,
             "the TX retry maps are not at their fixed page-0 offset");
    for (size_t w = 0u; w < sizeof maps->nodes / sizeof maps->nodes[0]; ++w)
        s_expect(maps->nodes[w] == 0u, "a fresh conn's TX retry node map was not all-free");
    for (size_t w = 0u; w < sizeof maps->copies / sizeof maps->copies[0]; ++w)
        s_expect(maps->copies[w] == 0u, "a fresh conn's TX retry copy map was not all-free");
    auto nodes = duct_conn_tx_retry_node_slot(conn, 0u);
    auto last = duct_conn_tx_retry_node_slot(conn, duct_conn_retry_tx_nodes - 1u);
    auto copies = duct_conn_tx_retry_copy_slot(conn, 0u);
    auto copy_end = duct_conn_tx_retry_copy_slot(conn, duct_conn_retry_tx_copies - 1u)
                    + duct_conn_retry_tx_copy_max;
    s_expect((uintptr_t)nodes >= (uintptr_t)conn + duct_conn_page0(),
             "the TX retry node slots start inside page 0");
    s_expect((uintptr_t)copy_end - (uintptr_t)nodes == conn_retry_tx_region,
             "the TX retry region's span disagrees with its knobs");
    s_expect((uintptr_t)last + conn_retry_tx_node_span <= (uintptr_t)copies,
             "the last node slot runs into the copy slots");
    s_expect((uintptr_t)copy_end <= (uintptr_t)conn + conn_block_size,
             "the TX retry region overruns the block");
    /* Scribble the maps the way a conn's parked sends leave them, then let a
     * recycle zero them: a stale claim must never outlive its block. */
    maps->nodes[0] = 1u;
    maps->copies[0] = 1u;
    duct_conn_release(conn);
    auto again = duct_conn_acquire();
    s_expect(again != nullptr, "re-acquire refused the pool");
    s_expect(again == conn, "the recycled block moved under the pool's lowest-first rule");
    auto again_maps = duct_conn_tx_retry_maps(again);
    for (size_t w = 0u; w < sizeof again_maps->nodes / sizeof again_maps->nodes[0]; ++w)
        s_expect(again_maps->nodes[w] == 0u,
                 "a recycled conn's TX retry node map kept a stale claim");
    for (size_t w = 0u; w < sizeof again_maps->copies / sizeof again_maps->copies[0]; ++w)
        s_expect(again_maps->copies[w] == 0u,
                 "a recycled conn's TX retry copy map kept a stale claim");
    for (unsigned i = 0u; i < n_held; ++i)
        duct_conn_release(held[i]);
    free(held);
}

static void t_run_all_free(void)
{
    if (duct_max_conns < 2u * block_run_drop) {
        printf("conn_block: run-of-64 skipped, preset holds %u conns\n", duct_max_conns);
        return;
    }
    /* A release into an already-full word claims it for the batch drop, so
     * earlier sections can leave claims pending: drain them first, or the
     * acquires below start past the claimed words and the recorded indices
     * are not the ones a fixed-range walk would expect. */
    for (unsigned rounds = 0u; duct_conn_pool_sweep(64u); ++rounds)
        s_expect(rounds < 100u, "the pre-run drain never finished");
    duct_conn_t *conns[2u * block_run_drop];
    uint32_t idxs[2u * block_run_drop];
    for (unsigned i = 0u; i < 2u * block_run_drop; ++i) {
        conns[i] = duct_conn_acquire();
        s_expect(conns[i] != nullptr, "run acquire refused");
        idxs[i] = duct_conn_idx_get(conns[i]);
        conns[i]->xport_type = x_tcp;
        duct_conn_carve_olb(conns[i], duct_conn_rx_olb_cap, duct_conn_tx_olb_cap);
        s_stage_rx(duct_conn_rx_olb(conns[i]), duct_conn_rx_olb_cap);
        duct_conn_rx_staged(conns[i], duct_conn_rx_olb_cap);
    }
    uint32_t w0 = idxs[0] / block_run_drop, w1 = idxs[2u * block_run_drop - 1u] / block_run_drop;
    s_expect(idxs[2u * block_run_drop - 1u] - idxs[0u] == 2u * block_run_drop - 1u,
             "the run acquires were not two contiguous words");
    for (unsigned i = 0u; i < 2u * block_run_drop; ++i)
        duct_conn_release(conns[i]);

    auto pool = duct_conn_pool_blocks();
    for (unsigned rounds = 0u; duct_conn_pool_sweep(16u); ++rounds)
        s_expect(rounds < 1000u, "the run sweep never drained");
    s_expect(duct_atomic_load(&duct_at(pool->free_bits)[w0], relaxed) == UINT64_MAX
             && duct_atomic_load(&duct_at(pool->free_bits)[w1], relaxed) == UINT64_MAX,
             "a fully freed run did not return whole");
    s_expect(duct_atomic_load(&pool->dirty_bytes, relaxed) == 0u
             && duct_atomic_load(&pool->live_bytes, relaxed) == 0u,
             "the run drop left resident bytes counted");
    for (unsigned i = 0u; i < 2u * block_run_drop; ++i) {
        duct_blk_state_t state = duct_atomic_load(&s_meta()[idxs[i]].state, relaxed);
        s_expect(state == blk_discarded, "a run block was not discarded");
        s_expect(s_meta()[idxs[i]].touched == 0u, "a dropped run block kept its touched");
    }

    auto conn = duct_conn_acquire();
    s_expect(conn != nullptr, "acquire after the run drop refused the pool");
    conn->xport_type = x_tcp;
    duct_conn_carve_olb(conn, duct_conn_rx_olb_cap, duct_conn_tx_olb_cap);
    s_stage_rx(duct_conn_rx_olb(conn), duct_conn_tx_olb_cap);
    s_expect(duct_atomic_load(&s_meta()[duct_conn_idx_get(conn)].state, relaxed)
             == blk_active, "a discarded block did not reactivate");
    duct_conn_release(conn);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    t_carve_shapes();
    t_page0_aba();
    t_churn_watermark();
    t_tx_retry_region();
    t_run_all_free();

    printf("conn_block: OK (page-0 offsets and carve shapes, handle ABA over the "
           "generation word, watermark churn dropping tails past page 0, the TX "
           "retry region's geometry and acquire-reset maps, run-of-128 "
           "free returning whole)\n");
    return 0;
}
