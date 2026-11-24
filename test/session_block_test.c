/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file session_block_test.c
 * @brief The session pool carved over @c duct_block_pool: page-0 identity,
 *  the streams region's carve, the retry regions' geometry, and the touched
 *  watermark's stream source.
 *
 * No engine, no io thread: the pool's own constructor has already run in
 * every binary that links the library. Each section leaves the pool with
 * every block released, so the sections compose in any order.
 */

/* AI-generated test code. */

#include "duct_session.h"
#include "duct_session_block.h"
#include "../src/pool/duct_block_pool.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void s_fail(const char *what)
{
    fprintf(stderr, "session_block: %s\n", what);
    exit(1);
}

static void s_expect(bool ok, const char *what)
{
    if (!ok)
        s_fail(what);
}

static duct_result_t s_ignore_frame([[maybe_unused]] duct_session_t *s,
                                    [[maybe_unused]] duct_conn_id_t conn_id,
                                    [[maybe_unused]] const duct_frame_t *frame,
                                    [[maybe_unused]] duct_response_t *out,
                                    [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

static duct_proto_t *s_mux_proto(void)
{
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "session-block", .wire = wire, .on_frame = s_ignore_frame,
        .flags = fl_proto_multiplexed,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    return proto;
}

static void t_page0_shape(void)
{
    /* The anchor pins the run word: a release completing a whole
     * sixty-four-block word claims it for the batch drop, and the freed slot
     * only returns with that drop's sweep — warm lowest-first reuse is
     * observable solely inside a word another session still holds. */
    auto anchor = duct_session_acquire(3u);
    s_expect(anchor != nullptr, "anchor acquire refused the pool");
    auto s = duct_session_acquire(3u);
    s_expect(s != nullptr, "acquire refused an empty pool");
    s_expect(s->worker_id == 3u, "acquire did not store the worker id");
    s_expect(duct_session_block_at(duct_session_idx_get(s)) == s,
             "block_at disagrees with the acquired slot");
    s_expect((uintptr_t)duct_session_counters(s) == (uintptr_t)s + session_off_counters,
             "counters off their page-0 offset");
    s_expect((uintptr_t)duct_session_timer_keys(s) == (uintptr_t)s + session_off_timer_keys,
             "timer keys off their page-0 offset");
    s_expect((uintptr_t)duct_session_timer_hold(s) == (uintptr_t)s + session_off_timer_hold,
             "timer hold off its page-0 offset");
    s_expect((uintptr_t)duct_session_retry_maps(s) == (uintptr_t)s + session_off_retry_maps,
             "retry maps off their page-0 offset");
    s_expect((uintptr_t)duct_session_stats(s) == (uintptr_t)s + session_off_stats,
             "stats off their page-0 offset");
    s_expect((uintptr_t)duct_session_defer_maps(s) == (uintptr_t)s + session_off_defer_maps,
             "defer maps off their page-0 offset");
    s_expect((uintptr_t)duct_session_defer_region(s) == (uintptr_t)s + session_off_defer,
             "defer region off its page-0 offset");
    s_expect(session_off_defer + duct_session_defer_bytes <= duct_session_page0(),
             "the defer region overruns the runtime page 0");
    uint32_t page0 = duct_session_page0();
    s_expect(page0 >= session_off_defer + duct_session_defer_bytes,
             "page 0 starts ahead of the fixed tail");
    s_expect(page0 % duct_page_size() == 0u, "page 0 does not align to the page size");
    memset(duct_session_counters(s), 0xa5,
           duct_session_max_legs * sizeof(duct_conn_counters_t));
    memset(duct_session_timer_keys(s), 0x5a,
           session_timer_keys * sizeof(duct_session_timer_key_t));
    *duct_session_timer_hold(s) = (duct_tx_hold_t){ .leg = 1u, .ticket = 7u };
    duct_session_stats(s)->touched = 999u;
    auto dmaps = duct_session_defer_maps(s);
    for (size_t w = 0u; w < sizeof dmaps->units / sizeof dmaps->units[0]; ++w)
        dmaps->units[w] = ~0ull;
    duct_session_release(s);

    auto again = duct_session_acquire(3u);
    s_expect(again != nullptr, "re-acquire refused the pool");
    s_expect(again == s, "the released block was not reused lowest-first");
    auto counts = duct_session_counters(again);
    for (unsigned leg = 0u; leg < duct_session_max_legs; ++leg)
        for (size_t w = 0u; w < sizeof(duct_conn_counters_t) / sizeof(uint64_t); ++w)
            s_expect(((const uint64_t *)&counts[leg])[w] == 0u,
                     "a recycled block kept a stale counter");
    auto tk = duct_session_timer_keys(again);
    for (unsigned i = 0u; i < session_timer_keys; ++i)
        s_expect(tk[i].key == 0u && tk[i].timer == 0u,
                 "a recycled block kept a keyed-timer slot");
    s_expect(duct_session_timer_hold(again)->leg == 0u
             && duct_session_timer_hold(again)->ticket == 0u,
             "a recycled block kept a stale timer hold");
    s_expect(duct_session_stats(again)->touched == 0u,
             "a recycled block kept its touched high-water");
    auto again_dmaps = duct_session_defer_maps(again);
    for (size_t w = 0u; w < sizeof again_dmaps->units / sizeof again_dmaps->units[0]; ++w)
        s_expect(again_dmaps->units[w] == 0u,
                 "a recycled session's defer map kept a stale claim");
    duct_session_release(again);
    duct_session_release(anchor);
}

static void t_page0_aba(void)
{
    /* The anchor pins the run word incomplete: a release completing a whole
     * sixty-four claims it for the batch drop, and the freed slot only
     * returns with that drop's sweep. Warm lowest-first reuse is observable
     * solely inside a word another session still holds. */
    auto anchor = duct_session_acquire(0u);
    s_expect(anchor != nullptr, "anchor acquire refused the pool");
    auto s = duct_session_acquire(0u);
    s_expect(s != nullptr, "acquire refused the pool");
    uint32_t idx = duct_session_idx_get(s);
    s_expect(idx == duct_session_idx_get(anchor) + 1u, "acquire skipped the anchor's neighbor");
    duct_session_handle_t tok = duct_session_handle_from_live(s);
    duct_session_release(s);
    s_expect(!duct_session_block_live(idx), "a released block still resolves as live");
    s_expect(duct_session_by_handle(tok) == nullptr, "a stale token resolved after release");

    auto again = duct_session_acquire(0u);
    s_expect(again != nullptr, "re-acquire refused the pool");
    s_expect(again == s, "the freed block was not reused lowest-first");
    s_expect(duct_session_idx_get(again) == idx, "the recycled block changed slots");
    duct_session_handle_t tok2 = duct_session_handle_from_live(again);
    s_expect(tok2.gen != tok.gen, "the recycle did not advance the generation");
    s_expect(duct_session_by_handle(tok) == nullptr, "the pre-recycle token still resolves");
    s_expect(duct_session_by_handle(tok2) == again, "the post-recycle token does not resolve");
    duct_session_release(again);
    duct_session_release(anchor);
}

static void t_streams_region(void)
{
    auto proto = s_mux_proto();
    s_expect(proto != nullptr, "proto create failed");
    auto s = duct_session_acquire(0u);
    s_expect(s != nullptr, "acquire refused the pool");
    s_expect(!duct_has(s->flags, fl_session_multiplexed),
             "a fresh session claims a live streams region");
    uint8_t *streams = (uint8_t *)duct_session_streams(s);
    s_expect(streams == (uint8_t *)s + duct_session_page0(),
             "the streams table does not sit at page 0's end");
    s_expect((uint8_t *)duct_session_stream_buckets(s) == streams + session_streams_span,
             "buckets off their region offset");
    s_expect((uint8_t *)duct_session_stream_ctx_table(s)
                 == streams + session_streams_span + session_buckets_span,
             "ctx table off its region offset");

    duct_session_streams_alloc(s);
    s->proto = proto;
    s_expect(duct_has(s->flags, fl_session_multiplexed),
             "region init did not raise the multiplexed flag");
    s_expect(s->stream_free_head == &duct_session_streams(s)[0u].hh,
             "the free list does not start at slot 0");

    duct_response_t out = {};
    auto slot = duct_session_stream_claim(s, 1u, &out, nullptr);
    s_expect(slot == &duct_session_streams(s)[0u], "the first claim did not take slot 0");
    s_expect(duct_session_stream_ctx_slot(s, slot) == duct_session_stream_ctx_table(s),
             "slot 0's handler ctx is not ctx 0");
    for (uint32_t i = 1u; i < duct_session_max_streams; ++i)
        s_expect(duct_session_stream_claim(s, (duct_stream_id_t)(i + 1u), &out, nullptr) != nullptr,
                 "a claim refused the carved table");
    size_t want = (duct_session_page0() + session_streams_span + session_buckets_span
                   + (size_t)duct_session_max_streams * sizeof(duct_stream_ctx_t))
                  / duct_page_size();
    s_expect(duct_session_stats(s)->touched == want,
             "touched disagrees with the highest claimed stream slot");
    s_expect(s->stream_free_head == nullptr, "a full table still offers a free slot");

    /* The state merge end to end: closing fires no callbacks here (proto has
     * none), the token stops resolving in dead, the grace holds two ticks,
     * and the third frees the block. */
    duct_session_handle_t tok = duct_session_handle_from_live(s);
    duct_session_request_close(s, close_normal);
    s_expect(duct_session_by_handle(tok) == nullptr, "a dead session's token resolved");
    s_expect(!duct_session_dead_tick(s) && !duct_session_dead_tick(s),
             "the grace did not hold its two ticks");
    s_expect(duct_session_dead_tick(s), "the grace never expired");
    duct_proto_destroy(proto);
}

static void t_retry_regions(void)
{
    auto anchor = duct_session_acquire(0u);
    s_expect(anchor != nullptr, "anchor acquire refused the pool");
    auto s = duct_session_acquire(0u);
    s_expect(s != nullptr, "acquire refused the pool");
    auto maps = duct_session_retry_maps(s);
    s_expect((uintptr_t)maps == (uintptr_t)s + session_off_retry_maps,
             "the retry maps are not at their fixed page-0 offset");
    for (size_t w = 0u; w < sizeof maps->emit / sizeof maps->emit[0]; ++w)
        s_expect(maps->emit[w] == 0u, "a fresh session's emit map was not all-free");
    for (size_t w = 0u; w < sizeof maps->timer / sizeof maps->timer[0]; ++w)
        s_expect(maps->timer[w] == 0u, "a fresh session's timer map was not all-free");
    uint8_t *emit0 = duct_session_retry_emit_slot(s, 0u);
    uint8_t *timer0 = duct_session_retry_timer_slot(s, 0u);
    s_expect(emit0 == (uint8_t *)s + duct_session_page0() + session_streams_region,
             "emit slots off their region offset");
    s_expect(timer0 == emit0 + session_emit_region, "timer slots off their region offset");
    s_expect(timer0 + session_timer_region <= (uint8_t *)s + session_block_size,
             "the retry regions overrun the block");

    maps->emit[0] = 1u;
    maps->timer[0] = 1u;
    duct_session_release(s);
    auto again = duct_session_acquire(0u);
    s_expect(again != nullptr, "re-acquire refused the pool");
    s_expect(again == s, "the recycled block moved under the pool's lowest-first rule");
    auto again_maps = duct_session_retry_maps(again);
    for (size_t w = 0u; w < sizeof again_maps->emit / sizeof again_maps->emit[0]; ++w)
        s_expect(again_maps->emit[w] == 0u,
                 "a recycled session's emit map kept a stale claim");
    for (size_t w = 0u; w < sizeof again_maps->timer / sizeof again_maps->timer[0]; ++w)
        s_expect(again_maps->timer[w] == 0u,
                 "a recycled session's timer map kept a stale claim");
    duct_session_release(again);
    duct_session_release(anchor);
}

static void t_churn_watermark(void)
{
    constexpr uint32_t churn_n = 16u;
    s_expect(duct_max_conns >= churn_n + 2u, "preset too small for the churn set");
    auto proto = s_mux_proto();
    s_expect(proto != nullptr, "proto create failed");
    duct_response_t out = {};
    duct_session_t *sessions[churn_n];
    duct_session_handle_t toks[churn_n];
    uint32_t idxs[churn_n];
    for (uint32_t i = 0u; i < churn_n; ++i) {
        auto s = duct_session_acquire(0u);
        s_expect(s != nullptr, "churn acquire refused");
        duct_session_streams_alloc(s);
        s->proto = proto;
        for (uint32_t k = 0u; k < duct_session_max_streams; ++k)
            s_expect(duct_session_stream_claim(s, (duct_stream_id_t)(k + 1u), &out, nullptr)
                     != nullptr, "churn claim refused");
        sessions[i] = s;
        toks[i] = duct_session_handle_from_live(s);
        idxs[i] = duct_session_idx_get(s);
    }
    size_t per = (duct_session_page0() + session_streams_span + session_buckets_span
                  + (size_t)duct_session_max_streams * sizeof(duct_stream_ctx_t))
                 / duct_page_size();
    auto pool = (duct_block_pool_t *)duct_session_pool_blocks();
    uint64_t dirty0 = duct_atomic_load(&pool->dirty_bytes, relaxed);
    for (uint32_t i = 0u; i < churn_n; ++i)
        duct_session_release(sessions[i]);
    uint64_t dirty = duct_atomic_load(&pool->dirty_bytes, relaxed);
    s_expect(dirty - dirty0 == (uint64_t)churn_n * per * duct_page_size(),
             "the churn did not land in the dirty sum");
    s_expect(dirty > pool->floor, "the churn stayed under the watermark floor");

    duct_sweep_cursor_t cur = {};
    for (unsigned rounds = 0u; duct_block_pool_sweep_step(pool, &cur, 4u); ++rounds)
        s_expect(rounds < 1000u, "the watermark sweep never drained");
    dirty = duct_atomic_load(&pool->dirty_bytes, relaxed);
    s_expect(dirty <= pool->floor, "the sweep left dirty above the floor");

    uint32_t dropped = 0u;
    for (uint32_t i = 0u; i < churn_n; ++i) {
        s_expect(duct_session_by_handle(toks[i]) == nullptr,
                 "a stale token resolved into a dropped tail");
        auto meta = &duct_at(pool->meta)[idxs[i]];
        dropped += duct_atomic_load(&meta->state, relaxed) == blk_discarded;
        if (duct_atomic_load(&meta->state, relaxed) == blk_discarded)
            s_expect(duct_atomic_load(&duct_session_block_at(idxs[i])->generation, relaxed) != 0u,
                     "page 0 did not survive the tail drop with its generation");
    }
    s_expect(dropped > 0u, "the watermark dropped no tails");

    auto revived = duct_session_acquire(0u);
    s_expect(revived != nullptr, "re-acquire after the sweep refused the pool");
    duct_session_release(revived);
    duct_proto_destroy(proto);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    t_page0_shape();
    t_page0_aba();
    t_streams_region();
    t_retry_regions();
    t_churn_watermark();

    printf("session_block: OK (page-0 offsets and acquire reset, handle ABA over the "
           "generation word, the carved streams region with its touched source, the "
           "session-owned retry regions' geometry and reset maps, churn dropping "
           "tails past page 0)\n");
    return 0;
}
