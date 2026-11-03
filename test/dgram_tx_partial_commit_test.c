/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file dgram_tx_partial_commit_test.c
 * @brief Exercises the exact duct_vmq_drain_begin/_peek/duct_vmq_commit_head
 * sequence s_dgram_tx_outbox_drain (src/duct_io.c) uses to stop a lane at
 * the first EAGAIN-equivalent instead of the generic duct_vmq_drain's
 * commit-everything-visited contract.
 *
 * A fake send callback fails at a chosen index, standing in for
 * duct_xsend_dgram's EAGAIN return without depending on real socket
 * backpressure, which this session's own litmus testing found is not
 * reliably forceable on loopback UDP on either Linux or Windows.
 */

#include "duct_vmq.h"
#include "duct_wfq_msg.h"
#include "duct_core.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

static unsigned s_fail_at;   /* index (0-based) the fake send refuses; UINT_MAX = never */
static unsigned s_calls;

static bool s_fake_send(duct_vmq_hdr_t *hdr, [[maybe_unused]] void *arg)
{
    auto seq = *(const uint32_t *)hdr->payload;
    bool ok = seq != s_fail_at;
    ++s_calls;
    return ok;
}

/** @brief Same shape as s_dgram_tx_outbox_drain's own loop, one lane. */
static size_t s_drain_one_lane(const duct_vmq_lane_t *ln)
{
    auto pos = duct_vmq_drain_begin(ln);
    duct_vmq_hdr_t *hdr;
    size_t sent = 0u;
    while ((hdr = duct_vmq_drain_peek(ln, &pos)) != nullptr) {
        if (!s_fake_send(hdr, nullptr))
            break;
        pos.head += pos.step;
        ++sent;
    }
    if (sent)
        duct_vmq_commit_head(ln, pos.gen, pos.head);
    return sent;
}

static void s_push(const duct_vmq_lane_t *ln, uint32_t seq)
{
    duct_vmq_reserve_pos_t pos;
    duct_vmq_push_rc_t rc;
    auto payload = duct_vmq_reserve(ln, dgram_tx_msg, 0u, sizeof seq, &pos, &rc);
    assert(payload);
    *(uint32_t *)payload = seq;
    duct_vmq_publish(ln, &pos);
}

int main(void)
{
    static constexpr unsigned n = 5u;
    size_t cap = 4096u;
    auto q = duct_vmq_mpsc_create(1u, &cap, 0u);
    assert(q);
    auto ln = duct_mpsc_lane(q, 0u);

    for (uint32_t i = 0u; i < n; ++i)
        s_push(&ln, i);

    /* First pass: refuse index 2 -- only 0,1 should commit. */
    s_fail_at = 2u;
    s_calls = 0u;
    size_t sent = s_drain_one_lane(&ln);
    assert(sent == 2u);
    assert(s_calls == 3u); /* saw 0 (ok), 1 (ok), 2 (refused) -- stopped there */

    /* Second pass, nothing refused: the rest (2,3,4) must still be queued,
     * in order, exactly once -- not lost, not re-delivering 0/1. */
    s_fail_at = UINT32_MAX;
    s_calls = 0u;
    uint32_t seen[n];
    unsigned n_seen = 0u;
    {
        auto pos = duct_vmq_drain_begin(&ln);
        duct_vmq_hdr_t *hdr;
        while ((hdr = duct_vmq_drain_peek(&ln, &pos)) != nullptr) {
            seen[n_seen++] = *(const uint32_t *)hdr->payload;
            pos.head += pos.step;
        }
        duct_vmq_commit_head(&ln, pos.gen, pos.head);
    }
    assert(n_seen == 3u);
    assert(seen[0] == 2u && seen[1] == 3u && seen[2] == 4u);

    duct_vmq_mpsc_del(q);
    printf("dgram_tx_partial_commit_test OK\n");
    return 0;
}
