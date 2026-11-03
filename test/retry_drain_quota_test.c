/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file retry_drain_quota_test.c
 * @brief s_retry_drain's per-pass quota: a single call resolves at most
 * retry_drain_quota nodes, the rest survive untouched for the next call,
 * and repeated calls drain an arbitrarily long list without ever walking
 * past the quota in one pass.
 *
 * Includes duct_worker.c directly to reach s_retry_drain/retry_node_t
 * (static symbols), same pattern as handler_dispatch_test.c. Every node
 * carries an all-zero (gen=0) duct_conn_handle_t, which duct_conn_by_handle
 * rejects before ever touching the conn pool (src/conn/duct_conn.c's own
 * guard) -- s_dispatch_resolve reports res_gone, hitting s_retry_drain's
 * cheapest resolution path with no live engine/session/conn required.
 */

#include "../src/duct_worker.c"

#include <assert.h>
#include <stdio.h>

static unsigned s_list_len(const retry_node_t *head)
{
    unsigned n = 0u;
    for (auto node = head; node; node = node->next)
        ++n;
    return n;
}

static void s_build_gone_frame_chain(duct_worker_t *w, unsigned count)
{
    for (unsigned i = 0u; i < count; ++i) {
        auto node = duct_new(retry_node_t);
        assert(node);
        *node = (retry_node_t){
            .kind = retry_frame,
            .frame = { .handle = (duct_conn_handle_t){ .word = 0u } },
        };
        s_retry_enqueue(w, node); /* real FIFO append, keeps retry_tail valid */
    }
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    static constexpr unsigned total = retry_drain_quota * 3u + 5u;
    duct_worker_t w = {};
    s_build_gone_frame_chain(&w, total);
    assert(s_list_len(w.retry_head) == total);
    assert(w.retry_tail && !w.retry_tail->next);

    unsigned passes = 0u;
    while (w.retry_head) {
        unsigned before = s_list_len(w.retry_head);
        bool progress = s_retry_drain(&w);
        unsigned after = s_list_len(w.retry_head);
        unsigned resolved = before - after;
        ++passes;

        unsigned want = before > retry_drain_quota ? retry_drain_quota : before;
        if (resolved != want) {
            fprintf(stderr, "retry_drain_quota: pass %u resolved %u of %u pending, expected %u\n",
                   passes, resolved, before, want);
            return 1;
        }
        if (!progress) {
            fprintf(stderr, "retry_drain_quota: pass %u made no progress despite %u pending\n",
                   passes, before);
            return 1;
        }
    }

    unsigned expected_passes = (total + retry_drain_quota - 1u) / retry_drain_quota;
    if (passes != expected_passes) {
        fprintf(stderr, "retry_drain_quota: took %u passes, expected %u (quota=%u, total=%u)\n",
               passes, expected_passes, retry_drain_quota, total);
        return 1;
    }

    printf("retry_drain_quota: OK (%u nodes, quota=%u, drained in %u passes, "
          "never more than quota resolved in one pass)\n",
          total, retry_drain_quota, passes);
    return 0;
}
