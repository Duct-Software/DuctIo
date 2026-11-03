/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file vmq_publish_shrink_test.c
 * @brief Unit test for @ref duct_vmq_publish_shrink: reserve at a
 * worst-case bound, publish at a smaller real size, confirm @c total_len
 * reflects the real size and the freed tail is available to the very next
 * reserve on the same lane — no engine, no io thread.
 */

#include "duct_vmq.h"

#include "duct_core.h"

#include <stdio.h>
#include <string.h>

#define CHECK(expr, msg) \
    do { if (!(expr)) { fprintf(stderr, "FAIL: %s\n", msg); return 1; } } while (0)

static constexpr size_t lane_cap = 4096u;
static constexpr size_t reserved_payload = 200u;
static constexpr size_t actual_payload = 17u;

int main(void)
{
    size_t caps[1] = { lane_cap };
    auto q = duct_vmq_mpsc_create(1u, caps, 0u);
    CHECK(q, "alloc mpsc");
    auto ln = duct_mpsc_lane(q, 0u);

    /* Reserve a generous worst-case span, write far less than that. */
    duct_vmq_reserve_pos_t pos1;
    duct_vmq_push_rc_t rc1;
    auto span1 = duct_vmq_reserve(&ln, 1u, 0u, reserved_payload, &pos1, &rc1);
    CHECK(span1, "reserve #1");
    CHECK(pos1.off == 0u, "first reserve starts at offset 0");
    memset(span1, 'a', actual_payload);
    duct_vmq_publish_shrink(&ln, &pos1, actual_payload);

    /* total_len must reflect the real size, not the original reservation. */
    auto hdr1 = (duct_vmq_hdr_t *)(ln.data + pos1.off);
    size_t expect_total1 = sizeof(duct_vmq_hdr_t) + actual_payload;
    CHECK(hdr1->total_len == expect_total1, "total_len shrunk to actual size");

    /* Next reserve on this lane must start right after the SHRUNK size,
     * not the original worst-case reservation — the whole point of shrink
     * over a plain publish: the unused tail becomes available immediately,
     * not just after a drain. */
    duct_vmq_reserve_pos_t pos2;
    duct_vmq_push_rc_t rc2;
    auto span2 = duct_vmq_reserve(&ln, 1u, 0u, reserved_payload, &pos2, &rc2);
    CHECK(span2, "reserve #2");
    size_t expect_off2 = duct_align_up(expect_total1, 8u);
    CHECK(pos2.off == expect_off2, "second reserve reuses the freed tail, not the original span");

    /* Drain confirms exactly one message so far (msg #2 not yet
     * published), with the shrunk size and the real bytes written. */
    auto dpos = duct_vmq_drain_begin(&ln);
    auto peeked = duct_vmq_drain_peek(&ln, &dpos);
    CHECK(peeked, "drain sees msg #1");
    CHECK(peeked->total_len == expect_total1, "drained total_len matches shrunk size");
    CHECK(memcmp(peeked->payload, span1, actual_payload) == 0, "drained payload matches what was written");
    dpos.head += dpos.step;
    auto peeked2 = duct_vmq_drain_peek(&ln, &dpos);
    CHECK(!peeked2, "drain sees nothing past msg #1 (msg #2 still unpublished)");
    duct_vmq_commit_head(&ln, dpos.gen, dpos.head);

    duct_vmq_mpsc_del(q);
    printf("vmq_publish_shrink_test OK\n");
    return 0;
}
