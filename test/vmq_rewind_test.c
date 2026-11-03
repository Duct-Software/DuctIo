/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file vmq_rewind_test.c
 * @brief Unit test for when a lane rewinds to offset 0, and what that moves —
 * no engine, no io thread.
 *
 * Four scenarios around the single precondition a rewind carries, the consumer
 * having reached the allocation cursor. A drained lane rewinds on its next
 * reserve rather than running on, carving in the following epoch, and the
 * consumer resyncs into it. A lane still holding an unread message runs on in
 * the same epoch. One holding an unread message with no contiguous room left
 * answers @c vmq_push_rewind_fail, and takes that same reserve at offset 0
 * once the message drains. And a reserve repeated to resize an unpublished
 * slot moves that slot to the lane start when the consumer caught up in
 * between — the relocation @c s_dgram_shared_route answers with a memmove and
 * a shift of the frame pointers it had already computed.
 */

#include "duct_vmq.h"

#include "duct_core.h"

#include <stdio.h>
#include <string.h>

#define CHECK(expr, msg) \
    do { if (!(expr)) { fprintf(stderr, "FAIL: %s\n", msg); return 1; } } while (0)

static constexpr size_t lane_cap = 4096u;
static constexpr size_t small = 64u;
static constexpr uint8_t msg_a = 1u;
static constexpr uint8_t msg_b = 2u;

static size_t s_drain_count(const duct_vmq_lane_t *ln, uint8_t *first_type)
{
    auto pos = duct_vmq_drain_begin(ln);
    size_t n = 0u;
    duct_vmq_hdr_t *hdr = nullptr;
    while ((hdr = duct_vmq_drain_peek(ln, &pos)) != nullptr) {
        if (!n && first_type)
            *first_type = hdr->type;
        pos.head += pos.step;
        ++n;
    }
    if (n)
        duct_vmq_commit_head(ln, pos.gen, pos.head);
    return n;
}

static size_t s_slot_size(size_t payload)
{
    return duct_align_up(sizeof(duct_vmq_hdr_t) + payload, 8u);
}

static int sc_idle_lane_rewinds(duct_vmq_mpsc_t *q)
{
    auto ln = duct_mpsc_lane(q, 0u);
    duct_vmq_reserve_pos_t pos;
    duct_vmq_push_rc_t rc;
    auto span = duct_vmq_reserve(&ln, msg_a, 0u, small, &pos, &rc);
    CHECK(span, "first reserve");
    CHECK(pos.off == 0u, "the first slot starts the lane");
    uint32_t gen0 = pos.gen;
    duct_vmq_publish(&ln, &pos);
    CHECK(s_drain_count(&ln, nullptr) == 1u, "the first message drains");

    span = duct_vmq_reserve(&ln, msg_b, 0u, small, &pos, &rc);
    CHECK(span, "reserve on the drained lane");
    CHECK(pos.off == 0u, "an idle lane rewinds instead of running on");
    CHECK(pos.gen == gen0 + 1u, "the rewind opens the next epoch");
    duct_vmq_publish(&ln, &pos);

    uint8_t first = 0u;
    CHECK(s_drain_count(&ln, &first) == 1u,
          "the consumer resyncs into the epoch the rewind opened");
    CHECK(first == msg_b, "and reads the message carved there");
    return 0;
}

static int sc_unread_lane_runs_on(duct_vmq_mpsc_t *q)
{
    auto ln = duct_mpsc_lane(q, 0u);
    duct_vmq_reserve_pos_t pos;
    duct_vmq_push_rc_t rc;
    auto span = duct_vmq_reserve(&ln, msg_a, 0u, small, &pos, &rc);
    CHECK(span, "first reserve");
    uint32_t gen0 = pos.gen;
    duct_vmq_publish(&ln, &pos);

    span = duct_vmq_reserve(&ln, msg_b, 0u, small, &pos, &rc);
    CHECK(span, "reserve behind unread traffic");
    CHECK(pos.off == s_slot_size(small), "a lane with a message unread runs on");
    CHECK(pos.gen == gen0, "and stays in the same epoch");
    duct_vmq_publish(&ln, &pos);

    uint8_t first = 0u;
    CHECK(s_drain_count(&ln, &first) == 2u, "both messages drain in one pass");
    CHECK(first == msg_a, "in lane order");
    return 0;
}

static int sc_unread_at_the_end_refuses(duct_vmq_mpsc_t *q)
{
    auto ln = duct_mpsc_lane(q, 0u);
    duct_vmq_reserve_pos_t pos;
    duct_vmq_push_rc_t rc;
    size_t bulk = ln.capacity - ln.capacity / 4u - sizeof(duct_vmq_hdr_t);
    auto span = duct_vmq_reserve(&ln, msg_a, 0u, bulk, &pos, &rc);
    CHECK(span, "bulk reserve");
    duct_vmq_publish(&ln, &pos);

    auto refused = duct_vmq_reserve(&ln, msg_b, 0u, bulk, &pos, &rc);
    CHECK(!refused, "no room ahead and the consumer behind: refused");
    CHECK(rc == vmq_push_rewind_fail, "refused for the wrap, not for size");

    CHECK(s_drain_count(&ln, nullptr) == 1u, "the bulk drains");
    span = duct_vmq_reserve(&ln, msg_b, 0u, bulk, &pos, &rc);
    CHECK(span, "the same reserve lands once the consumer catches up");
    CHECK(pos.off == 0u, "at the lane start");
    duct_vmq_publish(&ln, &pos);

    uint8_t first = 0u;
    CHECK(s_drain_count(&ln, &first) == 1u, "the second bulk drains");
    CHECK(first == msg_b, "and is the message that was refused");
    return 0;
}

static int sc_resize_moves_the_slot(duct_vmq_mpsc_t *q)
{
    auto ln = duct_mpsc_lane(q, 0u);
    duct_vmq_reserve_pos_t pos;
    duct_vmq_push_rc_t rc;
    auto pinned = duct_vmq_reserve(&ln, msg_a, 0u, small, &pos, &rc);
    CHECK(pinned, "the message that holds the consumer back");
    duct_vmq_publish(&ln, &pos);

    duct_vmq_reserve_pos_t gpos;
    auto carved = duct_vmq_reserve(&ln, msg_b, 0u, small, &gpos, &rc);
    CHECK(carved, "unpublished reserve behind unread traffic");
    CHECK(gpos.off == s_slot_size(small), "carved past the pinned message");

    CHECK(s_drain_count(&ln, nullptr) == 1u, "the consumer catches up mid-reserve");

    size_t bigger = small * 2u;
    auto moved = duct_vmq_reserve(&ln, msg_b, 0u, bigger, &gpos, &rc);
    CHECK(moved, "the resizing reserve");
    CHECK(moved != carved, "a caught-up consumer moves the resized slot");
    CHECK(gpos.off == 0u, "to the lane start");
    memset(moved, 'b', bigger);
    duct_vmq_publish(&ln, &gpos);

    uint8_t first = 0u;
    CHECK(s_drain_count(&ln, &first) == 1u, "the moved slot delivers once");
    CHECK(first == msg_b, "carrying the resized message");
    return 0;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    size_t caps[1] = { lane_cap };
    int (*const scenarios[])(duct_vmq_mpsc_t *) = {
        sc_idle_lane_rewinds,
        sc_unread_lane_runs_on,
        sc_unread_at_the_end_refuses,
        sc_resize_moves_the_slot,
    };

    for (size_t i = 0u; i < sizeof scenarios / sizeof scenarios[0]; ++i) {
        auto q = duct_vmq_mpsc_create(1u, caps, 0u);
        CHECK(q, "alloc mpsc");
        int rc = scenarios[i](q);
        duct_vmq_mpsc_del(q);
        if (rc)
            return rc;
    }

    printf("vmq_rewind_test OK\n");
    return 0;
}
