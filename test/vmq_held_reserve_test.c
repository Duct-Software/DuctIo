/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file vmq_held_reserve_test.c
 * @brief Unit test for the held reservation: what a producer may do while one
 * is open, and what the consumer sees — no engine, no io thread.
 *
 * Six scenarios, one property each. A nested push is not refused and stays
 * invisible until the hold resolves, then both appear in lane order. An
 * abandoned hold with traffic behind it never reaches a callback, since the
 * pad is consumed inside the drain. An abandoned hold with nothing behind it
 * hands its span straight back to the next reserve. Publishing a hold below
 * its reserved size returns the tail to the very next reserve, and does it
 * behind a pad when later traffic has already claimed the ground past it.
 * And a hold cannot be jumped over: a nested reserve needing a wrap past it
 * is refused with @c vmq_push_rewind_fail instead.
 *
 * Lane arithmetic runs off @c ln.capacity, not the requested size — a lane
 * rounds its capacity up at creation, so sizing from the request leaves the
 * wrap scenario passing without ever reaching the wrap.
 */

#include "duct_vmq.h"

#include "duct_core.h"

#include <stdio.h>
#include <string.h>

#define CHECK(expr, msg) \
    do { if (!(expr)) { fprintf(stderr, "FAIL: %s\n", msg); return 1; } } while (0)

static constexpr size_t lane_cap = 4096u;
static constexpr size_t held_payload = 64u;
static constexpr size_t nested_payload = 32u;

/** @brief Source bytes for a push behind a hold.
 *  Sized by @c nested_payload because that is what the pushes copy out of
 *  it; no scenario reads the bytes back. */
static const uint8_t nested_src[nested_payload] = {};
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

static int sc_nested_push_waits(duct_vmq_mpsc_t *q)
{
    auto ln = duct_mpsc_lane(q, 0u);
    duct_vmq_reserve_pos_t hpos;
    duct_vmq_push_rc_t rc;
    auto held = duct_vmq_reserve_held(&ln, msg_a, 0u, held_payload, &hpos, &rc);
    CHECK(held, "held reserve");
    CHECK(hpos.off == 0u, "held slot starts the lane");

    CHECK(duct_vmq_push(&ln, msg_b, 0u, nested_src, nested_payload) == vmq_push_ok,
          "a nested push is not refused while a hold is open");
    CHECK(s_drain_count(&ln, nullptr) == 0u,
          "neither the hold nor what landed behind it is visible yet");

    memset(held, 'a', held_payload);
    duct_vmq_publish_held(&ln, &hpos, held_payload);
    uint8_t first = 0u;
    CHECK(s_drain_count(&ln, &first) == 2u, "both messages appear at once");
    CHECK(first == msg_a, "the held slot keeps its place in the lane order");
    return 0;
}

static int sc_abandon_with_traffic(duct_vmq_mpsc_t *q)
{
    auto ln = duct_mpsc_lane(q, 0u);
    duct_vmq_reserve_pos_t hpos;
    duct_vmq_push_rc_t rc;
    auto held = duct_vmq_reserve_held(&ln, msg_a, 0u, held_payload, &hpos, &rc);
    CHECK(held, "held reserve");
    CHECK(duct_vmq_push(&ln, msg_b, 0u, nested_src, nested_payload) == vmq_push_ok,
          "nested push behind the hold");

    duct_vmq_abandon_held(&ln, &hpos);
    uint8_t first = 0u;
    CHECK(s_drain_count(&ln, &first) == 1u, "only the nested message is delivered");
    CHECK(first == msg_b, "the abandoned slot never reaches a callback");
    return 0;
}

static int sc_abandon_alone(duct_vmq_mpsc_t *q)
{
    auto ln = duct_mpsc_lane(q, 0u);
    duct_vmq_reserve_pos_t hpos;
    duct_vmq_push_rc_t rc;
    auto held = duct_vmq_reserve_held(&ln, msg_a, 0u, held_payload, &hpos, &rc);
    CHECK(held, "held reserve");
    duct_vmq_abandon_held(&ln, &hpos);
    CHECK(s_drain_count(&ln, nullptr) == 0u, "nothing to drain");

    duct_vmq_reserve_pos_t pos;
    auto span = duct_vmq_reserve(&ln, msg_b, 0u, nested_payload, &pos, &rc);
    CHECK(span, "reserve after the abandon");
    CHECK(pos.off == hpos.off, "the abandoned span is handed straight back");
    duct_vmq_publish(&ln, &pos);
    CHECK(s_drain_count(&ln, nullptr) == 1u, "the reused span delivers");
    return 0;
}

static int sc_shrink_returns_tail(duct_vmq_mpsc_t *q)
{
    auto ln = duct_mpsc_lane(q, 0u);
    duct_vmq_reserve_pos_t hpos;
    duct_vmq_push_rc_t rc;
    auto held = duct_vmq_reserve_held(&ln, msg_a, 0u, held_payload, &hpos, &rc);
    CHECK(held, "held reserve");
    duct_vmq_publish_held(&ln, &hpos, nested_payload);

    duct_vmq_reserve_pos_t pos;
    auto span = duct_vmq_reserve(&ln, msg_b, 0u, nested_payload, &pos, &rc);
    CHECK(span, "reserve after the shrunk publish");
    size_t kept = duct_align_up(sizeof(duct_vmq_hdr_t) + nested_payload, 8u);
    CHECK(pos.off == hpos.off + kept, "the unused tail came back at once");
    duct_vmq_publish(&ln, &pos);
    CHECK(s_drain_count(&ln, nullptr) == 2u, "both messages drain");
    return 0;
}

static int sc_shrink_pads_the_gap(duct_vmq_mpsc_t *q)
{
    auto ln = duct_mpsc_lane(q, 0u);
    duct_vmq_reserve_pos_t hpos;
    duct_vmq_push_rc_t rc;
    auto held = duct_vmq_reserve_held(&ln, msg_a, 0u, held_payload, &hpos, &rc);
    CHECK(held, "held reserve");
    CHECK(duct_vmq_push(&ln, msg_b, 0u, nested_src, nested_payload) == vmq_push_ok,
          "nested push behind the hold");

    duct_vmq_publish_held(&ln, &hpos, nested_payload);
    uint8_t first = 0u;
    CHECK(s_drain_count(&ln, &first) == 2u,
          "the gap the shrink left is stepped over, not parsed as a message");
    CHECK(first == msg_a, "lane order survives the shrink");
    return 0;
}

static int sc_hold_blocks_rewind(duct_vmq_mpsc_t *q)
{
    auto ln = duct_mpsc_lane(q, 0u);
    duct_vmq_reserve_pos_t pos;
    duct_vmq_push_rc_t rc;
    size_t bulk = ln.capacity - ln.capacity / 4u;
    auto span = duct_vmq_reserve(&ln, msg_b, 0u, bulk, &pos, &rc);
    CHECK(span, "bulk reserve");
    duct_vmq_publish(&ln, &pos);

    duct_vmq_reserve_pos_t hpos;
    auto held = duct_vmq_reserve_held(&ln, msg_a, 0u, held_payload, &hpos, &rc);
    CHECK(held, "held reserve near the lane end");
    CHECK(hpos.off > 0u, "the hold sits past the lane start");

    auto nested = duct_vmq_reserve(&ln, msg_b, 0u, bulk, &pos, &rc);
    CHECK(!nested, "a nested reserve needing a wrap is refused, not wrapped");
    CHECK(rc == vmq_push_rewind_fail, "refused for the wrap, not for size");

    duct_vmq_publish_held(&ln, &hpos, held_payload);
    uint8_t first = 0u;
    CHECK(s_drain_count(&ln, &first) == 2u, "the hold delivers once released");
    CHECK(first == msg_b, "the bulk keeps its place ahead of the hold");
    return 0;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    size_t caps[1] = { lane_cap };

    auto q = duct_vmq_mpsc_create(1u, caps, 0u);
    CHECK(q, "alloc mpsc");
    int rc = sc_nested_push_waits(q);
    duct_vmq_mpsc_del(q);
    if (rc)
        return rc;

    q = duct_vmq_mpsc_create(1u, caps, 0u);
    CHECK(q, "alloc mpsc");
    rc = sc_abandon_with_traffic(q);
    duct_vmq_mpsc_del(q);
    if (rc)
        return rc;

    q = duct_vmq_mpsc_create(1u, caps, 0u);
    CHECK(q, "alloc mpsc");
    rc = sc_abandon_alone(q);
    duct_vmq_mpsc_del(q);
    if (rc)
        return rc;

    q = duct_vmq_mpsc_create(1u, caps, 0u);
    CHECK(q, "alloc mpsc");
    rc = sc_shrink_returns_tail(q);
    duct_vmq_mpsc_del(q);
    if (rc)
        return rc;

    q = duct_vmq_mpsc_create(1u, caps, 0u);
    CHECK(q, "alloc mpsc");
    rc = sc_shrink_pads_the_gap(q);
    duct_vmq_mpsc_del(q);
    if (rc)
        return rc;

    q = duct_vmq_mpsc_create(1u, caps, 0u);
    CHECK(q, "alloc mpsc");
    rc = sc_hold_blocks_rewind(q);
    duct_vmq_mpsc_del(q);
    if (rc)
        return rc;

    printf("vmq_held_reserve_test OK\n");
    return 0;
}
