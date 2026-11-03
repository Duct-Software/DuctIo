/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file tx_pool_test.c
 * @brief White-box test of the per-worker TX staging pool
 * (duct_tx_pool.h): refs/hold interplay, in-order-only
 * reclaim past a dead region blocked by a still-live predecessor,
 * pool-pressure acquire failure (both "can never fit" and "genuinely
 * full right now"), and the wrap transition (a region's own footprint
 * skipping the too-small tail fragment, live data surviving intact on
 * both sides of the wrap, and reclaim correctly un-wrapping once it
 * crosses high_water).
 *
 * Includes duct_worker.c directly to reach duct_tx_pool_t,
 * duct_tx_pool_hdr_t, s_tx_pool_reclaim, s_tx_pool_drop_hold, s_tx_pool_hdr_of and
 * s_tx_pool_region_bytes (all static/internal), same pattern as
 * handler_dispatch_test.c. duct_tx_pool_acquire is the one public entry point
 * under test; every worker-thread-only contract it carries is satisfied here
 * by a single-threaded main() and one plain, stack-local duct_worker_t -- no
 * engine, no session, no real socket anywhere.
 */

#include "../src/duct_worker.c"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static int s_failures;

#define CHECK(cond) do { \
        if (!(cond)) { \
            fprintf(stderr, "tx_pool_test: FAILED %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++s_failures; \
        } \
    } while (0)

/** @brief Basic acquire -> write -> seal -> reclaim round trip: refs never
 *  touched (the degenerate x_udp_peer fast-path shape), hold alone gates
 *  freeing. */
static void s_test_basic_roundtrip(void)
{
    duct_worker_t w = {};
    s_this_worker = &w;

    void *p = duct_tx_pool_acquire(100u);
    CHECK(p != nullptr);
    memset(p, 0xAB, 100u);
    CHECK(w.tx_pool.head == 0u);
    CHECK(w.tx_pool.tail == s_tx_pool_region_bytes(100u));
    CHECK(s_tx_pool_hdr_of(p)->hold);
    CHECK(s_tx_pool_hdr_of(p)->refs == 0u);

    /* Held, zero refs: still not reclaimable. */
    s_tx_pool_reclaim(&w.tx_pool);
    CHECK(w.tx_pool.head == 0u);

    s_tx_pool_drop_hold(p);
    CHECK(!s_tx_pool_hdr_of(p)->hold);
    s_tx_pool_reclaim(&w.tx_pool);
    CHECK(w.tx_pool.head == w.tx_pool.tail);
}

/** @brief refs and hold each independently gate reclaim -- both must
 *  reach zero/false before a region frees, matching the "transient
 *  refs==0 between two mid-walk flushes must not free the buffer"
 *  invariant (duct_tx_pool_hdr_t's own doc). */
static void s_test_refs_and_hold_independent(void)
{
    duct_worker_t w = {};
    s_this_worker = &w;

    void *p = duct_tx_pool_acquire(50u);
    CHECK(p != nullptr);
    auto hdr = s_tx_pool_hdr_of(p);
    hdr->refs = 1u; /* simulate one in-flight batch entry referencing it */

    s_tx_pool_reclaim(&w.tx_pool);
    CHECK(w.tx_pool.head == 0u); /* hold still true */

    s_tx_pool_drop_hold(p);
    s_tx_pool_reclaim(&w.tx_pool);
    CHECK(w.tx_pool.head == 0u); /* hold cleared, but refs == 1 still pins it */

    hdr->refs = 0u;
    s_tx_pool_reclaim(&w.tx_pool);
    CHECK(w.tx_pool.head == w.tx_pool.tail);
}

/** @brief A dead region waits for a still-live predecessor -- reclaim
 *  never skips ahead in ring order, even though a later region resolved
 *  first. Once the predecessor also dies, one reclaim pass sweeps both. */
static void s_test_out_of_order_dead_waits(void)
{
    duct_worker_t w = {};
    s_this_worker = &w;

    void *pa = duct_tx_pool_acquire(64u);
    void *pb = duct_tx_pool_acquire(64u);
    CHECK(pa && pb);
    auto hdr_a = s_tx_pool_hdr_of(pa);
    auto hdr_b = s_tx_pool_hdr_of(pb);

    /* B (the later region) is fully dead; A (the earlier one) is still held. */
    s_tx_pool_drop_hold(pb);
    hdr_b->refs = 0u;
    s_tx_pool_reclaim(&w.tx_pool);
    CHECK(w.tx_pool.head == 0u); /* blocked by A, not by B */

    s_tx_pool_drop_hold(pa);
    hdr_a->refs = 0u;
    s_tx_pool_reclaim(&w.tx_pool);
    /* Fully drained: reclaim's empty rewind normalizes to offset 0. */
    CHECK(w.tx_pool.head == 0u && w.tx_pool.tail == 0u);
}

/** @brief A request wider than the whole arena can ever hold fails every
 *  time, regardless of how empty the pool is right now. */
static void s_test_never_fits(void)
{
    duct_worker_t w = {};
    s_this_worker = &w;

    void *p = duct_tx_pool_acquire(duct_worker_tx_pool_cap);
    CHECK(p == nullptr);
    CHECK(w.tx_pool.head == 0u && w.tx_pool.tail == 0u); /* no partial state left behind */
}

/** @brief Genuine pressure: a request that would fit an empty pool fails
 *  once an earlier, still-live region has already claimed the rest of
 *  the arena -- and the pool-pressure rtstat counts exactly that. */
static void s_test_pressure_when_full(void)
{
    duct_worker_t w = {};
    s_this_worker = &w;

    /* Three quarters of the arena fits comfortably alone; a second,
     * equally sized request cannot possibly fit alongside a still-live
     * first one (together they would need 1.5x the whole arena) --
     * genuine pressure, not a can-never-fit-ever rejection. */
    uint32_t big = duct_worker_tx_pool_cap * 3u / 4u;
    void *p1 = duct_tx_pool_acquire(big);
    CHECK(p1 != nullptr);

    void *p2 = duct_tx_pool_acquire(big);
    CHECK(p2 == nullptr);
#if DUCT_RUNTIME_STATS
    CHECK(w.rtstats.tx_pool_acquire_fail == 1u);
#endif

    /* Freeing p1 makes the exact same request succeed again. */
    s_tx_pool_drop_hold(p1);
    s_tx_pool_hdr_of(p1)->refs = 0u;
    s_tx_pool_reclaim(&w.tx_pool);
    void *p3 = duct_tx_pool_acquire(big);
    CHECK(p3 != nullptr);
}

/** @brief Wrap: a region that would not fit before the arena's physical
 *  end, with room only behind head, skips the leftover tail fragment
 *  and continues at offset 0 -- live payload bytes on both sides of the
 *  wrap survive untouched, and reclaim correctly crosses high_water back
 *  into the single-lap regime once the old lap's own remnant fully
 *  drains. Also confirms a wrap is refused outright when even the
 *  wrapped side has no room -- never overlaps live data.
 */
static void s_test_wrap(void)
{
    duct_worker_t w = {};
    s_this_worker = &w;

    uint32_t cap = duct_worker_tx_pool_cap;
    uint32_t psize = cap / 5u; /* five of these roughly fill the arena once */

    void *r0 = duct_tx_pool_acquire(psize);
    void *r1 = duct_tx_pool_acquire(psize);
    void *r2 = duct_tx_pool_acquire(psize);
    CHECK(r0 && r1 && r2);
    memset(r0, 0x11, psize);
    memset(r1, 0x22, psize);
    memset(r2, 0x33, psize);

    /* Free r0 and r1 (in order), advancing head well away from 0 while
     * r2 stays live and tail keeps growing. */
    s_tx_pool_drop_hold(r0); s_tx_pool_hdr_of(r0)->refs = 0u;
    s_tx_pool_drop_hold(r1); s_tx_pool_hdr_of(r1)->refs = 0u;
    s_tx_pool_reclaim(&w.tx_pool);
    CHECK(w.tx_pool.head == 2u * s_tx_pool_region_bytes(psize));
    CHECK(!w.tx_pool.wrapped);

    /* r2 is still live; verify its bytes are untouched by the reclaim
     * that just ran past its own predecessors. */
    CHECK(((uint8_t *)r2)[0] == 0x33 && ((uint8_t *)r2)[psize - 1u] == 0x33);

    uint32_t head_before_wrap = w.tx_pool.head;
    uint32_t tail_before_wrap = w.tx_pool.tail;

    /* Two more chunks: the arena (5 * psize =~ cap) has room for one more
     * before cap, but not two -- the second must wrap into the room
     * s_test freed above (head_before_wrap bytes at offset 0). */
    void *r3 = duct_tx_pool_acquire(psize);
    CHECK(r3 != nullptr);
    CHECK(!w.tx_pool.wrapped); /* still fit before cap */
    memset(r3, 0x44, psize);

    void *r4 = duct_tx_pool_acquire(psize);
    CHECK(r4 != nullptr);
    CHECK(w.tx_pool.wrapped);
    CHECK(w.tx_pool.high_water == tail_before_wrap + s_tx_pool_region_bytes(psize));
    CHECK((const void *)r4 == (const void *)(w.tx_pool.arena + duct_tx_pool_hdr_bytes)); /* landed at offset 0 */
    memset(r4, 0x55, psize);

    /* r2 (never freed) must still read back intact after both the r3
     * bump and the r4 wrap-around allocation. */
    CHECK(((uint8_t *)r2)[0] == 0x33 && ((uint8_t *)r2)[psize - 1u] == 0x33);

    /* A wrap that would collide with the still-live r2 (sitting at
     * head_before_wrap) must be refused, not silently corrupt it. */
    void *r5 = duct_tx_pool_acquire(head_before_wrap + 1u);
    CHECK(r5 == nullptr);
    CHECK(((uint8_t *)r2)[0] == 0x33); /* untouched by the refused attempt */

    /* Drain everything: r2, then the old-lap high-water crossing, then
     * the new lap's own r3/r4. */
    s_tx_pool_drop_hold(r2); s_tx_pool_hdr_of(r2)->refs = 0u;
    s_tx_pool_drop_hold(r3); s_tx_pool_hdr_of(r3)->refs = 0u;
    s_tx_pool_drop_hold(r4); s_tx_pool_hdr_of(r4)->refs = 0u;
    s_tx_pool_reclaim(&w.tx_pool);
    CHECK(!w.tx_pool.wrapped);
    CHECK(w.tx_pool.head == w.tx_pool.tail);
}

/** @brief head == tail is the ring's one "empty" sentinel: reclaim rewinds
 *  a drained pool to offset 0, so a request larger than either fragment
 *  around a mid-arena cursor parking spot still succeeds; and a wrapped
 *  tail is never allowed to catch head exactly (the strict-fit rule in
 *  s_tx_pool_place), so the sentinel stays unambiguous. */
static void s_test_empty_rewind_and_strict_wrap(void)
{
    duct_worker_t w = {};
    s_this_worker = &w;

    /* Park the cursor past the arena's midpoint, drain, then ask for
     * more than the pre-rewind tail fragment could hold -- reclaim's
     * rewind must make the whole arena available again. */
    uint32_t big = duct_worker_tx_pool_cap * 3u / 5u;
    void *p1 = duct_tx_pool_acquire(big);
    CHECK(p1 != nullptr);
    s_tx_pool_drop_hold(p1);
    void *p2 = duct_tx_pool_acquire(big);
    CHECK(p2 != nullptr);
    CHECK(w.tx_pool.head == 0u && (const void *)p2 == (const void *)(w.tx_pool.arena + duct_tx_pool_hdr_bytes));

    /* Exact-fit wrap: a wrap whose region footprint equals the freed
     * space at offset 0 exactly would land tail on head -- refused, one
     * byte of the gap stays unusable by design. */
    s_tx_pool_drop_hold(p2);
    void *p3 = duct_tx_pool_acquire(big);           /* rewound again: head == tail == 0 */
    CHECK(p3 != nullptr);
    uint32_t psize = duct_worker_tx_pool_cap / 5u;
    void *p4 = duct_tx_pool_acquire(psize);         /* live region the wrap must not cross */
    CHECK(p4 != nullptr);
    memset(p4, 0x66, psize);
    s_tx_pool_drop_hold(p3);
    s_tx_pool_hdr_of(p3)->refs = 0u;
    s_tx_pool_reclaim(&w.tx_pool);                  /* head = p3's footprint, p4 live behind tail */
    uint32_t hole = w.tx_pool.head;                 /* bytes available at offset 0 after a wrap */
    CHECK(hole != 0u && !w.tx_pool.wrapped);
    void *p5 = duct_tx_pool_acquire(hole - duct_tx_pool_hdr_bytes); /* region footprint == hole exactly */
    CHECK(p5 == nullptr);
    CHECK(((uint8_t *)p4)[0] == 0x66 && ((uint8_t *)p4)[psize - 1u] == 0x66); /* no overlap happened */

    s_tx_pool_drop_hold(p4);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    s_test_basic_roundtrip();
    s_test_refs_and_hold_independent();
    s_test_out_of_order_dead_waits();
    s_test_never_fits();
    s_test_pressure_when_full();
    s_test_wrap();
    s_test_empty_rewind_and_strict_wrap();

    s_this_worker = nullptr;
    if (s_failures) {
        fprintf(stderr, "tx_pool_test: %d check(s) failed\n", s_failures);
        return 1;
    }
    printf("tx_pool_test: OK\n");
    return 0;
}
