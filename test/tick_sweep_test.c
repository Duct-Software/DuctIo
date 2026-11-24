/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file tick_sweep_test.c
 * @brief The sweep an io thread runs at its tick reaches every slot pool the thread holds: the RX pool of a
 * listener and the thread's one device rx pool, each given back down to the floor once it has gone a period
 * without growing, and grown again by the next drive.
 *
 * Includes duct_io.c directly to reach the io module state and the static sweep, as dgram_scratch_test.c
 * does; the io thread is started and joined before the sweep runs on the main thread in its place.
 */

#include "../src/duct_io.c"

#include "duct_wfq.h"
#include "test_helpers.h"

#include <assert.h>
#include <stdio.h>

static void fill_and_empty(duct_x_slot_pool_t *pool, uint32_t slots, uint32_t live_after)
{
    uint32_t got[64];
    assert(slots <= 64u);
    for (uint32_t i = 0u; i < slots; ++i) {
        got[i] = duct_x_slot_acquire(pool);
        assert(got[i] != treiber_empty);
    }
    assert(duct_atomic_load(&pool->live, relaxed) == live_after);
    for (uint32_t i = 0u; i < slots; ++i)
        duct_x_slot_release(pool, got[i]);
}

static void check_sweep_reaches_pools(duct_vmq_mpsc_t *wfq)
{
    assert(duct_io_init(1u, wfq, 1u));
    assert(duct_io_start_threads());
    duct_io_request_shutdown();
    duct_io_join();
    auto t = &s_imod.xports[0];
    s_io_this = t;

    duct_x_slot_pool_t rx;
    assert(duct_x_slot_pool_init(&rx, 8u, 256u, 8u, 0u, 2u, (duct_x_slot_hooks_t){}));
    auto l = duct_new(duct_listener_t);
    assert(l);
    l->rx_slots = &rx;
    t->listeners = l;

    auto dev = s_device_rx_pool(t);
    assert(dev);
    assert(dev->n_chunks == duct_device_hold_cap && dev->chunk_slots == 1u);

    fill_and_empty(&rx, 8u, rx.n_chunks);
    fill_and_empty(dev, 8u, 8u);

    /* Growth makes both busy for one tick, which only notes it. */
    s_pools_sweep(t);
    assert(duct_atomic_load(&rx.live, relaxed) == rx.n_chunks);
    assert(duct_atomic_load(&dev->live, relaxed) == 8u);

    /* The next tick finds them calm and keeps the floor of each. */
    s_pools_sweep(t);
    assert(duct_atomic_load(&rx.live, relaxed) == duct_x_slot_floor_chunks);
    assert(duct_atomic_load(&dev->live, relaxed) == duct_x_slot_floor_chunks);

    /* A drive that needs more slots grows the device pool by the slot. */
    uint32_t a = duct_x_slot_acquire(dev),
             b = duct_x_slot_acquire(dev),
             c = duct_x_slot_acquire(dev);
    assert(a != treiber_empty && b != treiber_empty && c != treiber_empty);
    assert(duct_atomic_load(&dev->live, relaxed) == 3u);
    duct_x_slot_release(dev, a);
    duct_x_slot_release(dev, b);
    duct_x_slot_release(dev, c);

    t->listeners = nullptr;
    duct_x_slot_pool_free(dev);
    t->device_rx_live = false;
    duct_x_slot_pool_free(&rx);
    duct_del(l);
    s_io_this = nullptr;
    duct_io_cleanup();
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto wfq = duct_wfq_new(1u, 1u, DUCT_WFQ_CAP_HI, DUCT_WFQ_CAP_NORM, DUCT_WFQ_CAP_LO);
    assert(wfq);
    check_sweep_reaches_pools(wfq);
    duct_vmq_mpsc_del(wfq);
    printf("tick_sweep: OK (the tick's sweep gives back a listener's RX pool and the thread's device rx pool)\n");
    return 0;
}
