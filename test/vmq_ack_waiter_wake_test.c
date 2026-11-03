/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file vmq_ack_waiter_wake_test.c
 * @brief Unit test for the ack-waiter CAS-claim contract.
 * @ref duct_vmq_ack_waiter on an unarmed @c wait_latch claims nothing; on an
 * armed one it claims exactly once and leaves the latch cleared — no engine,
 * no producer thread.
 */

#include "duct_vmq.h"

#include "duct_core.h"

#include <stdio.h>

#define CHECK(expr, msg) \
    do { if (!(expr)) { fprintf(stderr, "FAIL: %s\n", msg); return 1; } } while (0)

static constexpr size_t lane_cap = 256u;

int main(void)
{
    size_t caps[1] = { lane_cap };
    auto q = duct_vmq_mpsc_create(1u, caps, 0u);
    CHECK(q, "alloc mpsc");
    auto ctrl = duct_mpsc_ctrl(q, 0u);

    CHECK(!duct_vmq_ack_waiter(ctrl), "unarmed latch claims nothing");

    duct_atomic_store(&ctrl->wait_latch, 1, relaxed);
    atomic_thread_fence(memory_order_seq_cst);
    CHECK(duct_vmq_ack_waiter(ctrl), "armed latch is claimed");
    CHECK(!duct_atomic_load(&ctrl->wait_latch, relaxed), "claim clears the latch");
    CHECK(!duct_vmq_ack_waiter(ctrl), "cleared latch is not claimed again");

    duct_vmq_mpsc_del(q);
    printf("vmq_ack_waiter_wake_test OK\n");
    return 0;
}
