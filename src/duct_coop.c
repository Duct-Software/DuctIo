/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_coop.c
 *  @brief Per-worker coop runtime: init/fini, bounded drain cycle, wake.
 *
 *  @par Scope
 *  - Owns: stackful/stackless drain quotas per cycle.
 *  - The stack pool itself is platform-specific.
 */

#include "duct_coro.h"

duct_result_t duct_coop_init(duct_coop_t *cp,
                             unsigned stack_slots,
                             unsigned async_slots,
                             size_t stack_bytes)
{
    duct_do_if(cp->open, return rc_ok);
    duct_do_if(!stack_slots && !async_slots, return rc_invalid_arg);
    *cp = (duct_coop_t){};
    cp->stack_slots = stack_slots;
    cp->async_slots = async_slots;
    /* Armed before the pools exist, so a failed step's own rollback in
     * @ref duct_coop_fini passes its @c !open gate and tears down regardless of
     * slots flags; @ref duct_coop_fini resets it with @c *cp = {}. */
    cp->open = true;
    duct_coro_queue_init(&cp->queue);
    duct_async_queue_init(&cp->async_queue);
    duct_result_t rc = stack_slots ? duct_coro_pool_new(&cp->pool, stack_slots, stack_bytes) : rc_ok;
    duct_do_if(rc != rc_ok, duct_coop_fini(cp); return rc);
    rc = async_slots ? duct_async_pool_init(&cp->async_pool, async_slots) : rc_ok;
    duct_do_if(rc != rc_ok, duct_coop_fini(cp); return rc);
    return rc_ok;
}

void duct_coop_fini(duct_coop_t *cp)
{
    duct_do_if(!cp->open, return);
    if (cp->stack_slots)
        duct_coro_pool_del(&cp->pool);
    if (cp->async_slots)
        duct_async_pool_fini(&cp->async_pool);
    *cp = (duct_coop_t){};
}

size_t duct_coop_cycle(duct_coop_t *cp)
{
    duct_do_if(!cp->open, return 0u);
    size_t stepped = 0u;
    if (cp->stack_slots) {
        for (unsigned i = 0u; i < duct_coro_cycle_quota; ++i) {
            auto co = duct_coro_queue_next(&cp->queue);
            if (!co)
                break;
            ++stepped;
            duct_coro_resume(co);
            if (co->on_resume) {
                co->on_resume(co, co->on_resume_ctx);
                if (co->state == coro_state_done)
                    duct_coro_release(&cp->pool, co);
            } else {
                if (co->state == coro_state_done)
                    duct_coro_release(&cp->pool, co);
                else
                    duct_coro_queue_put(&cp->queue, co);
            }
        }
    }

    if (cp->async_slots) {
        for (unsigned i = 0u; i < duct_async_cycle_quota; ++i) {
            auto co = duct_async_queue_next(&cp->async_queue);
            if (!co)
                break;
            ++stepped;
            auto rc = co->step(co->state);
            if (co->on_done) {
                co->on_done(co, rc, co->on_done_ctx);
                if (rc == async_done)
                    duct_async_release(&cp->async_pool, co);
            } else
                switch (rc) {
                case async_done:
                    duct_async_release(&cp->async_pool, co);
                    break;
                case async_yield:
                    duct_async_queue_enqueue(&cp->async_queue, co, coop_run);
                    break;
                case async_wait:
                    duct_async_queue_enqueue(&cp->async_queue, co, coop_wait);
                    break;
                case async_count:
                    duct_unreachable();
                }
        }
    }
    return stepped;
}

void duct_coop_wake(duct_coop_t *cp, duct_coro_t *coro)
{
    duct_do_if(!cp->open, return);
    if (cp->stack_slots)
        duct_coro_queue_wake(&cp->queue, coro);
}
