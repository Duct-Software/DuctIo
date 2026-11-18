/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file session_pool_stress.c
 * @brief Isolate the session-pool alloc/release/close machine from io/engine.
 *
 * N hammer threads race the pool's shared face alone — the free bitmap:
 *   - acquire (block take + body/page-0 reset) with the thread's own
 *     worker_id, the id stored inside the acquire
 *   - resolve with correct + wrong generation (gen-guard check)
 *   - the rollback path: duct_session_release returns the block straight to
 *     the pool, no worker list, no epoch
 * The closing path is owner-side by contract, so the close arm runs
 * exclusively on each slot's holder: request_close drives the state merge
 * (attached → closing → dead, the flags byte folded into the enum), the
 * dead session's token must stop resolving, and duct_session_dead_tick
 * counts the grace down before the block returns.
 * A last single-threaded step gives a protocol a close callback, releases
 * one session through the rollback path and leaves another attached, then
 * runs the shutdown walk over the free bitmap's complement: it fires the
 * attached session's close and the released one's never, that session's
 * open having never run.
 */

#include "duct_session.h"
#include "duct_session_block.h"

#include <limits.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

static constexpr unsigned stress_threads = 16u;
static constexpr unsigned stress_iters  = 50000u;

/** @brief Counters block of a freshly acquired session slot. */
static const duct_conn_counters_t s_no_counts[duct_session_max_legs] = {};

static atomic_uint s_double_acquire = 0u;
static atomic_uint s_stale_reset    = 0u;
static atomic_uint s_gen_guard_hit  = 0u;
static atomic_uint s_acquire_fail   = 0u;
static atomic_uint s_dead_early     = 0u;
static atomic_uint s_grace_wrong    = 0u;
static atomic_bool s_done           = false;
static atomic_uint s_closes_fired   = 0u;

static void s_note_close([[maybe_unused]] duct_session_t *s,
                         [[maybe_unused]] duct_close_reason_t reason,
                         [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &s_closes_fired, 1u, relaxed);
}

static duct_result_t s_ignore_frame([[maybe_unused]] duct_session_t *s,
                                    [[maybe_unused]] duct_conn_id_t conn_id,
                                    [[maybe_unused]] const duct_frame_t *frame,
                                    [[maybe_unused]] duct_response_t *out,
                                    [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

/** @brief Close callbacks the shutdown walk fires for one attached session and one rolled back.
 *  @return UINT_MAX when the protocol did not build. */
static unsigned s_shutdown_closes(void)
{
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "pool-shutdown", .wire = wire, .on_frame = s_ignore_frame,
        .on_session_close = s_note_close,
    });
    if (!proto) {
        duct_wire_destroy(wire);
        return UINT_MAX;
    }
    proto->owned_wire = wire;
    auto live = duct_session_acquire(0u);
    auto dead = duct_session_acquire(0u);
    if (!live || !dead)
        return UINT_MAX;
    live->proto = proto;
    dead->proto = proto;
    duct_session_release(dead);
    duct_sessions_reclaim_shutdown();
    duct_proto_destroy(proto);
    return duct_atomic_load(&s_closes_fired, acquire);
}

static void *s_hammer(void *arg)
{
    unsigned tid = (unsigned)(uintptr_t)arg;
    for (unsigned i = 0u; i < stress_iters; ++i) {
        auto s = duct_session_acquire(tid % duct_runtime_max_workers);
        if (!s) {
            duct_atomic_fetch(add, &s_acquire_fail, 1u, relaxed);
            continue;
        }
        /* Acquire must reset proto, proto_state, flags and the counters block.
           The flags check catches a stale fl_session_multiplexed left by a
           multiplexed life; the marker written into the counters below
           reaches the slot's next acquirer if the block reset misses it. */
        bool dirty = memcmp(duct_session_counters(s), s_no_counts,
                            sizeof s_no_counts) != 0;
        if (s->proto != nullptr || s->proto_state != nullptr
            || s->flags != fl_session_none || dirty) {
            fprintf(stderr, "sess_stress: tid=%u sid=%u stale reset "
                            "(proto=%p proto_state=%p flags=%u counters dirty=%d)\n",
                    tid, duct_session_idx_get(s), (const void *)s->proto,
                    s->proto_state, (unsigned)s->flags, dirty);
            duct_atomic_fetch(add, &s_stale_reset, 1u, relaxed);
        }
        duct_session_counters(s)[tid % duct_session_max_legs].tx_refused = i + 1u;
        uint32_t my_gen = duct_atomic_load(&s->generation, acquire);
        duct_session_id_t sid = duct_session_idx_get(s);
        s->proto_state = (void *)(uintptr_t)(tid + 1u);

        /* Resolve with the wrong generation must never succeed. */
        auto bad = duct_session_by_handle((duct_session_handle_t){
            .id = sid, .gen = my_gen + 1u,
        });
        if (bad != nullptr)
            duct_atomic_fetch(add, &s_gen_guard_hit, 1u, relaxed);

        /* Re-read gen; a change means another thread acquired this slot. */
        if (duct_atomic_load(&s->generation, acquire) != my_gen)
            duct_atomic_fetch(add, &s_double_acquire, 1u, relaxed);

        s->proto_state = nullptr;
        if (i & 1u) {
            duct_session_release(s);
            continue;
        }
        /* The owner-shaped close arm, exclusive on this thread's slot: the
           state merge runs attached → closing → dead with no flags byte, a
           token captured live must stop resolving in dead, and the grace
           counts down before the block returns. */
        auto tok = duct_session_handle_from_live(s);
        duct_session_request_close(s, close_normal);
        if (duct_session_by_handle(tok) != nullptr) {
            fprintf(stderr, "sess_stress: tid=%u a dead session's token resolved\n", tid);
            duct_atomic_fetch(add, &s_dead_early, 1u, relaxed);
        }
        if (duct_session_dead_tick(s) || duct_session_dead_tick(s))
            duct_atomic_fetch(add, &s_grace_wrong, 1u, relaxed);
        if (!duct_session_dead_tick(s))
            duct_atomic_fetch(add, &s_grace_wrong, 1u, relaxed);
    }
    return nullptr;
}

/** @brief Portable hang guard: a plain thread, not SIGALRM/alarm() (no MinGW
 *  equivalent) — same 10s budget and behavior on every platform. */
static void *s_watchdog([[maybe_unused]] void *arg)
{
    struct timespec ts = { .tv_sec = 10 };
    nanosleep(&ts, nullptr);
    if (!atomic_load(&s_done)) {
        fprintf(stderr, "sess_stress: timeout — hung pool\n");
        _Exit(2);
    }
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    pthread_t watchdog;
    pthread_create(&watchdog, nullptr, s_watchdog, nullptr);
    pthread_detach(watchdog);
    pthread_t th[stress_threads];
    for (unsigned i = 0u; i < stress_threads; ++i)
        pthread_create(&th[i], nullptr, s_hammer, (void *)(uintptr_t)i);
    for (unsigned i = 0u; i < stress_threads; ++i)
        pthread_join(th[i], nullptr);
    atomic_store(&s_done, true);

    unsigned da = duct_atomic_load(&s_double_acquire, acquire);
    unsigned sr = duct_atomic_load(&s_stale_reset, acquire);
    unsigned gg = duct_atomic_load(&s_gen_guard_hit, acquire);
    unsigned af = duct_atomic_load(&s_acquire_fail, acquire);
    unsigned de = duct_atomic_load(&s_dead_early, acquire);
    unsigned gw = duct_atomic_load(&s_grace_wrong, acquire);

    /* Final invariant: the shutdown walk returns every block still held,
       then the pool must yield every slot exactly once — held, so the
       rollback release cannot hand the same warm block straight back. A
       leak surfaces as a missing idx; a double-return as a dup. */
    duct_sessions_reclaim_shutdown();
    unsigned seen = 0u;
    auto held = (duct_session_t **)calloc(duct_max_conns, sizeof(duct_session_t *));
    bool idx_seen[duct_max_conns] = {};
    if (!held)
        return 1;
    for (;;) {
        auto s = duct_session_acquire(0u);
        if (!s)
            break;
        unsigned idx = duct_session_idx_get(s);
        if (idx_seen[idx]) {
            fprintf(stderr, "sess_stress: FAIL duplicate idx %u in final pool\n", idx);
            return 1;
        }
        idx_seen[idx] = true;
        held[seen++] = s;
    }
    for (unsigned i = 0u; i < seen; ++i)
        duct_session_release(held[i]);
    free(held);
    duct_sessions_reclaim_shutdown();

    if (da != 0u) {
        fprintf(stderr, "sess_stress: FAIL double_acquire=%u\n", da);
        return 1;
    }
    if (sr != 0u) {
        fprintf(stderr, "sess_stress: FAIL stale_reset=%u\n", sr);
        return 1;
    }
    if (gg != 0u) {
        fprintf(stderr, "sess_stress: FAIL gen_guard_hit=%u\n", gg);
        return 1;
    }
    if (de != 0u) {
        fprintf(stderr, "sess_stress: FAIL dead_early=%u\n", de);
        return 1;
    }
    if (gw != 0u) {
        fprintf(stderr, "sess_stress: FAIL grace_wrong=%u\n", gw);
        return 1;
    }
    if (seen != duct_max_conns) {
        fprintf(stderr, "sess_stress: FAIL final pool=%u expected=%u (leak)\n",
                seen, duct_max_conns);
        return 1;
    }
    unsigned closes = s_shutdown_closes();
    if (closes != 1u) {
        fprintf(stderr, "sess_stress: FAIL the shutdown walk fired %u close callbacks, "
                        "expected 1: the attached session's alone\n", closes);
        return 1;
    }
    /* acquire_fail is a transient pile-up signal (free bitmap momentarily
       empty while slots sit dead awaiting their grace), not a bug. */
    printf("sess_stress: OK (%u threads x %u iters, rollback + owner close with "
           "grace ticks, no double-acquire, final pool=%u, transient fail=%u, "
           "shutdown closes the attached session alone)\n",
           stress_threads, stress_iters, seen, af);
    return 0;
}
