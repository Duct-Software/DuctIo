/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file session_pool_stress.c
 * @brief Isolate the session-pool alloc/free/close/resolve/drain race from io/engine.
 *
 * N hammer threads + two independent drainers hammer one shared session pool:
 *   - alloc (Treiber pop + leg-array alloc)
 *   - resolve with correct + wrong generation (gen-guard check)
 *   - both release paths: duct_session_release (direct quarantine, rollback
 *     semantics) and duct_session_request_close (closing → quarantine, the real
 *     production close path with the EBR grace window)
 *   - two drainers advance separate epoch counters + call drain_quarantine, so
 *     closing→quarantine and quarantine→free race on the same slot across
 *     drain_epoch values — the exact window that the pre-CAS until publication
 *     + monotonic max must close
 * All paths feed the same free stack that alloc pops from. Detects:
 *   - double-acquire (two threads holding the same slot) via gen re-read
 *   - stale proto, proto_state, flags or per-leg counters after reuse (acquire
 *     must reset every one of them)
 *   - gen-guard violation (resolve with wrong gen returns non-null)
 *   - leak (final stack not full) or duplicate (final stack has repeats)
 * No io threads, no epoll, no real protocol callbacks (proto stays null so the
 * close path fires no callback). Mirrors @c conn_pool_stress.c.
 *
 * A last single-threaded step gives a protocol a close callback, releases one
 * session through the rollback path and leaves another attached, then runs the
 * shutdown walk: it fires the attached session's close and the released one's
 * never, that session's open having never run.
 */

#include "duct_session.h"

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
static constexpr unsigned drain_iters   = stress_iters / 2u;

/** @brief Counters block of a freshly acquired session slot. */
static const duct_conn_counters_t s_no_counts[duct_session_max_legs] = {};

static atomic_uint s_double_acquire = 0u;
static atomic_uint s_stale_reset    = 0u;
static atomic_uint s_gen_guard_hit  = 0u;
static atomic_uint s_acquire_fail   = 0u;
static atomic_uint s_drain_epoch_a  = 0u;
static atomic_uint s_drain_epoch_b  = 0u;
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
    auto live = duct_session_acquire();
    auto dead = duct_session_acquire();
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
        auto s = duct_session_acquire();
        if (!s) {
            duct_atomic_fetch(add, &s_acquire_fail, 1u, relaxed);
            continue;
        }
        /* Acquire must reset proto, proto_state, flags and the counters block.
           The flags check catches a stale fl_session_teardown_done left by the
           close path; the marker written into the counters below reaches the
           slot's next acquirer if the block is not zeroed. */
        auto flags = duct_atomic_load(&s->flags, relaxed);
        auto counts = duct_session_counters(s);
        bool dirty = memcmp(counts, s_no_counts, sizeof s_no_counts) != 0;
        if (s->proto != nullptr || s->proto_state != nullptr || flags != 0u || dirty) {
            fprintf(stderr, "sess_stress: tid=%u sid=%u stale reset "
                            "(proto=%p proto_state=%p conns=%p flags=%u counters dirty=%d)\n",
                    tid, s->session_id, (const void *)s->proto,
                    s->proto_state, (const void *)s->conns, flags, dirty);
            duct_atomic_fetch(add, &s_stale_reset, 1u, relaxed);
        }
        counts[tid % duct_session_max_legs].tx_refused = i + 1u;
        uint32_t my_gen = duct_atomic_load(&s->generation, acquire);
        duct_session_id_t sid = s->session_id;
        s->proto_state = (void *)(uintptr_t)(tid + 1u);

        /* Resolve with the wrong generation must never succeed. */
        auto bad = duct_session_by_handle((duct_session_handle_t){
            .id = sid, .gen = my_gen + 1u,
        });
        if (bad != nullptr)
            duct_atomic_fetch(add, &s_gen_guard_hit, 1u, relaxed);

        /* Re-read gen; a change means another thread acquired this slot. */
        uint32_t cur_gen = duct_atomic_load(&s->generation, acquire);
        if (cur_gen != my_gen)
            duct_atomic_fetch(add, &s_double_acquire, 1u, relaxed);

        /* Clear the marker, then alternate release paths so the closing→
           quarantine transition is exercised under concurrent drain. proto is
           null, so request_close fires no on_session_close callback. */
        s->proto_state = nullptr;
        if (i & 1u)
            duct_session_release(s);
        else
            duct_session_request_close(s, close_normal);
    }
    return nullptr;
}

static void *s_drainer(void *arg)
{
    auto counter = (atomic_uint *)arg;
    struct timespec ts = { .tv_nsec = 100L };
    for (unsigned i = 0u; i < drain_iters; ++i) {
        uint64_t ep = duct_atomic_fetch(add, counter, 1u, relaxed) + 1u;
        duct_sessions_reclaim(ep);
        nanosleep(&ts, nullptr);
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
    pthread_t drainer_a, drainer_b;
    pthread_create(&drainer_a, nullptr, s_drainer, &s_drain_epoch_a);
    pthread_create(&drainer_b, nullptr, s_drainer, &s_drain_epoch_b);
    pthread_t th[stress_threads];
    for (unsigned i = 0u; i < stress_threads; ++i)
        pthread_create(&th[i], nullptr, s_hammer, (void *)(uintptr_t)i);
    for (unsigned i = 0u; i < stress_threads; ++i)
        pthread_join(th[i], nullptr);
    pthread_join(drainer_a, nullptr);
    pthread_join(drainer_b, nullptr);
    atomic_store(&s_done, true);

    unsigned da = duct_atomic_load(&s_double_acquire, acquire);
    unsigned sr = duct_atomic_load(&s_stale_reset, acquire);
    unsigned gg = duct_atomic_load(&s_gen_guard_hit, acquire);
    unsigned af = duct_atomic_load(&s_acquire_fail, acquire);

    /* Final invariant: drain every remaining closing/quarantined slot at
       near-max epoch, then the free stack must yield every slot exactly once.
       A leak (drain push broken) surfaces as a missing idx; a double-push as
       a dup. Two drains cover both the closing and quarantine tail. */
    duct_sessions_reclaim(UINT64_MAX - 1u);
    duct_sessions_reclaim(UINT64_MAX - 1u);
    unsigned seen = 0u;
    bool idx_seen[duct_max_conns] = {};
    for (;;) {
        auto s = duct_session_acquire();
        if (!s)
            break;
        unsigned idx = s->session_id;
        if (idx_seen[idx]) {
            fprintf(stderr, "sess_stress: FAIL duplicate idx %u in final stack\n", idx);
            return 1;
        }
        idx_seen[idx] = true;
        ++seen;
        /* alloc gave us a leg array; return it via the rollback path. */
        duct_session_release(s);
    }
    duct_sessions_reclaim(UINT64_MAX - 1u);

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
    if (seen != duct_max_conns) {
        fprintf(stderr, "sess_stress: FAIL final stack=%u expected=%u (leak)\n",
                seen, duct_max_conns);
        return 1;
    }
    unsigned closes = s_shutdown_closes();
    if (closes != 1u) {
        fprintf(stderr, "sess_stress: FAIL the shutdown walk fired %u close callbacks, "
                        "expected 1: the attached session's alone\n", closes);
        return 1;
    }
    /* acquire_fail is a transient pile-up signal (free stack momentarily empty
       while slots sit in closing/quarantine awaiting drain), not a bug. */
    printf("sess_stress: OK (%u threads x %u iters, 2 drainers, closing+rollback, "
           "no double-acquire, final stack=%u, transient fail=%u, shutdown closes "
           "the attached session alone)\n",
           stress_threads, stress_iters, seen, af);
    return 0;
}
