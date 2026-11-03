/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file conn_pool_stress.c
 * @brief Isolate the conn-pool acquire/release race from session/io machinery.
 *
 * N threads hammer duct_conn_acquire/duct_conn_release on one shared pool:
 * release is unconditionally the fast path (generation bump + push onto the
 * FREE Treiber stack; see duct_conn.h's gen_req doc), which
 * is also the only list acquire pops from, so a race surfaces as two threads
 * holding the same slot concurrently (double acquire), detected by re-reading
 * generation before release. No io threads, no sessions, no epoll — pure pool.
 *
 * At rest @c duct_conns_free reads @c duct_max_conns and @c duct_conns_refused
 * equals the acquires that failed under contention. Drained, the free count is 0
 * and the one acquire that finds the stack empty adds a refusal; released, the
 * count is back to @c duct_max_conns.
 *
 * The pool is a hidden process-wide singleton: no pool handle to create or
 * pass, and no raw field access.
 */

#include "duct.h"
#include "duct_conn.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>

static constexpr unsigned stress_threads = 16u;
static constexpr unsigned stress_iters = 50000u;

static atomic_uint s_double_acquire = 0u;
static atomic_uint s_acquire_fail = 0u;
static atomic_bool s_done = false;

/** @brief Portable hang guard: a plain thread, not SIGALRM/alarm() (no MinGW
 *  equivalent) — same 5s budget and behavior on every platform. */
static void *s_watchdog([[maybe_unused]] void *arg)
{
    struct timespec ts = { .tv_sec = 5 };
    nanosleep(&ts, nullptr);
    if (!atomic_load(&s_done)) {
        fprintf(stderr, "\n[hang] pool internals are no longer inspectable "
                         "from here (hidden singleton)\n");
        _Exit(2);
    }
    return nullptr;
}

static void *s_hammer(void *arg)
{
    unsigned tid = (unsigned)(uintptr_t)arg;
    for (unsigned i = 0u; i < stress_iters; ++i) {
        auto conn = duct_conn_acquire();
        if (!conn) {
            duct_atomic_fetch(add, &s_acquire_fail, 1u, relaxed);
            continue;
        }
        uint64_t my_gen = duct_gen_req_gen(duct_atomic_load(duct_conn_gen_req(conn), acquire));
        uint64_t cur_gen = duct_gen_req_gen(duct_atomic_load(duct_conn_gen_req(conn), acquire));
        if (cur_gen != my_gen) {
            unsigned idx = duct_conn_idx_get(conn);
            fprintf(stderr, "pool_stress: tid=%u idx=%u my_gen=%llu cur_gen=%llu\n",
                    tid, idx, (unsigned long long)my_gen, (unsigned long long)cur_gen);
            duct_atomic_fetch(add, &s_double_acquire, 1u, relaxed);
        }
        duct_conn_release(conn);
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
    unsigned af = duct_atomic_load(&s_acquire_fail, acquire);

    /* Final invariant: the FREE stack must hold every conn exactly once. A
       leak (release path broken, lost slot) surfaces here as a missing or
       duplicate idx. */
    unsigned seen = 0u;
    duct_conn_t *held[duct_max_conns] = {};
    if (duct_conns_free() != duct_max_conns || duct_conns_refused() != af) {
        fprintf(stderr, "pool_stress: FAIL at rest free=%u refused=%llu, expected %u and %u\n",
                duct_conns_free(), (unsigned long long)duct_conns_refused(), duct_max_conns, af);
        return 1;
    }
    for (;;) {
        auto c = duct_conn_acquire();
        if (!c)
            break;
        unsigned idx = duct_conn_idx_get(c);
        if (held[idx]) {
            fprintf(stderr, "pool_stress: FAIL duplicate idx %u in final stack\n", idx);
            return 1;
        }
        held[idx] = c;
        ++seen;
    }

    if (da != 0u) {
        fprintf(stderr, "pool_stress: FAIL double_acquire=%u\n", da);
        return 1;
    }
    if (seen != duct_max_conns) {
        fprintf(stderr, "pool_stress: FAIL final stack=%u expected=%u (leak)\n",
                seen, duct_max_conns);
        return 1;
    }
    if (duct_conns_free() != 0u || duct_conns_refused() != af + 1u) {
        fprintf(stderr, "pool_stress: FAIL drained free=%u refused=%llu, expected 0 and %u\n",
                duct_conns_free(), (unsigned long long)duct_conns_refused(), af + 1u);
        return 1;
    }
    for (unsigned i = 0u; i < duct_max_conns; ++i)
        duct_conn_release(held[i]);
    if (duct_conns_free() != duct_max_conns) {
        fprintf(stderr, "pool_stress: FAIL released free=%u, expected %u\n",
                duct_conns_free(), duct_max_conns);
        return 1;
    }
    /* acquire_fail is a transient contention signal, not a correctness bug:
       stress_threads threads can momentarily hold every live slot between
       their own acquire and release. Logged for info only. */
    printf("pool_stress: OK (%u threads x %u iters, no double-acquire, "
           "final stack=%u, transient fail=%u)\n",
           stress_threads, stress_iters, seen, af);
    return 0;
}
