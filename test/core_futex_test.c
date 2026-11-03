/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file core_futex_test.c
 * @brief Contract test for @c duct_futex_wait / @c duct_futex_wake.
 *
 * Every backend implements these primitives differently: @c SYS_futex on Linux,
 * @c WaitOnAddress on Windows, @c os_sync_wait_on_address on Darwin. They also sit on the
 * thread-start rendezvous and the worker wake path, so a subtly wrong port
 * shows up as an occasional hang somewhere else entirely rather than as a
 * failure here — which is exactly why the contract is worth pinning down on
 * its own.
 *
 * The cases cover the documented contract:
 *   1. @c *addr already differs from @p expected  -> true, without parking
 *   2. nothing wakes it inside @p timeout_ms      -> false, having waited
 *   3. a waker publishes and wakes                -> true, under an infinite wait
 *   4. @c count > 1 and wake-all sentinel         -> every parked waiter released
 *
 * A spurious wake is legal, so each
 * case re-checks its predicate and re-parks the way a real caller does —
 * @c duct_thread_started_wait is the model.
 */

#include "duct.h"
#include "duct_ticks.h"
#include "test_helpers.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>

static constexpr unsigned n_parkers = 4u;

/* ── 1. mismatch returns without parking ──────────────────────────── */

static const char *tc_no_park(void)
{
    unsigned _Atomic w = 7u;
    auto t0 = duct_ticks_mono_ns();
    bool r = duct_futex_wait(&w, 0u, 5000u);
    auto elapsed_ms = (duct_ticks_mono_ns() - t0) / 1000000ull;

    if (!r)
        return "wait on an already-differing word reported a timeout";
    if (elapsed_ms > 1000ull)
        return "wait on an already-differing word parked instead of returning";
    return nullptr;
}

/* ── 2. timeout returns false, and actually waits ─────────────────── */

static const char *tc_timeout(void)
{
    unsigned _Atomic w = 0u;
    constexpr uint32_t want_ms = 150u;
    /* 10% slack: coarse timer resolution can trim a few ms off legitimately. */
    constexpr uint64_t floor_ns = (uint64_t)want_ms * 900000ull;

    auto t0 = duct_ticks_mono_ns();
    bool timed_out = false;
    for (unsigned attempt = 0u; attempt < 8u && !timed_out; ++attempt) {
        auto spent_ms = (duct_ticks_mono_ns() - t0) / 1000000ull;
        if (spent_ms >= (uint64_t)want_ms)
            break;
        timed_out = !duct_futex_wait(&w, 0u, want_ms - (uint32_t)spent_ms);
    }
    auto elapsed_ns = duct_ticks_mono_ns() - t0;

    if (!timed_out)
        return "wait never reported a timeout on a word that nobody touched";
    if (elapsed_ns < floor_ns)
        return "wait reported a timeout well before the requested window";
    return nullptr;
}

/* ── 3. a wake releases an infinite wait ──────────────────────────── */

typedef struct {
    unsigned _Atomic *w;
    unsigned          delay_ms;
} waker_arg_t;

static void *s_waker(void *arg)
{
    auto a = (waker_arg_t *)arg;
    th_sleep_ms(a->delay_ms);
    duct_atomic_store(a->w, 1u, release);   /* publish before waking */
    duct_futex_wake(a->w, 1u);
    return nullptr;
}

static const char *tc_wake_one(void)
{
    unsigned _Atomic w = 0u;
    waker_arg_t arg = { .w = &w, .delay_ms = 60u };
    pthread_t th;
    if (pthread_create(&th, nullptr, s_waker, &arg) != 0)
        return "waker thread create failed";

    /* Predicate-first, so a wake that lands before this parks is not lost:
     * the wait would return true on the mismatch anyway, but the loop is
     * what makes that guaranteed rather than incidental. */
    bool ok = true;
    while (duct_atomic_load(&w, acquire) == 0u)
        if (!duct_futex_wait(&w, 0u, DUCT_TIMEOUT_INFINITE)) {
            ok = false;                     /* infinite must never time out */
            break;
        }
    pthread_join(th, nullptr);

    if (!ok)
        return "an infinite wait reported a timeout";
    if (duct_atomic_load(&w, acquire) != 1u)
        return "wait returned but the waker's store was not visible";
    return nullptr;
}

/* ── 4. count > 1 releases every waiter ───────────────────────────── */

static unsigned _Atomic g_word  = 0u;
static atomic_uint      g_awake = 0u;
static atomic_uint      g_entered = 0u;

static void *s_parker([[maybe_unused]] void *arg)
{
    duct_atomic_fetch(add, &g_entered, 1u, release);
    while (duct_atomic_load(&g_word, acquire) == 0u)
        if (!duct_futex_wait(&g_word, 0u, 5000u))
            return nullptr;                 /* timed out: not counted awake */
    duct_atomic_fetch(add, &g_awake, 1u, relaxed);
    return nullptr;
}

static const char *s_wake_parkers(uint32_t count)
{
    duct_atomic_store(&g_word, 0u, release);
    duct_atomic_store(&g_awake, 0u, release);
    duct_atomic_store(&g_entered, 0u, release);

    pthread_t th[n_parkers];
    for (unsigned i = 0u; i < n_parkers; ++i)
        if (pthread_create(&th[i], nullptr, s_parker, nullptr) != 0)
            return "parker thread create failed";

    /* Each waiter must reach the wait loop before the publication. The
     * short settle time then exercises the parked path; the predicate loop
     * also covers a wake in the remaining pre-park window. */
    auto deadline = duct_ticks_mono_ns() + 1000000000ull;
    while (duct_atomic_load(&g_entered, acquire) != n_parkers
           && duct_ticks_mono_ns() < deadline)
        th_sleep_ms(1u);
    bool entered = duct_atomic_load(&g_entered, acquire) == n_parkers;
    if (entered)
        th_sleep_ms(25u);
    duct_atomic_store(&g_word, 1u, release);
    duct_futex_wake(&g_word, count);

    for (unsigned i = 0u; i < n_parkers; ++i)
        pthread_join(th[i], nullptr);

    if (!entered)
        return "not every waiter reached the wait loop before the deadline";

    if (duct_atomic_load(&g_awake, acquire) != n_parkers) {
        fprintf(stderr, "core_futex: only %u of %u waiters released\n",
                duct_atomic_load(&g_awake, acquire), n_parkers);
        return "a multi-count wake left waiters parked";
    }
    return nullptr;
}

static const char *tc_wake_many(void)
{
    return s_wake_parkers(n_parkers);
}

static const char *tc_wake_all(void)
{
    return s_wake_parkers(duct_futex_wake_all);
}

/** @brief The whole contract, once. */
static int s_run_cases(void)
{
    const struct { const char *name; const char *(*fn)(void); } cases[] = {
        { "mismatch returns without parking", tc_no_park  },
        { "timeout returns false",            tc_timeout  },
        { "wake releases an infinite wait",   tc_wake_one },
        { "count>1 releases every waiter",    tc_wake_many },
        { "wake-all releases every waiter",   tc_wake_all  },
    };

    for (unsigned i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        auto err = cases[i].fn();
        if (err) {
            fprintf(stderr, "core_futex: %s: %s\n", cases[i].name, err);
            return 1;
        }
        printf("core_futex: %s: ok\n", cases[i].name);
    }
    return 0;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    if (s_run_cases())
        return 1;
    printf("core_futex: OK (5/5)\n");
    return 0;
}
