/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file bench_wake.c
 * @brief Price of parking: signal-to-resume latency as a function of idle gap.
 *
 * The spin-before-park window is only defensible if it sits above what a park
 * actually costs, and that cost is not one number — it grows with how long the
 * waiter's core has been idle. So the gap is swept rather than fixed, and the
 * result is a curve: idle for G, pay W(G) to wake. Spinning through G pays off
 * exactly while G < W(G).
 *
 * Two kicker shapes bracket reality. Spinning keeps the package awake, which
 * is what the engine's own always-busy producer does; sleeping lets it descend
 * and gives the upper bound. Deliberately no warm-up kicks: they would hold
 * the core hot and report the optimistic case, which is the one measurement
 * error that would make a too-small window look justified.
 *
 * Uses the engine's own duct_futex_wait/wake, so it prices what the engine
 * pays rather than a hand-rolled equivalent. Touches no engine code.
 */

#include "duct_core.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static inline uint64_t s_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static _Atomic(uint32_t) s_latch = 0u;
static _Atomic(uint32_t) s_ready = 0u;
static _Atomic(uint64_t) s_signal_ns = 0u;
static _Atomic(bool)     s_stop = false;

static uint64_t *s_wake_ns;
static uint64_t *s_gap_ns;
static uint32_t  s_n;
static _Atomic(uint32_t) s_taken = 0u;

typedef struct {
    unsigned cpu;
    bool     pin;
} thread_arg_t;

static void *s_waiter(void *arg)
{
    auto ta = (thread_arg_t *)arg;
    if (ta->pin)
        duct_discard duct_thread_bind_cpu(ta->cpu);
    while (!duct_atomic_load(&s_stop, acquire)) {
        duct_atomic_store(&s_ready, 1u, release);
        while (!duct_atomic_load(&s_latch, acquire)) {
            if (duct_atomic_load(&s_stop, acquire))
                return nullptr;
            duct_discard duct_futex_wait((void *)&s_latch, 0u, 50u);
        }
        uint64_t t1 = s_now_ns();
        uint32_t i = duct_atomic_fetch(add, &s_taken, 1u, relaxed);
        if (i < s_n)
            s_wake_ns[i] = t1 - duct_atomic_load(&s_signal_ns, acquire);
        duct_atomic_store(&s_latch, 0u, release);
    }
    return nullptr;
}

static int s_u64_cmp(const void *a, const void *b)
{
    uint64_t va = *(const uint64_t *)a,
             vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

static void s_report(const char *label, uint64_t target_gap)
{
    uint32_t n = duct_atomic_load(&s_taken, relaxed);
    if (n > s_n)
        n = s_n;
    if (!n) {
        printf("    %-10s no samples\n", label);
        return;
    }
    qsort(s_gap_ns, n, sizeof(uint64_t), s_u64_cmp);
    uint64_t gap_med = s_gap_ns[n / 2u];
    qsort(s_wake_ns, n, sizeof(uint64_t), s_u64_cmp);
    printf("    gap=%-7llu actual_gap_p50=%-8llu  wake p50=%-7llu p99=%-8llu p99.9=%-8llu max=%llu\n",
           (unsigned long long)target_gap, (unsigned long long)gap_med,
           (unsigned long long)s_wake_ns[n / 2u],
           (unsigned long long)s_wake_ns[(uint64_t)n * 99u / 100u],
           (unsigned long long)s_wake_ns[(uint64_t)n * 999u / 1000u],
           (unsigned long long)s_wake_ns[n - 1u]);
}

static void s_gap_spin(uint64_t deadline)
{
    while (s_now_ns() < deadline)
        ;
}

static void s_gap_sleep(uint64_t ns)
{
    struct timespec ts = { .tv_sec = (time_t)(ns / 1000000000ull),
                           .tv_nsec = (long)(ns % 1000000000ull) };
    nanosleep(&ts, nullptr);
}

/** @brief One sweep point: @p count kicks separated by @p gap_ns, with the
 *  kicker either spinning (package stays awake) or sleeping (it descends). */
static void s_sweep_point(uint64_t gap_ns, bool spin_gap)
{
    duct_atomic_store(&s_taken, 0u, relaxed);
    for (uint32_t i = 0u; i < s_n; ++i) {
        /* Wait for the waiter to be back at its park point before timing the
         * gap, so the gap is the waiter's idle time and not ours. */
        while (!duct_atomic_load(&s_ready, acquire))
            duct_cpu_relax();
        duct_atomic_store(&s_ready, 0u, relaxed);

        uint64_t start = s_now_ns();
        if (spin_gap)
            s_gap_spin(start + gap_ns);
        else
            s_gap_sleep(gap_ns);
        uint64_t t0 = s_now_ns();
        s_gap_ns[i] = t0 - start;

        duct_atomic_store(&s_signal_ns, t0, release);
        duct_atomic_store(&s_latch, 1u, release);
        duct_futex_wake((void *)&s_latch, 1);

        while (duct_atomic_load(&s_latch, acquire))
            duct_cpu_relax();
    }
}

int main(int argc, char **argv)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    s_n = 20000u;
    bool pin = true;
    unsigned cpu_waiter = 2u,
             cpu_kicker = 4u;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--samples") && i + 1 < argc)
            s_n = (uint32_t)strtoul(argv[++i], nullptr, 10);
        else if (!strcmp(argv[i], "--no-pin"))
            pin = false;
        else if (!strcmp(argv[i], "--cpus") && i + 2 < argc) {
            cpu_waiter = (unsigned)strtoul(argv[++i], nullptr, 10);
            cpu_kicker = (unsigned)strtoul(argv[++i], nullptr, 10);
        } else {
            fprintf(stderr, "usage: %s [--samples N] [--no-pin] [--cpus WAITER KICKER]\n", argv[0]);
            return 2;
        }
    }

    s_wake_ns = (uint64_t *)calloc(s_n, sizeof(uint64_t));
    s_gap_ns = (uint64_t *)calloc(s_n, sizeof(uint64_t));
    duct_do_if(!s_wake_ns || !s_gap_ns, fprintf(stderr, "bench_wake: alloc failed\n"); return 1);

    thread_arg_t wa = { .cpu = cpu_waiter, .pin = pin };
    pthread_t waiter;
    duct_do_if(pthread_create(&waiter, nullptr, s_waiter, &wa) != 0,
        fprintf(stderr, "bench_wake: waiter spawn failed\n"); return 1);
    if (pin)
        duct_discard duct_thread_bind_cpu(cpu_kicker);

    printf("bench_wake: samples=%u pin=%s (waiter cpu%u, kicker cpu%u)\n",
           s_n, pin ? "yes" : "no", cpu_waiter, cpu_kicker);
    printf("  all times in ns\n\n");

    static const uint64_t gaps[] = { 1000ull, 10000ull, 100000ull, 1000000ull, 10000000ull };
    constexpr unsigned n_gaps = sizeof gaps / sizeof gaps[0];

    printf("  kicker spinning — package stays awake, matches an engine with a busy producer\n");
    for (unsigned g = 0u; g < n_gaps; ++g) {
        s_sweep_point(gaps[g], true);
        s_report("spin", gaps[g]);
    }

    /* nanosleep resolution is coarse (tens of us on Linux, ~1 ms on Windows
     * without timeBeginPeriod), so the short gaps are unreachable here — the
     * printed actual_gap says what was really achieved. */
    printf("\n  kicker sleeping — package descends, upper bound\n");
    for (unsigned g = 2u; g < n_gaps; ++g) {
        s_sweep_point(gaps[g], false);
        s_report("sleep", gaps[g]);
    }

    duct_atomic_store(&s_stop, true, release);
    duct_atomic_store(&s_latch, 1u, release);
    duct_futex_wake((void *)&s_latch, 1);
    pthread_join(waiter, nullptr);
    free(s_wake_ns);
    free(s_gap_ns);
    return 0;
}
