/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file ticks_test.c
 *  @brief The tick clocks over a simulated TSC and kernel clocks, around one step of the wall clock.
 *
 *  The test replaces clock_gettime and the TSC: simulated time runs the TSC at three ticks a
 *  nanosecond, CLOCK_MONOTONIC reads that time and CLOCK_REALTIME adds an offset each case steps
 *  once. A case reads both tick clocks at a fixed period for 3 s and steps the wall clock at 1 s.
 *  It expects the monotonic tick clock within 1 us of the kernel's throughout, and the wall tick
 *  clock never going back, never past the higher of the wall clock's two timelines, and level with
 *  the kernel's once a window has passed the step and the kernel's clock has passed every reading
 *  given; a read sparser than the window is level at once. Linux only.
 */

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#if defined(__x86_64__)
#include <x86intrin.h>
#endif

/** @brief Simulated time, ns: CLOCK_MONOTONIC, and the TSC at three ticks a nanosecond. */
static uint64_t g_ns = 100'000'000'000u;
/** @brief CLOCK_REALTIME less CLOCK_MONOTONIC, ns, modulo 2^64. */
static uint64_t g_wall = 1'700'000'000'000'000'000u;

#if defined(__x86_64__)
static uint64_t s_tsc(void)
{
    return g_ns * 3u;
}
#define __rdtsc s_tsc
#endif

int clock_gettime(clockid_t clk, struct timespec *ts)
{
    uint64_t v = g_ns + (clk == CLOCK_REALTIME ? g_wall : 0u);
    *ts = (struct timespec){ .tv_sec = (time_t)(v / 1'000'000'000u), .tv_nsec = (long)(v % 1'000'000'000u) };
    return 0;
}

#include "duct_ticks.h"

/** @brief Return @p msg from the calling check when @p cond fails. */
#define expect(cond, msg) do { if (!(cond)) return msg; } while (0)

/** @brief Slack every comparison with a kernel clock takes, ns. */
static constexpr uint64_t s_slack_ns = 1000u;

/** @brief Read both tick clocks every @p period_ns for 3 s, stepping the wall clock by @p step_ns at 1 s.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *s_case(uint64_t period_ns, int64_t step_ns)
{
    uint64_t start = g_ns, step_at = start + 1'000'000'000u, old = g_wall, prev = 0u,
             settle = period_ns >= duct_tickclock_window_ns ? 0u : duct_tickclock_window_ns + period_ns;
    for (; g_ns < start + 3'000'000'000u; g_ns += period_ns) {
        if (g_ns >= step_at && g_ns < step_at + period_ns)
            g_wall += (uint64_t)step_ns;
        uint64_t mono = duct_ticks_mono_ns(), wall = duct_ticks_wall_ns(), kwall = g_ns + g_wall,
                 high = g_ns + (step_ns < 0 ? old : g_wall);
        bool settled = g_ns < step_at || g_ns >= step_at + settle;
        expect(mono + s_slack_ns >= g_ns && mono <= g_ns + s_slack_ns, "the monotonic tick clock leaves the kernel's");
        expect(wall >= prev, "the wall tick clock goes back");
        expect(wall <= high + s_slack_ns, "the wall tick clock runs ahead of the wall clock's higher timeline");
        if (settled && kwall + s_slack_ns >= prev)
            expect(wall + s_slack_ns >= kwall && wall <= kwall + s_slack_ns,
                   "the wall tick clock is not level with the kernel's once it settles");
        prev = wall;
    }
    return nullptr;
}

int main(void)
{
    static const struct { const char *name; uint64_t period_ns; int64_t step_ns; } cases[] = {
        { "a 0.5 s step forward, a read every 100 us", 100'000u,     500'000'000 },
        { "a 2.9 s step forward, a read every 1 ms",   1'000'000u,   2'900'000'000 },
        { "a 0.5 s step back, a read every 100 us",    100'000u,     -500'000'000 },
        { "a 0.5 s step forward, a read every 100 ms", 100'000'000u, 500'000'000 },
    };
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        auto err = s_case(cases[i].period_ns, cases[i].step_ns);
        if (err) {
            fprintf(stderr, "ticks: %s: %s\n", cases[i].name, err);
            return 1;
        }
    }
    printf("ticks: OK\n");
    return 0;
}
