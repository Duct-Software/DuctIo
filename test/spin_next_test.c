/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file spin_next_test.c
 *  @brief The spin-before-park choice, driven by a synthetic clock.
 *
 *  duct_spin_next reads nothing but its state, the policy and the time it is
 *  handed, so each scenario sets the policy, plays a run of idle stretches, and
 *  asks whether the next empty poll spins and for how long.
 *
 *  Covers: a fresh state parking at once and work ending a stretch, short
 *  stretches opening the shortest window that covers them, stretches past one
 *  step picking the window above, stretches past every window parking, a run of
 *  long stretches turning a learned spin off, and a cutoff of 0 never spinning.
 */

#include "duct_time.h"

#include <stdio.h>

static constexpr uint64_t spin_window = 30000u;
static constexpr uint64_t spin_step = spin_window / (duct_spin_cands - 1u);

static void s_policy(uint64_t cutoff_ns)
{
    duct_spin_policy = (duct_spin_policy_t){ .window_ns = spin_window,
                                             .cutoff_ns = cutoff_ns };
}

static void s_stretches(duct_spin_state_t *ss, uint64_t *now, uint64_t idle,
                        unsigned n)
{
    for (unsigned i = 0u; i < n; ++i) {
        duct_discard duct_spin_next(ss, false, *now);
        *now += idle;
        duct_discard duct_spin_next(ss, true, *now);
        *now += 1000u;
    }
}

static const char *sc_fresh(void)
{
    s_policy(spin_window);
    duct_spin_state_t ss = {};
    if (duct_spin_next(&ss, false, 1000u))
        return "a fresh state spun before any stretch was scored";
    if (ss.idle_since_ns != 1000u)
        return "an empty poll did not start the stretch";
    if (!duct_spin_next(&ss, true, 2000u) || ss.idle_since_ns != 0u)
        return "work did not end the stretch and poll again";
    return nullptr;
}

static const char *sc_short(void)
{
    s_policy(spin_window);
    duct_spin_state_t ss = {};
    uint64_t now = 1u;
    s_stretches(&ss, &now, spin_step / 2u, 64u);
    if (!duct_spin_next(&ss, false, now)
        || !duct_spin_next(&ss, false, now + spin_step - 1u))
        return "short stretches did not open the shortest window covering them";
    if (duct_spin_next(&ss, false, now + spin_step))
        return "the spin ran past the window short stretches chose";
    return nullptr;
}

static const char *sc_middle(void)
{
    s_policy(spin_window);
    duct_spin_state_t ss = {};
    uint64_t now = 1u;
    s_stretches(&ss, &now, spin_step + spin_step / 2u, 64u);
    if (!duct_spin_next(&ss, false, now)
        || !duct_spin_next(&ss, false, now + 2u * spin_step - 1u))
        return "stretches past one step did not pick the window covering them";
    if (duct_spin_next(&ss, false, now + 2u * spin_step))
        return "the spin ran past the window covering the stretches";
    return nullptr;
}

static const char *sc_long(void)
{
    s_policy(spin_window);
    duct_spin_state_t ss = {};
    uint64_t now = 1u;
    s_stretches(&ss, &now, 100u * spin_window, 64u);
    if (duct_spin_next(&ss, false, now))
        return "stretches past every window still made the loop spin";
    return nullptr;
}

static const char *sc_adapt(void)
{
    s_policy(spin_window);
    duct_spin_state_t ss = {};
    uint64_t now = 1u;
    s_stretches(&ss, &now, spin_step / 2u, 64u);
    if (!duct_spin_next(&ss, false, now))
        return "short stretches did not make the loop spin";
    duct_discard duct_spin_next(&ss, true, now + 1u);
    now += 1000u;
    s_stretches(&ss, &now, 100u * spin_window, 64u);
    if (duct_spin_next(&ss, false, now))
        return "a run of long stretches did not turn the spin off";
    return nullptr;
}

static const char *sc_cutoff_zero(void)
{
    s_policy(0u);
    duct_spin_state_t ss = {};
    uint64_t now = 1u;
    s_stretches(&ss, &now, spin_step / 2u, 64u);
    if (duct_spin_next(&ss, false, now))
        return "a cutoff of 0 still spun";
    return nullptr;
}

typedef struct {
    const char *name;
    const char *(*run)(void);
} scenario_t;

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    static const scenario_t scenarios[] = {
        { "fresh",       sc_fresh },
        { "short",       sc_short },
        { "middle",      sc_middle },
        { "long",        sc_long },
        { "adapt",       sc_adapt },
        { "cutoff zero", sc_cutoff_zero },
    };
    for (size_t i = 0u; i < sizeof scenarios / sizeof scenarios[0]; ++i) {
        auto err = scenarios[i].run();
        if (err) {
            fprintf(stderr, "spin_next: %s: %s\n", scenarios[i].name, err);
            return 1;
        }
    }
    printf("spin_next: OK (%zu scenarios)\n", sizeof scenarios / sizeof scenarios[0]);
    return 0;
}
