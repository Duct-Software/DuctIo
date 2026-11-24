/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

#include "duct_pmtu.h"

#include <stdio.h>

static constexpr uint16_t eth = 1500u;
static constexpr uint16_t jumbo = 9000u;

static unsigned s_run_burst_sim(duct_pmtu_t *p, uint16_t truth)
{
    uint16_t rungs[duct_pmtu_burst_max];
    unsigned bursts = 0u;
    for (uint8_t n = duct_pmtu_burst(p, rungs); n; n = duct_pmtu_burst(p, rungs)) {
        if (++bursts > 16u)
            return bursts;
        uint16_t smallest_silent = 0u;
        bool lower_echo = false;
        for (uint8_t i = 0u; i < n; ++i)
            if (rungs[i] <= truth)
                duct_pmtu_ack(p, rungs[i]);
        for (uint8_t i = 0u; i < n; ++i) {
            if (rungs[i] > truth && rungs[i] > p->good
                && (!smallest_silent || rungs[i] < smallest_silent))
                smallest_silent = rungs[i];
            if (rungs[i] <= truth)
                lower_echo = true;
        }
        if (smallest_silent && (lower_echo || p->failed)) {
            bool any_lower = false;
            for (uint8_t i = 0u; i < n; ++i)
                if (rungs[i] <= truth && rungs[i] < smallest_silent)
                    any_lower = true;
            if (!p->failed || smallest_silent < p->failed) {
                p->failed = smallest_silent;
                p->failed_strikes = any_lower ? 1u : 0u;
            } else if (smallest_silent == p->failed && any_lower
                       && p->failed_strikes < duct_pmtu_fail_strikes_max)
                ++p->failed_strikes;
        }
    }
    return bursts;
}

static const char *sc_ceiling_first(void)
{
    duct_pmtu_t p;
    duct_pmtu_init(&p, duct_pmtu_base_min, eth);
    if (duct_pmtu_mtu(&p) != duct_pmtu_base_min)
        return "a fresh search does not start usable at its base";
    uint16_t rungs[duct_pmtu_burst_max];
    uint8_t n = duct_pmtu_burst(&p, rungs);
    if (n != 4u || rungs[0] != eth || rungs[n - 1u] != duct_pmtu_base_min)
        return "the initial coarse burst does not cover ceiling to floor";
    duct_pmtu_ack(&p, eth);
    if (duct_pmtu_mtu(&p) != eth || !duct_pmtu_done(&p) || duct_pmtu_burst(&p, rungs) != 0u)
        return "a ceiling that answers did not settle the search at once";
    return nullptr;
}

static const char *sc_silent_drop_converges(void)
{
    static constexpr uint16_t truth = 1380u;
    duct_pmtu_t p;
    duct_pmtu_init(&p, duct_pmtu_base_min, eth);
    unsigned bursts = s_run_burst_sim(&p, truth);
    uint16_t mtu = duct_pmtu_mtu(&p);
    if (bursts > 3u)
        return "silent drop convergence took more than 3 bursts";
    if (mtu > truth || truth - mtu > duct_pmtu_stop_gap)
        return "silent drop settled outside the 16-byte window";
    uint16_t rungs[duct_pmtu_burst_max];
    if (duct_pmtu_burst(&p, rungs) != 0u)
        return "a closed search still emits rungs";
    return nullptr;
}

static const char *sc_never_exceeds_truth(void)
{
    static constexpr uint16_t truth = 1387u;
    duct_pmtu_t p;
    duct_pmtu_init(&p, duct_pmtu_base_min, jumbo);
    unsigned bursts = s_run_burst_sim(&p, truth);
    if (bursts > 12u || duct_pmtu_mtu(&p) > truth || truth - duct_pmtu_mtu(&p) > duct_pmtu_stop_gap)
        return "wide range did not converge cleanly within 16 bytes of truth";
    return nullptr;
}

static const char *sc_flaky_rehab(void)
{
    duct_pmtu_t p;
    duct_pmtu_init(&p, duct_pmtu_base_min, eth);
    uint16_t rungs[duct_pmtu_burst_max];
    uint8_t n = duct_pmtu_burst(&p, rungs);
    if (n != 4u)
        return "expected 4 coarse rungs";
    duct_pmtu_ack(&p, 1232u);
    duct_pmtu_ack(&p, 1366u);
    p.failed = 1433u;
    p.failed_strikes = 1u;

    n = duct_pmtu_burst(&p, rungs);
    if (n != 4u || rungs[n - 1u] != 1433u)
        return "refine with 1 strike did not re-probe failed rung";
    for (uint8_t i = 0u; i < n; ++i)
        duct_pmtu_ack(&p, rungs[i]);
    if (p.good != 1433u || p.failed != 0u || p.failed_strikes != 0u)
        return "D1 did not rehabilitate the failed upper bound";

    n = duct_pmtu_burst(&p, rungs);
    if (n == 0u || rungs[0] != eth)
        return "rehabilitated search did not reopen coarse probing to ceiling";
    for (uint8_t i = 0u; i < n; ++i)
        duct_pmtu_ack(&p, rungs[i]);
    if (duct_pmtu_mtu(&p) != eth || !duct_pmtu_done(&p))
        return "rehabilitated search did not finish at ceiling in 3 bursts";
    return nullptr;
}

static const char *sc_hard_fail_cutoff(void)
{
    duct_pmtu_t p;
    duct_pmtu_init(&p, duct_pmtu_base_min, eth);
    p.good = 1300u;
    p.failed = 1400u;
    p.failed_strikes = duct_pmtu_fail_strikes_max;
    uint16_t rungs[duct_pmtu_burst_max];
    uint8_t n = duct_pmtu_burst(&p, rungs);
    for (uint8_t i = 0u; i < n; ++i)
        if (rungs[i] == 1400u)
            return "a hard-failed bound is still included in refine burst";
    duct_pmtu_ack(&p, 1400u);
    if (p.good != 1300u || p.failed != 1400u)
        return "a late echo of a hard-failed bound reopened good";
    return nullptr;
}

static const char *sc_floor_mru(void)
{
    duct_pmtu_t p;
    duct_pmtu_init(&p, duct_pmtu_base_min, eth);
    unsigned bursts = s_run_burst_sim(&p, duct_pmtu_base_min);
    if (bursts > 3u || !duct_pmtu_done(&p) || duct_pmtu_mtu(&p) != duct_pmtu_base_min)
        return "MRU equal to floor did not settle at 1232 within 3 bursts";
    return nullptr;
}

static const char *sc_ack_ignores_junk(void)
{
    duct_pmtu_t p;
    duct_pmtu_init(&p, duct_pmtu_base_min, eth);
    duct_pmtu_ack(&p, 576u);
    duct_pmtu_ack(&p, eth + 1u);
    if (duct_pmtu_mtu(&p) != duct_pmtu_base_min)
        return "an out-of-range echo moved the MTU";
    return nullptr;
}

static const char *sc_restart_reopens(void)
{
    duct_pmtu_t p;
    duct_pmtu_init(&p, duct_pmtu_base_min, eth);
    duct_pmtu_ack(&p, 1400u);
    p.failed = 1410u;
    if (!duct_pmtu_done(&p))
        return "window <= 16 bytes did not close";
    duct_pmtu_restart(&p);
    if (duct_pmtu_mtu(&p) != duct_pmtu_base_min || p.failed != 0u || p.failed_strikes != 0u)
        return "restart did not reset search state";
    return nullptr;
}

static const char *sc_degenerate_bounds(void)
{
    duct_pmtu_t p;
    uint16_t rungs[duct_pmtu_burst_max];
    duct_pmtu_init(&p, 576u, eth);
    if (duct_pmtu_mtu(&p) != duct_pmtu_base_min)
        return "a base under 1232 was taken as given";
    duct_pmtu_init(&p, duct_pmtu_base_min, 900u);
    if (duct_pmtu_mtu(&p) != duct_pmtu_base_min || duct_pmtu_burst(&p, rungs) != 0u)
        return "a ceiling under base left a search to run";
    duct_pmtu_init(&p, duct_pmtu_base_min, duct_pmtu_base_min);
    if (duct_pmtu_burst(&p, rungs) != 0u)
        return "a zero-span range left a search to run";
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
        { "ceiling first",         sc_ceiling_first },
        { "silent drop converges", sc_silent_drop_converges },
        { "never exceeds truth",   sc_never_exceeds_truth },
        { "flaky rehab",           sc_flaky_rehab },
        { "hard fail cutoff",      sc_hard_fail_cutoff },
        { "floor MRU",             sc_floor_mru },
        { "ack ignores junk",      sc_ack_ignores_junk },
        { "restart reopens",       sc_restart_reopens },
        { "degenerate bounds",     sc_degenerate_bounds },
    };
    for (size_t i = 0u; i < sizeof scenarios / sizeof scenarios[0]; ++i) {
        auto err = scenarios[i].run();
        if (err) {
            fprintf(stderr, "pmtu: %s: %s\n", scenarios[i].name, err);
            return 1;
        }
    }
    printf("pmtu: OK (%zu scenarios)\n",
           sizeof scenarios / sizeof scenarios[0]);
    return 0;
}
