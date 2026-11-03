/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file pmtu_test.c
 *  @brief The path-MTU search driven by a stand-in path.
 *
 *  A scenario running a whole search names a true path width and answers every
 *  probe by it, so the search runs against a path that cannot lie differently
 *  from one probe to the next. Nothing here opens a socket: the search takes
 *  sizes in and answers sizes out, which is the whole of its contract.
 *
 *  Covers: the ceiling tried first and settling in one probe, convergence on a
 *  narrower path inside a halving's worth of sizes, the reported MTU never
 *  exceeding the true path while the search runs, a path answering nothing
 *  leaving the base usable, a size failing only at its last unanswered probe
 *  in a row, that count restarted by an answer moving the search and by no
 *  other, acknowledgements outside the search window ignored, losses of any
 *  size but the one under probe ignored, a restart reopening the ceiling, and
 *  bounds that cross or collapse.
 */

#include "duct_pmtu.h"

#include <stdio.h>

static constexpr uint16_t eth = 1500u;
static constexpr uint16_t jumbo = 9000u;

static const char *sc_ceiling_first(void)
{
    duct_pmtu_t p;
    duct_pmtu_init(&p, duct_pmtu_base_min, eth);
    if (duct_pmtu_mtu(&p) != duct_pmtu_base_min)
        return "a fresh search does not start usable at its base";
    if (duct_pmtu_probe(&p) != eth)
        return "the first probe is not the ceiling";
    duct_pmtu_ack(&p, eth);
    if (duct_pmtu_mtu(&p) != eth || duct_pmtu_probe(&p) != 0u)
        return "a ceiling that answers did not settle the search at once";
    return nullptr;
}

static const char *sc_converges_below(void)
{
    static constexpr uint16_t truth = 1400u;
    duct_pmtu_t p;
    duct_pmtu_init(&p, duct_pmtu_base_min, eth);
    unsigned steps = 0u;
    for (uint16_t probe = duct_pmtu_probe(&p); probe;
         probe = duct_pmtu_probe(&p)) {
        if (++steps > 32u)
            return "the search did not terminate";
        if (probe <= truth)
            duct_pmtu_ack(&p, probe);
        else
            duct_pmtu_lost(&p, probe);
    }
    if (duct_pmtu_mtu(&p) != truth)
        return "the search settled somewhere other than the true path";
    if (steps > 12u * duct_pmtu_unanswered_max)
        return "the search took more probes than a halving needs";
    return nullptr;
}

static const char *sc_never_exceeds_truth(void)
{
    static constexpr uint16_t truth = 1387u;
    duct_pmtu_t p;
    duct_pmtu_init(&p, duct_pmtu_base_min, jumbo);
    for (uint16_t probe = duct_pmtu_probe(&p); probe;
         probe = duct_pmtu_probe(&p)) {
        if (probe <= truth)
            duct_pmtu_ack(&p, probe);
        else
            duct_pmtu_lost(&p, probe);
        if (duct_pmtu_mtu(&p) > truth)
            return "the search reported an MTU the path does not carry";
    }
    if (duct_pmtu_mtu(&p) != truth)
        return "a wide range did not converge on the true path";
    return nullptr;
}

static const char *sc_lost_leaves_usable(void)
{
    duct_pmtu_t p;
    duct_pmtu_init(&p, duct_pmtu_base_min, jumbo);
    for (unsigned i = 0u; i < 40u * duct_pmtu_unanswered_max; ++i) {
        uint16_t probe = duct_pmtu_probe(&p);
        if (!probe)
            break;
        duct_pmtu_lost(&p, probe);
    }
    if (duct_pmtu_probe(&p) != 0u)
        return "a path that answers nothing left the search running";
    if (duct_pmtu_mtu(&p) != duct_pmtu_base_min)
        return "a path that answers nothing moved the usable MTU";
    return nullptr;
}

static const char *sc_isolated_loss(void)
{
    duct_pmtu_t p;
    duct_pmtu_init(&p, duct_pmtu_base_min, eth);
    for (unsigned i = 1u; i < duct_pmtu_unanswered_max; ++i)
        if (duct_pmtu_lost(&p, eth))
            return "a size failed before its last probe went unanswered";
    if (duct_pmtu_probe(&p) != eth || duct_pmtu_mtu(&p) != duct_pmtu_base_min)
        return "an unanswered probe moved the search before its size failed";
    duct_pmtu_ack(&p, eth);
    if (duct_pmtu_mtu(&p) != eth)
        return "an answer after isolated losses was refused";

    duct_pmtu_init(&p, duct_pmtu_base_min, jumbo);
    duct_pmtu_lost(&p, jumbo);
    duct_pmtu_ack(&p, eth);
    for (unsigned i = 1u; i < duct_pmtu_unanswered_max; ++i)
        if (duct_pmtu_lost(&p, jumbo))
            return "an answer between losses did not restart the count";
    if (duct_pmtu_lost(&p, 5000u) || duct_pmtu_probe(&p) != jumbo)
        return "a loss of a size not under probe counted";
    if (!duct_pmtu_lost(&p, jumbo))
        return "the last unanswered probe did not fail its size";
    if (duct_pmtu_mtu(&p) != eth || duct_pmtu_probe(&p) == jumbo)
        return "a failed size did not move the search on";
    return nullptr;
}

static const char *sc_ack_ignores_junk(void)
{
    duct_pmtu_t p;
    duct_pmtu_init(&p, duct_pmtu_base_min, eth);
    for (unsigned i = 0u; i < duct_pmtu_unanswered_max; ++i)
        duct_pmtu_lost(&p, eth);
    uint16_t probe = duct_pmtu_probe(&p);
    duct_pmtu_ack(&p, eth);
    if (duct_pmtu_mtu(&p) >= eth)
        return "an acknowledgement above a failed size was believed";
    duct_pmtu_ack(&p, duct_pmtu_base_min - 100u);
    if (duct_pmtu_mtu(&p) != duct_pmtu_base_min)
        return "an acknowledgement below the base moved the usable MTU";
    duct_pmtu_ack(&p, probe);
    if (duct_pmtu_mtu(&p) != probe)
        return "the outstanding probe's own acknowledgement was refused";
    return nullptr;
}

static const char *sc_lost_ignores_junk(void)
{
    duct_pmtu_t p;
    duct_pmtu_init(&p, duct_pmtu_base_min, eth);
    for (unsigned i = 1u; i < duct_pmtu_unanswered_max; ++i) {
        duct_pmtu_lost(&p, eth);
        duct_pmtu_ack(&p, duct_pmtu_base_min);
    }
    if (!duct_pmtu_lost(&p, eth))
        return "an echo of settled ground restarted the count";

    duct_pmtu_init(&p, duct_pmtu_base_min, eth);
    duct_pmtu_ack(&p, eth);
    for (unsigned i = 0u; i < duct_pmtu_unanswered_max; ++i)
        if (duct_pmtu_lost(&p, 0u))
            return "a loss after the search settled failed a size";
    if (duct_pmtu_mtu(&p) != eth || duct_pmtu_probe(&p) != 0u)
        return "a loss after the search settled reopened it";
    return nullptr;
}

static const char *sc_restart_reopens(void)
{
    duct_pmtu_t p;
    duct_pmtu_init(&p, duct_pmtu_base_min, eth);
    duct_pmtu_ack(&p, eth);
    if (duct_pmtu_probe(&p) != 0u)
        return "the search did not settle";
    duct_pmtu_restart(&p);
    if (duct_pmtu_mtu(&p) != duct_pmtu_base_min)
        return "a restart kept an MTU the path may no longer carry";
    if (duct_pmtu_probe(&p) != eth)
        return "a restart did not try the ceiling again";
    return nullptr;
}

static const char *sc_degenerate_bounds(void)
{
    duct_pmtu_t p;
    duct_pmtu_init(&p, 576u, eth);
    if (duct_pmtu_mtu(&p) != duct_pmtu_base_min)
        return "a base under the floor was taken as given";
    duct_pmtu_init(&p, duct_pmtu_base_min, 900u);
    if (duct_pmtu_mtu(&p) != duct_pmtu_base_min || duct_pmtu_probe(&p) != 0u)
        return "a ceiling under the base left a search to run";
    duct_pmtu_init(&p, duct_pmtu_base_min, duct_pmtu_base_min);
    if (duct_pmtu_probe(&p) != 0u)
        return "a range of one size left a search to run";
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
        { "ceiling first",        sc_ceiling_first },
        { "converges below",      sc_converges_below },
        { "never exceeds truth",  sc_never_exceeds_truth },
        { "lost leaves usable",   sc_lost_leaves_usable },
        { "isolated loss",        sc_isolated_loss },
        { "ack ignores junk",     sc_ack_ignores_junk },
        { "lost ignores junk",    sc_lost_ignores_junk },
        { "restart reopens",      sc_restart_reopens },
        { "degenerate bounds",    sc_degenerate_bounds },
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
