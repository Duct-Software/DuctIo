/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file liveness_test.c
 *  @brief Rest detection and the silence check on a synthetic clock.
 *
 *  @c sc_rest expects a link to rest only after traffic and a rest span past
 *  the last, and a frame heard to leave the span alone. @c sc_check expects a
 *  check to open once the peer has been quiet for the span and not before, and
 *  to refuse a second one beside it. @c sc_due expects no verdict before the
 *  deadline, a ping at each of the first two with the wait doubled, and a dead
 *  verdict at the third that closes the check. @c sc_heard expects a frame heard
 *  to close the check and the quiet span to run from it, and @c sc_close
 *  expects a closed check to give no verdict and keep the time heard.
 */

#include "duct.h"
#include "duct_liveness.h"

#include <stdio.h>

/** @brief Return @p msg from the calling check when @p cond fails. */
#define expect(cond, msg) do { if (!(cond)) return msg; } while (0)

/** @brief Synthetic clock origin, nanoseconds. */
static constexpr uint64_t t0    = 1'000'000'000'000u;
/** @brief One millisecond, nanoseconds. */
static constexpr uint64_t ms    = 1'000'000u;
/** @brief Base wait of a probe, nanoseconds. */
static constexpr uint64_t rto   = 500u * ms;
/** @brief Quiet span before a check opens, nanoseconds. */
static constexpr uint64_t quiet = 1000u * ms;
/** @brief Rest span, nanoseconds. */
static constexpr uint64_t rest  = 120'000u * ms;

/** @brief Walk the rest span around the first traffic, a later packet and a frame heard.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_rest(void)
{
    duct_liveness_t l = {};
    expect(!duct_liveness_resting(&l, t0 + 10u * rest, rest), "a link that never moved a packet rests");
    duct_liveness_active(&l, t0);
    expect(!duct_liveness_resting(&l, t0 + rest - 1u, rest), "a link rests before the rest span ends");
    expect(duct_liveness_resting(&l, t0 + rest, rest), "a link does not rest once the rest span ends");
    duct_liveness_active(&l, t0 + rest);
    expect(!duct_liveness_resting(&l, t0 + rest + 1u, rest), "a packet does not restart the rest span");
    duct_liveness_heard(&l, t0 + 2u * rest);
    expect(duct_liveness_resting(&l, t0 + 2u * rest, rest), "hearing the peer restarts the rest span");
    return nullptr;
}

/** @brief Open a check at the edge of the quiet span and again beside the open one.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_check(void)
{
    duct_liveness_t l = {};
    duct_liveness_heard(&l, t0);
    expect(!duct_liveness_check(&l, t0 + quiet - 1u, quiet, rto), "a check opens before the peer has been quiet");
    expect(!l.due_at, "a check that did not open left a deadline");
    expect(duct_liveness_check(&l, t0 + quiet, quiet, rto), "a check does not open once the peer has been quiet");
    expect(l.due_at == t0 + quiet + rto && l.passed == 0u, "an opened check misses its first deadline");
    expect(!duct_liveness_check(&l, t0 + quiet + 1u, quiet, rto), "a second check opens beside the open one");
    expect(l.due_at == t0 + quiet + rto, "a refused check moved the open one's deadline");
    return nullptr;
}

/** @brief Judge an open check through its three deadlines.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_due(void)
{
    duct_liveness_t l = {};
    expect(duct_liveness_due(&l, t0, rto) == live_quiet, "a verdict comes with no check open");
    duct_liveness_heard(&l, t0);
    expect(duct_liveness_check(&l, t0 + quiet, quiet, rto), "the check did not open");
    uint64_t at = t0 + quiet;
    expect(duct_liveness_due(&l, at + rto - 1u, rto) == live_quiet, "a verdict comes before the deadline");
    expect(l.passed == 0u && l.due_at == at + rto, "an early look moved the check");
    expect(duct_liveness_due(&l, at + rto, rto) == live_ping, "the first deadline does not ask for another probe");
    expect(l.passed == 1u && l.due_at == at + rto + 2u * rto, "the second wait is not twice the first");
    at = l.due_at;
    expect(duct_liveness_due(&l, at, rto) == live_ping, "the second deadline does not ask for another probe");
    expect(l.passed == 2u && l.due_at == at + 4u * rto, "the third wait is not four times the first");
    at = l.due_at;
    expect(duct_liveness_due(&l, at + 10u * rto, rto) == live_dead,
           "the third deadline does not end the check with a dead verdict");
    expect(!l.due_at, "a dead verdict left the check open");
    expect(duct_liveness_due(&l, at + 20u * rto, rto) == live_quiet, "a dead verdict is given twice");
    return nullptr;
}

/** @brief Close an open check by a frame heard and reopen it after a new quiet span.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_heard(void)
{
    duct_liveness_t l = {};
    duct_liveness_heard(&l, t0);
    expect(duct_liveness_check(&l, t0 + quiet, quiet, rto), "the check did not open");
    duct_liveness_heard(&l, t0 + quiet + 10u * ms);
    expect(!l.due_at, "a frame heard left the check open");
    expect(duct_liveness_due(&l, t0 + quiet + 2u * rto, rto) == live_quiet,
           "a check closed by a frame still gives a verdict");
    expect(!duct_liveness_check(&l, t0 + quiet + 10u * ms + quiet - 1u, quiet, rto),
           "a check opens before the peer has been quiet again");
    expect(duct_liveness_check(&l, t0 + quiet + 10u * ms + quiet, quiet, rto),
           "a check does not open again once the peer has been quiet");
    expect(l.passed == 0u, "a reopened check keeps the count of the last one");
    return nullptr;
}

/** @brief Close an open check without a frame and read the verdict and the stamps.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_close(void)
{
    duct_liveness_t l = {};
    duct_liveness_heard(&l, t0);
    expect(duct_liveness_check(&l, t0 + quiet, quiet, rto), "the check did not open");
    duct_liveness_close(&l);
    expect(!l.due_at && duct_liveness_due(&l, t0 + 10u * quiet, rto) == live_quiet,
           "a closed check still gives a verdict");
    expect(l.heard_at == t0, "closing a check moved the time the peer was last heard");
    return nullptr;
}

int main(void)
{
    static const struct { const char *name; const char *(*fn)(void); } cases[] = {
        { "rest",  sc_rest },
        { "check", sc_check },
        { "due",   sc_due },
        { "heard", sc_heard },
        { "close", sc_close },
    };
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        auto err = cases[i].fn();
        if (err) {
            fprintf(stderr, "liveness: %s: %s\n", cases[i].name, err);
            return 1;
        }
    }
    printf("liveness: OK\n");
    return 0;
}
