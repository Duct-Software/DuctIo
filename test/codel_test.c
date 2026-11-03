/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file codel_test.c
 *  @brief CoDel's state machine, delay sample, socket reading and signal answer on
 *  a synthetic clock, and the leg-bound offer over a live standing queue.
 *
 *  @c sc_step walks the state machine: nothing before a whole interval above
 *  target, the first signal at it, the next ones interval / sqrt(count) apart and
 *  losses an interval past first_above, a sample below leaving, a re-entry within
 *  16 intervals resuming at count - last_count, and a later one starting over at
 *  1. Gaps are checked within a window, the control law taking an integer root
 *  with 16 fractional bits. @c sc_far checks a far sample: it signals at once,
 *  cuts a running interval short, and leaves the control law to space the signals
 *  after it.
 *
 *  @c sc_sample walks the sample: an empty queue keeps no tracer, a queue stamps
 *  one at its end, an open tracer's age counts past target, a queue at the floor
 *  stays below, a sent tracer closes a sojourn, an open tracer past four targets
 *  samples far, and an emptied queue drops both. @c sc_socket dates a tracer off a
 *  scripted reader: nothing read in the ring, unsent in the socket not left, the
 *  next reading held for the socket's last queue in writes, the crossing
 *  interpolated, lull readings a target apart till the socket drains, a failed
 *  reading dating it at the hand-off, and the first reading ever or a span past
 *  32 bits dating it at the reading.
 *
 *  @c sc_laws classes samples under a law with no far rule and a deep one, and
 *  past half the ring. @c sc_bound expects the largest interval not to signal
 *  early. @c sc_act walks the signal's answers over IPv4 records and packets of
 *  every ECN codepoint, a short record and one carrying FIN. @c sc_leg runs a
 *  session behind a peer that reads nothing, fills its TX ring past half, and
 *  offers frames at synthetic times: a signal after a whole interval, a loss after
 *  it, a full verdict for a frame the ring cannot take, the open tracer's age as
 *  the delay, and a leg that does not exist leaving the state as it was.
 */

#include "duct.h"
#include "duct_codel.h"
#include "duct_ticks.h"
#include "test_helpers.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/** @brief Return @p msg from the calling check when @p cond fails. */
#define expect(cond, msg) do { if (!(cond)) return msg; } while (0)

/** @brief Synthetic clock origin, nanoseconds. */
static constexpr uint64_t t0 = 1'000'000'000'000u;
/** @brief One millisecond, nanoseconds. */
static constexpr uint64_t ms = 1'000'000u;
/** @brief RFC 8289's interval, nanoseconds. */
static constexpr uint64_t iv = duct_codel_interval_ns;
/** @brief Ceiling no queue reaches, bytes. */
static constexpr size_t unbound = SIZE_MAX;
/** @brief Floor the sample and reading scenarios pass, bytes. */
static constexpr size_t least = 32'768u;

/** @brief Law of RFC 8289's figures with a far rule at four targets. */
static constexpr duct_codel_law_t law_quick = {
    .target = duct_codel_target_ns, .interval = duct_codel_interval_ns,
    .at_once = 4u * duct_codel_target_ns,
};
/** @brief Law of RFC 8289's figures with no far rule. */
static constexpr duct_codel_law_t law_plain = {
    .target = duct_codel_target_ns, .interval = duct_codel_interval_ns, .at_once = UINT64_MAX,
};
/** @brief Law of a 50 ms target and a 300 ms interval with no far rule. */
static constexpr duct_codel_law_t law_deep = {
    .target = 50'000'000u, .interval = 300'000'000u, .at_once = UINT64_MAX,
};

/** @brief Test @p gap against the window between @p lo and @p hi, nanoseconds,
 *  printing it on stderr when it falls outside. */
static bool gap_ok(uint64_t gap, uint64_t lo, uint64_t hi)
{
    if (gap > lo && gap < hi)
        return true;
    fprintf(stderr, "gap %llu ns outside (%llu, %llu)\n", (unsigned long long)gap,
            (unsigned long long)lo, (unsigned long long)hi);
    return false;
}

/** @brief Step CoDel from idle through a run, its end, a re-entry within 16
 *  intervals and a later one.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_step(void)
{
    duct_codel_t q = {};
    expect(duct_codel_step(&q, &law_quick, codel_below, t0) == codel_pass, "below passes");
    expect(duct_codel_step(&q, &law_quick, codel_above, t0) == codel_pass,
           "the first above only starts the interval");
    expect(duct_codel_step(&q, &law_quick, codel_above, t0 + iv - 1u) == codel_pass,
           "above for less than an interval passes");
    expect(duct_codel_step(&q, &law_quick, codel_above, t0 + iv) == codel_signal && q.count == 1u,
           "a whole interval above signals");
    expect(q.signal_next == t0 + 2u * iv, "the next signal comes an interval later");
    expect(duct_codel_step(&q, &law_quick, codel_above, t0 + 2u * iv - 1u) == codel_pass,
           "no signal before its time");
    expect(duct_codel_step(&q, &law_quick, codel_above, t0 + 2u * iv) == codel_loss && q.count == 2u,
           "the second signal comes on time, an interval into its run: a loss");
    expect(gap_ok(q.signal_next - (t0 + 2u * iv), 70'700'000u, 70'720'000u),
           "the second gap is interval / sqrt(2)");
    uint64_t third = q.signal_next;
    expect(duct_codel_step(&q, &law_quick, codel_above, third) == codel_loss && q.count == 3u,
           "the third signal comes on time, a loss");
    expect(gap_ok(q.signal_next - third, 57'725'000u, 57'745'000u),
           "the third gap is interval / sqrt(3)");

    expect(duct_codel_step(&q, &law_quick, codel_below, third + ms) == codel_pass && !q.signalling,
           "below leaves signalling");
    uint64_t back = third + 2u * ms;
    expect(duct_codel_step(&q, &law_quick, codel_above, back) == codel_pass,
           "re-entry starts a new interval");
    expect(duct_codel_step(&q, &law_quick, codel_above, back + iv) == codel_signal && q.count == 2u,
           "re-entry within 16 intervals resumes at count - last_count");
    expect(gap_ok(q.signal_next - (back + iv), 70'700'000u, 70'720'000u),
           "the resumed gap is interval / sqrt(count)");
    uint64_t next = q.signal_next;
    expect(duct_codel_step(&q, &law_quick, codel_above, next) == codel_signal && q.count == 3u,
           "a resumed run signals within its first interval");
    next = q.signal_next;
    expect(duct_codel_step(&q, &law_quick, codel_above, next) == codel_loss && q.count == 4u,
           "past the run's first interval its signals are losses");

    expect(duct_codel_step(&q, &law_quick, codel_below, next + ms) == codel_pass && !q.signalling,
           "below again");
    uint64_t late = q.signal_next + 17u * iv;
    expect(duct_codel_step(&q, &law_quick, codel_above, late) == codel_pass,
           "a late re-entry starts an interval");
    expect(duct_codel_step(&q, &law_quick, codel_above, late + iv) == codel_signal && q.count == 1u,
           "re-entry past 16 intervals starts over at one");
    return nullptr;
}

/** @brief Step far samples: at once, inside a run and on a running interval.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_far(void)
{
    duct_codel_t q = {};
    expect(duct_codel_step(&q, &law_quick, codel_far, t0) == codel_signal && q.count == 1u
               && q.first_above == t0,
           "a far sample signals at once");
    expect(duct_codel_step(&q, &law_quick, codel_above, t0 + ms) == codel_pass && q.signalling,
           "signalling goes on above target");
    expect(duct_codel_step(&q, &law_quick, codel_above, q.signal_next) == codel_loss
               && q.count == 2u,
           "the control law spaces the next signal, an interval into the run: a loss");
    duct_codel_t r = {};
    expect(duct_codel_step(&r, &law_quick, codel_above, t0) == codel_pass,
           "an above sample starts the interval");
    expect(duct_codel_step(&r, &law_quick, codel_far, t0 + ms) == codel_signal
               && r.first_above == t0 + ms,
           "a far sample cuts the running interval short");
    return nullptr;
}

/** @brief Take samples from an empty queue to a far one and back to empty, then
 *  under a lower floor.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_sample(void)
{
    duct_codel_t q = {};
    duct_tx_pos_t a = { .at = 1u, .leg = 7u },
                  b = { .at = 2u, .leg = 7u };
    expect(duct_codel_sample(&q, &law_quick, a, 0u, least, unbound, 0u, t0) == codel_below
               && !q.tracer_at,
           "an empty queue is below and keeps no tracer");
    expect(duct_codel_sample(&q, &law_quick, a, least + 1u, least, unbound, 0u, t0) == codel_below
               && q.tracer_at == t0 && q.tracer.at == a.at,
           "a queue stamps a tracer at its end");
    expect(duct_codel_sample(&q, &law_quick, b, least + 1u, least, unbound, 0u, t0 + 6u * ms)
               == codel_above,
           "an open tracer past target counts from its stamp");
    expect(duct_codel_sample(&q, &law_quick, b, least, least, unbound, 0u, t0 + 6u * ms)
               == codel_below,
           "a queue at the floor stays below past target");
    expect(duct_codel_sample(&q, &law_quick, b, least + 1u, least, unbound, t0 + 7u * ms,
                             t0 + 7u * ms) == codel_above
               && q.sojourn == 7u * ms && q.tracer_at == t0 + 7u * ms && q.tracer.at == b.at,
           "a sent tracer closes a sojourn and a new one stamps at the end");
    expect(duct_codel_sample(&q, &law_quick, b, least + 1u, least, unbound, t0 + 8u * ms,
                             t0 + 8u * ms) == codel_below
               && q.sojourn == ms,
           "a short sojourn brings the delay under target");
    expect(duct_codel_sample(&q, &law_quick, b, least + 1u, least, unbound, 0u, t0 + 28u * ms)
               == codel_far,
           "an open tracer past four targets samples far");
    expect(duct_codel_sample(&q, &law_quick, b, least, least, unbound, 0u, t0 + 28u * ms)
               == codel_below,
           "a queue at the floor stays below however far past target");
    expect(duct_codel_sample(&q, &law_quick, b, 0u, least, unbound, 0u, t0 + 29u * ms)
               == codel_below
               && !q.tracer_at && !q.sojourn,
           "an emptied queue drops its tracer and its sojourn");

    duct_codel_t r = {};
    size_t small = 3'448u;
    duct_discard duct_codel_sample(&r, &law_quick, a, small + 1u, small, unbound, 0u, t0);
    expect(duct_codel_sample(&r, &law_quick, b, small + 1u, small, unbound, 0u, t0 + 6u * ms)
               == codel_above,
           "a lower floor counts a shorter queue as standing");
    expect(duct_codel_sample(&r, &law_quick, b, small + 1u, least, unbound, 0u, t0 + 6u * ms)
               == codel_below,
           "the same queue under the higher floor stays below");
    return nullptr;
}

/** @brief Readings the scripted reader answers, in order. */
static uint64_t s_reads[10];
/** @brief Next reading to answer, and readings asked so far. */
static unsigned s_read_n, s_read_calls;
/** @brief Set to make the scripted reader answer unread. */
static bool     s_read_fails;

/** @brief Answer the next scripted reading, counting every call; unread while
 *  @c s_read_fails is set. */
static uint64_t scripted([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t leg)
{
    ++s_read_calls;
    return s_read_fails ? duct_tx_unsent_unread : s_reads[s_read_n++];
}

/** @brief Date tracers off the scripted reader through the readings' timing and
 *  spans.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_socket(void)
{
    const duct_codel_law_t *law = &law_deep;
    duct_codel_t q = { .tracer = { .at = 1000u, .leg = 7u }, .tracer_at = t0 };
    duct_tx_pos_t end = { .at = 1500u, .leg = 7u };
    expect(duct_codel_left(&q, law, end, 600u, least, scripted, nullptr, 7u, t0 + ms) == 0u
               && !s_read_calls,
           "a tracer still in the ring has not left, and nothing is read");
    s_reads[0] = 600u;
    expect(duct_codel_left(&q, law, end, 500u, least, scripted, nullptr, 7u, t0 + 2u * ms) == 0u
               && s_read_calls == 1u && q.unsent == 600u && q.read_sent == 400u,
           "a tracer handed to the socket and unsent there has not left");
    end.at = 1900u;
    expect(duct_codel_left(&q, law, end, 500u, least, scripted, nullptr, 7u, t0 + 3u * ms) == 0u
               && s_read_calls == 1u,
           "the next reading waits for the socket's last queue in writes past the tracer");
    end.at = 2200u;
    s_reads[1] = 300u;
    expect(duct_codel_left(&q, law, end, 500u, least, scripted, nullptr, 7u, t0 + 4u * ms)
               == t0 + 2u * ms + 1'200'000u,
           "a tracer sent dates its crossing between the readings either side");
    q.tracer = end;
    q.tracer_at = t0 + 4u * ms;
    s_reads[2] = 0u;
    expect(duct_codel_left(&q, law, end, 0u, least, scripted, nullptr, 7u, t0 + 53u * ms) == 0u
               && s_read_calls == 2u,
           "a lull under the law's target reads nothing");
    expect(duct_codel_left(&q, law, end, 0u, least, scripted, nullptr, 7u, t0 + 54u * ms)
               == t0 + 54u * ms && s_read_calls == 3u,
           "a lull at the law's target takes one confirming reading");
    q.tracer = (duct_tx_pos_t){ .at = 3000u, .leg = 7u };
    q.tracer_at = t0 + 60u * ms;
    q.unsent = 0u;
    end.at = 3500u;
    s_read_fails = true;
    expect(duct_codel_left(&q, law, end, 0u, least, scripted, nullptr, 7u, t0 + 61u * ms)
               == t0 + 61u * ms,
           "a reading that fails dates the tracer at the ring's hand-off");
    q.tracer_at = 0u;
    expect(duct_codel_left(&q, law, end, 0u, least, scripted, nullptr, 7u, t0 + 62u * ms) == 0u,
           "with no tracer open nothing has left");

    s_read_fails = false;
    duct_codel_t r = {};
    duct_tx_pos_t at = { .at = least, .leg = 7u };
    unsigned calls = s_read_calls;
    expect(duct_codel_left(&r, law, at, 0u, least, scripted, nullptr, 7u, t0) == 0u
               && s_read_calls == calls,
           "with no tracer open, a socket handed the floor since its last reading is not read");
    at.at = least + 1u;
    s_reads[3] = 5000u;
    expect(duct_codel_left(&r, law, at, 0u, least, scripted, nullptr, 7u, t0 + ms) == 0u
               && s_read_calls == calls + 1u && r.unsent == 5000u && r.read_at == t0 + ms
               && r.read_sent == least + 1u - 5000u,
           "past the floor one reading falls due, and the queue it finds stands as the last one");
    at.at = least + 2u;
    expect(duct_codel_left(&r, law, at, 0u, least, scripted, nullptr, 7u, t0 + 2u * ms) == 0u
               && s_read_calls == calls + 1u,
           "the next one waits for the floor past that reading's sent offset");
    at.at = r.read_sent + least + 1u;
    expect(duct_codel_left(&r, law, at, 0u, least, scripted, nullptr, 7u, t0 + 50u * ms) == 0u
               && s_read_calls == calls + 1u,
           "and for the law's target past that reading");
    s_reads[4] = 0u;
    expect(duct_codel_left(&r, law, at, 0u, least, scripted, nullptr, 7u, t0 + 51u * ms) == 0u
               && s_read_calls == calls + 2u && !r.unsent && r.read_sent == at.at,
           "past both it falls due again");

    duct_codel_t u = { .tracer = { .at = 1000u, .leg = 7u }, .tracer_at = t0 };
    duct_tx_pos_t still = { .at = 1000u, .leg = 7u };
    s_reads[5] = 400u;
    expect(duct_codel_left(&u, law, still, 0u, least, scripted, nullptr, 7u, t0 + 50u * ms) == 0u
               && u.unsent == 400u && u.read_at == t0 + 50u * ms,
           "a reading finds the tracer unsent in a socket handed nothing past it");
    expect(duct_codel_left(&u, law, still, 0u, least, scripted, nullptr, 7u, t0 + 99u * ms) == 0u
               && s_read_calls == calls + 3u,
           "the next lull reading waits the law's target past that one");
    s_reads[6] = 0u;
    expect(duct_codel_left(&u, law, still, 0u, least, scripted, nullptr, 7u, t0 + 100u * ms)
               == t0 + 100u * ms && s_read_calls == calls + 4u,
           "and finds the socket drained with no write, the tracer left");

    duct_codel_t f = { .tracer = { .at = 1000u, .leg = 7u }, .tracer_at = ms };
    duct_tx_pos_t first = { .at = 2000u, .leg = 7u };
    s_reads[7] = 100u;
    expect(duct_codel_left(&f, law, first, 500u, least, scripted, nullptr, 7u, 10u * ms)
               == 10u * ms,
           "a tracer found sent by the first reading ever is dated at that reading");
    duct_codel_t g = { .tracer = { .at = 1000u, .leg = 7u }, .tracer_at = t0, .unsent = 600u,
                       .read_at = t0 + ms, .read_sent = 400u };
    duct_tx_pos_t later = { .at = 3000u, .leg = 7u };
    s_reads[8] = 0u;
    expect(duct_codel_left(&g, law, later, 0u, least, scripted, nullptr, 7u, t0 + 5'000u * ms)
               == t0 + 5'000u * ms,
           "a reading before the last one by more than 32 bits of nanoseconds dates nothing");
    duct_codel_t h = { .tracer = { .at = 10'000'000'000u, .leg = 7u }, .tracer_at = t0,
                       .read_at = t0 + ms, .read_sent = 1'000'000'000u };
    duct_tx_pos_t wide = { .at = 20'000'000'000u, .leg = 7u };
    s_reads[9] = 0u;
    expect(duct_codel_left(&h, law, wide, 0u, least, scripted, nullptr, 7u, t0 + 60u * ms)
               == t0 + 60u * ms,
           "a reading more than 32 bits of bytes below the tracer dates nothing");
    return nullptr;
}

/** @brief Class samples and step signals under a law with no far rule and a deep
 *  one, and past half the ring.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_laws(void)
{
    duct_tx_pos_t a = { .at = 1u, .leg = 7u };
    duct_codel_t q = {};
    duct_discard duct_codel_sample(&q, &law_plain, a, least + 1u, least, unbound, 0u, t0);
    expect(duct_codel_sample(&q, &law_plain, a, least + 1u, least, unbound, 0u, t0 + 28u * ms)
               == codel_above,
           "a law with no far rule samples four targets above");
    duct_codel_t b = {};
    duct_discard duct_codel_sample(&b, &law_deep, a, least + 1u, least, unbound, 0u, t0);
    expect(duct_codel_sample(&b, &law_deep, a, least + 1u, least, unbound, 0u, t0 + 49u * ms)
               == codel_below,
           "the deep law takes 49 ms as below");
    expect(duct_codel_sample(&b, &law_deep, a, least + 1u, least, unbound, 0u, t0 + 400u * ms)
               == codel_above,
           "the deep law samples 400 ms above, its far rule off");
    duct_codel_t c = {};
    uint64_t biv = law_deep.interval;
    expect(duct_codel_step(&c, &law_deep, codel_above, t0) == codel_pass
               && duct_codel_step(&c, &law_deep, codel_above, t0 + biv - 1u) == codel_pass,
           "the deep law passes under its interval above target");
    expect(duct_codel_step(&c, &law_deep, codel_above, t0 + biv) == codel_signal
               && c.signal_next == t0 + 2u * biv,
           "the deep law signals at its interval and spaces the next one by it");
    duct_codel_t d = {};
    size_t half = 2u * least;
    expect(duct_codel_sample(&d, &law_deep, a, half + 1u, least, half, 0u, t0) == codel_above,
           "a queue past half the ring samples above target as its tracer stamps");
    expect(duct_codel_sample(&d, &law_deep, a, half, least, half, 0u, t0 + ms) == codel_below,
           "a queue at half the ring is left to the law, here under its target");
    expect(duct_codel_sample(&d, &law_deep, a, half, least, half, 0u, t0 + 400u * ms)
               == codel_above,
           "and past it, the law's own far rule off");
    duct_codel_t e = {};
    expect(duct_codel_sample(&e, &law_quick, a, half + 1u, least, half, 0u, t0) == codel_above
               && duct_codel_sample(&e, &law_quick, a, half + 1u, least, half, 0u, t0 + 28u * ms)
                      == codel_far,
           "past half the ring the law's own far rule still applies");
    return nullptr;
}

/** @brief Step a law whose interval is the largest value.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_bound(void)
{
    static constexpr duct_codel_law_t never = {
        .target = duct_codel_target_ns, .interval = UINT64_MAX, .at_once = UINT64_MAX,
    };
    duct_codel_t q = {};
    expect(duct_codel_step(&q, &never, codel_above, t0) == codel_pass,
           "a law with the largest interval does not signal at its first sample");
    expect(duct_codel_step(&q, &never, codel_above, t0 + 1'000u * iv) == codel_pass,
           "and not a thousand intervals on");
    expect(duct_codel_step(&q, &never, codel_above, t0 + (UINT64_MAX >> 16u)) == codel_signal,
           "it signals once the interval the control law carries has run");
    return nullptr;
}

/** @brief Buffer @c s_record builds its frame in. */
static uint8_t s_rec[2u + 40u + 350u];

/** @brief Build in @c s_rec a GSO record of @p payload bytes in 100-byte segments,
 *  one IPv4 TCP packet under @p tcp_flags and ECN codepoint @p ecn; @p gso false
 *  hands out the packet alone, without its lead. */
static duct_frame_t s_record(size_t payload, uint8_t tcp_flags, uint8_t ecn, bool gso)
{
    memset(s_rec, 0, sizeof s_rec);
    s_rec[1] = 100u;
    uint8_t *ip = s_rec + 2u;
    ip[0] = 0x45u;
    ip[1] = ecn;
    ip[2] = (uint8_t)((40u + payload) >> 8u);
    ip[3] = (uint8_t)(40u + payload);
    ip[8] = 64u;
    ip[9] = 6u;
    ip[20 + 12] = 5u << 4u;
    ip[20 + 13] = tcp_flags;
    size_t lead = gso ? 2u : 0u;
    return (duct_frame_t){ .payload = { .data = ip - lead, .size = lead + 40u + payload },
                           .flags = gso ? fl_frame_gso : fl_frame_none };
}

/** @brief The frame's bytes as @c s_record built them, to compare with what an answer leaves. */
static uint8_t s_before[sizeof s_rec];

/** @brief Test whether the bytes of @c s_rec are as @c s_record built them. */
static bool s_rec_untouched(void)
{
    return memcmp(s_rec, s_before, sizeof s_rec) == 0;
}

/** @brief Answer signals and losses over records and packets of every ECN
 *  codepoint, a short record and one carrying FIN. A mark and a trim edit the
 *  frame where it lies and the response forwards it; every other answer leaves
 *  the frame's bytes alone.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_act(void)
{
    duct_response_t out = {};
    auto frame = s_record(350u, 0x10u, 0u, true);
    memcpy(s_before, s_rec, sizeof s_rec);
    expect(duct_codel_act(&out, &frame, codel_signal, duct_conn_id_primary) == codel_act_trim,
           "a not-ect record of four segments trims");
    const uint8_t *t = out.payload.data;
    expect(out.payload.data == frame.payload.data && out.payload.size == 2u + 40u + 300u
               && ((size_t)t[4] << 8u | t[5]) == 40u + 300u,
           "the short last segment goes and the ipv4 length follows, in the frame's own memory");
    expect(out.flags == fl_send_copy && out.frame_flags == fl_frame_gso && !out.release
               && out.conn_id == duct_conn_id_primary,
           "the trimmed record goes out as a copy-send on the leg named, still a record");
    expect(frame.payload.size == 2u + 40u + 350u, "the frame the callback was handed keeps its size");
    out = (duct_response_t){};
    frame = s_record(350u, 0x10u, 2u, true);
    expect(duct_codel_act(&out, &frame, codel_signal, duct_conn_id_primary) == codel_act_mark
               && out.payload.data == frame.payload.data && out.payload.size == frame.payload.size
               && (((const uint8_t *)out.payload.data)[3] & 3u) == 3u && out.flags == fl_send_copy
               && out.conn_id == duct_conn_id_primary,
           "an ect record goes out whole, marked ce in its own memory");
    out = (duct_response_t){};
    frame = s_record(350u, 0x10u, 1u, false);
    expect(duct_codel_act(&out, &frame, codel_signal, 3u) == codel_act_mark
               && out.payload.data == frame.payload.data
               && (((const uint8_t *)out.payload.data)[1] & 3u) == 3u && out.conn_id == 3u,
           "an ect(1) packet is marked ce, going out on the leg named");
    out = (duct_response_t){};
    frame = s_record(350u, 0x10u, 3u, true);
    memcpy(s_before, s_rec, sizeof s_rec);
    expect(duct_codel_act(&out, &frame, codel_signal, duct_conn_id_primary) == codel_act_keep
               && !out.payload.data && s_rec_untouched(),
           "a record already ce goes out as it came, out and the frame untouched");
    frame = s_record(350u, 0x10u, 0u, false);
    memcpy(s_before, s_rec, sizeof s_rec);
    expect(duct_codel_act(&out, &frame, codel_signal, duct_conn_id_primary) == codel_act_drop
               && !out.payload.data && s_rec_untouched(),
           "a not-ect packet drops, the frame untouched");
    frame = s_record(200u, 0x10u, 0u, true);
    memcpy(s_before, s_rec, sizeof s_rec);
    expect(duct_codel_act(&out, &frame, codel_signal, duct_conn_id_primary) == codel_act_drop
               && s_rec_untouched(),
           "a not-ect record of two segments drops, the frame untouched");
    frame = s_record(350u, 0x11u, 0u, true);
    memcpy(s_before, s_rec, sizeof s_rec);
    expect(duct_codel_act(&out, &frame, codel_signal, duct_conn_id_primary) == codel_act_drop
               && s_rec_untouched(),
           "a not-ect record carrying fin drops, the frame untouched");

    frame = s_record(350u, 0x10u, 2u, true);
    expect(duct_codel_act(&out, &frame, codel_loss, duct_conn_id_primary) == codel_act_trim
               && out.payload.data == frame.payload.data && out.payload.size == 2u + 40u + 300u
               && (((const uint8_t *)out.payload.data)[3] & 3u) == 2u,
           "a loss trims an ect record, its codepoint kept");
    out = (duct_response_t){};
    frame = s_record(350u, 0x10u, 3u, true);
    expect(duct_codel_act(&out, &frame, codel_loss, duct_conn_id_primary) == codel_act_trim,
           "a loss trims a record already ce");
    out = (duct_response_t){};
    frame = s_record(350u, 0x10u, 2u, false);
    memcpy(s_before, s_rec, sizeof s_rec);
    expect(duct_codel_act(&out, &frame, codel_loss, duct_conn_id_primary) == codel_act_drop
               && !out.payload.data && s_rec_untouched(),
           "a loss drops an ect packet, the frame untouched");
    return nullptr;
}

/** @brief Longest wait for the session to open or the ring to fill, milliseconds. */
static constexpr unsigned wait_ms = 5000u;
/** @brief Time the ring's queue holds still before it counts as standing,
 *  nanoseconds. */
static constexpr uint64_t still_for_ns = 100'000'000u;
/** @brief TX ring capacity the server protocol asks for, bytes. */
static constexpr size_t ring_cap = (size_t)1u << 20u;

/** @brief Payload the server session stages while its ring fills. */
static uint8_t       g_chunk[65536];
/** @brief 1 once the server session has opened. */
static atomic_int    g_opened = 0;
/** @brief Token of the server session. */
static duct_handle_t g_tok;

/** @brief One probe's inputs and answers, run in the session's callbacks. */
typedef struct {
    duct_codel_t         q;       /**< State the offers share. */
    duct_codel_law_t     law;     /**< Law the offers run under. */
    duct_conn_id_t       leg;     /**< Leg probed. */
    size_t               size, ring, cap; /**< Frame size offered; ring queue and capacity
                                            *  read by @c ring_fn. */
    uint64_t             at, delay; /**< Synthetic time of the next call; delay answered. */
    duct_codel_verdict_t verdict; /**< Verdict answered. */
} probe_t;

/** @brief Session open of the server protocol: publish the token and start the
 *  filling timer. */
static duct_result_t srv_on_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok,
                                 [[maybe_unused]] void *user_ctx, duct_response_t *out,
                                 [[maybe_unused]] void *proto_state)
{
    g_tok = tok;
    duct_atomic_store(&g_opened, 1, release);
    out->control.timer.delay_ms = 1u;
    out->control.timer.interval_ms = 1u;
    return rc_ok;
}

/** @brief Timer of the server protocol: stage a chunk while the ring's queue is under
 *  three quarters of its capacity. */
static duct_result_t srv_on_timer(duct_session_t *s, duct_response_t *out,
                                  [[maybe_unused]] void *proto_state,
                                  [[maybe_unused]] uint64_t arg)
{
    duct_tx_pos_t end = {};
    size_t queued = 0u;
    if (duct_conn_tx_end(s, duct_conn_id_primary, &end, &queued) != rc_ok
        || queued >= duct_conn_tx_cap(s, duct_conn_id_primary) / 4u * 3u)
        return rc_ok;
    duct_response_same(out, duct_view(duct_view_u8, g_chunk, sizeof g_chunk),
                       fl_send_static, 0);
    return rc_ok;
}

/** @brief Frame callback of the server protocol, taking nothing. */
static duct_result_t on_frame([[maybe_unused]] duct_session_t *s,
                              [[maybe_unused]] duct_conn_id_t conn_id,
                              [[maybe_unused]] const duct_frame_t *frame,
                              [[maybe_unused]] duct_response_t *out,
                              [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

/** @brief Offer a frame of @c p->size at @c p->at and store the verdict. */
static duct_result_t offer_fn(duct_session_t *s, [[maybe_unused]] duct_response_t *out, void *ctx)
{
    auto p = (probe_t *)ctx;
    p->verdict = duct_conn_codel(s, p->leg, &p->q, &p->law, p->size, p->at);
    return rc_ok;
}

/** @brief Read the queue delay at @c p->at and store it. */
static duct_result_t delay_fn(duct_session_t *s, [[maybe_unused]] duct_response_t *out, void *ctx)
{
    auto p = (probe_t *)ctx;
    p->delay = duct_conn_codel_delay(s, p->leg, &p->q, &p->law, p->at);
    return rc_ok;
}

/** @brief Read the leg's ring queue and capacity and store them. */
static duct_result_t ring_fn(duct_session_t *s, [[maybe_unused]] duct_response_t *out, void *ctx)
{
    auto p = (probe_t *)ctx;
    duct_tx_pos_t end = {};
    duct_discard duct_conn_tx_end(s, p->leg, &end, &p->ring);
    p->cap = duct_conn_tx_cap(s, p->leg);
    return rc_ok;
}

/** @brief Run @p fn on @p p in the server session's worker.
 *  @return false when the invoke did not run. */
static bool run(duct_engine_t *io, duct_session_fn fn, probe_t *p)
{
    return duct_session_invoke_sync(io, g_tok, fn, p) == rc_ok;
}

/** @brief Wait for the ring's queue to pass half its capacity and hold still.
 *  @return false when it does not within @c wait_ms. */
static bool ring_standing(duct_engine_t *io)
{
    probe_t p = { .leg = duct_conn_id_primary };
    size_t last = SIZE_MAX;
    uint64_t since = 0u;
    for (unsigned waited = 0u; waited < wait_ms; waited += 10u) {
        if (!run(io, ring_fn, &p))
            return false;
        uint64_t now = duct_ticks_mono_ns();
        if (p.ring != last) {
            last = p.ring;
            since = now;
        } else if (p.cap && p.ring > p.cap / 2u && now - since >= still_for_ns)
            return true;
        th_sleep_ms(10u);
    }
    return false;
}

/** @brief Offer frames to the standing queue at synthetic times and read its delay.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *offers(duct_engine_t *io)
{
    probe_t p = { .law = law_plain, .leg = duct_conn_id_primary, .size = 1500u, .at = t0 };
    expect(run(io, ring_fn, &p), "the ring read did not run");
    expect(run(io, offer_fn, &p), "the offer did not run");
    expect(p.verdict == codel_pass && p.q.tracer_at == t0 && p.q.queued > ring_cap / 2u,
           "the first offer on a standing queue opens the tracer and the interval");
    p.at = t0 + iv - 1u;
    expect(run(io, offer_fn, &p), "the offer did not run");
    expect(p.verdict == codel_pass, "a standing queue under a whole interval passes");
    p.at = t0 + iv;
    expect(run(io, offer_fn, &p), "the offer did not run");
    expect(p.verdict == codel_signal && p.q.count == 1u && p.q.signalling,
           "a standing queue for a whole interval signals");
    p.at = p.q.signal_next;
    expect(run(io, offer_fn, &p), "the offer did not run");
    expect(p.verdict == codel_loss && p.q.count == 2u,
           "the next signal, an interval into the run, is a loss");
    p.at = p.q.signal_next;
    p.size = p.cap / 3u;
    expect(run(io, offer_fn, &p), "the offer did not run");
    expect(p.verdict == codel_full && p.q.count == 3u,
           "a frame the ring cannot take is full, CoDel having stepped regardless");
    p.at = t0 + 5u * iv;
    expect(run(io, delay_fn, &p), "the delay did not run");
    expect(p.delay == 5u * iv, "an open tracer's age is the queue's delay");

    duct_codel_t before;
    memcpy(&before, &p.q, sizeof before);
    p.leg = duct_session_max_legs;
    p.size = 1500u;
    expect(run(io, offer_fn, &p), "the offer did not run");
    expect(p.verdict == codel_pass && memcmp(&before, &p.q, sizeof before) == 0,
           "a leg that does not exist passes and leaves the state as it was");
    expect(run(io, delay_fn, &p), "the delay did not run");
    expect(p.delay == 0u && memcmp(&before, &p.q, sizeof before) == 0,
           "a leg that does not exist has no delay and leaves the state as it was");
    return nullptr;
}

/** @brief Length-prefixed protocol whose session fills its TX ring behind a peer that
 *  reads nothing.
 *  @return the protocol, nullptr on failure. */
static duct_proto_t *standing_proto(void)
{
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "codel-standing", .wire = wire, .on_frame = on_frame,
        .on_session_open = srv_on_open, .on_timer = srv_on_timer,
        .max_response = sizeof g_chunk, .tx_olb_cap = ring_cap,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    return proto;
}

/** @brief Launch an engine, hold a standing queue on a leg and run @c offers over it.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_leg(void)
{
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1u, .workers = 1u });
    if (!io)
        return "engine launch failed";
    auto proto = standing_proto();
    if (!proto) {
        duct_engine_destroy(io);
        return "proto create failed";
    }
    const char *err = nullptr;
    uint16_t port = 0u;
    pthread_t th;
    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok)
        err = "listen failed";
    else if (pthread_create(&th, nullptr, th_run, io) != 0)
        err = "thread create failed";
    else {
        duct_sock_t fd = th_connect(port);
        if (fd == duct_sock_bad)
            err = "connect failed";
        else if (!th_wait_int(&g_opened, 1, wait_ms))
            err = "the session never opened";
        else if (!ring_standing(io))
            err = "the ring never filled behind a peer that reads nothing";
        else
            err = offers(io);
        if (fd != duct_sock_bad)
            duct_sock_close(fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return err;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    static const struct { const char *name; const char *(*fn)(void); } cases[] = {
        { "step",   sc_step },
        { "far",    sc_far },
        { "sample", sc_sample },
        { "socket", sc_socket },
        { "laws",   sc_laws },
        { "bound",  sc_bound },
        { "act",    sc_act },
        { "leg",    sc_leg },
    };
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        auto err = cases[i].fn();
        if (err) {
            fprintf(stderr, "codel: %s: %s\n", cases[i].name, err);
            return 1;
        }
    }
    printf("codel: OK\n");
    return 0;
}
