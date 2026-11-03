/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_codel.c
 *  @brief CoDel's arithmetic, tracer and socket reading, and the leg-bound entries
 *  that feed them from the @c duct_conn_tx_* positions.
 *
 *  Every input of the pure entries comes by argument; @c duct_codel_left reaches the
 *  session only through its reader. The @c duct_conn_* entries read the leg's ring
 *  and socket first.
 */

#include "duct_codel.h"
#include "duct_vnet.h"

#include <assert.h>

/** @brief Fractional bits of the control law's square root. */
static constexpr unsigned s_root_bits = 16u;
/** @brief Largest interval the step reads, 2^48 - 1 ns: the control law shifts it
 *  left by @c s_root_bits. */
static constexpr uint64_t s_interval_max = UINT64_MAX >> s_root_bits;

/** @brief Square root of @p v, rounded down. */
static uint64_t s_isqrt(uint64_t v)
{
    uint64_t root = 0u,
             bit = (uint64_t)1u << 62u;
    while (bit > v)
        bit >>= 2u;
    for (; bit; bit >>= 2u) {
        if (v >= root + bit) {
            v -= root + bit;
            root = (root >> 1u) + bit;
        } else
            root >>= 1u;
    }
    return root;
}

/** @brief Step @p t on by @p interval / sqrt(@p count), RFC 8289's control law.
 *  The root carries @c s_root_bits fractional bits; @p count is at least 1. */
static uint64_t s_control_law(uint64_t t, uint32_t count, uint64_t interval)
{
    return t + (interval << s_root_bits) / s_isqrt((uint64_t)count << (2u * s_root_bits));
}

/** @brief Close @p q's tracer at @p left_at where that is set, open one at @p end
 *  where none is, and answer the delay a queue of @p queued bytes shows now, 0 for
 *  an empty one. */
static uint64_t s_track(duct_codel_t *q, duct_tx_pos_t end, size_t queued, uint64_t left_at,
                        uint64_t now)
{
    if (!queued) {
        q->tracer_at = q->sojourn = 0u;
        return 0u;
    }
    if (q->tracer_at && left_at) {
        q->sojourn = left_at - q->tracer_at;
        q->tracer_at = 0u;
    }
    if (!q->tracer_at) {
        q->tracer = end;
        q->tracer_at = now;
    }
    /* An open tracer has waited at least its age, so a stalled drain counts
     * before its sojourn closes. */
    return duct_max(q->sojourn, now - q->tracer_at);
}

duct_codel_sample_t duct_codel_sample(duct_codel_t *q, const duct_codel_law_t *law,
                                      duct_tx_pos_t end, size_t queued, size_t least,
                                      size_t most, uint64_t left_at, uint64_t now)
{
    uint64_t delay = s_track(q, end, queued, left_at, now);
    if (queued <= least || (delay < law->target && queued <= most))
        return codel_below;
    return delay >= law->at_once ? codel_far : codel_above;
}

duct_codel_verdict_t duct_codel_step(duct_codel_t *q, const duct_codel_law_t *law,
                                     duct_codel_sample_t sample, uint64_t now)
{
    uint64_t interval = duct_min(law->interval, s_interval_max);
    bool due = false;
    if (sample == codel_below)
        q->first_above = 0u;
    else {
        if (sample == codel_far && (!q->first_above || q->first_above > now))
            q->first_above = now;
        else if (!q->first_above)
            q->first_above = now + interval;
        due = duct_codel_due(q, now);
    }

    if (q->signalling) {
        if (!due) {
            q->signalling = false;
            return codel_pass;
        }
        if (now < q->signal_next)
            return codel_pass;
        ++q->count;
        q->signal_next = s_control_law(q->signal_next, q->count, interval);
        return now - q->first_above < interval ? codel_signal : codel_loss;
    }
    if (!due)
        return codel_pass;
    uint32_t delta = q->count - q->last_count;
    /* A run resumes at the count the last one gained while now is under 16
     * intervals past signal_next, the date that run's next signal fell due; it
     * lies ahead of now after a run that ended between signals. */
    bool recent = (int64_t)(now - q->signal_next) < (int64_t)(16u * interval);
    q->count = delta > 1u && recent ? delta : 1u;
    q->signal_next = s_control_law(now, q->count, interval);
    q->last_count = q->count;
    q->signalling = true;
    return codel_signal;
}

/** @brief Store a reading of leg @p leg's socket, handed @p w bytes, in @p q; false
 *  where @p read reads nothing, @p q untouched. */
static bool s_read(duct_codel_t *q, duct_codel_unsent_fn read, duct_session_t *s,
                   duct_conn_id_t leg, uint64_t w, uint64_t now)
{
    uint64_t unsent = read(s, leg);
    if (unsent == duct_tx_unsent_unread)
        return false;
    q->unsent = unsent;
    q->read_at = now;
    q->read_sent = unsent < w ? w - unsent : 0u;
    return true;
}

uint64_t duct_codel_left(duct_codel_t *q, const duct_codel_law_t *law, duct_tx_pos_t end,
                         size_t ring, size_t least, duct_codel_unsent_fn read,
                         duct_session_t *s, duct_conn_id_t leg, uint64_t now)
{
    uint64_t w = end.at - ring;
    bool lull = law && now - duct_max(q->read_at, q->tracer_at) >= law->target;
    if (!q->tracer_at) {
        if (lull && w - q->read_sent > least)
            duct_discard s_read(q, read, s, leg, w, now);
        return 0u;
    }
    uint64_t t = q->tracer.at;
    if (w < t || (w < t + q->unsent && !lull))
        return 0u;
    uint64_t prev_at = q->read_at,
             prev_sent = q->read_sent;
    if (!s_read(q, read, s, leg, w, now))
        return now;
    uint64_t sent = q->read_sent;
    if (sent < t)
        return 0u;
    /* A reading that found this tracer unsent left read_sent under T; an earlier
     * tracer's reading, and one taken with none open, lie under the T a non-empty
     * queue stamped. */
    assert(prev_sent < t);
    if (!prev_at || now - prev_at > UINT32_MAX || t - prev_sent > UINT32_MAX)
        return now;
    uint64_t x = prev_at + (now - prev_at) * (t - prev_sent) / (sent - prev_sent);
    return duct_max(x, q->tracer_at);
}

duct_codel_verdict_t duct_conn_codel(duct_session_t *s, duct_conn_id_t conn_id, duct_codel_t *q,
                                     const duct_codel_law_t *law, size_t size, uint64_t now)
{
    duct_tx_pos_t end;
    size_t ring = 0u;
    if (duct_conn_tx_end(s, conn_id, &end, &ring) != rc_ok)
        return codel_pass;
    size_t least = duct_conn_tx_quantum(s, conn_id) + size;
    uint64_t left_at = duct_codel_left(q, law, end, ring, least, duct_conn_tx_unsent, s, conn_id,
                                       now);
    q->queued = ring + (size_t)q->unsent;
    auto verdict = duct_codel_step(q, law,
                                   duct_codel_sample(q, law, end, q->queued, least,
                                                     duct_conn_tx_cap(s, conn_id) / 2u, left_at,
                                                     now),
                                   now);
    return duct_conn_tx_fits(s, conn_id, size) ? verdict : codel_full;
}

uint64_t duct_conn_codel_delay(duct_session_t *s, duct_conn_id_t conn_id, duct_codel_t *q,
                               const duct_codel_law_t *law, uint64_t now)
{
    duct_tx_pos_t end;
    size_t ring = 0u;
    if (duct_conn_tx_end(s, conn_id, &end, &ring) != rc_ok)
        return 0u;
    uint64_t left_at = duct_codel_left(q, law, end, ring, duct_conn_tx_quantum(s, conn_id),
                                       duct_conn_tx_unsent, s, conn_id, now);
    return s_track(q, end, ring + (size_t)q->unsent, left_at, now);
}

duct_codel_action_t duct_codel_act(duct_response_t *out, const duct_frame_t *frame,
                                   duct_codel_verdict_t verdict, duct_conn_id_t leg)
{
    auto ecn = duct_frame_ecn(frame);
    bool mark = verdict == codel_signal && ecn != ecn_not_ect;
    if (ecn == ecn_none || (mark && ecn == ecn_ce))
        return codel_act_keep;
    if (!mark && !duct_has(frame->flags, fl_frame_gso))
        return codel_act_drop;
    size_t n = mark ? duct_frame_mark_ce(frame) : duct_gso_trim(frame->payload);
    if (!n)
        return codel_act_drop;
    duct_response_forward(out, frame, leg);
    out->payload.size = n;
    return mark ? codel_act_mark : codel_act_trim;
}
