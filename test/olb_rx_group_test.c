/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file olb_rx_group_test.c
 * @brief Unit test for the coalesced-group and compaction arithmetic on a @c duct_olb_rx_t.
 *
 * Driven directly against the buffer — no engine, no io thread, no socket:
 * how compaction carries a live group down, what a discard abandons with the
 * bytes, the floor a space request owes its caller, and when a consumed
 * buffer rewinds to its base.
 */

#include "duct_olb_rx.h"

#include "duct_core.h"

#include <stdio.h>
#include <string.h>

#define CHECK(expr, msg) \
    do { if (!(expr)) { fprintf(stderr, "FAIL: %s\n", msg); return 1; } } while (0)

static constexpr size_t group_test_cap = 4096u;
static constexpr size_t lead_len = 100u;
static constexpr size_t group_len = 60u;
static constexpr size_t seg_len = 20u;

/** @brief Stage @p len bytes of @p fill at the cursor.
 *  @c duct_olb_rx_append_raw leaves the space check to its caller, so a
 *  constant edited past the buffer must fail here rather than off the end.
 *  @return false with nothing staged.
 */
static bool s_stage(duct_olb_rx_t *rx, char fill, size_t len)
{
    char chunk[256];
    memset(chunk, fill, sizeof chunk);
    if (len > rx->h.buf_size - rx->h.stage)
        return false;
    for (size_t left = len; left;) {
        size_t take = left < sizeof chunk ? left : sizeof chunk;
        duct_olb_rx_append_raw(rx, chunk, take);
        left -= take;
    }
    return true;
}

/** @brief Put the buffer where a worker that has consumed everything up to
 *  @p upto leaves it: parse frontier, ack and dispatch frontier together.
 *
 *  @c duct_olb_rx_compact takes a boundary at or before both @c head and
 *  @c posted_off, so moving the frontier alone builds a state the engine never
 *  reaches and proves nothing about the one it does.
 */
static void s_post(duct_olb_rx_t *rx, size_t upto)
{
    rx->posted_off = (uint32_t)upto;
    duct_olb_rx_ack(rx, upto - duct_atomic_load(&rx->acked, relaxed));
    duct_discard duct_olb_rx_ack_apply(rx);
    duct_atomic_store(&rx->dispatch_frontier, (uint32_t)upto, relaxed);
}

/** @brief A buffer in the shape a coalesced read leaves: posted records first,
 *  then an undescribed group running to the tail.
 *  @return nullptr when the allocation or the staging failed.
 */
static duct_olb_rx_t *s_rx_with_group(void)
{
    auto rx = duct_olb_rx_new(group_test_cap);
    if (!rx)
        return nullptr;
    if (!s_stage(rx, 'L', lead_len) || !s_stage(rx, 'G', group_len)) {
        duct_olb_del(&rx->h);
        return nullptr;
    }
    s_post(rx, lead_len);
    rx->group_off = (uint32_t)lead_len;
    rx->group_seg = (uint32_t)seg_len;
    rx->group_bytes = (uint32_t)group_len;
    return rx;
}

int main(void)
{
    /* A live group survives compaction: it sits at or past the boundary, so it
     * slides by that distance while the frontier resets. */
    {
        auto rx = s_rx_with_group();
        CHECK(rx, "alloc (compact with a live group)");
        CHECK(rx->group_off + rx->group_bytes
                  == duct_atomic_load(&rx->h.tail, relaxed),
              "a staged group ends at the tail");
        uint8_t *ptr = nullptr;
        size_t free_after = duct_olb_rx_compact(rx, lead_len, &ptr);
        CHECK(rx->group_off == 0u, "group_off must slide down by the boundary");
        CHECK(rx->group_bytes == group_len, "compaction must not consume group bytes");
        CHECK(rx->group_seg == seg_len, "compaction must not touch the segment size");
        CHECK(rx->posted_off == 0u, "parse frontier resets on compaction");
        CHECK(rx->h.stage == group_len, "only the group survives the boundary");
        CHECK(duct_atomic_load(&rx->h.tail, relaxed) == group_len, "tail follows stage");
        CHECK(free_after == rx->h.buf_size - group_len, "free span is what is left");
        CHECK(rx->data[0] == 'G' && rx->data[group_len - 1u] == 'G',
              "group bytes must land at the buffer base");
        duct_olb_del(&rx->h);
    }

    /* Boundary 0 discards nothing, so the group keeps the offset it had. This
     * is what separates sliding by the boundary from resetting to zero the way
     * the frontier does — at any other boundary the two look alike. */
    {
        auto rx = s_rx_with_group();
        CHECK(rx, "alloc (compact at boundary 0)");
        rx->posted_off = 0u;
        uint8_t *ptr = nullptr;
        duct_discard duct_olb_rx_compact(rx, 0u, &ptr);
        CHECK(rx->group_off == lead_len, "a zero boundary must leave group_off alone");
        CHECK(rx->group_bytes == group_len, "a zero boundary must leave the group whole");
        CHECK(rx->h.stage == lead_len + group_len, "nothing is discarded at boundary 0");
        CHECK(rx->data[0] == 'L' && rx->data[lead_len] == 'G',
              "a zero boundary must not shift the bytes");
        duct_olb_del(&rx->h);
    }

    /* With no group pending, the offset is nobody's to maintain: whatever a
     * previous group left there stays, and no reader is gated on it. */
    {
        auto rx = duct_olb_rx_new(group_test_cap);
        CHECK(rx, "alloc (dead group)");
        CHECK(s_stage(rx, 'L', lead_len), "stage the lead");
        s_post(rx, lead_len);
        rx->group_off = 12345u;
        uint8_t *ptr = nullptr;
        duct_discard duct_olb_rx_compact(rx, lead_len, &ptr);
        CHECK(rx->group_off == 12345u, "a dead group's offset is not maintained");
        CHECK(rx->h.stage == 0u, "everything before the boundary is discarded");
        duct_olb_del(&rx->h);
    }

    /* A discard throws away the bytes the group describes, so the group goes
     * with them: left standing, its offset outlives them and the next
     * compaction slides a stale one down. */
    {
        auto rx = s_rx_with_group();
        CHECK(rx, "alloc (discard)");
        size_t tail = duct_atomic_load(&rx->h.tail, relaxed);
        duct_olb_rx_discard(rx, tail);
        CHECK(rx->posted_off == tail, "discard moves the parse frontier to the tail");
        CHECK(rx->group_bytes == 0u, "discard abandons the group with the bytes");
        duct_olb_del(&rx->h);
    }

    /* Dropping the unposted tail leaves its bytes in place and counts them
     * skipped, so the acks already given cover every posted byte and a rewind
     * follows. */
    {
        auto rx = s_rx_with_group();
        CHECK(rx, "alloc (discard of the unposted tail)");
        size_t tail = duct_atomic_load(&rx->h.tail, relaxed);
        duct_olb_rx_recv_hint_set(rx, 7u);
        duct_olb_rx_discard(rx, tail);
        CHECK(rx->h.stage == tail && rx->skip == group_len,
              "discard leaves the bytes in place and counts them skipped");
        CHECK(rx->group_bytes == 0u && duct_olb_rx_recv_hint_get(rx) == 0u,
              "the group and the parser's hint go with the dropped bytes");
        CHECK(duct_olb_rx_posted_total(rx) == lead_len,
              "the skipped bytes are no ack the worker owes");
        CHECK(duct_olb_rx_consumed(rx), "the acks already given cover every posted byte");
        duct_olb_rx_rewind(rx);
        CHECK(rx->h.stage == 0u && rx->pass_base == lead_len && rx->skip == 0u,
              "a consumed buffer rewinds past the discard");
        duct_olb_del(&rx->h);
    }

    /* One argument fixes the read span and the threshold that has to clear it,
     * including the fallback both take when it is zero. */
    {
        auto rx = duct_olb_rx_new(group_test_cap);
        CHECK(rx, "alloc (threshold and read unit)");
        duct_olb_rx_threshold_set(rx, 1000u);
        CHECK(rx->read_unit == 1000u, "read_unit takes the argument whole");
        CHECK(duct_olb_rx_threshold_get(rx)
                  == duct_min((size_t)1000u * olb_rx_th_factor,
                              rx->h.buf_size / olb_rx_th_div),
              "threshold is the argument scaled, capped at the buffer share");
        duct_olb_rx_threshold_set(rx, 0u);
        CHECK(rx->read_unit == 0u, "a zero argument leaves no read span");
        CHECK(duct_olb_rx_threshold_get(rx) == rx->h.buf_size / olb_rx_compact_div,
              "a zero argument falls back to the buffer share");
        duct_olb_del(&rx->h);
    }

    /* The free span is parked inside the relaxed branch's window — above half
     * the threshold, below the read unit — and compaction is held off by a
     * frame still in a handler's hands. The one-byte need proves the window is
     * really where the answer comes from; the unit-sized need is the one that
     * must be refused. Fractions of the buffer, not byte counts: the sizing
     * holds whatever duct_olb_rx_new rounds to. */
    {
        auto rx = duct_olb_rx_new(group_test_cap);
        CHECK(rx, "alloc (min_avail floor)");
        size_t buf = rx->h.buf_size,
               unit = buf / 3u,
               avail_want = buf * 3u / 10u;
        duct_olb_rx_threshold_set(rx, unit);
        CHECK(s_stage(rx, 'L', buf - avail_want), "stage up to the relaxed window");
        duct_atomic_store(&rx->held_frames, 1u, relaxed);

        uint8_t *ptr = nullptr;
        size_t avail = 0u;
        CHECK(duct_olb_rx_try_space(rx, 1u, false, &ptr, &avail) == olb_rx_ok,
              "the relaxed branch must answer for a one-byte need");
        CHECK(avail == avail_want && avail < unit,
              "the free span must sit inside the relaxed window");
        CHECK(duct_olb_rx_try_space(rx, unit, false, &ptr, &avail) == olb_rx_full,
              "no branch may answer success below min_avail");
        duct_olb_del(&rx->h);
    }

    {
        auto rx = duct_olb_rx_new(group_test_cap);
        CHECK(rx, "alloc (compaction short of min_avail)");
        size_t buf = rx->h.buf_size,
               posted = buf / 2u,
               staged = buf * 3u / 4u,
               unit = buf * 9u / 10u;
        duct_olb_rx_threshold_set(rx, unit);
        CHECK(s_stage(rx, 'L', staged), "stage past the threshold");
        s_post(rx, posted);

        uint8_t *ptr = nullptr;
        size_t avail = 0u;
        CHECK(duct_olb_rx_try_space(rx, unit, false, &ptr, &avail) == olb_rx_full,
              "a compaction short of min_avail answers full");
        CHECK(rx->h.stage == staged - posted,
              "the compaction ran: the unparsed tail slid down");
        CHECK(avail == buf - (staged - posted) && avail < unit,
              "what it freed is real, and still short");
        duct_olb_del(&rx->h);
    }

    /* The rewind waits for every staged byte to be posted and for the worker to
     * be done with all of them; each condition alone holds the bytes where
     * they are. */
    {
        auto rx = duct_olb_rx_new(group_test_cap);
        CHECK(rx, "alloc (rewind)");
        CHECK(s_stage(rx, 'L', lead_len), "stage the lead");
        duct_olb_rx_rewind(rx);
        CHECK(rx->h.stage == lead_len, "unposted bytes hold the rewind");
        rx->posted_off = (uint32_t)lead_len;
        duct_olb_rx_rewind(rx);
        CHECK(rx->h.stage == lead_len, "an unacked frame holds the rewind");
        s_post(rx, lead_len);
        duct_atomic_store(&rx->held_frames, 1u, relaxed);
        duct_olb_rx_rewind(rx);
        CHECK(rx->h.stage == lead_len, "a held frame holds the rewind");
        duct_atomic_store(&rx->held_frames, 0u, relaxed);
        duct_atomic_store(&rx->dispatch_frontier, 0u, relaxed);
        duct_olb_rx_rewind(rx);
        CHECK(rx->h.stage == lead_len, "an undispatched frame holds the rewind");
        duct_atomic_store(&rx->dispatch_frontier, (uint32_t)lead_len, relaxed);
        duct_olb_rx_rewind(rx);
        CHECK(rx->h.stage == 0u && rx->posted_off == 0u,
              "a consumed buffer rewinds to the base");
        CHECK(duct_atomic_load(&rx->h.tail, relaxed) == 0u, "tail follows stage");
        CHECK(duct_atomic_load(&rx->acked, relaxed) == lead_len
                  && rx->pass_base == lead_len,
              "the worker's ack count stands; the pass starts where it is");
        duct_olb_del(&rx->h);
    }

    /* An undescribed group sits past the parse frontier, so it holds the rewind
     * like any unposted bytes. */
    {
        auto rx = s_rx_with_group();
        CHECK(rx, "alloc (rewind with a live group)");
        duct_olb_rx_rewind(rx);
        CHECK(rx->h.stage == lead_len + group_len && rx->group_bytes == group_len,
              "an undescribed group holds the rewind");
        duct_olb_del(&rx->h);
    }

    /* A record-framed read out of tail room opens a second pass at offset 0
     * over what the worker released, grows it as the release point moves,
     * and retires the first pass once the worker is past its end. */
    {
        auto rx = duct_olb_rx_new(group_test_cap);
        CHECK(rx, "alloc (second pass)");
        size_t buf = rx->h.buf_size,
               p = buf / 8u,
               staged = buf - p / 2u;
        duct_olb_rx_threshold_set(rx, p);
        CHECK(s_stage(rx, 'A', staged), "stage the first pass");
        rx->posted_off = (uint32_t)staged;
        duct_olb_rx_ack(rx, 3u * p);

        uint8_t *ptr = nullptr;
        size_t avail = 0u;
        CHECK(duct_olb_rx_try_space(rx, p, false, &ptr, &avail) == olb_rx_full,
              "without a second pass the tail is all there is");
        CHECK(duct_olb_rx_try_space(rx, p, true, &ptr, &avail) == olb_rx_compacted,
              "a released head of the buffer takes the next read");
        CHECK(ptr == rx->data && avail == 3u * p && rx->h.stage == 0u,
              "the second pass starts at the base, up to what the worker released");
        CHECK(rx->pass_end == staged && rx->posted_off == 0u
                  && duct_olb_rx_posted_total(rx) == staged,
              "the first pass ends where it was staged, its bytes still posted");
        CHECK(rx->data[staged - 1u] == 'A', "the first pass's bytes stay in place");

        CHECK(s_stage(rx, 'B', 2u * p), "stage into the second pass");
        rx->posted_off = (uint32_t)(2u * p);
        CHECK(duct_olb_rx_try_space(rx, p, true, &ptr, &avail) == olb_rx_ok
                  && avail == p && ptr == rx->data + 2u * p,
              "the second pass grows up to the first pass's release point");
        CHECK(duct_olb_rx_try_space(rx, 2u * p, true, &ptr, &avail) == olb_rx_full,
              "and no further");
        CHECK(duct_olb_rx_resume_total(rx, 2u * p, true) == staged,
              "the read resumes once the worker is down to one read of backlog");
        duct_olb_rx_ack(rx, p);
        CHECK(duct_olb_rx_try_space(rx, 2u * p, true, &ptr, &avail) == olb_rx_ok
                  && avail == 2u * p,
              "a later ack widens the gap");

        duct_olb_rx_ack(rx, staged - 4u * p);
        CHECK(duct_olb_rx_try_space(rx, p, true, &ptr, &avail) == olb_rx_ok,
              "the buffer answers once the first pass is done");
        CHECK(rx->pass_end == 0u && rx->pass_base == staged,
              "the first pass retires once the worker is past its end");
        CHECK(avail == buf - 2u * p, "the rest of the buffer belongs to the second pass");

        duct_olb_rx_ack(rx, 2u * p);
        duct_atomic_store(&rx->dispatch_frontier, (uint32_t)(2u * p), relaxed);
        duct_olb_rx_rewind(rx);
        CHECK(rx->h.stage == 0u && rx->pass_base == staged + 2u * p,
              "a consumed second pass rewinds like any other");
        duct_olb_del(&rx->h);
    }

    /* Unposted bytes and a held frame keep the second pass closed, and leave
     * the full drain as the only resume target; a conn without records has
     * no other one either. */
    {
        auto rx = duct_olb_rx_new(group_test_cap);
        CHECK(rx, "alloc (second pass held off)");
        size_t buf = rx->h.buf_size,
               p = buf / 8u,
               staged = buf - p / 2u;
        duct_olb_rx_threshold_set(rx, p);
        CHECK(s_stage(rx, 'A', staged), "stage the first pass");
        rx->posted_off = (uint32_t)(staged - p);
        duct_olb_rx_ack(rx, 3u * p);

        uint8_t *ptr = nullptr;
        size_t avail = 0u;
        CHECK(duct_olb_rx_try_space(rx, p, true, &ptr, &avail) == olb_rx_full,
              "unposted bytes hold the second pass");
        CHECK(duct_olb_rx_resume_total(rx, p, true) == staged - p,
              "unposted bytes leave only the full drain to resume the read");
        rx->posted_off = (uint32_t)staged;
        duct_atomic_store(&rx->held_frames, 1u, relaxed);
        CHECK(duct_olb_rx_try_space(rx, p, true, &ptr, &avail) == olb_rx_full
                  && rx->pass_end == 0u,
              "a held frame holds the second pass");
        CHECK(duct_olb_rx_resume_total(rx, p, true) == staged,
              "with a frame held only a full drain resumes the read");
        duct_atomic_store(&rx->held_frames, 0u, relaxed);
        CHECK(duct_olb_rx_resume_total(rx, p, true) == staged - p,
              "otherwise the read resumes once the worker is down to one read of backlog");
        CHECK(duct_olb_rx_resume_total(rx, p, false) == staged,
              "a conn without records waits for the full drain");
        duct_olb_del(&rx->h);
    }

    /* A pass holding less than one read resumes at the full drain: the point
     * one read of backlog short of it lies before the pass even starts. */
    {
        auto rx = duct_olb_rx_new(group_test_cap);
        CHECK(rx, "alloc (short pass)");
        size_t p = rx->h.buf_size / 8u;
        CHECK(s_stage(rx, 'A', p / 2u), "stage less than one read");
        rx->posted_off = (uint32_t)(p / 2u);
        CHECK(duct_olb_rx_resume_total(rx, p, true) == p / 2u,
              "a pass shorter than one read resumes at the full drain");
        duct_olb_del(&rx->h);
    }

    /* Skipped bytes at the end of the first pass are no ack the worker owes,
     * yet that pass retires only once acks from the second cover them too:
     * the count of acked bytes runs short of the buffer offset by the skip. */
    {
        auto rx = duct_olb_rx_new(group_test_cap);
        CHECK(rx, "alloc (skip across passes)");
        size_t buf = rx->h.buf_size,
               p = buf / 8u,
               staged = buf - p / 2u,
               hole = p / 2u;
        duct_olb_rx_threshold_set(rx, p);
        CHECK(s_stage(rx, 'A', staged), "stage the first pass");
        rx->posted_off = (uint32_t)(staged - hole);
        duct_olb_rx_discard(rx, staged);
        duct_olb_rx_ack(rx, 3u * p);

        uint8_t *ptr = nullptr;
        size_t avail = 0u;
        CHECK(duct_olb_rx_try_space(rx, p, true, &ptr, &avail) == olb_rx_compacted
                  && rx->pass_end == staged,
              "a pass ending in skipped bytes hands its released front to a second pass");
        CHECK(s_stage(rx, 'B', p), "stage into the second pass");
        rx->posted_off = (uint32_t)p;
        CHECK(duct_olb_rx_posted_total(rx) == staged - hole + p,
              "the posted total leaves the skipped bytes out");
        duct_olb_rx_ack(rx, staged - hole - 3u * p);
        CHECK(duct_olb_rx_try_space(rx, p, true, &ptr, &avail) == olb_rx_ok
                  && rx->pass_end == staged,
              "the first pass holds until acks cover its skipped bytes as well");
        duct_olb_rx_ack(rx, p);
        CHECK(duct_olb_rx_try_space(rx, p, true, &ptr, &avail) == olb_rx_ok
                  && rx->pass_end == 0u,
              "acks past the skipped bytes retire the first pass");
        CHECK(duct_olb_rx_posted_total(rx) == duct_atomic_load(&rx->h.head, relaxed),
              "every posted byte is acked");
        duct_atomic_store(&rx->dispatch_frontier, (uint32_t)p, relaxed);
        CHECK(duct_olb_rx_consumed(rx), "and the buffer counts as consumed");
        duct_olb_del(&rx->h);
    }

    /* The ack total at a staged byte names that byte through a rewind, a
     * second pass opening and the first one retiring; a discard ahead of it
     * lowers it by the bytes skipped. */
    {
        auto rx = duct_olb_rx_new(group_test_cap);
        CHECK(rx, "alloc (totals across layouts)");
        size_t buf = rx->h.buf_size,
               p = buf / 8u,
               staged = buf - p / 2u;
        duct_olb_rx_threshold_set(rx, p);
        CHECK(s_stage(rx, 'A', p), "stage one read");
        s_post(rx, p);
        CHECK(duct_olb_rx_total_at(rx, rx->h.stage) == p, "the total at the cursor counts every staged byte");
        duct_olb_rx_rewind(rx);
        CHECK(rx->h.stage == 0u && duct_olb_rx_total_at(rx, 0u) == p,
              "a rewind keeps the total at the cursor");

        CHECK(s_stage(rx, 'B', staged), "stage the first pass");
        rx->posted_off = (uint32_t)staged;
        uint64_t first_end = duct_olb_rx_total_at(rx, staged);
        duct_olb_rx_ack(rx, 3u * p);
        uint8_t *ptr = nullptr;
        size_t avail = 0u;
        CHECK(duct_olb_rx_try_space(rx, p, true, &ptr, &avail) == olb_rx_compacted
                  && rx->pass_end == staged,
              "a released front opens a second pass");
        CHECK(duct_olb_rx_total_at(rx, 0u) == first_end,
              "the second pass starts at the total the first one ends at");

        CHECK(s_stage(rx, 'C', p), "stage into the second pass");
        rx->posted_off = (uint32_t)(p / 2u);
        duct_olb_rx_discard(rx, p);
        uint64_t past_hole = duct_olb_rx_total_at(rx, p);
        CHECK(past_hole == first_end + p / 2u, "discarded bytes add nothing to the total past them");

        duct_olb_rx_ack(rx, past_hole - 4u * p);
        CHECK(duct_olb_rx_try_space(rx, p, true, &ptr, &avail) == olb_rx_ok
                  && rx->pass_end == 0u,
              "acks past the second pass's hole retire the first pass");
        CHECK(duct_olb_rx_total_at(rx, p) == past_hole,
              "retiring the first pass keeps the total at the cursor");

        duct_atomic_store(&rx->dispatch_frontier, (uint32_t)(p / 2u), relaxed);
        duct_olb_rx_rewind(rx);
        CHECK(rx->h.stage == 0u && duct_olb_rx_total_at(rx, 0u) == past_hole,
              "a rewind past the hole keeps the total at the cursor");
        duct_olb_del(&rx->h);
    }

    printf("olb_rx_group_test OK\n");
    return 0;
}
