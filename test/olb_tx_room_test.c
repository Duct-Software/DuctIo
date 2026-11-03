/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file olb_tx_room_test.c
 * @brief Unit test for the TX buffer's passes and a worker's train on them.
 * What @ref duct_olb_tx_room_contig answers, a second pass bounded by io's
 * head, io draining one pass before folding into the next, and a train of
 * unpublished frames sent whole, sent in part, or handed to io. The stream end
 * the worker keeps through publishes, sends of its own and a fold, and the
 * point io has drained up to, are checked through the same cases. So is
 * @ref duct_olb_tx_rewind_idle: a drained ring rewinds to offset 0, one with bytes
 * queued or staged keeps its pass, and on Linux a drained pass the one before
 * outran by more than @c olb_tx_trim_div times reads zero past @c min_room
 * once rewound, while one within that factor keeps its pages.
 * Driven directly against a @c duct_olb_tx_t, with no engine and no io
 * thread.
 */

#include "duct_olb_tx.h"

#include "duct_core.h"

#include <stdio.h>
#include <string.h>

#define CHECK(expr, msg) \
    do { if (!(expr)) { fprintf(stderr, "FAIL: %s\n", msg); return 1; } } while (0)

static constexpr size_t room_test_cap = 4096u;

/** @brief Stage exactly @p fill bytes in one shot, leaving @c stage at
 *  @p fill — @p fill is derived from the tx's real (page-rounded) @c
 *  buf_size by every caller, never a compile-time guess. */
static duct_olb_tx_result_t s_stage_fill(duct_olb_tx_t *tx, size_t fill)
{
    auto filler = duct_at(duct_new(char, fill));
    if (!filler)
        return olb_tx_too_large;
    memset(filler, 'a', fill);
    auto rc = duct_olb_tx_stage(tx, nullptr, 0u, filler, fill);
    duct_del(filler);
    return rc;
}

int main(void)
{
    /* Tail-room disjunct: fresh ring, small need well within buf_size. */
    {
        auto tx = duct_olb_tx_new(room_test_cap);
        CHECK(tx, "alloc (tail-room case)");
        CHECK(duct_olb_tx_room_contig(tx, 100u), "tail room must fit a small need");
        duct_olb_del(&tx->h);
    }

    /* Drained buffer: the 100-byte tail room alone is too small for a
     * 200-byte need, but io has drained everything staged so far (head
     * caught up to stage), so a new pass takes the whole buffer. */
    {
        auto tx = duct_olb_tx_new(room_test_cap);
        CHECK(tx, "alloc (io_idle case)");
        size_t fill = tx->h.buf_size - 100u;
        CHECK(s_stage_fill(tx, fill) == olb_tx_ok, "stage up to fill");
        duct_olb_tx_publish(tx);
        duct_olb_tx_advance(tx, fill);
        CHECK(duct_olb_tx_published(tx) == 0u, "io must be idle here");
        CHECK(duct_olb_tx_room_contig(tx, 200u), "io_idle disjunct must cover a wrap-sized need");
        duct_olb_del(&tx->h);
    }

    /* Nothing drained: same tight tail room, and io's head still at offset 0
     * leaves a new pass no room, so a need bigger than the tail room fails. */
    {
        auto tx = duct_olb_tx_new(room_test_cap);
        CHECK(tx, "alloc (false case)");
        size_t fill = tx->h.buf_size - 100u;
        CHECK(s_stage_fill(tx, fill) == olb_tx_ok, "stage up to fill");
        duct_olb_tx_publish(tx);
        CHECK(duct_olb_tx_published(tx) == fill, "io must not be idle here");
        CHECK(!duct_olb_tx_room_contig(tx, 200u), "neither disjunct should hold");
        duct_olb_del(&tx->h);
    }

    /* A second pass opens over the front io has drained, stops at io's head,
     * and gets the whole buffer once io folds into it; no third pass opens
     * while io is still in the first. */
    {
        auto tx = duct_olb_tx_new(room_test_cap);
        CHECK(tx, "alloc (second pass)");
        size_t fill = tx->h.buf_size - 100u,
               lead = 1000u;
        uint64_t head = 0u;
        CHECK(s_stage_fill(tx, fill) == olb_tx_ok, "stage up to fill");
        duct_olb_tx_publish(tx);
        CHECK(duct_olb_tx_readable(tx, &head) == fill && head == 0u, "one pass is readable");
        duct_olb_tx_advance(tx, lead);
        CHECK(!duct_olb_tx_room_contig(tx, lead + 1u), "a new pass cannot outgrow io's head");
        CHECK(duct_olb_tx_room_contig(tx, lead), "the drained front admits a new pass");
        CHECK(s_stage_fill(tx, 600u) == olb_tx_ok, "stage into the drained front");
        duct_olb_tx_publish(tx);
        CHECK(tx->stage_gen == 1u && tx->h.stage == 600u, "staging moved to a second pass");
        CHECK(duct_olb_tx_published(tx) == fill - lead + 600u, "both passes count as published");
        CHECK(duct_olb_tx_readable(tx, &head) == fill - lead && head == lead,
              "io drains the first pass before the second");
        CHECK(!duct_olb_tx_span_open(tx, lead - 600u + 1u), "a span stops at io's head");
        CHECK(s_stage_fill(tx, lead - 600u + 1u) == olb_tx_full, "a stage stops at io's head");
        CHECK(s_stage_fill(tx, lead - 600u) == olb_tx_ok, "the second pass fills up to io's head");
        duct_olb_tx_publish(tx);
        CHECK(!duct_olb_tx_room_contig(tx, 1u) && s_stage_fill(tx, 1u) == olb_tx_full,
              "no third pass while io is in the first");
        duct_olb_tx_advance(tx, fill - lead);
        CHECK(duct_olb_tx_readable(tx, &head) == lead && head == 0u, "io folds into the second pass");
        CHECK(s_stage_fill(tx, 100u) == olb_tx_ok && tx->h.stage == lead + 100u,
              "the fold frees the rest of the buffer");
        duct_olb_del(&tx->h);
    }

    /* Bytes staged but not published open a frame, so no new pass opens
     * under them, and the room test admits the wrap once they are published. */
    {
        auto tx = duct_olb_tx_new(room_test_cap);
        CHECK(tx, "alloc (unpublished span)");
        size_t fill = tx->h.buf_size - 100u;
        CHECK(s_stage_fill(tx, fill) == olb_tx_ok, "stage up to fill");
        duct_olb_tx_publish(tx);
        duct_olb_tx_advance(tx, fill);
        CHECK(s_stage_fill(tx, 50u) == olb_tx_ok, "half a frame fits the tail");
        CHECK(s_stage_fill(tx, 200u) == olb_tx_full && tx->stage_gen == 0u,
              "no wrap under an unpublished span");
        CHECK(!duct_olb_tx_room_contig(tx, 200u), "the room test refuses under an unpublished span");
        duct_olb_tx_publish(tx);
        CHECK(duct_olb_tx_room_contig(tx, 200u), "publishing the span admits the wrap");
        duct_olb_del(&tx->h);
    }

    /* A pass opened over a drained buffer spans all of it, and a worker that
     * sent the front of its span itself moves io past those bytes. The tail
     * is rolled back once by hand to stand in for io's stale snapshot of it:
     * a head already folded past that tail stays where it is. */
    {
        auto tx = duct_olb_tx_new(room_test_cap);
        CHECK(tx, "alloc (idle wrap)");
        size_t fill = tx->h.buf_size - 100u;
        uint64_t head = 0u;
        CHECK(s_stage_fill(tx, fill) == olb_tx_ok, "stage up to fill");
        duct_olb_tx_publish(tx);
        duct_olb_tx_advance(tx, fill);
        auto mark = duct_olb_tx_mark(tx);
        CHECK(s_stage_fill(tx, 200u) == olb_tx_ok, "an idle ring wraps");
        CHECK(tx->stage_gen == 1u && tx->pass_free == tx->h.buf_size,
              "a pass opened over an idle ring spans the whole buffer");
        CHECK(duct_olb_tx_staged_since(tx, mark) == 200u, "the wrap counts from offset 0");
        duct_olb_tx_advance_worker(tx, 50u);
        uint64_t tail_now = duct_atomic_load(&tx->h.tail, relaxed);
        duct_atomic_store(&tx->h.tail, olb_pack(0u, fill), relaxed);
        CHECK(duct_olb_tx_readable(tx, &head) == 0u
              && duct_atomic_load(&tx->h.head, relaxed) == olb_pack(1u, 50u),
              "a head folded past a stale tail stays put");
        duct_atomic_store(&tx->h.tail, tail_now, relaxed);
        duct_olb_tx_publish(tx);
        CHECK(duct_olb_tx_readable(tx, &head) == 150u && head == 50u,
              "io resumes past what the worker sent itself");
        duct_olb_del(&tx->h);
    }

    /* A train the socket took whole rewinds its staging, leaves io nothing and
     * moves the stream end past itself. */
    {
        auto tx = duct_olb_tx_new(room_test_cap);
        CHECK(tx, "alloc (train sent whole)");
        CHECK(s_stage_fill(tx, 300u) == olb_tx_ok && s_stage_fill(tx, 200u) == olb_tx_ok,
              "stage a train of two frames");
        CHECK(duct_olb_tx_published(tx) == 0u, "a train stays unpublished while it runs");
        duct_olb_tx_sent_staged(tx);
        CHECK(tx->h.stage == 0u && duct_olb_tx_published(tx) == 0u && tx->stream_end == 500u,
              "a train sent whole leaves nothing staged, nothing for io, and its bytes in the end");
        CHECK(s_stage_fill(tx, 100u) == olb_tx_ok && tx->h.stage == 100u,
              "the next frame stages from where the sent train began");
        duct_olb_del(&tx->h);
    }

    /* A train the socket took in part publishes the unsent tail alone, and io
     * starts at its first byte. */
    {
        auto tx = duct_olb_tx_new(room_test_cap);
        CHECK(tx, "alloc (train sent in part)");
        uint64_t head = 0u;
        CHECK(s_stage_fill(tx, 300u) == olb_tx_ok && s_stage_fill(tx, 200u) == olb_tx_ok,
              "stage a train of two frames");
        duct_olb_tx_advance_worker(tx, 350u);
        duct_olb_tx_publish(tx);
        CHECK(duct_olb_tx_published(tx) == 150u, "only the unsent tail is published");
        CHECK(duct_olb_tx_readable(tx, &head) == 150u && head == 350u,
              "io starts at the first byte the socket refused");
        duct_olb_tx_advance(tx, 150u);
        CHECK(duct_olb_tx_published(tx) == 0u, "io's drain of the tail empties the ring");
        duct_olb_del(&tx->h);
    }

    /* A train published unsent is io's from its first byte. */
    {
        auto tx = duct_olb_tx_new(room_test_cap);
        CHECK(tx, "alloc (train handed to io)");
        uint64_t head = 0u;
        CHECK(s_stage_fill(tx, 300u) == olb_tx_ok && s_stage_fill(tx, 200u) == olb_tx_ok,
              "stage a train of two frames");
        duct_olb_tx_publish(tx);
        CHECK(duct_olb_tx_readable(tx, &head) == 500u && head == 0u,
              "a train handed over whole is io's from its first byte");
        duct_olb_del(&tx->h);
    }

    /* An unpublished train leaves the stream end in place. Its publish moves
     * the end past the whole train, the part the worker sent itself counting
     * as drained, and io's drain of the rest reaches the end. */
    {
        auto tx = duct_olb_tx_new(room_test_cap);
        CHECK(tx, "alloc (positions)");
        uint64_t empty = tx->stream_end;
        CHECK(duct_olb_tx_drained(tx) == empty && duct_olb_tx_published(tx) == 0u,
              "an empty ring is drained up to its end, nothing queued");
        CHECK(s_stage_fill(tx, 300u) == olb_tx_ok && s_stage_fill(tx, 200u) == olb_tx_ok,
              "stage a train of two frames");
        CHECK(tx->stream_end == empty && duct_olb_tx_published(tx) == 0u,
              "an unpublished train leaves the end in place and queues nothing");
        duct_olb_tx_advance_worker(tx, 350u);
        duct_olb_tx_publish(tx);
        uint64_t end = tx->stream_end;
        CHECK(end == empty + 500u, "the publish moves the end past the whole train, sent part included");
        CHECK(duct_olb_tx_drained(tx) == empty + 350u && duct_olb_tx_published(tx) == 150u,
              "the bytes a worker's direct send took are drained, its rest queued up to the end");
        duct_olb_tx_advance(tx, 150u);
        CHECK(duct_olb_tx_drained(tx) == end && duct_olb_tx_published(tx) == 0u,
              "io's drain reaches the end");
        duct_olb_del(&tx->h);
    }

    /* Positions in two passes: the stream end counts each pass's bytes, and a
     * head at the first pass's end, folded or not, is drained up to it. */
    {
        auto tx = duct_olb_tx_new(room_test_cap);
        CHECK(tx, "alloc (positions across a fold)");
        size_t fill = tx->h.buf_size - 100u,
               lead = 1000u;
        CHECK(s_stage_fill(tx, fill) == olb_tx_ok, "stage up to fill");
        duct_olb_tx_publish(tx);
        uint64_t first = tx->stream_end;
        duct_olb_tx_advance(tx, lead);
        CHECK(s_stage_fill(tx, 600u) == olb_tx_ok && tx->stage_gen == 1u,
              "stage into a second pass");
        duct_olb_tx_publish(tx);
        uint64_t second = tx->stream_end;
        CHECK(first == fill && second == fill + 600u,
              "the end counts each pass's bytes, none of the first pass's unused rest");
        CHECK(duct_olb_tx_published(tx) == fill - lead + 600u,
              "the queue keeps the first pass's rest beside the second's bytes");
        CHECK(duct_olb_tx_drained(tx) == lead,
              "io in the first pass is drained up to its head there");
        duct_olb_tx_advance(tx, fill - lead);
        CHECK(duct_olb_tx_drained(tx) == first,
              "a head at the first pass's end is drained up to that pass's end");
        CHECK(duct_olb_tx_published(tx) == 600u, "after the fold only the second pass is queued");
        uint64_t head = 0u;
        CHECK(duct_olb_tx_readable(tx, &head) == 600u && head == 0u,
              "io folds into the second pass");
        CHECK(duct_olb_tx_drained(tx) == first,
              "a folded head at the second pass's start is drained up to the first pass's end");
        duct_olb_tx_advance(tx, 600u);
        CHECK(duct_olb_tx_drained(tx) == second && duct_olb_tx_published(tx) == 0u,
              "io's drain of the second pass reaches its end");
        duct_olb_del(&tx->h);
    }

    /* A wrap on an idle ring leaves io's head at the old pass's end, and a
     * train sent whole rewinds the stage to the new pass's start: the ring
     * reads drained past the train with no send to fold the head. */
    {
        auto tx = duct_olb_tx_new(room_test_cap);
        CHECK(tx, "alloc (positions past an unfolded pass)");
        size_t fill = tx->h.buf_size - 100u;
        CHECK(s_stage_fill(tx, fill) == olb_tx_ok, "stage up to fill");
        duct_olb_tx_publish(tx);
        duct_olb_tx_advance(tx, fill);
        CHECK(s_stage_fill(tx, 200u) == olb_tx_ok && tx->stage_gen == 1u, "an idle ring wraps");
        duct_olb_tx_sent_staged(tx);
        uint64_t tail = duct_atomic_load(&tx->h.tail, relaxed);
        CHECK(olb_gen(tail) == 1u && olb_off(tail) == 0u
                  && tail == duct_olb_tx_stage_packed(tx),
              "a train sent whole rewinds to the new pass's start");
        CHECK(olb_gen(duct_atomic_load(&tx->h.head, relaxed)) == 0u,
              "io has not folded into the new pass");
        CHECK(tx->stream_end == fill + 200u && duct_olb_tx_drained(tx) == tx->stream_end
                  && duct_olb_tx_published(tx) == 0u,
              "a pass io drained without folding leaves the ring drained past the sent train");
        duct_olb_del(&tx->h);
    }

    /* A train the socket takes whole and a send past the ring each move the
     * stream end, drained with nothing queued. */
    {
        auto tx = duct_olb_tx_new(room_test_cap);
        CHECK(tx, "alloc (positions, train sent whole)");
        uint64_t start = tx->stream_end;
        CHECK(s_stage_fill(tx, 300u) == olb_tx_ok, "stage one frame");
        duct_olb_tx_sent_staged(tx);
        CHECK(tx->stream_end == start + 300u && duct_olb_tx_drained(tx) == tx->stream_end
                  && duct_olb_tx_published(tx) == 0u,
              "a train the socket took whole moves the end past itself, drained");
        duct_olb_tx_sent_direct(tx, 100u);
        CHECK(tx->stream_end == start + 400u && duct_olb_tx_drained(tx) == tx->stream_end,
              "a direct send past the ring moves the end, drained");
        duct_olb_del(&tx->h);
    }

    /* The idle check rewinds a drained ring alone, and gives the pages back
     * once a drained pass falls past olb_tx_trim_div below the one before. */
    {
        auto tx = duct_olb_tx_new(duct_max(room_test_cap * 16u, duct_page_size() * 16u));
        CHECK(tx, "alloc (rewind)");
        uint64_t head = 0u;
        CHECK(s_stage_fill(tx, 300u) == olb_tx_ok, "stage a short queue");
        duct_olb_tx_publish(tx);
        CHECK(!duct_olb_tx_rewind_idle(tx) && tx->stage_gen == 0u && tx->h.stage == 300u,
              "a ring io has not drained is not idle and keeps its pass");
        duct_olb_tx_advance(tx, 300u);
        CHECK(s_stage_fill(tx, 100u) == olb_tx_ok, "stage behind the drained queue");
        CHECK(duct_olb_tx_rewind_idle(tx) && tx->stage_gen == 0u && tx->h.stage == 400u,
              "unpublished bytes keep the pass of an idle ring");
        duct_olb_tx_publish(tx);
        duct_olb_tx_advance(tx, 100u);
        CHECK(duct_olb_tx_rewind_idle(tx) && tx->stage_gen == 1u && tx->h.stage == 0u
                  && duct_olb_tx_published(tx) == 0u,
              "a drained ring starts its next pass at offset 0");
        CHECK(duct_olb_tx_rewind_idle(tx) && tx->stage_gen == 1u, "a ring at offset 0 stays in its pass");
        CHECK(duct_olb_tx_readable(tx, &head) == 0u && head == 0u,
              "io folds into the new pass with nothing to read");
        size_t page = duct_page_size();
        duct_olb_tx_min_room_set(tx, page / 2u);
        size_t room = duct_olb_tx_min_room_get(tx),
               deep = 8u * room + page;
        CHECK(s_stage_fill(tx, deep) == olb_tx_ok, "stage a queue eight min_rooms deep");
        duct_olb_tx_publish(tx);
        duct_olb_tx_advance(tx, deep);
        CHECK(duct_olb_tx_rewind_idle(tx) && tx->stage_gen == 2u && tx->h.stage == 0u,
              "a deep queue rewinds as well");
        CHECK(tx->data[deep - 1u] == 'a', "a deep pass keeps its pages through its own drain");
        CHECK(s_stage_fill(tx, 100u) == olb_tx_ok, "stage a short queue past the deep one");
        duct_olb_tx_publish(tx);
        CHECK(duct_olb_tx_readable(tx, &head) == 100u && head == 0u, "io folds into the short queue");
        duct_olb_tx_advance(tx, 100u);
        CHECK(duct_olb_tx_rewind_idle(tx) && tx->stage_gen == 3u && tx->h.stage == 0u,
              "the short queue rewinds");
#ifdef __linux__
        CHECK(tx->data[room - 1u] == 'a' && tx->data[deep - 1u] == 0,
              "a drop to an eighth of the resident span gives the pages past min_room back");
#endif
        size_t mid = room + 2u * page;
        CHECK(s_stage_fill(tx, mid) == olb_tx_ok, "stage a queue longer than the one before");
        duct_olb_tx_publish(tx);
        CHECK(duct_olb_tx_readable(tx, &head) == mid && head == 0u, "io folds into it");
        duct_olb_tx_advance(tx, mid);
        CHECK(duct_olb_tx_rewind_idle(tx) && tx->data[mid - 1u] == 'a',
              "a pass longer than the one before keeps its pages");
        CHECK(s_stage_fill(tx, 100u) == olb_tx_ok, "stage a short queue past it");
        duct_olb_tx_publish(tx);
        CHECK(duct_olb_tx_readable(tx, &head) == 100u && head == 0u, "io folds into that one");
        duct_olb_tx_advance(tx, 100u);
        CHECK(duct_olb_tx_rewind_idle(tx) && tx->data[mid - 1u] == 'a',
              "a drop short of an eighth keeps the pages");
        duct_olb_del(&tx->h);
    }

    /* A short pass drained after one that ran out of room gives back every
     * page past min_room. */
    {
        auto tx = duct_olb_tx_new(duct_max(room_test_cap * 16u, duct_page_size() * 16u));
        CHECK(tx, "alloc (traversal)");
        duct_olb_tx_min_room_set(tx, duct_page_size() / 2u);
        size_t room = duct_olb_tx_min_room_get(tx),
               fill = tx->h.buf_size - 100u;
        uint64_t head = 0u;
        CHECK(s_stage_fill(tx, fill) == olb_tx_ok, "stage up to fill");
        duct_olb_tx_publish(tx);
        duct_olb_tx_advance(tx, fill);
        CHECK(s_stage_fill(tx, 200u) == olb_tx_ok && tx->stage_gen == 1u,
              "a pass out of room wraps");
        duct_olb_tx_publish(tx);
        CHECK(duct_olb_tx_readable(tx, &head) == 200u && head == 0u, "io folds into the wrap");
        duct_olb_tx_advance(tx, 200u);
        CHECK(duct_olb_tx_rewind_idle(tx) && tx->stage_gen == 2u && tx->h.stage == 0u,
              "the short pass past the wrap rewinds");
#ifdef __linux__
        CHECK(tx->data[room - 1u] == 'a' && tx->data[fill - 1u] == 0,
              "a drain past a traversal gives the pages past min_room back");
#endif
        duct_olb_del(&tx->h);
    }

    printf("olb_tx_room_test OK\n");
    return 0;
}
