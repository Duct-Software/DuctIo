/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file olb_tx_room_test.c
 * @brief Unit test for the TX descriptor ring's admission, staging and the
 * §5.2 completion stepper.
 * What @ref duct_olb_tx_room_contig answers over its two limbs — the byte
 * budget and the descriptor count — the staged record walk with its wire-byte
 * accounting, the materialize arena's contiguous runs and their completion
 * order, the cursor a short write leaves inside the head record, and the
 * worker's own direct-send settlement of its staged records. The stream end
 * the worker keeps through publishes, sends of its own and completions, and
 * the point io has drained up to, are checked through the same cases. So is
 * the TX-wait value latch: a target the drained position crosses fires the
 * edge exactly once.
 * Driven directly against a @c duct_olb_tx_t, with no engine and no io
 * thread.
 */

#define _GNU_SOURCE

#include "duct_conn_block.h"
#include "duct_olb_tx.h"

#include "duct_core.h"

#include <stdio.h>
#include <string.h>

#define CHECK(expr, msg) \
    do { if (!(expr)) { fprintf(stderr, "FAIL: %s\n", msg); return 1; } } while (0)

/* AI-generated test code. */
static duct_olb_tx_t *s_tx_new(size_t cap)
{
    auto conn = duct_conn_acquire();
    if (!conn)
        return nullptr;
    conn->xport_type = x_tcp;
    duct_conn_carve_olb(conn, 256u, cap);
    return duct_conn_tx_olb(conn);
}

static void s_tx_del(duct_olb_tx_t *tx)
{
    duct_conn_release((duct_conn_t *)((uintptr_t)tx - conn_off_tx));
}

static constexpr size_t room_test_cap = kbytes(4u);

/** @brief Stage one whole materialize record of @p fill payload bytes plus a
 *  4-byte inline header. */
static duct_olb_tx_result_t s_stage_fill(duct_olb_tx_t *tx, size_t fill)
{
    uint8_t hdr[4] = { 1u, 2u, 3u, 4u };
    auto filler = duct_at(duct_new(char, fill));
    if (!filler)
        return olb_tx_too_large;
    memset(filler, 'a', fill);
    auto rc = duct_olb_tx_stage(tx, hdr, sizeof hdr, filler, fill);
    duct_del(filler);
    return rc;
}

int main(void)
{
    /* Tail-room disjunct: fresh ring, small need well within the budget. */
    {
        auto tx = s_tx_new(room_test_cap);
        CHECK(tx, "alloc (tail-room case)");
        CHECK(duct_olb_tx_room_contig(tx, 100u), "tail room must fit a small need");
        s_tx_del(tx);
    }

    /* A record past the byte budget never fits, whatever the descriptors. */
    {
        auto tx = s_tx_new(room_test_cap);
        CHECK(tx, "alloc (too large)");
        CHECK(!duct_olb_tx_room_contig(tx, duct_olb_tx_byte_cap(tx) + 1u),
              "a need past the budget is terminal");
        s_tx_del(tx);
    }

    /* The budget fills: staged-but-unpublished bytes count against it. */
    {
        auto tx = s_tx_new(room_test_cap);
        CHECK(tx, "alloc (budget)");
        size_t fill = duct_olb_tx_byte_cap(tx) - 100u;
        CHECK(s_stage_fill(tx, fill) == olb_tx_ok, "stage up to the budget");
        CHECK(duct_olb_tx_bytes_held(tx) == fill + 4u,
              "staged bytes count against the budget");
        CHECK(!duct_olb_tx_room_contig(tx, 100u),
              "a staged need past the budget is refused");
        duct_olb_tx_publish(tx);
        CHECK(duct_olb_tx_published(tx) == fill + 4u,
              "publishing moves the stream end past the record");
        duct_olb_tx_advance(tx, fill + 4u, false);
        CHECK(duct_olb_tx_published(tx) == 0u, "io must be idle here");
        CHECK(duct_olb_tx_room_contig(tx, 100u), "the drained budget reopens");
        s_tx_del(tx);
    }

    /* The descriptor count is the second limb: byte-sized records under the
     * build's full budget fill the ring's slots long before the budget runs
     * out, and completion of any one frees a slot again. */
    {
        auto tx = s_tx_new(duct_conn_tx_olb_cap);
        CHECK(tx, "alloc (descriptor count)");
        unsigned staged = 0u;
        while (s_stage_fill(tx, 8u) == olb_tx_ok)
            ++staged;
        CHECK(staged == duct_conn_tx_desc_n,
              "the staged walk stops exactly at the descriptor count");
        CHECK(duct_olb_tx_bytes_held(tx) + 4096u <= duct_olb_tx_byte_cap(tx),
              "the byte budget still has headroom past the full slots");
        CHECK(s_stage_fill(tx, 8u) == olb_tx_full,
              "a full descriptor ring is backpressure");
        duct_olb_tx_publish(tx);
        duct_olb_tx_advance(tx, 12u, false);
        CHECK(duct_olb_tx_descs_held(tx) == duct_conn_tx_desc_n - 1u,
              "one completion frees one slot");
        CHECK(s_stage_fill(tx, 8u) == olb_tx_ok, "the freed slot stages again");
        s_tx_del(tx);
    }

    /* The materialize arena wraps: a run crossing the arena's end is refused
     * even where the free bytes exist across it, and the front reopens only
     * past the wrap. */
    {
        auto tx = s_tx_new(duct_conn_tx_olb_cap);
        CHECK(tx, "alloc (arena wrap)");
        size_t first = duct_conn_tx_mat_cap - 64u;
        CHECK(s_stage_fill(tx, first) == olb_tx_ok, "stage up to the arena's end");
        duct_olb_tx_publish(tx);
        duct_olb_tx_advance(tx, first + 4u, false);
        CHECK(s_stage_fill(tx, 48u) == olb_tx_ok, "a run inside the freed tail fits");
        CHECK(s_stage_fill(tx, 32u) == olb_tx_full,
              "a run crossing the arena's end is refused");
        CHECK(s_stage_fill(tx, 16u) == olb_tx_ok, "the tail's last bytes fill");
        duct_olb_tx_publish(tx);
        duct_olb_tx_advance(tx, 68u, false);
        CHECK(s_stage_fill(tx, 32u) == olb_tx_ok,
              "the wrap reopened the arena's front");
        s_tx_del(tx);
    }

    /* The stepper: a short write leaves the cursor inside the head record,
     * the gather resumes past it, and the record completes — its arena bytes
     * back with it — only at the last byte. */
    {
        auto tx = s_tx_new(room_test_cap);
        CHECK(tx, "alloc (stepper)");
        CHECK(s_stage_fill(tx, 300u) == olb_tx_ok && s_stage_fill(tx, 200u) == olb_tx_ok,
              "stage two records");
        duct_olb_tx_publish(tx);
        duct_view_u8 iov[2u * duct_tx_peek_recs];
        unsigned n = duct_olb_tx_peek_iov(tx, false, duct_tx_peek_recs, iov);
        CHECK(n == 4u, "two records gather four spans");
        size_t total = 0u;
        for (unsigned i = 0u; i < n; ++i)
            total += iov[i].size;
        CHECK(total == 508u, "the gather spans both records");
        duct_olb_tx_advance(tx, 350u, false);
        CHECK(duct_atomic_load(&tx->cursor_off, relaxed) == 46u,
              "the cursor rests inside the second record");
        CHECK(duct_olb_tx_published(tx) == 204u,
              "the unfinished record stays whole against the budget");
        n = duct_olb_tx_peek_iov(tx, false, duct_tx_peek_recs, iov);
        CHECK(n == 2u && iov[0].size == 0u && iov[1].size == 158u,
              "the resume gather skips the sent head bytes");
        duct_olb_tx_advance(tx, 158u, false);
        CHECK(duct_olb_tx_published(tx) == 0u && duct_olb_tx_descs_held(tx) == 0u,
              "the last byte completes the record and the ring");
        CHECK(duct_atomic_load(&tx->mat_head, relaxed) == 500u,
              "the arena returned both runs");
        s_tx_del(tx);
    }

    /* A record-framed leg ships its head record whole or not at all. */
    {
        auto tx = s_tx_new(room_test_cap);
        CHECK(tx, "alloc (record framed)");
        CHECK(s_stage_fill(tx, 300u) == olb_tx_ok && s_stage_fill(tx, 200u) == olb_tx_ok,
              "stage two records");
        duct_olb_tx_publish(tx);
        duct_view_u8 iov[2u * duct_tx_peek_recs];
        unsigned n = duct_olb_tx_peek_iov(tx, true, duct_tx_peek_recs, iov);
        CHECK(n == 2u && iov[0].size == 4u && iov[1].size == 300u,
              "a record-framed gather answers its head record alone");
        duct_olb_tx_advance(tx, 100u, true);
        CHECK(duct_olb_tx_descs_held(tx) == 2u && duct_atomic_load(&tx->cursor_off, relaxed) == 0u,
              "a partial datagram send completes nothing");
        duct_olb_tx_advance(tx, 304u, true);
        CHECK(duct_olb_tx_descs_held(tx) == 1u, "the whole record completes alone");
        s_tx_del(tx);
    }

    /* A train the socket took whole rewinds its staging, leaves io nothing
     * and moves the stream end past itself; one taken in part publishes the
     * unsent remainder alone, io starting at its first byte. */
    {
        auto tx = s_tx_new(room_test_cap);
        CHECK(tx, "alloc (train sent whole)");
        CHECK(s_stage_fill(tx, 300u) == olb_tx_ok && s_stage_fill(tx, 200u) == olb_tx_ok,
              "stage a train of two records");
        CHECK(duct_olb_tx_published(tx) == 0u, "a train stays unpublished while it runs");
        duct_olb_tx_sent_staged(tx);
        CHECK(tx->h.stage == 0u && duct_olb_tx_published(tx) == 0u && tx->stream_end == 508u,
              "a train sent whole leaves nothing staged, nothing for io, its bytes in the end");
        CHECK(s_stage_fill(tx, 100u) == olb_tx_ok && tx->h.stage == 1u,
              "the next record stages after the sent train");
        s_tx_del(tx);
    }
    {
        auto tx = s_tx_new(room_test_cap);
        CHECK(tx, "alloc (train sent in part)");
        CHECK(s_stage_fill(tx, 300u) == olb_tx_ok && s_stage_fill(tx, 200u) == olb_tx_ok,
              "stage a train of two records");
        duct_olb_tx_advance_worker(tx, 350u);
        duct_olb_tx_publish(tx);
        CHECK(duct_olb_tx_published(tx) == 204u,
              "the refused record publishes whole, its sent head accounted");
        duct_view_u8 iov[2u * duct_tx_peek_recs];
        unsigned n = duct_olb_tx_peek_iov(tx, false, duct_tx_peek_recs, iov);
        CHECK(n == 2u && iov[0].size == 0u && iov[1].size == 158u,
              "io starts at the first byte the socket refused");
        duct_olb_tx_advance(tx, 158u, false);
        CHECK(duct_olb_tx_published(tx) == 0u, "io's drain of the tail empties the ring");
        s_tx_del(tx);
    }

    /* The wait latch: a target the drained position crosses fires the edge
     * exactly once, and an unarmed word never crosses. */
    {
        auto tx = s_tx_new(room_test_cap);
        CHECK(tx, "alloc (wait latch)");
        CHECK(s_stage_fill(tx, 300u) == olb_tx_ok, "stage one record");
        duct_olb_tx_publish(tx);
        duct_olb_tx_wait_arm(tx, 150u);
        CHECK(duct_olb_tx_wait_crossed(0u, 150u, 150u), "the crossing edge fires");
        CHECK(!duct_olb_tx_wait_crossed(0u, 149u, 150u), "a shy advance never crosses");
        CHECK(!duct_olb_tx_wait_crossed(150u, 200u, 150u), "a spent target never crosses again");
        CHECK(!duct_olb_tx_wait_crossed(0u, 200u, 0u), "the unarmed word never crosses");
        duct_olb_tx_advance(tx, 100u, false);
        duct_olb_tx_wait_arm(tx, duct_olb_tx_wait_target(tx, 0u));
        duct_olb_tx_advance(tx, 204u, false);
        s_tx_del(tx);
    }

    /* The close paths' purge: records still held — one published, one staged
     * — complete without any send, their arena bytes back, the staging
     * window rewound, and the budget reopened whole. */
    {
        auto tx = s_tx_new(room_test_cap);
        CHECK(tx, "alloc (purge)");
        CHECK(s_stage_fill(tx, 100u) == olb_tx_ok, "stage one record");
        duct_olb_tx_publish(tx);
        CHECK(s_stage_fill(tx, 60u) == olb_tx_ok, "stage a second, unpublished");
        duct_olb_tx_purge(tx);
        CHECK(duct_olb_tx_descs_held(tx) == 0u && tx->h.stage == 0u
              && duct_olb_tx_bytes_held(tx) == 0u,
              "the purge empties published and staged alike");
        CHECK(duct_atomic_load(&tx->mat_head, relaxed) == 160u,
              "both arena runs returned");
        CHECK(duct_olb_tx_room_contig(tx, 100u), "the budget reopens whole");
        s_tx_del(tx);
    }

    printf("olb_tx_room_test OK\n");
    return 0;
}
