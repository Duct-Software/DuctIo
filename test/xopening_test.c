/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file xopening_test.c
 *  @brief The opening layer driven without a socket or an engine: the loop that
 *  hands a protocol's packets to a conn, and the write boundaries a stream socket
 *  keeps for them.
 *
 *  @c sc_emit holds the loop to its three ends, a length of 0, a length past the
 *  room and a sink that refuses, to the source's index counting from 0, and to the
 *  bytes reaching the sink as the source wrote them. @c sc_cuts walks the
 *  boundaries: each piece is the rest of the packet at the head, a short write
 *  leaves the rest as the next piece, the bytes of a lead staged ahead of the
 *  first packet are a piece of their own, bytes past the end count for nothing,
 *  and a ninth entry, a zero length and a figure past 16 bits are refused.
 *  @c sc_race has a writer push eight packets while a reader takes pieces off the
 *  same state, and the reader's takes are the packets' lengths, in order.
 */

#include "duct.h"
#include "duct_xopening.h"

#include <pthread.h>
#include <stdio.h>

#include "test_helpers.h"

static_assert(duct_x_opening_max == 8u, "the stream opening holds eight packets");

/** @brief What the loop's test source was asked and how it answers. */
typedef struct {
    size_t   len[4];     /**< Lengths of the packets it hands out. */
    unsigned count,      /**< How many of them. */
             asks,       /**< Times the loop asked. */
             skew;       /**< Asks whose index was not the number of asks before it. */
    size_t   room;       /**< The room the last ask offered. */
} src_t;

/** @brief Test source handing out @c len[idx] bytes of @c idx * 16 + position. */
static size_t src_next(void *ctx, unsigned idx, uint8_t *out, size_t cap)
{
    auto src = (src_t *)ctx;
    src->skew += idx != src->asks;
    ++src->asks;
    src->room = cap;
    if (idx >= src->count)
        return 0u;
    size_t n = src->len[idx];
    for (size_t j = 0u; j < n && n <= cap; ++j)
        out[j] = (uint8_t)(idx * 16u + j);
    return n;
}

/** @brief What the loop's test sink took. */
typedef struct {
    size_t   len[8];
    uint8_t  first[8];   /**< First byte of each packet taken. */
    unsigned taken,
             refuse_at;  /**< Packet count at which the sink refuses. */
} sink_t;

/** @brief Test sink taking packets up to @c refuse_at of them, eight at most. */
static bool sink_put(void *sink, duct_view_u8 bytes)
{
    auto s = (sink_t *)sink;
    if (s->taken >= s->refuse_at || s->taken >= 8u)
        return false;
    s->len[s->taken] = bytes.size;
    s->first[s->taken] = ((const uint8_t *)bytes.data)[0];
    ++s->taken;
    return true;
}

/** @brief Drive the emit loop to each of its ends.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_emit(void)
{
    uint8_t buf[64];
    src_t src = { .len = { 5u, 9u, 20u, 1u }, .count = 4u };
    sink_t sink = { .refuse_at = ~0u };
    unsigned took = duct_x_opening_emit(src_next, &src, buf, sizeof buf, sink_put, &sink);
    if (took != 4u || sink.taken != 4u || src.asks != 5u || src.skew)
        return "the loop did not ask once per packet and once more for the end, from 0";
    for (unsigned i = 0u; i < 4u; ++i)
        if (sink.len[i] != src.len[i] || sink.first[i] != (uint8_t)(i * 16u))
            return "a packet changed between the source and the sink";
    if (src.room != sizeof buf)
        return "the source was offered other room than the buffer's";

    src = (src_t){ .len = { 5u, 70u, 3u, 3u }, .count = 4u };
    sink = (sink_t){ .refuse_at = ~0u };
    took = duct_x_opening_emit(src_next, &src, buf, sizeof buf, sink_put, &sink);
    if (took != 1u || sink.taken != 1u)
        return "a packet past the room did not end the opening";

    src = (src_t){ .len = { 5u, 6u, 7u, 8u }, .count = 4u };
    sink = (sink_t){ .refuse_at = 2u };
    took = duct_x_opening_emit(src_next, &src, buf, sizeof buf, sink_put, &sink);
    if (took != 2u || src.asks != 3u)
        return "a refusing sink did not end the opening at its refusal";

    src = (src_t){ .count = 0u };
    sink = (sink_t){ .refuse_at = ~0u };
    took = duct_x_opening_emit(src_next, &src, buf, sizeof buf, sink_put, &sink);
    if (took != 0u || src.asks != 1u)
        return "an empty source did not end the opening at once";
    return nullptr;
}

/** @brief Stage a packet the way the worker does: room, then push. */
static bool stage(duct_x_opening_t *o, uint64_t ahead, size_t len)
{
    if (!duct_x_opening_room(o, ahead, len))
        return false;
    duct_x_opening_push(o, ahead, len);
    return true;
}

/** @brief Walk the write boundaries through staging, short writes and refusals.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_cuts(void)
{
    duct_x_opening_t o = {};
    if (duct_x_opening_piece(&o) != 0u)
        return "an opening never staged capped a write";
    duct_x_opening_sent(&o, 500u);
    if (o.sent != 0u)
        return "an opening never staged counted bytes";

    if (!stage(&o, 0u, 100u) || !stage(&o, 0u, 50u) || !stage(&o, 0u, 7u))
        return "three packets were refused";
    if (duct_x_opening_piece(&o) != 100u)
        return "the first piece is not the first packet";
    duct_x_opening_sent(&o, 60u);
    if (duct_x_opening_piece(&o) != 40u)
        return "a short write did not leave the rest of its packet as the piece";
    duct_x_opening_sent(&o, 40u);
    if (duct_x_opening_piece(&o) != 50u)
        return "the second piece is not the second packet";
    duct_x_opening_sent(&o, 50u);
    if (duct_x_opening_piece(&o) != 7u)
        return "the third piece is not the third packet";
    duct_x_opening_sent(&o, 7u);
    if (duct_x_opening_piece(&o) != 0u)
        return "a spent opening still capped a write";
    uint32_t done = o.sent;
    duct_x_opening_sent(&o, 1000u);
    if (o.sent != done)
        return "bytes kept counting past the end";

    o = (duct_x_opening_t){};
    if (!stage(&o, 30u, 100u))
        return "a packet behind a lead was refused";
    if (duct_x_opening_piece(&o) != 30u)
        return "the lead ahead of the first packet is not a piece of its own";
    duct_x_opening_sent(&o, 30u);
    if (duct_x_opening_piece(&o) != 100u)
        return "the first packet behind a lead is not the piece after it";
    if (!stage(&o, UINT64_C(1) << 40, 20u))
        return "a second packet was refused over a figure only the first reads";
    duct_x_opening_sent(&o, 100u);
    if (duct_x_opening_piece(&o) != 20u)
        return "the second packet behind a lead is not the next piece";

    o = (duct_x_opening_t){};
    for (unsigned i = 0u; i < duct_x_opening_max; ++i)
        if (!stage(&o, 0u, 3u))
            return "a packet within the limit was refused";
    if (stage(&o, 0u, 3u))
        return "a ninth packet was taken";
    o = (duct_x_opening_t){};
    for (unsigned i = 0u; i + 1u < duct_x_opening_max; ++i)
        if (!stage(&o, 5u, 3u))
            return "a packet within the limit, behind a lead, was refused";
    if (stage(&o, 5u, 3u))
        return "a packet past the limit, behind a lead, was taken";

    o = (duct_x_opening_t){};
    if (stage(&o, 0u, 0u) || stage(&o, 0u, (size_t)UINT16_MAX + 1u)
        || stage(&o, (uint64_t)UINT16_MAX + 1u, 3u))
        return "an empty packet, one past 16 bits or a lead past 16 bits was taken";
    if (!stage(&o, 0u, UINT16_MAX) || duct_x_opening_piece(&o) != UINT16_MAX)
        return "a packet of 16 bits was refused";
    return nullptr;
}

/** @brief What the race's two sides share. */
typedef struct {
    duct_x_opening_t o;
    size_t           len[8];
} race_t;

/** @brief Push the eight packets of a @c race_t, a millisecond apart. */
static void *race_writer(void *arg)
{
    auto r = (race_t *)arg;
    for (unsigned i = 0u; i < 8u; ++i) {
        duct_x_opening_push(&r->o, 0u, r->len[i]);
        th_sleep_ms(1u);
    }
    return nullptr;
}

/** @brief Read pieces off a state a writer thread is staging.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_race(void)
{
    race_t r = { .len = { 64u, 120u, 33u, 700u, 1200u, 17u, 5u, 4000u } };
    pthread_t th;
    if (pthread_create(&th, nullptr, race_writer, &r) != 0)
        return "writer thread create failed";
    size_t total = 0u;
    unsigned taken = 0u;
    const char *err = nullptr;
    for (unsigned spins = 0u; taken < 8u && spins < 20'000u; ++spins) {
        size_t piece = duct_x_opening_piece(&r.o);
        if (!piece) {
            th_sleep_ms(1u);
            continue;
        }
        if (piece != r.len[taken]) {
            err = "a piece other than the next packet, whole, was read off a state being written";
            break;
        }
        duct_x_opening_sent(&r.o, piece);
        total += piece;
        ++taken;
    }
    pthread_join(th, nullptr);
    if (err)
        return err;
    size_t want = 0u;
    for (unsigned i = 0u; i < 8u; ++i)
        want += r.len[i];
    return taken == 8u && total == want ? nullptr : "the reader did not take all eight packets";
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    const char *err = sc_emit();
    if (!err)
        err = sc_cuts();
    if (!err)
        err = sc_race();
    if (err) {
        fprintf(stderr, "xopening: %s\n", err);
        return 1;
    }
    printf("xopening: OK (the loop's ends, the stream cuts, a reader against a writer)\n");
    return 0;
}
