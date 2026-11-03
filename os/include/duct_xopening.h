/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_xopening.h
 *  @brief The opening of a dialed conn: the packets its protocol puts on the wire
 *  ahead of its first handshake flight, on a datagram socket and on a stream
 *  socket alike.
 *
 *  The protocol supplies the packets through a source, @ref duct_x_opening_next_t,
 *  and @ref duct_x_opening_emit asks it for one at a time and hands each to the
 *  conn's TX through a sink. The size, count and bytes of a packet are the
 *  protocol's, and a protocol with no source has no opening.
 *
 *  A datagram socket needs no more: its TX ring keeps a record per datagram, so
 *  each packet leaves as one. A stream socket's ring holds one byte stream, so the
 *  packets' ends are written down in a @ref duct_x_opening_t, which the socket's
 *  send state carries, and io cuts each write at the next end: the packets leave
 *  as writes of their own, the first flight behind them. The worker that stages
 *  the packets alone writes the ends; io and a worker's direct write read them
 *  through @c duct_x_sock_tx_piece and count the bytes taken through
 *  @c duct_x_sock_tx_sent.
 *
 *  - @c end is the one member published to io: the ends before it are final.
 *  - @c sent is the one member that changes once the packets are staged.
 *  - All-zero is no opening, which is what a fresh TX ring holds.
 */

#ifndef DUCT_XOPENING_H
#define DUCT_XOPENING_H

#include "duct_core.h"
#include "duct_types.h"

#include <assert.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

/** @brief Source of a conn's opening packets.
 *  Writes packet @p idx, counting from 0, into the @p cap bytes at @p out and
 *  returns its length. A length of 0 ends the opening, and so does one past @p cap.
 */
typedef size_t (*duct_x_opening_next_t)(void *ctx, unsigned idx, uint8_t *out, size_t cap);

/** @brief Sink of a conn's opening packets.
 *  Takes the bytes of one, whole, and answers false once the conn takes no more.
 */
typedef bool (*duct_x_opening_put_t)(void *sink, duct_view_u8 bytes);

/** @brief Entries a stream socket's opening holds, a stream lead ahead of the
 *  first packet taking one.
 */
static constexpr unsigned duct_x_opening_max = 8u;

/** @brief Write boundaries of the packets staged ahead of a stream socket's first
 *  flight.
 */
typedef struct duct_x_opening {
    uint32_t _Atomic sent, /**< Stream bytes the socket has taken, counted until it
                             *  reaches @c end. io's drive and a worker's direct
                             *  write add to it, relaxed. */
                     end;  /**< Stream bytes the staged packets span, a stream lead
                             *  ahead of them included; 0 for none. The staging
                             *  worker stores it with release behind each packet's
                             *  @c cut. */
    uint16_t         cut[duct_x_opening_max]; /**< Bytes of each staged packet, in
                             *  stream order, a stream lead's first. */
} duct_x_opening_t;

/** @brief Count the entries of @p o in use, a stream lead's included.
 *  An unused entry of @c cut is 0, which no staged length is.
 */
duct_nonnull(1) static inline unsigned
duct_x_opening_count(const duct_x_opening_t *o)
{
    unsigned n = 0u;
    while (n < duct_x_opening_max && o->cut[n] != 0u)
        ++n;
    return n;
}

/** @brief Hand @p sink the packets @p next supplies, each in @p buf.
 *  The source writes into the @p room bytes at @p buf, and what it returns goes to
 *  @p put as it is. The opening ends at a length of 0, at one past @p room and at
 *  the first packet @p put refuses.
 *  @return the packets @p put took.
 */
static inline unsigned
duct_x_opening_emit(duct_x_opening_next_t next, void *ctx, uint8_t *buf, size_t room,
                    duct_x_opening_put_t put, void *sink)
{
    unsigned taken = 0u;
    for (;; ++taken) {
        size_t n = next(ctx, taken, buf, room);
        if (n == 0u || n > room || !put(sink, (duct_view_u8){ .data = buf, .size = n }))
            return taken;
    }
}

/** @brief Tell whether @p o has room for a packet of @p len bytes with @p ahead
 *  stream bytes before it.
 *  @p ahead counts only while @p o is empty, when a stream lead takes an entry of
 *  its own. A packet of 0 bytes or over 65535, a lead over 65535 and a ninth entry
 *  have no room.
 */
duct_nonnull(1) static inline bool
duct_x_opening_room(const duct_x_opening_t *o, uint64_t ahead, size_t len)
{
    unsigned n = duct_x_opening_count(o);
    bool lead = n == 0u && ahead != 0u;
    return len != 0u && len <= UINT16_MAX && (!lead || ahead <= UINT16_MAX)
        && n + (lead ? 2u : 1u) <= duct_x_opening_max;
}

/** @brief Write down a staged packet of @p len bytes.
 *  Called before the packet's bytes are published, and only after
 *  @ref duct_x_opening_room answered true for the same arguments. The staging
 *  worker alone calls it.
 */
duct_nonnull(1) static inline void
duct_x_opening_push(duct_x_opening_t *o, uint64_t ahead, size_t len)
{
    assert(duct_x_opening_room(o, ahead, len));
    unsigned n = duct_x_opening_count(o);
    uint32_t end = duct_atomic_load(&o->end, relaxed);
    if (n == 0u && ahead != 0u) {
        o->cut[n++] = (uint16_t)ahead;
        end += (uint32_t)ahead;
    }
    o->cut[n] = (uint16_t)len;
    duct_atomic_store(&o->end, end + (uint32_t)len, release);
}

/** @brief Read the piece the next write of @p o's socket takes.
 *  The bytes left in the packet at the head, 0 where the staged packets are all out.
 */
duct_nonnull(1) static inline size_t
duct_x_opening_piece(const duct_x_opening_t *o)
{
    uint32_t sent = duct_atomic_load(&o->sent, relaxed),
             end = duct_atomic_load(&o->end, acquire),
             at = 0u;
    for (unsigned i = 0u; i < duct_x_opening_max && sent < end; ++i) {
        at += o->cut[i];
        if (sent < at)
            return at - sent;
    }
    return 0u;
}

/** @brief Count @p n bytes @p o's socket took.
 *  Nothing counts once @c sent has reached @c end.
 */
duct_nonnull(1) static inline void
duct_x_opening_sent(duct_x_opening_t *o, size_t n)
{
    if (duct_atomic_load(&o->sent, relaxed) < duct_atomic_load(&o->end, relaxed))
        duct_atomic_fetch(add, &o->sent, (uint32_t)duct_min(n, (size_t)INT32_MAX), relaxed);
}

#endif
