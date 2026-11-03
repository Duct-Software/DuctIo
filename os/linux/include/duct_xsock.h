/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_xsock.h
 *  @brief Send and receive state of one Linux socket and the sizes it sets: the
 *  lowat in force, the write boundaries of the opening's packets, the cap that
 *  keeps each write under them, the bytes io hands the socket per writable edge,
 *  and the receive buffer that follows what the conn consumes.
 *
 *  Every platform's @c duct_xsock.h supplies @c duct_x_sock_tx_fields,
 *  @c duct_x_sock_tx_of, @c duct_x_sock_stats_fields, @c duct_x_sock_stats_of,
 *  @c duct_x_sock_tx_cap, @c duct_x_sock_tx_piece, @c duct_x_sock_tx_sent,
 *  @c duct_x_sock_tx_quantum, @c duct_x_sock_rx_fields and @c duct_x_sock_rx_of
 *  under these names, and its @c duct_xport.h sets the state up and reads the
 *  socket. The TX ring expands @c duct_x_sock_tx_fields on the line io keeps, so a
 *  worker's direct write reads the cap without touching the socket, and
 *  @c duct_x_sock_stats_fields on the staging worker's line; the RX ring expands
 *  @c duct_x_sock_rx_fields among its io-only fields. Each is reached through its
 *  accessor alone: a platform that keeps none declares no member.
 */

#ifndef DUCT_XSOCK_H
#define DUCT_XSOCK_H

#include "duct_core.h"
#include "duct_xopening.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

/** @brief Sentinel @c wait_from holds once its stretch of unacknowledged bytes
 *  counted a timeout. */
static constexpr uint64_t duct_x_wait_counted = UINT64_MAX;

/** @brief Send state of one stream or connected datagram socket.
 *  All-zero, as a fresh TX ring holds it, is a socket under no bound and no
 *  opening. */
typedef struct duct_x_sock_tx {
    uint32_t _Atomic notsent_lowat; /**< @c TCP_NOTSENT_LOWAT in force, bytes; 0 for
                                      *  none. io stores it, the worker loads it,
                                      *  both relaxed. */
    uint32_t         lowat_max,     /**< Bound the socket was created with, bytes:
                                      *  a TCP socket's lowat, the ceiling a
                                      *  following lowat stays under, or a
                                      *  connected UDP socket's granted send
                                      *  buffer. Set before the conn reaches a
                                      *  worker. */
                     lowat_us;      /**< Unsent span the lowat follows, µs at the
                                      *  pacing rate; 0 leaves it fixed. Set with
                                      *  @c lowat_max. */
    duct_x_opening_t opening;       /**< Write boundaries of the packets staged ahead
                                      *  of a TCP socket's first flight. */
    uint64_t         lowat_at;      /**< Monotonic time io next reads the pacing
                                      *  rate, ns; io only. */
} duct_x_sock_tx_t;

/** @brief State the stats reads of one TCP socket keep between them.
 *  The session's worker alone writes it, in each read of the socket's TCP figures.
 */
typedef struct duct_x_sock_stats {
    uint32_t         seen,          /**< The kernel's own timeout count at the
                                      *  last read: its RTO recoveries, or on a
                                      *  kernel counting none the entries into and
                                      *  exits from @c TCP_CA_Loss the reads saw,
                                      *  odd while the last found the socket in
                                      *  it. */
                     timeouts;      /**< Timeouts the reads report: the kernel's,
                                      *  and one per stretch of bytes left
                                      *  unacknowledged for two RTOs that the
                                      *  kernel counted none in. */
    uint64_t         acked,         /**< @c tcpi_bytes_acked at the read that
                                      *  opened the stretch or last found it
                                      *  moved. */
                     wait_from;     /**< Monotonic time the bytes outstanding have
                                      *  waited from, ns; 0 with none outstanding
                                      *  at the last read, @c duct_x_wait_counted
                                      *  once their stretch counted a timeout. */
} duct_x_sock_stats_t;

/** @brief TX ring members this platform adds: the socket's send state. */
#define duct_x_sock_tx_fields duct_x_sock_tx_t sock;

/** @brief Send state TX ring @p tx carries. */
#define duct_x_sock_tx_of(tx) (&(tx)->sock)

/** @brief TX ring members this platform adds on the staging worker's line: the
 *  state of the socket's stats reads. */
#define duct_x_sock_stats_fields duct_x_sock_stats_t stats;

/** @brief Stats-read state TX ring @p tx carries. */
#define duct_x_sock_stats_of(tx) (&(tx)->stats)

/** @brief Receive state of one TCP socket whose buffer follows what its conn
 *  consumes.
 *  io alone reads and writes it. All-zero, as a fresh RX ring holds it, is a
 *  socket left to the kernel's own tuning. */
typedef struct duct_x_sock_rx {
    uint64_t at,     /**< Monotonic time of the last step, ns; 0 while the
                       *  kernel tunes the buffer itself. */
             mark;   /**< Bytes the conn had consumed at the last step. */
    uint32_t floor,  /**< Window the socket opened with, bytes, the least any
                       *  step sets. */
             window, /**< Window the last step chose, bytes: the clamp it set,
                       *  and the bytes consumed past @c mark that make the next
                       *  step due. */
             buf;    /**< @c SO_RCVBUF request in force, bytes, which the kernel
                       *  doubles: the larger of the last two windows. */
} duct_x_sock_rx_t;

/** @brief RX ring members this platform adds: the socket's receive state. */
#define duct_x_sock_rx_fields duct_x_sock_rx_t rcv;

/** @brief Receive state RX ring @p rx carries. */
#define duct_x_sock_rx_of(rx) (&(rx)->rcv)

/** @brief Twice the lowat in force while it sits under @c lowat_max, else 0. */
duct_nonnull(1) static inline size_t
duct_x_sock_tx_lowat_cap(const duct_x_sock_tx_t *x)
{
    uint32_t lowat = duct_atomic_load(&x->notsent_lowat, relaxed);
    return lowat < x->lowat_max ? 2u * (size_t)lowat : 0u;
}

/** @brief Read the piece the opening's packets give the socket's next write, 0
 *  for none. */
duct_nonnull(1) static inline size_t
duct_x_sock_tx_piece(const duct_x_sock_tx_t *x)
{
    return duct_x_opening_piece(&x->opening);
}

/** @brief Count @p n bytes the socket took toward the opening's packets. */
duct_nonnull(1) static inline void
duct_x_sock_tx_sent(duct_x_sock_tx_t *x, size_t n)
{
    duct_x_opening_sent(&x->opening, n);
}

/** @brief Most bytes one stream write may hand the socket, 0 for no cap, with the
 *  send flags that write takes stored in @p flags.
 *  The smaller non-zero of the lowat cap and the opening's piece, under
 *  @c MSG_EOR: @c tcp_sendmsg checks the lowat only before a new skb and appends
 *  to an unsent one otherwise, up to 64 KB past the lowat, and the flag ends each
 *  write's skb, so the next write meets the check and a piece goes out as its own
 *  skb. With neither no cap applies and @p flags is 0. */
duct_nonnull(1, 2) static inline size_t
duct_x_sock_tx_cap(const duct_x_sock_tx_t *x, int *flags)
{
    size_t cap = duct_x_sock_tx_lowat_cap(x),
           piece = duct_x_sock_tx_piece(x);
    cap = piece && (!cap || piece < cap) ? piece : cap;
    *flags = cap ? MSG_EOR : 0;
    return cap;
}

/** @brief Bytes io hands the socket per writable edge.
 *  The lowat cap, or half of @c lowat_max where none applies: a TCP socket at
 *  its lowat ceiling reports @c EPOLLOUT once its unsent bytes fall under half
 *  the lowat, and a connected UDP socket reports writable under half its
 *  granted send buffer. 0 for a socket with neither. The opening's piece never
 *  enters it. */
duct_nonnull(1) static inline size_t
duct_x_sock_tx_quantum(const duct_x_sock_tx_t *x)
{
    size_t cap = duct_x_sock_tx_lowat_cap(x);
    return cap ? cap : x->lowat_max / 2u;
}

#endif
