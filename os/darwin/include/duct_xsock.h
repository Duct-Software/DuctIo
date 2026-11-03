/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, authors: Constantin Papizh, Dmitriy Puzyrkov */

/** @file duct_xsock.h
 *  @brief Send state of one Darwin socket: the write boundaries of the opening's
 *  packets and the bound the socket was created with; no receive state.
 *
 *  A write runs under a cap only while the opening's packets give a piece. The
 *  names are the ones every platform's @c duct_xsock.h supplies.
 */

#ifndef DUCT_XSOCK_H
#define DUCT_XSOCK_H

#include "duct_core.h"
#include "duct_xopening.h"

#include <stddef.h>

/** @brief Send state of one Darwin socket.
 *  All-zero, as a fresh TX ring holds it, is no opening and no bound. */
typedef struct duct_x_sock_tx {
    duct_x_opening_t opening;   /**< Write boundaries of the packets staged ahead
                                  *  of a TCP socket's first flight. */
    uint32_t         lowat_max; /**< Bound the socket was created with, bytes: a
                                  *  TCP socket's lowat or a connected UDP
                                  *  socket's granted send buffer. Set before the
                                  *  conn reaches a worker. */
} duct_x_sock_tx_t;

/** @brief TX ring members this platform adds: the socket's send state. */
#define duct_x_sock_tx_fields duct_x_sock_tx_t sock;

/** @brief Send state TX ring @p tx carries. */
#define duct_x_sock_tx_of(tx) (&(tx)->sock)

/** @brief TX ring members this platform adds on the staging worker's line:
 *  none. */
#define duct_x_sock_stats_fields

/** @brief Stats-read state TX ring @p tx carries: a null pointer, Darwin keeping
 *  none.
 *  Every function in @c duct_xport.h that takes it ignores it. */
#define duct_x_sock_stats_of(tx) nullptr

/** @brief RX ring members this platform adds: none. */
#define duct_x_sock_rx_fields

/** @brief Receive state RX ring @p rx carries: a null pointer, Darwin keeping
 *  none.
 *  Every function in @c duct_xport.h that takes it ignores it. */
#define duct_x_sock_rx_of(rx) nullptr

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
 *  The opening's piece, 0 once its packets are out; @p flags is always 0. */
duct_nonnull(1, 2) static inline size_t
duct_x_sock_tx_cap(const duct_x_sock_tx_t *x, int *flags)
{
    *flags = 0;
    return duct_x_sock_tx_piece(x);
}

/** @brief Bytes io hands the socket per writable edge: half of @c lowat_max, 0
 *  for a socket without a bound. */
static inline size_t duct_x_sock_tx_quantum([[maybe_unused]] const duct_x_sock_tx_t *x)
{
    return x->lowat_max / 2u;
}

#endif
