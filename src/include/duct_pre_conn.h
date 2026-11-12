/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_pre_conn.h
 *  @brief Pre-conn: a not-yet-a-@c duct_conn_t lightweight state waiting
 *  for one more asynchronous signal — dial resolution or first
 *  protocol-probe bytes — before a real conn slot or a protocol decision
 *  is committed. Owned and resolved entirely by the io thread; portable
 *  across backends.
 */

#ifndef DUCT_PRE_CONN_H
#define DUCT_PRE_CONN_H

#include "duct_core.h"
#include "duct_types.h"
#include "duct_timer.h"
#include "duct_relay.h"
#include "duct_listener.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Which asynchronous signal this pre-conn is waiting for. */
typedef enum : uint8_t {
    pre_conn_dial,      /**< Outbound connect, waiting for
                          *  dial resolution. */
    pre_conn_probe,     /**< Inbound accept, waiting for
                          *  first protocol-probe bytes. */
} duct_pre_conn_kind_t;

/** @name Probe-wait read buffer
 *  The first bytes of an accepted stream in an allocation of the listener's
 *  probe read span, at most @c DUCT_LISTENER_PEEK_MAX.
 *  @{
 */
/** @} */

/** @brief Where a dial connects, read by the dial's xport.
 *  The peer for @c x_tcp and @c x_udp_peer, the socket path for @c x_local. */
typedef union duct_dial_target {
    duct_peer_t peer;                       /**< IP peer of an @c x_tcp or @c x_udp_peer dial. */
    char        path[duct_local_path_max];  /**< Socket path of an @c x_local dial, NUL included. */
} duct_dial_target_t;

/** @brief One pending admission: a raw fd + whatever context its terminal
 *  step needs, linked on the owning @c duct_io_t::pre_conns list.
 *
 *  Heap-allocated, same discipline as @ref duct_msg_pre_parse — transient,
 *  low-volume, admission-time only.
 *  Referenced by raw pointer since a pre-conn is created and resolved only
 *  by the owning io thread.
 */
typedef struct duct_pre_conn {
    duct_sock_t            fd;
    duct_pre_conn_kind_t   kind;
    /** @brief Flag: the dial's deadline already fired.
     *  Set only by @c s_pre_conn_timeout_fire, which closes the fd. A reactive fire
     *  resolves on the spot; on IOCP the completion its cancel owes reads this to
     *  report @c rc_conn_timeout and to touch no socket the fire closed.
     */
    bool                    timed_out;
    duct_timer_handle_t     timeout; /**< timer_handle_null if none armed. */
    union {
        struct {
            duct_conn_intent_t seed;
            /** @brief The dial target in portable form, keeping this struct
             *  OS-free.
             *
             *  The IOCP backend rebuilds the sockaddr its @c ConnectEx
             *  needs from this, by the seed's xport through
             *  @ref duct_io_sockaddr_from_path or
             *  @ref duct_io_sockaddr_from_peer — the one reader this field
             *  has.
             */
            duct_dial_target_t target;
        }                   dial;     /**< kind == pre_conn_dial. */
        struct {
            duct_listener_t *listener;
            duct_peer_t      peer;
            /** @brief First bytes of the connection read so far, in an allocation of
             *  the listener's probe read span made at the wait's start.
             *
             *  The wait fills it by one read or several, each landing at the end of its
             *  bytes, in the room @ref duct_pre_conn_probe_room names: the target of an
             *  iocp @c WSARecv and of the read in @c duct_io_on_pre_conn_readable. A
             *  resolution classifies these bytes.
             */
            duct_ptr_t(uint8_t) peek;
            uint16_t            peek_len; /**< Bytes @c peek holds. */
        }                   probe;    /**< kind == pre_conn_probe. */
    };
    struct duct_pre_conn   *next; /**< duct_io_t::pre_conns intrusive list. */
} duct_pre_conn_t;

/** @brief Free tail of @p pre_conn's probe buffer, the target of its next read.
 *  Starts past the bytes held and ends at the buffer's own span, so a pre-parse
 *  never sees more than an accept-time read offers. A waiting pre_conn always
 *  has room: it holds fewer bytes than @c peek_min, or none, and the bind keeps
 *  @c peek_min within that span. */
static inline duct_view_u8 duct_pre_conn_probe_room(duct_pre_conn_t *pre_conn)
{
    auto p = &pre_conn->probe;
    return (duct_view_u8){
        .data = duct_at(p->peek) + p->peek_len,
        .size = duct_listener_peek_span(p->listener->peek_cap) - p->peek_len,
    };
}

#ifdef __cplusplus
}
#endif

#endif /* DUCT_PRE_CONN_H */
