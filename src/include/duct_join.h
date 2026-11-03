/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_join.h
 *  @brief Joining a dial to a session that already holds its peer: the
 *  session's join key, the one-time stream lead a dial leads with, the index io
 *  resolves it through, and the identity a joined leg is held to.
 *
 *  The session's worker keys it and builds its leads; io matches a lead at
 *  accept, ahead of every protocol preparse. Both ends of one session derive
 *  the same key and name from its first named leg, so nothing carrying them
 *  crosses the wire. A stream lead verifies once: its counter is spent in the
 *  session's window by the match that takes it. A datagram's lead, written by
 *  the initiator's codec, is checked against that datagram's own bytes and
 *  spends nothing.
 */

#ifndef DUCT_JOIN_H
#define DUCT_JOIN_H

#include "duct_core.h"
#include "duct_session.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Join lead bytes: name 2, counter 4, conn id 1, MAC 8. */
static constexpr size_t   duct_join_lead_size       = 15u;
/** @brief Join deadline a protocol's @c join_auth_timeout_ms of 0 takes, 10 s. */
static constexpr uint32_t duct_join_auth_default_ms = 10000u;

/** @brief Store the identity @p s's first leg named and key the session for
 *  joins.
 *  The key and name come from @p vt's @c derive over @p engine, and the
 *  session is listed in the index under that name. An engine without
 *  @c derive, or one refusing, leaves the identity stored and the session
 *  unkeyed. The identity is copied into an allocation of its own size, which
 *  replaces the one the session holds.
 *  @return false when the allocation fails; the session then holds no
 *          identity and is unkeyed. */
duct_nonnull(1, 3, 4) bool
duct_join_install(duct_session_t *s, duct_view_u8 identity,
                  const duct_seal_engine_vtbl_t *vt, duct_seal_engine_t *engine);

/** @brief Free the identity @p s holds, leaving it none. */
duct_nonnull(1) void duct_join_forget(duct_session_t *s);

/** @brief Whether @p identity is the one @p s's first naming stored.
 *  The bytes are compared in constant time; a session that holds no identity
 *  matches none. */
duct_nonnull(1) bool
duct_join_same_peer(const duct_session_t *s, duct_view_u8 identity);

/** @brief Build the next lead for a dial joining @p s at @p conn_id,
 *  spending one counter.
 *  The name, the counter and the conn id go out covered, exclusive-ored with bytes
 *  SipHash draws from the lead's MAC under the @c cover_key of the wire @p s's
 *  protocol runs on, so the first 7 bytes read as noise; the MAC itself is in the
 *  clear.
 *  @return false for a session holding no key, a spent counter space, or
 *          @p conn_id past @c duct_session_max_legs. */
duct_nonnull(1, 3) bool
duct_join_lead(duct_session_t *s, duct_conn_id_t conn_id,
               uint8_t out[duct_join_lead_size]);

/** @brief Resolve @p lead to the session it joins, on io.
 *  The lead's first bytes uncover under the @c cover_key of each protocol among
 *  @p protos, the accepting listener's, in turn. A candidate is a session listed
 *  under the name that protocol's key uncovers whose protocol it is; its MAC must
 *  hold, and the counter must be fresh in its window, which this spends.
 *  @return false, nothing written, for any lead it does not take. */
duct_nonnull(1, 2, 4, 5, 6) bool
duct_join_match(const uint8_t lead[duct_join_lead_size],
                const duct_proto_t *const *protos, unsigned n_protos,
                duct_session_handle_t *tok, duct_conn_id_t *conn_id,
                const duct_proto_t **proto);

/** @brief Derive the join key and name @p engine's handshake gives both ends.
 *  The one derivation behind a session's key, which @ref duct_join_install
 *  stores, and behind the key an initiator's datagram codec leads its PDUs with,
 *  so the two agree.
 *  @return false for an engine without @c derive or one refusing; @p key and
 *          @p name are then untouched. */
duct_nonnull(1, 2, 3, 4) bool
duct_join_derive(const duct_seal_engine_vtbl_t *vt, duct_seal_engine_t *engine,
                 uint8_t key[duct_siphash_key_size], uint8_t name[2]);

/** @brief Resolve the lead of datagram @p dgram to the session of @p proto it
 *  names, on io.
 *  @p proto runs on a wire that raises @c fl_wire_join_lead. The name is uncovered
 *  under that wire's @c cover_key, and a candidate is a session of @p proto listed
 *  under it; the lead's MAC must hold over the PDU that starts the wire's
 *  @c rx_prefix_len bytes into the datagram. Nothing is spent: a lead belongs to
 *  one datagram, and a replay of it ends at the transport's own window.
 *  @return the session's handle, or one with a @c handle_null word for a
 *          datagram it does not take, one that @c duct_dgram_lead_fits refuses
 *          included. */
duct_nonnull(1, 3) duct_session_handle_t
duct_join_dgram_match(const uint8_t *dgram, size_t len, const duct_proto_t *proto);

#ifdef __cplusplus
}
#endif

#endif /* DUCT_JOIN_H */
