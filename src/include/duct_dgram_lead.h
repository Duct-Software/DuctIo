/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_dgram_lead.h
 *  @brief The lead of a sealed datagram: a session name and a MAC over the PDU
 *  it leads.
 *
 *  A datagram's source address names its conn while it holds; the lead names the
 *  session once the address changes under it, so the server reads it only where
 *  no conn holds the address. It is built from the session's join key, which both
 *  ends derive from the handshake, so nothing carrying it crosses the wire, and it
 *  changes with every datagram: the MAC covers the first
 *  @c duct_dgram_lead_bind bytes of the PDU, which hold a sequence number no two
 *  datagrams of one key set share.
 *
 *  The name goes out covered: exclusive-ored with 16 bits SipHash draws from the
 *  deployment's cover key and the datagram's own MAC. The reader has the MAC in
 *  the clear, so it uncovers the name with no session in hand, looks the session
 *  up by it and checks the MAC under that session's key.
 *
 *  The lead opens the wire's prefix and the PDU starts where the prefix ends, so
 *  every function here takes that offset from the prefix width in force: the
 *  initiator's codec passes its @c tx_prefix_len, io the receiving wire's
 *  @c rx_prefix_len. The initiator's codec writes the layout after sealing, and
 *  io checks it through @ref duct_join_dgram_match.
 */

#ifndef DUCT_DGRAM_LEAD_H
#define DUCT_DGRAM_LEAD_H

#include "duct_hash.h"
#include "duct_seal_engine.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/** @brief PDU bytes the MAC covers, behind the prefix. */
static constexpr size_t duct_dgram_lead_bind = 16u;

static_assert(duct_seal_lead_size == 2u + sizeof(uint64_t),
    "a lead is the session's 2-byte name and an 8-byte MAC");
static_assert(duct_wire_cover_key_size == duct_siphash_key_size,
    "the key covering a lead's name is a SipHash key");

/** @brief Check whether a datagram of @p len bytes with its PDU @p pdu_off bytes
 *  in can carry a lead.
 *  The prefix has to hold the lead and the datagram has to reach the PDU bytes
 *  the MAC covers. */
static inline bool
duct_dgram_lead_fits(size_t pdu_off, size_t len)
{
    return pdu_off >= duct_seal_lead_size && len >= pdu_off + duct_dgram_lead_bind;
}

/** @brief Compute the MAC of @p name and the PDU at @p pdu under @p key.
 *  @p pdu holds at least @c duct_dgram_lead_bind bytes. */
static inline uint64_t
duct_dgram_lead_mac(const uint8_t key[duct_siphash_key_size], const uint8_t name[2],
                    const uint8_t *pdu)
{
    uint8_t in[2u + duct_dgram_lead_bind];
    memcpy(in, name, 2u);
    memcpy(in + 2u, pdu, duct_dgram_lead_bind);
    return duct_siphash24(key, in, sizeof in);
}

/** @brief Cover or uncover the 2 bytes of a lead's name at @p name in place.
 *  The bytes are exclusive-ored with 16 bits SipHash-2-4 draws from @p cover and
 *  the lead's @p mac, so one call does either direction. */
static inline void
duct_dgram_lead_cover(uint8_t name[2], const uint8_t cover[duct_siphash_key_size],
                      uint64_t mac)
{
    duct_siphash_cover(name, 2u, cover, mac);
}

/** @brief Write the lead of datagram @p dgram into its first bytes, its PDU
 *  beginning @p pdu_off bytes in.
 *  The lead is @c duct_seal_lead_size bytes, the name covered under @p cover.
 *  @p len counts the whole datagram; one @ref duct_dgram_lead_fits refuses is left
 *  as it is. */
static inline void
duct_dgram_lead_fill(uint8_t *dgram, size_t pdu_off, size_t len,
                     const uint8_t key[duct_siphash_key_size],
                     const uint8_t cover[duct_siphash_key_size], const uint8_t name[2])
{
    if (!duct_dgram_lead_fits(pdu_off, len))
        return;
    uint64_t mac = duct_dgram_lead_mac(key, name, dgram + pdu_off);
    memcpy(dgram, name, 2u);
    duct_dgram_lead_cover(dgram, cover, mac);
    duct_sip_put_le64(dgram + 2u, sizeof mac, mac);
}

#endif /* DUCT_DGRAM_LEAD_H */
