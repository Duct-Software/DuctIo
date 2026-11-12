/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_wire_codec.h
 *  @brief Per-conn sealed-wire reassembly state.
 *
 *  Holds one sealed connection's decrypted cleartext @c ct_buf
 *  and the tracking cursors, and the join lead state of the datagrams an
 *  initiator's codec seals.
 */

#ifndef DUCT_WIRE_CODEC_H
#define DUCT_WIRE_CODEC_H

#include "duct_hash.h"
#include "duct_seal_engine.h"
#include "duct_wire.h"
#include "duct_types.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct duct_seal_engine duct_seal_engine_t;

/** @brief Where a codec stands on leading its datagrams with a join lead. */
typedef enum duct_lead_state : uint8_t {
    lead_state_none,    /**< The codec's datagrams carry no join lead. */
    lead_state_unkeyed, /**< Led from the first datagram sealed after the engine
                          *  can derive the join key. */
    lead_state_keyed,   /**< Key and name derived: every datagram is led. */
} duct_lead_state_t;

static_assert(sizeof(duct_lead_state_t) == sizeof(uint8_t),
              "duct_lead_state_t width must be 1 byte");

/** @brief Decryption and reassembly state for one sealed connection's
 *  incoming records.
 *
 *  Heap-allocated by a sealed wire's @c create_codec, mutated only by
 *  the worker thread. A parked, multiplexed handler or a parked answer can
 *  hold a live pointer into that cleartext across an async boundary, and
 *  takes a hold on @c ct_buf for as long: the buffer is not compacted while
 *  held, and outlives @c destroy until the last hold is dropped.
 *
 *  Field order is load-bearing: the pointers and cursors the parse and
 *  unseal paths read fill the first cache line exactly.
 */
typedef struct duct_wire_codec {
    /** @brief The inner wire framing unsealed cleartext.
     *
     *  Its own @c on_parse drives @c inner_parser to split @c ct_buf's
     *  cleartext into frames. Nullptr means whole-record dispatch — the
     *  sealed record's cleartext is one frame, no inner wire to drain
     *  through.
     *
     *  Borrowed; must outlive this codec.
     */
    const duct_wire_t *inner;

    duct_wire_parser_t *inner_parser; /**< @c inner's parse state. */

    duct_ptr_t(uint8_t) ct_buf; /**< Cleartext buffer, nullptr on the codec of an
                               *  @c x_udp_shared conn.
                               *  The codec is one holder and every pin adds one;
                               *  its @c duct_byte_len is the capacity. */

    uint32_t ct_ack_off,   /**< Ack cursor: bytes before this offset
                             *  have been acknowledged by the handler and
                             *  are safe to discard on the next
                             *  compaction. */
             ct_parse_off, /**< Parse cursor: @c [ct_ack_off,ct_parse_off)
                             *  has been parsed but may still be held by
                             *  parked handler. Advanced by the consumed
                             *  byte count each time @c inner->on_parse
                             *  extracts a frame. */

             ct_len;       /**< Total decrypted bytes currently in
                             *  @c ct_buf. @c [ct_parse_off,ct_len) is
                             *  still unparsed. */

    duct_seal_engine_t *engine; /**< Seal-engine instance. */

    /** @brief Bytes this conn leads every PDU it sends with, the wire's
     *  @c tx_prefix until the protocol names the conn. Only the first
     *  @c tx_prefix_len go out. */
    uint8_t prefix[duct_seal_prefix_max],
            tx_prefix_len, /**< Live width of @c prefix, copied from the wire
                             *  when this codec is built. */
            rx_prefix_len; /**< Width taken off an incoming PDU before the
                             *  engine sees it, copied from the wire the same
                             *  way. */

    /** @brief True once this codec's engine handed its peer identity to the
     *  protocol, which happens at most once per codec.
     *
     *  A wire rebind destroys this codec, so the fresh handshake that
     *  follows authenticates its peer and announces again.
     */
    bool peer_announced;

    /** @brief True once this codec's key set has outlived its lifetime, until
     *  the conn's next PDU either way takes the rekey.
     *
     *  It ends with the codec: a wire rebind's fresh key set starts a new
     *  lifetime, and a flag set under an engine that rekeys never reaches one
     *  that does not.
     */
    bool rekey_due;

    /** @brief Join lead state of the datagrams this codec seals.
     *
     *  A codec of an initiator's @c join_lead wire starts @c lead_state_unkeyed
     *  and turns @c lead_state_keyed at the first datagram sealed after its engine
     *  can derive the key; every other codec stays @c lead_state_none. Read for
     *  every datagram sealed, so it sits with the prefix the lead replaces.
     */
    duct_lead_state_t lead_state;

    uint64_t rekey_timer; /**< Handle of this codec's last lifetime timer;
                            *  a fire carrying another belongs to a codec this
                            *  one replaced and marks nothing. */

    uint16_t opening_ceiling; /**< Largest opening packet, bytes: the wire's
                                *  @c opening_ceiling, 0 for a wire with none. */

    /** @brief Join lead material of this codec's datagrams.
     *  @c key and @c name hold the engine's derivation once @c lead_state is
     *  @c lead_state_keyed; @c cover_key is the wire's, copied when a codec with a
     *  lead is built.
     */
    struct {
        uint8_t key[duct_siphash_key_size],
                cover_key[duct_siphash_key_size],
                name[2];
    } lead;

    uint32_t engine_park_len; /**< Bytes waiting in @c engine_park, 0 for an
                                *  empty park. */

    /** @brief Release this codec.
     *  Frees the inner parser, the seal engine, @c engine_park and @c self, and
     *  drops the codec's hold on @c ct_buf: a pin keeps the buffer until it is
     *  released. Callable at any time.
     */
    void (*destroy)(struct duct_wire_codec *self);
    duct_ptr_t(uint8_t) engine_park; /**< Engine egress that met a full TX ring or bytes
                            *  parked ahead of it, as whole records leaving
                            *  ahead of every later byte of the conn. Allocated
                            *  at its first use, freed with the codec; its
                            *  @c duct_byte_len is the capacity. Worker only. */
} duct_wire_codec_t;

/** @brief Derive @p c's lead key at the first datagram after the handshake and
 *  write the lead into @p dgram.
 *  A datagram sealed before the engine can derive the key keeps the prefix it
 *  has. Callers go through @ref duct_wire_codec_lead, which has checked
 *  @c lead_state. */
void duct_wire_codec_lead_write(duct_wire_codec_t *c, uint8_t *dgram, size_t len);

/** @brief Lead datagram @p dgram with @p c's join lead.
 *
 *  @p len counts the whole datagram, its prefix already in place. Called after
 *  the PDU behind the prefix is written, since the MAC covers it. A datagram of a
 *  codec in @c lead_state_none keeps the prefix it has. The first call after the
 *  handshake derives the key.
 */
static inline void duct_wire_codec_lead(duct_wire_codec_t *c, uint8_t *dgram, size_t len)
{
    if (c->lead_state != lead_state_none)
        duct_wire_codec_lead_write(c, dgram, len);
}

/** @brief Advance @p pdu past this codec's RX prefix.
 *
 *  The one strip both readers take: the wire's own @c unseal, and the redirect
 *  sizing on the datagram path, which asks the engine how much cleartext a PDU
 *  holds and must not count bytes that are not the engine's.
 *
 *  @return false when @p pdu is too short to carry the prefix, @p pdu left
 *          untouched — what is refused here never reaches the AEAD.
 */
static inline bool duct_wire_codec_rx_strip(const duct_wire_codec_t *c,
                                            duct_view_u8 *pdu)
{
    if (pdu->size < c->rx_prefix_len)
        return false;
    pdu->data = (uint8_t *)pdu->data + c->rx_prefix_len;
    pdu->size -= c->rx_prefix_len;
    return true;
}

#ifdef __cplusplus
}
#endif

#endif /* DUCT_WIRE_CODEC_H */
