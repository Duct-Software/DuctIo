/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_dgram_rec.h
 *  @brief Codec for the internal datagram record length prefix.
 *
 *  One canonical encode/decode pair for @ref duct_dgram_record_hdr_size
 *  shared by the io thread's RX ingest and the worker's TX
 *  stage so both sides agree on one byte layout. @ref duct_dgram_rx_append
 *  owns the RX-side record framing — header + payload committed as one OLB
 *  transaction — for dgram-listener classification and pending-create
 *  injection; a direct in-place datagram read uses @ref
 *  duct_dgram_rx_header_commit instead.
 *
 *  A prefix holds a datagram length, except where it carries a marker: a
 *  batched read writes @ref duct_dgram_rec_padded and @ref duct_dgram_rec_void,
 *  and a vnet leg's GSO records carry @ref duct_dgram_rec_gso.
 */

#ifndef DUCT_DGRAM_REC_H
#define DUCT_DGRAM_REC_H

#include "duct_olb_rx.h"
#include "duct_wire.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief True when @p wire's whole per-datagram header is the record prefix.
 *
 *  Such a wire parses one record to its own body, with no flags and the default
 *  stream, so a reader holding the record length already has the parse result.
 *  @ref duct_wire_dgram_min counts the same split from the other side, as the
 *  bytes a wire keeps past that prefix.
 */
static inline bool duct_wire_records(const duct_wire_t *wire)
{
    return wire && wire->header_size == duct_dgram_record_hdr_size;
}

/** @brief True when @p wire's framing matches the record framing @p xport uses.
 *
 *  A sealed wire fixes its framing at construction while the record is the
 *  transport's property — a conn ring for @c x_udp_peer and @c x_raw_packet, the
 *  inter lane for @c x_udp_shared — so the two agree only by construction: a
 *  mismatch hands a record header to the engine's @c pdu_len as a PDU length
 *  prefix. Gated on @c unseal, since a length-prefix wire's own header is four
 *  bytes as well. A byte stream, @c x_tcp, @c x_raw or @c x_local, carries no
 *  record and fits a wire whose header is not the record prefix.
 *
 *  Carrying records and tolerating loss are separate answers: a packet fd
 *  carries them and loses nothing, so @c sealed_dgram_ok stays a question the
 *  datagram listener asks on its own.
 */
static inline bool
duct_wire_framing_fits_xport(const duct_wire_t *wire, duct_xport_t xport)
{
    return !wire || !wire->unseal || duct_wire_records(wire) == duct_xport_delimited(xport);
}

/** @brief Report whether a conn on @p xport must keep a wire for its whole life.
 *
 *  True for @c x_raw_packet alone: its ring holds records, each led by the
 *  internal length prefix, and only a wire strips it, so a leg bound to none
 *  hands that prefix to the protocol inside every frame. An attach and a
 *  protocol switch both refuse to leave such a leg without one.
 */
static inline bool duct_xport_needs_wire(duct_xport_t xport)
{
    return xport == x_raw_packet;
}

/** @brief Encode @p len as a big-endian @c duct_dgram_record_hdr_size prefix. */
static inline void
duct_dgram_rec_hdr_encode(uint8_t out[duct_dgram_record_hdr_size], size_t len)
{
    duct_store_be32(out, (uint32_t)len);
}

/** @brief Decode a big-endian @c duct_dgram_record_hdr_size length prefix. */
static inline size_t
duct_dgram_rec_hdr_decode(const uint8_t in[duct_dgram_record_hdr_size])
{
    return duct_load_be32(in);
}

/** @brief Internal RX record header.
 *
 *  Length-prefix framing ahead of each received datagram in a
 *  datagram-bound conn's RX OLB, so the wire-driven parse loop can batch
 *  several records per WFQ post. Byte-shape and size mirror @ref
 *  duct_dgram_record_hdr_size / @c duct_wire_t::header_size; never reaches
 *  the peer.
 */
typedef struct { uint8_t octets[4]; } duct_dgram_rec_hdr_t;
static_assert(sizeof(duct_dgram_rec_hdr_t) == duct_dgram_record_hdr_size,
    "duct_dgram_rec_hdr_t must match the public duct_dgram_record_hdr_size contract");

/** @brief Record prefix bit marking a record padded out to the end of its read
 *  unit.
 *
 *  A batched read lays one datagram per @c read_unit and sets it on every record
 *  shorter than its unit but the last one staged. The parse strips it in place
 *  before @c on_parse reads the length, and posts the unit's remainder as a
 *  @c duct_frame_pad descriptor. No datagram length reaches this bit.
 */
static constexpr uint32_t duct_dgram_rec_padded = 1u << 31;

/** @brief Record prefix bit marking a GSO record in a vnet leg's ring.
 *
 *  The cut sets it on RX, and @c s_tx_stage_frame on TX from @c fl_frame_gso.
 *  The transparent datagram parse turns it back into that flag,
 *  @c duct_io_tx_peek masks it out of the length, and @c duct_io_tx_send reads
 *  it to build the record's header. No datagram length reaches this bit.
 */
static constexpr uint32_t duct_dgram_rec_gso = 1u << 30;

/** @brief Record prefix of a read unit holding no datagram.
 *  A batched read writes it where the datagram fell outside the wire's bounds
 *  or was truncated; the parse posts the whole unit as one @c duct_frame_pad
 *  descriptor. */
static constexpr uint32_t duct_dgram_rec_void = UINT32_MAX;

/** @brief Smallest datagram @p wire can parse into a frame.
 *
 *  Whatever @c duct_wire_t::header_size counts past the record prefix is the
 *  wire's own per-datagram header, and a shorter datagram holds no frame.
 *  Dropping it falls to the caller: @c on_parse answering @c rc_invalid_arg
 *  ends the conn, where a datagram costs only itself. 0 for a wire
 *  that adds nothing of its own, and for no wire at all.
 */
static inline size_t duct_wire_dgram_min(const duct_wire_t *wire)
{
    return wire && wire->header_size > duct_dgram_record_hdr_size
         ? wire->header_size - duct_dgram_record_hdr_size : 0u;
}

/** @brief Write the record header for a payload already in place at @p rx's
 *  tail (caller recv()s straight past the header gap), then advance past
 *  both. Caller has verified the space.
 */
duct_nonnull(1) static inline void
duct_dgram_rx_header_commit(duct_olb_rx_t *rx, size_t len)
{
    auto h = &rx->h;
    auto dst = rx->data + h->stage;
    duct_dgram_rec_hdr_t rhdr;
    duct_dgram_rec_hdr_encode(rhdr.octets, len);
    memcpy(dst, &rhdr, sizeof(rhdr));
    size_t total = sizeof(rhdr) + len;
    duct_atomic_store(&h->tail, h->stage + total, release);
    h->stage += total;
}

/** @brief Append one @c [len][payload] record at @p rx's tail, copying
 *  @p data in.
 *
 *  For a classification or injection path whose payload lives in a separate
 *  buffer; @ref duct_dgram_rx_header_commit takes the in-place recv() case.
 *  Caller has already verified @c sizeof(duct_dgram_rec_hdr_t) + @p len
 *  bytes of space.
 */
duct_nonnull(1) static inline void
duct_dgram_rx_append(duct_olb_rx_t *rx, const void *data, size_t len)
{
    if (len)
        memcpy(rx->data + rx->h.stage
               + sizeof(duct_dgram_rec_hdr_t), data, len);
    duct_dgram_rx_header_commit(rx, len);
}

#ifdef __cplusplus
}
#endif

#endif /* DUCT_DGRAM_REC_H */
