/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_vnet.h
 *  @brief Segmentation offload across a tun leg's @c virtio_net_hdr, with the ECN read, CE mark and GSO trim of the packets the leg carries.
 *
 *  A tun opened with @c IFF_VNET_HDR frames every packet with this header, and
 *  with TSO or USO on, one read carries a TCP or UDP superpacket of many
 *  segments. The io thread cuts each read into record-framed packets,
 *  @ref duct_vnet_cut; the worker merges consecutive TCP segments of one flow,
 *  and UDP datagrams where the leg's tun took the USO flags, into one segmented
 *  write, @ref duct_vnet_gro_offer. The leg's wire sees IP
 *  packets both ways, and GSO records where the leg's bound groups segments: a
 *  2-byte big-endian segment size, then one TCP packet of several segments,
 *  marked @c fl_frame_gso.
 *
 *  - Every cut segment or record carries its own IP length, IPv4 ID, sequence
 *    number and flags; a segment its TCP checksum, a record the pseudo-header
 *    sum for its own length, which the kernel writing it completes. A cut UDP
 *    datagram carries its own IP length, IPv4 ID, UDP length and checksum.
 *  - A merge takes plain segments and datagrams whose checksums verify, the
 *    segmented write leaving with fresh ones, and records unverified: their
 *    checksum field holds only that sum.
 *  - Queue control answers a signal on a relayed packet through @c duct_frame_ecn,
 *    which reads its codepoint, then @c duct_frame_mark_ce, CE set in the packet, or
 *    @c duct_gso_trim, a record less its last segment, both written where the
 *    frame lies. Its caller is @c duct_codel_act.
 */

#ifndef DUCT_VNET_H
#define DUCT_VNET_H

#include "duct_wire.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Longest @c virtio_net_hdr a vnet leg takes, bytes.
 *  A tun set longer fails @c duct_conn_setup with @c rc_not_supported. */
static constexpr size_t duct_vnet_hdr_max = 12u;

/** @brief Largest segmented packet one tun read carries, bytes: a tun's default
 *  @c gso_max_size. */
static constexpr size_t duct_vnet_gso_max = 65536u;

/** @brief Shortest segment payload a whole cut is sized for, bytes: the MSS of
 *  IPv4's minimum datagram.
 *  A superpacket of shorter segments fits only where the ring holds more room
 *  than its reserve guarantees; otherwise its read drops. */
static constexpr size_t duct_vnet_mss_min = 536u;

/** @brief Longest IP plus TCP header a whole cut is sized for, bytes: both at
 *  their 60-byte maximum. */
static constexpr size_t duct_vnet_l4_hdr_max = 120u;

/** @brief Ring room one cut takes at most, bytes.
 *  Sized for segments of @ref duct_vnet_mss_min under headers of
 *  @ref duct_vnet_l4_hdr_max, each segment repeating the headers behind its own
 *  record prefix. A vnet leg's RX ring is this much larger, and its io thread
 *  reads only once this much is free. The read lands in that room, and a tun
 *  clips a read longer than its span with no sign: the span, this room less a
 *  record prefix, stays above @ref duct_vnet_gso_max. */
static constexpr size_t duct_vnet_cut_max = duct_vnet_gso_max
    + (duct_vnet_gso_max / duct_vnet_mss_min + 1u) * (duct_vnet_l4_hdr_max + duct_dgram_record_hdr_size);

/** @brief All-zero @c virtio_net_hdr, the prefix of a tun write carrying one
 *  plain packet. */
extern const uint8_t duct_vnet_zero[duct_vnet_hdr_max];

/** @brief Bytes a GSO record's segment size takes ahead of its packet. */
static constexpr size_t duct_vnet_gso_lead = 2u;

/** @brief Cut the tun read landed behind a record prefix at @p rec into record-framed packets, in place.
 *
 *  The packet of @p len bytes lies at @c rec + @c duct_dgram_record_hdr_size and
 *  the read's header @p vh stays apart. A TCPv4 or TCPv6 segmented read becomes
 *  one packet per segment, or GSO records of as many whole segments as
 *  @p rec_max holds where it holds two and the headers carry no IPv4 options or
 *  IPv6 extension headers; a lone segment leaves as a packet. A UDP segmented
 *  read becomes one packet per datagram. A read with no segmentation stays
 *  where it landed, its checksum completed where the header marks it partial.
 *  The records follow one another from @p rec.
 *  @param vh       The read's @c virtio_net_hdr, 10 bytes at least.
 *  @param rec_max  Largest record, bytes, lead and headers included.
 *  @param room     Bytes from @p rec the cut may write; the packet lies within them.
 *  @param pkts     Packets and records written.
 *  @return Bytes written from @p rec; 0, with nothing written, for a malformed
 *          read, another segmentation type, or a cut over @p room.
 */
size_t duct_vnet_cut(const uint8_t *vh, uint8_t *rec, size_t len, size_t rec_max,
                     size_t room, unsigned *pkts);

/** @brief Outcome of offering one packet to a train. */
typedef enum duct_vnet_gro_rc : uint8_t {
    vnet_gro_taken,       /**< Packet joined; the train stays open. */
    vnet_gro_taken_last,  /**< Packet joined; the train is complete, flush it. */
    vnet_gro_flush_first, /**< Packet continues no open train: flush, then offer it again. */
    vnet_gro_alone,       /**< Packet merges with nothing: flush, then write it by itself. */
} duct_vnet_gro_rc_t;

/** @brief Buffers of @c duct_vnet_gro_t::bufs ahead of the payload spans, the
 *  caller's @c virtio_net_hdr and the packet's headers. */
static constexpr unsigned duct_vnet_gro_front = 2u;

/** @brief Payload spans one train holds at most.
 *  A gathered write takes 1024 buffers, the kernel's per-call limit, and
 *  @ref duct_vnet_gro_front of them are not payload. */
static constexpr unsigned duct_vnet_gro_span_max = 1024u - duct_vnet_gro_front;

/** @brief One flow's segments or datagrams being merged: the first packet's
 *  headers, copied, then every payload taken, by reference. */
typedef struct duct_vnet_gro {
    size_t   len,  /**< Bytes of the packet the train makes, headers and every
                     *  payload. */
             hdr,  /**< IP plus transport header length. */
             mss;  /**< The write's segment size: the first packet's payload, or
                     *  the segment size of a record that opened the train. */
    unsigned segs, /**< Segments taken; 0 is an empty train. */
             nspans; /**< Payload spans taken, one per packet or record. */
    bool     v6;   /**< IPv6 train. */
    uint8_t  head[duct_vnet_l4_hdr_max]; /**< The first packet's headers.
                                           *  @ref duct_vnet_gro_finish rewrites them
                                           *  in place. */
    duct_view_u8 bufs[duct_vnet_gro_front + duct_vnet_gro_span_max]; /**< The write list.
                                           *  Slot 0 is the caller's
                                           *  @c virtio_net_hdr, slot 1 the headers,
                                           *  which @ref duct_vnet_gro_finish fills in,
                                           *  and each payload span follows, pointing
                                           *  where its packet lies. */
} duct_vnet_gro_t;

/** @brief Plain packets a leg's write train merges. */
typedef enum duct_vnet_merge : uint8_t {
    vnet_merge_tcp,     /**< TCP segments. */
    vnet_merge_tcp_udp, /**< TCP segments and UDP datagrams, for a conn carrying
                          *  @c fl_conn_vnet_uso. */
} duct_vnet_merge_t;

/** @brief Datagrams one UDP train holds at most.
 *  The kernel refuses a segmented write of more segments than its
 *  @c UDP_MAX_SEGMENTS, 128 on Linux 6.6; the bound is half of that. */
static constexpr unsigned duct_vnet_udp_segs_max = 64u;

/** @brief Offer IP packet @p pkt to the train in @p g.
 *
 *  @p mss is the segment size of a GSO record's packet, 0 for a plain packet.
 *  @p merge admits UDP datagrams beside the TCP segments; a record is TCP.
 *  A packet joins when it continues the train under the same headers, a TCP
 *  segment also by its sequence, a record with the train's segment size and a
 *  plain packet with a payload no longer than it; a
 *  payload that is not a whole number of segments, a PSH, a packet length within
 *  one segment of 65535 bytes, @ref duct_vnet_gro_span_max spans or, for UDP,
 *  @ref duct_vnet_udp_segs_max datagrams completes the train. A candidate
 *  carries a payload and either IPv4 with DF, no options and the next ID counted
 *  in segments, or IPv6 with no extension headers; a TCP candidate carries ACK
 *  and at most PSH among its flags. A plain packet's checksums verify; a
 *  record's go unverified.
 *
 *  A packet that joins has its payload recorded where it lies, not copied: those
 *  bytes of @p pkt stay unchanged until the train has been written. Its headers
 *  are copied only when it opens the train.
 */
duct_vnet_gro_rc_t duct_vnet_gro_offer(duct_vnet_gro_t *g, const uint8_t *pkt, size_t len,
                                       size_t mss, duct_vnet_merge_t merge);

/** @brief Close the train in @p g and write its @c virtio_net_hdr to @p vnet.
 *
 *  Several segments become one TCPv4, TCPv6 or UDP segmented write: IP length
 *  and header checksum rewritten, a UDP length rewritten with them, the
 *  transport checksum seeded with the pseudo-header sum. A single segment keeps
 *  its packet as taken, under a zero header.
 *  The write list is then @c g->bufs, @ref duct_vnet_gro_front plus @c g->nspans
 *  buffers long, slot 0 left for the caller's header. @p g takes new offers
 *  afterwards; @c bufs and @c nspans stay as they are until the next one.
 */
void duct_vnet_gro_finish(duct_vnet_gro_t *g, uint8_t vnet[duct_vnet_hdr_max]);

/** @brief Open GSO record @p rec for a write to the device.
 *
 *  Steps @p rec past its segment size onto its packet and writes to @p vnet the
 *  header a segmented write of that packet takes: TCPv4 or TCPv6 from the IP
 *  version, ECN where the packet carries CWR.
 *  @return The segment size; 0, with @p rec and @p vnet untouched, for a record
 *          no segmentation takes: one no longer than its lead, a segment size
 *          of 0 or one covering the whole payload, IPv4 options, IPv6 extension
 *          headers, a transport other than TCP, or IP lengths that disagree
 *          with the packet.
 */
size_t duct_vnet_gso_open(duct_view_u8 *rec, uint8_t vnet[duct_vnet_hdr_max]);

/** @brief Cut the last segment off GSO record @p rec where it lies.
 *
 *  @p rec is an @c fl_frame_gso payload as a vnet leg cuts it: a 2-byte segment
 *  size, then one TCP packet whose checksum field holds the pseudo-header sum, in
 *  memory that takes a write. The record keeps its segment size and every segment
 *  but the last, its IP length, IPv4 header checksum and that sum rewritten for
 *  the shorter packet.
 *
 *  @return the record's new length, lead included; 0, nothing written, for a
 *          record of fewer than three segments, one carrying FIN, SYN or RST, or
 *          one the offload does not parse.
 */
size_t duct_gso_trim(duct_view_u8 rec);

/** @brief ECN codepoint of an IP packet, its header's 2-bit field.
 *  The codes 0 to 3 are the field's own values; @c ecn_none stands for a packet
 *  with no header to read. */
typedef enum : int8_t {
    ecn_none    = -1, /**< No IPv4 or IPv6 header to read. */
    ecn_not_ect = 0,  /**< Not ECN-capable. */
    ecn_ect1    = 1,  /**< ECN-capable, ECT(1). */
    ecn_ect0    = 2,  /**< ECN-capable, ECT(0). */
    ecn_ce      = 3,  /**< Congestion experienced. */
} duct_ecn_t;

/** @brief Read the ECN codepoint of the IP packet @p frame carries.
 *  A frame carrying @c fl_frame_gso is read past its 2-byte segment size.
 *  @return @c ecn_none where no whole IPv4 or IPv6 header leads the packet.
 */
duct_nonnull(1) duct_ecn_t duct_frame_ecn(const duct_frame_t *frame);

/** @brief Set CE on the IP packet @p frame carries, where it lies.
 *  The payload is memory that takes a write. An IPv4 header's checksum is
 *  recomputed and the TCP checksum stays. A GSO record holds one IP header, the
 *  one marked.
 *
 *  @return the payload's size; 0, nothing written, unless the packet is
 *          @c ecn_ect0 or @c ecn_ect1.
 */
duct_nonnull(1) size_t duct_frame_mark_ce(const duct_frame_t *frame);

#ifdef __cplusplus
}
#endif

#endif /* DUCT_VNET_H */
