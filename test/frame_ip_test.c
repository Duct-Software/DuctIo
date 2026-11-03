/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file frame_ip_test.c
 *  @brief The IP packet a frame carries: its header and length fields, and what a frame's destination, volume and flow key make of it.
 *
 *  @c sc_view expects the view of a frame to find the packet at the first byte, or behind the lead of a
 *  GSO record, with that record's segment size, and none in a short or empty frame. Every reader
 *  below takes that view. @c sc_header expects the header length to be an IPv4 packet's IHL in words times 4 and an IPv6
 *  packet's 40, and 0 for another version, an IPv4 header under 20 bytes and a header past the bytes
 *  given; and the version to be reported only for one whole packet, the length its header states
 *  equal to the bytes given. @c sc_group expects the destinations of a group, a short packet, a GSO
 *  record behind its lead and an unknown version. @c sc_peer expects a packet to a peer's address
 *  and port over TCP or UDP in either IP version, and not a later fragment, another protocol, a
 *  short packet or a peer of no family. @c sc_volume expects a frame with no GSO flag to be one
 *  packet of its whole size and a GSO record to count as many packets as it holds segments, and one
 *  packet where it cannot be read. @c sc_key expects a flow key for TCP, UDP and a later fragment
 *  and none for a pure ACK, ICMP, an empty frame and a header that does not parse.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdio.h>
#include <string.h>

/** @brief Return @p msg from the calling check when @p cond fails. */
#define expect(cond, msg) do { if (!(cond)) return msg; } while (0)

static constexpr uint8_t s_icmp4 = 1u;
static constexpr uint8_t s_tcp = 6u;
static constexpr uint8_t s_udp = 17u;
static constexpr uint8_t s_icmp6 = 58u;
static constexpr uint8_t s_fin = 0x01u;
static constexpr uint8_t s_syn = 0x02u;
static constexpr uint8_t s_rst = 0x04u;
static constexpr uint8_t s_ack = 0x10u;

/** @brief The packet of the scenario under test. */
static uint8_t s_pkt[2048u * 40u];

/** @brief Build an IPv4 packet header of 20 bytes stating @p len into @p p, the rest zero. */
static void s_v4(uint8_t *p, size_t len)
{
    memset(p, 0, len);
    p[0] = 0x45u;
    p[2] = (uint8_t)(len >> 8u);
    p[3] = (uint8_t)len;
}

/** @brief Build an IPv6 packet header stating @p len into @p p, the rest zero. */
static void s_v6(uint8_t *p, size_t len)
{
    memset(p, 0, len);
    p[0] = 0x60u;
    p[4] = (uint8_t)((len - duct_ipv6_hdr_size) >> 8u);
    p[5] = (uint8_t)(len - duct_ipv6_hdr_size);
}

/** @brief Build an IPv4 or IPv6 packet of @p proto into @c s_pkt, from source port @p sport to port 80, with @p payload bytes behind the transport header.
 *  The addresses run from 10.0.0.1 to 10.0.0.2, or from fd00::1 to fd00::2 over IPv6. A TCP
 *  packet carries @p tcp_flags, and a GSO record has its 2-byte lead ahead of the packet.
 *  @return the frame over @c s_pkt.
 */
static duct_frame_t s_packet(unsigned ver, uint8_t proto, uint16_t sport, size_t payload,
                             uint8_t tcp_flags, bool gso)
{
    memset(s_pkt, 0, 4096u);
    size_t lead = gso ? 2u : 0u,
           hdr = ver == 4u ? 20u : 40u,
           len = hdr + (proto == s_tcp ? 20u : 8u) + payload;
    uint8_t *ip = s_pkt + lead;
    if (ver == 4u) {
        ip[0] = 0x45u;
        ip[2] = (uint8_t)(len >> 8u);
        ip[3] = (uint8_t)len;
        ip[9] = proto;
        ip[12] = ip[16] = 10u;
        ip[15] = 1u;
        ip[19] = 2u;
    } else {
        ip[0] = 0x60u;
        ip[4] = (uint8_t)((len - hdr) >> 8u);
        ip[5] = (uint8_t)(len - hdr);
        ip[6] = proto;
        ip[8] = ip[24] = 0xfdu;
        ip[23] = 1u;
        ip[39] = 2u;
    }
    uint8_t *l4 = ip + hdr;
    l4[0] = (uint8_t)(sport >> 8u);
    l4[1] = (uint8_t)sport;
    l4[3] = 80u;
    if (proto == s_tcp) {
        l4[12] = 5u << 4u;
        l4[13] = tcp_flags;
    }
    return (duct_frame_t){ .payload = { .data = s_pkt, .size = lead + len },
                           .flags = gso ? fl_frame_gso : fl_frame_none };
}

/** @brief The group test on the IP view of frame @p f. */
static bool s_group(const duct_frame_t *f)
{
    auto ip = duct_frame_ip(f->payload, f->flags);
    return duct_frame_to_group(&ip);
}

/** @brief The peer test on the IP view of frame @p f. */
static bool s_peer(const duct_frame_t *f, const duct_peer_t *peer)
{
    auto ip = duct_frame_ip(f->payload, f->flags);
    return duct_frame_to_peer(&ip, peer);
}

/** @brief The flow key on the IP view of frame @p f. */
static uint64_t s_key(const duct_frame_t *f)
{
    auto ip = duct_frame_ip(f->payload, f->flags);
    return duct_frame_flow_key(&ip);
}

/** @brief The volume on the IP view of @p payload with @p flags. */
static duct_frame_volume_t s_vol(duct_view_u8 payload, duct_frame_flags_t flags)
{
    auto ip = duct_frame_ip(payload, flags);
    return duct_frame_volume(&ip);
}

/** @brief Read the header fields of IPv4 and IPv6 packets, short, long, malformed and of no packet.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_header(void)
{
    uint8_t *p = s_pkt;
    s_v4(p, 100u);
    expect(duct_ip_hdr_len(p, 100u) == 20u && duct_ip_len(p) == 100u && duct_ip_version(p, 100u) == 4u,
           "an IPv4 packet of 100 bytes is not read as one");
    expect(duct_ip_version(p, 99u) == 0u && duct_ip_version(p, 101u) == 0u && duct_ip_version(p, 0u) == 0u,
           "a version is reported for bytes other than the length the header states");
    expect(duct_ip_version(p, duct_ipv4_len_max + 1u) == 0u,
           "an IPv4 packet longer than its length field reaches is whole");
    expect(duct_ip_hdr_len(p, 20u) == 20u && duct_ip_hdr_len(p, 19u) == 0u,
           "an IPv4 header past the bytes given is read");
    p[0] = 0x46u;
    expect(duct_ip_hdr_len(p, 100u) == 24u && duct_ip_version(p, 100u) == 4u, "IPv4 options do not widen the header");
    p[0] = 0x4fu;
    expect(duct_ip_hdr_len(p, 60u) == 60u && duct_ip_hdr_len(p, 59u) == 0u,
           "the longest IPv4 header is not 60 bytes");
    p[0] = 0x44u;
    expect(duct_ip_hdr_len(p, 100u) == 0u && duct_ip_version(p, 100u) == 0u,
           "an IPv4 header under 20 bytes is read");
    p[0] = 0x55u;
    expect(duct_ip_hdr_len(p, 100u) == 0u && duct_ip_version(p, 100u) == 0u, "version 5 is read");
    p[0] = 0u;
    expect(duct_ip_hdr_len(p, 100u) == 0u, "version 0 is read");
    s_v6(p, 100u);
    expect(duct_ip_hdr_len(p, 100u) == 40u && duct_ip_len(p) == 100u && duct_ip_version(p, 100u) == 6u,
           "an IPv6 packet of 100 bytes is not read as one");
    expect(duct_ip_version(p, 99u) == 0u && duct_ip_version(p, 101u) == 0u,
           "a version is reported for IPv6 bytes other than the length the header states");
    expect(duct_ip_hdr_len(p, 40u) == 40u && duct_ip_hdr_len(p, 39u) == 0u,
           "an IPv6 header past the bytes given is read");
    expect(duct_ip_hdr_len(nullptr, 0u) == 0u && duct_ip_version(nullptr, 0u) == 0u,
           "no bytes are read as a header");
    return nullptr;
}

/** @brief Test unicast, multicast and broadcast destinations, link-local ones, short packets, GSO-led records and IPv6 for group addressing.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_group(void)
{
    auto v4 = s_packet(4u, s_udp, 5353u, 20u, 0u, false);
    expect(!s_group(&v4), "a unicast ipv4 destination is a group");
    s_pkt[16] = 224u;
    expect(s_group(&v4), "an ipv4 multicast destination is no group");
    memset(s_pkt + 16, 0xff, 4u);
    expect(s_group(&v4), "the limited broadcast is no group");
    s_pkt[16] = 223u;
    expect(!s_group(&v4), "223.x is a group");
    s_pkt[16] = 169u;
    s_pkt[17] = 254u;
    expect(!s_group(&v4), "an ipv4 link-local destination is a group");
    v4.payload.size = 19u;
    s_pkt[16] = 224u;
    expect(!s_group(&v4), "a packet short of an ipv4 header is a group");
    v4.payload.size = 20u;
    expect(s_group(&v4), "an ipv4 header alone is not read to its destination");
    s_pkt[0] = 0x44u;
    expect(!s_group(&v4), "an ipv4 header under 20 bytes is a group");
    auto rec = s_packet(4u, s_udp, 5353u, 20u, 0u, true);
    expect(!s_group(&rec), "a unicast gso record is a group");
    s_pkt[2u + 16u] = 224u;
    expect(s_group(&rec), "a gso record is read past its lead");
    rec.payload.size = 2u + 19u;
    expect(!s_group(&rec), "a gso record short of an ipv4 header is a group");
    auto rec6 = s_packet(6u, s_udp, 5353u, 20u, 0u, true);
    s_pkt[2u + 24u] = 0xffu;
    expect(s_group(&rec6), "a gso ipv6 record is read past its lead");
    rec6.payload.size = 2u + 39u;
    expect(!s_group(&rec6), "a gso ipv6 record short of its header is a group");
    auto v6 = s_packet(6u, s_udp, 5353u, 20u, 0u, false);
    expect(!s_group(&v6), "a unicast ipv6 destination is a group");
    s_pkt[24] = 0xffu;
    s_pkt[25] = 0x02u;
    expect(s_group(&v6), "an ipv6 multicast destination is no group");
    s_pkt[24] = 0xfeu;
    s_pkt[25] = 0x80u;
    expect(!s_group(&v6), "an ipv6 link-local destination is a group");
    s_pkt[24] = 0xffu;
    v6.payload.size = 39u;
    expect(!s_group(&v6), "a packet short of an ipv6 header is a group");
    v6.payload.size = 40u;
    expect(s_group(&v6), "an ipv6 header alone is not read to its destination");
    s_pkt[0] = 0x20u;
    expect(!s_group(&v6), "an unknown version is a group");
    duct_frame_t empty = {};
    expect(!s_group(&empty), "an empty frame is a group");
    return nullptr;
}

/** @brief Test which packets are addressed to a peer: its address and port over TCP or UDP in either IP version, a GSO record behind its lead, and not a later fragment, another protocol, a short packet or a peer of no family.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_peer(void)
{
    duct_peer_t v4 = { .family = AF_INET, .port = 80u, .addr.v4 = { 10u, 0u, 0u, 2u } },
                v6 = { .family = AF_INET6, .port = 80u, .addr.v6 = { 0xfdu, [15] = 2u } },
                mapped = { .family = AF_INET6, .port = 80u,
                           .addr.v6 = { [10] = 0xffu, [11] = 0xffu, 10u, 0u, 0u, 2u } },
                none = {};
    auto tcp4 = s_packet(4u, s_tcp, 5000u, 20u, 0u, false);
    expect(s_peer(&tcp4, &v4), "a TCP packet to the peer is not its own");
    auto udp4 = s_packet(4u, s_udp, 5000u, 20u, 0u, false);
    expect(s_peer(&udp4, &v4), "a UDP packet to the peer is not its own");
    expect(!s_peer(&udp4, &v6) && !s_peer(&udp4, &none),
           "an IPv4 packet is the own of a peer of another family or of none");
    expect(s_peer(&udp4, &mapped), "an IPv4 packet to an IPv4-mapped peer is not its own");
    s_pkt[19] = 3u;
    expect(!s_peer(&udp4, &mapped),
           "an IPv4 packet to another address than an IPv4-mapped peer's is the peer's");
    s_pkt[19] = 2u;
    s_pkt[20u + 3u] = 81u;
    expect(!s_peer(&udp4, &v4), "a packet to another port is the peer's");
    s_pkt[20u + 3u] = 80u;
    s_pkt[19] = 3u;
    expect(!s_peer(&udp4, &v4), "a packet to another address is the peer's");
    s_pkt[19] = 2u;
    s_pkt[9] = s_icmp4;
    expect(!s_peer(&udp4, &v4), "an ICMP packet is the peer's");
    s_pkt[9] = s_udp;
    s_pkt[7] = 1u;
    expect(!s_peer(&udp4, &v4), "a later fragment is read for a port it does not carry");
    s_pkt[7] = 0u;
    udp4.payload.size = 20u;
    expect(!s_peer(&udp4, &v4), "a header with no ports is the peer's");
    udp4.payload.size = 19u;
    expect(!s_peer(&udp4, &v4), "a packet short of a header is the peer's");
    auto rec = s_packet(4u, s_tcp, 5000u, 20u, 0u, true);
    expect(s_peer(&rec, &v4), "a GSO record is not read behind its lead");
    s_pkt[2u + 19u] = 3u;
    expect(!s_peer(&rec, &v4), "a GSO record to another address is the peer's");
    auto tcp6 = s_packet(6u, s_tcp, 5000u, 20u, 0u, false);
    expect(s_peer(&tcp6, &v6), "an IPv6 packet to the peer is not its own");
    expect(!s_peer(&tcp6, &v4) && !s_peer(&tcp6, &mapped),
           "an IPv6 packet is the own of an IPv4 peer or of an IPv4-mapped one");
    s_pkt[24u + 15u] = 3u;
    expect(!s_peer(&tcp6, &v6), "an IPv6 packet to another address is the peer's");
    s_pkt[24u + 15u] = 2u;
    tcp6.payload.size = 40u;
    expect(!s_peer(&tcp6, &v6), "an IPv6 header with no ports is the peer's");
    return nullptr;
}

/** @brief Build a GSO record of segment size @p seg over an IP header of @p ip_hdr bytes, a TCP header of @p tcp_hdr and @p payload bytes behind them.
 *  @return its size.
 */
static size_t s_make(unsigned ver, size_t ip_hdr, size_t tcp_hdr, size_t payload, uint16_t seg)
{
    memset(s_pkt, 0, sizeof s_pkt);
    s_pkt[0] = (uint8_t)(seg >> 8u);
    s_pkt[1] = (uint8_t)seg;
    uint8_t *ip = s_pkt + 2;
    ip[0] = ver == 4u ? (uint8_t)(0x40u | ip_hdr / 4u) : (uint8_t)(ver << 4u);
    ip[ip_hdr + 12u] = (uint8_t)(tcp_hdr / 4u << 4u);
    return 2u + ip_hdr + tcp_hdr + payload;
}

/** @brief Count the record of @p size bytes in @c s_pkt. */
static duct_frame_volume_t s_volume(size_t size)
{
    return s_vol((duct_view_u8){ s_pkt, size }, fl_frame_gso);
}

/** @brief Count frames with no GSO flag, GSO records by segment, and records that cannot be cut.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_volume(void)
{
    auto volume = s_vol((duct_view_u8){ s_pkt, 1400u }, fl_frame_none);
    expect(volume.bytes == 1400u && volume.packets == 1u, "a plain frame is not one packet of its size");
    volume = s_vol((duct_view_u8){ s_pkt, 0u }, fl_frame_fin);
    expect(volume.bytes == 0u && volume.packets == 1u, "an empty frame is not one packet of no bytes");
    volume = s_volume(s_make(4u, 20u, 20u, 3u * 1448u, 1448u));
    expect(volume.bytes == 40u + 3u * 1448u && volume.packets == 3u, "three IPv4 segments do not count three packets");
    volume = s_volume(s_make(4u, 20u, 20u, 2u * 1448u + 100u, 1448u));
    expect(volume.packets == 3u, "a short last segment is not a packet");
    volume = s_volume(s_make(4u, 20u, 20u, 2u * 1448u + 1u, 1448u));
    expect(volume.packets == 3u, "a last segment of one byte is not a packet");
    volume = s_volume(s_make(6u, 40u, 32u, 5u * 1000u, 1000u));
    expect(volume.bytes == 72u + 5000u && volume.packets == 5u, "five IPv6 segments with TCP options do not count five packets");
    volume = s_volume(s_make(4u, 24u, 20u, 2000u, 1000u));
    expect(volume.packets == 2u, "IPv4 options widen the header out of the payload");
    volume = s_volume(s_make(4u, 20u, 20u, 45u * 1448u, 1448u));
    expect(volume.packets == 45u, "a record of 45 segments does not count 45 packets");
    volume = s_volume(s_make(4u, 20u, 20u, 1448u + 1u, 1448u));
    expect(volume.packets == 2u, "two segments, the last of one byte, do not count two packets");
    volume = s_volume(s_make(4u, 20u, 20u, 3000u, 0u));
    expect(volume.bytes == 3040u && volume.packets == 1u, "a segment size of 0 is not one packet");
    expect(s_volume(s_make(5u, 20u, 20u, 3000u, 1000u)).packets == 1u, "a version that is neither is not one packet");
    expect(s_volume(s_make(4u, 20u, 20u, 0u, 1000u)).packets == 1u, "a record with no payload is not one packet");
    expect(s_volume(2u + 30u).packets == 1u, "headers reaching past the record are not one packet");
    s_make(4u, 20u, 20u, 3000u, 1000u);
    s_pkt[2u + 20u + 12u] = 3u << 4u;
    expect(s_volume(2u + 40u + 3000u).packets == 1u, "a TCP header under its least is not one packet");
    s_make(4u, 20u, 20u, 3000u, 1000u);
    s_pkt[2] = 0x43u;
    expect(s_volume(2u + 40u + 3000u).packets == 1u, "an IPv4 header under its least is not one packet");
    volume = s_volume(2u);
    expect(volume.bytes == 0u && volume.packets == 1u, "a record of the lead alone is not one packet of no bytes");
    volume = s_volume(0u);
    expect(volume.bytes == 0u && volume.packets == 1u, "a record of no bytes is not one packet of no bytes");
    return nullptr;
}

/** @brief Key packets of every shape: pure ACKs, ICMP, fragments, GSO records, both IP versions and malformed headers.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_key(void)
{
    auto f = s_packet(4u, s_tcp, 1000u, 0u, s_ack, false);
    expect(!s_key(&f), "a pure ack has a key");
    f = s_packet(4u, s_tcp, 1000u, 0u, s_ack | s_fin, false);
    uint64_t fin = s_key(&f);
    expect(fin & 1u, "a flow key is even or zero");
    f = s_packet(4u, s_tcp, 1000u, 100u, s_ack, false);
    expect(s_key(&f) == fin, "a fin and the data of one connection do not share a key");
    f = s_packet(4u, s_tcp, 1000u, 0u, s_ack | s_syn, false);
    expect(s_key(&f) == fin, "a syn does not take the key of its connection");
    f = s_packet(4u, s_tcp, 1000u, 0u, s_ack | s_rst, false);
    expect(s_key(&f) == fin, "a rst does not take the key of its connection");
    f = s_packet(4u, s_tcp, 1000u, 0u, 0u, false);
    expect(s_key(&f) == fin, "a segment carrying no ack has no key");
    f = s_packet(4u, s_tcp, 1000u, 0u, s_ack, false);
    s_pkt[6] = 0x20u;
    expect(s_key(&f) == fin, "the first fragment of an ack has no key");
    duct_frame_t empty = {};
    expect(!s_key(&empty), "an empty frame has a key");
    f = s_packet(4u, s_tcp, 1000u, 300u, s_ack, true);
    expect(s_key(&f) == fin, "a gso record is keyed past its lead as its packet");
    f = s_packet(4u, s_tcp, 1001u, 100u, s_ack, false);
    uint64_t other = s_key(&f);
    expect(other && other != fin, "another port has the key of the first");
    f = s_packet(6u, s_tcp, 1000u, 100u, s_ack, false);
    uint64_t v6 = s_key(&f);
    expect(v6 && v6 != fin && v6 != other, "an ipv6 connection has no key of its own");
    f = s_packet(6u, s_tcp, 1000u, 0u, s_ack, false);
    expect(!s_key(&f), "an ipv6 pure ack has a key");
    f = s_packet(4u, s_udp, 1000u, 100u, 0u, false);
    uint64_t udp = s_key(&f);
    expect(udp && udp != fin && udp != other, "udp is not keyed by its protocol and ports");
    f = s_packet(4u, s_icmp4, 0u, 56u, 0u, false);
    expect(!s_key(&f), "icmp has a key");
    f = s_packet(6u, s_icmp6, 0u, 56u, 0u, false);
    expect(!s_key(&f), "icmpv6 has a key");
    f = s_packet(4u, s_tcp, 1000u, 100u, s_ack, false);
    s_pkt[7] = 0x10u;
    uint64_t later = s_key(&f);
    f = s_packet(4u, s_tcp, 1234u, 100u, s_ack, false);
    s_pkt[7] = 0x10u;
    expect(later && later != fin && s_key(&f) == later, "a later fragment is keyed by its ports");
    f = s_packet(4u, s_tcp, 1000u, 100u, s_ack, false);
    s_pkt[0] = 0x25u;
    expect(!s_key(&f), "an unknown ip version has a key");
    s_pkt[0] = 0x45u;
    f.payload.size = 19u;
    expect(!s_key(&f), "a packet short of an ipv4 header has a key");
    return nullptr;
}

/** @brief Locate the packet in plain frames, GSO records, short frames and empty ones, and carry what the readers need.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_view(void)
{
    auto f = s_packet(4u, s_tcp, 1000u, 100u, s_ack, true);
    s_pkt[0] = 0x05u;
    s_pkt[1] = 0xa8u;
    auto v = duct_frame_ip(f.payload, f.flags);
    expect(v.packet == s_pkt + 2u && v.hdr == 20u && v.size == f.payload.size - 2u
               && v.total == f.payload.size && v.gso && v.seg == 1448u,
           "a GSO record is not located behind its lead with its segment size");
    f = s_packet(6u, s_udp, 1000u, 10u, 0u, false);
    v = duct_frame_ip(f.payload, f.flags);
    expect(v.packet == s_pkt && v.hdr == 40u && v.size == f.payload.size && v.total == f.payload.size
               && !v.gso && v.seg == 0u,
           "a plain IPv6 frame is not located at its first byte");
    v = duct_frame_ip((duct_view_u8){ s_pkt, 19u }, fl_frame_none);
    expect(!v.packet && !v.hdr && !v.size && v.total == 19u, "a frame short of an IPv4 header is located");
    v = duct_frame_ip((duct_view_u8){ s_pkt, 1u }, fl_frame_gso);
    expect(!v.packet && v.total == 1u && v.gso && v.seg == 0u, "a record shorter than its lead is read");
    v = duct_frame_ip((duct_view_u8){}, fl_frame_none);
    expect(!v.packet && !v.total && !v.gso, "an empty frame is located");
    return nullptr;
}

int main(void)
{
    static const struct { const char *name; const char *(*fn)(void); } cases[] = {
        { "view",   sc_view },
        { "header", sc_header },
        { "group",  sc_group },
        { "peer",   sc_peer },
        { "volume", sc_volume },
        { "key",    sc_key },
    };
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        auto err = cases[i].fn();
        if (err) {
            fprintf(stderr, "frame_ip: %s: %s\n", cases[i].name, err);
            return 1;
        }
    }
    printf("frame_ip: OK (view, header fields, group, peer, volume, flow key)\n");
    return 0;
}
