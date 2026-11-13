/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file vnet_cut_test.c
 *  @brief Unit test for the tun segmentation offload codec, @c duct_vnet.h.
 *
 *  Driven straight against the codec, with no engine and no tun: superpackets
 *  cut into segments and, under a bound, into GSO records, every rewritten
 *  field and checksum checked against a byte-wise big-endian sum; trains merged
 *  back into the superpacket they came from, out of segments and out of
 *  records; records opened for a device write and trimmed of their last
 *  segment; packets and records marked CE; and the packets either side
 *  refuses.
 */

#include "duct_vnet.h"
#include "duct_dgram_rec.h"
#include "duct_protocol.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include "duct_xport.h"

#include <sys/socket.h>
#include <unistd.h>
#endif

#define CHECK(expr, msg) \
    do { if (!(expr)) { fprintf(stderr, "FAIL: %s\n", msg); return 1; } } while (0)

static constexpr size_t t_vnet = 10u;
static constexpr uint8_t t_fin = 0x01u;
static constexpr uint8_t t_psh = 0x08u;
static constexpr uint8_t t_ack = 0x10u;
static constexpr uint8_t t_cwr = 0x80u;
static constexpr uint8_t t_canary = 0xa5u;
static constexpr uint8_t t_gso_udp = 5u;
static constexpr uint32_t t_seq0 = 0xfffff000u;
static constexpr uint16_t t_id0 = 0xfffeu;

static constexpr size_t t_read_max = duct_vnet_hdr_max + duct_vnet_gso_max;

static uint8_t s_in[t_read_max];
static uint8_t s_out[duct_vnet_cut_max];

/** @brief Cut the read of @p n bytes in @p in as the io thread does: the packet lands behind a
 *  record slot at @p out, the header stays apart, and the cut runs in place. The room past the
 *  packet is filled with a mark first, and a cut that leaves any of it changed past the bytes it
 *  returns, or past the packet it refuses, ends the test. */
static size_t s_cut_uso(const uint8_t *in, size_t n, size_t rec_max, bool uso,
                        uint8_t *out, size_t room, unsigned *pkts)
{
    size_t len = n - t_vnet,
           at = duct_dgram_record_hdr_size + len;
    memcpy(out + duct_dgram_record_hdr_size, in + t_vnet, len);
    if (room > at)
        memset(out + at, t_canary, room - at);
    size_t cut = duct_vnet_cut(in, out, len, rec_max, uso, room, pkts);
    for (size_t i = cut > at ? cut : at; i < room; ++i)
        if (out[i] != t_canary) {
            fprintf(stderr, "FAIL: the cut wrote past its packets, at byte %zu of %zu\n", i, room);
            exit(1);
        }
    if (cut > room) {
        fprintf(stderr, "FAIL: the cut returned %zu bytes for a room of %zu\n", cut, room);
        exit(1);
    }
    return cut;
}

static size_t s_cut(const uint8_t *in, size_t n, size_t rec_max, uint8_t *out, size_t room,
                    unsigned *pkts)
{
    return s_cut_uso(in, n, rec_max, false, out, room, pkts);
}

static uint16_t s_n16(const uint8_t *p) { return (uint16_t)(p[0] << 8u | p[1]); }
static uint32_t s_n32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24u | (uint32_t)p[1] << 16u | (uint32_t)p[2] << 8u | p[3];
}
static void s_p16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8u); p[1] = (uint8_t)v; }
static void s_p32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24u); p[1] = (uint8_t)(v >> 16u);
    p[2] = (uint8_t)(v >> 8u); p[3] = (uint8_t)v;
}

/** @brief Add @p len bytes to a ones'-complement sum as big-endian words, the
 *  reference the codec's host-order sums are checked against. */
static uint32_t s_ref_sum(uint32_t acc, const uint8_t *p, size_t len)
{
    for (size_t i = 0u; i + 1u < len; i += 2u)
        acc += (uint32_t)(p[i] << 8u | p[i + 1u]);
    if (len & 1u)
        acc += (uint32_t)p[len - 1u] << 8u;
    return acc;
}

/** @brief Fold a reference sum to 16 bits, uncomplemented. */
static uint16_t s_ref_fold(uint32_t acc)
{
    while (acc >> 16u)
        acc = (acc & 0xffffu) + (acc >> 16u);
    return (uint16_t)acc;
}

/** @brief Reference sum of packet @p p's pseudo-header for @p tlen transport bytes, the protocol
 *  read off the packet's own header. */
static uint32_t s_ref_pseudo(const uint8_t *p, bool v6, size_t tlen)
{
    if (v6) {
        uint8_t t[8] = { 0u, 0u, (uint8_t)(tlen >> 8u), (uint8_t)tlen, 0u, 0u, 0u, p[6] };
        return s_ref_sum(s_ref_sum(0u, p + 8u, 32u), t, sizeof t);
    }
    uint8_t t[4] = { 0u, p[9], (uint8_t)(tlen >> 8u), (uint8_t)tlen };
    return s_ref_sum(s_ref_sum(0u, p + 12u, 8u), t, sizeof t);
}

/** @brief Recompute the IPv4 header checksum of an edited packet. */
static void s_fix_ip4(uint8_t *p)
{
    p[10] = p[11] = 0u;
    s_p16(p + 10u, (uint16_t)~s_ref_fold(s_ref_sum(0u, p, 20u)));
}

/** @brief Recompute the TCP checksum of an edited IPv4 packet of @p len bytes. */
static void s_fix_tcp4(uint8_t *p, size_t len)
{
    uint8_t *th = p + 20u;
    th[16] = th[17] = 0u;
    uint32_t acc = s_ref_sum(s_ref_pseudo(p, false, len - 20u), th, len - 20u);
    s_p16(th + 16u, (uint16_t)~s_ref_fold(acc));
}

/** @brief Recompute the UDP checksum of an edited IPv4 datagram of @p len bytes. */
static void s_fix_udp4(uint8_t *p, size_t len)
{
    uint8_t *uh = p + 20u;
    uh[6] = uh[7] = 0u;
    uint32_t acc = s_ref_sum(s_ref_pseudo(p, false, len - 20u), uh, len - 20u);
    uint16_t c = (uint16_t)~s_ref_fold(acc);
    s_p16(uh + 6u, c ? c : 0xffffu);
}

/** @brief Write the IP header of a packet of @p len bytes carrying @p proto at @p p. */
static void s_ip_hdr(uint8_t *p, bool v6, uint8_t proto, size_t len)
{
    if (v6) {
        p[0] = 0x60u;
        s_p16(p + 4u, (uint16_t)(len - 40u));
        p[6] = proto;
        p[7] = 64u;
        for (unsigned i = 0u; i < 16u; ++i) {
            p[8u + i] = (uint8_t)(0x20u + i);
            p[24u + i] = (uint8_t)(0x40u + i);
        }
    } else {
        p[0] = 0x45u;
        s_p16(p + 2u, (uint16_t)len);
        s_p16(p + 4u, t_id0);
        p[6] = 0x40u;
        p[8] = 64u;
        p[9] = proto;
        memcpy(p + 12u, (const uint8_t[]){ 10u, 90u, 0u, 1u, 10u, 90u, 7u, 2u }, 8u);
    }
}

/** @brief Write the virtio_net_hdr of a read at @c s_in: @p vflags, GSO type @p gso, segment size
 *  @p mss, and the checksum start @p l4 and offset @p csum_off. */
static void s_vnet_hdr(uint8_t vflags, uint8_t gso, size_t hdr_len, uint16_t mss, size_t l4,
                       uint16_t csum_off)
{
    s_in[0] = vflags;
    s_in[1] = gso;
    uint16_t v = (uint16_t)hdr_len;
    memcpy(s_in + 2u, &v, sizeof v);
    memcpy(s_in + 4u, &mss, sizeof mss);
    v = (uint16_t)l4;
    memcpy(s_in + 6u, &v, sizeof v);
    memcpy(s_in + 8u, &csum_off, sizeof csum_off);
}

/** @brief Build a tun read in @c s_in: header, one TCP packet of @p payload
 *  bytes, and the kernel's pseudo-header seed where @p vflags marks a partial
 *  checksum.
 *  @return Bytes of the read. */
static size_t s_build(bool v6, size_t topt, size_t payload, uint16_t mss,
                      uint8_t tflags, uint8_t vflags, uint8_t gso)
{
    size_t l4 = v6 ? 40u : 20u,
           thl = 20u + topt,
           len = l4 + thl + payload;
    memset(s_in, 0, t_vnet + len);
    s_vnet_hdr(vflags, gso, l4 + thl, mss, l4, 16u);
    uint8_t *p = s_in + t_vnet;
    s_ip_hdr(p, v6, 6u, len);
    uint8_t *th = p + l4;
    s_p16(th, 443u);
    s_p16(th + 2u, 50000u);
    s_p32(th + 4u, t_seq0);
    s_p32(th + 8u, 0x01020304u);
    th[12] = (uint8_t)((thl / 4u) << 4u);
    th[13] = tflags;
    s_p16(th + 14u, 512u);
    memset(th + 20u, 1, topt);
    for (size_t i = 0u; i < payload; ++i)
        p[l4 + thl + i] = (uint8_t)(i * 7u + 3u);
    if (vflags & 1u)
        s_p16(th + 16u, s_ref_fold(s_ref_pseudo(p, v6, thl + payload)));
    return t_vnet + len;
}

/** @brief Build a tun read in @c s_in: header, one UDP packet of @p payload bytes for a cut into
 *  datagrams of @p mss, and the kernel's pseudo-header seed in its checksum field.
 *  @return Bytes of the read. */
static size_t s_build_udp(bool v6, size_t payload, uint16_t mss)
{
    size_t l4 = v6 ? 40u : 20u,
           ulen = duct_udp_hdr_size + payload,
           len = l4 + ulen;
    memset(s_in, 0, t_vnet + len);
    s_vnet_hdr(1u, t_gso_udp, l4 + duct_udp_hdr_size, mss, l4, 6u);
    uint8_t *p = s_in + t_vnet;
    s_ip_hdr(p, v6, 17u, len);
    uint8_t *uh = p + l4;
    s_p16(uh, 5353u);
    s_p16(uh + 2u, 40000u);
    s_p16(uh + 4u, (uint16_t)ulen);
    for (size_t i = 0u; i < payload; ++i)
        uh[duct_udp_hdr_size + i] = (uint8_t)(i * 5u + 11u);
    s_p16(uh + 6u, s_ref_fold(s_ref_pseudo(p, v6, ulen)));
    return t_vnet + len;
}

/** @brief Check that the headers at @p p equal the read's at @p orig in every byte the cut does not
 *  rewrite: the IP lengths, ID and header checksum, and the TCP sequence, flags and checksum, or the
 *  UDP length and checksum. */
static bool s_hdr_kept(const uint8_t *p, const uint8_t *orig, size_t hdr, bool v6, size_t l4)
{
    uint8_t h[128];
    memcpy(h, p, hdr);
    if (v6)
        memcpy(h + 4u, orig + 4u, 2u);
    else {
        memcpy(h + 2u, orig + 2u, 4u);
        memcpy(h + 10u, orig + 10u, 2u);
    }
    memcpy(h + l4 + 4u, orig + l4 + 4u, 4u);
    if (hdr - l4 > duct_udp_hdr_size) {
        h[l4 + 13u] = orig[l4 + 13u];
        memcpy(h + l4 + 16u, orig + l4 + 16u, 2u);
    }
    return !memcmp(h, orig, hdr);
}

/** @brief Cut the read of @p n bytes in @c s_in again, whose cut under @p rec_max took @p outn
 *  bytes: a room one byte short refuses it, and one of the cut and a lead takes it, the same bytes. */
static int s_check_room(size_t n, size_t rec_max, size_t outn)
{
    unsigned pkts = 0u;
    CHECK(s_cut(s_in, n, rec_max, s_out, outn - 1u, &pkts) == 0u,
          "a room one byte short of the cut refuses it");
    CHECK(s_cut(s_in, n, rec_max, s_out, outn + duct_vnet_gso_lead, &pkts) == outn,
          "a room of the cut and a lead takes it");
    return 0;
}

/** @brief Cut one built superpacket and check every segment against the
 *  reference sums. */
static int s_check_cut(bool v6, size_t topt, size_t payload, uint16_t mss,
                       uint8_t tflags, uint8_t gso)
{
    size_t n = s_build(v6, topt, payload, mss, tflags, 1u, gso);
    unsigned pkts = 0u;
    size_t outn = s_cut(s_in, n, 0u, s_out, sizeof s_out, &pkts);
    size_t l4 = v6 ? 40u : 20u,
           thl = 20u + topt,
           hdr = l4 + thl,
           nseg = (payload + mss - 1u) / mss;
    const uint8_t *orig = s_in + t_vnet + hdr;
    CHECK(outn > 0u, "a well-formed superpacket is cut");
    CHECK(pkts == nseg, "one packet per mss of payload");
    size_t off = 0u, i = 0u;
    for (const uint8_t *o = s_out; o < s_out + outn; ++i) {
        size_t plen = duct_dgram_rec_hdr_decode(o);
        const uint8_t *p = o + duct_dgram_record_hdr_size,
                      *th = p + l4;
        size_t chunk = plen - hdr;
        CHECK(i < nseg, "no packet past the count");
        CHECK(chunk == (i + 1u < nseg ? mss : payload - i * mss), "segment payload length");
        CHECK(s_hdr_kept(p, s_in + t_vnet, hdr, v6, l4), "a segment keeps every header byte the cut does not rewrite");
        if (v6)
            CHECK(s_n16(p + 4u) == plen - 40u, "ipv6 payload length");
        else {
            CHECK(s_n16(p + 2u) == plen, "ipv4 total length");
            CHECK(s_n16(p + 4u) == (uint16_t)(t_id0 + i), "ipv4 id steps per segment");
            CHECK(s_ref_fold(s_ref_sum(0u, p, 20u)) == 0xffffu, "ipv4 header checksum");
        }
        CHECK(s_n32(th + 4u) == t_seq0 + (uint32_t)(i * mss), "tcp sequence advances by mss");
        uint8_t f = th[13];
        bool last = i + 1u == nseg;
        CHECK(!!(f & t_fin) == (last && (tflags & t_fin)), "fin only on the last segment");
        CHECK(!!(f & t_psh) == (last && (tflags & t_psh)), "psh only on the last segment");
        CHECK(!!(f & t_cwr) == (i == 0u && (tflags & t_cwr)), "cwr only on the first segment");
        CHECK((f & t_ack) == (tflags & t_ack), "ack survives the cut");
        uint32_t acc = s_ref_sum(s_ref_pseudo(p, v6, thl + chunk), th, thl + chunk);
        CHECK(s_ref_fold(acc) == 0xffffu, "tcp checksum over pseudo header and segment");
        CHECK(memcmp(p + hdr, orig + off, chunk) == 0, "payload bytes in order");
        off += chunk;
        o = p + plen;
    }
    CHECK(i == nseg && off == payload, "every payload byte lands once");
    return s_check_room(n, 0u, outn);
}

/** @brief Cut the UDP superpacket of @p payload bytes in datagrams of @p mss that @c s_build_udp left
 *  in @c s_in, @p n bytes, and check every datagram against the reference sums: lengths, IPv4 ID and
 *  header checksum, UDP length and checksum, payload in order. */
static int s_check_udp(bool v6, size_t payload, uint16_t mss, size_t n)
{
    unsigned pkts = 0u;
    size_t outn = s_cut(s_in, n, 0u, s_out, sizeof s_out, &pkts);
    size_t l4 = v6 ? 40u : 20u,
           hdr = l4 + duct_udp_hdr_size,
           ndg = (payload + mss - 1u) / mss;
    const uint8_t *orig = s_in + t_vnet + hdr;
    CHECK(outn > 0u, "a well-formed udp superpacket is cut");
    CHECK(pkts == ndg, "one datagram per mss of payload");
    size_t off = 0u, i = 0u;
    for (const uint8_t *o = s_out; o < s_out + outn; ++i) {
        uint32_t raw = (uint32_t)duct_dgram_rec_hdr_decode(o);
        size_t plen = raw;
        CHECK(!(raw & duct_dgram_rec_gso), "a datagram is a plain record");
        const uint8_t *p = o + duct_dgram_record_hdr_size,
                      *uh = p + l4;
        size_t chunk = plen - hdr;
        CHECK(i < ndg, "no datagram past the count");
        CHECK(chunk == (i + 1u < ndg ? mss : payload - i * mss), "datagram payload length");
        CHECK(s_hdr_kept(p, s_in + t_vnet, hdr, v6, l4), "a datagram keeps every header byte the cut does not rewrite");
        if (v6)
            CHECK(s_n16(p + 4u) == plen - 40u, "ipv6 payload length");
        else {
            CHECK(s_n16(p + 2u) == plen, "ipv4 total length");
            CHECK(s_n16(p + 4u) == (uint16_t)(t_id0 + i), "ipv4 id steps per datagram");
            CHECK(s_ref_fold(s_ref_sum(0u, p, 20u)) == 0xffffu, "ipv4 header checksum");
        }
        CHECK(s_n16(uh + 4u) == duct_udp_hdr_size + chunk, "udp length");
        CHECK(s_n16(uh + 6u) != 0u, "a udp checksum is never sent as 0");
        uint32_t acc = s_ref_sum(s_ref_pseudo(p, v6, duct_udp_hdr_size + chunk), uh, duct_udp_hdr_size + chunk);
        CHECK(s_ref_fold(acc) == 0xffffu, "udp checksum over pseudo header and datagram");
        CHECK(memcmp(p + hdr, orig + off, chunk) == 0, "payload bytes in order");
        off += chunk;
        o = p + plen;
    }
    CHECK(i == ndg && off == payload, "every payload byte lands once");
    return s_check_room(n, 0u, outn);
}

static uint8_t s_first[duct_vnet_cut_max];
static uint8_t s_again[t_read_max];
static duct_vnet_gro_t s_gro;

/** @brief Lay the train's headers and payload spans end to end at @p out, the packet a
 *  gathered write puts together. */
static size_t s_gro_flat(const duct_vnet_gro_t *g, uint8_t *out)
{
    size_t len = 0u;
    for (unsigned i = 1u; i < duct_vnet_gro_front + g->nspans; ++i) {
        memcpy(out + len, g->bufs[i].data, g->bufs[i].size);
        len += g->bufs[i].size;
    }
    return len;
}

/** @brief Cut the superpacket of @p n bytes in @c s_in, merge its packets back into one train under
 *  @p merge, and cut that train again: both cuts match byte for byte. Each offer but the last joins
 *  the open train, and the last answers @p last. The train's write stays in @c s_again. */
static int s_merge_back(size_t n, duct_vnet_merge_t merge, duct_vnet_gro_rc_t last)
{
    unsigned pkts = 0u;
    size_t firstn = s_cut(s_in, n, 0u, s_first, sizeof s_first, &pkts);
    CHECK(firstn && pkts > 1u, "the superpacket cuts into several packets");
    unsigned i = 0u;
    for (const uint8_t *o = s_first; o < s_first + firstn; ++i) {
        size_t plen = duct_dgram_rec_hdr_decode(o);
        auto rc = duct_vnet_gro_offer(&s_gro, o + duct_dgram_record_hdr_size, plen, 0u, merge);
        CHECK(rc == (i + 1u < pkts ? vnet_gro_taken : last),
              "consecutive packets of one flow join one train, the last as the flow ends");
        o += duct_dgram_record_hdr_size + plen;
    }
    duct_vnet_gro_finish(&s_gro, s_again);
    size_t len = s_gro_flat(&s_gro, s_again + t_vnet);
    CHECK(len == n - t_vnet && len == s_gro.len, "the train is the superpacket's size");
    size_t againn = s_cut(s_again, t_vnet + len, 0u, s_out, sizeof s_out, &pkts);
    CHECK(againn == firstn && !memcmp(s_out, s_first, firstn),
          "cutting the train again gives back the same packets");
    return 0;
}

/** @brief Merge the segments of a TCP superpacket back into one train: it goes out as a TCP
 *  segmented write. */
static int s_check_gro_round_trip(bool v6, size_t topt, size_t payload, uint16_t mss)
{
    size_t n = s_build(v6, topt, payload, mss, t_ack | t_psh, 1u, v6 ? 4u : 1u);
    if (s_merge_back(n, vnet_merge_tcp, vnet_gro_taken_last))
        return 1;
    CHECK(s_again[0] == 1u && s_again[1] == (v6 ? 4u : 1u), "a train goes out as a segmented write");
    return 0;
}

/** @brief A train stops taking at its span bound; its spans then leave in one gathered
 *  write, the virtio header and the headers ahead of 1022 payloads, and arrive as the
 *  packet they make. */
static int s_check_gro_spans(void)
{
    static constexpr size_t seg = 64u;
    static uint8_t many[128u * 1024u];
    size_t n = s_build(false, 12u, duct_vnet_gro_span_max * seg, (uint16_t)seg, t_ack, 1u, 1u);
    unsigned pkts = 0u;
    size_t cutn = s_cut(s_in, n, 0u, many, sizeof many, &pkts);
    CHECK(cutn && pkts == duct_vnet_gro_span_max, "a superpacket of the span bound's segments cuts to one packet each");
    unsigned i = 0u;
    for (const uint8_t *o = many; o < many + cutn; ++i) {
        size_t plen = duct_dgram_rec_hdr_decode(o);
        auto rc = duct_vnet_gro_offer(&s_gro, o + duct_dgram_record_hdr_size, plen, 0u,
                                      vnet_merge_tcp);
        CHECK(rc == (i + 1u < pkts ? vnet_gro_taken : vnet_gro_taken_last),
              "the span bound closes the train, no sooner and no later");
        o += duct_dgram_record_hdr_size + plen;
    }
    uint8_t vh[duct_vnet_hdr_max];
    duct_vnet_gro_finish(&s_gro, vh);
    size_t len = s_gro_flat(&s_gro, s_again + t_vnet);
    CHECK(s_gro.nspans == duct_vnet_gro_span_max && len == n - t_vnet,
          "the train holds every segment of the superpacket");
#ifdef __linux__
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0, "socketpair");
    memcpy(s_again, vh, t_vnet);
    s_gro.bufs[0] = (duct_view_u8){ .data = vh, .size = t_vnet };
    size_t written = 0u;
    auto rc = duct_xwritev(sv[0], x_raw_packet, s_gro.bufs, duct_vnet_gro_front + s_gro.nspans,
                           &written, 0);
    static uint8_t got[t_read_max];
    ssize_t r = recv(sv[1], got, sizeof got, 0);
    close(sv[0]);
    close(sv[1]);
    CHECK(rc == rc_ok && written == t_vnet + len, "1024 spans go out in one write");
    CHECK(r == (ssize_t)written && !memcmp(got, s_again, written), "every byte arrives in order");
#endif
    return 0;
}

/** @brief Merge the datagrams of a UDP superpacket back into one train: it goes out as a type 5
 *  write naming the datagram's headers. Only the last datagram closes the train, by being shorter
 *  or by leaving no room for another of the first's size. */
static int s_check_udp_train(bool v6, size_t payload, uint16_t mss)
{
    size_t l4 = v6 ? 40u : 20u,
           hdr = l4 + duct_udp_hdr_size;
    bool closes = payload % mss || hdr + payload + mss > 0xffffu;
    if (s_merge_back(s_build_udp(v6, payload, mss), vnet_merge_tcp_udp,
                     closes ? vnet_gro_taken_last : vnet_gro_taken))
        return 1;
    uint16_t f16[4];
    memcpy(f16, s_again + 2u, sizeof f16);
    CHECK(s_again[0] == 1u && s_again[1] == t_gso_udp, "a train goes out as a UDP segmented write");
    CHECK(f16[0] == hdr && f16[1] == mss && f16[2] == l4 && f16[3] == 6u,
          "hdr_len, gso_size, csum_start and csum_offset name the datagram's headers");
    return 0;
}

/** @brief What continues a UDP train, what flushes it first and what stays alone, over IPv4 and a
 *  few IPv6 cases, and the shorter datagram that closes it. */
static int s_check_udp_rules(void)
{
    static constexpr size_t seg = 1200u;
    static constexpr size_t hdr = 28u;
    size_t n = s_build_udp(false, 2u * seg, seg);
    unsigned pkts = 0u;
    size_t firstn = s_cut(s_in, n, 0u, s_first, sizeof s_first, &pkts);
    CHECK(firstn && pkts == 2u, "two datagrams to play with");
    size_t la = duct_dgram_rec_hdr_decode(s_first);
    CHECK(la == hdr + seg, "a datagram is its headers and its segment");
    uint8_t a[hdr + seg],
            b[hdr + seg],
            alt[48u + seg + 1u];
    memcpy(a, s_first + duct_dgram_record_hdr_size, la);
    memcpy(b, s_first + 2u * duct_dgram_record_hdr_size + la, la);
    CHECK(duct_vnet_gro_offer(&s_gro, a, la, 0u, vnet_merge_tcp) == vnet_gro_alone,
          "a leg that took no USO flags merges no datagram");
    CHECK(duct_vnet_gro_offer(&s_gro, a, la, 0u, vnet_merge_tcp_udp) == vnet_gro_taken,
          "a datagram opens a train");
    memcpy(alt, b, la);
    alt[20] ^= 1u;
    s_fix_udp4(alt, la);
    CHECK(duct_vnet_gro_offer(&s_gro, alt, la, 0u, vnet_merge_tcp_udp) == vnet_gro_flush_first,
          "another port flushes the train first");
    memcpy(alt, b, la);
    alt[19] ^= 1u;
    s_fix_ip4(alt);
    s_fix_udp4(alt, la);
    CHECK(duct_vnet_gro_offer(&s_gro, alt, la, 0u, vnet_merge_tcp_udp) == vnet_gro_flush_first,
          "another address flushes the train first");
    memcpy(alt, b, la);
    s_p16(alt + 4u, (uint16_t)(t_id0 + 5u));
    s_fix_ip4(alt);
    CHECK(duct_vnet_gro_offer(&s_gro, alt, la, 0u, vnet_merge_tcp_udp) == vnet_gro_flush_first,
          "an ipv4 id out of step flushes the train first");
    memcpy(alt, b, la);
    alt[8] ^= 1u;
    s_fix_ip4(alt);
    CHECK(duct_vnet_gro_offer(&s_gro, alt, la, 0u, vnet_merge_tcp_udp) == vnet_gro_flush_first,
          "another TTL flushes the train first");
    memcpy(alt, b, la);
    alt[1] ^= 4u;
    s_fix_ip4(alt);
    CHECK(duct_vnet_gro_offer(&s_gro, alt, la, 0u, vnet_merge_tcp_udp) == vnet_gro_flush_first,
          "another TOS flushes the train first");
    memcpy(alt, b, la);
    alt[la] = 0x5au;
    s_p16(alt + 2u, (uint16_t)(la + 1u));
    s_p16(alt + 24u, (uint16_t)(la + 1u - 20u));
    s_fix_ip4(alt);
    s_fix_udp4(alt, la + 1u);
    CHECK(duct_vnet_gro_offer(&s_gro, alt, la + 1u, 0u, vnet_merge_tcp_udp) == vnet_gro_flush_first,
          "a datagram longer than the first flushes the train first");
    size_t tn = s_build(false, 0u, seg, 0u, t_ack, 0u, 0u) - t_vnet;
    uint8_t tcp[20u + 20u + seg];
    memcpy(tcp, s_in + t_vnet, tn);
    s_fix_ip4(tcp);
    s_fix_tcp4(tcp, tn);
    CHECK(duct_vnet_gro_offer(&s_gro, tcp, tn, 0u, vnet_merge_tcp_udp) == vnet_gro_flush_first,
          "a TCP segment flushes a UDP train first");
    memcpy(alt, b, la);
    alt[hdr + 3u] ^= 1u;
    CHECK(duct_vnet_gro_offer(&s_gro, alt, la, 0u, vnet_merge_tcp_udp) == vnet_gro_alone,
          "a datagram failing its checksum stays alone");
    memcpy(alt, b, la);
    alt[26] = alt[27] = 0u;
    CHECK(duct_vnet_gro_offer(&s_gro, alt, la, 0u, vnet_merge_tcp_udp) == vnet_gro_alone,
          "a datagram with no checksum stays alone");
    memcpy(alt, b, la);
    s_p16(alt + 24u, (uint16_t)(la - 20u - 1u));
    CHECK(duct_vnet_gro_offer(&s_gro, alt, la, 0u, vnet_merge_tcp_udp) == vnet_gro_alone,
          "a UDP length off the IP length stays alone");
    memcpy(alt, b, la);
    alt[10] ^= 1u;
    CHECK(duct_vnet_gro_offer(&s_gro, alt, la, 0u, vnet_merge_tcp_udp) == vnet_gro_alone,
          "a datagram failing its ipv4 header checksum stays alone");
    memcpy(alt, b, la);
    alt[6] = 0u;
    s_fix_ip4(alt);
    CHECK(duct_vnet_gro_offer(&s_gro, alt, la, 0u, vnet_merge_tcp_udp) == vnet_gro_alone,
          "a datagram without DF stays alone");
    memcpy(alt, b, la);
    alt[0] = 0x46u;
    CHECK(duct_vnet_gro_offer(&s_gro, alt, la, 0u, vnet_merge_tcp_udp) == vnet_gro_alone,
          "a datagram under ipv4 options stays alone");
    memcpy(alt, b, hdr);
    s_p16(alt + 2u, hdr);
    s_p16(alt + 24u, duct_udp_hdr_size);
    s_fix_ip4(alt);
    s_fix_udp4(alt, hdr);
    CHECK(duct_vnet_gro_offer(&s_gro, alt, hdr, 0u, vnet_merge_tcp_udp) == vnet_gro_alone,
          "a datagram with no payload stays alone");
    CHECK(duct_vnet_gro_offer(&s_gro, b, la, 0u, vnet_merge_tcp_udp) == vnet_gro_taken,
          "the next datagram of the flow joins");
    memcpy(alt, b, la);
    s_p16(alt + 4u, (uint16_t)(t_id0 + 2u));
    s_p16(alt + 2u, (uint16_t)(hdr + 800u));
    s_p16(alt + 24u, (uint16_t)(duct_udp_hdr_size + 800u));
    s_fix_ip4(alt);
    s_fix_udp4(alt, hdr + 800u);
    CHECK(duct_vnet_gro_offer(&s_gro, alt, hdr + 800u, 0u, vnet_merge_tcp_udp) == vnet_gro_taken_last,
          "a shorter datagram joins and closes the train");
    uint8_t vh[duct_vnet_hdr_max];
    duct_vnet_gro_finish(&s_gro, vh);
    uint16_t f16[4];
    memcpy(f16, vh + 2u, sizeof f16);
    CHECK(s_gro.len == hdr + 2u * seg + 800u && s_gro.nspans == 3u, "three datagrams make the train");
    CHECK(vh[1] == t_gso_udp && f16[1] == seg, "the segment size is the first datagram's");
    CHECK(duct_vnet_gro_offer(&s_gro, a, la, 0u, vnet_merge_tcp_udp) == vnet_gro_taken,
          "a datagram opens a train again");
    memcpy(alt, b, la);
    alt[20] ^= 1u;
    CHECK(duct_vnet_gro_offer(&s_gro, alt, la, 0u, vnet_merge_tcp_udp) == vnet_gro_flush_first,
          "a datagram of another flow flushes the train before its checksum is read");
    duct_vnet_gro_finish(&s_gro, vh);
    CHECK(duct_vnet_gro_offer(&s_gro, alt, la, 0u, vnet_merge_tcp_udp) == vnet_gro_alone,
          "offered again to the empty train, the same datagram fails its checksum");

    n = s_build_udp(true, 2u * seg, seg);
    firstn = s_cut(s_in, n, 0u, s_first, sizeof s_first, &pkts);
    la = duct_dgram_rec_hdr_decode(s_first);
    uint8_t a6[48u + seg],
            b6[48u + seg];
    memcpy(a6, s_first + duct_dgram_record_hdr_size, la);
    memcpy(b6, s_first + 2u * duct_dgram_record_hdr_size + la, la);
    CHECK(firstn && pkts == 2u && la == 48u + seg, "two ipv6 datagrams to play with");
    CHECK(duct_vnet_gro_offer(&s_gro, a6, la, 0u, vnet_merge_tcp_udp) == vnet_gro_taken,
          "an ipv6 datagram opens a train");
    memcpy(alt, b6, la);
    alt[7] ^= 1u;
    CHECK(duct_vnet_gro_offer(&s_gro, alt, la, 0u, vnet_merge_tcp_udp) == vnet_gro_flush_first,
          "another hop limit flushes the train first");
    memcpy(alt, b6, la);
    alt[1] ^= 0x10u;
    CHECK(duct_vnet_gro_offer(&s_gro, alt, la, 0u, vnet_merge_tcp_udp) == vnet_gro_flush_first,
          "another traffic class flushes the train first");
    memcpy(alt, b6, la);
    alt[48u + 3u] ^= 1u;
    CHECK(duct_vnet_gro_offer(&s_gro, alt, la, 0u, vnet_merge_tcp_udp) == vnet_gro_alone,
          "an ipv6 datagram failing its checksum stays alone");
    CHECK(duct_vnet_gro_offer(&s_gro, b6, la, 0u, vnet_merge_tcp_udp) == vnet_gro_taken,
          "the next ipv6 datagram of the flow joins");
    duct_vnet_gro_finish(&s_gro, vh);
    return 0;
}

/** @brief A train stops at the datagram bound: of 65 datagrams the first 64 leave as one train and
 *  the 65th opens the next. */
static int s_check_udp_cap(void)
{
    static constexpr size_t seg = 100u;
    size_t n = s_build_udp(false, (duct_vnet_udp_segs_max + 1u) * seg, seg);
    unsigned pkts = 0u;
    size_t firstn = s_cut(s_in, n, 0u, s_first, sizeof s_first, &pkts);
    CHECK(firstn && pkts == duct_vnet_udp_segs_max + 1u, "a superpacket of one datagram over the bound");
    unsigned i = 0u;
    for (const uint8_t *o = s_first; o < s_first + firstn; ++i) {
        size_t plen = duct_dgram_rec_hdr_decode(o);
        auto rc = duct_vnet_gro_offer(&s_gro, o + duct_dgram_record_hdr_size, plen, 0u,
                                      vnet_merge_tcp_udp);
        if (i + 1u == duct_vnet_udp_segs_max) {
            CHECK(rc == vnet_gro_taken_last, "the bound closes the train");
            uint8_t vh[duct_vnet_hdr_max];
            duct_vnet_gro_finish(&s_gro, vh);
            CHECK(s_gro.nspans == duct_vnet_udp_segs_max && vh[1] == t_gso_udp,
                  "the train holds the bound's datagrams");
        } else
            CHECK(rc == vnet_gro_taken, "a datagram under the bound joins");
        o += duct_dgram_record_hdr_size + plen;
    }
    uint8_t vh[duct_vnet_hdr_max];
    duct_vnet_gro_finish(&s_gro, vh);
    CHECK(s_gro.nspans == 1u && !memcmp(vh, duct_vnet_zero, sizeof vh),
          "the datagram past the bound goes out alone under a zero header");
    return 0;
}

/** @brief Offer every packet and record in the @p n cut bytes at @p out to
 *  @c s_gro under @p merge, and answer what the last offer returned. */
static duct_vnet_gro_rc_t s_offer_all(const uint8_t *out, size_t n, duct_vnet_merge_t merge)
{
    auto rc = vnet_gro_alone;
    for (const uint8_t *o = out; o < out + n; ) {
        uint32_t raw = (uint32_t)duct_dgram_rec_hdr_decode(o);
        duct_view_u8 pkt = { .data = (void *)(o + duct_dgram_record_hdr_size),
                           .size = raw & ~duct_dgram_rec_gso };
        uint8_t vh[duct_vnet_hdr_max];
        size_t mss = raw & duct_dgram_rec_gso ? duct_vnet_gso_open(&pkt, vh) : 0u;
        rc = duct_vnet_gro_offer(&s_gro, pkt.data, pkt.size, mss, merge);
        o += duct_dgram_record_hdr_size + (raw & ~duct_dgram_rec_gso);
    }
    return rc;
}

/** @brief Cut one built superpacket under bound @p rec_max and check every
 *  record's prefix, lead, headers, partial sum and payload against the
 *  reference, a lone remainder segment against its full checksum. */
static int s_check_records(bool v6, size_t topt, size_t payload, uint16_t mss,
                           uint8_t tflags, uint8_t gso, size_t rec_max)
{
    size_t n = s_build(v6, topt, payload, mss, tflags, 1u, gso);
    unsigned pkts = 0u;
    size_t outn = s_cut(s_in, n, rec_max, s_out, sizeof s_out, &pkts);
    size_t l4 = v6 ? 40u : 20u,
           thl = 20u + topt,
           hdr = l4 + thl,
           nseg = (payload + mss - 1u) / mss,
           k = (rec_max - duct_vnet_gso_lead - hdr) / mss;
    const uint8_t *orig = s_in + t_vnet + hdr;
    CHECK(outn > 0u && k > 1u, "a superpacket cuts under a bound of several segments");
    CHECK(pkts == (nseg + k - 1u) / k, "one record per bound's worth of segments");
    size_t off = 0u,
           first = 0u;
    for (const uint8_t *o = s_out; o < s_out + outn; first += k) {
        uint32_t raw = (uint32_t)duct_dgram_rec_hdr_decode(o);
        size_t take = nseg - first < k ? nseg - first : k,
               rlen = raw & ~duct_dgram_rec_gso,
               lead = take > 1u ? duct_vnet_gso_lead : 0u;
        const uint8_t *p = o + duct_dgram_record_hdr_size + lead,
                      *th = p + l4;
        size_t plen = rlen - lead,
               chunk = plen - hdr;
        bool last = first + take == nseg;
        CHECK(first < nseg, "no record past the count");
        CHECK(!!(raw & duct_dgram_rec_gso) == (take > 1u), "the prefix marks a record of several segments");
        CHECK(!lead || s_n16(o + duct_dgram_record_hdr_size) == mss, "a record leads with its segment size");
        CHECK(chunk == (last ? payload - first * mss : take * mss), "record payload length");
        CHECK(s_hdr_kept(p, s_in + t_vnet, hdr, v6, l4), "a record keeps every header byte the cut does not rewrite");
        if (v6)
            CHECK(s_n16(p + 4u) == plen - 40u, "ipv6 payload length");
        else {
            CHECK(s_n16(p + 2u) == plen, "ipv4 total length");
            CHECK(s_n16(p + 4u) == (uint16_t)(t_id0 + first), "ipv4 id of the record's first segment");
            CHECK(s_ref_fold(s_ref_sum(0u, p, 20u)) == 0xffffu, "ipv4 header checksum");
        }
        CHECK(s_n32(th + 4u) == t_seq0 + (uint32_t)(first * mss), "tcp sequence of the first segment");
        uint8_t f = th[13];
        CHECK(!!(f & t_fin) == (last && (tflags & t_fin)), "fin only on the last record");
        CHECK(!!(f & t_psh) == (last && (tflags & t_psh)), "psh only on the last record");
        CHECK(!!(f & t_cwr) == (first == 0u && (tflags & t_cwr)), "cwr only on the first record");
        if (lead)
            CHECK(s_n16(th + 16u) == s_ref_fold(s_ref_pseudo(p, v6, thl + chunk)),
                  "a record's checksum field holds its pseudo-header sum");
        else
            CHECK(s_ref_fold(s_ref_sum(s_ref_pseudo(p, v6, thl + chunk), th, thl + chunk)) == 0xffffu,
                  "a lone segment carries its full checksum");
        CHECK(memcmp(p + hdr, orig + off, chunk) == 0, "payload bytes in order");
        off += chunk;
        o += duct_dgram_record_hdr_size + rlen;
    }
    CHECK(off == payload, "every payload byte lands once");
    return s_check_room(n, rec_max, outn);
}

/** @brief Cut a superpacket into records under @p rec_max, merge them into one
 *  train and cut that train per segment: it matches the superpacket's own
 *  per-segment cut byte for byte, and so does a cut under a bound short of two
 *  segments. */
static int s_check_record_round_trip(bool v6, size_t topt, size_t payload, uint16_t mss,
                                     size_t rec_max)
{
    size_t n = s_build(v6, topt, payload, mss, t_ack | t_psh, 1u, v6 ? 4u : 1u);
    unsigned pkts = 0u;
    size_t firstn = s_cut(s_in, n, 0u, s_first, sizeof s_first, &pkts);
    size_t hdr = (v6 ? 40u : 20u) + 20u + topt;
    size_t outn = s_cut(s_in, n, hdr + 2u * mss + 1u, s_out, sizeof s_out, &pkts);
    CHECK(outn == firstn && !memcmp(s_out, s_first, firstn),
          "a bound short of two segments cuts as with none");
    outn = s_cut(s_in, n, rec_max, s_out, sizeof s_out, &pkts);
    CHECK(outn && outn < firstn, "records save the repeated headers");
    CHECK(s_offer_all(s_out, outn, vnet_merge_tcp) == vnet_gro_taken_last,
          "records and a remainder join one train");
    duct_vnet_gro_finish(&s_gro, s_again);
    size_t len = s_gro_flat(&s_gro, s_again + t_vnet);
    CHECK(len == n - t_vnet && len == s_gro.len, "the train is the superpacket's size");
    outn = s_cut(s_again, t_vnet + len, 0u, s_out, sizeof s_out, &pkts);
    CHECK(outn == firstn && !memcmp(s_out, s_first, firstn),
          "the train cut again gives back the per-segment packets");
    return 0;
}

static uint8_t s_trim[duct_vnet_gso_lead + duct_vnet_gso_max];

/** @brief Trim a copy of @p rec in place, in @c s_trim.
 *  @return the trim's answer; where it is 0 the copy still equals @p rec. */
static size_t s_trim_copy(duct_view_u8 rec)
{
    memcpy(s_trim, rec.data, rec.size);
    return duct_gso_trim((duct_view_u8){ .data = s_trim, .size = rec.size });
}

/** @brief Cut a superpacket under @p rec_max, trim its first record and check
 *  the trimmed copy's lengths, checksums and payload against the reference, and
 *  that it still opens for a device write. */
static int s_check_trim(bool v6, size_t topt, size_t payload, uint16_t mss, size_t rec_max)
{
    size_t n = s_build(v6, topt, payload, mss, t_ack | t_psh, 1u, v6 ? 4u : 1u);
    unsigned pkts = 0u;
    size_t outn = s_cut(s_in, n, rec_max, s_out, sizeof s_out, &pkts);
    size_t l4 = v6 ? 40u : 20u,
           hdr = l4 + 20u + topt;
    uint32_t raw = (uint32_t)duct_dgram_rec_hdr_decode(s_out);
    duct_view_u8 rec = { .data = s_out + duct_dgram_record_hdr_size,
                       .size = raw & ~duct_dgram_rec_gso };
    size_t chunk = rec.size - duct_vnet_gso_lead - hdr,
           nseg = (chunk + mss - 1u) / mss;
    CHECK(outn && (raw & duct_dgram_rec_gso) && nseg >= 3u, "a record of three segments or more");
    size_t tn = s_trim_copy(rec);
    size_t plen = tn - duct_vnet_gso_lead;
    CHECK(tn && plen == hdr + (nseg - 1u) * mss, "the trim takes the last segment");
    const uint8_t *p = s_trim + duct_vnet_gso_lead,
                  *th = p + l4;
    CHECK(s_n16(s_trim) == mss, "the segment size stays");
    if (v6)
        CHECK(s_n16(p + 4u) == plen - 40u, "ipv6 payload length");
    else {
        CHECK(s_n16(p + 2u) == plen, "ipv4 total length");
        CHECK(s_n16(p + 4u) == t_id0, "ipv4 id stays");
        CHECK(s_ref_fold(s_ref_sum(0u, p, 20u)) == 0xffffu, "ipv4 header checksum");
    }
    CHECK(s_n32(th + 4u) == t_seq0, "tcp sequence stays");
    CHECK(s_n16(th + 16u) == s_ref_fold(s_ref_pseudo(p, v6, plen - l4)),
          "the checksum field holds the trimmed record's pseudo-header sum");
    CHECK(!memcmp(p + hdr, (const uint8_t *)rec.data + duct_vnet_gso_lead + hdr, plen - hdr),
          "the kept payload is untouched");
    duct_view_u8 open = { .data = s_trim, .size = tn };
    uint8_t vh[duct_vnet_hdr_max];
    CHECK(duct_vnet_gso_open(&open, vh) == mss, "the trimmed record opens for a device write");
    return 0;
}

static uint8_t s_ce[duct_vnet_gso_lead + duct_vnet_gso_max];

/** @brief Mark CE on a copy of @p f's payload, in place, in @c s_ce.
 *  @return the mark's answer; where it is 0 the copy still equals the payload. */
static size_t s_mark_copy(const duct_frame_t *f)
{
    memcpy(s_ce, f->payload.data, f->payload.size);
    duct_frame_t copy = *f;
    copy.payload.data = s_ce;
    return duct_frame_mark_ce(&copy);
}

/** @brief Read and set CE on an IPv4 packet, an IPv6 packet and a record,
 *  checking the header checksum and every other byte, and refuse the
 *  codepoints and headers the mark does not take. */
static int s_check_ce(void)
{
    size_t n = s_build(false, 12u, 900u, 0u, t_ack, 0u, 0u);
    uint8_t *p = s_in + t_vnet;
    size_t len = n - t_vnet;
    p[1] = 0x02u;
    s_fix_ip4(p);
    duct_frame_t f = { .payload = { .data = p, .size = len } };
    CHECK(duct_frame_ecn(&f) == ecn_ect0, "an ipv4 packet reads ect(0)");
    CHECK(s_mark_copy(&f) == len && (s_ce[1] & 3u) == 3u
              && s_ref_fold(s_ref_sum(0u, s_ce, 20u)) == 0xffffu
              && !memcmp(s_ce + 20u, p + 20u, len - 20u),
          "ce lands on an ipv4 packet with its header checksum");
    p[1] = 0x03u;
    CHECK(duct_frame_ecn(&f) == ecn_ce && !s_mark_copy(&f) && !memcmp(s_ce, p, len),
          "a ce packet is not marked again, and left as it was");
    p[1] = 0x00u;
    CHECK(duct_frame_ecn(&f) == ecn_not_ect && !s_mark_copy(&f) && !memcmp(s_ce, p, len),
          "a not-ect packet is not marked, and left as it was");
    p[0] = 0x55u;
    CHECK(duct_frame_ecn(&f) == ecn_none && !s_mark_copy(&f) && !memcmp(s_ce, p, len),
          "no ip header, no codepoint, and the packet left as it was");

    n = s_build(true, 0u, 900u, 0u, t_ack, 0u, 0u);
    len = n - t_vnet;
    p[1] |= 0x10u;
    f.payload.size = len;
    CHECK(duct_frame_ecn(&f) == ecn_ect1, "an ipv6 packet reads ect(1)");
    CHECK(s_mark_copy(&f) == len && ((s_ce[1] >> 4u) & 3u) == 3u
              && (s_ce[1] & 0x0fu) == (p[1] & 0x0fu) && !memcmp(s_ce + 2u, p + 2u, len - 2u),
          "ce lands on an ipv6 packet's traffic class alone");

    n = s_build(false, 12u, 20000u, 1448u, t_ack, 1u, 1u);
    s_in[t_vnet + 1u] = 0x02u;
    unsigned pkts = 0u;
    size_t outn = s_cut(s_in, n, 6000u, s_out, sizeof s_out, &pkts);
    uint32_t raw = (uint32_t)duct_dgram_rec_hdr_decode(s_out);
    f = (duct_frame_t){ .payload = { .data = s_out + duct_dgram_record_hdr_size,
                                     .size = raw & ~duct_dgram_rec_gso },
                        .flags = fl_frame_gso };
    CHECK(outn && (raw & duct_dgram_rec_gso) && duct_frame_ecn(&f) == ecn_ect0, "a record reads past its lead");
    CHECK(s_mark_copy(&f) == f.payload.size && s_n16(s_ce) == 1448u
              && (s_ce[duct_vnet_gso_lead + 1u] & 3u) == 3u
              && s_ref_fold(s_ref_sum(0u, s_ce + duct_vnet_gso_lead, 20u)) == 0xffffu,
          "ce lands on a record's header, its lead kept");
    duct_view_u8 open = { .data = s_ce, .size = f.payload.size };
    uint8_t vh[duct_vnet_hdr_max];
    CHECK(duct_vnet_gso_open(&open, vh) == 1448u, "the marked record opens for a device write");
    return 0;
}

/** @brief Grow the built read's IP header by 4 bytes of IPv4 options or an
 *  8-byte IPv6 hop-by-hop header, the pseudo-header seed unchanged.
 *  @return Bytes of the read. */
static size_t s_l3_ext(size_t n, bool v6)
{
    size_t l4 = v6 ? 40u : 20u,
           add = v6 ? 8u : 4u;
    uint8_t *p = s_in + t_vnet;
    memmove(p + l4 + add, p + l4, n - t_vnet - l4);
    memset(p + l4, 0, add);
    if (v6) {
        p[l4] = 6u;
        p[6] = 0u;
        s_p16(p + 4u, (uint16_t)(s_n16(p + 4u) + add));
    } else {
        p[0] = 0x46u;
        s_p16(p + 2u, (uint16_t)(s_n16(p + 2u) + add));
    }
    for (size_t at = 2u; at <= 6u; at += 4u) {
        uint16_t v;
        memcpy(&v, s_in + at, sizeof v);
        v = (uint16_t)(v + add);
        memcpy(s_in + at, &v, sizeof v);
    }
    return n + add;
}

/** @brief Cut superpackets whose payload sits under, on and one byte over a whole number of segments,
 *  over both IP versions, with and without TCP options, at four segment sizes and under four record
 *  bounds, and the same UDP superpackets, each as the fixed cases are checked. The cut runs in place,
 *  so each record is checked against a copy of the read that the cut never touched. */
static int s_check_sweep(void)
{
    static const uint16_t msses[] = { 536u, 1220u, 1448u, 8960u };
    for (unsigned v6 = 0u; v6 < 2u; ++v6)
        for (size_t topt = 0u; topt <= 12u; topt += 12u)
            for (size_t m = 0u; m < sizeof msses / sizeof msses[0]; ++m) {
                size_t mss = msses[m],
                       hdr = (v6 ? 40u : 20u) + 20u + topt;
                uint8_t gso = v6 ? 4u : 1u;
                for (size_t segs = 1u; segs <= 36u; segs = segs < 4u ? segs + 1u : segs * 3u)
                    for (size_t cut = 0u; cut < 3u; ++cut) {
                        size_t payload = segs * mss - (cut == 1u ? 1u : cut == 2u ? mss - 1u : 0u);
                        if (hdr + payload > duct_vnet_gso_max)
                            continue;
                        if (s_check_cut(v6, topt, payload, (uint16_t)mss, t_ack | t_psh, gso))
                            return 1;
                        if (!topt && s_check_udp(v6, payload, (uint16_t)mss, s_build_udp(v6, payload, (uint16_t)mss)))
                            return 1;
                        if (!topt && segs > 1u && s_check_udp_train(v6, payload, (uint16_t)mss))
                            return 1;
                        for (size_t k = 2u; k <= 5u; ++k)
                            if (s_check_records(v6, topt, payload, (uint16_t)mss, t_ack | t_psh, gso,
                                                duct_vnet_gso_lead + hdr + k * mss + 7u))
                                return 1;
                    }
            }
    return 0;
}

int main(void)
{
    if (s_check_gro_round_trip(false, 12u, 5000u, 1448u))
        return 1;
    if (s_check_gro_round_trip(true, 12u, 7000u, 1220u))
        return 1;
    if (s_check_gro_spans())
        return 1;
    if (s_check_udp_train(false, 5000u, 1200u))
        return 1;
    if (s_check_udp_train(true, 7000u, 1220u))
        return 1;
    if (s_check_udp_train(false, 46u * 1400u, 1400u))
        return 1;
    if (s_check_udp_rules())
        return 1;
    if (s_check_udp_cap())
        return 1;

    {
        size_t n = s_build(false, 12u, 2896u, 1448u, t_ack, 1u, 1u);
        unsigned pkts = 0u;
        size_t firstn = s_cut(s_in, n, 0u, s_first, sizeof s_first, &pkts);
        const uint8_t *a = s_first + duct_dgram_record_hdr_size,
                      *b = a + 1448u + 52u + duct_dgram_record_hdr_size;
        size_t la = duct_dgram_rec_hdr_decode(s_first);
        CHECK(firstn && pkts == 2u, "two segments to play with");
        CHECK(duct_vnet_gro_offer(&s_gro, a, la, 0u, vnet_merge_tcp) == vnet_gro_taken,
              "a full segment opens a train");
        uint8_t alt[1600];
        memcpy(alt, b, la);
        alt[20] ^= 1u;
        s_fix_tcp4(alt, la);
        CHECK(duct_vnet_gro_offer(&s_gro, alt, la, 0u, vnet_merge_tcp) == vnet_gro_flush_first,
              "another flow flushes the train first");
        memcpy(alt, b, la);
        alt[27] ^= 1u;
        s_fix_tcp4(alt, la);
        CHECK(duct_vnet_gro_offer(&s_gro, alt, la, 0u, vnet_merge_tcp) == vnet_gro_flush_first,
              "a gap in the sequence flushes the train first");
        memcpy(alt, b, la);
        s_p16(alt + 4u, (uint16_t)(t_id0 + 5u));
        s_fix_ip4(alt);
        CHECK(duct_vnet_gro_offer(&s_gro, alt, la, 0u, vnet_merge_tcp) == vnet_gro_flush_first,
              "an ipv4 id out of step flushes the train first");
        memcpy(alt, b, la);
        alt[20u + 16u] ^= 1u;
        CHECK(duct_vnet_gro_offer(&s_gro, alt, la, 0u, vnet_merge_tcp) == vnet_gro_alone,
              "a segment failing its checksum stays alone");
        memcpy(alt, b, la);
        alt[10] ^= 1u;
        CHECK(duct_vnet_gro_offer(&s_gro, alt, la, 0u, vnet_merge_tcp) == vnet_gro_alone,
              "a segment failing its ipv4 header checksum stays alone");
        memcpy(alt, a, 52u);
        s_p16(alt + 2u, 52u);
        CHECK(duct_vnet_gro_offer(&s_gro, alt, 52u, 0u, vnet_merge_tcp) == vnet_gro_alone,
              "a packet with no payload stays alone");
        memcpy(alt, b, la);
        alt[33] |= 0x02u;
        CHECK(duct_vnet_gro_offer(&s_gro, alt, la, 0u, vnet_merge_tcp) == vnet_gro_alone,
              "a syn stays alone");
        uint8_t vh[duct_vnet_hdr_max];
        duct_vnet_gro_finish(&s_gro, vh);
        CHECK(s_gro_flat(&s_gro, alt) == la
                  && !memcmp(vh, duct_vnet_zero, sizeof vh) && !memcmp(alt, a, la),
              "a train of one goes out untouched with a zero header");
    }

    if (s_check_cut(false, 12u, 5000u, 1448u, t_ack | t_psh | t_fin | t_cwr, 1u | 0x80u))
        return 1;
    if (s_check_cut(true, 0u, 4000u, 1220u, t_ack | t_psh, 4u))
        return 1;
    if (s_check_cut(false, 0u, 2896u, 1448u, t_ack, 1u))
        return 1;
    if (s_check_cut(false, 12u, 700u, 1448u, t_ack | t_psh, 1u))
        return 1;

    if (s_check_records(false, 12u, 20000u, 1448u, t_ack | t_psh | t_fin | t_cwr, 1u | 0x80u, 6000u))
        return 1;
    if (s_check_records(true, 0u, 9000u, 1220u, t_ack | t_psh, 4u, 16380u))
        return 1;
    if (s_check_records(false, 12u, 5000u, 1448u, t_ack, 1u, 4400u))
        return 1;
    if (s_check_record_round_trip(false, 12u, 20000u, 1448u, 6000u))
        return 1;
    if (s_check_record_round_trip(true, 12u, 7000u, 1220u, 4000u))
        return 1;
    if (s_check_record_round_trip(false, 12u, 5000u, 1448u, 4400u))
        return 1;
    if (s_check_record_round_trip(false, 12u, 64000u, 1448u, 16380u))
        return 1;

    {
        size_t n = s_build(false, 12u, 5000u, 1448u, t_ack | t_psh | t_fin | t_cwr, 1u, 1u | 0x80u);
        unsigned pkts = 0u;
        size_t outn = s_cut(s_in, n, 3000u, s_out, sizeof s_out, &pkts);
        CHECK(outn && pkts == 2u, "two records of two segments");
        uint32_t raw = (uint32_t)duct_dgram_rec_hdr_decode(s_out);
        duct_view_u8 rec = { .data = s_out + duct_dgram_record_hdr_size,
                           .size = raw & ~duct_dgram_rec_gso };
        uint8_t vh[duct_vnet_hdr_max];
        size_t mss = duct_vnet_gso_open(&rec, vh);
        CHECK(mss == 1448u && vh[0] == 1u && vh[1] == (1u | 0x80u),
              "a record carrying cwr goes out as a segmented write with ecn");
        uint16_t f16[4];
        memcpy(f16, vh + 2u, sizeof f16);
        CHECK(f16[0] == 52u && f16[1] == 1448u && f16[2] == 20u && f16[3] == 16u,
              "hdr_len, gso_size, csum_start and csum_offset come from the record");
        CHECK(duct_vnet_gro_offer(&s_gro, rec.data, rec.size, mss, vnet_merge_tcp) == vnet_gro_alone,
              "a record carrying cwr stays alone");
        const uint8_t *o = s_out + duct_dgram_record_hdr_size + (raw & ~duct_dgram_rec_gso);
        raw = (uint32_t)duct_dgram_rec_hdr_decode(o);
        size_t rlen = raw & ~duct_dgram_rec_gso;
        rec = (duct_view_u8){ .data = (void *)(o + duct_dgram_record_hdr_size), .size = rlen };
        mss = duct_vnet_gso_open(&rec, vh);
        CHECK(mss == 1448u && vh[1] == 1u, "a record carrying no cwr goes out without ecn");
        CHECK(duct_vnet_gro_offer(&s_gro, rec.data, rec.size, mss, vnet_merge_tcp) == vnet_gro_alone,
              "a record carrying fin stays alone");
        uint8_t bad[3000];
        memcpy(bad, o + duct_dgram_record_hdr_size, rlen);
        s_p16(bad, 0u);
        rec = (duct_view_u8){ .data = bad, .size = rlen };
        CHECK(!duct_vnet_gso_open(&rec, vh) && rec.data == bad, "a record needs its segment size");
        s_p16(bad, (uint16_t)(rlen - duct_vnet_gso_lead - 52u));
        CHECK(!duct_vnet_gso_open(&rec, vh), "a record of one segment is refused");
        s_p16(bad, 1448u);
        rec.size = rlen - 1u;
        CHECK(!duct_vnet_gso_open(&rec, vh), "a truncated record is refused");
        rec.size = duct_vnet_gso_lead;
        CHECK(!duct_vnet_gso_open(&rec, vh), "a record holding only its lead is refused");
    }

    if (s_check_trim(false, 12u, 20000u, 1448u, 6000u))
        return 1;
    if (s_check_ce())
        return 1;
    if (s_check_trim(true, 0u, 9000u, 1220u, 16380u))
        return 1;

    {
        size_t n = s_build(false, 12u, 5000u, 1448u, t_ack, 1u, 1u);
        unsigned pkts = 0u;
        size_t outn = s_cut(s_in, n, 3000u, s_out, sizeof s_out, &pkts);
        uint32_t raw = (uint32_t)duct_dgram_rec_hdr_decode(s_out);
        duct_view_u8 rec = { .data = s_out + duct_dgram_record_hdr_size,
                           .size = raw & ~duct_dgram_rec_gso };
        CHECK(outn && (raw & duct_dgram_rec_gso) && !s_trim_copy(rec)
                  && !memcmp(s_trim, rec.data, rec.size),
              "a record of two segments is not trimmed, and left as it was");
        n = s_build(false, 12u, 6u * 1448u, 1448u, t_ack | t_fin, 1u, 1u);
        outn = s_cut(s_in, n, 2u + 52u + 3u * 1448u, s_out, sizeof s_out, &pkts);
        raw = (uint32_t)duct_dgram_rec_hdr_decode(s_out);
        rec = (duct_view_u8){ .data = s_out + duct_dgram_record_hdr_size,
                            .size = raw & ~duct_dgram_rec_gso };
        CHECK(outn && pkts == 2u && s_trim_copy(rec), "a record short of the fin is trimmed");
        const uint8_t *o = s_out + duct_dgram_record_hdr_size + rec.size;
        raw = (uint32_t)duct_dgram_rec_hdr_decode(o);
        rec = (duct_view_u8){ .data = (void *)(o + duct_dgram_record_hdr_size),
                            .size = raw & ~duct_dgram_rec_gso };
        CHECK((raw & duct_dgram_rec_gso) && !s_trim_copy(rec) && !memcmp(s_trim, rec.data, rec.size),
              "a record carrying fin is not trimmed, and left as it was");
        rec.size = duct_vnet_gso_lead;
        CHECK(!s_trim_copy(rec), "a record holding only its lead is not trimmed");
    }

    for (unsigned v6 = 0u; v6 < 2u; ++v6) {
        size_t n = s_l3_ext(s_build(v6, 0u, 5000u, 1448u, t_ack, 1u, v6 ? 4u : 1u), v6);
        unsigned pkts = 0u;
        size_t outn = s_cut(s_in, n, 16380u, s_out, sizeof s_out, &pkts);
        CHECK(outn && pkts == 4u, "ip options or extension headers cut per segment under any bound");
        for (const uint8_t *o = s_out; o < s_out + outn;
             o += duct_dgram_record_hdr_size + duct_dgram_rec_hdr_decode(o))
            CHECK(!(duct_dgram_rec_hdr_decode(o) & duct_dgram_rec_gso),
                  "no record under ip options or extension headers");
    }

    {
        size_t n = s_build(false, 12u, 900u, 0u, t_ack | t_psh, 1u, 0u);
        unsigned pkts = 0u;
        size_t outn = s_cut(s_in, n, 0u, s_out, sizeof s_out, &pkts);
        CHECK(outn == duct_dgram_record_hdr_size + n - t_vnet && pkts == 1u,
              "a plain packet is one record");
        const uint8_t *q = s_out + duct_dgram_record_hdr_size;
        uint32_t acc = s_ref_sum(s_ref_pseudo(q, false, 32u + 900u), q + 20u, 32u + 900u);
        CHECK(s_ref_fold(acc) == 0xffffu, "needs_csum completes the transport checksum");
    }

    {
        size_t n = s_build(false, 0u, 300u, 0u, t_ack, 0u, 0u);
        unsigned pkts = 0u;
        size_t outn = s_cut(s_in, n, 0u, s_out, sizeof s_out, &pkts);
        CHECK(outn == duct_dgram_record_hdr_size + n - t_vnet
                  && memcmp(s_out + duct_dgram_record_hdr_size, s_in + t_vnet, n - t_vnet) == 0,
              "a packet with no offload flag passes as it came");
    }

    {
        unsigned pkts = 7u;
        size_t n = s_build(false, 0u, 3000u, 1448u, t_ack, 1u, 1u);
        CHECK(s_cut(s_in, t_vnet, 0u, s_out, sizeof s_out, &pkts) == 0u
                  && pkts == 0u, "a read with no packet is refused");
        CHECK(s_cut(s_in, n, 0u, s_out, 3000u, &pkts) == 0u,
              "a cut that does not fit is refused");
        s_build(false, 0u, 3000u, 0u, t_ack, 1u, 1u);
        CHECK(s_cut(s_in, n, 0u, s_out, sizeof s_out, &pkts) == 0u,
              "a segmented read without a segment size is refused");
        s_build(false, 0u, 3000u, 1448u, t_ack, 1u, 3u);
        CHECK(s_cut(s_in, n, 0u, s_out, sizeof s_out, &pkts) == 0u,
              "udp fragmentation offload is refused");
        s_build(false, 0u, 3000u, 1448u, t_ack, 1u, 1u);
        s_in[t_vnet] = 0x46u;
        CHECK(s_cut(s_in, n, 0u, s_out, sizeof s_out, &pkts) == 0u,
              "an ipv4 header length off the checksum start is refused");
        n = s_build_udp(false, 3000u, 0u);
        CHECK(s_cut(s_in, n, 0u, s_out, sizeof s_out, &pkts) == 0u,
              "a udp segmented read without a segment size is refused");
        n = s_build_udp(false, 0u, 1400u);
        CHECK(s_cut(s_in, n, 0u, s_out, sizeof s_out, &pkts) == 0u,
              "a udp segmented read with no payload is refused");
        n = s_build_udp(false, 3000u, 1400u);
        s_in[t_vnet] = 0x46u;
        CHECK(s_cut(s_in, n, 0u, s_out, sizeof s_out, &pkts) == 0u,
              "a udp ipv4 header length off the checksum start is refused");
        n = s_build_udp(true, 3000u, 1400u);
        CHECK(s_cut(s_in, n, 0u, s_out, 3000u, &pkts) == 0u,
              "a udp cut that does not fit is refused");
    }

    if (s_check_udp(false, 5000u, 1472u, s_build_udp(false, 5000u, 1472u)))
        return 1;
    if (s_check_udp(true, 3u * 1232u, 1232u, s_build_udp(true, 3u * 1232u, 1232u)))
        return 1;
    if (s_check_udp(false, 100u, 1400u, s_build_udp(false, 100u, 1400u)))
        return 1;

    {
        /* A datagram whose checksum comes to 0 is sent as 0xffff. */
        size_t n = s_build_udp(false, 100u, 1400u);
        uint8_t *p = s_in + t_vnet,
                *uh = p + 20u;
        uh[duct_udp_hdr_size + 98u] = uh[duct_udp_hdr_size + 99u] = 0u;
        s_p16(uh + 6u, 0u);
        uint32_t base = s_ref_fold(s_ref_sum(s_ref_pseudo(p, false, 108u), uh, 108u));
        s_p16(uh + duct_udp_hdr_size + 98u, (uint16_t)(0xffffu - base));
        s_p16(uh + 6u, s_ref_fold(s_ref_pseudo(p, false, 108u)));
        if (s_check_udp(false, 100u, 1400u, n))
            return 1;
        CHECK(s_n16(s_out + duct_dgram_record_hdr_size + 20u + 6u) == 0xffffu,
              "a udp checksum of 0 is sent as 0xffff");
    }

    if (s_check_sweep())
        return 1;

    {
        size_t n = s_build_udp(false, 10000u, 1400u);
        unsigned pkts = 0u;
        size_t cut_off = s_cut_uso(s_in, n, 16380u, false, s_out, sizeof s_out, &pkts);
        CHECK(cut_off && pkts == 8u, "without uso confirmation a udp superpacket cuts into datagrams");

        size_t cut_on = s_cut_uso(s_in, n, 16380u, true, s_out, sizeof s_out, &pkts);
        CHECK(cut_on && pkts == 1u, "with uso confirmation a udp superpacket packs into one gso record");
        uint32_t raw = (uint32_t)duct_dgram_rec_hdr_decode(s_out);
        CHECK(raw & duct_dgram_rec_gso, "udp gso record carries gso bit");
        duct_view_u8 rec = { .data = s_out + duct_dgram_record_hdr_size,
                           .size = raw & ~duct_dgram_rec_gso };
        uint8_t vh[duct_vnet_hdr_max];
        size_t mss = duct_vnet_gso_open(&rec, vh);
        CHECK(mss == 1400u && duct_vnet_gso_is_udp(vh), "udp gso record opens with udp vnet header");
        s_gro = (duct_vnet_gro_t){};
        CHECK(duct_vnet_gro_offer(&s_gro, rec.data, rec.size, mss, vnet_merge_tcp) == vnet_gro_alone,
              "udp gso record is refused without vnet_merge_tcp_udp");
        s_gro = (duct_vnet_gro_t){};
        CHECK(duct_vnet_gro_offer(&s_gro, rec.data, rec.size, mss, vnet_merge_tcp_udp) == vnet_gro_taken_last,
              "udp gso record with short tail completes train under vnet_merge_tcp_udp");
        duct_vnet_gro_finish(&s_gro, vh);
        CHECK(s_gro.nspans == 1u && duct_vnet_gso_is_udp(vh), "finished udp gso train produces udp vnet header");
    }

    printf("vnet_cut_test OK\n");
    return 0;
}
