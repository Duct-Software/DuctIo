/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

#include "duct_vnet.h"

#include "duct_dgram_rec.h"
#include "duct_hash.h"
#include "duct_protocol.h"

#include <stdbool.h>
#include <string.h>

static constexpr uint8_t s_f_needs_csum = 1u;
static constexpr uint8_t s_gso_none = 0u;
static constexpr uint8_t s_gso_tcpv4 = 1u;
static constexpr uint8_t s_gso_tcpv6 = 4u;
static constexpr uint8_t s_gso_udp_l4 = 5u;
static constexpr uint8_t s_gso_ecn = 0x80u;
static constexpr uint8_t s_tcp_fin = 0x01u;
static constexpr uint8_t s_tcp_syn = 0x02u;
static constexpr uint8_t s_tcp_rst = 0x04u;
static constexpr uint8_t s_tcp_psh = 0x08u;
static constexpr uint8_t s_tcp_ack = 0x10u;
static constexpr uint8_t s_tcp_cwr = 0x80u;
static constexpr uint8_t s_proto_tcp = 6u;
static constexpr uint8_t s_proto_udp = 17u;
static constexpr uint8_t s_proto_icmp4 = 1u;
static constexpr uint8_t s_proto_icmp6 = 58u;
static constexpr uint8_t s_ip4_group = 224u;
static constexpr uint8_t s_ip6_group = 0xffu;

const uint8_t duct_vnet_zero[duct_vnet_hdr_max] = {};

/** @brief Read a 16-bit word in host byte order. */
static uint16_t s_host16(const uint8_t *p)
{
    uint16_t v;
    memcpy(&v, p, sizeof v);
    return v;
}

/** @brief Add @p b to @p a in 64-bit ones'-complement, the carry out folded back in. */
static uint64_t s_add1c(uint64_t a, uint64_t b)
{
    a += b;
    return a + (a < b);
}

/** @brief Add @p len bytes to a ones'-complement sum, as host-order words.
 *  The folded result is byte-order independent, RFC 1071, as long as every
 *  operand of one sum is read the same way. Whole 8-byte words run on four
 *  chains of end-around-carry adds, which keeps their carry dependencies
 *  apart. */
static uint64_t s_sum(uint64_t acc, const uint8_t *p, size_t len)
{
    uint64_t a0 = 0u, a1 = 0u, a2 = 0u, a3 = 0u;
    for (; len >= 32u; p += 32u, len -= 32u) {
        uint64_t w0, w1, w2, w3;
        memcpy(&w0, p, sizeof w0);
        memcpy(&w1, p + 8u, sizeof w1);
        memcpy(&w2, p + 16u, sizeof w2);
        memcpy(&w3, p + 24u, sizeof w3);
        a0 = s_add1c(a0, w0);
        a1 = s_add1c(a1, w1);
        a2 = s_add1c(a2, w2);
        a3 = s_add1c(a3, w3);
    }
    for (; len >= 8u; p += 8u, len -= 8u) {
        uint64_t w;
        memcpy(&w, p, sizeof w);
        a0 = s_add1c(a0, w);
    }
    a0 = s_add1c(s_add1c(a0, a1), s_add1c(a2, a3));
    acc += (a0 & 0xffffffffu) + (a0 >> 32u);
    if (len >= 4u) {
        uint32_t w;
        memcpy(&w, p, sizeof w);
        acc += w;
        p += 4u;
        len -= 4u;
    }
    if (len >= 2u) {
        acc += s_host16(p);
        p += 2u;
        len -= 2u;
    }
    if (len)
        acc += s_host16((const uint8_t[2]){ *p, 0u });
    return acc;
}

/** @brief Fold a ones'-complement sum and complement it into a checksum field. */
static uint16_t s_csum(uint64_t acc)
{
    acc = (acc & 0xffffffffu) + (acc >> 32u);
    acc = (acc & 0xffffu) + (acc >> 16u);
    acc = (acc & 0xffffu) + (acc >> 16u);
    acc = (acc & 0xffffu) + (acc >> 16u);
    return (uint16_t)~acc;
}

/** @brief Frame one unsegmented packet in place as a record, completing a
 *  partial checksum from @p start to the field at @p start + @p off. */
static size_t s_whole(uint8_t *rec, size_t len, uint8_t flags,
                      size_t start, size_t off, unsigned *pkts)
{
    uint8_t *p = rec + duct_dgram_record_hdr_size;
    if (flags & s_f_needs_csum) {
        if (start + off + 2u > len)
            return 0u;
        uint16_t c = s_csum(s_sum(0u, p + start, len - start));
        /* A UDP checksum of 0 means none was sent; 0xffff is the same sum. */
        c = c ? c : 0xffffu;
        memcpy(p + start + off, &c, sizeof c);
    }
    duct_dgram_rec_hdr_encode(rec, len);
    *pkts = 1u;
    return duct_dgram_record_hdr_size + len;
}

/** @brief Check a segmented read's IP header against its version and the
 *  checksum start @p l4. */
static bool s_l3_ok(const uint8_t *pkt, size_t l4, bool v6)
{
    if (v6)
        return (pkt[0] >> 4u) == 6u && l4 >= duct_ipv6_hdr_size;
    return (pkt[0] >> 4u) == 4u && (size_t)(pkt[0] & 0xfu) * 4u == l4
        && l4 >= duct_ipv4_hdr_min;
}

/** @brief Rewrite the IP length of packet @p p to @p len bytes, and an IPv4
 *  header checksum over its @p l4 header bytes. */
static void s_l3_fix(uint8_t *p, bool v6, size_t len, size_t l4)
{
    if (v6) {
        duct_store_be16(p + 4u, (uint16_t)(len - duct_ipv6_hdr_size));
        return;
    }
    duct_store_be16(p + 2u, (uint16_t)len);
    p[10] = p[11] = 0u;
    uint16_t c = s_csum(s_sum(0u, p, l4));
    memcpy(p + 10u, &c, sizeof c);
}

/** @brief Build the pseudo-header of packet @p p for @p tlen transport bytes
 *  into @p ph.
 *  Its protocol field is the packet's own, TCP or UDP.
 *  @return Its length. */
static size_t s_pseudo(const uint8_t *p, bool v6, size_t tlen, uint8_t ph[40])
{
    if (v6) {
        memcpy(ph, p + 8u, 32u);
        duct_store_be32(ph + 32u, (uint32_t)tlen);
        ph[36] = ph[37] = ph[38] = 0u;
        ph[39] = p[6];
        return 40u;
    }
    memcpy(ph, p + 12u, 8u);
    ph[8] = 0u;
    ph[9] = p[9];
    duct_store_be16(ph + 10u, (uint16_t)tlen);
    return 12u;
}

/** @brief Transport header offset of a mergeable packet, which carries no IPv4
 *  options and no IPv6 extension headers. */
static size_t s_gro_l4(bool v6)
{
    return v6 ? duct_ipv6_hdr_size : duct_ipv4_hdr_min;
}

/** @brief Move the headers of packet @p pkt and the @p chunk payload bytes at @p off to @p p.
 *  The payload moves first: the headers' new place may overlap its old one.
 *  Nothing moves where @p p is @p pkt. */
static void s_place(uint8_t *p, const uint8_t *pkt, size_t hdr, size_t off, size_t chunk)
{
    if (p != pkt) {
        memmove(p + hdr, pkt + hdr + off, chunk);
        memmove(p, pkt, hdr);
    }
}

/** @brief Swap length term @p from of pseudo-header sum @p sum for @p to.
 *  @p sum is the kernel's seed read as a host word; the result is the unfolded
 *  sum a transport's own bytes are added to. */
static uint64_t s_swap_len(uint16_t sum, size_t to, size_t from)
{
    uint8_t adj[4];
    duct_store_be16(adj, (uint16_t)to);
    duct_store_be16(adj + 2u, (uint16_t)~from);
    return s_sum(sum, adj, sizeof adj);
}

/** @brief Cut a TCP superpacket in place into record-framed packets from
 *  @p rec: GSO records of the @p mss segments @p rec_max holds, a packet per
 *  segment where it holds fewer than two. */
static size_t s_segments(uint8_t *rec, size_t len, bool v6, size_t mss,
                         size_t l4, size_t rec_max, size_t room, unsigned *pkts)
{
    uint8_t *pkt = rec + duct_dgram_record_hdr_size;
    if (l4 + duct_tcp_hdr_min > len || !s_l3_ok(pkt, l4, v6))
        return 0u;
    size_t thl = (size_t)(pkt[l4 + 12u] >> 4u) * 4u,
           hdr = l4 + thl;
    if (thl < duct_tcp_hdr_min || hdr >= len || hdr + mss > 0xffffu)
        return 0u;
    /* Records group only the headers a receiving train and duct_vnet_gso_open
     * parse, IPv4 without options and IPv6 without extension headers; the
     * receiver refuses a record under any other. */
    size_t payload = len - hdr,
           nseg = (payload + mss - 1u) / mss,
           k = l4 == s_gro_l4(v6) && rec_max >= duct_vnet_gso_lead + hdr + 2u * mss
             ? (rec_max - duct_vnet_gso_lead - hdr) / mss : 1u,
           nrec = (nseg + k - 1u) / k,
           lead_k = k > 1u ? duct_vnet_gso_lead : 0u,
           stride = duct_dgram_record_hdr_size + lead_k + hdr + k * mss;
    /* Where the last record ends from rec, a lead further when that record takes none. */
    if (nrec * (duct_dgram_record_hdr_size + hdr + lead_k) + payload > room)
        return 0u;
    /* The TCP checksum field holds the kernel's pseudo-header sum for the whole
     * superpacket. Each segment or record swaps that sum's length for its own,
     * as the kernel's own segmentation does: a routing header puts a
     * destination in the pseudo-header that the IP header does not carry. A
     * record keeps the result, the NEEDS_CSUM form its writer's kernel
     * completes; a segment adds its own bytes. */
    uint32_t seq = duct_load_be32(pkt + l4 + 4u);
    uint16_t id = v6 ? 0u : duct_load_be16(pkt + 4u),
             seed = s_host16(pkt + l4 + 16u);
    uint8_t flags = pkt[l4 + 13u];
    size_t total = 0u;
    /* The packet landed at rec + prefix and is cut over itself, last record
     * first. Record r starts r * stride in and its payload moves forward by
     * r * (prefix + lead_k + hdr) + lead, never back, so it overwrites no
     * segment still to move. The first packet's headers, which every record
     * copies, change only in record 0, the last to run. */
    for (size_t r = nrec; r-- > 0u; ) {
        size_t first = r * k,
               take = duct_min(k, nseg - first),
               chunk = first + take < nseg ? take * mss : payload - first * mss,
               plen = hdr + chunk,
               lead = take > 1u ? duct_vnet_gso_lead : 0u;
        uint8_t *o = rec + r * stride,
                *p = o + duct_dgram_record_hdr_size + lead,
                *th = p + l4;
        s_place(p, pkt, hdr, first * mss, chunk);
        if (r + 1u == nrec)
            total = (size_t)(p + plen - rec);
        if (!v6)
            duct_store_be16(p + 4u, (uint16_t)(id + first));
        s_l3_fix(p, v6, plen, l4);
        duct_store_be32(th + 4u, seq + (uint32_t)(first * mss));
        /* FIN and PSH belong to the superpacket's end, CWR to its start. */
        uint8_t f = flags;
        if (first + take < nseg)
            f &= (uint8_t)~(s_tcp_fin | s_tcp_psh);
        if (first)
            f &= (uint8_t)~s_tcp_cwr;
        th[13] = f;
        th[16] = th[17] = 0u;
        uint64_t sum = s_swap_len(seed, plen - l4, len - l4);
        uint16_t tc = lead ? (uint16_t)~s_csum(sum) : s_csum(s_sum(sum, th, plen - l4));
        memcpy(th + 16u, &tc, sizeof tc);
        duct_dgram_rec_hdr_encode(o, (lead + plen) | (lead ? duct_dgram_rec_gso : 0u));
        if (lead)
            duct_store_be16(o + duct_dgram_record_hdr_size, (uint16_t)mss);
    }
    *pkts = (unsigned)nrec;
    return total;
}

/** @brief Cut a UDP superpacket in place into one record-framed datagram per
 *  @p mss payload bytes from @p rec.
 *  A datagram is a plain record with its UDP length set and its checksum
 *  computed in full. */
static size_t s_datagrams(uint8_t *rec, size_t len, size_t mss, size_t l4,
                          size_t rec_max, bool uso, size_t room, unsigned *pkts)
{
    uint8_t *pkt = rec + duct_dgram_record_hdr_size;
    bool v6 = (pkt[0] >> 4u) == 6u;
    size_t hdr = l4 + duct_udp_hdr_size;
    if (hdr >= len || hdr + mss > 0xffffu || !s_l3_ok(pkt, l4, v6))
        return 0u;
    size_t payload = len - hdr,
           ndg = (payload + mss - 1u) / mss,
           k = uso && l4 == s_gro_l4(v6) && rec_max >= duct_vnet_gso_lead + hdr + 2u * mss
             ? duct_min(duct_min((rec_max - duct_vnet_gso_lead - hdr) / mss,
                                 (0xffffu - hdr) / mss),
                        (size_t)duct_vnet_udp_segs_max)
             : 1u,
           nrec = (ndg + k - 1u) / k,
           lead_k = k > 1u ? duct_vnet_gso_lead : 0u,
           stride = duct_dgram_record_hdr_size + lead_k + hdr + k * mss;
    if (nrec * (duct_dgram_record_hdr_size + hdr + lead_k) + payload > room)
        return 0u;
    uint16_t id = v6 ? 0u : duct_load_be16(pkt + 4u),
             seed = s_host16(pkt + l4 + 6u);
    size_t total = 0u;
    for (size_t r = nrec; r-- > 0u; ) {
        size_t first = r * k,
               take = duct_min(k, ndg - first),
               chunk = first + take < ndg ? take * mss : payload - first * mss,
               plen = hdr + chunk,
               lead = take > 1u ? duct_vnet_gso_lead : 0u;
        uint8_t *o = rec + r * stride,
                *p = o + duct_dgram_record_hdr_size + lead,
                *u = p + l4;
        s_place(p, pkt, hdr, first * mss, chunk);
        if (r + 1u == nrec)
            total = (size_t)(p + plen - rec);
        if (!v6)
            duct_store_be16(p + 4u, (uint16_t)(id + first));
        s_l3_fix(p, v6, plen, l4);
        duct_store_be16(u + 4u, (uint16_t)(plen - l4));
        u[6] = u[7] = 0u;
        uint64_t sum = s_swap_len(seed, plen - l4, len - l4);
        uint16_t uc;
        if (lead) {
            uc = (uint16_t)~s_csum(sum);
        } else {
            uc = s_csum(s_sum(sum, u, plen - l4));
            uc = uc ? uc : 0xffffu;
        }
        memcpy(u + 6u, &uc, sizeof uc);
        duct_dgram_rec_hdr_encode(o, (lead + plen) | (lead ? duct_dgram_rec_gso : 0u));
        if (lead)
            duct_store_be16(o + duct_dgram_record_hdr_size, (uint16_t)mss);
    }
    *pkts = (unsigned)nrec;
    return total;
}

/** @brief Header length of the @p proto packet @p p of @p len bytes, IP and
 *  transport together.
 *  The packet carries a payload, no IPv4 options, no IPv6 extension headers, an
 *  IP length equal to @p len and, for UDP, a UDP length equal to its transport
 *  bytes; 0 for any other packet. */
static size_t s_l4_hdr(const uint8_t *p, size_t len, uint8_t proto)
{
    size_t ip_hdr = duct_ip_hdr_len(p, len);
    bool v6 = ip_hdr && (p[0] >> 4u) == 6u;
    size_t l4 = s_gro_l4(v6);
    if (len > 0xffffu || ip_hdr != l4 || p[v6 ? 6 : 9] != proto || duct_ip_len(p) != len)
        return 0u;
    if (proto == s_proto_udp)
        return l4 + duct_udp_hdr_size < len && duct_load_be16(p + l4 + 4u) == len - l4
             ? l4 + duct_udp_hdr_size : 0u;
    if (l4 + duct_tcp_hdr_min > len)
        return 0u;
    size_t thl = (size_t)(p[l4 + 12u] >> 4u) * 4u;
    return thl >= duct_tcp_hdr_min && l4 + thl < len ? l4 + thl : 0u;
}

/** @brief Whether the headers of @p hdr bytes, @p l4 of them IP, end in a UDP header.
 *  A TCP header is 20 bytes at least, so a transport header of 8 bytes is UDP's. */
static bool s_is_udp(size_t hdr, size_t l4)
{
    return hdr == l4 + duct_udp_hdr_size;
}

/** @brief Find the header length of @p p where it can join a train, 0 where it
 *  cannot.
 *  A TCP segment carries ACK and at most PSH; a UDP datagram qualifies under
 *  @c vnet_merge_tcp_udp alone, and never as a record. An IPv4 packet carries DF,
 *  no fragment and a header checksum that verifies.
 *  A record, @p mss nonzero, holds two segments at least and only the
 *  pseudo-header sum in its TCP checksum field. */
static size_t s_gro_parse(const uint8_t *p, size_t len, size_t mss, duct_vnet_merge_t merge)
{
    size_t hdr = s_l4_hdr(p, len, s_proto_tcp);
    if (!hdr && merge == vnet_merge_tcp_udp)
        hdr = s_l4_hdr(p, len, s_proto_udp);
    if (!hdr)
        return 0u;
    bool v6 = (p[0] >> 4u) == 6u;
    size_t l4 = s_gro_l4(v6);
    if (!s_is_udp(hdr, l4)) {
        uint8_t f = p[l4 + 13u];
        if (!(f & s_tcp_ack) || (f & (uint8_t)~(s_tcp_ack | s_tcp_psh)))
            return 0u;
    }
    if (!v6 && ((duct_load_be16(p + 6u) & 0x7fffu) != 0x4000u
                || s_csum(s_sum(0u, p, duct_ipv4_hdr_min))))
        return 0u;
    if (mss)
        return len - hdr > mss ? hdr : 0u;
    return hdr;
}

/** @brief Test the TCP or UDP checksum of plain packet @p p of @p len bytes.
 *  A segmented write leaves with fresh checksums, so a corrupted segment merged into a train reaches its
 *  receiver undetectable. */
static bool s_gro_sum_ok(const uint8_t *p, size_t len, bool v6)
{
    size_t l4 = s_gro_l4(v6);
    uint8_t ph[40];
    size_t phl = s_pseudo(p, v6, len - l4, ph);
    return !s_csum(s_sum(s_sum(0u, ph, phl), p + l4, len - l4));
}

/** @brief Check that candidate @p p continues the train in @p g.
 *  A UDP datagram continues it by the addresses, ports, TOS, TTL and next IPv4 id
 *  alone; a TCP segment also by its sequence, acknowledgement, window and options. */
static bool s_gro_fits(const duct_vnet_gro_t *g, const uint8_t *p, size_t hdr, bool v6,
                       size_t pay, size_t mss)
{
    if (v6 != g->v6 || hdr != g->hdr || (mss ? mss != g->mss : pay > g->mss)
        || g->len + pay > 0xffffu)
        return false;
    size_t l4 = s_gro_l4(v6);
    const uint8_t *q = g->head,
                  *th = p + l4,
                  *qh = q + l4;
    bool l3 = v6 ? !memcmp(p, q, 4u) && p[7] == q[7] && !memcmp(p + 8u, q + 8u, 32u)
                 : p[1] == q[1] && p[8] == q[8] && !memcmp(p + 12u, q + 12u, 8u)
                       && duct_load_be16(p + 4u) == (uint16_t)(duct_load_be16(q + 4u) + g->segs);
    if (!l3 || memcmp(th, qh, 4u))
        return false;
    if (s_is_udp(hdr, l4)) {
        size_t seg = mss ? mss : pay;
        return g->segs + (pay + seg - 1u) / seg <= duct_vnet_udp_segs_max;
    }
    return !memcmp(th + 8u, qh + 8u, 4u)
        && !memcmp(th + 14u, qh + 14u, 2u)
        && !memcmp(th + duct_tcp_hdr_min, qh + duct_tcp_hdr_min, hdr - l4 - duct_tcp_hdr_min)
        && duct_load_be32(th + 4u) == duct_load_be32(qh + 4u) + (uint32_t)(g->len - hdr);
}

duct_vnet_gro_rc_t duct_vnet_gro_offer(duct_vnet_gro_t *g, const uint8_t *pkt, size_t len,
                                       size_t mss, duct_vnet_merge_t merge)
{
    size_t hdr = s_gro_parse(pkt, len, mss, merge);
    if (!hdr)
        return vnet_gro_alone;
    bool v6 = (pkt[0] >> 4u) == 6u;
    size_t l4 = s_gro_l4(v6),
           pay = len - hdr,
           seg = mss ? mss : pay;
    bool udp = s_is_udp(hdr, l4),
         psh = !udp && (pkt[l4 + 13u] & s_tcp_psh);
    if (g->segs && !s_gro_fits(g, pkt, hdr, v6, pay, mss))
        return vnet_gro_flush_first;
    /* After the fit test: a packet that flushes the train is offered again, and verified then. */
    if (!mss && !s_gro_sum_ok(pkt, len, v6))
        return vnet_gro_alone;
    if (!g->segs) {
        memcpy(g->head, pkt, hdr);
        g->len = len;
        g->hdr = hdr;
        g->mss = seg;
        g->v6 = v6;
        g->nspans = 0u;
    } else {
        g->len += pay;
        if (psh)
            g->head[l4 + 13u] |= s_tcp_psh;
    }
    g->bufs[duct_vnet_gro_front + g->nspans] = (duct_view_u8){ .data = (void *)(pkt + hdr), .size = pay };
    ++g->nspans;
    g->segs += (unsigned)((pay + seg - 1u) / seg);
    return psh || pay % g->mss || g->len + g->mss > 0xffffu
           || (udp ? g->segs == duct_vnet_udp_segs_max : g->nspans == duct_vnet_gro_span_max)
         ? vnet_gro_taken_last : vnet_gro_taken;
}

/** @brief Write to @p vnet the header a segmented write of packet @p p takes.
 *  A TCP packet takes TCPv4 or TCPv6 from its IP version, with ECN where it
 *  carries CWR; a UDP packet takes UDP segmentation, with its checksum field at
 *  offset 6 and no ECN bit. */
static void s_gso_hdr(const uint8_t *p, size_t hdr, size_t mss,
                      uint8_t vnet[duct_vnet_hdr_max])
{
    bool v6 = (p[0] >> 4u) == 6u;
    size_t l4 = s_gro_l4(v6);
    bool udp = s_is_udp(hdr, l4);
    uint16_t h16 = (uint16_t)hdr,
             m16 = (uint16_t)mss,
             start = (uint16_t)l4,
             off = udp ? 6u : 16u;
    memset(vnet, 0, duct_vnet_hdr_max);
    vnet[0] = s_f_needs_csum;
    vnet[1] = udp ? s_gso_udp_l4
                  : (uint8_t)((v6 ? s_gso_tcpv6 : s_gso_tcpv4)
                              | (p[l4 + 13u] & s_tcp_cwr ? s_gso_ecn : 0u));
    memcpy(vnet + 2u, &h16, sizeof h16);
    memcpy(vnet + 4u, &m16, sizeof m16);
    memcpy(vnet + 6u, &start, sizeof start);
    memcpy(vnet + 8u, &off, sizeof off);
}

void duct_vnet_gro_finish(duct_vnet_gro_t *g, uint8_t vnet[duct_vnet_hdr_max])
{
    if (g->segs > 1u) {
        size_t l4 = s_gro_l4(g->v6);
        uint8_t *p = g->head;
        s_l3_fix(p, g->v6, g->len, l4);
        if (s_is_udp(g->hdr, l4))
            duct_store_be16(p + l4 + 4u, (uint16_t)(g->len - l4));
        /* NEEDS_CSUM: the field holds the pseudo-header sum uncomplemented,
         * and the kernel completes it for every segment it cuts. The header
         * just written names the field: offset 16 in TCP, 6 in UDP. */
        uint8_t ph[40];
        size_t phl = s_pseudo(p, g->v6, g->len - l4, ph);
        uint16_t partial = (uint16_t)~s_csum(s_sum(0u, ph, phl));
        s_gso_hdr(p, g->hdr, g->mss, vnet);
        memcpy(p + l4 + s_host16(vnet + 8u), &partial, sizeof partial);
    } else
        memset(vnet, 0, duct_vnet_hdr_max);
    g->bufs[1] = (duct_view_u8){ .data = g->head, .size = g->hdr };
    g->segs = 0u;
}

size_t duct_vnet_gso_open(duct_view_u8 *rec, uint8_t vnet[duct_vnet_hdr_max])
{
    if (rec->size <= duct_vnet_gso_lead)
        return 0u;
    auto lead = (const uint8_t *)rec->data;
    const uint8_t *pkt = lead + duct_vnet_gso_lead;
    size_t mss = duct_load_be16(lead),
           len = rec->size - duct_vnet_gso_lead,
           hdr = s_l4_hdr(pkt, len, s_proto_tcp);
    if (!hdr)
        hdr = s_l4_hdr(pkt, len, s_proto_udp);
    if (!hdr || !mss || len - hdr <= mss)
        return 0u;
    s_gso_hdr(pkt, hdr, mss, vnet);
    *rec = (duct_view_u8){ .data = (void *)pkt, .size = len };
    return mss;
}

bool duct_vnet_gso_is_udp(const uint8_t vnet[duct_vnet_hdr_max])
{
    return (vnet[1] & (uint8_t)~s_gso_ecn) == s_gso_udp_l4;
}

size_t duct_gso_trim(duct_view_u8 rec)
{
    if (rec.size <= duct_vnet_gso_lead)
        return 0u;
    auto lead = (uint8_t *)rec.data;
    uint8_t *pkt = lead + duct_vnet_gso_lead;
    size_t mss = duct_load_be16(lead),
           len = rec.size - duct_vnet_gso_lead,
           hdr = s_l4_hdr(pkt, len, s_proto_tcp);
    if (!hdr || !mss)
        return 0u;
    bool v6 = (pkt[0] >> 4u) == 6u;
    size_t l4 = s_gro_l4(v6),
           payload = len - hdr,
           nseg = (payload + mss - 1u) / mss;
    /* FIN ends the sequence at the last segment, the one a trim takes. */
    if (nseg < 3u || (pkt[l4 + 13u] & (s_tcp_fin | s_tcp_syn | s_tcp_rst)))
        return 0u;
    size_t keep = hdr + (nseg - 1u) * mss;
    uint8_t *th = pkt + l4;
    /* The checksum field stays the pseudo-header sum, its length term swapped
     * for the kept length. */
    uint16_t tc = (uint16_t)~s_csum(s_swap_len(s_host16(th + 16u), keep - l4, len - l4));
    s_l3_fix(pkt, v6, keep, l4);
    memcpy(th + 16u, &tc, sizeof tc);
    return duct_vnet_gso_lead + keep;
}

duct_frame_ip_t duct_frame_ip(duct_view_u8 payload, duct_frame_flags_t flags)
{
    bool gso = duct_has(flags, fl_frame_gso);
    size_t lead = gso ? duct_vnet_gso_lead : 0u;
    duct_frame_ip_t v = { .total = payload.size, .gso = gso,
                          .seg = gso && payload.size >= lead ? duct_load_be16(payload.data) : 0u };
    if (payload.size <= lead)
        return v;
    auto p = (const uint8_t *)payload.data + lead;
    size_t n = payload.size - lead,
           hdr = duct_ip_hdr_len(p, n);
    if (hdr) {
        v.packet = p;
        v.size = n;
        v.hdr = hdr;
    }
    return v;
}

/** @brief ECN codepoint of the IPv4 or IPv6 header at @p ip. */
static duct_ecn_t s_ip_ecn(const uint8_t *ip)
{
    return (duct_ecn_t)((ip[0] >> 4u) == 4u ? ip[1] & 3u : (ip[1] >> 4u) & 3u);
}

duct_ecn_t duct_frame_ecn(const duct_frame_t *frame)
{
    auto v = duct_frame_ip(frame->payload, frame->flags);
    return v.packet ? s_ip_ecn(v.packet) : ecn_none;}

size_t duct_frame_mark_ce(const duct_frame_t *frame)
{
    auto v = duct_frame_ip(frame->payload, frame->flags);
    if (!v.packet)
        return 0u;
    auto ecn = s_ip_ecn(v.packet);
    if (ecn != ecn_ect1 && ecn != ecn_ect0)
        return 0u;
    auto ip = (uint8_t *)v.packet;
    if ((ip[0] >> 4u) == 6u) {
        ip[1] |= 0x30u;
        return frame->payload.size;
    }
    ip[1] |= 3u;
    ip[10] = ip[11] = 0u;
    uint16_t c = s_csum(s_sum(0u, ip, v.hdr));
    memcpy(ip + 10u, &c, sizeof c);
    return frame->payload.size;
}

bool duct_frame_to_group(const duct_frame_ip_t *ip)
{
    auto p = ip->packet;
    return p && ((p[0] >> 4u) == 4u ? p[16] >= s_ip4_group : p[24] == s_ip6_group);
}

/** @brief Test whether a TCP or UDP header names destination @p port.
 *  The header starts @p hdr bytes into the packet @p p, of which @p n bytes are at hand. False for
 *  another @p proto and for a packet that ends inside the ports.
 */
static bool s_to_port(const uint8_t *p, size_t n, size_t hdr, uint8_t proto, uint16_t port)
{
    return (proto == s_proto_tcp || proto == s_proto_udp) && n >= hdr + 4u
        && duct_load_be16(p + hdr + 2u) == port;
}

bool duct_frame_to_peer(const duct_frame_ip_t *ip, const duct_peer_t *peer)
{
    auto p = ip->packet;
    if (!p)
        return false;
    auto want = duct_peer_ip_flags(peer);
    if ((p[0] >> 4u) == 4u) {
        auto host = peer->family == AF_INET ? peer->addr.v4 : peer->addr.v6 + 12u;
        return want == fl_ip_v4 && !(p[6] & 0x1fu) && !p[7]
            && memcmp(p + 16u, host, sizeof peer->addr.v4) == 0
            && s_to_port(p, ip->size, ip->hdr, p[9], peer->port);
    }
    return want == fl_ip_v6 && memcmp(p + 24u, peer->addr.v6, sizeof peer->addr.v6) == 0
        && s_to_port(p, ip->size, ip->hdr, p[6], peer->port);
}

duct_frame_volume_t duct_frame_volume(const duct_frame_ip_t *ip)
{
    size_t lead = ip->gso ? duct_vnet_gso_lead : 0u;
    duct_frame_volume_t volume = { .bytes = ip->total > lead ? ip->total - lead : 0u, .packets = 1u };
    if (!ip->gso || !ip->seg || !ip->packet || ip->hdr >= ip->size)
        return volume;
    uint8_t proto = (ip->packet[0] >> 4u) == 4u ? ip->packet[9] : ip->packet[6];
    size_t hdr;
    if (proto == s_proto_udp) {
        hdr = ip->hdr + duct_udp_hdr_size;
    } else {
        if (ip->size < ip->hdr + duct_tcp_hdr_min)
            return volume;
        hdr = ip->hdr + (size_t)(ip->packet[ip->hdr + 12u] >> 4u) * 4u;
        if (hdr < ip->hdr + duct_tcp_hdr_min)
            return volume;
    }
    if (hdr >= ip->size)
        return volume;
    volume.packets = (unsigned)((ip->size - hdr + ip->seg - 1u) / ip->seg);
    return volume;
}

/** @brief Test whether the TCP segment behind the @p hdr IP header bytes of @p p is an ACK that carries no data.
 *  FIN, SYN and RST are clear, and the IP length, which must fit the @p n bytes at hand, ends where
 *  the TCP header does.
 */
static bool s_pure_ack(const uint8_t *p, size_t n, size_t hdr)
{
    size_t len = duct_ip_len(p);
    if (len > n || hdr + duct_tcp_hdr_min > len)
        return false;
    auto tcp = p + hdr;
    size_t doff = (size_t)(tcp[12] >> 4u) * 4u;
    return doff >= duct_tcp_hdr_min && !(tcp[13] & (s_tcp_fin | s_tcp_syn | s_tcp_rst))
        && (tcp[13] & s_tcp_ack) && len == hdr + doff;
}

uint64_t duct_frame_flow_key(const duct_frame_ip_t *ip)
{
    auto p = ip->packet;
    if (!p)
        return 0u;
    size_t n = ip->size,
           hdr = ip->hdr;
    bool v4 = (p[0] >> 4u) == 4u;
    uint8_t proto = v4 ? p[9] : p[6];
    bool first = !v4 || (!(p[6] & 0x1fu) && !p[7]),
         whole = first && (!v4 || !(p[6] & 0x20u));
    if (proto == s_proto_icmp4 || proto == s_proto_icmp6
        || (proto == s_proto_tcp && whole && s_pure_ack(p, n, hdr)))
        return 0u;
    uint64_t key = duct_splitmix64(proto);
    const uint8_t *addrs = p + (v4 ? 12u : 8u);
    for (size_t at = 0u; at < (v4 ? 8u : 32u); at += 8u) {
        uint64_t word;
        memcpy(&word, addrs + at, sizeof word);
        key = duct_splitmix64(key ^ word);
    }
    if (first && (proto == s_proto_tcp || proto == s_proto_udp) && hdr + 4u <= n) {
        uint32_t ports;
        memcpy(&ports, p + hdr, sizeof ports);
        key = duct_splitmix64(key ^ ports);
    }
    return key | 1u;
}

size_t duct_vnet_cut(const uint8_t *vh, uint8_t *rec, size_t len, size_t rec_max,
                     bool uso, size_t room, unsigned *pkts)
{
    *pkts = 0u;
    if (!len)
        return 0u;
    uint8_t flags = vh[0],
            type = vh[1] & (uint8_t)~s_gso_ecn;
    size_t mss = s_host16(vh + 4u),
           start = s_host16(vh + 6u),
           off = s_host16(vh + 8u);
    if (type == s_gso_none)
        return s_whole(rec, len, flags, start, off, pkts);
    if (type == s_gso_udp_l4 && mss)
        return s_datagrams(rec, len, mss, start, rec_max, uso, room, pkts);
    if ((type != s_gso_tcpv4 && type != s_gso_tcpv6) || !mss)
        return 0u;
    return s_segments(rec, len, type == s_gso_tcpv6, mss, start, rec_max, room, pkts);
}
