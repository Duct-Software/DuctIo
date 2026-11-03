/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file vnet_train_test.c
 * @brief White-box test of the worker's vnet train over the cleartext region ring.
 *
 * Includes duct_worker.c directly, as tx_pool_test.c does, to reach
 * s_vnet_train_take, s_vnet_train_flush and the ring's regions. A seqpacket
 * socketpair stands in for the tun: one gathered write is one record on the
 * peer, so what arrives is the packet the kernel would segment.
 *
 * Three ways a payload gets into a train are driven: by reference, where it lies
 * in the region of the packet in dispatch; copied into a region of its own,
 * where it lies anywhere else; and flushed at once, where the ring has no room
 * for the copy. Each ends with every reference returned and the ring drained.
 * A last train fills to its span bound out of copies. UDP datagrams join a train
 * only on a leg whose conn carries @c fl_conn_vnet_uso, and a train of them
 * closes at @c duct_vnet_udp_segs_max.
 */

#include "../src/duct_worker.c"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int s_failures;

#define CHECK(cond) do { \
        if (!(cond)) { \
            fprintf(stderr, "vnet_train_test: FAILED %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++s_failures; \
        } \
    } while (0)

static constexpr size_t vt_ip = 20u;
static constexpr size_t vt_hdr = 40u;
static constexpr size_t vt_udp = 28u;
static constexpr size_t vt_seg = 1448u;
static constexpr size_t vt_vnet = 10u;

static duct_worker_t s_w;
static duct_conn_t *s_conn;
static int s_peer;

static uint32_t vt_add(uint32_t acc, const uint8_t *p, size_t n)
{
    for (size_t i = 0u; i + 1u < n; i += 2u)
        acc += (uint32_t)(p[i] << 8u | p[i + 1u]);
    if (n & 1u)
        acc += (uint32_t)p[n - 1u] << 8u;
    return acc;
}

static uint16_t vt_fold(uint32_t acc)
{
    while (acc >> 16u)
        acc = (acc & 0xffffu) + (acc >> 16u);
    return (uint16_t)~acc;
}

/** @brief Write the IPv4 header of the @p n-th packet of one flow at @p p: DF, no options, @p len
 *  bytes of @p proto, the id stepping with @p n, the header checksum valid. */
static void vt_ip4(uint8_t *p, unsigned n, size_t len, uint8_t proto)
{
    memset(p, 0, vt_ip);
    p[0] = 0x45u;
    duct_store_be16(p + 2u, (uint16_t)len);
    duct_store_be16(p + 4u, (uint16_t)(100u + n));
    p[6] = 0x40u;
    p[8] = 64u;
    p[9] = proto;
    static const uint8_t addrs[8] = { 10u, 0u, 0u, 1u, 10u, 0u, 0u, 2u };
    memcpy(p + 12u, addrs, sizeof addrs);
    duct_store_be16(p + 10u, vt_fold(vt_add(0u, p, vt_ip)));
}

/** @brief Checksum of the @p tlen transport bytes behind the IPv4 header at @p p, its zeroed
 *  checksum field included, over the pseudo-header that header makes. */
static uint16_t vt_l4_sum(const uint8_t *p, size_t tlen)
{
    uint8_t ph[12] = {};
    memcpy(ph, p + 12u, 8u);
    ph[9] = p[9];
    duct_store_be16(ph + 10u, (uint16_t)tlen);
    return vt_fold(vt_add(vt_add(0u, ph, sizeof ph), p + vt_ip, tlen));
}

/** @brief Write the @p n-th segment of one flow at @p p: IPv4 with DF, TCP with
 *  ACK, no options on either, both checksums valid, @p pay payload bytes. */
static void vt_packet(uint8_t *p, unsigned n, size_t pay)
{
    size_t len = vt_hdr + pay;
    vt_ip4(p, n, len, 6u);
    uint8_t *th = p + vt_ip;
    memset(th, 0, vt_hdr - vt_ip);
    duct_store_be16(th, 443u);
    duct_store_be16(th + 2u, 50000u);
    duct_store_be32(th + 4u, 1000u + n * (uint32_t)pay);
    duct_store_be32(th + 8u, 7u);
    th[12] = 5u << 4u;
    th[13] = 0x10u;
    duct_store_be16(th + 14u, 512u);
    for (size_t i = 0u; i < pay; ++i)
        p[vt_hdr + i] = (uint8_t)(n * 31u + i);
    duct_store_be16(th + 16u, vt_l4_sum(p, len - vt_ip));
}

/** @brief Write the @p n-th datagram of one flow at @p p: IPv4 with DF, UDP, the
 *  id stepping with @p n, both checksums valid, @p pay payload bytes. */
static void vt_datagram(uint8_t *p, unsigned n, size_t pay)
{
    size_t len = vt_udp + pay;
    vt_ip4(p, n, len, 17u);
    uint8_t *uh = p + vt_ip;
    memset(uh, 0, vt_udp - vt_ip);
    duct_store_be16(uh, 5353u);
    duct_store_be16(uh + 2u, 40000u);
    duct_store_be16(uh + 4u, (uint16_t)(len - vt_ip));
    for (size_t i = 0u; i < pay; ++i)
        p[vt_udp + i] = (uint8_t)(n * 31u + i);
    uint16_t c = vt_l4_sum(p, len - vt_ip);
    duct_store_be16(uh + 6u, c ? c : 0xffffu);
}

/** @brief Check the @p count payloads of @p pay bytes in the write @p got of @p n bytes, behind
 *  @p hdr bytes of headers, against the packets @c vt_packet or @c vt_datagram make. */
static bool vt_payloads(const uint8_t *got, ssize_t n, size_t hdr, unsigned count, size_t pay)
{
    if (n != (ssize_t)(vt_vnet + hdr + count * pay))
        return false;
    for (unsigned k = 0u; k < count; ++k)
        for (size_t i = 0u; i < pay; ++i)
            if (got[vt_vnet + hdr + k * pay + i] != (uint8_t)(k * 31u + i))
                return false;
    return true;
}

static void vt_setup(void)
{
    s_this_worker = &s_w;
    s_w.vnet_train = duct_new(vnet_train_t);
    assert(s_w.vnet_train);
    s_conn = duct_conn_acquire();
    assert(s_conn);
    int sv[2];
    int rc = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv);
    assert(rc == 0);
    s_conn->fd = sv[0];
    s_peer = sv[1];
    s_conn->xport_type = x_raw_packet;
    s_conn->vnet_hdr_len = vt_vnet;
}

/** @brief Every region back, the ring empty. */
static bool vt_drained(void)
{
    s_tx_pool_reclaim(&s_w.ct_pool);
    return s_w.ct_pool.head == s_w.ct_pool.tail;
}

/** @brief Two segments lying in the region of the packet in dispatch are
 *  taken by reference: the spans point into the region, which holds one
 *  reference each until the flush. */
static void vt_by_reference(void)
{
    size_t room = 2u * (vt_hdr + vt_seg);
    auto home = (uint8_t *)s_pool_acquire(&s_w.ct_pool, room);
    CHECK(home);
    redirect_t r = { .ct = home, .cap = room };
    vt_packet(home, 0u, vt_seg);
    vt_packet(home + vt_hdr + vt_seg, 1u, vt_seg);
    CHECK(s_vnet_train_take(s_conn, (duct_view_u8){ home, vt_hdr + vt_seg }, 0u, &r));
    CHECK(s_vnet_train_take(s_conn, (duct_view_u8){ home + vt_hdr + vt_seg, vt_hdr + vt_seg }, 0u, &r));
    auto region = s_tx_pool_hdr_of(home);
    CHECK(region->refs == 2u);
    CHECK(s_w.vnet_train->gro.nspans == 2u);
    CHECK(s_w.vnet_train->gro.bufs[duct_vnet_gro_front].data == home + vt_hdr);
    s_tx_pool_drop_hold(home);
    CHECK(!vt_drained());
    s_vnet_train_flush(&s_w);
    CHECK(region->refs == 0u);
    uint8_t got[vt_vnet + vt_hdr + 2u * vt_seg + 16u];
    ssize_t n = recv(s_peer, got, sizeof got, MSG_DONTWAIT);
    CHECK(vt_payloads(got, n, vt_hdr, 2u, vt_seg));
    CHECK(got[0] == 1u && got[1] == 1u);
    CHECK(duct_load_be16(got + vt_vnet + 2u) == vt_hdr + 2u * vt_seg);
    CHECK(vt_drained());
}

/** @brief Segments lying anywhere else are copied into regions before the call
 *  returns, so the memory they came from may go. */
static void vt_copied_in(void)
{
    static uint8_t outside[2][vt_hdr + vt_seg];
    for (unsigned k = 0u; k < 2u; ++k) {
        vt_packet(outside[k], k, vt_seg);
        CHECK(s_vnet_train_take(s_conn, (duct_view_u8){ outside[k], sizeof outside[k] }, 0u, nullptr));
    }
    for (unsigned k = 0u; k < 2u; ++k) {
        auto at = (const uint8_t *)s_w.vnet_train->gro.bufs[duct_vnet_gro_front + k].data;
        CHECK(at >= s_w.ct_pool.arena && at < s_w.ct_pool.arena + duct_worker_tx_pool_cap);
        CHECK(s_w.vnet_train->regions[k]->refs == 1u && !s_w.vnet_train->regions[k]->hold);
    }
    memset(outside, 0, sizeof outside);
    s_vnet_train_flush(&s_w);
    uint8_t got[vt_vnet + vt_hdr + 2u * vt_seg + 16u];
    ssize_t n = recv(s_peer, got, sizeof got, MSG_DONTWAIT);
    CHECK(vt_payloads(got, n, vt_hdr, 2u, vt_seg));
    CHECK(vt_drained());
}

/** @brief A copy the ring has no room for flushes the train at once, the
 *  segment going out in it from where it lies. */
static void vt_ring_full(void)
{
    auto big = s_pool_acquire(&s_w.ct_pool, duct_worker_tx_pool_cap - 256u);
    CHECK(big);
    static uint8_t outside[vt_hdr + vt_seg];
    vt_packet(outside, 0u, vt_seg);
    CHECK(s_vnet_train_take(s_conn, (duct_view_u8){ outside, sizeof outside }, 0u, nullptr));
    CHECK(s_w.vnet_train->gro.segs == 0u);
    uint8_t got[vt_vnet + vt_hdr + vt_seg + 16u];
    ssize_t n = recv(s_peer, got, sizeof got, MSG_DONTWAIT);
    CHECK(n == (ssize_t)(vt_vnet + sizeof outside));
    CHECK(!memcmp(got + vt_vnet, outside, sizeof outside));
    s_tx_pool_drop_hold(big);
    CHECK(vt_drained());
}

/** @brief A train of @p count copies, built by @p build behind @p hdr bytes of headers, closes at
 *  its bound and goes out whole as a write of GSO type @p type. */
static void vt_bound(unsigned count, size_t hdr, uint8_t type,
                     void (*build)(uint8_t *, unsigned, size_t))
{
    static constexpr size_t pay = 64u;
    uint8_t p[vt_hdr + pay];
    for (unsigned k = 0u; k < count; ++k) {
        build(p, k, pay);
        CHECK(s_vnet_train_take(s_conn, (duct_view_u8){ p, hdr + pay }, 0u, nullptr));
    }
    CHECK(s_w.vnet_train->gro.segs == 0u);
    static uint8_t got[vt_vnet + vt_hdr + duct_vnet_gro_span_max * pay + 16u];
    ssize_t n = recv(s_peer, got, sizeof got, MSG_DONTWAIT);
    CHECK(vt_payloads(got, n, hdr, count, pay));
    CHECK(got[0] == 1u && got[1] == type);
    CHECK(vt_drained());
}

/** @brief Datagrams leave as type 5 writes on a leg that took the USO flags, three as one write and
 *  a full train closing at its bound, and each leaves alone on a leg that did not. */
static void vt_datagrams(void)
{
    static constexpr size_t pay = 600u;
    static uint8_t d[3][vt_udp + pay];
    for (unsigned k = 0u; k < 3u; ++k)
        vt_datagram(d[k], k, pay);
    duct_conn_state_set(s_conn, fl_conn_vnet_uso);
    for (unsigned k = 0u; k < 3u; ++k)
        CHECK(s_vnet_train_take(s_conn, (duct_view_u8){ d[k], sizeof d[k] }, 0u, nullptr));
    CHECK(s_w.vnet_train->gro.segs == 3u);
    s_vnet_train_flush(&s_w);
    uint8_t got[vt_vnet + vt_udp + 3u * pay + 16u];
    ssize_t n = recv(s_peer, got, sizeof got, MSG_DONTWAIT);
    CHECK(vt_payloads(got, n, vt_udp, 3u, pay));
    CHECK(got[0] == 1u && got[1] == 5u);
    uint16_t h16[4];
    memcpy(h16, got + 2u, sizeof h16);
    CHECK(h16[0] == vt_udp && h16[1] == pay && h16[2] == vt_ip && h16[3] == 6u);
    CHECK(duct_load_be16(got + vt_vnet + 2u) == vt_udp + 3u * pay);
    CHECK(duct_load_be16(got + vt_vnet + vt_ip + 4u) == 8u + 3u * pay);
    CHECK(vt_drained());

    vt_bound(duct_vnet_udp_segs_max, vt_udp, 5u, vt_datagram);

    duct_conn_state_clear(s_conn, fl_conn_vnet_uso);
    CHECK(!s_vnet_train_take(s_conn, (duct_view_u8){ d[0], sizeof d[0] }, 0u, nullptr));
    CHECK(s_w.vnet_train->gro.segs == 0u);
    CHECK(vt_drained());
}

int main(void)
{
    vt_setup();
    vt_by_reference();
    vt_copied_in();
    vt_ring_full();
    vt_bound(duct_vnet_gro_span_max, vt_hdr, 1u, vt_packet);
    vt_datagrams();
    s_this_worker = nullptr;
    if (s_failures) {
        fprintf(stderr, "vnet_train_test: %d failure(s)\n", s_failures);
        return 1;
    }
    printf("vnet_train_test: OK\n");
    return 0;
}
