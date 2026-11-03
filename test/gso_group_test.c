/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file gso_group_test.c
 * @brief Unit test for where a coalescable datagram group ends.
 *
 * Both halves of the answer — the scan that stops at the first entry a single
 * segmented write cannot carry, and the two bounds that cut such a write —
 * driven directly, no socket.
 */

#include "duct_xport.h"

#include "duct_core.h"
#include "duct_wire.h"

#include <stdio.h>
#include <string.h>

#define CHECK(expr, msg) \
    do { if (!(expr)) { fprintf(stderr, "FAIL: %s\n", msg); return 1; } } while (0)

static constexpr uint32_t group_test_max = 256u;
static constexpr size_t mtu_seg = 1416u;
static constexpr size_t tiny_seg = 64u;

/** @brief Bytes for the descriptors to point at. @ref duct_x_gso_group reads
 *  sizes and addresses alone, so one segment's worth covers every entry. */
static uint8_t group_test_bytes[mtu_seg];

/** @brief Fill @p n entries as one peer's uniform @p seg-sized group, the shape
 *  a coalescing write takes whole. */
static void s_fill(duct_dgram_out_t *m, uint32_t n, size_t seg)
{
    for (uint32_t i = 0u; i < n; ++i) {
        m[i] = (duct_dgram_out_t){
            .peer = { .family = AF_INET, .port = 51999u },
            .body = { .data = group_test_bytes, .size = seg },
        };
        m[i].peer.addr.v4[3] = 1u;
    }
}

int main(void)
{
    static duct_dgram_out_t m[group_test_max];

    {
        s_fill(m, 8u, mtu_seg);
        m[3].peer.addr.v4[3] = 2u;
        CHECK(duct_x_gso_group(m,8u) == 3u, "a group ends at the first entry addressed elsewhere");
    }

    /* Two clients behind one NAT share an address and differ only by port, so
     * the port is part of what ends a group: merged, one client's bytes leave in
     * a write addressed to the other. */
    {
        s_fill(m, 8u, mtu_seg);
        m[5].peer.port = (uint16_t)(m[0].peer.port + 1u);
        CHECK(duct_x_gso_group(m,8u) == 5u, "a group ends at the first entry on another port");
    }

    {
        s_fill(m, 8u, mtu_seg);
        m[4].body.size = mtu_seg + 1u;
        CHECK(duct_x_gso_group(m,8u) == 4u, "a group ends at the first longer entry");
    }

    {
        s_fill(m, 8u, mtu_seg);
        m[2].body.size = mtu_seg - 10u;
        CHECK(duct_x_gso_group(m,8u) == 3u, "a shorter entry is admitted as the group's last");
    }

    {
        s_fill(m, 8u, mtu_seg);
        m[2].body.size = 0u;
        CHECK(duct_x_gso_group(m,8u) == 2u, "a zero-length entry ends the group outside it");
    }

    /* Nothing in the entries ends this group, so the bound does. Past it the
     * stack refuses the whole write and the rest of the call goes out
     * unsegmented — the deep batches this exists for are the ones that lose
     * it. */
    {
        s_fill(m, group_test_max, mtu_seg);
        uint32_t group = duct_x_gso_group(m,group_test_max);
        CHECK(group == (uint32_t)(duct_udp4_payload_max / mtu_seg),
              "a uniform group is cut to what one payload holds");
        CHECK((size_t)group * mtu_seg <= duct_udp4_payload_max,
              "the cut group must fit one write");
    }

    /* The other bound: 256 segments of this size fit the payload with room to
     * spare, so the count is what cuts them. */
    {
        s_fill(m, group_test_max, tiny_seg);
        CHECK(duct_x_gso_group(m,group_test_max) == (uint32_t)duct_x_gso_segs_max,
              "small segments are cut by the segment count, not the payload");
    }

    {
        s_fill(m, 8u, 0u);
        CHECK(duct_x_gso_group(m,8u) == 1u, "a zero-length lead entry carries no group");
    }

    /* A lead entry no single datagram can hold. Such a size divides the
     * payload cap to zero, which leaves the clamp answering 1 on its own; the
     * guard says so outright rather than leaning on a division flooring. */
    {
        s_fill(m, 8u, (size_t)UINT16_MAX + 1u);
        CHECK(duct_x_gso_group(m,8u) == 1u,
              "a lead entry past one datagram carries no group");
    }

    {
        s_fill(m, 8u, mtu_seg);
        CHECK(duct_x_gso_group(m,1u) == 1u, "a single entry answers itself");
    }

    printf("gso_group_test OK\n");
    return 0;
}
