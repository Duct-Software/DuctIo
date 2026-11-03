/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file darwin_xport_test.c
 *  @brief UDP disables fragmentation and drops truncation without losing later packets.
 */
#include "duct_xport.h"

#include <poll.h>
#include <stdio.h>

int main(void)
{
    int receiver = socket(AF_INET, SOCK_DGRAM, 0);
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    int pass = 0;
    if (receiver < 0 || sender < 0)
        goto done;
    struct sockaddr_in address = { .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (bind(receiver, (struct sockaddr *)&address, sizeof address) != 0)
        goto done;
    socklen_t length = sizeof address;
    if (getsockname(receiver, (struct sockaddr *)&address, &length) != 0
        || connect(sender, (struct sockaddr *)&address, length) != 0)
        goto done;
    duct_xset_fd_flags(receiver);
    duct_xset_dgram_bufs(sender, AF_INET);
    int df = 0;
    length = sizeof df;
    if (getsockopt(sender, IPPROTO_IP, IP_DONTFRAG, &df, &length) != 0 || df != 1) {
        fprintf(stderr, "darwin_xport: UDP fragmentation was not disabled\n");
        goto done;
    }
    int ipv6 = socket(AF_INET6, SOCK_DGRAM, 0);
    if (ipv6 < 0)
        goto done;
    duct_xset_dgram_bufs(ipv6, AF_INET6);
    df = 0;
    length = sizeof df;
    bool ipv6_df = getsockopt(ipv6, IPPROTO_IPV6, IPV6_DONTFRAG, &df, &length) == 0 && df == 1;
    close(ipv6);
    if (!ipv6_df) {
        fprintf(stderr, "darwin_xport: IPv6 UDP fragmentation was not disabled\n");
        goto done;
    }
    char oversized[64] = {}, small[8] = {};
    size_t n = 0u;
    if (send(sender, oversized, sizeof oversized, 0) != sizeof oversized)
        goto done;
    struct pollfd readable = { .fd = receiver, .events = POLLIN };
    if (poll(&readable, 1, 1000) != 1)
        goto done;
    if (duct_xread(receiver, x_udp_peer, (duct_view_u8){ small, sizeof small },
                   &n, nullptr, MSG_DONTWAIT, nullptr) != rc_drop || n != 0u) {
        fprintf(stderr, "darwin_xport: truncated datagram was accepted\n");
        goto done;
    }
    if (send(sender, "ok", 2, 0) != 2 || poll(&readable, 1, 1000) != 1
        || duct_xread(receiver, x_udp_peer, (duct_view_u8){ small, sizeof small },
                      &n, nullptr, MSG_DONTWAIT, nullptr) != rc_ok
        || n != 2u || memcmp(small, "ok", 2) != 0)
        goto done;
    if (send(sender, "", 0, 0) != 0 || poll(&readable, 1, 1000) != 1
        || duct_xread(receiver, x_udp_peer, (duct_view_u8){ small, sizeof small },
                      &n, nullptr, MSG_DONTWAIT, nullptr) != rc_ok || n != 0u)
        goto done;
    pass = 1;
done:
    if (receiver >= 0) close(receiver);
    if (sender >= 0) close(sender);
    return pass ? 0 : 1;
}
