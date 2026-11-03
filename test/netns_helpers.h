/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file netns_helpers.h
 *  @brief Linux test helpers: a private user and network namespace for the
 *  process, and the ioctl calls that bring an interface up inside it.
 *
 *  A test enters the namespace in @c main before it starts a thread. A tun it
 *  opens and the interface it brings up then exist for that process alone.
 */

#ifndef DUCT_TEST_NETNS_HELPERS_H
#define DUCT_TEST_NETNS_HELPERS_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <sched.h>

/** @brief Run interface ioctl @p request on @p ifr through a throwaway datagram socket.
 *  @return whether the socket opened and the ioctl succeeded.
 */
static inline bool th_ifreq_ioctl(unsigned long request, struct ifreq *ifr)
{
    duct_sock_t sock = (duct_sock_t)socket(AF_INET, SOCK_DGRAM, 0);
    bool ok = sock != duct_sock_bad && ioctl(sock, request, ifr) == 0;
    if (sock != duct_sock_bad)
        duct_sock_close(sock);
    return ok;
}

/** @brief Bring interface @p name up, with @p addr under a /24 mask when it is not null and @p mtu when it is not 0.
 *  Each step runs only if the steps before it did, and none is undone.
 *  @return whether every step the kernel was asked for succeeded.
 */
static inline bool th_ifup(const char *name, const char *addr, int mtu)
{
    struct ifreq ifr = {};
    snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", name);
    auto sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    bool ok = !addr || (inet_pton(AF_INET, addr, &sin->sin_addr) == 1 && th_ifreq_ioctl(SIOCSIFADDR, &ifr));
    if (ok && addr) {
        inet_pton(AF_INET, "255.255.255.0", &sin->sin_addr);
        ok = th_ifreq_ioctl(SIOCSIFNETMASK, &ifr);
    }
    struct ifreq flags = {};
    snprintf(flags.ifr_name, sizeof flags.ifr_name, "%s", name);
    ok = ok && th_ifreq_ioctl(SIOCGIFFLAGS, &flags);
    flags.ifr_flags = (short)(flags.ifr_flags | IFF_UP | IFF_RUNNING);
    ok = ok && th_ifreq_ioctl(SIOCSIFFLAGS, &flags);
    if (mtu) {
        struct ifreq size = {};
        snprintf(size.ifr_name, sizeof size.ifr_name, "%s", name);
        size.ifr_mtu = mtu;
        ok = ok && th_ifreq_ioctl(SIOCSIFMTU, &size);
    }
    return ok;
}

/** @brief Enter a new user and network namespace and bring its loopback up.
 *  The user namespace gives the process the right to configure interfaces in the
 *  network namespace made with it, so the call asks no privilege of the user.
 *  The kernel refuses @c CLONE_NEWUSER to a process with more than one thread:
 *  call this before any thread exists.
 *  A new namespace that refuses its loopback ends the process with status 1.
 *  @return @c "unshare refused" where the host refuses the namespaces, nullptr after entering.
 */
static inline const char *th_enter_netns(void)
{
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0)
        return "unshare refused";
    if (!th_ifup("lo", nullptr, 0)) {
        fprintf(stderr, "netns: the new namespace refused its loopback\n");
        exit(1);
    }
    return nullptr;
}

#endif
