/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file tun_open.h
 *  @brief The tests' own tun opener, the @c IFF_VNET_HDR shape the engine's
 *  packet-fd attach reads.
 */

#ifndef TUN_OPEN_H
#define TUN_OPEN_H

#include "duct.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/** @brief Capacity of a tun's interface name, terminator included, bytes. */
static constexpr size_t tun_name_max = 16u;

/** @brief One opened tun: the status, the descriptor and the interface name. */
typedef struct tun_opened {
    duct_result_t rc;  /**< Open status. Any code but @c rc_ok leaves @c fd at
                         *  @c duct_sock_bad and @c name empty. */
    duct_sock_t   fd;  /**< Tun descriptor, non-blocking and close-on-exec. */
    char          name[tun_name_max]; /**< Interface name the kernel settled
                                       *  on, NUL-terminated. */
} tun_opened_t;

static_assert(tun_name_max == IFNAMSIZ, "tun_opened_t::name holds one interface name whole");

/** @brief Build the result of a refused open: @p rc, no descriptor and no name. */
static tun_opened_t tun_refused(duct_result_t rc)
{
    return (tun_opened_t){ .rc = rc, .fd = duct_sock_bad };
}

/** @brief Open a Linux tun whose packets carry a @c virtio_net_hdr, named by @p hint.
 *  An exact name, a template with one @c %d, or @c nullptr or empty for the
 *  kernel's own pick. @c rc_again answers a name another descriptor holds.
 */
static tun_opened_t tun_open(const char *hint)
{
    auto want = hint ? hint : "";
    size_t len = strnlen(want, tun_name_max);
    if (len == tun_name_max)
        return tun_refused(rc_invalid_arg);
    int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        return tun_refused(errno == ENOENT || errno == ENODEV ? rc_not_supported : rc_fatal);
    struct ifreq ifr = { .ifr_flags = IFF_TUN | IFF_NO_PI | IFF_VNET_HDR };
    /* The initializer zeroed the name, so a copy shorter than the field ends
     * in a NUL. */
    memcpy(ifr.ifr_name, want, len);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        int err = errno;
        close(fd);
        switch (err) {
        case EBUSY:    return tun_refused(rc_again);
        case EINVAL:   return tun_refused(rc_invalid_arg);
        case ENOENT:
        case ENODEV:   return tun_refused(rc_not_supported);
        case ENOMEM:   return tun_refused(rc_no_memory);
        default:       return tun_refused(rc_fatal);
        }
    }
    tun_opened_t tun = { .rc = rc_ok, .fd = fd };
    memcpy(tun.name, ifr.ifr_name, sizeof tun.name);
    return tun;
}

#endif
