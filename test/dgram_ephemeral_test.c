/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file dgram_ephemeral_test.c
 * @brief An ephemeral datagram bind is handed a port no other socket holds.
 *
 * The listeners set SO_REUSEADDR and SO_REUSEPORT, and the kernel leaves a port
 * alone only when the socket holding it would conflict, which a socket with the
 * same options does not. Asked for port 0, such a socket is handed a port another
 * one already holds, another process's included, and the datagrams of two
 * engines then land on either by the hash of their source. A held set of
 * listener sockets and many more draws make that a certainty without the
 * draw by a plain socket in os/duct_listener.c.
 */

#include "duct.h"
#include "duct_listener.h"
#include "test_helpers.h"

static constexpr unsigned n_held = 200u;
static constexpr unsigned n_draws = 1500u;

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    static bool held_port[65536];
    duct_sock_t held[n_held];
    unsigned n_open = 0u;
    bool ok = true;

    for (unsigned i = 0u; ok && i < n_held; ++i) {
        uint16_t port = 0u;
        held[i] = duct_dgram_socket_open("127.0.0.1", &port, false);
        ok = held[i] != duct_sock_bad && port != 0u;
        n_open += held[i] != duct_sock_bad;
        held_port[port] = true;
    }
    if (!ok)
        fprintf(stderr, "dgram_ephemeral: could not open the held set\n");

    for (unsigned i = 0u; ok && i < n_draws; ++i) {
        uint16_t port = 0u;
        duct_sock_t fd = duct_dgram_socket_open("127.0.0.1", &port, false);
        ok = fd != duct_sock_bad && port != 0u;
        if (!ok)
            fprintf(stderr, "dgram_ephemeral: draw %u failed\n", i);
        else if (held_port[port]) {
            fprintf(stderr, "dgram_ephemeral: draw %u was handed port %u, which a held socket binds\n",
                    i, (unsigned)port);
            ok = false;
        }
        if (fd != duct_sock_bad)
            duct_sock_close(fd);
    }

    for (unsigned i = 0u; i < n_open; ++i)
        duct_sock_close(held[i]);
    if (!ok)
        return 1;
    printf("dgram_ephemeral: OK (%u draws, none on one of %u held ports)\n", n_draws, n_held);
    return 0;
}
