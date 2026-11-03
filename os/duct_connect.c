/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_connect.c
 *  @brief Outbound connect: address parsing, host detection, and resolver dispatch.
 *
 *  Hostname resolution delegates to the platform resolver via @ref duct_resolve_start.
 *
 *  @ref duct_connect_start is the entry point for all dials: a literal
 *  IPv4/IPv6 peer posts directly to the target I/O thread; a symbolic hostname
 *  hands off to @ref duct_resolve_start. An @c x_local dial names a socket path
 *  and posts directly to the target I/O thread.
 */

#include "duct_relay.h"
#include "duct_dgram_rec.h"
#include "duct_listener.h"
#include "duct_protocol.h"
#include "duct_xport.h"

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <netinet/in.h>
#endif

/* Split "host:port" / "[ipv6]:port" into a NUL-terminated host and a numeric
 * port. Brackets are required whenever the host contains a ':' — every IPv6
 * literal does; the last colon splits otherwise, since neither a hostname nor
 * an IPv4 literal ever contains one. Non-static for direct unit testing.
 * host must be pure ASCII, every byte < 0x80: Windows auto-encodes IDN in
 * GetAddrInfoExW and Linux getaddrinfo does not, so the same name resolves on
 * one and fails on the other. An IPv4/IPv6 literal is pure ASCII by its own
 * syntax, so only a non-ASCII symbolic hostname is rejected. */
bool duct_connect_parse_addr(const char *addr, char *host, size_t host_cap, uint16_t *port)
{
    duct_do_if(!addr || !*addr || !host || !host_cap || !port, return false);
    auto split = duct_str_split(addr);
    duct_do_if(!split.host || split.host_len == 0u || split.host_len >= host_cap, return false);
    for (size_t i = 0u; i < split.host_len; ++i)
        if ((unsigned char)split.host[i] >= 0x80u)
            return false;
    memcpy(host, split.host, split.host_len);
    host[split.host_len] = '\0';
    char *end = nullptr;
    unsigned long p = strtoul(split.port, &end, 10);
    duct_do_if(!end || *end || end == split.port || p == 0u || p > UINT16_MAX, return false);
    *port = (uint16_t)p;
    return true;
}

/** @brief Fill @p out from an IPv4/IPv6 literal; false if @p host is not a
 *  literal — caller falls back to DNS resolution.
 */
static bool s_peer_from_literal(const char *host, uint16_t port, duct_peer_t *out)
{
    struct in6_addr v6;
    if (inet_pton(AF_INET6, host, &v6) == 1) {
        *out = (duct_peer_t){ .family = AF_INET6, .port = port };
        memcpy(out->addr.v6, &v6, sizeof out->addr.v6);
        return true;
    }
    struct in_addr v4;
    if (inet_pton(AF_INET, host, &v4) == 1) {
        *out = (duct_peer_t){ .family = AF_INET, .port = port };
        memcpy(out->addr.v4, &v4, sizeof out->addr.v4);
        return true;
    }
    return false;
}

duct_ip_flags_t duct_peer_ip_flags(const duct_peer_t *peer)
{
    static constexpr uint8_t mapped[12] = { [10] = 0xffu, [11] = 0xffu };
    if (peer->family == AF_INET)
        return fl_ip_v4;
    if (peer->family != AF_INET6)
        return fl_ip_none;
    return memcmp(peer->addr.v6, mapped, sizeof mapped) == 0 ? fl_ip_v4 : fl_ip_v6;
}

duct_result_t duct_connect_start(unsigned io_id, const char *addr,
                                 const duct_conn_intent_t *seed, uint32_t connect_timeout_ms)
{
    switch (seed->xport) {
    case x_tcp:
    case x_udp_peer:
    case x_local:
        break;
    default:
        return rc_invalid_arg;
    }
    /* The dial's only synchronous answer: the bind that also catches this runs
     * on an io thread long after this returns, and its refusal reaches the
     * caller as nothing but a conn that never opens. */
    if (!duct_wire_framing_fits_xport(duct_proto_cfg_of(seed->proto)->wire,
                                      seed->xport))
        return rc_invalid_arg;
    if (seed->xport == x_local) {
        bool fits = duct_local_path_fits(addr);
        duct_do_if(seed->egress_if || !fits, return rc_invalid_arg);
        duct_do_if(!duct_x_local_floor, return rc_not_supported);
        return duct_io_post_connect_local(io_id, addr, seed, connect_timeout_ms) ? rc_ok : rc_fatal;
    }
    char host[256];
    uint16_t port = 0u;
    if (!duct_connect_parse_addr(addr, host, sizeof host, &port))
        return rc_invalid_arg;

    duct_peer_t peer = {};
    if (s_peer_from_literal(host, port, &peer))
        return duct_io_post_connect(io_id, &peer, seed, connect_timeout_ms) ? rc_ok : rc_fatal;

    return duct_resolve_start(io_id, host, port, connect_timeout_ms, seed);
}
