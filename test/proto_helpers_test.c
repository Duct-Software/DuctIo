/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file proto_helpers_test.c
 *  @brief duct_response_forward, duct_proto_create_owning, the length-prefix
 *  header size, the built-in protocol creators and the IP version of a peer.
 *
 *  @c sc_forward expects the response to carry the frame's payload, copied under
 *  the frame's flags, on the leg named, and to equal an echo's in every other
 *  field. @c sc_owning gives a wire counting its destructions to the creator: the
 *  wire is bound into the configuration and owned by the handle and destroyed
 *  once with it, destroyed once when the configuration is refused and once when
 *  it is null, and a null wire makes nothing. @c sc_length_prefix expects the
 *  header the wire packs and the one it declares to be the declared size.
 *  @c sc_builtin expects the TCP and UDP creators to own the wire they built.
 *  @c sc_peer_ip expects an IPv4 address and an IPv4-mapped IPv6 one to read as
 *  IPv4, any other IPv6 address as IPv6, and a peer of no family as neither.
 */

#include "duct.h"

#include <stdio.h>

#ifdef _WIN32
  #include <winsock2.h>
#else
  #include <sys/socket.h>
#endif

static unsigned s_destroyed;

/** @brief Count a destruction without freeing, the wire living on the stack. */
static void s_wire_destroy([[maybe_unused]] duct_wire_t *self)
{
    ++s_destroyed;
}

static duct_result_t s_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                                [[maybe_unused]] const duct_frame_t *frame,
                                [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

/** @brief Forward a frame and compare the response with an echo of it.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_forward(void)
{
    static const char bytes[] = "forwarded";
    duct_frame_t frame = { .stream_id = 7u, .flags = fl_frame_fin,
                           .payload = { .data = (void *)bytes, .size = sizeof bytes - 1u } };
    duct_response_t out = {},
                    echo = {};
    duct_response_forward(&out, &frame, 5u);
    duct_response_echo(&echo, &frame);
    if (out.payload.data != frame.payload.data || out.payload.size != frame.payload.size)
        return "the payload is not the frame's";
    if (out.flags != fl_send_copy || out.frame_flags != frame.flags)
        return "the response does not copy the payload under the frame's flags";
    if (out.conn_id != 5u)
        return "the response does not name the leg it was asked to";
    if (out.stream_id != echo.stream_id || out.control.stream_op_conn_id != echo.control.stream_op_conn_id
        || out.control.close_target != echo.control.close_target || out.control.timer.delay_ms != 0u)
        return "the response differs from an echo in more than its leg";
    duct_response_forward(&out, &frame, duct_conn_id_same);
    return out.conn_id == duct_conn_id_same ? nullptr : "the same-leg sentinel was not passed through";
}

/** @brief Create protocols over a wire that counts its destructions.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_owning(void)
{
    duct_wire_t wire = { .name = "counting", .destroy = s_wire_destroy };
    duct_proto_cfg_t cfg = { .name = "owning", .on_frame = s_on_frame };
    s_destroyed = 0u;
    auto proto = duct_proto_create_owning(&cfg, &wire);
    if (!proto)
        return "a valid configuration made no protocol";
    if (cfg.wire != &wire || proto->cfg.wire != &wire || proto->owned_wire != &wire)
        return "the wire is not bound into the configuration and owned by the protocol";
    if (s_destroyed != 0u)
        return "the wire was destroyed with the protocol alive";
    duct_proto_destroy(proto);
    if (s_destroyed != 1u)
        return "destroying the protocol did not destroy its wire once";

    s_destroyed = 0u;
    cfg = (duct_proto_cfg_t){ .name = "invalid" };
    if (duct_proto_create_owning(&cfg, &wire))
        return "a configuration without on_frame made a protocol";
    if (s_destroyed != 1u)
        return "a refused configuration left the wire to the caller";

    s_destroyed = 0u;
    if (duct_proto_create_owning(nullptr, &wire))
        return "a null configuration made a protocol";
    if (s_destroyed != 1u)
        return "a null configuration left the wire to the caller";
    cfg = (duct_proto_cfg_t){ .name = "owning", .on_frame = s_on_frame };
    if (duct_proto_create_owning(&cfg, nullptr))
        return "a null wire made a protocol";
    return nullptr;
}

/** @brief Compare the length-prefix wire's header with the declared size.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_length_prefix(void)
{
    auto wire = duct_wire_create_length_prefix(0u);
    if (!wire)
        return "the length-prefix wire was not made";
    uint8_t header[16] = {};
    size_t written = wire->pack_header(wire, &(duct_frame_t){}, header);
    size_t declared = wire->header_size;
    duct_wire_destroy(wire);
    if (written != duct_wire_length_prefix_hdr_size || declared != duct_wire_length_prefix_hdr_size)
        return "the length-prefix header is not the size the engine declares";
    return nullptr;
}

/** @brief Create the TCP and UDP protocols and look at the wire each owns.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_builtin(void)
{
    auto tcp = duct_proto_create_tcp("tcp", s_on_frame);
    auto udp = duct_proto_create_udp("udp", s_on_frame);
    const char *err = nullptr;
    if (!tcp || !udp)
        err = "a built-in protocol was not made";
    else if (!tcp->owned_wire || tcp->cfg.wire != tcp->owned_wire
             || !udp->owned_wire || udp->cfg.wire != udp->owned_wire)
        err = "a built-in protocol does not own the wire it was built with";
    duct_proto_destroy(tcp);
    duct_proto_destroy(udp);
    return err;
}

/** @brief Read the IP version of peers in and out of the IPv4-mapped range.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_peer_ip(void)
{
    static const struct {
        const char *fail;
        duct_peer_t peer;
        duct_ip_flags_t want;
    } cases[] = {
        { "an IPv4 peer is not IPv4",
          { .family = AF_INET, .addr = { .v4 = { 192, 0, 2, 1 } } }, fl_ip_v4 },
        { "an IPv4-mapped IPv6 peer is not IPv4",
          { .family = AF_INET6, .addr = { .v6 = { [10] = 0xff, [11] = 0xff, 192, 0, 2, 1 } } }, fl_ip_v4 },
        { "a global IPv6 peer is not IPv6",
          { .family = AF_INET6, .addr = { .v6 = { 0x20, 0x01, 0x0d, 0xb8, [15] = 1 } } }, fl_ip_v6 },
        { "the IPv6 loopback is not IPv6",
          { .family = AF_INET6, .addr = { .v6 = { [15] = 1 } } }, fl_ip_v6 },
        { "an IPv4-compatible IPv6 peer is not IPv6",
          { .family = AF_INET6, .addr = { .v6 = { [12] = 192, 0, 2, 1 } } }, fl_ip_v6 },
        { "a NAT64 peer is not IPv6",
          { .family = AF_INET6, .addr = { .v6 = { 0x00, 0x64, 0xff, 0x9b, [12] = 192, 0, 2, 1 } } }, fl_ip_v6 },
        { "a mapped prefix behind a set byte is not IPv6",
          { .family = AF_INET6, .addr = { .v6 = { [9] = 1, [10] = 0xff, [11] = 0xff, 192, 0, 2, 1 } } }, fl_ip_v6 },
        { "a peer of no family has a version", {}, fl_ip_none },
    };
    for (size_t i = 0u; i < sizeof cases / sizeof *cases; ++i)
        if (duct_peer_ip_flags(&cases[i].peer) != cases[i].want)
            return cases[i].fail;
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    const char *err = sc_forward();
    if (!err)
        err = sc_owning();
    if (!err)
        err = sc_length_prefix();
    if (!err)
        err = sc_builtin();
    if (!err)
        err = sc_peer_ip();
    if (err) {
        fprintf(stderr, "proto_helpers: %s\n", err);
        return 1;
    }
    printf("proto_helpers: OK (forward, create owning, the length-prefix header, the built-in creators, the peer's IP version)\n");
    return 0;
}
