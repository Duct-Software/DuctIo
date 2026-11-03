/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file noise_dgram_test.c
 * @brief The Noise engine behind a sealed wire on a datagram listener.
 *
 * The server side is the real engine: a Noise sealed wire with no inner wire on
 * a listener_dgram listener under fl_proto_dgram_shared, so RX arrives on the
 * conn's inter lane and the engine answers message 1 and decrypts transport PDUs.
 *
 * Three peers exercise it. One drives Noise by hand over a UDP socket, framing
 * every PDU with the engine's own 2-byte big-endian length. One is a whole duct
 * client dialled with x_udp_peer under seal_framing_datagram: it proves a sealed
 * wire drives a handshake from the initiator side over datagrams, that its first
 * payload survives parking until the keys exist, and that one listener holds both
 * peers as separate sessions. The third is nd_framing, which calls on_parse
 * directly: the record cases it covers are unreachable through a socket.
 *
 * Record framing belongs to the wire on both parse drivers, so a datagram
 * reaching unseal is one whole PDU with its record consumed. The tail of main
 * walks the three refusals of a disagreeing framing: dial and both listeners.
 *
 * nd_forgery holds what a datagram costs when it fails: records are independent,
 * so nothing a peer sends ends more than the record it sent, and a record
 * matching the control rule, once the keys exist, reaches the AEAD like any
 * other. nd_ctl_framing drives unseal by hand: before any key, a control payload
 * the rule hands over arrives as one inner frame, a datagram the rule turns away
 * goes to the engine, and a rule on a stream wire is refused.
 *
 * nd_inner puts a length-prefix inner wire under a second shared listener and
 * an x_udp_peer client: a frame carrying fl_frame_gso crosses both parse paths,
 * the inter lane's and the ring's, with its flag and without the inner header.
 *
 * nd_open dials a hand-written responder with an x_udp_peer client whose config
 * names an opening source: the datagrams ahead of message 1 are the source's,
 * bare and byte for byte, and the handshake behind them completes with the
 * client's first frame arriving whole.
 *
 * nd_dgram holds the datagram vtbl: its shape against the stream one, its bytes
 * against a hand-written responder that holds only the Noise primitives, and its
 * two ends against each other.
 */

#include "duct.h"
#include "duct_ticks.h"
#include "duct_tls.h"
#include "duct_noise.h"
#include "duct_noise_internal.h"
#include "duct_dgram_rec.h"
#include "duct_wire_codec.h"

#include <openssl/crypto.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "test_helpers.h"
#include "dgram_test_helpers.h"

static constexpr size_t nd_prefix = 2u;

/* The handshake pattern of the whole run, named on the command line. */
static duct_noise_pattern_t g_pattern = noise_pattern_ikpsk2;

static atomic_int g_srv_frames = 0;
static atomic_int g_cli_echo   = 0;

static const char nd_cli_hello[] = "dgram-client-hello";

/** @brief The duct client's opening payload, returned before any key exists.
 *  seal_size answers 0 until the handshake lands, so this parks on the
 *  retry-emit path and must still arrive once message 2 does.
 */
static duct_result_t
nd_cli_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    out->payload = (duct_view_u8){ (void *)nd_cli_hello, sizeof nd_cli_hello - 1u };
    out->flags = fl_send_copy;
    return rc_ok;
}

/** @brief Count the duct client's echo, once its cleartext matches. */
static duct_result_t
nd_cli_frame([[maybe_unused]] duct_session_t *s,
             [[maybe_unused]] duct_conn_id_t conn_id,
             const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    if (frame->payload.size == sizeof nd_cli_hello - 1u
        && memcmp(frame->payload.data, nd_cli_hello,
                  sizeof nd_cli_hello - 1u) == 0)
        atomic_fetch_add_explicit(&g_cli_echo, 1, memory_order_release);
    return rc_ok;
}

/** @brief Write @p body as the engine's 2-byte big-endian PDU length. */
static void nd_put_len(uint8_t out[2], size_t body)
{
    out[0] = (uint8_t)(body >> 8u);
    out[1] = (uint8_t)body;
}

/** @brief Read a PDU length off the wire's 2-byte prefix. */
static size_t nd_get_len(const uint8_t in[2])
{
    return ((size_t)in[0] << 8u) | (size_t)in[1];
}

static atomic_int g_srv_sessions = 0;
static atomic_int g_srv_errors = 0;

static duct_result_t
nd_srv_error([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_result_t err,
             [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    atomic_fetch_add_explicit(&g_srv_errors, 1, memory_order_release);
    return rc_ok;
}

/** @brief Count sessions the one listener opens, one per peer address. */
static duct_result_t
nd_srv_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    atomic_fetch_add_explicit(&g_srv_sessions, 1, memory_order_release);
    return rc_ok;
}

/** @brief Echo the decrypted payload back and count the frame. */
static duct_result_t
nd_on_frame([[maybe_unused]] duct_session_t *s,
            [[maybe_unused]] duct_conn_id_t conn_id,
            const duct_frame_t *frame, duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    duct_response_same(out, frame->payload, fl_send_copy, fl_frame_none);
    atomic_fetch_add_explicit(&g_srv_frames, 1, memory_order_release);
    return rc_ok;
}

/** @brief Pin the handshake budget's ceiling against the engine park.
 *
 *  A conn's park holds two engine messages and flushes them whole into the
 *  smallest TX ring, so a budget past half of it would wait for room the ring
 *  never has. A datagram-framed conn adds a record header and the wire's prefix
 *  to each message; a stream conn adds neither. Per framing and prefix, the
 *  largest budget that fits builds and one byte more does not.
 */
static const char *nd_budget_cap(duct_noise_cfg_t *cfg)
{
    static const struct {
        duct_seal_framing_t framing;
        uint8_t             prefix;
        size_t              cap;
    } cases[] = {
        { seal_framing_stream,   0u, duct_conn_tx_olb_cap / 2u },
        { seal_framing_datagram, 0u, duct_conn_tx_olb_cap / 2u - duct_dgram_record_hdr_size },
        { seal_framing_datagram, duct_seal_prefix_max,
          duct_conn_tx_olb_cap / 2u - duct_dgram_record_hdr_size - duct_seal_prefix_max },
    };
    for (unsigned i = 0u; i < sizeof cases / sizeof cases[0]; ++i)
        for (size_t past = 0u; past < 2u; ++past) {
            duct_seal_engine_vtbl_t vt;
            duct_noise_vtbl_make(&vt, cases[i].cap + past);
            auto wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
                .engine = &vt, .engine_cfg = cfg,
                .role = seal_role_initiator, .framing = cases[i].framing,
                .tx_prefix_len = cases[i].prefix });
            if (wire)
                duct_wire_destroy(wire);
            if (past && wire)
                return "a budget past the engine park's room was accepted";
            if (!past && !wire)
                return "a budget the engine park has room for was refused";
        }
    return nullptr;
}

/** @brief Pin the framing half to stream framing alone.
 *
 *  An engine cutting no PDU of its own belongs on a record, where the length
 *  arrives ahead of the bytes; the same engine on a byte stream leaves
 *  @c s_tls_on_parse nothing to cut on. Both answers are checked here, so the
 *  gate tightened back to every framing fails the first and the gate dropped
 *  altogether fails the second.
 */
static const char *nd_framing_half(duct_noise_cfg_t *cfg)
{
    duct_seal_engine_vtbl_t vt;
    duct_noise_vtbl_make(&vt, duct_noise_vtbl()->engine_hs_budget);
    vt.pdu_len = nullptr;
    vt.pdu_hdr_size = 0u;

    auto dgram = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .engine = &vt, .engine_cfg = cfg,
        .role = seal_role_initiator, .framing = seal_framing_datagram });
    if (!dgram)
        return "a datagram wire was refused an engine carrying no PDU framing";
    duct_wire_destroy(dgram);

    auto stream = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .engine = &vt, .engine_cfg = cfg,
        .role = seal_role_initiator, .framing = seal_framing_stream });
    if (stream) {
        duct_wire_destroy(stream);
        return "a stream wire was built on an engine that cuts no PDU";
    }
    return nullptr;
}

/** @brief Drive on_parse and tx_bound directly over the datagram contract.
 *
 *  Every case turns on the record length being the only length that decides
 *  anything: an empty record consumes itself rather than parking the ring on
 *  a PDU header that never comes, a truncated one asks for its own declared
 *  length, and a record whose contents disagree with themselves is still cut
 *  whole and left for the AEAD to refuse.
 *
 *  The tx_bound pair holds the other half of that: one datagram carries one
 *  PDU, while stream framing keeps the segmentation this takes away.
 */
static const char *nd_framing(duct_noise_cfg_t *cfg)
{
    auto w = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .engine = duct_noise_vtbl(), .engine_cfg = cfg,
        .role = seal_role_initiator, .framing = seal_framing_datagram });
    if (!w)
        return "framing probe wire create failed";

    const char *err = nullptr;
    auto parser = duct_wire_parser_create(w);
    uint8_t buf[64] = {};
    duct_frame_t frame = {};
    size_t consumed = 0u, needed = 0u;

    if (w->on_parse(w, (duct_view_u8){ buf, duct_dgram_record_hdr_size }, &frame,
                    parser, &consumed, &needed) != rc_ok
        || consumed != duct_dgram_record_hdr_size
        || frame.payload.size != 0u)
        err = "an empty datagram record did not consume itself whole";

    if (!err) {
        duct_dgram_rec_hdr_encode(buf, 50u);
        consumed = needed = 0u;
        if (w->on_parse(w, (duct_view_u8){ buf, duct_dgram_record_hdr_size + nd_prefix },
                        &frame, parser, &consumed, &needed) != rc_again
            || needed != duct_dgram_record_hdr_size + 50u)
            err = "a truncated record did not ask for its own declared length";
    }
    if (!err) {
        consumed = needed = 0u;
        if (w->on_parse(w, (duct_view_u8){ buf, duct_dgram_record_hdr_size + 50u },
                        &frame, parser, &consumed, &needed) != rc_ok
            || consumed != duct_dgram_record_hdr_size + 50u
            || frame.payload.size != 50u)
            err = "a whole record did not cut exactly one datagram";
    }
    if (!err) {
        nd_put_len(buf + duct_dgram_record_hdr_size, 9u);
        consumed = needed = 0u;
        if (w->on_parse(w, (duct_view_u8){ buf, duct_dgram_record_hdr_size + 50u },
                        &frame, parser, &consumed, &needed) != rc_ok
            || consumed != duct_dgram_record_hdr_size + 50u
            || frame.payload.size != 50u)
            err = "a record whose content disagrees with itself was judged before unseal";
    }
    if (!err) {
        size_t ct_max = duct_noise_vtbl()->pdu_ct_max;
        if (w->tx_bound(w, ct_max) == SIZE_MAX)
            err = "one whole PDU of cleartext was refused on a datagram wire";
        else if (w->tx_bound(w, ct_max + 1u) != SIZE_MAX)
            err = "a datagram wire accepted cleartext that spans two PDUs";
    }
    duct_wire_parser_destroy(w, parser);
    duct_wire_destroy(w);

    if (!err) {
        auto sw = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .engine = duct_noise_vtbl(), .engine_cfg = cfg,
            .role = seal_role_initiator, .framing = seal_framing_stream });
        if (!sw)
            return "stream framing probe wire create failed";
        if (sw->tx_bound(sw, duct_noise_vtbl()->pdu_ct_max + 1u) == SIZE_MAX)
            err = "stream framing lost its own multi-PDU segmentation";
        duct_wire_destroy(sw);
    }
    return err;
}

static atomic_int g_forge_bytes = 0;
static atomic_int g_forge_closed = 0;

static const char nd_forge_hello[] = "forge-client-hello";
static const char nd_ctl_msg[] = "control-before-keys";
/** @brief First byte of a control datagram. */
static constexpr uint8_t nd_ctl = 0xc7u;

/** @brief Bytes the forged datagram carries behind its lead byte and length. */
static constexpr size_t nd_forged = 48u;

/** @brief What the wire's control rule takes for a control datagram. */
typedef struct {
    uint8_t lead; /**< First byte. */
    size_t  len;  /**< Whole datagram, bytes. */
} nd_ctl_rule_t;

/** @brief The wire's control rule: hand the protocol the part of @p datagram past
 *  its lead byte when it is the size and leads with the byte @p ctx names, else
 *  nothing. */
static duct_view_u8 nd_ctl_rx(void *ctx, duct_view_u8 datagram)
{
    auto rule = (const nd_ctl_rule_t *)ctx;
    auto bytes = (uint8_t *)datagram.data;
    if (datagram.size != rule->len || bytes[0] != rule->lead)
        return (duct_view_u8){};
    return duct_view(duct_view_u8, bytes + 1u, datagram.size - 1u);
}

static duct_result_t
nd_forge_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
              [[maybe_unused]] void *user_ctx, duct_response_t *out,
              [[maybe_unused]] void *proto_state)
{
    out->payload = (duct_view_u8){ (void *)nd_forge_hello, sizeof nd_forge_hello - 1u };
    out->flags = fl_send_copy;
    return rc_ok;
}

static duct_result_t
nd_forge_frame([[maybe_unused]] duct_session_t *s,
               [[maybe_unused]] duct_conn_id_t conn_id,
               const duct_frame_t *frame,
               [[maybe_unused]] duct_response_t *out,
               [[maybe_unused]] void *proto_state)
{
    atomic_fetch_add_explicit(&g_forge_bytes, (int)frame->payload.size, memory_order_release);
    return rc_ok;
}

static void
nd_forge_close([[maybe_unused]] duct_session_t *s,
               [[maybe_unused]] duct_close_reason_t reason,
               [[maybe_unused]] void *proto_state)
{
    atomic_fetch_add_explicit(&g_forge_closed, 1, memory_order_release);
}

/** @brief One datagram into @p buf, its sender kept for the reply. */
static ssize_t nd_peer_recv(duct_sock_t fd, uint8_t *buf, size_t cap,
                            struct sockaddr_in *from)
{
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    if (poll(&pfd, 1, TH_DGRAM_RECV_TIMEOUT_MS) <= 0)
        return -1;
    socklen_t flen = sizeof *from;
    return recvfrom(fd, (char *)buf, (int)cap, 0, (struct sockaddr *)from, &flen);
}

/** @brief The pre-shared key of the one peer there is, @p ctx being that key. */
static bool nd_psk_for(void *ctx, [[maybe_unused]] const uint8_t remote[duct_noise_key_size],
                       uint8_t out[duct_noise_key_size])
{
    memcpy(out, ctx, duct_noise_key_size);
    return true;
}

/** @brief The responder's handshake under the pattern of the run. */
static duct_noise_hs_t *nd_resp_new(const duct_noise_keypair_t *srv_kp, const uint8_t *psk)
{
    return duct_noise_hs_create_for(g_pattern, srv_kp, nullptr, psk, false, (duct_view_u8){});
}

/** @brief The responder reads message 1. */
static bool nd_resp_read1(duct_noise_hs_t *hs, duct_view_u8 msg)
{
    uint8_t learned[duct_noise_key_size],
            offer[duct_noise_hs_pad_max];
    size_t offer_len = 0u;
    return g_pattern == noise_pattern_xkpsk3
         ? duct_noise_hs_read_msg1_xk(hs, msg, offer, sizeof offer, &offer_len)
         : duct_noise_hs_read_msg1(hs, msg, learned, offer, sizeof offer, &offer_len);
}

/** @brief The responder writes message 2 around no payload. */
static bool nd_resp_write2(duct_noise_hs_t *hs, uint8_t *out, size_t cap, size_t *len)
{
    return g_pattern == noise_pattern_xkpsk3
         ? duct_noise_hs_write_msg2_xk(hs, (duct_view_u8){}, out, cap, len)
         : duct_noise_hs_write_msg2(hs, (duct_view_u8){}, out, cap, len);
}

/** @brief Under XKpsk3 take message 3 off @p fd, each PDU leading with @p prefix
 *  bytes of length, and read it; IKpsk2 ended with message 2.
 *  @return nullptr when the handshake is over, else what failed. */
static const char *nd_resp_last(duct_sock_t fd, duct_noise_hs_t *hs, const uint8_t *psk,
                                size_t prefix, struct sockaddr_in *peer)
{
    if (g_pattern != noise_pattern_xkpsk3)
        return nullptr;
    uint8_t buf[512],
            learned[duct_noise_key_size],
            offer[duct_noise_hs_pad_max];
    size_t offer_len = 0u;
    ssize_t got = nd_peer_recv(fd, buf, sizeof buf, peer);
    if (got < (ssize_t)prefix || (prefix != 0u && nd_get_len(buf) != (size_t)got - prefix))
        return "message 3 never arrived as one framed datagram";
    return duct_noise_hs_read_msg3_xk(hs, (duct_view_u8){ buf + prefix, (size_t)got - prefix },
                                      nd_psk_for, (void *)psk, learned, offer, sizeof offer,
                                      &offer_len)
         ? nullptr : "read_msg3 failed";
}

/** @brief Check that a forged datagram costs only itself.
 *
 *  The responder is written out by hand because a duct server never produces
 *  the one datagram this is about: framing the engine accepts, contents that
 *  authenticate as nothing. Anyone able to send from the server's address can
 *  produce it, so a conn that dies on it is a conn anyone can end. It matches
 *  the wire's control rule and arrives past the handshake.
 *
 *  The proof is the protocol seeing exactly the good record's bytes after it:
 *  a close ends the conn before them, and a forgery reaching the protocol adds
 *  its own.
 *
 *  The conn stays open past the scenario, so its protocol goes to @p keep for
 *  main to release once the engine stops, and its wire borrows @p cfg.
 */
static const char *nd_forgery(duct_engine_t *io, const duct_noise_keypair_t *srv_kp,
                              duct_noise_cfg_t *cfg, const uint8_t *psk, duct_proto_t **keep)
{
    uint16_t port = 0u;
    duct_sock_t fd = uc_bind(&port);
    if (fd == duct_sock_bad)
        return "forgery probe socket failed";

    const char *err = nullptr;
    duct_proto_t *proto = nullptr;
    duct_noise_transport_t tp = {};
    duct_noise_hs_t *hs = nullptr;
    uint8_t buf[512];
    struct sockaddr_in peer = {};
    ssize_t got = 0;
    size_t len = 0u;
    char addr[64];
    static const char probe[] = "still-here";
    static const nd_ctl_rule_t forged_rule = { nd_ctl, 1u + nd_prefix + nd_forged };

    auto wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .engine = duct_noise_vtbl(), .engine_cfg = cfg,
        .role = seal_role_initiator, .framing = seal_framing_datagram,
        .rx_prefix_len = 1u, .rx_ctl = nd_ctl_rx, .rx_ctl_ctx = (void *)&forged_rule });
    if (!wire) { err = "forgery wire create failed"; goto done; }
    proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "noise-dgram-forge", .wire = wire,
        .on_frame = nd_forge_frame,
        .on_session_open = nd_forge_open,
        .on_session_close = nd_forge_close,
        .max_response = 2048u,
    });
    if (proto)
        proto->owned_wire = wire;
    else
        duct_wire_destroy(wire);
    if (!proto) { err = "forgery proto create failed"; goto done; }
    *keep = proto;

    snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)port);
    if (duct_io_connect(io, addr, proto, nullptr, x_udp_peer) != rc_ok) {
        err = "forgery client connect failed";
        goto done;
    }

    got = nd_peer_recv(fd, buf, sizeof buf, &peer);
    if (got < (ssize_t)nd_prefix || nd_get_len(buf) != (size_t)got - nd_prefix) {
        err = "message 1 never arrived as one framed datagram";
        goto done;
    }
    hs = nd_resp_new(srv_kp, psk);
    if (!hs) { err = "responder handshake create failed"; goto done; }
    if (!nd_resp_read1(hs, (duct_view_u8){ buf + nd_prefix, (size_t)got - nd_prefix })) {
        err = "read_msg1 failed";
        goto done;
    }
    if (!nd_resp_write2(hs, buf + 1u + nd_prefix, sizeof buf - 1u - nd_prefix, &len)) {
        err = "write_msg2 failed";
        goto done;
    }
    buf[0] = 0u;
    nd_put_len(buf + 1u, len);
    if (sendto(fd, (char *)buf, (int)(1u + nd_prefix + len), 0,
               (struct sockaddr *)&peer, sizeof peer) < 0) {
        err = "message 2 send failed";
        goto done;
    }
    err = nd_resp_last(fd, hs, psk, nd_prefix, &peer);
    if (err) goto done;
    if (!duct_noise_hs_split(hs, &tp)) { err = "responder split failed"; goto done; }
    duct_noise_hs_destroy(hs);
    hs = nullptr;

    got = nd_peer_recv(fd, buf, sizeof buf, &peer);
    if (got < (ssize_t)nd_prefix) { err = "client's first payload never arrived"; goto done; }

    {
        uint8_t junk[nd_forged];
        memset(junk, 0xA5, sizeof junk);
        buf[0] = nd_ctl;
        nd_put_len(buf + 1u, sizeof junk);
        memcpy(buf + 1u + nd_prefix, junk, sizeof junk);
        if (sendto(fd, (char *)buf, (int)(1u + nd_prefix + sizeof junk), 0,
                   (struct sockaddr *)&peer, sizeof peer) < 0) {
            err = "forged datagram send failed";
            goto done;
        }
    }

    {
        size_t sealed = duct_noise_transport_seal(&tp,
            &(duct_view_u8){ (void *)probe, sizeof probe - 1u }, 1u,
            buf + 1u + nd_prefix, sizeof buf - 1u - nd_prefix);
        if (!sealed) { err = "probe seal failed"; goto done; }
        buf[0] = 0u;
        nd_put_len(buf + 1u, sealed);
        if (sendto(fd, (char *)buf, (int)(1u + nd_prefix + sealed), 0,
                   (struct sockaddr *)&peer, sizeof peer) < 0) {
            err = "probe send failed";
            goto done;
        }
    }
    if (!th_wait_int(&g_forge_bytes, (int)(sizeof probe - 1u), 5000u))
        err = "a forged datagram took the conn down with it or reached the protocol";
    else if (atomic_load_explicit(&g_forge_closed, memory_order_acquire) != 0)
        err = "the session closed even though the good record arrived";

done:
    duct_noise_hs_destroy(hs);
    duct_noise_transport_destroy(&tp);
    duct_sock_close(fd);
    return err;
}

/** @brief Reserve the codec's cleartext buffer past what it holds. */
static void *nd_ctl_reserve(duct_unseal_ctx_t *self, size_t *out_cap)
{
    *out_cap = duct_byte_len(self->codec->ct_buf) - self->codec->ct_len;
    return duct_at(self->codec->ct_buf) + self->codec->ct_len;
}

/** @brief Publish @p len reserved bytes as the codec's cleartext. */
static bool nd_ctl_commit(duct_unseal_ctx_t *self, size_t len)
{
    self->codec->ct_len += (uint32_t)len;
    return true;
}

/** @brief Check which framings take a control rule.
 *
 *  A datagram wire is built with a rule or without one, a stream wire only
 *  without.
 *  @return nullptr when every config was taken or refused as it must be, else
 *  what failed. */
static const char *nd_ctl_cfg(duct_noise_cfg_t *cfg)
{
    static const nd_ctl_rule_t rule = { nd_ctl, sizeof nd_ctl_msg };
    static const struct {
        duct_seal_framing_t framing;
        duct_seal_ctl_fn    rx_ctl;
        bool                admitted;
    } cases[] = {
        { seal_framing_datagram, nd_ctl_rx, true  },
        { seal_framing_datagram, nullptr,   true  },
        { seal_framing_stream,   nullptr,   true  },
        { seal_framing_stream,   nd_ctl_rx, false },
    };
    for (size_t i = 0u; i < sizeof cases / sizeof *cases; ++i) {
        auto w = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .engine = duct_noise_vtbl(), .engine_cfg = cfg,
            .role = seal_role_initiator, .framing = cases[i].framing,
            .rx_ctl = cases[i].rx_ctl, .rx_ctl_ctx = (void *)&rule });
        bool admitted = w != nullptr;
        if (w)
            duct_wire_destroy(w);
        if (admitted != cases[i].admitted)
            return cases[i].admitted ? "a control rule config the wire must take was refused"
                                     : "a control rule config the wire must refuse was taken";
    }
    return nullptr;
}

/** @brief Unseal a control payload before any key and read it back as one
 *  inner frame.
 *
 *  A datagram of another size that leads with the same byte is no control
 *  datagram: the engine takes it, refuses it, and nothing reaches the protocol.
 */
static const char *nd_ctl_framing(duct_noise_cfg_t *cfg)
{
    auto err = nd_ctl_cfg(cfg);
    if (err)
        return err;
    static const nd_ctl_rule_t rule = { nd_ctl, sizeof nd_ctl_msg };
    auto inner = duct_wire_create_length_prefix(0u);
    auto w = inner ? duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .inner = inner, .engine = duct_noise_vtbl(), .engine_cfg = cfg,
        .role = seal_role_initiator, .framing = seal_framing_datagram,
        .rx_ctl = nd_ctl_rx, .rx_ctl_ctx = (void *)&rule }) : nullptr;
    auto codec = w ? w->create_codec(w, x_udp_peer) : nullptr;
    err = codec ? nullptr : "control framing wire create failed";
    if (!err) {
        uint8_t pdu[sizeof nd_ctl_msg] = { nd_ctl };
        memcpy(pdu + 1u, nd_ctl_msg, sizeof nd_ctl_msg - 1u);
        duct_unseal_ctx_t ctx = { .codec = codec, .reserve = nd_ctl_reserve,
                                  .commit = nd_ctl_commit };
        duct_frame_t frame = {};
        size_t consumed = 0u,
               needed = 0u;
        if (w->unseal(w, codec, (duct_view_u8){ pdu, sizeof pdu }, &ctx) != rc_ok
            || inner->on_parse(inner, (duct_view_u8){ duct_at(codec->ct_buf), codec->ct_len }, &frame,
                               codec->inner_parser, &consumed, &needed) != rc_ok
            || consumed != codec->ct_len
            || frame.payload.size != sizeof nd_ctl_msg - 1u
            || memcmp(frame.payload.data, nd_ctl_msg, frame.payload.size) != 0)
            err = "a control payload before the keys did not arrive as one whole frame";
        /* One byte shorter and one byte longer, the same first byte: neither is
         * control, so neither reaches the protocol. */
        uint8_t longer[sizeof pdu + 1u];
        memcpy(longer, pdu, sizeof pdu);
        longer[sizeof pdu] = 0x5au;
        for (unsigned side = 0u; !err && side < 2u; ++side) {
            codec->ct_len = 0u;
            codec->ct_parse_off = 0u;
            duct_view_u8 other = side ? (duct_view_u8){ longer, sizeof longer }
                                    : (duct_view_u8){ pdu, sizeof pdu - 1u };
            if (w->unseal(w, codec, other, &ctx) == rc_ok || codec->ct_len != 0u)
                err = "a datagram of another size than the control datagram's was taken for one";
        }
    }
    if (codec)
        codec->destroy(codec);
    if (w)
        duct_wire_destroy(w);
    if (inner)
        duct_wire_destroy(inner);
    return err;
}

static atomic_int g_inner_srv = -1;
static atomic_int g_inner_cli = -1;

static const char nd_inner_hello[] = "inner-framed-hello";

/** @brief True when @p frame carries exactly the inner-framed hello. */
static bool nd_inner_is_hello(const duct_frame_t *frame)
{
    return frame->payload.size == sizeof nd_inner_hello - 1u
        && memcmp(frame->payload.data, nd_inner_hello, sizeof nd_inner_hello - 1u) == 0;
}

/** @brief The inner-framed client's opening payload, sent with @c fl_frame_gso. */
static duct_result_t
nd_inner_cli_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                  [[maybe_unused]] void *user_ctx, duct_response_t *out,
                  [[maybe_unused]] void *proto_state)
{
    out->payload = (duct_view_u8){ (void *)nd_inner_hello, sizeof nd_inner_hello - 1u };
    out->flags = fl_send_copy;
    out->frame_flags = fl_frame_gso;
    return rc_ok;
}

/** @brief Record the flags the echo of the hello arrived with. */
static duct_result_t
nd_inner_cli_frame([[maybe_unused]] duct_session_t *s,
                   [[maybe_unused]] duct_conn_id_t conn_id,
                   const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
                   [[maybe_unused]] void *proto_state)
{
    if (nd_inner_is_hello(frame))
        atomic_store_explicit(&g_inner_cli, (int)frame->flags, memory_order_release);
    return rc_ok;
}

/** @brief Record the flags the hello arrived with and echo it under them. */
static duct_result_t
nd_inner_srv_frame([[maybe_unused]] duct_session_t *s,
                   [[maybe_unused]] duct_conn_id_t conn_id,
                   const duct_frame_t *frame, duct_response_t *out,
                   [[maybe_unused]] void *proto_state)
{
    if (nd_inner_is_hello(frame))
        atomic_store_explicit(&g_inner_srv, (int)frame->flags, memory_order_release);
    duct_response_same(out, frame->payload, fl_send_copy, frame->flags);
    return rc_ok;
}

/** @brief Build the protocol @p pcfg describes over a datagram-framed sealed
 *  wire of @p engine on @p inner, the protocol owning that wire.
 *  @p ceiling is the wire's opening ceiling, 0 for none.
 *  @return the protocol, or nullptr with the wire already destroyed. */
static duct_proto_t *nd_inner_proto(const duct_seal_engine_vtbl_t *engine,
                                    const duct_wire_t *inner, duct_noise_cfg_t *cfg,
                                    duct_seal_role_t role, duct_proto_cfg_t pcfg,
                                    uint16_t ceiling)
{
    auto wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .inner = inner, .engine = engine, .engine_cfg = cfg,
        .role = role, .framing = seal_framing_datagram, .opening_ceiling = ceiling });
    if (!wire)
        return nullptr;
    pcfg.wire = wire;
    auto proto = duct_proto_create(&pcfg);
    if (proto)
        proto->owned_wire = wire;
    else
        duct_wire_destroy(wire);
    return proto;
}

/** @brief What nd_inner builds and main releases after the engine stops: the
 *  runtime borrows both protocols until then, and their wires borrow the rest. */
typedef struct {
    duct_wire_t      *inner;
    duct_proto_t     *srv,
                     *cli;
    duct_noise_cfg_t  srv_cfg,
                      cli_cfg;
} nd_inner_t;

/** @brief Echo one @c fl_frame_gso frame between an inner-framed shared listener
 *  and an inner-framed x_udp_peer client.
 *  @return nullptr on success, else what failed. */
static const char *nd_inner(duct_engine_t *io, const duct_noise_keypair_t *srv_kp,
                            const duct_noise_keypair_t *cli_kp, nd_inner_t *keep)
{
    keep->srv_cfg = (duct_noise_cfg_t){ .local_static = *srv_kp, .suite.pattern = g_pattern };
    keep->cli_cfg = (duct_noise_cfg_t){ .local_static = *cli_kp, .suite.pattern = g_pattern };
    memcpy(keep->cli_cfg.remote_static_pub, srv_kp->pub, duct_noise_key_size);
    keep->inner = duct_wire_create_length_prefix(0u);
    keep->srv = keep->inner
        ? nd_inner_proto(duct_noise_vtbl(), keep->inner, &keep->srv_cfg,
                         seal_role_responder, (duct_proto_cfg_t){
              .name = "noise-dgram-inner", .on_frame = nd_inner_srv_frame,
              .max_response = 2048u, .flags = fl_proto_dgram_shared }, 0u)
        : nullptr;
    keep->cli = keep->srv
        ? nd_inner_proto(duct_noise_vtbl(), keep->inner, &keep->cli_cfg,
                         seal_role_initiator, (duct_proto_cfg_t){
              .name = "noise-dgram-inner-cli", .on_frame = nd_inner_cli_frame,
              .on_session_open = nd_inner_cli_open, .max_response = 2048u }, 0u)
        : nullptr;
    if (!keep->cli)
        return "inner-framed sealed protocols did not build";
    uint16_t port = 0u;
    if (duct_listener_bind(io, &(duct_listener_cfg_t){
            .kind = listener_dgram, .addr = "127.0.0.1",
            .n_protos = 1, .protos = (const duct_proto_t *[]){ keep->srv },
        }, &port, nullptr, 0u, nullptr) != rc_ok)
        return "inner-framed sealed wire refused on a datagram listener";
    char addr[64];
    snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)port);
    if (duct_io_connect(io, addr, keep->cli, nullptr, x_udp_peer) != rc_ok)
        return "inner-framed client connect failed";
    if (!th_wait_int(&g_inner_srv, (int)fl_frame_gso, 5000u))
        return atomic_load_explicit(&g_inner_srv, memory_order_acquire) == -1
             ? "a shared-listener datagram lost its frame inside the inner header"
             : "a shared-listener datagram lost its inner frame flags";
    if (!th_wait_int(&g_inner_cli, (int)fl_frame_gso, 5000u))
        return "the echo lost its inner frame or flags on the peer socket";
    return nullptr;
}

static constexpr size_t   nd_open_size    = 1000u;
static constexpr uint16_t nd_open_ceiling = 1200u;

/** @brief Lengths of the packets the source hands out; the last fills the
 *  ceiling. */
static const size_t nd_open_len[] = { 64u, 120u, 33u, 700u, nd_open_ceiling };
static constexpr unsigned nd_open_n = sizeof nd_open_len / sizeof *nd_open_len;

/** @brief Byte @p j of the source's packet @p idx.
 *  The first two bytes of every packet read as a length above any datagram the
 *  test receives, so none passes for a framed PDU. */
static uint8_t nd_open_byte(unsigned idx, size_t j)
{
    return (uint8_t)(0xC0u + 41u * idx + 3u * j);
}

/** @brief The client's opening source: packet @p idx into @p out.
 *  @return its length, 0 past the last packet or where it does not fit @p cap. */
static size_t nd_open_next([[maybe_unused]] void *ctx, unsigned idx, uint8_t *out, size_t cap)
{
    if (idx >= nd_open_n || nd_open_len[idx] > cap)
        return 0u;
    for (size_t j = 0u; j < nd_open_len[idx]; ++j)
        out[j] = nd_open_byte(idx, j);
    return nd_open_len[idx];
}

/** @brief True when the @p len bytes at @p dgram are the source's packet @p idx,
 *  whole. */
static bool nd_open_match(unsigned idx, const uint8_t *dgram, size_t len)
{
    if (idx >= nd_open_n || len != nd_open_len[idx])
        return false;
    for (size_t j = 0u; j < len; ++j)
        if (dgram[j] != nd_open_byte(idx, j))
            return false;
    return true;
}

/** @brief Fill @p p with the frame's byte pattern. */
static void nd_open_fill(uint8_t *p, size_t n)
{
    for (size_t i = 0u; i < n; ++i)
        p[i] = (uint8_t)(i * 7u + 3u);
}

/** @brief The opening client's first payload: the pattern frame. */
static duct_result_t
nd_open_first([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
              [[maybe_unused]] void *user_ctx, duct_response_t *out,
              [[maybe_unused]] void *proto_state)
{
    static uint8_t body[nd_open_size];
    nd_open_fill(body, sizeof body);
    out->payload = (duct_view_u8){ body, sizeof body };
    out->flags = fl_send_copy;
    return rc_ok;
}

static duct_result_t
nd_open_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
              [[maybe_unused]] const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
              [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

/** @brief Take the pattern frame off @p fd, skipping the initiator's key
 *  confirmation, an empty PDU.
 *  @return nullptr when the first PDU with content unseals to the pattern frame,
 *  else what failed. */
static const char *nd_open_recv(duct_sock_t fd, duct_noise_transport_t *tp)
{
    uint8_t dgram[2048],
            plain[2048],
            want[nd_open_size];
    for (;;) {
        ssize_t n = uc_recv(fd, (char *)dgram, sizeof dgram);
        if (n < (ssize_t)nd_prefix || nd_get_len(dgram) != (size_t)n - nd_prefix)
            return "a datagram did not arrive as one framed PDU";
        size_t plen = 0u;
        if (!duct_noise_transport_unseal(tp, (duct_view_u8){ dgram + nd_prefix, (size_t)n - nd_prefix },
                                         plain, sizeof plain, &plen))
            return "a datagram did not unseal";
        if (!plen)
            continue;
        nd_open_fill(want, sizeof want);
        return plen == sizeof want && memcmp(plain, want, sizeof want) == 0
             ? nullptr : "the first frame arrived altered";
    }
}

/** @brief Hand-driven responder to a real client with an opening source: check
 *  the datagrams ahead of message 1 against the source, answer the handshake and
 *  check the client's first frame.
 *  @return nullptr on success, else what failed. */
static const char *nd_open_from(duct_engine_t *io, duct_proto_t *cli,
                                const duct_noise_keypair_t *srv_kp, const uint8_t *psk)
{
    uint16_t port = 0u;
    duct_sock_t fd = uc_bind(&port);
    if (fd == duct_sock_bad)
        return "opening responder socket failed";

    const char *err = nullptr;
    duct_noise_hs_t *hs = nullptr;
    duct_noise_transport_t tp = {};
    struct sockaddr_in peer = {};
    uint8_t buf[2048];
    ssize_t got = 0;
    size_t len = 0u;
    unsigned lead_n = 0u;
    char addr[64];

    snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)port);
    if (duct_io_connect(io, addr, cli, nullptr, x_udp_peer) != rc_ok) {
        err = "opening client connect failed";
        goto done;
    }
    for (;;) {
        got = nd_peer_recv(fd, buf, sizeof buf, &peer);
        if (got < 0) {
            err = "message 1 never arrived";
            goto done;
        }
        if (got >= (ssize_t)nd_prefix && nd_get_len(buf) == (size_t)got - nd_prefix)
            break;
        if (!nd_open_match(lead_n++, buf, (size_t)got)) {
            err = "a datagram ahead of message 1 is not the opening source's, bare and whole";
            goto done;
        }
    }
    if (lead_n != nd_open_n) {
        err = "the datagrams ahead of message 1 are not all the opening source's";
        goto done;
    }
    hs = nd_resp_new(srv_kp, psk);
    if (!hs) { err = "responder handshake create failed"; goto done; }
    if (!nd_resp_read1(hs, (duct_view_u8){ buf + nd_prefix, (size_t)got - nd_prefix })) {
        err = "read_msg1 failed";
        goto done;
    }
    if (!nd_resp_write2(hs, buf + nd_prefix, sizeof buf - nd_prefix, &len)) {
        err = "write_msg2 failed";
        goto done;
    }
    nd_put_len(buf, len);
    if (sendto(fd, (char *)buf, (int)(nd_prefix + len), 0,
               (struct sockaddr *)&peer, sizeof peer) < 0) {
        err = "message 2 send failed";
        goto done;
    }
    err = nd_resp_last(fd, hs, psk, nd_prefix, &peer);
    if (err) goto done;
    if (!duct_noise_hs_split(hs, &tp)) { err = "responder split failed"; goto done; }
    if (connect(fd, (struct sockaddr *)&peer, sizeof peer) != 0) {
        err = "responder connect failed";
        goto done;
    }
    err = nd_open_recv(fd, &tp);

done:
    duct_noise_hs_destroy(hs);
    duct_noise_transport_destroy(&tp);
    duct_sock_close(fd);
    return err;
}

/** @brief What nd_open builds and main releases after the engine stops: the
 *  client's protocol, whose wire borrows @c cli_cfg. */
typedef struct {
    duct_proto_t     *cli;
    duct_noise_cfg_t  cli_cfg;
} nd_open_t;

/** @brief Dial a hand-driven responder with a client whose config names an
 *  opening source and whose wire has an opening ceiling.
 *  @return nullptr on success, else what failed. */
static const char *nd_open(duct_engine_t *io, const duct_noise_keypair_t *srv_kp,
                           const duct_noise_keypair_t *cli_kp, const uint8_t *psk,
                           nd_open_t *keep)
{
    keep->cli_cfg = (duct_noise_cfg_t){ .local_static = *cli_kp, .opening_next = nd_open_next,
                                        .suite.pattern = g_pattern };
    memcpy(keep->cli_cfg.remote_static_pub, srv_kp->pub, duct_noise_key_size);
    keep->cli = nd_inner_proto(duct_noise_vtbl(), nullptr, &keep->cli_cfg,
                               seal_role_initiator, (duct_proto_cfg_t){
        .name = "noise-dgram-open-cli", .on_frame = nd_open_frame,
        .on_session_open = nd_open_first, .max_response = 2048u }, nd_open_ceiling);
    if (!keep->cli)
        return "opening protocol did not build";
    return nd_open_from(io, keep->cli, srv_kp, psk);
}

/** @brief The hand-driven client: one handshake, then three sealed rounds. */
static const char *nd_run(uint16_t port,
                          const duct_noise_keypair_t *cli_kp,
                          const uint8_t *srv_pub, const uint8_t *psk)
{
    duct_sock_t fd = uc_connect(port);
    if (fd == duct_sock_bad)
        return "client socket failed";

    const char *err = nullptr;
    duct_noise_transport_t tp = {};
    uint8_t buf[512];
    ssize_t got = 0;
    size_t len = 0u;

    bool xk = g_pattern == noise_pattern_xkpsk3;
    auto hs = duct_noise_hs_create_for(g_pattern, cli_kp, srv_pub, psk, true, (duct_view_u8){});
    if (!hs) { err = "handshake create failed"; goto done; }

    if (!(xk ? duct_noise_hs_write_msg1_xk(hs, (duct_view_u8){}, buf + nd_prefix,
                                           sizeof buf - nd_prefix, &len)
             : duct_noise_hs_write_msg1(hs, (duct_view_u8){}, buf + nd_prefix,
                                        sizeof buf - nd_prefix, &len))) {
        err = "write_msg1 failed";
        goto done;
    }
    nd_put_len(buf, len);
    if (uc_send(fd, buf, nd_prefix + len) != 0) { err = "msg1 send failed"; goto done; }

    got = uc_recv(fd, (char *)buf, sizeof buf);
    if (got < (ssize_t)nd_prefix
        || nd_get_len(buf) != (size_t)got - nd_prefix) {
        err = "message 2 not received as one framed datagram";
        goto done;
    }
    {
        duct_view_u8 msg2 = { buf + nd_prefix, (size_t)got - nd_prefix };
        if (!(xk ? duct_noise_hs_read_msg2_xk(hs, msg2) : duct_noise_hs_read_msg2(hs, msg2))) {
            err = "read_msg2 failed";
            goto done;
        }
    }
    if (xk) {
        if (!duct_noise_hs_write_msg3_xk(hs, (duct_view_u8){}, buf + nd_prefix,
                                         sizeof buf - nd_prefix, &len)) {
            err = "write_msg3 failed";
            goto done;
        }
        nd_put_len(buf, len);
        if (uc_send(fd, buf, nd_prefix + len) != 0) { err = "msg3 send failed"; goto done; }
    }
    if (!duct_noise_hs_split(hs, &tp)) { err = "split failed"; goto done; }
    duct_noise_hs_destroy(hs);
    hs = nullptr;

    for (unsigned round = 0u; round < 3u; ++round) {
        char plain[32];
        int plen = snprintf(plain, sizeof plain, "dgram-round-%u", round);
        size_t sealed = duct_noise_transport_seal(&tp,
            &(duct_view_u8){ plain, (size_t)plen }, 1u, buf + nd_prefix,
            sizeof buf - nd_prefix);
        if (!sealed) { err = "seal failed"; goto done; }
        nd_put_len(buf, sealed);
        if (uc_send(fd, buf, nd_prefix + sealed) != 0) {
            err = "sealed send failed";
            goto done;
        }
        got = uc_recv(fd, (char *)buf, sizeof buf);
        if (got < (ssize_t)nd_prefix
            || nd_get_len(buf) != (size_t)got - nd_prefix) {
            err = "echo not received as one framed datagram";
            goto done;
        }
        char back[64];
        size_t back_len = 0u;
        if (!duct_noise_transport_unseal(&tp,
                (duct_view_u8){ buf + nd_prefix, (size_t)got - nd_prefix },
                (uint8_t *)back, sizeof back, &back_len)) {
            err = "echo unseal failed";
            goto done;
        }
        if (back_len != (size_t)plen || memcmp(back, plain, back_len) != 0) {
            err = "echo cleartext mismatch";
            goto done;
        }
    }

    if (!th_wait_int(&g_srv_frames, 3, 3000u)) {
        err = "server did not see three cleartext frames";
        goto done;
    }

    /* Past the sealed wire's own max_frame, so the io side drops it before any
     * lane reservation. on_error staying at zero is what separates that from
     * the datagram reaching unseal and being refused there: both leave the
     * session alive, only one spends a lane slot on garbage. */
    {
        static constexpr size_t oversize = 40000u;
#ifdef __APPLE__
        /* Darwin's UDP send buffer starts at net.inet.udp.maxdgram, 9216, and
         * send() refuses a larger datagram with EMSGSIZE. Raised past it, the
         * datagram leaves in fragments that lo0 reassembles for the io side. */
        int sndbuf = 65536;
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf) != 0) {
            err = "raising the client's send buffer failed";
            goto done;
        }
#endif
        auto junk = duct_at(duct_new(char, oversize));
        if (!junk) { err = "oversize buffer alloc failed"; goto done; }
        memset(junk, 0x5A, oversize);
        int sent = uc_send(fd, junk, oversize);
        duct_del(junk);
        if (sent != 0) { err = "oversize send failed"; goto done; }
    }

    {
        static const char after[] = "after-oversize";
        size_t sealed = duct_noise_transport_seal(&tp,
            &(duct_view_u8){ (void *)after, sizeof after - 1u }, 1u,
            buf + nd_prefix, sizeof buf - nd_prefix);
        if (!sealed) { err = "post-oversize seal failed"; goto done; }
        nd_put_len(buf, sealed);
        if (uc_send(fd, buf, nd_prefix + sealed) != 0) {
            err = "post-oversize send failed";
            goto done;
        }
    }
    if (!th_wait_int(&g_srv_frames, 4, 3000u))
        err = "an oversize datagram took the session down with it";
    else if (atomic_load_explicit(&g_srv_errors, memory_order_acquire) != 0)
        err = "an oversize datagram reached unseal instead of being dropped on io";

done:
    duct_noise_hs_destroy(hs);
    duct_noise_transport_destroy(&tp);
    duct_sock_close(fd);
    return err;
}

/** @brief Pin the datagram vtbl against the stream one.
 *
 *  The two hold the same cleartext per PDU under the same flags and handshake
 *  budget; the datagram one has no length prefix and its overhead is smaller by
 *  the counter's narrowing alone. A stream wire is refused it, and a datagram
 *  wire charges a PDU no prefix.
 *  @return nullptr when each held, else what failed. */
static const char *nd_dgram_vtbl(duct_noise_cfg_t *cfg)
{
    auto stream_vt = duct_noise_vtbl();
    auto dgram_vt = duct_noise_vtbl_dgram();
    if (dgram_vt->pdu_hdr_size != 0u || dgram_vt->pdu_len)
        return "the datagram engine still carries a length prefix of its own";
    if (dgram_vt->pdu_overhead + (duct_noise_counter_size - duct_noise_counter_compact_size)
            != stream_vt->pdu_overhead
        || dgram_vt->pdu_ct_max != stream_vt->pdu_ct_max
        || dgram_vt->flags != stream_vt->flags
        || dgram_vt->engine_hs_budget != stream_vt->engine_hs_budget)
        return "the two framings of the engine disagree on what a PDU holds";

    auto stream = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .engine = dgram_vt, .engine_cfg = cfg,
        .role = seal_role_initiator, .framing = seal_framing_stream });
    if (stream) {
        duct_wire_destroy(stream);
        return "a stream wire was built on an engine that cuts no PDU";
    }
    auto dgram = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .engine = dgram_vt, .engine_cfg = cfg,
        .role = seal_role_initiator, .framing = seal_framing_datagram });
    if (!dgram)
        return "a datagram wire was refused the datagram engine";
    const char *err = nullptr;
    if (dgram->tx_bound(dgram, 1u) != 1u + dgram_vt->pdu_overhead)
        err = "a datagram PDU is charged a length prefix it does not carry";
    else if (dgram->tx_bound(dgram, dgram_vt->pdu_ct_max) == SIZE_MAX)
        err = "one whole PDU of cleartext was refused on the datagram engine";
    else if (dgram->tx_bound(dgram, dgram_vt->pdu_ct_max + 1u) != SIZE_MAX)
        err = "the datagram engine accepted cleartext that spans two PDUs";
    duct_wire_destroy(dgram);
    return err;
}

/** @brief What nd_dgram builds and main releases after the engine stops: the
 *  runtime borrows the protocols until then, and their wires borrow the
 *  configs. */
typedef struct {
    duct_proto_t     *hand,
                     *srv,
                     *cli;
    duct_noise_cfg_t  hand_cfg,
                      srv_cfg,
                      cli_cfg;
} nd_dgram_t;

/** @brief Check the datagram engine's bytes against a hand-written responder
 *  that holds only the Noise primitives.
 *
 *  Message 1 and the client's first payload parse bare, and the echo sealed bare
 *  reaches the client.
 *  @return nullptr on success, else what failed. */
static const char *nd_dgram_hand(duct_engine_t *io, const duct_noise_keypair_t *srv_kp,
                                 const uint8_t *psk, nd_dgram_t *keep)
{
    uint16_t port = 0u;
    duct_sock_t fd = uc_bind(&port);
    if (fd == duct_sock_bad)
        return "datagram engine probe socket failed";

    const char *err = nullptr;
    duct_noise_hs_t *hs = nullptr;
    duct_noise_transport_t tp = {};
    struct sockaddr_in peer = {};
    uint8_t buf[512],
            plain[512];
    ssize_t got = 0;
    size_t len = 0u,
           plen = 0u;
    char addr[64];
    int want = atomic_load_explicit(&g_cli_echo, memory_order_acquire) + 1;

    keep->hand = nd_inner_proto(duct_noise_vtbl_dgram(), nullptr, &keep->hand_cfg,
                                seal_role_initiator, (duct_proto_cfg_t){
        .name = "noise-dgram-hand", .on_frame = nd_cli_frame,
        .on_session_open = nd_cli_open, .max_response = 2048u }, 0u);
    if (!keep->hand) { err = "datagram engine client proto create failed"; goto done; }
    snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)port);
    if (duct_io_connect(io, addr, keep->hand, nullptr, x_udp_peer) != rc_ok) {
        err = "datagram engine client connect failed";
        goto done;
    }

    got = nd_peer_recv(fd, buf, sizeof buf, &peer);
    hs = nd_resp_new(srv_kp, psk);
    if (!hs) { err = "responder handshake create failed"; goto done; }
    if (got <= 0 || !nd_resp_read1(hs, (duct_view_u8){ buf, (size_t)got })) {
        err = "message 1 did not parse as the bare datagram";
        goto done;
    }
    if (!nd_resp_write2(hs, buf, sizeof buf, &len)
        || sendto(fd, (char *)buf, (int)len, 0, (struct sockaddr *)&peer, sizeof peer) < 0) {
        err = "message 2 send failed";
        goto done;
    }
    err = nd_resp_last(fd, hs, psk, 0u, &peer);
    if (err) goto done;
    if (!duct_noise_hs_split(hs, &tp)) { err = "responder split failed"; goto done; }
    /* The datagram form leads its PDU with the counter's low four bytes. */
    tp.counter_size = duct_noise_counter_compact_size;

    do {
        got = nd_peer_recv(fd, buf, sizeof buf, &peer);
        if (got <= 0
            || !duct_noise_transport_unseal(&tp, (duct_view_u8){ buf, (size_t)got },
                                            plain, sizeof plain, &plen)) {
            err = "a datagram did not unseal as one bare PDU";
            goto done;
        }
    } while (!plen);
    if (plen != sizeof nd_cli_hello - 1u || memcmp(plain, nd_cli_hello, plen) != 0) {
        err = "the client's first payload came out altered";
        goto done;
    }
    len = duct_noise_transport_seal(&tp, &(duct_view_u8){ plain, plen }, 1u, buf, sizeof buf);
    if (!len || sendto(fd, (char *)buf, (int)len, 0, (struct sockaddr *)&peer,
                       sizeof peer) < 0) {
        err = "echo send failed";
        goto done;
    }
    if (!th_wait_int(&g_cli_echo, want, 5000u))
        err = "the client did not read an echo sealed without a length prefix";

done:
    duct_noise_hs_destroy(hs);
    duct_noise_transport_destroy(&tp);
    duct_sock_close(fd);
    return err;
}

/** @brief Round-trip one frame between the datagram engine's own two ends: a
 *  client under x_udp_peer and a server on a shared listener.
 *  @return nullptr on success, else what failed. */
static const char *nd_dgram_pair(duct_engine_t *io, nd_dgram_t *keep)
{
    keep->srv = nd_inner_proto(duct_noise_vtbl_dgram(), nullptr, &keep->srv_cfg,
                               seal_role_responder, (duct_proto_cfg_t){
        .name = "noise-dgram-engine", .on_frame = nd_on_frame,
        .max_response = 2048u, .flags = fl_proto_dgram_shared }, 0u);
    keep->cli = keep->srv
        ? nd_inner_proto(duct_noise_vtbl_dgram(), nullptr, &keep->cli_cfg,
                         seal_role_initiator, (duct_proto_cfg_t){
              .name = "noise-dgram-engine-cli", .on_frame = nd_cli_frame,
              .on_session_open = nd_cli_open, .max_response = 2048u }, 0u)
        : nullptr;
    if (!keep->cli)
        return "datagram engine protocols did not build";
    uint16_t port = 0u;
    if (duct_listener_bind(io, &(duct_listener_cfg_t){
            .kind = listener_dgram, .addr = "127.0.0.1",
            .n_protos = 1, .protos = (const duct_proto_t *[]){ keep->srv },
        }, &port, nullptr, 0u, nullptr) != rc_ok)
        return "the datagram engine was refused on a datagram listener";
    char addr[64];
    snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)port);
    int want = atomic_load_explicit(&g_cli_echo, memory_order_acquire) + 1;
    if (duct_io_connect(io, addr, keep->cli, nullptr, x_udp_peer) != rc_ok)
        return "datagram engine client connect failed";
    if (!th_wait_int(&g_cli_echo, want, 5000u))
        return "the datagram engine did not round-trip between its own two ends";
    return nullptr;
}

/** @brief Hold the datagram engine to its shape, its bytes and its two ends.
 *  @return nullptr on success, else what failed. */
static const char *nd_dgram(duct_engine_t *io, const duct_noise_keypair_t *srv_kp,
                            const duct_noise_keypair_t *cli_kp, const uint8_t *psk,
                            nd_dgram_t *keep)
{
    keep->srv_cfg = (duct_noise_cfg_t){ .local_static = *srv_kp, .suite.pattern = g_pattern };
    keep->cli_cfg = (duct_noise_cfg_t){ .local_static = *cli_kp, .suite.pattern = g_pattern };
    memcpy(keep->cli_cfg.remote_static_pub, srv_kp->pub, duct_noise_key_size);
    keep->hand_cfg = keep->cli_cfg;
    auto err = nd_dgram_vtbl(&keep->cli_cfg);
    if (!err)
        err = nd_dgram_hand(io, srv_kp, psk, keep);
    return err ? err : nd_dgram_pair(io, keep);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    if (argc > 1 && strcmp(argv[1], "xk") == 0)
        g_pattern = noise_pattern_xkpsk3;

    duct_noise_keypair_t srv_kp, cli_kp;
    if (!duct_noise_keypair_generate(&srv_kp)
        || !duct_noise_keypair_generate(&cli_kp)) {
        fprintf(stderr, "noise_dgram: keypair generation failed\n");
        return 1;
    }
    uint8_t psk[duct_noise_key_size] = {};

    duct_noise_cfg_t srv_cfg = {};
    srv_cfg.local_static = srv_kp;
    srv_cfg.suite.pattern = g_pattern;

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) {
        fprintf(stderr, "noise_dgram: io create failed\n");
        return 1;
    }

    duct_proto_t *proto = nullptr, *cli_proto = nullptr, *mismatch_proto = nullptr,
                 *forge_proto = nullptr;
    duct_wire_t *wire = nullptr, *cli_wire = nullptr;
    duct_noise_cfg_t cli_cfg = {};
    cli_cfg.suite.pattern = g_pattern;
    nd_inner_t inner_keep = {};
    nd_open_t open_keep = {};
    nd_dgram_t dgram_keep = {};
    const char *err = nullptr;
    pthread_t th;
    bool running = false;
    uint16_t port = 0u;
    char addr[64];

    wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = nullptr, .engine = duct_noise_vtbl(),
            .engine_cfg = &srv_cfg, .role = seal_role_responder,
            .framing = seal_framing_datagram });
    if (!wire) { err = "sealed wire create failed"; goto done; }
    proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "noise-dgram", .wire = wire,
        .on_frame = nd_on_frame,
        .on_session_open = nd_srv_open,
        .on_error = nd_srv_error,
        .max_response = 2048u,
        .flags = fl_proto_dgram_shared,
    });
    if (proto)
        proto->owned_wire = wire;
    else
        duct_wire_destroy(wire);
    wire = nullptr;
    if (!proto) { err = "proto create failed"; goto done; }

    if (duct_listener_bind(io, &(duct_listener_cfg_t){
            .kind = listener_dgram, .addr = "127.0.0.1",
            .n_protos = 1, .protos = (const duct_proto_t *[]){ proto },
        }, &port, nullptr, 0u, nullptr) != rc_ok) {
        err = "sealed wire refused on a datagram listener";
        goto done;
    }
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        err = "engine thread create failed";
        goto done;
    }
    running = true;

    err = nd_run(port, &cli_kp, srv_kp.pub, psk);
    if (err) goto done;

    cli_cfg.local_static = cli_kp;
    memcpy(cli_cfg.remote_static_pub, srv_kp.pub, duct_noise_key_size);
    cli_wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .engine = duct_noise_vtbl(), .engine_cfg = &cli_cfg,
        .role = seal_role_initiator, .framing = seal_framing_datagram });
    if (!cli_wire) { err = "client sealed wire create failed"; goto done; }
    cli_proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "noise-dgram-cli", .wire = cli_wire,
        .on_frame = nd_cli_frame,
        .on_session_open = nd_cli_open,
        .max_response = 2048u,
    });
    if (cli_proto)
        cli_proto->owned_wire = cli_wire;
    else
        duct_wire_destroy(cli_wire);
    cli_wire = nullptr;
    if (!cli_proto) { err = "client proto create failed"; goto done; }

    snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)port);
    if (duct_io_connect(io, addr, cli_proto, nullptr, x_udp_peer) != rc_ok) {
        err = "client connect failed";
        goto done;
    }
    if (!th_wait_int(&g_cli_echo, 1, 5000u))
        err = "duct client over x_udp_peer never got its echo back";
    else if (atomic_load_explicit(&g_srv_sessions, memory_order_acquire) != 2)
        err = "one dgram listener did not hold both peers as separate sessions";
    if (err) goto done;
    err = nd_framing(&cli_cfg);
    if (!err)
        err = nd_budget_cap(&cli_cfg);
    if (!err)
        err = nd_framing_half(&cli_cfg);
    if (!err)
        err = nd_forgery(io, &srv_kp, &cli_cfg, psk, &forge_proto);
    if (!err)
        err = nd_ctl_framing(&cli_cfg);
    if (!err)
        err = nd_inner(io, &srv_kp, &cli_kp, &inner_keep);
    if (!err)
        err = nd_open(io, &srv_kp, &cli_kp, psk, &open_keep);
    if (!err)
        err = nd_dgram(io, &srv_kp, &cli_kp, psk, &dgram_keep);
    if (!err) {
        /* The dial is checked for its return value because duct_io_connect
         * answers before any bind runs: a refusal deferred to the io thread
         * reaches an application as nothing but a conn that never opens. */
        auto stream_wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .engine = duct_noise_vtbl(), .engine_cfg = &cli_cfg,
            .role = seal_role_initiator, .framing = seal_framing_stream });
        if (!stream_wire) { err = "stream wire create failed"; goto done; }
        mismatch_proto = duct_proto_create(&(duct_proto_cfg_t){
            .name = "noise-dgram-mismatch", .wire = stream_wire,
            .on_frame = nd_cli_frame, .max_response = 2048u,
        });
        if (mismatch_proto)
            mismatch_proto->owned_wire = stream_wire;
        else
            duct_wire_destroy(stream_wire);
        if (!mismatch_proto) { err = "mismatch proto create failed"; goto done; }
        if (duct_io_connect(io, addr, mismatch_proto, nullptr, x_udp_peer) == rc_ok)
            err = "a stream-framed sealed wire was dialled on a datagram transport";
        else if (duct_listener_bind(io, &(duct_listener_cfg_t){
                     .kind = listener_dgram, .addr = "127.0.0.1",
                     .n_protos = 1,
                     .protos = (const duct_proto_t *[]){ mismatch_proto },
                 }, &(uint16_t){ 0u }, nullptr, 0u, nullptr) == rc_ok)
            err = "a stream-framed sealed wire was bound to a datagram listener";
        else if (duct_io_listen(io, "127.0.0.1", &(uint16_t){ 0u }, proto) == rc_ok)
            err = "a datagram-framed sealed wire was bound to a stream listener";
    }

done:
    duct_engine_stop(io);
    if (running)
        pthread_join(th, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(forge_proto);
    duct_proto_destroy(mismatch_proto);
    duct_proto_destroy(cli_proto);
    duct_proto_destroy(proto);
    duct_proto_destroy(dgram_keep.cli);
    duct_proto_destroy(dgram_keep.srv);
    duct_proto_destroy(dgram_keep.hand);
    duct_proto_destroy(open_keep.cli);
    duct_proto_destroy(inner_keep.cli);
    duct_proto_destroy(inner_keep.srv);
    if (inner_keep.inner)
        duct_wire_destroy(inner_keep.inner);

    if (err) {
        fprintf(stderr, "noise_dgram: %s\n", err);
        return 1;
    }
    printf("noise_dgram: OK (%s, sealed wire on a datagram listener, "
           "engine-driven handshake, three sealed round trips)\n",
           g_pattern == noise_pattern_xkpsk3 ? "XKpsk3" : "IKpsk2");
    return 0;
}
