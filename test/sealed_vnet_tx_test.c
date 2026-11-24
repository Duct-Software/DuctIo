/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file sealed_vnet_tx_test.c
 *  @brief What a sealed record stages onto a vnet leg's TX ring, and what refuses there.
 *
 *  A datagram-framed sealed wire over the null engine on an @c x_raw_packet
 *  conn carrying a vnet header: the record stages whole — its inline header is
 *  the zeroed virtio header, the span's meta carries the header length, and
 *  the staged bytes count header and ciphertext together. The gso flag refuses
 *  on the sealed class, the codec owning the record's cut. A length-prefix
 *  wire stages header bytes of its own, which the virtio header would
 *  overwrite: the record refuses on a vnet leg and stages plain where the leg
 *  carries none.
 */

#include "../src/duct_worker.c"
#include "tls_engine_null.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <unistd.h>
#endif

#define CHECK(expr, msg) \
    do { if (!(expr)) { fprintf(stderr, "FAIL: %s\n", msg); return msg; } } while (0)

/* AI-generated test code. */

/** @brief Vnet header the test's conn reports, bytes. */
static constexpr size_t vnet_len = 10u;
/** @brief Cleartext payload each frame carries, bytes. */
static constexpr size_t pay_len = 32u;

typedef struct {
    duct_proto_t   *proto;
    duct_session_t *s;
    duct_conn_t    *x,     /**< Primary leg, no wire. */
                   *leg;   /**< Leg under test, its wire and vnet header set. */
    duct_wire_t    *wire;  /**< The leg wire, the fixture's to destroy. */
    duct_worker_t   w;
} fixture_t;

enum : duct_conn_id_t { leg_test = 1u };

/** @brief Swallow one engine egress record: the handshake reply the fixture's
 *  engine writes has nowhere to go. */
static bool s_tx_append_swallow([[maybe_unused]] struct duct_unseal_ctx *self,
                                [[maybe_unused]] duct_view_u8 bytes)
{
    return true;
}

static duct_result_t on_frame([[maybe_unused]] duct_session_t *s,
                              [[maybe_unused]] duct_conn_id_t conn_id,
                              [[maybe_unused]] const duct_frame_t *frame,
                              [[maybe_unused]] duct_response_t *out,
                              [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

static duct_conn_t *conn_new(duct_xport_t xport, const duct_wire_t *wire, size_t vnet)
{
    auto conn = duct_conn_acquire();
    assert(conn);
    conn->xport_type = xport;
    conn->wire = (duct_wire_t *)wire;
    conn->vnet_hdr_len = (uint8_t)vnet;
    duct_conn_carve_olb(conn, kbytes(4u), kbytes(4u));
    return conn;
}

static void fixture_init(fixture_t *f, duct_wire_t *wire)
{
    *f = (fixture_t){};
    f->proto = duct_proto_create_tcp("sealed-vnet-tx", on_frame);
    assert(f->proto);
    f->wire = wire;
    f->x = conn_new(x_tcp, nullptr, 0u);
    f->leg = conn_new(x_raw_packet, wire, vnet_len);
    auto xh = duct_conn_handle_get(f->x);

    duct_response_t out = {};
    f->s = duct_session_open(f->proto, duct_conn_id_primary, xh, nullptr, 0u, &out);
    assert(f->s);
    auto arc = duct_session_attach_conn(f->s, leg_test, duct_conn_handle_get(f->leg));
    assert(arc == rc_ok);
    duct_discard arc;

    duct_timers_init(&f->w.timers);
    s_this_worker = &f->w;
}

static void fixture_fini(fixture_t *f)
{
    s_retry_clear(&f->w);
    duct_timers_destroy(&f->w.timers);
    s_this_worker = nullptr;
    duct_discard duct_session_detach_leg(f->s, leg_test, close_normal);
    duct_discard duct_session_detach_leg(f->s, duct_conn_id_primary, close_normal);
    duct_conn_teardown_worker(f->x);
    duct_conn_release(f->x);
    duct_conn_teardown_worker(f->leg);
    duct_conn_release(f->leg);
    if (f->w.ct_chunks_live) {
        duct_x_slot_pool_free(&f->w.ct_chunks);
        f->w.ct_chunks_live = false;
    }
    duct_proto_destroy(f->proto);
    if (f->wire)
        duct_wire_destroy(f->wire);
}

/** @brief The sealed record stages whole onto the vnet leg: the zeroed virtio
 *  header rides the inline half, the body is the engine's own seal, the staged
 *  bytes count both halves. The gso flag refuses on the sealed class and
 *  leaves the ring as it stood. */
static const char *sc_sealed_vnet_stage(void)
{
    auto wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .inner = nullptr, .engine = tls_null_vtbl(),
        .role = seal_role_responder, .framing = seal_framing_datagram });
    if (!wire)
        return "the sealed dgram wire refused to build";
    fixture_t f;
    fixture_init(&f, wire);

    uint8_t clear[pay_len];
    for (size_t i = 0u; i < pay_len; ++i)
        clear[i] = (uint8_t)(i * 31u + 7u);
    /* The responder's seal answers past its handshake record: one unseal of a
     * handshake record arms the engine, its reply swallowed here. */
    auto codec = s_tls_codec(f.leg);
    CHECK(codec != nullptr, "the codec did not carve");
    duct_unseal_ctx_t hs_ctx = { .tx_append = s_tx_append_swallow };
    uint8_t hs[] = { 1u, 0u, 0u, 0u, 1u, 0u };
    CHECK(codec->engine->vtbl->unseal(codec->engine,
                                      duct_view(duct_view_u8, hs, sizeof hs),
                                      &hs_ctx) == rc_ok,
          "the null engine refused its handshake");

    duct_response_t own = {};
    auto st = s_tx_stage_frame(f.leg, f.s,
        &(duct_frame_t){ .payload = { .data = clear, .size = pay_len } }, &own, nullptr);
    if (st != olb_tx_ok) {
        fprintf(stderr, "FAIL: the sealed record did not stage: %d\n", (int)st);
        fixture_fini(&f);
        return "the sealed record did not stage on the vnet leg";
    }

    auto tx = duct_conn_tx_olb(f.leg);
    duct_view_u8 iov[2];
    CHECK(duct_olb_tx_peek_staged_iov(tx, 1u, iov) == 2u, "the ring holds no staged record");
    CHECK(iov[0].size == vnet_len, "the record's inline header is not the vnet header");
    CHECK(memcmp(iov[0].data, duct_vnet_zero, vnet_len) == 0, "the vnet header is not zeroed");
    uint8_t sealed[pay_len + 2u], expect[pay_len + 2u + 5u];
    size_t ct = tls_null_seal(clear, pay_len, sealed, sizeof sealed);
    CHECK(ct != 0u, "the null engine refused to seal");
    size_t body = tls_null_record(expect, 2u, sealed, ct);
    CHECK(iov[1].size == body, "the record's body is not the whole sealed PDU");
    CHECK(memcmp(iov[1].data, expect, body) == 0, "the sealed body differs from the engine's seal");
    CHECK(tx->staged_bytes == vnet_len + body, "the staged bytes miss the record's header half");

    st = s_tx_stage_frame(f.leg, f.s,
        &(duct_frame_t){ .payload = { .data = clear, .size = pay_len },
                         .flags = fl_frame_gso }, &own, nullptr);
    CHECK(st == olb_tx_too_large, "the gso flag did not refuse on the sealed class");
    CHECK(duct_olb_tx_peek_staged_iov(tx, 2u, iov) == 2u,
          "the refusal disturbed the ring's staged records");

    fixture_fini(&f);
    return nullptr;
}

/** @brief A wire staging header bytes of its own refuses where the virtio
 *  header would overwrite them, and stages plain on a leg carrying no vnet
 *  header: the refusal is the leg's answer, not the wire's. */
static const char *sc_header_wire_vnet(void)
{
    auto wire = duct_wire_create_length_prefix(0u);
    if (!wire)
        return "the length-prefix wire refused to build";
    fixture_t f;
    fixture_init(&f, wire);

    uint8_t clear[pay_len];
    for (size_t i = 0u; i < pay_len; ++i)
        clear[i] = (uint8_t)(i * 31u + 7u);
    duct_response_t own = {};
    auto st = s_tx_stage_frame(f.leg, f.s,
        &(duct_frame_t){ .payload = { .data = clear, .size = pay_len } }, &own, nullptr);
    CHECK(st == olb_tx_too_large, "a header-carrying wire did not refuse on the vnet leg");
    auto tx = duct_conn_tx_olb(f.leg);
    duct_view_u8 iov[2];
    CHECK(duct_olb_tx_peek_staged_iov(tx, 1u, iov) == 0u, "the refusal left a record behind");

    f.leg->vnet_hdr_len = 0u;
    st = s_tx_stage_frame(f.leg, f.s,
        &(duct_frame_t){ .payload = { .data = clear, .size = pay_len } }, &own, nullptr);
    CHECK(st == olb_tx_ok, "the same wire did not stage plain on a leg without the vnet header");
    CHECK(duct_olb_tx_peek_staged_iov(tx, 1u, iov) == 2u, "the plain leg holds no staged record");
    CHECK(iov[0].size == 4u, "the wire's own header did not ride the plain leg's record");
    CHECK(duct_load_be32((const uint8_t *)iov[0].data) == pay_len,
          "the wire's header is not the payload's length prefix");

    fixture_fini(&f);
    return nullptr;
}

/** @brief Build a minimal valid IPv4/TCP ACK packet that @c duct_vnet_gro_offer
 *  would merge into a train if the commit path did not gate on a transparent
 *  wire first. */
static void s_make_ipv4_tcp(uint8_t *p, size_t len)
{
    memset(p, 0, len);
    p[0] = 0x45u;
    duct_store_be16(p + 2u, (uint16_t)len);
    p[4] = 0u; p[5] = 1u;
    p[6] = 0x40u;
    p[8] = 64u;
    p[9] = 6u;
    static const uint8_t addrs[8] = { 10u, 0u, 0u, 1u, 10u, 0u, 0u, 2u };
    memcpy(p + 12u, addrs, sizeof addrs);
    uint32_t acc = 0u;
    for (size_t i = 0u; i < 20u; i += 2u)
        acc += (uint32_t)(p[i] << 8u | p[i + 1u]);
    while (acc >> 16u)
        acc = (acc & 0xffffu) + (acc >> 16u);
    uint16_t csum = (uint16_t)~acc;
    memcpy(p + 10u, &csum, sizeof csum);
    uint8_t *th = p + 20u;
    duct_store_be16(th, 12345u);
    duct_store_be16(th + 2u, 80u);
    th[12] = 0x50u;
    th[13] = 0x10u; /* ACK */
    duct_store_be16(th + 14u, 65535u);
}

/** @brief @c s_commit_packet_fd on an idle vnet leg must not divert sealed or
 *  header-framing wires into @c s_vnet_train_take (sending cleartext or
 *  skipping refusals). */
static const char *sc_commit_packet_fd_wire_gate(void)
{
    static constexpr size_t ip_len = 48u;
    uint8_t pkt[ip_len];
    s_make_ipv4_tcp(pkt, sizeof pkt);

    auto lp = duct_wire_create_length_prefix(0u);
    if (!lp)
        return "the length-prefix wire refused to build";
    fixture_t flp;
    fixture_init(&flp, lp);
    vnet_train_t train_lp = {};
    flp.w.vnet_train = &train_lp;
    duct_response_t lp_out = { .payload = { .data = pkt, .size = sizeof pkt },
                               .flags = fl_send_copy };
    commit_ctx_t lp_ctx = {
        .s = flp.s, .out_conn = leg_test, .out = &lp_out,
        .conn = flp.leg, .handle = duct_conn_handle_get(flp.leg),
    };
    CHECK(s_commit_packet_fd(&lp_ctx) == commit_invalid,
          "idle s_commit_packet_fd did not refuse a header-carrying wire on vnet");
    CHECK(train_lp.gro.segs == 0u,
          "idle s_commit_packet_fd boarded a header-carrying wire onto the vnet train");
    fixture_fini(&flp);

    auto wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .inner = nullptr, .engine = tls_null_vtbl(),
        .role = seal_role_responder, .framing = seal_framing_datagram });
    if (!wire)
        return "the sealed dgram wire refused to build";
    fixture_t f;
    fixture_init(&f, wire);
    vnet_train_t train = {};
    f.w.vnet_train = &train;
    auto codec = s_tls_codec(f.leg);
    CHECK(codec != nullptr, "the codec did not carve");
    duct_unseal_ctx_t hs_ctx = { .tx_append = s_tx_append_swallow };
    uint8_t hs[] = { 1u, 0u, 0u, 0u, 1u, 0u };
    CHECK(codec->engine->vtbl->unseal(codec->engine,
                                      duct_view(duct_view_u8, hs, sizeof hs),
                                      &hs_ctx) == rc_ok,
          "the null engine refused its handshake");

    duct_response_t gso_out = { .payload = { .data = pkt, .size = sizeof pkt },
                                .flags = fl_send_copy, .frame_flags = fl_frame_gso };
    commit_ctx_t gso_ctx = {
        .s = f.s, .out_conn = leg_test, .out = &gso_out,
        .conn = f.leg, .handle = duct_conn_handle_get(f.leg),
    };
    CHECK(s_commit_packet_fd(&gso_ctx) == commit_invalid,
          "idle s_commit_packet_fd did not refuse fl_frame_gso on sealed+vnet");
    CHECK(train.gro.segs == 0u,
          "idle s_commit_packet_fd boarded sealed+gso onto the vnet train");

#ifndef _WIN32
    int sv[2] = { -1, -1 };
    CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0, "socketpair failed");
    f.leg->fd = sv[0];
    duct_response_t out = { .payload = { .data = pkt, .size = sizeof pkt },
                            .flags = fl_send_copy };
    commit_ctx_t ctx = {
        .s = f.s, .out_conn = leg_test, .out = &out,
        .conn = f.leg, .handle = duct_conn_handle_get(f.leg),
    };
    CHECK(s_commit_packet_fd(&ctx) == commit_ok,
          "idle s_commit_packet_fd failed on sealed+vnet");
    CHECK(train.gro.segs == 0u,
          "idle s_commit_packet_fd diverted sealed+vnet into the vnet train");
    uint8_t wire_buf[vnet_len + ip_len + 16u];
    ssize_t got = recv(sv[1], wire_buf, sizeof wire_buf, MSG_DONTWAIT);
    uint8_t sealed[ip_len + 2u], expect[ip_len + 2u + 5u];
    size_t ct = tls_null_seal(pkt, sizeof pkt, sealed, sizeof sealed);
    CHECK(ct != 0u, "the null engine refused to seal");
    size_t body = tls_null_record(expect, 2u, sealed, ct);
    CHECK(got == (ssize_t)(vnet_len + body),
          "idle s_commit_packet_fd wrote wrong byte count for sealed+vnet");
    CHECK(memcmp(wire_buf, duct_vnet_zero, vnet_len) == 0,
          "idle s_commit_packet_fd missed zeroed vnet header on sealed+vnet");
    CHECK(memcmp(wire_buf + vnet_len, expect, body) == 0,
          "idle s_commit_packet_fd sent unsealed or malformed bytes on sealed+vnet");
    f.leg->fd = duct_sock_bad;
    close(sv[0]);
    close(sv[1]);
#endif

    fixture_fini(&f);
    return nullptr;
}

int main(void)
{
    const char *err = sc_sealed_vnet_stage();
    if (!err)
        err = sc_header_wire_vnet();
    if (!err)
        err = sc_commit_packet_fd_wire_gate();
    if (err) {
        fprintf(stderr, "sealed_vnet_tx_test: %s\n", err);
        return 1;
    }
    printf("sealed_vnet_tx_test: ok\n");
    return 0;
}
