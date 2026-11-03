/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file dgram_prefix_roam_test.c
 * @brief A sealed datagram wire's RX prefix as the demux key a preparse reads
 * before holding any key.
 *
 * One shared datagram listener, three client sockets, no VPN. The first opens
 * a session with all-zero leading bytes, the shape a conn carries until its
 * peer names it, and the handshake reply comes back bare because the two
 * prefix widths are set apart. The second socket is the same session reaching
 * the listener from an address it holds no conn for: its datagram leads with
 * the tag, preparse answers resolve_join, the session count stays at one and
 * the echo follows to the new address. The third leads with a tag naming
 * nothing and gets silence, no session and no frame.
 *
 * The middle step is what the prefix buys. It also fails without one: with
 * rx_prefix_len zero the engine reads the tag bytes as its own record header
 * and the very first datagram never reaches the protocol.
 *
 * The null seal engine stands in for real crypto so a plain UDP socket can
 * build a datagram the far side accepts; the tag here is a constant the test
 * publishes to both halves, where a real protocol mints one per session.
 */

#include "duct.h"
#include "duct_wire.h"
#include "tls_engine_null.h"

#include <stdatomic.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

#include "test_helpers.h"
#include "dgram_test_helpers.h"

static constexpr size_t   roam_tag_size = 8u;
static constexpr unsigned wait_ms       = 5000u;
static constexpr int      silence_ms    = 400;

static const uint8_t roam_zero[roam_tag_size]  = {};
static const uint8_t roam_tag[roam_tag_size]   = { 0x9e, 0x41, 0x0b, 0xd7,
                                                   0x62, 0xaa, 0x35, 0xf0 };
static const uint8_t roam_wrong[roam_tag_size] = { 0x01, 0x02, 0x03, 0x04,
                                                   0x05, 0x06, 0x07, 0x08 };

static const char roam_first[]  = "roam-one";
static const char roam_second[] = "roam-two";

static atomic_int g_open_count  = 0;
static atomic_int g_accepted    = 0;
static atomic_int g_join_count  = 0;
static atomic_int g_reject_count = 0;
static _Atomic duct_handle_t g_tok;
static atomic_bool g_named = false;

static duct_resolve_disposition_t
roam_preparse([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer,
              duct_view_u8 peek, duct_handle_t *out_tok,
              duct_conn_id_t *out_conn_id, [[maybe_unused]] void **out_user_ctx,
              [[maybe_unused]] size_t *out_lead)
{
    if (peek.size < roam_tag_size) {
        duct_atomic_fetch(add, &g_reject_count, 1, release);
        return resolve_reject;
    }
    if (memcmp(peek.data, roam_zero, roam_tag_size) == 0)
        return resolve_new;
    auto tok = duct_atomic_load(&g_tok, acquire);
    if (duct_atomic_load(&g_named, acquire) && tok != handle_null
        && memcmp(peek.data, roam_tag, roam_tag_size) == 0) {
        *out_tok = tok;
        *out_conn_id = 0u;
        duct_atomic_fetch(add, &g_join_count, 1, release);
        return resolve_join;
    }
    duct_atomic_fetch(add, &g_reject_count, 1, release);
    return resolve_reject;
}

static duct_result_t
roam_on_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok,
             [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_tok, tok, release);
    duct_atomic_fetch(add, &g_open_count, 1, release);
    return rc_ok;
}

static duct_result_t
roam_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
              const duct_frame_t *frame, duct_response_t *out,
              [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    duct_atomic_fetch(add, &g_accepted, 1, release);
    return rc_ok;
}

static int s_send_tagged(duct_sock_t fd, const uint8_t *tag, const void *ct, size_t ct_len)
{
    uint8_t sealed[128],
            out[roam_tag_size + duct_tls_record_hdr_size + sizeof sealed];
    size_t len = tls_null_seal(ct, ct_len, sealed, sizeof sealed);
    if (!len)
        return -1;
    memcpy(out, tag, roam_tag_size);
    size_t n = tls_null_record(out + roam_tag_size, 2u, sealed, len);
    return uc_send(fd, out, roam_tag_size + n);
}

static int s_send_tagged_hs(duct_sock_t fd, const uint8_t *tag, const void *body, size_t len)
{
    uint8_t out[roam_tag_size + duct_tls_record_hdr_size + 16u];
    memcpy(out, tag, roam_tag_size);
    size_t n = tls_null_record(out + roam_tag_size, 1u, body, len);
    return uc_send(fd, out, roam_tag_size + n);
}

static int s_recv_sealed_eq(duct_sock_t fd, const char *expected, size_t elen)
{
    char buf[512];
    ssize_t n = uc_recv(fd, buf, sizeof buf);
    if (n < (ssize_t)duct_tls_record_hdr_size)
        return -1;
    uint8_t ct[256];
    size_t got = tls_null_unseal_body((const uint8_t *)buf + duct_tls_record_hdr_size,
                                      (size_t)n - duct_tls_record_hdr_size,
                                      ct, sizeof ct);
    if (got == SIZE_MAX || got != elen)
        return -1;
    return memcmp(ct, expected, elen) == 0 ? 0 : -1;
}

static const char *sc_roam(void)
{
    duct_atomic_store(&g_open_count, 0, relaxed);
    duct_atomic_store(&g_accepted, 0, relaxed);
    duct_atomic_store(&g_join_count, 0, relaxed);
    duct_atomic_store(&g_reject_count, 0, relaxed);
    duct_atomic_store(&g_tok, handle_null, relaxed);
    duct_atomic_store(&g_named, false, relaxed);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return "io create failed";
    auto wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .inner = nullptr, .engine = tls_null_vtbl(),
        .role = seal_role_responder, .framing = seal_framing_datagram,
        .rx_prefix_len = (uint8_t)roam_tag_size });
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "dgram-prefix-roam", .wire = wire,
        .on_frame = roam_on_frame, .on_session_open = roam_on_open,
        .preparse = roam_preparse, .preparse_mode = resolve_sync,
        .max_response = 4096u, .flags = fl_proto_dgram_shared,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!proto) {
        duct_engine_destroy(io);
        return "proto create failed";
    }
    const duct_proto_t *protos[1] = { proto };
    uint16_t port = 0u;
    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
            .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
        }, &port, nullptr, 0u, nullptr) != rc_ok) {
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return "bind failed";
    }
    pthread_t th;
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return "thread create failed";
    }

    const char *error = nullptr;
    duct_sock_t fd1 = uc_connect(port),
                fd2 = duct_sock_bad,
                fd3 = duct_sock_bad;
    if (fd1 == duct_sock_bad)
        error = "first socket connect failed";
    if (!error && s_send_tagged_hs(fd1, roam_zero, "helo", 4u) != 0)
        error = "handshake datagram send failed";
    if (!error && !th_wait_int(&g_open_count, 1, wait_ms))
        error = "an unnamed datagram opened no session";
    if (!error) {
        char buf[64];
        ssize_t n = uc_recv(fd1, buf, sizeof buf);
        bool ok = n == (ssize_t)(duct_tls_record_hdr_size + sizeof tls_null_server_hello)
               && memcmp(buf + duct_tls_record_hdr_size, tls_null_server_hello,
                         sizeof tls_null_server_hello) == 0;
        if (!ok)
            error = "the handshake reply carried a prefix or never arrived";
    }
    if (!error && s_send_tagged(fd1, roam_zero, roam_first, sizeof roam_first - 1u) != 0)
        error = "first sealed datagram send failed";
    if (!error && !th_wait_int(&g_accepted, 1, wait_ms))
        error = "the first sealed datagram never reached the protocol";
    if (!error && s_recv_sealed_eq(fd1, roam_first, sizeof roam_first - 1u) != 0)
        error = "the first echo did not come back to the first address";

    duct_atomic_store(&g_named, true, release);

    if (!error) {
        fd2 = uc_connect(port);
        if (fd2 == duct_sock_bad)
            error = "roamed socket connect failed";
    }
    if (!error && s_send_tagged(fd2, roam_tag, roam_second, sizeof roam_second - 1u) != 0)
        error = "tagged datagram send from the roamed address failed";
    if (!error && !th_wait_int(&g_accepted, 2, wait_ms))
        error = "the tagged datagram never reached the protocol";
    if (!error && duct_atomic_load(&g_join_count, acquire) != 1)
        error = "the tag did not resolve to a join";
    if (!error && duct_atomic_load(&g_open_count, acquire) != 1)
        error = "the roamed address opened a second session";
    if (!error && s_recv_sealed_eq(fd2, roam_second, sizeof roam_second - 1u) != 0)
        error = "the echo did not follow the session to the roamed address";

    if (!error) {
        fd3 = uc_connect(port);
        if (fd3 == duct_sock_bad)
            error = "stranger socket connect failed";
    }
    if (!error && s_send_tagged(fd3, roam_wrong, roam_second, sizeof roam_second - 1u) != 0)
        error = "stranger datagram send failed";
    if (!error && uc_recv_none(fd3, silence_ms) != 0)
        error = "an unknown tag drew a reply";
    if (!error && duct_atomic_load(&g_open_count, acquire) != 1)
        error = "an unknown tag opened a session";
    if (!error && duct_atomic_load(&g_accepted, acquire) != 2)
        error = "an unknown tag reached the protocol";
    if (!error && duct_atomic_load(&g_reject_count, acquire) != 1)
        error = "the unknown tag was not refused by preparse";

    if (fd1 != duct_sock_bad) close(fd1);
    if (fd2 != duct_sock_bad) close(fd2);
    if (fd3 != duct_sock_bad) close(fd3);
    duct_engine_stop(io);
    pthread_join(th, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return error;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto error = sc_roam();
    if (error) {
        fprintf(stderr, "dgram_prefix_roam: %s\n", error);
        return 1;
    }
    printf("dgram_prefix_roam: OK (an unnamed datagram opens the session, the "
           "tag it later leads with joins that session from a new address and "
           "moves the reply there, and an unknown tag opens nothing)\n");
    return 0;
}
