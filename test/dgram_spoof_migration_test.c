/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file dgram_spoof_migration_test.c
 *  @brief Peer adoption on an @c x_udp_shared leg takes an affirmative
 *  @c rc_ok from the protocol.
 *
 *  A CID-keyed preparse joins any source address to the one live session, so a
 *  second socket reaches the victim's leg by design — the demux layer's job
 *  ends there and authentication is the protocol's. @c on_frame rejects that
 *  datagram with @c rc_invalid_arg, and the session's reply path must still
 *  point at the first address.
 *
 *  A server-initiated @c duct_session_invoke is what reads that path. Traffic
 *  the client drives cannot: every legitimate datagram re-adopts its own source
 *  before the reply it triggers, so an echo lands at the right address on a
 *  build that adopts unconditionally.
 *
 *  The positive control is the same second address sending an accepted
 *  datagram: the reply path moves to it and the first address goes quiet, which
 *  is what separates "adoption is gated" from "migration is broken".
 *
 *  A second scenario runs the same shape over a datagram-framed sealed wire,
 *  where the unseal is the authentication: the second address moves the reply
 *  path even though @c on_frame answers @c rc_invalid_arg. Holding both here is
 *  what pins one rule per wire kind, rather than one per stream.
 */

#include "duct.h"
#include "duct_wire.h"
#include "tls_engine_null.h"

#include <stdatomic.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "test_helpers.h"
#include "dgram_test_helpers.h"

static constexpr uint32_t k_cid      = 0x5EEDBEEFu;
static constexpr unsigned wait_ms    = 5000u;
static constexpr int      silence_ms = 400;
static constexpr size_t   msg_size   = 8u;

static const char invoke_payload[] = "server-initiated";

static atomic_bool g_open       = false;
static atomic_int  g_open_count = 0;
static atomic_int  g_accepted   = 0;
static atomic_int  g_rejected   = 0;
static _Atomic duct_handle_t g_tok;

static duct_result_t
on_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok,
        [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
        [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_tok, tok, release);
    duct_atomic_store(&g_open, true, release);
    duct_atomic_fetch(add, &g_open_count, 1, relaxed);
    return rc_ok;
}

static duct_result_t
on_dgram([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame, duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    auto body = (const char *)frame->payload.data;
    if (frame->payload.size > sizeof(uint32_t) && body[sizeof(uint32_t)] == 's') {
        duct_atomic_fetch(add, &g_rejected, 1, release);
        return rc_invalid_arg;
    }
    duct_atomic_fetch(add, &g_accepted, 1, release);
    duct_response_same(out, frame->payload, fl_send_copy, 0);
    return rc_ok;
}

static duct_resolve_disposition_t
preparse([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer,
         duct_view_u8 peek, duct_handle_t *out_tok,
         duct_conn_id_t *out_conn_id, [[maybe_unused]] void **out_user_ctx,
         [[maybe_unused]] size_t *out_lead)
{
    if (peek.size < sizeof(uint32_t))
        return resolve_reject;
    uint32_t cid;
    memcpy(&cid, peek.data, sizeof cid);
    if (cid != k_cid)
        return resolve_reject;
    if (!duct_atomic_load(&g_open, acquire))
        return resolve_new;
    *out_tok = duct_atomic_load(&g_tok, acquire);
    *out_conn_id = duct_conn_id_primary;
    return resolve_join;
}

static duct_result_t
s_invoke_fn([[maybe_unused]] duct_session_t *s, duct_response_t *out,
            [[maybe_unused]] void *ctx)
{
    *out = (duct_response_t){
        .payload = { .data = (void *)invoke_payload,
                     .size = sizeof invoke_payload - 1u },
        .flags = fl_send_static,
    };
    return rc_ok;
}

static void s_msg(uint8_t *out, char kind)
{
    memcpy(out, &k_cid, sizeof k_cid);
    memset(out + sizeof k_cid, kind, msg_size - sizeof k_cid);
}

static const char *sc_spoof_does_not_redirect(void)
{
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return "io create failed";
    auto wire = duct_wire_create_dgram_batch(0u, false);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "dgram-spoof", .wire = wire,
        .on_frame = on_dgram, .on_session_open = on_open,
        .preparse = preparse, .preparse_mode = resolve_sync,
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
    uint8_t msg[msg_size];
    duct_sock_t fd1 = uc_connect(port),
                fd2 = duct_sock_bad;
    if (fd1 == duct_sock_bad)
        error = "victim socket connect failed";

    if (!error) {
        s_msg(msg, 'g');
        if (uc_send(fd1, msg, sizeof msg) != 0
            || uc_recv_eq(fd1, (const char *)msg, sizeof msg) != 0)
            error = "the victim's own first datagram was not echoed";
    }
    if (!error && !th_wait_int(&g_open_count, 1, wait_ms))
        error = "no session opened for the victim";

    if (!error) {
        fd2 = uc_connect(port);
        if (fd2 == duct_sock_bad)
            error = "attacker socket connect failed";
    }
    if (!error) {
        s_msg(msg, 's');
        if (uc_send(fd2, msg, sizeof msg) != 0)
            error = "spoofed datagram send failed";
    }
    if (!error && !th_wait_int(&g_rejected, 1, wait_ms))
        error = "the spoofed datagram never reached the session";

    if (!error) {
        auto rc = duct_session_invoke(io, duct_atomic_load(&g_tok, acquire),
                                      s_invoke_fn, nullptr);
        if (rc != rc_ok)
            error = "duct_session_invoke refused after the spoof";
    }
    if (!error && uc_recv_eq(fd1, invoke_payload, sizeof invoke_payload - 1u) != 0)
        error = "the server-initiated send did not reach the victim";
    if (!error && uc_recv_none(fd2, silence_ms) != 0)
        error = "a rejected datagram redirected the session's reply path";

    if (!error) {
        s_msg(msg, 'g');
        if (uc_send(fd2, msg, sizeof msg) != 0
            || uc_recv_eq(fd2, (const char *)msg, sizeof msg) != 0)
            error = "an accepted datagram from the second address was not echoed";
    }
    if (!error) {
        auto rc = duct_session_invoke(io, duct_atomic_load(&g_tok, acquire),
                                      s_invoke_fn, nullptr);
        if (rc != rc_ok)
            error = "duct_session_invoke refused after the migration";
    }
    if (!error && uc_recv_eq(fd2, invoke_payload, sizeof invoke_payload - 1u) != 0)
        error = "an accepted datagram failed to move the reply path at all";
    if (!error && uc_recv_none(fd1, silence_ms) != 0)
        error = "the old address still receives after a real migration";

    if (fd1 != duct_sock_bad)
        close(fd1);
    if (fd2 != duct_sock_bad)
        close(fd2);
    duct_engine_stop(io);
    pthread_join(th, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return error;
}

static duct_resolve_disposition_t
preparse_sealed([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer,
                [[maybe_unused]] duct_view_u8 peek, duct_handle_t *out_tok,
                duct_conn_id_t *out_conn_id, [[maybe_unused]] void **out_user_ctx,
                [[maybe_unused]] size_t *out_lead)
{
    if (!duct_atomic_load(&g_open, acquire))
        return resolve_new;
    *out_tok = duct_atomic_load(&g_tok, acquire);
    *out_conn_id = duct_conn_id_primary;
    return resolve_join;
}

static duct_result_t
on_sealed([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
          [[maybe_unused]] const duct_frame_t *frame,
          [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_rejected, 1, release);
    return rc_invalid_arg;
}

static int s_recv_sealed_eq(duct_sock_t fd, const char *expected, size_t elen)
{
    char buf[512];
    ssize_t n = uc_recv(fd, buf, sizeof buf);
    if (n < (ssize_t)duct_tls_record_hdr_size)
        return -1;
    uint8_t ct[256];
    size_t got = tls_null_unseal_body((const uint8_t *)buf + duct_tls_record_hdr_size,
                                      (size_t)n - duct_tls_record_hdr_size, ct, sizeof ct);
    if (got == SIZE_MAX || got != elen)
        return -1;
    return memcmp(ct, expected, elen) == 0 ? 0 : -1;
}

static int s_send_sealed(duct_sock_t fd, const void *ct, size_t ct_len)
{
    uint8_t sealed[128],
            rec[duct_tls_record_hdr_size + sizeof sealed];
    size_t len = tls_null_seal(ct, ct_len, sealed, sizeof sealed);
    if (!len)
        return -1;
    size_t n = tls_null_record(rec, 2u, sealed, len);
    return uc_send(fd, rec, n);
}

static const char *sc_sealed_adopts_on_unseal(void)
{
    duct_atomic_store(&g_open, false, relaxed);
    duct_atomic_store(&g_open_count, 0, relaxed);
    duct_atomic_store(&g_rejected, 0, relaxed);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return "io create failed";
    auto wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .inner = nullptr, .engine = tls_null_vtbl(),
        .role = seal_role_responder, .framing = seal_framing_datagram });
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "dgram-sealed-adopt", .wire = wire,
        .on_frame = on_sealed, .on_session_open = on_open,
        .preparse = preparse_sealed, .preparse_mode = resolve_sync,
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
        return "sealed dgram bind failed";
    }
    pthread_t th;
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return "thread create failed";
    }

    const char *error = nullptr;
    uint8_t hello[duct_tls_record_hdr_size + 4u];
    duct_sock_t fd1 = uc_connect(port),
                fd2 = duct_sock_bad;
    if (fd1 == duct_sock_bad)
        error = "victim socket connect failed";
    if (!error) {
        size_t n = tls_null_record(hello, 1u, "helo", 4u);
        if (uc_send(fd1, hello, n) != 0)
            error = "handshake datagram send failed";
    }
    if (!error && !th_wait_int(&g_open_count, 1, wait_ms))
        error = "no session opened for the sealed victim";
    if (!error) {
        char buf[64];
        ssize_t n = uc_recv(fd1, buf, sizeof buf);
        bool hello = n == (ssize_t)(duct_tls_record_hdr_size + sizeof tls_null_server_hello)
                  && memcmp(buf + duct_tls_record_hdr_size, tls_null_server_hello,
                            sizeof tls_null_server_hello) == 0;
        if (!hello)
            error = "the handshake reply did not reach the first address";
    }

    if (!error) {
        fd2 = uc_connect(port);
        if (fd2 == duct_sock_bad)
            error = "second socket connect failed";
    }
    if (!error && s_send_sealed(fd2, "payload", 7u) != 0)
        error = "sealed datagram send from the second address failed";
    if (!error && !th_wait_int(&g_rejected, 1, wait_ms))
        error = "the sealed datagram never reached the protocol";

    if (!error) {
        auto rc = duct_session_invoke(io, duct_atomic_load(&g_tok, acquire),
                                      s_invoke_fn, nullptr);
        if (rc != rc_ok)
            error = "duct_session_invoke refused";
    }
    if (!error && s_recv_sealed_eq(fd2, invoke_payload, sizeof invoke_payload - 1u) != 0)
        error = "an authenticated datagram did not move the reply path";
    if (!error && uc_recv_none(fd1, silence_ms) != 0)
        error = "the old address still receives after an authenticated move";

    if (fd1 != duct_sock_bad)
        close(fd1);
    if (fd2 != duct_sock_bad)
        close(fd2);
    duct_engine_stop(io);
    pthread_join(th, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return error;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto error = sc_spoof_does_not_redirect();
    if (error) {
        fprintf(stderr, "dgram_spoof_migration: plain wire: %s "
                        "(accepted=%d rejected=%d)\n",
                error, duct_atomic_load(&g_accepted, acquire),
                duct_atomic_load(&g_rejected, acquire));
        return 1;
    }
    error = sc_sealed_adopts_on_unseal();
    if (error) {
        fprintf(stderr, "dgram_spoof_migration: sealed wire: %s (rejected=%d)\n",
                error, duct_atomic_load(&g_rejected, acquire));
        return 1;
    }
    printf("dgram_spoof_migration: OK (a plain wire gates adoption on the "
           "protocol; a sealed wire gates it on the unseal)\n");
    return 0;
}
