/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file tls_openssl_test.c
 * @brief Integration test: the OpenSSL engine adapter over a real TCP
 * conn, client side driven by a genuine independent OpenSSL @c SSL — proof
 * of real interop, not just internal self-consistency (unlike
 * @c tls_null_test.c, whose fake engine cannot be handshaken by anything
 * other than itself).
 *
 * loopback
 * handshake + echo + close_notify. Every other RX-dispatch edge case
 * (parked handler, mid-record defer/replay, auth-failure close, STARTTLS
 * lifecycle) is already proven engine-agnostic by tls_null_test.c and
 * wire_change_test.c — this file only has to prove the *adapter* is
 * correct, not the dispatch machinery again. One addition beyond the bare
 * test: ALPN, since ALPN passthrough is otherwise a
 * claimed but never-exercised capability.
 *
 * Certificate: a self-signed EC P-256 leaf, generated programmatically at
 * startup (no checked-in key material, no external files, no subprocess —
 * this codebase's tests never shell out). Client-side verification is
 * disabled (SSL_VERIFY_NONE) — expected and correct for a self-signed
 * loopback test, not a production recommendation.
 */

#include "duct.h"
#include "duct_tls_openssl.h"
#include "duct_stream_ctx.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "test_helpers.h"

/* ── Private "mux" inner wire: [sid(4 BE)][flags(1)][len(4 BE)] + payload —
 * same shape every other TLS/stream test in this tree already uses locally. */

static constexpr size_t mux_hdr_size = 9u;

typedef struct {
    uint8_t  hdr_buf[9];
    uint32_t partial_len;
    bool     hdr_done;
} mux_parser_t;

typedef struct { duct_wire_t base; } mux_wire_t;

static duct_result_t
mux_parse([[maybe_unused]] const duct_wire_t *self,
         duct_view_u8 input, duct_frame_t *out, duct_wire_parser_t *parser,
         size_t *consumed, size_t *needed)
{
    auto st = (mux_parser_t *)parser;
    *consumed = 0u;
    *needed = 0u;
    uint8_t *p = (uint8_t *)input.data;
    uint8_t *end = p + input.size;

    if (!st->hdr_done) {
        if (st->partial_len > 0u) {
            p += st->partial_len;
            uint32_t want = (uint32_t)mux_hdr_size - st->partial_len;
            uint32_t copy = (uint32_t)(end - p) < want ? (uint32_t)(end - p) : want;
            memcpy(st->hdr_buf + st->partial_len, p, copy);
            st->partial_len += copy;
            p += copy;
            if (st->partial_len < (uint32_t)mux_hdr_size) {
                *needed = mux_hdr_size - st->partial_len;
                return rc_again;
            }
            st->hdr_done = true;
        } else if ((size_t)(end - p) >= mux_hdr_size) {
            memcpy(st->hdr_buf, p, mux_hdr_size);
            p += mux_hdr_size;
            st->hdr_done = true;
        } else {
            memcpy(st->hdr_buf, p, (size_t)(end - p));
            st->partial_len = (uint32_t)(end - p);
            *needed = mux_hdr_size - st->partial_len;
            return rc_again;
        }
    } else {
        p += mux_hdr_size;
    }

    uint32_t sid = ((uint32_t)st->hdr_buf[0] << 24u) | ((uint32_t)st->hdr_buf[1] << 16u)
                 | ((uint32_t)st->hdr_buf[2] <<  8u) |  (uint32_t)st->hdr_buf[3];
    uint32_t len = ((uint32_t)st->hdr_buf[5] << 24u) | ((uint32_t)st->hdr_buf[6] << 16u)
                 | ((uint32_t)st->hdr_buf[7] <<  8u) |  (uint32_t)st->hdr_buf[8];
    st->hdr_done = false;
    st->partial_len = 0u;

    if (len > (1u << 16u)) {
        *consumed = (size_t)(p - (uint8_t *)input.data);
        return rc_invalid_arg;
    }
    if ((size_t)(end - p) < len) {
        st->hdr_done = true;
        *consumed = (size_t)(p - (uint8_t *)input.data);
        *needed = len;
        return rc_again;
    }
    *out = (duct_frame_t){ .stream_id = sid, .flags = fl_frame_none,
                           .payload = { .data = p, .size = len } };
    *consumed = (size_t)((p + len) - (uint8_t *)input.data);
    return rc_ok;
}

static size_t
mux_pack_header([[maybe_unused]] const duct_wire_t *self,
               const duct_frame_t *frame, uint8_t buf[16])
{
    uint32_t sid = frame->stream_id;
    uint32_t len = (uint32_t)frame->payload.size;
    buf[0] = (uint8_t)(sid >> 24u); buf[1] = (uint8_t)(sid >> 16u);
    buf[2] = (uint8_t)(sid >>  8u); buf[3] = (uint8_t)(sid);
    buf[4] = 0u;
    buf[5] = (uint8_t)(len >> 24u); buf[6] = (uint8_t)(len >> 16u);
    buf[7] = (uint8_t)(len >>  8u); buf[8] = (uint8_t)(len);
    return mux_hdr_size;
}

static duct_result_t
mux_pack(const duct_wire_t *self, [[maybe_unused]] duct_session_t *s,
        const duct_frame_t *frame, duct_wire_tx_t *stage,
        [[maybe_unused]] duct_wire_codec_t *codec)
{
    uint8_t hdr[16];
    mux_pack_header(self, frame, hdr);
    return duct_wire_tx_stage(stage,
        duct_view(duct_view_u8, hdr, mux_hdr_size), frame->payload);
}

static duct_wire_parser_t *mux_create_parser([[maybe_unused]] const duct_wire_t *self)
{
    auto st = duct_new(mux_parser_t);
    duct_do_if(!st, return nullptr);
    return (duct_wire_parser_t *)st;
}

static void mux_destroy_parser([[maybe_unused]] const duct_wire_t *self, duct_wire_parser_t *parser)
{
    auto st = (mux_parser_t *)parser;
    duct_del(st);
}

static void mux_destroy(duct_wire_t *self) { duct_del(self); }

static duct_wire_t *mux_wire_create(void)
{
    auto w = duct_new(mux_wire_t);
    duct_do_if(!w, return nullptr);
    w->base = (duct_wire_t){
        .name = "tls-openssl-mux", .header_size = mux_hdr_size,
        .destroy = mux_destroy, .on_parse = mux_parse, .on_pack = mux_pack,
        .pack_header = mux_pack_header,
        .create_parser = mux_create_parser, .destroy_parser = mux_destroy_parser,
    };
    return &w->base;
}

static size_t s_mux_frame(uint8_t *out, size_t cap, uint32_t sid, const void *payload, size_t len)
{
    if (cap < mux_hdr_size + len)
        return 0u;
    out[0] = (uint8_t)(sid >> 24u); out[1] = (uint8_t)(sid >> 16u);
    out[2] = (uint8_t)(sid >>  8u); out[3] = (uint8_t)(sid);
    out[4] = 0u;
    out[5] = (uint8_t)(len >> 24u); out[6] = (uint8_t)(len >> 16u);
    out[7] = (uint8_t)(len >>  8u); out[8] = (uint8_t)(len);
    memcpy(out + mux_hdr_size, payload, len);
    return mux_hdr_size + len;
}

/* ── Self-signed EC P-256 leaf, generated once at startup ────────────── */

static bool s_make_self_signed(EVP_PKEY **out_pkey, X509 **out_cert)
{
    auto pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx)
        return false;
    EVP_PKEY *pkey = nullptr;
    bool ok = EVP_PKEY_keygen_init(pctx) > 0
           && EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) > 0
           && EVP_PKEY_keygen(pctx, &pkey) > 0;
    EVP_PKEY_CTX_free(pctx);
    if (!ok)
        return false;

    auto cert = X509_new();
    if (!cert) { EVP_PKEY_free(pkey); return false; }
    X509_set_version(cert, 2); /* X.509 v3 is version value 2 (zero-based) */
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 3600L); /* 1h, test-only */
    X509_set_pubkey(cert, pkey);
    auto name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char *)"duct-tls-openssl-test", -1, -1, 0);
    X509_set_issuer_name(cert, name); /* self-signed: issuer == subject */
    if (X509_sign(cert, pkey, EVP_sha256()) == 0) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return false;
    }
    *out_pkey = pkey;
    *out_cert = cert;
    return true;
}

/* ── ALPN ─────────────────────────────────────────────────────────────── */

static const char alpn_proto[] = "duct-echo";
/* Client-side wire format: [len][bytes...], one entry. */
static const unsigned char client_alpn_wire[] = { 9u, 'd','u','c','t','-','e','c','h','o' };

/* Unconditionally selects alpn_proto rather than negotiating against `in` —
 * this test's own client always offers exactly one, matching protocol, so a
 * real negotiation (SSL_select_next_proto) would pick the same result; a
 * real integrator's own callback should validate against `in`/`inlen`. */
static int
s_alpn_select_cb([[maybe_unused]] SSL *ssl, const unsigned char **out, unsigned char *outlen,
                 [[maybe_unused]] const unsigned char *in, [[maybe_unused]] unsigned int inlen,
                 [[maybe_unused]] void *arg)
{
    *out = (const unsigned char *)alpn_proto;
    *outlen = (unsigned char)(sizeof(alpn_proto) - 1u);
    return SSL_TLSEXT_ERR_OK;
}

/* ── g_records log (tls_null_test.c's own pattern) ───────────────────── */

typedef struct { duct_stream_id_t stream_id; size_t len; char data[64]; } record_t;
static constexpr unsigned max_records = 8u;
static record_t g_records[max_records];
static atomic_uint g_next_idx = 0u;
static atomic_uint g_published = 0u;
static atomic_int  g_open_count = 0;

static void s_log(duct_stream_id_t sid, duct_view_u8 data)
{
    unsigned i = atomic_fetch_add(&g_next_idx, 1u);
    if (i < max_records) {
        g_records[i].stream_id = sid;
        g_records[i].len = data.size < sizeof(g_records[i].data) ? data.size : sizeof(g_records[i].data);
        memcpy(g_records[i].data, data.data, g_records[i].len);
    }
    atomic_store(&g_published, i + 1u);
}

/* ── Protocol callbacks ───────────────────────────────────────────────── */

static constexpr duct_stream_id_t echo_stream_id = 1u;
static constexpr duct_stream_id_t close_stream_id = 2u;

static duct_result_t
s_on_frame([[maybe_unused]] duct_session_t *s,
          [[maybe_unused]] duct_conn_id_t conn_id,
          [[maybe_unused]] const duct_frame_t *frame,
          [[maybe_unused]] duct_response_t *out,
          [[maybe_unused]] void *proto_state)
{
    return rc_drop; /* stream-0 fallback, never reached -- every frame here targets a real stream */
}

/* Same one-yield-then-commit shape as tls_null_test.c's own s_handler:
 * async_yield's hctx->out is what actually gets committed
 * (s_hctx_async_done), a plain async_done never emits — so a real response
 * is staged on the first (yield) step and the second (done) step is a
 * pure no-op, gated by hctx->stream_state. */
static duct_async_rc_t s_handler(void *state)
{
    auto hctx = (duct_stream_ctx_t *)state;
    duct_view_u8 p = hctx->frame.payload;
    duct_response_reset(&hctx->out);

    if (hctx->stream_id == close_stream_id) {
        if (!hctx->stream_state) {
            hctx->stream_state = (void *)(uintptr_t)1;
            duct_response_close_session(&hctx->out, close_normal);
            return async_yield;
        }
        return async_done;
    }
    if (hctx->stream_id == echo_stream_id) {
        if (!hctx->stream_state) {
            hctx->stream_state = (void *)(uintptr_t)1;
            hctx->out.payload = p;
            hctx->out.flags = fl_send_copy;
            hctx->out.conn_id = duct_conn_id_same;
            hctx->out.stream_id = duct_stream_id_same;
            return async_yield;
        }
        return async_done;
    }
    s_log(hctx->stream_id, p);
    return async_done;
}

static duct_result_t
s_on_session_open([[maybe_unused]] duct_session_t *s,
                  [[maybe_unused]] duct_handle_t tok,
                  [[maybe_unused]] void *user_ctx,
                  [[maybe_unused]] duct_response_t *out,
                  [[maybe_unused]] void *proto_state)
{
    atomic_fetch_add(&g_open_count, 1);
    return rc_ok;
}

/* ── Scenarios ────────────────────────────────────────────────────────── */

static int s_ssl_recv_exact(SSL *ssl, void *buf, size_t n)
{
    size_t got = 0u;
    while (got < n) {
        int r = SSL_read(ssl, (char *)buf + got, (int)(n - got));
        if (r <= 0)
            return -1;
        got += (size_t)r;
    }
    return 0;
}

static const char *sc_handshake_and_alpn(SSL *ssl)
{
    const unsigned char *sel = nullptr;
    unsigned int sel_len = 0u;
    SSL_get0_alpn_selected(ssl, &sel, &sel_len);
    if (!sel || sel_len != sizeof(alpn_proto) - 1u || memcmp(sel, alpn_proto, sel_len) != 0)
        return "ALPN negotiation mismatch";
    return nullptr;
}

static const char *sc_echo(SSL *ssl)
{
    uint8_t plain[32];
    size_t plen = s_mux_frame(plain, sizeof plain, echo_stream_id, "echo-me!", 8u);
    if (!plen || SSL_write(ssl, plain, (int)plen) != (int)plen)
        return "echo send failed";
    uint8_t decoded[32];
    if (s_ssl_recv_exact(ssl, decoded, plen) != 0)
        return "echo response not received";
    if (memcmp(decoded, plain, plen) != 0)
        return "echo response content mismatch";
    return nullptr;
}

static const char *sc_close_notify(SSL *ssl)
{
    uint8_t trigger[16];
    size_t tlen = s_mux_frame(trigger, sizeof trigger, close_stream_id, "bye", 3u);
    if (!tlen || SSL_write(ssl, trigger, (int)tlen) != (int)tlen)
        return "close trigger send failed";
    uint8_t buf[4];
    int r = SSL_read(ssl, buf, sizeof buf);
    if (r > 0)
        return "conn still delivering data after close trigger";
    if (SSL_get_error(ssl, r) != SSL_ERROR_ZERO_RETURN)
        return "expected a clean TLS close_notify shutdown";
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    /* Every early-return goes through cleanup: below, which frees whatever
     * of these has been created so far (each free is nullptr/no-op-safe) --
     * pre-declared here, not at first use, specifically to support that. */
    EVP_PKEY *pkey = nullptr;
    X509 *cert = nullptr;
    SSL_CTX *server_ctx = nullptr,
            *client_ctx = nullptr;
    duct_engine_t *io = nullptr;
    duct_wire_t *inner = nullptr,
                *tls_wire = nullptr;
    duct_proto_t *proto = nullptr;
    duct_sock_t fd = duct_sock_bad;
    SSL *ssl = nullptr;
    bool thread_started = false;
    pthread_t th;
    const char *err = nullptr;

    if (!s_make_self_signed(&pkey, &cert)) { err = "self-signed cert generation failed"; goto cleanup; }

    server_ctx = SSL_CTX_new(TLS_server_method());
    client_ctx = SSL_CTX_new(TLS_client_method());
    if (!server_ctx || !client_ctx) { err = "SSL_CTX_new failed"; goto cleanup; }
    if (SSL_CTX_use_certificate(server_ctx, cert) != 1
        || SSL_CTX_use_PrivateKey(server_ctx, pkey) != 1) {
        err = "server cert/key install failed";
        goto cleanup;
    }
    SSL_CTX_set_alpn_select_cb(server_ctx, s_alpn_select_cb, nullptr);
    SSL_CTX_set_verify(client_ctx, SSL_VERIFY_NONE, nullptr);
    if (SSL_CTX_set_alpn_protos(client_ctx, client_alpn_wire, sizeof client_alpn_wire) != 0) {
        err = "client ALPN setup failed";
        goto cleanup;
    }

    io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) { err = "io create failed"; goto cleanup; }

    inner = mux_wire_create();
    if (!inner) { err = "inner wire create failed"; goto cleanup; }
    tls_wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = inner, .engine = duct_tls_openssl_vtbl(),
            .engine_cfg = server_ctx, .role = seal_role_responder,
            .framing = seal_framing_stream });
    if (!tls_wire) { err = "tls wire create failed"; goto cleanup; }
    proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "tls-openssl", .wire = tls_wire,
        .flags = fl_proto_multiplexed,
        .on_frame = s_on_frame,
        .handler_kind = handler_async, .handler_async = s_handler,
        .on_session_open = s_on_session_open,
    });
    if (!proto) { err = "proto create failed"; goto cleanup; }

    uint16_t port = 0u;
    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok) { err = "listen failed"; goto cleanup; }
    if (pthread_create(&th, nullptr, th_run, io) != 0) { err = "thread create failed"; goto cleanup; }
    thread_started = true;

    fd = th_connect(port);
    if (fd == duct_sock_bad) {
        err = "connect failed";
    } else if (!(ssl = SSL_new(client_ctx))) {
        err = "SSL_new failed";
    } else {
        SSL_set_fd(ssl, (int)fd);
        if (SSL_connect(ssl) != 1) {
            err = "SSL_connect failed";
        } else if (!th_wait_int(&g_open_count, 1, 2000u)) {
            err = "session not opened";
        } else {
            if (!err) err = sc_handshake_and_alpn(ssl);
            if (!err) err = sc_echo(ssl);
            if (!err) err = sc_close_notify(ssl);
        }
    }

cleanup:
    if (ssl) SSL_free(ssl);
    if (fd != duct_sock_bad) duct_sock_close(fd);
    if (thread_started) {
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    duct_wire_destroy(tls_wire);
    duct_wire_destroy(inner);
    SSL_CTX_free(server_ctx);
    SSL_CTX_free(client_ctx);
    X509_free(cert);
    EVP_PKEY_free(pkey);

    if (err) {
        fprintf(stderr, "tls_openssl: %s\n", err);
        ERR_print_errors_fp(stderr);
        return 1;
    }
    printf("tls_openssl: OK (real OpenSSL handshake+ALPN, echo, close_notify)\n");
    return 0;
}
