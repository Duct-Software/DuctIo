/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/**
 * @file https_server.c
 * @brief Primitive HTTPS server built from the public API only:
 * duct_wire_create_sealed wraps a per-listener SSL_CTX,
 * TLS 1.3 pinned by the adapter itself. on_frame only ever sees decrypted
 * bytes — no SSL type or handshake state anywhere in this file.
 *
 * main() generates a self-signed cert, starts the engine, binds the
 * listener. A second thread plays an external client: three plain
 * OpenSSL HTTPS requests over their own TLS connections (/, /about, an
 * unknown path), each printing the response status line.
 */

#include "duct.h"
#include "duct_tls_openssl.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

static constexpr size_t http_header_buf_size = 8192u;

/** @brief Per-connection request buffer — one TLS record at a time, not
 *  one HTTP request at a time, so the header block may span several
 *  on_frame calls. */
typedef struct {
    char   buf[http_header_buf_size];
    size_t len;
} http_session_t;

static duct_result_t
s_create_state([[maybe_unused]] duct_session_t *s, [[maybe_unused]] void *ctx, void **out)
{
    auto st = duct_new(http_session_t);
    duct_do_if(!st, return rc_no_memory);
    *out = st;
    return rc_ok;
}

static void
s_destroy_state([[maybe_unused]] duct_session_t *s, [[maybe_unused]] void *ctx, void *state)
{
    auto st = (http_session_t *)state;
    duct_del(st);
}

static const char *
s_find_header_end(const char *buf, size_t len)
{
    for (size_t i = 0u; i + 4u <= len; ++i)
        if (memcmp(buf + i, "\r\n\r\n", 4u) == 0)
            return buf + i;
    return nullptr;
}

typedef struct {
    const char *status,
               *body;
} http_page_t;

static http_page_t
s_page_for(const char *path)
{
    if (strcmp(path, "/") == 0)
        return (http_page_t){ "200 OK",
            "<html><body><h1>Hello from DuctIO over TLS 1.3</h1></body></html>" };
    if (strcmp(path, "/about") == 0)
        return (http_page_t){ "200 OK",
            "<html><body><p>Served by duct_wire_create_sealed + "
            "duct_tls_openssl_vtbl, one SSL_CTX per listener.</p></body></html>" };
    return (http_page_t){ "404 Not Found",
        "<html><body><h1>404 Not Found</h1></body></html>" };
}

/** @brief Hand the first @p len bytes of the @c duct_new block @p buf to the
 *  framework as the response, then close the session — this server answers
 *  one request per connection. With no @c release set, the framework frees
 *  @p buf with @c duct_del once it is staged. */
static void
s_respond_owned_then_close(duct_response_t *out, void *buf, size_t len)
{
    *out = (duct_response_t){
        .payload = { buf, len },
        .flags = fl_send_owned,
        .conn_id = duct_conn_id_same,
        .stream_id = duct_stream_id_same,
        .control.stream_op_conn_id = duct_conn_id_same,
        .control.close_target = close_target_session,
        .control.close_reason = close_normal,
    };
}

/** @brief Write @p peer as address:port, an IPv6 address bracketed. */
static void
s_peer_text(const duct_peer_t *peer, char *out, size_t cap)
{
    char ip[INET6_ADDRSTRLEN] = "?";
    duct_discard inet_ntop(peer->family, &peer->addr, ip, sizeof ip);
    snprintf(out, cap, peer->family == AF_INET6 ? "[%s]:%u" : "%s:%u", ip, (unsigned)peer->port);
}

static duct_result_t
s_on_frame(duct_session_t *s, duct_conn_id_t conn_id,
          const duct_frame_t *frame, duct_response_t *out, void *proto_state)
{
    auto st = (http_session_t *)proto_state;

    size_t room = sizeof(st->buf) - st->len;
    size_t copy = frame->payload.size < room ? frame->payload.size : room;
    memcpy(st->buf + st->len, frame->payload.data, copy);
    st->len += copy;

    if (!s_find_header_end(st->buf, st->len)) {
        if (st->len < sizeof(st->buf))
            return rc_ok; /* headers incomplete, wait for the next frame */

        static const char msg[] =
            "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n";
        duct_response_respond_then_close(out, duct_view_bytes((duct_view_cc){ msg, sizeof(msg) - 1u }),
                                         fl_send_static, fl_frame_none, close_protocol_error);
        return rc_ok;
    }

    char method[8] = {},
         path[256] = {};
    sscanf(st->buf, "%7s %255s", method, path);

    auto page = s_page_for(path);
    duct_peer_t client = {};
    char who[INET6_ADDRSTRLEN + sizeof "[]:65535"] = "?";
    if (duct_conn_addrs(s, conn_id, nullptr, &client) == rc_ok)
        s_peer_text(&client, who, sizeof who);
    printf("server: %s %s %s -> %s\n", who, method, path, page.status);

    size_t body_len = strlen(page.body);
    size_t cap = 256u + body_len;
    auto resp = duct_at(duct_new(char, cap));
    duct_do_if(!resp, return rc_drop);
    size_t resp_len = (size_t)snprintf(resp, cap,
        "HTTP/1.1 %s\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n%s",
        page.status, body_len, page.body);

    s_respond_owned_then_close(out, resp, resp_len);
    return rc_ok;
}

/** @brief Self-signed EC P-256 leaf, generated fresh on every run — no
 *  checked-in key material, no external files. */
static bool
s_make_self_signed(EVP_PKEY **out_pkey, X509 **out_cert)
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
    X509_set_version(cert, 2); /* X.509 v3 is version value 2, zero-based */
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 31536000L); /* ~1 year */
    X509_set_pubkey(cert, pkey);
    auto name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char *)"duct-https-example", -1, -1, 0);
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

typedef struct {
    uint16_t  port;
    SSL_CTX  *client_ctx;
} client_args_t;

static void
s_client_request(SSL_CTX *ctx, uint16_t port, const char *path)
{
    auto fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == duct_sock_bad) {
        fprintf(stderr, "client: socket failed\n");
        return;
    }
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        fprintf(stderr, "client: connect failed\n");
        duct_sock_close(fd);
        return;
    }

    auto ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)fd);
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "client: TLS handshake failed for %s\n", path);
        SSL_free(ssl);
        duct_sock_close(fd);
        return;
    }

    char req[256];
    int req_len = snprintf(req, sizeof req,
        "GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", path);
    SSL_write(ssl, req, req_len);

    char resp[4096];
    size_t total = 0u;
    for (;;) {
        int r = SSL_read(ssl, resp + total, (int)(sizeof(resp) - 1u - total));
        if (r <= 0)
            break;
        total += (size_t)r;
    }
    resp[total] = '\0';

    auto line_end = strstr(resp, "\r\n");
    size_t status_len = line_end ? (size_t)(line_end - resp) : total;
    printf("client: GET %-8s -> %.*s\n", path, (int)status_len, resp);

    SSL_free(ssl);
    duct_sock_close(fd);
}

static void *
s_client_thread(void *arg)
{
    auto a = (const client_args_t *)arg;
    s_client_request(a->client_ctx, a->port, "/");
    s_client_request(a->client_ctx, a->port, "/about");
    s_client_request(a->client_ctx, a->port, "/nope");
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    EVP_PKEY      *pkey = nullptr;
    X509          *cert = nullptr;
    SSL_CTX       *server_ctx = nullptr,
                  *client_ctx = nullptr;
    duct_engine_t *io = nullptr;
    duct_wire_t   *tls_wire = nullptr;
    duct_proto_t  *proto = nullptr;
    pthread_t      client_th;
    const char    *err = nullptr;
    uint16_t       port = 0u;
    client_args_t  client_args = {};

    if (!s_make_self_signed(&pkey, &cert)) { err = "self-signed cert generation failed"; goto cleanup; }

    server_ctx = SSL_CTX_new(TLS_server_method());
    client_ctx = SSL_CTX_new(TLS_client_method());
    if (!server_ctx || !client_ctx) { err = "SSL_CTX_new failed"; goto cleanup; }
    if (SSL_CTX_use_certificate(server_ctx, cert) != 1
        || SSL_CTX_use_PrivateKey(server_ctx, pkey) != 1) {
        err = "server cert/key install failed";
        goto cleanup;
    }
    SSL_CTX_set_verify(client_ctx, SSL_VERIFY_NONE, nullptr); /* self-signed leaf, loopback demo */

    io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) { err = "engine launch failed"; goto cleanup; }

    tls_wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = nullptr, .engine = duct_tls_openssl_vtbl(),
            .engine_cfg = server_ctx, .role = seal_role_responder,
            .framing = seal_framing_stream });
    if (!tls_wire) { err = "tls wire create failed"; goto cleanup; }
    proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "https", .wire = tls_wire,
        .on_frame = s_on_frame,
        .create_state = s_create_state,
        .destroy_state = s_destroy_state,
        .max_response = 4096u,
    });
    if (proto)
        proto->owned_wire = tls_wire;
    else
        duct_wire_destroy(tls_wire);
    if (!proto) { err = "proto create failed"; goto cleanup; }

    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok) { err = "listen failed"; goto cleanup; }
    printf("server: listening on https://127.0.0.1:%u\n", port);

    client_args = (client_args_t){ .port = port, .client_ctx = client_ctx };
    if (pthread_create(&client_th, nullptr, s_client_thread, &client_args) != 0) {
        err = "client thread create failed";
        goto cleanup;
    }
    pthread_join(client_th, nullptr);

cleanup:
    if (io) {
        duct_engine_stop(io);
        duct_engine_destroy(io);
    }
    duct_proto_destroy(proto); /* frees tls_wire too, via owned_wire above */
    SSL_CTX_free(server_ctx);
    SSL_CTX_free(client_ctx);
    X509_free(cert);
    EVP_PKEY_free(pkey);

    if (err) {
        fprintf(stderr, "https_server: %s\n", err);
        ERR_print_errors_fp(stderr);
        return 1;
    }
    printf("https_server: done\n");
    return 0;
}
