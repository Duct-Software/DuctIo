/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file noise_test.c
 * @brief Noise crypto core test: standalone, no engine/wire/xport
 * integration — proves @c duct_noise.c's handshake + transport AEAD over a
 * pair of real, connected loopback UDP sockets, proving the crypto core
 * standalone before any wire integration.
 *
 * Scenarios: full IKpsk2 handshake (message 1 + message 2, including the
 * responder learning/authenticating the initiator's static key and the
 * initiator authenticating the responder's), transport data both
 * directions, and a replay-rejection negative test — resending an already-
 * accepted sealed message must fail without disturbing the window for
 * genuinely new counters. The cipher contexts a transport builds are secret blocks:
 * the engine's allocator stands in OpenSSL and the key-holding calls run in its secret scope.
 */

#include "duct.h"
#include "duct_noise_internal.h"
#include "duct_core.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "test_helpers.h" /* must follow duct.h — see its own file doc */

/** @brief Bind a UDP socket on loopback, ephemeral port; @p out_port filled
 *  with the OS-assigned port. */
static duct_sock_t s_udp_bind(uint16_t *out_port)
{
    duct_sock_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    duct_do_if(fd == duct_sock_bad, return duct_sock_bad);
    struct sockaddr_in addr = { .sin_family = AF_INET };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        duct_sock_close(fd);
        return duct_sock_bad;
    }
    socklen_t alen = sizeof addr;
    if (getsockname(fd, (struct sockaddr *)&addr, &alen) != 0) {
        duct_sock_close(fd);
        return duct_sock_bad;
    }
    *out_port = ntohs(addr.sin_port);
    return fd;
}

/** @brief connect() @p fd to 127.0.0.1:@p port, so plain send()/recv() work. */
static bool s_udp_connect(duct_sock_t fd, uint16_t port)
{
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    return connect(fd, (struct sockaddr *)&addr, sizeof addr) == 0;
}

static const char *s_send(duct_sock_t fd, const void *buf, size_t len)
{
    return send(fd, buf, len, 0) == (ssize_t)len ? nullptr : "send failed";
}

static const char *s_recv(duct_sock_t fd, void *buf, size_t cap, size_t *out_len)
{
    ssize_t n = recv(fd, buf, cap, 0);
    duct_do_if(n < 0, return "recv failed");
    *out_len = (size_t)n;
    return nullptr;
}

/** @brief One handshake round-trip: message 1 (initiator -> responder,
 *  carrying @p hello as its cleartext payload) then message 2 (responder ->
 *  initiator). Isolated in its own function, not inline in @c main, so every
 *  buffer it needs is scoped to a call that returns (not a goto target) —
 *  sidesteps the "goto must not jump over a declaration with initializer"
 *  constraint entirely for these locals. */
static const char *
s_do_handshake(duct_noise_hs_t *hs_i, duct_noise_hs_t *hs_r,
              duct_sock_t sock_i, duct_sock_t sock_r,
              const duct_noise_keypair_t *kp_i, const char *hello, size_t hello_len)
{
    uint8_t msg1[256];
    size_t msg1_len = 0u;
    if (!duct_noise_hs_write_msg1(hs_i, (duct_view_u8){ (void *)hello, hello_len },
                                  msg1, sizeof msg1, &msg1_len))
        return "write_msg1 failed";
    const char *err = s_send(sock_i, msg1, msg1_len);
    if (err) return err;

    uint8_t rbuf[256];
    size_t rlen = 0u;
    if ((err = s_recv(sock_r, rbuf, sizeof rbuf, &rlen))) return err;

    uint8_t learned_static[32];
    uint8_t payload_out[64];
    size_t payload_out_len = 0u;
    if (!duct_noise_hs_read_msg1(hs_r, (duct_view_u8){ rbuf, rlen },
                                 learned_static, payload_out, sizeof payload_out, &payload_out_len))
        return "read_msg1 failed";
    if (memcmp(learned_static, kp_i->pub, 32u) != 0)
        return "learned static key mismatch";
    if (payload_out_len != hello_len || memcmp(payload_out, hello, hello_len) != 0)
        return "msg1 payload mismatch";

    uint8_t msg2[128];
    size_t msg2_len = 0u;
    if (!duct_noise_hs_write_msg2(hs_r, (duct_view_u8){}, msg2, sizeof msg2, &msg2_len))
        return "write_msg2 failed";
    if ((err = s_send(sock_r, msg2, msg2_len))) return err;

    if ((err = s_recv(sock_i, rbuf, sizeof rbuf, &rlen))) return err;
    if (!duct_noise_hs_read_msg2(hs_i, (duct_view_u8){ rbuf, rlen }))
        return "read_msg2 failed (mutual auth)";
    return nullptr;
}

/** @brief One transport-data round trip @p from -> @p to, plus the
 *  replay-rejection negative check on the same sealed message. Same
 *  own-function scoping rationale as @ref s_do_handshake. */
static const char *
s_do_transport_round(duct_noise_transport_t *send_side, duct_noise_transport_t *recv_side,
                     duct_sock_t sock_from, duct_sock_t sock_to,
                     const char *plain, size_t plain_len)
{
    uint8_t sealed[64];
    size_t sealed_len = duct_noise_transport_seal(send_side, &(duct_view_u8){ (void *)plain, plain_len },
                                                  1u, sealed, sizeof sealed);
    if (!sealed_len) return "seal failed";
    const char *err = s_send(sock_from, sealed, sealed_len);
    if (err) return err;

    uint8_t rbuf[64];
    size_t rlen = 0u;
    if ((err = s_recv(sock_to, rbuf, sizeof rbuf, &rlen))) return err;

    uint8_t opened[32];
    size_t opened_len = 0u;
    if (!duct_noise_transport_unseal(recv_side, (duct_view_u8){ rbuf, rlen }, opened, sizeof opened, &opened_len))
        return "unseal failed";
    if (opened_len != plain_len || memcmp(opened, plain, opened_len) != 0)
        return "transport payload mismatch";

    if (duct_noise_transport_unseal(recv_side, (duct_view_u8){ rbuf, rlen }, opened, sizeof opened, &opened_len))
        return "replayed message was accepted";
    return nullptr;
}

/** @brief Fail unless OpenSSL allocates through the engine and @p ctx, a context a transport
 *  built over its key, is a secret block. */
static const char *s_secret_ctx(const void *ctx)
{
    CRYPTO_malloc_fn malloc_fn = nullptr;
    CRYPTO_get_mem_functions(&malloc_fn, nullptr, nullptr);
    if (malloc_fn == CRYPTO_malloc)
        return "OpenSSL kept its own allocator";
    if (!ctx)
        return "a transport built no cipher context";
    auto hdr = (const duct_alloc_hdr_t *)((const unsigned char *)ctx - sizeof(duct_alloc_hdr_t));
    return hdr->secret ? nullptr : "a transport's cipher context is not a secret block";
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    duct_sock_t sock_i = duct_sock_bad,
                sock_r = duct_sock_bad;
    duct_noise_hs_t *hs_i = nullptr,
                    *hs_r = nullptr;
    const char *err = nullptr;
    duct_noise_keypair_t kp_i = {}, kp_r = {};
    uint8_t psk[32] = {};
    uint16_t port_i = 0u, port_r = 0u;
    duct_noise_transport_t t_i = {}, t_r = {};
    static const char hello[] = "hello-noise";

    if (!duct_noise_keypair_generate(&kp_i) || !duct_noise_keypair_generate(&kp_r)) {
        err = "keypair generation failed";
        goto cleanup;
    }
    RAND_bytes(psk, sizeof psk);

    sock_i = s_udp_bind(&port_i);
    sock_r = s_udp_bind(&port_r);
    if (sock_i == duct_sock_bad || sock_r == duct_sock_bad) { err = "udp bind failed"; goto cleanup; }
    if (!s_udp_connect(sock_i, port_r) || !s_udp_connect(sock_r, port_i)) {
        err = "udp connect failed";
        goto cleanup;
    }

    hs_i = duct_noise_hs_create(&kp_i, kp_r.pub, psk, true);
    hs_r = duct_noise_hs_create(&kp_r, nullptr, psk, false);
    if (!hs_i || !hs_r) { err = "handshake state create failed"; goto cleanup; }

    err = s_do_handshake(hs_i, hs_r, sock_i, sock_r, &kp_i, hello, sizeof(hello) - 1u);
    if (err) goto cleanup;

    if (!duct_noise_hs_split(hs_i, &t_i) || !duct_noise_hs_split(hs_r, &t_r)) {
        err = "split failed"; goto cleanup;
    }
    duct_noise_hs_destroy(hs_i); hs_i = nullptr;
    duct_noise_hs_destroy(hs_r); hs_r = nullptr;

    for (unsigned round = 0u; round < 4u; ++round) {
        char plain[32];
        int plen = snprintf(plain, sizeof plain, "ping-%u", round);

        err = s_do_transport_round(&t_i, &t_r, sock_i, sock_r, plain, (size_t)plen);
        if (err) goto cleanup;
        err = s_do_transport_round(&t_r, &t_i, sock_r, sock_i, plain, (size_t)plen);
        if (err) goto cleanup;
    }

    if ((err = s_secret_ctx(t_i.send_ctx)) || (err = s_secret_ctx(t_i.recv_ctx)))
        goto cleanup;

cleanup:
    duct_noise_transport_destroy(&t_i);
    duct_noise_transport_destroy(&t_r);
    duct_noise_hs_destroy(hs_i);
    duct_noise_hs_destroy(hs_r);
    if (sock_i != duct_sock_bad) duct_sock_close(sock_i);
    if (sock_r != duct_sock_bad) duct_sock_close(sock_r);

    if (err) {
        fprintf(stderr, "noise: %s\n", err);
        return 1;
    }
    printf("noise: OK (IKpsk2 handshake, mutual auth, transport data both ways, replay rejected)\n");
    return 0;
}
