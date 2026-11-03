/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file noise_stream_open_test.c
 *  @brief A stream conn's opening: the packets a client's config names reach a
 *  hand-written TCP responder as bytes of the stream ahead of message 1, whole
 *  and in order, and the handshake behind them completes.
 *
 *  Four dials of the real client, each against a listener of its own. `five
 *  packets` holds the plain case. `past the stream limit` has a source with twelve
 *  packets and sees eight leave, then message 1 parse in the ninth packet's
 *  place. `a packet past the room` has a ceiling under the second packet and sees
 *  only the first. `no ceiling` has the source named and the wire without a
 *  ceiling, and sees message 1 first. On Linux the responder also asks its socket
 *  how many payload segments it took, at least one per packet and one for message
 *  1. After message 2 the responder reads the client's key confirmation and
 *  unseals it, which proves the stream stayed in step.
 */

#include "duct.h"
#include "duct_tls.h"
#include "duct_noise.h"
#include "duct_noise_internal.h"
#include "duct_xopening.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#ifdef __linux__
#include <netinet/tcp.h>
#endif

#include "test_helpers.h"

#ifdef __linux__
/** @brief Byte offset of @c tcpi_data_segs_in in the kernel's @c struct tcp_info.
 *  The libc header's struct ends before the field, so it is read by offset. */
static constexpr size_t so_data_segs_in_at = 152u;

/** @brief Read the segments carrying payload that @p fd has taken off the wire.
 *  @return the count, @c UINT32_MAX where the kernel's report ends short of it. */
static uint32_t so_data_segs_in(duct_sock_t fd)
{
    uint8_t info[so_data_segs_in_at + sizeof(uint32_t)];
    socklen_t len = sizeof info;
    uint32_t segs = UINT32_MAX;
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, info, &len) == 0 && len >= sizeof info)
        memcpy(&segs, info + so_data_segs_in_at, sizeof segs);
    return segs;
}
#endif

/** @brief Lengths of the packets the source hands out, cycling. */
static const size_t so_len[] = { 64u, 120u, 33u, 700u, 1200u, 17u };
static constexpr unsigned so_lens = sizeof so_len / sizeof *so_len;
static constexpr uint16_t so_ceiling = 1452u;

/** @brief Packets the source has before its 0; set before each dial. */
static unsigned s_count;

/** @brief Byte @p j of the source's packet @p idx. */
static uint8_t so_byte(unsigned idx, size_t j)
{
    return (uint8_t)(0xA0u + 29u * idx + 5u * j);
}

static size_t so_next([[maybe_unused]] void *ctx, unsigned idx, uint8_t *out, size_t cap)
{
    if (idx >= s_count)
        return 0u;
    size_t n = so_len[idx % so_lens];
    for (size_t j = 0u; j < n && n <= cap; ++j)
        out[j] = so_byte(idx, j);
    return n;
}

static duct_result_t
so_cli_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             [[maybe_unused]] const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

typedef struct {
    const char *name;
    uint16_t    ceiling; /**< The client wire's opening ceiling. */
    unsigned    count,   /**< Packets the source has. */
                leaves;  /**< Packets that must reach the responder. */
} so_case_t;

static const so_case_t so_cases[] = {
    { "five packets",           so_ceiling, 5u,  5u },
    { "past the stream limit",  so_ceiling, 12u, duct_x_opening_max },
    { "a packet past the room", 100u,       5u,  1u },
    { "no ceiling",             0u,         5u,  0u },
};
static constexpr unsigned so_n = sizeof so_cases / sizeof *so_cases;

/** @brief Listen on an ephemeral loopback port.
 *  @return the socket and its port in @p port, or @c duct_sock_bad. */
static duct_sock_t so_listen(uint16_t *port)
{
    duct_sock_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == duct_sock_bad)
        return duct_sock_bad;
    struct sockaddr_in a = { .sin_family = AF_INET };
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    socklen_t alen = sizeof a;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(fd, 1) != 0
        || getsockname(fd, (struct sockaddr *)&a, &alen) != 0) {
        duct_sock_close(fd);
        return duct_sock_bad;
    }
    *port = ntohs(a.sin_port);
    return fd;
}

/** @brief Read one length-prefixed Noise PDU off @p fd into @p buf.
 *  @return its length, 0 on a failed read or a prefix past @p cap. */
static size_t so_read_pdu(duct_sock_t fd, uint8_t *buf, size_t cap)
{
    uint8_t hdr[2];
    if (th_read_exact(fd, hdr, sizeof hdr) != 0)
        return 0u;
    size_t n = ((size_t)hdr[0] << 8u) | hdr[1];
    return n && n <= cap && th_read_exact(fd, buf, n) == 0 ? n : 0u;
}

/** @brief The PSK of the one peer there is. */
static bool so_psk_for(void *ctx, [[maybe_unused]] const uint8_t remote[duct_noise_key_size],
                       uint8_t out[duct_noise_key_size])
{
    memcpy(out, ctx, duct_noise_key_size);
    return true;
}

/** @brief Accept the client on @p lfd and walk its stream: the opening packets,
 *  message 1, message 2 back, and under IKpsk2 the key confirmation, under XKpsk3
 *  message 3.
 *  @return nullptr when each held, else what failed. */
static const char *so_peer(duct_sock_t lfd, const so_case_t *c,
                           const duct_noise_keypair_t *srv_kp, const uint8_t *psk,
                           duct_noise_pattern_t pattern)
{
    struct pollfd pfd = { .fd = lfd, .events = POLLIN };
    if (poll(&pfd, 1, TH_ROUNDTRIP_TIMEOUT_MS) <= 0)
        return "the client never dialed";
    duct_sock_t fd = accept(lfd, nullptr, nullptr);
    if (fd == duct_sock_bad)
        return "accept failed";

    const char *err = nullptr;
    duct_noise_hs_t *hs = nullptr;
    duct_noise_transport_t tp = {};
    uint8_t buf[2048],
            out[2048],
            learned[duct_noise_key_size],
            offer[duct_noise_hs_pad_max];
    size_t len = 0u,
           offer_len = 0u,
           plen = 0u;
    bool ok = false;

    for (unsigned i = 0u; i < c->leaves; ++i) {
        size_t n = so_len[i % so_lens];
        if (th_read_exact(fd, buf, n) != 0) {
            err = "an opening packet never arrived";
            goto done;
        }
        for (size_t j = 0u; j < n; ++j)
            if (buf[j] != so_byte(i, j)) {
                err = "an opening packet arrived altered or out of order";
                goto done;
            }
    }
    len = so_read_pdu(fd, buf, sizeof buf);
    if (!len) {
        err = "message 1 never followed the opening";
        goto done;
    }
#ifdef __linux__
    /* A write of its own per packet is a segment of its own at this socket,
     * message 1 the last of them. */
    if (so_data_segs_in(fd) < c->leaves + 1u) {
        err = "the opening's packets did not arrive as segments of their own";
        goto done;
    }
#endif
    hs = duct_noise_hs_create_for(pattern, srv_kp, nullptr, psk, false, (duct_view_u8){});
    if (!hs) { err = "responder handshake create failed"; goto done; }
    ok = pattern == noise_pattern_xkpsk3
        ? duct_noise_hs_read_msg1_xk(hs, (duct_view_u8){ buf, len }, offer, sizeof offer, &offer_len)
        : duct_noise_hs_read_msg1(hs, (duct_view_u8){ buf, len }, learned, offer, sizeof offer, &offer_len);
    if (!ok) {
        err = "message 1 did not parse behind the opening";
        goto done;
    }
    ok = pattern == noise_pattern_xkpsk3
        ? duct_noise_hs_write_msg2_xk(hs, (duct_view_u8){}, out + 2u, sizeof out - 2u, &len)
        : duct_noise_hs_write_msg2(hs, (duct_view_u8){}, out + 2u, sizeof out - 2u, &len);
    if (!ok) {
        err = "write_msg2 failed";
        goto done;
    }
    out[0] = (uint8_t)(len >> 8u);
    out[1] = (uint8_t)len;
    if (send(fd, (const char *)out, (int)(2u + len), 0) != (int)(2u + len)) {
        err = "message 2 send failed";
        goto done;
    }
    if (pattern == noise_pattern_xkpsk3) {
        len = so_read_pdu(fd, buf, sizeof buf);
        if (!len) {
            err = "the client's message 3 never arrived";
            goto done;
        }
        if (!duct_noise_hs_read_msg3_xk(hs, (duct_view_u8){ buf, len }, so_psk_for, (void *)psk, learned,
                                        offer, sizeof offer, &offer_len)) {
            err = "message 3 did not read";
            goto done;
        }
    }
    if (!duct_noise_hs_split(hs, &tp)) { err = "responder split failed"; goto done; }
    if (pattern == noise_pattern_xkpsk3)
        goto done;
    len = so_read_pdu(fd, buf, sizeof buf);
    if (!len) {
        err = "the client's key confirmation never arrived";
        goto done;
    }
    if (!duct_noise_transport_unseal(&tp, (duct_view_u8){ buf, len }, out, sizeof out, &plen))
        err = "the key confirmation did not unseal";

done:
    duct_noise_hs_destroy(hs);
    duct_noise_transport_destroy(&tp);
    duct_sock_close(fd);
    return err;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    duct_noise_pattern_t pattern = argc > 1 && strcmp(argv[1], "xk") == 0 ? noise_pattern_xkpsk3
                                                                          : noise_pattern_ikpsk2;

    duct_noise_keypair_t srv_kp, cli_kp;
    if (!duct_noise_keypair_generate(&srv_kp) || !duct_noise_keypair_generate(&cli_kp)) {
        fprintf(stderr, "noise_stream_open: keypair generation failed\n");
        return 1;
    }
    uint8_t psk[duct_noise_key_size] = {};
    duct_noise_cfg_t cli_cfg = { .local_static = cli_kp, .opening_next = so_next,
                                 .suite = { .pattern = pattern } };
    memcpy(cli_cfg.remote_static_pub, srv_kp.pub, duct_noise_key_size);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) {
        fprintf(stderr, "noise_stream_open: io create failed\n");
        return 1;
    }

    const char *err = nullptr;
    duct_proto_t *cli[so_n] = {};
    pthread_t th;
    bool running = false;
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        err = "engine thread create failed";
        goto done;
    }
    running = true;
    for (unsigned i = 0u; i < so_n && !err; ++i) {
        auto wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .engine = duct_noise_vtbl(), .engine_cfg = &cli_cfg,
            .role = seal_role_initiator, .framing = seal_framing_stream,
            .opening_ceiling = so_cases[i].ceiling });
        if (!wire) { err = "client sealed wire create failed"; break; }
        cli[i] = duct_proto_create(&(duct_proto_cfg_t){
            .name = "noise-stream-open-cli", .wire = wire,
            .on_frame = so_cli_frame, .max_response = 2048u });
        if (cli[i])
            cli[i]->owned_wire = wire;
        else
            duct_wire_destroy(wire);
        if (!cli[i]) { err = "client proto create failed"; break; }

        uint16_t port = 0u;
        duct_sock_t lfd = so_listen(&port);
        if (lfd == duct_sock_bad) { err = "listen failed"; break; }
        s_count = so_cases[i].count;
        char addr[64];
        snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)port);
        if (duct_io_connect(io, addr, cli[i], nullptr, x_tcp) != rc_ok)
            err = "connect failed";
        else
            err = so_peer(lfd, &so_cases[i], &srv_kp, psk, pattern);
        duct_sock_close(lfd);
        if (err)
            fprintf(stderr, "noise_stream_open: case \"%s\"\n", so_cases[i].name);
    }

done:
    duct_engine_stop(io);
    if (running)
        pthread_join(th, nullptr);
    duct_engine_destroy(io);
    for (unsigned i = 0u; i < so_n; ++i)
        duct_proto_destroy(cli[i]);
    if (err) {
        fprintf(stderr, "noise_stream_open: %s\n", err);
        return 1;
    }
    printf("noise_stream_open: OK (%s, the opening's packets ahead of message 1 on a stream, "
           "the stream's limit, a ceiling that cuts it, none without one)\n",
           pattern == noise_pattern_xkpsk3 ? "XKpsk3" : "IKpsk2");
    return 0;
}
