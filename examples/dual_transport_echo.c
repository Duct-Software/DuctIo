/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/**
 * @file dual_transport_echo.c
 * @brief TCP and UDP echo bound to the same address:port. TCP and UDP
 * are independent port namespaces at the OS level, so duct_listener_bind's
 * @c kind is the only thing that decides which transport a given bind
 * call opens — the numeric port never conflicts across the two.
 *
 * main() binds TCP first on an ephemeral port, then UDP explicitly on
 * that same port, then round-trips one message over each from a client
 * thread to prove both actually carry traffic.
 */

#include "duct.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

duct_wire_t *duct_wire_create_length_prefix(size_t max_frame);
duct_wire_t *duct_wire_create_dgram_batch(size_t max_dgram, bool framed);

static duct_result_t
s_tcp_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
              const duct_frame_t *frame, duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

static duct_result_t
s_udp_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
              const duct_frame_t *frame, duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_response_same(out, frame->payload, fl_send_copy, 0);
    return rc_ok;
}

static duct_sock_t
s_connect(int socktype, uint16_t port)
{
    auto fd = socket(AF_INET, socktype, 0);
    if (fd == duct_sock_bad)
        return duct_sock_bad;
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) == 0)
        return fd;
    duct_sock_close(fd);
    return duct_sock_bad;
}

/** @brief Client side of the built-in length-prefix wire: 4-byte big-endian
 *  length, then the payload. */
static bool
s_tcp_roundtrip(uint16_t port, const char *msg)
{
    auto fd = s_connect(SOCK_STREAM, port);
    duct_do_if(fd == duct_sock_bad, return false);

    size_t len = strlen(msg);
    uint8_t hdr[4] = {
        (uint8_t)(len >> 24u), (uint8_t)(len >> 16u), (uint8_t)(len >> 8u), (uint8_t)len,
    };
    bool ok = send(fd, (const char *)hdr, sizeof hdr, 0) == (int)sizeof hdr
           && send(fd, msg, (int)len, 0) == (int)len;

    char buf[256] = {};
    ok = ok && recv(fd, (char *)hdr, sizeof hdr, 0) == (int)sizeof hdr
            && recv(fd, buf, (int)len, 0) == (int)len
            && memcmp(buf, msg, len) == 0;
    duct_sock_close(fd);
    return ok;
}

static bool
s_udp_roundtrip(uint16_t port, const char *msg)
{
    auto fd = s_connect(SOCK_DGRAM, port);
    duct_do_if(fd == duct_sock_bad, return false);

    size_t len = strlen(msg);
    char buf[256] = {};
    bool ok = send(fd, msg, (int)len, 0) == (int)len
           && recv(fd, buf, sizeof buf, 0) == (int)len
           && memcmp(buf, msg, len) == 0;
    duct_sock_close(fd);
    return ok;
}

static void *
s_client_thread(void *arg)
{
    auto port = *(uint16_t *)arg;
    printf("client: tcp echo -> %s\n", s_tcp_roundtrip(port, "hello-over-tcp") ? "ok" : "FAILED");
    printf("client: udp echo -> %s\n", s_udp_roundtrip(port, "hello-over-udp") ? "ok" : "FAILED");
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    duct_engine_t *io = nullptr;
    duct_wire_t   *tcp_wire = nullptr,
                  *udp_wire = nullptr;
    duct_proto_t  *tcp_proto = nullptr,
                  *udp_proto = nullptr;
    pthread_t      client_th;
    const char    *err = nullptr;
    uint16_t       port = 0u;

    io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) { err = "engine launch failed"; goto cleanup; }

    tcp_wire = duct_wire_create_length_prefix(0u);
    if (!tcp_wire) { err = "tcp wire create failed"; goto cleanup; }
    tcp_proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "tcp-echo", .wire = tcp_wire, .on_frame = s_tcp_on_frame,
    });
    if (tcp_proto)
        tcp_proto->owned_wire = tcp_wire;
    else
        duct_wire_destroy(tcp_wire);
    if (!tcp_proto) { err = "tcp proto create failed"; goto cleanup; }

    udp_wire = duct_wire_create_dgram_batch(0u, false);
    if (!udp_wire) { err = "udp wire create failed"; goto cleanup; }
    udp_proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "udp-echo", .wire = udp_wire, .on_frame = s_udp_on_frame,
        .max_response = 65535u,
    });
    if (udp_proto)
        udp_proto->owned_wire = udp_wire;
    else
        duct_wire_destroy(udp_wire);
    if (!udp_proto) { err = "udp proto create failed"; goto cleanup; }

    {
        const duct_proto_t *tcp_protos[1] = { tcp_proto };
        if (duct_listener_bind(io, &(duct_listener_cfg_t){
                .kind = listener_stream, .addr = "127.0.0.1",
                .n_protos = 1, .protos = tcp_protos,
            }, &port, nullptr, 0u, nullptr) != rc_ok) {
            err = "tcp bind failed";
            goto cleanup;
        }
    }
    printf("server: tcp echo on 127.0.0.1:%u\n", port);

    {
        /* port is non-zero now: an explicit same-port bind, not ephemeral
         * resolution — TCP and UDP have independent port namespaces, so
         * this never conflicts with the tcp listener above. */
        const duct_proto_t *udp_protos[1] = { udp_proto };
        if (duct_listener_bind(io, &(duct_listener_cfg_t){
                .kind = listener_dgram, .addr = "127.0.0.1",
                .n_protos = 1, .protos = udp_protos,
            }, &port, nullptr, 0u, nullptr) != rc_ok) {
            err = "udp bind on the tcp port failed";
            goto cleanup;
        }
    }
    printf("server: udp echo on 127.0.0.1:%u (same port)\n", port);

    if (pthread_create(&client_th, nullptr, s_client_thread, &port) != 0) {
        err = "client thread create failed";
        goto cleanup;
    }
    pthread_join(client_th, nullptr);

cleanup:
    if (io) {
        duct_engine_stop(io);
        duct_engine_destroy(io);
    }
    duct_proto_destroy(tcp_proto); /* frees tcp_wire too, via owned_wire above */
    duct_proto_destroy(udp_proto); /* frees udp_wire too, via owned_wire above */

    if (err) {
        fprintf(stderr, "dual_transport_echo: %s\n", err);
        return 1;
    }
    printf("dual_transport_echo: done\n");
    return 0;
}
