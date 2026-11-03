/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file path_mtu_test.c
 * @brief duct_conn_path_mtu over loopback, on a stream pair and on a datagram
 * pair over IPv4 and IPv6.
 *
 * Each client leg answers from its connected socket, loopback's 65536 clamped
 * to 65535, and so does the stream server's accepted leg. A shared datagram
 * server's leg holds no socket of its own and is refused as unsupported. A leg
 * id past the session's legs is refused as an argument, an empty slot as an
 * order. The client's stream leg, under no lowat, answers no quantum; its
 * datagram leg answers one from its send buffer on Linux, where its socket also
 * refuses to fragment in either family.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>

#ifdef __linux__
#include <netinet/in.h>
#include <sys/socket.h>
#endif

static atomic_int g_opened = 0;
static atomic_int g_cli_rc = -1;
static atomic_int g_cli_mtu = 0;
static atomic_int g_cli_quantum = -1;
static atomic_int g_srv_rc = -1;
static atomic_int g_srv_mtu = 0;
static atomic_int g_range_rc = -1;
static atomic_int g_empty_rc = -1;

static const char ping[] = "path-mtu-ping";

static void s_reset(void)
{
    duct_atomic_store(&g_opened, 0, relaxed);
    duct_atomic_store(&g_cli_rc, -1, relaxed);
    duct_atomic_store(&g_cli_mtu, 0, relaxed);
    duct_atomic_store(&g_cli_quantum, -1, relaxed);
    duct_atomic_store(&g_srv_rc, -1, relaxed);
    duct_atomic_store(&g_srv_mtu, 0, relaxed);
    duct_atomic_store(&g_range_rc, -1, relaxed);
    duct_atomic_store(&g_empty_rc, -1, relaxed);
}

static duct_result_t
srv_on_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    uint16_t mtu = 0u;
    duct_atomic_store(&g_srv_rc, (int)duct_conn_path_mtu(s, duct_conn_id_primary, &mtu),
                      relaxed);
    duct_atomic_store(&g_srv_mtu, (int)mtu, relaxed);
    duct_atomic_fetch(add, &g_opened, 1, release);
    return rc_ok;
}

static duct_result_t
cli_on_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    uint16_t mtu = 0u;
    duct_atomic_store(&g_cli_rc, (int)duct_conn_path_mtu(s, duct_conn_id_primary, &mtu),
                      relaxed);
    duct_atomic_store(&g_cli_mtu, (int)mtu, relaxed);
    duct_atomic_store(&g_cli_quantum, (int)duct_conn_tx_quantum(s, duct_conn_id_primary),
                      relaxed);
    uint16_t unused = 0u;
    duct_atomic_store(&g_range_rc,
                      (int)duct_conn_path_mtu(s, duct_session_max_legs, &unused), relaxed);
    duct_atomic_store(&g_empty_rc,
                      (int)duct_conn_path_mtu(s, duct_conn_id_primary + 1u, &unused), relaxed);
    duct_atomic_fetch(add, &g_opened, 1, release);
    duct_response_same(out, duct_view(duct_view_u8, (void *)ping, sizeof ping - 1u),
                       fl_send_static, 0);
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
         [[maybe_unused]] const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

static duct_result_t
s_connect_retry(duct_engine_t *io, const char *addr, duct_proto_t *proto,
                duct_xport_t xport)
{
    duct_result_t rc = rc_invalid_order;
    for (unsigned waited = 0u; waited < 3000u; waited += 5u) {
        rc = duct_io_connect(io, addr, proto, nullptr, xport);
        if (rc != rc_invalid_order)
            return rc;
        struct timespec ts = { .tv_nsec = 5L * 1000L * 1000L };
        nanosleep(&ts, nullptr);
    }
    return rc;
}

#ifdef __linux__
/** @brief Check that this process's connected datagram socket of the family
 *  that peers at @p port refuses to fragment.
 *  @return null when it does, else what failed. */
static const char *s_check_df(bool v6, uint16_t port)
{
    int family = v6 ? AF_INET6 : AF_INET;
    for (int fd = 3; fd < 1024; ++fd) {
        int type = 0, domain = 0, mode = -1;
        socklen_t len = sizeof type;
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) != 0 || type != SOCK_DGRAM)
            continue;
        len = sizeof domain;
        if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &len) != 0 || domain != family)
            continue;
        struct sockaddr_storage peer;
        len = sizeof peer;
        if (getpeername(fd, (struct sockaddr *)&peer, &len) != 0)
            continue;
        if (ntohs(v6 ? ((struct sockaddr_in6 *)&peer)->sin6_port
                     : ((struct sockaddr_in *)&peer)->sin_port) != port)
            continue;
        len = sizeof mode;
        if (getsockopt(fd, v6 ? IPPROTO_IPV6 : IPPROTO_IP, v6 ? IPV6_MTU_DISCOVER : IP_MTU_DISCOVER,
                       &mode, &len) != 0)
            return "the client's datagram socket answers no discovery mode";
        return mode == (v6 ? IPV6_PMTUDISC_DO : IP_PMTUDISC_DO)
             ? nullptr : "the client's datagram socket lets IP fragment";
    }
    return "no connected datagram socket to read";
}
#endif

static duct_proto_t *s_proto(const char *name, duct_wire_t *wire, duct_proto_flags_t flags,
                             duct_session_open_fn on_open)
{
    if (!wire)
        return nullptr;
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = name, .wire = wire, .flags = flags,
        .on_frame = on_frame, .on_session_open = on_open,
        .max_response = 1024u,
    });
    if (proto)
        proto->owned_wire = wire;
    else
        duct_wire_destroy(wire);
    return proto;
}

static const char *s_run(bool udp, bool v6)
{
    const char *host = v6 ? "::1" : "127.0.0.1";
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return "io create failed";
    auto srv = udp ? s_proto("path-mtu-srv", duct_wire_create_dgram_batch(0u, false),
                             fl_proto_dgram_shared, srv_on_open)
                   : s_proto("path-mtu-srv", duct_wire_create_length_prefix(0u),
                             (duct_proto_flags_t)0, srv_on_open);
    auto cli = udp ? s_proto("path-mtu-cli", duct_wire_create_dgram_batch(0u, false),
                             (duct_proto_flags_t)0, cli_on_open)
                   : s_proto("path-mtu-cli", duct_wire_create_length_prefix(0u),
                             (duct_proto_flags_t)0, cli_on_open);
    if (!srv || !cli) {
        duct_proto_destroy(srv);
        duct_proto_destroy(cli);
        duct_engine_destroy(io);
        return "proto create failed";
    }

    const char *err = nullptr;
    uint16_t port = 0u;
    bool listening = udp
        ? duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
              .addr = host, .n_protos = 1,
              .protos = (const duct_proto_t *[]){ srv },
          }, &port, nullptr, 0u, nullptr) == rc_ok
        : duct_io_listen(io, host, &port, srv) == rc_ok;
    pthread_t th;
    if (!listening)
        err = "listen failed";
    else if (pthread_create(&th, nullptr, th_run, io) != 0)
        err = "thread create failed";
    else {
        char addr[64];
        snprintf(addr, sizeof addr, v6 ? "[%s]:%u" : "%s:%u", host, (unsigned)port);
        if (s_connect_retry(io, addr, cli, udp ? x_udp_peer : x_tcp) != rc_ok)
            err = "connect failed";
        else if (!th_wait_int(&g_opened, 2, 3000u))
            err = "both sessions did not open";
#ifdef __linux__
        else if (udp)
            err = s_check_df(v6, port);
#endif
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(srv);
    duct_proto_destroy(cli);
    if (err)
        return err;

    if (duct_atomic_load(&g_cli_rc, acquire) != (int)rc_ok)
        return "the client's connected leg did not answer its path MTU";
    if (duct_atomic_load(&g_cli_mtu, acquire) < 1280)
        return "the client's path MTU came back under IPv6's minimum";
    int quantum = duct_atomic_load(&g_cli_quantum, acquire);
    if (!udp && quantum != 0)
        return "a stream leg without a lowat answered a quantum";
#ifdef __linux__
    if (udp && quantum <= 0)
        return "a connected datagram leg answered no quantum from its send buffer";
#endif
    if (duct_atomic_load(&g_range_rc, acquire) != (int)rc_invalid_arg)
        return "a leg id past the session's legs was not refused as an argument";
    if (duct_atomic_load(&g_empty_rc, acquire) != (int)rc_invalid_order)
        return "an empty leg slot was not refused as an order";
    int srv_rc = duct_atomic_load(&g_srv_rc, acquire);
    if (udp && srv_rc != (int)rc_not_supported)
        return "a shared datagram leg answered a path MTU it has no socket for";
    if (!udp && (srv_rc != (int)rc_ok || duct_atomic_load(&g_srv_mtu, acquire) < 1280))
        return "the server's accepted stream leg did not answer its path MTU";
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    int pass = 1;
    auto err = s_run(false, false);
    if (err) { fprintf(stderr, "path_mtu: tcp: %s\n", err); pass = 0; }
    int tcp_mtu = duct_atomic_load(&g_cli_mtu, acquire);
    err = s_run(true, false);
    if (err) { fprintf(stderr, "path_mtu: udp: %s\n", err); pass = 0; }
    int udp_mtu = duct_atomic_load(&g_cli_mtu, acquire);
    err = s_run(true, true);
    if (err) { fprintf(stderr, "path_mtu: udp6: %s\n", err); pass = 0; }
    if (!pass)
        return 1;
    printf("path_mtu: OK (tcp %d, udp %d, udp6 %d)\n", tcp_mtu, udp_mtu,
           duct_atomic_load(&g_cli_mtu, acquire));
    return 0;
}
