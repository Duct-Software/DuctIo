/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file handshake_retry_test.c
 * @brief The XKpsk3 handshake over datagrams that go missing, healed by the
 * initiator's resend timer.
 *
 * A client dials a Noise server through a relay that drops chosen datagrams,
 * counted per direction from the first. The server greets from @c on_peer_auth,
 * so a greeting reaching the client proves the whole exchange: message 1, message 2
 * and message 3 each lost once, message 1 and message 3 lost twice, all healed by
 * the engine's retry with @c hs_rto_ms small.
 *
 * With @c hs_rto_ms at 0 and message 1 lost, nothing resends and no greeting comes:
 * the control that shows the timer is what heals the rest. With every datagram lost
 * and a join deadline shorter than the timer chain, the conn is closed while timers
 * stand armed; none sends a datagram afterwards, and an ASan build finds any of them
 * reaching a conn or codec that is gone.
 */

#include "duct.h"
#include "duct_noise.h"
#include "test_helpers.h"
#include "dgram_test_helpers.h"

#include <stdatomic.h>

static constexpr unsigned wait_ms = 3000u;
static constexpr unsigned silent_ms = 700u;
static constexpr unsigned chain_ms = 1000u;
static constexpr uint16_t rto_ms = 40u;
static constexpr uint32_t join_ms = 70u;

static const char greeting[] = "greeting-after-the-handshake";

static atomic_int g_greeted = 0;
static atomic_int g_closed = 0;

/** @brief A relay between the client and the server that drops chosen datagrams. */
typedef struct {
    duct_sock_t        cfd,           /**< Faces the client. */
                       sfd;           /**< Faces the server, connected to it. */
    struct sockaddr_in cli;           /**< The client's address, zero until its first datagram. */
    uint32_t           up_drop,       /**< Bit n drops the n + 1th datagram of the client. */
                       down_drop;     /**< Bit n drops the n + 1th datagram of the server. */
    atomic_uint        up_seen,       /**< Datagrams the client sent, dropped ones included. */
                       down_seen;
    atomic_bool        stop;
} relay_t;

static bool dropped(uint32_t mask, unsigned n)
{
    return n < 32u && (mask >> n & 1u) != 0u;
}

static void *relay_run(void *arg)
{
    auto px = (relay_t *)arg;
    uint8_t buf[2048];
    while (!atomic_load_explicit(&px->stop, memory_order_acquire)) {
        struct pollfd pf[2] = { { .fd = px->cfd, .events = POLLIN }, { .fd = px->sfd, .events = POLLIN } };
        if (poll(pf, 2, 20) <= 0)
            continue;
        if (pf[0].revents & POLLIN) {
            struct sockaddr_in from;
            socklen_t flen = sizeof from;
            ssize_t n = recvfrom(px->cfd, (char *)buf, sizeof buf, 0, (struct sockaddr *)&from, &flen);
            if (n > 0) {
                px->cli = from;
                unsigned k = atomic_fetch_add_explicit(&px->up_seen, 1u, memory_order_relaxed);
                if (!dropped(px->up_drop, k))
                    send(px->sfd, (char *)buf, (int)n, 0);
            }
        }
        if (pf[1].revents & POLLIN) {
            ssize_t n = recv(px->sfd, (char *)buf, sizeof buf, 0);
            if (n > 0 && px->cli.sin_family != 0) {
                unsigned k = atomic_fetch_add_explicit(&px->down_seen, 1u, memory_order_relaxed);
                if (!dropped(px->down_drop, k))
                    sendto(px->cfd, (char *)buf, (int)n, 0, (struct sockaddr *)&px->cli, sizeof px->cli);
            }
        }
    }
    return nullptr;
}

static void
srv_on_peer_auth([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                 [[maybe_unused]] duct_view_u8 identity, duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    duct_response_same(out, duct_view(duct_view_u8, (void *)greeting, sizeof greeting - 1u),
                       fl_send_static, 0);
}

static duct_result_t
srv_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             [[maybe_unused]] const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

static duct_result_t
cli_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    if (frame->payload.size == sizeof greeting - 1u
        && memcmp(frame->payload.data, greeting, frame->payload.size) == 0)
        atomic_fetch_add_explicit(&g_greeted, 1, memory_order_release);
    return rc_ok;
}

static void
cli_on_close([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_close_reason_t reason,
             [[maybe_unused]] void *proto_state)
{
    atomic_fetch_add_explicit(&g_closed, 1, memory_order_release);
}

/** @brief A Noise protocol of @p role over a datagram-framed wire of the datagram vtbl.
 *  @p pcfg arrives by value and takes its wire here. */
static duct_proto_t *proto_make(duct_proto_cfg_t pcfg, duct_seal_role_t role, duct_noise_cfg_t *cfg)
{
    auto wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .engine = duct_noise_vtbl_dgram(), .engine_cfg = cfg,
        .role = role, .framing = seal_framing_datagram });
    duct_do_if(!wire, return nullptr);
    pcfg.wire = wire;
    auto proto = duct_proto_create(&pcfg);
    if (!proto) {
        duct_wire_destroy(wire);
        return nullptr;
    }
    proto->owned_wire = wire;
    return proto;
}

/** @brief What a case expects of the client by the end. */
typedef enum : uint8_t {
    expect_greeted, /**< The greeting arrives. */
    expect_silent,  /**< Nothing arrives and the conn stands. */
    expect_closed,  /**< The join deadline closes the conn and nothing is sent after. */
} expect_t;

typedef struct {
    const char *name;
    expect_t    expect;
    uint16_t    rto;        /**< The client's @c hs_rto_ms. */
    uint32_t    join,       /**< The client's @c join_auth_timeout_ms, 0 for the default. */
                up_drop,
                down_drop;
} case_t;

static const case_t cases[] = {
    { "message 1 lost once",       expect_greeted, rto_ms, 0u,      0x1u,       0u },
    { "message 1 lost twice",      expect_greeted, rto_ms, 0u,      0x3u,       0u },
    { "message 2 lost once",       expect_greeted, rto_ms, 0u,      0u,         0x1u },
    { "message 3 lost once",       expect_greeted, rto_ms, 0u,      0x2u,       0u },
    { "message 3 lost twice",      expect_greeted, rto_ms, 0u,      0x6u,       0u },
    { "message 1 lost, no resend", expect_silent,  0u,     0u,      0x1u,       0u },
    { "a conn closed mid-exchange", expect_closed, rto_ms, join_ms, UINT32_MAX, UINT32_MAX },
};

/** @brief Run what a case expects once the client is dialling.
 *  @return nullptr when it held, else what failed. */
static const char *judge(const case_t *c, relay_t *px)
{
    switch (c->expect) {
    case expect_greeted:
        if (!th_wait_int(&g_greeted, 1, wait_ms))
            return "the handshake never completed with the datagrams lost";
        return atomic_load_explicit(&g_closed, memory_order_acquire) != 0
             ? "the conn closed though the handshake completed" : nullptr;
    case expect_silent:
        th_sleep_ms(silent_ms);
        if (atomic_load_explicit(&g_greeted, memory_order_acquire) != 0)
            return "a greeting came with nothing resending";
        return atomic_load_explicit(&g_closed, memory_order_acquire) != 0
             ? "the conn closed before its deadline" : nullptr;
    case expect_closed: {
        if (!th_wait_int(&g_closed, 1, wait_ms))
            return "the join deadline never closed the conn";
        th_sleep_ms(100u);
        unsigned sent = atomic_load_explicit(&px->up_seen, memory_order_acquire);
        th_sleep_ms(chain_ms);
        if (atomic_load_explicit(&px->up_seen, memory_order_acquire) != sent)
            return "a datagram was sent after the conn had closed";
        return atomic_load_explicit(&g_greeted, memory_order_acquire) != 0
             ? "a greeting came through a dead link" : nullptr;
    }
    }
    duct_unreachable();
}

static const char *run_case(const case_t *c, const duct_noise_keypair_t *srv_kp,
                            const duct_noise_keypair_t *cli_kp)
{
    atomic_store_explicit(&g_greeted, 0, memory_order_release);
    atomic_store_explicit(&g_closed, 0, memory_order_release);
    duct_noise_cfg_t srv_cfg = { .local_static = *srv_kp, .suite.pattern = noise_pattern_xkpsk3 },
                     cli_cfg = { .local_static = *cli_kp, .suite.pattern = noise_pattern_xkpsk3,
                                 .hs_rto_ms = c->rto };
    memcpy(cli_cfg.remote_static_pub, srv_kp->pub, duct_noise_key_size);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return "engine launch failed";
    auto srv = proto_make((duct_proto_cfg_t){
        .name = "retry-srv", .on_frame = srv_on_frame, .on_peer_auth = srv_on_peer_auth,
        .max_response = 2048u, .flags = fl_proto_dgram_shared }, seal_role_responder, &srv_cfg);
    auto cli = proto_make((duct_proto_cfg_t){
        .name = "retry-cli", .on_frame = cli_on_frame, .on_session_close = cli_on_close,
        .max_response = 2048u, .join_auth_timeout_ms = c->join }, seal_role_initiator, &cli_cfg);

    static relay_t px;
    px = (relay_t){ .cfd = duct_sock_bad, .sfd = duct_sock_bad,
                    .up_drop = c->up_drop, .down_drop = c->down_drop };
    const char *err = srv && cli ? nullptr : "proto create failed";
    uint16_t port = 0u, relay_port = 0u;
    pthread_t th_io, th_relay;
    bool io_running = false, relay_running = false;
    if (!err && duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram, .addr = "127.0.0.1",
            .n_protos = 1, .protos = (const duct_proto_t *[]){ srv } }, &port, nullptr, 0u, nullptr) != rc_ok)
        err = "listener bind failed";
    if (!err) {
        px.cfd = uc_bind(&relay_port);
        px.sfd = uc_connect(port);
        if (px.cfd == duct_sock_bad || px.sfd == duct_sock_bad)
            err = "relay sockets failed";
    }
    if (!err && pthread_create(&th_io, nullptr, th_run, io) != 0)
        err = "engine thread failed";
    io_running = !err;
    if (!err && pthread_create(&th_relay, nullptr, relay_run, &px) != 0)
        err = "relay thread failed";
    relay_running = !err;
    if (!err) {
        char addr[64];
        snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)relay_port);
        if (th_connect_retry(io, addr, cli, x_udp_peer) != rc_ok)
            err = "connect failed";
        else
            err = judge(c, &px);
    }

    atomic_store_explicit(&px.stop, true, memory_order_release);
    if (relay_running)
        pthread_join(th_relay, nullptr);
    duct_engine_stop(io);
    if (io_running)
        pthread_join(th_io, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(cli);
    duct_proto_destroy(srv);
    if (px.cfd != duct_sock_bad)
        duct_sock_close(px.cfd);
    if (px.sfd != duct_sock_bad)
        duct_sock_close(px.sfd);
    return err;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    duct_noise_keypair_t srv_kp, cli_kp;
    if (!duct_noise_keypair_generate(&srv_kp) || !duct_noise_keypair_generate(&cli_kp)) {
        fprintf(stderr, "handshake_retry: keypair generation failed\n");
        return 1;
    }
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        auto err = run_case(&cases[i], &srv_kp, &cli_kp);
        if (err) {
            fprintf(stderr, "handshake_retry: %s: %s\n", cases[i].name, err);
            return 1;
        }
    }
    printf("handshake_retry: OK (XKpsk3 over datagrams: message 1 lost once and twice, message 2 once, message 3 "
           "once and twice, all healed by the resend timer; none without it; a conn closed mid-exchange leaves "
           "its timers sending nothing)\n");
    return 0;
}
