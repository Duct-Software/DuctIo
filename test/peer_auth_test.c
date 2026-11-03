/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file peer_auth_test.c
 * @brief on_peer_auth acceptance: each side of a Noise handshake is named to
 * the other.
 *
 * One engine hosts both ends, the responder behind a listener and the
 * initiator dialling it, and sc_auth runs the pair once per framing — over a
 * stream and over datagrams, which are the two call sites the runtime fires
 * from. sc_silent replaces the initiator with a socket that connects and sends
 * nothing, the case the responder's own deadline exists for.
 *
 * Asserts: the callback reaches both roles; the responder is handed the
 * initiator's static public key and the initiator the responder's; it names
 * conn 0; it fires exactly once per handshake; a packet-fd leg the responder
 * attaches from inside it joins, which is how a protocol commits a client's
 * resources only once that client is named; and the session carries a frame
 * afterwards, so naming the peer costs the transport nothing.
 *
 * And the deadline both ways: a peer that sends nothing is closed by it, while
 * the two that authenticate outlive it — the second half separates a deadline
 * that discriminates from one that merely fires.
 */

#include "duct.h"
#include "duct_noise.h"
#include "test_helpers.h"

#include <stdatomic.h>

static constexpr unsigned wait_ms = 3000u;

static atomic_int g_srv_auth   = 0;
static atomic_int g_cli_auth   = 0;
static atomic_int g_srv_id_bad = 0;
static atomic_int g_cli_id_bad = 0;
static atomic_uint g_srv_auth_conn = UINT32_MAX;
static atomic_int g_roundtrip  = 0;

static atomic_int g_srv_join1 = 0;
static _Atomic(duct_sock_t) g_srv_hold_fd = duct_sock_bad;
static atomic_int g_srv_closed = 0;

static constexpr uint64_t timer_hs = 9u;
static constexpr uint32_t hs_deadline_ms = 100u;

static uint8_t g_srv_pub[duct_noise_key_size];
static uint8_t g_cli_pub[duct_noise_key_size];

static duct_wire_t *g_leg_wire;

duct_wire_t *duct_wire_create_dgram_batch(size_t max_dgram, bool framed);

static const uint8_t ping[] = "peer-auth-ping";

static void
srv_on_peer_auth(duct_session_t *s, duct_conn_id_t conn_id,
                 duct_view_u8 identity, [[maybe_unused]] duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    if (identity.size != sizeof g_cli_pub
        || memcmp(identity.data, g_cli_pub, identity.size) != 0)
        duct_atomic_store(&g_srv_id_bad, 1, release);
    duct_sock_t sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0) {
        if (duct_conn_attach_packet_fd(s, 1u, sv[0], g_leg_wire) == rc_ok)
            duct_atomic_store(&g_srv_hold_fd, sv[1], release);
        else
            close(sv[1]);
    }
    duct_atomic_store(&g_srv_auth_conn, (unsigned)conn_id, release);
    duct_atomic_fetch(add, &g_srv_auth, 1, release);
}

static duct_result_t
srv_on_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    out->control.timer.delay_ms = hs_deadline_ms;
    out->control.timer.arg = timer_hs;
    return rc_ok;
}

/** @brief The responder's handshake deadline, in the shape the VPN server uses
 *  it: armed at session open, closing whatever has not authenticated by the
 *  time it fires. */
static duct_result_t
srv_on_timer([[maybe_unused]] duct_session_t *s, duct_response_t *out,
             [[maybe_unused]] void *proto_state, uint64_t arg)
{
    if (arg != timer_hs || duct_atomic_load(&g_srv_auth, acquire) != 0)
        return rc_ok;
    duct_response_close_session(out, close_timeout);
    return rc_ok;
}

static void
srv_on_close([[maybe_unused]] duct_session_t *s,
             [[maybe_unused]] duct_close_reason_t reason,
             [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_srv_closed, 1, release);
}

static duct_result_t
srv_on_conn_join([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
                 [[maybe_unused]] const duct_peer_t *peer,
                 [[maybe_unused]] duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    if (conn_id == 1u)
        duct_atomic_fetch(add, &g_srv_join1, 1, release);
    return rc_ok;
}

static void
cli_on_peer_auth([[maybe_unused]] duct_session_t *s,
                 [[maybe_unused]] duct_conn_id_t conn_id,
                 duct_view_u8 identity, [[maybe_unused]] duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    if (identity.size != sizeof g_srv_pub
        || memcmp(identity.data, g_srv_pub, identity.size) != 0)
        duct_atomic_store(&g_cli_id_bad, 1, release);
    duct_atomic_fetch(add, &g_cli_auth, 1, release);
}

static duct_result_t
srv_on_frame([[maybe_unused]] duct_session_t *s,
             [[maybe_unused]] duct_conn_id_t conn_id,
             const duct_frame_t *frame, duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

static duct_result_t
cli_on_frame([[maybe_unused]] duct_session_t *s,
             [[maybe_unused]] duct_conn_id_t conn_id,
             const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    if (frame->payload.size == sizeof ping - 1u
        && memcmp(frame->payload.data, ping, frame->payload.size) == 0)
        duct_atomic_fetch(add, &g_roundtrip, 1, release);
    return rc_ok;
}

static duct_result_t
cli_on_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    duct_response_same(out, (duct_view_u8){ .data = (void *)ping,
                                          .size = sizeof ping - 1u },
                       fl_send_static, 0);
    return rc_ok;
}

/** @brief A Noise protocol of @p role over @p framing.
 *  @p proto_cfg arrives by value and takes its wire here, so a caller passes a
 *  compound literal and the wire's lifetime belongs to the protocol. */
static duct_proto_t *s_proto_make(duct_proto_cfg_t proto_cfg,
                                  duct_seal_role_t role,
                                  duct_noise_cfg_t *noise_cfg,
                                  duct_seal_framing_t framing)
{
    auto wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .engine = duct_noise_vtbl(), .engine_cfg = noise_cfg,
        .role = role, .framing = framing });
    duct_do_if(!wire, return nullptr);
    proto_cfg.wire = wire;
    auto proto = duct_proto_create(&proto_cfg);
    if (!proto) {
        duct_wire_destroy(wire);
        return nullptr;
    }
    proto->owned_wire = wire;
    return proto;
}

static duct_result_t
s_connect_retry(duct_engine_t *io, const char *addr, duct_proto_t *proto,
                duct_xport_t xport, unsigned timeout_ms)
{
    duct_result_t rc = rc_invalid_order;
    for (unsigned waited = 0u; waited < timeout_ms; waited += 5u) {
        rc = duct_io_connect(io, addr, proto, nullptr, xport);
        if (rc != rc_invalid_order)
            return rc;
        struct timespec ts = { .tv_nsec = 5L * 1000L * 1000L };
        nanosleep(&ts, nullptr);
    }
    return rc;
}

/** @brief The responder every scenario runs, named once so a callback added
 *  here reaches all of them. */
static duct_proto_cfg_t s_srv_cfg(void)
{
    return (duct_proto_cfg_t){
        .name = "peer-auth-srv", .on_frame = srv_on_frame,
        .on_peer_auth = srv_on_peer_auth, .on_conn_join = srv_on_conn_join,
        .on_session_open = srv_on_open, .on_timer = srv_on_timer,
        .on_session_close = srv_on_close,
    };
}

static void s_reset(void)
{
    duct_atomic_store(&g_srv_auth, 0, relaxed);
    duct_atomic_store(&g_cli_auth, 0, relaxed);
    duct_atomic_store(&g_srv_id_bad, 0, relaxed);
    duct_atomic_store(&g_cli_id_bad, 0, relaxed);
    duct_atomic_store(&g_srv_auth_conn, UINT32_MAX, relaxed);
    duct_atomic_store(&g_roundtrip, 0, relaxed);
    duct_atomic_store(&g_srv_join1, 0, relaxed);
    duct_atomic_store(&g_srv_hold_fd, duct_sock_bad, relaxed);
    duct_atomic_store(&g_srv_closed, 0, relaxed);
}

/** @brief A socket that connects to the sealed listener and sends nothing is
 *  closed by the deadline, with no identity ever named.
 *
 *  What it pins on the runtime is that a timer armed from on_session_open under
 *  a sealed wire fires at all when no handshake follows it — nothing else in
 *  the session has run by then.
 */
static const char *sc_silent(const duct_noise_keypair_t *srv_kp, duct_noise_pattern_t pattern)
{
    s_reset();
    duct_noise_cfg_t srv_cfg = {};
    srv_cfg.suite.pattern = pattern;
    srv_cfg.local_static = *srv_kp;

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return "io create failed";

    auto srv = s_proto_make(s_srv_cfg(), seal_role_responder, &srv_cfg,
                            seal_framing_stream);
    if (!srv) { duct_engine_destroy(io); return "proto create failed"; }

    const char *err = nullptr;
    uint16_t port = 0u;
    pthread_t th;
    if (duct_io_listen(io, "127.0.0.1", &port, srv) != rc_ok)
        err = "listen failed";
    else if (pthread_create(&th, nullptr, th_run, io) != 0)
        err = "thread create failed";
    else {
        duct_sock_t fd = th_connect(port);
        if (fd == duct_sock_bad)
            err = "connect failed";
        else if (!th_wait_int(&g_srv_closed, 1, wait_ms))
            err = "a peer that sent nothing was never closed";
        else if (duct_atomic_load(&g_srv_auth, acquire) != 0)
            err = "on_peer_auth fired for a peer that sent nothing";
        if (fd != duct_sock_bad)
            close(fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }

    duct_engine_destroy(io);
    duct_proto_destroy(srv);
    return err;
}

static const char *sc_auth(duct_seal_framing_t framing,
                           const duct_noise_keypair_t *srv_kp,
                           const duct_noise_keypair_t *cli_kp,
                           duct_noise_pattern_t pattern)
{
    bool dgram = framing == seal_framing_datagram;
    s_reset();
    duct_noise_cfg_t srv_cfg = {}, cli_cfg = {};
    srv_cfg.suite.pattern = cli_cfg.suite.pattern = pattern;
    srv_cfg.local_static = *srv_kp;
    cli_cfg.local_static = *cli_kp;
    memcpy(cli_cfg.remote_static_pub, srv_kp->pub, duct_noise_key_size);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return "io create failed";

    auto srv = s_proto_make(s_srv_cfg(), seal_role_responder, &srv_cfg, framing);
    auto cli = s_proto_make((duct_proto_cfg_t){
        .name = "peer-auth-cli", .on_frame = cli_on_frame,
        .on_session_open = cli_on_open, .on_peer_auth = cli_on_peer_auth,
    }, seal_role_initiator, &cli_cfg, framing);
    if (!srv || !cli) {
        duct_proto_destroy(srv); duct_proto_destroy(cli); duct_engine_destroy(io);
        return "proto create failed";
    }

    const char *err = nullptr;
    uint16_t port = 0u;
    bool bound = dgram
        ? duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
              .addr = "127.0.0.1", .n_protos = 1,
              .protos = (const duct_proto_t *[]){ srv },
          }, &port, nullptr, 0u, nullptr) == rc_ok
        : duct_io_listen(io, "127.0.0.1", &port, srv) == rc_ok;

    pthread_t th;
    if (!bound)
        err = "listen failed";
    else if (pthread_create(&th, nullptr, th_run, io) != 0)
        err = "thread create failed";
    else {
        char addr[64];
        snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)port);
        if (s_connect_retry(io, addr, cli, dgram ? x_udp_peer : x_tcp, 3000u) != rc_ok)
            err = "connect failed";
        else if (!th_wait_int(&g_srv_auth, 1, wait_ms))
            err = "on_peer_auth never fired on the responder";
        else if (!th_wait_int(&g_cli_auth, 1, wait_ms))
            err = "on_peer_auth never fired on the initiator";
        else if (duct_atomic_load(&g_srv_id_bad, acquire) != 0)
            err = "responder saw an identity that is not the initiator's key";
        else if (duct_atomic_load(&g_cli_id_bad, acquire) != 0)
            err = "initiator saw an identity that is not the responder's key";
        else if (duct_atomic_load(&g_srv_auth_conn, acquire) != duct_conn_id_primary)
            err = "responder's on_peer_auth named a leg other than conn 0";
        else if (!th_wait_int(&g_srv_join1, 1, wait_ms))
            err = "a leg attached from on_peer_auth never joined";
        else if (!th_wait_int(&g_roundtrip, 1, wait_ms))
            err = "the session carried no traffic after the handshake";
        else if (duct_atomic_load(&g_srv_auth, acquire) != 1
                 || duct_atomic_load(&g_cli_auth, acquire) != 1)
            err = "on_peer_auth fired more than once for one handshake";
        else if (duct_atomic_load(&g_srv_closed, acquire) != 0)
            err = "the handshake deadline closed a session that authenticated";

        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }

    duct_engine_destroy(io);
    duct_proto_destroy(srv);
    duct_proto_destroy(cli);
    duct_sock_t held = duct_atomic_load(&g_srv_hold_fd, acquire);
    if (held != duct_sock_bad) close(held);
    return err;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    duct_noise_keypair_t srv_kp, cli_kp;
    if (!duct_noise_keypair_generate(&srv_kp)
        || !duct_noise_keypair_generate(&cli_kp)) {
        fprintf(stderr, "peer_auth: keypair generation failed\n");
        return 1;
    }
    memcpy(g_srv_pub, srv_kp.pub, sizeof g_srv_pub);
    memcpy(g_cli_pub, cli_kp.pub, sizeof g_cli_pub);

    g_leg_wire = duct_wire_create_dgram_batch(0u, false);
    if (!g_leg_wire) {
        fprintf(stderr, "peer_auth: leg wire creation failed\n");
        return 1;
    }

    static const struct { duct_noise_pattern_t pattern; const char *name; } patterns[] = {
        { noise_pattern_ikpsk2, "IKpsk2" },
        { noise_pattern_xkpsk3, "XKpsk3" },
    };
    int pass = 1;
    for (size_t i = 0u; i < sizeof patterns / sizeof patterns[0]; ++i) {
        auto err = sc_auth(seal_framing_stream, &srv_kp, &cli_kp, patterns[i].pattern);
        if (err) { fprintf(stderr, "peer_auth: %s, stream: %s\n", patterns[i].name, err); pass = 0; }
        err = sc_silent(&srv_kp, patterns[i].pattern);
        if (err) { fprintf(stderr, "peer_auth: %s, silent: %s\n", patterns[i].name, err); pass = 0; }
        err = sc_auth(seal_framing_datagram, &srv_kp, &cli_kp, patterns[i].pattern);
        if (err) { fprintf(stderr, "peer_auth: %s, datagram: %s\n", patterns[i].name, err); pass = 0; }
    }

    duct_wire_destroy(g_leg_wire);
    if (!pass)
        return 1;
    printf("peer_auth: OK (IKpsk2 and XKpsk3: both roles get the peer's static key once, on conn 0, "
           "over a stream and over datagrams, session carries traffic after)\n");
    return 0;
}
