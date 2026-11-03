/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file noise_join_test.c
 *  @brief Joins over Noise: a lead the engine builds, a leg under another key,
 *  and a join that never authenticates.
 *
 *  One engine hosts a responder behind a stream listener declaring a probe
 *  wait, and two initiators under keys of their own. The responder greets each
 *  client from on_peer_auth. Client A answers with leg_kind_join on conn 1;
 *  client B with leg_kind_connect on conn 2, led by the bytes the responder's
 *  preparse joins to A's session.
 *
 *  Asserts: A's join attaches to A's session, both ends naming the peer on it,
 *  and opens no session of its own. B's leg is closed with
 *  close_protocol_error, A's session standing and on_peer_auth never firing
 *  for it; under fl_proto_join_any_peer it is kept and named instead. A raw
 *  socket sending only the preparse's lead is joined, then closed with
 *  close_timeout at join_auth_timeout_ms.
 */

#include "duct.h"
#include "duct_noise.h"
#include "test_helpers.h"

#include <stdatomic.h>

static constexpr unsigned       wait_ms     = 3000u;
static constexpr uint32_t       auth_ms     = 300u;
static constexpr duct_conn_id_t join_leg    = 1u;
static constexpr duct_conn_id_t foreign_leg = 2u;
static constexpr uint8_t        foreign_lead[] = { 'J', 'N', '0', '2' };

static const char hello[] = "noise-join-hello";

static char                  g_addr[64];
static _Atomic duct_handle_t g_first_tok;
static uint8_t               g_pub_a[duct_noise_key_size];
static uint8_t               g_pub_b[duct_noise_key_size];

static atomic_int g_sessions     = 0;
static atomic_int g_closed       = 0;
static atomic_int g_joined1      = 0;
static atomic_int g_joined2      = 0;
static atomic_int g_auth1        = 0;
static atomic_int g_auth2        = 0;
static atomic_int g_cli_auth1    = 0;
static atomic_int g_lost2_proto  = 0;
static atomic_int g_lost2_time   = 0;
static atomic_int g_id_bad       = 0;

static bool s_is(const duct_frame_t *frame, const char *text, size_t size)
{
    return frame->payload.size == size && memcmp(frame->payload.data, text, size) == 0;
}

static bool s_id_is(duct_view_u8 id, const uint8_t *pub)
{
    return id.size == duct_noise_key_size && memcmp(id.data, pub, id.size) == 0;
}

static duct_resolve_disposition_t
srv_preparse([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer,
             duct_view_u8 peek, duct_handle_t *out_tok, duct_conn_id_t *out_conn_id,
             [[maybe_unused]] void **out_user_ctx, size_t *out_lead)
{
    if (peek.size == 0u)
        return resolve_not_me;
    if (peek.size < sizeof foreign_lead
        || memcmp(peek.data, foreign_lead, sizeof foreign_lead) != 0)
        return resolve_new;
    *out_tok = duct_atomic_load(&g_first_tok, acquire);
    *out_conn_id = foreign_leg;
    *out_lead = sizeof foreign_lead;
    return resolve_join;
}

static duct_result_t
srv_on_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    duct_handle_t none = handle_null;
    duct_discard duct_atomic_cas(strong, &g_first_tok, &none, tok, acq_rel, relaxed);
    duct_atomic_fetch(add, &g_sessions, 1, acq_rel);
    return rc_ok;
}

static void
srv_on_close([[maybe_unused]] duct_session_t *s,
             [[maybe_unused]] duct_close_reason_t reason,
             [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_closed, 1, acq_rel);
}

static duct_result_t
srv_on_conn_join([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
                 [[maybe_unused]] const duct_peer_t *peer,
                 [[maybe_unused]] duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    if (conn_id == join_leg)
        duct_atomic_fetch(add, &g_joined1, 1, acq_rel);
    else if (conn_id == foreign_leg)
        duct_atomic_fetch(add, &g_joined2, 1, acq_rel);
    return rc_ok;
}

static void
srv_on_conn_lost([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
                 duct_close_reason_t reason, [[maybe_unused]] duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    if (conn_id != foreign_leg)
        return;
    if (reason == close_protocol_error)
        duct_atomic_fetch(add, &g_lost2_proto, 1, acq_rel);
    else if (reason == close_timeout)
        duct_atomic_fetch(add, &g_lost2_time, 1, acq_rel);
}

static void
srv_on_peer_auth([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
                 duct_view_u8 identity, duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    if (conn_id == duct_conn_id_primary) {
        duct_response_same(out, (duct_view_u8){ .data = (void *)hello,
                                              .size = sizeof hello - 1u },
                           fl_send_static, 0);
    } else if (conn_id == join_leg) {
        if (!s_id_is(identity, g_pub_a))
            duct_atomic_store(&g_id_bad, 1, release);
        duct_atomic_fetch(add, &g_auth1, 1, acq_rel);
    } else if (conn_id == foreign_leg) {
        if (!s_id_is(identity, g_pub_b))
            duct_atomic_store(&g_id_bad, 1, release);
        duct_atomic_fetch(add, &g_auth2, 1, acq_rel);
    }
}

static duct_result_t
srv_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             [[maybe_unused]] const duct_frame_t *frame,
             [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

static duct_result_t
cli_a_on_frame([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
               const duct_frame_t *frame, duct_response_t *out,
               [[maybe_unused]] void *proto_state)
{
    if (conn_id == duct_conn_id_primary && s_is(frame, hello, sizeof hello - 1u)) {
        out->control.open_leg.kind = leg_kind_join;
        out->control.open_leg.conn_id = join_leg;
        out->control.open_leg.connect_addr = g_addr;
    }
    return rc_ok;
}

static void
cli_a_on_peer_auth([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
                   [[maybe_unused]] duct_view_u8 identity,
                   [[maybe_unused]] duct_response_t *out,
                   [[maybe_unused]] void *proto_state)
{
    if (conn_id == join_leg)
        duct_atomic_fetch(add, &g_cli_auth1, 1, acq_rel);
}

static duct_result_t
cli_b_on_frame([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
               const duct_frame_t *frame, duct_response_t *out,
               [[maybe_unused]] void *proto_state)
{
    if (conn_id == duct_conn_id_primary && s_is(frame, hello, sizeof hello - 1u)) {
        out->control.open_leg.kind = leg_kind_connect;
        out->control.open_leg.conn_id = foreign_leg;
        out->control.open_leg.connect_addr = g_addr;
        out->control.open_leg.tx_prefix = (duct_view_u8){ .data = (void *)foreign_lead,
                                                        .size = sizeof foreign_lead };
    }
    return rc_ok;
}

static duct_proto_t *s_proto_make(duct_proto_cfg_t proto_cfg, duct_seal_role_t role,
                                  duct_noise_cfg_t *noise_cfg)
{
    auto wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .engine = duct_noise_vtbl(), .engine_cfg = noise_cfg,
        .role = role, .framing = seal_framing_stream });
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

static duct_result_t s_connect_retry(duct_engine_t *io, duct_proto_t *proto)
{
    duct_result_t rc = rc_invalid_order;
    for (unsigned waited = 0u; waited < wait_ms; waited += 5u) {
        rc = duct_io_connect(io, g_addr, proto, nullptr, x_tcp);
        if (rc != rc_invalid_order)
            return rc;
        th_sleep_ms(5u);
    }
    return rc;
}

static void s_reset(void)
{
    duct_atomic_store(&g_first_tok, handle_null, relaxed);
    duct_atomic_store(&g_sessions, 0, relaxed);
    duct_atomic_store(&g_closed, 0, relaxed);
    duct_atomic_store(&g_joined1, 0, relaxed);
    duct_atomic_store(&g_joined2, 0, relaxed);
    duct_atomic_store(&g_auth1, 0, relaxed);
    duct_atomic_store(&g_auth2, 0, relaxed);
    duct_atomic_store(&g_cli_auth1, 0, relaxed);
    duct_atomic_store(&g_lost2_proto, 0, relaxed);
    duct_atomic_store(&g_lost2_time, 0, relaxed);
    duct_atomic_store(&g_id_bad, 0, relaxed);
}

static const char *s_scenarios(duct_engine_t *io, uint16_t port, bool any_peer,
                               duct_proto_t *cli_a, duct_proto_t *cli_b)
{
    if (s_connect_retry(io, cli_a) != rc_ok)
        return "client A failed to connect";
    if (!th_wait_int(&g_joined1, 1, wait_ms))
        return "a leg dialed with leg_kind_join never joined its own session";
    if (!th_wait_int(&g_auth1, 1, wait_ms) || !th_wait_int(&g_cli_auth1, 1, wait_ms))
        return "the joined leg did not name its peer on both ends";
    if (duct_atomic_load(&g_sessions, acquire) != 1)
        return "the joining dial opened a session of its own";
    if (s_connect_retry(io, cli_b) != rc_ok)
        return "client B failed to connect";
    if (!th_wait_int(&g_joined2, 1, wait_ms))
        return "a leg resolved by the protocol's own lead never joined";
    if (any_peer) {
        if (!th_wait_int(&g_auth2, 1, wait_ms))
            return "fl_proto_join_any_peer did not keep a leg under another key";
        if (duct_atomic_load(&g_lost2_proto, acquire) != 0)
            return "fl_proto_join_any_peer still closed a leg under another key";
    } else {
        if (!th_wait_int(&g_lost2_proto, 1, wait_ms))
            return "a joined leg under another key was not closed";
        if (duct_atomic_load(&g_auth2, acquire) != 0)
            return "on_peer_auth fired for a leg under another key";
        duct_sock_t fd = th_connect(port);
        if (fd == duct_sock_bad)
            return "raw connect failed";
        bool sent = send(fd, (const char *)foreign_lead, (int)sizeof foreign_lead, 0)
                 == (int)sizeof foreign_lead;
        bool joined = sent && th_wait_int(&g_joined2, 2, wait_ms);
        bool timed = joined && th_wait_int(&g_lost2_time, 1, wait_ms);
        close(fd);
        if (!joined)
            return "a silent leg leading with the protocol's lead never joined";
        if (!timed)
            return "a joined leg that never authenticated outlived join_auth_timeout_ms";
    }
    if (duct_atomic_load(&g_sessions, acquire) != 2)
        return "the session count is not one per client";
    if (duct_atomic_load(&g_closed, acquire) != 0)
        return "a session closed while only its legs were refused";
    if (duct_atomic_load(&g_id_bad, acquire) != 0)
        return "on_peer_auth named a leg with a key that is not its dialer's";
    return nullptr;
}

static const char *sc_join(bool any_peer, const duct_noise_keypair_t *srv_kp,
                           const duct_noise_keypair_t *kp_a,
                           const duct_noise_keypair_t *kp_b)
{
    s_reset();
    duct_noise_cfg_t srv_cfg = {}, cfg_a = {}, cfg_b = {};
    srv_cfg.local_static = *srv_kp;
    cfg_a.local_static = *kp_a;
    cfg_b.local_static = *kp_b;
    memcpy(cfg_a.remote_static_pub, srv_kp->pub, duct_noise_key_size);
    memcpy(cfg_b.remote_static_pub, srv_kp->pub, duct_noise_key_size);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return "io create failed";
    auto srv = s_proto_make((duct_proto_cfg_t){
        .name = "noise-join-srv", .on_frame = srv_on_frame,
        .on_session_open = srv_on_open, .on_session_close = srv_on_close,
        .on_conn_join = srv_on_conn_join, .on_conn_lost = srv_on_conn_lost,
        .on_peer_auth = srv_on_peer_auth,
        .preparse = srv_preparse, .preparse_mode = resolve_sync,
        .join_auth_timeout_ms = auth_ms,
        .flags = any_peer ? fl_proto_join_any_peer : fl_proto_none,
    }, seal_role_responder, &srv_cfg);
    auto cli_a = s_proto_make((duct_proto_cfg_t){
        .name = "noise-join-a", .on_frame = cli_a_on_frame,
        .on_peer_auth = cli_a_on_peer_auth,
    }, seal_role_initiator, &cfg_a);
    auto cli_b = s_proto_make((duct_proto_cfg_t){
        .name = "noise-join-b", .on_frame = cli_b_on_frame,
    }, seal_role_initiator, &cfg_b);
    if (!srv || !cli_a || !cli_b) {
        duct_proto_destroy(srv);
        duct_proto_destroy(cli_a);
        duct_proto_destroy(cli_b);
        duct_engine_destroy(io);
        return "proto create failed";
    }

    const char *err = nullptr;
    uint16_t port = 0u;
    pthread_t th;
    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_stream,
            .addr = "127.0.0.1", .n_protos = 1,
            .protos = (const duct_proto_t *[]){ srv },
            .probe_wait_ms = wait_ms,
        }, &port, nullptr, 0u, nullptr) != rc_ok)
        err = "listen failed";
    else if (pthread_create(&th, nullptr, th_run, io) != 0)
        err = "thread create failed";
    else {
        snprintf(g_addr, sizeof g_addr, "127.0.0.1:%u", (unsigned)port);
        err = s_scenarios(io, port, any_peer, cli_a, cli_b);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }

    duct_engine_destroy(io);
    duct_proto_destroy(srv);
    duct_proto_destroy(cli_a);
    duct_proto_destroy(cli_b);
    return err;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    duct_noise_keypair_t srv_kp, kp_a, kp_b;
    if (!duct_noise_keypair_generate(&srv_kp) || !duct_noise_keypair_generate(&kp_a)
        || !duct_noise_keypair_generate(&kp_b)) {
        fprintf(stderr, "noise_join: keypair generation failed\n");
        return 1;
    }
    memcpy(g_pub_a, kp_a.pub, sizeof g_pub_a);
    memcpy(g_pub_b, kp_b.pub, sizeof g_pub_b);

    int pass = 1;
    auto err = sc_join(false, &srv_kp, &kp_a, &kp_b);
    if (err) { fprintf(stderr, "noise_join: same peer: %s\n", err); pass = 0; }
    err = sc_join(true, &srv_kp, &kp_a, &kp_b);
    if (err) { fprintf(stderr, "noise_join: any peer: %s\n", err); pass = 0; }

    if (!pass)
        return 1;
    printf("noise_join: OK (leg_kind_join joins its own session under the engine's "
           "lead, a leg under another key closes with the session standing unless "
           "fl_proto_join_any_peer, a silent join closes at join_auth_timeout_ms)\n");
    return 0;
}
