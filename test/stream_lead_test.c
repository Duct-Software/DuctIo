/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file stream_lead_test.c
 * @brief Stream lead acceptance: a dial's leading bytes join it to the session
 * they name.
 *
 * One engine hosts a Noise responder behind a stream listener and an initiator
 * dialling it. Once conn 0 has carried a frame both ways, the initiator declares
 * a second leg through open_leg.tx_prefix; the listener's preparse reads that
 * lead, joins the leg to the session under the conn id it names, and consumes
 * it through out_lead. The run goes once with a sync preparse and once with an
 * async one, whose round trip carries the lead back to the io thread.
 *
 * The listener holds a first read to duct_seal_prefix_max bytes, the widest
 * lead a dial writes, before it asks the preparse anything.
 *
 * Asserts: the leg's first frame reaches the responder whole and echoes back,
 * so its engine never saw the lead; one session opened in all; the preparse saw
 * the lead once, message 1 behind it in the same read, which the dialer's one
 * publish of both makes certain.
 */

#include "duct.h"
#include "duct_noise.h"
#include "test_helpers.h"

#include <stdatomic.h>

static constexpr unsigned       wait_ms  = 3000u;
static constexpr duct_conn_id_t lead_leg = 2u;
static constexpr uint8_t        lead[]   = { 'l', 'e', 'a', 'd', '-', 'b', 'y', 't', 'e', 's',
                                             lead_leg };
static constexpr uint8_t        dial_lead[] = { 'd', 'i', 'a', 'l', '-', 'l', 'e', 'a', 'd' };

static const char ping[]  = "stream-lead-ping";
static const char first[] = "stream-lead-first-frame";

static char                  g_addr[64];
static _Atomic duct_handle_t g_srv_tok;
static atomic_int            g_sessions   = 0;
static atomic_int            g_leads      = 0;
static atomic_int            g_lead_whole = 0;
static atomic_int            g_dial_leads = 0;
static atomic_int            g_dial_whole = 0;
static atomic_int            g_joined     = 0;
static atomic_int            g_first_ok   = 0;
static atomic_int            g_echo_ok    = 0;
static atomic_int            g_opens      = 0;
static atomic_int            g_closes     = 0;
static atomic_int            g_errors     = 0;
static atomic_int            g_states     = 0;
static atomic_int            g_srv_closes = 0;

static bool s_is(const duct_frame_t *frame, const char *text, size_t size)
{
    return frame->payload.size == size && memcmp(frame->payload.data, text, size) == 0;
}

/** @brief Join a dial leading with @c lead to the session conn 0 opened.
 *  An empty read answers resolve_not_me, which the listener's probe wait
 *  retries once. */
static duct_resolve_disposition_t
srv_preparse([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer,
             duct_view_u8 peek, duct_handle_t *out_tok, duct_conn_id_t *out_conn_id,
             [[maybe_unused]] void **out_user_ctx, size_t *out_lead)
{
    if (peek.size == 0u)
        return resolve_not_me;
    if (peek.size >= sizeof dial_lead && memcmp(peek.data, dial_lead, sizeof dial_lead) == 0) {
        duct_atomic_fetch(add, &g_dial_leads, 1, acq_rel);
        if (peek.size > sizeof dial_lead)
            duct_atomic_store(&g_dial_whole, 1, release);
        *out_lead = sizeof dial_lead;
        return resolve_new;
    }
    if (peek.size < sizeof lead || memcmp(peek.data, lead, sizeof lead) != 0)
        return resolve_new;
    duct_atomic_fetch(add, &g_leads, 1, acq_rel);
    if (peek.size > sizeof lead)
        duct_atomic_store(&g_lead_whole, 1, release);
    *out_tok = duct_atomic_load(&g_srv_tok, acquire);
    *out_conn_id = lead[sizeof lead - 1u];
    *out_lead = sizeof lead;
    return resolve_join;
}

static duct_result_t
srv_on_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_srv_tok, tok, release);
    duct_atomic_fetch(add, &g_sessions, 1, acq_rel);
    return rc_ok;
}

static duct_result_t
srv_on_conn_join([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
                 [[maybe_unused]] const duct_peer_t *peer,
                 [[maybe_unused]] duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    if (conn_id == lead_leg)
        duct_atomic_fetch(add, &g_joined, 1, acq_rel);
    return rc_ok;
}

static duct_result_t
srv_on_frame([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
             const duct_frame_t *frame, duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    if (conn_id == lead_leg && s_is(frame, first, sizeof first - 1u))
        duct_atomic_store(&g_first_ok, 1, release);
    duct_response_echo(out, frame);
    out->conn_id = conn_id;
    return rc_ok;
}

static duct_result_t
cli_on_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    duct_response_same(out, duct_view(duct_view_u8, (void *)ping, sizeof ping - 1u),
                       fl_send_static, 0);
    return rc_ok;
}

static duct_result_t
cli_on_frame([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
             const duct_frame_t *frame, duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    if (conn_id == duct_conn_id_primary && s_is(frame, ping, sizeof ping - 1u)) {
        out->control.open_leg.kind = leg_kind_connect;
        out->control.open_leg.conn_id = lead_leg;
        out->control.open_leg.connect_addr = g_addr;
        out->control.open_leg.tx_prefix = (duct_view_u8){ .data = (void *)lead,
                                                        .size = sizeof lead };
    } else if (conn_id == lead_leg && s_is(frame, first, sizeof first - 1u))
        duct_atomic_store(&g_echo_ok, 1, release);
    return rc_ok;
}

/** @brief The dial under test is the first connection: its ping's echo is the round trip. */
static duct_result_t
dial_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
              const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
              [[maybe_unused]] void *proto_state)
{
    if (s_is(frame, ping, sizeof ping - 1u))
        duct_atomic_store(&g_echo_ok, 1, release);
    return rc_ok;
}

static duct_result_t
plain_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
               const duct_frame_t *frame, duct_response_t *out,
               [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

static duct_result_t
plain_create_state([[maybe_unused]] duct_session_t *s, [[maybe_unused]] void *ctx, void **out)
{
    static int marker;
    duct_atomic_fetch(add, &g_states, 1, acq_rel);
    *out = &marker;
    return rc_ok;
}

static duct_result_t
plain_on_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
              [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
              [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_opens, 1, acq_rel);
    return rc_ok;
}

static void
plain_on_close([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_close_reason_t reason,
               [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_closes, 1, acq_rel);
}

static duct_result_t
plain_on_error(duct_session_t *s, duct_result_t error, [[maybe_unused]] duct_response_t *out,
               [[maybe_unused]] void *proto_state)
{
    if (!s && error == rc_invalid_arg)
        duct_atomic_fetch(add, &g_errors, 1, acq_rel);
    return rc_ok;
}

static void
plain_srv_on_close([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_close_reason_t reason,
                   [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_srv_closes, 1, acq_rel);
}

static void
cli_on_peer_auth([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
                 [[maybe_unused]] duct_view_u8 identity, duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    if (conn_id != lead_leg)
        return;
    duct_response_same(out, duct_view(duct_view_u8, (void *)first, sizeof first - 1u),
                       fl_send_static, 0);
    out->conn_id = lead_leg;
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

static duct_result_t s_connect_retry(duct_engine_t *io, duct_proto_t *proto, duct_view_u8 prefix)
{
    duct_result_t rc = rc_invalid_order;
    for (unsigned waited = 0u; waited < wait_ms; waited += 5u) {
        rc = duct_io_connect_via(io, g_addr, proto, nullptr, x_tcp, 0u, prefix);
        if (rc != rc_invalid_order)
            return rc;
        struct timespec ts = { .tv_nsec = 5L * 1000L * 1000L };
        nanosleep(&ts, nullptr);
    }
    return rc;
}

static void s_reset(void)
{
    duct_atomic_store(&g_srv_tok, handle_null, relaxed);
    duct_atomic_store(&g_sessions, 0, relaxed);
    duct_atomic_store(&g_leads, 0, relaxed);
    duct_atomic_store(&g_lead_whole, 0, relaxed);
    duct_atomic_store(&g_dial_leads, 0, relaxed);
    duct_atomic_store(&g_dial_whole, 0, relaxed);
    duct_atomic_store(&g_joined, 0, relaxed);
    duct_atomic_store(&g_first_ok, 0, relaxed);
    duct_atomic_store(&g_echo_ok, 0, relaxed);
    duct_atomic_store(&g_opens, 0, relaxed);
    duct_atomic_store(&g_closes, 0, relaxed);
    duct_atomic_store(&g_errors, 0, relaxed);
    duct_atomic_store(&g_states, 0, relaxed);
    duct_atomic_store(&g_srv_closes, 0, relaxed);
}

/** @brief What the initiator leads with: a second leg's join lead, or the first connection's dial lead. */
typedef enum : uint8_t { scenario_leg, scenario_dial } scenario_t;

static const char *s_judge_leg(void)
{
    if (!th_wait_int(&g_echo_ok, 1, wait_ms))
        return "the leg dialed with a lead carried no round trip";
    if (duct_atomic_load(&g_first_ok, acquire) != 1)
        return "the joined leg's first frame did not arrive whole";
    if (duct_atomic_load(&g_joined, acquire) != 1)
        return "the leading dial did not join the session under the id its lead names";
    if (duct_atomic_load(&g_leads, acquire) != 1)
        return "the preparse saw the lead other than once";
    if (duct_atomic_load(&g_sessions, acquire) != 1)
        return "the leading dial opened a session of its own";
    if (duct_atomic_load(&g_lead_whole, acquire) != 1)
        return "the lead reached the listener without message 1 behind it";
    return nullptr;
}

static const char *s_judge_dial(void)
{
    if (!th_wait_int(&g_echo_ok, 1, wait_ms))
        return "the first dial led by a prefix carried no round trip";
    if (duct_atomic_load(&g_dial_leads, acquire) != 1)
        return "the preparse saw the dial's lead other than once";
    if (duct_atomic_load(&g_leads, acquire) != 0 || duct_atomic_load(&g_joined, acquire) != 0)
        return "the first dial was taken for a join";
    if (duct_atomic_load(&g_sessions, acquire) != 1)
        return "the first dial opened other than one session";
    if (duct_atomic_load(&g_dial_whole, acquire) != 1)
        return "the dial's lead reached the listener without message 1 behind it";
    return nullptr;
}

static const char *sc_lead(scenario_t scenario, duct_resolve_mode_t mode,
                           const duct_noise_keypair_t *srv_kp, const duct_noise_keypair_t *cli_kp)
{
    s_reset();
    duct_noise_cfg_t srv_cfg = {}, cli_cfg = {};
    srv_cfg.local_static = *srv_kp;
    cli_cfg.local_static = *cli_kp;
    memcpy(cli_cfg.remote_static_pub, srv_kp->pub, duct_noise_key_size);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return "io create failed";

    auto srv = s_proto_make((duct_proto_cfg_t){
        .name = "stream-lead-srv", .on_frame = srv_on_frame,
        .on_session_open = srv_on_open, .on_conn_join = srv_on_conn_join,
        .preparse = srv_preparse, .preparse_mode = mode,
    }, seal_role_responder, &srv_cfg);
    auto cli = s_proto_make((duct_proto_cfg_t){
        .name = "stream-lead-cli",
        .on_frame = scenario == scenario_dial ? dial_on_frame : cli_on_frame,
        .on_session_open = cli_on_open, .on_peer_auth = cli_on_peer_auth,
    }, seal_role_initiator, &cli_cfg);
    if (!srv || !cli) {
        duct_proto_destroy(srv); duct_proto_destroy(cli); duct_engine_destroy(io);
        return "proto create failed";
    }
    duct_view_u8 prefix = scenario == scenario_dial
                      ? duct_view(duct_view_u8, (void *)dial_lead, sizeof dial_lead)
                      : (duct_view_u8){};

    const char *err = nullptr;
    uint16_t port = 0u;
    pthread_t th;
    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_stream,
            .addr = "127.0.0.1", .n_protos = 1,
            .protos = (const duct_proto_t *[]){ srv },
            .probe_wait_ms = wait_ms,
            .peek_min = duct_seal_prefix_max,
        }, &port, nullptr, 0u, nullptr) != rc_ok)
        err = "listen failed";
    else if (pthread_create(&th, nullptr, th_run, io) != 0)
        err = "thread create failed";
    else {
        snprintf(g_addr, sizeof g_addr, "127.0.0.1:%u", (unsigned)port);
        err = s_connect_retry(io, cli, prefix) != rc_ok ? "connect failed"
            : scenario == scenario_dial ? s_judge_dial() : s_judge_leg();

        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }

    duct_engine_destroy(io);
    duct_proto_destroy(srv);
    duct_proto_destroy(cli);
    return err;
}

/** @brief Dial a port nothing listens on: an accepted call ends in a refused connect nobody hears of. */
static duct_result_t s_dial_dead_port(duct_engine_t *io, duct_proto_t *proto, duct_view_u8 prefix)
{
    return duct_io_connect_via(io, "127.0.0.1:9", proto, nullptr, x_tcp, 0u, prefix);
}

/** @brief The prefix argument's bounds, answered where it is passed. */
static const char *sc_args(const duct_noise_keypair_t *srv_kp, const duct_noise_keypair_t *cli_kp)
{
    duct_noise_cfg_t cli_cfg = {};
    cli_cfg.local_static = *cli_kp;
    memcpy(cli_cfg.remote_static_pub, srv_kp->pub, duct_noise_key_size);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return "io create failed";
    auto cli = s_proto_make((duct_proto_cfg_t){
        .name = "stream-lead-args", .on_frame = dial_on_frame,
    }, seal_role_initiator, &cli_cfg);
    if (!cli) {
        duct_engine_destroy(io);
        return "proto create failed";
    }

    static const uint8_t wide[duct_seal_prefix_max + 1u];
    const char *err = nullptr;
    if (s_dial_dead_port(io, cli, duct_view(duct_view_u8, (void *)dial_lead, sizeof dial_lead))
        != rc_ok)
        err = "a prefix within the bound was refused";
    else if (s_dial_dead_port(io, cli, duct_view(duct_view_u8, (void *)wide, sizeof wide))
             != rc_invalid_arg)
        err = "a prefix past duct_seal_prefix_max was taken";
    else if (s_dial_dead_port(io, cli, duct_view(duct_view_u8, (void *)wide, duct_seal_prefix_max))
             != rc_ok)
        err = "a prefix of duct_seal_prefix_max bytes was refused";
    else if (s_dial_dead_port(io, cli, (duct_view_u8){ .size = 1u }) != rc_invalid_arg)
        err = "a size with no data was taken";

    duct_engine_destroy(io);
    duct_proto_destroy(cli);
    return err;
}

/** @brief Whether the dial over a plain wire names a prefix, which no codec of that wire could carry. */
typedef enum : uint8_t { plain_bare, plain_led } plain_t;

/** @brief A plain wire has no codec to lead with a prefix: a led dial opens no session, runs no
 *  session callback and loses its conn; the bare dial over the same wires opens, which gives the
 *  silence its teeth. */
static const char *sc_plain(plain_t kind)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return "io create failed";

    auto srv_wire = duct_wire_create_length_prefix(0u);
    auto cli_wire = duct_wire_create_length_prefix(0u);
    auto srv = duct_proto_create(&(duct_proto_cfg_t){
        .name = "stream-lead-plain-srv", .wire = srv_wire, .on_frame = plain_on_frame,
        .on_session_close = plain_srv_on_close,
    });
    auto cli = duct_proto_create(&(duct_proto_cfg_t){
        .name = "stream-lead-plain-cli", .wire = cli_wire, .on_frame = plain_on_frame,
        .create_state = plain_create_state,
        .on_session_open = plain_on_open, .on_session_close = plain_on_close,
        .on_error = plain_on_error,
    });
    if (srv) srv->owned_wire = srv_wire; else duct_wire_destroy(srv_wire);
    if (cli) cli->owned_wire = cli_wire; else duct_wire_destroy(cli_wire);
    if (!srv || !cli) {
        duct_proto_destroy(srv); duct_proto_destroy(cli); duct_engine_destroy(io);
        return "proto create failed";
    }

    const char *err = nullptr;
    uint16_t port = 0u;
    pthread_t th;
    if (duct_io_listen(io, "127.0.0.1", &port, srv) != rc_ok)
        err = "listen failed";
    else if (pthread_create(&th, nullptr, th_run, io) != 0)
        err = "thread create failed";
    else {
        snprintf(g_addr, sizeof g_addr, "127.0.0.1:%u", (unsigned)port);
        duct_view_u8 prefix = kind == plain_led
                          ? duct_view(duct_view_u8, (void *)dial_lead, sizeof dial_lead)
                          : (duct_view_u8){};
        if (s_connect_retry(io, cli, prefix) != rc_ok)
            err = "connect failed";
        else if (kind == plain_bare)
            err = th_wait_int(&g_opens, 1, wait_ms) ? nullptr : "a dial with no prefix never opened";
        else
            err = !th_wait_int(&g_srv_closes, 1, wait_ms) ? "a dial led by a prefix its wire cannot carry kept its conn"
                : !th_wait_int(&g_errors, 1, wait_ms) ? "the refused dial never reached on_error"
                : duct_atomic_load(&g_opens, acquire) != 0 ? "the refused dial reached on_session_open"
                : duct_atomic_load(&g_closes, acquire) != 0 ? "the refused dial reached on_session_close"
                : duct_atomic_load(&g_states, acquire) != 0 ? "the refused dial ran create_state"
                : nullptr;
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }

    duct_engine_destroy(io);
    duct_proto_destroy(srv);
    duct_proto_destroy(cli);
    return err;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    duct_noise_keypair_t srv_kp, cli_kp;
    if (!duct_noise_keypair_generate(&srv_kp)
        || !duct_noise_keypair_generate(&cli_kp)) {
        fprintf(stderr, "stream_lead: keypair generation failed\n");
        return 1;
    }

    int pass = 1;
    static const struct {
        const char     *name;
        scenario_t      scenario;
        duct_resolve_mode_t mode;
    } runs[] = {
        { "leg, sync",   scenario_leg,  resolve_sync },
        { "leg, async",  scenario_leg,  resolve_async },
        { "dial, sync",  scenario_dial, resolve_sync },
        { "dial, async", scenario_dial, resolve_async },
    };
    for (size_t i = 0u; i < sizeof runs / sizeof runs[0]; ++i) {
        auto err = sc_lead(runs[i].scenario, runs[i].mode, &srv_kp, &cli_kp);
        if (err) { fprintf(stderr, "stream_lead: %s: %s\n", runs[i].name, err); pass = 0; }
    }
    auto err = sc_args(&srv_kp, &cli_kp);
    if (err) { fprintf(stderr, "stream_lead: args: %s\n", err); pass = 0; }
    err = sc_plain(plain_bare);
    if (err) { fprintf(stderr, "stream_lead: plain, bare: %s\n", err); pass = 0; }
    err = sc_plain(plain_led);
    if (err) { fprintf(stderr, "stream_lead: plain, led: %s\n", err); pass = 0; }

    if (!pass)
        return 1;
    printf("stream_lead: OK (a stream dial's lead joins it to the session, and the first "
           "dial's prefix reaches the preparse, under a sync and an async preparse, "
           "message 1 behind it in one write, its first frame whole; a prefix past the "
           "bound is refused, and one a plain wire cannot carry loses the dial's conn "
           "with no session callback)\n");
    return 0;
}
