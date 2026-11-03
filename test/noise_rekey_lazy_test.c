/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file noise_rekey_lazy_test.c
 * @brief The runtime's lazy key turnover on a Noise TCP conn under a 200 ms key
 * lifetime.
 *
 * The client sends four payloads the responder echoes: the first at open, the
 * second on a timer 700 ms after the first echo, each next on the echo before
 * it. The client's TX end stands still across the idle; the send past it
 * carries an offer beside its PDU, and the next carries its PDU alone. A
 * refused offer ends a stream, so the echoes past it prove the responder took
 * it.
 */

#include "duct.h"
#include "duct_tls.h"
#include "duct_noise.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "test_helpers.h"

static constexpr uint64_t s_lifetime_ms = 200u;
static constexpr uint64_t s_idle_ms     = 700u;
static constexpr uint64_t s_pdu_extra   = 2u + 8u + 16u;

static const char s_hello[]  = "rekey-lazy-hello";
static const char s_second[] = "after-the-idle";
static const char s_third[]  = "still-old-keys";
static const char s_fourth[] = "under-the-fresh-keys";

static atomic_int g_cli_frames = 0;
static uint64_t   g_end[4];
static const char *volatile s_err = nullptr;

static bool s_payload_is(const duct_frame_t *frame, const char *want)
{
    size_t len = strlen(want);
    return frame->payload.size == len && memcmp(frame->payload.data, want, len) == 0;
}

static uint64_t s_tx_end(duct_session_t *s)
{
    duct_tx_pos_t pos = {};
    size_t queued = 0u;
    if (duct_conn_tx_end(s, duct_conn_id_primary, &pos, &queued) != rc_ok)
        s_err = "the client's leg answered no TX end";
    return pos.at;
}

static void s_send(duct_response_t *out, const char *what)
{
    out->payload = (duct_view_u8){ (void *)what, strlen(what) };
    out->flags = fl_send_copy;
    out->conn_id = duct_conn_id_primary;
    out->stream_id = duct_stream_id_default;
}

static duct_result_t
s_srv_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
            const duct_frame_t *frame, duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    out->payload = frame->payload;
    out->flags = fl_send_copy;
    out->conn_id = duct_conn_id_same;
    out->stream_id = duct_stream_id_same;
    return rc_ok;
}

static duct_result_t
s_cli_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
           [[maybe_unused]] void *user_ctx, duct_response_t *out,
           [[maybe_unused]] void *proto_state)
{
    s_send(out, s_hello);
    return rc_ok;
}

static duct_result_t
s_cli_frame(duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
            const duct_frame_t *frame, duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    static const char *const echoed[] = { s_hello, s_second, s_third, s_fourth };
    int n = atomic_load_explicit(&g_cli_frames, memory_order_relaxed);
    if (n >= 4 || !s_payload_is(frame, echoed[n]))
        s_err = "an echo came back other than the payload sent";
    else if (n == 0) {
        g_end[0] = s_tx_end(s);
        out->control.timer.delay_ms = s_idle_ms;
    } else if (n == 1) {
        g_end[2] = s_tx_end(s);
        s_send(out, s_third);
    } else if (n == 2) {
        g_end[3] = s_tx_end(s);
        s_send(out, s_fourth);
    }
    atomic_fetch_add_explicit(&g_cli_frames, 1, memory_order_release);
    return rc_ok;
}

static duct_result_t
s_cli_timer(duct_session_t *s, duct_response_t *out, [[maybe_unused]] void *proto_state,
            [[maybe_unused]] uint64_t arg)
{
    g_end[1] = s_tx_end(s);
    s_send(out, s_second);
    return rc_ok;
}

static duct_proto_t *s_proto_make(const char *name, duct_seal_role_t role, duct_noise_cfg_t *cfg,
                                  duct_frame_fn on_frame, duct_session_open_fn on_open,
                                  duct_timer_fn on_timer)
{
    auto wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .engine = duct_noise_vtbl(), .engine_cfg = cfg,
        .role = role, .framing = seal_framing_stream });
    duct_do_if(!wire, return nullptr);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = name, .wire = wire,
        .on_frame = on_frame, .on_session_open = on_open, .on_timer = on_timer,
    });
    if (!proto) {
        duct_wire_destroy(wire);
        return nullptr;
    }
    proto->owned_wire = wire;
    return proto;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    duct_noise_pattern_t pattern = argc > 1 && strcmp(argv[1], "xk") == 0 ? noise_pattern_xkpsk3
                                                                          : noise_pattern_ikpsk2;

    duct_noise_keypair_t srv_kp, cli_kp;
    if (!duct_noise_keypair_generate(&srv_kp) || !duct_noise_keypair_generate(&cli_kp)) {
        fprintf(stderr, "noise_rekey_lazy: keypair generation failed\n");
        return 1;
    }
    duct_noise_cfg_t srv_cfg = {}, cli_cfg = {};
    srv_cfg.suite.pattern = cli_cfg.suite.pattern = pattern;
    srv_cfg.local_static = srv_kp;
    cli_cfg.local_static = cli_kp;
    memcpy(cli_cfg.remote_static_pub, srv_kp.pub, duct_noise_key_size);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){
        .io_threads = 1, .workers = 1, .seal_key_lifetime_ms = s_lifetime_ms });
    if (!io) {
        fprintf(stderr, "noise_rekey_lazy: io create failed\n");
        return 1;
    }

    const char *err = nullptr;
    pthread_t th;
    bool running = false;
    uint16_t port = 0u;
    char addr[64];
    auto srv = s_proto_make("rekey-lazy-srv", seal_role_responder, &srv_cfg, s_srv_frame,
                            nullptr, nullptr);
    auto cli = s_proto_make("rekey-lazy-cli", seal_role_initiator, &cli_cfg, s_cli_frame,
                            s_cli_open, s_cli_timer);
    if (!srv || !cli) { err = "proto create failed"; goto done; }
    if (duct_io_listen(io, "127.0.0.1", &port, srv) != rc_ok) { err = "listen failed"; goto done; }
    if (pthread_create(&th, nullptr, th_run, io) != 0) { err = "engine thread failed"; goto done; }
    running = true;
    snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)port);
    if (duct_io_connect(io, addr, cli, nullptr, x_tcp) != rc_ok) { err = "connect failed"; goto done; }
    if (!th_wait_int(&g_cli_frames, 4, 5000u)) { err = "the four echoes never came back"; goto done; }
    if (s_err) { err = s_err; goto done; }
    if (g_end[1] != g_end[0])
        err = "the client sent while idle past the key lifetime";
    else if (g_end[2] - g_end[1] <= s_pdu_extra + strlen(s_second))
        err = "the first send past an expired key carried no offer";
    else if (g_end[3] - g_end[2] != s_pdu_extra + strlen(s_third))
        err = "a send right after the offer carried more than its own PDU";

done:
    duct_engine_stop(io);
    if (running)
        pthread_join(th, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(cli);
    duct_proto_destroy(srv);
    if (err) {
        fprintf(stderr, "noise_rekey_lazy: %s\n", err);
        return 1;
    }
    printf("noise_rekey_lazy: OK (%s, idle %llu ms past a %llu ms key sent nothing, "
           "the next send carried the offer, the server took it)\n",
           pattern == noise_pattern_xkpsk3 ? "XKpsk3" : "IKpsk2",
           (unsigned long long)s_idle_ms, (unsigned long long)s_lifetime_ms);
    return 0;
}
