/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file noise_wire_test.c
 * @brief duct_noise_vtbl behind a live sealed wire, both ends real conns.
 *
 * The engine carries the handshake alone: start() emits message 1 when the
 * codec is created, the responder answers message 2 out of unseal through
 * tx_append, and no callback in this file sees a handshake byte.
 *
 * Inner wire is nullptr on both sides, so one PDU's cleartext is one frame and
 * s_tls_on_pack hands seal a zero-length first span — the shape the VPN legs
 * use, and the case the engine's contiguous-chunk path has to get right.
 *
 * The client's first payload is returned from on_session_open, before the
 * handshake can establish, so it parks on seal_size answering 0 and must still
 * arrive once message 2 lands.
 *
 * Both frame callbacks raise their counter last, after any s_err write:
 * th_wait_int loads that counter with acquire, so a mismatch recorded after
 * the raise never reaches main.
 *
 * A second client carrying an unadmitted static key then proves the responder
 * cfg's verify_peer: its handshake stops before message 2, so nothing it sends
 * ever becomes a frame on the server.
 *
 * Sealed and cleartext are indistinguishable from here, since both ends share
 * one wire.
 */

#include "duct.h"
#include "duct_tls.h"
#include "duct_noise.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "test_helpers.h"

static const char s_hello[]  = "noise-wire-hello";
static const char s_second[] = "second-round-trip";

static atomic_int g_srv_frames = 0;
static atomic_int g_cli_frames = 0;
static atomic_int g_cli_open   = 0;
static atomic_int g_verify     = 0;
static const char *volatile s_err = nullptr;

static uint8_t s_allowed_pub[duct_noise_key_size];

/** @brief Admit only @c s_allowed_pub, counting every call. */
static bool s_verify_peer([[maybe_unused]] void *ctx,
                          const uint8_t peer_pub[duct_noise_key_size])
{
    atomic_fetch_add_explicit(&g_verify, 1, memory_order_release);
    return memcmp(peer_pub, s_allowed_pub, duct_noise_key_size) == 0;
}

/** @brief Frame sink for the rejected client, which never receives one. */
static duct_result_t
s_rogue_frame([[maybe_unused]] duct_session_t *s,
              [[maybe_unused]] duct_conn_id_t conn_id,
              [[maybe_unused]] const duct_frame_t *frame,
              [[maybe_unused]] duct_response_t *out,
              [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

/** @brief True when @p frame carries exactly @p want. */
static bool s_payload_is(const duct_frame_t *frame, const char *want, size_t len)
{
    return frame->payload.size == len && memcmp(frame->payload.data, want, len) == 0;
}

/** @brief Echo each frame's cleartext back through the same wire. */
static duct_result_t
s_srv_frame([[maybe_unused]] duct_session_t *s,
            [[maybe_unused]] duct_conn_id_t conn_id,
            const duct_frame_t *frame, duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    int n = atomic_load_explicit(&g_srv_frames, memory_order_relaxed);
    if (n == 0 && !s_payload_is(frame, s_hello, sizeof s_hello - 1u))
        s_err = "server saw wrong first cleartext";
    if (n == 1 && !s_payload_is(frame, s_second, sizeof s_second - 1u))
        s_err = "server saw wrong second cleartext";
    out->payload = frame->payload;
    out->flags = fl_send_copy;
    out->conn_id = duct_conn_id_same;
    out->stream_id = duct_stream_id_same;
    atomic_fetch_add_explicit(&g_srv_frames, 1, memory_order_release);
    return rc_ok;
}

/** @brief The client's opening payload. */
static duct_result_t
s_cli_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
           [[maybe_unused]] void *user_ctx, duct_response_t *out,
           [[maybe_unused]] void *proto_state)
{
    atomic_fetch_add(&g_cli_open, 1);
    out->payload = (duct_view_u8){ (void *)s_hello, sizeof s_hello - 1u };
    out->flags = fl_send_copy;
    return rc_ok;
}

/** @brief Check the echo, answer the first one, fall silent after the second. */
static duct_result_t
s_cli_frame([[maybe_unused]] duct_session_t *s,
            [[maybe_unused]] duct_conn_id_t conn_id,
            const duct_frame_t *frame, duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    int n = atomic_load_explicit(&g_cli_frames, memory_order_relaxed);
    if (n == 0) {
        if (!s_payload_is(frame, s_hello, sizeof s_hello - 1u)) {
            s_err = "client echo of the parked first payload mismatched";
        } else {
            out->payload = (duct_view_u8){ (void *)s_second, sizeof s_second - 1u };
            out->flags = fl_send_copy;
            out->conn_id = duct_conn_id_same;
            out->stream_id = duct_stream_id_same;
        }
    } else if (n == 1 && !s_payload_is(frame, s_second, sizeof s_second - 1u)) {
        s_err = "client echo of the second payload mismatched";
    }
    atomic_fetch_add_explicit(&g_cli_frames, 1, memory_order_release);
    return rc_ok;
}

/** @brief One role's sealed wire and the proto that takes ownership of it. */
static duct_proto_t *s_proto_make(const char *name, duct_seal_role_t role,
                                  duct_noise_cfg_t *cfg,
                                  duct_frame_fn on_frame,
                                  duct_session_open_fn on_open)
{
    auto wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .engine = duct_noise_vtbl(), .engine_cfg = cfg,
        .role = role, .framing = seal_framing_stream });
    duct_do_if(!wire, return nullptr);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = name, .wire = wire,
        .on_frame = on_frame,
        .on_session_open = on_open,
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
    if (!duct_noise_keypair_generate(&srv_kp)
        || !duct_noise_keypair_generate(&cli_kp)) {
        fprintf(stderr, "noise_wire: keypair generation failed\n");
        return 1;
    }
    duct_noise_keypair_t rogue_kp;
    if (!duct_noise_keypair_generate(&rogue_kp)) {
        fprintf(stderr, "noise_wire: rogue keypair generation failed\n");
        return 1;
    }
    memcpy(s_allowed_pub, cli_kp.pub, duct_noise_key_size);

    duct_noise_cfg_t srv_cfg = {}, cli_cfg = {}, rogue_cfg = {};
    srv_cfg.suite.pattern = cli_cfg.suite.pattern = rogue_cfg.suite.pattern = pattern;
    srv_cfg.local_static = srv_kp;
    srv_cfg.verify_peer = s_verify_peer;
    cli_cfg.local_static = cli_kp;
    memcpy(cli_cfg.remote_static_pub, srv_kp.pub, duct_noise_key_size);
    rogue_cfg.local_static = rogue_kp;
    memcpy(rogue_cfg.remote_static_pub, srv_kp.pub, duct_noise_key_size);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) {
        fprintf(stderr, "noise_wire: io create failed\n");
        return 1;
    }

    duct_proto_t *srv = nullptr, *cli = nullptr, *rogue = nullptr;
    const char *err = nullptr;
    pthread_t th;
    bool running = false;
    uint16_t port = 0u;
    char addr[64];

    srv = s_proto_make("noise-wire-srv", seal_role_responder, &srv_cfg, s_srv_frame, nullptr);
    cli = s_proto_make("noise-wire-cli", seal_role_initiator, &cli_cfg, s_cli_frame, s_cli_open);
    if (!srv || !cli) { err = "proto create failed"; goto done; }

    if (duct_io_listen(io, "127.0.0.1", &port, srv) != rc_ok) {
        err = "listen failed";
        goto done;
    }
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        err = "engine thread create failed";
        goto done;
    }
    running = true;

    snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)port);
    if (duct_io_connect(io, addr, cli, nullptr, x_tcp) != rc_ok) {
        err = "connect failed";
        goto done;
    }

    if (!th_wait_int(&g_cli_open, 1, 3000u)) { err = "client session never opened"; goto done; }
    if (!th_wait_int(&g_srv_frames, 2, 5000u)) { err = "server did not receive both frames"; goto done; }
    if (!th_wait_int(&g_cli_frames, 2, 5000u)) { err = "client did not receive both echoes"; goto done; }
    if (s_err) { err = s_err; goto done; }

    /* A second client whose static key is not the admitted one. The verify
     * counter reaching 2 is what proves the check ran for it: a client that
     * merely failed to connect also leaves the server frame count alone. */
    rogue = s_proto_make("noise-wire-rogue", seal_role_initiator, &rogue_cfg,
                         s_rogue_frame, s_cli_open);
    if (!rogue) { err = "rogue proto create failed"; goto done; }
    if (duct_io_connect(io, addr, rogue, nullptr, x_tcp) != rc_ok) {
        err = "rogue connect failed";
        goto done;
    }
    if (!th_wait_int(&g_verify, 2, 5000u)) {
        err = "verify_peer did not run for both clients";
        goto done;
    }
    if (th_wait_int(&g_srv_frames, 3, 700u)) {
        err = "a rejected peer's frame reached the server";
        goto done;
    }

done:
    duct_engine_stop(io);
    if (running)
        pthread_join(th, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(rogue);
    duct_proto_destroy(cli);
    duct_proto_destroy(srv);

    if (err) {
        fprintf(stderr, "noise_wire: %s\n", err);
        return 1;
    }
    printf("noise_wire: OK (%s, engine-driven handshake, parked first payload, "
           "two round trips both directions)\n", pattern == noise_pattern_xkpsk3 ? "XKpsk3" : "IKpsk2");
    return 0;
}
