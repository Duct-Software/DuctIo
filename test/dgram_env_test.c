/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

#include "duct.h"
#include "duct_codel.h"
#include "duct_core.h"
#include "duct_ticks.h"
#include "duct_wire.h"
#include "duct_wire_codec.h"
#include "test_helpers.h"
#include "dgram_test_helpers.h"
#include "tls_engine_null.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define expect(cond, msg) do { if (!(cond)) return msg; } while (0)

static const char *sc_cfg_and_bound(void)
{
    auto lp = duct_wire_create_length_prefix(0u);
    auto mux = duct_wire_create_mux(0u);
    auto dg = duct_wire_create_dgram_batch(0u, false);
    expect(lp && mux && dg, "inner wire create failed");

    const char *err = nullptr;
    auto w_stream = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .inner = lp, .engine = tls_null_vtbl(),
        .role = seal_role_responder, .framing = seal_framing_stream, .dgram_env = true,
    });
    if (w_stream) {
        duct_wire_destroy(w_stream);
        err = "dgram_env accepted stream framing";
    }
    if (!err) {
        auto w_no_inner = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = nullptr, .engine = tls_null_vtbl(),
            .role = seal_role_responder, .framing = seal_framing_datagram, .dgram_env = true,
        });
        if (w_no_inner) {
            duct_wire_destroy(w_no_inner);
            err = "dgram_env accepted nullptr inner";
        }
    }
    if (!err) {
        auto w_no_flags = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = dg, .engine = tls_null_vtbl(),
            .role = seal_role_responder, .framing = seal_framing_datagram, .dgram_env = true,
        });
        if (w_no_flags) {
            duct_wire_destroy(w_no_flags);
            err = "dgram_env accepted inner without fl_wire_frame_flags";
        }
    }
    if (!err) {
        auto w_mux = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = mux, .engine = tls_null_vtbl(),
            .role = seal_role_responder, .framing = seal_framing_datagram, .dgram_env = true,
        });
        if (!w_mux)
            err = "dgram_env rejected mux inner";
        else
            duct_wire_destroy(w_mux);
    }
    if (!err) {
        auto w_plain = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = lp, .engine = tls_null_vtbl(),
            .role = seal_role_responder, .framing = seal_framing_datagram, .dgram_env = false,
        });
        auto w_env = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = lp, .engine = tls_null_vtbl(),
            .role = seal_role_responder, .framing = seal_framing_datagram, .dgram_env = true,
        });
        size_t max_plain = tls_null_vtbl()->pdu_ct_max - lp->header_size;
        size_t max_env = max_plain - sizeof(duct_dgram_env_t);
        if (!w_plain || !w_env)
            err = "dgram sealed wire create failed";
        else if (w_plain->tx_bound(w_plain, max_plain) == SIZE_MAX)
            err = "plain sealed wire rejected max payload";
        else if (w_env->tx_bound(w_env, max_env) == SIZE_MAX)
            err = "dgram_env wire rejected max - 8 payload";
        else if (w_env->tx_bound(w_env, max_env + 1u) != SIZE_MAX)
            err = "dgram_env wire accepted max - 7 payload";
        if (w_plain) duct_wire_destroy(w_plain);
        if (w_env) duct_wire_destroy(w_env);
    }
    duct_wire_destroy(dg);
    duct_wire_destroy(mux);
    duct_wire_destroy(lp);
    return err;
}

static const char *sc_owd(void)
{
    duct_wire_codec_t c = { .env_capable = true, .env_on = true };
    uint64_t t = 100'000'000'000ull;

    duct_dgram_env_t in = { .tx_us = (uint32_t)(t / 1000ull - 5'000u), .peer_q_us = 12'000u };
    duct_wire_codec_owd_rx(&c, &in, t);
    expect(c.owd.have && c.owd.remote_q_have && c.owd.remote_q_ns == 12'000'000ull,
           "initial RX did not record remote_q");
    duct_dgram_env_t out = {};
    duct_wire_codec_owd_tx(&c, &out, t + 1'000'000ull);
    expect(out.peer_q_us == 0u, "initial packet produced nonzero rx_q");

    t += 50'000'000ull;
    in = (duct_dgram_env_t){ .tx_us = (uint32_t)(t / 1000ull - 25'000u), .peer_q_us = 0u };
    duct_wire_codec_owd_rx(&c, &in, t);
    expect(c.owd.remote_q_ns == 0u, "peer_q_us == 0 did not clear remote_q_ns immediately");
    duct_wire_codec_owd_tx(&c, &out, t);
    expect(out.peer_q_us == 20'000u, "spike did not rise immediately");

    t += 10'000'000ull;
    in.tx_us = (uint32_t)(t / 1000ull - 5'000u);
    duct_wire_codec_owd_rx(&c, &in, t);
    duct_wire_codec_owd_tx(&c, &out, t);
    expect(out.peer_q_us == 15'000u, "decay step was not 3/4");

    c.owd.rx_q_us = 3u;
    for (int i = 0; i < 3; ++i) {
        t += 10'000'000ull;
        in.tx_us = (uint32_t)(t / 1000ull - 5'000u);
        duct_wire_codec_owd_rx(&c, &in, t);
    }
    expect(c.owd.rx_q_us == 0u, "small rx_q_us failed to decay down to zero");

    uint64_t wrap_ns = ((uint64_t)0xFFFF'FC00u + 1'000u) * 1000ull;
    c.owd = (typeof(c.owd)){};
    uint32_t base_tx = 0xFFFF'FB00u;
    duct_wire_codec_owd_rx(&c, &(duct_dgram_env_t){ .tx_us = base_tx }, wrap_ns);
    wrap_ns += 5'000'000ull;
    uint32_t later_tx = base_tx + 4'500u;
    duct_wire_codec_owd_rx(&c, &(duct_dgram_env_t){ .tx_us = later_tx }, wrap_ns);
    duct_wire_codec_owd_tx(&c, &out, wrap_ns);
    expect(out.peer_q_us == 500u, "32-bit us wrap broke OWD subtraction");

    t = wrap_ns + duct_owd_window_ns + 5'000'000ull;
    uint32_t raised = (uint32_t)(t / 1000ull - 45'000u);
    duct_wire_codec_owd_rx(&c, &(duct_dgram_env_t){ .tx_us = raised }, t);
    t += duct_owd_window_ns;
    raised = (uint32_t)(t / 1000ull - 45'000u);
    duct_wire_codec_owd_rx(&c, &(duct_dgram_env_t){ .tx_us = raised }, t);
    duct_wire_codec_owd_tx(&c, &out, t);
    expect(out.peer_q_us == 0u, "two-half window did not absorb elevated path baseline");

    t += duct_owd_stale_ns + 1u;
    duct_wire_codec_owd_tx(&c, &out, t);
    expect(out.peer_q_us == 0u, "stale rx_q was not zeroed on TX");

    duct_wire_codec_owd_reset(&c);
    expect(!c.owd.have && !c.owd.remote_q_have && c.owd.remote_q_ns == 0u,
           "owd_reset left OWD state populated");
    return nullptr;
}

static constexpr uint64_t s_cid = 0xD6E4E471u;
static _Atomic(duct_handle_t) g_srv_tok;
static atomic_int g_srv_open = 0;
static atomic_int g_srv_frames = 0;
static _Atomic(const char *) g_srv_err = nullptr;
static duct_codel_t g_codel = {};
static const duct_codel_law_t g_law = {
    .target = 5'000'000ull,
    .interval = 100'000'000ull,
    .at_once = 20'000'000ull,
};

static duct_resolve_disposition_t
s_preparse([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer,
           [[maybe_unused]] duct_view_u8 peek, duct_handle_t *out_tok,
           duct_conn_id_t *out_conn_id, [[maybe_unused]] void **out_user_ctx,
           [[maybe_unused]] size_t *out_lead)
{
    if (!duct_atomic_load(&g_srv_open, acquire))
        return resolve_new;
    *out_tok = duct_atomic_load(&g_srv_tok, acquire);
    *out_conn_id = duct_conn_id_primary;
    return resolve_join;
}

static duct_result_t s_on_open(duct_session_t *s, duct_handle_t tok,
                               [[maybe_unused]] void *uctx,
                               [[maybe_unused]] duct_response_t *out,
                               [[maybe_unused]] void *pstate)
{
    if (duct_conn_set_dgram_env(s, duct_session_max_legs, true) != rc_invalid_arg)
        duct_atomic_store(&g_srv_err, "bad conn_id was not rc_invalid_arg", release);
    else if (duct_conn_set_dgram_env(s, duct_conn_id_primary, true) != rc_ok)
        duct_atomic_store(&g_srv_err, "duct_conn_set_dgram_env failed", release);
    duct_atomic_store(&g_srv_tok, tok, release);
    duct_atomic_fetch(add, &g_srv_open, 1, release);
    return rc_ok;
}

static duct_result_t s_on_frame(duct_session_t *s, duct_conn_id_t conn_id,
                                const duct_frame_t *frame, duct_response_t *out,
                                [[maybe_unused]] void *pstate)
{
    if (duct_has(frame->flags, fl_frame_env)) {
        duct_atomic_store(&g_srv_err, "fl_frame_env leaked into on_frame", release);
        return rc_ok;
    }
    if (frame->payload.size == 4u && memcmp(frame->payload.data, "PING", 4u) == 0) {
        uint64_t now = duct_ticks_mono_ns();
        uint64_t delay = duct_conn_codel_delay(s, conn_id, &g_codel, &g_law, now);
        auto v1 = duct_conn_codel(s, conn_id, &g_codel, &g_law, 4u, now);
        auto v_stale = duct_conn_codel(s, conn_id, &g_codel, &g_law, 4u,
                                       now + duct_owd_stale_ns + 10'000ull);
        if (delay != 25'000'000ull)
            duct_atomic_store(&g_srv_err, "codel_delay missed 25ms remote queue", release);
        else if (v1 != codel_signal)
            duct_atomic_store(&g_srv_err, "codel failed to signal >= at_once remote queue", release);
        else if (v_stale != codel_pass)
            duct_atomic_store(&g_srv_err, "stale remote queue did not return codel_pass", release);
        static uint8_t pong[4] = { 'P', 'O', 'N', 'G' };
        duct_response_same(out, (duct_view_u8){ pong, 4u }, fl_send_copy, fl_frame_none);
    } else if (frame->payload.size == 4u && memcmp(frame->payload.data, "ZERO", 4u) == 0) {
        uint64_t now = duct_ticks_mono_ns();
        uint64_t delay = duct_conn_codel_delay(s, conn_id, &g_codel, &g_law, now);
        if (delay != 0u)
            duct_atomic_store(&g_srv_err, "zero peer_q_us failed to reset codel_delay", release);
    }
    duct_atomic_fetch(add, &g_srv_frames, 1, release);
    return rc_ok;
}

static int s_send_frame(duct_sock_t fd, uint8_t flags, const char *body, size_t body_len,
                        const duct_dgram_env_t *env)
{
    uint8_t pt[128], sealed[128], rec[duct_tls_record_hdr_size + sizeof sealed];
    size_t pos = 4u;
    pt[0] = (uint8_t)(flags & 0x0fu);
    pt[1] = 0u;
    pt[2] = (uint8_t)(body_len >> 8u);
    pt[3] = (uint8_t)body_len;
    memcpy(pt + pos, body, body_len);
    pos += body_len;
    if (env) {
        pt[0] |= (uint8_t)fl_frame_env;
        duct_store_le32(pt + pos, env->tx_us);
        duct_store_le32(pt + pos + 4u, env->peer_q_us);
        pos += sizeof(duct_dgram_env_t);
    }
    size_t slen = tls_null_seal(pt, pos, sealed, sizeof sealed);
    if (!slen)
        return -1;
    size_t rlen = tls_null_record(rec, 2u, sealed, slen);
    return uc_send(fd, rec, rlen);
}

static const char *sc_e2e_shared_and_codel(void)
{
    duct_handle_t zero = {};
    duct_atomic_store(&g_srv_tok, zero, relaxed);
    duct_atomic_store(&g_srv_open, 0, relaxed);
    duct_atomic_store(&g_srv_frames, 0, relaxed);
    duct_atomic_store(&g_srv_err, nullptr, relaxed);
    g_codel = (duct_codel_t){};

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    expect(io != nullptr, "engine launch failed");
    auto inner = duct_wire_create_length_prefix(0u);
    auto wire = inner ? duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .inner = inner, .engine = tls_null_vtbl(),
        .role = seal_role_responder, .framing = seal_framing_datagram, .dgram_env = true,
    }) : nullptr;
    if (!wire) {
        if (inner)
            duct_wire_destroy(inner);
        duct_engine_destroy(io);
        return "wire create failed";
    }

    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "dgram-env-e2e", .wire = wire,
        .on_frame = s_on_frame, .on_session_open = s_on_open,
        .preparse = s_preparse, .preparse_mode = resolve_sync,
        .max_response = 1024u, .flags = fl_proto_dgram_shared,
    });
    if (proto)
        proto->owned_wire = wire;
    else
        duct_wire_destroy(wire);
    if (!proto) {
        duct_wire_destroy(inner);
        duct_engine_destroy(io);
        return "proto create failed";
    }

    const duct_proto_t *proto_list = proto;
    uint16_t port = 0u;
    if (duct_listener_bind(io, &(duct_listener_cfg_t){
            .kind = listener_dgram, .addr = "127.0.0.1", .n_protos = 1, .protos = &proto_list,
        }, &port, nullptr, 0u, nullptr) != rc_ok) {
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        duct_wire_destroy(inner);
        return "dgram listener bind failed";
    }
    pthread_t th;
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        duct_wire_destroy(inner);
        return "thread create failed";
    }

    const char *err = nullptr;
    duct_sock_t fd = uc_connect(port);
    if (fd == duct_sock_bad)
        err = "udp client connect failed";

    uint8_t buf[256], pt[256];
    if (!err) {
        uint8_t hello[duct_tls_record_hdr_size + 4u];
        size_t hlen = tls_null_record(hello, 1u, "CHLO", 4u);
        if (uc_send(fd, hello, hlen) != 0)
            err = "handshake send failed";
        else if (uc_recv(fd, (char *)buf, sizeof buf) != (ssize_t)(duct_tls_record_hdr_size + 4u))
            err = "server hello recv failed";
    }
    if (!err && !th_wait_int(&g_srv_open, 1, 2000u))
        err = "server session did not open";

    if (!err) {
        duct_dgram_env_t env = { .tx_us = 10'000u, .peer_q_us = 25'000u };
        if (s_send_frame(fd, 0u, "PING", 4u, &env) != 0)
            err = "PING send failed";
        else if (!th_wait_int(&g_srv_frames, 1, 2000u))
            err = "server missed PING";
    }
    if (!err) {
        ssize_t n = uc_recv(fd, (char *)buf, sizeof buf);
        if (n < (ssize_t)(duct_tls_record_hdr_size + 18u))
            err = "PONG recv too short";
        else {
            size_t pt_len = tls_null_unseal_body(buf + duct_tls_record_hdr_size,
                                                 (size_t)n - duct_tls_record_hdr_size,
                                                 pt, sizeof pt);
            if (pt_len != 16u)
                err = "PONG cleartext length != 4 + 4 + 8";
            else if (!(pt[0] & (uint8_t)fl_frame_env))
                err = "server TX omitted fl_frame_env bit";
            else if (memcmp(pt + 4u, "PONG", 4u) != 0)
                err = "server TX payload mismatch";
            else if (duct_load_le32(pt + 12u) != 0u)
                err = "server initial peer_q_us was not 0";
        }
    }
    if (!err) {
        duct_dgram_env_t env = { .tx_us = 20'000u, .peer_q_us = 0u };
        if (s_send_frame(fd, 0u, "ZERO", 4u, &env) != 0)
            err = "ZERO send failed";
        else if (!th_wait_int(&g_srv_frames, 2, 2000u))
            err = "server missed ZERO";
    }
    if (!err)
        err = duct_atomic_load(&g_srv_err, acquire);

    if (fd != duct_sock_bad)
        duct_sock_close(fd);
    duct_engine_stop(io);
    pthread_join(th, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    duct_wire_destroy(inner);
    return err;
}

int main(void)
{
    static const struct { const char *name; const char *(*fn)(void); } cases[] = {
        { "cfg_and_bound",      sc_cfg_and_bound },
        { "owd",                sc_owd },
        { "e2e_shared_codel",   sc_e2e_shared_and_codel },
    };
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        auto err = cases[i].fn();
        if (err) {
            fprintf(stderr, "dgram_env: %s: %s\n", cases[i].name, err);
            return 1;
        }
    }
    printf("dgram_env: OK (cfg/tx_bound, OWD 32-bit wrap & decay, e2e trailer & CoDel)\n");
    return 0;
}
