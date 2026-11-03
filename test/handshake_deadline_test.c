/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file handshake_deadline_test.c
 *  @brief The bound on a sealed leg's handshake, @c join_auth_timeout_ms, over
 *  TCP and Noise.
 *
 *  Every protocol here sets the bound to 300 ms. @c sc_silent connects a raw
 *  socket to a sealed responder and sends nothing; it expects the session to
 *  open, never name a peer, and close with @c close_timeout at the bound,
 *  counted from the open callback. @c sc_dial expects the same of a sealed
 *  initiator whose peer accepts at the kernel and never answers. @c sc_plain
 *  expects a plain wire to arm no bound, its session standing three bounds on.
 *  @c sc_named expects two sealed legs that finish their handshake, each naming
 *  the other, to stand three bounds on.
 */

#include "duct.h"
#include "duct_noise.h"
#include "duct_ticks.h"
#include "test_helpers.h"

#include <stdatomic.h>

/** @brief Return @p msg from the calling check when @p cond fails. */
#define expect(cond, msg) do { if (!(cond)) return msg; } while (0)

/** @brief Handshake bound every protocol sets, milliseconds. */
static constexpr uint32_t bound_ms = 300u;
/** @brief The bound, nanoseconds. */
static constexpr uint64_t bound_ns = (uint64_t)bound_ms * 1'000'000u;
/** @brief How far ahead of the bound a close may land, nanoseconds; the bound is armed just before the open callback. */
static constexpr uint64_t early_ns = 30'000'000u;
/** @brief How far past the bound a close may land, nanoseconds. */
static constexpr uint64_t late_ns  = 400'000'000u;
/** @brief Longest wait for an event, milliseconds. */
static constexpr unsigned wait_ms  = 5000u;

/** @brief Sessions opened since the scenario began. */
static atomic_int       g_opened = 0;
/** @brief Sessions closed since the scenario began. */
static atomic_int       g_closed = 0;
/** @brief Peers named since the scenario began. */
static atomic_int       g_auth   = 0;
/** @brief Reason of the last close, -1 before one. */
static atomic_int       g_reason = -1;
/** @brief Tick time of the last open, nanoseconds. */
static _Atomic uint64_t g_opened_at;
/** @brief Tick time of the last close, nanoseconds. */
static _Atomic uint64_t g_closed_at;

/** @brief Clear the counts, the reason and the stamps between scenarios. */
static void s_reset(void)
{
    duct_atomic_store(&g_opened, 0, relaxed);
    duct_atomic_store(&g_closed, 0, relaxed);
    duct_atomic_store(&g_auth, 0, relaxed);
    duct_atomic_store(&g_reason, -1, relaxed);
    duct_atomic_store(&g_opened_at, 0u, relaxed);
    duct_atomic_store(&g_closed_at, 0u, relaxed);
}

/** @brief Stamp the open and count it. */
static duct_result_t on_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                             [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
                             [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_opened_at, duct_ticks_mono_ns(), release);
    duct_atomic_fetch(add, &g_opened, 1, release);
    return rc_ok;
}

/** @brief Stamp the close, keep its reason and count it. */
static void on_close([[maybe_unused]] duct_session_t *s, duct_close_reason_t reason,
                     [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_closed_at, duct_ticks_mono_ns(), release);
    duct_atomic_store(&g_reason, (int)reason, release);
    duct_atomic_fetch(add, &g_closed, 1, release);
}

/** @brief Count one peer named. */
static void on_peer_auth([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                         [[maybe_unused]] duct_view_u8 identity, [[maybe_unused]] duct_response_t *out,
                         [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_auth, 1, release);
}

/** @brief Take every frame and answer none. */
static duct_result_t on_frame([[maybe_unused]] duct_session_t *s,
                              [[maybe_unused]] duct_conn_id_t conn_id,
                              [[maybe_unused]] const duct_frame_t *frame,
                              [[maybe_unused]] duct_response_t *out,
                              [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

/** @brief A protocol @p name over @p wire with the bound and the counting callbacks, owning @p wire.
 *  @return nullptr when @p wire is null or the protocol is not built; @p wire is destroyed in the latter case.
 */
static duct_proto_t *s_proto(const char *name, duct_wire_t *wire)
{
    if (!wire)
        return nullptr;
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = name, .wire = wire, .on_frame = on_frame, .on_session_open = on_open,
        .on_session_close = on_close, .on_peer_auth = on_peer_auth,
        .join_auth_timeout_ms = bound_ms, .max_response = 1024u,
    });
    if (proto)
        proto->owned_wire = wire;
    else
        duct_wire_destroy(wire);
    return proto;
}

/** @brief The pattern every config of the running scenario carries. */
static duct_noise_pattern_t g_pattern;

/** @brief A stream-framed Noise wire in @p role over @p cfg, which takes the scenario's pattern.
 *  @return nullptr when the wire is not built.
 */
static duct_wire_t *s_sealed(duct_seal_role_t role, duct_noise_cfg_t *cfg)
{
    cfg->suite.pattern = g_pattern;
    return duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .engine = duct_noise_vtbl(), .engine_cfg = cfg, .role = role,
        .framing = seal_framing_stream });
}

/** @brief Check that the last close was a timeout inside the slack around the bound, counted from the last open.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *s_lag(void)
{
    uint64_t opened = duct_atomic_load(&g_opened_at, acquire),
             closed = duct_atomic_load(&g_closed_at, acquire);
    expect(duct_atomic_load(&g_reason, acquire) == (int)close_timeout,
           "the session closed for another reason than close_timeout");
    expect(closed >= opened + bound_ns - early_ns, "the session closed before its bound had elapsed");
    expect(closed <= opened + bound_ns + late_ns, "the session outlived its bound");
    return nullptr;
}

/** @brief An engine running on a thread of its own. */
typedef struct {
    duct_engine_t *io;      /**< The engine. */
    pthread_t      th;      /**< Thread running the engine. */
    uint16_t       port;    /**< Port of the listener, 0 for none. */
} rig_t;

/** @brief Launch the engine, with a listener for @p listen when it is not null, and run it on a thread.
 *  A failed start leaves the engine destroyed.
 *  @return the text of the failure, nullptr when the rig runs.
 */
static const char *rig_start(rig_t *rig, duct_proto_t *listen)
{
    rig->io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!rig->io)
        return "engine launch failed";
    const char *err = listen && duct_io_listen(rig->io, "127.0.0.1", &rig->port, listen) != rc_ok
                    ? "listen failed"
                    : pthread_create(&rig->th, nullptr, th_run, rig->io) != 0 ? "thread create failed"
                    : nullptr;
    if (err)
        duct_engine_destroy(rig->io);
    return err;
}

/** @brief Stop the engine, join its thread and destroy it. */
static void rig_stop(rig_t *rig)
{
    duct_engine_stop(rig->io);
    pthread_join(rig->th, nullptr);
    duct_engine_destroy(rig->io);
}

/** @brief Connect a raw socket to a sealed responder, say nothing, and read when its session closes.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_silent(void)
{
    s_reset();
    duct_noise_keypair_t kp;
    expect(duct_noise_keypair_generate(&kp), "keypair generation failed");
    duct_noise_cfg_t cfg = { .local_static = kp };
    auto srv = s_proto("handshake-srv", s_sealed(seal_role_responder, &cfg));
    expect(srv, "proto create failed");
    rig_t rig = {};
    auto err = rig_start(&rig, srv);
    if (!err) {
        duct_sock_t fd = th_connect(rig.port);
        bool opened = fd != duct_sock_bad && th_wait_int(&g_opened, 1, wait_ms),
             closed = opened && th_wait_int(&g_closed, 1, wait_ms);
        if (fd != duct_sock_bad)
            close(fd);
        err = fd == duct_sock_bad ? "connect failed"
            : !opened ? "the session never opened"
            : !closed ? "a sealed leg that never named its peer outlived its bound"
            : duct_atomic_load(&g_auth, acquire) != 0 ? "a silent leg named its peer"
            : s_lag();
        rig_stop(&rig);
    }
    duct_proto_destroy(srv);
    return err;
}

/** @brief Connect to a plain-wire server and expect no close over three bounds.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_plain(void)
{
    s_reset();
    auto srv = s_proto("handshake-plain", duct_wire_create_length_prefix(0u));
    expect(srv, "proto create failed");
    rig_t rig = {};
    auto err = rig_start(&rig, srv);
    if (!err) {
        duct_sock_t fd = th_connect(rig.port);
        bool opened = fd != duct_sock_bad && th_wait_int(&g_opened, 1, wait_ms);
        th_sleep_ms(3u * bound_ms);
        int closed = duct_atomic_load(&g_closed, acquire);
        if (fd != duct_sock_bad)
            close(fd);
        err = fd == duct_sock_bad ? "connect failed"
            : !opened ? "the session never opened"
            : closed != 0 ? "a plain wire's session was closed by a handshake deadline"
            : nullptr;
        rig_stop(&rig);
    }
    duct_proto_destroy(srv);
    return err;
}

/** @brief Run a sealed pair through its handshake and expect no close over three bounds.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_named(void)
{
    s_reset();
    duct_noise_keypair_t srv_kp,
                         cli_kp;
    expect(duct_noise_keypair_generate(&srv_kp) && duct_noise_keypair_generate(&cli_kp),
           "keypair generation failed");
    duct_noise_cfg_t srv_cfg = { .local_static = srv_kp },
                     cli_cfg = { .local_static = cli_kp };
    memcpy(cli_cfg.remote_static_pub, srv_kp.pub, duct_noise_key_size);
    auto srv = s_proto("handshake-srv", s_sealed(seal_role_responder, &srv_cfg));
    auto cli = s_proto("handshake-cli", s_sealed(seal_role_initiator, &cli_cfg));
    const char *err = !srv || !cli ? "proto create failed" : nullptr;
    rig_t rig = {};
    if (!err)
        err = rig_start(&rig, srv);
    if (!err) {
        char addr[64];
        snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)rig.port);
        err = th_connect_retry(rig.io, addr, cli, x_tcp) != rc_ok ? "connect failed"
            : !th_wait_int(&g_auth, 2, wait_ms) ? "the handshake did not finish"
            : nullptr;
        if (!err) {
            th_sleep_ms(3u * bound_ms);
            err = duct_atomic_load(&g_closed, acquire) != 0 ? "a leg that named its peer was closed by the deadline"
                : nullptr;
        }
        rig_stop(&rig);
    }
    duct_proto_destroy(srv);
    duct_proto_destroy(cli);
    return err;
}

/** @brief Dial a sealed initiator at a listener that never answers and read when its session closes.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_dial(void)
{
    s_reset();
    duct_noise_keypair_t kp;
    expect(duct_noise_keypair_generate(&kp), "keypair generation failed");
    duct_noise_cfg_t cfg = { .local_static = kp };
    memcpy(cfg.remote_static_pub, kp.pub, duct_noise_key_size);
    auto cli = s_proto("handshake-cli", s_sealed(seal_role_initiator, &cfg));
    expect(cli, "proto create failed");
    duct_sock_t silent = (duct_sock_t)socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in at = { .sin_family = AF_INET };
    inet_pton(AF_INET, "127.0.0.1", &at.sin_addr);
    socklen_t len = sizeof at;
    const char *err = silent == duct_sock_bad || bind(silent, (struct sockaddr *)&at, sizeof at) != 0
                   || listen(silent, 4) != 0 || getsockname(silent, (struct sockaddr *)&at, &len) != 0
                    ? "the silent peer's socket failed" : nullptr;
    rig_t rig = {};
    if (!err)
        err = rig_start(&rig, nullptr);
    if (!err) {
        char addr[64];
        snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)ntohs(at.sin_port));
        bool dialed = th_connect_retry(rig.io, addr, cli, x_tcp) == rc_ok,
             opened = dialed && th_wait_int(&g_opened, 1, wait_ms),
             closed = opened && th_wait_int(&g_closed, 1, wait_ms);
        err = !dialed ? "connect failed"
            : !opened ? "the session never opened"
            : !closed ? "a dialed leg that its peer never answered outlived its bound"
            : s_lag();
        rig_stop(&rig);
    }
    if (silent != duct_sock_bad)
        close(silent);
    duct_proto_destroy(cli);
    return err;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    static const struct { const char *name; const char *(*fn)(void); } cases[] = {
        { "silent", sc_silent },
        { "plain",  sc_plain },
        { "named",  sc_named },
        { "dial",   sc_dial },
    };
    static const struct { duct_noise_pattern_t pattern; const char *name; } patterns[] = {
        { noise_pattern_ikpsk2, "IKpsk2" },
        { noise_pattern_xkpsk3, "XKpsk3" },
    };
    for (size_t p = 0u; p < sizeof patterns / sizeof patterns[0]; ++p) {
        g_pattern = patterns[p].pattern;
        for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
            auto err = cases[i].fn();
            if (err) {
                fprintf(stderr, "handshake_deadline: %s, %s: %s\n", patterns[p].name, cases[i].name, err);
                return 1;
            }
        }
    }
    printf("handshake_deadline: OK (IKpsk2 and XKpsk3)\n");
    return 0;
}
