/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file idle_timeout_test.c
 * @brief idle_timeout_ms closes a session whose socket legs stopped delivering
 * accepted frames, and no other.
 *
 * Each scenario runs its own engine with a 500 ms bound and measures, from the
 * last frame @c on_frame accepted to the session's close. A close lands within
 * [bound - 30 ms, bound + 400 ms] of that frame, with the reason
 * @c close_timeout:
 *
 * - alive: a frame every 100 ms for 1.4 s keeps the session open past its first
 *   bound, and the close follows the last frame by the bound;
 * - rejected: frames @c on_frame refuses with @c rc_drop do not postpone it;
 * - device: packets arriving on an attached packet fd for the whole span do not
 *   postpone it, POSIX only;
 * - switch: a session switching into a protocol with a bound starts the bound
 *   there;
 * - off: a protocol with no bound closes nothing;
 * - early: a session the protocol closes before its bound ends with the
 *   protocol's own reason;
 * - retired: a session closed while its idle timer is pending leaves the timer's
 *   node behind, and the engine lives through that node's deadline and bounds the
 *   next session as before.
 */

#include "duct.h"
#include "duct_ticks.h"
#include "duct_wire.h"

#include <stdatomic.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

#include "test_helpers.h"
#include "dgram_test_helpers.h"

static constexpr uint32_t bound_ms = 500u;
static constexpr uint64_t bound_ns = (uint64_t)bound_ms * 1'000'000u;
static constexpr uint64_t early_ns = 30'000'000u;
static constexpr uint64_t late_ns  = 400'000'000u;
static constexpr unsigned gap_ms   = 100u;
static constexpr unsigned wait_ms  = 5000u;
static constexpr unsigned off_ms   = 1500u;
static constexpr unsigned linger_ms = bound_ms + 400u;

static atomic_int       g_closed;
static atomic_int       g_reason;
static atomic_int       g_attached;
static _Atomic uint64_t g_heard_at;
static _Atomic uint64_t g_closed_at;
static _Atomic uint64_t g_dev_at;
static _Atomic(const duct_proto_t *) g_next;
static double           g_lag_ms;

#ifndef _WIN32
static duct_wire_t *g_dev_wire;
static duct_sock_t  g_dev_peer = duct_sock_bad;
#endif

/** @brief Forget the last close and the frame it followed. */
static void s_reset_close(void)
{
    duct_atomic_store(&g_closed, 0, relaxed);
    duct_atomic_store(&g_reason, -1, relaxed);
    duct_atomic_store(&g_heard_at, 0u, relaxed);
    duct_atomic_store(&g_closed_at, 0u, relaxed);
}

static void s_reset(void)
{
    s_reset_close();
    duct_atomic_store(&g_attached, 0, relaxed);
    duct_atomic_store(&g_dev_at, 0u, relaxed);
    duct_atomic_store(&g_next, nullptr, relaxed);
    g_lag_ms = 0.0;
}

/** @brief Stamp the first close and its reason, then count it. */
static void
s_on_close([[maybe_unused]] duct_session_t *s, duct_close_reason_t reason,
           [[maybe_unused]] void *proto_state)
{
    uint64_t none = 0u;
    if (duct_atomic_cas(strong, &g_closed_at, &none, duct_ticks_mono_ns(), acq_rel, relaxed))
        duct_atomic_store(&g_reason, (int)reason, relaxed);
    duct_atomic_fetch(add, &g_closed, 1, release);
}

/** @brief Accept every frame of the primary leg except those leading with 'x',
 *  which it refuses, and close the session on one leading with 'c'.
 *  Frames of any other leg are stamped and accepted. */
static duct_result_t
s_on_frame([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
           const duct_frame_t *frame, duct_response_t *out,
           [[maybe_unused]] void *proto_state)
{
    if (conn_id != duct_conn_id_primary) {
        duct_atomic_store(&g_dev_at, duct_ticks_mono_ns(), release);
        return rc_ok;
    }
    char lead = frame->payload.size ? *(const char *)frame->payload.data : '\0';
    if (lead == 'x')
        return rc_drop;
    duct_atomic_store(&g_heard_at, duct_ticks_mono_ns(), release);
    if (lead == 'c')
        duct_response_close_session(out, close_normal);
    return rc_ok;
}

/** @brief Stamp the first frame and switch to the protocol in @c g_next. */
static duct_result_t
s_on_frame_switch(duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                  [[maybe_unused]] const duct_frame_t *frame, duct_response_t *out,
                  [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_heard_at, duct_ticks_mono_ns(), release);
    return duct_response_switch(out, s, duct_atomic_load(&g_next, acquire), nullptr);
}

/** @brief Wait up to @p timeout_ms for the first close. */
static bool s_wait_closed(unsigned timeout_ms)
{
    for (unsigned waited = 0u; waited < timeout_ms; waited += 10u) {
        if (duct_atomic_load(&g_closed, acquire) != 0)
            return true;
        th_sleep_ms(10u);
    }
    return duct_atomic_load(&g_closed, acquire) != 0;
}

/** @brief Judge the close against the last accepted frame and store the gap in
 *  @c g_lag_ms.
 *  @return nullptr for a @c close_timeout inside the window, else what was
 *  wrong. */
static const char *s_check_lag(void)
{
    if (duct_atomic_load(&g_closed, acquire) == 0)
        return "the session was never closed";
    uint64_t heard = duct_atomic_load(&g_heard_at, acquire),
             closed = duct_atomic_load(&g_closed_at, acquire);
    if (duct_atomic_load(&g_reason, relaxed) != (int)close_timeout)
        return "the session closed for another reason than close_timeout";
    if (heard == 0u)
        return "no frame was ever accepted";
    g_lag_ms = ((double)closed - (double)heard) / 1e6;
    if (closed < heard + bound_ns - early_ns)
        return "the session closed before its bound had elapsed";
    if (closed > heard + bound_ns + late_ns)
        return "the session outlived its bound";
    return nullptr;
}

/** @brief What a scenario expects once its script has run. */
typedef enum expect {
    expect_lag_after_script, /**< The session stays open through the script, then
                               *  closes inside the window. */
    expect_lag,              /**< The session closes inside the window. */
    expect_none,             /**< The session does not close. */
    expect_normal,           /**< The session closes with @c close_normal. */
} expect_t;

/** @brief Run an engine with a shared datagram listener serving @p proto, send
 *  @p script as one datagram per character, wait up to @p watch_ms for the close
 *  and judge it by @p expect.
 *  @return nullptr, or what failed. */
static const char *
s_udp_run(const duct_proto_t *proto, const char *script, unsigned watch_ms, expect_t expect)
{
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return "engine launch failed";
    const duct_proto_t *protos[1] = { proto };
    uint16_t port = 0u;
    const char *err = nullptr;
    pthread_t th;
    bool running = false;
    duct_sock_t fd = duct_sock_bad;
    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
            .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
        }, &port, nullptr, 0u, nullptr) != rc_ok)
        err = "listener bind failed";
    else if (pthread_create(&th, nullptr, th_run, io) != 0)
        err = "thread create failed";
    else {
        running = true;
        fd = uc_connect(port);
        if (fd == duct_sock_bad)
            err = "client socket failed";
    }
    for (const char *c = script; !err && *c; ++c) {
        uint8_t datagram[8] = { (uint8_t)*c, 'd', 'a', 't', 'a' };
        if (uc_send(fd, datagram, sizeof datagram) != 0)
            err = "send failed";
        else if (c[1])
            th_sleep_ms(gap_ms);
    }
    bool open_through_script = duct_atomic_load(&g_closed, acquire) == 0;
    bool closed = !err && s_wait_closed(watch_ms);
    if (!err) {
        switch (expect) {
        case expect_lag_after_script:
            err = !open_through_script ? "frames did not keep the session open"
                : !closed              ? "the session was never closed"
                :                        s_check_lag();
            break;
        case expect_lag:
            err = s_check_lag();
            break;
        case expect_none:
            err = closed ? "a protocol with no bound closed its session" : nullptr;
            break;
        case expect_normal:
            err = !closed ? "the protocol's own close never arrived"
                : duct_atomic_load(&g_reason, relaxed) != (int)close_normal
                    ? "the protocol's own close lost its reason"
                    : nullptr;
            break;
        }
    }

    if (fd != duct_sock_bad)
        close(fd);
    duct_engine_stop(io);
    if (running)
        pthread_join(th, nullptr);
    duct_engine_destroy(io);
    return err;
}

/** @brief Create a shared datagram protocol over @p wire with @p bound ms of
 *  idle bound. */
static duct_proto_t *
s_udp_proto(const char *name, duct_frame_fn on_frame, uint32_t bound, duct_wire_t *wire)
{
    return duct_proto_create(&(duct_proto_cfg_t){
        .name = name, .wire = wire, .on_frame = on_frame,
        .on_session_close = s_on_close, .max_response = 4096u,
        .flags = fl_proto_dgram_shared, .idle_timeout_ms = bound,
    });
}

/** @brief Run @p script against one datagram protocol of @p bound ms. */
static const char *
s_single(const char *name, uint32_t bound, const char *script, unsigned watch_ms, expect_t expect)
{
    s_reset();
    auto wire = duct_wire_create_dgram_batch(0u, false);
    auto proto = wire ? s_udp_proto(name, s_on_frame, bound, wire) : nullptr;
    if (!proto) {
        if (wire)
            duct_wire_destroy(wire);
        return "proto create failed";
    }
    proto->owned_wire = wire;
    const char *err = s_udp_run(proto, script, watch_ms, expect);
    duct_proto_destroy(proto);
    return err;
}

static const char *sc_alive(void)
{
    return s_single("idle-alive", bound_ms, "aaaaaaaaaaaaaaa", wait_ms, expect_lag_after_script);
}

static const char *sc_rejected(void)
{
    return s_single("idle-rejected", bound_ms, "axxxxxxxx", wait_ms, expect_lag);
}

static const char *sc_off(void)
{
    return s_single("idle-off", 0u, "a", off_ms, expect_none);
}

static const char *sc_early(void)
{
    return s_single("idle-early", 60'000u, "c", wait_ms, expect_normal);
}

static const char *sc_switch(void)
{
    s_reset();
    auto wire = duct_wire_create_dgram_batch(0u, false);
    auto first = wire ? s_udp_proto("idle-first", s_on_frame_switch, 0u, wire) : nullptr;
    auto then = wire ? s_udp_proto("idle-then", s_on_frame, bound_ms, wire) : nullptr;
    if (!first || !then) {
        duct_proto_destroy(first);
        duct_proto_destroy(then);
        if (wire)
            duct_wire_destroy(wire);
        return "proto create failed";
    }
    first->owned_wire = wire;
    duct_atomic_store(&g_next, then, release);
    const char *err = s_udp_run(first, "a", wait_ms, expect_lag);
    duct_proto_destroy(first);
    duct_proto_destroy(then);
    return err;
}

/** @brief One datagram opens a session and arms its idle timer, a second closes
 *  the session from the protocol, and the test keeps the engine running past the
 *  bound before a second client opens another session, which the bound closes. */
static const char *sc_retired(void)
{
    s_reset();
    auto wire = duct_wire_create_dgram_batch(0u, false);
    auto proto = wire ? s_udp_proto("idle-retired", s_on_frame, bound_ms, wire) : nullptr;
    if (!proto) {
        if (wire)
            duct_wire_destroy(wire);
        return "proto create failed";
    }
    proto->owned_wire = wire;
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    const duct_proto_t *protos[1] = { proto };
    uint16_t port = 0u;
    const char *err = io ? nullptr : "engine launch failed";
    pthread_t th;
    bool running = false;
    duct_sock_t first = duct_sock_bad, second = duct_sock_bad;
    static const uint8_t keep[8] = { 'a', 'd', 'a', 't', 'a' };
    static const uint8_t close_it[8] = { 'c', 'd', 'a', 't', 'a' };
    if (!err && duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
            .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
        }, &port, nullptr, 0u, nullptr) != rc_ok)
        err = "listener bind failed";
    if (!err) {
        if (pthread_create(&th, nullptr, th_run, io) != 0)
            err = "thread create failed";
        else
            running = true;
    }
    if (!err) {
        first = uc_connect(port);
        if (first == duct_sock_bad || uc_send(first, keep, sizeof keep) != 0)
            err = "first datagram failed";
    }
    if (!err) {
        th_sleep_ms(gap_ms);
        if (uc_send(first, close_it, sizeof close_it) != 0)
            err = "closing datagram failed";
    }
    if (!err && !s_wait_closed(wait_ms))
        err = "the protocol's own close never arrived";
    if (!err) {
        th_sleep_ms(linger_ms);
        s_reset_close();
        second = uc_connect(port);
        if (second == duct_sock_bad || uc_send(second, keep, sizeof keep) != 0)
            err = "second datagram failed";
    }
    if (!err)
        err = s_wait_closed(wait_ms) ? s_check_lag() : "the session after the retired one was never closed";

    if (first != duct_sock_bad)
        close(first);
    if (second != duct_sock_bad)
        close(second);
    if (io)
        duct_engine_stop(io);
    if (running)
        pthread_join(th, nullptr);
    if (io)
        duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return err;
}

#ifndef _WIN32

/** @brief Attach one end of a socketpair as the packet fd leg 1 and keep the
 *  other in @c g_dev_peer. */
static duct_result_t
s_on_open_dev(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
              [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
              [[maybe_unused]] void *proto_state)
{
    duct_sock_t sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0)
        return rc_ok;
    g_dev_peer = sv[0];
    if (duct_conn_attach_packet_fd(s, 1u, sv[1], g_dev_wire) == rc_ok)
        duct_atomic_store(&g_attached, 1, release);
    return rc_ok;
}

/** @brief Keep packets arriving on the device leg through the whole span and
 *  judge the close of the session whose primary leg went quiet. */
static const char *sc_device(void)
{
    s_reset();
    g_dev_peer = duct_sock_bad;
    g_dev_wire = duct_wire_create_dgram_batch(2048u, false);
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = (g_dev_wire && wire) ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "idle-device", .wire = wire, .on_frame = s_on_frame,
        .on_session_open = s_on_open_dev, .on_session_close = s_on_close,
        .max_response = 4096u, .idle_timeout_ms = bound_ms,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    auto io = proto ? duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 })
                    : nullptr;
    const char *err = !io ? "setup failed" : nullptr;
    uint16_t port = 0u;
    pthread_t th;
    bool running = false;
    duct_sock_t fd = duct_sock_bad;
    if (!err && duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok)
        err = "listen failed";
    if (!err) {
        if (pthread_create(&th, nullptr, th_run, io) != 0)
            err = "thread create failed";
        else
            running = true;
    }
    if (!err) {
        fd = th_connect(port);
        if (fd == duct_sock_bad)
            err = "connect failed";
        else if (th_send(fd, "adata", 5u) != 0)
            err = "send failed";
    }
    if (!err && !th_wait_int(&g_attached, 1, wait_ms))
        err = "the packet fd never attached";
    static constexpr unsigned packet_gap_ms = 80u;
    uint8_t packet[64] = {};
    for (unsigned sent = 0u; !err && sent < 20u && duct_atomic_load(&g_closed, acquire) == 0; ++sent) {
        if (write(g_dev_peer, packet, sizeof packet) != (ssize_t)sizeof packet)
            err = "write to the packet fd failed";
        th_sleep_ms(packet_gap_ms);
    }
    if (!err && !s_wait_closed(wait_ms))
        err = "the session was never closed";
    if (!err)
        err = s_check_lag();
    if (!err && duct_atomic_load(&g_dev_at, acquire) < duct_atomic_load(&g_heard_at, acquire) + bound_ns / 2u)
        err = "packets did not keep arriving through the span";

    if (fd != duct_sock_bad)
        close(fd);
    if (io)
        duct_engine_stop(io);
    if (running)
        pthread_join(th, nullptr);
    if (io)
        duct_engine_destroy(io);
    duct_proto_destroy(proto);
    if (g_dev_wire)
        duct_wire_destroy(g_dev_wire);
    if (g_dev_peer != duct_sock_bad)
        close(g_dev_peer);
    return err;
}

#endif

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    static const struct {
        const char *name;
        const char *(*run)(void);
    } scenarios[] = {
        { "alive",    sc_alive },
        { "rejected", sc_rejected },
#ifndef _WIN32
        { "device",   sc_device },
#endif
        { "switch",   sc_switch },
        { "off",      sc_off },
        { "early",    sc_early },
        { "retired",  sc_retired },
    };
    int failed = 0;
    for (unsigned i = 0u; i < sizeof scenarios / sizeof scenarios[0]; ++i) {
        const char *err = scenarios[i].run();
        if (err) {
            fprintf(stderr, "idle_timeout: %s: %s\n", scenarios[i].name, err);
            ++failed;
        } else if (g_lag_ms > 0.0) {
            printf("idle_timeout: %s OK (closed %.1f ms after the last accepted frame)\n",
                   scenarios[i].name, g_lag_ms);
        } else {
            printf("idle_timeout: %s OK\n", scenarios[i].name);
        }
    }
    return failed ? 1 : 0;
}
