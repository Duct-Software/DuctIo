/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file udp_liveness_test.c
 * @brief Client-side dead-peer detection over a connected UDP socket.
 *
 * One engine hosts both ends: a listener_dgram server echoing until the test
 * mutes it, and an x_udp_peer client whose session is held by a socketpair leg
 * at conn 1, so conn 0 can go and come back. The client runs the detector the
 * WinTun example runs — a repeating tick, a probe whenever nothing answered,
 * and duct_response_close_conn(0, close_timeout) at miss_cap unanswered ticks.
 *
 * Asserts: probes round-trip over UDP; a peer that keeps answering is never
 * torn down; a muted peer produces on_conn_lost carrying close_timeout; the
 * leg_kind_connect_dgram redial rejoins at conn 0 and carries traffic again.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>

duct_wire_t *duct_wire_create_dgram_batch(size_t max_dgram, bool framed);

static constexpr unsigned wait_ms      = 5000u;
static constexpr uint64_t timer_probe  = 1u;
static constexpr uint64_t timer_redial = 2u;
static constexpr uint32_t tick_ms      = 40u;
static constexpr unsigned miss_cap     = 3u;

static const char probe_msg[] = "liveness-probe";

static atomic_int  g_srv_mute     = 0;
static atomic_int  g_cli_replies  = 0;
static atomic_int  g_lost_count   = 0;
static atomic_int  g_lost_reason  = -1;
static atomic_int  g_join0_count  = 0;
static _Atomic(duct_sock_t) g_hold_peer_fd = duct_sock_bad;

static char g_addr[64];

typedef struct {
    bool     established;
    bool     answered;
    unsigned misses;
} cli_link_t;

static cli_link_t g_link;

/** @brief Stage one probe on conn 0.
 *  A timer's response routes to the session's first live leg, which is the
 *  socketpair at conn 1 whenever conn 0 is down, so the leg is pinned here.
 */
static void s_probe(duct_response_t *out)
{
    duct_response_same(out, (duct_view_u8){ .data = (void *)probe_msg,
                                          .size = sizeof probe_msg - 1u },
                       fl_send_static, 0);
    out->conn_id = duct_conn_id_primary;
}

/** @brief Echo every frame until @c g_srv_mute, which is how the peer falls
 *  silent without closing anything — the failure a connected UDP socket has no
 *  signal for. */
static duct_result_t
srv_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             const duct_frame_t *frame, duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    if (duct_atomic_load(&g_srv_mute, acquire) != 0)
        return rc_ok;
    duct_response_echo(out, frame);
    return rc_ok;
}

static duct_result_t
cli_on_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    duct_sock_t sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
        if (duct_conn_attach_fd(s, 1u, sv[0]) == rc_ok)
            duct_atomic_store(&g_hold_peer_fd, sv[1], release);
        else
            close(sv[1]);
    }
    g_link = (cli_link_t){ .established = true };
    s_probe(out);
    out->control.timer.delay_ms = tick_ms;
    out->control.timer.interval_ms = tick_ms;
    out->control.timer.arg = timer_probe;
    return rc_ok;
}

static duct_result_t
cli_on_frame([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
             [[maybe_unused]] const duct_frame_t *frame,
             [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    if (conn_id != duct_conn_id_primary)
        return rc_ok;
    g_link.answered = true;
    duct_atomic_fetch(add, &g_cli_replies, 1, release);
    return rc_ok;
}

/** @brief The detector: one tick carrying the probe, the miss count and the
 *  close.
 *
 *  A tick that saw nothing on conn 0 counts a miss; at @c miss_cap the leg
 *  closes with @c close_timeout, which reaches on_conn_lost exactly as a FIN
 *  does on TCP.
 */
static duct_result_t
cli_on_timer([[maybe_unused]] duct_session_t *s, duct_response_t *out,
             [[maybe_unused]] void *proto_state, uint64_t arg)
{
    switch (arg) {
    case timer_redial:
        out->control.open_leg.kind = leg_kind_connect_dgram;
        out->control.open_leg.conn_id = duct_conn_id_primary;
        out->control.open_leg.connect_addr = g_addr;
        return rc_ok;
    case timer_probe:
        if (!g_link.established)
            return rc_ok;
        if (g_link.answered) {
            g_link.answered = false;
            g_link.misses = 0u;
        } else if (++g_link.misses >= miss_cap) {
            g_link.established = false;
            duct_response_close_conn(out, duct_conn_id_primary, close_timeout);
            return rc_ok;
        }
        s_probe(out);
        return rc_ok;
    default:
        return rc_ok;
    }
}

/** @brief Arm the redial; the socketpair at conn 1 carries the session across
 *  the gap, and the reopened leg takes its I/O thread from it. */
static void
cli_on_conn_lost([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
                 duct_close_reason_t reason, duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    if (conn_id != duct_conn_id_primary)
        return;
    g_link.established = false;
    duct_atomic_store(&g_lost_reason, (int)reason, release);
    duct_atomic_fetch(add, &g_lost_count, 1, release);
    out->control.timer.delay_ms = tick_ms;
    out->control.timer.arg = timer_redial;
}

static duct_result_t
cli_on_conn_join([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
                 [[maybe_unused]] const duct_peer_t *peer, duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    if (conn_id != duct_conn_id_primary)
        return rc_ok;
    g_link = (cli_link_t){ .established = true };
    s_probe(out);
    duct_atomic_fetch(add, &g_join0_count, 1, release);
    return rc_ok;
}

/** @brief Spin until *@p p >= @p target or @p timeout_ms expires.
 *  Every counter here keeps climbing, so th_wait_int's equality can be stepped
 *  over by a slow poll. */
static bool s_wait_at_least(atomic_int *p, int target, unsigned timeout_ms)
{
    for (unsigned waited = 0u; waited < timeout_ms; waited += 10u) {
        if (duct_atomic_load(p, acquire) >= target)
            return true;
        struct timespec ts = { .tv_nsec = 10L * 1000L * 1000L };
        nanosleep(&ts, nullptr);
    }
    return false;
}

static duct_result_t
s_connect_retry(duct_engine_t *io, duct_proto_t *proto, unsigned timeout_ms)
{
    duct_result_t rc = rc_invalid_order;
    for (unsigned waited = 0u; waited < timeout_ms; waited += 5u) {
        rc = duct_io_connect(io, g_addr, proto, nullptr, x_udp_peer);
        if (rc != rc_invalid_order)
            return rc;
        struct timespec ts = { .tv_nsec = 5L * 1000L * 1000L };
        nanosleep(&ts, nullptr);
    }
    return rc;
}

static const char *test_udp_liveness(void)
{
    if (!s_wait_at_least(&g_cli_replies, (int)(2u * miss_cap), wait_ms))
        return "probe/echo never round-tripped over UDP";
    if (duct_atomic_load(&g_lost_count, acquire) != 0)
        return "an answering peer was torn down anyway";

    duct_atomic_store(&g_srv_mute, 1, release);
    if (!s_wait_at_least(&g_lost_count, 1, wait_ms))
        return "a silent peer never produced on_conn_lost";
    if (duct_atomic_load(&g_lost_reason, acquire) != (int)close_timeout)
        return "on_conn_lost carried a reason other than close_timeout";

    int before = duct_atomic_load(&g_cli_replies, acquire);
    duct_atomic_store(&g_srv_mute, 0, release);
    if (!s_wait_at_least(&g_join0_count, 1, wait_ms))
        return "the redialled UDP leg never joined at conn 0";
    if (!s_wait_at_least(&g_cli_replies, before + 1, wait_ms))
        return "the redialled leg carried no traffic";
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) { fprintf(stderr, "udp_liveness: io create failed\n"); return 1; }

    auto srv_wire = duct_wire_create_dgram_batch(0u, false);
    auto cli_wire = duct_wire_create_dgram_batch(0u, false);
    auto srv = duct_proto_create(&(duct_proto_cfg_t){
        .name = "udp-liveness-srv", .wire = srv_wire,
        .on_frame = srv_on_frame,
    });
    auto cli = duct_proto_create(&(duct_proto_cfg_t){
        .name = "udp-liveness-cli", .wire = cli_wire,
        .on_frame = cli_on_frame, .on_session_open = cli_on_open,
        .on_conn_join = cli_on_conn_join, .on_conn_lost = cli_on_conn_lost,
        .on_timer = cli_on_timer,
    });
    if (srv) srv->owned_wire = srv_wire; else duct_wire_destroy(srv_wire);
    if (cli) cli->owned_wire = cli_wire; else duct_wire_destroy(cli_wire);
    if (!srv || !cli) {
        fprintf(stderr, "udp_liveness: proto create failed\n");
        duct_proto_destroy(srv); duct_proto_destroy(cli); duct_engine_destroy(io);
        return 1;
    }

    uint16_t port = 0u;
    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
            .addr = "127.0.0.1", .n_protos = 1,
            .protos = (const duct_proto_t *[]){ srv },
        }, &port, nullptr, 0u, nullptr) != rc_ok) {
        fprintf(stderr, "udp_liveness: listen failed\n");
        duct_proto_destroy(srv); duct_proto_destroy(cli); duct_engine_destroy(io);
        return 1;
    }
    snprintf(g_addr, sizeof g_addr, "127.0.0.1:%u", (unsigned)port);

    pthread_t th;
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        fprintf(stderr, "udp_liveness: thread create failed\n");
        duct_proto_destroy(srv); duct_proto_destroy(cli); duct_engine_destroy(io);
        return 1;
    }

    const char *err = s_connect_retry(io, cli, 3000u) == rc_ok
                    ? test_udp_liveness()
                    : "x_udp_peer dial failed";

    duct_engine_stop(io);
    pthread_join(th, nullptr);

    duct_sock_t held = duct_atomic_load(&g_hold_peer_fd, acquire);
    if (held != duct_sock_bad) close(held);

    duct_engine_destroy(io);
    duct_proto_destroy(srv);
    duct_proto_destroy(cli);

    if (err) {
        fprintf(stderr, "udp_liveness: %s\n", err);
        return 1;
    }
    printf("udp_liveness: OK (probe round-trip, silent peer -> on_conn_lost "
           "close_timeout on conn 0, dgram redial rejoins and carries traffic)\n");
    return 0;
}
