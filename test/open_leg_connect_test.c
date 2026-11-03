/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file open_leg_connect_test.c
 * @brief PD5b acceptance: control.open_leg = leg_kind_connect dials a peer
 * and attaches the resulting leg onto conn_id of the already-live session,
 * instead of duct_io_connect's "always a new session".
 *
 * One engine hosts both ends: proto_leg is the plain echo server the dial
 * targets, proto_hub is the session under test — on_session_open declares
 * open_leg = { leg_kind_connect, conn_id=1, addr(proto_leg) }. Scenario 1
 * proves the dialed leg joins (on_conn_join conn_id=1) and is a fully wired
 * conn: a frame on the driver's primary leg (conn 0) is forwarded onto the
 * dialed leg (conn 1), echoed by proto_leg, and forwarded back to conn 0.
 * Scenario 2 points the dial at a closed port and proves the refusal reaches
 * on_error(s, rc_conn_refused, ...) with s the live hub session (not the
 * pre-session nullptr form) while the primary leg stays open. Scenario 3 dials
 * with an open_leg.tx_prefix over a plain wire, which no codec takes: the leg
 * is refused at its join, never reaching on_conn_join, the target sees its conn
 * close, and the primary leg stays open.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>

static constexpr unsigned wait_ms = 3000u;

static char g_leg_addr[64];

static atomic_int  g_join_count     = 0;
static atomic_uint g_join_conn_id   = 0u;
static atomic_int  g_roundtrip      = 0;
static atomic_int  g_err_count      = 0;
static atomic_int  g_err_code       = 0;
static atomic_int  g_err_session_ok = 0; /* on_error's s != nullptr and matches g_hub_session */
static atomic_int  g_leg_closed     = 0;
static _Atomic(duct_session_t *) g_hub_session;

static void s_reset(void)
{
    duct_atomic_store(&g_join_count, 0, relaxed);
    duct_atomic_store(&g_join_conn_id, 0u, relaxed);
    duct_atomic_store(&g_roundtrip, 0, relaxed);
    duct_atomic_store(&g_err_count, 0, relaxed);
    duct_atomic_store(&g_err_code, 0, relaxed);
    duct_atomic_store(&g_err_session_ok, 0, relaxed);
    duct_atomic_store(&g_leg_closed, 0, relaxed);
    duct_atomic_store(&g_hub_session, nullptr, relaxed);
}

/* ── proto_leg: plain echo target for the dial ───────────────────── */

static duct_result_t
leg_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             const duct_frame_t *frame, duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

static void
leg_on_close([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_close_reason_t reason,
             [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_leg_closed, 1, release);
}

/* ── proto_hub: the session under test ───────────────────────────── */

static duct_result_t
hub_on_session_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                    [[maybe_unused]] void *user_ctx, duct_response_t *out,
                    [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_hub_session, s, release);
    out->control.open_leg.kind = leg_kind_connect;
    out->control.open_leg.conn_id = 1u;
    out->control.open_leg.connect_addr = g_leg_addr;
    return rc_ok;
}

/** @brief Declare hub_on_session_open's dial, led by a prefix no plain wire takes. */
static duct_result_t
hub_on_session_open_prefixed(duct_session_t *s, duct_handle_t tok, void *user_ctx,
                             duct_response_t *out, void *proto_state)
{
    static const char lead[] = "lead";
    auto rc = hub_on_session_open(s, tok, user_ctx, out, proto_state);
    out->control.open_leg.tx_prefix = duct_view(duct_view_u8, (void *)lead, sizeof lead - 1u);
    return rc;
}

static duct_result_t
hub_on_conn_join([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
                 [[maybe_unused]] const duct_peer_t *peer, [[maybe_unused]] duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_join_conn_id, (unsigned)conn_id, release);
    duct_atomic_fetch(add, &g_join_count, 1, release);
    return rc_ok;
}

/** @brief conn 0 (driver) forwards onto conn 1 (the dialed leg); conn 1
 *  (proto_leg's echo) forwards back to conn 0 — proves the leg is wired for
 *  both TX and RX, not just joined. Used by sc_success only — sc_refused
 *  never gets a live conn 1 to forward onto. */
static duct_result_t
hub_on_frame_roundtrip([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
                       const duct_frame_t *frame, duct_response_t *out,
                       [[maybe_unused]] void *proto_state)
{
    *out = (duct_response_t){
        .payload = frame->payload, .flags = fl_send_copy, .frame_flags = frame->flags,
        .conn_id = conn_id == 0u ? 1u : 0u, .stream_id = duct_stream_id_default,
    };
    if (conn_id == 1u)
        duct_atomic_fetch(add, &g_roundtrip, 1, release);
    return rc_ok;
}

/** @brief Plain same-conn echo — sc_refused's liveness probe on conn 0 after
 *  the leg dial fails, with no live conn 1 to forward onto. */
static duct_result_t
hub_on_frame_echo([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                  const duct_frame_t *frame, duct_response_t *out,
                  [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

static duct_result_t
hub_on_error(duct_session_t *s, duct_result_t error, [[maybe_unused]] duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_err_code, (int)error, relaxed);
    if (s && s == duct_atomic_load(&g_hub_session, acquire))
        duct_atomic_store(&g_err_session_ok, 1, relaxed);
    duct_atomic_fetch(add, &g_err_count, 1, release);
    return rc_ok;
}

/* ── Scenario 1: dialed leg joins and round-trips ────────────────── */

static bool sc_success(void)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto leg_wire = duct_wire_create_length_prefix(0u);
    auto hub_wire = duct_wire_create_length_prefix(0u);
    auto leg_proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "open-leg-connect-target", .wire = leg_wire, .on_frame = leg_on_frame,
    });
    auto hub_proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "open-leg-connect-hub", .wire = hub_wire,
        .on_frame = hub_on_frame_roundtrip, .on_session_open = hub_on_session_open,
        .on_conn_join = hub_on_conn_join, .on_error = hub_on_error,
    });
    if (leg_proto) leg_proto->owned_wire = leg_wire; else duct_wire_destroy(leg_wire);
    if (hub_proto) hub_proto->owned_wire = hub_wire; else duct_wire_destroy(hub_wire);
    if (!leg_proto || !hub_proto) {
        duct_proto_destroy(leg_proto); duct_proto_destroy(hub_proto); duct_engine_destroy(io);
        return false;
    }

    uint16_t leg_port = 0u,
             hub_port = 0u;
    bool ok = duct_io_listen(io, "127.0.0.1", &leg_port, leg_proto) == rc_ok
           && duct_io_listen(io, "127.0.0.1", &hub_port, hub_proto) == rc_ok;
    snprintf(g_leg_addr, sizeof g_leg_addr, "127.0.0.1:%u", (unsigned)leg_port);

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        duct_sock_t driver_fd = th_connect(hub_port);
        ok = driver_fd != duct_sock_bad;
        ok = ok && th_wait_int(&g_join_count, 1, wait_ms);
        ok = ok && duct_atomic_load(&g_join_conn_id, acquire) == 1u;

        static const char msg[] = "leg-kind-connect-roundtrip";
        ok = ok && th_send(driver_fd, msg, sizeof msg - 1u) == 0;
        ok = ok && th_recv_eq(driver_fd, msg, sizeof msg - 1u) == 0;
        ok = ok && duct_atomic_load(&g_roundtrip, acquire) == 1
                && duct_atomic_load(&g_err_count, acquire) == 0;

        if (driver_fd != duct_sock_bad) close(driver_fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(leg_proto);
    duct_proto_destroy(hub_proto);
    return ok;
}

/* ── Scenario 2: dial refused reaches the live session's on_error ───── */

static uint16_t s_get_closed_port(void)
{
    duct_sock_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == duct_sock_bad) return 0u;
    struct sockaddr_in addr = { .sin_family = AF_INET };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    socklen_t alen = sizeof addr;
    uint16_t port = 0u;
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) == 0
        && getsockname(fd, (struct sockaddr *)&addr, &alen) == 0)
        port = ntohs(addr.sin_port);
    duct_sock_close(fd);
    return port;
}

static bool sc_refused(void)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto hub_wire = duct_wire_create_length_prefix(0u);
    auto hub_proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "open-leg-connect-refused", .wire = hub_wire,
        .on_frame = hub_on_frame_echo, .on_session_open = hub_on_session_open,
        .on_conn_join = hub_on_conn_join, .on_error = hub_on_error,
    });
    if (hub_proto) hub_proto->owned_wire = hub_wire; else duct_wire_destroy(hub_wire);
    if (!hub_proto) { duct_engine_destroy(io); return false; }

    uint16_t closed_port = s_get_closed_port(),
             hub_port = 0u;
    bool ok = closed_port != 0u && duct_io_listen(io, "127.0.0.1", &hub_port, hub_proto) == rc_ok;
    snprintf(g_leg_addr, sizeof g_leg_addr, "127.0.0.1:%u", (unsigned)closed_port);

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        duct_sock_t driver_fd = th_connect(hub_port);
        ok = driver_fd != duct_sock_bad;
        ok = ok && th_wait_int(&g_err_count, 1, wait_ms);
        ok = ok && duct_atomic_load(&g_err_code, relaxed) == (int)rc_conn_refused;
        ok = ok && duct_atomic_load(&g_err_session_ok, relaxed) == 1;
        ok = ok && duct_atomic_load(&g_join_count, acquire) == 0;

        /* The primary leg must stay live through the failed leg-attach. */
        static const char msg[] = "still-alive";
        ok = ok && th_send(driver_fd, msg, sizeof msg - 1u) == 0
                && th_recv_eq(driver_fd, msg, sizeof msg - 1u) == 0;

        if (driver_fd != duct_sock_bad) close(driver_fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(hub_proto);
    return ok;
}

static bool sc_prefix_unfit(void)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto leg_wire = duct_wire_create_length_prefix(0u);
    auto hub_wire = duct_wire_create_length_prefix(0u);
    auto leg_proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "open-leg-prefix-target", .wire = leg_wire, .on_frame = leg_on_frame,
        .on_session_close = leg_on_close,
    });
    auto hub_proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "open-leg-prefix-hub", .wire = hub_wire,
        .on_frame = hub_on_frame_echo, .on_session_open = hub_on_session_open_prefixed,
        .on_conn_join = hub_on_conn_join, .on_error = hub_on_error,
    });
    if (leg_proto) leg_proto->owned_wire = leg_wire; else duct_wire_destroy(leg_wire);
    if (hub_proto) hub_proto->owned_wire = hub_wire; else duct_wire_destroy(hub_wire);
    if (!leg_proto || !hub_proto) {
        duct_proto_destroy(leg_proto); duct_proto_destroy(hub_proto); duct_engine_destroy(io);
        return false;
    }

    uint16_t leg_port = 0u,
             hub_port = 0u;
    bool ok = duct_io_listen(io, "127.0.0.1", &leg_port, leg_proto) == rc_ok
           && duct_io_listen(io, "127.0.0.1", &hub_port, hub_proto) == rc_ok;
    snprintf(g_leg_addr, sizeof g_leg_addr, "127.0.0.1:%u", (unsigned)leg_port);

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        duct_sock_t driver_fd = th_connect(hub_port);
        ok = driver_fd != duct_sock_bad;
        ok = ok && th_wait_int(&g_leg_closed, 1, wait_ms);
        ok = ok && duct_atomic_load(&g_join_count, acquire) == 0;

        static const char msg[] = "still-alive";
        ok = ok && th_send(driver_fd, msg, sizeof msg - 1u) == 0
                && th_recv_eq(driver_fd, msg, sizeof msg - 1u) == 0;

        if (driver_fd != duct_sock_bad) close(driver_fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(leg_proto);
    duct_proto_destroy(hub_proto);
    return ok;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    int pass = 1;

    if (!sc_success()) { fprintf(stderr, "open_leg_connect: success failed\n"); pass = 0; }
    if (!sc_refused())  { fprintf(stderr, "open_leg_connect: refused failed\n"); pass = 0; }
    if (!sc_prefix_unfit()) { fprintf(stderr, "open_leg_connect: prefix unfit failed\n"); pass = 0; }

    if (pass) {
        printf("open_leg_connect: OK (leg_kind_connect joins + round-trips, "
               "refused dial reaches the live session's on_error)\n");
        return 0;
    }
    return 1;
}
