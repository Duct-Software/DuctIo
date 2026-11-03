/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file conn_lost_test.c
 * @brief on_conn_lost acceptance: a leg's departure reaches the protocol with
 * its conn_id and reason, and the control that callback declares is applied
 * after the detach.
 *
 * One engine hosts both ends of the three two-leg scenarios, which
 * s_hub_scenario runs from a single skeleton: the target proto is the dial's
 * peer, and the hub session under test dials it at conn 1 from on_session_open,
 * so a loss on conn 1 is produced on demand. sc_last_leg stands apart on one
 * proto, where conn 0 is the only leg there is.
 *
 * What the four differ by is the declaration: a redial into the slot the loss
 * freed, a session close, or nothing at all.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>

static constexpr unsigned wait_ms = 3000u;

static char g_target_addr[64];

static atomic_int  g_join_count   = 0;
static atomic_int  g_lost_count   = 0;
static atomic_uint g_lost_conn_id = 0u;
static atomic_int  g_lost_reason  = -1;
static atomic_int  g_roundtrip    = 0;
static atomic_int  g_target_hits   = 0;
static atomic_int  g_close_count   = 0;
static atomic_int  g_close_saw_lost = -1;
static atomic_int  g_redials       = 0;

static void s_reset(void)
{
    duct_atomic_store(&g_join_count, 0, relaxed);
    duct_atomic_store(&g_lost_count, 0, relaxed);
    duct_atomic_store(&g_lost_conn_id, 0u, relaxed);
    duct_atomic_store(&g_lost_reason, -1, relaxed);
    duct_atomic_store(&g_roundtrip, 0, relaxed);
    duct_atomic_store(&g_target_hits, 0, relaxed);
    duct_atomic_store(&g_close_count, 0, relaxed);
    duct_atomic_store(&g_close_saw_lost, -1, relaxed);
    duct_atomic_store(&g_redials, 0, relaxed);
}

/** @brief Kills its own session on the first frame it ever receives, echoes
 *  after — one on-demand peer close, then an ordinary echo peer for the
 *  redialled leg to round-trip against. */
static duct_result_t
target_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                const duct_frame_t *frame, duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    if (duct_atomic_fetch(add, &g_target_hits, 1, acq_rel) == 0)
        duct_response_close_session(out, close_normal);
    else
        duct_response_echo(out, frame);
    return rc_ok;
}

static duct_result_t
hub_on_session_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                    [[maybe_unused]] void *user_ctx, duct_response_t *out,
                    [[maybe_unused]] void *proto_state)
{
    out->control.open_leg.kind = leg_kind_connect;
    out->control.open_leg.conn_id = 1u;
    out->control.open_leg.connect_addr = g_target_addr;
    return rc_ok;
}

static duct_result_t
hub_on_conn_join([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                 [[maybe_unused]] const duct_peer_t *peer, [[maybe_unused]] duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_join_count, 1, release);
    return rc_ok;
}

static void s_record_lost(duct_conn_id_t conn_id, duct_close_reason_t reason)
{
    duct_atomic_store(&g_lost_conn_id, (unsigned)conn_id, relaxed);
    duct_atomic_store(&g_lost_reason, (int)reason, relaxed);
    duct_atomic_fetch(add, &g_lost_count, 1, release);
}

/** @brief Redials the lost leg into its own conn_id, once — the guard keeps
 *  the engine's own shutdown close from dialing into a stopping engine. */
static void
hub_on_conn_lost_redial([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
                        duct_close_reason_t reason, duct_response_t *out,
                        [[maybe_unused]] void *proto_state)
{
    s_record_lost(conn_id, reason);
    if (conn_id == 1u && duct_atomic_fetch(add, &g_redials, 1, acq_rel) == 0) {
        out->control.open_leg.kind = leg_kind_connect;
        out->control.open_leg.conn_id = conn_id;
        out->control.open_leg.connect_addr = g_target_addr;
    }
}

static void
record_on_conn_lost([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
                       duct_close_reason_t reason, [[maybe_unused]] duct_response_t *out,
                       [[maybe_unused]] void *proto_state)
{
    s_record_lost(conn_id, reason);
}

/** @brief Closes the dialed leg from the join that announced it, giving
 *  sc_local_close an author-initiated loss carrying the author's own reason. */
static duct_result_t
hub_on_conn_join_close([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
                       [[maybe_unused]] const duct_peer_t *peer, duct_response_t *out,
                       [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_join_count, 1, release);
    if (conn_id == 1u)
        duct_response_close_conn(out, conn_id, close_normal);
    return rc_ok;
}

static duct_result_t
hub_on_frame([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
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

/** @brief A peer close on the dialed leg reports conn 1 and close_peer, and
 *  the open_leg the callback declares rejoins that slot and carries a frame. */
static duct_result_t
echo_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
              const duct_frame_t *frame, duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

/** @brief The author's own close of a sibling leg reports that leg's conn_id
 *  and the reason the author gave it, and leaves conn 0 serving. */
static void
solo_on_session_close([[maybe_unused]] duct_session_t *s,
                      [[maybe_unused]] duct_close_reason_t reason,
                      [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_close_saw_lost, duct_atomic_load(&g_lost_count, acquire), relaxed);
    duct_atomic_fetch(add, &g_close_count, 1, release);
}

static void s_hang_up(duct_sock_t fd)
{
    close(fd);
}

/** @brief A single-leg session whose client ends the leg with @p end reports the loss with @p expect,
 *  then closes: both callbacks fire, on_conn_lost first. */
static bool s_solo_leg(void (*end)(duct_sock_t), duct_close_reason_t expect)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "conn-lost-solo", .wire = wire, .on_frame = echo_on_frame,
        .on_conn_lost = record_on_conn_lost, .on_session_close = solo_on_session_close,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    if (!proto) { duct_engine_destroy(io); return false; }

    uint16_t port = 0u;
    bool ok = duct_io_listen(io, "127.0.0.1", &port, proto) == rc_ok;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        duct_sock_t fd = th_connect(port);
        ok = fd != duct_sock_bad;
        static const char msg[] = "alive";
        ok = ok && th_send(fd, msg, sizeof msg - 1u) == 0
                && th_recv_eq(fd, msg, sizeof msg - 1u) == 0;

        if (fd != duct_sock_bad) end(fd);
        ok = ok && th_wait_int(&g_lost_count, 1, wait_ms);
        ok = ok && duct_atomic_load(&g_lost_conn_id, acquire) == 0u
                && duct_atomic_load(&g_lost_reason, relaxed) == (int)expect;
        ok = ok && th_wait_int(&g_close_count, 1, wait_ms)
                && duct_atomic_load(&g_close_saw_lost, relaxed) == 1;

        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return ok;
}

/** @brief A peer that closes the leg reports close_peer. */
static bool sc_last_leg(void)
{
    return s_solo_leg(s_hang_up, close_peer);
}

/** @brief A peer that resets the leg reports close_io_error, as the read's own failure does. */
static bool sc_peer_reset(void)
{
    return s_solo_leg(th_reset, close_io_error);
}

/** @brief Loss recorder that also declares a session close.
 *  The shape a protocol takes when every leg is essential, so one leaving ends
 *  the session instead of leaving it running short. */
static void
hub_on_conn_lost_close([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
                       duct_close_reason_t reason, duct_response_t *out,
                       [[maybe_unused]] void *proto_state)
{
    s_record_lost(conn_id, reason);
    duct_response_close_session(out, close_normal);
}

/** @brief Scenario body, run against a connected driver socket; true on pass. */
typedef bool (*hub_body_fn)(duct_sock_t driver_fd);

/** @brief One run of the two-leg shape: target listener, hub listener, a driver
 *  socket into the hub, @p body, teardown.
 *
 *  Both cfgs arrive by value and take their wire here, so a caller passes a
 *  compound literal and every wire's lifetime belongs to this function.
 */
static bool s_hub_scenario(duct_proto_cfg_t target_cfg, duct_proto_cfg_t hub_cfg,
                           hub_body_fn body)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto target_wire = duct_wire_create_length_prefix(0u);
    auto hub_wire = duct_wire_create_length_prefix(0u);
    target_cfg.wire = target_wire;
    hub_cfg.wire = hub_wire;
    auto target_proto = duct_proto_create(&target_cfg);
    auto hub_proto = duct_proto_create(&hub_cfg);
    if (target_proto) target_proto->owned_wire = target_wire; else duct_wire_destroy(target_wire);
    if (hub_proto) hub_proto->owned_wire = hub_wire; else duct_wire_destroy(hub_wire);
    if (!target_proto || !hub_proto) {
        duct_proto_destroy(target_proto); duct_proto_destroy(hub_proto); duct_engine_destroy(io);
        return false;
    }

    uint16_t target_port = 0u,
             hub_port = 0u;
    bool ok = duct_io_listen(io, "127.0.0.1", &target_port, target_proto) == rc_ok
           && duct_io_listen(io, "127.0.0.1", &hub_port, hub_proto) == rc_ok;
    snprintf(g_target_addr, sizeof g_target_addr, "127.0.0.1:%u", (unsigned)target_port);

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        duct_sock_t driver_fd = th_connect(hub_port);
        ok = driver_fd != duct_sock_bad && body(driver_fd);
        if (driver_fd != duct_sock_bad) close(driver_fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(target_proto);
    duct_proto_destroy(hub_proto);
    return ok;
}

static bool s_body_redial(duct_sock_t driver_fd)
{
    if (!th_wait_int(&g_join_count, 1, wait_ms))
        return false;
    static const char kill_msg[] = "die";
    if (th_send(driver_fd, kill_msg, sizeof kill_msg - 1u) != 0)
        return false;
    if (!th_wait_int(&g_lost_count, 1, wait_ms))
        return false;
    if (duct_atomic_load(&g_lost_conn_id, acquire) != 1u
        || duct_atomic_load(&g_lost_reason, relaxed) != (int)close_peer)
        return false;
    /* Join 2 is the redial's: on_conn_join fires for dialed legs only, so
     * conn 0 never contributes a count. */
    if (!th_wait_int(&g_join_count, 2, wait_ms))
        return false;
    static const char msg[] = "after-redial";
    if (th_send(driver_fd, msg, sizeof msg - 1u) != 0
        || th_recv_eq(driver_fd, msg, sizeof msg - 1u) != 0)
        return false;
    return duct_atomic_load(&g_roundtrip, acquire) == 1
        && duct_atomic_load(&g_lost_count, acquire) == 1;
}

static bool s_body_local_close(duct_sock_t driver_fd)
{
    if (!th_wait_int(&g_join_count, 1, wait_ms)
        || !th_wait_int(&g_lost_count, 1, wait_ms))
        return false;
    if (duct_atomic_load(&g_lost_conn_id, acquire) != 1u
        || duct_atomic_load(&g_lost_reason, relaxed) != (int)close_normal)
        return false;
    static const char msg[] = "sibling-still-alive";
    if (th_send(driver_fd, msg, sizeof msg - 1u) != 0
        || th_recv_eq(driver_fd, msg, sizeof msg - 1u) != 0)
        return false;
    return duct_atomic_load(&g_lost_count, acquire) == 1;
}

static bool s_body_close_from_lost(duct_sock_t driver_fd)
{
    if (!th_wait_int(&g_join_count, 1, wait_ms))
        return false;
    static const char kill_msg[] = "die";
    if (th_send(driver_fd, kill_msg, sizeof kill_msg - 1u) != 0)
        return false;
    if (!th_wait_int(&g_close_count, 1, wait_ms))
        return false;
    return duct_atomic_load(&g_lost_count, acquire) >= 2;
}

/** @brief A peer close on the dialed leg reports conn 1 and close_peer, and the
 *  open_leg the callback declares rejoins that slot and carries a frame. */
static bool sc_redial(void)
{
    return s_hub_scenario(
        (duct_proto_cfg_t){ .name = "conn-lost-target", .on_frame = target_on_frame },
        (duct_proto_cfg_t){ .name = "conn-lost-hub",
            .on_frame = hub_on_frame, .on_session_open = hub_on_session_open,
            .on_conn_join = hub_on_conn_join, .on_conn_lost = hub_on_conn_lost_redial },
        s_body_redial);
}

/** @brief The author's own close of a sibling leg reports that leg's conn_id
 *  and the reason the author gave it, and leaves conn 0 serving. */
static bool sc_local_close(void)
{
    return s_hub_scenario(
        (duct_proto_cfg_t){ .name = "conn-lost-local-target", .on_frame = echo_on_frame },
        (duct_proto_cfg_t){ .name = "conn-lost-local-hub",
            .on_frame = echo_on_frame, .on_session_open = hub_on_session_open,
            .on_conn_join = hub_on_conn_join_close, .on_conn_lost = record_on_conn_lost },
        s_body_local_close);
}

/** @brief A session close declared from on_conn_lost for a leg that is not the
 *  last tears down the leg still serving and fires on_session_close. */
static bool sc_close_from_lost(void)
{
    return s_hub_scenario(
        (duct_proto_cfg_t){ .name = "conn-lost-close-target", .on_frame = target_on_frame },
        (duct_proto_cfg_t){ .name = "conn-lost-close-hub",
            .on_frame = hub_on_frame, .on_session_open = hub_on_session_open,
            .on_conn_join = hub_on_conn_join, .on_conn_lost = hub_on_conn_lost_close,
            .on_session_close = solo_on_session_close },
        s_body_close_from_lost);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    int pass = 1;

    if (!sc_redial())      { fprintf(stderr, "conn_lost: redial failed\n"); pass = 0; }
    if (!sc_local_close()) { fprintf(stderr, "conn_lost: local_close failed\n"); pass = 0; }
    if (!sc_last_leg())    { fprintf(stderr, "conn_lost: last_leg failed\n"); pass = 0; }
    if (!sc_peer_reset())  { fprintf(stderr, "conn_lost: peer_reset failed\n"); pass = 0; }
    if (!sc_close_from_lost())
        { fprintf(stderr, "conn_lost: close_from_lost failed\n"); pass = 0; }

    if (pass) {
        printf("conn_lost: OK (leg loss reported with conn_id + reason, redial from the "
               "callback rejoins and carries traffic, local close reports its own reason, "
               "last leg reports both, a reset peer reports close_io_error, close_session "
               "from on_conn_lost tears down the surviving leg)\n");
        return 0;
    }
    return 1;
}
