/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file primary_reattach_test.c
 * @brief Reopening conn 0 while a second leg holds the session.
 *
 * on_session_open attaches a socketpair end at conn 1, then the test drops the
 * accepted TCP leg at conn 0. on_conn_lost arms a timer and the timer attaches
 * a fresh fd back at conn 0 — the sequence a client's redial machine runs,
 * where the second leg is what carries the session across the gap and what the
 * reopened leg takes its I/O thread from.
 * Asserts: on_conn_lost fires for conn 0, the attach from the timer returns
 * rc_ok, on_conn_join fires for conn 0 a second time, and the reattached leg
 * round-trips an echo.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>

static constexpr unsigned wait_ms = 3000u;
static constexpr uint64_t timer_reattach = 7u;

static _Atomic(duct_sock_t) g_hold_peer_fd = duct_sock_bad;
static atomic_int  g_lost0_count = 0;
static atomic_int  g_timer_count = 0;
static atomic_int  g_reattach_rc = -1;
static _Atomic(duct_sock_t) g_reattach_peer_fd = duct_sock_bad;
static atomic_int  g_join0_count = 0;
static atomic_int  g_join1_count = 0;

static duct_result_t
on_session_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_sock_t sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return rc_ok;
    if (duct_conn_attach_fd(s, 1u, sv[0]) == rc_ok)
        duct_atomic_store(&g_hold_peer_fd, sv[1], release);
    else
        close(sv[1]);
    return rc_ok;
}

static void
on_conn_lost([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
             [[maybe_unused]] duct_close_reason_t reason,
             duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    if (conn_id != duct_conn_id_primary)
        return;
    out->control.timer.delay_ms = 10u;
    out->control.timer.arg = timer_reattach;
    duct_atomic_fetch(add, &g_lost0_count, 1, release);
}

static duct_result_t
on_timer(duct_session_t *s, [[maybe_unused]] duct_response_t *out,
         [[maybe_unused]] void *proto_state, uint64_t arg)
{
    if (arg != timer_reattach)
        return rc_ok;
    duct_sock_t sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        duct_atomic_store(&g_reattach_rc, (int)rc_no_memory, release);
        duct_atomic_fetch(add, &g_timer_count, 1, release);
        return rc_ok;
    }
    auto rc = duct_conn_attach_fd(s, duct_conn_id_primary, sv[0]);
    if (rc == rc_ok)
        duct_atomic_store(&g_reattach_peer_fd, sv[1], release);
    else
        close(sv[1]);
    duct_atomic_store(&g_reattach_rc, (int)rc, release);
    duct_atomic_fetch(add, &g_timer_count, 1, release);
    return rc_ok;
}

static duct_result_t
on_conn_join([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
             [[maybe_unused]] const duct_peer_t *peer,
             [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    if (conn_id == duct_conn_id_primary)
        duct_atomic_fetch(add, &g_join0_count, 1, release);
    else
        duct_atomic_fetch(add, &g_join1_count, 1, release);
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame, duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

static const char *test_primary_reattach(uint16_t port)
{
    duct_sock_t primary_fd = th_connect(port);
    if (primary_fd == duct_sock_bad)
        return "primary connect failed";

    static const char p0[] = "primary-hello";
    if (th_send(primary_fd, p0, sizeof p0 - 1u) != 0
     || th_recv_eq(primary_fd, p0, sizeof p0 - 1u) != 0) {
        close(primary_fd);
        return "primary leg echo failed";
    }
    if (!th_wait_int(&g_join1_count, 1, wait_ms)) {
        close(primary_fd);
        return "holding leg never joined";
    }

    close(primary_fd);
    if (!th_wait_int(&g_lost0_count, 1, wait_ms))
        return "on_conn_lost never fired for the primary";
    if (!th_wait_int(&g_timer_count, 1, wait_ms))
        return "the timer armed from on_conn_lost never fired";
    if (duct_atomic_load(&g_reattach_rc, acquire) != (int)rc_ok)
        return "reattach at conn 0 was rejected";
    if (!th_wait_int(&g_join0_count, 1, wait_ms))
        return "the reattached primary never joined";

    duct_sock_t peer_fd = duct_atomic_load(&g_reattach_peer_fd, acquire);
    static const char p1[] = "reattached";
    if (th_send(peer_fd, p1, sizeof p1 - 1u) != 0
     || th_recv_eq(peer_fd, p1, sizeof p1 - 1u) != 0)
        return "reattached primary does not carry traffic";
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) { fprintf(stderr, "primary_reattach: io create failed\n"); return 1; }

    auto wire = duct_wire_create_length_prefix(0u);
    if (!wire) {
        fprintf(stderr, "primary_reattach: wire create failed\n");
        duct_engine_destroy(io);
        return 1;
    }
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "primary_reattach", .wire = wire,
        .on_frame = on_frame,
        .on_session_open = on_session_open,
        .on_conn_join = on_conn_join,
        .on_conn_lost = on_conn_lost,
        .on_timer = on_timer,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    if (!proto) {
        fprintf(stderr, "primary_reattach: proto create failed\n");
        duct_engine_destroy(io);
        return 1;
    }

    uint16_t port = 0u;
    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok) {
        fprintf(stderr, "primary_reattach: listen failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto);
        return 1;
    }
    pthread_t th;
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        fprintf(stderr, "primary_reattach: thread create failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto);
        return 1;
    }

    const char *err = test_primary_reattach(port);

    duct_engine_stop(io);
    pthread_join(th, nullptr);

    duct_sock_t held = duct_atomic_load(&g_hold_peer_fd, acquire);
    if (held != duct_sock_bad) close(held);
    duct_sock_t reattached = duct_atomic_load(&g_reattach_peer_fd, acquire);
    if (reattached != duct_sock_bad) close(reattached);

    duct_engine_destroy(io);
    duct_proto_destroy(proto);

    if (err) {
        fprintf(stderr, "primary_reattach: %s\n", err);
        return 1;
    }
    printf("primary_reattach: OK (conn 0 lost, session held by conn 1, "
           "timer reattach at conn 0 joins and carries traffic)\n");
    return 0;
}
