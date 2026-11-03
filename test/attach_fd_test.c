/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file attach_fd_test.c
 * @brief ST-AF acceptance: duct_conn_attach_fd end to end.
 *
 * on_session_open creates an AF_UNIX socketpair and attaches one end at
 * conn_id=1 via duct_conn_attach_fd; the other end stays with the test as a
 * stand-in for an externally-owned fd (TUN/TAP, pipe, anything pollable).
 * Asserts: on_conn_join fires for the attached leg, the attached leg's
 * traffic round-trips through the xport_raw read()/write() path (not
 * recv()/send()) exactly like the primary TCP leg's on_frame/echo, the two
 * legs are independent (one closing does not affect the other), and a
 * second attach at an already-occupied conn_id is rejected.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>

static constexpr unsigned wait_ms = 3000u;

static atomic_int  g_open_count = 0;
static atomic_int  g_join_count = 0;
static atomic_uint g_join_conn_id = 0u;
static atomic_int  g_attach_rc = -1;
static atomic_int  g_reattach_rc = -1;
static _Atomic(duct_sock_t) g_attached_fd = duct_sock_bad;
static _Atomic(duct_handle_t) g_tok;

static duct_result_t
on_session_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok,
                [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_tok, tok, release);
    duct_atomic_fetch(add, &g_open_count, 1, relaxed);
    duct_sock_t sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        duct_atomic_store(&g_attach_rc, (int)rc_no_memory, release);
        return rc_ok;
    }
    auto rc = duct_conn_attach_fd(s, 1u, sv[0]);
    duct_atomic_store(&g_attach_rc, (int)rc, release);
    if (rc != rc_ok) {
        close(sv[0]);
        close(sv[1]);
        return rc_ok;
    }
    duct_atomic_store(&g_attached_fd, sv[1], release);
    return rc_ok;
}

static duct_result_t
on_conn_join(duct_session_t *s, duct_conn_id_t conn_id,
             [[maybe_unused]] const duct_peer_t *peer, [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    /* s->conns[1] is already claimed (this callback fires after the join
     * commits it) — a second attach at the same conn_id must be rejected.
     * g_reattach_rc must land before g_join_count so main()'s wait on the
     * latter never observes the former's unset (-1) init value. */
    duct_sock_t sv2[2];
    if (conn_id == 1u && socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) == 0) {
        duct_atomic_store(&g_reattach_rc, (int)duct_conn_attach_fd(s, 1u, sv2[0]), release);
        close(sv2[1]);
    }
    duct_atomic_store(&g_join_conn_id, (unsigned)conn_id, release);
    duct_atomic_fetch(add, &g_join_count, 1, release);
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

static const char *test_attach_fd(uint16_t port)
{
    duct_sock_t primary_fd = th_connect(port);
    if (primary_fd == duct_sock_bad)
        return "primary connect failed";

    static const char p0[] = "primary-hello";
    if (th_send(primary_fd, p0, sizeof p0 - 1u) != 0 || th_recv_eq(primary_fd, p0, sizeof p0 - 1u) != 0) {
        close(primary_fd);
        return "primary leg echo failed";
    }

    if (!th_wait_int(&g_join_count, 1, wait_ms)) {
        close(primary_fd);
        return "on_conn_join did not fire for the attached leg";
    }
    if (duct_atomic_load(&g_join_conn_id, acquire) != 1u) {
        close(primary_fd);
        return "on_conn_join conn_id != 1";
    }
    if (duct_atomic_load(&g_attach_rc, acquire) != (int)rc_ok) {
        close(primary_fd);
        return "duct_conn_attach_fd did not return rc_ok";
    }
    if (duct_atomic_load(&g_reattach_rc, acquire) != (int)rc_invalid_order) {
        close(primary_fd);
        return "second attach at an occupied conn_id did not return rc_invalid_order";
    }

    duct_sock_t peer_fd = duct_atomic_load(&g_attached_fd, acquire);
    if (peer_fd == duct_sock_bad) {
        close(primary_fd);
        return "attached leg's peer fd never published";
    }

    /* Round-trip through xport_raw's read()/write(), same LP framing as the
     * primary TCP leg — proves the attached leg is a fully-functional conn,
     * not just a registered fd. */
    static const char a0[] = "attach-fd-one", a1[] = "attach-fd-two";
    if (th_send(peer_fd, a0, sizeof a0 - 1u) != 0 || th_recv_eq(peer_fd, a0, sizeof a0 - 1u) != 0) {
        close(primary_fd);
        return "attached leg echo #1 failed";
    }
    if (th_send(peer_fd, a1, sizeof a1 - 1u) != 0 || th_recv_eq(peer_fd, a1, sizeof a1 - 1u) != 0) {
        close(primary_fd);
        return "attached leg echo #2 failed";
    }

    /* Legs are independent: closing the attached leg's peer end must not
     * disturb the primary leg. */
    close(peer_fd);
    static const char p1[] = "still-alive";
    if (th_send(primary_fd, p1, sizeof p1 - 1u) != 0 || th_recv_eq(primary_fd, p1, sizeof p1 - 1u) != 0) {
        close(primary_fd);
        return "primary leg broke after the attached leg closed";
    }

    close(primary_fd);
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) { fprintf(stderr, "attach_fd: io create failed\n"); return 1; }

    auto wire = duct_wire_create_length_prefix(0u);
    if (!wire) { fprintf(stderr, "attach_fd: wire create failed\n"); duct_engine_destroy(io); return 1; }
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "attach_fd", .wire = wire,
        .on_frame = on_frame,
        .on_session_open = on_session_open,
        .on_conn_join = on_conn_join,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    if (!proto) { fprintf(stderr, "attach_fd: proto create failed\n"); duct_engine_destroy(io); return 1; }

    uint16_t port = 0u;
    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok) {
        fprintf(stderr, "attach_fd: listen failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto);
        return 1;
    }
    pthread_t th;
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        fprintf(stderr, "attach_fd: thread create failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto);
        return 1;
    }

    const char *err = test_attach_fd(port);

    duct_engine_stop(io);
    pthread_join(th, nullptr);

    if (!err && duct_atomic_load(&g_open_count, acquire) != 1)
        err = "on_session_open fired more than once";

    duct_engine_destroy(io);
    duct_proto_destroy(proto);

    if (err) {
        fprintf(stderr, "attach_fd: %s\n", err);
        return 1;
    }
    printf("attach_fd: OK (attach join, xport_raw echo round-trips, leg independence, "
           "occupied-slot rejection)\n");
    return 0;
}
