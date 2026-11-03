/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file session_closing_test.c
 * @brief The @c duct_session_closing predicate: false in a live session's
 *  @c on_conn_join, true in every @c on_conn_lost of a teardown the session's
 *  own response declared.
 *
 *  One engine hosts a session whose conn 0 is a driver socket and whose conn 1
 *  is a device leg. The first frame the proto takes closes the session with
 *  @c close_normal, so the close walk reports both legs: a teardown pass, not
 *  a transport loss, is what @c on_conn_lost of the device leg sees.
 */

#include "duct.h"
#include "test_helpers.h"
#include "device_signal.h"

#include <stdatomic.h>

static constexpr unsigned wait_ms = 3000u;

static atomic_int g_join_count   = 0;
static atomic_int g_join_closing = -1;
static atomic_int g_lost_count   = 0;
static atomic_int g_lost_conn_id = -1;
static atomic_int g_lost_closing = -1;
static atomic_int g_close_count  = 0;

static th_signal_t g_device = 0;

static duct_result_t device_read(void *ctx,
                                 [[maybe_unused]] duct_view_u8 *out,
                                 [[maybe_unused]] unsigned max,
                                 unsigned *n)
{
    th_signal_drain((th_signal_t)(intptr_t)ctx);
    *n = 0u;
    return rc_again;
}

static void *device_write_reserve([[maybe_unused]] void *ctx,
                                  [[maybe_unused]] size_t size)
{
    return nullptr;
}

static duct_result_t device_write_commit([[maybe_unused]] void *ctx,
                                         [[maybe_unused]] void *buf,
                                         [[maybe_unused]] size_t len)
{
    return rc_ok;
}

static void device_release([[maybe_unused]] void *ctx) {}

static duct_result_t
on_session_open([[maybe_unused]] duct_session_t *s,
                [[maybe_unused]] duct_handle_t tok,
                [[maybe_unused]] void *user_ctx,
                [[maybe_unused]] duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    g_device = th_signal_open();
    if (!g_device)
        return rc_no_memory;
    auto ops = (duct_device_ops_t){
        .wait_handle = (void *)(intptr_t)g_device,
        .read = device_read,
        .write_reserve = device_write_reserve,
        .write_commit = device_write_commit,
        .release = device_release,
        .ctx = (void *)(intptr_t)g_device,
    };
    return duct_conn_attach_device(s, 1u, &ops);
}

static duct_result_t
on_conn_join([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             [[maybe_unused]] const duct_peer_t *peer, [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_join_closing, duct_session_closing(s) ? 1 : 0, release);
    duct_atomic_fetch(add, &g_join_count, 1, release);
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
         [[maybe_unused]] const duct_frame_t *frame, duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    duct_response_close_session(out, close_normal);
    return rc_ok;
}

static void
on_conn_lost(duct_session_t *s, duct_conn_id_t conn_id,
             [[maybe_unused]] duct_close_reason_t reason, [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    if (conn_id == 1u)
        duct_atomic_store(&g_lost_closing, duct_session_closing(s) ? 1 : 0, release);
    duct_atomic_store(&g_lost_conn_id, (int)conn_id, relaxed);
    duct_atomic_fetch(add, &g_lost_count, 1, release);
}

static void
on_session_close([[maybe_unused]] duct_session_t *s,
                 [[maybe_unused]] duct_close_reason_t reason,
                 [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_close_count, 1, release);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) {
        fprintf(stderr, "session_closing: io create failed\n");
        return 1;
    }
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "session-closing", .wire = wire, .on_frame = on_frame,
        .on_session_open = on_session_open, .on_conn_join = on_conn_join,
        .on_conn_lost = on_conn_lost, .on_session_close = on_session_close,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!proto) {
        fprintf(stderr, "session_closing: proto create failed\n");
        duct_engine_destroy(io);
        return 1;
    }
    uint16_t port = 0u;
    const char *error = duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok
        ? "listen failed" : nullptr;
    pthread_t thread;
    if (!error && pthread_create(&thread, nullptr, th_run, io) != 0) {
        error = "thread create failed";
    } else if (!error) {
        auto fd = th_connect(port);
        static const char msg[] = "close-me";
        if (fd == duct_sock_bad)
            error = "connect failed";
        /* The device leg joins before the frame that closes the session, so
         * the teardown walk reports it rather than beating its attach. */
        else if (!th_wait_int(&g_join_count, 1, wait_ms))
            error = "the device leg never joined";
        else if (th_send(fd, msg, sizeof msg - 1u) != 0)
            error = "send failed";
        if (fd != duct_sock_bad)
            close(fd);
        if (!error && !th_wait_int(&g_close_count, 1, wait_ms))
            error = "the session never closed";
        if (!error && !th_wait_int(&g_lost_count, 2, wait_ms))
            error = "the teardown did not report both legs";
        duct_engine_stop(io);
        pthread_join(thread, nullptr);
    }

    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    if (g_device)
        th_signal_close(g_device);

    if (!error && duct_atomic_load(&g_join_closing, acquire) != 0)
        error = "a live session's on_conn_join saw the session closing";
    if (!error && duct_atomic_load(&g_lost_count, acquire) < 2)
        error = "the teardown did not report both legs";
    if (!error && duct_atomic_load(&g_lost_closing, acquire) != 1)
        error = "the device leg's on_conn_lost did not see the session closing";
    if (!error && duct_atomic_load(&g_lost_conn_id, acquire) != 1)
        error = "the device leg's loss was never reported";
    if (error) {
        fprintf(stderr, "session_closing: %s\n", error);
        return 1;
    }
    printf("session_closing: OK (on_conn_join sees attached, teardown's on_conn_lost sees closing)\n");
    return 0;
}
