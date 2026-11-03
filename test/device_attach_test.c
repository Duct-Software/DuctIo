/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file device_attach_test.c
 *  @brief Device-leg attach ownership and lifecycle, on every model that can
 *  watch a device.
 *
 *  Proves the attach contract: the leg opens and joins at the requested
 *  conn_id, an attach onto an occupied slot is refused, a second attach of a
 *  handle the I/O thread already watches is refused there and never joins, and
 *  ctx release fires exactly once per transferred table — once for each refused
 *  duplicate, once at teardown. Last, the borrowed device still signals after
 *  duct_engine_destroy, so no backend closed it.
 *
 *  The device is whatever the platform makes waitable, see device_signal.h:
 *  an auto-reset event on Windows, an eventfd on Linux, a pipe on Darwin, where
 *  kqueue and poll watch it as they watch a utun. Signalling it mid-run is the only coverage
 *  the four registration paths have, and the read side must consume the
 *  signal — a level-triggered descriptor that nothing drains spins the io
 *  thread. It still asserts nothing about delivery: this fake device answers
 *  every read with no packets, so what the signals catch is a crash, a hang
 *  or a leak.
 */

#include "duct.h"
#include "test_helpers.h"
#include "device_signal.h"

#include <stdatomic.h>

static constexpr unsigned wait_ms = 3000u;

static atomic_int  g_attach_rc = -1;
static atomic_int  g_reject_rc = -1;
static atomic_int  g_same_handle_rc = -1;
static atomic_int  g_join_count = 0;
static atomic_int  g_same_handle_joins = 0;
static atomic_int  g_release_count = 0;

static th_signal_t g_device_event = 0;

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

static void device_release([[maybe_unused]] void *ctx)
{
    duct_atomic_fetch(add, &g_release_count, 1, release);
}

static duct_device_ops_t device_ops(th_signal_t handle)
{
    return (duct_device_ops_t){
        .wait_handle = (void *)(intptr_t)handle,
        .read = device_read,
        .write_reserve = device_write_reserve,
        .write_commit = device_write_commit,
        .release = device_release,
        .ctx = (void *)(intptr_t)handle,
    };
}

static duct_result_t
on_session_open([[maybe_unused]] duct_session_t *s,
                [[maybe_unused]] duct_handle_t tok,
                [[maybe_unused]] void *user_ctx,
                [[maybe_unused]] duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    g_device_event = th_signal_open();
    if (!g_device_event) {
        duct_atomic_store(&g_attach_rc, (int)rc_no_memory, release);
        return rc_ok;
    }
    auto ops = device_ops(g_device_event);
    auto rc = duct_conn_attach_device(s, 1u, &ops);
    duct_atomic_store(&g_attach_rc, (int)rc, release);
    if (rc != rc_ok) {
        th_signal_close(g_device_event);
        g_device_event = 0;
    }
    return rc_ok;
}

static duct_result_t
on_conn_join([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
             [[maybe_unused]] const duct_peer_t *peer,
             [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    switch (conn_id) {
    case 1u:
        auto duplicate = th_signal_open();
        if (duplicate) {
            auto ops = device_ops(duplicate);
            auto rc = duct_conn_attach_device(s, 1u, &ops);
            duct_atomic_store(&g_reject_rc, (int)rc, release);
            th_signal_close(duplicate);
        }
        /* The handle conn 1 already holds, onto a free slot: posted, then
         * refused by the I/O thread's events model, so conn 2 never joins. */
        auto same = device_ops(g_device_event);
        auto same_rc = duct_conn_attach_device(s, 2u, &same);
        duct_atomic_store(&g_same_handle_rc, (int)same_rc, release);
        duct_atomic_fetch(add, &g_join_count, 1, release);
        break;
    case 2u:
        duct_atomic_fetch(add, &g_same_handle_joins, 1, release);
        break;
    }
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

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){
        .io_threads = 1, .workers = 1,
    });
    if (!io) {
        fprintf(stderr, "device_attach: io create failed\n");
        return 1;
    }
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "device_attach", .wire = wire, .on_frame = on_frame,
        .on_session_open = on_session_open, .on_conn_join = on_conn_join,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!proto) {
        fprintf(stderr, "device_attach: proto create failed\n");
        duct_engine_destroy(io);
        return 1;
    }
    uint16_t port = 0u;
    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok) {
        fprintf(stderr, "device_attach: listen failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }
    pthread_t thread;
    if (pthread_create(&thread, nullptr, th_run, io) != 0) {
        fprintf(stderr, "device_attach: thread create failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }
    auto primary = th_connect(port);
    const char *error = nullptr;
    if (primary == duct_sock_bad)
        error = "primary connect failed";
    else if (!th_wait_int(&g_join_count, 1, wait_ms))
        error = "device on_conn_join did not fire";
    else if (duct_atomic_load(&g_attach_rc, acquire) != (int)rc_ok)
        error = "duct_conn_attach_device did not return rc_ok";
    else if (duct_atomic_load(&g_same_handle_rc, acquire) != (int)rc_ok)
        error = "the same-handle attach was not posted";
    else if (!th_wait_int(&g_release_count, 2, wait_ms))
        error = "a second attach of a watched handle was not refused";
    if (!error && g_device_event) {
        /* An auto-reset event needs its wait re-armed before the next signal
         * lands, hence the gap; the fourth is left unspaced so it races
         * teardown, putting a completion in flight against unwatch. */
        for (unsigned i = 0u; i < 3u; ++i) {
            duct_discard th_signal_raise(g_device_event);
            th_sleep_ms(20u);
        }
        duct_discard th_signal_raise(g_device_event);
    }
    if (primary != duct_sock_bad)
        close(primary);

    duct_engine_stop(io);
    pthread_join(thread, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);

    if (!error && duct_atomic_load(&g_reject_rc, acquire) != (int)rc_invalid_order)
        error = "occupied device attach was not rejected";
    if (!error && duct_atomic_load(&g_same_handle_joins, acquire) != 0)
        error = "a second leg joined on a handle already watched";
    if (!error && duct_atomic_load(&g_release_count, acquire) != 3)
        error = "device release lifecycle count is wrong";
    if (!error && (!g_device_event || !th_signal_alive(g_device_event)))
        error = "backend closed the borrowed device handle";
    if (g_device_event)
        th_signal_close(g_device_event);
    if (error) {
        fprintf(stderr, "device_attach: %s\n", error);
        return 1;
    }
    printf("device_attach: OK (attach, join, borrowed handle, release lifecycle)\n");
    return 0;
}
