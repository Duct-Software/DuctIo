/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file device_eof_test.c
 *  @brief A device whose read reports the end of the device (@c rc_closed) leaves
 *  its leg lost and the events backend intact, on every model that can watch a
 *  device.
 *
 *  The read runs inside the io thread's own dispatch of the device's readiness, so
 *  the close it asks for unwatches the device while that dispatch is still
 *  running. What the backend does after the dispatch returns is the contract:
 *  on iocp it re-arms the watch, which must not touch a device the unwatch has
 *  freed. The test pins the loss (@c on_conn_lost once), a second device attached
 *  from the timer and reached by its own signals, a release per transferred table,
 *  and the borrowed handle still alive. A freed device surfaces under a sanitizer
 *  or as a crash; nothing else here observes it.
 */

#include "duct.h"
#include "test_helpers.h"
#include "device_signal.h"

#include <stdatomic.h>

static constexpr unsigned wait_ms      = 5000u;
static constexpr uint64_t reattach_arg = 9u;
static constexpr uint64_t reattach_ms  = 20u;

static atomic_int g_eof           = 0;
static atomic_int g_join_count    = 0;
static atomic_int g_lost_count    = 0;
static atomic_int g_release_count = 0;
static atomic_int g_attach_rc     = -1;
static atomic_int g_reattach_rc   = -1;
static atomic_int g_second_reads  = 0;

static th_signal_t g_first  = 0;
static th_signal_t g_second = 0;

static duct_result_t device_read(void *ctx,
                                 [[maybe_unused]] duct_view_u8 *out,
                                 [[maybe_unused]] unsigned max,
                                 unsigned *n)
{
    auto handle = (th_signal_t)(intptr_t)ctx;
    th_signal_drain(handle);
    *n = 0u;
    if (handle == g_first && duct_atomic_load(&g_eof, acquire))
        return rc_closed;
    if (handle == g_second)
        duct_atomic_fetch(add, &g_second_reads, 1, release);
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

static duct_result_t s_attach(duct_session_t *s, th_signal_t handle)
{
    duct_device_ops_t ops = {
        .wait_handle = (void *)(intptr_t)handle,
        .read = device_read,
        .write_reserve = device_write_reserve,
        .write_commit = device_write_commit,
        .release = device_release,
        .ctx = (void *)(intptr_t)handle,
    };
    return duct_conn_attach_device(s, 1u, &ops);
}

static duct_result_t
on_session_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                [[maybe_unused]] void *user_ctx,
                [[maybe_unused]] duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    g_first = th_signal_open();
    if (!g_first) {
        duct_atomic_store(&g_attach_rc, (int)rc_no_memory, release);
        return rc_ok;
    }
    duct_atomic_store(&g_attach_rc, (int)s_attach(s, g_first), release);
    return rc_ok;
}

static duct_result_t
on_conn_join([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
             [[maybe_unused]] const duct_peer_t *peer,
             [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    if (conn_id == 1u)
        duct_atomic_fetch(add, &g_join_count, 1, release);
    return rc_ok;
}

static void
on_conn_lost([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
             [[maybe_unused]] duct_close_reason_t reason,
             duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    if (conn_id != 1u)
        return;
    out->control.timer.delay_ms = reattach_ms;
    out->control.timer.arg = reattach_arg;
    duct_atomic_fetch(add, &g_lost_count, 1, release);
}

static duct_result_t
on_timer(duct_session_t *s, [[maybe_unused]] duct_response_t *out,
         [[maybe_unused]] void *proto_state, uint64_t arg)
{
    if (arg != reattach_arg)
        return rc_ok;
    g_second = th_signal_open();
    duct_atomic_store(&g_reattach_rc, g_second ? (int)s_attach(s, g_second) : (int)rc_no_memory, release);
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
         [[maybe_unused]] const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) {
        fprintf(stderr, "device_eof: io create failed\n");
        return 1;
    }
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "device_eof", .wire = wire, .on_frame = on_frame,
        .on_session_open = on_session_open, .on_conn_join = on_conn_join,
        .on_conn_lost = on_conn_lost, .on_timer = on_timer,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!proto) {
        fprintf(stderr, "device_eof: proto create failed\n");
        duct_engine_destroy(io);
        return 1;
    }
    uint16_t port = 0u;
    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok) {
        fprintf(stderr, "device_eof: listen failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }
    pthread_t thread;
    if (pthread_create(&thread, nullptr, th_run, io) != 0) {
        fprintf(stderr, "device_eof: thread create failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }

    const char *error = nullptr;
    auto driver = th_connect(port);
    if (driver == duct_sock_bad)
        error = "driver connect failed";
    if (!error && !th_wait_int(&g_attach_rc, (int)rc_ok, wait_ms))
        error = "the first device leg did not attach";
    if (!error && !th_wait_int(&g_join_count, 1, wait_ms))
        error = "the first device leg never joined";
    if (!error) {
        duct_atomic_store(&g_eof, 1, release);
        duct_discard th_signal_raise(g_first);
    }
    if (!error && !th_wait_int(&g_lost_count, 1, wait_ms))
        error = "a device read that reports its end did not lose the leg";
    if (!error && !th_wait_int(&g_reattach_rc, (int)rc_ok, wait_ms))
        error = "a device leg could not be attached after the loss";
    if (!error && !th_wait_int(&g_join_count, 2, wait_ms))
        error = "the device leg attached after the loss never joined";
    if (!error && g_second) {
        /* An auto-reset event needs its wait re-armed before the next signal
         * lands, hence the gaps. */
        for (unsigned i = 0u; i < 4u; ++i) {
            duct_discard th_signal_raise(g_second);
            th_sleep_ms(30u);
        }
        if (duct_atomic_load(&g_second_reads, acquire) < 1)
            error = "the device attached after the loss was never read";
    }

    if (driver != duct_sock_bad)
        close(driver);
    duct_engine_stop(io);
    pthread_join(thread, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);

    if (!error && duct_atomic_load(&g_lost_count, acquire) != 1)
        error = "the leg was reported lost more than once";
    if (!error && duct_atomic_load(&g_release_count, acquire) != 2)
        error = "device ctx release did not fire once per transferred table";
    if (!error && (!g_first || !th_signal_alive(g_first)))
        error = "backend closed the borrowed device handle";
    if (g_first)
        th_signal_close(g_first);
    if (g_second)
        th_signal_close(g_second);
    if (error) {
        fprintf(stderr, "device_eof: %s (attach=%d reattach=%d joins=%d lost=%d releases=%d reads=%d)\n",
                error, duct_atomic_load(&g_attach_rc, acquire),
                duct_atomic_load(&g_reattach_rc, acquire),
                duct_atomic_load(&g_join_count, acquire),
                duct_atomic_load(&g_lost_count, acquire),
                duct_atomic_load(&g_release_count, acquire),
                duct_atomic_load(&g_second_reads, acquire));
        return 1;
    }
    printf("device_eof: OK (end of device, loss, attach after the loss, release lifecycle)\n");
    return 0;
}
