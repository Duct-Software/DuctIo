/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file device_reattach_test.c
 *  @brief A device leg re-opens at the same @c conn_id after it is lost, and
 *  when the slot becomes free to take it.
 *
 *  The session survives the loss because conn 0 is a socket leg, so
 *  @c proto_state and the timer outlive the device. That is the shape a tunnel
 *  client needs: the adapter goes away and the session does not.
 *
 *  Timing is the contract this pins. @c on_conn_lost runs ahead of
 *  @c duct_session_detach_leg, so conn 1 is still occupied there and an attach
 *  from inside it answers @c rc_invalid_order; the re-attach belongs on the
 *  timer that callback arms. Both halves are asserted, so an edit moving the
 *  detach earlier or later reports here.
 *
 *  @c release fires once per @c duct_device_ops_t handed over — the refused
 *  table's and the lost leg's — which is what separates a re-attach from a
 *  leaked device.
 *
 *  The device is an auto-reset event on Windows and an eventfd elsewhere, and
 *  answers every read with no packets: this file asserts lifecycle, not
 *  delivery.
 */

#include "duct.h"
#include "test_helpers.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/eventfd.h>
#include <unistd.h>
#endif
#include <stdatomic.h>

static constexpr unsigned wait_ms       = 5000u;
static constexpr uint64_t reattach_arg  = 7u;
static constexpr uint64_t reattach_ms   = 20u;

static atomic_int g_attach_rc     = -1;
static atomic_int g_in_lost_rc    = -1;
static atomic_int g_reattach_rc   = -1;
static atomic_int g_join_count    = 0;
static atomic_int g_lost_count    = 0;
static atomic_int g_release_count = 0;

#ifdef _WIN32
typedef HANDLE device_signal_t;
static device_signal_t s_signal_open(void)
{
    return CreateEventW(nullptr, FALSE, FALSE, nullptr);
}
static void s_signal_close(device_signal_t d) { CloseHandle(d); }
static void s_signal_drain([[maybe_unused]] device_signal_t d) {}
#else
typedef int device_signal_t;
static device_signal_t s_signal_open(void)
{
    int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    return fd < 0 ? 0 : fd;
}
static void s_signal_close(device_signal_t d) { close(d); }
static void s_signal_drain(device_signal_t d)
{
    uint64_t v = 0u;
    duct_discard read(d, &v, sizeof v);
}
#endif

static device_signal_t g_first  = 0;
static device_signal_t g_second = 0;

static duct_result_t device_read(void *ctx,
                                 [[maybe_unused]] duct_view_u8 *out,
                                 [[maybe_unused]] unsigned max,
                                 unsigned *n)
{
    s_signal_drain((device_signal_t)(intptr_t)ctx);
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

static duct_result_t s_attach(duct_session_t *s, device_signal_t d)
{
    duct_device_ops_t ops = {
        .wait_handle = (void *)(intptr_t)d,
        .read = device_read,
        .write_reserve = device_write_reserve,
        .write_commit = device_write_commit,
        .release = device_release,
        .ctx = (void *)(intptr_t)d,
    };
    return duct_conn_attach_device(s, 1u, &ops);
}

static duct_result_t
on_session_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                [[maybe_unused]] void *user_ctx,
                [[maybe_unused]] duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    g_first = s_signal_open();
    if (!g_first) {
        duct_atomic_store(&g_attach_rc, (int)rc_no_memory, release);
        return rc_ok;
    }
    auto rc = s_attach(s, g_first);
    duct_atomic_store(&g_attach_rc, (int)rc, release);
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
on_conn_lost(duct_session_t *s, duct_conn_id_t conn_id,
             [[maybe_unused]] duct_close_reason_t reason,
             duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    if (conn_id != 1u)
        return;
    g_second = s_signal_open();
    if (g_second)
        duct_atomic_store(&g_in_lost_rc, (int)s_attach(s, g_second), release);
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
    if (!g_second)
        g_second = s_signal_open();
    if (!g_second) {
        duct_atomic_store(&g_reattach_rc, (int)rc_no_memory, release);
        return rc_ok;
    }
    duct_atomic_store(&g_reattach_rc, (int)s_attach(s, g_second), release);
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
         [[maybe_unused]] const duct_frame_t *frame, duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    duct_response_close_conn(out, 1u, close_normal);
    return rc_ok;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) {
        fprintf(stderr, "device_reattach: io create failed\n");
        return 1;
    }
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "device_reattach", .wire = wire, .on_frame = on_frame,
        .on_session_open = on_session_open, .on_conn_join = on_conn_join,
        .on_conn_lost = on_conn_lost, .on_timer = on_timer,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!proto) {
        fprintf(stderr, "device_reattach: proto create failed\n");
        duct_engine_destroy(io);
        return 1;
    }
    uint16_t port = 0u;
    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok) {
        fprintf(stderr, "device_reattach: listen failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }
    pthread_t thread;
    if (pthread_create(&thread, nullptr, th_run, io) != 0) {
        fprintf(stderr, "device_reattach: thread create failed\n");
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
        static const char trigger[] = { 0u, 1u, 'x' };
        if (th_send(driver, trigger, sizeof trigger) != 0)
            error = "trigger send failed";
    }
    if (!error && !th_wait_int(&g_lost_count, 1, wait_ms))
        error = "on_conn_lost never fired for the device leg";
    if (!error && !th_wait_int(&g_reattach_rc, (int)rc_ok, wait_ms))
        error = "the device leg could not be re-attached from a timer";
    if (!error && !th_wait_int(&g_join_count, 2, wait_ms))
        error = "the re-attached device leg never joined";
    if (!error && duct_atomic_load(&g_in_lost_rc, acquire) != (int)rc_invalid_order)
        error = "an attach from inside on_conn_lost did not report an occupied slot";
    if (!error && !th_wait_int(&g_release_count, 2, wait_ms))
        error = "device ctx release did not fire once per transferred table";

    if (driver != duct_sock_bad)
        close(driver);
    duct_engine_stop(io);
    pthread_join(thread, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);

    if (error) {
        fprintf(stderr, "device_reattach: %s (attach=%d in_lost=%d reattach=%d "
                        "joins=%d lost=%d releases=%d)\n",
                error, duct_atomic_load(&g_attach_rc, acquire),
                duct_atomic_load(&g_in_lost_rc, acquire),
                duct_atomic_load(&g_reattach_rc, acquire),
                duct_atomic_load(&g_join_count, acquire),
                duct_atomic_load(&g_lost_count, acquire),
                duct_atomic_load(&g_release_count, acquire));
        return 1;
    }
    printf("device_reattach: OK (a lost device leg re-opens at the same conn_id "
           "from a timer; the same attach inside on_conn_lost is refused)\n");
    return 0;
}
