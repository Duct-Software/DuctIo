/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file device_readonly_test.c
 *  @brief A device with no write side, on every model that can watch a device.
 *
 *  A device that sets neither write callback attaches, joins and delivers what
 *  its read hands over, once per signal. A response a protocol routes down that
 *  leg is refused with rc_invalid_arg through on_error and costs the session
 *  nothing. A device that sets one write callback alone, or asks for a read span
 *  past one IP packet, is refused at the attach with rc_invalid_arg, and its
 *  release runs in the call. The release of the
 *  accepted device runs once, at teardown, and the borrowed handle outlives the
 *  engine. The device sets no rx_span, so none of its reads is offered a buffer.
 */

#include "duct.h"
#include "test_helpers.h"
#include "device_signal.h"

#include <stdatomic.h>

static constexpr unsigned wait_ms = 3000u;
static constexpr char     payload[] = "route";

static th_signal_t g_event;
static atomic_uint g_signals;
static unsigned    g_delivered;

static atomic_int  g_attach_rc = -1;
static atomic_int  g_half_rc = -1;
static atomic_int  g_wide_rc = -1;
static atomic_int  g_joined;
static atomic_int  g_frames;
static atomic_int  g_errors;
static atomic_int  g_error_rc = -1;
static atomic_int  g_releases;
static atomic_int  g_offered;
static char        g_got[sizeof payload];

static duct_result_t device_read(void *ctx, duct_view_u8 *out, unsigned max, unsigned *n)
{
    for (unsigned i = 0u; i < max; ++i)
        if (out[i].data)
            duct_atomic_fetch(add, &g_offered, 1, relaxed);
    th_signal_drain((th_signal_t)(intptr_t)ctx);
    unsigned signals = duct_atomic_load(&g_signals, acquire);
    *n = signals != g_delivered ? 1u : 0u;
    if (*n) {
        g_delivered = signals;
        out[0] = (duct_view_u8){ (void *)payload, sizeof payload };
    }
    return rc_ok;
}

static void *device_reserve([[maybe_unused]] void *ctx, [[maybe_unused]] size_t size)
{
    return nullptr;
}

static void device_release([[maybe_unused]] void *ctx)
{
    duct_atomic_fetch(add, &g_releases, 1, release);
}

static duct_result_t
on_session_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok, [[maybe_unused]] void *user_ctx,
                [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    g_event = th_signal_open();
    if (!g_event) {
        duct_atomic_store(&g_attach_rc, (int)rc_no_memory, release);
        return rc_ok;
    }
    duct_device_ops_t readonly = {
        .wait_handle = (void *)(intptr_t)g_event,
        .read = device_read,
        .release = device_release,
        .ctx = (void *)(intptr_t)g_event,
    };
    duct_atomic_store(&g_attach_rc, (int)duct_conn_attach_device(s, 1u, &readonly), release);
    auto spare = th_signal_open();
    if (spare) {
        duct_device_ops_t half = {
            .wait_handle = (void *)(intptr_t)spare,
            .read = device_read,
            .write_reserve = device_reserve,
            .release = device_release,
            .ctx = (void *)(intptr_t)spare,
        };
        duct_atomic_store(&g_half_rc, (int)duct_conn_attach_device(s, 2u, &half), release);
        duct_device_ops_t wide = {
            .wait_handle = (void *)(intptr_t)spare,
            .rx_span = duct_ipv4_len_max + 1u,
            .read = device_read,
            .release = device_release,
            .ctx = (void *)(intptr_t)spare,
        };
        duct_atomic_store(&g_wide_rc, (int)duct_conn_attach_device(s, 3u, &wide), release);
        th_signal_close(spare);
    }
    return rc_ok;
}

static duct_result_t
on_conn_join([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id, [[maybe_unused]] const duct_peer_t *peer,
             [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    if (conn_id == 1u)
        duct_atomic_store(&g_joined, 1, release);
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id, const duct_frame_t *frame,
         duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    if (conn_id == 1u) {
        if (frame->payload.size == sizeof payload)
            memcpy(g_got, frame->payload.data, sizeof g_got);
        duct_atomic_fetch(add, &g_frames, 1, release);
        return rc_ok;
    }
    duct_response_same(out, frame->payload, fl_send_copy, frame->flags);
    out->conn_id = 1u;
    return rc_ok;
}

static duct_result_t
on_error([[maybe_unused]] duct_session_t *s, duct_result_t error, [[maybe_unused]] duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_error_rc, (int)error, release);
    duct_atomic_fetch(add, &g_errors, 1, release);
    return rc_ok;
}

/** @brief Raise the device once and wait for the frame it brings.
 *  @return false when no frame came or it carried other bytes.
 */
static bool signal_and_wait(int frames_after)
{
    duct_atomic_fetch(add, &g_signals, 1u, release);
    duct_discard th_signal_raise(g_event);
    return th_wait_int(&g_frames, frames_after, wait_ms) && memcmp(g_got, payload, sizeof payload) == 0;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){
        .io_threads = 1, .workers = 1,
    });
    if (!io) {
        fprintf(stderr, "device_readonly: io create failed\n");
        return 1;
    }
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "device_readonly", .wire = wire, .on_frame = on_frame,
        .on_session_open = on_session_open, .on_conn_join = on_conn_join, .on_error = on_error,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!proto) {
        fprintf(stderr, "device_readonly: proto create failed\n");
        duct_engine_destroy(io);
        return 1;
    }
    uint16_t port = 0u;
    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok) {
        fprintf(stderr, "device_readonly: listen failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }
    pthread_t thread;
    if (pthread_create(&thread, nullptr, th_run, io) != 0) {
        fprintf(stderr, "device_readonly: thread create failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }
    auto primary = th_connect(port);
    const char *error = nullptr;
    if (primary == duct_sock_bad)
        error = "primary connect failed";
    else if (!th_wait_int(&g_joined, 1, wait_ms))
        error = "the read-only device did not join";
    else if (duct_atomic_load(&g_attach_rc, acquire) != (int)rc_ok)
        error = "a device with no write side was not attached";
    else if (duct_atomic_load(&g_half_rc, acquire) != (int)rc_invalid_arg)
        error = "a device with one write callback was not refused with rc_invalid_arg";
    else if (duct_atomic_load(&g_wide_rc, acquire) != (int)rc_invalid_arg)
        error = "a device asking for a span past one IP packet was not refused with rc_invalid_arg";
    else if (duct_atomic_load(&g_releases, acquire) != 2)
        error = "a refused device was not released in the call";
    else if (!signal_and_wait(1))
        error = "a signal did not deliver the device's packet";
    else if (!signal_and_wait(2))
        error = "a second signal did not deliver the device's packet";
    else if (th_send(primary, "x", 1u) != 0)
        error = "the primary leg could not send";
    else if (!th_wait_int(&g_errors, 1, wait_ms))
        error = "a response routed to the read-only leg was not refused";
    else if (duct_atomic_load(&g_error_rc, acquire) != (int)rc_invalid_arg)
        error = "the refusal did not carry rc_invalid_arg";
    else if (!signal_and_wait(3))
        error = "the leg stopped delivering after a refused send";
    if (primary != duct_sock_bad)
        close(primary);

    duct_engine_stop(io);
    pthread_join(thread, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);

    if (!error && duct_atomic_load(&g_releases, acquire) != 3)
        error = "the accepted device was not released once at teardown";
    if (!error && (!g_event || !th_signal_alive(g_event)))
        error = "the engine closed the borrowed device handle";
    if (!error && duct_atomic_load(&g_offered, acquire) != 0)
        error = "a device that sets no rx_span was offered engine buffers";
    if (g_event)
        th_signal_close(g_event);
    if (error) {
        fprintf(stderr, "device_readonly: %s\n", error);
        return 1;
    }
    printf("device_readonly: OK (attach, delivery, refused send, half-writer refused, release)\n");
    return 0;
}
