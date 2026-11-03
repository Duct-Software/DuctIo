/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file device_rx_resume_test.c
 *  @brief Device-leg RX backpressure: the lane fills, the io thread stops,
 *  and the worker's drain is what starts it reading again.
 *
 *  The device is signalled once and stays readable for the rest of the run,
 *  which is the harder case: one edge is all any model delivers, since the
 *  Windows handles auto-reset by contract, epoll watches a device
 *  edge-triggered, and poll has its read interest cleared while the conn sits
 *  latched. Everything past the first lane-full therefore reaches the
 *  protocol only through the resume post. Drop that post and this test stops
 *  at 96 of 320 packets and hangs to its timeout.
 *
 *  Payload runs to several times the lane, so the run crosses the stall
 *  boundary repeatedly rather than resting on one race landing well. Each
 *  packet carries its sequence number, making a loss report where the gap
 *  starts and how long it is instead of only that the count came up short:
 *  the delivered count must be every packet the device handed over, since a
 *  read is only issued once the whole batch has somewhere to land.
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

static constexpr unsigned wait_ms   = 15000u;
static constexpr unsigned pkt_bytes = 1400u;
static constexpr unsigned pkt_total  = 320u;
static constexpr unsigned read_batch = 32u;

static atomic_int g_attach_rc = -1;
static atomic_int g_frames    = 0;
static atomic_int g_bad_size  = 0;
static atomic_int g_reads     = 0;
static atomic_int g_drained   = 0;

static unsigned g_left = pkt_total;
static unsigned g_seq  = 0u;
static uint8_t g_pkt[read_batch][pkt_bytes];

static atomic_int g_gap_at   = -1;
static atomic_int g_gap_size = 0;
static unsigned   g_expect   = 0u;

#ifdef _WIN32
typedef HANDLE device_signal_t;
static device_signal_t s_signal_open(void)
{
    return CreateEventW(nullptr, FALSE, FALSE, nullptr);
}
static bool s_signal_raise(device_signal_t d) { return SetEvent(d) != 0; }
static void s_signal_close(device_signal_t d) { CloseHandle(d); }
#else
typedef int device_signal_t;
static device_signal_t s_signal_open(void)
{
    int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    return fd < 0 ? 0 : fd;
}
static bool s_signal_raise(device_signal_t d)
{
    uint64_t one = 1u;
    return write(d, &one, sizeof one) == (ssize_t)sizeof one;
}
static void s_signal_close(device_signal_t d) { close(d); }
#endif

static device_signal_t g_device_event = 0;

static duct_result_t device_read([[maybe_unused]] void *ctx, duct_view_u8 *out,
                                 unsigned max, unsigned *n)
{
    duct_discard duct_atomic_fetch(add, &g_reads, 1, relaxed);
    unsigned produced = 0u;
    while (produced < max && produced < read_batch && g_left > 0u) {
        memcpy(g_pkt[produced], &g_seq, sizeof g_seq);
        out[produced] = duct_view(duct_view_u8, g_pkt[produced], pkt_bytes);
        ++produced;
        ++g_seq;
        --g_left;
    }
    *n = produced;
    if (!produced)
        duct_atomic_store(&g_drained, 1, release);
    return produced ? rc_ok : rc_again;
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
    g_device_event = s_signal_open();
    if (!g_device_event) {
        duct_atomic_store(&g_attach_rc, (int)rc_no_memory, release);
        return rc_ok;
    }
    duct_device_ops_t ops = {
        .wait_handle = (void *)(intptr_t)g_device_event,
        .read = device_read,
        .write_reserve = device_write_reserve,
        .write_commit = device_write_commit,
        .release = device_release,
        .ctx = (void *)(intptr_t)g_device_event,
    };
    auto rc = duct_conn_attach_device(s, 1u, &ops);
    duct_atomic_store(&g_attach_rc, (int)rc, release);
    if (rc != rc_ok) {
        s_signal_close(g_device_event);
        g_device_event = 0;
    }
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
         const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    if (conn_id != 1u)
        return rc_ok;
    if (frame->payload.size != pkt_bytes)
        duct_discard duct_atomic_fetch(add, &g_bad_size, 1, release);
    unsigned seq = 0u;
    memcpy(&seq, frame->payload.data, sizeof seq);
    if (seq != g_expect) {
        if (duct_atomic_load(&g_gap_at, acquire) < 0) {
            duct_atomic_store(&g_gap_at, (int)g_expect, release);
            duct_atomic_store(&g_gap_size, (int)(seq - g_expect), release);
        }
        g_expect = seq;
    }
    ++g_expect;
    duct_discard duct_atomic_fetch(add, &g_frames, 1, release);
    return rc_ok;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){
        .io_threads = 1, .workers = 1,
    });
    if (!io) {
        fprintf(stderr, "device_rx_resume: io create failed\n");
        return 1;
    }
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "device_rx_resume", .wire = wire, .on_frame = on_frame,
        .on_session_open = on_session_open,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!proto) {
        fprintf(stderr, "device_rx_resume: proto create failed\n");
        duct_engine_destroy(io);
        return 1;
    }
    uint16_t port = 0u;
    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok) {
        fprintf(stderr, "device_rx_resume: listen failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }
    pthread_t thread;
    if (pthread_create(&thread, nullptr, th_run, io) != 0) {
        fprintf(stderr, "device_rx_resume: thread create failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }
    auto primary = th_connect(port);
    const char *error = nullptr;
    if (primary == duct_sock_bad)
        error = "primary connect failed";
    else if (!th_wait_int(&g_attach_rc, (int)rc_ok, wait_ms))
        error = "duct_conn_attach_device did not return rc_ok";
    if (!error && !s_signal_raise(g_device_event))
        error = "device signal failed";
    if (!error && !th_wait_int(&g_drained, 1, wait_ms))
        error = "device RX stalled: reads stopped after a lane-full latch";
    if (!error && duct_atomic_load(&g_reads, acquire) < 4)
        error = "device drained without crossing a latch: backpressure never hit";
    if (!error && !th_wait_int(&g_frames, (int)pkt_total, wait_ms))
        error = "packets lost to backpressure: a drive started on a lane it could not fill";
    if (!error && duct_atomic_load(&g_bad_size, acquire) != 0)
        error = "device frame arrived with the wrong payload size";

    if (primary != duct_sock_bad)
        close(primary);
    duct_engine_stop(io);
    pthread_join(thread, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    if (g_device_event)
        s_signal_close(g_device_event);

    if (error) {
        fprintf(stderr, "device_rx_resume: %s (frames=%d of %u, reads=%d, "
                        "first gap at %d size %d)\n",
                error, duct_atomic_load(&g_frames, acquire), pkt_total,
                duct_atomic_load(&g_reads, acquire),
                duct_atomic_load(&g_gap_at, acquire),
                duct_atomic_load(&g_gap_size, acquire));
        return 1;
    }
    printf("device_rx_resume: OK (%u read, %d delivered, %d device reads)\n",
           pkt_total, duct_atomic_load(&g_frames, acquire),
           duct_atomic_load(&g_reads, acquire));
    return 0;
}
