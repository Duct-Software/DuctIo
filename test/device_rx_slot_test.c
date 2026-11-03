/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file device_rx_slot_test.c
 *  @brief Device-leg RX without a copy: the device reads into the engine's own
 *  slot and the batch carries offsets into it.
 *
 *  The device fills whatever buffers @c ops.read is handed and falls back to
 *  its own memory when it is handed none, so a run that never reaches the slot
 *  path still delivers and reports which shape it took instead of hanging.
 *
 *  Packet lengths vary across the run and each body is derived from its own
 *  sequence number: at equal lengths a wrong offset still lands on a plausible
 *  packet boundary. Every byte of every packet is checked against what the
 *  device wrote, so a descriptor off by any amount surfaces as a body
 *  mismatch instead of a size that happens to agree.
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

static constexpr unsigned wait_ms    = 15000u;
static constexpr unsigned pkt_total  = 200u;
static constexpr unsigned read_batch = 32u;
static constexpr unsigned pkt_min    = 64u;
static constexpr unsigned pkt_spread = 1500u;

static atomic_int g_attach_rc  = -1;
static atomic_int g_frames     = 0;
static atomic_int g_bad_size   = 0;
static atomic_int g_bad_body   = 0;
static atomic_int g_offered    = 0;
static atomic_int g_handed     = 0;
static atomic_int g_drained    = 0;

static unsigned g_left = pkt_total;
static unsigned g_seq  = 0u;
static uint8_t g_own[read_batch][pkt_min + pkt_spread];

static atomic_int g_gap_at = -1;
static unsigned   g_expect = 0u;

static unsigned s_len_of(unsigned seq) { return pkt_min + seq % pkt_spread; }

static void s_fill(unsigned char *p, unsigned seq, unsigned len)
{
    memcpy(p, &seq, sizeof seq);
    for (unsigned i = (unsigned)sizeof seq; i < len; ++i)
        p[i] = (unsigned char)(seq + i);
}

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
    unsigned produced = 0u;
    while (produced < max && produced < read_batch && g_left > 0u) {
        unsigned len = s_len_of(g_seq);
        if (out[produced].data && out[produced].size >= len) {
            s_fill((unsigned char *)out[produced].data, g_seq, len);
            out[produced].size = len;
            duct_discard duct_atomic_fetch(add, &g_offered, 1, relaxed);
        } else {
            s_fill(g_own[produced], g_seq, len);
            out[produced] = duct_view(duct_view_u8, g_own[produced], len);
            duct_discard duct_atomic_fetch(add, &g_handed, 1, relaxed);
        }
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
        .rx_span = pkt_min + pkt_spread,
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
    unsigned seq = 0u;
    if (frame->payload.size >= sizeof seq)
        memcpy(&seq, frame->payload.data, sizeof seq);
    unsigned len = s_len_of(seq);
    if (frame->payload.size != len)
        duct_discard duct_atomic_fetch(add, &g_bad_size, 1, release);
    else {
        auto p = (const unsigned char *)frame->payload.data;
        for (unsigned i = (unsigned)sizeof seq; i < len; ++i)
            if (p[i] != (unsigned char)(seq + i)) {
                duct_discard duct_atomic_fetch(add, &g_bad_body, 1, release);
                break;
            }
    }
    if (seq != g_expect && duct_atomic_load(&g_gap_at, acquire) < 0)
        duct_atomic_store(&g_gap_at, (int)g_expect, release);
    g_expect = seq + 1u;
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
        fprintf(stderr, "device_rx_slot: io create failed\n");
        return 1;
    }
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "device_rx_slot", .wire = wire, .on_frame = on_frame,
        .on_session_open = on_session_open,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!proto) {
        fprintf(stderr, "device_rx_slot: proto create failed\n");
        duct_engine_destroy(io);
        return 1;
    }
    uint16_t port = 0u;
    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok) {
        fprintf(stderr, "device_rx_slot: listen failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }
    pthread_t thread;
    if (pthread_create(&thread, nullptr, th_run, io) != 0) {
        fprintf(stderr, "device_rx_slot: thread create failed\n");
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
        error = "device never drained";
    if (!error && !th_wait_int(&g_frames, (int)pkt_total, wait_ms))
        error = "packets lost between the device and the protocol";
    if (!error && duct_atomic_load(&g_offered, acquire) != (int)pkt_total)
        error = "engine did not offer its own buffers for every packet";
    if (!error && duct_atomic_load(&g_bad_size, acquire) != 0)
        error = "frame size did not match the packet the device wrote";
    if (!error && duct_atomic_load(&g_bad_body, acquire) != 0)
        error = "frame body did not match: slot offsets are wrong";
    if (!error && duct_atomic_load(&g_gap_at, acquire) >= 0)
        error = "frames arrived out of order";

    if (primary != duct_sock_bad)
        close(primary);
    duct_engine_stop(io);
    pthread_join(thread, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    if (g_device_event)
        s_signal_close(g_device_event);

    if (error) {
        fprintf(stderr, "device_rx_slot: %s (frames=%d of %u, in-slot=%d, "
                        "handed-back=%d, bad size=%d, bad body=%d, gap at %d)\n",
                error, duct_atomic_load(&g_frames, acquire), pkt_total,
                duct_atomic_load(&g_offered, acquire),
                duct_atomic_load(&g_handed, acquire),
                duct_atomic_load(&g_bad_size, acquire),
                duct_atomic_load(&g_bad_body, acquire),
                duct_atomic_load(&g_gap_at, acquire));
        return 1;
    }
    printf("device_rx_slot: OK (%u packets, all read into engine slots, "
           "sizes and bodies intact)\n", pkt_total);
    return 0;
}
