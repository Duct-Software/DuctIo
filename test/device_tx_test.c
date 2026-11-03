/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file device_tx_test.c
 *  @brief Device-leg TX: the worker writes the response into the device's own
 *  send ring, with nothing queued behind it.
 *
 *  The device hands up packets carrying their own sequence number and the
 *  protocol echoes each one straight back, so the commit side checks size and
 *  order together — a drop that reordered the rest shows up here as a sequence
 *  going backwards.
 *
 *  Every fourth reservation is refused, which is what a full ring looks like
 *  from the engine's side. Such a packet is parked and retried, not dropped,
 *  so the run demands all of them and demands the refusals cost no order:
 *  the ticket sequence a leg without a TX OLB keeps in the conn is what stops
 *  the packets behind a parked one from overtaking it.
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
static constexpr unsigned pkt_bytes = 512u;
static constexpr unsigned pkt_total = 96u;
static constexpr unsigned ring_slots = 4u;

static atomic_int g_attach_rc  = -1;
static atomic_int g_committed  = 0;
static atomic_int g_bad_write  = 0;
static atomic_int g_out_order  = -1;
static atomic_int g_refused    = 0;
static atomic_int g_attempts   = 0;

static unsigned g_left = pkt_total;
static unsigned g_seq  = 0u;
static constexpr unsigned read_batch = 32u;
static uint8_t g_pkt[read_batch][pkt_bytes];

static char     g_ring[ring_slots][pkt_bytes];
static unsigned g_ring_next = 0u;
static unsigned g_reserves  = 0u;

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
        memcpy(g_pkt[produced], &g_seq, sizeof g_seq);
        out[produced] = duct_view(duct_view_u8, g_pkt[produced], pkt_bytes);
        ++produced;
        ++g_seq;
        --g_left;
    }
    *n = produced;
    return produced ? rc_ok : rc_again;
}

static void *device_write_reserve([[maybe_unused]] void *ctx, size_t size)
{
    if (size > pkt_bytes)
        return nullptr;
    duct_discard duct_atomic_fetch(add, &g_attempts, 1, release);
    if (++g_reserves % 4u == 0u) {
        duct_discard duct_atomic_fetch(add, &g_refused, 1, relaxed);
        return nullptr;
    }
    auto slot = g_ring[g_ring_next];
    g_ring_next = (g_ring_next + 1u) % ring_slots;
    return slot;
}

static duct_result_t device_write_commit([[maybe_unused]] void *ctx,
                                         void *buf, size_t len)
{
    auto c = (const char *)buf;
    if (len != pkt_bytes || c < g_ring[0]
        || c >= g_ring[0] + (size_t)ring_slots * pkt_bytes) {
        duct_discard duct_atomic_fetch(add, &g_bad_write, 1, release);
        return rc_ok;
    }
    unsigned seq = 0u;
    memcpy(&seq, buf, sizeof seq);
    if ((int)seq <= duct_atomic_load(&g_out_order, acquire))
        duct_discard duct_atomic_fetch(add, &g_bad_write, 1, release);
    duct_atomic_store(&g_out_order, (int)seq, release);
    duct_discard duct_atomic_fetch(add, &g_committed, 1, release);
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
         const duct_frame_t *frame, duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    if (conn_id != 1u)
        return rc_ok;
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
        fprintf(stderr, "device_tx: io create failed\n");
        return 1;
    }
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "device_tx", .wire = wire, .on_frame = on_frame,
        .on_session_open = on_session_open,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!proto) {
        fprintf(stderr, "device_tx: proto create failed\n");
        duct_engine_destroy(io);
        return 1;
    }
    uint16_t port = 0u;
    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok) {
        fprintf(stderr, "device_tx: listen failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }
    pthread_t thread;
    if (pthread_create(&thread, nullptr, th_run, io) != 0) {
        fprintf(stderr, "device_tx: thread create failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }
    auto primary = th_connect(port);
    const char *error = nullptr;
    if (primary == duct_sock_bad)
        error = "primary connect failed";
    else if (!th_wait_int(&g_attach_rc, (int)rc_ok, wait_ms))
        error = "duct_conn_attach_device refused the reserve/commit pair";
    if (!error && !s_signal_raise(g_device_event))
        error = "device signal failed";
    if (!error && !th_wait_int(&g_committed, (int)pkt_total, wait_ms))
        error = "a refused reservation lost its packet instead of parking it";
    if (!error && duct_atomic_load(&g_refused, acquire) == 0)
        error = "no reservation was refused: the retry path never ran";
    if (!error && duct_atomic_load(&g_attempts, acquire) <= (int)pkt_total)
        error = "refusals were never retried";
    if (!error && duct_atomic_load(&g_bad_write, acquire) != 0)
        error = "a committed slot held the wrong bytes, or arrived out of order";

    if (primary != duct_sock_bad)
        close(primary);
    duct_engine_stop(io);
    pthread_join(thread, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    if (g_device_event)
        s_signal_close(g_device_event);

    if (error) {
        fprintf(stderr, "device_tx: %s (committed=%d of %u, reserve calls=%d, "
                        "refused=%d, bad=%d, last seq=%d)\n",
                error, duct_atomic_load(&g_committed, acquire), pkt_total,
                duct_atomic_load(&g_attempts, acquire),
                duct_atomic_load(&g_refused, acquire),
                duct_atomic_load(&g_bad_write, acquire),
                duct_atomic_load(&g_out_order, acquire));
        return 1;
    }
    printf("device_tx: OK (%u packets into the device's own ring, in order, "
           "%d reservations refused and retried, no egress lane)\n",
           pkt_total, duct_atomic_load(&g_refused, acquire));
    return 0;
}
