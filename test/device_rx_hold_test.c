/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file device_rx_hold_test.c
 *  @brief Device-leg RX out of the device's own memory, lent to the engine
 *  rather than copied.
 *
 *  The device answers out of a fixed pool of its own, the shape a driver ring
 *  has, and with @c ops.release_read set that memory is lent rather than
 *  copied out of. A delivered frame whose payload points inside the pool is
 *  the proof no copy was taken, and every packet the device sourced there must
 *  arrive that way: the hold budget covers a whole drive, so nothing falls
 *  back to a copy for want of room to track it.
 *
 *  The pool is deliberately smaller than the run: the device stalls when it is
 *  empty and can only continue once the engine returns what it holds, so a
 *  release that never comes is a timeout rather than a pass. Every returned
 *  buffer is poisoned, which turns a release taken before the worker consumed
 *  the frame into a body mismatch.
 *
 *  The first two reads mix the two memories, filling the buffers @c ops.read
 *  offers for every other packet. Such a batch is addressed both ways at once,
 *  so its pool-backed half arrives lent like any other while the engine's own
 *  buffers stay the engine's: a @c release_read handed anything outside the
 *  pool is counted by @c g_alien_release and fails the run.
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
static constexpr unsigned pkt_total  = 400u;
static constexpr unsigned read_batch = 32u;
static constexpr unsigned pkt_min    = 64u;
static constexpr unsigned pkt_spread = 512u;
static constexpr unsigned pool_bufs  = 72u;
static constexpr unsigned buf_bytes  = pkt_min + pkt_spread;

static atomic_int g_attach_rc = -1;
static atomic_int g_frames    = 0;
static atomic_int g_bad_size  = 0;
static atomic_int g_bad_body  = 0;
static atomic_int g_lent      = 0;
static atomic_int g_not_lent    = 0;
static atomic_int g_pool_out  = 0;
static atomic_int g_released  = 0;
static atomic_int g_starved   = 0;
static atomic_int g_mixed_batches = 0;
static atomic_int g_alien_release = 0;

static unsigned g_left = pkt_total;
static unsigned g_seq  = 0u;
static unsigned g_expect = 0u;
static atomic_int g_gap_at = -1;

/* Pool and free stack: ops.read and ops.release_read both run on the I/O
 * thread that owns the leg, so neither needs a lock. */
static unsigned char g_pool[pool_bufs][buf_bytes];
static unsigned      g_free[pool_bufs];
static unsigned      g_free_n = 0u;

static unsigned s_len_of(unsigned seq) { return pkt_min + seq % pkt_spread; }

static void s_fill(unsigned char *p, unsigned seq, unsigned len)
{
    memcpy(p, &seq, sizeof seq);
    for (unsigned i = (unsigned)sizeof seq; i < len; ++i)
        p[i] = (unsigned char)(seq + i);
}

static bool s_in_pool(const void *p)
{
    auto c = (const unsigned char *)p;
    return c >= g_pool[0] && c < g_pool[0] + (size_t)pool_bufs * buf_bytes;
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

static unsigned g_reads = 0u;

static duct_result_t device_read([[maybe_unused]] void *ctx, duct_view_u8 *out,
                                 unsigned max, unsigned *n)
{
    bool mixed = ++g_reads <= 2u;
    unsigned produced = 0u, from_pool = 0u, from_engine = 0u;
    while (produced < max && produced < read_batch && g_left > 0u) {
        unsigned len = s_len_of(g_seq);
        bool offered = mixed && (produced & 1u)
                    && out[produced].data && out[produced].size >= len;
        if (offered) {
            s_fill((unsigned char *)out[produced].data, g_seq, len);
            out[produced].size = len;
            ++from_engine;
        } else {
            if (!g_free_n)
                break;
            unsigned idx = g_free[--g_free_n];
            s_fill(g_pool[idx], g_seq, len);
            out[produced] = duct_view(duct_view_u8, g_pool[idx], len);
            ++from_pool;
        }
        ++produced;
        ++g_seq;
        --g_left;
    }
    *n = produced;
    if (from_pool && from_engine)
        duct_discard duct_atomic_fetch(add, &g_mixed_batches, 1, relaxed);
    duct_discard duct_atomic_fetch(add, &g_pool_out, (int)from_pool, relaxed);
    if (!produced && g_left > 0u)
        duct_atomic_store(&g_starved, 1, release);
    return produced ? rc_ok : rc_again;
}

/** @brief Take one lent buffer back into the pool.
 *  Poisoned before it returns: a frame the worker has not consumed yet then
 *  arrives as a body mismatch instead of stale-but-plausible bytes.
 *  Re-signalling is what a driver does when its ring has room again — without
 *  it a device that stalled empty never gets read a second time.
 */
static void device_release_read([[maybe_unused]] void *ctx, duct_view_u8 pkt)
{
    if (!s_in_pool(pkt.data)) {
        duct_discard duct_atomic_fetch(add, &g_alien_release, 1, release);
        return;
    }
    size_t idx = ((unsigned char *)pkt.data - g_pool[0]) / buf_bytes;
    memset(g_pool[idx], 0xEE, buf_bytes);
    g_free[g_free_n++] = (unsigned)idx;
    duct_discard duct_atomic_fetch(add, &g_released, 1, relaxed);
    if (g_left > 0u)
        duct_discard s_signal_raise(g_device_event);
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
        .rx_span = buf_bytes,
        .read = device_read,
        .release_read = device_release_read,
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
    if (s_in_pool(frame->payload.data))
        duct_discard duct_atomic_fetch(add, &g_lent, 1, relaxed);
    else
        duct_discard duct_atomic_fetch(add, &g_not_lent, 1, relaxed);
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
    for (unsigned i = 0u; i < pool_bufs; ++i)
        g_free[g_free_n++] = i;

    auto io = duct_engine_launch(&(duct_engine_cfg_t){
        .io_threads = 1, .workers = 1,
    });
    if (!io) {
        fprintf(stderr, "device_rx_hold: io create failed\n");
        return 1;
    }
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "device_rx_hold", .wire = wire, .on_frame = on_frame,
        .on_session_open = on_session_open,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!proto) {
        fprintf(stderr, "device_rx_hold: proto create failed\n");
        duct_engine_destroy(io);
        return 1;
    }
    uint16_t port = 0u;
    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok) {
        fprintf(stderr, "device_rx_hold: listen failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }
    pthread_t thread;
    if (pthread_create(&thread, nullptr, th_run, io) != 0) {
        fprintf(stderr, "device_rx_hold: thread create failed\n");
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
    if (!error && !th_wait_int(&g_frames, (int)pkt_total, wait_ms))
        error = "packets lost between the device and the protocol";
    if (!error && duct_atomic_load(&g_lent, acquire) == 0)
        error = "every frame was copied: the device's memory was never lent";
    if (!error && duct_atomic_load(&g_bad_size, acquire) != 0)
        error = "frame size did not match the packet the device wrote";
    if (!error && duct_atomic_load(&g_bad_body, acquire) != 0)
        error = "frame body did not match: a lent buffer moved or came back early";
    if (!error && duct_atomic_load(&g_gap_at, acquire) >= 0)
        error = "frames arrived out of order";

    if (primary != duct_sock_bad)
        close(primary);
    duct_engine_stop(io);
    pthread_join(thread, nullptr);
    duct_engine_destroy(io);

    /* Past teardown the device owns its memory again, so every lent buffer
     * must have come back — including any the leg still held at close. */
    int lent_out = duct_atomic_load(&g_pool_out, acquire),
        released = duct_atomic_load(&g_released, acquire);
    if (!error && released != lent_out)
        error = "device buffers were kept past teardown, or freed twice";
    if (!error && duct_atomic_load(&g_lent, acquire) != lent_out)
        error = "a packet the device owned was copied: the hold budget bound";
    if (!error && duct_atomic_load(&g_mixed_batches, acquire) == 0)
        error = "no mixed batch was ever produced";
    if (!error && duct_atomic_load(&g_alien_release, acquire) != 0)
        error = "release_read was handed memory the device never owned";

    duct_proto_destroy(proto);
    if (g_device_event)
        s_signal_close(g_device_event);

    if (error) {
        fprintf(stderr, "device_rx_hold: %s (frames=%d of %u, lent=%d, "
                        "copied=%d, lent out=%d, released=%d, alien=%d, "
                        "mixed batches=%d, starved=%d, "
                        "bad size=%d, bad body=%d, gap at %d)\n",
                error, duct_atomic_load(&g_frames, acquire), pkt_total,
                duct_atomic_load(&g_lent, acquire),
                duct_atomic_load(&g_not_lent, acquire), lent_out, released,
                duct_atomic_load(&g_alien_release, acquire),
                duct_atomic_load(&g_mixed_batches, acquire),
                duct_atomic_load(&g_starved, acquire),
                duct_atomic_load(&g_bad_size, acquire),
                duct_atomic_load(&g_bad_body, acquire),
                duct_atomic_load(&g_gap_at, acquire));
        return 1;
    }
    printf("device_rx_hold: OK (%u packets, %d lent without a copy — every one "
           "the device owned, %d out of engine buffers, %d batches mixing the "
           "two, all %d lent buffers returned)\n",
           pkt_total, duct_atomic_load(&g_lent, acquire),
           duct_atomic_load(&g_not_lent, acquire),
           duct_atomic_load(&g_mixed_batches, acquire), released);
    return 0;
}
