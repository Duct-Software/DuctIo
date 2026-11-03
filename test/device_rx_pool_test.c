/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file device_rx_pool_test.c
 *  @brief Two device legs on one io thread, each reading into its own RX slots:
 *  one leg's lane held by its worker never leaves the other's reads without
 *  engine buffers.
 *
 *  Both devices fill only the buffers the engine offers, so a read handed none
 *  counts as starved and produces nothing. The first leg's handler holds the
 *  one worker on that leg's first frame while its whole drive sits in the
 *  lane, and the second leg is signalled and read meanwhile. Once the handler
 *  lets go, every packet of both legs is checked for order and bytes.
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
static constexpr unsigned read_batch = 32u;
static constexpr unsigned pkt_len    = 512u;
static constexpr unsigned held_total = read_batch * duct_dgram_rx_max_passes * 2u;
static constexpr unsigned free_total = read_batch * 2u;

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

typedef struct device {
    device_signal_t signal;
    atomic_uint     left;
    unsigned        seq;
    unsigned        expect;
    atomic_int      attach_rc;
    atomic_int      reads;
    atomic_int      starved;
    atomic_int      frames;
    atomic_int      bad;
} device_t;

static device_t g_dev[2] = {
    { .attach_rc = -1 },
    { .attach_rc = -1 },
};
static duct_session_t *g_sess[2];
static unsigned        g_opened;
static atomic_int      g_blocked = 0;
static atomic_int      g_release = 0;

static duct_result_t device_read(void *ctx, duct_view_u8 *out, unsigned max, unsigned *n)
{
    auto d = (device_t *)ctx;
    unsigned left = duct_atomic_load(&d->left, acquire);
    if (left)
        duct_discard duct_atomic_fetch(add, &d->reads, 1, release);
    unsigned produced = 0u;
    while (produced < max && produced < read_batch && produced < left) {
        if (!out[produced].data || out[produced].size < pkt_len) {
            duct_discard duct_atomic_fetch(add, &d->starved, 1, release);
            break;
        }
        auto p = (unsigned char *)out[produced].data;
        memcpy(p, &d->seq, sizeof d->seq);
        memset(p + sizeof d->seq, (int)(d->seq & 0xffu), pkt_len - sizeof d->seq);
        out[produced].size = pkt_len;
        ++produced;
        ++d->seq;
    }
    duct_discard duct_atomic_fetch(sub, &d->left, produced, release);
    *n = produced;
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
on_session_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    if (g_opened >= 2u)
        return rc_ok;
    auto d = &g_dev[g_opened];
    g_sess[g_opened++] = s;
    d->signal = s_signal_open();
    if (!d->signal) {
        duct_atomic_store(&d->attach_rc, (int)rc_no_memory, release);
        return rc_ok;
    }
    duct_device_ops_t ops = {
        .wait_handle = (void *)(intptr_t)d->signal,
        .rx_span = pkt_len,
        .read = device_read,
        .write_reserve = device_write_reserve,
        .write_commit = device_write_commit,
        .release = device_release,
        .ctx = d,
    };
    auto rc = duct_conn_attach_device(s, 1u, &ops);
    duct_atomic_store(&d->attach_rc, (int)rc, release);
    return rc_ok;
}

static duct_result_t
on_frame(duct_session_t *s, duct_conn_id_t conn_id, const duct_frame_t *frame,
         [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    if (conn_id != 1u)
        return rc_ok;
    auto d = s == g_sess[0] ? &g_dev[0] : &g_dev[1];
    if (d == &g_dev[0] && !duct_atomic_load(&g_release, acquire)) {
        duct_atomic_store(&g_blocked, 1, release);
        for (unsigned waited = 0u; waited < wait_ms && !duct_atomic_load(&g_release, acquire);
             ++waited)
            th_sleep_ms(1u);
    }
    unsigned seq = 0u;
    if (frame->payload.size != pkt_len)
        duct_discard duct_atomic_fetch(add, &d->bad, 1, release);
    else {
        memcpy(&seq, frame->payload.data, sizeof seq);
        auto p = (const unsigned char *)frame->payload.data;
        if (seq != d->expect || p[pkt_len - 1u] != (unsigned char)(seq & 0xffu))
            duct_discard duct_atomic_fetch(add, &d->bad, 1, release);
        d->expect = seq + 1u;
    }
    duct_discard duct_atomic_fetch(add, &d->frames, 1, release);
    return rc_ok;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){
        .io_threads = 1, .workers = 1,
    });
    if (!io) {
        fprintf(stderr, "device_rx_pool: io create failed\n");
        return 1;
    }
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "device_rx_pool", .wire = wire, .on_frame = on_frame,
        .on_session_open = on_session_open,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!proto) {
        fprintf(stderr, "device_rx_pool: proto create failed\n");
        duct_engine_destroy(io);
        return 1;
    }
    uint16_t port = 0u;
    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok) {
        fprintf(stderr, "device_rx_pool: listen failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }
    pthread_t thread;
    if (pthread_create(&thread, nullptr, th_run, io) != 0) {
        fprintf(stderr, "device_rx_pool: thread create failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }
    const char *error = nullptr;
    duct_sock_t peers[2] = { duct_sock_bad, duct_sock_bad };
    for (unsigned i = 0u; i < 2u && !error; ++i) {
        peers[i] = th_connect(port);
        if (peers[i] == duct_sock_bad)
            error = "connect failed";
        else if (!th_wait_int(&g_dev[i].attach_rc, (int)rc_ok, wait_ms))
            error = "duct_conn_attach_device did not return rc_ok";
    }
    duct_atomic_store(&g_dev[0].left, held_total, release);
    if (!error && !s_signal_raise(g_dev[0].signal))
        error = "device signal failed";
    if (!error && !th_wait_int(&g_blocked, 1, wait_ms))
        error = "the held leg's first frame never reached the protocol";
    duct_atomic_store(&g_dev[1].left, free_total, release);
    if (!error && !s_signal_raise(g_dev[1].signal))
        error = "device signal failed";
    for (unsigned waited = 0u; !error && waited < wait_ms
         && !duct_atomic_load(&g_dev[1].reads, acquire); waited += 10u)
        th_sleep_ms(10u);
    if (!error && !duct_atomic_load(&g_dev[1].reads, acquire))
        error = "the second leg was never read";
    int starved = duct_atomic_load(&g_dev[1].starved, acquire);
    duct_atomic_store(&g_release, 1, release);
    if (!error && starved)
        error = "a leg was read with no engine buffers while another leg's lane was held";
    if (!error && !th_wait_int(&g_dev[0].frames, (int)held_total, wait_ms))
        error = "packets lost on the held leg";
    if (!error && !th_wait_int(&g_dev[1].frames, (int)free_total, wait_ms))
        error = "packets lost on the second leg";
    if (!error && (duct_atomic_load(&g_dev[0].bad, acquire)
                   || duct_atomic_load(&g_dev[1].bad, acquire)))
        error = "a frame arrived out of order or with the wrong bytes";

    for (unsigned i = 0u; i < 2u; ++i)
        if (peers[i] != duct_sock_bad)
            close(peers[i]);
    duct_engine_stop(io);
    pthread_join(thread, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    for (unsigned i = 0u; i < 2u; ++i)
        if (g_dev[i].signal)
            s_signal_close(g_dev[i].signal);

    if (error) {
        fprintf(stderr, "device_rx_pool: %s (held frames=%d of %u, second frames=%d of %u, "
                        "second reads=%d, starved=%d)\n",
                error, duct_atomic_load(&g_dev[0].frames, acquire), held_total,
                duct_atomic_load(&g_dev[1].frames, acquire), free_total,
                duct_atomic_load(&g_dev[1].reads, acquire), starved);
        return 1;
    }
    printf("device_rx_pool: OK (%u + %u packets, the second leg read into engine buffers "
           "while the first held its own)\n", held_total, free_total);
    return 0;
}
