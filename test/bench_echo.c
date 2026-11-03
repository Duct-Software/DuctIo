/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file bench_echo.c
 * @brief End-to-end throughput benchmarks: real engine, real TCP.
 *
 * Sender pushes frames as fast as TCP allows, no sync round-trip.
 * Measures raw pipeline throughput: epoll recv → WFQ → on_frame → ack.
 */

#include "duct.h"
#include "duct_wire.h"
#include "bench_stats.h"
#include "duct_worker.h"
#include "duct_runtime_stats.h"
#include "duct_io.h"
#include "duct_xport.h"
#include "duct_conn.h"
#include "duct_olb_rx.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <process.h> /* _getpid */
    /* MSG_DONTWAIT has no Windows equivalent; every socket here is instead
     * set non-blocking directly at connect time (see set_nonblock), same
     * fallback shape as os/windows/include/duct_xport.h. */
    #ifndef MSG_DONTWAIT
        #define MSG_DONTWAIT 0
    #endif
    #define close(fd) closesocket(fd)
    #define read(fd, buf, n) recv((fd), (char *)(buf), (int)(n), 0)
    #define getpid() ((int)_getpid())
    #define poll(fds, n, timeout) WSAPoll((fds), (ULONG)(n), (timeout))
    typedef WSAPOLLFD bench_pollfd_t;
    /* Sleep in whole microseconds via nanosleep — already relied on
     * elsewhere in this file, works on MinGW; Windows has no usleep(). */
    static inline void usleep(unsigned usec)
    {
        struct timespec ts = { .tv_sec = usec / 1000000u,
                                .tv_nsec = (long)(usec % 1000000u) * 1000L };
        nanosleep(&ts, nullptr);
    }
#else
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <poll.h>
    #include <sched.h>
    #include <sys/socket.h>
    #include <sys/uio.h>
    #include <unistd.h>
    typedef struct pollfd bench_pollfd_t;
#endif

static uint16_t g_port;
static constexpr unsigned bench_sec = 1u;
static constexpr unsigned warmup_frames = 0u;
/** @brief Extra time receiver_fn/pipe get to drain the backlog after the
 *  sender's own deadline. Senders share this as a hard cap on the partial-
 *  write retry loop: if the peer never reads again (receiver gave up, or
 *  never existed), send() keeps returning EAGAIN forever and the retry loop
 *  has no deadline check of its own — bound it to the receiver's lifetime so
 *  a stalled peer degrades the run (reported as ok=0 / a short frame count)
 *  instead of hanging the whole benchmark suite. */
static constexpr unsigned bench_recv_grace_sec = 2u;

/* ── Helpers ────────────────────────────────────────────────────── */

static inline uint64_t ns_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static duct_sock_t do_connect(uint16_t port)
{
    for (unsigned w = 0u; w < 5000u; w += 10u) {
        duct_sock_t fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == duct_sock_bad) return duct_sock_bad;
        struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) };
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0) {
            /* sender_fn/receiver_fn's send()/read() assume non-blocking:
             * MSG_DONTWAIT is a no-op on Windows (see this file's own
             * top-of-file note), and the outer deadline check only runs
             * between calls, never inside one — a blocking fd lets a single
             * slow send()/read() (peer draining slowly under high connection
             * count) overrun the whole benchmark's own time budget with no
             * way to notice. */
            duct_xset_nonblock(fd);
            return fd;
        }
        close(fd);
        struct timespec ts = { .tv_nsec = 10000000L };
        nanosleep(&ts, nullptr);
    }
    return duct_sock_bad;
}

/** @brief Send @p hdr (@p h_len bytes) immediately followed by @p payload
 *  (@p p_len bytes) as one logical write: writev() on POSIX; two sequential
 *  send() calls on Windows (no writev/scatter-gather wrapper needed here —
 *  TCP reassembles either way, and this is a throughput benchmark, not a
 *  framing-atomicity test). Returns total bytes written, or the first
 *  short/failed write's own return. */
static ssize_t bench_send2(duct_sock_t fd, const void *hdr, size_t h_len, const void *payload, size_t p_len)
{
#ifdef _WIN32
    ssize_t w1 = send(fd, (const char *)hdr, (int)h_len, 0);
    if (w1 != (ssize_t)h_len)
        return w1;
    ssize_t w2 = send(fd, (const char *)payload, (int)p_len, 0);
    if (w2 != (ssize_t)p_len)
        return w1;
    return w1 + w2;
#else
    struct iovec iov[2] = { { (void *)hdr, h_len }, { (void *)payload, p_len } };
    return writev(fd, iov, 2);
#endif
}

/* ── Server callbacks ───────────────────────────────────────────── */

/* Server-side frame counters for integrity verification. */
static _Atomic(uint64_t) g_srv_frames_rx;
static _Atomic(uint64_t) g_srv_frames_tx;

static duct_result_t
on_frame_echo([[maybe_unused]] duct_session_t *s,
              [[maybe_unused]] duct_conn_id_t cid,
              const duct_frame_t *f, duct_response_t *out,
              [[maybe_unused]] void *ps)
{
    duct_atomic_fetch(add, &g_srv_frames_rx, 1u, relaxed);
    bench_inc_frame_rx(f->payload.size);
    duct_response_echo(out, f);
    bench_inc_frame_tx(f->payload.size);
    duct_atomic_fetch(add, &g_srv_frames_tx, 1u, relaxed);
    return rc_ok;
}

/* Zero-copy echo: payload points directly into RX OLB, no memcpy. */
static duct_result_t
on_frame_echo_zerocopy([[maybe_unused]] duct_session_t *s,
                       [[maybe_unused]] duct_conn_id_t cid,
                       const duct_frame_t *f, duct_response_t *out,
                       [[maybe_unused]] void *ps)
{
    duct_atomic_fetch(add, &g_srv_frames_rx, 1u, relaxed);
    bench_inc_frame_rx(f->payload.size);
    out->payload = f->payload;
    out->flags = fl_send_static;
    out->conn_id = duct_conn_id_same;
    out->stream_id = duct_stream_id_same;
    bench_inc_frame_tx(f->payload.size);
    duct_atomic_fetch(add, &g_srv_frames_tx, 1u, relaxed);
    return rc_ok;
}

static duct_result_t
on_frame_sink([[maybe_unused]] duct_session_t *s,
              [[maybe_unused]] duct_conn_id_t cid,
              const duct_frame_t *f,
              [[maybe_unused]] duct_response_t *out,
              [[maybe_unused]] void *ps)
{
    bench_inc_frame_rx(f->payload.size);
    return rc_drop;
}

static duct_result_t
on_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t t,
        [[maybe_unused]] void *u, [[maybe_unused]] duct_response_t *o,
        [[maybe_unused]] void *p)
{
    bench_inc_session_open();
    return rc_ok;
}

static void on_close([[maybe_unused]] duct_session_t *s,
                     [[maybe_unused]] duct_close_reason_t r,
                     [[maybe_unused]] void *p)
{
    bench_inc_session_close();
}

/* ── Stats printing ─────────────────────────────────────────────── */

static void print_worker_stats(unsigned n_workers)
{
#if DUCT_RUNTIME_STATS
    for (unsigned i = 0u; i < n_workers; ++i) {
        auto st = duct_worker_rtstats(i);
        if (st) {
            printf("  worker[%u]: wfq_drain=%lu  futex_wait=%lu  batch_defer=%lu\n",
                   i, (unsigned long)st->wfq_drain, (unsigned long)st->futex_wait,
                   (unsigned long)st->batch_partial_defer);
        }
    }
#endif
}

static void print_io_stats(unsigned n_io)
{
#if DUCT_RUNTIME_STATS
    for (unsigned i = 0u; i < n_io; ++i) {
        auto st = duct_io_rtstats(i);
        if (st) {
            printf("  io[%u]: drain_posts=%lu  drain_deduped=%lu  push_full=%lu  fence_push_full=%lu\n",
                   i, (unsigned long)st->tx_drain_posts,
                   (unsigned long)st->tx_drain_deduped,
                   (unsigned long)st->wfq_push_full,
                   (unsigned long)st->fence_push_full);
        }
    }
#endif
}

/* ── Server lifecycle ───────────────────────────────────────────── */

typedef enum { ECHO_OFF, ECHO_COPY, ECHO_ZEROCOPY } echo_mode_t;

typedef struct {
    duct_engine_t    *io;
    duct_proto_t *proto;
    duct_wire_t  *wire;
    pthread_t     th;
} server_t;

static int srv_start(server_t *s, echo_mode_t mode, unsigned n_workers)
{
    bench_reset();
    duct_atomic_store(&g_srv_frames_rx, 0u, relaxed);
    duct_atomic_store(&g_srv_frames_tx, 0u, relaxed);
    s->io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = n_workers });
    if (!s->io) return -1;
    s->wire = duct_wire_create_length_prefix(0u);
    if (!s->wire) { duct_engine_destroy(s->io); return -1; }
    duct_frame_fn frame_cb = nullptr;
    if (mode == ECHO_COPY)     frame_cb = on_frame_echo;
    if (mode == ECHO_ZEROCOPY) frame_cb = on_frame_echo_zerocopy;
    s->proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = mode == ECHO_OFF ? "sink" : "echo",
        .wire = s->wire,
        .on_frame = frame_cb ? frame_cb : on_frame_sink,
        .on_session_open = on_open,
        .on_session_close = on_close,
    });
    if (!s->proto) {
        duct_wire_destroy(s->wire); duct_engine_destroy(s->io); return -1;
    }
    g_port = 0;
    if (duct_io_listen(s->io, "127.0.0.1", &g_port, s->proto) != rc_ok) {
        duct_proto_destroy(s->proto); duct_wire_destroy(s->wire);
        duct_engine_destroy(s->io); return -1;
    }
    if (pthread_create(&s->th, nullptr, (void *(*)(void *))duct_engine_wait, s->io) != 0)
        return -1;
    usleep(50000);
    printf("  [bench] server started on port %u (%u workers, %s)\n",
           g_port, n_workers,
           mode == ECHO_OFF ? "sink" : mode == ECHO_COPY ? "echo-copy" : "echo-zerocopy");
    return 0;
}

/** @brief Join io/worker threads so rtstats stop mutating; @c io stays valid for reads. */
static void srv_stop_io(server_t *s)
{
    duct_engine_stop(s->io);
    pthread_join(s->th, nullptr);
}

static void srv_destroy(server_t *s)
{
    duct_engine_destroy(s->io);
    duct_proto_destroy(s->proto);
    duct_wire_destroy(s->wire);
}

static void srv_stop(server_t *s)
{
    srv_stop_io(s);
    srv_destroy(s);
}

/* ================================================================== */
/*  Sender: push frames continuously for bench_sec seconds             */
/* ================================================================== */

typedef struct {
    duct_sock_t  fd;
    unsigned     payload_sz;
    unsigned     sec;
    unsigned     idx;
    uint64_t     frames;
    uint64_t     bytes;
    _Atomic(int) ok;
} sender_t;

static void *sender_fn(void *arg)
{
    auto ctx = (sender_t *)arg;
    unsigned pl = ctx->payload_sz;
    size_t flen = 4u + pl;
    char *buf = malloc(flen);
    buf[0] = (char)(pl >> 24u); buf[1] = (char)(pl >> 16u);
    buf[2] = (char)(pl >>  8u); buf[3] = (char)(pl);
    memset(buf + 4u, 'X', pl);
    /* Tag the payload with the connection index so the receiver can detect
     * cross-connection data delivery (a routing bug), not just aggregate
     * frame-count drift. */
    if (pl >= 4u) {
        buf[4] = (char)(ctx->idx >> 24u); buf[5] = (char)(ctx->idx >> 16u);
        buf[6] = (char)(ctx->idx >>  8u); buf[7] = (char)(ctx->idx);
    }

    /* Warmup: send a few frames to verify pipeline works */
    for (unsigned w = 0u; w < warmup_frames; ++w) {
        ssize_t wr = send(ctx->fd, buf, flen, 0);
        if (wr != (ssize_t)flen) {
            free(buf);
            duct_atomic_store(&ctx->ok, 0, relaxed);
            return nullptr;
        }
    }

    uint64_t deadline = ns_now() + (uint64_t)ctx->sec * 1000000000ull;
    uint64_t hard_deadline = ns_now()
        + (uint64_t)(ctx->sec + bench_recv_grace_sec) * 1000000000ull;
    uint64_t frames = 0u, bytes = 0u;

    while (ns_now() < deadline) {
        size_t off = 0u;
        while (off < flen) {
            ssize_t wr = send(ctx->fd, buf + off, flen - off, MSG_DONTWAIT);
            if (wr > 0) {
                off += (size_t)wr;
                continue;
            }
            if (wr < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                if (ns_now() >= hard_deadline)
                    goto done;
                bench_pollfd_t pfd = { .fd = ctx->fd, .events = POLLOUT };
                poll(&pfd, 1, 10);
                continue;
            }
            goto done;
        }
        ++frames; bytes += flen;
    }
done:
    ctx->frames = frames;
    ctx->bytes = bytes;
    free(buf);
    duct_atomic_store(&ctx->ok, 1, relaxed);
    return nullptr;
}

/* ================================================================== */
/*  Receiver: drain echo responses                                     */
/* ================================================================== */

typedef struct {
    duct_sock_t  fd;
    unsigned     sec;
    unsigned     idx;
    uint64_t     frames;
    uint64_t     bytes;
    uint64_t     tag_mismatches;
    _Atomic(int) done;
} receiver_t;

static void *receiver_fn(void *arg)
{
    auto ctx = (receiver_t *)arg;
    uint64_t frames = 0u, bytes = 0u, tag_mismatches = 0u;
    uint64_t deadline = ns_now()
        + (uint64_t)(ctx->sec + bench_recv_grace_sec) * 1000000000ull;

    while (ns_now() < deadline) {
        uint8_t hdr[4];
        size_t got = 0u;
        while (got < 4u) {
            bench_pollfd_t pfd = { .fd = ctx->fd, .events = POLLIN };
            if (poll(&pfd, 1, 200) <= 0) goto done;
            ssize_t n = read(ctx->fd, hdr + got, 4u - got);
            if (n <= 0) goto done;
            got += (size_t)n;
        }
        uint32_t plen = ((uint32_t)hdr[0] << 24u) | ((uint32_t)hdr[1] << 16u)
                      | ((uint32_t)hdr[2] <<  8u) |  (uint32_t)hdr[3];
        /* skip payload, checking the connection-index tag in its first 4
         * bytes against ctx->idx to catch cross-connection delivery. */
        uint32_t rem = plen;
        bool first_chunk = true;
        while (rem > 0u) {
            char skip[4096];
            uint32_t to_read = rem < 4096u ? rem : 4096u;
            bench_pollfd_t pfd = { .fd = ctx->fd, .events = POLLIN };
            if (poll(&pfd, 1, 200) <= 0) goto done;
            ssize_t n = read(ctx->fd, skip, to_read);
            if (n <= 0) goto done;
            if (first_chunk && n >= 4) {
                uint32_t tag = ((uint32_t)(uint8_t)skip[0] << 24u)
                             | ((uint32_t)(uint8_t)skip[1] << 16u)
                             | ((uint32_t)(uint8_t)skip[2] <<  8u)
                             |  (uint32_t)(uint8_t)skip[3];
                if (tag != ctx->idx)
                    ++tag_mismatches;
            }
            first_chunk = false;
            rem -= (uint32_t)n;
        }
        ++frames; bytes += 4u + plen;
    }
done:
    ctx->frames = frames;
    ctx->bytes = bytes;
    ctx->tag_mismatches = tag_mismatches;
    duct_atomic_store(&ctx->done, 1, release);
    return nullptr;
}

/* ================================================================== */
/*  Bench: inbound throughput (server drops frames)                    */
/* ================================================================== */

static void bench_inbound(unsigned n, unsigned psz, unsigned n_workers)
{
    server_t srv;
    if (srv_start(&srv, ECHO_OFF, n_workers) != 0) {
        fprintf(stderr, "  srv_start failed\n"); return;
    }

    sender_t *senders = calloc(n, sizeof(sender_t));
    pthread_t *threads = calloc(n, sizeof(pthread_t));

    for (unsigned i = 0u; i < n; ++i) {
        duct_sock_t fd = do_connect(g_port);
        if (fd == duct_sock_bad) { fprintf(stderr, "  connect %u failed\n", i); return; }
        senders[i] = (sender_t){ .fd = fd, .payload_sz = psz, .sec = bench_sec };
        atomic_init(&senders[i].ok, 0);
    }

    uint64_t t0 = ns_now();
    for (unsigned i = 0u; i < n; ++i)
        pthread_create(&threads[i], nullptr, sender_fn, &senders[i]);
    for (unsigned i = 0u; i < n; ++i)
        pthread_join(threads[i], nullptr);
    uint64_t elapsed = ns_now() - t0;

    srv_stop_io(&srv);
    print_worker_stats(n_workers);
    print_io_stats(1);
    bench_print_server_stats();
    srv_destroy(&srv);

    uint64_t tf = 0u, tb = 0u;
    int ok = 1;
    for (unsigned i = 0u; i < n; ++i) {
        if (!duct_atomic_load(&senders[i].ok, relaxed)) ok = 0;
        tf += senders[i].frames;
        tb += senders[i].bytes;
        close(senders[i].fd);
    }
    if (ok) {
        double s = (double)elapsed / 1e9;
        printf("  inbound_%ux%u  %lu frames  %.1f MB  %.3fs  %7.2f Mf/s  %7.1f MB/s\n",
               n, psz, (unsigned long)tf, (double)tb / 1048576.0, s,
               (double)tf / s / 1e6, (double)tb / s / 1048576.0);
    }
    free(senders); free(threads);
}

/* ================================================================== */
/*  Bench: echo throughput (sender + receiver per conn)                */
/* ================================================================== */

static void bench_echo(unsigned n, unsigned psz, unsigned n_workers)
{
    server_t srv;
    if (srv_start(&srv, ECHO_COPY, n_workers) != 0) {
        fprintf(stderr, "  srv_start failed\n"); return;
    }

    sender_t   *senders = calloc(n, sizeof(sender_t));
    receiver_t *receivers = calloc(n, sizeof(receiver_t));
    pthread_t  *snd_ths = calloc(n, sizeof(pthread_t));
    pthread_t  *rcv_ths = calloc(n, sizeof(pthread_t));

    for (unsigned i = 0u; i < n; ++i) {
        duct_sock_t fd = do_connect(g_port);
        if (fd == duct_sock_bad) { fprintf(stderr, "  connect %u failed\n", i); return; }
        senders[i] = (sender_t){ .fd = fd, .payload_sz = psz, .sec = bench_sec, .idx = i };
        atomic_init(&senders[i].ok, 0);
        receivers[i] = (receiver_t){ .fd = fd, .sec = bench_sec, .idx = i };
        atomic_init(&receivers[i].done, 0);
    }

    /* Start receivers first so they're ready when responses arrive */
    for (unsigned i = 0u; i < n; ++i)
        pthread_create(&rcv_ths[i], nullptr, receiver_fn, &receivers[i]);

    /* Brief pause so receivers are blocking on read() before senders start */
    usleep(10000);

    uint64_t t0 = ns_now();
    for (unsigned i = 0u; i < n; ++i)
        pthread_create(&snd_ths[i], nullptr, sender_fn, &senders[i]);
    for (unsigned i = 0u; i < n; ++i)
        pthread_join(snd_ths[i], nullptr);
    /* Give receiver time to drain remaining responses */
    for (unsigned i = 0u; i < n; ++i)
        pthread_join(rcv_ths[i], nullptr);
    uint64_t elapsed = ns_now() - t0;

    /* Join io/worker threads before reading rtstats: they otherwise still
     * mutate concurrently with this read. */
    srv_stop_io(&srv);
    print_worker_stats(n_workers);
    print_io_stats(1);
    bench_print_server_stats();
    srv_destroy(&srv);

    /* Per-conn lines are useful at small n; at high concurrency they just
     * flood the log, so report an aggregate instead past this threshold. */
    static constexpr unsigned per_conn_print_max = 8u;
    uint64_t sf = 0u, rf = 0u, sb = 0u, rb = 0u,
             mismatches = 0u;
    unsigned failed = 0u;
    int ok = 1;
    for (unsigned i = 0u; i < n; ++i) {
        if (!duct_atomic_load(&senders[i].ok, relaxed)) { ok = 0; ++failed; }
        sf += senders[i].frames; sb += senders[i].bytes;
        rf += receivers[i].frames; rb += receivers[i].bytes;
        mismatches += receivers[i].tag_mismatches;
        if (n <= per_conn_print_max)
            printf("    conn[%u] sent=%lu recv=%lu tag_mismatches=%lu\n", i,
                   (unsigned long)senders[i].frames, (unsigned long)receivers[i].frames,
                   (unsigned long)receivers[i].tag_mismatches);
        close(senders[i].fd);
    }
    if (n > per_conn_print_max)
        printf("    conns=%u failed=%u tag_mismatches=%lu\n",
               n, failed, (unsigned long)mismatches);
    if (ok) {
        double s = (double)elapsed / 1e9;
        double send_mfps = (double)sf / s / 1e6;
        double recv_mfps = (double)rf / s / 1e6;
        double send_mbps = (double)sb / s / 1048576.0;
        printf("  echo_%ux%u  sent=%lu  recv=%lu  %.3fs  in=%7.2f Mf/s %6.1f MB/s  out=%7.2f Mf/s\n",
               n, psz, (unsigned long)sf, (unsigned long)rf, s,
               send_mfps, send_mbps, recv_mfps);
    }
    free(senders); free(receivers); free(snd_ths); free(rcv_ths);
}

/* ================================================================== */
/*  Pipelined echo benchmark: true full-duplex send+recv on each conn */
/* ================================================================== */

static _Atomic(int) g_pipe_stop;

typedef struct {
    duct_sock_t  fd;
    unsigned     payload_sz;
    unsigned     sec;
    uint64_t     frames;
    _Atomic(int) ok;
} pipe_sender_t;

typedef struct {
    duct_sock_t  fd;
    uint64_t     frames;
    _Atomic(int) ok;
} pipe_receiver_t;

static void *pipe_sender_fn(void *arg)
{
    auto ctx = (pipe_sender_t *)arg;
    unsigned pl = ctx->payload_sz;
    size_t flen = 4u + pl;
    char frame[flen];
    frame[0] = (char)(pl >> 24u); frame[1] = (char)(pl >> 16u);
    frame[2] = (char)(pl >>  8u); frame[3] = (char)(pl);
    memset(frame + 4u, 'X', pl);

    uint64_t deadline = ns_now() + (uint64_t)ctx->sec * 1000000000ull;
    uint64_t hard_deadline = ns_now()
        + (uint64_t)(ctx->sec + bench_recv_grace_sec) * 1000000000ull;
    uint64_t frames = 0u;

    while (ns_now() < deadline) {
        size_t off = 0u;
        while (off < flen) {
            ssize_t wr = send(ctx->fd, frame + off, flen - off, MSG_DONTWAIT);
            if (wr > 0) {
                off += (size_t)wr;
                continue;
            }
            if (wr < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                if (ns_now() >= hard_deadline)
                    goto done;
                bench_pollfd_t pfd = { .fd = ctx->fd, .events = POLLOUT };
                poll(&pfd, 1, 10);
                continue;
            }
            goto done;
        }
        ++frames;
    }
done:
    ctx->frames = frames;
    duct_atomic_store(&ctx->ok, 1, relaxed);
    return nullptr;
}

/** @brief Read up to @p n bytes off non-blocking @p fd, waiting for readability
 *  while the socket has nothing and the run lasts: a frame split across reads
 *  must not end the receiver.
 *  @return bytes read; 0 at the peer's end, a hard error, or the run's stop. */
static ssize_t pipe_read(duct_sock_t fd, void *buf, size_t n)
{
    for (;;) {
        ssize_t got = read(fd, buf, n);
        if (got > 0)
            return got;
        if (got == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)
            || duct_atomic_load(&g_pipe_stop, acquire))
            return 0;
        bench_pollfd_t pfd = { .fd = fd, .events = POLLIN };
        duct_discard poll(&pfd, 1, 500);
    }
}

static void *pipe_receiver_fn(void *arg)
{
    auto ctx = (pipe_receiver_t *)arg;
    uint64_t frames = 0u;

    while (!duct_atomic_load(&g_pipe_stop, acquire)) {
        bench_pollfd_t pfd = { .fd = ctx->fd, .events = POLLIN };
        if (poll(&pfd, 1, 500) <= 0) continue;
        uint8_t hdr[4];
        size_t got = 0u;
        while (got < 4u) {
            ssize_t n = pipe_read(ctx->fd, hdr + got, 4u - got);
            if (n <= 0) goto done;
            got += (size_t)n;
        }
        uint32_t plen = ((uint32_t)hdr[0] << 24u) | ((uint32_t)hdr[1] << 16u)
                      | ((uint32_t)hdr[2] <<  8u) |  (uint32_t)hdr[3];
        uint32_t rem = plen;
        while (rem > 0u) {
            char skip[4096];
            uint32_t to_read = rem < 4096u ? rem : 4096u;
            ssize_t n = pipe_read(ctx->fd, skip, to_read);
            if (n <= 0) goto done;
            rem -= (uint32_t)n;
        }
        ++frames;
    }
done:
    ctx->frames = frames;
    duct_atomic_store(&ctx->ok, 1, release);
    return nullptr;
}

static void bench_echo_pipelined(unsigned n_conns, unsigned payload_sz, unsigned n_workers)
{
    server_t srv;
    if (srv_start(&srv, ECHO_COPY, n_workers) != 0) {
        fprintf(stderr, "  srv_start failed\n"); return;
    }

    duct_atomic_store(&g_pipe_stop, 0, relaxed);

    pipe_sender_t   *senders   = calloc(n_conns, sizeof(pipe_sender_t));
    pipe_receiver_t *receivers = calloc(n_conns, sizeof(pipe_receiver_t));
    pthread_t       *snd_ths   = calloc(n_conns, sizeof(pthread_t));
    pthread_t       *rcv_ths   = calloc(n_conns, sizeof(pthread_t));

    for (unsigned i = 0u; i < n_conns; ++i) {
        duct_sock_t fd = do_connect(g_port);
        if (fd == duct_sock_bad) { fprintf(stderr, "  connect %u failed\n", i); return; }
        /* Nagle stays on. Under TCP_NODELAY every 68-byte frame leaves as a
         * segment of its own, which the server's receive queue charges at its
         * skb truesize, about 1 KB; once backpressure stops the server reading,
         * that queue overflows before the window closes, the kernel drops a
         * segment, and the run stalls on the retransmission timer instead of
         * measuring the engine. */
        senders[i] = (pipe_sender_t){
            .fd = fd, .payload_sz = payload_sz, .sec = bench_sec,
        };
        atomic_init(&senders[i].ok, 0);
        receivers[i] = (pipe_receiver_t){ .fd = fd };
        atomic_init(&receivers[i].ok, 0);
    }

    for (unsigned i = 0u; i < n_conns; ++i)
        pthread_create(&rcv_ths[i], nullptr, pipe_receiver_fn, &receivers[i]);
    usleep(10000);

    uint64_t t0 = ns_now();
    for (unsigned i = 0u; i < n_conns; ++i)
        pthread_create(&snd_ths[i], nullptr, pipe_sender_fn, &senders[i]);
    for (unsigned i = 0u; i < n_conns; ++i)
        pthread_join(snd_ths[i], nullptr);
    /* Grace period: let receivers drain buffered responses before stopping. */
    usleep(200000);
    duct_atomic_store(&g_pipe_stop, 1, release);
    for (unsigned i = 0u; i < n_conns; ++i)
        pthread_join(rcv_ths[i], nullptr);
    uint64_t elapsed = ns_now() - t0;

    srv_stop_io(&srv);
    print_worker_stats(n_workers);
    print_io_stats(1);
    bench_print_server_stats();
    srv_destroy(&srv);

    uint64_t sf = 0u, rf = 0u;
    int ok = 1;
    for (unsigned i = 0u; i < n_conns; ++i) {
        if (!duct_atomic_load(&senders[i].ok, relaxed)) ok = 0;
        if (!duct_atomic_load(&receivers[i].ok, relaxed)) ok = 0;
        sf += senders[i].frames;
        rf += receivers[i].frames;
        close(senders[i].fd);
    }
    if (ok) {
        double s = (double)elapsed / 1e9;
        printf("  echo_pipe_%ux%u  sent=%lu  recv=%lu  %.3fs  in=%7.2f Mf/s  out=%7.2f Mf/s\n",
               n_conns, payload_sz, (unsigned long)sf, (unsigned long)rf, s,
               (double)sf / s / 1e6, (double)rf / s / 1e6);
    }
    free(senders); free(receivers); free(snd_ths); free(rcv_ths);
}

/* ================================================================== */
/*  Echo latency (single client)                                       */
/* ================================================================== */

static void bench_latency_test(unsigned n_frames, unsigned payload_size, unsigned n_workers)
{
    server_t srv;
    if (srv_start(&srv, ECHO_COPY, n_workers) != 0) {
        fprintf(stderr, "  srv_start failed\n"); return;
    }

    duct_sock_t fd = do_connect(g_port);
    if (fd == duct_sock_bad) { srv_stop(&srv); return; }

    char payload[256];
    memset(payload, 'L', payload_size);
    char recv_buf[8192];
    bench_latency_t lat = {};
    atomic_init(&lat.idx, 0);

    for (unsigned i = 0u; i < n_frames; ++i) {
        uint64_t t1 = ns_now();
        uint8_t hdr[4] = {
            (uint8_t)(payload_size >> 24u), (uint8_t)(payload_size >> 16u),
            (uint8_t)(payload_size >>  8u), (uint8_t)(payload_size),
        };
        if (bench_send2(fd, hdr, 4u, payload, payload_size) != (ssize_t)(4u + payload_size)) break;

        /* recv */
        uint8_t rhdr[4];
        size_t got = 0u;
        while (got < 4u) {
            bench_pollfd_t pfd = { .fd = fd, .events = POLLIN };
            if (poll(&pfd, 1, 5000) <= 0) goto done;
            ssize_t n = read(fd, rhdr + got, 4u - got);
            if (n <= 0) goto done;
            got += (size_t)n;
        }
        uint32_t rlen = ((uint32_t)rhdr[0] << 24u) | ((uint32_t)rhdr[1] << 16u)
                      | ((uint32_t)rhdr[2] <<  8u) |  (uint32_t)rhdr[3];
        got = 0u;
        while (got < rlen) {
            ssize_t n = read(fd, recv_buf + got, rlen - got);
            if (n <= 0) goto done;
            got += (size_t)n;
        }
        bench_latency_record(&lat, ns_now() - t1);
    }
done:
    close(fd);
    srv_stop_io(&srv);
    print_worker_stats(n_workers);
    print_io_stats(1);
    srv_destroy(&srv);
    bench_latency_print(&lat, "echo RTT");
}

/* ================================================================== */
/*  Main                                                               */
/* ================================================================== */

/* Temporary crash-capture aid: freeze (instead of dying) on fault so gdb -p
 * can attach to a live process and inspect the faulting stack. Remove once
 * the race under investigation is root-caused. */
[[maybe_unused]] static void s_crash_freeze(int sig)
{
    fprintf(stderr, "\n*** signal %d in pid %d -- attach: gdb -p %d ***\n",
            sig, (int)getpid(), (int)getpid());
    fflush(stderr);
    for (volatile int stop = 1; stop; )
        ;
}

int main(void)
{
#ifndef _WIN32
    /* Windows sockets report a broken pipe as a send() error (WSAECONNRESET/
     * WSAESHUTDOWN), not a signal — nothing to ignore here. */
    signal(SIGPIPE, SIG_IGN);
#endif
#if !defined(__SANITIZE_ADDRESS__) && !defined(__SANITIZE_THREAD__)
    signal(SIGSEGV, s_crash_freeze);
    signal(SIGABRT, s_crash_freeze);
    #ifndef _WIN32
    signal(SIGBUS, s_crash_freeze); /* no Windows equivalent */
    #endif
#endif
    setvbuf(stdout, nullptr, _IOLBF, 0);

    printf("=============================================================\n");
    printf("  DuctIO Throughput Benchmarks\n");
    printf("  duration=%us  DUCT_RUNTIME_STATS=%d  %s\n",
           bench_sec, DUCT_RUNTIME_STATS,
#ifdef NDEBUG
           "Release");
#else
           "Debug");
#endif
    printf("  hint: taskset -c 0-%u for pinned runs\n", duct_cpu_online_count());
    printf("=============================================================\n\n");

    /* ── Inbound: server recv→drop, pure receive throughput ──────── */
    printf("--- Inbound (recv→drop, 1 worker) ---\n");
    bench_inbound(1, 64, 1);
    bench_inbound(2, 64, 1);
    bench_inbound(4, 64, 1);
    bench_inbound(1, 256, 1);
    bench_inbound(1, 1024, 1);
    printf("\n");

    /* ── Echo copy: default fl_send_copy path ────────────────────── */
    printf("--- Echo copy (1 worker) ---\n");
    bench_echo(1, 64, 1);
    bench_echo(2, 64, 1);
    bench_echo(4, 64, 1);
    bench_echo(1, 256, 1);
    printf("\n");

    /* ── Echo zero-copy: fl_send_static, no memcpy in TX path ───── */
    printf("--- Echo zero-copy (fl_send_static, 1 worker) ---\n");
    /* bench_echo uses ECHO_COPY; run a quick zerocopy variant */
    {
        server_t srv;
        if (srv_start(&srv, ECHO_ZEROCOPY, 1) == 0) {
            unsigned n = 4u, psz = 64u;
            sender_t   *senders = calloc(n, sizeof(sender_t));
            receiver_t *receivers = calloc(n, sizeof(receiver_t));
            pthread_t  *snd_ths = calloc(n, sizeof(pthread_t));
            pthread_t  *rcv_ths = calloc(n, sizeof(pthread_t));
            for (unsigned i = 0u; i < n; ++i) {
                duct_sock_t fd = do_connect(g_port);
                if (fd == duct_sock_bad) break;
                senders[i] = (sender_t){ .fd = fd, .payload_sz = psz, .sec = bench_sec };
                atomic_init(&senders[i].ok, 0);
                receivers[i] = (receiver_t){ .fd = fd, .sec = bench_sec };
                atomic_init(&receivers[i].done, 0);
            }
            for (unsigned i = 0u; i < n; ++i)
                pthread_create(&rcv_ths[i], nullptr, receiver_fn, &receivers[i]);
            usleep(10000);
            uint64_t t0 = ns_now();
            for (unsigned i = 0u; i < n; ++i)
                pthread_create(&snd_ths[i], nullptr, sender_fn, &senders[i]);
            for (unsigned i = 0u; i < n; ++i)
                pthread_join(snd_ths[i], nullptr);
            for (unsigned i = 0u; i < n; ++i)
                pthread_join(rcv_ths[i], nullptr);
            uint64_t elapsed = ns_now() - t0;
            srv_stop_io(&srv);
            print_worker_stats(1);
            print_io_stats(1);
            bench_print_server_stats();
            uint64_t sf = 0u, rf = 0u;
            for (unsigned i = 0u; i < n; ++i) {
                sf += senders[i].frames; rf += receivers[i].frames;
                close(senders[i].fd);
            }
            double s = (double)elapsed / 1e9;
            printf("  echo_zerocopy_%ux%u  sent=%lu  recv=%lu  %.3fs  in=%7.2f Mf/s  out=%7.2f Mf/s\n",
                   n, psz, (unsigned long)sf, (unsigned long)rf, s,
                   (double)sf / s / 1e6, (double)rf / s / 1e6);
            srv_destroy(&srv);
            free(senders); free(receivers); free(snd_ths); free(rcv_ths);
        }
    }
    printf("\n");

    /* ── Echo pipelined: true full-duplex, payload scaling ───────── */
    printf("--- Echo pipelined (1 worker, payload scaling) ---\n");
    bench_echo_pipelined(1, 64, 1);
    bench_echo_pipelined(2, 64, 1);
    bench_echo_pipelined(4, 64, 1);
    bench_echo_pipelined(1, 256, 1);
    bench_echo_pipelined(1, 1024, 1);
    printf("\n");

    /* ── Multi-worker scaling ────────────────────────────────────── */
    printf("--- Echo copy (2 workers) ---\n");
    bench_echo(1, 64, 2);
    bench_echo(2, 64, 2);
    bench_echo(4, 64, 2);
    printf("\n");

    printf("--- Echo copy (4 workers) ---\n");
    bench_echo(1, 64, 4);
    bench_echo(2, 64, 4);
    bench_echo(4, 64, 4);
    printf("\n");

    printf("--- Echo pipelined (2 workers) ---\n");
    bench_echo_pipelined(1, 64, 2);
    bench_echo_pipelined(2, 64, 2);
    bench_echo_pipelined(4, 64, 2);
    printf("\n");

    printf("--- Echo pipelined (4 workers) ---\n");
    bench_echo_pipelined(1, 64, 4);
    bench_echo_pipelined(2, 64, 4);
    bench_echo_pipelined(4, 64, 4);
    printf("\n");

    /* ── High concurrency: many conns fanned out over the worker pool,
     * as opposed to the <=4-conn scenarios above ─────────────────── */
    printf("--- High concurrency (100 conns, 4 workers) ---\n");
    bench_inbound(100, 64, 1);
    bench_echo(100, 64, 4);
    bench_echo_pipelined(100, 64, 4);
    printf("\n");

    /* ── Latency ─────────────────────────────────────────────────── */
    printf("--- Echo latency (1 worker) ---\n");
    bench_latency_test(10000, 64, 1);
    printf("\n");

    printf("=============================================================\n");
    printf("  Done.\n");
    printf("=============================================================\n");
    return 0;
}
