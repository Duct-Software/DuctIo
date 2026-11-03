/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file bench_recv.c
 * @brief Receive-side hop: wire -> engine -> the harness's own consumer ring.
 *
 * bench_hops.c already prices the send side (source ring -> engine -> UDP).
 * Nothing this tree has measured yet is the other half: a datagram arriving
 * -> io-thread parse -> worker on_frame -> published into the shm ring an
 * external consumer reads from. That publish target is reproduced here
 * byte-for-byte against harness/include/shm_ring.h (relaxed load of
 * write_index, memcpy, release-store seq, release-store write_index) so the
 * memcpy/atomic cost is the real one, not a stand-in.
 *
 * The sender side is deliberately NOT this engine: a raw sendto() loop, so
 * this bench isolates the receive path's own cost instead of re-measuring
 * what bench_hops.c already priced. The reader thread reproduces consumer.cpp's
 * loop verbatim (tight ring_read(), no sleep) so t1 is stamped exactly where
 * the real consumer would stamp it, not at the engine's own publish call.
 *
 * Record layout (24-byte header + fixed filler) is a placeholder for the
 * still-undesigned compact wire format — this bench prices what the engine
 * costs to move N given bytes from socket to ring, not the format itself.
 *
 * --sync replaces the engine with one thread doing recv() -> ring_publish()
 * inline, no WFQ, no worker: prices the io/WFQ/worker round trip by removing
 * it. Not a proposed production mode — the two-thread split exists so a slow
 * callback never stalls the socket drain loop into a kernel-level drop; this
 * flag only answers "how much does the round trip cost today."
 *
 * --framed MAX runs the engine on a framed datagram wire of that max_frame, the
 * sender putting a zero flags byte ahead of each record. Such a wire takes no
 * GRO, so the io thread reads queued datagrams several to a receive call, and
 * a build with DUCT_DGRAM_RX_BATCH at 1 reads the same run one at a time. The
 * engine line splits the io and worker threads' CPU out of the process total,
 * which the spinning sender and reader dominate.
 */

#include "duct.h"
#include "duct_wire.h"
#include "duct_worker.h"
#include "duct_runtime_stats.h"
#include "test_helpers.h"
#include "dgram_test_helpers.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
    #include <dirent.h>
    #include <fcntl.h>
#endif

static inline uint64_t s_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/** @brief Process CPU time, user + kernel, across every thread — same
 *  measure bench_hops.c trades spin budget against. */
static uint64_t s_cpu_ns(void)
{
    duct_cpu_time_t cpu = duct_process_cpu();
    return cpu.user_ns + cpu.kernel_ns;
}

/** @brief Sum the on-CPU time of this process's threads whose name starts with
 *  @p prefix, nanoseconds.
 *  Read from each thread's schedstat; 0 off Linux. */
static uint64_t s_task_cpu_ns([[maybe_unused]] const char *prefix)
{
    uint64_t ns = 0u;
#if defined(__linux__)
    DIR *d = opendir("/proc/self/task");
    if (!d)
        return 0u;
    for (struct dirent *e; (e = readdir(d)) != nullptr; ) {
        if (e->d_name[0] == '.')
            continue;
        char path[288], comm[32] = {};
        duct_discard snprintf(path, sizeof path, "/proc/self/task/%s/comm", e->d_name);
        FILE *f = fopen(path, "r");
        if (!f)
            continue;
        bool hit = fgets(comm, sizeof comm, f) && !strncmp(comm, prefix, strlen(prefix));
        fclose(f);
        if (!hit)
            continue;
        duct_discard snprintf(path, sizeof path, "/proc/self/task/%s/schedstat", e->d_name);
        unsigned long long run = 0ull;
        if ((f = fopen(path, "r"))) {
            if (fscanf(f, "%llu", &run) != 1)
                run = 0ull;
            fclose(f);
        }
        ns += run;
    }
    closedir(d);
#endif
    return ns;
}

/* ---- harness/include/message.h's Header, reproduced ---- */

typedef struct {
    uint64_t seq_id;
    uint64_t send_ts_ns;
    uint16_t type;
    uint16_t version;
    uint32_t body_len;
} msg_header_t;

/** @brief Placeholder compact record: real header, filler body. Sized well
 *  under harness's 576-byte OrderBook — the point of compacting at all. */
typedef struct {
    msg_header_t header;
    uint8_t      body[40];
} record_t;

static constexpr uint64_t record_seq_control = 0u;

/* ---- harness/include/shm_ring.h's Ring, reproduced ---- */

static constexpr uint32_t ring_frame_cap = 576u; /* msg::kMaxFrame */
static constexpr uint32_t ring_slots = 4096u;

typedef struct {
    _Atomic(uint64_t) seq;
    uint32_t          frame_len;
    uint8_t           frame[ring_frame_cap];
} ring_slot_t;

typedef struct {
    _Atomic(uint64_t) write_index;
    ring_slot_t       *slots;
    uint32_t          mask;
} mock_ring_t;

static void ring_init(mock_ring_t *r, ring_slot_t *storage, uint32_t slots)
{
    r->slots = storage;
    r->mask = slots - 1u;
    duct_atomic_store(&r->write_index, 0u, relaxed);
    for (uint32_t i = 0u; i < slots; ++i)
        duct_atomic_store(&storage[i].seq, 0u, relaxed);
}

static void ring_publish(mock_ring_t *r, const void *frame, uint32_t len)
{
    uint64_t idx = duct_atomic_load(&r->write_index, relaxed);
    auto slot = &r->slots[idx & r->mask];
    slot->frame_len = len;
    memcpy(slot->frame, frame, len);
    duct_atomic_store(&slot->seq, idx + 1u, release);
    duct_atomic_store(&r->write_index, idx + 1u, release);
}

typedef enum { ring_ok, ring_empty, ring_lapped } ring_status_t;

static ring_status_t ring_read(mock_ring_t *r, uint64_t read_index, void *out,
                               uint32_t *out_len, uint64_t *resume_at)
{
    auto slot = &r->slots[read_index & r->mask];
    uint64_t seq = duct_atomic_load(&slot->seq, acquire),
             want = read_index + 1u;
    if (seq < want)
        return ring_empty;
    if (seq > want) {
        uint64_t edge = duct_atomic_load(&r->write_index, acquire);
        *resume_at = edge > ring_slots ? edge - ring_slots : 0u;
        return ring_lapped;
    }
    uint32_t len = slot->frame_len;
    memcpy(out, slot->frame, len);
    if (duct_atomic_load(&slot->seq, acquire) != want) {
        uint64_t edge = duct_atomic_load(&r->write_index, acquire);
        *resume_at = edge > ring_slots ? edge - ring_slots : 0u;
        return ring_lapped;
    }
    *out_len = len;
    return ring_ok;
}

static ring_slot_t   *s_ring_storage;
static mock_ring_t    s_ring;

/* ---- sample store / percentiles, same shape as bench_hops.c ---- */

typedef struct {
    uint64_t *total;
    uint32_t  cap;
    _Atomic(uint32_t) n_total;
} samples_t;

static samples_t s_samples;
static _Atomic(bool) s_reader_stop = false;
static duct_engine_t *s_engine;
static atomic_int s_session_open = 0;

static void s_record(uint64_t v)
{
    uint32_t i = duct_atomic_fetch(add, &s_samples.n_total, 1u, relaxed);
    if (i < s_samples.cap)
        s_samples.total[i] = v;
}

static int s_u64_cmp(const void *a, const void *b)
{
    uint64_t va = *(const uint64_t *)a,
             vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

static void s_print_pct(uint32_t n)
{
    if (!n) {
        printf("  no samples\n");
        return;
    }
    qsort(s_samples.total, n, sizeof(uint64_t), s_u64_cmp);
    uint64_t sum = 0u;
    for (uint32_t i = 0u; i < n; ++i)
        sum += s_samples.total[i];
    printf("  t0->ring n=%-7u mean=%-8llu p50=%-8llu p99=%-8llu p99.9=%-9llu p99.99=%-9llu max=%llu\n",
           n, (unsigned long long)(sum / n),
           (unsigned long long)s_samples.total[n / 2u],
           (unsigned long long)s_samples.total[(uint64_t)n * 99u / 100u],
           (unsigned long long)s_samples.total[(uint64_t)n * 999u / 1000u],
           (unsigned long long)s_samples.total[(uint64_t)n * 9999u / 10000u],
           (unsigned long long)s_samples.total[n - 1u]);
}

/* ---- engine side: plain dgram listener, on_frame publishes into s_ring ---- */

static constexpr unsigned bench_io_threads = 1u;
static constexpr unsigned bench_workers = 1u;
static constexpr unsigned bench_cpu_base = bench_io_threads + bench_workers;

static duct_result_t
on_session_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &s_session_open, 1, relaxed);
    return rc_ok;
}

static duct_result_t
on_frame_recv([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    duct_do_if(frame->payload.size != sizeof(record_t), return rc_drop);
    auto rec = (const record_t *)frame->payload.data;
    if (rec->header.seq_id == record_seq_control)
        return rc_drop;
    ring_publish(&s_ring, frame->payload.data, (uint32_t)frame->payload.size);
    return rc_drop;
}

#if DUCT_RUNTIME_STATS
static duct_worker_rt_t s_rt_base;

static void s_rt_mark(void)
{
    auto rt = duct_worker_rtstats(0u);
    if (rt)
        s_rt_base = *rt;
}

static void s_rt_dump(void)
{
    auto rt = duct_worker_rtstats(0u);
    if (!rt)
        return;
    uint64_t pass = rt->loop_pass - s_rt_base.loop_pass,
             spin = rt->busy_spin - s_rt_base.busy_spin,
             park = rt->futex_wait - s_rt_base.futex_wait;
    printf("  worker   pass=%llu spin=%llu park=%llu\n",
           (unsigned long long)pass, (unsigned long long)spin, (unsigned long long)park);
}
#else
static void s_rt_mark(void) {}
static void s_rt_dump(void) {}
#endif

/* ---- synthetic UDP sender: bypasses the engine on purpose, see @file ---- */

static void s_pace(uint64_t deadline)
{
    while (s_now_ns() < deadline)
        ;
}

typedef struct {
    uint64_t count;
    double   rate;
    unsigned cpu;
    duct_sock_t fd;
    unsigned lead;
} sender_arg_t;

/** @brief Send @p rec on @p fd as one datagram behind @p lead zero flag bytes,
 *  at most one. */
static void s_send_rec(duct_sock_t fd, const record_t *rec, unsigned lead)
{
    uint8_t dgram[1u + sizeof(record_t)] = {};
    memcpy(dgram + lead, rec, sizeof *rec);
    duct_discard send(fd, (const char *)dgram, (int)(lead + sizeof *rec), 0);
}

static void *s_sender(void *arg)
{
    auto sa = (sender_arg_t *)arg;
    if (duct_thread_pinning) duct_discard duct_thread_bind_cpu(sa->cpu);
    uint64_t interval = sa->rate > 0.0 ? (uint64_t)(1e9 / sa->rate) : 0u,
             next = s_now_ns();
    record_t rec = {};
    for (uint64_t i = 1u; i <= sa->count; ++i) {
        if (interval) {
            s_pace(next);
            next += interval;
        }
        rec.header.seq_id = i;
        rec.header.type = 1u;
        rec.header.version = 1u;
        rec.header.body_len = sizeof rec;
        rec.header.send_ts_ns = s_now_ns();
        s_send_rec(sa->fd, &rec, sa->lead);
    }
    return nullptr;
}

/* ---- EXPERIMENT: --sync mode, no engine at all ----
 * One thread, raw non-blocking socket, recv() -> ring_publish() inline —
 * prices the io/WFQ/worker round trip by removing it entirely. Same ring,
 * same sender, same consumer-reader as the engine path; only this leg
 * differs, so the delta between --sync and normal runs IS the round trip. */

static duct_sock_t s_bind_raw_udp(uint16_t *out_port)
{
    duct_sock_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    duct_do_if(fd == duct_sock_bad, return duct_sock_bad);
    struct sockaddr_in addr = { .sin_family = AF_INET };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    duct_do_if(bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0, close(fd); return duct_sock_bad);
    socklen_t len = sizeof addr;
    duct_do_if(getsockname(fd, (struct sockaddr *)&addr, &len) != 0, close(fd); return duct_sock_bad);
    *out_port = ntohs(addr.sin_port);
#ifdef _WIN32
    unsigned long nb = 1ul;
    ioctlsocket(fd, FIONBIO, &nb);
#else
    int fl = fcntl(fd, F_GETFL, 0);
    duct_discard fcntl(fd, F_SETFL, fl | O_NONBLOCK);
#endif
    return fd;
}

static duct_sock_t s_sync_recv_fd = duct_sock_bad;

typedef struct { unsigned cpu; unsigned batch; } sync_arg_t;

static void *s_sync_recv(void *arg)
{
    auto sa = (sync_arg_t *)arg;
    if (duct_thread_pinning) duct_discard duct_thread_bind_cpu(sa->cpu);
    record_t buf;
    while (!duct_atomic_load(&s_reader_stop, acquire)) {
        ssize_t n = recv(s_sync_recv_fd, (char *)&buf, (int)sizeof buf, 0);
        if (n == (ssize_t)sizeof buf && buf.header.seq_id != record_seq_control)
            ring_publish(&s_ring, &buf, (uint32_t)n);
        /* EAGAIN/short read: spin, same discipline the engine's own io
         * thread uses under its busy-spin budget. */
    }
    return nullptr;
}

/* ---- EXPERIMENT: --recvmmsg mode, batches the syscall itself ----
 * Same single-thread shape as --sync, but one recvmmsg() drains up to
 * sa->batch datagrams per call instead of one recv() per datagram — prices
 * the syscall-count reduction strace found (recvfrom ~1:1 with messages),
 * isolated from the io/WFQ/worker round trip already priced by --sync.
 * Batch size is runtime (--batch), not a constant: whether a bigger batch
 * helps is exactly the open question, not an assumption. Linux-only:
 * recvmmsg has no Windows equivalent. Fixed-size record_t slots side-step
 * the variable-length padding problem discussed for the real wire format —
 * see the design note this was measured for. */
#if defined(__linux__)
static void *s_mmsg_recv(void *arg)
{
    auto sa = (sync_arg_t *)arg;
    if (duct_thread_pinning) duct_discard duct_thread_bind_cpu(sa->cpu);
    unsigned n = sa->batch;
    auto scratch = (record_t *)calloc(n, sizeof(record_t));
    auto iov = (struct iovec *)calloc(n, sizeof(struct iovec));
    auto msgs = (struct mmsghdr *)calloc(n, sizeof(struct mmsghdr));
    duct_do_if(!scratch || !iov || !msgs,
        fprintf(stderr, "bench_recv: mmsg alloc failed\n"); return nullptr);
    for (unsigned i = 0u; i < n; ++i) {
        iov[i] = (struct iovec){ .iov_base = &scratch[i], .iov_len = sizeof scratch[i] };
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }
    while (!duct_atomic_load(&s_reader_stop, acquire)) {
        int got = recvmmsg(s_sync_recv_fd, msgs, n, MSG_DONTWAIT, nullptr);
        for (int i = 0; i < got; ++i)
            if (msgs[i].msg_len == sizeof(record_t) && scratch[i].header.seq_id != record_seq_control)
                ring_publish(&s_ring, &scratch[i], (uint32_t)msgs[i].msg_len);
        /* got <= 0 (EAGAIN) or a short/oversized datagram: spin. */
    }
    free(scratch);
    free(iov);
    free(msgs);
    return nullptr;
}
#endif

/* ---- consumer-side reader: consumer.cpp's own loop, verbatim shape ---- */

typedef struct { unsigned cpu; } reader_arg_t;

static void *s_reader(void *arg)
{
    auto ra = (reader_arg_t *)arg;
    if (duct_thread_pinning) duct_discard duct_thread_bind_cpu(ra->cpu);
    record_t buf;
    uint64_t read_index = 0u;
    while (!duct_atomic_load(&s_reader_stop, acquire)) {
        uint32_t len = 0u;
        uint64_t resume = 0u;
        auto st = ring_read(&s_ring, read_index, &buf, &len, &resume);
        if (st == ring_ok) {
            uint64_t recv_ts = s_now_ns();
            s_record(recv_ts - buf.header.send_ts_ns);
            ++read_index;
        } else if (st == ring_lapped)
            read_index = resume;
        /* ring_empty: spin, exactly consumer.cpp's own idle branch. */
    }
    return nullptr;
}

static uint32_t s_settle(uint32_t want, unsigned quiet_ms, unsigned cap_ms)
{
    uint64_t start = s_now_ns(),
             last_change = start;
    uint32_t last = duct_atomic_load(&s_samples.n_total, relaxed);
    for (;;) {
        th_sleep_ms(1);
        uint32_t now_n = duct_atomic_load(&s_samples.n_total, relaxed);
        if (now_n >= want)
            return now_n;
        uint64_t now = s_now_ns();
        if (now_n != last) {
            last = now_n;
            last_change = now;
        } else if (now - last_change > (uint64_t)quiet_ms * 1000000ull)
            return now_n;
        if (now - start > (uint64_t)cap_ms * 1000000ull)
            return now_n;
    }
}

typedef struct {
    uint64_t count;
    double   rates[8];
    unsigned n_rates;
    bool     sync_mode;
    bool     mmsg_mode;
    unsigned mmsg_batch;
    size_t   framed_max;
} cfg_t;

/** @brief Flag bytes the run's wire takes ahead of each record: 1 on a framed
 *  wire, 0 otherwise. */
static unsigned s_lead(const cfg_t *cfg)
{
    return cfg->framed_max ? 1u : 0u;
}

static void s_run_one(const cfg_t *cfg, double rate, duct_sock_t fd)
{
    ring_init(&s_ring, s_ring_storage, ring_slots);
    duct_atomic_store(&s_samples.n_total, 0u, relaxed);
    duct_atomic_store(&s_reader_stop, false, release);
    s_rt_mark();

    uint64_t cpu0 = s_cpu_ns(),
             io0 = s_task_cpu_ns("duct-io-"),
             wrk0 = s_task_cpu_ns("duct-wrk-"),
             wall0 = s_now_ns();

    reader_arg_t ra = { .cpu = bench_cpu_base };
    pthread_t reader_th;
    duct_do_if(pthread_create(&reader_th, nullptr, s_reader, &ra) != 0,
        printf("  reader spawn failed\n"); return);

    sync_arg_t ya = { .cpu = bench_cpu_base + 2u, .batch = cfg->mmsg_batch };
    pthread_t recv_th;
    if (cfg->sync_mode)
        duct_do_if(pthread_create(&recv_th, nullptr, s_sync_recv, &ya) != 0,
            printf("  sync-recv spawn failed\n"); return);
#if defined(__linux__)
    else if (cfg->mmsg_mode)
        duct_do_if(pthread_create(&recv_th, nullptr, s_mmsg_recv, &ya) != 0,
            printf("  mmsg-recv spawn failed\n"); return);
#endif

    sender_arg_t sa = { .count = cfg->count, .rate = rate,
                        .cpu = bench_cpu_base + 1u, .fd = fd, .lead = s_lead(cfg) };
    pthread_t sender_th;
    duct_do_if(pthread_create(&sender_th, nullptr, s_sender, &sa) != 0,
        printf("  sender spawn failed\n"); return);
    pthread_join(sender_th, nullptr);

    uint32_t landed = s_settle((uint32_t)cfg->count, 300u, 5000u);
    duct_atomic_store(&s_reader_stop, true, release);
    pthread_join(reader_th, nullptr);
    if (cfg->sync_mode || cfg->mmsg_mode)
        pthread_join(recv_th, nullptr);

    uint64_t cpu_ns = s_cpu_ns() - cpu0,
             io_ns = s_task_cpu_ns("duct-io-") - io0,
             wrk_ns = s_task_cpu_ns("duct-wrk-") - wrk0,
             wall_ns = s_now_ns() - wall0;

    uint32_t delivered = landed;
    if (landed > s_samples.cap)
        landed = s_samples.cap;
    printf("rate=%-9.0f landed=%u\n", rate, delivered);
    printf("  cpu      %.2f us/msg  cores=%.2f  wall=%.0f ms\n",
           cfg->count ? (double)cpu_ns / 1000.0 / (double)cfg->count : 0.0,
           wall_ns ? (double)cpu_ns / (double)wall_ns : 0.0,
           (double)wall_ns / 1e6);
    if (io_ns || wrk_ns)
        printf("  engine   io %.3f us/msg  worker %.3f us/msg\n",
               delivered ? (double)io_ns / 1000.0 / (double)delivered : 0.0,
               delivered ? (double)wrk_ns / 1000.0 / (double)delivered : 0.0);
    s_rt_dump();
    s_print_pct(landed);
}

static bool s_parse_args(int argc, char **argv, cfg_t *cfg)
{
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--count") && i + 1 < argc)
            cfg->count = strtoull(argv[++i], nullptr, 10);
        else if (!strcmp(argv[i], "--rate") && i + 1 < argc) {
            cfg->rates[0] = strtod(argv[++i], nullptr);
            cfg->n_rates = 1u;
        } else if (!strcmp(argv[i], "--sync"))
            cfg->sync_mode = true;
        else if (!strcmp(argv[i], "--recvmmsg")) {
#if defined(__linux__)
            cfg->mmsg_mode = true;
#else
            fprintf(stderr, "bench_recv: --recvmmsg is Linux-only\n");
            return false;
#endif
        } else if (!strcmp(argv[i], "--batch") && i + 1 < argc)
            cfg->mmsg_batch = (unsigned)strtoul(argv[++i], nullptr, 10);
        else if (!strcmp(argv[i], "--framed") && i + 1 < argc)
            cfg->framed_max = strtoul(argv[++i], nullptr, 10);
        else
            return false;
    }
    /* --framed picks the engine's wire: the raw receivers take bare records,
     * and a max_frame short of a flags byte and a record drops every one. */
    return !cfg->framed_max
        || (cfg->framed_max > sizeof(record_t) && !cfg->sync_mode && !cfg->mmsg_mode);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    cfg_t cfg = {
        .count = 200000u,
        .rates = { 10000.0, 50000.0, 200000.0, 1000000.0 },
        .n_rates = 4u,
        .mmsg_batch = 64u,
    };
    duct_do_if(!s_parse_args(argc, argv, &cfg),
        fprintf(stderr, "usage: %s [--count N] [--rate R] [--sync] [--recvmmsg] [--batch N]"
                        " [--framed MAX]\n", argv[0]);
        return 2);

    s_samples.cap = cfg.count > (1u << 20) ? (1u << 20) : (uint32_t)cfg.count;
    s_samples.total = (uint64_t *)calloc(s_samples.cap, sizeof(uint64_t));
    s_ring_storage = (ring_slot_t *)calloc(ring_slots, sizeof(ring_slot_t));
    duct_do_if(!s_samples.total || !s_ring_storage,
        fprintf(stderr, "bench_recv: alloc failed\n"); return 1);

    if (cfg.sync_mode || cfg.mmsg_mode) {
        uint16_t port = 0u;
        s_sync_recv_fd = s_bind_raw_udp(&port);
        duct_do_if(s_sync_recv_fd == duct_sock_bad, fprintf(stderr, "bench_recv: raw bind failed\n"); return 1);

        duct_sock_t fd = uc_connect(port);
        duct_do_if(fd == duct_sock_bad, fprintf(stderr, "bench_recv: client connect failed\n");
            close(s_sync_recv_fd); return 1);

        printf("bench_recv %s: count=%llu recv=cpu%u bench=cpu%u,%u (no engine)\n\n",
               cfg.mmsg_mode ? "--recvmmsg" : "--sync",
               (unsigned long long)cfg.count, bench_cpu_base + 2u,
               bench_cpu_base, bench_cpu_base + 1u);
        for (unsigned r = 0u; r < cfg.n_rates; ++r)
            s_run_one(&cfg, cfg.rates[r], fd);

        close(fd);
        close(s_sync_recv_fd);
        free(s_samples.total);
        free(s_ring_storage);
        return 0;
    }

    s_engine = duct_engine_launch(&(duct_engine_cfg_t){
        .io_threads = bench_io_threads, .workers = bench_workers,
    });
    duct_do_if(!s_engine, fprintf(stderr, "bench_recv: engine create failed\n"); return 1);

    auto wire = duct_wire_create_dgram_batch(cfg.framed_max, cfg.framed_max != 0u);
    duct_do_if(!wire, fprintf(stderr, "bench_recv: wire create failed\n");
                      duct_engine_destroy(s_engine); return 1);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "bench_recv", .wire = wire,
        .on_frame = on_frame_recv,
        .on_session_open = on_session_open,
        .max_response = 8u, /* never emits a response */
    });
    if (proto)
        proto->owned_wire = wire;
    else
        duct_wire_destroy(wire);
    duct_do_if(!proto, fprintf(stderr, "bench_recv: proto create failed\n");
                       duct_engine_destroy(s_engine); return 1);

    const duct_proto_t *protos[1] = { proto };
    uint16_t port = 0u;
    duct_do_if(duct_listener_bind(s_engine, &(duct_listener_cfg_t){ .kind = listener_dgram,
                   .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
               }, &port, nullptr, 0u, nullptr) != rc_ok,
        fprintf(stderr, "bench_recv: bind failed\n");
        duct_engine_destroy(s_engine); duct_proto_destroy(proto); return 1);

    duct_sock_t fd = uc_connect(port);
    duct_do_if(fd == duct_sock_bad, fprintf(stderr, "bench_recv: client connect failed\n");
        duct_engine_destroy(s_engine); duct_proto_destroy(proto); return 1);

    pthread_t engine_th;
    duct_do_if(pthread_create(&engine_th, nullptr, th_run, s_engine) != 0,
        fprintf(stderr, "bench_recv: engine thread create failed\n");
        close(fd); duct_engine_destroy(s_engine); duct_proto_destroy(proto); return 1);

    record_t boot = { .header = { .seq_id = record_seq_control } };
    s_send_rec(fd, &boot, s_lead(&cfg));
    if (!th_wait_int(&s_session_open, 1, 2000))
        fprintf(stderr, "bench_recv: session never opened\n");

    printf("bench_recv: count=%llu io=cpu0 worker=cpu1 bench=cpu%u,%u wire=%s\n\n",
           (unsigned long long)cfg.count, bench_cpu_base, bench_cpu_base + 1u,
           cfg.framed_max ? "framed" : "dgram-batch");
    for (unsigned r = 0u; r < cfg.n_rates; ++r)
        s_run_one(&cfg, cfg.rates[r], fd);

    duct_engine_stop(s_engine);
    pthread_join(engine_th, nullptr);
    close(fd);
    duct_engine_destroy(s_engine);
    duct_proto_destroy(proto);
    free(s_samples.total);
    free(s_ring_storage);
    return 0;
}
