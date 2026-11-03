/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file bench_hops.c
 * @brief Ingress-architecture comparison: who reads the source ring.
 *
 * A producer thread publishes timestamped records into a ring shaped like the
 * harness's shared-memory transport and stamps t0 at publish. Three modes then
 * carry those records to a UDP peer, differing only in which thread reads the
 * ring:
 *
 *   a       host thread -> duct_io_inter_batch -> worker on_frame -> io -> sendto
 *   b       worker stackless stream handler polls the ring -> emit -> io -> sendto
 *   direct  one thread -> sendto, no engine (control)
 *
 * t0 is stamped by the producer in every mode, so t0 -> recv measures the same
 * span throughout and the modes are directly comparable. Rate is swept because
 * the worker and io busy-poll ramps decay on idle passes, so the same handoff
 * is a spin at high rate and a futex wake at low rate.
 */

#include "duct.h"
#include "duct_wire.h"
#include "duct_stream.h"
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
    #include <sys/time.h>
#endif

static inline uint64_t s_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/** @brief Process CPU time, user + kernel, across every thread. The spin
 *  budget trades this against wake latency, so it has to be on the same line
 *  as the percentiles or the trade stays an opinion. */
static uint64_t s_cpu_ns(void)
{
    duct_cpu_time_t cpu = duct_process_cpu();
    return cpu.user_ns + cpu.kernel_ns;
}

typedef enum { mode_a, mode_b, mode_direct } bench_mode_t;

/** @brief Record payload, sized like a compacted market-data message. */
typedef struct {
    uint64_t t0,
             t1,
             seq;
    uint8_t  pad[40];
} probe_t;

static constexpr uint64_t probe_seq_control = 0u;
static constexpr uint32_t ring_slots = 4096u;
static constexpr unsigned batch_max = 32u;

/** @brief Stream mode B's handler runs on. The built-in dgram-batch wire pins
 *  every frame to stream 0, and a handler is only ever created by a frame
 *  arriving on a non-zero stream, so the wire's parse is wrapped below purely
 *  to retag it. */
static constexpr duct_stream_id_t boot_stream_id = 1u;

/** @brief Engine thread layout, mirrored from duct_engine_cfg_t below: the
 *  runtime binds io thread i to cpu i and worker j to cpu io_threads + j, both
 *  unconditionally. The bench's own threads must therefore start past both,
 *  or they land on a core the engine already owns. */
static constexpr unsigned bench_io_threads = 1u;
static constexpr unsigned bench_workers = 1u;
static constexpr unsigned bench_cpu_base = bench_io_threads + bench_workers;

/** @brief Logical-CPU step between the bench's own threads. Windows numbers
 *  SMT siblings adjacently (0/1 are one core), so a stride of 1 puts two
 *  busy-poll threads on one core's execution ports; 2 keeps them on distinct
 *  cores. Overridable to measure exactly that. */
static unsigned s_cpu_stride = 1u;

static duct_result_t (*s_dgram_parse_inner)(const duct_wire_t *, duct_view_u8, duct_frame_t *,
                                            duct_wire_parser_t *, size_t *, size_t *);

static duct_result_t s_boot_parse(const duct_wire_t *self, duct_view_u8 input, duct_frame_t *out,
                                  duct_wire_parser_t *parser, size_t *consumed, size_t *needed)
{
    auto rc = s_dgram_parse_inner(self, input, out, parser, consumed, needed);
    if (rc == rc_ok)
        out->stream_id = boot_stream_id;
    return rc;
}

/** @brief Source ring: single producer, one consumer at a time, publish by
 *  release-storing the slot sequence — the harness ring's shape. */
typedef struct {
    _Atomic(uint64_t) seq;
    probe_t           p;
} slot_t;

static slot_t   s_ring[ring_slots];
static uint64_t s_read_idx;

static void s_ring_reset(void)
{
    for (uint32_t i = 0u; i < ring_slots; ++i)
        duct_atomic_store(&s_ring[i].seq, 0u, relaxed);
    s_read_idx = 0u;
}

static void s_ring_publish(uint64_t idx, const probe_t *p)
{
    auto slot = &s_ring[idx & (ring_slots - 1u)];
    slot->p = *p;
    duct_atomic_store(&slot->seq, idx + 1u, release);
}

/** @brief Take the next published record, if any. Consumer-side cursor is a
 *  plain local: exactly one thread consumes per run. */
static bool s_ring_take(probe_t *out)
{
    auto slot = &s_ring[s_read_idx & (ring_slots - 1u)];
    if (duct_atomic_load(&slot->seq, acquire) != s_read_idx + 1u)
        return false;
    *out = slot->p;
    ++s_read_idx;
    return true;
}

typedef struct {
    uint64_t *total;
    uint32_t  cap;
    _Atomic(uint32_t) n_total;
} samples_t;

static samples_t s_samples;
static _Atomic(duct_handle_t) s_tok;
static atomic_int s_join_count = 0;
static _Atomic(bool) s_reader_stop = false,
                     s_run_active = false;
static _Atomic(uint64_t) s_emitted = 0u,
                         s_max_seq = 0u;
static _Atomic(int) s_active_mode = 0;
static _Atomic(uint64_t) s_steps = 0u;
static duct_engine_t *s_engine;

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

static void s_print_pct(const char *label, uint32_t n)
{
    if (!n) {
        printf("  %-8s no samples\n", label);
        return;
    }
    qsort(s_samples.total, n, sizeof(uint64_t), s_u64_cmp);
    uint64_t sum = 0u;
    for (uint32_t i = 0u; i < n; ++i)
        sum += s_samples.total[i];
    printf("  %-8s n=%-7u mean=%-8llu p50=%-8llu p99=%-8llu p99.9=%-9llu p99.99=%-9llu max=%llu\n",
           label, n, (unsigned long long)(sum / n),
           (unsigned long long)s_samples.total[n / 2u],
           (unsigned long long)s_samples.total[(uint64_t)n * 99u / 100u],
           (unsigned long long)s_samples.total[(uint64_t)n * 999u / 1000u],
           (unsigned long long)s_samples.total[(uint64_t)n * 9999u / 10000u],
           (unsigned long long)s_samples.total[n - 1u]);
}

/** @brief Response payload storage. fl_send_copy stages after the callback
 *  returns, so a callback-local would already be dead. */
static _Thread_local probe_t s_out_probe;

static void s_fill_response(duct_response_t *out, const probe_t *p)
{
    s_out_probe = *p;
    s_out_probe.t1 = s_now_ns();
    *out = (duct_response_t){
        .payload = { .data = (void *)&s_out_probe, .size = sizeof s_out_probe },
        .flags = fl_send_copy,
        .conn_id = 0u,
        .stream_id = duct_stream_id_same,
        .control.stream_op_conn_id = duct_conn_id_same,
    };
}

static duct_result_t
on_session_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok,
                [[maybe_unused]] void *user_ctx, duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&s_tok, tok, release);
    out->control.open_leg.kind = leg_kind_inter;
    out->control.open_leg.conn_id = 1u;
    return rc_ok;
}

static duct_result_t
on_conn_join([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             [[maybe_unused]] const duct_peer_t *peer, [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &s_join_count, 1, relaxed);
    return rc_ok;
}

/* Mode A: the host thread already read the ring; this only forwards. */
static duct_result_t
on_frame_a([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
           const duct_frame_t *frame, duct_response_t *out,
           [[maybe_unused]] void *proto_state)
{
    duct_do_if(frame->payload.size != sizeof(probe_t), return rc_drop);
    probe_t p;
    memcpy(&p, frame->payload.data, sizeof p);
    if (p.seq == probe_seq_control)
        return rc_drop;
    duct_atomic_fetch(add, &s_emitted, 1u, relaxed);
    s_fill_response(out, &p);
    return rc_ok;
}

/** @brief Mode B: the worker's own poll step. Yields unconditionally so the
 *  coop cycle keeps re-entering it; an empty ring costs one acquire load. The
 *  handler is claimed once at startup and lives across every run, so it must
 *  stay off the ring while another mode owns it. */
static duct_async_rc_t s_poll_step(void *state)
{
    auto ctx = (duct_stream_ctx_t *)state;
    duct_atomic_fetch(add, &s_steps, 1u, relaxed);
    if (!duct_atomic_load(&s_run_active, acquire)
        || duct_atomic_load(&s_active_mode, acquire) != (int)mode_b)
        return async_yield;
    probe_t p;
    if (!s_ring_take(&p))
        return async_yield;
    duct_atomic_fetch(add, &s_emitted, 1u, relaxed);
    duct_response_t resp;
    s_fill_response(&resp, &p);
    duct_stream_emit_response(ctx, &resp);
    return async_yield;
}

static void s_on_host(void (*fn)(void *ctx), void *ctx, [[maybe_unused]] void *queue_ctx)
{
    fn(ctx);
}

typedef struct {
    uint64_t count;
    double   rates[8];
    unsigned n_rates;
    bench_mode_t   modes[3];
    unsigned n_modes;
} cfg_t;

static void s_pace(uint64_t deadline)
{
    while (s_now_ns() < deadline)
        ;
}

typedef struct {
    uint64_t count;
    double   rate;
    unsigned cpu;
} producer_arg_t;

static void *s_producer(void *arg)
{
    auto pa = (producer_arg_t *)arg;
    if (duct_thread_pinning) duct_discard duct_thread_bind_cpu(pa->cpu);
    uint64_t interval = pa->rate > 0.0 ? (uint64_t)(1e9 / pa->rate) : 0u,
             next = s_now_ns();
    probe_t p = {};
    for (uint64_t i = 1u; i <= pa->count; ++i) {
        if (interval) {
            s_pace(next);
            next += interval;
        }
        p.seq = i;
        p.t1 = 0u;
        p.t0 = s_now_ns();
        s_ring_publish(i - 1u, &p);
    }
    return nullptr;
}

typedef struct {
    duct_sock_t fd;
    unsigned cpu;
    bench_mode_t   mode;
    uint64_t count;
} ingress_arg_t;

/** @brief Mode A's reader of the ring: batches whatever is already published
 *  into one inter push, never waiting to fill a batch. */
static void *s_ingress_a(void *arg)
{
    auto ia = (ingress_arg_t *)arg;
    if (duct_thread_pinning) duct_discard duct_thread_bind_cpu(ia->cpu);
    alignas(8) char buf[duct_inter_batch_bytes(batch_max)];
    auto batch = (duct_inter_batch_t *)buf;
    probe_t staged[batch_max];
    duct_handle_t tok = duct_atomic_load(&s_tok, acquire);
    uint64_t seen = 0u;
    while (seen < ia->count && duct_atomic_load(&s_run_active, acquire)) {
        unsigned n = 0u;
        while (n < batch_max && s_ring_take(&staged[n]))
            ++n;
        if (!n)
            continue;
        batch->n = n;
        for (unsigned i = 0u; i < n; ++i)
            *duct_inter_batch_pkt(batch, i) = (duct_inter_pkt_t){
                .payload = { .data = (void *)&staged[i], .size = sizeof staged[i] },
                .stream_id = duct_stream_id_default, .flags = fl_frame_none,
            };
        duct_discard duct_io_inter_batch(s_engine, tok, 1u, batch);
        seen += n;
    }
    return nullptr;
}

/** @brief Control mode: one thread, ring to socket, no engine. */
static void *s_ingress_direct(void *arg)
{
    auto ia = (ingress_arg_t *)arg;
    if (duct_thread_pinning) duct_discard duct_thread_bind_cpu(ia->cpu);
    probe_t p;
    uint64_t seen = 0u;
    while (seen < ia->count && duct_atomic_load(&s_run_active, acquire)) {
        if (!s_ring_take(&p))
            continue;
        duct_discard send(ia->fd, (const char *)&p, (int)sizeof p, 0);
        ++seen;
    }
    return nullptr;
}

typedef struct {
    duct_sock_t fd;
    unsigned cpu;
} reader_arg_t;

/** @brief Bounded recv so the stop flag is observed without depending on a
 *  wake datagram the engine may legitimately not echo. */
static void s_set_rcvtimeo(duct_sock_t fd, unsigned ms)
{
#ifdef _WIN32
    DWORD tv = ms;
#else
    struct timeval tv = { .tv_sec = ms / 1000u, .tv_usec = (long)(ms % 1000u) * 1000L };
#endif
    duct_discard setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
}

static void *s_reader(void *arg)
{
    auto ra = (reader_arg_t *)arg;
    if (duct_thread_pinning) duct_discard duct_thread_bind_cpu(ra->cpu);
    s_set_rcvtimeo(ra->fd, 100u);
    probe_t p;
    while (!duct_atomic_load(&s_reader_stop, acquire)) {
        ssize_t got = recv(ra->fd, (char *)&p, (int)sizeof p, 0);
        uint64_t t2 = s_now_ns();
        if (got != (ssize_t)sizeof p || p.seq == probe_seq_control)
            continue;
        if (p.seq > duct_atomic_load(&s_max_seq, relaxed))
            duct_atomic_store(&s_max_seq, p.seq, relaxed);
        s_record(t2 - p.t0);
    }
    return nullptr;
}

static void s_grow_rcvbuf(duct_sock_t fd)
{
    int want = 8 * 1024 * 1024;
    duct_discard setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&want, sizeof want);
}

static duct_sock_t s_bind_loopback(uint16_t *out_port)
{
    duct_sock_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    duct_do_if(fd == duct_sock_bad, return duct_sock_bad);
    struct sockaddr_in addr = { .sin_family = AF_INET };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    duct_do_if(bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0, close(fd); return duct_sock_bad);
    socklen_t len = sizeof addr;
    duct_do_if(getsockname(fd, (struct sockaddr *)&addr, &len) != 0, close(fd); return duct_sock_bad);
    *out_port = ntohs(addr.sin_port);
    s_grow_rcvbuf(fd);
    return fd;
}

/** @brief Drain until @p want lands or the reader goes quiet: a fixed deadline
 *  would report everything still in flight as loss. */
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

static const char *s_mode_name(bench_mode_t m)
{
    return m == mode_a ? "a" : m == mode_b ? "b" : "direct";
}

#if DUCT_RUNTIME_STATS
static duct_worker_rt_t s_rt_base;

static void s_rt_mark(void)
{
    auto rt = duct_worker_rtstats(0u);
    if (rt)
        s_rt_base = *rt;
}

/** @brief Worker ramp state over the run: whether it ever reached spin mode,
 *  and how the idle passes split between spinning and parking. */
static void s_rt_dump(void)
{
    auto rt = duct_worker_rtstats(0u);
    if (!rt)
        return;
    uint64_t pass = rt->loop_pass - s_rt_base.loop_pass,
             spin = rt->busy_spin - s_rt_base.busy_spin,
             park = rt->futex_wait - s_rt_base.futex_wait,
             ent = rt->busy_enter - s_rt_base.busy_enter,
             ext = rt->busy_exit - s_rt_base.busy_exit;
    printf("  worker   pass=%llu spin=%llu park=%llu enter=%llu exit=%llu\n",
           (unsigned long long)pass, (unsigned long long)spin,
           (unsigned long long)park, (unsigned long long)ent,
           (unsigned long long)ext);
}
#else
static void s_rt_mark(void) {}
static void s_rt_dump(void) {}
#endif

static void s_run_one(bench_mode_t mode, duct_sock_t engine_fd, duct_sock_t ctl_tx,
                      duct_sock_t ctl_rx, const cfg_t *cfg, double rate)
{
    s_ring_reset();
    duct_atomic_store(&s_active_mode, (int)mode, release);
    duct_atomic_store(&s_samples.n_total, 0u, relaxed);
    duct_atomic_store(&s_max_seq, 0u, relaxed);
    duct_atomic_store(&s_emitted, 0u, relaxed);
    duct_atomic_store(&s_steps, 0u, relaxed);
    s_rt_mark();
    duct_atomic_store(&s_reader_stop, false, release);

    uint64_t cpu0 = s_cpu_ns(),
             wall0 = s_now_ns();
    duct_sock_t rx_fd = mode == mode_direct ? ctl_rx : engine_fd;
    reader_arg_t ra = { .fd = rx_fd, .cpu = bench_cpu_base + 2u * s_cpu_stride };
    pthread_t reader_th;
    duct_do_if(pthread_create(&reader_th, nullptr, s_reader, &ra) != 0,
        printf("  reader spawn failed\n"); return);

    duct_atomic_store(&s_run_active, true, release);
    ingress_arg_t ia = { .fd = ctl_tx, .cpu = bench_cpu_base + s_cpu_stride,
                         .mode = mode, .count = cfg->count };
    pthread_t ingress_th;
    bool has_ingress = mode != mode_b;
    if (has_ingress)
        duct_do_if(pthread_create(&ingress_th, nullptr,
                                  mode == mode_a ? s_ingress_a : s_ingress_direct, &ia) != 0,
            printf("  ingress spawn failed\n"); return);

    producer_arg_t pa = { .count = cfg->count, .rate = rate,
                          .cpu = bench_cpu_base };
    pthread_t producer_th;
    duct_do_if(pthread_create(&producer_th, nullptr, s_producer, &pa) != 0,
        printf("  producer spawn failed\n"); return);

    pthread_join(producer_th, nullptr);
    uint32_t landed = s_settle((uint32_t)cfg->count, 300u, 5000u);
    duct_atomic_store(&s_run_active, false, release);
    if (has_ingress)
        pthread_join(ingress_th, nullptr);

    duct_atomic_store(&s_reader_stop, true, release);
    pthread_join(reader_th, nullptr);
    uint64_t cpu_ns = s_cpu_ns() - cpu0,
             wall_ns = s_now_ns() - wall0;

    if (landed > s_samples.cap)
        landed = s_samples.cap;
    printf("%-6s rate=%-9.0f published=%llu emitted=%llu landed=%u top_seq=%llu steps=%llu\n",
           s_mode_name(mode), rate, (unsigned long long)cfg->count,
           (unsigned long long)duct_atomic_load(&s_emitted, relaxed), landed,
           (unsigned long long)duct_atomic_load(&s_max_seq, relaxed),
           (unsigned long long)duct_atomic_load(&s_steps, relaxed));
    /* cores = CPU time over wall time: how many cores this run kept busy. */
    printf("  cpu      %.2f us/msg  cores=%.2f  wall=%.0f ms\n",
           cfg->count ? (double)cpu_ns / 1000.0 / (double)cfg->count : 0.0,
           wall_ns ? (double)cpu_ns / (double)wall_ns : 0.0,
           (double)wall_ns / 1e6);
    if (mode != mode_direct)
        s_rt_dump();
    s_print_pct("t0->recv", landed);
}

static bool s_parse_args(int argc, char **argv, cfg_t *cfg)
{
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--count") && i + 1 < argc)
            cfg->count = strtoull(argv[++i], nullptr, 10);
        else if (!strcmp(argv[i], "--rate") && i + 1 < argc) {
            cfg->rates[0] = strtod(argv[++i], nullptr);
            cfg->n_rates = 1u;
        } else if (!strcmp(argv[i], "--mode") && i + 1 < argc) {
            auto v = argv[++i];
            cfg->n_modes = 1u;
            if (!strcmp(v, "a"))
                cfg->modes[0] = mode_a;
            else if (!strcmp(v, "b"))
                cfg->modes[0] = mode_b;
            else if (!strcmp(v, "direct"))
                cfg->modes[0] = mode_direct;
            else
                return false;
        } else if (!strcmp(argv[i], "--cpu-stride") && i + 1 < argc)
            s_cpu_stride = (unsigned)strtoul(argv[++i], nullptr, 10);
        else
            return false;
    }
    return true;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    cfg_t cfg = {
        .count = 200000u,
        .rates = { 10000.0, 50000.0, 200000.0, 1000000.0 },
        .n_rates = 4u,
        .modes = { mode_direct, mode_a, mode_b },
        .n_modes = 3u,
    };
    duct_do_if(!s_parse_args(argc, argv, &cfg),
        fprintf(stderr, "usage: %s [--count N] [--rate R] [--mode a|b|direct]\n", argv[0]);
        return 2);

    s_samples.cap = cfg.count > (1u << 20) ? (1u << 20) : (uint32_t)cfg.count;
    s_samples.total = (uint64_t *)calloc(s_samples.cap, sizeof(uint64_t));
    duct_do_if(!s_samples.total, fprintf(stderr, "bench_hops: alloc failed\n"); return 1);

    bool need_b = false;
    for (unsigned i = 0u; i < cfg.n_modes; ++i)
        need_b |= cfg.modes[i] == mode_b;

    s_engine = duct_engine_launch(&(duct_engine_cfg_t){
        .io_threads = bench_io_threads, .workers = bench_workers,
        .host = { .run = s_on_host },
    });
    duct_do_if(!s_engine, fprintf(stderr, "bench_hops: io create failed\n"); return 1);

    auto wire = duct_wire_create_dgram_batch(0u, false);
    duct_do_if(!wire, fprintf(stderr, "bench_hops: wire create failed\n");
                      duct_engine_destroy(s_engine); return 1);
    s_dgram_parse_inner = wire->on_parse;
    wire->on_parse = s_boot_parse;
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "bench_hops", .wire = wire,
        /* Stream 0 keeps on_frame (mode A); a non-zero stream reaches the
         * handler instead (mode B), so both coexist in one protocol. */
        .on_frame = on_frame_a,
        .on_session_open = on_session_open,
        .on_conn_join = on_conn_join,
        .handler_kind = need_b ? handler_async : handler_none,
        .handler_async = need_b ? s_poll_step : nullptr,
        /* Always multiplexed: the wrapped parse tags every inbound frame with
         * boot_stream_id, which a non-multiplexed proto would reject. */
        .flags = fl_proto_multiplexed,
        /* Admission reserves this per in-flight response regardless of the
         * actual size, so an oversized value shrinks TX OLB depth by the same
         * factor. Sized to the probe plus its record framing. */
        .max_response = 128u,
    });
    if (proto)
        proto->owned_wire = wire;
    else
        duct_wire_destroy(wire);
    duct_do_if(!proto, fprintf(stderr, "bench_hops: proto create failed\n");
                       duct_engine_destroy(s_engine); return 1);

    const duct_proto_t *protos[1] = { proto };
    uint16_t port = 0u;
    duct_do_if(duct_listener_bind(s_engine, &(duct_listener_cfg_t){ .kind = listener_dgram,
                   .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
               }, &port, nullptr, 0u, nullptr) != rc_ok,
        fprintf(stderr, "bench_hops: bind failed\n");
        duct_engine_destroy(s_engine); duct_proto_destroy(proto); return 1);

    duct_sock_t fd = uc_connect(port);
    duct_do_if(fd == duct_sock_bad, fprintf(stderr, "bench_hops: client connect failed\n");
        duct_engine_destroy(s_engine); duct_proto_destroy(proto); return 1);
    s_grow_rcvbuf(fd);

    pthread_t engine_th;
    duct_do_if(pthread_create(&engine_th, nullptr, th_run, s_engine) != 0,
        fprintf(stderr, "bench_hops: engine thread create failed\n");
        close(fd); duct_engine_destroy(s_engine); duct_proto_destroy(proto); return 1);

    probe_t boot = { .seq = probe_seq_control };
    duct_discard uc_send(fd, &boot, sizeof boot);
    if (!th_wait_int(&s_join_count, 1, 2000))
        fprintf(stderr, "bench_hops: inter leg never joined\n");

    /* The bootstrap datagram above already claims boot_stream_id and starts
     * mode B's handler; give the worker a moment to run that. */
    if (need_b)
        th_sleep_ms(50);

    uint16_t ctl_port = 0u;
    duct_sock_t ctl_rx = s_bind_loopback(&ctl_port);
    duct_sock_t ctl_tx = ctl_rx != duct_sock_bad ? uc_connect(ctl_port) : duct_sock_bad;
    duct_do_if(ctl_tx == duct_sock_bad, fprintf(stderr, "bench_hops: control socket failed\n"));

    printf("bench_hops: count=%llu io=cpu0 worker=cpu%u bench=cpu%u,%u,%u (stride %u)\n\n",
           (unsigned long long)cfg.count, bench_io_threads,
           bench_cpu_base, bench_cpu_base + s_cpu_stride,
           bench_cpu_base + 2u * s_cpu_stride, s_cpu_stride);
    for (unsigned r = 0u; r < cfg.n_rates; ++r) {
        for (unsigned m = 0u; m < cfg.n_modes; ++m)
            s_run_one(cfg.modes[m], fd, ctl_tx, ctl_rx, &cfg, cfg.rates[r]);
        printf("\n");
    }

    if (ctl_tx != duct_sock_bad)
        close(ctl_tx);
    if (ctl_rx != duct_sock_bad)
        close(ctl_rx);
    duct_engine_stop(s_engine);
    pthread_join(engine_th, nullptr);
    close(fd);
    duct_engine_destroy(s_engine);
    duct_proto_destroy(proto);
    free(s_samples.total);
    return 0;
}
