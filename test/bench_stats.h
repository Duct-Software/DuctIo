/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file bench_stats.h
 * @brief Runtime benchmark counters and helpers.
 *
 * When DUCT_BENCH is defined (compile with -DDUCT_BENCH=1), the struct and
 * macros expand to real atomic counters.  Otherwise all ops are no-ops so the
 * production code path is untouched.
 *
 * Usage:
 *   1. Include this header in the benchmark TU.
 *   2. Define DUCT_BENCH_STATS before including (or pass -DDUCT_BENCH=1).
 *   3. Call bench_*_inc() from callbacks / hot paths.
 *   4. Call bench_print_*() to dump results.
 */

#ifndef DUCT_BENCH_STATS_H
#define DUCT_BENCH_STATS_H

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── Timing ─────────────────────────────────────────────────────── */

static inline uint64_t bench_ns_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* ── Stats struct ───────────────────────────────────────────────── */

typedef struct bench_stats {
    _Atomic(uint64_t) frames_rx;      /**< Server: frames received + dispatched. */
    _Atomic(uint64_t) frames_tx;      /**< Server: response frames staged. */
    _Atomic(uint64_t) bytes_rx;       /**< Server: payload bytes received. */
    _Atomic(uint64_t) bytes_tx;       /**< Server: payload bytes staged. */
    _Atomic(uint64_t) sessions_open;  /**< Server: on_session_open calls. */
    _Atomic(uint64_t) sessions_close; /**< Server: on_session_close calls. */
    _Atomic(uint64_t) errors;         /**< Server: on_error calls. */
} bench_stats_t;

static bench_stats_t g_bench;

static inline void bench_reset(void)
{
    duct_atomic_store(&g_bench.frames_rx, 0u, relaxed);
    duct_atomic_store(&g_bench.frames_tx, 0u, relaxed);
    duct_atomic_store(&g_bench.bytes_rx, 0u, relaxed);
    duct_atomic_store(&g_bench.bytes_tx, 0u, relaxed);
    duct_atomic_store(&g_bench.sessions_open, 0u, relaxed);
    duct_atomic_store(&g_bench.sessions_close, 0u, relaxed);
    duct_atomic_store(&g_bench.errors, 0u, relaxed);
}

static inline void bench_inc_frame_rx(size_t bytes)
{
    duct_atomic_fetch(add, &g_bench.frames_rx, 1u, relaxed);
    duct_atomic_fetch(add, &g_bench.bytes_rx, bytes, relaxed);
}

static inline void bench_inc_frame_tx(size_t bytes)
{
    duct_atomic_fetch(add, &g_bench.frames_tx, 1u, relaxed);
    duct_atomic_fetch(add, &g_bench.bytes_tx, bytes, relaxed);
}

static inline void bench_inc_session_open(void)
{
    duct_atomic_fetch(add, &g_bench.sessions_open, 1u, relaxed);
}

static inline void bench_inc_session_close(void)
{
    duct_atomic_fetch(add, &g_bench.sessions_close, 1u, relaxed);
}

static inline void bench_inc_error(void)
{
    duct_atomic_fetch(add, &g_bench.errors, 1u, relaxed);
}

/* ── Latency sampling ───────────────────────────────────────────── */

#ifndef BENCH_LATENCY_SAMPLES
#define BENCH_LATENCY_SAMPLES (1u << 16) /* 64K samples */
#endif

typedef struct bench_latency {
    uint64_t samples[BENCH_LATENCY_SAMPLES];
    _Atomic(uint32_t) idx;
} bench_latency_t;

static inline void bench_latency_record(bench_latency_t *lat, uint64_t ns)
{
    uint32_t i = duct_atomic_fetch(add, &lat->idx, 1u, relaxed);
    if (i < BENCH_LATENCY_SAMPLES)
        lat->samples[i] = ns;
}

static int bench_u64_cmp(const void *a, const void *b)
{
    uint64_t va = *(const uint64_t *)a, vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

static inline void bench_latency_print(bench_latency_t *lat, const char *label)
{
    uint32_t n = duct_atomic_load(&lat->idx, relaxed);
    if (n > BENCH_LATENCY_SAMPLES)
        n = BENCH_LATENCY_SAMPLES;
    if (n == 0) {
        printf("  %s: no samples\n", label);
        return;
    }
    qsort(lat->samples, n, sizeof(uint64_t), bench_u64_cmp);
    uint64_t p50 = lat->samples[n / 2];
    uint64_t p90 = lat->samples[(uint64_t)n * 90 / 100];
    uint64_t p99 = lat->samples[(uint64_t)n * 99 / 100];
    uint64_t pmax = lat->samples[n - 1];
    printf("  %s: n=%u  p50=%lu ns  p90=%lu ns  p99=%lu ns  max=%lu ns\n",
           label, n,
           (unsigned long)p50, (unsigned long)p90,
           (unsigned long)p99, (unsigned long)pmax);
}

/* ── Result printing ────────────────────────────────────────────── */

static inline void bench_print_throughput(const char *scenario,
                                          unsigned n_clients,
                                          unsigned frames_per_client,
                                          uint64_t elapsed_ns,
                                          uint64_t total_bytes)
{
    double sec = (double)elapsed_ns / 1e9;
    uint64_t total_frames = (uint64_t)n_clients * frames_per_client;
    double mfps = (double)total_frames / sec / 1e6;
    double mbps = (double)total_bytes / sec / (1024.0 * 1024.0);
    double ns_per = (double)elapsed_ns / (double)total_frames;

    printf("  %-28s  %u×%u frames  %.3fs  %7.2f Mf/s  %7.1f MB/s  %.0f ns/frame\n",
           scenario, n_clients, frames_per_client, sec, mfps, mbps, ns_per);
}

static inline void bench_print_server_stats(void)
{
    printf("  server: rx=%lu tx=%lu sessions=%lu/%lu errors=%lu\n",
           (unsigned long)duct_atomic_load(&g_bench.frames_rx, relaxed),
           (unsigned long)duct_atomic_load(&g_bench.frames_tx, relaxed),
           (unsigned long)duct_atomic_load(&g_bench.sessions_open, relaxed),
           (unsigned long)duct_atomic_load(&g_bench.sessions_close, relaxed),
           (unsigned long)duct_atomic_load(&g_bench.errors, relaxed));
}

#endif /* DUCT_BENCH_STATS_H */
