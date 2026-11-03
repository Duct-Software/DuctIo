/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file timer_test.c
 * @brief Declarative @c control.timer fire-precision coverage: one-shot
 * (several concurrent sessions), repeating with delay_ms != interval_ms
 * (regression for the delay/interval conflation @ref duct_timer_add once
 * had), and a 1ms-interval scenario at the exact floor @ref
 * duct_timers_due_soon exists to skip-wait for.
 *
 * Drives a real @ref duct_engine_launch engine over a real TCP loopback
 * connection, exactly like control_test.c's T1/T2 — @c on_session_open
 * arms the timer, @c on_timer records @ref duct_time_now() into a plain
 * array. Only that measurement (matching the library's own clock source
 * for an apples-to-apples delta) reaches into src/include; the engine,
 * wire and worker driving the timer are the real production path, not a
 * hand-rolled drain loop.
 */

#include "duct.h"
#include "test_helpers.h"

#include "duct_time.h"
#include "duct_timer.h"

#include <assert.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>

static uint16_t th_port = 0;

static int64_t s_diff_us(struct timespec a, struct timespec b)
{
    return duct_time_diff_ns(a, b) / 1000;
}

/* ------------------------------------------------------------------ */
/* Scenario A: one-shot fire precision, several concurrent sessions.  */

static constexpr unsigned s_oneshot_n = 5u;
static constexpr uint64_t s_oneshot_delay_ms[s_oneshot_n] = { 3u, 6u, 9u, 12u, 15u };

static atomic_uint    g_oneshot_idx = 0u;
static struct timespec g_oneshot_open_at[s_oneshot_n];
static struct timespec g_oneshot_fired_at[s_oneshot_n];
static atomic_int      g_oneshot_fired[s_oneshot_n];

static void s_oneshot_reset(void)
{
    duct_atomic_store(&g_oneshot_idx, 0u, seq_cst);
    for (unsigned i = 0u; i < s_oneshot_n; ++i)
        duct_atomic_store(&g_oneshot_fired[i], 0, seq_cst);
}

static duct_result_t
a_open([[maybe_unused]] duct_session_t *s,
       [[maybe_unused]] duct_handle_t tok,
       [[maybe_unused]] void *user_ctx,
       duct_response_t *out,
       [[maybe_unused]] void *proto_state)
{
    unsigned i = duct_atomic_fetch(add, &g_oneshot_idx, 1u, relaxed);
    if (i >= s_oneshot_n)
        return rc_ok;
    g_oneshot_open_at[i] = duct_time_now();
    out->control.timer.delay_ms = s_oneshot_delay_ms[i];
    out->control.timer.arg = i;
    return rc_ok;
}

static duct_result_t
a_timer([[maybe_unused]] duct_session_t *s,
        [[maybe_unused]] duct_response_t *out,
        [[maybe_unused]] void *proto_state,
        uint64_t arg)
{
    unsigned i = (unsigned)arg;
    if (i >= s_oneshot_n)
        return rc_ok;
    g_oneshot_fired_at[i] = duct_time_now();
    duct_atomic_store(&g_oneshot_fired[i], 1, release);
    return rc_ok;
}

static const char *test_oneshot(void)
{
    s_oneshot_reset();
    duct_sock_t fds[s_oneshot_n];
    for (unsigned i = 0u; i < s_oneshot_n; ++i) {
        fds[i] = th_connect(th_port);
        if (fds[i] == duct_sock_bad) return "connect failed";
    }

    for (unsigned i = 0u; i < s_oneshot_n; ++i)
        if (!th_wait_int(&g_oneshot_fired[i], 1, 1000u)) return "timer did not fire";

    for (unsigned i = 0u; i < s_oneshot_n; ++i)
        close(fds[i]);

    int64_t sum_jitter_us = 0,
            max_jitter_us = 0;
    for (unsigned i = 0u; i < s_oneshot_n; ++i) {
        auto ideal = duct_time_add(g_oneshot_open_at[i],
            duct_time_from_us(s_oneshot_delay_ms[i] * 1000u));
        int64_t j = s_diff_us(g_oneshot_fired_at[i], ideal);
        /* duct_timers_drain_at fires within [deadline - coalesce_us,
         * deadline + late]; per-sample upper bound is a hang-catcher
         * only, the average is the real precision signal. */
        if (j < -(int64_t)duct_timer_coalesce_us - 500) return "fired too early";
        if (j > 3000000) return "fired absurdly late (hang?)";
        sum_jitter_us += j;
        if (j > max_jitter_us) max_jitter_us = j;
    }
    int64_t avg_jitter_us = sum_jitter_us / (int64_t)s_oneshot_n;
    printf("  oneshot: n=%u avg_jitter_us=%lld max_jitter_us=%lld\n",
          s_oneshot_n, (long long)avg_jitter_us, (long long)max_jitter_us);
    if (avg_jitter_us >= 50000) return "avg jitter too high";
    return nullptr;
}

/* ------------------------------------------------------------------ */
/* Scenario B: repeating timer, delay_ms != interval_ms — regression   */
/* for duct_timer_add's own delay/interval conflation bug. Self-cancel */
/* after s_repeat_want fires (declarative repeat is otherwise          */
/* unbounded — see duct_worker.c's control.timer handling).            */

static constexpr unsigned s_repeat_want = 6u;
static constexpr uint64_t b_delay_ms = 8u;
static constexpr uint64_t b_interval_ms = 23u;

static atomic_int      g_repeat_count = 0;
static _Atomic(uint64_t) g_repeat_id = 0;
static struct timespec g_repeat_open_at;
static struct timespec g_repeat_fire_at[s_repeat_want];

static duct_result_t
b_open([[maybe_unused]] duct_session_t *s,
       [[maybe_unused]] duct_handle_t tok,
       [[maybe_unused]] void *user_ctx,
       duct_response_t *out,
       [[maybe_unused]] void *proto_state)
{
    g_repeat_open_at = duct_time_now();
    out->control.timer.delay_ms = b_delay_ms;
    out->control.timer.interval_ms = b_interval_ms;
    out->control.timer.id_out = (duct_timer_id_t *)&g_repeat_id;
    return rc_ok;
}

static duct_result_t
b_timer([[maybe_unused]] duct_session_t *s,
        duct_response_t *out,
        [[maybe_unused]] void *proto_state,
        [[maybe_unused]] uint64_t arg)
{
    int idx = duct_atomic_load(&g_repeat_count, relaxed);
    if (idx < (int)s_repeat_want)
        g_repeat_fire_at[idx] = duct_time_now();
    int n = duct_atomic_fetch(add, &g_repeat_count, 1, release) + 1;
    if (n == (int)s_repeat_want)
        out->control.timer.cancel_id =
            (duct_timer_id_t)duct_atomic_load(&g_repeat_id, seq_cst);
    return rc_ok;
}

static const char *test_repeat(void)
{
    duct_atomic_store(&g_repeat_count, 0, seq_cst);
    duct_atomic_store(&g_repeat_id, 0, seq_cst);

    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    for (unsigned waited = 0u; waited < 2000u; waited += 10u) {
        if (duct_atomic_load(&g_repeat_count, acquire) >= (int)s_repeat_want) break;
        th_sleep_ms(10u);
    }
    close(fd);
    /* Margin: if cancel-during-exec were broken, one more fire would
     * land within interval_ms + slack. */
    th_sleep_ms((unsigned)b_interval_ms + 100u);

    if (duct_atomic_load(&g_repeat_count, seq_cst) != (int)s_repeat_want)
        return "count != want (cancel-during-exec failed, or under-fired)";

    int64_t max_abs_jitter_us = 0,
            sum_abs_jitter_us = 0;
    for (unsigned i = 0u; i < s_repeat_want; ++i) {
        auto ideal = duct_time_add(g_repeat_open_at,
            duct_time_from_us((b_delay_ms + (uint64_t)i * b_interval_ms) * 1000u));
        int64_t j = s_diff_us(g_repeat_fire_at[i], ideal);
        printf("  repeat: fire[%u] jitter_us=%lld\n", i, (long long)j);
        if (j < -(int64_t)duct_timer_coalesce_us - 500) return "fired too early";
        if (j > 3000000) return "fired absurdly late (hang?)";
        int64_t aj = j < 0 ? -j : j;
        sum_abs_jitter_us += aj;
        if (aj > max_abs_jitter_us) max_abs_jitter_us = aj;
    }
    int64_t avg_abs_jitter_us = sum_abs_jitter_us / (int64_t)s_repeat_want;
    printf("  repeat: avg_abs_jitter_us=%lld max_abs_jitter_us=%lld\n",
          (long long)avg_abs_jitter_us, (long long)max_abs_jitter_us);
    if (avg_abs_jitter_us >= 50000) return "avg jitter too high";
    return nullptr;
}

/* ------------------------------------------------------------------ */
/* Scenario C: interval_ms == 1, the exact floor duct_timers_due_soon  */
/* exists for — duct_deadline_to_ms_at can never express less than    */
/* 1ms, so before that fix every fire in this scenario paid a full    */
/* blocking-wait's worth of latency instead of the worker catching it */
/* promptly. Self-cancel after s_fast_want fires.                     */

static constexpr unsigned s_fast_want = 100u;
static constexpr uint64_t c_delay_ms = 1u;
static constexpr uint64_t c_interval_ms = 1u;

static atomic_int      g_fast_count = 0;
static _Atomic(uint64_t) g_fast_id = 0;
static struct timespec g_fast_open_at;
static struct timespec g_fast_fire_at[s_fast_want];

static duct_result_t
c_open([[maybe_unused]] duct_session_t *s,
       [[maybe_unused]] duct_handle_t tok,
       [[maybe_unused]] void *user_ctx,
       duct_response_t *out,
       [[maybe_unused]] void *proto_state)
{
    g_fast_open_at = duct_time_now();
    out->control.timer.delay_ms = c_delay_ms;
    out->control.timer.interval_ms = c_interval_ms;
    out->control.timer.id_out = (duct_timer_id_t *)&g_fast_id;
    return rc_ok;
}

static duct_result_t
c_timer([[maybe_unused]] duct_session_t *s,
        duct_response_t *out,
        [[maybe_unused]] void *proto_state,
        [[maybe_unused]] uint64_t arg)
{
    int idx = duct_atomic_load(&g_fast_count, relaxed);
    if (idx < (int)s_fast_want)
        g_fast_fire_at[idx] = duct_time_now();
    int n = duct_atomic_fetch(add, &g_fast_count, 1, release) + 1;
    if (n == (int)s_fast_want)
        out->control.timer.cancel_id =
            (duct_timer_id_t)duct_atomic_load(&g_fast_id, seq_cst);
    return rc_ok;
}

static const char *test_fast_repeat(void)
{
    duct_atomic_store(&g_fast_count, 0, seq_cst);
    duct_atomic_store(&g_fast_id, 0, seq_cst);

    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    for (unsigned waited = 0u; waited < 5000u; waited += 10u) {
        if (duct_atomic_load(&g_fast_count, acquire) >= (int)s_fast_want) break;
        th_sleep_ms(10u);
    }
    close(fd);
    th_sleep_ms((unsigned)c_interval_ms + 50u);

    if (duct_atomic_load(&g_fast_count, seq_cst) != (int)s_fast_want)
        return "count != want (cancel-during-exec failed, or under-fired)";

    int64_t sum_jitter_us = 0,
            max_jitter_us = 0,
            min_jitter_us = INT64_MAX;
    for (unsigned i = 0u; i < s_fast_want; ++i) {
        auto ideal = duct_time_add(g_fast_open_at,
            duct_time_from_us((c_delay_ms + (uint64_t)i * c_interval_ms) * 1000u));
        int64_t j = s_diff_us(g_fast_fire_at[i], ideal);
        if (j < -(int64_t)duct_timer_coalesce_us - 500) return "fired too early";
        if (j > 3000000) return "fired absurdly late (hang?)";
        sum_jitter_us += j;
        if (j > max_jitter_us) max_jitter_us = j;
        if (j < min_jitter_us) min_jitter_us = j;
    }
    int64_t avg_jitter_us = sum_jitter_us / (int64_t)s_fast_want;
    printf("  fast_repeat(interval=%llums): n=%u jitter_us[min=%lld avg=%lld max=%lld]\n",
          (unsigned long long)c_interval_ms, s_fast_want,
          (long long)min_jitter_us, (long long)avg_jitter_us, (long long)max_jitter_us);
    /* Regression guard for duct_timers_due_soon: without it, every fire
     * here pays a real wait-primitive block instead of the worker
     * catching a due-soon deadline via relax-spin, which on a stock
     * (no timeBeginPeriod) Windows box alone can be tens of ms per
     * fire. This bound is a meaningful multiple of the 1ms grid, not a
     * hard latency SLA. */
    if (avg_jitter_us >= 20000) return "avg jitter too high (due_soon skip-wait regressed?)";
    return nullptr;
}

/* ------------------------------------------------------------------ */
/* Unified test table — one engine per entry, same shape as control_test.c. */

typedef const char *(*test_fn)(void);

typedef struct {
    const char           *name;
    test_fn                fn;
    duct_session_open_fn   open;
    duct_timer_fn          timer;
} test_entry;

static duct_result_t
t_empty_frame([[maybe_unused]] duct_session_t *s,
              [[maybe_unused]] duct_conn_id_t conn_id,
              [[maybe_unused]] const duct_frame_t *frame,
              [[maybe_unused]] duct_response_t *out,
              [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

static test_entry s_tests[] = {
    { "oneshot",     test_oneshot,     .open = a_open, .timer = a_timer },
    { "repeat",      test_repeat,      .open = b_open, .timer = b_timer },
    { "fast_repeat", test_fast_repeat, .open = c_open, .timer = c_timer },
};

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    int pass = 1;

    for (unsigned t = 0u; t < sizeof(s_tests) / sizeof(s_tests[0]); ++t) {
        auto e = &s_tests[t];
        auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
        if (!io) { fprintf(stderr, "timer: %s: engine launch failed\n", e->name); pass = 0; continue; }
        auto wire = duct_wire_create_length_prefix(0u);
        if (!wire) { duct_engine_destroy(io); pass = 0; continue; }

        auto proto = duct_proto_create(&(duct_proto_cfg_t){
            .name = "timer-test", .wire = wire,
            .on_frame = t_empty_frame,
            .on_session_open = e->open,
            .on_timer = e->timer,
        });
        if (!proto) { duct_engine_destroy(io); duct_wire_destroy(wire); pass = 0; continue; }

        th_port = 0;
        if (duct_io_listen(io, "127.0.0.1", &th_port, proto) != rc_ok) {
            duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(wire);
            pass = 0; continue;
        }
        pthread_t th;
        if (pthread_create(&th, nullptr, th_run, io) != 0) {
            duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(wire);
            pass = 0; continue;
        }

        const char *err = e->fn();

        duct_engine_stop(io);
        pthread_join(th, nullptr);
        /* Engine first: duct_proto_destroy's own contract is "after the
         * runtime has stopped borrowing it" — duct_engine_destroy's own
         * shutdown-reclaim sweep can still touch proto for a session this
         * test never waited to close explicitly. */
        duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(wire);

        if (err) { fprintf(stderr, "timer: %s: FAIL: %s\n", e->name, err); pass = 0; }
        else printf("timer: %s: OK\n", e->name);
    }
    return pass ? 0 : 1;
}
