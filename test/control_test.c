/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file control_test.c
 * @brief Declarative control litmus tests.
 *
 *   T1  timer_decl_on_open      — on_session_open sets control.timer → on_timer fires
 *   T2  timer_repeating_cancel  — native repeating + self-cancel from on_timer (cancel-during-exec)
 *   T3  timer_cancel            — cancel_id from on_frame prevents a timer from firing
 *   T4  r8_defer_no_control     — rc_defer: RX not advanced, control not applied
 *   T5  rx_pause_resume         — rx_op_pause stops reads; rx_op_resume wakes
 *   T6  close_send_then_close   — payload sent before session close walks
 *   T7  drop_no_ack_no_control  — rc_drop: bytes consumed, no response/close/control
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>

static uint16_t th_port = 0;

/* ── Atomic counters ─────────────────────────────────────────────── */

static atomic_int g_open_count      = 0;
static atomic_int g_timer_count     = 0;
static atomic_int g_frame_count     = 0;
static atomic_int g_close_count     = 0;
static atomic_int g_bad_timer_count = 0;
static atomic_int g_defer_phase     = 0;
static atomic_int g_t5_phase        = 0;

static atomic_uint_fast64_t g_last_timer_token = 0;
static _Atomic(uint64_t)   g_timer_id          = 0;

static void s_counters_reset(void)
{
    duct_atomic_store(&g_open_count, 0, seq_cst);
    duct_atomic_store(&g_timer_count, 0, seq_cst);
    duct_atomic_store(&g_frame_count, 0, seq_cst);
    duct_atomic_store(&g_close_count, 0, seq_cst);
    duct_atomic_store(&g_bad_timer_count, 0, seq_cst);
    duct_atomic_store(&g_defer_phase, 0, seq_cst);
    duct_atomic_store(&g_t5_phase, 0, seq_cst);
    duct_atomic_store(&g_last_timer_token, 0, seq_cst);
    duct_atomic_store(&g_timer_id, 0, seq_cst);
}

static duct_result_t
t_empty_frame([[maybe_unused]] duct_session_t *s,
              [[maybe_unused]] duct_conn_id_t conn_id,
              [[maybe_unused]] const duct_frame_t *frame,
              [[maybe_unused]] duct_response_t *out,
              [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

/* ── T1: timer_decl_on_open ─────────────────────────────────────── */

static duct_result_t
t1_open([[maybe_unused]] duct_session_t *s,
        [[maybe_unused]] duct_handle_t tok,
        [[maybe_unused]] void *user_ctx,
        duct_response_t *out,
        [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_open_count, 1, relaxed);
    out->control.timer.delay_ms = 50u;
    out->control.timer.arg = 0xABCDu;
    out->control.timer.id_out = (duct_timer_id_t *)&g_timer_id;
    return rc_ok;
}

static duct_result_t
t1_timer([[maybe_unused]] duct_session_t *s,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state,
         uint64_t arg)
{
    duct_atomic_fetch(add, &g_timer_count, 1, release);
    duct_atomic_store(&g_last_timer_token, arg, relaxed);
    static const uint8_t ping[] = "ping";
    *out = (duct_response_t){
        .payload = { .data = (void *)ping, .size = sizeof(ping) - 1u },
        .flags = fl_send_copy,
        .conn_id = duct_conn_id_same,
        .stream_id = duct_stream_id_same,
    };
    return rc_ok;
}

static const char *test_timer_decl_on_open(void)
{
    s_counters_reset();
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    if (th_recv_eq(fd, "ping", 4u) != 0) { close(fd); return "no ping"; }
    close(fd);
    struct timespec ts = { .tv_nsec = 200L * 1000L * 1000L };
    nanosleep(&ts, nullptr);

    if (duct_atomic_load(&g_timer_count, seq_cst) != 1) return "timer_count != 1";
    if (duct_atomic_load(&g_last_timer_token, seq_cst) != 0xABCDu) return "token wrong";
    if (duct_atomic_load(&g_timer_id, seq_cst) == 0) return "timer_id not filled";
    return nullptr;
}

/* ── T2: timer_repeating_cancel (native repeating + self-cancel) ── */

static duct_result_t
t2_open([[maybe_unused]] duct_session_t *s,
        [[maybe_unused]] duct_handle_t tok,
        [[maybe_unused]] void *user_ctx,
        duct_response_t *out,
        [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_open_count, 1, relaxed);
    out->control.timer.delay_ms = 40u;
    out->control.timer.interval_ms = 40u;
    out->control.timer.arg = 1u;
    out->control.timer.id_out = (duct_timer_id_t *)&g_timer_id;
    return rc_ok;
}

static duct_result_t
t2_timer([[maybe_unused]] duct_session_t *s,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state,
         uint64_t arg)
{
    int n = duct_atomic_fetch(add, &g_timer_count, 1, release) + 1;
    duct_atomic_store(&g_last_timer_token, arg, relaxed);
    static const uint8_t ping[] = "ping";
    out->payload = duct_view(duct_view_u8, (void *)ping, sizeof(ping) - 1u);
    out->flags = fl_send_copy;
    out->conn_id = duct_conn_id_same;
    out->stream_id = duct_stream_id_same;

    if (n == 3 && arg == 1u) {
        /* Self-cancel: exercises cancel-during-exec path (drain detects
         * hh.pprev==NULL and frees the node instead of reinserting). */
        out->control.timer.cancel_id = (duct_timer_id_t)duct_atomic_load(&g_timer_id, seq_cst);
    }
    if (n == 4 && arg == 1u) {
        /* After cancel, this is the drain's cleanup fire (arg already freed).
         * Should never reach here because cancel-during-exec frees arg. */
        duct_atomic_fetch(add, &g_bad_timer_count, 1, relaxed);
    }
    return rc_ok;
}

static const char *test_timer_repeating_cancel(void)
{
    s_counters_reset();
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    /* Receive 3 pings from the repeating timer. */
    for (int i = 0; i < 3; ++i) {
        if (th_recv_eq(fd, "ping", 4u) != 0) { close(fd); return "missing ping"; }
    }
    close(fd);

    /* Wait long enough that the cancelled timer would have fired again
     * if cancel didn't work. 40ms interval × 3 fires + margin. */
    struct timespec ts = { .tv_nsec = 250L * 1000L * 1000L };
    nanosleep(&ts, nullptr);

    if (duct_atomic_load(&g_timer_count, seq_cst) != 3)
        return "timer_count != 3 (cancel-during-exec failed)";
    if (duct_atomic_load(&g_last_timer_token, seq_cst) != 1u)
        return "last token != 1";
    if (duct_atomic_load(&g_bad_timer_count, seq_cst) != 0)
        return "timer fired after cancel";
    return nullptr;
}

/* ── T3: timer_cancel (from on_frame) ──────────────────────────── */

static duct_result_t
t3_open([[maybe_unused]] duct_session_t *s,
        [[maybe_unused]] duct_handle_t tok,
        [[maybe_unused]] void *user_ctx,
        duct_response_t *out,
        [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_open_count, 1, relaxed);
    out->control.timer.delay_ms = 200u;
    out->control.timer.arg = 7u;
    out->control.timer.id_out = (duct_timer_id_t *)&g_timer_id;
    return rc_ok;
}

static duct_result_t
t3_frame([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    out->control.timer.delay_ms = 20u;
    out->control.timer.arg = 99u;
    out->control.timer.cancel_id = (duct_timer_id_t)duct_atomic_load(&g_timer_id, seq_cst);
    return rc_ok;
}

static duct_result_t
t3_timer([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_response_t *out,
         [[maybe_unused]] void *proto_state,
         uint64_t arg)
{
    duct_atomic_fetch(add, &g_timer_count, 1, release);
    duct_atomic_store(&g_last_timer_token, arg, relaxed);
    return rc_ok;
}

static const char *test_timer_cancel(void)
{
    s_counters_reset();
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    if (th_send(fd, "go", 2u) != 0) { close(fd); return "send failed"; }
    if (th_recv_eq(fd, "go", 2u) != 0) { close(fd); return "no echo"; }

    struct timespec ts = { .tv_nsec = 400L * 1000L * 1000L };
    nanosleep(&ts, nullptr);
    close(fd);
    ts.tv_nsec = 100L * 1000L * 1000L;
    nanosleep(&ts, nullptr);

    if (duct_atomic_load(&g_timer_count, seq_cst) != 1) return "timer_count != 1";
    if (duct_atomic_load(&g_last_timer_token, seq_cst) != 99u) return "last token != 99";
    return nullptr;
}

/* ── T4: r8_defer_no_control ───────────────────────────────────── */

static duct_result_t
t4_open([[maybe_unused]] duct_session_t *s,
        [[maybe_unused]] duct_handle_t tok,
        [[maybe_unused]] void *user_ctx,
        duct_response_t *out,
        [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_open_count, 1, relaxed);
    out->control.timer.delay_ms = 40u;
    out->control.timer.arg = 0xF0u;
    return rc_ok;
}

static duct_result_t
t4_frame([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    int phase = duct_atomic_fetch(add, &g_defer_phase, 1, relaxed);
    if (phase == 0) {
        out->control.timer.delay_ms = 500u;
        out->control.timer.arg = 0xBADu;
        return rc_defer;
    }
    duct_response_echo(out, frame);
    return rc_ok;
}

static duct_result_t
t4_timer([[maybe_unused]] duct_session_t *s,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state,
         uint64_t arg)
{
    if (arg == 0xBADu) {
        duct_atomic_fetch(add, &g_bad_timer_count, 1, relaxed);
        return rc_ok;
    }
    duct_atomic_fetch(add, &g_timer_count, 1, release);
    duct_atomic_store(&g_last_timer_token, arg, relaxed);
    if (duct_atomic_load(&g_timer_count, seq_cst) < 3) {
        out->control.timer.delay_ms = 40u;
        out->control.timer.arg = 0xF0u;
    }
    return rc_ok;
}

static const char *test_r8_defer_no_control(void)
{
    s_counters_reset();
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    if (th_send(fd, "r8", 2u) != 0) { close(fd); return "send failed"; }
    if (th_recv_eq(fd, "r8", 2u) != 0) { close(fd); return "no echo (defer broken)"; }

    /* 250ms: enough for 3 fires at 40ms intervals + margin. */
    struct timespec ts = { .tv_nsec = 250L * 1000L * 1000L };
    nanosleep(&ts, nullptr);
    close(fd);
    ts.tv_nsec = 100L * 1000L * 1000L;
    nanosleep(&ts, nullptr);

    if (duct_atomic_load(&g_bad_timer_count, seq_cst) != 0) return "decoy timer fired";
    if (duct_atomic_load(&g_timer_count, seq_cst) < 3) return "prior timer stalled";
    return nullptr;
}

/* ── T5: rx_pause_resume ───────────────────────────────────────── */

static duct_result_t
t5_open([[maybe_unused]] duct_session_t *s,
        [[maybe_unused]] duct_handle_t tok,
        [[maybe_unused]] void *user_ctx,
        [[maybe_unused]] duct_response_t *out,
        [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_open_count, 1, relaxed);
    return rc_ok;
}

static duct_result_t
t5_frame([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    int phase = duct_atomic_fetch(add, &g_t5_phase, 1, relaxed);
    duct_atomic_fetch(add, &g_frame_count, 1, relaxed);
    duct_response_echo(out, frame);
    if (phase == 0) {
        out->control.rx = rx_op_pause;
        /* Start resumer here — not in on_session_open — to avoid the race
         * where the timer fires before on_frame processes "a". */
        out->control.timer.delay_ms = 250u;
        out->control.timer.arg = 0x52u;
    }
    return rc_ok;
}

static duct_result_t
t5_timer([[maybe_unused]] duct_session_t *s,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state,
         [[maybe_unused]] uint64_t arg)
{
    duct_atomic_fetch(add, &g_timer_count, 1, release);
    out->control.rx = rx_op_resume;
    return rc_ok;
}

static const char *test_rx_pause_resume(void)
{
    s_counters_reset();
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    if (th_send(fd, "a", 1u) != 0) { close(fd); return "send a failed"; }
    if (th_recv_eq(fd, "a", 1u) != 0) { close(fd); return "no echo a"; }

    if (th_send(fd, "b", 1u) != 0) { close(fd); return "send b failed"; }
    /* 150ms: generous margin for CI load (pause window is 100ms). */
    if (th_recv_none(fd, 150) != 0) { close(fd); return "echo b too early (pause failed)"; }

    if (th_recv_eq(fd, "b", 1u) != 0) { close(fd); return "no echo b after resume"; }

    close(fd);
    struct timespec ts = { .tv_nsec = 200L * 1000L * 1000L };
    nanosleep(&ts, nullptr);

    if (duct_atomic_load(&g_frame_count, seq_cst) != 2) return "frame_count != 2";
    return nullptr;
}

/* ── T6: close_send_then_close ─────────────────────────────────── */

static duct_result_t
t6_frame([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_frame_count, 1, relaxed);
    duct_response_echo(out, frame);
    out->control.close_target = close_target_session;
    out->control.close_reason = close_normal;
    return rc_ok;
}

static void
t6_on_close([[maybe_unused]] duct_session_t *s,
            [[maybe_unused]] duct_close_reason_t reason,
            [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_close_count, 1, relaxed);
}

static const char *test_close_send_then_close(void)
{
    s_counters_reset();
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    if (th_send(fd, "bye", 3u) != 0) { close(fd); return "send failed"; }
    if (th_recv_eq(fd, "bye", 3u) != 0) { close(fd); return "no echo (close before TX)"; }

    char buf[64] = {};
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    if (poll(&pfd, 1, 2000) <= 0) { close(fd); return "no EOF after echo"; }
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n != 0) { close(fd); return "expected EOF, got data"; }
    close(fd);

    for (int waited = 0; waited < 1000; waited += 20) {
        if (duct_atomic_load(&g_close_count, seq_cst) >= 1) return nullptr;
        struct timespec ts = { .tv_nsec = 20L * 1000L * 1000L };
        nanosleep(&ts, nullptr);
    }
    return "on_session_close did not fire";
}

/* ── T7: drop_no_ack_no_control ────────────────────────────────── */

static duct_result_t
t7_frame([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    if (frame->payload.size == 4u &&
        memcmp(frame->payload.data, "drop", 4u) == 0) {
        out->control.timer.delay_ms = 500u;
        out->control.timer.arg = 0xBADu;
        out->control.close_target = close_target_session;
        return rc_drop;
    }
    duct_response_echo(out, frame);
    return rc_ok;
}

static duct_result_t
t7_timer([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_response_t *out,
         [[maybe_unused]] void *proto_state,
         uint64_t arg)
{
    if (arg == 0xBADu)
        duct_atomic_fetch(add, &g_bad_timer_count, 1, relaxed);
    return rc_ok;
}

static const char *test_drop_no_ack_no_control(void)
{
    s_counters_reset();
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    if (th_send(fd, "drop", 4u) != 0) { close(fd); return "send drop failed"; }
    if (th_recv_none(fd, 200) != 0) { close(fd); return "drop echoed"; }

    if (th_send(fd, "alive", 5u) != 0) { close(fd); return "send alive failed"; }
    if (th_recv_eq(fd, "alive", 5u) != 0) { close(fd); return "no echo alive"; }

    close(fd);
    struct timespec ts = { .tv_nsec = 200L * 1000L * 1000L };
    nanosleep(&ts, nullptr);

    if (duct_atomic_load(&g_bad_timer_count, seq_cst) != 0) return "decoy timer fired on drop";
    return nullptr;
}

/* ── Unified test table ─────────────────────────────────────────── */

typedef const char *(*test_fn)(void);

typedef struct {
    const char          *name;
    test_fn              fn;
    duct_session_open_fn open;
    duct_frame_fn        frame;
    duct_timer_fn        timer;
    duct_session_close_fn close;
} test_entry;

static test_entry s_tests[] = {
    { "timer_decl_on_open",    test_timer_decl_on_open,
      .open = t1_open, .frame = nullptr,    .timer = t1_timer,  .close = nullptr },
    { "timer_repeating_cancel", test_timer_repeating_cancel,
      .open = t2_open, .frame = nullptr,    .timer = t2_timer,  .close = nullptr },
    { "timer_cancel",          test_timer_cancel,
      .open = t3_open, .frame = t3_frame,   .timer = t3_timer,  .close = nullptr },
    { "close_send_then_close", test_close_send_then_close,
      .open = nullptr,  .frame = t6_frame,   .timer = nullptr,   .close = t6_on_close },
    { "drop_no_ack_no_control", test_drop_no_ack_no_control,
      .open = nullptr,  .frame = t7_frame,   .timer = t7_timer,  .close = nullptr },
    { "r8_defer_no_control",   test_r8_defer_no_control,
      .open = t4_open, .frame = t4_frame,   .timer = t4_timer,  .close = nullptr },
    { "rx_pause_resume",       test_rx_pause_resume,
      .open = t5_open, .frame = t5_frame,   .timer = t5_timer,  .close = nullptr },
};

/* ── Main ───────────────────────────────────────────────────────── */

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    int pass = 1;

    for (unsigned t = 0u; t < sizeof(s_tests) / sizeof(s_tests[0]); ++t) {
        auto e = &s_tests[t];
        auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
        if (!io) { fprintf(stderr, "control: %s: io failed\n", e->name); pass = 0; continue; }
        auto wire = duct_wire_create_length_prefix(0u);
        if (!wire) { duct_engine_destroy(io); pass = 0; continue; }

        auto proto = duct_proto_create(&(duct_proto_cfg_t){
            .name = "ctrl-test", .wire = wire,
            .on_frame = e->frame ? e->frame : t_empty_frame,
            .on_session_open = e->open,
            .on_session_close = e->close,
            .on_timer = e->timer,
        });
        if (!proto) { duct_engine_destroy(io); duct_wire_destroy(wire); pass = 0; continue; }

        th_port = 0;
        if (duct_io_listen(io, "127.0.0.1", &th_port, proto) != rc_ok) {
            duct_proto_destroy(proto); duct_engine_destroy(io); duct_wire_destroy(wire);
            pass = 0; continue;
        }
        pthread_t th;
        if (pthread_create(&th, nullptr, th_run, io) != 0) {
            duct_proto_destroy(proto); duct_engine_destroy(io); duct_wire_destroy(wire);
            pass = 0; continue;
        }

        const char *err = e->fn();

        duct_engine_stop(io);
        pthread_join(th, nullptr);
        duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(wire);

        if (err) { fprintf(stderr, "control: %s: FAIL: %s\n", e->name, err); pass = 0; }
        else printf("control: %s: OK\n", e->name);
    }
    return pass ? 0 : 1;
}
