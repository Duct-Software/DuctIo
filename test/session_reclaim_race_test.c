/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file session_reclaim_race_test.c
 * @brief Multi-worker lifetime stress:
 *
 * One thread group opens a conn, sends a frame that the callback always
 * defers (`rc_defer`, never replayed away), then closes immediately. Its FIN
 * reaches the worker as the end of the conn's input, deferred behind that
 * frame, so the session's idle bound ends the leg instead — the conn-lost
 * consume must discard both defer nodes on the owner worker
 * before the session's `conn_count` reaches 0 and it becomes eligible for
 * closing → quarantine → free. A second thread group churns plain
 * echo conns concurrently across all workers, keeping every worker's idle
 * drain (`duct_session_idle_drain`) busy scanning the shared session table
 * while the held sessions transition through the reclaim gate. A third
 * thread group drives worker-initiated close: `on_frame` replies and
 * sets `close_target_session` itself, so `duct_session_close_walk` marks
 * `session_state_closing` and posts the I/O close while the leg is still
 * attached — the conn_lost fence must still detach it (the closing →
 * quarantine gate must not race ahead of that detach).
 *
 * Pass: no crash/UAF (the real assertion, verified by running this binary
 * under ASAN/TSAN), every opened session closes exactly once, and the
 * server still answers a plain echo after the storm.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>

static uint16_t th_port = 0;

static atomic_int s_open_count  = 0;
static atomic_int s_close_count = 0;

static duct_result_t
on_session_open([[maybe_unused]] duct_session_t *s,
                [[maybe_unused]] duct_handle_t tok,
                [[maybe_unused]] void *user_ctx,
                [[maybe_unused]] duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &s_open_count, 1, relaxed);
    return rc_ok;
}

static void
on_session_close([[maybe_unused]] duct_session_t *s,
                 [[maybe_unused]] duct_close_reason_t reason,
                 [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &s_close_count, 1, relaxed);
}

static const char hold_marker[] = "HOLD";
static const char close_marker[] = "CLOSE";

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    /* Every call for a HOLD-marked frame defers again: the only way it
     * leaves the worker's defer queue is duct_worker_conn_defer_discard on
     * conn-lost consume, never a normal replay. */
    if (frame->payload.size >= sizeof hold_marker - 1u &&
        memcmp(frame->payload.data, hold_marker, sizeof hold_marker - 1u) == 0)
        return rc_defer;
    duct_response_echo(out, frame);
    if (frame->payload.size == sizeof close_marker - 1u &&
        memcmp(frame->payload.data, close_marker, sizeof close_marker - 1u) == 0) {
        out->control.close_target = close_target_session;
        out->control.close_reason = close_normal;
    }
    return rc_ok;
}

/* A small duct_runtime_max_conns (wsaevent clamps it to 63 — see
 * os/windows/wsaevent/duct_events.c's own @file doc) means the 12 unthrottled
 * threads below can out-race conn-slot reclaim: a HOLD session in particular
 * lingers past a plain churn/close conn (conn-lost consume must discard its
 * defer node before the slot frees), so sustained concurrent pressure from
 * the full-size thread counts pins the pool near-exhausted for most of the
 * run instead of the occasional dip the 3/4 pass bar expects. Scale
 * concurrency down with the pool instead of loosening the pass bar — see
 * conn_churn_test.c's own identical guard. */
static constexpr bool     small_pool     = duct_runtime_max_conns < 256u;
static constexpr unsigned churn_threads  = small_pool ?   2u :   6u;
static constexpr unsigned churn_rounds   = small_pool ?  60u : 120u;
static constexpr unsigned hold_threads   = small_pool ?   1u :   3u;
static constexpr unsigned hold_rounds    = small_pool ?  40u :  80u;
static constexpr unsigned close_threads  = small_pool ?   1u :   3u;
static constexpr unsigned close_rounds   = small_pool ?  40u :  80u;
/* Long enough for a churn, close or probe session to deliver its first frame
 * under TSAN; a HOLD session, which never delivers one, ends this long after
 * its open. */
static constexpr uint32_t hold_idle_ms   = 1000u;

static void *s_churn_thread([[maybe_unused]] void *arg)
{
    for (unsigned i = 0u; i < churn_rounds; ++i) {
        duct_sock_t fd = th_connect(th_port);
        if (fd == duct_sock_bad)
            continue;
        static const char msg[] = "ping";
        if (th_send(fd, msg, sizeof msg - 1u) == 0)
            duct_discard th_recv_eq(fd, msg, sizeof msg - 1u);
        close(fd);
    }
    return nullptr;
}

static void *s_hold_thread([[maybe_unused]] void *arg)
{
    for (unsigned i = 0u; i < hold_rounds; ++i) {
        duct_sock_t fd = th_connect(th_port);
        if (fd == duct_sock_bad)
            continue;
        static const char msg[] = "HOLD-a-permanently-busy-handler-payload";
        duct_discard th_send(fd, msg, sizeof msg - 1u);
        /* No reply ever comes (on_frame always defers this marker); close
         * right away. The FIN waits behind the deferred frame, and the idle
         * bound's conn-lost races both still-queued defer nodes against
         * concurrent idle-drain of other sessions on every worker. */
        close(fd);
    }
    return nullptr;
}

static void *s_close_thread([[maybe_unused]] void *arg)
{
    for (unsigned i = 0u; i < close_rounds; ++i) {
        duct_sock_t fd = th_connect(th_port);
        if (fd == duct_sock_bad)
            continue;
        if (th_send(fd, close_marker, sizeof close_marker - 1u) == 0)
            duct_discard th_recv_eq(fd, close_marker, sizeof close_marker - 1u);
        /* Server closes after the echo (worker-initiated); drain the
         * fd instead of asserting EOF here — under heavy churn the response
         * may not have landed before this read, and that is not what this
         * thread group is stress-testing (session_reclaim_race covers the
         * plain respond-then-close contract in control_test). */
        char buf[64];
        while (read(fd, buf, sizeof buf) > 0)
            ;
        close(fd);
    }
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 2, .workers = 4 });
    if (!io) { fprintf(stderr, "session_reclaim_race: io create failed\n"); return 1; }

    auto wire = duct_wire_create_length_prefix(0u);
    if (!wire) { fprintf(stderr, "session_reclaim_race: wire create failed\n"); duct_engine_destroy(io); return 1; }
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "session-reclaim-race", .wire = wire,
        .on_frame = on_frame,
        .on_session_open = on_session_open,
        .on_session_close = on_session_close,
        .max_response = 4096u,
        .idle_timeout_ms = hold_idle_ms,
    });
    if (!proto) { fprintf(stderr, "session_reclaim_race: proto create failed\n"); duct_engine_destroy(io); duct_wire_destroy(wire); return 1; }

    if (duct_io_listen(io, "127.0.0.1", &th_port, proto) != rc_ok) {
        fprintf(stderr, "session_reclaim_race: listen failed\n");
        duct_proto_destroy(proto); duct_engine_destroy(io); duct_wire_destroy(wire);
        return 1;
    }
    pthread_t run_th;
    if (pthread_create(&run_th, nullptr, th_run, io) != 0) {
        fprintf(stderr, "session_reclaim_race: thread create failed\n");
        duct_proto_destroy(proto); duct_engine_destroy(io); duct_wire_destroy(wire);
        return 1;
    }

    pthread_t churn[churn_threads];
    for (unsigned i = 0u; i < churn_threads; ++i)
        pthread_create(&churn[i], nullptr, s_churn_thread, nullptr);
    pthread_t hold[hold_threads];
    for (unsigned i = 0u; i < hold_threads; ++i)
        pthread_create(&hold[i], nullptr, s_hold_thread, nullptr);
    pthread_t closer[close_threads];
    for (unsigned i = 0u; i < close_threads; ++i)
        pthread_create(&closer[i], nullptr, s_close_thread, nullptr);

    for (unsigned i = 0u; i < hold_threads; ++i)
        pthread_join(hold[i], nullptr);
    for (unsigned i = 0u; i < close_threads; ++i)
        pthread_join(closer[i], nullptr);
    for (unsigned i = 0u; i < churn_threads; ++i)
        pthread_join(churn[i], nullptr);

    /* Every bound session must close exactly once; conn-lost consume, the
     * last session_open control messages, and idle-drain reclaim all run
     * asynchronously on the worker threads after the client fds are gone,
     * so require open == close to hold for several consecutive samples
     * before declaring it settled — a single equal sample could be a
     * mid-flight coincidence while more opens are still landing. */
    int opened = 0,
        closed = 0;
    bool closed_up = false;
    /* Bound is generous (well beyond the ~2s a normal run needs) because
     * TSAN instrumentation on the full-table idle-drain scan adds enough
     * jitter to occasionally miss a tighter deadline without an actual
     * stuck session. */
    for (unsigned waited = 0u, stable = 0u; waited < 30000u; waited += 10u) {
        opened = duct_atomic_load(&s_open_count, acquire);
        closed = duct_atomic_load(&s_close_count, acquire);
        if (opened == closed) {
            if (++stable >= 5u) {
                closed_up = true;
                break;
            }
        } else
            stable = 0u;
        struct timespec ts = { .tv_nsec = 10L * 1000L * 1000L };
        nanosleep(&ts, nullptr);
    }

    int pass = 1;
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) {
        fprintf(stderr, "session_reclaim_race: final probe connect failed\n");
        pass = 0;
    } else {
        static const char probe[] = "still-alive";
        if (th_send(fd, probe, sizeof probe - 1u) != 0 ||
            th_recv_eq(fd, probe, sizeof probe - 1u) != 0) {
            fprintf(stderr, "session_reclaim_race: final probe echo failed\n");
            pass = 0;
        }
        close(fd);
    }

    duct_engine_stop(io);
    pthread_join(run_th, nullptr);

    int opened_final = duct_atomic_load(&s_open_count, acquire),
        closed_final = duct_atomic_load(&s_close_count, acquire);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    duct_wire_destroy(wire);

    if (!closed_up) {
        fprintf(stderr, "session_reclaim_race: close_count=%d never settled at open_count=%d\n",
                closed, opened);
        pass = 0;
    }
    unsigned expected_min = (churn_threads * churn_rounds + hold_threads * hold_rounds +
                              close_threads * close_rounds) * 3u / 4u;
    if ((unsigned)opened < expected_min) {
        fprintf(stderr, "session_reclaim_race: on_session_open=%d below min=%u\n",
                opened, expected_min);
        pass = 0;
    }

    if (pass) {
        printf("session_reclaim_race: OK (open=%d, close=%d)\n", opened_final, closed_final);
        return 0;
    }
    return 1;
}
