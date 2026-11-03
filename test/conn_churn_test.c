/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file conn_churn_test.c
 * @brief Stress the fast-release prepend path under concurrent io threads.
 *
 * Two io threads share one conn pool. Many short-lived clients connect and
 * close immediately without sending a frame — each accepted conn is dropped
 * via the non-WFQ fast-release path (r_head prepend).
 *
 * Pass: no crash, opens >= 75% of expected (pool exhaustion is acceptable
 * under extreme churn, but the vast majority must succeed).
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>

static uint16_t th_port = 0;

/* A small duct_runtime_max_conns (wsaevent clamps it to 63 — see
 * os/windows/wsaevent/duct_events.c's own @file doc) means every conn
 * registration costs a real WSACreateEvent/WSAEventSelect pair instead of
 * poll's plain array write; a loopback-speed burst from the full-size
 * volume below outruns that well before the pool itself would matter.
 * Scale the burst down with the pool instead of loosening the pass bar. */
static constexpr bool     churn_small_pool  = duct_runtime_max_conns < 256u;
static constexpr unsigned churn_threads     = churn_small_pool ? 2u : 32u;
static constexpr unsigned churn_per_thread  = churn_small_pool ? 40u : 100u;

static atomic_int s_open_count = 0;

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

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_conn_id_t conn_id,
         [[maybe_unused]] const duct_frame_t *frame,
         [[maybe_unused]] duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

static void *s_churn_thread([[maybe_unused]] void *arg)
{
    for (unsigned i = 0u; i < churn_per_thread; ++i) {
        duct_sock_t fd = th_connect(th_port);
        if (fd == duct_sock_bad)
            continue;
        /* A WSAEventSelect registration is asynchronous and costs a real OS
         * event. Give its small-pool consumer a turn before closing; otherwise
         * the client may disappear before on_session_open can observe it. */
#ifdef _WIN32
        th_sleep_ms(1u);
#else
        if (churn_small_pool)
            th_sleep_ms(1u);
#endif
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 2, .workers = 2 });
    if (!io) { fprintf(stderr, "churn: io create failed\n"); return 1; }

    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "churn", .on_frame = on_frame, .on_session_open = on_session_open,
        .max_response = 4096u,
    });
    if (!proto) { fprintf(stderr, "churn: proto create failed\n"); duct_engine_destroy(io); return 1; }

    if (duct_io_listen(io, "127.0.0.1", &th_port, proto) != rc_ok) {
        fprintf(stderr, "churn: listen failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto);
        return 1;
    }
    pthread_t run_th;
    if (pthread_create(&run_th, nullptr, th_run, io) != 0) {
        fprintf(stderr, "churn: thread create failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto);
        return 1;
    }

    pthread_t clients[churn_threads];
    for (unsigned i = 0u; i < churn_threads; ++i)
        pthread_create(&clients[i], nullptr, s_churn_thread, nullptr);
    for (unsigned i = 0u; i < churn_threads; ++i)
        pthread_join(clients[i], nullptr);

    unsigned expected = churn_threads * churn_per_thread;
    unsigned min_accepts = expected * 3u / 4u;
    for (unsigned waited = 0u; waited < 5000u
         && duct_atomic_load(&s_open_count, acquire) < (int)min_accepts; waited += 10u)
        th_sleep_ms(10u);
    /* Let the io threads finish pending drops and drain. */
    struct timespec drain_ts = { .tv_nsec = 200L * 1000L * 1000L };
    nanosleep(&drain_ts, nullptr);

    duct_engine_stop(io);
    pthread_join(run_th, nullptr);

    int opens = duct_atomic_load(&s_open_count, acquire);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);

    if (opens < (int)min_accepts) {
        fprintf(stderr, "churn: on_session_open=%d, expected~%u, min=%u\n",
                opens, expected, min_accepts);
        return 1;
    }
    printf("churn: OK (on_session_open=%d, expected~%u)\n", opens, expected);
    return 0;
}
