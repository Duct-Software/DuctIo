/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file listener_reuseport_test.c
 * @brief Listener placement follows the platform's port-sharing capability.
 * Balancing kernels open one socket per I/O thread; other kernels use one
 * listener on I/O thread 0. The conn pool is a fully hidden
 * singleton, so this reads each io thread's
 * @c conns_added telemetry counter (duct_io_rtstats) instead of scanning
 * pool internals — only built when @c DUCT_RUNTIME_STATS is on (`stats`
 * preset); under a plain build this test only checks that every client
 * connected, not the io_id split.
 */

#include "duct.h"
#include "test_helpers.h"
#include "duct_io.h"
#include "duct_runtime_stats.h"
#include "duct_xport.h"

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_conn_id_t conn_id,
         [[maybe_unused]] const duct_frame_t *frame,
         [[maybe_unused]] duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

#if DUCT_RUNTIME_STATS
/** @brief Sum of conns_added across io threads 0 and 1 (this test's
 * io_threads count) — safe to poll concurrently, each io thread only ever
 * increments its own counter. */
static unsigned
s_accepted_total(void)
{
    auto st0 = duct_io_rtstats(0u);
    auto st1 = duct_io_rtstats(1u);
    return (unsigned)((st0 ? st0->conns_added : 0u) + (st1 ? st1->conns_added : 0u));
}
#endif

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 2, .workers = 2 });
    if (!io) { fprintf(stderr, "listener_reuseport: io create failed\n"); return 1; }

    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "reuseport", .on_frame = on_frame, .max_response = 256u,
    });
    if (!proto) {
        fprintf(stderr, "listener_reuseport: proto create failed\n");
        duct_engine_destroy(io);
        return 1;
    }

    uint16_t port = 0u;
    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok) {
        fprintf(stderr, "listener_reuseport: listen failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }
    pthread_t th;
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        fprintf(stderr, "listener_reuseport: thread create failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }

    int pass = 1;
    /* wsaevent clamps duct_runtime_max_conns to 63, and its wait set holds the wake event, the RIO
     * queue's event and the listener besides the conns: 61 conns at most, 62 without RIO. 64 clients
     * at once would leave the last ones in the backlog and the accept count short. Scale the burst
     * with the pool, as conn_churn_test does. */
    static constexpr unsigned n_clients = duct_runtime_max_conns < 256u ? 32u : 64u;
    duct_sock_t fds[n_clients];
    unsigned n_connected = 0u;
    for (; n_connected < n_clients; ++n_connected) {
        fds[n_connected] = th_connect(port);
        if (fds[n_connected] == duct_sock_bad) {
            fprintf(stderr, "listener_reuseport: connect #%u failed\n", n_connected);
            pass = 0;
            break;
        }
    }

    unsigned live = 0u;
#if DUCT_RUNTIME_STATS
    for (unsigned waited = 0u; waited < 3000u; waited += 10u) {
        live = s_accepted_total();
        if (live >= n_connected)
            break;
        struct timespec ts = { .tv_nsec = 10L * 1000L * 1000L };
        nanosleep(&ts, nullptr);
    }
    if (live != n_connected) {
        fprintf(stderr, "listener_reuseport: only %u/%u accepts observed\n", live, n_connected);
        pass = 0;
    }
#else
    /* No accept counter without DUCT_RUNTIME_STATS — give the io threads a
     * fixed grace window instead of polling for an exact count. */
    struct timespec ts = { .tv_nsec = 200L * 1000L * 1000L };
    nanosleep(&ts, nullptr);
    live = n_connected;
#endif

    for (unsigned i = 0u; i < n_connected; ++i)
        close(fds[i]);

    /* duct_engine_stop joins every io/worker thread before returning, so the
     * counters read below are final — no concurrent writer left. */
    duct_engine_stop(io);
    pthread_join(th, nullptr);

#if DUCT_RUNTIME_STATS
    auto st0 = duct_io_rtstats(0u);
    auto st1 = duct_io_rtstats(1u);
    unsigned io0 = st0 ? (unsigned)st0->conns_added : 0u,
             io1 = st1 ? (unsigned)st1->conns_added : 0u;
    if (duct_x_port_sharing == x_port_share_spread && (io0 == 0u || io1 == 0u)) {
        fprintf(stderr, "listener_reuseport: accepts not spread (io_id=0: %u, io_id=1: %u)\n",
                io0, io1);
        pass = 0;
    } else if (duct_x_port_sharing != x_port_share_spread
               && (io0 != n_connected || io1 != 0u)) {
        fprintf(stderr, "listener_reuseport: single listener placement (io_id=0: %u, io_id=1: %u)\n",
                io0, io1);
        pass = 0;
    } else {
        printf("listener_reuseport: accept counters io_id=0: %u, io_id=1: %u\n", io0, io1);
    }
#else
    printf("listener_reuseport: DUCT_RUNTIME_STATS off — skipping io_id split check\n");
#endif

    duct_engine_destroy(io);
    duct_proto_destroy(proto);

    if (pass) {
    printf("listener_reuseport: OK (%u accepts, %s listener placement)\n", live,
           duct_x_port_sharing == x_port_share_spread ? "spread" : "single");
        return 0;
    }
    return 1;
}
