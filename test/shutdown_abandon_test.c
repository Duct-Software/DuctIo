/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file shutdown_abandon_test.c
 * @brief What an io stack and a worker's ctrl stack still hold at teardown is
 * given back once each.
 *
 * Includes duct_io.c directly to reach the module state and the static message
 * kinds, same pattern as retry_drain_quota_test.c uses for duct_worker.c. The
 * io thread is started and joined before anything is posted, so every message
 * sits on its stack until duct_io_cleanup runs: a late post from a worker's
 * shutdown drain or from a host thread leaves the stack in just this state.
 *
 * Each kind is checked against what it owns: the device's release runs, an fd
 * is closed (its peer sees the end), a listener and a sync handle are signalled
 * failed and freed, a pre-parse job drops its fd and its listener reference,
 * and a packet fd's open reaches on_error with rc_closed and its user_ctx.
 * A message embedded in its owner is left alone. The worker half posts a
 * session invoke to a worker that never ran and checks that its completion is
 * reported closed instead of dropped with the node.
 */

#include "../src/duct_io.c"

#include "duct_wfq.h"
#include "duct_worker.h"
#include "test_helpers.h"

#include <assert.h>
#include <stdio.h>

static unsigned      g_released;
static unsigned      g_done_n;
static duct_result_t g_done_rc = rc_ok;

enum { failed_cap = 16 };
static struct { void *ctx; duct_result_t rc; } g_failed[failed_cap];
static unsigned g_failed_n;
static duct_sock_t g_staged[2];
static unsigned g_staged_n;

static bool capture_staged([[maybe_unused]] void *ctx, duct_sock_t fd,
                           [[maybe_unused]] int family)
{
    assert(g_staged_n < 2u);
    g_staged[g_staged_n++] = fd;
    return true;
}

static void device_release([[maybe_unused]] void *ctx)
{
    ++g_released;
}

static duct_result_t on_error(duct_session_t *s, duct_result_t err,
                              [[maybe_unused]] duct_response_t *out, void *state)
{
    if (s)
        return rc_ok;
    assert(g_failed_n < failed_cap);
    g_failed[g_failed_n].ctx = state;
    g_failed[g_failed_n].rc = err;
    ++g_failed_n;
    return rc_ok;
}

static duct_proto_t g_proto = { .cfg = { .on_error = on_error } };
static int          g_packet_ctx;
static int          g_dial_ctx;
static int          g_accept_ctx;
static int          g_connect_ctx;
static int          g_lookup_ctx;
static int          g_leg_ctx;
static int          g_pending_ctx;
static int          g_pending_leg_ctx;

/* Reports reaching on_error for @p ctx, any code. */
static unsigned failed_for(const void *ctx)
{
    unsigned n = 0u;
    for (unsigned i = 0u; i < g_failed_n; ++i)
        n += g_failed[i].ctx == ctx;
    return n;
}

/* Exactly one report for @p ctx, carrying @p rc. */
static void expect_failed(const void *ctx, duct_result_t rc, const char *what)
{
    if (failed_for(ctx) != 1u) {
        fprintf(stderr, "shutdown_abandon: %s reached on_error %u times, expected once\n",
                what, failed_for(ctx));
        exit(1);
    }
    for (unsigned i = 0u; i < g_failed_n; ++i)
        if (g_failed[i].ctx == ctx && g_failed[i].rc != rc) {
            fprintf(stderr, "shutdown_abandon: %s reached on_error with rc %d, expected %d\n",
                    what, (int)g_failed[i].rc, (int)rc);
            exit(1);
        }
}

static void expect_silent(const void *ctx, const char *what)
{
    if (failed_for(ctx) != 0u) {
        fprintf(stderr, "shutdown_abandon: %s reached on_error, a leg's dial owes none\n", what);
        exit(1);
    }
}

static void invoke_done(duct_result_t rc, [[maybe_unused]] void *ctx)
{
    ++g_done_n;
    g_done_rc = rc;
}

static duct_result_t invoke_fn([[maybe_unused]] duct_session_t *s,
                               [[maybe_unused]] duct_response_t *out,
                               [[maybe_unused]] void *ctx)
{
    return rc_ok;
}

static void pair_open(duct_sock_t sv[2])
{
    int rc = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    assert(rc == 0);
    duct_discard rc;
}

static duct_listener_t *listener_new(duct_sock_t fd)
{
    auto l = duct_new(duct_listener_t);
    assert(l);
    l->listen_fd = fd;
    l->xport_type = x_tcp;
    return l;
}

static duct_listener_sync_t *sync_new(void)
{
    auto sync = duct_new(duct_listener_sync_t);
    assert(sync);
    return sync;
}

static void sync_expect_failed(duct_listener_sync_t *sync, const char *what)
{
    if (duct_atomic_load(&sync->done, acquire) != 1u || sync->ok
        || duct_atomic_load(&((duct_alloc_hdr_t *)((uintptr_t)sync - sizeof(duct_alloc_hdr_t)))->holders,
                            relaxed) != 1u) {
        fprintf(stderr, "shutdown_abandon: %s sync not signalled failed with one owner left\n", what);
        exit(1);
    }
    duct_del(sync);
}

static void expect_closed(duct_sock_t peer, const char *what)
{
    if (!th_peer_closed(peer, 1000)) {
        fprintf(stderr, "shutdown_abandon: %s fd was not closed\n", what);
        exit(1);
    }
}

static void expect_open(duct_sock_t peer, const char *what)
{
    if (th_peer_closed(peer, 0)) {
        fprintf(stderr, "shutdown_abandon: %s fd closed before the sweep\n", what);
        exit(1);
    }
}

static void io_stack_sweep(duct_vmq_mpsc_t *wfq)
{
    assert(duct_io_init(1u, wfq, 1u));
    assert(duct_io_start_threads());
    duct_io_request_shutdown();
    duct_io_join();

    duct_session_handle_t tok = {};

    duct_device_ops_t ops = { .release = device_release };
    assert(duct_io_post_attach_device(0u, &tok, 1u, &ops, nullptr));

    duct_sock_t attach[2], packet[2], pre[2], reg_l[2];
    pair_open(attach);
    pair_open(packet);
    pair_open(pre);
    pair_open(reg_l);
    assert(duct_io_post_attach_fd(0u, &tok, 1u, attach[0], x_raw, nullptr, nullptr));
    assert(duct_io_post_open_packet_fd(0u, packet[0], &g_proto, &g_packet_ctx));

    /* A dial posted but never run: the session seed and the lookup failure owe on_error,
     * the leg seed none; g_leg_ctx rides in the leg seed's first word, where a session
     * seed keeps user_ctx, so a leg report would name it. */
    duct_peer_t peer = { .family = AF_INET, .port = 9u };
    duct_conn_intent_t session_seed = { .kind = intent_session, .proto = &g_proto, .xport = x_tcp,
                                        .user_ctx = &g_connect_ctx };
    duct_conn_intent_t lookup_seed = session_seed;
    lookup_seed.user_ctx = &g_lookup_ctx;
    duct_conn_intent_t leg_seed = { .kind = intent_leg, .proto = &g_proto, .xport = x_tcp };
    leg_seed.leg.hsession = (duct_handle_t)(uintptr_t)&g_leg_ctx;
    duct_io_configure_sockets(capture_staged, nullptr);
    assert(duct_io_post_connect(0u, &peer, &session_seed, 0u));
    assert(duct_io_post_connect_failed(0u, &lookup_seed, rc_dns_fail));
    assert(duct_io_post_connect(0u, &peer, &leg_seed, 0u));
    duct_io_configure_sockets(nullptr, nullptr);
    assert(g_staged_n == 2u);

    /* A dial connecting and a probe waiting on the io thread's list: the session dial
     * owes on_error, the leg dial and the probe none, and all three give their fd back. */
    duct_sock_t pending[2], pending_leg[2], probe[2];
    pair_open(pending);
    pair_open(pending_leg);
    pair_open(probe);
    duct_conn_intent_t pending_seed = session_seed, pending_leg_seed = leg_seed;
    pending_seed.user_ctx = &g_pending_ctx;
    pending_leg_seed.leg.hsession = (duct_handle_t)(uintptr_t)&g_pending_leg_ctx;
    duct_pre_conn_t *list[3];
    for (unsigned i = 0u; i < 3u; ++i) {
        list[i] = duct_new(duct_pre_conn_t);
        assert(list[i]);
        list[i]->timeout = timer_handle_null;
        list[i]->next = s_imod.xports[0].pre_conns;
        s_imod.xports[0].pre_conns = list[i];
    }
    list[0]->fd = pending[0];
    list[0]->kind = pre_conn_dial;
    list[0]->dial.seed = pending_seed;
    list[1]->fd = pending_leg[0];
    list[1]->kind = pre_conn_dial;
    list[1]->dial.seed = pending_leg_seed;
    list[2]->fd = probe[0];
    list[2]->kind = pre_conn_probe;

    auto pre_listener = listener_new(duct_sock_bad);
    pre_listener->pre_conn_refs = 1u;
    auto pm = duct_msg_new_kind(pre_parse, s_preparse_exec_result, 8u);
    assert(pm);
    pm->listener = pre_listener;
    pm->fd = pre[0];
    pm->payload_len = 8u;
    s_msg_post(0u, pm);

    auto reg_listener = listener_new(reg_l[0]);
    auto reg_sync = sync_new();
    assert(duct_io_post_listener_register(reg_listener, reg_sync));
    auto close_sync = sync_new();
    assert(duct_io_post_listener_close(0u, duct_sock_bad, close_sync));

    assert(duct_io_post_attach_inter(0u, &tok, 1u, nullptr));

    /* The three messages embedded in their owners, each posted onto the stack: the thread's own rx
     * resume, a listener's datagram tx kick and a conn's request. All three carry the embedded kind
     * from the place their owner sets them up, and none is released or freed by the sweep. */
    s_msg_post(0u, &s_imod.xports[0].rx_resume);
    auto kick_listener = listener_new(duct_sock_bad);
    duct_io_dgram_tx_kick_init(kick_listener);
    s_msg_post(0u, &kick_listener->dgram_tx_kick);
    auto req_conn = duct_conn_acquire();
    assert(req_conn);
    assert(duct_io_trunk_req_post(&s_imod.xports[0].trunk, duct_conn_handle_get(req_conn), fl_req_tx_drain));
    for (unsigned i = 0u; i < duct_max_conns; ++i)
        assert(duct_conn_req_msg(duct_conn_by_idx(i))->msg.arg == (void *)msg_kind_embedded);
    assert(s_imod.xports[0].rx_resume.msg.arg == (void *)msg_kind_embedded);
    assert(kick_listener->dgram_tx_kick.msg.arg == (void *)msg_kind_embedded);

    assert(g_released == 0u);
    expect_open(attach[1], "attach_fd");
    expect_open(packet[1], "open_packet_fd");
    expect_open(pre[1], "pre_parse");
    expect_open(reg_l[1], "listener_register");
    assert(duct_atomic_load(&reg_sync->done, acquire) == 0u);
    assert(duct_atomic_load(&close_sync->done, acquire) == 0u);

    duct_io_cleanup();

    for (unsigned i = 0u; i < g_staged_n; ++i) {
        assert(fcntl(g_staged[i], F_GETFD) == -1 && errno == EBADF);
    }

    if (g_released != 1u) {
        fprintf(stderr, "shutdown_abandon: device release ran %u times, expected 1\n", g_released);
        exit(1);
    }
    expect_failed(&g_packet_ctx, rc_closed, "the packet fd's open");
    expect_failed(&g_connect_ctx, rc_closed, "a dial posted and never run");
    expect_failed(&g_lookup_ctx, rc_dns_fail, "a lookup failure posted and never run");
    expect_silent(&g_leg_ctx, "a leg dial posted and never run");
    expect_failed(&g_pending_ctx, rc_closed, "a dial still connecting");
    expect_silent(&g_pending_leg_ctx, "a leg dial still connecting");
    if (g_failed_n != 4u) {
        fprintf(stderr, "shutdown_abandon: %u reports reached on_error, expected 4\n", g_failed_n);
        exit(1);
    }
    expect_closed(attach[1], "attach_fd");
    expect_closed(packet[1], "open_packet_fd");
    expect_closed(pre[1], "pre_parse");
    expect_closed(reg_l[1], "listener_register");
    expect_closed(pending[1], "a dial still connecting");
    expect_closed(pending_leg[1], "a leg dial still connecting");
    expect_closed(probe[1], "a probe still waiting");
    if (pre_listener->pre_conn_refs != 0u) {
        fprintf(stderr, "shutdown_abandon: pre_parse kept its listener reference\n");
        exit(1);
    }
    sync_expect_failed(reg_sync, "listener_register");
    sync_expect_failed(close_sync, "listener_close");
    if (kick_listener->dgram_tx_kick.msg.exec_fn != s_msg_exec_dgram_tx_kick
        || duct_conn_req_msg(req_conn)->msg.exec_fn != s_req_exec) {
        fprintf(stderr, "shutdown_abandon: an embedded message did not survive the sweep\n");
        exit(1);
    }

    duct_conn_release(req_conn);
    duct_listener_destroy(kick_listener);
    duct_listener_destroy(pre_listener);
    duct_sock_close(attach[1]);
    duct_sock_close(packet[1]);
    duct_sock_close(pre[1]);
    duct_sock_close(reg_l[1]);
    duct_sock_close(pending[1]);
    duct_sock_close(pending_leg[1]);
    duct_sock_close(probe[1]);
}

static void worker_ctrl_residue(duct_vmq_mpsc_t *wfq)
{
    assert(duct_worker_module_init(1u, 1u, wfq, 0u));

    duct_session_handle_t tok = {};
    assert(duct_worker_post_session_invoke(0u, &tok, invoke_fn, nullptr, invoke_done, nullptr));

    auto dialed = duct_conn_acquire();
    auto accepted = duct_conn_acquire();
    assert(dialed && accepted);
    dialed->worker_id = 0u;
    accepted->worker_id = 0u;
    assert(duct_sessions_post_session_open(dialed, &g_proto, &g_dial_ctx, (duct_seal_prefix_t){}, true));
    assert(duct_sessions_post_session_open(accepted, &g_proto, &g_accept_ctx, (duct_seal_prefix_t){}, false));
    assert(g_done_n == 0u);

    duct_worker_module_cleanup();

    if (g_done_n != 1u || g_done_rc != rc_closed) {
        fprintf(stderr, "shutdown_abandon: stranded invoke reported %u times, last rc %d\n",
                g_done_n, (int)g_done_rc);
        exit(1);
    }
    expect_failed(&g_dial_ctx, rc_closed, "a stranded dialed session open");
    if (failed_for(&g_accept_ctx) != 0u) {
        fprintf(stderr, "shutdown_abandon: a stranded accepted session open reached on_error\n");
        exit(1);
    }
    duct_conn_release(dialed);
    duct_conn_release(accepted);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    auto wfq = duct_wfq_new(1u, 1u, DUCT_WFQ_CAP_HI, DUCT_WFQ_CAP_NORM, DUCT_WFQ_CAP_LO);
    assert(wfq);

    io_stack_sweep(wfq);
    worker_ctrl_residue(wfq);

    duct_vmq_mpsc_del(wfq);
    printf("shutdown_abandon: OK (io stack kinds release what they own, embedded message "
           "left alone, stranded invoke and dialed open reported closed)\n");
    return 0;
}
