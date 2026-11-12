/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct.c
 *  @brief Engine, session, and stats façade — public API entry points, plus
 *  thin listener-API wrappers. The inter-conn host bridge, egress and ingress
 *  to the embedding application, lives in the host module; the listener bind,
 *  close and teardown logic lives in the listener module, reached through
 *  @ref duct_listener_route_t so @c struct duct_engine never leaves this
 *  file.
 */

#include "duct_io.h"
#include "duct_dgram_rec.h"
#include "duct_xport.h"
#include "duct_worker.h"
#include "duct_relay.h"
#include "duct_host.h"
#include "duct_listener.h"
#include "duct_session.h"
#include "duct_vmq.h"
#include "duct_wfq.h"
#include "duct_timer.h"
#include "duct_time.h"
#include "duct.h"
#include "duct_runtime_stats.h"
#include "duct_stats.h"

#include <assert.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <unistd.h>

typedef enum : uint32_t {
    engine_state_init    = 0,
    engine_state_running,
    engine_state_stopping,
    engine_state_dead
} engine_state_t;

static constexpr uint32_t host_egress_quiesce_ms = 250u;

/** @brief The stop request the waiters sleep on: 0 until requested, then 1.
 *  A word of the process, kept out of @c struct duct_engine so that an OS hook
 *  running as the engine is destroyed touches no freed memory. Cleared by
 *  @ref duct_engine_launch.
 */
static uint32_t _Atomic s_stop_requested;

struct duct_engine {
    uint32_t _Atomic        state;
    unsigned                n_io;
    unsigned                n_workers;
    /** @brief Whether the stop hook is armed.
     *  Set by @c duct_engine_stop_on_signals, read by @ref s_engine_destroy. */
    bool                    stop_on_signals;
    duct_vmq_mpsc_t        *wfq;
    duct_listener_reg_t     listener_regs[duct_runtime_max_listeners];
    /** @brief RX slot pool of each worker, by worker index.
     *  Created by the worker's first datagram listener node, freed last at
     *  teardown. */
    duct_x_slot_pool_t *_Atomic rx_pools[duct_runtime_max_workers];
    unsigned _Atomic        connect_rr; /**< Round-robins duct_io_connect across io threads. */
    unsigned _Atomic        timer_rr; /**< Round-robins duct_timer_start across workers. */
    /** @brief Outstanding @c duct_session_invoke_sync calls.
     *  Held nonzero from before the post until the worker's on_done fires, so
     *  @ref s_engine_drain_sync_invokes blocks teardown until they clear.
     */
    uint32_t _Atomic        sync_invokes_inflight;
    /** @brief Threads currently inside @c duct_engine_wait or
     *  @c duct_engine_wait_request, still touching @c e.
     *
     *  Their sleep, and for @c duct_engine_wait the @ref duct_engine_stop call it
     *  makes once woken. Held nonzero for that whole span, so
     *  @ref s_engine_drain_wait_inflight blocks @c duct_del(e) until they
     *  clear.
     */
    uint32_t _Atomic        wait_inflight;
    duct_stats_t *_Atomic   stats; /**< Head of the list of statistics sections, newest first. Freed by @ref s_engine_destroy. */
};

/** @brief Halt I/O and worker modules by requesting shutdown and joining both.
 *  Shared tail of @ref duct_engine_stop, @ref s_engine_destroy, and
 *  @ref duct_engine_launch start-failure branch. Does not touch @c e->state —
 *  callers manage that transition, since @ref duct_engine_launch sets
 *  @c engine_state_dead directly.
 */
static void s_engine_halt_threads(void)
{
    duct_io_request_shutdown();
    duct_io_join();
    duct_worker_module_request_shutdown();
    duct_worker_module_join();
}

/** @brief Set the stop request and wake every waiter.
 *  An atomic store and a futex wake, which a signal handler may run.
 */
static void s_request_stop(void)
{
    duct_atomic_store(&s_stop_requested, 1u, release);
    duct_futex_wake(&s_stop_requested, duct_futex_wake_all);
}

void duct_on_stop_signal(void)
{
    s_request_stop();
}

/** @brief Sleep until the stop request is set. */
static void s_wait_request(void)
{
    while (duct_atomic_load(&s_stop_requested, acquire) == 0u)
        duct_futex_wait(&s_stop_requested, 0u, DUCT_TIMEOUT_INFINITE);
}

static void s_sync_inflight_release(duct_engine_t *e)
{
    if (duct_atomic_fetch(sub, &e->sync_invokes_inflight, 1u, acq_rel) == 1u)
        duct_futex_wake(&e->sync_invokes_inflight, 1);
}

/** @brief Registers intent to post a sync invoke; false when the engine is
 *  not running, in which case the caller must not post. Always pairs with
 *  exactly one @ref s_sync_inflight_release, win or lose — see the acquire/
 *  release ordering note on @ref s_engine_drain_sync_invokes.
 */
static bool s_sync_inflight_acquire(duct_engine_t *e)
{
    duct_atomic_fetch(add, &e->sync_invokes_inflight, 1u, acq_rel);
    if (duct_atomic_load(&e->state, acquire) == engine_state_running)
        return true;
    s_sync_inflight_release(e);
    return false;
}

/** @brief Blocks until @c sync_invokes_inflight drains to zero or
 *  @c duct_sync_bound_ms elapses, whichever first — a plain futex_wait on
 *  the counter itself, woken the instant the invoke that brings it to zero
 *  finishes; no polling. Ordering against @ref s_sync_inflight_acquire is the
 *  usual quiescence-barrier pair: the caller here sets @c state to
 *  @c engine_state_stopping (release) before checking the counter (acquire),
 *  and an acquirer increments the counter before checking @c state — so
 *  either this call observes the increment and waits for it, or the acquirer
 *  observes @c stopping and backs out before ever posting; the increment and
 *  the state check can never both miss each other. Called before tearing
 *  workers down, so an in-flight invoke gets a chance to reach a
 *  still-live worker before @c duct_worker_module_cleanup begins its
 *  late-arrival sweep. Bounded so a stalled @c fn does not hang shutdown
 *  indefinitely; matches the bound in @ref duct_session_invoke_sync.
 */
static void s_engine_drain_sync_invokes(duct_engine_t *e)
{
    duct_drain_wait(&e->sync_invokes_inflight, duct_sync_bound_ms);
}

static void s_wait_inflight_release(duct_engine_t *e)
{
    if (duct_atomic_fetch(sub, &e->wait_inflight, 1u, acq_rel) == 1u)
        duct_futex_wake(&e->wait_inflight, 1);
}

/** @brief Block until @c wait_inflight drains to zero or
 *  @c duct_sync_bound_ms elapses.
 *
 *  A thread woken in @ref duct_engine_wait or @ref duct_engine_wait_request
 *  still reads @c e: the release of @c wait_inflight, and in
 *  @ref duct_engine_wait the @ref duct_engine_stop call ahead of it.
 *  @ref duct_engine_destroy calls this ahead of the free of @c e.
 */
static void s_engine_drain_wait_inflight(duct_engine_t *e)
{
    duct_drain_wait(&e->wait_inflight, duct_sync_bound_ms);
}

static void s_engine_destroy(duct_engine_t *e)
{
    if (e->stop_on_signals)
        duct_stop_hook_disarm();
    /* CAS, not load-then-store: this call and a concurrent duct_engine_stop
     * can both reach here with the engine still running, and a wait that
     * returned on the winner's request comes here while the winner's halt is
     * in flight. Only the CAS winner halts the threads, since joining a joined
     * thread is undefined; a loser waits for that halt. */
    uint32_t expected = engine_state_running;
    bool own_halt = duct_atomic_cas(strong, &e->state, &expected, engine_state_stopping, release, acquire);
    bool was_live = own_halt || expected == engine_state_stopping;
    if (own_halt)
        s_request_stop();
    /* Placed after the state flip and before halt: duct_io_connect's
       engine_state_running gate now rejects a fresh dial, so no resolve
       starts after this walk, and io/worker threads are still alive, so a
       cancelled resolve's rc_dns_fail delivers through the ordinary error
       path — a post into a stopped-but-live engine becomes an orphan ctrl
       node, which duct_io_cleanup's late-arrival sweep below frees. On Linux
       it closes the posting gate instead, and a lookup returning later drops
       its result. Returns at once whenever no resolve is in flight. */
    duct_resolve_cancel_all();
    if (own_halt) {
        s_engine_drain_sync_invokes(e);
        /* Stop io before workers: a worker's shutdown drain must not race with
           io-posted ctrl nodes (conn-lost) landing in an already-exited worker's
           ctrl_stack. Workers keep draining WFQ while io stops; io cleanup frees
           any orphan io-op nodes the workers still post. */
        s_engine_halt_threads();
        duct_atomic_store(&e->state, engine_state_dead, release);
    } else if (was_live) {
        while (duct_atomic_load(&e->state, acquire) == engine_state_stopping)
            duct_futex_wait(&e->state, engine_state_stopping, 1000u);
    }
    /* The detached chain must outlive duct_io_cleanup below: its per-conn walk
       calls duct_events_unwatch, which on a proactive backend reads listen_fd
       off these same duct_listener_t structs, through that backend's private
       ctx nodes. duct_listener_destroy_chain frees them later. Threads are
       already joined by s_engine_halt_threads above, so this per-thread-list
       walk needs no lock, and module cleanups free late-arrival ctrl nodes
       without executing them, so no TLS borrow either. */
    auto listener_head = duct_io_listeners_detach();
    duct_io_cleanup();
    /* Pool-level safety net: a conn stays at fence_retire_ready if its io
       thread exited before the retire-bitmap scan, or was never linked to the
       conn list duct_io_cleanup walks — the x_inter and x_udp_shared
       light-attach path links none. Must precede duct_listener_destroy_chain:
       an x_udp_shared teardown reaches its listener back-reference through
       duct_conn_teardown's duct_listener_release_pre_conn_ref, and that frees
       every listener struct. Also before the caller's proto/wire teardown. */
    duct_conn_pool_reclaim();
    /* Session-pool analogue of duct_conn_pool_reclaim just above; see
       duct_sessions_reclaim_shutdown documentation. Orders session identity
       teardown after transport; conn_count is cleared unconditionally either
       way. */
    duct_sessions_reclaim_shutdown();
    duct_listener_destroy_chain(listener_head);
    /* Between the worker join far above and the lane free just below — the
     * only window where no producer is left and the memory a scheduled drain
     * reads is still alive. */
    duct_host_egress_quiesce(e->n_workers, host_egress_quiesce_ms);
    duct_worker_module_cleanup();
    if (e->wfq) {
        duct_vmq_mpsc_del(e->wfq);
        e->wfq = nullptr;
    }
    /* The session-close callbacks run by the reclaim above still ask a section for their shard. */
    duct_stats_list_free(&e->stats);
    /* Last: every conn that returns a slot and every node that reads one is
     * gone by here. */
    for (unsigned i = 0u; i < duct_runtime_max_workers; ++i) {
        auto pool = duct_atomic_exchange(&e->rx_pools[i], nullptr, acquire);
        if (!pool)
            continue;
        duct_x_slot_pool_free(pool);
        duct_del(pool);
    }
    duct_atomic_store(&e->state, engine_state_dead, release);
}

duct_spin_policy_t duct_spin_policy = { duct_busy_spin_ns, duct_spin_gap_cutoff_ns };

/** @brief Resolve one spin figure, nanoseconds: environment variable @p env,
 *  else a non-zero @p cfg_us, else @p build_ns. */
static uint64_t s_spin_ns(const char *env, uint32_t cfg_us, uint64_t build_ns)
{
    const char *s = getenv(env);
    long long v = s ? atoll(s) : -1;
    return v >= 0 ? (uint64_t)v : cfg_us ? (uint64_t)cfg_us * 1000u : build_ns;
}

duct_engine_t *duct_engine_launch(const duct_engine_cfg_t *cfg)
{
    if (!cfg || cfg->io_threads == 0u || cfg->workers == 0u)
        return nullptr;
    if (cfg->io_threads > duct_runtime_max_io_threads || cfg->workers < cfg->io_threads)
        return nullptr;
    if (cfg->workers > duct_runtime_max_workers)
        return nullptr;
    auto e = duct_new(duct_engine_t);
    if (!e)
        return nullptr;
    atomic_init(&e->state, engine_state_init);
    atomic_init(&e->connect_rr, 0u);
    atomic_init(&e->sync_invokes_inflight, 0u);
    atomic_init(&e->wait_inflight, 0u);
    atomic_init(&e->stats, nullptr);
    duct_atomic_store(&s_stop_requested, 0u, release);
    for (unsigned i = 0u; i < duct_runtime_max_listeners; ++i)
        atomic_init(&e->listener_regs[i].fd, duct_sock_bad);
    e->n_io = cfg->io_threads;
    e->n_workers = cfg->workers;
    duct_host_init(&cfg->host);
    /* Ahead of duct_io_start_threads below: its threads read the policy
     * unsynchronized. One cpu online leaves no window: a spinning loop holds
     * the only core against every other thread. */
    duct_spin_policy = (duct_spin_policy_t){
        .window_ns = duct_cpu_online_count() == 1u ? 0u
                   : s_spin_ns("DUCT_BUSY_SPIN_NS", cfg->spin_window_us, duct_busy_spin_ns),
        .cutoff_ns = s_spin_ns("DUCT_SPIN_GAP_CUTOFF_NS", cfg->spin_gap_cutoff_us,
                               duct_spin_gap_cutoff_ns),
    };

    e->wfq = duct_wfq_new(e->n_workers, e->n_io,
                          DUCT_WFQ_CAP_HI, DUCT_WFQ_CAP_NORM, DUCT_WFQ_CAP_LO);
    if (!e->wfq)
        goto fail;

    if (!duct_io_init(e->n_io, e->wfq, e->n_workers))
        goto fail;

    duct_io_configure_sockets(cfg->socket_prepare, cfg->socket_ctx);

    if (!duct_worker_module_init(e->n_workers, e->n_io, e->wfq,
                                 cfg->seal_key_lifetime_ms))
        goto fail;

    duct_atomic_store(&e->state, engine_state_running, release);
    if (!duct_io_start_threads() || !duct_worker_module_start_threads()) {
        duct_atomic_store(&e->state, engine_state_dead, release);
        s_engine_halt_threads();
        goto fail;
    }

    return e;

fail:
    s_engine_destroy(e);
    duct_del(e);
    return nullptr;
}

void duct_engine_destroy(duct_engine_t *e)
{
    duct_do_if(!e, return);
    s_engine_destroy(e);
    s_engine_drain_wait_inflight(e);
    duct_del(e);
}

duct_result_t duct_engine_stop(duct_engine_t *e)
{
    duct_do_if(!e, return rc_invalid_arg);
    /* A second join on an already-joined thread hangs; only the CAS winner
     * halts threads. Every other caller sees state past running and returns
     * immediately. */
    uint32_t expected = engine_state_running;
    if (!duct_atomic_cas(strong, &e->state, &expected, engine_state_stopping, release, acquire))
        return rc_ok;
    s_request_stop();
    s_engine_drain_sync_invokes(e);
    s_engine_halt_threads();
    duct_atomic_store(&e->state, engine_state_dead, release);
    return rc_ok;
}

duct_result_t duct_engine_wait(duct_engine_t *e)
{
    duct_do_if(!e, return rc_invalid_arg);
    duct_atomic_fetch(add, &e->wait_inflight, 1u, acq_rel);
    s_wait_request();
    auto rc = duct_engine_stop(e);
    s_wait_inflight_release(e);
    return rc;
}

duct_result_t duct_engine_request_stop(duct_engine_t *e)
{
    duct_do_if(!e, return rc_invalid_arg);
    s_request_stop();
    return rc_ok;
}

duct_result_t duct_engine_wait_request(duct_engine_t *e)
{
    duct_do_if(!e, return rc_invalid_arg);
    duct_atomic_fetch(add, &e->wait_inflight, 1u, acq_rel);
    s_wait_request();
    s_wait_inflight_release(e);
    return rc_ok;
}

duct_result_t duct_engine_stop_on_signals(duct_engine_t *e)
{
    duct_do_if(!e, return rc_invalid_arg);
    /* Armed once: the hook records the prior handlers on first arm; repeated
     * arming overwrites them. */
    if (!e->stop_on_signals) {
        duct_stop_hook_arm();
        e->stop_on_signals = true;
    }
    return rc_ok;
}

int duct_engine_thread_cpu(const duct_engine_t *e, duct_thread_role_t role, unsigned index)
{
    duct_do_if(!e, return -1);
    switch (role) {
    case thread_io:
        return duct_io_thread_cpu(index);
    case thread_worker:
        return duct_worker_thread_cpu(index);
    }
    return -1;
}

duct_result_t duct_io_listen(duct_engine_t *e, const char *host, uint16_t *port,
                              duct_proto_t *proto)
{
    if (!proto)
        return rc_invalid_arg;
    return duct_listener_bind(e, &(duct_listener_cfg_t){
        .addr = host,
        .n_protos = 1u,
        .protos = (const duct_proto_t *[]){ proto },
        .peek_cap = 0u,
    }, port, nullptr, 0u, nullptr);
}

duct_result_t duct_listener_bind(duct_engine_t *e, const duct_listener_cfg_t *cfg,
                                  uint16_t *port,
                                  duct_sock_t *out_fds, unsigned max_fds,
                                  unsigned *out_n_fds)
{
    duct_do_if(!e, return rc_invalid_arg);
    duct_listener_route_t route = {
        .regs = e->listener_regs, .n_workers = e->n_workers, .n_io = e->n_io,
        .rx_pools = e->rx_pools,
    };
    duct_listener_out_fds_t out = { .fds = out_fds, .cap = max_fds };
    duct_result_t rc = duct_listener_route_bind(&route, cfg, port, &out);
    if (out_n_fds)
        *out_n_fds = out.n;
    return rc;
}

duct_result_t duct_listener_close(duct_engine_t *e, duct_sock_t fd)
{
    duct_do_if(!e, return rc_invalid_arg);
    duct_listener_route_t route = { .regs = e->listener_regs };
    return duct_listener_route_close(&route, fd);
}

/** @brief Trampoline that closes a session from an invoke.
 *
 *  Boxes @p reason into @c ctx as @c (void *)(uintptr_t), the way pthread
 *  entry args are boxed elsewhere in this tree, so @ref duct_session_close
 *  needs no second message type. @p s is always live here, resolved by the
 *  invoke machinery before this runs.
 */
static duct_result_t s_session_close_trampoline(duct_session_t *s, duct_response_t *out,
                                                void *ctx)
{
    *out = (duct_response_t){};
    duct_session_close_walk(s, (duct_close_reason_t)(uintptr_t)ctx);
    return rc_ok;
}

/** @brief Return the id of the worker that serves the session of @p tok, @c conn_worker_none when @p tok names no attached session. */
static unsigned s_worker_of(duct_handle_t tok)
{
    auto s = duct_session_attached_by_handle((duct_session_handle_t){ .word = tok });
    return s ? duct_atomic_load(&s->worker_id, acquire) : conn_worker_none;
}

duct_result_t duct_session_invoke(duct_engine_t *e, duct_handle_t tok,
                                  duct_session_fn fn, void *ctx)
{
    duct_do_if(!e || !fn, return rc_invalid_arg);
    auto worker_id = s_worker_of(tok);
    duct_do_if(worker_id == conn_worker_none, return rc_closed);
    auto h = (duct_session_handle_t){ .word = tok };
    /* The async post can fail on message OOM like the sync form below. */
    if (!duct_worker_post_session_invoke(worker_id, &h, fn, ctx, nullptr, nullptr))
        return rc_no_memory;
    return rc_ok;
}

duct_result_t duct_session_close(duct_engine_t *e, duct_handle_t tok,
                                 duct_close_reason_t reason)
{
    return duct_session_invoke(e, tok, s_session_close_trampoline,
                               (void *)(uintptr_t)reason);
}

/** @brief Function and context a dispatch posted to the session's worker carries.
 *  @c s_dispatch_done frees it.
 */
typedef struct {
    duct_session_dispatch_fn fn;
    void                    *ctx;
} dispatch_t;

/** @brief Run the function a posted dispatch carries and leave the response empty. */
static duct_result_t s_dispatch_run([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_response_t *out,
                                    void *ctx)
{
    auto call = (const dispatch_t *)ctx;
    call->fn(call->ctx);
    return rc_ok;
}

/** @brief Free the carrier of a posted dispatch, on whichever path the post ends.
 *  The paths are the run, the session gone, the post refused and the engine stopped first.
 */
static void s_dispatch_done([[maybe_unused]] duct_result_t rc, void *ctx)
{
    duct_del(ctx);
}

duct_result_t duct_session_dispatch(duct_engine_t *e, duct_handle_t tok,
                                    duct_session_dispatch_fn fn, void *ctx)
{
    duct_do_if(!e || !fn, return rc_invalid_arg);
    auto worker_id = s_worker_of(tok);
    duct_do_if(worker_id == conn_worker_none, return rc_closed);
    /* The in-place call is part of the callback that made it and commits nothing: a commit from there applies
     * that turn's pending switch ahead of its own response. */
    if (duct_worker_self() == worker_id) {
        /* A reused slot holds worker_id 0 from its acquire to its open, so the token is resolved again after
         * the read. */
        if (s_worker_of(tok) != worker_id)
            return rc_closed;
        fn(ctx);
        return rc_ok;
    }
    auto call = duct_new(dispatch_t);
    duct_do_if(!call, return rc_no_memory);
    *call = (dispatch_t){ .fn = fn, .ctx = ctx };
    auto h = (duct_session_handle_t){ .word = tok };
    /* A refused post has already run s_dispatch_done, which freed the carrier. */
    return duct_worker_post_session_invoke(worker_id, &h, s_dispatch_run, call,
                                           s_dispatch_done, call)
         ? rc_ok : rc_no_memory;
}

/** @brief Completion bridge from the worker back to the host thread blocked in a sync invoke.
 *  Two holders, the waiter and the worker's @c s_sync_invoke_done, each end with @c duct_del and
 *  the later one frees the block, so neither side frees memory the other still touches.
 */
typedef struct {
    uint32_t _Atomic  done;
    duct_result_t     result;
    duct_engine_t     *e;
} sync_invoke_t;

static void s_sync_invoke_done(duct_result_t rc, void *ctx)
{
    duct_auto_del auto sync = (sync_invoke_t *)ctx;
    sync->result = rc;
    duct_atomic_store(&sync->done, 1u, release);
    duct_futex_wake(&sync->done, 1);
    s_sync_inflight_release(sync->e);
}

duct_result_t duct_session_invoke_sync(duct_engine_t *e, duct_handle_t tok,
                                       duct_session_fn fn, void *ctx)
{
    duct_do_if(!e || !fn, return rc_invalid_arg);
    bool running = s_sync_inflight_acquire(e);
    duct_do_if(!running, return rc_closed);
    auto worker_id = s_worker_of(tok);
    if (worker_id == conn_worker_none) {
        s_sync_inflight_release(e);
        return rc_closed;
    }
    duct_auto_del auto sync = duct_new(sync_invoke_t);
    if (!sync) {
        s_sync_inflight_release(e);
        return rc_no_memory;
    }
    sync->e = e;
    auto h = (duct_session_handle_t){ .word = tok };
    /* A refused post has already run s_sync_invoke_done on this thread, which let go the
     * worker's holder and the inflight count: only the waiter's holder is left, for auto_del. */
    if (!duct_worker_post_session_invoke(worker_id, &h, fn, ctx, s_sync_invoke_done, duct_share(sync)))
        return rc_closed;
    auto deadline = duct_time_add(duct_time_now(),
                                  duct_time_from_us((uint64_t)duct_sync_bound_ms * 1000ull));
    duct_result_t rc = rc_timeout;
    for (;;) {
        if (duct_atomic_load(&sync->done, acquire)) {
            rc = sync->result;
            break;
        }
        if (!duct_deadline_wait(&sync->done, 0u, deadline))
            break;
    }
    return rc;
}

duct_result_t duct_io_connect(duct_engine_t *e, const char *addr,
                              duct_proto_t *proto, void *user_ctx, duct_xport_t xport)
{
    return duct_io_connect_via(e, addr, proto, user_ctx, xport, 0u, (duct_view_u8){});
}

duct_result_t duct_io_connect_via(duct_engine_t *e, const char *addr, duct_proto_t *proto,
                                  void *user_ctx, duct_xport_t xport, uint32_t egress_if,
                                  duct_view_u8 tx_prefix)
{
    duct_do_if(!e || !addr || !*addr || !proto, return rc_invalid_arg);
    auto seed = (duct_conn_intent_t){
        .kind = intent_session, .proto = proto, .xport = xport, .egress_if = egress_if,
        .user_ctx = user_ctx,
    };
    if (!duct_seal_prefix_set(&seed.tx_prefix, tx_prefix))
        return rc_invalid_arg;
    if (duct_atomic_load(&e->state, acquire) != engine_state_running)
        return rc_invalid_order;
    unsigned io_id = duct_atomic_fetch(add, &e->connect_rr, 1u, relaxed)
                   % e->n_io;
    return duct_connect_start(io_id, addr, &seed, duct_proto_cfg_of(proto)->connect_timeout_ms);
}

/** @brief Judge an attach over a packet fd: @c rc_ok, or the refusal the entry returns. */
static duct_result_t s_packet_fd_refusal(duct_engine_t *e, duct_sock_t fd, const duct_proto_t *proto)
{
    duct_do_if(!e || !proto || fd == duct_sock_bad, return rc_invalid_arg);
    duct_do_if(!duct_x_packet_fd_session, return rc_not_supported);
    auto state = duct_atomic_load(&e->state, acquire);
    duct_do_if(state != engine_state_running, return rc_invalid_order);
    auto cfg = duct_proto_cfg_of(proto);
    return cfg->wire && duct_wire_framing_fits_xport(cfg->wire, x_raw_packet) ? rc_ok : rc_invalid_arg;
}

duct_result_t duct_io_attach_packet_fd(duct_engine_t *e, duct_sock_t fd, duct_proto_t *proto,
                                       void *user_ctx)
{
    auto refusal = s_packet_fd_refusal(e, fd, proto);
    if (refusal != rc_ok) {
        duct_sock_close(fd);
        return refusal;
    }
    unsigned io_id = duct_atomic_fetch(add, &e->connect_rr, 1u, relaxed) % e->n_io;
    return duct_io_post_open_packet_fd(io_id, fd, proto, user_ctx) ? rc_ok : rc_no_memory;
}

duct_result_t duct_timer_start(duct_engine_t *e, duct_proto_t *proto, void *user_ctx,
                               uint64_t delay_ms, uintptr_t arg)
{
    duct_do_if(!e || !proto, return rc_invalid_arg);
    auto cfg = duct_proto_cfg_of(proto);
    uint64_t delay_us = 0u;
    bool of = duct_ckd_mul(&delay_us, delay_ms, 1000u);
    duct_do_if(!cfg->on_timer || of, return rc_invalid_arg);
    if (duct_atomic_load(&e->state, acquire) != engine_state_running)
        return rc_invalid_order;
    /* No session ties the timer to a worker, so workers take them in turn. */
    unsigned worker_id = duct_atomic_fetch(add, &e->timer_rr, 1u, relaxed) % e->n_workers;
    return duct_worker_post_timer_start(worker_id, proto, user_ctx, delay_us, arg);
}

bool duct_engine_stats(duct_engine_t *e, duct_rt_stats_t *out)
{
    duct_do_if(!out, return false);
    *out = (duct_rt_stats_t){};
    duct_do_if(!e, return false);
#if DUCT_RUNTIME_STATS
    for (unsigned i = 0u; i < e->n_workers; ++i) {
        auto st = duct_worker_rtstats(i);
        duct_do_if(!st, continue);
        out->wfq_drain           += duct_atomic_load(&st->wfq_drain, relaxed);
        out->futex_wait          += duct_atomic_load(&st->futex_wait, relaxed);
        out->rx_resume_post      += duct_atomic_load(&st->rx_resume_post, relaxed);
        out->batch_partial_defer += duct_atomic_load(&st->batch_partial_defer, relaxed);
        out->defer_oom_drop      += duct_atomic_load(&st->defer_oom_drop, relaxed);
        out->commit_internal     += duct_atomic_load(&st->commit_internal, relaxed);
        out->retry_saved         += duct_atomic_load(&st->retry_saved, relaxed);
        out->fastpath_armed_skip += duct_atomic_load(&st->fastpath_armed_skip, relaxed);
        out->fastpath_eagain     += duct_atomic_load(&st->fastpath_eagain, relaxed);
        out->dgram_shared_tx_drop += duct_atomic_load(&st->dgram_shared_tx_drop, relaxed);
        out->dgram_tx_batch_calls += duct_atomic_load(&st->dgram_batch_calls, relaxed);
        out->dgram_tx_batch_msgs  += duct_atomic_load(&st->dgram_batch_msgs, relaxed);
        out->dgram_tx_batch_max    = duct_max(out->dgram_tx_batch_max,
                                              duct_atomic_load(&st->dgram_batch_max, relaxed));
        out->dgram_fast_sent      += duct_atomic_load(&st->dgram_fast_sent, relaxed);
        out->dgram_lane_staged    += duct_atomic_load(&st->dgram_lane_staged, relaxed);
        out->dgram_tx_gso_writes  += duct_atomic_load(&st->dgram_tx_gso_writes, relaxed);
        out->dgram_tx_gso_dgrams  += duct_atomic_load(&st->dgram_tx_gso_dgrams, relaxed);
        out->tx_pool_acquire_fail += duct_atomic_load(&st->tx_pool_acquire_fail, relaxed);
        out->inter_held           += duct_atomic_load(&st->inter_held, relaxed);
        out->vnet_tx_gro_writes   += duct_atomic_load(&st->vnet_tx_gro_writes, relaxed);
        out->vnet_tx_gro_pkts     += duct_atomic_load(&st->vnet_tx_gro_pkts, relaxed);
        out->vnet_tx_drop         += duct_atomic_load(&st->vnet_tx_drop, relaxed);
        out->vnet_tx_gro_single   += duct_atomic_load(&st->vnet_tx_gro_single, relaxed);
        out->tx_train_flush_full  += duct_atomic_load(&st->tx_train_flush_full, relaxed);
        out->tx_train_flush_end   += duct_atomic_load(&st->tx_train_flush_end, relaxed);
        out->tx_train_flush_wait  += duct_atomic_load(&st->tx_train_flush_wait, relaxed);
        out->tcp_writes           += duct_atomic_load(&st->tcp_writes, relaxed);
        out->tcp_eor_writes       += duct_atomic_load(&st->tcp_eor_writes, relaxed);
        out->tcp_cut_writes       += duct_atomic_load(&st->tcp_cut_writes, relaxed);
    }
    for (unsigned i = 0u; i < e->n_io; ++i) {
        auto st = duct_io_rtstats(i);
        duct_do_if(!st, continue);
        out->tx_drain_posts   += duct_atomic_load(&st->tx_drain_posts, relaxed);
        out->tx_drain_deduped += duct_atomic_load(&st->tx_drain_deduped, relaxed);
        out->wfq_push_full    += duct_atomic_load(&st->wfq_push_full, relaxed);
        out->fence_push_full  += duct_atomic_load(&st->fence_push_full, relaxed);
        out->rx_full_latch    += duct_atomic_load(&st->rx_full_latch, relaxed);
        out->io_loop_pass     += duct_atomic_load(&st->loop_pass, relaxed);
        out->io_busy_spin     += duct_atomic_load(&st->busy_spin, relaxed);
        out->io_busy_enter    += duct_atomic_load(&st->busy_enter, relaxed);
        out->io_busy_exit     += duct_atomic_load(&st->busy_exit, relaxed);
        out->dgram_tx_real_kick      += duct_atomic_load(&st->dgram_tx_real_kick, relaxed);
        out->dgram_tx_real_kick_idle += duct_atomic_load(&st->dgram_tx_real_kick_idle, relaxed);
        out->dgram_shared_rx_drop    += duct_atomic_load(&st->dgram_shared_rx_drop, relaxed);
        out->dgram_rx_slot_route     += duct_atomic_load(&st->dgram_rx_slot_route, relaxed);
        out->dgram_rx_slot_copy      += duct_atomic_load(&st->dgram_rx_slot_copy, relaxed);
        out->dgram_tx_batch_calls    += duct_atomic_load(&st->dgram_tx_batch_calls, relaxed);
        out->dgram_tx_batch_msgs     += duct_atomic_load(&st->dgram_tx_batch_msgs, relaxed);
        out->dgram_tx_batch_max      = duct_max(out->dgram_tx_batch_max,
                                                duct_atomic_load(&st->dgram_tx_batch_max, relaxed));
        out->dgram_lane_sent         += duct_atomic_load(&st->dgram_tx_lane_sent, relaxed);
        out->dgram_tx_gso_writes     += duct_atomic_load(&st->dgram_tx_gso_writes, relaxed);
        out->dgram_tx_gso_dgrams     += duct_atomic_load(&st->dgram_tx_gso_dgrams, relaxed);
        out->dgram_rx_gro_reads      += duct_atomic_load(&st->dgram_rx_gro_reads, relaxed);
        out->dgram_rx_gro_dgrams     += duct_atomic_load(&st->dgram_rx_gro_dgrams, relaxed);
        out->vnet_rx_tso_reads       += duct_atomic_load(&st->vnet_rx_tso_reads, relaxed);
        out->vnet_rx_tso_pkts        += duct_atomic_load(&st->vnet_rx_tso_pkts, relaxed);
        out->vnet_rx_drop            += duct_atomic_load(&st->vnet_rx_drop, relaxed);
        out->tcp_writes              += duct_atomic_load(&st->tcp_writes, relaxed);
        out->tcp_eor_writes          += duct_atomic_load(&st->tcp_eor_writes, relaxed);
        out->tcp_lowat_reads         += duct_atomic_load(&st->tcp_lowat_reads, relaxed);
        out->tcp_lowat_sets          += duct_atomic_load(&st->tcp_lowat_sets, relaxed);
        out->tcp_rcvbuf_reads        += duct_atomic_load(&st->tcp_rcvbuf_reads, relaxed);
        out->tcp_rcvbuf_sets         += duct_atomic_load(&st->tcp_rcvbuf_sets, relaxed);
    }
    return true;
#else
    return false;
#endif
}

void duct_engine_stats_print(duct_engine_t *e, FILE *out, const char *tag)
{
    duct_do_if(!e || !out || !tag, return);
    duct_log(out, "%s: conn pool refused=%" PRIu64, tag, duct_conns_refused());
    duct_rt_stats_t st = {};
    if (!duct_engine_stats(e, &st)) {
        duct_log(out, "%s: engine stats compiled out", tag);
        return;
    }
    uint64_t offered = st.dgram_fast_sent + st.dgram_lane_staged,
             taken = st.dgram_rx_slot_route + st.dgram_rx_slot_copy;
    duct_log(out,
            "%s: fastpath tx_slow=%.2f%% rx_copy=%.2f%% batch_avg=%.2f"
            " batch_max=%" PRIu64,
            tag,
            offered ? 100.0 * (double)st.dgram_lane_staged / (double)offered : 0.0,
            taken ? 100.0 * (double)st.dgram_rx_slot_copy / (double)taken : 0.0,
            st.dgram_tx_batch_calls
                ? (double)st.dgram_tx_batch_msgs
                      / (double)st.dgram_tx_batch_calls
                : 0.0,
            st.dgram_tx_batch_max);
    duct_log(out,
            "%s: offload gso_writes=%" PRIu64 " gso_avg=%.2f"
            " gro_reads=%" PRIu64 " gro_avg=%.2f"
            " tso_reads=%" PRIu64 " tso_avg=%.2f"
            " vnet_gro_writes=%" PRIu64 " vnet_gro_avg=%.2f"
            " vnet_gro_single=%" PRIu64,
            tag,
            st.dgram_tx_gso_writes,
            st.dgram_tx_gso_writes
                ? (double)st.dgram_tx_gso_dgrams / (double)st.dgram_tx_gso_writes
                : 0.0,
            st.dgram_rx_gro_reads,
            st.dgram_rx_gro_reads
                ? (double)st.dgram_rx_gro_dgrams / (double)st.dgram_rx_gro_reads
                : 0.0,
            st.vnet_rx_tso_reads,
            st.vnet_rx_tso_reads
                ? (double)st.vnet_rx_tso_pkts / (double)st.vnet_rx_tso_reads
                : 0.0,
            st.vnet_tx_gro_writes,
            st.vnet_tx_gro_writes
                ? (double)st.vnet_tx_gro_pkts / (double)st.vnet_tx_gro_writes
                : 0.0,
            st.vnet_tx_gro_single);
    duct_log(out,
            "%s: train flush full=%" PRIu64 " end=%" PRIu64 " wait=%" PRIu64,
            tag, st.tx_train_flush_full, st.tx_train_flush_end, st.tx_train_flush_wait);
    duct_log(out,
            "%s: tcp writes=%" PRIu64 " eor=%" PRIu64 " cut=%" PRIu64
            " lowat_reads=%" PRIu64 " lowat_sets=%" PRIu64
            " rcvbuf_reads=%" PRIu64 " rcvbuf_sets=%" PRIu64,
            tag, st.tcp_writes, st.tcp_eor_writes, st.tcp_cut_writes,
            st.tcp_lowat_reads, st.tcp_lowat_sets, st.tcp_rcvbuf_reads, st.tcp_rcvbuf_sets);
    duct_log(out,
            "%s: drops tx=%" PRIu64 " rx=%" PRIu64 " defer_oom=%" PRIu64
            " vnet_rx=%" PRIu64 " vnet_tx=%" PRIu64,
            tag, st.dgram_shared_tx_drop, st.dgram_shared_rx_drop,
            st.defer_oom_drop, st.vnet_rx_drop, st.vnet_tx_drop);
    duct_log(out,
            "%s: backpressure commit_internal=%" PRIu64 " retry_saved=%" PRIu64
            " wfq_full=%" PRIu64 " tx_pool_fail=%" PRIu64
            " inter_held=%" PRIu64 " rx_stall=%" PRIu64 "/%" PRIu64,
            tag, st.commit_internal, st.retry_saved, st.wfq_push_full,
            st.tx_pool_acquire_fail, st.inter_held,
            st.rx_full_latch, st.rx_resume_post);
}

/** Section name for engine-level runtime counters. */
static constexpr char engine_section[] = "engine";

/** @brief Member @p member of the struct that checks the list, typed as the member of that name in @c duct_rt_stats_t. */
#define rt_member(member) typeof(((duct_rt_stats_t *)nullptr)->member) member;
/* A name the struct lacks or a name listed twice fails to compile, and a member the list
 * leaves out fails the size; the check stands in every build, runtime stats on or off. */
static_assert(sizeof(struct { duct_rt_stats_members(rt_member) }) == sizeof(duct_rt_stats_t),
    "duct_rt_stats_members names each member of duct_rt_stats_t once");
#undef rt_member

#if DUCT_RUNTIME_STATS
/** @brief Row of @c s_rt_fields for member @p member of @c duct_rt_stats_t. */
#define rt_field(member) duct_stat_field(duct_rt_stats_t, member),
/** @brief Table of every counter of @c duct_rt_stats_t by member name, which a reading reports under @c engine. */
static const duct_stat_field_t s_rt_fields[] = { duct_rt_stats_members(rt_field) };
#undef rt_field
#endif

duct_stats_t *duct_stats_create(duct_engine_t *e, const duct_stats_cfg_t *cfg)
{
    duct_do_if(!e || !cfg, return nullptr);
    if (duct_atomic_load(&e->state, acquire) != engine_state_running)
        return nullptr;
    return duct_stats_list_add(&e->stats, e->n_io + e->n_workers, cfg);
}

void duct_stats_read(duct_engine_t *e, duct_stats_visit_fn visit, void *ctx)
{
    duct_do_if(!e || !visit, return);
    duct_rt_stats_t rt;
    bool counted = duct_engine_stats(e, &rt);
    visit(ctx, engine_section, "conns_free", duct_conns_free());
    visit(ctx, engine_section, "conns_refused", duct_conns_refused());
    visit(ctx, engine_section, "stats_enabled", counted ? 1u : 0u);
#if DUCT_RUNTIME_STATS
    for (unsigned i = 0u; i < sizeof s_rt_fields / sizeof s_rt_fields[0]; ++i)
        visit(ctx, engine_section, s_rt_fields[i].name,
              *(const uint64_t *)((const char *)&rt + s_rt_fields[i].offset));
#endif
    duct_stats_list_read(&e->stats, visit, ctx);
}
