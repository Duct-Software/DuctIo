/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file handler_dispatch_test.c
 * @brief Integration tests: full worker handler dispatch path.
 *
 * Includes @c duct_worker.c directly to access static symbols
 * (@c s_dispatch_frame, @c s_hctx_async_done, @c s_this_worker,
 * @c duct_worker_t). Each test constructs a minimal worker + session + conn
 * with real OLBs, posts a frame via @c s_dispatch_frame, cycles the coro
 * runtime, and asserts on TX staging, RX acking, stream lifecycle, and
 * handler context cleanup.
 *
 * Tests:
 *   T1 handler_async_basic           — yield then done (1 response, teardown)
 *   T2 handler_async_multi_yield     — async_yield×2 then async_done
 *   T3 handler_async_done            — wait→wake→done cycle
 *   T4 handler_async_fin_delivers    — FIN frame reaches the parked handler
 *   T5 handler_async_concurrent_defer— second frame while handler busy → defer
 *   T6 handler_sf_basic           — stackful yield then done
 *   T7 handler_stream0_on_frame   — stream 0 goes to on_frame, not handler
 *   T8 handler_no_slots           — async_pool exhausted → on_error + stream close
 *   T9 handler_sf_concurrent_defer— stackful: second frame while coro busy → defer
 *  T10 handler_sf_fin_delivers    — stackful: FIN reaches it, RST still cancels
 *  T11 handler_async_fin_busy_defers — FIN while handler busy (in_wait=false) → defer, like any frame
 *  T12 handler_async_conn_lost_discard — conn-lost cancels the busy handler
 *      (RX-held frame acked) and the defer queue
 *  T13 frame_header_size_pinned_across_wire_rebind — task->header_size survives
 *      a defer/replay spanning a wire rebind gate
 *  T14 handler_async_interleaved_reset — two streams share w->response_out
 *      within one cycle; a bare yield (no EMIT) on one must never re-commit
 *      the other's already-sent response
 *  T15 frame_sealed_task_dropped_after_wire_switch — task->sealed_epoch,
 *      pinned at parse time like task->header_size (T13), must survive a
 *      proto_switch away from a sealed wire: a stale sealed task replaying
 *      once conn's wire-binding generation has moved past it is
 *      ack-and-dropped, never rerouted to on_frame
 *  T16 frame_sealed_stale_after_switch_no_double_ack — a sealed task deferred
 *      *after* ack-at-unseal (unlike T15's before) must not be double-acked
 *      when the codec it would have drained into is torn down first; the
 *      "ack already done" bit (duct_sealed_conn_ctx_t::head_unsealed) must
 *      outlive the codec that set it
 *  T17 frame_sealed_raw_mode_skips_empty_record — inner == nullptr must not
 *      dispatch a phantom empty frame for a record that unseals to zero
 *      cleartext bytes (a handshake-only record, in production)
 *  T18 frame_sealed_pre_ack_defer_stale_after_sealed_switch — the residual
 *      case T16 doesn't cover: deferred *before* ack-at-unseal (guard (a)),
 *      then a switch to a *different* sealed wire rather than a plain one —
 *      duct_conn_t::wire_epoch is what catches this uniformly
 *      with T15/T16, proving the stale task reaches neither the old nor
 *      the new engine's unseal
 *
 * Note: the defer replay path (batch_defer_node → s_defer_replay_node)
 * is not exercised here — that needs the engine-level io+WFQ harness. T5/T9
 * verify the defer @b decision (exec_defer return), not the replay. T12
 * pushes a defer node directly to exercise the discard without a full WFQ.
 */

#include "../src/duct_worker.c"
#include "duct_span.h"

#include "duct_io.h"
#include "duct_listener.h"
#include "duct_pmtu.h"
#include "duct_tls.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* AI-generated test code. */
static duct_x_slot_pool_t s_ct_pool;

static duct_x_slot_pool_t *s_ct_chunks_test(void)
{
    if (!s_ct_pool.range.base) {
        if (duct_x_slot_pool_init(&s_ct_pool, 8u,
                                  duct_x_slot_span_bytes(0u, 0u,
                                                         (uint32_t)duct_wire_ct_buf_max),
                                  0u, 0u, 4u, (duct_x_slot_hooks_t){}))
            duct_x_slot_pool_engage(&s_ct_pool);
        else
            duct_x_slot_pool_free(&s_ct_pool);
    }
    return s_ct_pool.range.base ? &s_ct_pool : nullptr;
}

/* ── Counters ─────────────────────────────────────────────────────── */

static unsigned s_create_calls,
                s_open_calls,
                s_close_calls,
                s_destroy_calls,
                s_on_frame_calls,
                s_on_error_calls;

/** @brief T16 forces s_on_frame to return rc_defer once, to reach
 *  s_dispatch_one_frame's own rc_defer exit (stream 0, no handler
 *  involved) without needing a multiplexed handler at all. */
static bool g_on_frame_defer;

/* ── Step mode selector ───────────────────────────────────────────── */

enum {
    step_done,
    step_yield_then_done,
    step_yield_x2_then_done,
    step_yield_then_wait,
    step_wait,
};
static unsigned g_step_mode = step_done;
static unsigned g_step_calls;

/* ── Mock protocol callbacks ──────────────────────────────────────── */

static duct_result_t s_on_frame([[maybe_unused]] duct_session_t *s,
                                [[maybe_unused]] duct_conn_id_t cid,
                                [[maybe_unused]] const duct_frame_t *fr,
                                [[maybe_unused]] duct_response_t *out,
                                [[maybe_unused]] void *proto_state)
{
    ++s_on_frame_calls;
    if (g_on_frame_defer) {
        g_on_frame_defer = false;
        return rc_defer;
    }
    out->payload = fr->payload;
    out->conn_id = duct_conn_id_same;
    out->stream_id = duct_stream_id_same;
    return rc_ok;
}

static duct_result_t s_on_session_open([[maybe_unused]] duct_session_t *s,
                                       [[maybe_unused]] duct_handle_t tok,
                                       [[maybe_unused]] void *user_ctx,
                                       [[maybe_unused]] duct_response_t *out,
                                       [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

static void s_on_session_close([[maybe_unused]] duct_session_t *s,
                               [[maybe_unused]] duct_close_reason_t reason,
                               [[maybe_unused]] void *proto_state)
{
}

static duct_result_t s_create_stream_state([[maybe_unused]] duct_session_t *s,
                                           [[maybe_unused]] duct_stream_id_t stream_id,
                                           [[maybe_unused]] void *ctx,
                                           void **out)
{
    ++s_create_calls;
    auto st = duct_new(int);
    duct_do_if(!st, return rc_no_memory);
    *st = (int)stream_id;
    *out = st;
    return rc_ok;
}

static void s_destroy_stream_state([[maybe_unused]] duct_session_t *s,
                                   [[maybe_unused]] duct_stream_id_t stream_id,
                                   [[maybe_unused]] void *ctx,
                                   void *state)
{
    ++s_destroy_calls;
    duct_del(state);
}

static duct_result_t s_on_stream_open([[maybe_unused]] duct_session_t *s,
                                      [[maybe_unused]] duct_stream_id_t stream_id,
                                      [[maybe_unused]] duct_response_t *out,
                                      [[maybe_unused]] void *stream_state)
{
    ++s_open_calls;
    return rc_ok;
}

static void s_on_stream_close([[maybe_unused]] duct_session_t *s,
                              [[maybe_unused]] duct_stream_id_t stream_id,
                              [[maybe_unused]] duct_close_reason_t reason,
                              [[maybe_unused]] void *stream_state)
{
    ++s_close_calls;
}

static duct_result_t s_on_error([[maybe_unused]] duct_session_t *s,
                                [[maybe_unused]] duct_result_t err,
                                [[maybe_unused]] duct_response_t *out,
                                [[maybe_unused]] void *proto_state)
{
    ++s_on_error_calls;
    return rc_ok;
}

/* ── Stackless handler step ───────────────────────────────────────── */

static duct_async_rc_t s_handler_step(void *state)
{
    auto hctx = (duct_stream_ctx_t *)state;
    hctx->out = (duct_response_t){
        .payload = hctx->frame.payload,
        .conn_id = duct_conn_id_same,
        .stream_id = duct_stream_id_same,
    };
    ++g_step_calls;
    switch (g_step_mode) {
    case step_yield_then_done:
        return g_step_calls >= 2u ? async_done : async_yield;
    case step_yield_x2_then_done:
        return g_step_calls >= 3u ? async_done : async_yield;
    case step_yield_then_wait:
        return g_step_calls >= 2u ? async_wait : async_yield;
    case step_wait:
        return async_wait;
    default:
        return async_done;
    }
}

/* ── Stackful handler func ────────────────────────────────────────── */

static bool g_sf_wait_mode = false;

static void s_handler_sf(void *arg)
{
    auto hctx = (duct_stream_ctx_t *)arg;
    hctx->out = (duct_response_t){
        .payload = hctx->frame.payload,
        .conn_id = duct_conn_id_same,
        .stream_id = duct_stream_id_same,
    };
    if (g_sf_wait_mode)
        duct_coro_wait();
    else
        duct_coro_yield();
}

/* ── Proto factories ──────────────────────────────────────────────── */

static duct_proto_t *s_make_proto_sl(void)
{
    return duct_proto_create(&(duct_proto_cfg_t){
        .name = "dispatch_sl_test",
        .on_frame = s_on_frame,
        .on_session_open = s_on_session_open,
        .on_session_close = s_on_session_close,
        .create_stream_state = s_create_stream_state,
        .destroy_stream_state = s_destroy_stream_state,
        .on_stream_open = s_on_stream_open,
        .on_stream_close = s_on_stream_close,
        .on_error = s_on_error,
        .flags = fl_proto_multiplexed,
        .handler_kind = handler_async,
        .handler_async = s_handler_step,
        .max_response = 4096u,
    });
}

static duct_proto_t *s_make_proto_sf(void)
{
    return duct_proto_create(&(duct_proto_cfg_t){
        .name = "dispatch_sf_test",
        .on_frame = s_on_frame,
        .on_session_open = s_on_session_open,
        .on_session_close = s_on_session_close,
        .create_stream_state = s_create_stream_state,
        .destroy_stream_state = s_destroy_stream_state,
        .on_stream_open = s_on_stream_open,
        .on_stream_close = s_on_stream_close,
        .on_error = s_on_error,
        .flags = fl_proto_multiplexed,
        .handler_kind = handler_coro,
        .handler_coro = s_handler_sf,
        .max_response = 4096u,
    });
}

/* ── Test fixture ─────────────────────────────────────────────────── */

#ifdef _WIN32
#include <ws2tcpip.h>
typedef int         duct_socklen_t;
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
typedef socklen_t   duct_socklen_t;
#endif

/** @brief Loopback TCP pair, @p out_a's kernel send buffer pre-saturated
 *  and @p out_b's end never drained -- @c send() on @p out_a stays
 *  reliably @c EAGAIN for the fixture's whole lifetime, so the worker-side
 *  TX fast path (duct_worker.c's x_tcp case) always falls through to
 *  ordinary OLB staging, matching what every existing assertion in this
 *  file already expects. A requested @c SO_SNDBUF alone is not enough --
 *  the kernel enforces its own minimum (e.g. Linux's net.core.wmem_min)
 *  regardless of what was requested, so this actively writes until a real
 *  @c EAGAIN instead of trusting the request. Portable: same
 *  connect-back-to-an-ephemeral-listener shim as test_helpers.h's own
 *  th_socketpair, not duplicated here since this file doesn't otherwise
 *  need that header.
 */
static void s_tiny_pair_open(duct_sock_t *out_a, duct_sock_t *out_b)
{
    duct_sock_t listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener != duct_sock_bad);
    struct sockaddr_in addr = { .sin_family = AF_INET };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    [[maybe_unused]] int brc = bind(listener, (struct sockaddr *)&addr, sizeof addr);
    assert(brc == 0);
    [[maybe_unused]] int lrc = listen(listener, 1);
    assert(lrc == 0);
    duct_socklen_t alen = sizeof addr;
    [[maybe_unused]] int grc = getsockname(listener, (struct sockaddr *)&addr, &alen);
    assert(grc == 0);

    duct_sock_t a = socket(AF_INET, SOCK_STREAM, 0);
    assert(a != duct_sock_bad);
    [[maybe_unused]] int crc = connect(a, (struct sockaddr *)&addr, sizeof addr);
    assert(crc == 0);
    duct_sock_t b = accept(listener, nullptr, nullptr);
    assert(b != duct_sock_bad);
    duct_sock_close(listener);

    int tiny = 1;
    duct_discard setsockopt(a, SOL_SOCKET, SO_SNDBUF, (const char *)&tiny, sizeof tiny);
#ifdef _WIN32
    u_long one = 1u;
    ioctlsocket(a, FIONBIO, &one);
#else
    int flags = fcntl(a, F_GETFL, 0);
    if (flags >= 0)
        duct_discard fcntl(a, F_SETFL, flags | O_NONBLOCK);
#endif
    /* Saturate for real: b is never read, so this loop terminates once the
     * kernel's actual (possibly clamped-up) send buffer is genuinely full.
     * Content is irrelevant -- never read meaningfully -- left uninitialized. */
    char filler[kbytes(64u)];
    for (;;) {
        int n = send(a, filler, sizeof filler, 0);
        if (n < 0)
            break; /* EAGAIN/EWOULDBLOCK -- saturated */
    }
    *out_a = a;
    *out_b = b;
}

typedef struct {
    duct_proto_t        *proto;
    duct_conn_t         *conn;
    duct_session_t      *s;
    duct_conn_handle_t   handle;
    duct_worker_t        w;
    duct_sock_t          peer_fd; /**< s_tiny_pair_open's unread end; f->conn->fd
                                    *  is the other end, closed by
                                    *  duct_conn_discard in s_fixture_fini. */
} s_fixture_t;

static constexpr size_t s_olb_cap = kbytes(8u);
static constexpr unsigned s_async_slots = 8u;
static constexpr unsigned s_stack_slots = 4u;
static constexpr unsigned s_stack_bytes = 65536u;

static void s_fixture_init(s_fixture_t *f, duct_proto_t *proto)
{
    *f = (s_fixture_t){};
    f->proto = proto;

    f->conn = duct_conn_acquire();
    assert(f->conn);
    f->handle = duct_conn_handle_get(f->conn);

    /* A real, live fd: duct_worker.c's x_tcp/x_raw TX fast path reads
     * conn->fd directly and asserts it is never duct_sock_bad -- the same
     * conn-fence liveness guarantee a properly admitted conn always has
     * (s_conn_create's own contract), which this synthetic fixture must
     * now honor too instead of relying on an unset zero default. */
    duct_sock_t conn_fd;
    s_tiny_pair_open(&conn_fd, &f->peer_fd);
    f->conn->fd = conn_fd;
    f->conn->xport_type = x_tcp;
    /* Model the IO-side EAGAIN latch explicitly. A transient kernel EAGAIN
     * can clear during fixture setup as ACKs arrive, even without a reader.
     * The latch is the tx header's io-line value, resident in page 0 ahead
     * of the carve. */
    duct_olb_tx_write_armed_set(duct_conn_tx_hdr(f->conn), true);
    duct_conn_carve_olb(f->conn, s_olb_cap, s_olb_cap);
    assert(duct_conn_rx_olb(f->conn) && duct_conn_tx_olb(f->conn));

    duct_response_t out = {};
    f->s = duct_session_open(f->proto, duct_conn_id_primary,
                             f->handle, nullptr, 0u, &out);
    assert(f->s);
    assert(duct_has(f->s->flags, fl_session_multiplexed));
    /* duct_session_open does not bind the conn's session_token (that's the
     * ctrl executor's job in production); do it here so duct_session_of
     * resolves. */
    auto live = duct_session_handle_from_live(f->s);
    duct_conn_session_bind(f->conn, *(duct_handle_t *)&live);

    auto cp = (&f->w.coop);
    auto rc = duct_coop_init(cp, s_stack_slots, s_async_slots, s_stack_bytes);
    assert(rc == rc_ok);
    duct_timers_init(&f->w.timers);

    s_this_worker = &f->w;
}

static void s_fixture_fini(s_fixture_t *f)
{
    /* Cancel live handlers while TLS worker is still set so
     * duct_stream_cancel can reach the coro runtime. */
    duct_session_streams_destroy(f->s);
    duct_timers_destroy(&f->w.timers);
    s_this_worker = nullptr;
    auto cp = (&f->w.coop);
    duct_coop_fini(cp);

    /* A conn-lost scenario already tore the conn down and drained its
     * release count: the slot moved on and the handle no longer resolves. */
    if (duct_conn_by_handle(f->handle))
        duct_conn_discard(f->conn); /* closes f->conn->fd, the other half of the pair */
    /* The fabricated worker owns what a sealed scenario lazily carved in it:
     * duct_worker_module_cleanup, the production freeing side, never runs here. */
    if (f->w.ct_chunks_live) {
        duct_x_slot_pool_free(&f->w.ct_chunks);
        f->w.ct_chunks_live = false;
    }
    duct_sock_close(f->peer_fd);
    duct_session_detach_leg(f->s, duct_conn_id_primary, close_normal);
    duct_proto_destroy(f->proto);
}

static void s_reset_counters(void)
{
    s_create_calls = 0u;
    s_open_calls = 0u;
    s_close_calls = 0u;
    s_destroy_calls = 0u;
    s_on_frame_calls = 0u;
    s_on_error_calls = 0u;
    g_step_calls = 0u;
    g_on_frame_defer = false;
}

/** @brief Write @p payload into the conn's RX OLB and call s_dispatch_frame. */
static duct_exec_rc_t s_post_frame(s_fixture_t *f,
                                   duct_stream_id_t stream_id,
                                   const char *payload, size_t len,
                                   duct_frame_flags_t flags)
{
    auto rx = duct_conn_rx_olb(f->conn);
    auto h = &rx->h;
    uint64_t prev = duct_atomic_load(&h->tail, relaxed);
    uint8_t *dst = duct_olb_rx_data(rx) + prev;
    memcpy(dst, payload, len);
    uint64_t new_tail = prev + (uint64_t)len;
    h->stage = (uint32_t)new_tail;
    duct_atomic_store(&h->tail, new_tail, release);

    duct_msg_frame_t task = {
        .stream_id = stream_id,
        .offset = (uint32_t)prev,
        .len = (uint32_t)len,
        .flags = flags,
    };
    return s_dispatch_frame(&f->w, f->handle, &task);
}

static size_t s_tx_published(s_fixture_t *f)
{
    return duct_olb_tx_published(duct_conn_tx_olb(f->conn));
}

static uint64_t s_rx_acked(s_fixture_t *f)
{
    return duct_atomic_load(&duct_conn_rx_olb(f->conn)->acked, relaxed);
}

/* ── T1: handler_async_basic ─────────────────────────────────────────── */

static void test_handler_async_basic(void)
{
    s_reset_counters();
    g_step_mode = step_yield_then_done;

    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    const char payload[] = "hello";
    auto rc = s_post_frame(&f, 5u, payload, sizeof payload, 0u);
    assert(rc == exec_done);
    assert(s_create_calls == 1u && s_open_calls == 1u);

    duct_coop_cycle((&f.w.coop));

    /* yield (response staged) then done (teardown): 2 steps, 1 response. */
    assert(g_step_calls == 2u);
    assert(s_tx_published(&f) == sizeof payload);
    assert(s_rx_acked(&f) == sizeof payload);
    assert(!duct_stream_state(f.s, 5u));
    assert(s_close_calls == 1u && s_destroy_calls == 1u);

    s_fixture_fini(&f);
    printf("  handler_async_basic OK\n");
}

/* ── T2: handler_async_multi_yield ───────────────────────────────────── */

static void test_handler_async_multi_yield(void)
{
    s_reset_counters();
    g_step_mode = step_yield_x2_then_done;

    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    const char payload[] = "multi";
    auto rc = s_post_frame(&f, 5u, payload, sizeof payload, 0u);
    assert(rc == exec_done);

    duct_coop_cycle((&f.w.coop));

    /* yield, yield (2 responses) then done (teardown): 3 steps, 2 responses. */
    assert(g_step_calls == 3u);
    assert(s_tx_published(&f) == 2u * sizeof payload);
    assert(s_rx_acked(&f) == sizeof payload);
    assert(!duct_stream_state(f.s, 5u));
    assert(s_close_calls == 1u && s_destroy_calls == 1u);

    s_fixture_fini(&f);
    printf("  handler_async_multi_yield OK\n");
}

/* ── T3: handler_async_done (yield→wait→wake→yield→done) ─────────────── */

static void test_handler_async_done(void)
{
    s_reset_counters();
    g_step_mode = step_yield_then_wait;

    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    const char payload1[] = "first";
    auto rc = s_post_frame(&f, 5u, payload1, sizeof payload1, 0u);
    assert(rc == exec_done);

    duct_coop_cycle((&f.w.coop));

    /* yield (response 1 staged) then wait (parks, acks). */
    assert(g_step_calls == 2u);
    assert(s_tx_published(&f) == sizeof payload1);
    assert(s_rx_acked(&f) == sizeof payload1);
    assert(duct_stream_state(f.s, 5u));
    auto slot = duct_session_stream_slot(f.s, 5u);
    assert(slot && slot->handler_ctx);
    assert(slot->handler_ctx->au->in_wait);

    /* Second frame wakes the coro: yield (response 2) then done (teardown). */
    g_step_mode = step_yield_then_done;
    g_step_calls = 0u;
    const char payload2[] = "second";
    rc = s_post_frame(&f, 5u, payload2, sizeof payload2, 0u);
    assert(rc == exec_done);

    duct_coop_cycle((&f.w.coop));

    assert(g_step_calls == 2u);
    assert(s_tx_published(&f) == sizeof payload1 + sizeof payload2);
    assert(s_rx_acked(&f) == sizeof payload1 + sizeof payload2);
    assert(!duct_stream_state(f.s, 5u));
    assert(s_close_calls == 1u && s_destroy_calls == 1u);

    s_fixture_fini(&f);
    printf("  handler_async_done OK\n");
}

/* ── T4: handler_async_fin_cancel ────────────────────────────────────── */

static void test_handler_async_fin_delivers(void)
{
    s_reset_counters();
    g_step_mode = step_yield_then_wait;

    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    const char payload[] = "fin-test";
    auto rc = s_post_frame(&f, 5u, payload, sizeof payload, 0u);
    assert(rc == exec_done);

    duct_coop_cycle((&f.w.coop));

    const char fin[] = "";
    rc = s_post_frame(&f, 5u, fin, 0u, fl_frame_fin);
    assert(rc == exec_done);

    assert(s_close_calls == 0u && s_destroy_calls == 0u);
    auto slot = duct_session_stream_slot(f.s, 5u);
    assert(slot && slot->handler_ctx);
    assert(duct_has(slot->flags, fl_stream_peer_done));

    rc = s_post_frame(&f, 5u, payload, sizeof payload, 0u);
    assert(rc == exec_done);
    assert(s_close_calls == 0u);

    s_fixture_fini(&f);
    printf("  handler_async_fin_delivers OK\n");
}

/* ── T5: handler_async_concurrent_defer ──────────────────────────────── */

static void test_handler_async_concurrent_defer(void)
{
    s_reset_counters();
    g_step_mode = step_yield_then_done;

    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    /* First frame creates the coro (in run queue, in_wait=false). */
    const char payload[] = "busy";
    auto rc = s_post_frame(&f, 5u, payload, sizeof payload, 0u);
    assert(rc == exec_done);

    /* Second frame before the cycle: handler is busy (in_wait=false) → defer. */
    rc = s_post_frame(&f, 5u, payload, sizeof payload, 0u);
    assert(rc == exec_defer);

    /* RX not acked yet (first frame not processed). */
    assert(s_rx_acked(&f) == 0u);

    duct_coop_cycle((&f.w.coop));

    /* After the cycle: yield (response) + done (teardown). */
    assert(s_rx_acked(&f) == sizeof payload);
    assert(!duct_stream_state(f.s, 5u));

    s_fixture_fini(&f);
    printf("  handler_async_concurrent_defer OK\n");
}

/* ── T6: handler_sf_basic ─────────────────────────────────────────── */

static void test_handler_sf_basic(void)
{
    s_reset_counters();

    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sf());

    const char payload[] = "stackful";
    auto rc = s_post_frame(&f, 5u, payload, sizeof payload, 0u);
    assert(rc == exec_done);
    assert(s_create_calls == 1u && s_open_calls == 1u);

    duct_coop_cycle((&f.w.coop));

    /* Stackful: yield (response staged) then func returns (done → teardown). */
    assert(s_tx_published(&f) == sizeof payload);
    assert(s_rx_acked(&f) == sizeof payload);
    assert(!duct_stream_state(f.s, 5u));
    assert(s_close_calls == 1u && s_destroy_calls == 1u);

    s_fixture_fini(&f);
    printf("  handler_sf_basic OK\n");
}

/* ── T7: handler_stream0_on_frame ─────────────────────────────────── */

static void test_handler_stream0_on_frame(void)
{
    s_reset_counters();
    g_step_mode = step_done;

    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    /* Stream 0 must go to on_frame, NOT the handler path. */
    const char payload[] = "stream-zero";
    auto rc = s_post_frame(&f, 0u, payload, sizeof payload, 0u);
    assert(rc == exec_done);

    assert(s_on_frame_calls == 1u);
    assert(s_create_calls == 0u && s_open_calls == 0u);
    assert(s_tx_published(&f) == sizeof payload);
    assert(s_rx_acked(&f) == sizeof payload);

    s_fixture_fini(&f);
    printf("  handler_stream0_on_frame OK\n");
}

/* ── T8: handler_no_slots ─────────────────────────────────────────── */

static void test_handler_no_slots(void)
{
    s_reset_counters();

    /* Use a fixture with async_slots=1 so the pool is exhausted after one coro. */
    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());
    /* Close the default runtime and re-open with 1 slot. */
    duct_coop_fini((&f.w.coop));
    auto rt_rc = duct_coop_init((&f.w.coop),
                                        0u, 1u, 0u);
    assert(rt_rc == rc_ok);
    s_this_worker = &f.w;

    /* First frame: create handler on stream 1, step returns async_wait (parks). */
    g_step_mode = step_wait;
    const char payload1[] = "occupy";
    auto rc = s_post_frame(&f, 1u, payload1, sizeof payload1, 0u);
    assert(rc == exec_done);
    duct_coop_cycle((&f.w.coop));
    assert(duct_stream_state(f.s, 1u));

    /* Second frame on stream 2: claim succeeds, sl_acquire fails → handler_oom. */
    s_on_error_calls = 0u;
    const char payload2[] = "no-slot";
    rc = s_post_frame(&f, 2u, payload2, sizeof payload2, 0u);
    assert(rc == exec_done);
    assert(s_on_error_calls == 1u);
    assert(!duct_stream_state(f.s, 2u));
    assert(s_rx_acked(&f) == sizeof payload1 + sizeof payload2);

    s_fixture_fini(&f);
    printf("  handler_no_slots OK\n");
}

/* ── T9: handler_sf_concurrent_defer ─────────────────────────────── */

static void test_handler_sf_concurrent_defer(void)
{
    s_reset_counters();
    g_sf_wait_mode = false;

    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sf());

    /* First frame creates the coro (in run queue). */
    const char payload[] = "sf-busy";
    auto rc = s_post_frame(&f, 5u, payload, sizeof payload, 0u);
    assert(rc == exec_done);

    /* Second frame before the cycle: handler is busy (state != coro_state_waiting) → defer. */
    rc = s_post_frame(&f, 5u, payload, sizeof payload, 0u);
    assert(rc == exec_defer);

    /* RX not acked yet (first frame not processed). */
    assert(s_rx_acked(&f) == 0u);

    duct_coop_cycle((&f.w.coop));

    /* After the cycle: yield (response) then func returns (done → teardown). */
    assert(s_tx_published(&f) == sizeof payload);
    assert(s_rx_acked(&f) == sizeof payload);
    assert(!duct_stream_state(f.s, 5u));
    assert(s_close_calls == 1u && s_destroy_calls == 1u);

    s_fixture_fini(&f);
    printf("  handler_sf_concurrent_defer OK\n");
}

/* ── T10: handler_sf_fin_cancel ──────────────────────────────────── */

static void test_handler_sf_fin_cancel(void)
{
    s_reset_counters();
    g_sf_wait_mode = true;

    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sf());

    /* Frame on stream 5 → handler enters coro_wait (parks). */
    const char payload[] = "sf-fin";
    auto rc = s_post_frame(&f, 5u, payload, sizeof payload, 0u);
    assert(rc == exec_done);

    duct_coop_cycle((&f.w.coop));

    const char fin[] = "";
    rc = s_post_frame(&f, 5u, fin, 0u, fl_frame_fin);
    assert(rc == exec_done);

    assert(s_close_calls == 0u && s_destroy_calls == 0u);
    auto slot = duct_session_stream_slot(f.s, 5u);
    assert(slot && slot->handler_ctx);
    assert(duct_has(slot->flags, fl_stream_peer_done));

    const char rst[] = "";
    rc = s_post_frame(&f, 5u, rst, 0u, fl_frame_rst);
    assert(rc == exec_done);
    assert(!duct_stream_state(f.s, 5u));
    assert(s_close_calls == 1u && s_destroy_calls == 1u);

    s_fixture_fini(&f);
    printf("  handler_sf_fin_delivers OK\n");
}

/* ── T11: handler_async_fin_busy_cancel ─────────────────────────────── */

static void test_handler_async_fin_busy_defers(void)
{
    s_reset_counters();
    g_step_mode = step_yield_then_done;

    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    /* First frame creates the coro (run queue, in_wait=false). No cycle yet. */
    const char payload[] = "busy-fin";
    auto rc = s_post_frame(&f, 5u, payload, sizeof payload, 0u);
    assert(rc == exec_done);
    auto slot = duct_session_stream_slot(f.s, 5u);
    assert(slot && slot->handler_ctx);
    assert(!slot->handler_ctx->au->in_wait);  /* busy, not parked */

    const char fin[] = "";
    rc = s_post_frame(&f, 5u, fin, 0u, fl_frame_fin);
    assert(rc == exec_defer);

    assert(s_close_calls == 0u && s_destroy_calls == 0u);
    slot = duct_session_stream_slot(f.s, 5u);
    assert(slot && slot->handler_ctx);
    assert(!duct_has(slot->flags, fl_stream_peer_done));

    assert(s_rx_acked(&f) == 0u);

    s_fixture_fini(&f);
    printf("  handler_async_fin_busy_defers OK\n");
}

/* ── T12: handler_async_conn_lost_discard ──────────────────────────────── */

static void test_handler_async_conn_lost_discard(void)
{
    s_reset_counters();
    g_step_mode = step_yield_then_done;

    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    /* First frame creates the coro, busy (no cycle yet): RX held, unacked. */
    const char payload[] = "held-frame";
    auto rc = s_post_frame(&f, 5u, payload, sizeof payload, 0u);
    assert(rc == exec_done);
    auto slot = duct_session_stream_slot(f.s, 5u);
    assert(slot && slot->handler_ctx);

    /* A second, unrelated frame batch for the same conn sits in the defer
     * queue (as a real WFQ-full/busy defer would leave it) — conn-lost
     * discard must ack it too, not just the handler's held frame. The node
     * carves its production home, the session's defer region, so the discard
     * releases real units instead of freeing nothing. */
    static constexpr uint32_t defer_len = 7u;
    auto node = (batch_defer_node_t *)s_defer_region_take(f.s, s_defer_units_of(1u));
    assert(node);
    node->from = 0u;
    node->batch = (duct_msg_frame_batch_t){
        .conn = f.handle.word,
        .n = 1u,
    };
    node->batch.frames[0] = (duct_msg_frame_t){
        .offset = 0u, .len = defer_len, .stream_id = 9u, .flags = 0u,
    };
    s_defer_node_push(&f.w.defer_q, node);
    assert(duct_bits_test(f.w.defer_q.mask, (unsigned)f.handle.idx));

    /* Simulate the I/O thread: quiesce, publish the lost, then run conn_lost
     * as the worker would after draining it off the WFQ normal lane.
     * duct_msg_conn_lost is a byte-copied VMQ payload (not heap-owned, see
     * s_conn_lost_publish in duct_io.c) — a stack-local mirrors that, not
     * duct_msg_new. */
    duct_conn_phase_t pre;
    duct_discard duct_conn_close_claim(f.conn, &pre);
    duct_discard duct_conn_phase_move(f.conn, conn_quiesced, conn_lost_posted);
    auto live = duct_session_handle_from_live(f.s);
    duct_msg_conn_lost msg = {
        .msg = { .exec_fn = duct_session_exec_conn_lost, .arg = nullptr },
        .conn = f.handle,
        .session = *(duct_handle_t *)&live,
        .reason = close_peer,
    };
    duct_discard msg.msg.exec_fn(&msg.msg);

    /* Handler cancelled (RX-held frame accounted), stream torn down, defer
     * node discarded, leg detached — session had one leg, so it also closed. */
    assert(!duct_stream_state(f.s, 5u));
    assert(s_close_calls == 1u && s_destroy_calls == 1u);
    slot = duct_session_stream_slot(f.s, 5u);
    assert(!slot || !slot->handler_ctx);
    assert(s_rx_acked(&f) == sizeof payload + defer_len);
    assert(!f.w.defer_q.q.head);
    assert(!duct_bits_test(f.w.defer_q.mask, (unsigned)f.handle.idx));
    assert(f.s->conn_count == 0u);

    s_fixture_fini(&f);
    printf("  handler_async_conn_lost_discard OK\n");
}

/* ── T13: frame_header_size_pinned_across_wire_rebind ─────────────── */

/** @brief task->header_size, not conn->wire, must survive a defer/replay
 *  spanning a wire rebind. Simulates the
 *  gate by toggling s->wire_rebind_next directly around a replay of the
 *  same duct_msg_frame_t — s_dispatch_frame never re-derives hdr from
 *  conn->wire (which stays nullptr throughout), so a wrong header_size
 *  would show up as a corrupted TX payload length/content, not a crash. */
static void test_frame_header_size_pinned_across_wire_rebind(void)
{
    s_reset_counters();
    g_step_mode = step_done;

    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    static constexpr uint32_t hdr_len = 4u;
    const char header[hdr_len] = { 'H', 'D', 'R', '!' };
    const char payload[] = "pinned-header-payload";

    auto rx = duct_conn_rx_olb(f.conn);
    auto h = &rx->h;
    uint64_t prev = duct_atomic_load(&h->tail, relaxed);
    uint8_t *dst = duct_olb_rx_data(rx) + prev;
    memcpy(dst, header, hdr_len);
    memcpy(dst + hdr_len, payload, sizeof payload);
    uint64_t new_tail = prev + hdr_len + (uint64_t)sizeof payload;
    h->stage = (uint32_t)new_tail;
    duct_atomic_store(&h->tail, new_tail, release);

    duct_msg_frame_t task = {
        .stream_id = 0u, /* stream 0 → on_frame directly, skips handler dispatch */
        .offset = (uint32_t)prev,
        .len = hdr_len + (uint32_t)sizeof payload,
        .header_size = hdr_len,
    };

    /* Gate up: fan-out in flight. Deferred, not delivered. */
    f.s->switch_next = f.proto;
    f.s->switch_stage = switch_fencing;
    auto rc = s_dispatch_frame(&f.w, f.handle, &task);
    assert(rc == exec_defer);
    assert(s_on_frame_calls == 0u);

    /* Fences landed: gate clears, replay the same descriptor unchanged. */
    f.s->switch_next = nullptr;
    f.s->switch_stage = switch_none;
    rc = s_dispatch_frame(&f.w, f.handle, &task);
    assert(rc == exec_done);
    assert(s_on_frame_calls == 1u);

    /* header_size from the task, pinned at parse time, must strip exactly
     * hdr_len bytes regardless of conn->wire (nullptr throughout this test). */
    assert(s_tx_published(&f) == sizeof payload);
    assert(memcmp(duct_conn_tx_data(f.conn), payload, sizeof payload) == 0);
    assert(s_rx_acked(&f) == task.len);

    s_fixture_fini(&f);
    printf("  frame_header_size_pinned_across_wire_rebind OK\n");
}

/* ── T14: handler_async_interleaved_reset ────────────────────────────── */

/** @brief Both streams run the same yield-then-done shape as T1
 *  (@c test_handler_async_basic): step 1 emits + async_yield (commits), step 2
 *  returns async_done with no EMIT (async_done never commits — only async_yield
 *  does). Stream A gets an extra step 2.5 in between: a bare async_yield with
 *  no EMIT at all. Both streams are created before any cycle, so the run
 *  queue drains A1, B1, A2(bare), B2, A3 within one @c duct_coop_cycle
 *  — B's step-1 commit lands strictly between A's step 1 and its bare
 *  step — same w->response_out A's *out points at. A's bare step
 *  relies on *out already being back at its reset default; if the reset
 *  discipline breaks, it re-commits B's already-sent response instead. */
static duct_stream_id_t g_interleave_a_stream;
static unsigned         g_interleave_a_calls;
static unsigned         g_interleave_b_calls;

static duct_async_rc_t s_handler_step_interleave(void *state)
{
    auto hctx = (duct_stream_ctx_t *)state;
    if (hctx->stream_id != g_interleave_a_stream) {
        ++g_interleave_b_calls;
        if (g_interleave_b_calls == 1u) {
            hctx->out = (duct_response_t){
                .payload = hctx->frame.payload,
                .conn_id = duct_conn_id_same, .stream_id = duct_stream_id_same,
            };
            return async_yield;
        }
        return async_done;
    }
    ++g_interleave_a_calls;
    if (g_interleave_a_calls == 1u) {
        hctx->out = (duct_response_t){
            .payload = hctx->frame.payload,
            .conn_id = duct_conn_id_same, .stream_id = duct_stream_id_same,
        };
        return async_yield;
    }
    /* Step 2: bare yield, no EMIT touch — must commit empty, not B's stale out. */
    return g_interleave_a_calls == 2u ? async_yield : async_done;
}

static duct_proto_t *s_make_proto_interleave(void)
{
    return duct_proto_create(&(duct_proto_cfg_t){
        .name = "interleave_test",
        .on_frame = s_on_frame,
        .on_session_open = s_on_session_open,
        .on_session_close = s_on_session_close,
        .create_stream_state = s_create_stream_state,
        .destroy_stream_state = s_destroy_stream_state,
        .on_stream_open = s_on_stream_open,
        .on_stream_close = s_on_stream_close,
        .on_error = s_on_error,
        .flags = fl_proto_multiplexed,
        .handler_kind = handler_async,
        .handler_async = s_handler_step_interleave,
        .max_response = 4096u,
    });
}

static void test_handler_async_interleaved_reset(void)
{
    s_reset_counters();
    g_interleave_a_stream = 10u;
    g_interleave_a_calls = 0u;
    g_interleave_b_calls = 0u;

    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_interleave());

    /* Both streams created (queued to run, not yet stepped) before any cycle:
     * run queue is [A, B] in creation order. */
    const char payload_a[] = "AAAA";
    const char payload_b[] = "BB";
    auto rc = s_post_frame(&f, g_interleave_a_stream, payload_a, sizeof payload_a, 0u);
    assert(rc == exec_done);
    rc = s_post_frame(&f, 20u, payload_b, sizeof payload_b, 0u);
    assert(rc == exec_done);

    duct_coop_cycle((&f.w.coop));

    assert(g_interleave_a_calls == 3u && g_interleave_b_calls == 2u);
    assert(s_create_calls == 2u && s_open_calls == 2u);
    assert(s_close_calls == 2u && s_destroy_calls == 2u);
    /* Exactly the two real payloads — no leaked re-send of B's response
     * during A's bare-yield step. */
    assert(s_tx_published(&f) == sizeof payload_a + sizeof payload_b);
    assert(s_rx_acked(&f) == sizeof payload_a + sizeof payload_b);
    assert(!duct_stream_state(f.s, g_interleave_a_stream));
    assert(!duct_stream_state(f.s, 20u));

    s_fixture_fini(&f);
    printf("  handler_async_interleaved_reset OK\n");
}

/* ── T15: frame_sealed_task_dropped_after_wire_switch ─────────────── */

/** @brief task->sealed_epoch, not conn->wire->unseal, decides
 *  s_dispatch_frame's sealed/plain branch — pinned at parse time exactly
 *  like task->header_size (T13), for the identical reason: a proto_switch
 *  away from a sealed wire can complete while a task parsed under the old
 *  wire still sits deferred. Simulates the post-switch state directly,
 *  T13-style: a task stamped with a stale generation (1) replays once
 *  conn's own generation (conn->wire_epoch, fixture default 0 — no bind ever
 *  ran) has already moved past it. Must ack-and-drop, never reach on_frame
 *  with the still-opaque bytes — stream 0 makes that observable via
 *  s_on_frame_calls. */
static void test_frame_sealed_task_dropped_after_wire_switch(void)
{
    s_reset_counters();
    g_step_mode = step_done;

    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    const char stale_bytes[] = "still-encrypted-garbage";

    auto rx = duct_conn_rx_olb(f.conn);
    auto h = &rx->h;
    uint64_t prev = duct_atomic_load(&h->tail, relaxed);
    uint8_t *dst = duct_olb_rx_data(rx) + prev;
    memcpy(dst, stale_bytes, sizeof stale_bytes);
    uint64_t new_tail = prev + (uint64_t)sizeof stale_bytes;
    h->stage = (uint32_t)new_tail;
    duct_atomic_store(&h->tail, new_tail, release);

    duct_msg_frame_t task = {
        .stream_id = 0u, /* on_frame path if (wrongly) delivered — see below */
        .offset = (uint32_t)prev,
        .len = (uint32_t)sizeof stale_bytes,
        .sealed_epoch = 1u, /* stamped as if parsed under sealed generation 1 */
    };

    /* f.conn starts at wire_epoch 0 (fixture default — no bind ever ran,
     * so no codec exists yet either): stands in for "conn has since moved
     * to a generation this task's own stamp no longer matches," T13's own
     * stand-in for a post-rebind conn->wire, one field over. */
    assert(!duct_conn_sealed_ctx(f.conn)->codec);
    assert(f.conn->wire_epoch == 0u);
    auto rc = s_dispatch_frame(&f.w, f.handle, &task);
    assert(rc == exec_done);

    /* Dropped, not misrouted: on_frame never saw the stale bytes as if they
     * were cleartext, and RX still advances so the ring does not stall. */
    assert(s_on_frame_calls == 0u);
    assert(s_rx_acked(&f) == task.len);

    s_fixture_fini(&f);
    printf("  frame_sealed_task_dropped_after_wire_switch OK\n");
}

/* ── Fake sealed (TLS-shaped) engines, for T16-T18 ────────────────────
 * Identity "cipher" (verbatim copy, no real crypto) so these tests can
 * drive s_dispatch_sealed_frame directly without a real handshake — only
 * dispatch/lifecycle correctness is under test here, not wire-format or
 * crypto correctness (tls_null_test.c already covers those end to end).
 * Two distinct engines (A/B), each with its own unseal call counter, so
 * T18 can prove a stale task never reaches *either* one across a
 * sealed-to-sealed switch. */

static duct_seal_engine_t *s_fake_engine_create(const struct duct_seal_engine_vtbl *self,
                                               [[maybe_unused]] void *cfg,
                                               [[maybe_unused]] duct_seal_role_t role)
{
    auto e = duct_new(duct_seal_engine_t);
    if (!e)
        return nullptr;
    *e = (duct_seal_engine_t){ .vtbl = self };
    return e;
}

static unsigned s_fake_engine_destroy_calls;

static void s_fake_engine_destroy(duct_seal_engine_t *e)
{
    ++s_fake_engine_destroy_calls;
    duct_del(e);
}

static unsigned s_fake_engine_a_unseal_calls;

static duct_result_t s_fake_engine_a_unseal([[maybe_unused]] duct_seal_engine_t *e,
                                            duct_view_u8 pdu, duct_unseal_ctx_t *ctx)
{
    ++s_fake_engine_a_unseal_calls;
    size_t cap = 0u;
    auto ct = (uint8_t *)ctx->reserve(ctx, &cap);
    if (pdu.size > cap)
        return rc_invalid_arg;
    if (pdu.size)
        memcpy(ct, pdu.data, pdu.size);
    if (!ctx->commit(ctx, pdu.size))
        return rc_invalid_arg;
    return rc_ok;
}

/** @brief Never exercised by T15-T18 (RX-only dispatch tests) — mandatory
 *  on the vtbl since duct_wire_create_sealed requires both, but a stub
 *  suffices since neither test drives duct_wire_t::on_pack. */
static size_t s_fake_engine_seal_size([[maybe_unused]] duct_seal_engine_t *e, size_t ct_len)
{
    return ct_len + 1u;
}

static void s_fake_engine_seal([[maybe_unused]] duct_seal_engine_t *e,
                               [[maybe_unused]] const duct_view_u8 *spans,
                               [[maybe_unused]] size_t n, [[maybe_unused]] void *dst) {}

/** @brief T19 only: records that duct_worker_tls_ensure_started actually
 *  reached the engine, and with which codec — never calls ctx->tx_append
 *  (that path's own duct_io_post_tx_drain reaches the global io-thread
 *  table, unset in this fixture; tls_null_test.c's own real-socket tests
 *  already cover tx_append itself end to end). */
static unsigned s_fake_engine_start_calls;
static duct_wire_codec_t *s_fake_engine_start_seen_codec;

static void s_fake_engine_start([[maybe_unused]] duct_seal_engine_t *e, duct_unseal_ctx_t *ctx)
{
    ++s_fake_engine_start_calls;
    s_fake_engine_start_seen_codec = ctx->codec;
}

static const duct_seal_engine_vtbl_t s_fake_engine_vtbl = {
    .create = s_fake_engine_create,
    .destroy = s_fake_engine_destroy,
    .unseal = s_fake_engine_a_unseal,
    .pdu_hdr_size = duct_tls_record_hdr_size,
    .pdu_len = duct_tls_record_len,
    .pdu_overhead = 0u,
    .pdu_ct_max = 256u,
    .engine_hs_budget = 64u,
    .seal_size = s_fake_engine_seal_size,
    .seal = s_fake_engine_seal,
    .start = s_fake_engine_start,
};

static unsigned s_fake_engine_b_unseal_calls;

static duct_result_t s_fake_engine_b_unseal([[maybe_unused]] duct_seal_engine_t *e,
                                            duct_view_u8 pdu, duct_unseal_ctx_t *ctx)
{
    ++s_fake_engine_b_unseal_calls;
    size_t cap = 0u;
    auto ct = (uint8_t *)ctx->reserve(ctx, &cap);
    if (pdu.size > cap)
        return rc_invalid_arg;
    if (pdu.size)
        memcpy(ct, pdu.data, pdu.size);
    if (!ctx->commit(ctx, pdu.size))
        return rc_invalid_arg;
    return rc_ok;
}

static const duct_seal_engine_vtbl_t s_fake_engine_b_vtbl = {
    .create = s_fake_engine_create,
    .destroy = s_fake_engine_destroy,
    .unseal = s_fake_engine_b_unseal,
    .pdu_hdr_size = duct_tls_record_hdr_size,
    .pdu_len = duct_tls_record_len,
    .pdu_overhead = 0u,
    .seal_size = s_fake_engine_seal_size,
    .seal = s_fake_engine_seal,
    .pdu_ct_max = 256u,
    .engine_hs_budget = 64u,
};

/* ── T16: frame_sealed_stale_after_switch_no_double_ack (V-1) ────── */

/** @brief A sealed task deferred *after* ack-at-unseal (head_unsealed
 *  true, rule c already ran) must not be double-acked if a proto_switch's
 *  fence tears the codec down before the defer resolves. Forces the defer
 *  via s_dispatch_one_frame's own rc_defer exit (stream 0, cfg->on_frame
 *  itself asks to be retried) — the simplest reachable path to "deferred
 *  after ack-at-unseal", no multiplexed handler needed. Simulates the
 *  switch itself the same way duct_conn_wire_rebind does (null wire/parser,
 *  then duct_conn_bind_wire against the new target — here f.proto, which
 *  has no wire, standing in for a switch to a plain proto and bumping
 *  wire_epoch in the process), then the fence landing by calling
 *  duct_session_exec_wire_fence directly (T12's own pattern for
 *  duct_session_exec_conn_lost, applied to the sibling fence), then
 *  retries the identical task. */
static void test_frame_sealed_stale_after_switch_no_double_ack(void)
{
    s_reset_counters();
    g_step_mode = step_done;

    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    auto sealed_wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = nullptr, .engine = &s_fake_engine_vtbl,
            .engine_cfg = nullptr, .role = seal_role_responder,
            .framing = seal_framing_stream });
    assert(sealed_wire);
    f.conn->wire = sealed_wire;
    auto sc = duct_conn_sealed_ctx(f.conn);
    assert(sc && !sc->codec);
    f.conn->wire_epoch = 1u; /* simulate the bind that installed sealed_wire */

    const char record[] = "some-app-data";

    auto rx = duct_conn_rx_olb(f.conn);
    auto h = &rx->h;
    uint64_t prev = duct_atomic_load(&h->tail, relaxed);
    uint8_t *dst = duct_olb_rx_data(rx) + prev;
    memcpy(dst, record, sizeof record);
    uint64_t new_tail = prev + (uint64_t)sizeof record;
    h->stage = (uint32_t)new_tail;
    duct_atomic_store(&h->tail, new_tail, release);

    duct_msg_frame_t task = {
        .stream_id = 0u,
        .offset = (uint32_t)prev,
        .len = (uint32_t)sizeof record,
        .sealed_epoch = 1u,
    };

    g_on_frame_defer = true;
    auto rc = s_dispatch_frame(&f.w, f.handle, &task);
    assert(rc == exec_defer);
    assert(s_on_frame_calls == 1u);
    assert(sc->codec && sc->head_unsealed);
    assert(s_rx_acked(&f) == task.len); /* rule (c) already ran */

    /* Simulate the switch landing mid-defer: duct_conn_wire_rebind's own
     * sequence (null wire/parser, then duct_conn_bind_wire against the
     * new target) bumps wire_epoch to 2 whether or not f.proto has a wire
     * of its own — it doesn't, standing in for a switch to a plain proto. */
    f.conn->wire = nullptr;
    f.conn->wire_parser = nullptr;
    auto bind_rc = duct_conn_bind_wire(f.conn, f.proto, nullptr);
    assert(bind_rc == rc_ok);
    assert(f.conn->wire_epoch == 2u);

    /* The fence's own codec teardown, separately: T12's own pattern for
     * duct_session_exec_conn_lost, applied to the sibling fence — this
     * fixture's session never sets wire_rebind_next, so the switch
     * machinery below the codec-teardown line is a no-op here; only that
     * teardown line is under test. */
    auto live = duct_session_handle_from_live(f.s);
    duct_msg_wire_fence fence_msg = {
        .msg = { .exec_fn = duct_session_exec_wire_fence, .arg = nullptr },
        .conn = f.handle.word,
        .session = *(duct_handle_t *)&live,
    };
    duct_discard fence_msg.msg.exec_fn(&fence_msg.msg);
    assert(!sc->codec);         /* detached */
    assert(sc->head_unsealed);  /* survives — still marks "ack already done" */

    rc = s_dispatch_frame(&f.w, f.handle, &task);
    assert(rc == exec_done);
    assert(s_on_frame_calls == 1u);  /* stale record never reaches on_frame again */
    assert(!sc->head_unsealed);      /* cleared by the stale-drop path */
    assert(s_rx_acked(&f) == task.len); /* not double-acked */

    s_fixture_fini(&f);
    duct_wire_destroy(sealed_wire);
    printf("  frame_sealed_stale_after_switch_no_double_ack OK\n");
}

/* ── T17: frame_sealed_raw_mode_skips_empty_record (V-3) ─────────── */

/** @brief inner == nullptr ("raw bytes over TLS") must not dispatch a
 *  phantom empty frame when a record unseals to zero cleartext bytes — the
 *  exact shape a handshake-only record has in production (the null
 *  engine's own hello exchange never calls commit). on_frame must
 *  never see it. */
static void test_frame_sealed_raw_mode_skips_empty_record(void)
{
    s_reset_counters();
    g_step_mode = step_done;

    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    auto sealed_wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = nullptr, .engine = &s_fake_engine_vtbl,
            .engine_cfg = nullptr, .role = seal_role_responder,
            .framing = seal_framing_stream });
    assert(sealed_wire);
    f.conn->wire = sealed_wire;
    f.conn->wire_epoch = 1u;

    /* Zero-length PDU: the fake engine's unseal commits 0 bytes, exactly
     * like a handshake-only record that yields no application cleartext. */
    duct_msg_frame_t task = {
        .stream_id = 0u,
        .offset = 0u,
        .len = 0u,
        .sealed_epoch = 1u,
    };

    auto rc = s_dispatch_frame(&f.w, f.handle, &task);
    assert(rc == exec_done);
    assert(s_on_frame_calls == 0u);
    auto sc = duct_conn_sealed_ctx(f.conn);
    assert(sc && sc->codec && !sc->head_unsealed);

    s_fixture_fini(&f);
    duct_wire_destroy(sealed_wire);
    printf("  frame_sealed_raw_mode_skips_empty_record OK\n");
}

/* ── T18: frame_sealed_pre_ack_defer_stale_after_sealed_switch (V-1 residual) ── */

/** @brief The one case T16 doesn't cover: a task deferred *before*
 *  ack-at-unseal (stuck at guard (a), ct_buf too full for one more
 *  worst-case record) rather than after, and the switch lands on a
 *  *different* sealed wire rather than a plain one. Neither original
 *  staleness check (conn->wire nullness/sealedness, head_unsealed's own
 *  survival) could tell this case apart from a fresh task on the new
 *  wire — the epoch mismatch alone does, regardless of which guard the
 *  task was sitting behind or what the new generation's wire is. Forces
 *  guard (a) deterministically by setting codec->ct_len to the size of
 *  ct_buf directly (white-box — the mechanism that fills ct_buf, e.g. a parked
 *  handler's pin, is exercised elsewhere in tls_null_test.c's own
 *  sc_parked; this test is about the switch, not about how ct_buf got
 *  full). Proves the stale task reaches *neither* engine's unseal — engine
 *  A's count stays where it was (never touched for this task at all,
 *  since it deferred before ever calling unseal), and engine B's count
 *  stays at 0 (the fresh-codec-under-a-foreign-wire path this residual
 *  gap used to fall into never runs). */
static void test_frame_sealed_pre_ack_defer_stale_after_sealed_switch(void)
{
    s_reset_counters();
    g_step_mode = step_done;
    s_fake_engine_b_unseal_calls = 0u;

    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    auto wire_a = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = nullptr, .engine = &s_fake_engine_vtbl,
            .engine_cfg = nullptr, .role = seal_role_responder,
            .framing = seal_framing_stream });
    auto wire_b = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = nullptr, .engine = &s_fake_engine_b_vtbl,
            .engine_cfg = nullptr, .role = seal_role_responder,
            .framing = seal_framing_stream });
    assert(wire_a && wire_b);
    f.conn->wire = wire_a;
    auto sc = duct_conn_sealed_ctx(f.conn);
    assert(sc && !sc->codec);
    f.conn->wire_epoch = 1u;

    /* Pre-create the codec and jam it full, standing in for "a parked
     * handler elsewhere already pins this much of ct_buf" without needing
     * to actually build one here. */
    auto codec = duct_conn_codec_slot(f.conn);
    auto inner_parser = duct_conn_wire_parser_slot(f.conn, 1u);
    memset(codec, 0, sizeof *codec);
    memset(inner_parser, 0, duct_wire_parser_slot);
    codec = wire_a->init_codec(wire_a, x_tcp, codec, inner_parser, s_ct_chunks_test());
    assert(codec);
    sc->codec = codec;
    codec->ct_len = (uint32_t)duct_x_slot_obj_cap(duct_at(codec->ct_buf));
    unsigned unseal_a_before = s_fake_engine_a_unseal_calls;

    const char record[] = "one-more-record";
    auto rx = duct_conn_rx_olb(f.conn);
    auto h = &rx->h;
    uint64_t prev = duct_atomic_load(&h->tail, relaxed);
    uint8_t *dst = duct_olb_rx_data(rx) + prev;
    memcpy(dst, record, sizeof record);
    uint64_t new_tail = prev + (uint64_t)sizeof record;
    h->stage = (uint32_t)new_tail;
    duct_atomic_store(&h->tail, new_tail, release);

    duct_msg_frame_t task = {
        .stream_id = 0u,
        .offset = (uint32_t)prev,
        .len = (uint32_t)sizeof record,
        .sealed_epoch = 1u,
    };

    /* Deferred at guard (a), strictly before unseal: head_unsealed never
     * sets, engine A's own unseal is never even attempted. */
    auto rc = s_dispatch_frame(&f.w, f.handle, &task);
    assert(rc == exec_defer);
    assert(!sc->head_unsealed);
    assert(s_fake_engine_a_unseal_calls == unseal_a_before);
    assert(s_rx_acked(&f) == 0u); /* not yet — this is the pre-ack sub-case */

    /* Switch to a *different* sealed wire — conn->wire is sealed again,
     * just not the instance that (would have) produced this task. */
    f.conn->wire = wire_b;
    f.conn->wire_epoch = 2u;

    rc = s_dispatch_frame(&f.w, f.handle, &task);
    assert(rc == exec_done);
    assert(s_on_frame_calls == 0u);
    assert(s_on_error_calls == 0u); /* dropped quietly, not treated as a fatal record */
    assert(s_fake_engine_a_unseal_calls == unseal_a_before); /* still never called */
    assert(s_fake_engine_b_unseal_calls == 0u); /* never handed to the new engine either */
    assert(s_rx_acked(&f) == task.len); /* ack happens exactly once, on the stale-drop */

    s_fixture_fini(&f);
    duct_wire_destroy(wire_a);
    duct_wire_destroy(wire_b);
    printf("  frame_sealed_pre_ack_defer_stale_after_sealed_switch OK\n");
}

/* ── T19: tls_ensure_started_creates_codec_and_starts_once ── */

/** @brief duct_worker_tls_ensure_started is the one hook a client-role
 *  engine has to ever emit a first flight: verifies it lazily creates the
 *  codec exactly once and fires the engine's own start() on that fresh
 *  creation only — every call after the first, at any of its three
 *  production call sites (session
 *  bind, wire-fence finish, s_tx_stage_frame's own belt), must be a
 *  plain no-op check, never a second start(). */
static void test_tls_ensure_started_creates_codec_and_starts_once(void)
{
    s_reset_counters();
    g_step_mode = step_done;

    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    unsigned start_before = s_fake_engine_start_calls;
    auto sealed_wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .engine = &s_fake_engine_vtbl, .role = seal_role_initiator,
        .framing = seal_framing_stream });
    assert(sealed_wire);
    f.conn->wire = sealed_wire;
    assert(!duct_conn_sealed_ctx(f.conn)->codec);

    duct_discard duct_worker_tls_ensure_started(f.handle, (duct_view_u8){});
    auto sc = duct_conn_sealed_ctx(f.conn);
    assert(sc && sc->codec);
    assert(s_fake_engine_start_calls == start_before + 1u);
    assert(s_fake_engine_start_seen_codec == sc->codec);

    /* Idempotent: codec already exists, so this is a plain check — no
     * second start(), no second codec. */
    auto codec_after_first = sc->codec;
    duct_discard duct_worker_tls_ensure_started(f.handle, (duct_view_u8){});
    assert(sc->codec == codec_after_first);
    assert(s_fake_engine_start_calls == start_before + 1u);

    s_fixture_fini(&f);
    duct_wire_destroy(sealed_wire);
    printf("  tls_ensure_started_creates_codec_and_starts_once OK\n");
}

/** @brief Holders of @p codec's cleartext buffer, as its allocation header counts
 *  them: 0 for one, 1 once a shared block is down to its last, 2 and up with a pin
 *  beside the codec. */
static unsigned s_ct_holders(const duct_wire_codec_t *codec)
{
    auto buf = duct_at(codec->ct_buf);
    auto pool = duct_x_slot_pool_of(buf);
    return duct_x_slot_hold_count(pool, duct_x_slot_index(pool, buf));
}

/* ── T20: retry_frame_save_copies_ct_buf_and_frees_orphan ──────────── */

/** @brief A response echoing cleartext out of a sealed conn's codec->ct_buf
 *  is copied at save time rather than pinned. s_retry_payload_own runs ahead
 *  of s_retry_frame_save's alias check, so ct_buf keeps its one holder and
 *  a fence detaching sc->codec destroys the codec at once. */
static void test_retry_frame_save_copies_ct_buf_and_frees_orphan(void)
{
    s_reset_counters();
    g_step_mode = step_done;

    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    auto sealed_wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = nullptr, .engine = &s_fake_engine_vtbl,
            .engine_cfg = nullptr, .role = seal_role_responder,
            .framing = seal_framing_stream });
    assert(sealed_wire);
    f.conn->wire = sealed_wire;
    auto sc = duct_conn_sealed_ctx(f.conn);
    assert(sc && !sc->codec);
    f.conn->wire_epoch = 1u;

    unsigned destroy_before = s_fake_engine_destroy_calls;
    auto codec = duct_conn_codec_slot(f.conn);
    auto inner_parser = duct_conn_wire_parser_slot(f.conn, 1u);
    memset(codec, 0, sizeof *codec);
    memset(inner_parser, 0, duct_wire_parser_slot);
    codec = sealed_wire->init_codec(sealed_wire, x_tcp, codec, inner_parser, s_ct_chunks_test());
    assert(codec);
    sc->codec = codec;

    /* White-box: stand in for a record this conn's own RX side already
     * unsealed into ct_buf, the way a real on_frame echo would find it. */
    const uint8_t ct_data[] = "some-cleartext";
    memcpy(duct_at(codec->ct_buf), ct_data, sizeof ct_data);
    codec->ct_len = (uint32_t)sizeof ct_data;

    duct_response_t out = { .payload = { .data = duct_at(codec->ct_buf), .size = sizeof ct_data } };
    bool saved = s_retry_frame_save(&f.w, f.s, duct_conn_id_primary, 0u, fl_frame_none, &out, 0u);
    assert(saved);
    assert(s_ct_holders(codec) < 2u);
    auto node = f.w.retry_head;
    assert(node && node->kind == retry_frame && node->frame.pin == alias_none);
    assert(node->frame.out.payload.data != duct_at(codec->ct_buf));
    assert(duct_has(node->frame.out.flags, fl_send_owned) && !node->frame.out.release);
    assert(memcmp(node->frame.out.payload.data, ct_data, sizeof ct_data) == 0);

    duct_conn_sealed_codec_detach(f.conn);
    assert(!sc->codec);
    assert(s_fake_engine_destroy_calls == destroy_before + 1u);

    s_retry_frame_out_release(node);
    s_retry_node_drop(node);
    f.w.retry_head = nullptr;
    s_fixture_fini(&f);
    duct_wire_destroy(sealed_wire);
    printf("  retry_frame_save_copies_ct_buf_and_frees_orphan OK\n");
}

/** @brief A pin on the cleartext buffer blocks its compaction and outlives the
 *  codec: a fence detaching the codec destroys it at once, the engine with it, and
 *  the pinned bytes stay readable until the last pin lets go. */
static void test_ct_pin_blocks_compaction_and_outlives_codec(void)
{
    s_reset_counters();
    g_step_mode = step_done;

    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    auto sealed_wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = nullptr, .engine = &s_fake_engine_vtbl,
            .engine_cfg = nullptr, .role = seal_role_responder,
            .framing = seal_framing_stream });
    assert(sealed_wire);
    f.conn->wire = sealed_wire;
    auto sc = duct_conn_sealed_ctx(f.conn);
    auto codec = duct_conn_codec_slot(f.conn);
    auto inner_parser = duct_conn_wire_parser_slot(f.conn, 1u);
    memset(codec, 0, sizeof *codec);
    memset(inner_parser, 0, duct_wire_parser_slot);
    codec = sealed_wire->init_codec(sealed_wire, x_tcp, codec, inner_parser, s_ct_chunks_test());
    assert(sc && codec);
    sc->codec = codec;

    /* Four bytes parsed and acked, four still unparsed behind them. */
    uint8_t *block = duct_at(codec->ct_buf);
    memcpy(block, "AAAABBBB", 8u);
    codec->ct_len = 8u;
    codec->ct_parse_off = 4u;
    codec->ct_ack_off = 4u;

    duct_frame_ack_t ack = { .kind = ack_ct, .ct = { .data = block, .size = 4u } };
    s_frame_hold_pin(f.conn, ack);
    assert(s_ct_holders(codec) == 2u);
    s_codec_compact(codec);
    assert(codec->ct_parse_off == 4u && !memcmp(block, "AAAABBBB", 8u));

    s_ct_pin_release(f.conn, block);
    assert(s_ct_holders(codec) == 1u);
    assert(codec->ct_len == 4u && codec->ct_parse_off == 0u && codec->ct_ack_off == 0u);
    assert(!memcmp(block, "BBBB", 4u));

    s_frame_hold_pin(f.conn, ack);
    unsigned destroy_before = s_fake_engine_destroy_calls;
    duct_conn_sealed_codec_detach(f.conn);
    assert(!sc->codec);
    assert(s_fake_engine_destroy_calls == destroy_before + 1u);
    assert(!memcmp(block, "BBBB", 4u));
    s_ct_pin_release(f.conn, block);

    s_fixture_fini(&f);
    duct_wire_destroy(sealed_wire);
    printf("  ct_pin_blocks_compaction_and_outlives_codec OK\n");
}

/** @brief The control path's shape: an engine whose cleartext is its datagram behind
 *  the inner wire's header, so it outgrows the datagram by that header. */
static duct_result_t s_fake_engine_c_unseal([[maybe_unused]] duct_seal_engine_t *e,
                                            duct_view_u8 pdu, duct_unseal_ctx_t *ctx)
{
    auto inner = ctx->codec->inner;
    size_t cap = 0u;
    auto dst = (uint8_t *)ctx->reserve(ctx, &cap);
    if (inner->header_size + pdu.size > cap)
        return rc_invalid_arg;
    duct_discard inner->pack_header(inner, &(duct_frame_t){ .payload = pdu }, dst);
    memcpy(dst + inner->header_size, pdu.data, pdu.size);
    return ctx->commit(ctx, inner->header_size + pdu.size) ? rc_ok : rc_invalid_arg;
}

static const duct_seal_engine_vtbl_t s_fake_engine_c_vtbl = {
    .create = s_fake_engine_create,
    .destroy = s_fake_engine_destroy,
    .unseal = s_fake_engine_c_unseal,
    .pdu_hdr_size = duct_tls_record_hdr_size,
    .pdu_len = duct_tls_record_len,
    .pdu_overhead = 0u,
    .pdu_ct_max = 256u,
    .engine_hs_budget = 64u,
    .seal_size = s_fake_engine_seal_size,
    .seal = s_fake_engine_seal,
};

static unsigned s_region_frames;
static const void *s_region_at;
static size_t s_region_len;
static char s_region_bytes[64];

static duct_result_t s_region_on_frame([[maybe_unused]] duct_session_t *s,
                                       [[maybe_unused]] duct_conn_id_t cid,
                                       const duct_frame_t *fr,
                                       [[maybe_unused]] duct_response_t *out,
                                       [[maybe_unused]] void *proto_state)
{
    ++s_region_frames;
    s_region_at = fr->payload.data;
    s_region_len = fr->payload.size;
    memcpy(s_region_bytes, fr->payload.data, duct_min(fr->payload.size, sizeof s_region_bytes));
    return rc_drop;
}

/** @brief One sealed datagram of a shared conn through s_inter_pkt: the engine
 *  names no cleartext size, so the cleartext lands in a heap block of the
 *  packet's own, which the packet's end hands back. The protocol sees the
 *  datagram's bytes whole, behind the inner wire's header where @p inner is
 *  given. */
static void s_region_scenario(const duct_seal_engine_vtbl_t *engine, const duct_wire_t *inner)
{
    s_region_frames = 0u;
    auto proto = s_make_proto_sl();
    assert(proto);
    proto->cfg.on_frame = s_region_on_frame;
    s_fixture_t f;
    s_fixture_init(&f, proto);
    auto wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .inner = inner, .engine = engine, .role = seal_role_responder,
        .framing = seal_framing_datagram });
    assert(wire);
    f.conn->wire = wire;
    f.conn->xport_type = x_udp_shared;
    *duct_conn_dgram_ctx(f.conn) = (duct_dgram_shared_ctx_t){};

    static const char dgram[] = "thirteen-byte";
    size_t len = sizeof dgram - 1u;
    alignas(16) char mem[512] = {};
    auto b = (duct_msg_inter_batch_t *)mem;
    b->conn = *(duct_handle_t *)&f.handle;
    b->n = 1u;
    b->pkts_off = sizeof *b;
    auto pkt = duct_msg_inter_pkts(b);
    pkt->offset = 256u;
    pkt->len = (uint32_t)len;
    memcpy(mem + pkt->offset, dgram, len);
    s_inter_pkt(f.handle, b, pkt);

    assert(s_region_frames == 1u);
    assert(s_region_len == len && !memcmp(s_region_bytes, dgram, len));
    auto sc = duct_conn_sealed_ctx(f.conn);
    assert(sc->codec && !sc->codec->ct_buf);

    *duct_conn_dgram_ctx(f.conn) = (duct_dgram_shared_ctx_t){};
    f.conn->xport_type = x_tcp;
    s_fixture_fini(&f);
    duct_wire_destroy(wire);
}

static void test_inter_pkt_decrypts_into_a_heap_block(void)
{
    s_reset_counters();
    s_region_scenario(&s_fake_engine_vtbl, nullptr);
    auto inner = duct_wire_create_length_prefix(0u);
    assert(inner);
    s_region_scenario(&s_fake_engine_c_vtbl, inner);
    duct_wire_destroy(inner);
    printf("  inter_pkt_decrypts_into_a_heap_block OK\n");
}

static unsigned s_slots_free(duct_x_slot_pool_t *pool)
{
    uint32_t taken[duct_dgram_rx_batch + 4u];
    unsigned n = 0u;
    for (uint32_t i; n < sizeof taken / sizeof *taken
                     && (i = duct_x_slot_acquire(pool)) != treiber_empty; )
        taken[n++] = i;
    for (unsigned i = 0u; i < n; ++i)
        duct_x_slot_release(pool, taken[i]);
    return n;
}

/** @brief A plain datagram a stream handler claims stays in its RX slot: the
 *  slot is out of the pool until the handler lets the frame go, the claim past
 *  the pool's headroom of one read batch copies, and the copy's slot goes back
 *  with the lane's hold. */
static void test_inter_pkt_claim_pins_the_rx_slot(void)
{
    s_reset_counters();
    g_step_mode = step_yield_then_done;
    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    duct_x_slot_pool_t pool;
    bool ok = duct_x_slot_pool_init(&pool, duct_dgram_rx_batch + 1u, 256u,
                                    0u, duct_dgram_record_hdr_size, duct_dgram_rx_batch + 1u,
                                    (duct_x_slot_hooks_t){});
    assert(ok);
    static const char dgram[] = "claimed";
    alignas(16) char mem[256] = {};
    uint32_t slot[2];
    duct_stream_id_t sid[2] = { 5u, 6u };
    for (unsigned i = 0u; i < 2u; ++i) {
        slot[i] = duct_x_slot_acquire(&pool);
        assert(slot[i] != treiber_empty);
        memcpy(duct_x_slot_data(&pool, slot[i]) + 8, dgram, sizeof dgram);
        auto b = (duct_msg_inter_batch_t *)mem;
        *b = (duct_msg_inter_batch_t){
            .conn = *(duct_handle_t *)&f.handle, .n = 1u, .pkts_off = sizeof *b,
            .rx_pool = &pool, .rx_slot = slot[i],
        };
        auto pkt = duct_msg_inter_pkts(b);
        *pkt = (duct_msg_inter_pkt_t){ .offset = 8u, .len = sizeof dgram, .stream_id = sid[i] };
        s_inter_pkt(f.handle, b, pkt);
    }
    auto pinned = duct_session_stream_slot(f.s, sid[0])->handler_ctx;
    auto copied = duct_session_stream_slot(f.s, sid[1])->handler_ctx;
    assert(pinned->ack.kind == ack_slot && pinned->ack.slot.idx == slot[0]);
    assert(pinned->frame.payload.data == duct_x_slot_data(&pool, slot[0]) + 8);
    assert(copied->ack.kind == ack_owned && copied->frame.payload.data != nullptr);
    assert(duct_x_slot_pool_owns(&pool, pinned->frame.payload.data));
    assert(!duct_x_slot_pool_owns(&pool, copied->frame.payload.data));
    assert(duct_atomic_load(&pool.claims, relaxed) == 1u);

    for (unsigned i = 0u; i < 2u; ++i)
        duct_io_rx_slot_drop(&pool, slot[i], false);
    assert(s_slots_free(&pool) == duct_dgram_rx_batch);

    for (unsigned n = 0u; n < 8u && (duct_session_stream_slot(f.s, sid[0])
                                     || duct_session_stream_slot(f.s, sid[1])); ++n)
        duct_coop_cycle((&f.w.coop));
    assert(!duct_session_stream_slot(f.s, sid[0]) && !duct_session_stream_slot(f.s, sid[1]));
    assert(s_slots_free(&pool) == duct_dgram_rx_batch + 1u);
    assert(duct_atomic_load(&pool.claims, relaxed) == 0u);

    duct_x_slot_pool_free(&pool);
    s_fixture_fini(&f);
    printf("  inter_pkt_claim_pins_the_rx_slot OK\n");
}

static void s_retry_drop_head(s_fixture_t *f)
{
    auto node = f->w.retry_head;
    assert(node);
    f->w.retry_head = node->next;
    if (!f->w.retry_head)
        f->w.retry_tail = nullptr;
    s_retry_node_drop(node);
}

/** @brief An answer to a datagram that lies in the batch's RX slot, parked on TX
 *  backpressure, is not copied: it takes a claim on the slot and rides it, the
 *  lane's release leaves the slot out, and the answer's own release is what
 *  returns it. A payload outside the slot, and a claim the pool's headroom
 *  refuses, both fall back to the copy. */
static void test_retry_frame_save_pins_the_rx_slot(void)
{
    s_reset_counters();
    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    uint32_t n = duct_dgram_rx_batch + 3u;
    duct_x_slot_pool_t pool;
    bool ok = duct_x_slot_pool_init(&pool, n, 256u, 0u, duct_dgram_record_hdr_size, n,
                                    (duct_x_slot_hooks_t){});
    assert(ok);
    uint32_t idx = duct_x_slot_acquire(&pool);
    assert(idx != treiber_empty);
    static const uint8_t src[] = "slot-resident-answer";
    uint8_t *at = duct_x_slot_data(&pool, idx) + 16;
    memcpy(at, src, sizeof src);
    duct_frame_ack_t cur = { .kind = ack_slot, .slot = { .pool = &pool, .idx = idx } };
    f.w.slot_now = &cur;

    duct_response_t out = { .payload = { .data = at, .size = sizeof src } };
    bool saved = s_retry_frame_save(&f.w, f.s, duct_conn_id_primary, 0u, fl_frame_none, &out, 0u);
    assert(saved);
    auto node = f.w.retry_head;
    assert(node && node->kind == retry_frame && node->frame.pin == alias_none);
    assert(node->frame.out.payload.data == at && node->frame.out.payload.size == sizeof src);
    assert(duct_has(node->frame.out.flags, fl_send_owned) && node->frame.out.release);
    assert(duct_atomic_load(&pool.claims, relaxed) == 1u);

    duct_io_rx_slot_drop(&pool, idx, false);
    assert(s_slots_free(&pool) == n - 1u);
    duct_response_release_owned(&node->frame.out);
    assert(duct_atomic_load(&pool.claims, relaxed) == 0u);
    assert(s_slots_free(&pool) == n);
    s_retry_drop_head(&f);

    idx = duct_x_slot_acquire(&pool);
    at = duct_x_slot_data(&pool, idx) + 16;
    memcpy(at, src, sizeof src);
    cur.slot.idx = idx;
    static const uint8_t elsewhere[] = "not-in-the-slot";
    duct_response_t foreign = { .payload = { .data = (void *)elsewhere, .size = sizeof elsewhere } };
    saved = s_retry_frame_save(&f.w, f.s, duct_conn_id_primary, 0u, fl_frame_none, &foreign, 0u);
    assert(saved);
    node = f.w.retry_head;
    assert(node->frame.out.payload.data != elsewhere && !node->frame.out.release);
    assert(duct_atomic_load(&pool.claims, relaxed) == 0u);
    s_retry_frame_out_release(node);
    s_retry_drop_head(&f);

    uint32_t room = n - duct_dgram_rx_batch;
    for (uint32_t i = 0u; i < room; ++i)
        assert(duct_x_slot_claim(&pool, idx));
    duct_response_t refused = { .payload = { .data = at, .size = sizeof src } };
    saved = s_retry_frame_save(&f.w, f.s, duct_conn_id_primary, 0u, fl_frame_none, &refused, 0u);
    assert(saved);
    node = f.w.retry_head;
    assert(node->frame.out.payload.data != at && !node->frame.out.release);
    assert(memcmp(node->frame.out.payload.data, src, sizeof src) == 0);
    assert(duct_atomic_load(&pool.claims, relaxed) == room);
    s_retry_frame_out_release(node);
    s_retry_drop_head(&f);

    f.w.slot_now = nullptr;
    for (uint32_t i = 0u; i < room; ++i)
        duct_io_rx_slot_drop(&pool, idx, true);
    duct_io_rx_slot_drop(&pool, idx, false);
    assert(s_slots_free(&pool) == n);
    duct_x_slot_pool_free(&pool);
    s_fixture_fini(&f);
    printf("  retry_frame_save_pins_the_rx_slot OK\n");
}

/** @brief The same rule on the emit path: a handler whose frame is pinned in the RX
 *  slot and whose answer lies in that frame parks the answer with a claim of
 *  its own, so the handler's turn can end first and the slot waits for the
 *  answer. */
static void test_retry_emit_save_pins_the_handler_slot(void)
{
    s_reset_counters();
    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    uint32_t n = duct_dgram_rx_batch + 3u;
    duct_x_slot_pool_t pool;
    bool ok = duct_x_slot_pool_init(&pool, n, 256u, 0u, duct_dgram_record_hdr_size, n,
                                    (duct_x_slot_hooks_t){});
    assert(ok);
    uint32_t idx = duct_x_slot_acquire(&pool);
    static const uint8_t src[] = "frame-in-the-slot";
    uint8_t *at = duct_x_slot_data(&pool, idx) + 16;
    memcpy(at, src, sizeof src);
    assert(duct_x_slot_claim(&pool, idx));
    duct_io_rx_slot_drop(&pool, idx, false);

    auto hctx = duct_new(duct_stream_ctx_t);
    assert(hctx);
    *hctx = (duct_stream_ctx_t){
        .s = f.s, .stream_id = 1u, .conn_id = duct_conn_id_primary,
        .frame = { .payload = { .data = at, .size = sizeof src } },
        .ack = { .kind = ack_slot, .slot = { .pool = &pool, .idx = idx } },
        .out = { .payload = { .data = at + 6, .size = 4u }, .conn_id = duct_conn_id_primary },
    };
    bool saved = s_retry_emit_save(&f.w, hctx, duct_tx_ticket_fresh);
    assert(saved);
    auto node = f.w.retry_head;
    assert(node && node->kind == retry_emit && node->emit.hctx == hctx);
    assert(node->emit.out.payload.data == at + 6);
    assert(duct_has(node->emit.out.flags, fl_send_owned) && node->emit.out.release);
    assert(duct_atomic_load(&pool.claims, relaxed) == 2u);
    assert(hctx->frame.payload.data == at);

    duct_stream_cancel(hctx);
    duct_del(hctx);
    assert(!f.w.retry_head);
    assert(duct_atomic_load(&pool.claims, relaxed) == 0u);
    assert(s_slots_free(&pool) == n);
    duct_x_slot_pool_free(&pool);
    s_fixture_fini(&f);
    printf("  retry_emit_save_pins_the_handler_slot OK\n");
}

/* ── T21: wire_create_tls_rejects_oversized_hs_budget ────────────────
 * (config-class finding from ultrareview) */

/** @brief An engine's park holds two replies of engine_hs_budget and stages
 *  whole: a park larger than the smallest TX ring (duct_conn_tx_olb_cap) never
 *  stages, and every commit of the conn waits behind it. A stream conn adds no
 *  record header and no prefix, so its largest budget is half the ring.
 *  duct_wire_create_sealed rejects one byte more at construction; the largest
 *  that fits is accepted. noise_dgram pins the datagram framing's cap. */
static void test_wire_create_tls_rejects_oversized_hs_budget(void)
{
    size_t largest = duct_conn_tx_olb_cap / 2u;
    auto vt = s_fake_engine_vtbl;
    vt.engine_hs_budget = largest + 1u;
    auto rejected = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = nullptr, .engine = &vt,
            .engine_cfg = nullptr, .role = seal_role_responder,
            .framing = seal_framing_stream });
    assert(!rejected);

    vt.engine_hs_budget = largest;
    auto accepted = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = nullptr, .engine = &vt,
            .engine_cfg = nullptr, .role = seal_role_responder,
            .framing = seal_framing_stream });
    assert(accepted);

    duct_wire_destroy(accepted);
    printf("  wire_create_tls_rejects_oversized_hs_budget OK\n");
}

/* ── T22: retry_frame_save_copies_unrecognized_payload ────────────────
 * (inter-tx-retry task) */

static int   s_defensive_release_calls;
static void *s_defensive_release_arg;
static void s_defensive_release(void *arg)
{
    ++s_defensive_release_calls;
    s_defensive_release_arg = arg;
}

/** @brief A payload aliasing neither conn->rx_buf nor a sealed codec's
 *  ct_buf — an inter conn's own inter_lane message, freed the instant its
 *  dispatch returns — is copied and re-flagged fl_send_owned rather than
 *  parked as a raw pointer. Verifies the copy and the release wiring, and
 *  that an already fl_send_owned payload is left untouched: its own
 *  release/release_arg preserved, no second copy. */
static void test_retry_frame_save_copies_unrecognized_payload(void)
{
    s_reset_counters();
    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    static const uint8_t src[] = "unrecognized-source-bytes";
    duct_response_t out = { .payload = { .data = (void *)src, .size = sizeof src } };
    bool saved = s_retry_frame_save(&f.w, f.s, duct_conn_id_primary, 0u, fl_frame_none, &out, 0u);
    assert(saved);
    auto node = f.w.retry_head;
    assert(node && node->kind == retry_frame);
    assert(node->frame.pin == alias_none); /* neither known ring claimed it */
    assert(node->frame.out.payload.data != src);        /* copied, not aliased */
    assert(node->frame.out.payload.size == sizeof src);
    assert(memcmp(node->frame.out.payload.data, src, sizeof src) == 0);
    assert(duct_has(node->frame.out.flags, fl_send_owned));
    assert(!node->frame.out.release);

    s_retry_frame_out_release(node); /* the same release s_commit_response's cleanup routes */
    s_retry_node_drop(node);
    f.w.retry_head = nullptr;
    f.w.retry_tail = nullptr;

    static uint8_t owned_buf[8] = "owned";
    s_defensive_release_calls = 0;
    duct_response_t out2 = {
        .payload = { .data = owned_buf, .size = sizeof owned_buf },
        .flags = fl_send_owned,
        .release = s_defensive_release,
        .release_arg = owned_buf,
    };
    saved = s_retry_frame_save(&f.w, f.s, duct_conn_id_primary, 0u, fl_frame_none, &out2, 0u);
    assert(saved);
    node = f.w.retry_head;
    assert(node && node->frame.out.payload.data == owned_buf); /* untouched */
    assert(node->frame.out.release == s_defensive_release);
    assert(node->frame.out.release_arg == owned_buf);

    node->frame.out.release(node->frame.out.release_arg);
    assert(s_defensive_release_calls == 1);
    assert(s_defensive_release_arg == owned_buf);

    s_retry_node_drop(node);
    f.w.retry_head = nullptr;
    s_fixture_fini(&f);
    printf("  retry_frame_save_copies_unrecognized_payload OK\n");
}

/* ── T23: retry_frame_save_copies_rx_ring_payload ──────────────────── */

/** @brief The RX-ring half of the same rule: a copy-mode payload aliasing
 *  conn->rx_buf is taken into a buffer the response owns, leaving
 *  rx->held_frames at zero. The pin is what blocks compaction, so a response
 *  parked on TX backpressure holding one stops the conn reading for every
 *  other stream on it. */
static void test_retry_frame_save_copies_rx_ring_payload(void)
{
    s_reset_counters();
    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    auto rx = duct_conn_rx_olb(f.conn);
    assert(rx);
    static const uint8_t src[] = "ring-resident-bytes";
    assert(rx->h.buf_size > sizeof src);
    memcpy(duct_olb_rx_data(rx), src, sizeof src);

    duct_response_t out = { .payload = { .data = duct_olb_rx_data(rx), .size = sizeof src } };
    bool saved = s_retry_frame_save(&f.w, f.s, duct_conn_id_primary, 0u, fl_frame_none, &out, 0u);
    assert(saved);
    auto node = f.w.retry_head;
    assert(node && node->kind == retry_frame);
    assert(node->frame.pin == alias_none);
    assert(duct_atomic_load(&rx->held_frames, acquire) == 0u);
    assert(node->frame.out.payload.data != duct_olb_rx_data(rx));
    assert(node->frame.out.payload.size == sizeof src);
    assert(memcmp(node->frame.out.payload.data, src, sizeof src) == 0);
    assert(duct_has(node->frame.out.flags, fl_send_owned));
    assert(!node->frame.out.release);

    s_retry_frame_out_release(node);
    s_retry_node_drop(node);
    f.w.retry_head = nullptr;
    f.w.retry_tail = nullptr;
    s_fixture_fini(&f);
    printf("  retry_frame_save_copies_rx_ring_payload OK\n");
}

/* ── T23b: the TX retry region's node quota ─────────────────────────── */

/** @brief The conn block's own node slots: a take past the quota answers
 *  null, a frame save then refuses exactly as its allocation failing would
 *  (nothing parked, nothing consumed), and one release reopens exactly its
 *  slot, lowest-free-first. */
/* AI-generated test code. */
static void test_retry_region_node_quota(void)
{
    s_reset_counters();
    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    static retry_node_t *taken[duct_conn_retry_tx_nodes];
    for (uint32_t i = 0u; i < duct_conn_retry_tx_nodes; ++i) {
        taken[i] = s_retry_node_take(f.conn);
        assert(taken[i]);
    }
    assert(!s_retry_node_take(f.conn));

    static uint8_t src[8] = "quota";
    duct_response_t out = { .payload = { .data = src, .size = sizeof src } };
    assert(!s_retry_frame_save(&f.w, f.s, duct_conn_id_primary, 0u, fl_frame_none,
                               &out, 0u));
    assert(!f.w.retry_head);

    s_retry_node_release(f.conn, taken[duct_conn_retry_tx_nodes / 2u]);
    assert(s_retry_node_take(f.conn) == taken[duct_conn_retry_tx_nodes / 2u]);
    for (uint32_t i = 0u; i < duct_conn_retry_tx_nodes; ++i)
        s_retry_node_release(f.conn, taken[i]);
    auto whole = s_retry_node_take(f.conn);
    assert(whole);
    s_retry_node_release(f.conn, whole);

    s_fixture_fini(&f);
    printf("  retry_region_node_quota OK\n");
}

/* ── T23c: the TX retry region's copy slots ─────────────────────────── */

/** @brief The copy slots: a copy-mode payload at the per-copy ceiling parks
 *  on the conn's own region, one past the ceiling refuses as its allocation
 *  failing would, exhausting the slots refuses an in-range copy the same
 *  way, and releasing a regional payload returns its slot to a later save. */
/* AI-generated test code. */
static void test_retry_region_copy_slots(void)
{
    s_reset_counters();
    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    static uint8_t big[duct_conn_retry_tx_copy_max];
    memset(big, 0xc5, sizeof big);
    duct_response_t out = { .payload = { .data = big, .size = sizeof big } };
    assert(s_retry_frame_save(&f.w, f.s, duct_conn_id_primary, 0u, fl_frame_none,
                              &out, 0u));
    auto node = f.w.retry_head;
    assert(node && node->kind == retry_frame);
    assert(node->frame.out.payload.data != (void *)big);
    assert(s_retry_copy_is_regional(f.conn, node->frame.out.payload.data));
    assert(memcmp(node->frame.out.payload.data, big, sizeof big) == 0);

    duct_response_t huge = { .payload = { .data = big, .size = sizeof big + 1u } };
    assert(!s_retry_frame_save(&f.w, f.s, duct_conn_id_primary, 0u, fl_frame_none,
                               &huge, 0u));
    assert(f.w.retry_head == node);

    static uint8_t second[16] = "second-copy";
    duct_response_t out2 = { .payload = { .data = second, .size = sizeof second } };
    assert(s_retry_frame_save(&f.w, f.s, duct_conn_id_primary, 0u, fl_frame_none,
                              &out2, 0u));
    auto second_node = f.w.retry_tail;
    assert(second_node && second_node != node);

    static uint8_t third[8] = "third";
    duct_response_t out3 = { .payload = { .data = third, .size = sizeof third } };
    assert(!s_retry_frame_save(&f.w, f.s, duct_conn_id_primary, 0u, fl_frame_none,
                               &out3, 0u));
    assert(f.w.retry_tail == second_node);

    /* Releasing the first node's regional payload returns its copy slot: the
     * next in-range save parks on it. */
    s_retry_frame_out_release(node);
    assert(node->frame.out.payload.size == 0u);
    assert(s_retry_frame_save(&f.w, f.s, duct_conn_id_primary, 0u, fl_frame_none,
                              &out3, 0u));
    while (f.w.retry_head) {
        auto n = f.w.retry_head;
        f.w.retry_head = n->next;
        s_retry_frame_out_release(n);
        s_retry_node_drop(n);
    }
    f.w.retry_tail = nullptr;

    /* AI-generated test code. A copy wider than one unit spans consecutive
     * units: it parks while the whole budget is free, holds every unit while
     * it lives, and its release returns the span — the ceil its length
     * derives, matching the take. Fresh responses throughout: a successful
     * save consumes its response, the parked node taking the payload, so a
     * reused one would park an empty answer no copy unit covers. */
    static uint8_t wide[duct_conn_retry_tx_copy_max + 512u];
    memset(wide, 0x5a, sizeof wide);
    duct_response_t wout = { .payload = { .data = wide, .size = sizeof wide } };
    assert(s_retry_frame_save(&f.w, f.s, duct_conn_id_primary, 0u, fl_frame_none,
                              &wout, 0u));
    auto wide_node = f.w.retry_head;
    assert(wide_node && wide_node->kind == retry_frame);
    assert(s_retry_copy_is_regional(f.conn, wide_node->frame.out.payload.data));
    assert(memcmp(wide_node->frame.out.payload.data, wide, sizeof wide) == 0);
    static uint8_t fourth[8] = "fourth";
    duct_response_t out4 = { .payload = { .data = fourth, .size = sizeof fourth } };
    assert(!s_retry_frame_save(&f.w, f.s, duct_conn_id_primary, 0u, fl_frame_none,
                               &out4, 0u));
    s_retry_frame_out_release(wide_node);
    assert(wide_node->frame.out.payload.size == 0u);
    assert(s_retry_frame_save(&f.w, f.s, duct_conn_id_primary, 0u, fl_frame_none,
                              &out4, 0u));
    while (f.w.retry_head) {
        auto n = f.w.retry_head;
        f.w.retry_head = n->next;
        s_retry_frame_out_release(n);
        s_retry_node_drop(n);
    }
    f.w.retry_tail = nullptr;
    s_fixture_fini(&f);
    printf("  retry_region_copy_slots OK\n");
}

/* ── T24: retry_emit_save_keeps_the_handler_frame ──────────────────── */

/** @brief A TX-backpressure park on the emit path comes from async_yield, and
 *  include/duct_stream.h#duct_stream_frame keeps the frame live until the
 *  handler answers async_wait or async_done — so s_retry_emit_save leaves
 *  hctx->frame and its ring pin untouched, and s_retry_drain hands them on to
 *  the resumed step rather than dropping them at resolution. Releasing the pin
 *  at either point gives the handler a zeroed frame and frees the bytes it
 *  cached. The response's own copy-mode payload goes into the node as a copy,
 *  the frame staying where it is.
 *
 *  The second ack in the middle is the other half: s_hctx_rx_ack_only sums
 *  into duct_olb_rx_ack, so acking one frame twice moves head past bytes
 *  nobody read. */
static void test_retry_emit_save_keeps_the_handler_frame(void)
{
    s_reset_counters();
    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    auto rx = duct_conn_rx_olb(f.conn);
    assert(rx);
    static const uint8_t src[] = "frame-the-handler-still-holds";
    assert(rx->h.buf_size > sizeof src);
    memcpy(duct_olb_rx_data(rx), src, sizeof src);

    auto hctx = duct_new(duct_stream_ctx_t);
    assert(hctx);
    *hctx = (duct_stream_ctx_t){
        .s = f.s, .stream_id = 1u, .conn_id = duct_conn_id_primary,
        .frame = { .payload = { .data = duct_olb_rx_data(rx), .size = sizeof src } },
        .ack = { .kind = ack_ring,
                 .ring = { .task_len = sizeof src, .end_off = (uint32_t)sizeof src } },
        .out = { .payload = { .data = duct_olb_rx_data(rx), .size = sizeof src },
                 .conn_id = duct_conn_id_primary },
    };
    duct_discard duct_atomic_fetch(add, &rx->held_frames, 1u, release);

    bool saved = s_retry_emit_save(&f.w, hctx, duct_tx_ticket_fresh);
    assert(saved);
    assert(hctx->frame.payload.data == duct_olb_rx_data(rx));
    assert(hctx->frame.payload.size == sizeof src);
    assert(memcmp(hctx->frame.payload.data, src, sizeof src) == 0);
    assert(duct_atomic_load(&rx->held_frames, acquire) == 1u);

    auto node = f.w.retry_head;
    assert(node && node->kind == retry_emit && node->emit.hctx == hctx);
    assert(node->emit.out.payload.data != duct_olb_rx_data(rx));
    assert(memcmp(node->emit.out.payload.data, src, sizeof src) == 0);
    assert(duct_has(node->emit.out.flags, fl_send_owned));

    auto acked_before = duct_atomic_load(&rx->acked, acquire);
    s_hctx_rx_ack_only(hctx);
    assert(duct_atomic_load(&rx->acked, acquire) == acked_before);

    assert(s_retry_drain(&f.w));
    assert(!f.w.retry_head);
    assert(duct_atomic_load(&rx->held_frames, acquire) == 1u);
    assert(hctx->frame.payload.data == duct_olb_rx_data(rx));
    assert(memcmp(hctx->frame.payload.data, src, sizeof src) == 0);

    duct_stream_cancel(hctx);
    duct_del(hctx);
    assert(duct_atomic_load(&rx->held_frames, acquire) == 0u);
    s_fixture_fini(&f);
    printf("  retry_emit_save_keeps_the_handler_frame OK\n");
}

static unsigned s_block_holders(const void *block)
{
    auto hdr = (const duct_alloc_hdr_t *)((uintptr_t)block - sizeof(duct_alloc_hdr_t));
    return duct_atomic_load(&hdr->holders, relaxed);
}

/** @brief An answer parked on backpressure that lies inside the handler's own
 *  copy of the frame is not copied again: the node takes a share of the copy's
 *  block, and the handler's release of the frame leaves the node's hold. */
static void test_retry_emit_save_shares_the_owned_frame(void)
{
    s_reset_counters();
    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    static const uint8_t src[] = "frame-copy-the-handler-owns";
    auto copy = duct_at(duct_new(uint8_t, sizeof src));
    assert(copy);
    memcpy(copy, src, sizeof src);
    auto hctx = duct_new(duct_stream_ctx_t);
    assert(hctx);
    *hctx = (duct_stream_ctx_t){
        .s = f.s, .stream_id = 1u, .conn_id = duct_conn_id_primary,
        .frame = { .payload = { .data = copy, .size = sizeof src } },
        .ack = { .kind = ack_owned, .owned = { .ptr = copy } },
        .out = { .payload = { .data = copy + 6, .size = 9u }, .conn_id = duct_conn_id_primary },
    };

    bool saved = s_retry_emit_save(&f.w, hctx, duct_tx_ticket_fresh);
    assert(saved);
    auto node = f.w.retry_head;
    assert(node && node->kind == retry_emit && node->emit.hctx == hctx);
    assert(node->emit.out.payload.data == (void *)(copy + 6));
    assert(duct_has(node->emit.out.flags, fl_send_owned));
    assert(!node->emit.out.release && node->emit.out.release_arg == copy);
    assert(s_block_holders(copy) == 2u);

    duct_stream_cancel(hctx);
    duct_del(hctx);
    assert(!f.w.retry_head);
    s_fixture_fini(&f);
    printf("  retry_emit_save_shares_the_owned_frame OK\n");
}

/** @brief A datagram staged for a listener that sends from slots rides a slot and
 *  leaves only its reference in the lane; one for a listener without slots rides
 *  inline. A dry class refuses with the lane's wake armed, a size past the large
 *  class is refused for good, and an aborted staging gives its slot back. */
static void test_dgram_out_stages_into_a_send_slot(void)
{
    s_reset_counters();
    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());
    size_t caps[1] = { duct_dgram_tx_outbox_cap };
    duct_listener_t lst = {};
    lst.dgram_tx_outbox = duct_vmq_mpsc_create(1u, caps, 0u);
    assert(lst.dgram_tx_outbox);
    bool made = duct_listener_tx_slots_new(&lst, 128u, 8u);
    assert(made);
    auto pools = lst.tx_slots;
    duct_peer_t peer = { .family = AF_INET, .port = 4242u, .addr.v4 = { 10u, 0u, 0u, 7u } };
    auto ln = duct_mpsc_lane(lst.dgram_tx_outbox, f.w.worker_id);
    dgram_out_t o;
    duct_vmq_push_rc_t rc;

    /* Nothing is in circulation until the first take grows the first chunk. */
    assert(duct_atomic_load(&pools[0].live, relaxed) == 0u);
    assert(s_dgram_out_open(&lst, &peer, 1000u, &o, &rc));
    assert(duct_atomic_load(&pools[0].live, relaxed) == 1u);
    assert(o.pools == pools && o.ref != treiber_empty && !(o.ref & duct_x_slot_ref_large));
    assert(o.span.size == duct_x_slot_cap(&pools[0]) && o.entry->slot == o.ref);
    assert(o.span.size >= duct_pmtu_path_default);
    memset(o.span.data, 0x37, 1000u);
    s_dgram_out_publish(&o, 1000u);
    auto pos = duct_vmq_drain_begin(&ln);
    auto hdr = duct_vmq_drain_peek(&ln, &pos);
    assert(hdr);
    auto entry = (const duct_dgram_tx_entry_t *)hdr->payload;
    assert(entry->len == 1000u && entry->slot == o.ref && entry->peer.port == 4242u);
    assert(((const uint8_t *)duct_x_slot_span(pools, entry->slot).data)[999] == 0x37u);
    assert(pos.step <= vmq_msg_aligned(sizeof *entry) + 8u);
    pos.head += pos.step;
    duct_vmq_commit_head(&ln, pos.gen, pos.head);
    duct_x_slot_put(pools, o.ref);

    /* A size past the large class is refused for good; one past the small class
     * takes the large pool, which is still ungrown and so not yet dry. */
    assert(!s_dgram_out_open(&lst, &peer, duct_x_slot_cap(&pools[1]) + 1u, &o, &rc)
           && rc == vmq_push_too_large);
    assert(s_dgram_out_fits(&lst, 9000u));
    assert(duct_atomic_load(&pools[1].live, relaxed) == 0u);

    /* The small class grows chunk by chunk to its ceiling, then runs dry. */
    uint32_t n_small = (uint32_t)duct_len(pools[0].slots);
    auto held = duct_at(duct_new(uint32_t, n_small));
    assert(held);
    for (uint32_t i = 0u; i < n_small; ++i) {
        held[i] = duct_x_slot_take(pools, 100u);
        assert(held[i] != treiber_empty);
    }
    assert(duct_atomic_load(&pools[0].live, relaxed) == pools[0].n_chunks);
    assert(!s_dgram_out_fits(&lst, 100u));
    assert(!s_dgram_out_open(&lst, &peer, 100u, &o, &rc) && rc == vmq_push_full);
    assert(duct_vmq_ack_waiter(ln.ctrl));
    duct_x_slot_put(pools, held[0]);
    assert(s_dgram_out_open(&lst, &peer, 100u, &o, &rc));
    assert(o.ref == held[0]);
    s_dgram_out_abort(&o);
    assert(duct_x_slot_take(pools, 100u) == held[0]);
    for (uint32_t i = 0u; i < n_small; ++i)
        duct_x_slot_put(pools, held[i]);
    duct_del(held);

    lst.tx_slots = nullptr;
    assert(s_dgram_out_open(&lst, &peer, 300u, &o, &rc));
    assert(!o.pools && o.span.data == o.entry->data && o.span.size == 300u);
    memset(o.span.data, 0x11, 300u);
    s_dgram_out_publish(&o, 300u);
    pos = duct_vmq_drain_begin(&ln);
    hdr = duct_vmq_drain_peek(&ln, &pos);
    assert(hdr);
    entry = (const duct_dgram_tx_entry_t *)hdr->payload;
    assert(entry->len == 300u && ((const uint8_t *)entry->data)[299] == 0x11u);
    assert(s_dgram_out_fits(&lst, 300u));

    duct_listener_tx_slots_free(pools);
    duct_vmq_mpsc_del((duct_vmq_mpsc_t *)lst.dgram_tx_outbox);
    s_fixture_fini(&f);
    printf("  dgram_out_stages_into_a_send_slot OK\n");
}

#if !DUCT_EVENTS_MODEL_IOCP
/** @brief An owned block answered on a shared datagram listener under a wire
 *  that gathers is sent from where it lies: the batch entry's span holds a
 *  share of the block until the flush resolves it, and a park for want of
 *  lane room takes that same span over whole — one reference, from the entry
 *  to the node, no second share. */
static void test_commit_dgram_shared_holds_an_owned_block(void)
{
    s_reset_counters();
    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());
    auto wire = duct_wire_create_dgram_batch(0u, false);
    assert(wire);
    f.conn->wire = wire;
    f.conn->xport_type = x_udp_shared;
    duct_listener_t lst = {};
    auto dctx = duct_conn_dgram_ctx(f.conn);
    dctx->listener = &lst;
    duct_worker_dgram_batch_entry_t entries[2] = {};
    dgram_pass_t pass = { .entries = entries };
    f.w.dgram_pass = &pass;

    /* Past the span threshold, so the taker shares the block instead of
     * copying the payload out of it. */
    static uint8_t src[duct_tx_span_threshold + 64u];
    for (size_t i = 0u; i < sizeof src; ++i)
        src[i] = (uint8_t)(i * 7u + 1u);
    auto block = duct_at(duct_new(uint8_t, sizeof src + 4u));
    assert(block);
    memcpy(block + 4, src, sizeof src);
    duct_response_t out = {
        .payload = { .data = block + 4, .size = sizeof src },
        .flags = fl_send_owned, .release_arg = block, .conn_id = duct_conn_id_primary,
    };
    commit_ctx_t ctx = {
        .s = f.s, .out_conn = duct_conn_id_primary, .out = &out,
        .conn = f.conn, .handle = f.handle,
    };
    assert(s_commit_dgram_shared(&ctx) == commit_ok);
    assert(pass.n == 1u && pass.listener == &lst);
    auto e = &pass.entries[0];
    assert(!e->hdr_len);
    assert(duct_span_kind_of(&e->span) == span_ptr
           && duct_span_base(&e->span) == block
           && duct_span_off(&e->span) == 4u
           && duct_span_len(&e->span) == sizeof src);
    assert(s_block_holders(block) == 2u);
    duct_response_release_owned(&out);
    assert(s_block_holders(block) == 1u);

    bool parked = s_retry_dgram_tx_save(&f.w, e, &lst);
    assert(parked);
    auto node = f.w.retry_head;
    assert(node && node->kind == retry_dgram_tx);
    assert(node->dgram_tx.span.tagged_base == e->span.tagged_base
           && node->dgram_tx.span.off == e->span.off
           && node->dgram_tx.span.len == e->span.len);
    /* The park took the entry's reference over, not a second one. */
    assert(s_block_holders(block) == 1u);
    auto body = s_dgram_span_body(&node->dgram_tx.span);
    assert(body.data == (void *)(block + 4) && body.size == sizeof src);
    assert(!memcmp(body.data, src, sizeof src));

    s_retry_dgram_block_release(node);
    /* The release above dropped the last holder: the block is freed, nothing
     * of it may be read from here. */
    s_retry_node_drop(node);
    f.w.retry_head = nullptr;
    f.w.retry_tail = nullptr;
    f.w.dgram_parked = 0u;
    f.w.dgram_pass = nullptr;
    dctx->listener = nullptr;
    f.conn->xport_type = x_tcp;
    f.conn->wire = nullptr;
    duct_wire_destroy(wire);
    s_fixture_fini(&f);
    printf("  commit_dgram_shared_holds_an_owned_block OK\n");
}
#endif

/** @brief A response taken while an older ticket waits on its leg parks behind
 *  that ticket, and stages once it resolves. */
static void test_response_take_parks_behind_older_ticket(void)
{
    s_reset_counters();
    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());

    auto seq = s_tx_seq_of(f.conn);
    uint32_t older = duct_tx_ticket_fresh;
    assert(s_tx_ticket_take(seq, &older));

    static const char msg[] = "behind-the-older-ticket";
    duct_response_t out = { .payload = { .data = (void *)msg, .size = sizeof msg },
                            .flags = fl_send_static, .conn_id = duct_conn_id_primary };
    auto rc = s_response_take(f.s, &out, duct_conn_id_primary, 0u, fl_frame_none,
                              nullptr, nullptr);
    assert(rc == commit_internal);
    auto node = f.w.retry_head;
    assert(node && node->kind == retry_frame && node->frame.ticket != older);

    s_tx_ticket_resolve(seq);
    assert(s_retry_drain(&f.w));
    assert(!f.w.retry_head);
    assert(*seq.serve == *seq.next);

    s_fixture_fini(&f);
    printf("  response_take_parks_behind_older_ticket OK\n");
}

/** @brief A pending protocol switch waits while a response of the session is
 *  parked, and applies at that response's replay. */
static void test_switch_waits_for_parked_response(void)
{
    s_reset_counters();
    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());
    auto next = s_make_proto_sf();
    assert(next);

    auto seq = s_tx_seq_of(f.conn);
    uint32_t older = duct_tx_ticket_fresh;
    assert(s_tx_ticket_take(seq, &older));

    static const char msg[] = "framed-under-the-old-proto";
    duct_response_t out = { .payload = { .data = (void *)msg, .size = sizeof msg },
                            .flags = fl_send_static, .conn_id = duct_conn_id_primary };
    assert(duct_proto_switch(f.s, next, nullptr) == rc_ok);
    assert(s_response_take(f.s, &out, duct_conn_id_primary, 0u, fl_frame_none, nullptr, nullptr)
           == commit_internal);
    s_response_switch(f.s);
    assert(f.s->proto == f.proto);

    s_tx_ticket_resolve(seq);
    assert(s_retry_drain(&f.w));
    assert(!f.w.retry_head);
    assert(f.s->proto == next);

    s_fixture_fini(&f);
    duct_proto_destroy(next);
    printf("  switch_waits_for_parked_response OK\n");
}

/** @brief A conn's inter bit leaves @c inter_pending equal to the bits set when
 *  the scan pops it, so the scan's zero skip keeps firing. */
static void test_inter_pending_follows_armed_bits(void)
{
    duct_worker_t w = {};
    s_this_worker = &w;
    s_wmod.workers = &w;
    s_wmod.n_workers = 1u;

    static constexpr unsigned idx = 5u;

    duct_worker_inter_arm(0u, idx);
    duct_worker_inter_arm(0u, idx);
    assert(w.inter_pending == 1u);
    assert(s_inter_drain(&w) == 0u);
    assert(w.inter_pending == 0u);

    s_wmod.workers = nullptr;
    s_wmod.n_workers = 0u;
    s_this_worker = nullptr;
    printf("  inter_pending_follows_armed_bits OK\n");
}

/* One four-byte packet pushed onto the conn's lane, its bit armed, the way a producer leaves it. */
static void s_inter_conn_push(duct_conn_t *conn)
{
    alignas(16) char mem[sizeof(duct_msg_inter_batch_t) + sizeof(duct_msg_inter_pkt_t) + 4u] = {};
    auto b = (duct_msg_inter_batch_t *)mem;
    auto h = duct_conn_handle_get(conn);
    b->conn = *(duct_handle_t *)&h;
    b->n = 1u;
    b->pkts_off = sizeof *b;
    auto pkt = duct_msg_inter_pkts(b);
    pkt->offset = (uint32_t)(sizeof *b + sizeof *pkt);
    pkt->len = 4u;
    memcpy(mem + pkt->offset, "ping", 4u);
    auto ln = duct_mpsc_lane(duct_conn_lane(conn), 0u);
    assert(duct_vmq_push(&ln, inter_msg_batch, 0u, mem, sizeof mem) == vmq_push_ok);
    duct_worker_inter_arm(0u, duct_conn_idx_get(conn));
}

/** @brief The scan reads the lane of the conn its worker is bound to and no other, whatever the word
 *  says: a bit met on a conn that was never bound, is bound to another worker, or has finished its
 *  conn_lost consume is dropped with the lane unread. The last case is the bit armed behind the
 *  retire-done phase. */
static void test_inter_drain_follows_the_bound_worker(void)
{
    duct_worker_t w = {};
    s_this_worker = &w;
    s_wmod.workers = &w;
    s_wmod.n_workers = 1u;

    auto conn = duct_conn_acquire();
    assert(conn);
    conn->xport_type = x_inter;
    conn->worker_id = 0u;
    duct_conn_carve_lane(conn);
    auto ln = duct_mpsc_lane(duct_conn_lane(conn), 0u);

    /* Never bound: the ctrl that would bind it is still queued. */
    s_inter_conn_push(conn);
    assert(w.inter_pending == 1u);
    assert(s_inter_drain(&w) == 0u);
    assert(w.inter_pending == 0u);
    assert(duct_vmq_unread(ln.ctrl));

    /* Bound to another worker. */
    assert(duct_conn_phase_move(conn, conn_unbound, conn_bound));
    conn->worker_id = 1u;
    duct_worker_inter_arm(0u, duct_conn_idx_get(conn));
    assert(s_inter_drain(&w) == 0u);
    assert(duct_vmq_unread(ln.ctrl));
    conn->worker_id = 0u;

    /* Bound by this worker: the lane drains. */
    duct_worker_inter_arm(0u, duct_conn_idx_get(conn));
    assert(s_inter_drain(&w) == 1u);
    assert(w.inter_pending == 0u);
    assert(!duct_vmq_unread(ln.ctrl));

    /* Closed, lost posted and consumed: a push and an arm behind the
     * retire-done phase leave the lane unread. */
    assert(duct_conn_phase_move(conn, conn_bound, conn_quiesced));
    assert(duct_conn_phase_move(conn, conn_quiesced, conn_lost_posted));
    assert(duct_conn_phase_move(conn, conn_lost_posted, conn_retire_done));
    s_inter_conn_push(conn);
    assert(s_inter_drain(&w) == 0u);
    assert(w.inter_pending == 0u);
    assert(duct_vmq_unread(ln.ctrl));

    duct_conn_discard(conn);
    s_wmod.workers = nullptr;
    s_wmod.n_workers = 0u;
    s_this_worker = nullptr;
    printf("  inter_drain_follows_the_bound_worker OK\n");
}

/* A second leg joined to the fixture's session at conn id 1, an inter conn: it owns no ring and takes
 * no wire of its own, which is all the session's count needs of it. */
static duct_conn_t *s_join_second_leg(s_fixture_t *f)
{
    auto leg = duct_conn_acquire();
    assert(leg);
    leg->xport_type = x_inter;
    auto handle = duct_conn_handle_get(leg);
    auto join = duct_msg_new(duct_msg_conn_join, duct_session_exec_conn_join, nullptr);
    assert(join);
    join->conn = handle;
    join->conn_id = 1u;
    join->tok = duct_session_handle_from_live(f->s);
    assert(duct_session_exec_conn_join(join) == exec_done);
    assert(duct_session_conn_at(f->s, 1u).word == handle.word);
    return leg;
}

static void s_drop_second_leg(s_fixture_t *f, duct_conn_t *leg)
{
    duct_session_detach_leg(f->s, 1u, close_normal);
    duct_conn_discard(leg);
}

/* The fixture's primary leg lost, as io leaves it for the worker: quiesced, its conn_lost posted. */
static void s_primary_conn_lost(s_fixture_t *f)
{
    duct_conn_phase_t pre;
    duct_discard duct_conn_close_claim(f->conn, &pre);
    duct_discard duct_conn_phase_move(f->conn, conn_quiesced, conn_lost_posted);
    auto live = duct_session_handle_from_live(f->s);
    duct_msg_conn_lost lost = {
        .msg = { .exec_fn = duct_session_exec_conn_lost, .arg = nullptr },
        .conn = f->handle,
        .session = *(duct_handle_t *)&live,
        .reason = close_peer,
    };
    duct_discard lost.msg.exec_fn(&lost.msg);
}

/** @brief A leg that closes while its wire fence is still owed settles it with its conn_lost, so the
 *  switch finishes on the fences of the legs that remain instead of waiting for one io will not post.
 *  The second leg stands for the rest of the session; the owed state is what io leaves behind a conn it
 *  closed first: the sentinel on the conn, the count on the session. */
static void test_conn_lost_settles_the_owed_fence(void)
{
    s_reset_counters();
    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());
    auto next = s_make_proto_sf();
    assert(next);
    auto second = s_join_second_leg(&f);

    f.s->switch_next = next;
    f.s->switch_stage = switch_fencing;
    f.s->switch_pending = 2u;
    duct_atomic_store(&f.conn->wire_rebind_next, next, relaxed);

    s_primary_conn_lost(&f);
    assert(!duct_session_conn_at(f.s, duct_conn_id_primary).word);
    assert(f.s->switch_pending == 1u);
    assert(f.s->switch_next == next && f.s->switch_stage == switch_fencing);
    assert(f.s->proto == f.proto);

    auto live = duct_session_handle_from_live(f.s);
    duct_msg_wire_fence fence = {
        .msg = { .exec_fn = duct_session_exec_wire_fence, .arg = nullptr },
        .conn = duct_conn_handle_get(second).word,
        .session = *(duct_handle_t *)&live,
    };
    duct_discard fence.msg.exec_fn(&fence.msg);
    assert(f.s->proto == next);
    assert(!f.s->switch_next && f.s->switch_pending == 0u
           && f.s->switch_stage == switch_none);

    s_drop_second_leg(&f, second);
    s_fixture_fini(&f);
    duct_proto_destroy(next);
    printf("  conn_lost_settles_the_owed_fence OK\n");
}

/** @brief A leg that closed owing no fence settles nothing: with its sentinel already cleared by io, or
 *  no switch in flight, the count of the session stays where it is. */
static void test_conn_lost_settles_only_an_owed_fence(void)
{
    s_reset_counters();
    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());
    auto next = s_make_proto_sf();
    assert(next);
    auto second = s_join_second_leg(&f);

    f.s->switch_next = next;
    f.s->switch_stage = switch_fencing;
    f.s->switch_pending = 2u;
    assert(!duct_atomic_load(&f.conn->wire_rebind_next, relaxed));

    s_primary_conn_lost(&f);
    assert(f.s->switch_pending == 2u);
    assert(f.s->switch_next == next && f.s->switch_stage == switch_fencing);

    f.s->switch_next = nullptr;
    f.s->switch_stage = switch_none;
    f.s->switch_pending = 0u;
    s_drop_second_leg(&f, second);
    s_fixture_fini(&f);
    duct_proto_destroy(next);
    printf("  conn_lost_settles_only_an_owed_fence OK\n");
}

/** @brief A conn io has begun to close posts no wire fence: the one it owes is settled by its conn_lost,
 *  and a fence behind that message would reach a conn its worker has already confirmed. A quiesced conn
 *  and one with its conn_lost posted leave the lane empty and keep the sentinel; put back to open, the
 *  conn posts the fence and clears it. */
static void test_wire_rebind_posts_no_fence_once_closing(void)
{
    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());
    auto next = s_make_proto_sf();
    assert(next);
    f.conn->worker_id = 0u;

    auto wfq = duct_wfq_new(1u, 1u, kbytes(4u), kbytes(4u), kbytes(4u));
    assert(wfq);
    duct_wfq_route_t route = { .wfq = wfq, .n_workers = 1u, .n_io = 1u, .thread_id = 0u };
    auto ln = duct_mpsc_lane(wfq, duct_wfq_pri_lane(wfq_pri_norm, 0u, 1u, 0u, 1u));

    duct_atomic_store(&f.conn->wire_rebind_next, next, relaxed);
    duct_conn_phase_t pre;
    duct_discard duct_conn_close_claim(f.conn, &pre);
    duct_conn_wire_rebind(&route, f.conn);
    assert(!duct_vmq_unread(ln.ctrl));
    assert(duct_atomic_load(&f.conn->wire_rebind_next, relaxed) == next);

    duct_discard duct_conn_phase_move(f.conn, conn_quiesced, conn_lost_posted);
    duct_conn_wire_rebind(&route, f.conn);
    assert(!duct_vmq_unread(ln.ctrl));
    assert(duct_atomic_load(&f.conn->wire_rebind_next, relaxed) == next);

    duct_discard duct_conn_phase_move(f.conn, conn_lost_posted, conn_bound);
    duct_conn_wire_rebind(&route, f.conn);
    assert(duct_vmq_unread(ln.ctrl));
    assert(!duct_atomic_load(&f.conn->wire_rebind_next, relaxed));

    duct_vmq_mpsc_del(wfq);
    s_fixture_fini(&f);
    duct_proto_destroy(next);
    printf("  wire_rebind_posts_no_fence_once_closing OK\n");
}

/** @brief The §2 window, one deterministic edge per decrement boundary:
 *  an unbound close whose io-unit drop lands while a ctrl still holds its
 *  borrowed unit returns the slot only at the ctrl's own release; a bind
 *  racing an already-claimed close loses the word CAS without touching the
 *  phase; a release reaching zero over live request flags defers the slot's
 *  return to the posted node's run (@c rel_pend), which a racing re-post
 *  re-arms instead of finishing. */
static void test_close_races_ctrl_at_release_boundaries(void)
{
    duct_conn_pool_reclaim();
    unsigned free_before = duct_conns_free();

    auto conn = duct_conn_acquire();
    assert(conn);
    auto handle = duct_conn_handle_get(conn);
    conn->xport_type = x_tcp;
    duct_conn_ref_take(conn);
    duct_conn_phase_t pre;
    assert(duct_conn_close_claim(conn, &pre) && pre == conn_unbound);
    duct_conn_discard(conn);
    assert(duct_conns_free() == free_before - 1u);
    assert(duct_conn_by_handle(handle));
    duct_conn_release(conn);
    assert(!duct_conn_by_handle(handle));
    assert(duct_conns_free() == free_before);

    conn = duct_conn_acquire();
    assert(conn);
    handle = duct_conn_handle_get(conn);
    assert(duct_conn_close_claim(conn, &pre) && pre == conn_unbound);
    assert(!duct_conn_session_bind(conn, UINT64_MAX));
    assert(duct_conn_phase(conn) == conn_quiesced);
    duct_conn_discard(conn);
    assert(duct_conns_free() == free_before);

    conn = duct_conn_acquire();
    assert(conn);
    handle = duct_conn_handle_get(conn);
    auto word = duct_conn_gen_req(conn);
    uint64_t old = duct_atomic_load(word, relaxed);
    assert(duct_atomic_cas(strong, word, &old,
                           old | (uint64_t)fl_req_tx_drain, acq_rel, acquire));
    duct_conn_release(conn);
    assert(duct_conns_free() == free_before - 1u);
    assert(duct_conn_by_handle(handle));
    assert(duct_atomic_load(word, relaxed) & gen_req_rel_pend);
    duct_atomic_fetch(and, word, ~(uint64_t)gen_req_flags_mask, acq_rel);
    duct_conn_release_finish(conn, handle.gen);
    assert(!duct_conn_by_handle(handle));
    assert(duct_conns_free() == free_before);

    conn = duct_conn_acquire();
    assert(conn);
    handle = duct_conn_handle_get(conn);
    word = duct_conn_gen_req(conn);
    old = duct_atomic_load(word, relaxed);
    assert(duct_atomic_cas(strong, word, &old,
                           old | (uint64_t)fl_req_close, acq_rel, acquire));
    duct_conn_release(conn);
    duct_atomic_fetch(and, word, ~(uint64_t)gen_req_flags_mask, acq_rel);
    uint64_t repost = duct_atomic_load(word, relaxed);
    assert(duct_atomic_cas(strong, word, &repost,
                           repost | (uint64_t)fl_req_tx_drain, acq_rel, acquire));
    duct_conn_release_finish(conn, handle.gen);
    assert(duct_atomic_load(word, relaxed) & gen_req_rel_pend);
    assert(duct_conn_by_handle(handle));
    duct_atomic_fetch(and, word, ~(uint64_t)gen_req_flags_mask, acq_rel);
    duct_conn_release_finish(conn, handle.gen);
    assert(!duct_conn_by_handle(handle));
    assert(duct_conns_free() == free_before);

    printf("  close_races_ctrl_at_release_boundaries OK\n");
}

/** @brief Поправка 3a-2: the unbound-retire defer window. The close claim
 *  clears @c fl_req_close in the same CAS that quiesces the phase, so one
 *  word read never shows the flag gone while the phase still invites a
 *  bind-defer; a release crossing zero over the armed bit defers to the
 *  node's run, whose claim consumes the bit before the trailing finish
 *  returns the slot; a stale post landing after the claim finds no claim
 *  left to win, and the losing path's bit clear keeps the word finishable. */
static void test_unbound_defer_window_closes_with_close_post(void)
{
    duct_conn_pool_reclaim();
    unsigned free_before = duct_conns_free();

    auto conn = duct_conn_acquire();
    assert(conn);
    conn->xport_type = x_tcp;
    auto word = duct_conn_gen_req(conn);
    uint64_t old = duct_atomic_load(word, relaxed);
    assert(duct_atomic_cas(strong, word, &old,
                           old | (uint64_t)fl_req_close, acq_rel, acquire));
    duct_conn_phase_t pre;
    assert(duct_conn_close_claim(conn, &pre) && pre == conn_unbound);
    uint64_t claimed = duct_atomic_load(word, relaxed);
    assert(duct_gen_req_phase(claimed) == conn_quiesced);
    assert(!(claimed & (uint64_t)fl_req_close));
    duct_conn_release(conn);
    assert(duct_conns_free() == free_before);

    conn = duct_conn_acquire();
    assert(conn);
    conn->xport_type = x_tcp;
    auto handle = duct_conn_handle_get(conn);
    word = duct_conn_gen_req(conn);
    old = duct_atomic_load(word, relaxed);
    assert(duct_atomic_cas(strong, word, &old,
                           old | (uint64_t)fl_req_close, acq_rel, acquire));
    duct_conn_release(conn);
    assert(duct_atomic_load(word, relaxed) & gen_req_rel_pend);
    assert(duct_conn_by_handle(handle));
    assert(duct_conn_close_claim(conn, &pre) && pre == conn_unbound);
    claimed = duct_atomic_load(word, relaxed);
    assert(duct_gen_req_phase(claimed) == conn_quiesced);
    assert(!(claimed & (uint64_t)fl_req_close));
    assert(claimed & gen_req_rel_pend);
    old = claimed;
    assert(duct_atomic_cas(strong, word, &old,
                           old | (uint64_t)fl_req_close, acq_rel, acquire));
    assert(!duct_conn_close_claim(conn, &pre));
    duct_atomic_fetch(and, word, ~(uint64_t)fl_req_close, release);
    duct_conn_release_finish(conn, handle.gen);
    assert(!duct_conn_by_handle(handle));
    assert(duct_conns_free() == free_before);

    printf("  unbound_defer_window_closes_with_close_post OK\n");
}

/** @brief §5: the pin CAS against the generation bump, and the spent finish.
 *  A stale generation never pins — the bump the release finish took moved
 *  the word past the handle, so the pin CAS refuses the raw page-0 slot a
 *  poster would still address, taking nothing. A live word pins and
 *  saturates at 15; the quiesce claim then shuts the door on new pins with
 *  the nibble preserved; the count's 0-crossing hands the finish to the pin
 *  side as @c conn_spent, which the last unpin completes — and the unpin
 *  running first leaves the count's own finish to observe @c pins == 0 and
 *  complete itself. */
static void test_pin_cas_against_gen_bump(void)
{
    duct_conn_pool_reclaim();
    unsigned free_before = duct_conns_free();

    /* Stale generation: the release bumped the word past the handle. */
    auto conn = duct_conn_acquire();
    assert(conn);
    conn->xport_type = x_inter;
    auto stale = duct_conn_handle_get(conn);
    duct_conn_release(conn);
    assert(duct_conns_free() == free_before);
    assert(duct_conn_pin(duct_conn_block_at(stale.idx), stale.gen)
           == rc_closed);

    /* Live word: bind opens the pin gate; the nibble saturates at 15. */
    conn = duct_conn_acquire();
    assert(conn);
    conn->xport_type = x_inter;
    auto handle = duct_conn_handle_get(conn);
    assert(duct_conn_session_bind(conn, UINT64_MAX));
    assert(duct_conn_pin(conn, handle.gen) == rc_ok);
    assert((duct_atomic_load(duct_conn_gen_req(conn), relaxed)
            & gen_req_pins_mask) == 1ull << gen_req_pins_shift);
    for (unsigned i = 1u; i < 15u; ++i)
        assert(duct_conn_pin(conn, handle.gen) == rc_ok);
    assert(duct_conn_pin(conn, handle.gen) == rc_defer);

    /* The quiesce claim closes the pin door, nibble held in the word. */
    duct_conn_phase_t pre;
    assert(duct_conn_close_claim(conn, &pre) && pre == conn_bound);
    assert(duct_conn_pin(conn, handle.gen) == rc_closed);

    /* Count first: the 0-crossing marks the word spent; the last unpin
     * finishes it, not one unpin sooner. */
    duct_conn_release(conn);
    assert(duct_conn_phase(conn) == conn_spent);
    assert(duct_conns_free() == free_before - 1u);
    assert(duct_conn_by_handle(handle));
    for (unsigned i = 0u; i < 14u; ++i)
        duct_conn_unpin(conn);
    assert(duct_conns_free() == free_before - 1u);
    duct_conn_unpin(conn);
    assert(duct_conns_free() == free_before);
    assert(!duct_conn_by_handle(handle));

    /* Pin side first: the last unpin on a count still holding its unit is
     * a no-op; the count's own finish observes pins == 0 and completes. */
    conn = duct_conn_acquire();
    assert(conn);
    conn->xport_type = x_inter;
    handle = duct_conn_handle_get(conn);
    assert(duct_conn_session_bind(conn, UINT64_MAX));
    assert(duct_conn_pin(conn, handle.gen) == rc_ok);
    duct_conn_unpin(conn);
    assert(duct_conn_by_handle(handle));
    duct_conn_release(conn);
    assert(!duct_conn_by_handle(handle));
    assert(duct_conns_free() == free_before);

    printf("  pin_cas_against_gen_bump OK\n");
}

/** @brief §6 value latches: both crossing edges are strictly single-shot.
 *  The rx ack edge posts at exactly the shift that reaches the armed target,
 *  the tx head edge wakes at exactly the advance that reaches it — and a
 *  target the moving side has already passed never fires again, which is
 *  what lets the values replace bits with no clear and no RMW. */
static void test_value_latch_crossing_edges(void)
{
    /* Unarmed never crosses. */
    assert(!duct_olb_rx_resume_crossed(0u, 100u, 0u));
    assert(!duct_olb_tx_wait_crossed(0u, 100u, 0u));

    /* Below the target, up to and touching it short, never crosses. */
    assert(!duct_olb_rx_resume_crossed(40u, 99u, 100u));
    assert(!duct_olb_tx_wait_crossed(40u, 99u, 100u));

    /* The crossing shift — exactly one: the shift that lands on the target. */
    assert(duct_olb_rx_resume_crossed(40u, 100u, 100u));
    assert(duct_olb_rx_resume_crossed(40u, 130u, 100u));
    assert(duct_olb_tx_wait_crossed(40u, 100u, 100u));
    assert(duct_olb_tx_wait_crossed(40u, 130u, 100u));

    /* Past the target nothing fires again: prev has caught up with it. */
    assert(!duct_olb_rx_resume_crossed(100u, 130u, 100u));
    assert(!duct_olb_rx_resume_crossed(130u, 140u, 100u));
    assert(!duct_olb_tx_wait_crossed(100u, 130u, 100u));
    assert(!duct_olb_tx_wait_crossed(130u, 140u, 100u));

    printf("  value_latch_crossing_edges OK\n");
}

/** @brief §6 rx latch: the worker posts the read resume strictly on the ack
 *  crossing edge and exactly once per latch.
 *  A light io module (threads never started) makes the resume post real:
 *  its gen_req bit rises at the crossing shift and at no other, the
 *  coalescing gate holding one node per latch — the edge, not a level, is
 *  what fires. */
static void test_rx_latch_edge_posts_once_per_latch(void)
{
    duct_conn_pool_reclaim();
    auto wfq = duct_wfq_new(1u, 1u, DUCT_WFQ_CAP_HI, DUCT_WFQ_CAP_NORM,
                            DUCT_WFQ_CAP_LO);
    assert(wfq);
    /* Threads up and joined at once, tick_sweep-style: the io module's
     * structures stand alive for the post below, and cleanup at the end
     * finds a real events backend to release. */
    assert(duct_io_init(1u, wfq, 1u));
    assert(duct_io_start_threads());
    duct_io_request_shutdown();
    duct_io_join();

    auto conn = duct_conn_acquire();
    assert(conn);
    conn->xport_type = x_tcp;
    duct_conn_carve_olb(conn, s_olb_cap, s_olb_cap);
    conn->io_id = 0u;
    auto word = duct_conn_gen_req(conn);
    auto rx = duct_conn_rx_olb(conn);
    duct_atomic_store(&rx->acked, 40u, release);
    /* io's latch: the target sits past the worker's acked total. */
    duct_atomic_store(&rx->resume_at, 100u, release);
    assert(duct_olb_rx_stalled(rx));

    /* A shift still short of the target posts nothing. */
    s_rx_ack(conn, 30u, s_dispatch_frontier_skip);
    assert(!(duct_atomic_load(word, relaxed) & (uint64_t)fl_req_rx_resume));

    /* The crossing shift posts the resume — one node, one bit. */
    s_rx_ack(conn, 30u, s_dispatch_frontier_skip);
    assert(duct_atomic_load(word, relaxed) & (uint64_t)fl_req_rx_resume);
    assert(!duct_olb_rx_stalled(rx));

    /* No later shift re-posts: the run consumed the bit, and prev_acked has
     * caught up with the target — the crossing cannot recur. */
    duct_atomic_fetch(and, word, ~(uint64_t)fl_req_rx_resume, acq_rel);
    s_rx_ack(conn, 10u, s_dispatch_frontier_skip);
    assert(!(duct_atomic_load(word, relaxed) & (uint64_t)fl_req_rx_resume));

    /* The disarmed word (0) is the unarmed one: no shift crosses it. */
    duct_atomic_store(&rx->resume_at, 0u, relaxed);
    s_rx_ack(conn, 5u, s_dispatch_frontier_skip);
    assert(!(duct_atomic_load(word, relaxed) & (uint64_t)fl_req_rx_resume));

    duct_conn_release(conn);
    duct_io_cleanup();
    duct_vmq_mpsc_del(wfq);
    printf("  rx_latch_edge_posts_once_per_latch OK\n");
}

/** @brief §2.3 (duct-zerocopy §5.1 span_rx): the pinned span holds the
 *  block. A conn whose rx spans ride descriptors anywhere keeps one unit of
 *  conn->refs per 0 → 1 pin edge — through the close claim and every other
 *  release the lifecycle takes, the slot never reaches the free bitmap, and
 *  the last pin's drop releases that unit last, which is what frees. */
static void test_span_pin_holds_block_across_close(void)
{
    duct_conn_pool_reclaim();
    unsigned free_before = duct_conns_free();

    /* The relay window: a pinned conn survives the close claim and the io
     * unit's release, and the last unpin frees. */
    auto conn = duct_conn_acquire();
    assert(conn);
    conn->xport_type = x_tcp;
    duct_conn_carve_olb(conn, s_olb_cap, s_olb_cap);
    auto handle = duct_conn_handle_get(conn);
    auto rx = duct_conn_rx_olb(conn);

    duct_span_rx_pin(conn, rx);
    assert(duct_atomic_load(&rx->pins, relaxed) == 1u);
    duct_span_rx_pin(conn, rx);
    assert(duct_atomic_load(&rx->pins, relaxed) == 2u);

    duct_conn_phase_t pre;
    assert(duct_conn_close_claim(conn, &pre) && pre == conn_unbound);
    duct_conn_release(conn); /* io unit; the two pin units stand */
    assert(duct_conn_by_handle(handle));
    assert(duct_conns_free() == free_before - 1u);

    duct_span_rx_unpin(conn, rx);
    assert(duct_atomic_load(&rx->pins, relaxed) == 1u);
    assert(duct_conn_by_handle(handle));
    assert(duct_conns_free() == free_before - 1u);

    duct_span_rx_unpin(conn, rx); /* the last: release last, block frees */
    assert(duct_conns_free() == free_before);
    assert(!duct_conn_by_handle(handle));

    /* The unbound fast path holds the same: pins taken, every unit the
     * lifecycle holds released, the block stays out of the bitmap until the
     * last pin drops. */
    conn = duct_conn_acquire();
    assert(conn);
    conn->xport_type = x_tcp;
    duct_conn_carve_olb(conn, s_olb_cap, s_olb_cap);
    rx = duct_conn_rx_olb(conn);
    duct_span_rx_pin(conn, rx);
    duct_conn_release(conn);
    assert(duct_conns_free() == free_before - 1u);
    duct_span_rx_unpin(conn, rx);
    assert(duct_conns_free() == free_before);

    printf("  span_pin_holds_block_across_close OK\n");
}

/** @brief §2.3 level check: the 1 → 0 pin drop re-checks the armed resume
 *  target by level and posts the read exactly when the ack edge is already
 *  past — the window the worker's crossing post cannot cover, since the
 *  acks may all be in while the pin still holds the wrap window. An
 *  unarmed word never posts: outside a pause R == 0, so a pin drop is
 *  never a spurious wake. */
static void test_span_pin_unpin_level_check_wake(void)
{
    duct_conn_pool_reclaim();
    auto wfq = duct_wfq_new(1u, 1u, DUCT_WFQ_CAP_HI, DUCT_WFQ_CAP_NORM,
                            DUCT_WFQ_CAP_LO);
    assert(wfq);
    /* Threads up and joined at once, rx_latch-style: the io module stands
     * alive so the level-check post lands in the gen_req word for real. */
    assert(duct_io_init(1u, wfq, 1u));
    assert(duct_io_start_threads());
    duct_io_request_shutdown();
    duct_io_join();

    fprintf(stderr, "[dbg] io up\n");
    auto conn = duct_conn_acquire();
    assert(conn);
    conn->xport_type = x_tcp;
    duct_conn_carve_olb(conn, s_olb_cap, s_olb_cap);
    conn->io_id = 0u;
    auto word = duct_conn_gen_req(conn);
    auto rx = duct_conn_rx_olb(conn);
    uint64_t req_bit = (uint64_t)fl_req_rx_resume;

    /* Acks already past the armed target: the drop posts. */
    duct_atomic_store(&rx->acked, 150u, release);
    duct_atomic_store(&rx->resume_at, 100u, release);
    duct_span_rx_pin(conn, rx);
    duct_span_rx_unpin(conn, rx);
    assert(duct_atomic_load(word, relaxed) & req_bit);
    assert(duct_atomic_load(&rx->pins, relaxed) == 0u);

    /* Acks still short of the armed target: the drop posts nothing — the
     * worker's later crossing ack is the post that carries this latch.
     * A fresh conn: the first conn's posted node still sits its trunk
     * stack, and a second post of it double-links the embedded node. */
    conn = duct_conn_acquire();
    assert(conn);
    conn->xport_type = x_tcp;
    duct_conn_carve_olb(conn, s_olb_cap, s_olb_cap);
    conn->io_id = 0u;
    word = duct_conn_gen_req(conn);
    rx = duct_conn_rx_olb(conn);
    duct_atomic_store(&rx->acked, 150u, release);
    duct_atomic_store(&rx->resume_at, 300u, release);
    duct_span_rx_pin(conn, rx);
    duct_span_rx_unpin(conn, rx);
    assert(!(duct_atomic_load(word, relaxed) & req_bit));
    s_rx_ack(conn, 200u, s_dispatch_frontier_skip); /* 150 -> 350 crosses 300 */
    assert(duct_atomic_load(word, relaxed) & req_bit);

    /* Unarmed: a drop never posts spuriously. */
    conn = duct_conn_acquire();
    assert(conn);
    conn->xport_type = x_tcp;
    duct_conn_carve_olb(conn, s_olb_cap, s_olb_cap);
    conn->io_id = 0u;
    word = duct_conn_gen_req(conn);
    rx = duct_conn_rx_olb(conn);
    duct_atomic_store(&rx->resume_at, 0u, relaxed);
    duct_span_rx_pin(conn, rx);
    duct_span_rx_unpin(conn, rx);
    assert(!(duct_atomic_load(word, relaxed) & req_bit));

    duct_conn_release(conn);
    duct_io_cleanup();
    duct_vmq_mpsc_del(wfq);
    printf("  span_pin_unpin_level_check_wake OK\n");
}

/** @brief §2.3 wrap gate: a live pin holds the ring's wrap/read window, not
 *  the ack cursor — acked advances with the frames as normal, and the
 *  second pass, the compaction and the done-count all wait on the count,
 *  the resume target arming at the posted drain until the last drop. */
static void test_span_pin_gates_wrap_and_compaction(void)
{
    duct_conn_pool_reclaim();
    auto conn = duct_conn_acquire();
    assert(conn);
    conn->xport_type = x_udp_peer;
    duct_conn_carve_olb(conn, s_olb_cap, s_olb_cap);
    auto rx = duct_conn_rx_olb(conn);

    /* One full pass, every posted byte acked, frontier at posted_off: only
     * the pin holds the window. */
    rx->posted_off = (uint32_t)s_olb_cap;
    rx->h.stage = s_olb_cap;
    duct_atomic_store(&rx->h.tail, s_olb_cap, release);
    duct_atomic_store(&rx->acked, s_olb_cap, release);
    duct_atomic_store(&rx->dispatch_frontier, (uint32_t)s_olb_cap, release);

    size_t done = 0u;
    /* Without a pin the pass folds: the pin, not the ack state, is the
     * only thing holding the window. */
    assert(duct_olb_rx_done(rx, &done) && done == s_olb_cap);
    assert(duct_olb_rx_consumed(rx));

    duct_span_rx_pin(conn, rx);
    assert(!duct_olb_rx_done(rx, &done));
    assert(!duct_olb_rx_consumed(rx));
    /* The wrap form arms at the posted drain: no ack edge is left to cross,
     * the last pin's level check is the wake. */
    assert(duct_olb_rx_resume_total(rx, 64u, true)
           == duct_olb_rx_posted_total(rx));
    uint8_t *ptr = nullptr;
    size_t avail = 0u;
    assert(duct_olb_rx_try_space(rx, 64u, true, &ptr, &avail) == olb_rx_full);

    duct_span_rx_unpin(conn, rx);
    assert(duct_olb_rx_done(rx, &done) && done == s_olb_cap);
    assert(duct_olb_rx_consumed(rx));
    assert(duct_olb_rx_resume_total(rx, 64u, true) < duct_olb_rx_posted_total(rx));
    assert(duct_olb_rx_try_space(rx, 64u, true, &ptr, &avail) == olb_rx_compacted);
    assert(avail == s_olb_cap);

    duct_conn_release(conn);
    printf("  span_pin_gates_wrap_and_compaction OK\n");
}

/** @brief §6 tx latch: the wait target is the exact flip point of the room
 *  condition that refused, monotonic in the packed-head coordinate and
 *  clamped past the observed head — and the arm itself parks a value no
 *  disarm write ever clears. A lane conn arms on its resident header's
 *  zeroed words: the any-signal form its device wake reads. */
static void test_tx_wait_target_forms(void)
{
    duct_conn_pool_reclaim();
    constexpr size_t cap = kbytes(8u);
    constexpr uint64_t k = 1024u;

    auto conn = duct_conn_acquire();
    assert(conn);
    conn->xport_type = x_tcp;
    duct_conn_carve_olb(conn, cap, cap);
    auto tx = duct_conn_tx_olb(conn);
    auto h = &tx->h;

    /* Coarse form, same pass: published spans past the wanted room, so the
     * target is the head offset that drops the span below it. */
    duct_olb_tx_cold_init(tx);
    h->stage = 7u * k + 512u;
    duct_atomic_store(&h->tail, olb_pack(0u, 7u * k + 512u), relaxed);
    duct_atomic_store(&h->head, olb_pack(0u, 410u), relaxed);
    uint64_t target = duct_olb_tx_wait_target(tx, 0u);
    assert(target == olb_pack(0u, 512u)); /* tail + min_room − buf */
    assert(!duct_olb_tx_wait_crossed(olb_pack(0u, 410u), olb_pack(0u, 511u), target));
    assert(duct_olb_tx_wait_crossed(olb_pack(0u, 410u), olb_pack(0u, 512u), target));

    /* Contig form, same pass: the wrap limb's flip at the buffer's front. */
    h->stage = 7u * k;
    duct_atomic_store(&h->tail, olb_pack(0u, 6u * k), relaxed);
    duct_atomic_store(&h->head, olb_pack(0u, 1u * k), relaxed);
    target = duct_olb_tx_wait_target(tx, 2u * k);
    assert(target == olb_pack(0u, 2u * k));

    /* A head already past the computed flip clamps one past itself: the
     * armed word always names a position io has not reached. */
    duct_atomic_store(&h->head, olb_pack(0u, 3u * k), relaxed);
    assert(duct_olb_tx_wait_target(tx, 2u * k) == olb_pack(0u, 3u * k) + 1u);

    /* Fold form: io a pass behind targets the fold into the staging pass. */
    duct_atomic_store(&h->head, olb_pack(0u, 1u * k), relaxed);
    tx->stage_gen = 1u;
    h->stage = 5u * k;
    target = duct_olb_tx_wait_target(tx, 2u * k);
    assert(target == olb_pack(1u, 0u)); /* stage + need ≤ buf: room at the fold */
    tx->pass_end = 6u * k;
    h->stage = 6u * k;
    target = duct_olb_tx_wait_target(tx, 4u * k);
    assert(target == olb_pack(1u, 4u * k)); /* wrap needed past the fold too */

    /* The arm parks the value on the worker's own line; nothing clears it. */
    s_tx_wait_arm(conn, 0u);
    uint64_t armed = duct_atomic_load(&tx->resume_at, relaxed);
    assert(armed != 0u);
    duct_atomic_store(&h->head, armed, relaxed);
    s_tx_wait_arm(conn, 0u); /* a re-arm past the advanced head */
    assert(duct_atomic_load(&tx->resume_at, relaxed) > armed);
    duct_conn_release(conn);

    /* A lane conn arms on the resident header: zeroed ring words give the
     * any-signal target no head advance ever crosses. */
    auto lane = duct_conn_acquire();
    assert(lane);
    lane->xport_type = x_inter;
    s_tx_wait_arm(lane, 0u);
    auto lane_hdr = duct_conn_tx_hdr(lane);
    uint64_t signal_form = duct_atomic_load(&lane_hdr->resume_at, relaxed);
    assert(signal_form != 0u);
    assert(!duct_olb_tx_wait_crossed(0u, signal_form - 1u, signal_form));
    duct_conn_release(lane);

    printf("  tx_wait_target_forms OK\n");
}

/** @brief The 3c edge: the worker frees the rings while an io completion is
 *  still in flight, the close's gate holding the rings' last references.
 *  The completion runs gated by @c fl_conn_closed — past it io touches
 *  page-0 words only — and the refs unit its armed submission borrowed is
 *  what keeps the slot from its next occupant while the worker's teardown
 *  half drains and closes against it. Whichever side runs first, the slot
 *  returns exactly once, at the last unit. */
static void test_worker_frees_rings_vs_io_completion(void)
{
    duct_conn_pool_reclaim();
    unsigned free_before = duct_conns_free();

    /* Completion first: the worker's teardown frees the rings while the
     * completion still holds its borrow, then the completion lands on the
     * gated conn. */
    auto conn = duct_conn_acquire();
    assert(conn);
    conn->xport_type = x_tcp;
    duct_conn_carve_olb(conn, s_olb_cap, s_olb_cap);
    duct_sock_t peer_fd, peer_fd2;
    s_tiny_pair_open(&conn->fd, &peer_fd);
    auto handle = duct_conn_handle_get(conn);
    duct_conn_ref_take(conn); /* the posted ctrl's unit, converted at bind */
    assert(duct_conn_session_bind(conn, UINT64_MAX));
    duct_conn_ref_take(conn); /* the armed kernel submission's borrow (§2) */
    duct_conn_phase_t pre;
    assert(duct_conn_close_claim(conn, &pre) && pre == conn_bound);
    duct_conn_state_set(conn, fl_conn_closed); /* the gate completions read */
    duct_conn_release(conn); /* io's own unit, dropped past the lost publish */

    /* The worker's half: rings, fd — the slot must outlive the completion. */
    duct_conn_teardown_worker(conn);
    duct_conn_release(conn);
    assert(duct_conns_free() == free_before - 1u);
    assert(duct_conn_by_handle(handle));

    /* The completion lands on the closed conn: gated to its page-0 words,
     * it clears the busy marker and drops the borrow — the last unit. */
    duct_olb_io_done(&duct_conn_rx_olb(conn)->h, conn);
    assert(!duct_conn_by_handle(handle));
    assert(duct_conns_free() == free_before);

    /* Worker-side completion order flipped: the completion drains its
     * borrow first, the worker's teardown half runs against the slot the
     * ctrl unit still holds, and its release is the final one. */
    conn = duct_conn_acquire();
    assert(conn);
    conn->xport_type = x_tcp;
    duct_conn_carve_olb(conn, s_olb_cap, s_olb_cap);
    s_tiny_pair_open(&conn->fd, &peer_fd2);
    handle = duct_conn_handle_get(conn);
    duct_conn_ref_take(conn);
    assert(duct_conn_session_bind(conn, UINT64_MAX));
    duct_conn_ref_take(conn);
    assert(duct_conn_close_claim(conn, &pre) && pre == conn_bound);
    duct_conn_state_set(conn, fl_conn_closed);
    duct_conn_release(conn);
    duct_olb_io_done(&duct_conn_tx_olb(conn)->h, conn); /* tx completion first */
    assert(duct_conns_free() == free_before - 1u);
    assert(duct_conn_by_handle(handle));
    duct_conn_teardown_worker(conn);
    duct_conn_release(conn);
    assert(!duct_conn_by_handle(handle));
    assert(duct_conns_free() == free_before);

    duct_sock_close(peer_fd);
    duct_sock_close(peer_fd2);
    printf("  worker_frees_rings_vs_io_completion OK\n");
}

/* ── Main ─────────────────────────────────────────────────────────── */

duct_msg_chain_decl(s_fifo_test_msg, bool *blocked; unsigned *calls;);
static duct_exec_rc_t s_fifo_test_exec(void *self)
{
    auto msg = (s_fifo_test_msg *)self;
    if (*msg->blocked) return exec_defer;
    ++*msg->calls;
    return duct_msg_done(msg);
}

static void test_external_fifo_tail_survives_defer(void)
{
    duct_worker_t w = {};
    bool blocked = true, ready = false;
    unsigned first = 0u, second = 0u;
    auto a = duct_msg_new(s_fifo_test_msg, s_fifo_test_exec, nullptr);
    auto b = duct_msg_new(s_fifo_test_msg, s_fifo_test_exec, nullptr);
    assert(a && b);
    a->blocked = &blocked; a->calls = &first;
    b->blocked = &ready; b->calls = &second;
    a->next = &b->msg;
    w.ext_pending.head = &a->msg; w.ext_pending.tail = &b->msg;
    assert(s_drain_ext(&w) == 0u && first == 0u && second == 0u);
    assert(duct_msg_next(w.ext_pending.head) == &b->msg);
    blocked = false;
    assert(s_drain_ext(&w) == 2u && first == 1u && second == 1u);
    assert(!w.ext_pending.head && !w.ext_pending.tail);
}

static void test_engine_egress_park_is_bounded_and_ordered(void)
{
    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());
    auto wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .engine = &s_fake_engine_vtbl, .role = seal_role_responder,
        .framing = seal_framing_stream });
    assert(wire);
    f.conn->wire = wire;
    auto slot = duct_conn_codec_slot(f.conn);
    auto slot_parser = duct_conn_wire_parser_slot(f.conn, 1u);
    memset(slot, 0, sizeof *slot);
    memset(slot_parser, 0, duct_wire_parser_slot);
    f.conn->seal.codec = wire->init_codec(wire, x_tcp, slot, slot_parser, s_ct_chunks_test());
    assert(f.conn->seal.codec);
    auto codec = f.conn->seal.codec;
    size_t budget = codec->engine->vtbl->engine_hs_budget,
           cap = 2u * s_hs_need(f.conn, codec);
    auto tx = duct_conn_tx_olb(f.conn);
    size_t room = duct_olb_tx_space(tx);
    char *fill = duct_at(duct_new(char, room));
    assert(fill);
    assert(duct_olb_tx_stage(tx, nullptr, 0u, fill, room) == olb_tx_ok);
    duct_olb_tx_publish(tx);
    duct_del(fill);
    auto first = s_engine_park_span(f.conn, codec, budget);
    assert(first);
    memset(first, 0x59, budget);
    auto second = s_engine_park_span(f.conn, codec, cap - budget);
    assert(second);
    memset(second, 0x5a, cap - budget);
    assert(!s_engine_park_span(f.conn, codec, duct_conn_park_cap - cap + 1u));
    assert(!s_engine_park_flush(f.conn));
    assert(f.w.retry_head == f.w.retry_tail); /* One node for the whole park. */
    auto next = s_make_proto_sl();
    assert(next);
    f.proto->cfg.wire = next->cfg.wire = wire;
    f.s->switch_next = next;
    s_response_switch(f.s);
    assert(f.s->proto == f.proto && f.s->switch_next == next
           && f.s->switch_stage == switch_parked_tx);
    duct_olb_tx_advance(tx, room);
    assert(s_retry_drain(&f.w));
    assert(!f.w.retry_head && !codec->engine_park_len);
    assert(duct_olb_tx_published(tx) == cap);
    assert(f.s->proto == next && !f.s->switch_next
           && f.s->switch_stage == switch_none);
    s_fixture_fini(&f);
    duct_proto_destroy(next);
    duct_wire_destroy(wire);
}

static void test_detached_frame_acks_once(bool sealed, bool already_unsealed)
{
    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());
    auto saved_token = duct_atomic_load(&f.conn->session_token, acquire);
    duct_wire_t *wire = nullptr;
    if (sealed) {
        wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .engine = &s_fake_engine_vtbl, .role = seal_role_responder,
            .framing = seal_framing_stream });
        assert(wire);
        f.conn->wire = wire;
        f.conn->seal.head_unsealed = already_unsealed;
    }
    duct_msg_frame_t task = { .len = 8u, .sealed_epoch = sealed ? 1u : 0u };
    duct_conn_rx_olb(f.conn)->h.stage = task.len;
    duct_atomic_store(&duct_conn_rx_olb(f.conn)->h.tail, task.len, release);
    if (already_unsealed)
        s_rx_ack(f.conn, task.len, task.len);
    duct_atomic_store(&f.conn->session_token, handle_null, release);
    assert(s_dispatch_frame(&f.w, f.handle, &task) == exec_done);
    assert(s_rx_acked(&f) == task.len);
    assert(!f.conn->seal.head_unsealed);
    duct_atomic_store(&f.conn->session_token, saved_token, release);
    s_fixture_fini(&f);
    if (wire)
        duct_wire_destroy(wire);
}

static duct_result_t s_join_no_output([[maybe_unused]] duct_session_t *s,
    [[maybe_unused]] duct_conn_id_t id, [[maybe_unused]] const duct_peer_t *peer,
    [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *state)
{
    return rc_ok;
}

static void test_join_admits_without_callback_under_unrelated_tx_pressure(void)
{
    s_fixture_t f;
    s_fixture_init(&f, s_make_proto_sl());
    auto tx = duct_conn_tx_olb(f.conn);
    size_t room = duct_olb_tx_space(tx);
    char *fill = duct_at(duct_new(char, room));
    assert(fill);
    assert(duct_olb_tx_stage(tx, nullptr, 0u, fill, room) == olb_tx_ok);
    duct_olb_tx_publish(tx);
    duct_del(fill);
    auto joining = duct_conn_acquire();
    assert(joining);
    joining->xport_type = x_inter;
    auto handle = duct_conn_handle_get(joining);
    auto msg = duct_msg_new(duct_msg_conn_join, duct_session_exec_conn_join, nullptr);
    assert(msg);
    msg->conn = handle;
    msg->conn_id = 1u;
    msg->tok = duct_session_handle_from_live(f.s);
    f.proto->cfg.on_conn_join = s_join_no_output;
    assert(duct_session_exec_conn_join(msg) == exec_defer);
    f.proto->cfg.on_conn_join = nullptr;
    assert(duct_session_exec_conn_join(msg) == exec_done);
    assert(duct_session_conn_at(f.s, 1u).word == handle.word);
    duct_session_detach_leg(f.s, 1u, close_normal);
    duct_conn_discard(joining);
    s_fixture_fini(&f);
}

int main(void)
{
    test_join_admits_without_callback_under_unrelated_tx_pressure();
    test_detached_frame_acks_once(false, false);
    test_detached_frame_acks_once(true, false);
    test_detached_frame_acks_once(true, true);
    test_external_fifo_tail_survives_defer();
    test_engine_egress_park_is_bounded_and_ordered();
    test_handler_async_basic();
    test_handler_async_multi_yield();
    test_handler_async_done();
    test_handler_async_fin_delivers();
    test_handler_async_concurrent_defer();
    test_handler_async_fin_busy_defers();
    test_handler_sf_basic();
    test_handler_sf_concurrent_defer();
    test_handler_sf_fin_cancel();
    test_handler_stream0_on_frame();
    test_handler_no_slots();
    test_handler_async_conn_lost_discard();
    test_frame_header_size_pinned_across_wire_rebind();
    test_handler_async_interleaved_reset();
    test_frame_sealed_task_dropped_after_wire_switch();
    test_frame_sealed_stale_after_switch_no_double_ack();
    test_frame_sealed_raw_mode_skips_empty_record();
    test_frame_sealed_pre_ack_defer_stale_after_sealed_switch();
    test_tls_ensure_started_creates_codec_and_starts_once();
    test_retry_frame_save_copies_ct_buf_and_frees_orphan();
    test_ct_pin_blocks_compaction_and_outlives_codec();
    test_inter_pkt_decrypts_into_a_heap_block();
    test_inter_pkt_claim_pins_the_rx_slot();
    test_retry_frame_save_pins_the_rx_slot();
    test_retry_emit_save_pins_the_handler_slot();
    test_wire_create_tls_rejects_oversized_hs_budget();
    test_retry_frame_save_copies_unrecognized_payload();
    test_retry_frame_save_copies_rx_ring_payload();
    test_retry_region_node_quota();
    test_retry_region_copy_slots();
    test_retry_emit_save_keeps_the_handler_frame();
    test_retry_emit_save_shares_the_owned_frame();
    test_dgram_out_stages_into_a_send_slot();
#if !DUCT_EVENTS_MODEL_IOCP
    test_commit_dgram_shared_holds_an_owned_block();
#endif
    test_response_take_parks_behind_older_ticket();
    test_switch_waits_for_parked_response();
    test_inter_pending_follows_armed_bits();
    test_inter_drain_follows_the_bound_worker();
    test_conn_lost_settles_the_owed_fence();
    test_conn_lost_settles_only_an_owed_fence();
    test_wire_rebind_posts_no_fence_once_closing();
    test_close_races_ctrl_at_release_boundaries();
    test_unbound_defer_window_closes_with_close_post();
    test_pin_cas_against_gen_bump();
    test_value_latch_crossing_edges();
    test_span_pin_holds_block_across_close();
    test_span_pin_unpin_level_check_wake();
    test_span_pin_gates_wrap_and_compaction();
    test_rx_latch_edge_posts_once_per_latch();
    test_tx_wait_target_forms();
    test_worker_frees_rings_vs_io_completion();
    printf("All handler_dispatch tests passed.\n");
    return 0;
}
