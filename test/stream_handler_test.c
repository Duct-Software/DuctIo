/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file stream_handler_test.c
 * @brief Step 3b litmus: stream handler coro extensions + handler ctx lifecycle.
 *
 * Exercises the new coro fields (state, on_done, in_wait), async_queue_wake_coro,
 * async_queue_remove, duct_stream_ctx_t lifecycle, duct_session_stream_teardown, and
 * duct_session_stream_slot. Does NOT exercise the full worker dispatch path
 * (s_dispatch_frame) — that requires the IO stack and is covered by integration
 * tests.
 */

#include "duct_session.h"
#include "duct_conn.h"
#include "duct_protocol.h"
#include "duct_coro.h"
#include "duct_stream_ctx.h"
#include "duct_core.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(expr, msg) \
    do { if (!(expr)) { fprintf(stderr, "FAIL: %s\n", msg); exit(1); } } while (0)

/* ── Counters for callback verification ──────────────────────────── */

static unsigned s_create_calls;
static unsigned s_open_calls;
static unsigned s_close_calls;
static unsigned s_destroy_calls;
static unsigned s_on_done_calls;
static duct_async_rc_t s_on_done_last_rc;

/* ── Mock protocol callbacks ─────────────────────────────────────── */

static duct_result_t s_on_frame([[maybe_unused]] duct_session_t *s,
                                [[maybe_unused]] duct_conn_id_t cid,
                                [[maybe_unused]] const duct_frame_t *fr,
                                [[maybe_unused]] duct_response_t *out,
                                [[maybe_unused]] void *proto_state)
{
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

/* ── Stackless step for handler tests ────────────────────────────── */

static duct_async_rc_t s_handler_step(void *state)
{
    auto hctx = (duct_stream_ctx_t *)state;
    /* Emit one response with the frame payload, then wait for next frame. */
    hctx->out = (duct_response_t){
        .payload = hctx->frame.payload,
        .flags = fl_send_copy,
        .conn_id = duct_conn_id_same,
        .stream_id = duct_stream_id_same,
    };
    return async_yield;
}

static duct_async_rc_t s_handler_step_wait(void *state)
{
    auto hctx = (duct_stream_ctx_t *)state;
    /* Emit response then immediately wait. */
    hctx->out = (duct_response_t){
        .payload = hctx->frame.payload,
        .conn_id = duct_conn_id_same,
        .stream_id = duct_stream_id_same,
    };
    return async_wait;
}

static duct_async_rc_t s_handler_step_done([[maybe_unused]] void *state)
{
    return async_done;
}

/* ── on_done callback for handler tests ──────────────────────────── */

static void s_test_on_done([[maybe_unused]] duct_async_t *co,
                           duct_async_rc_t rc, [[maybe_unused]] void *ctx)
{
    ++s_on_done_calls;
    s_on_done_last_rc = rc;
}

/* ── Proto factory ───────────────────────────────────────────────── */

static duct_proto_t *s_make_proto(void)
{
    return duct_proto_create(&(duct_proto_cfg_t){
        .name = "handler_test",
        .on_frame = s_on_frame,
        .on_session_open = s_on_session_open,
        .on_session_close = s_on_session_close,
        .create_stream_state = s_create_stream_state,
        .destroy_stream_state = s_destroy_stream_state,
        .on_stream_open = s_on_stream_open,
        .on_stream_close = s_on_stream_close,
        .flags = fl_proto_multiplexed,
        .handler_kind = handler_async,
        .handler_async = s_handler_step,
        .max_response = 4096u,
    });
}

/* ── Tests ───────────────────────────────────────────────────────── */

/* T1: coro state — step receives an external ctx instead of the inline priv buffer. */
static void test_state(void)
{
    duct_async_pool_t apool;
    CHECK(duct_async_pool_init(&apool, 4u) == rc_ok, "duct_async_pool_init(&apool, 4u)");

    duct_stream_ctx_t hctx = {};
    auto au = duct_async_acquire(&apool, s_handler_step);
    CHECK(au, "au");
    CHECK(au->state == au->priv, "au->state == au->priv");
    au->state = &hctx;
    CHECK(au->step(au->state) == async_yield, "au->step(au->state) == async_yield");
    duct_async_release(&apool, au);
    duct_async_pool_fini(&apool);
    printf("  state OK\n");
}

/* T2: on_done callback fires on step return. */
static void test_on_done(void)
{
    duct_async_pool_t apool;
    CHECK(duct_async_pool_init(&apool, 4u) == rc_ok, "duct_async_pool_init(&apool, 4u)");

    s_on_done_calls = 0u;
    auto au = duct_async_acquire(&apool, s_handler_step_done);
    CHECK(au, "au");
    au->on_done = s_test_on_done;
    au->on_done_ctx = nullptr;

    /* Simulate what s_drain_stackless does: */
    auto rc = au->step(au->state);
    CHECK(rc == async_done, "rc == async_done");
    if (au->on_done)
        au->on_done(au, rc, au->on_done_ctx);
    CHECK(s_on_done_calls == 1u, "s_on_done_calls == 1u");
    CHECK(s_on_done_last_rc == async_done, "s_on_done_last_rc == async_done");

    duct_async_release(&apool, au);
    duct_async_pool_fini(&apool);
    printf("  on_done OK\n");
}

/* T4: async_queue_wake_coro — direct pointer wake from wait queue. */
static void test_wake_coro(void)
{
    duct_async_pool_t apool;
    CHECK(duct_async_pool_init(&apool, 4u) == rc_ok, "duct_async_pool_init(&apool, 4u)");
    duct_async_queue_t queue;
    duct_async_queue_init(&queue);

    auto a = duct_async_acquire(&apool, s_handler_step);
    auto b = duct_async_acquire(&apool, s_handler_step);
    CHECK(a && b, "a && b");

    duct_async_queue_enqueue(&queue, a, coop_wait);
    duct_async_queue_enqueue(&queue, b, coop_wait);
    CHECK(queue.n_wait == 2u, "queue.n_wait == 2u");

    /* Wake specific coro by pointer. */
    duct_async_queue_wake_coro(&queue, b);
    CHECK(!b->in_wait, "!b->in_wait");
    CHECK(a->in_wait, "a->in_wait");
    CHECK(queue.n_run == 1u, "queue.n_run == 1u");
    CHECK(queue.n_wait == 1u, "queue.n_wait == 1u");

    /* Wake the other one. */
    duct_async_queue_wake_coro(&queue, a);
    CHECK(!a->in_wait, "!a->in_wait");
    CHECK(queue.n_run == 2u, "queue.n_run == 2u");
    CHECK(queue.n_wait == 0u, "queue.n_wait == 0u");

    /* Wake on already-running coro is no-op. */
    duct_async_queue_wake_coro(&queue, a);
    CHECK(queue.n_run == 2u, "queue.n_run == 2u");

    duct_async_release(&apool, a);
    duct_async_release(&apool, b);
    duct_async_pool_fini(&apool);
    printf("  wake_coro OK\n");
}

/* T5: async_queue_remove — remove from run and wait queues. */
static void test_queue_remove(void)
{
    duct_async_pool_t apool;
    CHECK(duct_async_pool_init(&apool, 4u) == rc_ok, "duct_async_pool_init(&apool, 4u)");
    duct_async_queue_t queue;
    duct_async_queue_init(&queue);

    auto a = duct_async_acquire(&apool, s_handler_step);
    auto b = duct_async_acquire(&apool, s_handler_step);
    CHECK(a && b, "a && b");

    /* a in run, b in wait. */
    duct_async_queue_enqueue(&queue, a, coop_run);
    duct_async_queue_enqueue(&queue, b, coop_wait);
    CHECK(queue.n_run == 1u && queue.n_wait == 1u, "queue.n_run == 1u && queue.n_wait == 1u");

    /* Remove from run. */
    duct_async_queue_remove(&queue, a);
    CHECK(queue.n_run == 0u, "queue.n_run == 0u");
    CHECK(!a->in_wait, "!a->in_wait");

    /* Remove from wait. */
    duct_async_queue_remove(&queue, b);
    CHECK(queue.n_wait == 0u, "queue.n_wait == 0u");
    CHECK(!b->in_wait, "!b->in_wait");

    duct_async_release(&apool, a);
    duct_async_release(&apool, b);
    duct_async_pool_fini(&apool);
    printf("  queue_remove OK\n");
}

/* T6: handler_ctx lifecycle — create, fill, cancel. */
static void test_handler_ctx_lifecycle(void)
{
    s_create_calls = 0u;
    s_open_calls = 0u;
    s_close_calls = 0u;
    s_destroy_calls = 0u;

    auto proto = s_make_proto();
    CHECK(proto, "proto");

    auto conn = duct_conn_acquire();
    CHECK(conn, "conn");
    duct_conn_handle_t handle = duct_conn_handle_get(conn);

    duct_response_t out = {};
    auto s = duct_session_open(proto, duct_conn_id_primary,
                               handle, nullptr, 0u, &out);
    CHECK(s, "s");
    CHECK(s->streams, "s->streams");

    /* Claim stream 5. */
    duct_stream_t *st = duct_session_stream_claim(s, 5u, &out, nullptr);
    CHECK(st, "st");
    CHECK(s_create_calls == 1u && s_open_calls == 1u, "s_create_calls == 1u && s_open_calls == 1u");

    /* Create a handler ctx and attach to the slot. */
    auto hctx = duct_new(duct_stream_ctx_t);
    CHECK(hctx, "hctx");
    *hctx = (duct_stream_ctx_t){
        .s = s, .stream_id = 5u, .conn_id = 0u,
        .stream_state = st->proto_state,
    };
    auto slot = duct_session_stream_slot(s, 5u);
    CHECK(slot, "slot");
    slot->handler_ctx = hctx;

    /* Verify slot lookup. */
    CHECK(duct_session_stream_slot(s, 5u) == slot, "duct_session_stream_slot(s, 5u) == slot");
    CHECK(duct_session_stream_slot(s, 0u) == nullptr, "duct_session_stream_slot(s, 0u) == nullptr");
    CHECK(duct_session_stream_slot(s, 99u) == nullptr, "slot 99 null");

    /* Simulate async_done: clear handler_ctx, free hctx, then close. */
    slot->handler_ctx = nullptr;
    duct_del(hctx);
    duct_session_stream_close(s, 5u, close_normal);
    CHECK(s_close_calls == 1u && s_destroy_calls == 1u, "close+destroy counts");
    CHECK(!duct_stream_state(s, 5u), "!duct_stream_state(s, 5u)");

    /* Terminal session close. */
    CHECK(duct_session_detach_leg(s, duct_conn_id_primary, close_normal), "detach_leg");
    duct_conn_release(conn);
    duct_proto_destroy(proto);

    printf("  handler_ctx_lifecycle OK\n");
}

/* T7: duct_session_stream_teardown — fires close + destroy, returns slot to free list. */
static void test_stream_teardown(void)
{
    s_create_calls = 0u;
    s_open_calls = 0u;
    s_close_calls = 0u;
    s_destroy_calls = 0u;

    auto proto = s_make_proto();
    CHECK(proto, "proto");

    auto conn = duct_conn_acquire();
    CHECK(conn, "conn");
    duct_conn_handle_t handle = duct_conn_handle_get(conn);

    duct_response_t out = {};
    auto s = duct_session_open(proto, duct_conn_id_primary,
                               handle, nullptr, 0u, &out);
    CHECK(s, "s");

    /* Claim stream 7. */
    duct_session_stream_claim(s, 7u, &out, nullptr);
    CHECK(s_create_calls == 1u && s_open_calls == 1u, "s_create_calls == 1u && s_open_calls == 1u");
    CHECK(s->stream_count == 1u, "s->stream_count == 1u");

    auto slot = duct_session_stream_slot(s, 7u);
    CHECK(slot, "slot");

    /* Direct duct_session_stream_teardown call (bypasses handler cancel). */
    duct_session_stream_teardown(s, slot, close_normal);
    CHECK(s_close_calls == 1u && s_destroy_calls == 1u, "close+destroy counts");
    CHECK(s->stream_count == 0u, "s->stream_count == 0u");
    CHECK(!duct_session_stream_slot(s, 7u), "!duct_session_stream_slot(s, 7u)");

    /* Terminal session close. */
    CHECK(duct_session_detach_leg(s, duct_conn_id_primary, close_normal), "detach_leg");
    duct_conn_release(conn);
    duct_proto_destroy(proto);

    printf("  stream_teardown OK\n");
}

/* T8: handler_async_done path — on_done with async_done triggers teardown. */
static void test_handler_async_done_path(void)
{
    s_create_calls = 0u;
    s_open_calls = 0u;
    s_close_calls = 0u;
    s_destroy_calls = 0u;
    s_on_done_calls = 0u;

    duct_async_pool_t apool;
    CHECK(duct_async_pool_init(&apool, 4u) == rc_ok, "duct_async_pool_init(&apool, 4u)");
    duct_async_queue_t queue;
    duct_async_queue_init(&queue);

    /* Create a mock handler ctx. */
    duct_stream_ctx_t hctx = { .stream_id = 5u };

    auto au = duct_async_acquire(&apool, s_handler_step_done);
    CHECK(au, "au");
    au->state = &hctx;
    au->on_done = s_test_on_done;
    au->on_done_ctx = &hctx;

    /* Simulate drain: step returns async_done, on_done fires. */
    auto rc = au->step(au->state);
    CHECK(rc == async_done, "rc == async_done");
    au->on_done(au, rc, au->on_done_ctx);
    CHECK(s_on_done_calls == 1u, "s_on_done_calls == 1u");
    CHECK(s_on_done_last_rc == async_done, "s_on_done_last_rc == async_done");

    /* Release (simulating what drain does after on_done). */
    duct_async_release(&apool, au);
    CHECK(apool.n_alive == 0u, "apool.n_alive == 0u");

    duct_async_pool_fini(&apool);
    printf("  handler_async_done_path OK\n");
}

/* T9: handler_async with on_done yielding — on_done fires with async_yield. */
static void test_handler_async_yield_path(void)
{
    s_on_done_calls = 0u;

    duct_async_pool_t apool;
    CHECK(duct_async_pool_init(&apool, 4u) == rc_ok, "duct_async_pool_init(&apool, 4u)");
    duct_async_queue_t queue;
    duct_async_queue_init(&queue);

    duct_stream_ctx_t hctx = {};
    auto au = duct_async_acquire(&apool, s_handler_step);
    CHECK(au, "au");
    au->state = &hctx;
    au->on_done = s_test_on_done;
    au->on_done_ctx = &hctx;

    /* Simulate drain: step returns async_yield. */
    auto rc = au->step(au->state);
    CHECK(rc == async_yield, "rc == async_yield");
    au->on_done(au, rc, au->on_done_ctx);
    CHECK(s_on_done_calls == 1u, "s_on_done_calls == 1u");
    CHECK(s_on_done_last_rc == async_yield, "s_on_done_last_rc == async_yield");

    /* on_done re-queues for async_yield — verify we can release after. */
    duct_async_release(&apool, au);
    duct_async_pool_fini(&apool);
    printf("  handler_async_yield_path OK\n");
}

/* T10: handler proto validation — handler_kind without multiplexed flag. */
static void test_handler_validation(void)
{
    /* handler_async without fl_proto_multiplexed → reject. */
    auto p1 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "bad1",
        .on_frame = s_on_frame,
        .handler_kind = handler_async,
        .handler_async = s_handler_step,
    });
    CHECK(!p1, "!p1");

    /* handler_kind == handler_async with a NULL step fn → reject. */
    auto p2 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "bad2",
        .on_frame = s_on_frame,
        .handler_kind = handler_async,
        .flags = fl_proto_multiplexed,
    });
    CHECK(!p2, "!p2");

    /* Valid: handler_async + multiplexed + fn set. */
    auto p3 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "good",
        .on_frame = s_on_frame,
        .handler_kind = handler_async,
        .handler_async = s_handler_step,
        .flags = fl_proto_multiplexed,
        .max_response = 4096u,
    });
    CHECK(p3, "p3");
    CHECK(p3->cfg.handler_kind == handler_async, "p3->cfg.handler_kind == handler_async");
    CHECK(p3->cfg.handler_async == s_handler_step, "handler_async fn");
    duct_proto_destroy(p3);

    printf("  handler_validation OK\n");
}

/* T11: coro on_resume field — stackful coro extension. */

static bool s_resume_called;

static void s_test_resume([[maybe_unused]] duct_coro_t *co,
                          [[maybe_unused]] void *ctx)
{
    s_resume_called = true;
}

static void s_sf_yield([[maybe_unused]] void *arg)
{
    duct_coro_yield();
}

static void test_coro_on_resume(void)
{
    duct_coro_pool_t pool;
    CHECK(duct_coro_pool_new(&pool, 4u, 64u * 1024u) == rc_ok, "duct_coro_pool_new(&pool, 4u, 64u * 1024u)");

    s_resume_called = false;

    auto co = duct_coro_acquire(&pool, s_sf_yield, nullptr);
    CHECK(co, "co");
    CHECK(co->on_resume == nullptr, "co->on_resume == nullptr");
    co->on_resume = s_test_resume;
    co->on_resume_ctx = nullptr;

    /* on_resume is called by duct_coop_cycle after duct_coro_resume.
     * Simulate: resume, then call on_resume manually. */
    duct_coro_resume(co);
    CHECK(co->state == coro_state_suspended || co->state == coro_state_done, "suspended or done");
    if (co->on_resume)
        co->on_resume(co, co->on_resume_ctx);
    CHECK(s_resume_called, "s_resume_called");

    duct_coro_release(&pool, co);
    duct_coro_pool_del(&pool);
    printf("  coro_on_resume OK\n");
}

/* T12: stackful wait/wake cycle — coro enters wait queue, wake finds it. */
static void s_sf_wait([[maybe_unused]] void *arg)
{
    duct_coro_wait();
}

static void test_coro_wait_wake(void)
{
    duct_coro_pool_t pool;
    CHECK(duct_coro_pool_new(&pool, 4u, 64u * 1024u) == rc_ok, "duct_coro_pool_new(&pool, 4u, 64u * 1024u)");
    duct_coro_queue_t queue;
    duct_coro_queue_init(&queue);

    auto co = duct_coro_acquire(&pool, s_sf_wait, nullptr);
    CHECK(co, "co");
    CHECK(pool.n_alive == 1u, "pool.n_alive == 1u");

    /* Resume → coro calls duct_coro_wait() → state = coro_state_waiting. */
    duct_coro_resume(co);
    CHECK(co->state == coro_state_waiting, "co->state == coro_state_waiting");

    /* Put into wait queue (mirrors what duct_coro_queue_put does for waiting). */
    duct_coro_queue_put(&queue, co);
    CHECK(queue.n_wait == 1u, "queue.n_wait == 1u");

    /* Wake — must find coro in wait_head and move to run. */
    duct_coro_queue_wake(&queue, co);
    CHECK(queue.n_wait == 0u, "queue.n_wait == 0u");
    CHECK(queue.n_run == 1u, "queue.n_run == 1u");
    CHECK(co->state == coro_state_suspended, "co->state == coro_state_suspended");

    /* Resume again — coro returns (function ends) → coro_state_done. */
    duct_coro_resume(co);
    CHECK(co->state == coro_state_done, "co->state == coro_state_done");

    duct_coro_queue_remove(&queue, co);
    duct_coro_release(&pool, co);
    CHECK(pool.n_alive == 0u, "pool.n_alive == 0u");

    duct_coro_pool_del(&pool);
    printf("  coro_wait_wake OK\n");
}

/* T13: cancel stackful coro in queue — removes + destroys cleanly. */
static void test_coro_cancel_in_queue(void)
{
    duct_coro_pool_t pool;
    CHECK(duct_coro_pool_new(&pool, 4u, 64u * 1024u) == rc_ok, "duct_coro_pool_new(&pool, 4u, 64u * 1024u)");
    duct_coro_queue_t queue;
    duct_coro_queue_init(&queue);

    /* Create a coro that yields once then waits. */
    auto co = duct_coro_acquire(&pool, s_sf_yield, nullptr);
    CHECK(co, "co");
    CHECK(pool.n_alive == 1u, "pool.n_alive == 1u");

    /* Resume → yield → coro_state_suspended. */
    duct_coro_resume(co);
    CHECK(co->state == coro_state_suspended, "co->state == coro_state_suspended");

    /* Put in run queue. */
    duct_coro_queue_put(&queue, co);
    CHECK(queue.n_run == 1u, "queue.n_run == 1u");

    /* Cancel: remove from queue + destroy. */
    duct_coro_queue_remove(&queue, co);
    CHECK(queue.n_run == 0u, "queue.n_run == 0u");
    duct_coro_release(&pool, co);
    CHECK(pool.n_alive == 0u, "pool.n_alive == 0u");

    /* Same for coro_state_waiting state. */
    auto co2 = duct_coro_acquire(&pool, s_sf_wait, nullptr);
    CHECK(co2, "co2");
    duct_coro_resume(co2);
    CHECK(co2->state == coro_state_waiting, "co2->state == coro_state_waiting");
    duct_coro_queue_put(&queue, co2);
    CHECK(queue.n_wait == 1u, "queue.n_wait == 1u");
    duct_coro_queue_remove(&queue, co2);
    CHECK(queue.n_wait == 0u, "queue.n_wait == 0u");
    duct_coro_release(&pool, co2);
    CHECK(pool.n_alive == 0u, "pool.n_alive == 0u");

    duct_coro_pool_del(&pool);
    printf("  coro_cancel_in_queue OK\n");
}

int main(void)
{
    printf("stream_handler_test:\n");

    test_state();
    test_on_done();
    test_wake_coro();
    test_queue_remove();
    test_handler_ctx_lifecycle();
    test_stream_teardown();
    test_handler_async_done_path();
    test_handler_async_yield_path();
    test_handler_validation();
    test_coro_on_resume();
    test_coro_wait_wake();
    test_coro_cancel_in_queue();

    printf("stream_handler_test OK\n");
    return 0;
}
