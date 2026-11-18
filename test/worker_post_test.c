/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

#include "duct.h"
#include "duct_session.h"
#include "test_helpers.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>

#define expect(cond, msg) do { if (!(cond)) return msg; } while (0)

static constexpr unsigned worker_count = 3u;
static constexpr unsigned wait_ms      = 3000u;

typedef struct {
    atomic_int hits[worker_count];
    atomic_int total;
    atomic_int bad_self;
    atomic_int bad_engine;
    atomic_int bad_ctx;
    atomic_int bad_arg;
} work_tally_t;

static duct_engine_t *g_e;
static int            g_cfg_ctx;
static int            g_call_ctx;
static work_tally_t   g_tally;

static atomic_int           g_switch_rc;
static uint64_t _Atomic     g_sess_tok;
static atomic_int           g_sess_opened;
static atomic_int           g_sess_closed;
static duct_proto_t        *g_work_only;

static void s_tally_reset(void)
{
    for (unsigned i = 0u; i < worker_count; ++i)
        atomic_store(&g_tally.hits[i], 0);
    atomic_store(&g_tally.total, 0);
    atomic_store(&g_tally.bad_self, 0);
    atomic_store(&g_tally.bad_engine, 0);
    atomic_store(&g_tally.bad_ctx, 0);
    atomic_store(&g_tally.bad_arg, 0);
}

static void s_raw_job(duct_engine_t *e, unsigned worker, void *ctx)
{
    if (duct_worker_self() != worker)
        atomic_fetch_add(&g_tally.bad_self, 1);
    if (e != g_e)
        atomic_fetch_add(&g_tally.bad_engine, 1);
    if (ctx != &g_call_ctx)
        atomic_fetch_add(&g_tally.bad_ctx, 1);
    if (worker < worker_count)
        atomic_fetch_add(&g_tally.hits[worker], 1);
    atomic_fetch_add(&g_tally.total, 1);
}

static void s_proto_job(duct_engine_t *e, unsigned worker, void *user_ctx, uintptr_t arg)
{
    if (duct_worker_self() != worker)
        atomic_fetch_add(&g_tally.bad_self, 1);
    if (e != g_e)
        atomic_fetch_add(&g_tally.bad_engine, 1);
    void *expected_ctx = arg == 1u ? (void *)&g_call_ctx : (void *)&g_cfg_ctx;
    if (user_ctx != expected_ctx)
        atomic_fetch_add(&g_tally.bad_ctx, 1);
    if (arg != 1u && arg != 2u)
        atomic_fetch_add(&g_tally.bad_arg, 1);
    if (worker < worker_count)
        atomic_fetch_add(&g_tally.hits[worker], 1);
    atomic_fetch_add(&g_tally.total, 1);
}

static duct_result_t s_nop_timer([[maybe_unused]] duct_session_t *s,
                                 [[maybe_unused]] duct_response_t *out,
                                 [[maybe_unused]] void *proto_state,
                                 [[maybe_unused]] uint64_t arg)
{
    return rc_ok;
}

static duct_resolve_disposition_t s_nop_preparse([[maybe_unused]] void *ctx,
                                                 [[maybe_unused]] const duct_peer_t *peer,
                                                 [[maybe_unused]] duct_view_u8 peek,
                                                 [[maybe_unused]] duct_handle_t *out_tok,
                                                 [[maybe_unused]] duct_conn_id_t *out_conn_id,
                                                 [[maybe_unused]] void **out_user_ctx,
                                                 [[maybe_unused]] size_t *out_lead)
{
    return resolve_not_me;
}

static void s_nop_coro([[maybe_unused]] void *arg) {}

static duct_result_t s_on_open([[maybe_unused]] duct_session_t *s,
                               duct_handle_t tok,
                               [[maybe_unused]] void *user_ctx,
                               [[maybe_unused]] duct_response_t *out,
                               [[maybe_unused]] void *proto_state)
{
    atomic_store(&g_sess_tok, tok);
    atomic_store(&g_sess_opened, 1);
    return rc_ok;
}

static duct_result_t s_on_frame(duct_session_t *s,
                                [[maybe_unused]] duct_conn_id_t conn_id,
                                [[maybe_unused]] const duct_frame_t *frame,
                                [[maybe_unused]] duct_response_t *out,
                                [[maybe_unused]] void *proto_state)
{
    atomic_store(&g_switch_rc, (int)duct_proto_switch(s, g_work_only, nullptr));
    return rc_ok;
}

static void s_on_close([[maybe_unused]] duct_session_t *s,
                       [[maybe_unused]] duct_close_reason_t reason,
                       [[maybe_unused]] void *proto_state)
{
    atomic_store(&g_sess_closed, 1);
}

static const char *sc_raw_post(void)
{
    s_tally_reset();
    expect(duct_engine_workers(nullptr) == 0u, "null engine reported workers");
    expect(duct_engine_workers(g_e) == worker_count, "wrong worker count");
    expect(duct_worker_self() == duct_worker_none, "host thread reported worker id");

    expect(duct_worker_post(nullptr, 0u, s_raw_job, &g_call_ctx) == rc_invalid_arg,
           "null engine accepted");
    expect(duct_worker_post(g_e, 0u, nullptr, &g_call_ctx) == rc_invalid_arg,
           "null fn accepted");
    expect(duct_worker_post(g_e, worker_count, s_raw_job, &g_call_ctx) == rc_invalid_arg,
           "out-of-range worker accepted");

    for (unsigned i = 0u; i < worker_count; ++i)
        expect(duct_worker_post(g_e, i, s_raw_job, &g_call_ctx) == rc_ok,
               "targeted post refused");

    expect(th_wait_int(&g_tally.total, (int)worker_count, wait_ms),
           "targeted jobs did not complete");
    th_sleep_ms(30u);
    expect(atomic_load(&g_tally.total) == (int)worker_count, "job ran more than once");
    expect(atomic_load(&g_tally.bad_self) == 0, "worker_self mismatch");
    expect(atomic_load(&g_tally.bad_engine) == 0, "engine pointer mismatch");
    expect(atomic_load(&g_tally.bad_ctx) == 0, "ctx mismatch");
    for (unsigned i = 0u; i < worker_count; ++i)
        expect(atomic_load(&g_tally.hits[i]) == 1, "worker hit count != 1");

    s_tally_reset();
    constexpr unsigned any_n = worker_count * 4u;
    for (unsigned i = 0u; i < any_n; ++i)
        expect(duct_worker_post(g_e, duct_worker_any, s_raw_job, &g_call_ctx) == rc_ok,
               "duct_worker_any post refused");
    expect(th_wait_int(&g_tally.total, (int)any_n, wait_ms),
           "any-worker jobs did not complete");
    unsigned non_zero = 0u;
    for (unsigned i = 0u; i < worker_count; ++i)
        non_zero += atomic_load(&g_tally.hits[i]) > 0;
    expect(non_zero > 1u, "duct_worker_any did not spread across workers");
    return nullptr;
}

static const char *sc_proto_work(void)
{
    s_tally_reset();
    expect(!duct_proto_create(&(duct_proto_cfg_t){ .name = "empty" }),
           "empty proto created");
    expect(!duct_proto_create(&(duct_proto_cfg_t){
               .name = "work-preparse", .on_work = s_proto_job,
               .preparse = s_nop_preparse, .preparse_mode = resolve_sync }),
           "frame-less proto with preparse created");
    expect(!duct_proto_create(&(duct_proto_cfg_t){
               .name = "work-handler", .on_work = s_proto_job,
               .handler_kind = handler_coro, .handler_coro = s_nop_coro }),
           "frame-less proto with handler created");

    auto work_p = duct_proto_create(&(duct_proto_cfg_t){
        .name = "work-only", .user_ctx = &g_cfg_ctx, .on_work = s_proto_job });
    auto timer_p = duct_proto_create(&(duct_proto_cfg_t){
        .name = "timer-only", .on_timer = s_nop_timer });
    expect(work_p && timer_p, "work/timer-only proto create failed");

    g_work_only = work_p;
    auto frame_p = duct_proto_create(&(duct_proto_cfg_t){
        .name = "frame-echo",
        .on_session_open = s_on_open,
        .on_frame = s_on_frame,
        .on_session_close = s_on_close,
        .max_response = 64u,
    });
    expect(frame_p, "frame proto create failed");

    uint16_t port = 0u;
    expect(duct_io_listen(g_e, "127.0.0.1", &port, work_p) == rc_invalid_arg,
           "listen accepted on_work-only proto");
    expect(duct_io_listen(g_e, "127.0.0.1", &port, timer_p) == rc_invalid_arg,
           "listen accepted on_timer-only proto");
    expect(duct_io_connect(g_e, "127.0.0.1:1", work_p, nullptr, x_tcp) == rc_invalid_arg,
           "connect accepted on_work-only proto");

    duct_sock_t sv[2] = { duct_sock_bad, duct_sock_bad };
    expect(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");
    expect(duct_io_attach_packet_fd(g_e, sv[0], work_p, nullptr) == rc_invalid_arg,
           "attach_packet_fd accepted on_work-only proto");
    close(sv[1]);

    expect(duct_proto_post(g_e, 0u, timer_p, nullptr, 1u) == rc_invalid_arg,
           "proto_post accepted timer-only proto");

    expect(duct_proto_post(g_e, 1u, work_p, &g_call_ctx, 1u) == rc_ok,
           "proto_post with explicit user_ctx failed");
    expect(duct_proto_post(g_e, duct_worker_any, work_p, nullptr, 2u) == rc_ok,
           "proto_post with default user_ctx failed");
    expect(th_wait_int(&g_tally.total, 2, wait_ms), "proto_post jobs did not run");
    expect(atomic_load(&g_tally.bad_self) == 0 && atomic_load(&g_tally.bad_engine) == 0
               && atomic_load(&g_tally.bad_ctx) == 0 && atomic_load(&g_tally.bad_arg) == 0,
           "proto_post callback saw wrong arguments");
    for (unsigned i = 0u; i < 100u && duct_atomic_load(&work_p->life, acquire) != 0u; ++i)
        th_sleep_ms(1u);
    expect(duct_atomic_load(&work_p->life, acquire) == 0u,
           "proto hold count non-zero after proto_post execution");

    port = 0u;
    atomic_store(&g_sess_opened, 0);
    atomic_store(&g_sess_closed, 0);
    atomic_store(&g_switch_rc, (int)rc_ok);
    expect(duct_io_listen(g_e, "127.0.0.1", &port, frame_p) == rc_ok, "echo listen failed");
    auto fd = th_connect(port);
    expect(fd != duct_sock_bad, "connect failed");
    expect(th_wait_int(&g_sess_opened, 1, wait_ms), "session did not open");
    expect(send(fd, "a", 1, 0) == 1, "send failed");
    expect(th_wait_int(&g_switch_rc, (int)rc_invalid_arg, wait_ms),
           "duct_proto_switch accepted on_work-only proto");
    close(fd);
    expect(th_wait_int(&g_sess_closed, 1, wait_ms), "session did not close");
    duct_session_handle_t stok = { .word = atomic_load(&g_sess_tok) };
    for (unsigned i = 0u; i < wait_ms && duct_session_by_handle(stok); ++i)
        th_sleep_ms(1u);
    expect(!duct_session_by_handle(stok), "session close walk did not finish");

    g_work_only = nullptr;
    duct_proto_destroy(frame_p);
    duct_proto_destroy(timer_p);
    duct_proto_destroy(work_p);
    return nullptr;
}

typedef struct {
    atomic_int *calls_out;
    atomic_int  calls;
    atomic_int  last_rc;
    bool        free_ctx;
} invoke_done_state_t;

static duct_result_t s_invoke_work([[maybe_unused]] duct_session_t *s,
                                   duct_response_t *out, void *ctx)
{
    *out = (duct_response_t){};
    return ctx ? *(const duct_result_t *)ctx : rc_ok;
}

static void s_invoke_done(duct_result_t rc, void *done_ctx)
{
    auto st = (invoke_done_state_t *)done_ctx;
    atomic_int *calls_out = st->calls_out;
    bool free_ctx = st->free_ctx;
    atomic_store(&st->last_rc, (int)rc);
    atomic_fetch_add(&st->calls, 1);
    if (free_ctx)
        free(st);
    if (calls_out)
        atomic_fetch_add(calls_out, 1);
}

static const char *sc_invoke_done(void)
{
    auto frame_p = duct_proto_create(&(duct_proto_cfg_t){
        .name = "invoke-done-proto",
        .on_session_open = s_on_open,
        .on_frame = s_on_frame,
        .on_session_close = s_on_close,
        .max_response = 64u,
    });
    expect(frame_p, "proto create failed");

    invoke_done_state_t invalid_st = {};
    expect(duct_session_invoke_done(nullptr, 1u, s_invoke_work, nullptr, s_invoke_done, &invalid_st)
               == rc_invalid_arg,
           "null engine accepted");
    expect(atomic_load(&invalid_st.calls) == 0, "on_done ran on rc_invalid_arg");

    invoke_done_state_t stale_st = {};
    expect(duct_session_invoke_done(g_e, 0u, s_invoke_work, nullptr, s_invoke_done, &stale_st)
               == rc_closed,
           "stale token accepted");
    expect(atomic_load(&stale_st.calls) == 1 && atomic_load(&stale_st.last_rc) == (int)rc_closed,
           "on_done did not report rc_closed for stale token");

    uint16_t port = 0u;
    atomic_store(&g_sess_opened, 0);
    atomic_store(&g_sess_closed, 0);
    expect(duct_io_listen(g_e, "127.0.0.1", &port, frame_p) == rc_ok, "listen failed");
    auto fd = th_connect(port);
    expect(fd != duct_sock_bad, "connect failed");
    expect(th_wait_int(&g_sess_opened, 1, wait_ms), "session did not open");
    duct_handle_t tok = atomic_load(&g_sess_tok);

    auto live_st = (invoke_done_state_t *)calloc(1u, sizeof(invoke_done_state_t));
    expect(live_st, "calloc failed");
    atomic_int heap_calls = 0;
    live_st->calls_out = &heap_calls;
    live_st->free_ctx = true;
    invoke_done_state_t norm_st = {};
    duct_result_t expect_norm = rc_again;
    expect(duct_session_invoke_done(g_e, tok, s_invoke_work, &expect_norm,
                                    s_invoke_done, &norm_st) == rc_ok,
           "live invoke_done refused");
    expect(th_wait_int(&norm_st.calls, 1, wait_ms), "live invoke on_done did not run");
    expect(atomic_load(&norm_st.last_rc) == (int)rc_again, "live invoke rc mismatch");

    expect(duct_session_close(g_e, tok, close_normal) == rc_ok, "session close refused");
    duct_result_t expect_race = rc_ok;
    duct_result_t rc_race = duct_session_invoke_done(g_e, tok, s_invoke_work,
                                                     &expect_race,
                                                     s_invoke_done, live_st);
    expect(rc_race == rc_ok || rc_race == rc_closed, "unexpected invoke rc after close");
    expect(th_wait_int(&heap_calls, 1, wait_ms), "heap-owned on_done did not run");
    expect(th_wait_int(&g_sess_closed, 1, wait_ms), "session did not close");
    close(fd);
    th_sleep_ms(30u);

    invoke_done_state_t after_close = {};
    expect(duct_session_invoke_done(g_e, tok, s_invoke_work, nullptr, s_invoke_done, &after_close)
               == rc_closed,
           "closed session invoke_done did not report rc_closed");
    expect(atomic_load(&after_close.calls) == 1
               && atomic_load(&after_close.last_rc) == (int)rc_closed,
           "after-close on_done mismatch");

    duct_proto_destroy(frame_p);
    return nullptr;
}

typedef struct {
    duct_engine_t *e;
    duct_proto_t  *proto;
} race_arg_t;

static void s_race_work([[maybe_unused]] duct_engine_t *e,
                        [[maybe_unused]] unsigned worker,
                        [[maybe_unused]] void *user_ctx,
                        [[maybe_unused]] uintptr_t arg)
{
}

static void *s_storm_thread(void *arg)
{
    auto ra = (race_arg_t *)arg;
    for (unsigned i = 0u; i < 400u; ++i) {
        auto rc = duct_proto_post(ra->e, duct_worker_any, ra->proto, nullptr, i);
        if (rc == rc_invalid_order)
            break;
    }
    return nullptr;
}

static const char *sc_stop_race(void)
{
    auto race_p = duct_proto_create(&(duct_proto_cfg_t){
        .name = "race-work", .on_work = s_race_work });
    /* The worker module serves one live engine: the first engine retires
     * here, its module cleanup behind it, so the second launch re-inits the
     * module instead of overwriting a live one's arrays. */
    duct_engine_stop(g_e);
    duct_engine_destroy(g_e);
    g_e = nullptr;
    auto race_e = race_p ? duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1u, .workers = 2u })
                         : nullptr;
    expect(race_e && race_p, "race setup failed");

    race_arg_t ra = { .e = race_e, .proto = race_p };
    pthread_t th[2];
    for (unsigned i = 0u; i < 2u; ++i)
        expect(pthread_create(&th[i], nullptr, s_storm_thread, &ra) == 0, "pthread_create failed");

    th_sleep_ms(2u);
    duct_engine_stop(race_e);

    for (unsigned i = 0u; i < 2u; ++i)
        pthread_join(th[i], nullptr);

    expect(duct_worker_post(race_e, 0u, s_raw_job, &g_call_ctx) == rc_invalid_order,
           "stopped engine accepted worker_post");
    expect(duct_proto_post(race_e, 0u, race_p, nullptr, 0u) == rc_invalid_order,
           "stopped engine accepted proto_post");

    invoke_done_state_t stop_done = {};
    expect(duct_session_invoke_done(race_e, 1u, s_invoke_work, nullptr, s_invoke_done, &stop_done)
               == rc_closed,
           "stopped engine did not refuse invoke_done with rc_closed");
    expect(atomic_load(&stop_done.calls) == 1
               && atomic_load(&stop_done.last_rc) == (int)rc_closed,
           "stopped engine on_done mismatch");

    duct_engine_destroy(race_e);
    expect(duct_atomic_load(&race_p->life, acquire) == 0u,
           "proto holds leaked across stop/destroy race");
    duct_proto_destroy(race_p);
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    g_e = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1u, .workers = worker_count });
    if (!g_e) {
        fprintf(stderr, "worker_post: engine launch failed\n");
        return 1;
    }

    static const struct { const char *name; const char *(*fn)(void); } cases[] = {
        { "raw_post",    sc_raw_post },
        { "proto_work",  sc_proto_work },
        { "invoke_done", sc_invoke_done },
        { "stop_race",   sc_stop_race },
    };

    int failed = 0;
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        auto err = cases[i].fn();
        if (err) {
            fprintf(stderr, "worker_post: %s: %s\n", cases[i].name, err);
            ++failed;
        }
    }

    if (failed)
        return 1;
    printf("worker_post: OK\n");
    return 0;
}
