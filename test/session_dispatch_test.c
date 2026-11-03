/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file session_dispatch_test.c
 *  @brief @c duct_session_dispatch on a live engine of two workers and four sessions.
 *
 *  @c sc_host expects a call from the host thread to be posted and to run on the session's worker. @c sc_here
 *  expects, from a callback on one worker, a call for the session it runs in and a call for another session of
 *  the same worker to run before the call returns, and a call for a session of the other worker to run on that
 *  worker. @c sc_args expects a null engine and a null function to be refused. @c sc_flood expects a burst
 *  of calls from the host thread to run once each. @c sc_ended parks the worker of a session, posts a call
 *  for the session behind a close of it, and expects the call, taken as posted, not to run once the session
 *  has ended before the worker reaches it. @c sc_gone expects the token of a session that has ended to be
 *  refused as closed, and the function not to run. The carriers of the posted calls the stopping engine strands
 *  at the end are freed, which the sanitizer builds check.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>

/** @brief Return @p msg from the calling check when @p cond fails. */
#define expect(cond, msg) do { if (!(cond)) return msg; } while (0)

/** @brief Longest wait for an event, milliseconds. */
static constexpr unsigned wait_ms  = 3000u;
/** @brief Sessions the scenarios share. */
static constexpr unsigned sessions = 6u;
/** @brief Sessions from the first that stay open to the end; the rest are for the scenarios that end sessions. */
static constexpr unsigned live     = 3u;
/** @brief Calls of the burst. */
static constexpr unsigned flood    = 4000u;

/** @brief What the open of one session recorded. */
typedef struct {
    duct_handle_t token;  /**< Token of the session. */
    pthread_t     thread; /**< Thread of the worker the session opened on. */
} sess_t;

/** @brief What one run of the dispatched function recorded. */
typedef struct {
    atomic_int ran;    /**< 1 once the function ran. */
    pthread_t  thread; /**< Thread it ran on, written before @c ran. */
} mark_t;

/** @brief The engine. */
static duct_engine_t *g_io;
/** @brief The sessions by the order they opened. */
static sess_t         g_s[sessions];
/** @brief Slots of @c g_s taken. */
static atomic_int     g_taken  = 0;
/** @brief Slots of @c g_s filled. */
static atomic_int     g_opened = 0;
/** @brief Sessions that ended. */
static atomic_int     g_closed = 0;
/** @brief Runs of the burst's function. */
static atomic_int     g_flooded = 0;
/** @brief Park of the worker @c sc_ended holds. */
static atomic_int     g_hold = th_hold_off;
/** @brief Reserved session that ends under a posted call, a live one on its worker, and the one that ends alone. */
static unsigned       g_victim, g_mate, g_gone;

/** @brief Record the token and the worker's thread of the session in the next slot. */
static duct_result_t on_session_open([[maybe_unused]] duct_session_t *s, duct_handle_t token,
                                     [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
                                     [[maybe_unused]] void *proto_state)
{
    int at = duct_atomic_fetch(add, &g_taken, 1, relaxed);
    if (at < (int)sessions)
        g_s[at] = (sess_t){ .token = token, .thread = pthread_self() };
    duct_atomic_fetch(add, &g_opened, 1, release);
    return rc_ok;
}

/** @brief Count the end of a session. */
static void on_session_close([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_close_reason_t reason,
                             [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_closed, 1, release);
}

/** @brief Take every frame and answer none. */
static duct_result_t on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                              [[maybe_unused]] const duct_frame_t *frame,
                              [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

/** @brief Record the thread the function runs on, then raise @c ran. */
static void s_mark(void *ctx)
{
    auto m = (mark_t *)ctx;
    m->thread = pthread_self();
    duct_atomic_store(&m->ran, 1, release);
}

/** @brief Count one run of the burst's function. */
static void s_count([[maybe_unused]] void *ctx)
{
    duct_atomic_fetch(add, &g_flooded, 1, relaxed);
}

/** @brief Hold the worker of the session the call runs in until the test releases it. */
static duct_result_t s_park([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_response_t *out,
                            [[maybe_unused]] void *ctx)
{
    th_hold_park(&g_hold, wait_ms);
    return rc_ok;
}

/** @brief Do nothing; a sync invoke of it returns once the worker has run every call posted before it. */
static duct_result_t s_nop([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_response_t *out,
                           [[maybe_unused]] void *ctx)
{
    return rc_ok;
}

/** @brief What a probe saw from inside a callback of the session @c self. */
typedef struct {
    unsigned      self;     /**< Index of the session the probe runs in. */
    unsigned      mate;     /**< Index of another session of the same worker. */
    unsigned      other;    /**< Index of a session of the other worker. */
    pthread_t     me;       /**< Thread the probe ran on. */
    mark_t        own,      /**< The run for the session the probe is in. */
                  same,     /**< The run for the mate. */
                  away;     /**< The run for the session of the other worker. */
    duct_result_t own_rc, same_rc, away_rc;
    int           own_ran,  /**< @c own.ran as the call returned. */
                  same_ran; /**< @c same.ran as the call returned. */
    atomic_int    done;     /**< 1 once the probe finished. */
} probe_t;

/** @brief Call the dispatch for the three sessions the probe names and note what each did by the time it returned. */
static duct_result_t s_probe([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_response_t *out, void *ctx)
{
    auto p = (probe_t *)ctx;
    p->me = pthread_self();
    p->own_rc = duct_session_dispatch(g_io, g_s[p->self].token, s_mark, &p->own);
    p->own_ran = duct_atomic_load(&p->own.ran, acquire);
    p->same_rc = duct_session_dispatch(g_io, g_s[p->mate].token, s_mark, &p->same);
    p->same_ran = duct_atomic_load(&p->same.ran, acquire);
    p->away_rc = duct_session_dispatch(g_io, g_s[p->other].token, s_mark, &p->away);
    duct_atomic_store(&p->done, 1, release);
    return rc_ok;
}

/** @brief Call the dispatch from the host thread for the first session.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_host(void)
{
    mark_t m = {};
    expect(duct_session_dispatch(g_io, g_s[0].token, s_mark, &m) == rc_ok, "a call from the host thread was refused");
    expect(th_wait_int(&m.ran, 1, wait_ms), "a call from the host thread never ran");
    expect(pthread_equal(m.thread, g_s[0].thread), "a call from the host thread did not run on the session's worker");
    expect(!pthread_equal(m.thread, pthread_self()), "a call from the host thread ran on the host thread");
    return nullptr;
}

/** @brief Pick a session that has a mate on its worker and a session on the other one, and probe from inside it.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_here(void)
{
    probe_t p = {};
    bool found = false;
    for (unsigned i = 0u; i < sessions && !found; ++i) {
        bool has_mate = false, has_other = false;
        for (unsigned j = 0u; j < sessions; ++j) {
            if (j == i)
                continue;
            if (pthread_equal(g_s[j].thread, g_s[i].thread)) {
                p.mate = j;
                has_mate = true;
            } else {
                p.other = j;
                has_other = true;
            }
        }
        p.self = i;
        found = has_mate && has_other;
    }
    expect(found, "the sessions did not spread over both workers");
    expect(duct_session_invoke(g_io, g_s[p.self].token, s_probe, &p) == rc_ok, "the probe was refused");
    expect(th_wait_int(&p.done, 1, wait_ms), "the probe never ran");
    expect(pthread_equal(p.me, g_s[p.self].thread), "the probe did not run on its session's worker");
    expect(p.own_rc == rc_ok && p.own_ran == 1 && pthread_equal(p.own.thread, p.me),
           "a call for the session it ran in did not run before it returned, on the same thread");
    expect(p.same_rc == rc_ok && p.same_ran == 1 && pthread_equal(p.same.thread, p.me),
           "a call for another session of the same worker did not run before it returned, on the same thread");
    expect(p.away_rc == rc_ok, "a call for a session of the other worker was refused");
    expect(th_wait_int(&p.away.ran, 1, wait_ms), "a call for a session of the other worker never ran");
    expect(pthread_equal(p.away.thread, g_s[p.other].thread) && !pthread_equal(p.away.thread, p.me),
           "a call for a session of the other worker did not run on that worker");
    return nullptr;
}

/** @brief Offer arguments the call refuses.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_args(void)
{
    expect(duct_session_dispatch(nullptr, g_s[0].token, s_mark, nullptr) == rc_invalid_arg, "a null engine was taken");
    expect(duct_session_dispatch(g_io, g_s[0].token, nullptr, nullptr) == rc_invalid_arg, "a null function was taken");
    return nullptr;
}

/** @brief Post a burst from the host thread over the live sessions and wait for it to run.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_flood(void)
{
    for (unsigned i = 0u; i < flood; ++i)
        expect(duct_session_dispatch(g_io, g_s[i % live].token, s_count, nullptr) == rc_ok,
               "a call of the burst was refused");
    expect(th_wait_int(&g_flooded, (int)flood, wait_ms), "a call of the burst never ran");
    return nullptr;
}

/** @brief Park the worker of the victim, post a call for it behind its close, and let the worker go.
 *  The session is attached when the call is taken, so the call is posted, and has ended when the worker reaches it.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_ended(void)
{
    mark_t m = {};
    expect(duct_session_invoke(g_io, g_s[g_mate].token, s_park, nullptr) == rc_ok, "the park was refused");
    expect(th_wait_int(&g_hold, th_hold_parked, wait_ms), "the worker never parked");
    expect(duct_session_close(g_io, g_s[g_victim].token, close_normal) == rc_ok, "the session was not closed");
    expect(duct_session_dispatch(g_io, g_s[g_victim].token, s_mark, &m) == rc_ok,
           "a call for a session still attached was refused");
    th_hold_release(&g_hold);
    expect(th_wait_int(&g_closed, 1, wait_ms), "the session never ended");
    expect(duct_session_invoke_sync(g_io, g_s[g_mate].token, s_nop, nullptr) == rc_ok, "the barrier was refused");
    expect(duct_atomic_load(&m.ran, acquire) == 0, "a posted call for a session that ended before it was reached ran");
    return nullptr;
}

/** @brief End the spare session and call for its token.
 *  The refusal queues nothing, so the function is known not to run as the call returns.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_gone(void)
{
    mark_t m = {};
    expect(duct_session_close(g_io, g_s[g_gone].token, close_normal) == rc_ok, "the session was not closed");
    expect(th_wait_int(&g_closed, 2, wait_ms), "the session never ended");
    expect(duct_session_dispatch(g_io, g_s[g_gone].token, s_mark, &m) == rc_closed,
           "a call for a session that ended was not refused as closed");
    expect(duct_atomic_load(&m.ran, acquire) == 0, "a call for a session that ended ran");
    return nullptr;
}

/** @brief Name the roles of the sessions past @c live: two on one worker, the third alone. */
static void s_roles(void)
{
    unsigned a = live, b = live + 1u, c = live + 2u;
    if (pthread_equal(g_s[a].thread, g_s[b].thread)) {
        g_victim = a;
        g_mate = b;
        g_gone = c;
    } else if (pthread_equal(g_s[a].thread, g_s[c].thread)) {
        g_victim = a;
        g_mate = c;
        g_gone = b;
    } else {
        g_victim = b;
        g_mate = c;
        g_gone = a;
    }
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "session-dispatch", .wire = wire, .on_frame = on_frame,
        .on_session_open = on_session_open, .on_session_close = on_session_close,
    });
    if (proto)
        proto->owned_wire = wire;
    else
        duct_wire_destroy(wire);
    g_io = proto ? duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 2 }) : nullptr;
    uint16_t port = 0u;
    pthread_t th;
    duct_sock_t fd[sessions];
    bool up = g_io && duct_io_listen(g_io, "127.0.0.1", &port, proto) == rc_ok
           && pthread_create(&th, nullptr, th_run, g_io) == 0;
    for (unsigned i = 0u; up && i < sessions; ++i) {
        fd[i] = th_connect(port);
        up = fd[i] != duct_sock_bad;
    }
    up = up && th_wait_int(&g_opened, (int)sessions, wait_ms);
    if (!up) {
        fprintf(stderr, "session_dispatch: setup failed\n");
        return 1;
    }
    static const struct { const char *name; const char *(*fn)(void); } cases[] = {
        { "host",  sc_host },
        { "here",  sc_here },
        { "args",  sc_args },
        { "flood", sc_flood },
        { "ended", sc_ended },
        { "gone",  sc_gone },
    };
    s_roles();
    int failed = 0;
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        auto err = cases[i].fn();
        if (err) {
            fprintf(stderr, "session_dispatch: %s: %s\n", cases[i].name, err);
            ++failed;
        }
    }
    /* A last burst, with the engine stopped under it: what the workers never reach is freed at their exit. */
    for (unsigned i = 0u; i < flood; ++i)
        duct_discard duct_session_dispatch(g_io, g_s[i % live].token, s_count, nullptr);
    for (unsigned i = 0u; i < sessions; ++i)
        close(fd[i]);
    duct_engine_stop(g_io);
    pthread_join(th, nullptr);
    duct_engine_destroy(g_io);
    duct_proto_destroy(proto);
    if (failed)
        return 1;
    printf("session_dispatch: OK\n");
    return 0;
}
