/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file session_timer_test.c
 * @brief The folded timer payload: the wheel node carries its own context.
 *
 * No engine, no worker: the timer set's own inline surface (duct_timer_add_ctx
 * over duct_timers_t) drives every edge — one-shot fire reading the folded
 * payload, cancel by handle, a repeating timer keeping its payload across
 * fires, destroy with a pending node, and the free-timer payload shape.
 */

/* AI-generated test code. */

#include "duct_timer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void s_fail(const char *what)
{
    fprintf(stderr, "session_timer: %s\n", what);
    exit(1);
}

static void s_expect(bool ok, const char *what)
{
    if (!ok)
        s_fail(what);
}

static duct_timer_ctx_t g_seen;
static unsigned g_fires;

static duct_exec_rc_t s_note_fire(void *arg)
{
    auto t = (duct_timer_t *)arg;
    s_expect(t->arg == t, "a folded timer's exec received a foreign arg");
    g_seen = t->ctx;
    ++g_fires;
    return exec_done;
}

static duct_exec_rc_t s_note_fire_free(void *arg)
{
    auto t = (duct_timer_t *)arg;
    s_expect(t->arg == t, "a folded free timer's exec received a foreign arg");
    g_seen = t->ctx;
    ++g_fires;
    return exec_done;
}

static struct timespec s_later_ms(uint64_t ms)
{
    return duct_time_add(duct_time_now(), duct_time_from_us(ms * 1000u));
}

static void t_fold_once(void)
{
    duct_timers_t tl;
    duct_timers_init(&tl);
    duct_timer_ctx_t ctx = { .session_tok = 0x1122'3344'5566'7788ull,
                             .token = 42u, .key = 7u };
    auto h = duct_timer_add_ctx(&tl, 3u, 0u, 0u, 0u, 1u, s_note_fire, &ctx);
    s_expect(h != timer_handle_null, "add_ctx refused a fresh set");
    s_expect(duct_timer_handle_proc(h) == 3u, "the handle lost its proc index");

    g_fires = 0u;
    g_seen = (duct_timer_ctx_t){};
    duct_discard duct_timers_drain_at(&tl, s_later_ms(50u));
    s_expect(g_fires == 1u, "the one-shot folded timer never fired");
    s_expect(g_seen.session_tok == 0x1122'3344'5566'7788ull
             && g_seen.token == 42u && g_seen.key == 7u,
             "the fire read a payload other than the one armed");
    s_expect(tl.free_count == 1u, "the fired node did not return to the free chain");
    s_expect(duct_timer_cancel(&tl, h) == false, "a fired handle still resolved");

    auto reuse = duct_timer_add_ctx(&tl, 3u, 0u, 3600'000'000u, 0u, 1u, s_note_fire,
                                    &(duct_timer_ctx_t){});
    duct_timers_destroy(&tl);
    s_expect(reuse != timer_handle_null, "the freed node was not reused");
    s_expect(g_fires == 1u, "destroy fired the pending node");
}

static void t_fold_cancel(void)
{
    duct_timers_t tl;
    duct_timers_init(&tl);
    duct_timer_ctx_t ctx = { .session_tok = 1u };
    auto h = duct_timer_add_ctx(&tl, 0u, 0u, 3000u, 0u, 1u, s_note_fire, &ctx);
    s_expect(h != timer_handle_null, "add_ctx refused a fresh set");
    s_expect(duct_timer_cancel(&tl, h) == true, "cancel refused a live handle");
    s_expect(duct_timer_cancel(&tl, h) == false, "a cancelled handle resolved twice");

    g_fires = 0u;
    duct_discard duct_timers_drain_at(&tl, s_later_ms(4000u));
    s_expect(g_fires == 0u, "a cancelled folded timer fired");

    auto t = duct_timer_add_ctx(&tl, 0u, 0u, 0u, 0u, 1u, s_note_fire, &ctx);
    s_expect(t != timer_handle_null, "the set refused a node after a cancel");
    duct_timers_destroy(&tl);
}

static void t_fold_repeat(void)
{
    duct_timers_t tl;
    duct_timers_init(&tl);
    duct_timer_ctx_t ctx = { .session_tok = 0xAu, .token = 0xBu, .key = 0xCu };
    auto opened = duct_time_now();
    auto h = duct_timer_add_ctx(&tl, 1u, 0u, 105'000u, 200'000u, 0u, s_note_fire, &ctx);
    s_expect(h != timer_handle_null, "add_ctx refused a repeating arm");

    static constexpr uint64_t drain_at_ms[3u] = {1000u, 3000u, 6000u};
    g_fires = 0u;
    for (unsigned i = 0u; i < 3u; ++i) {
        g_seen = (duct_timer_ctx_t){};
        duct_discard duct_timers_drain_at(
            &tl, duct_time_add(opened, duct_time_from_us(drain_at_ms[i] * 1000u)));
        s_expect(g_fires == i + 1u, "the repeating folded timer missed a fire");
        s_expect(g_seen.session_tok == 0xAu && g_seen.token == 0xBu && g_seen.key == 0xCu,
                 "a repeat fired a payload other than the one armed");
    }
    s_expect(duct_timer_cancel(&tl, h) == true, "cancel refused the repeating handle");
    duct_timers_destroy(&tl);
}

static void t_fold_free_class(void)
{
    static uint64_t scratch = 5u;
    duct_timers_t tl;
    duct_timers_init(&tl);
    duct_timer_ctx_t ctx = { .proto = (const struct duct_proto *)&scratch,
                             .user_ctx = &scratch, .arg = 0xDu };
    auto h = duct_timer_add_ctx(&tl, 0u, 0u, 0u, 0u, 1u, s_note_fire_free, &ctx);
    s_expect(h != timer_handle_null, "add_ctx refused the free-class arm");

    g_fires = 0u;
    g_seen = (duct_timer_ctx_t){};
    duct_discard duct_timers_drain_at(&tl, s_later_ms(50u));
    s_expect(g_fires == 1u, "the free-class folded timer never fired");
    s_expect(g_seen.proto == (const struct duct_proto *)&scratch
             && g_seen.user_ctx == (void *)&scratch && g_seen.arg == 0xDu,
             "the free-class fire read a payload other than the one armed");
    duct_timers_destroy(&tl);
}

static void t_fold_pending_destroy(void)
{
    duct_timers_t tl;
    duct_timers_init(&tl);
    duct_timer_ctx_t ctx = { .session_tok = 2u };
    auto h = duct_timer_add_ctx(&tl, 0u, 0u, 600'000u, 0u, 1u, s_note_fire, &ctx);
    s_expect(h != timer_handle_null, "add_ctx refused a long arm");

    g_fires = 0u;
    duct_discard duct_timers_drain_at(&tl, s_later_ms(50u));
    s_expect(g_fires == 0u, "a pending folded timer fired early");
    duct_timers_destroy(&tl);
    s_expect(g_fires == 0u, "destroy fired the pending folded timer");
    duct_timers_destroy(&tl);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    t_fold_once();
    t_fold_cancel();
    t_fold_repeat();
    t_fold_free_class();
    t_fold_pending_destroy();

    printf("session_timer: OK (the wheel node carries the folded payload through "
           "one-shot fire, cancel, repeat, the free-class shape and "
           "destroy-with-pending)\n");
    return 0;
}
