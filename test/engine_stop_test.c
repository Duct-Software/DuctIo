/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file engine_stop_test.c
 *  @brief The stop request: setting it, waiting for it and what ends a wait.
 *
 *  @c sc_request expects a wait for the request to return rc_ok once another
 *  thread requests a stop, and not before, and a stop after it to answer rc_ok.
 *  @c sc_level expects a request made ahead of the wait to end it, twice over, and
 *  a repeated request to answer rc_ok. @c sc_fresh expects the request of one run
 *  not to end the wait of the next. @c sc_wait_stops expects @c duct_engine_wait to
 *  answer rc_ok after a request, and a stop after it to answer rc_ok.
 *  @c sc_stop_wakes and @c sc_destroy_wakes expect a wait for the request to
 *  return rc_ok when another thread stops or destroys the engine, and not before.
 *  @c sc_null expects rc_invalid_arg from the three calls on no engine.
 */

#include "duct.h"
#include "duct_ticks.h"
#include "test_helpers.h"

#include <pthread.h>
#include <stdio.h>

/** @brief Delay of the helper threads, milliseconds. */
static constexpr unsigned delay_ms = 20u;
/** @brief Shortest wait that proves the request came from the helper, not earlier. */
static constexpr uint64_t early_ns = 10'000'000u;

/** @brief Launch an engine of one io thread and one worker. */
static duct_engine_t *launch(void)
{
    return duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1u, .workers = 1u });
}

/** @brief A thread waiting for the request, and what it saw. */
typedef struct {
    duct_engine_t   *engine;
    duct_result_t    rc;       /**< Answer of the wait. */
    uint32_t _Atomic returned; /**< 1 once the wait has returned. */
} waiter_t;

/** @brief Thread body: wait for the request, then record the answer. */
static void *wait_request_job(void *arg)
{
    auto w = (waiter_t *)arg;
    w->rc = duct_engine_wait_request(w->engine);
    duct_atomic_store(&w->returned, 1u, release);
    return nullptr;
}

/** @brief Thread body: ask for a stop after the delay. */
static void *request_later_job(void *arg)
{
    th_sleep_ms(delay_ms);
    duct_discard duct_engine_request_stop((duct_engine_t *)arg);
    return nullptr;
}

/** @brief Wait for a request that a thread makes after the delay, then stop.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_request(void)
{
    auto e = launch();
    if (!e)
        return "engine launch failed";
    pthread_t thread;
    if (pthread_create(&thread, nullptr, request_later_job, e) != 0) {
        duct_engine_destroy(e);
        return "the requesting thread did not start";
    }
    uint64_t began = duct_ticks_mono_ns();
    duct_result_t rc = duct_engine_wait_request(e);
    uint64_t spent = duct_ticks_mono_ns() - began;
    pthread_join(thread, nullptr);
    duct_result_t stopped = duct_engine_stop(e);
    duct_engine_destroy(e);
    if (rc != rc_ok)
        return "a wait for the request did not answer rc_ok";
    if (spent < early_ns)
        return "a wait for the request returned before anything asked for a stop";
    return stopped == rc_ok ? nullptr : "a stop after a request did not answer rc_ok";
}

/** @brief Request twice, then wait twice.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_level(void)
{
    auto e = launch();
    if (!e)
        return "engine launch failed";
    duct_result_t first = duct_engine_request_stop(e);
    duct_result_t again = duct_engine_request_stop(e);
    duct_result_t waited = duct_engine_wait_request(e);
    duct_result_t waited_again = duct_engine_wait_request(e);
    duct_engine_destroy(e);
    if (first != rc_ok || again != rc_ok)
        return "a request did not answer rc_ok";
    return waited == rc_ok && waited_again == rc_ok ? nullptr
         : "a request made before the wait did not end it, or did not stay";
}

/** @brief Request in one run, destroy, and wait in the next.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_fresh(void)
{
    auto e = launch();
    if (!e)
        return "engine launch failed";
    duct_discard duct_engine_request_stop(e);
    duct_engine_destroy(e);

    e = launch();
    if (!e)
        return "engine launch failed";
    pthread_t thread;
    if (pthread_create(&thread, nullptr, request_later_job, e) != 0) {
        duct_engine_destroy(e);
        return "the requesting thread did not start";
    }
    uint64_t began = duct_ticks_mono_ns();
    duct_discard duct_engine_wait_request(e);
    uint64_t spent = duct_ticks_mono_ns() - began;
    pthread_join(thread, nullptr);
    duct_engine_destroy(e);
    return spent < early_ns ? "a request of an earlier run ended the wait of the next" : nullptr;
}

/** @brief Request, then run @c duct_engine_wait and stop again.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_wait_stops(void)
{
    auto e = launch();
    if (!e)
        return "engine launch failed";
    duct_discard duct_engine_request_stop(e);
    duct_result_t waited = duct_engine_wait(e);
    duct_result_t stopped = duct_engine_stop(e);
    duct_engine_destroy(e);
    if (waited != rc_ok)
        return "a wait after a request did not answer rc_ok";
    return stopped == rc_ok ? nullptr : "a second stop did not answer rc_ok";
}

/** @brief Stop the engine under a thread that waits for the request.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_stop_wakes(void)
{
    auto e = launch();
    if (!e)
        return "engine launch failed";
    waiter_t waiter = { .engine = e, .rc = rc_invalid_arg };
    pthread_t thread;
    if (pthread_create(&thread, nullptr, wait_request_job, &waiter) != 0) {
        duct_engine_destroy(e);
        return "the waiting thread did not start";
    }
    th_sleep_ms(delay_ms);
    bool early = duct_atomic_load(&waiter.returned, acquire) != 0u;
    duct_result_t stopped = duct_engine_stop(e);
    pthread_join(thread, nullptr);
    duct_engine_destroy(e);
    if (early)
        return "a wait for the request returned before anything asked for a stop";
    if (stopped != rc_ok)
        return "a stop did not answer rc_ok";
    return waiter.rc == rc_ok ? nullptr : "a stop did not end a wait for the request";
}

/** @brief Destroy the engine under a thread that waits for the request.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_destroy_wakes(void)
{
    auto e = launch();
    if (!e)
        return "engine launch failed";
    waiter_t waiter = { .engine = e, .rc = rc_invalid_arg };
    pthread_t thread;
    if (pthread_create(&thread, nullptr, wait_request_job, &waiter) != 0) {
        duct_engine_destroy(e);
        return "the waiting thread did not start";
    }
    th_sleep_ms(delay_ms);
    bool early = duct_atomic_load(&waiter.returned, acquire) != 0u;
    duct_engine_destroy(e);
    pthread_join(thread, nullptr);
    if (early)
        return "a wait for the request returned before anything asked for a stop";
    return waiter.rc == rc_ok ? nullptr : "a destroy did not end a wait for the request";
}

/** @brief Call the three entries on no engine.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_null(void)
{
    if (duct_engine_request_stop(nullptr) != rc_invalid_arg)
        return "a request on no engine did not answer rc_invalid_arg";
    if (duct_engine_wait_request(nullptr) != rc_invalid_arg)
        return "a wait on no engine did not answer rc_invalid_arg";
    if (duct_engine_stop_on_signals(nullptr) != rc_invalid_arg)
        return "stop on signals for no engine did not answer rc_invalid_arg";
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    static const struct { const char *name; const char *(*fn)(void); } cases[] = {
        { "request",       sc_request },
        { "level",         sc_level },
        { "fresh",         sc_fresh },
        { "wait_stops",    sc_wait_stops },
        { "stop_wakes",    sc_stop_wakes },
        { "destroy_wakes", sc_destroy_wakes },
        { "null",          sc_null },
    };
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        auto err = cases[i].fn();
        if (err) {
            fprintf(stderr, "engine_stop: %s: %s\n", cases[i].name, err);
            return 1;
        }
    }
    printf("engine_stop: OK\n");
    return 0;
}
