/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file stop_signals_test.c
 *  @brief The stop signals as a stop request, and the handlers they replace.
 *
 *  @c sc_signals expects each of SIGINT, SIGTERM and SIGHUP, sent to the process
 *  while the calling thread blocks the three, to end the wait for the request that
 *  the calling thread sleeps in. @c sc_blocked expects the same of a signal sent to
 *  the sleeping thread itself; it is left out under ThreadSanitizer, which defers
 *  the handler of a thread asleep in a futex wait to its next intercepted call.
 *  @c sc_restore expects destroying an engine armed twice to put back the handlers
 *  of SIGINT and SIGTERM and the ignoring of SIGHUP. @c sc_untouched expects an
 *  engine launched without the call to leave the handlers as they were.
 */

#include "duct.h"
#include "test_helpers.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#if defined(__SANITIZE_THREAD__)
#define DUCT_TEST_THREAD_SANITIZER 1
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define DUCT_TEST_THREAD_SANITIZER 1
#endif
#endif

/** @brief Delay of the signalling thread, milliseconds. */
static constexpr unsigned delay_ms = 20u;

/** @brief The signals the stop hook handles. */
static const int s_stop_signals[] = { SIGINT, SIGTERM, SIGHUP };

static constexpr unsigned stop_count = sizeof s_stop_signals / sizeof *s_stop_signals;

/** @brief Signals @c s_count has taken. */
static volatile sig_atomic_t s_hits;

/** @brief Handler the scenarios install ahead of an engine: count a hit. */
static void s_count([[maybe_unused]] int signo)
{
    ++s_hits;
}

/** @brief Launch an engine of one io thread and one worker. */
static duct_engine_t *launch(void)
{
    return duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1u, .workers = 1u });
}

/** @brief Give the three stop signals their default handling. */
static void default_dispositions(void)
{
    struct sigaction fallback = { .sa_handler = SIG_DFL };
    sigemptyset(&fallback.sa_mask);
    for (unsigned i = 0u; i < stop_count; ++i)
        sigaction(s_stop_signals[i], &fallback, nullptr);
}

/** @brief What the signalling thread sends, and to whom. */
typedef struct {
    int       signo;
    pthread_t target;    /**< The thread a signal goes to when @c to_thread is set. */
    bool      to_thread;
} signal_job_t;

/** @brief Thread body: send the signal after the delay, to the process or to @c target. */
static void *signal_later_job(void *arg)
{
    auto job = (const signal_job_t *)arg;
    th_sleep_ms(delay_ms);
    if (job->to_thread)
        pthread_kill(job->target, job->signo);
    else
        kill(getpid(), job->signo);
    return nullptr;
}

/** @brief Arm an engine, send @p signo and wait for the request.
 *  A signal sent to the process is taken by the signalling thread, the calling
 *  thread blocking it; with @p to_thread it is sent to the calling thread.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *run_signal(int signo, bool to_thread)
{
    auto e = launch();
    if (!e)
        return "engine launch failed";
    if (duct_engine_stop_on_signals(e) != rc_ok) {
        duct_engine_destroy(e);
        return "stop on signals did not answer rc_ok";
    }
    signal_job_t job = { .signo = signo, .target = pthread_self(), .to_thread = to_thread };
    pthread_t thread;
    if (pthread_create(&thread, nullptr, signal_later_job, &job) != 0) {
        duct_engine_destroy(e);
        return "the signalling thread did not start";
    }
    sigset_t stop, before;
    sigemptyset(&stop);
    for (unsigned i = 0u; i < stop_count; ++i)
        sigaddset(&stop, s_stop_signals[i]);
    if (!to_thread)
        pthread_sigmask(SIG_BLOCK, &stop, &before);
    duct_result_t rc = duct_engine_wait_request(e);
    pthread_join(thread, nullptr);
    if (!to_thread)
        pthread_sigmask(SIG_SETMASK, &before, nullptr);
    duct_result_t stopped = duct_engine_stop(e);
    duct_engine_destroy(e);
    if (rc != rc_ok)
        return "a stop signal did not end the wait for the request";
    return stopped == rc_ok ? nullptr : "a stop after a signal did not answer rc_ok";
}

/** @brief Each stop signal sent to the process while the calling thread blocks it.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_signals(void)
{
    for (unsigned i = 0u; i < stop_count; ++i) {
        auto err = run_signal(s_stop_signals[i], false);
        if (err)
            return err;
    }
    return nullptr;
}

#ifndef DUCT_TEST_THREAD_SANITIZER
/** @brief Each stop signal sent to the calling thread while it waits.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_blocked(void)
{
    for (unsigned i = 0u; i < stop_count; ++i) {
        auto err = run_signal(s_stop_signals[i], true);
        if (err)
            return err;
    }
    return nullptr;
}
#endif

/** @brief Arm an engine twice, destroy it and read the handlers back.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_restore(void)
{
    struct sigaction count = { .sa_handler = s_count },
                     ignore = { .sa_handler = SIG_IGN },
                     now;
    sigemptyset(&count.sa_mask);
    sigemptyset(&ignore.sa_mask);
    sigaction(SIGINT, &count, nullptr);
    sigaction(SIGTERM, &count, nullptr);
    sigaction(SIGHUP, &ignore, nullptr);

    auto e = launch();
    if (!e)
        return "engine launch failed";
    bool armed = duct_engine_stop_on_signals(e) == rc_ok
              && duct_engine_stop_on_signals(e) == rc_ok;
    sigaction(SIGINT, nullptr, &now);
    bool replaced = now.sa_handler != s_count;
    duct_engine_destroy(e);

    const char *err = nullptr;
    if (!armed)
        err = "stop on signals did not answer rc_ok";
    else if (!replaced)
        err = "stop on signals left the handler of SIGINT as it was";
    sigaction(SIGINT, nullptr, &now);
    if (!err && now.sa_handler != s_count)
        err = "destroying the engine did not restore the handler of SIGINT";
    sigaction(SIGTERM, nullptr, &now);
    if (!err && now.sa_handler != s_count)
        err = "destroying the engine did not restore the handler of SIGTERM";
    sigaction(SIGHUP, nullptr, &now);
    if (!err && now.sa_handler != SIG_IGN)
        err = "destroying the engine did not restore the ignoring of SIGHUP";
    s_hits = 0;
    raise(SIGINT);
    raise(SIGTERM);
    raise(SIGHUP);
    if (!err && s_hits != 2)
        err = "a signal after the destroy did not reach the handler the engine replaced";
    default_dispositions();
    return err;
}

/** @brief Launch without arming and read the handlers.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_untouched(void)
{
    struct sigaction count = { .sa_handler = s_count }, now;
    sigemptyset(&count.sa_mask);
    for (unsigned i = 0u; i < stop_count; ++i)
        sigaction(s_stop_signals[i], &count, nullptr);

    auto e = launch();
    if (!e)
        return "engine launch failed";
    const char *err = nullptr;
    for (unsigned i = 0u; i < stop_count && !err; ++i) {
        sigaction(s_stop_signals[i], nullptr, &now);
        if (now.sa_handler != s_count)
            err = "an engine launched without stop on signals replaced a handler";
    }
    s_hits = 0;
    raise(SIGTERM);
    duct_engine_destroy(e);
    if (!err && s_hits != 1)
        err = "a signal did not reach the handler of an engine launched without stop on signals";
    default_dispositions();
    return err;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    static const struct { const char *name; const char *(*fn)(void); } cases[] = {
        { "signals",   sc_signals },
#ifndef DUCT_TEST_THREAD_SANITIZER
        { "blocked",   sc_blocked },
#endif
        { "restore",   sc_restore },
        { "untouched", sc_untouched },
    };
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        auto err = cases[i].fn();
        if (err) {
            fprintf(stderr, "stop_signals: %s: %s\n", cases[i].name, err);
            return 1;
        }
    }
    printf("stop_signals: OK\n");
    return 0;
}
