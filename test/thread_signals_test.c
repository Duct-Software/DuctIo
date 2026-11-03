/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file thread_signals_test.c
 *  @brief The engine's threads leave SIGINT, SIGTERM and SIGHUP to the host.
 *
 *  Handlers for the three signals count their hits and those taken off the
 *  calling thread. With an engine launched while the signals are unblocked, the
 *  calling thread blocks them and sends itself each once. An engine thread that
 *  kept one unblocked takes it at once, so no handler may have run by then and
 *  all three must stay pending for the process. Unblocking them runs the three
 *  handlers on the calling thread alone.
 */

#include "duct.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static pthread_t s_main;
static volatile sig_atomic_t s_hits,
                             s_foreign;

/** @brief Count a hit, and a hit on a thread other than the calling one. */
static void s_handler([[maybe_unused]] int sig)
{
    ++s_hits;
    if (!pthread_equal(pthread_self(), s_main))
        ++s_foreign;
}

/** @brief Send the three stop signals to the process while the calling thread
 *  blocks them.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_stop_signals(void)
{
    static const int stop[] = { SIGINT, SIGTERM, SIGHUP };
    s_main = pthread_self();
    sigset_t all;
    sigemptyset(&all);
    for (unsigned i = 0u; i < sizeof stop / sizeof stop[0]; ++i) {
        struct sigaction act = { .sa_handler = s_handler };
        sigemptyset(&act.sa_mask);
        if (sigaction(stop[i], &act, nullptr) != 0)
            return "handler install failed";
        sigaddset(&all, stop[i]);
    }

    auto e = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1u, .workers = 1u });
    if (!e)
        return "engine launch failed";
    if (pthread_sigmask(SIG_BLOCK, &all, nullptr) != 0) {
        duct_engine_destroy(e);
        return "mask of the calling thread failed";
    }
    for (unsigned i = 0u; i < sizeof stop / sizeof stop[0]; ++i)
        if (kill(getpid(), stop[i]) != 0) {
            duct_engine_destroy(e);
            return "signal send failed";
        }
    nanosleep(&(struct timespec){ .tv_nsec = 100'000'000 }, nullptr);

    sigset_t pending;
    sigemptyset(&pending);
    sigpending(&pending);
    bool held = true;
    for (unsigned i = 0u; i < sizeof stop / sizeof stop[0]; ++i)
        held = held && sigismember(&pending, stop[i]) == 1;
    sig_atomic_t early = s_hits;
    duct_engine_stop(e);
    duct_engine_destroy(e);
    if (early != 0)
        return "an engine thread took a stop signal";
    if (!held)
        return "a stop signal is not left pending for the process";

    if (pthread_sigmask(SIG_UNBLOCK, &all, nullptr) != 0)
        return "unmask of the calling thread failed";
    if (s_hits != 3 || s_foreign != 0)
        return "the signals did not all reach the calling thread's handler";
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    const char *err = sc_stop_signals();
    if (err) {
        fprintf(stderr, "thread_signals: %s\n", err);
        return 1;
    }
    printf("thread_signals: OK (no engine thread takes SIGINT, SIGTERM or SIGHUP)\n");
    return 0;
}
