/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_resolve.c
 *  @brief DNS resolver of every platform but Windows: a detached, one-shot
 *  pthread per symbolic hostname runs blocking @c getaddrinfo. Sole caller is
 *  the portable connect dispatch, via @ref duct_resolve_start.
 *
 *  A lookup cannot be cancelled, so its thread can return after the engine that
 *  started it is gone. Every thread posts its result through a gate that
 *  @ref duct_resolve_cancel_all closes at teardown: a thread finding the gate
 *  closed since its job started drops the result and touches no engine state.
 */

#ifndef _WIN32

#include "duct_relay.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** @brief Fill @p out from the first @c addrinfo result.
 *  @return false only if neither @c AF_INET nor @c AF_INET6;
 */
static bool s_peer_from_addrinfo(const struct addrinfo *ai, duct_peer_t *out)
{
    switch (ai->ai_family) {
    case AF_INET6:
        auto a6 = (const struct sockaddr_in6 *)ai->ai_addr;
        *out = (duct_peer_t){ .family = AF_INET6, .port = ntohs(a6->sin6_port) };
        memcpy(out->addr.v6, &a6->sin6_addr, sizeof out->addr.v6);
        break;
    case AF_INET:
        auto a4 = (const struct sockaddr_in *)ai->ai_addr;
        *out = (duct_peer_t){ .family = AF_INET, .port = ntohs(a4->sin_port) };
        memcpy(out->addr.v4, &a4->sin_addr, sizeof out->addr.v4);
        break;
    default:
        return false;
    }
    return true;
}

/** @brief Job handed to the detached DNS resolver thread.
 *  The thread frees it before exiting — nothing joins this thread.
 */
typedef struct {
    char                 host[256];
    char                 port_buf[6];
    unsigned             io_id;
    uint32_t             connect_timeout_ms,
                         gate;               /**< Value of @c s_gate at the job's start.
                                               *  The job posts only while the gate
                                               *  still holds it. */
    duct_conn_intent_t  seed;
} dns_job_t;

/** @brief Gate the resolver threads post through, odd while open.
 *  Opening and closing each add one, so a value names one open stretch and no
 *  later stretch repeats it. */
static uint32_t _Atomic s_gate;

/** @brief Count of threads inside the post section.
 *  The futex word @ref duct_resolve_cancel_all waits on. */
static uint32_t _Atomic s_posters;

/** @brief Open the gate if it is closed.
 *  @return the odd value a job started now posts under. */
static uint32_t s_gate_open(void)
{
    uint32_t g = duct_atomic_load(&s_gate, relaxed);
    while (!(g & 1u) && !duct_atomic_cas(weak, &s_gate, &g, g + 1u, relaxed, relaxed))
        ;
    return g | 1u;
}

/** @brief Enter the post section if the gate still holds the value @p gate.
 *  The count rises ahead of the read of the gate, and @ref duct_resolve_cancel_all
 *  closes the gate ahead of its read of the count, all four sequentially
 *  consistent: either this thread reads the gate closed or cancel_all reads the
 *  count raised.
 *  @return false once the gate has closed since the job started. */
static bool s_post_enter(uint32_t gate)
{
    duct_atomic_fetch(add, &s_posters, 1u, seq_cst);
    if (duct_atomic_load(&s_gate, seq_cst) == gate)
        return true;
    if (duct_atomic_fetch(sub, &s_posters, 1u, seq_cst) == 1u)
        duct_futex_wake(&s_posters, duct_futex_wake_all);
    return false;
}

/** @brief Leave the post section.
 *  The last thread out of a closed gate wakes @ref duct_resolve_cancel_all. */
static void s_post_leave(void)
{
    if (duct_atomic_fetch(sub, &s_posters, 1u, seq_cst) == 1u
        && !(duct_atomic_load(&s_gate, seq_cst) & 1u))
        duct_futex_wake(&s_posters, duct_futex_wake_all);
}

/** @brief Resolve one job's host and post the result while the gate holds the
 *  job's value. */
static void *s_dns_resolve_thread(void *arg)
{
    duct_thread_block_stop_signals();
    duct_auto_del auto job = (dns_job_t *)arg;
    struct addrinfo *res = nullptr,
                    hints = { .ai_family = AF_UNSPEC,
                              .ai_socktype = job->seed.xport == x_udp_peer ? SOCK_DGRAM : SOCK_STREAM };
    duct_peer_t peer = {};
    bool ok = getaddrinfo(job->host, job->port_buf, &hints, &res) == 0
            && res && s_peer_from_addrinfo(res, &peer);
    if (res)
        freeaddrinfo(res);
    if (s_post_enter(job->gate)) {
        if (ok)
            duct_io_post_connect(job->io_id, &peer, &job->seed, job->connect_timeout_ms);
        else
            duct_io_post_connect_failed(job->io_id, &job->seed, rc_dns_fail);
        s_post_leave();
    }
    return nullptr;
}

duct_result_t duct_resolve_start(unsigned io_id, const char *host, uint16_t port,
                                 uint32_t connect_timeout_ms, const duct_conn_intent_t *seed)
{
    duct_auto_del auto job = duct_new(dns_job_t);
    duct_do_if(!job, return rc_no_memory);
    job->seed = *seed;
    size_t hlen = strlen(host) + 1u;
    memcpy(job->host, host, hlen);
    duct_discard snprintf(job->port_buf, sizeof job->port_buf, "%u", (unsigned)port);
    job->io_id = io_id;
    job->connect_timeout_ms = connect_timeout_ms;
    job->gate = s_gate_open();

    pthread_t th;
    int err = pthread_create(&th, nullptr, s_dns_resolve_thread, job);
    duct_do_if(err != 0, return rc_dns_fail);
    /* The thread owns the job from its creation and frees it on every path. */
    duct_discard duct_move(job);
    pthread_detach(th);
    return rc_ok;
}

/* The gate closes ahead of the wait, so a lookup returning from here on finds it
 * closed and drops its result. The wait covers the post section alone, never a
 * lookup: that section is an allocation, a lock-free push and a non-blocking
 * wake, so it ends on its own and takes no bound. */
void duct_resolve_cancel_all(void)
{
    uint32_t g = duct_atomic_load(&s_gate, relaxed);
    while ((g & 1u) && !duct_atomic_cas(weak, &s_gate, &g, g + 1u, seq_cst, relaxed))
        ;
    uint32_t n = 0u;
    while ((n = duct_atomic_load(&s_posters, seq_cst)) != 0u)
        duct_futex_wait(&s_posters, n, DUCT_TIMEOUT_INFINITE);
}

#endif
