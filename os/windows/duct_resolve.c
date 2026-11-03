/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_resolve.c
 *  @brief Windows async DNS — overlapped @c GetAddrInfoExW, shared by both
 *  Windows backends. The completion routine runs on a system thread-pool
 *  thread and delivers through the thread-safe @c duct_io_post_connect*
 *  family; sole caller is the portable connect dispatch.
 *
 *  @c GetAddrInfoExW is the only family member that supports overlapped
 *  completion — the ANSI variant fails @c WSAEINVAL. It may also complete
 *  synchronously — @c NO_ERROR with no routine invocation; @ref
 *  duct_resolve_start then runs the same tail inline.
 *
 *  In-flight resolves live in a fixed slot table @c s_jobs, one @c duct_new
 *  block made at load, behind a Treiber free-list; a per-slot generation
 *  packed into @c state_gen lets
 *  @ref duct_resolve_cancel_all walk the table lock-free against concurrent
 *  acquire/release from io and thread-pool threads.
 */

#include "duct_core.h"
#include "duct_relay.h"
#include "duct_timer.h"
#include "duct_treiber.h"

#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wchar.h>

/* Cancel an in-flight GetAddrInfoExW resolve. Declared here because MinGW-w64
 * omits the prototype; the symbol is exported by libws2_32. */
WINSOCK_API_LINKAGE INT WSAAPI GetAddrInfoExCancel(LPHANDLE lpHandle);

/** @brief Longest wait for the completions after the cancels, milliseconds.
 *  Past it @ref duct_resolve_cancel_all returns with completions still owed. */
static constexpr uint32_t resolve_shutdown_bound_ms = 10'000u;

/** Max in-flight resolves. Defaults to @c duct_runtime_max_conns —
 *  worst case is every conn redialing at once during degraded, slow DNS.
 */
#ifndef DUCT_RESOLVE_MAX_JOBS
#define DUCT_RESOLVE_MAX_JOBS duct_runtime_max_conns
#endif

typedef enum : uint32_t {
    resolve_slot_free,
    resolve_slot_active
} resolve_slot_state_t;

/** @name Generation + state
 *  State in bit 0, generation in [1:63]
 *  @{
 */
static constexpr uint32_t resolve_state_bits = 1u;
static constexpr uint64_t resolve_state_mask = (1ull << resolve_state_bits) - 1;

#define resolve_slot_pack(gen, state) \
    (((uint64_t)(gen) << resolve_state_bits) | (uint64_t)(state))

#define resolve_slot_state(word) \
    ((resolve_slot_state_t)((word) & resolve_state_mask))

#define resolve_slot_gen(word) ((uint32_t)((word) >> resolve_state_bits))
/** @} */

/** @brief One resolve slot. @c ov must stay the first member — the
 *  completion routine's @c lpOverlapped is the slot's address.
 *  @c state_gen is the only field read outside the owning thread on
 *  shutdown walk; every other field is touched only by the current
 *  owner: acquirer until release, then one releasing completion.
 */
typedef struct {
    OVERLAPPED           ov;
    uint32_t _Atomic     next_free;
    uint64_t _Atomic     state_gen;
    wchar_t              hostw[256];
    wchar_t              portw[6];
    ADDRINFOEXW         *result;   /**< Written by the OS; freed via FreeAddrInfoExW. */
    HANDLE               cancel;   /**< GetAddrInfoExCancel handle. */
    unsigned             io_id;
    uint32_t             connect_timeout_ms;
    duct_conn_intent_t   seed;
} resolve_job_t;

/** @name Pop/push/seed over @c s_jobs[]::next_free.
 *  @{
 */
DUCT_TREIBER_DECLARE(s_job_stack, resolve_job_t, next_free)
/** @} */

/** @brief Slot table of in-flight resolves, @c DUCT_RESOLVE_MAX_JOBS slots. */
static duct_ptr_t(resolve_job_t) s_jobs;
static uint64_t _Atomic s_free_head;
static uint32_t _Atomic s_jobs_inflight; /**< Futex target for duct_resolve_cancel_all's drain. */

/** @brief Make the slot table and seed its free list.
 *  A table that cannot be made aborts the process: every resolve takes a slot of it.
 */
static void s_jobs_ctor(void) __attribute__((constructor(DUCT_CTOR_PRI_STATE)));
static void s_jobs_ctor(void)
{
    s_jobs = duct_new(resolve_job_t, DUCT_RESOLVE_MAX_JOBS);
    duct_fatal(!s_jobs);
    auto jobs = duct_at(s_jobs);
    /* Seed in reverse so pop yields idx 0 first — a bare 0|0 head
     * self-loops on slot 0. */
    s_job_stack_seed(&s_free_head, jobs, (uint32_t)duct_len(s_jobs));
    for (unsigned i = 0u; i < duct_len(s_jobs); ++i)
        atomic_init(&jobs[i].state_gen, resolve_slot_pack(0u, resolve_slot_free));
    atomic_init(&s_jobs_inflight, 0u);
}

/** @brief Free the slot table at process exit, unless a resolve completion is still owed.
 *  A completion runs on a system thread-pool thread and writes its slot, and
 *  @ref duct_resolve_cancel_all stops waiting for it after a bounded time; the table of a
 *  completion still owed stays for the process to reclaim.
 */
static void s_jobs_dtor(void) __attribute__((destructor(DUCT_CTOR_PRI_STATE)));
static void s_jobs_dtor(void)
{
    if (!duct_atomic_load(&s_jobs_inflight, acquire))
        duct_del(s_jobs);
}

/** @brief Pop a free slot and mark it active under
 *  a fresh generation.
 *  @return @c nullptr once all slots are in flight.
 */
static resolve_job_t *s_job_acquire(void)
{
    auto jobs = duct_at(s_jobs);
    uint32_t top = s_job_stack_pop(&s_free_head, jobs);
    duct_do_if(top == treiber_empty, return nullptr);
    auto job = &jobs[top];
    uint32_t gen = resolve_slot_gen(duct_atomic_load(&job->state_gen, relaxed)) + 1u;
    duct_atomic_store(&job->state_gen,
                      resolve_slot_pack(!gen ? 1u : gen, resolve_slot_active), release);
    return job;
}

/** @brief Release @p job back to free stack.
 *  Called by completion owning the slot teardown, once per acquire.
 */
static void s_job_release(resolve_job_t *job)
{
    uint32_t gen = resolve_slot_gen(duct_atomic_load(&job->state_gen, relaxed));
    duct_atomic_store(&job->state_gen, resolve_slot_pack(gen, resolve_slot_free), release);
    auto jobs = duct_at(s_jobs);
    s_job_stack_push(&s_free_head, jobs, (uint32_t)(job - jobs));
}

/** @brief Fill @p out from an @c ADDRINFOEXW result. */
static bool s_peer_from_addrinfoexw(const ADDRINFOEXW *ai, duct_peer_t *out)
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

/** @brief Drop one from the inflight count.
 *  At 0 this wakes a bounded @ref duct_resolve_cancel_all waiter.
 */
static void s_jobs_inflight_release(void)
{
    if (duct_atomic_fetch(sub, &s_jobs_inflight, 1u, release) == 1u)
        duct_futex_wake(&s_jobs_inflight, duct_futex_wake_all);
}

/** @brief @c GetAddrInfoExW completion routine.
 *
 *  Also called inline by @ref duct_resolve_start on synchronous completion.
 */
static void CALLBACK s_resolve_done(DWORD err, [[maybe_unused]] DWORD bytes,
                                    LPWSAOVERLAPPED ov)
{
    auto job = (resolve_job_t *)ov;
    duct_peer_t peer = {};
    bool ok = err == 0 && job->result && s_peer_from_addrinfoexw(job->result, &peer);
    if (job->result)
        FreeAddrInfoExW(job->result);
    if (ok)
        duct_io_post_connect(job->io_id, &peer, &job->seed, job->connect_timeout_ms);
    else
        duct_io_post_connect_failed(job->io_id, &job->seed, rc_dns_fail);
    s_job_release(job);
    s_jobs_inflight_release();
}

duct_result_t duct_resolve_start(unsigned io_id, const char *host, uint16_t port,
                                 uint32_t connect_timeout_ms, const duct_conn_intent_t *seed)
{
    auto job = s_job_acquire();
    duct_do_if(!job, return rc_no_memory);
    /* host is pure ASCII — duct_connect_parse_addr rejects anything else */
    duct_discard MultiByteToWideChar(CP_UTF8, 0, host, -1, job->hostw,
                                     (int)(sizeof job->hostw / sizeof job->hostw[0]));
    duct_discard swprintf(job->portw, sizeof job->portw / sizeof job->portw[0], L"%u", (unsigned)port);
    job->seed = *seed;
    job->io_id = io_id;
    job->connect_timeout_ms = connect_timeout_ms;
    /* A reused slot still holds last episode's freed pointer, and
     * GetAddrInfoExW is not documented to write *ppResult on every
     * failure path — clear both. */
    job->result = nullptr;
    job->cancel = nullptr;

    ADDRINFOEXW hints = { .ai_family = AF_UNSPEC,
                          .ai_socktype = seed->xport == x_udp_peer ? SOCK_DGRAM : SOCK_STREAM };

    duct_atomic_fetch(add, &s_jobs_inflight, 1u, relaxed);

    int rc = GetAddrInfoExW(job->hostw, job->portw, NS_ALL, nullptr, &hints,
                            &job->result, nullptr, &job->ov, s_resolve_done, &job->cancel);
    switch (rc) {
    case 0:
        s_resolve_done(0, 0, &job->ov); [[fallthrough]];
    case WSA_IO_PENDING:
        /* WSA_IO_PENDING arrives as the return value itself, not via
         * WSAGetLastError() — the latter is an undocumented side effect. */
        return rc_ok;
    default:
        s_job_release(job);
        s_jobs_inflight_release();
        return rc_dns_fail;
    }
}

/* Per active slot, a same-value CAS on state_gen proves the observed cancel
 * handle still belongs to the observed occupancy episode; a lost CAS means
 * either that episode ended or a new one began, so skip both. A completion
 * landing after a winning CAS only makes the target already-finished, and
 * cancel on a completed handle is fine. GetAddrInfoExCancel can block for a
 * legacy provider's whole lookup, so it is called with nothing held that the
 * completion routine needs. */
void duct_resolve_cancel_all(void)
{
    auto jobs = duct_at(s_jobs);
    for (unsigned i = 0u; i < duct_len(s_jobs); ++i) {
        auto job = &jobs[i];
        uint64_t word = duct_atomic_load(&job->state_gen, acquire);
        if (resolve_slot_state(word) != resolve_slot_active)
            continue;
        if (!duct_atomic_cas(strong, &job->state_gen, &word, word, acquire, relaxed))
            continue;
        GetAddrInfoExCancel(&job->cancel);
    }

    duct_drain_wait(&s_jobs_inflight, resolve_shutdown_bound_ms);
}
