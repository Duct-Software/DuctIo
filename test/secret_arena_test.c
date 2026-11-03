/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file secret_arena_test.c
 *  @brief The slots of the secret arena behind duct_new_secret.
 *
 *  @c t_classes expects a secret of each size to take the class its header and object need, one
 *  past 4088 bytes and one aligned past 8 to take the heap, and each object to sit on 8, zeroed.
 *  @c t_reuse expects a released slot to be the next its class hands out, zeroed again.
 *  @c t_threads expects eight threads making and releasing secrets of every class to find each
 *  slot zeroed, to keep their own pattern in it, and never to share one. @c t_smaps, on Linux,
 *  expects the page of a slot to read locked and out of core files. The argument @c nolock
 *  drops RLIMIT_MEMLOCK to zero first and expects every secret to still come, from the heap
 *  where the system refuses the lock. A build with AddressSanitizer takes the heap for every
 *  secret, and the classes it expects are 0.
 */

#include "duct_core.h"

#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>

#ifdef __linux__
#include <sys/mman.h>
#include <sys/resource.h>
#endif

#define CHECK(expr, msg) \
    do { if (!(expr)) { fprintf(stderr, "FAIL: %s\n", msg); return 1; } } while (0)

#ifdef __SANITIZE_ADDRESS__
static constexpr bool sanitized = true;
#else
static constexpr bool sanitized = false;
#endif

static duct_alloc_hdr_t *s_hdr(const void *p)
{
    return (duct_alloc_hdr_t *)((uintptr_t)p - sizeof(duct_alloc_hdr_t));
}

static bool s_all(const uint8_t *p, size_t n, uint8_t value)
{
    for (size_t i = 0u; i < n; ++i)
        if (p[i] != value)
            return false;
    return true;
}

static const struct { size_t bytes; unsigned arena; } rows[] = {
    { 1u, 1u }, { 32u, 1u }, { 56u, 1u }, { 57u, 2u }, { 120u, 2u }, { 121u, 3u }, { 248u, 3u },
    { 249u, 4u }, { 504u, 4u }, { 505u, 5u }, { 1016u, 5u }, { 1017u, 6u }, { 2040u, 6u },
    { 2041u, 7u }, { 4088u, 7u }, { 4089u, 0u }, { 10000u, 0u },
};
static constexpr size_t row_count = sizeof rows / sizeof rows[0];

static int t_classes(void)
{
    for (size_t i = 0u; i < row_count; ++i) {
        auto p = duct_new_secret(uint8_t, rows[i].bytes);
        unsigned want = sanitized ? 0u : rows[i].arena;
        CHECK(p && s_hdr(p)->secret && s_hdr(p)->arena == want, "a secret takes the class its size needs");
        CHECK(((uintptr_t)p & 7u) == 0u && duct_len(p) == rows[i].bytes, "the object sits on 8 and keeps its count");
        CHECK(s_all(duct_at(p), rows[i].bytes, 0u), "a secret comes zeroed");
        memset(duct_at(p), 0xa5, rows[i].bytes);
        duct_del(p);
        CHECK(!p, "a release nulls the pointer");
    }
    auto wide = duct_new_secret(uint8_t, 32, 16);
    CHECK(wide && s_hdr(wide)->secret && s_hdr(wide)->arena == 0u && ((uintptr_t)wide & 15u) == 0u,
          "an alignment past 8 takes the heap");
    duct_del(wide);
    auto narrow = duct_new_secret(uint8_t, 32, 8);
    CHECK(narrow && s_hdr(narrow)->arena == (sanitized ? 0u : 1u), "an alignment of 8 takes the arena");
    duct_del(narrow);
    return 0;
}

static int t_reuse(void)
{
    auto first = duct_new_secret(uint8_t, 100);
    CHECK(first, "a secret comes");
    auto at = duct_at(first);
    memset(at, 0x5a, 100u);
    duct_del(first);
    auto second = duct_new_secret(uint8_t, 100);
    CHECK(second && (sanitized || duct_at(second) == at), "a released slot is the next its class hands out");
    CHECK(s_all(duct_at(second), 100u, 0u), "and it comes back zeroed");
    duct_del(second);
    return 0;
}

static constexpr unsigned threads = 8u;
static constexpr unsigned rounds = 25000u;
static atomic_uint s_bad;

static void *s_worker(void *arg)
{
    auto id = (unsigned)(uintptr_t)arg;
    auto pattern = (uint8_t)(id + 1u);
    unsigned seed = id * 2654435761u + 1u;
    for (unsigned i = 0u; i < rounds; ++i) {
        seed = seed * 1103515245u + 12345u;
        size_t n = rows[(seed >> 16) % row_count].bytes;
        auto p = duct_new_secret(uint8_t, n);
        if (!p || !s_all(duct_at(p), n, 0u)) {
            atomic_fetch_add(&s_bad, 1u);
            return nullptr;
        }
        memset(duct_at(p), pattern, n);
        if (seed >> 8 & 1u)
            sched_yield();
        if (!s_all(duct_at(p), n, pattern))
            atomic_fetch_add(&s_bad, 1u);
        duct_del(p);
    }
    return nullptr;
}

static int t_threads(void)
{
    pthread_t pool[threads];
    for (unsigned i = 0u; i < threads; ++i)
        CHECK(pthread_create(&pool[i], nullptr, s_worker, (void *)(uintptr_t)i) == 0, "a thread starts");
    for (unsigned i = 0u; i < threads; ++i)
        pthread_join(pool[i], nullptr);
    CHECK(atomic_load(&s_bad) == 0u, "each slot came zeroed, kept its pattern and was held by one thread");
    return 0;
}

#ifdef __linux__
/* The ThreadSanitizer runtime answers mlock with success and locks nothing. */
#ifdef __SANITIZE_THREAD__
static constexpr bool lock_is_real = false;
#else
static constexpr bool lock_is_real = true;
#endif

static int t_smaps(void)
{
    if (sanitized || !lock_is_real)
        return 0;
    auto p = duct_new_secret(uint8_t, 100);
    CHECK(p && s_hdr(p)->arena != 0u, "a secret comes from the arena");
    auto at = (uintptr_t)duct_at(p);
    FILE *file = fopen("/proc/self/smaps", "r");
    CHECK(file, "smaps opens");
    char line[512];
    bool inside = false,
         locked = false,
         dumpless = false;
    while (fgets(line, sizeof line, file)) {
        unsigned long lo, hi;
        if (sscanf(line, "%lx-%lx ", &lo, &hi) == 2)
            inside = at >= lo && at < hi;
        else if (inside && strncmp(line, "Locked:", 7) == 0)
            locked = strtoul(line + 7, nullptr, 10) > 0u;
        else if (inside && strncmp(line, "VmFlags:", 8) == 0)
            dumpless = strstr(line, " lo") && strstr(line, " dd");
    }
    fclose(file);
    duct_del(p);
    CHECK(locked, "the page of a slot reads Locked");
    CHECK(dumpless, "the page of a slot is flagged lo and dd");
    return 0;
}

static int t_nolock(void)
{
    struct rlimit none = { 0, 0 };
    CHECK(setrlimit(RLIMIT_MEMLOCK, &none) == 0, "the lock limit drops to zero");
    void *page = mmap(nullptr, 4096u, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(page != MAP_FAILED, "a probe page maps");
    bool refused = mlock(page, 4096u) != 0;
    munmap(page, 4096u);
    for (size_t i = 0u; i < row_count; ++i) {
        auto p = duct_new_secret(uint8_t, rows[i].bytes);
        CHECK(p && s_all(duct_at(p), rows[i].bytes, 0u), "a secret still comes, zeroed");
        CHECK(!(refused || sanitized) || s_hdr(p)->arena == 0u, "a refused lock sends a secret to the heap");
        memset(duct_at(p), 0xa5, rows[i].bytes);
        duct_del(p);
    }
    return 0;
}
#endif

int main([[maybe_unused]] int argc, [[maybe_unused]] char **argv)
{
#ifdef __linux__
    if (argc > 1 && strcmp(argv[1], "nolock") == 0) {
        if (t_nolock())
            return 1;
        printf("secret_arena: OK (no lock)\n");
        return 0;
    }
#endif
    static int (*const tests[])(void) = {
        t_classes, t_reuse, t_threads,
#ifdef __linux__
        t_smaps,
#endif
    };
    for (size_t i = 0u; i < sizeof tests / sizeof tests[0]; ++i)
        if (tests[i]())
            return 1;
    printf("secret_arena: OK\n");
    return 0;
}
