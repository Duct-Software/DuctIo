/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, authors: Constantin Papizh, Dmitriy Puzyrkov, Olzhas Zharasbayev */

#include "duct_core.h"
#include "duct_xport.h"

#include <errno.h>
#include <limits.h>
#include <os/os_sync_wait_on_address.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

size_t pg_size = 4096u;
unsigned cpu_count = 1u;

duct_result_t duct_x_vnet_offload([[maybe_unused]] int fd) { return rc_not_supported; }

bool duct_x_has_gso(void) { return false; }
size_t duct_x_vnet_hdr_len([[maybe_unused]] int fd) { return 0u; }

static void duct_ctor(void) __attribute__((constructor));
static void duct_ctor(void)
{
    long n = sysconf(_SC_PAGESIZE);
    pg_size = n > 0 ? (size_t)n : 4096u;
    n = sysconf(_SC_NPROCESSORS_ONLN);
    cpu_count = n > 0 ? (unsigned)n : 1u;
    /* A full engine needs duct_runtime_max_fds descriptors, more than the usual soft
     * default of 256: the soft limit goes up to its ceiling first, and a limit still
     * short of that stops the process here, ahead of main. setrlimit answers EINVAL to a
     * soft limit of RLIM_INFINITY, the usual hard value here, and its manual prescribes
     * OPEN_MAX as the ceiling. */
    struct rlimit fds;
    if (getrlimit(RLIMIT_NOFILE, &fds) == 0) {
        rlim_t ceiling = duct_min(fds.rlim_max, (rlim_t)OPEN_MAX),
               limit = fds.rlim_cur;
        if (limit < ceiling
            && setrlimit(RLIMIT_NOFILE, &(struct rlimit){ ceiling, fds.rlim_max }) == 0)
            limit = ceiling;
        if (limit < duct_runtime_max_fds)
            duct_diag("descriptor limit %llu is under the %u a full engine holds",
                      (unsigned long long)limit, duct_runtime_max_fds);
        duct_fatal(limit < duct_runtime_max_fds);
    }
}

/** @brief Map @p size bytes, rounded up to the page size, with protection @p prot.
 *  @return Zeroed handle on failure.
 */
static duct_vm_handle_t s_vm_map(size_t size, int prot)
{
    duct_do_if(size == 0, return (duct_vm_handle_t){});
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    duct_do_if(!page, return (duct_vm_handle_t){});
    size_t aligned = duct_align_up(size, page);
    duct_do_if(!aligned, return (duct_vm_handle_t){});
    void *base = mmap(nullptr, aligned, prot, MAP_PRIVATE | MAP_ANON, -1, 0);
    return base == MAP_FAILED ? (duct_vm_handle_t){}
                              : (duct_vm_handle_t){ .base = base, .size = aligned };
}

duct_vm_handle_t duct_vm_new(size_t size)
{
    return s_vm_map(size, PROT_READ | PROT_WRITE);
}

duct_vm_handle_t duct_vm_reserve(size_t size)
{
    return s_vm_map(size, PROT_NONE);
}

/* mprotect read-write and mlock, then MADV_ZERO_WIRED_PAGES, whose answer is not read. A failure of
 * the first two unlocks the range and makes it inaccessible again. */
duct_result_t duct_vm_lock(void *base, size_t size)
{
    if (mprotect(base, size, PROT_READ | PROT_WRITE) == 0 && mlock(base, size) == 0) {
        duct_discard madvise(base, size, MADV_ZERO_WIRED_PAGES);
        return rc_ok;
    }
    duct_discard munlock(base, size);
    duct_discard mprotect(base, size, PROT_NONE);
    return rc_no_memory;
}

void duct_vm_del(duct_vm_handle_t *h)
{
    duct_do_if(!h->base || !h->size, return);
    munmap(h->base, h->size);
    *h = (duct_vm_handle_t){};
}

/* MADV_FREE_REUSABLE takes the pages out of the footprint at once. A page written
 * again keeps its data and counts once the pageout scan finds it in use, so no
 * MADV_FREE_REUSE precedes the reuse. */
void duct_vm_discard(void *base, size_t size)
{
    if (size)
        duct_discard madvise(base, size, MADV_FREE_REUSABLE);
}

int duct_thread_bind_cpu([[maybe_unused]] unsigned cpu_index)
{
    return -1; /* Darwin's affinity tags are advisory; pinning defaults off. */
}

void duct_thread_set_name(const char *name)
{
    duct_discard pthread_setname_np(name);
}

bool duct_futex_wait(void *addr, uint32_t expected, uint32_t timeout_ms)
{
    for (;;) {
        int rc = timeout_ms == DUCT_TIMEOUT_INFINITE
            ? os_sync_wait_on_address(addr, expected, sizeof expected,
                                      OS_SYNC_WAIT_ON_ADDRESS_NONE)
            : os_sync_wait_on_address_with_timeout(addr, expected, sizeof expected,
                                                   OS_SYNC_WAIT_ON_ADDRESS_NONE,
                                                   OS_CLOCK_MACH_ABSOLUTE_TIME,
                                                   (uint64_t)timeout_ms * 1000000ull);
        if (rc >= 0)
            return true;
        if (errno != EINTR && errno != EFAULT)
            return false;
        /* os_sync can fail copyin transiently. Re-read before
         * retrying so a publication does not leave the waiter parked. */
        if (atomic_load_explicit((uint32_t _Atomic *)addr, memory_order_acquire) != expected)
            return true;
    }
}

void duct_futex_wake(void *addr, uint32_t count)
{
    if (count == duct_futex_wake_all) {
        duct_discard os_sync_wake_by_address_all(addr, sizeof(uint32_t),
                                                OS_SYNC_WAKE_BY_ADDRESS_NONE);
        return;
    }
    for (uint32_t i = 0u; i < count; ++i)
        if (os_sync_wake_by_address_any(addr, sizeof(uint32_t), OS_SYNC_WAKE_BY_ADDRESS_NONE) < 0)
            return;
}

/* One list serves duct_thread_block_stop_signals and the stop hook, so a
 * signal the hook handles is one the engine's threads block. */
static const int s_stop_signals[] = { SIGINT, SIGTERM, SIGHUP };

static constexpr unsigned s_stop_count = sizeof s_stop_signals / sizeof *s_stop_signals;

static struct sigaction s_stop_previous[s_stop_count];

void duct_thread_block_stop_signals(void)
{
    sigset_t stop;
    sigemptyset(&stop);
    for (unsigned i = 0u; i < s_stop_count; ++i)
        sigaddset(&stop, s_stop_signals[i]);
    duct_discard pthread_sigmask(SIG_BLOCK, &stop, nullptr);
}

static void s_on_stop_signal([[maybe_unused]] int signo)
{
    int saved = errno;
    duct_on_stop_signal();
    errno = saved;
}

void duct_stop_hook_arm(void)
{
    struct sigaction act = { .sa_handler = s_on_stop_signal, .sa_flags = SA_RESTART };
    sigemptyset(&act.sa_mask);
    for (unsigned i = 0u; i < s_stop_count; ++i)
        duct_discard sigaction(s_stop_signals[i], &act, &s_stop_previous[i]);
}

void duct_stop_hook_disarm(void)
{
    for (unsigned i = 0u; i < s_stop_count; ++i)
        duct_discard sigaction(s_stop_signals[i], &s_stop_previous[i], nullptr);
}

/** @brief Convert @p tv to nanoseconds. */
static uint64_t s_timeval_ns(struct timeval tv)
{
    return (uint64_t)tv.tv_sec * 1000000000ull + (uint64_t)tv.tv_usec * 1000u;
}

duct_cpu_time_t duct_process_cpu(void)
{
    struct rusage ru = {};
    duct_discard getrusage(RUSAGE_SELF, &ru);
    return (duct_cpu_time_t){ .user_ns = s_timeval_ns(ru.ru_utime), .kernel_ns = s_timeval_ns(ru.ru_stime) };
}
