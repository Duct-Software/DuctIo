/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

#include "duct_core.h"
#include "duct_dgram_out.h"
#include "duct_file.h"
#include "duct_xport.h"

#include <errno.h>
#include <linux/futex.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

size_t pg_size;
unsigned cpu_count;

static bool s_gso;

bool duct_x_has_gso(void)
{
    return s_gso;
}

/* A tap stays out: its packets open with an Ethernet header, and the cut and
 * the merge both read IP at offset 0. */
size_t duct_x_vnet_hdr_len(int fd)
{
    struct ifreq ifr = {};
    int sz = 0;
    if (ioctl(fd, TUNGETIFF, &ifr) != 0 || !(ifr.ifr_flags & IFF_TUN)
        || !(ifr.ifr_flags & IFF_VNET_HDR) || ioctl(fd, TUNGETVNETHDRSZ, &sz) != 0)
        return 0u;
    return (size_t)sz;
}

#ifndef TUN_F_USO4
/* Declared here when the build host's headers predate the flags: the values
 * are kernel UAPI, so a binary built against older headers still asks a newer
 * kernel for them. */
#define TUN_F_USO4 0x20
#define TUN_F_USO6 0x40
#endif

/* CSUM covers the partial checksum a NEEDS_CSUM record carries, TSO4 and TSO6
 * the TCP segmentation types of src/duct_vnet.c, TSO_ECN its ECN bit, USO4 and
 * USO6 its UDP type. The kernel takes the USO pair together or not at all, and
 * a request it refuses sets nothing: the request goes out with the pair and,
 * refused, again without it. A type added there needs its bits here. */
duct_result_t duct_x_vnet_offload(int fd)
{
    constexpr unsigned tcp = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_TSO_ECN;
    if (ioctl(fd, TUNSETOFFLOAD, tcp | TUN_F_USO4 | TUN_F_USO6) == 0)
        return rc_ok;
    if (ioctl(fd, TUNSETOFFLOAD, tcp) == 0)
        return rc_not_supported;
    duct_log_err(stderr, duct_sock_err, "duct: tun offload refused, reads stay single packets");
    return rc_fatal;
}

/** @brief Add every cpu of a sysfs list, "0-3,5" form, to @p out.
 *  False when the file is unreadable; @p out then keeps whatever it held.
 */
static bool s_read_cpu_list(const char *path, cpu_set_t *out)
{
    auto file = duct_file_open(path, duct_file_in);
    duct_do_if(!file, return false);
    char buf[256] = {};
    size_t len = 0u;
    auto rc = duct_file_read(file, buf, sizeof buf - 1u, &len);
    duct_file_close(file);
    duct_do_if(rc != rc_ok, return false);
    buf[len] = '\0';

    for (char *p = buf; *p; ) {
        char *end;
        unsigned long lo = strtoul(p, &end, 10);
        if (end == p)
            break;
        unsigned long hi = *end == '-' ? strtoul(end + 1, &end, 10) : lo;
        for (unsigned long c = lo; c <= hi && c < (unsigned long)CPU_SETSIZE; ++c)
            CPU_SET((int)c, out);
        p = *end == ',' ? end + 1 : end;
    }
    return true;
}

/** @brief Cpus this process may pin onto.
 *  Filled by duct_ctor's first call, before any bind narrows a thread's mask: a
 *  mask read after a bind describes that one thread alone. The set is non-empty
 *  whenever the snapshot succeeded, so emptiness marks it unfilled.
 */
static const cpu_set_t *s_pin_pool(void)
{
    static cpu_set_t pool;
    int n = CPU_COUNT(&pool);
    if (n != 0)
        return &pool;

    cpu_set_t aff;
    n = sched_getaffinity(0, sizeof aff, &aff);
    duct_do_if(n != 0, return &pool);

    cpu_set_t iso = {};
    duct_discard s_read_cpu_list("/sys/devices/system/cpu/isolated", &iso);
    CPU_AND(&pool, &iso, &aff);
    /* Inherited masks exclude isolcpus cores -- PID1 and every descendant get
     * the unisolated set -- so an empty intersection still leaves those cores
     * available, and the isolated set itself is the better pool. */
    if (CPU_COUNT(&pool) == 0)
        pool = CPU_COUNT(&iso) ? iso : aff;
    return &pool;
}

/** @brief Resolve pin slot @p slot to a logical cpu, one per physical core.
 *  Walks ascending; -1 once the walk runs out, which an empty pool does
 *  immediately.
 */
static int s_pin_cpu_at(unsigned slot)
{
    auto pool = s_pin_pool();
    cpu_set_t taken = {};
    unsigned n = 0u;
    for (unsigned cpu = 0u; cpu < (unsigned)CPU_SETSIZE; ++cpu) {
        if (!CPU_ISSET((int)cpu, pool) || CPU_ISSET((int)cpu, &taken))
            continue;
        /* Claiming the whole SMT group keeps two pinned roles off one core.
         * A sysfs view without the file, e.g. a minimal container, claims just
         * this cpu and degrades to every cpu being its own core. */
        char path[80];
        snprintf(path, sizeof path,
                 "/sys/devices/system/cpu/cpu%u/topology/thread_siblings_list", cpu);
        if (!s_read_cpu_list(path, &taken))
            CPU_SET((int)cpu, &taken);

        if (n++ == slot)
            return (int)cpu;
    }
    return -1;
}

/** @brief Settle @c s_gso on a throwaway UDP socket.
 *  A failed socket or a refused option leaves it false; the early exits end
 *  this function, clear of the rest of @c duct_ctor. */
static void s_probe_udp(void)
{
#ifdef UDP_SEGMENT
    /* Only a kernel carrying UDP GSO answers this option. */
    int probe = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    duct_do_if(probe < 0, return);
    int seg = 0;
    int rc = getsockopt(probe, SOL_UDP, UDP_SEGMENT, &seg, &(socklen_t){ sizeof seg });
    close(probe);
    duct_do_if(rc != 0, return);
    s_gso = true;
#endif
}

static void duct_ctor(void) __attribute__((constructor(DUCT_CTOR_PRI_CORE)));
static void duct_ctor(void)
{
    long n = sysconf(_SC_PAGESIZE);
    pg_size = (n > 0) ? (size_t)n : 4096u;
    n = sysconf(_SC_NPROCESSORS_ONLN);
    cpu_count = (n > 0) ? (unsigned)n : 0u;
    /* Primes the pin pool while this process is still single-threaded and no
     * bind has narrowed a mask. */
    duct_discard s_pin_pool();
    /* A full engine needs duct_runtime_max_fds descriptors, more than the usual soft
     * default of 1024: the soft limit goes up to the hard one first, and a limit still
     * short of that stops the process here, ahead of main. */
    struct rlimit fds;
    if (getrlimit(RLIMIT_NOFILE, &fds) == 0) {
        rlim_t limit = fds.rlim_cur;
        if (limit < fds.rlim_max
            && setrlimit(RLIMIT_NOFILE, &(struct rlimit){ fds.rlim_max, fds.rlim_max }) == 0)
            limit = fds.rlim_max;
        if (limit < duct_runtime_max_fds)
            duct_diag("descriptor limit %llu is under the %u a full engine holds",
                      (unsigned long long)limit, duct_runtime_max_fds);
        duct_fatal(limit < duct_runtime_max_fds);
    }
    s_probe_udp();
}

/** @brief Map @p size bytes, rounded up to the page size, with protection @p prot.
 *  @return Zeroed handle on failure.
 */
static duct_vm_handle_t s_vm_map(size_t size, int prot)
{
    duct_do_if(size == 0, return (duct_vm_handle_t){});
    auto aligned_size = duct_align_up(size, pg_size);
    duct_do_if(aligned_size == 0, return (duct_vm_handle_t){});
    auto p = mmap(nullptr, aligned_size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? (duct_vm_handle_t){}
                           : (duct_vm_handle_t){ .base = p, .size = aligned_size };
}

duct_vm_handle_t duct_vm_new(size_t size)
{
    return s_vm_map(size, PROT_READ | PROT_WRITE);
}

duct_vm_handle_t duct_vm_reserve(size_t size)
{
    return s_vm_map(size, PROT_NONE);
}

/* mprotect read-write, mlock, then MADV_DONTDUMP to keep the pages out of core files. All three
 * or none: a failure of any one unlocks the range and makes it inaccessible again. */
duct_result_t duct_vm_lock(void *base, size_t size)
{
    if (mprotect(base, size, PROT_READ | PROT_WRITE) == 0 && mlock(base, size) == 0
        && madvise(base, size, MADV_DONTDUMP) == 0)
        return rc_ok;
    duct_discard munlock(base, size);
    duct_discard mprotect(base, size, PROT_NONE);
    return rc_no_memory;
}

void duct_vm_del(duct_vm_handle_t *h)
{
    duct_do_if(!h->base || h->size == 0, return);
    munmap(h->base, h->size);
    *h = (duct_vm_handle_t){};
}

void duct_vm_discard(void *base, size_t size)
{
    if (size)
        duct_discard madvise(base, size, MADV_DONTNEED);
}

int duct_thread_bind_cpu(unsigned cpu_index)
{
    int cpu = s_pin_cpu_at(cpu_index);
    duct_do_if(cpu < 0, return -1);
    cpu_set_t set = {};
    CPU_SET(cpu, &set);
    /* pid 0 names this thread on Linux and Bionic, including Android before API 36. */
    return sched_setaffinity(0, sizeof(set), &set) == 0 ? cpu : -1;
}

void duct_thread_set_name(const char *name)
{
    duct_discard pthread_setname_np(pthread_self(), name);
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

/** @brief Handler of the stop hook: set the stop request.
 *  Keeps @c errno, which the code the signal interrupted may read.
 */
static void s_on_stop_signal([[maybe_unused]] int signo)
{
    int saved = errno;
    duct_on_stop_signal();
    errno = saved;
}

void duct_stop_hook_arm(void)
{
    /* SA_RESTART: restartable system calls the signal interrupts resume. */
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

bool duct_futex_wait(void *addr, uint32_t expected, uint32_t timeout_ms)
{
    while (syscall(SYS_futex,
                   addr,
                   FUTEX_WAIT_PRIVATE,
                   expected,
                   timeout_ms ? &(struct timespec){
                        .tv_sec = timeout_ms / 1000u,
                        .tv_nsec = (long)(timeout_ms % 1000u) * 1000000L,
                    } : nullptr, nullptr, 0))
        switch (errno) {
        case EINTR: continue;
        case EAGAIN: return true;
        case ETIMEDOUT:
        default: return false;
        }
    return true;
}

void duct_futex_wake(void *addr, uint32_t count)
{
    duct_discard syscall(SYS_futex,
                         addr,
                         FUTEX_WAKE_PRIVATE,
                         count,
                         nullptr, nullptr, 0);
}
