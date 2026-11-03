/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

#include "duct_core.h"

#include "duct_xport.h"

#include <winsock2.h>
#include <windows.h>
#include <pthread.h>

size_t pg_size;
unsigned cpu_count;

static LPFN_WSARECVMSG s_wsa_recvmsg;
static bool s_gso;

LPFN_WSARECVMSG duct_x_wsa_recvmsg(void)
{
    return s_wsa_recvmsg;
}

bool duct_x_has_gso(void)
{
    return s_gso;
}

typedef struct {
    KAFFINITY avail,        /**< Cpus of group 0 this process may run on. Zero marks the pool unfilled. */
              core[64];     /**< Per cpu, the mask of every logical cpu sharing its physical core. */
} pin_pool_t;

/** @brief Cpus this process may pin onto, and the physical core of each.
 *  Filled by duct_ctor's first call, so every later bind resolves against one
 *  map. A process affinity mask is never legitimately zero, which lets
 *  @c avail double as the filled marker.
 */
static const pin_pool_t *s_pin_pool(void)
{
    static pin_pool_t pool;
    if (pool.avail != 0)
        return &pool;

    DWORD_PTR proc,
              sys;
    /* A process spanning several processor groups reports failure here;
     * pinning stays disabled to avoid addressing a cpu in the wrong group. */
    BOOL ok = GetProcessAffinityMask(GetCurrentProcess(), &proc, &sys);
    duct_do_if(!ok, return &pool);

    /* Each cpu maps to its individual core until the topology query refines it; a
     * buffer too small for the reply leaves this standing and hands out one
     * slot per logical cpu. */
    for (unsigned cpu = 0u; cpu < 64u; ++cpu)
        pool.core[cpu] = (KAFFINITY)1 << cpu;

    alignas(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX) char buf[8192];
    DWORD len = sizeof buf;
    if (GetLogicalProcessorInformationEx(
            RelationProcessorCore, (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)buf, &len))
        for (DWORD off = 0u; off < len; ) {
            auto rec = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)(buf + off);
            /* Advancing by a zero Size never terminates the walk. */
            if (rec->Size == 0u)
                break;
            off += rec->Size;
            /* SetThreadIdealProcessor addresses the calling thread's own group,
             * so only group 0 is usable. A core record carries exactly one. */
            if (rec->Processor.GroupMask[0].Group != 0)
                continue;
            KAFFINITY m = rec->Processor.GroupMask[0].Mask;
            for (unsigned cpu = 0u; cpu < 64u; ++cpu)
                if (m & ((KAFFINITY)1 << cpu))
                    pool.core[cpu] = m;
        }

    pool.avail = (KAFFINITY)proc;
    return &pool;
}

/** @brief Resolve pin slot @p slot to a logical cpu, one per physical core.
 *  Walks ascending; -1 once the walk runs out, which an empty pool does
 *  immediately.
 */
static int s_pin_cpu_at(unsigned slot)
{
    auto pool = s_pin_pool();
    KAFFINITY taken = 0;
    unsigned n = 0u;
    for (unsigned cpu = 0u; cpu < 64u; ++cpu) {
        KAFFINITY bit = (KAFFINITY)1 << cpu;
        if (!(pool->avail & bit) || (taken & bit))
            continue;
        /* Claiming the whole SMT group keeps two pinned roles off one core.
         * The mask always carries this cpu, so the walk cannot stall on it. */
        taken |= pool->core[cpu];
        if (n++ == slot)
            return (int)cpu;
    }
    return -1;
}

/** @brief Settle @c s_wsa_recvmsg and @c s_gso on a throwaway UDP socket.
 *  A failed socket leaves both at their zero values and a refused option
 *  leaves @c s_gso false; the early exits end this function, clear of the
 *  rest of @c duct_ctor. */
static void s_probe_udp(void)
{
    auto probe = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    duct_do_if(probe == INVALID_SOCKET, return);
    s_wsa_recvmsg =
        (LPFN_WSARECVMSG)duct_x_wsa_ext_pfn(probe, (GUID)WSAID_WSARECVMSG);
    /* Only a stack that segments sends answers this option. */
    DWORD seg = 0u;
    int rc = getsockopt(probe, IPPROTO_UDP, UDP_SEND_MSG_SIZE,
                        (char *)&seg, &(int){ sizeof seg });
    closesocket(probe);
    duct_do_if(rc != 0, return);
    s_gso = true;
}

static void duct_ctor(void) __attribute__((constructor(DUCT_CTOR_PRI_CORE)));
static void duct_ctor(void)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    pg_size = si.dwPageSize ? (size_t)si.dwPageSize : 4096u;

    DWORD n = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    cpu_count = n ? (unsigned)n : 0u;
    /* Primes the pin pool while the map is still the one every later bind
     * resolves against: a SetProcessAffinityMask after this point cannot shift
     * a slot onto a cpu another thread already holds. */
    duct_discard s_pin_pool();
    duct_discard WSAStartup(MAKEWORD(2, 2), &(WSADATA){});
    s_probe_udp();
}

/** @brief Winsock teardown at process exit.
 *  CORE tier runs last among destructors, which keeps sockets usable through
 *  any STATE-tier teardown.
 */
static void duct_dtor(void) __attribute__((destructor(DUCT_CTOR_PRI_CORE)));
static void duct_dtor(void)
{
    duct_discard WSACleanup();
}

/** @brief Allocate @p size bytes, rounded up to the page size, as @p type with protection @p protect.
 *  @return Zeroed handle on failure.
 */
static duct_vm_handle_t s_vm_map(size_t size, DWORD type, DWORD protect)
{
    duct_do_if(size == 0, return (duct_vm_handle_t){});
    auto aligned_size = duct_align_up(size, pg_size);
    duct_do_if(aligned_size == 0, return (duct_vm_handle_t){});
    auto p = VirtualAlloc(nullptr, aligned_size, type, protect);
    return p ? (duct_vm_handle_t){ p, aligned_size }
             : (duct_vm_handle_t){};
}

duct_vm_handle_t duct_vm_new(size_t size)
{
    return s_vm_map(size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}

duct_vm_handle_t duct_vm_reserve(size_t size)
{
    return s_vm_map(size, MEM_RESERVE, PAGE_NOACCESS);
}

/* MEM_COMMIT, then VirtualLock. A lock refused for the working-set quota is tried once more after
 * the process's minimum and maximum working set are raised by size; a range not locked is
 * decommitted. */
duct_result_t duct_vm_lock(void *base, size_t size)
{
    auto committed = VirtualAlloc(base, size, MEM_COMMIT, PAGE_READWRITE);
    duct_do_if(!committed, return rc_no_memory);
    bool locked = VirtualLock(base, size) != 0;
    if (!locked && GetLastError() == ERROR_WORKING_SET_QUOTA) {
        SIZE_T low, high;
        locked = GetProcessWorkingSetSize(GetCurrentProcess(), &low, &high)
              && SetProcessWorkingSetSize(GetCurrentProcess(), low + size, high + size)
              && VirtualLock(base, size);
    }
    if (locked)
        return rc_ok;
    duct_discard VirtualFree(base, size, MEM_DECOMMIT);
    return rc_no_memory;
}

void duct_vm_del(duct_vm_handle_t *h)
{
    duct_do_if(!h->base || h->size == 0, return);
    VirtualFree(h->base, 0, MEM_RELEASE);
    *h = (duct_vm_handle_t){};
}

/* DiscardVirtualMemory gives the RAM back at once and leaves the range committed,
 * so a later touch faults nothing and finds undefined contents. */
void duct_vm_discard(void *base, size_t size)
{
    if (size)
        duct_discard DiscardVirtualMemory(base, size);
}

/* The cpu returned is the thread's ideal processor; the scheduler stays free to
 * run the thread on any other. */
int duct_thread_bind_cpu(unsigned cpu_index)
{
    int cpu = s_pin_cpu_at(cpu_index);
    duct_do_if(cpu < 0, return -1);
    return SetThreadIdealProcessor(GetCurrentThread(), (DWORD)cpu) != (DWORD)-1 ? cpu : -1;
}

void duct_thread_set_name(const char *name)
{
    duct_discard pthread_setname_np(pthread_self(), name);
}

/* Console control events arrive on a thread the system starts, so there is no
 * signal mask to set. */
void duct_thread_block_stop_signals(void)
{
}

/* Windows ends the process when the handler for a closed console returns, so
 * that handler waits instead: main's teardown runs meanwhile and its return ends
 * the process inside the wait. The figure stays under the few seconds the system
 * allows such a handler. */
static constexpr DWORD s_close_hold_ms = 4000u;

/** @brief Turn Ctrl-C, Ctrl-Break and a closed console into a stop request.
 *  Any other event answers FALSE, which leaves it to the next handler.
 */
static BOOL WINAPI s_on_console_event(DWORD type)
{
    switch (type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
        duct_on_stop_signal();
        return TRUE;
    case CTRL_CLOSE_EVENT:
        duct_on_stop_signal();
        Sleep(s_close_hold_ms);
        return TRUE;
    default:
        return FALSE;
    }
}

void duct_stop_hook_arm(void)
{
    duct_discard SetConsoleCtrlHandler(s_on_console_event, TRUE);
}

void duct_stop_hook_disarm(void)
{
    duct_discard SetConsoleCtrlHandler(s_on_console_event, FALSE);
}

/** @brief Convert @p ft, a count of 100 ns ticks, to nanoseconds. */
static uint64_t s_filetime_ns(FILETIME ft)
{
    return ((uint64_t)ft.dwHighDateTime << 32 | ft.dwLowDateTime) * 100u;
}

duct_cpu_time_t duct_process_cpu(void)
{
    FILETIME created,
             exited,
             kernel,
             user;
    duct_cpu_time_t cpu = {};
    if (GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
        cpu = (duct_cpu_time_t){ .user_ns = s_filetime_ns(user), .kernel_ns = s_filetime_ns(kernel) };
    return cpu;
}

bool duct_futex_wait(void *addr, uint32_t expected, uint32_t timeout_ms)
{
    uint32_t exp = expected;
    /* WaitOnAddress returns TRUE both when woken and when *addr already
     * differs from exp. For WaitOnAddress, 0 means non-blocking poll,
     * whereas DUCT_TIMEOUT_INFINITE (0) requests blocking indefinitely. */
    return WaitOnAddress(addr, &exp, sizeof exp,
                         timeout_ms == DUCT_TIMEOUT_INFINITE
                         ? INFINITE : timeout_ms) != FALSE;
}

void duct_futex_wake(void *addr, uint32_t count)
{
    count > 1u ? WakeByAddressAll(addr) : WakeByAddressSingle(addr);
}
