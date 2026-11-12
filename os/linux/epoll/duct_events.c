/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_events.c
 *  @brief Linux @c epoll / @c eventfd reactor — readiness-driven admission.
 *
 *  Round-trips an opaque tag word through @c epoll_event's @c data.u64.
 */

#include "duct_events.h"

#include "duct_listener.h"
#include "duct_pre_conn.h"
#include "duct_xport.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <unistd.h>

/** Wait batch capacity. */
static constexpr unsigned events_max_batch = 64u;

/** @brief This backend's own @c duct_events_env_t body — @c epoll
 *  instance + wake @c eventfd, heap-allocated on the owning I/O thread.
 */
typedef struct duct_events_env {
    void (*cancel_io)(duct_sock_t fd);
    int epoll_fd,
        wake_fd;
} duct_events_env_t;

/** @name Tag pack/unpack
 *  Bits 0-1 for tag kind; 2-63 for the caller's opaque payload —
 *  a heap pointer with its alignment-low bits zero or a packed word.
 *  @{
 */
static constexpr uint64_t events_tag_mask  = 3u;
static constexpr uint64_t events_ptr_mask  = ~events_tag_mask;

static inline uint64_t s_tag_pack(duct_io_tag_t kind, void *ptr)
{
    assert(((uint64_t)(uintptr_t)ptr & events_tag_mask) == 0u);
    return ((uint64_t)(uintptr_t)ptr & events_ptr_mask) | (uint64_t)kind;
}

static inline void *s_tag_unpack(uint64_t word, duct_io_tag_t *kind)
{
    *kind = (duct_io_tag_t)(word & events_tag_mask);
    return (void *)(uintptr_t)(word & events_ptr_mask);
}

/** @} */

/** @brief Translate @c epoll_events into @c duct_io_ev_flags_t. */
static inline duct_io_ev_flags_t s_events_flags(uint32_t epoll_events)
{
    duct_io_ev_flags_t flags = 0u;
    if (epoll_events & EPOLLIN)
        flags = duct_or(flags, io_ev_read);
    if (epoll_events & EPOLLOUT)
        flags = duct_or(flags, io_ev_write);
    if (epoll_events & EPOLLERR)
        flags = duct_or(flags, io_ev_error);
    if (epoll_events & EPOLLHUP)
        flags = duct_or(flags, io_ev_hup);
    return flags;
}

/** @brief Map dial event @p epoll_events on @p fd to the connect's outcome.
 *  A failed connect always raises EPOLLERR, so an event free of it and of EPOLLHUP is
 *  a connection made, and SO_ERROR is read for the others alone. */
static duct_result_t s_dial_outcome(duct_sock_t fd, uint32_t epoll_events)
{
    if (!(epoll_events & (EPOLLERR | EPOLLHUP)))
        return rc_ok;
    auto rc = duct_xconnect_result(fd);
    return rc == rc_ok ? rc_fatal : rc;
}

/** @brief Kernel-side busy polling for this epoll instance, opt-in through
 *  @c DUCT_BUSY_POLL_US (microseconds; unset or 0 leaves it off).
 *
 *  Ordinary readiness wakeups travel NIC -> IRQ -> softirq -> socket queue
 *  -> epoll; with this set the thread already inside @c epoll_wait polls
 *  the device's NAPI queue itself, so the softirq scheduling step drops
 *  out of the arrival path. Distinct from the engine userspace spin
 *  (@c DUCT_BUSY_SPIN_US), which removes thread park/wake:
 *  both can be active together.
 *
 *  Configured per-epoll via @c EPIOCSPARAMS (Linux 6.9+), requiring no privilege
 *  and touching no other process. The budget stays at the kernel unprivileged
 *  ceiling (@c NAPI_POLL_WEIGHT) -- asking for more is @c EPERM without
 *  CAP_NET_ADMIN. Best-effort: an older kernel, a socket with no
 *  NAPI id behind it (loopback, veth), or a refused ioctl all leave
 *  the ordinary readiness path in place.
 */
#ifndef EPIOCSPARAMS
/* Declared here when the build host headers predate Linux 6.9: the
 * layout and request code are kernel UAPI, so a binary
 * built against older headers still drives a newer kernel correctly, and
 * an older kernel refuses the ioctl with ENOTTY, which this path ignores.
 * Reaches a stable published contract without pulling a header that may
 * not exist on the builder. */
struct epoll_params {
    uint32_t busy_poll_usecs;
    uint16_t busy_poll_budget;
    uint8_t  prefer_busy_poll;
    uint8_t  __pad;
};
#define EPOLL_IOC_TYPE 0x8A
#define EPIOCSPARAMS _IOW(EPOLL_IOC_TYPE, 0x01, struct epoll_params)
#endif

static void s_epoll_busy_poll_arm(int epoll_fd)
{
    const char *env = getenv("DUCT_BUSY_POLL_US");
    long us = env ? atol(env) : 0;
    if (us <= 0)
        return;
    struct epoll_params params = {
        .busy_poll_usecs = (uint32_t)us,
        .busy_poll_budget = 64u, /* NAPI_POLL_WEIGHT: the unprivileged ceiling */
        .prefer_busy_poll = 1u,
    };
    duct_discard ioctl(epoll_fd, EPIOCSPARAMS, &params);
}

duct_events_env_t *duct_events_init(void)
{
    auto env = duct_new(duct_events_env_t);
    duct_do_if(!env, goto fail);

    env->cancel_io = nullptr;
    env->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    duct_do_if(env->epoll_fd < 0, goto fail);
    s_epoll_busy_poll_arm(env->epoll_fd);

    env->wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    duct_do_if(env->wake_fd < 0, goto fail);

    struct epoll_event kev = {
        .events = EPOLLIN,
        .data.u64 = s_tag_pack(io_tag_wake, nullptr),
    };
    int rc = epoll_ctl(env->epoll_fd, EPOLL_CTL_ADD, env->wake_fd, &kev);
    duct_do_if(rc < 0, goto fail);
    return env;
fail:
    if (env->epoll_fd != duct_sock_bad)
        close(env->epoll_fd);
    if (env->wake_fd != duct_sock_bad)
        close(env->wake_fd);
    duct_del(env);
    return nullptr;
}

void (*duct_events_cancel_io_of(duct_events_env_t *env))(duct_sock_t fd)
{
    return env->cancel_io;
}

void duct_events_fini(duct_events_env_t *env)
{
    close(env->wake_fd);
    close(env->epoll_fd);
    duct_del(env);
}

void duct_events_rx_stall([[maybe_unused]] duct_sock_t fd,
                          [[maybe_unused]] void *rx_io_priv)
{
    /* No-op for EPOLLET mode. */
}

void duct_events_drive_rx(void *tag)
{
    duct_result_t rc = rc_again;
    duct_io_xfer_t r;
    while (duct_io_rx_reserve(tag, &r)) {
        if (r.units > 1u) {
            rc = duct_io_dgram_rx_units(tag, &r);
            if (rc != rc_ok)
                break;
            continue;
        }
        size_t nread = 0u,
               seg = 0u;
        rc = duct_xread(r.fd, r.xport_type, (duct_view_u8){ .data = r.buf, .size = r.size },
                             &nread, r.ctx, 0, &seg);
        if (rc == rc_ok) {
            duct_io_rx_commit(tag, nread, seg);
            continue;
        }
        if (rc == rc_drop) {
            /* Truncated datagram, already dequeued by recv() itself —
             * nothing to commit, keep draining. Reset rc so a stale
             * rc_drop never reaches duct_io_rx_done below. */
            rc = rc_again;
            continue;
        }
        break;
    }
    duct_io_rx_done(tag, rc);
}

void duct_events_drive_tx(void *tag)
{
    duct_result_t rc = rc_again;
    bool filled = false;
    duct_io_xfer_t p;
    while ((filled = duct_io_tx_peek(tag, &p))) {
        if (!duct_io_tx_send(tag, &p, &rc))
            break;
    }
    duct_io_tx_write_armed_set(tag, filled);
    duct_io_tx_done(tag, rc); /* no-op unless rc is rc_fatal */
}

bool duct_events_watch(duct_events_env_t *env, duct_sock_t fd,
                       duct_io_tag_t kind, void *tag_ptr,
                       [[maybe_unused]] duct_xport_t xport_type)
{
    duct_do_if(fd == duct_sock_bad, return false);
    uint32_t interest = 0u;
    switch (kind) {
    case io_tag_listener:
        /* Level-triggered on purpose, no EPOLLET: independent of the
         * listener's own read side, which isn't proven to drain-to-EAGAIN.
         * EPOLLOUT starts unarmed even for a dgram_tx_outbox listener — a
         * UDP socket is writable almost always, so leaving it on
         * unconditionally spins epoll_wait every turn regardless of
         * traffic; @ref duct_events_dgram_tx_interest arms it reactively,
         * only while a real EAGAIN is outstanding. */
        interest = EPOLLIN;
        break;
    case io_tag_pre_conn:
        switch (((duct_pre_conn_t *)tag_ptr)->kind) {
        case pre_conn_probe:
            /* Level-triggered: a read that leaves the first bytes short is
             * completed by a later wake, nothing posts it again. */
            interest = EPOLLIN;
            break;
        case pre_conn_dial:
            interest = EPOLLIN | EPOLLOUT | EPOLLET;
            break;
        }
        break;
    case io_tag_conn:
        /* SO_REUSEPORT on Linux demuxes a per-peer datagram socket ahead of
         * its shared listener, so xport_type doesn't narrow read interest. */
        interest = EPOLLIN | EPOLLOUT | EPOLLET;
        break;
    case io_tag_wake:
    case io_tag_rio_cq:
        duct_unreachable();
    }
    struct epoll_event ev = {
        .events = interest,
        .data.u64 = s_tag_pack(kind, tag_ptr),
    };
    return epoll_ctl(env->epoll_fd, EPOLL_CTL_ADD, fd, &ev) >= 0;
}

bool duct_events_promote(duct_events_env_t *env, duct_sock_t fd, void *tag_ptr)
{
    duct_do_if(fd == duct_sock_bad, return false);
    /* MOD not ADD: fd is already in this epoll instance's set, a second
     * ADD fails EEXIST. Full conn set regardless of what the pre_conn
     * carried — pre_conn_probe arms EPOLLIN alone. */
    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLOUT | EPOLLET,
        .data.u64 = s_tag_pack(io_tag_conn, tag_ptr),
    };
    return epoll_ctl(env->epoll_fd, EPOLL_CTL_MOD, fd, &ev) >= 0;
}

/* EPOLLIN alone, level-triggered. The drive loop is bounded and stops with the
 * device still holding packets; level re-delivers that residue on the next
 * turn, while an edge announces only the next arrival — the same reason a
 * listener carries no EPOLLET. EPOLLOUT stays off: a tun descriptor is
 * writable almost always and arming it spins epoll_wait every turn.
 * EPOLL_CTL_ADD answering EEXIST refuses a device already watched. */
/* Edge-triggered like other connections here. Every early exit in the device
 * drive leaves an explicit continuation behind it — the resume post a latched
 * conn is owed, or the self-repost on a spent pass budget — ensuring subsequent
 * wakeups remain available without continuous re-announcements during backpressure. */
bool duct_events_watch_device(duct_events_env_t *env, void *device, void *tag_ptr)
{
    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLET,
        .data.u64 = s_tag_pack(io_tag_conn, tag_ptr),
    };
    return epoll_ctl(env->epoll_fd, EPOLL_CTL_ADD,
                     (int)(intptr_t)device, &ev) >= 0;
}

void duct_events_device_rx_interest([[maybe_unused]] duct_events_env_t *env,
                                    [[maybe_unused]] void *device,
                                    [[maybe_unused]] bool want)
{
}

void duct_events_unwatch_device(duct_events_env_t *env, void *device)
{
    duct_events_unwatch(env, (duct_sock_t)(intptr_t)device, nullptr);
}

void duct_events_unwatch(duct_events_env_t *env, duct_sock_t fd,
                         [[maybe_unused]] void *rx_io_priv)
{
    if (fd == duct_sock_bad)
        return;
    duct_discard epoll_ctl(env->epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
}

void duct_events_kick(duct_events_env_t *env)
{
    duct_discard write(env->wake_fd, &(uint64_t){ 1 }, sizeof(uint64_t));
}

/** @brief Rewrite @p listener's level-triggered mask: EPOLLIN for @p rx,
 *  EPOLLOUT for @p tx. */
static void s_listener_interest(duct_events_env_t *env, duct_listener_t *listener,
                                bool rx, bool tx)
{
    struct epoll_event ev = {
        .events = (rx ? (uint32_t)EPOLLIN : 0u) | (tx ? (uint32_t)EPOLLOUT : 0u),
        .data.u64 = s_tag_pack(io_tag_listener, listener),
    };
    duct_discard epoll_ctl(env->epoll_fd, EPOLL_CTL_MOD, listener->listen_fd, &ev);
}

void duct_events_dgram_tx_interest(duct_events_env_t *env, duct_listener_t *listener, bool armed)
{
    s_listener_interest(env, listener, !listener->rx_parked, armed);
}

void duct_events_listener_rx_interest(duct_events_env_t *env, duct_listener_t *listener, bool want)
{
    s_listener_interest(env, listener, want,
                        duct_atomic_load(&listener->dgram_tx_write_armed, relaxed));
}

bool duct_events_dgram_tx_pool_alloc([[maybe_unused]] duct_listener_t *listener)
{
    return true;
}

void duct_events_dgram_tx_pool_free([[maybe_unused]] duct_listener_t *listener)
{
}

bool duct_events_dgram_tx_kick([[maybe_unused]] duct_events_env_t *env,
                               [[maybe_unused]] duct_listener_t *listener)
{
    return false;
}

duct_x_slot_hooks_t duct_events_x_slot_hooks(void)
{
    return (duct_x_slot_hooks_t){};
}


/** @brief Accept from @p listener until its queue is empty, an accept fails, a pace holds it or a want of descriptors parks it.
 *  Each accepted fd dispatches through @ref duct_io_on_accept, which starts that pace;
 *  @ref duct_io_accept parks the listener.
 */
static inline void s_handle_accept(duct_listener_t *listener)
{
    duct_sock_t fd;
    struct sockaddr_storage addr;
    while (!duct_listener_held(listener) && duct_io_accept(listener, &fd, &addr) == rc_ok) {
        duct_peer_t peer = duct_io_peer_from_sockaddr((struct sockaddr *)&addr);
        duct_io_on_accept(listener, fd, &peer);
    }
    /* TODO: process EAGAIN (drained, rc_ok) or a hard error */
}

/** @brief Dispatch one signaled slot, route by tag kind. */
static inline void s_events_dispatch(duct_events_env_t *env, struct epoll_event *ev)
{
    duct_io_tag_t kind;
    auto tag = s_tag_unpack(ev->data.u64, &kind);
    switch (kind) {
    case io_tag_wake:
        duct_discard duct_xread(env->wake_fd, x_raw,
                                (duct_view_u8){ (uint8_t *)&(uint64_t){}, sizeof(uint64_t) },
                                &(size_t){}, nullptr, 0, nullptr);
        duct_io_on_wake();
        break;
    case io_tag_listener:
        auto flags = s_events_flags(ev->events);
        auto listener = (duct_listener_t *)tag;
        if (duct_has(flags, duct_or(io_ev_error, io_ev_hup))) {
            /* UDP: EPOLLERR here is a per-destination async ICMP error
             * (e.g. Port Unreachable once some registered peer goes away),
             * not listener socket failure -- getsockopt(SO_ERROR) reads and
             * clears it. Left unread, epoll keeps re-reporting EPOLLERR on
             * every pass and io_ev_read below never runs again, silently
             * refusing every future peer's registration on this listener.
             * A stream listener's own accept socket erroring here is a
             * real fault -- still bail for that case. */
            if (listener->xport_type == x_udp) {
                int sock_err = 0;
                socklen_t err_len = sizeof sock_err;
                duct_discard getsockopt(listener->listen_fd, SOL_SOCKET, SO_ERROR,
                                        &sock_err, &err_len);
            } else
                break;
        }
        if (duct_has(flags, io_ev_write))
            duct_io_on_dgram_tx_writable(listener);
        if (duct_has(flags, io_ev_read))
            listener->xport_type == x_udp ? duct_io_dgram_rx_drain(listener)
                                          : s_handle_accept(listener);
        break;
    case io_tag_pre_conn:
        auto pre_conn = (duct_pre_conn_t *)tag;
        switch (pre_conn->kind) {
        case pre_conn_probe:
            duct_io_on_pre_conn_readable(pre_conn);
            break;
        case pre_conn_dial:
            duct_io_on_pre_conn_dialed(pre_conn, s_dial_outcome(pre_conn->fd, ev->events));
            break;
        }
        break;
    case io_tag_conn:
        duct_io_on_event(&(duct_io_event_t){ kind, tag, s_events_flags(ev->events) });
        break;
    case io_tag_rio_cq:
        duct_unreachable();
    }
}

void duct_events_run_loop(duct_events_env_t *env, bool _Atomic *shutdown)
{
    struct epoll_event events[events_max_batch];
    duct_spin_state_t spin = {};
    bool in_window = true;
    while (!duct_atomic_load(shutdown, acquire)) {
        uint32_t timer_ms = duct_io_on_tick();
#if DUCT_RUNTIME_STATS
        duct_io_rtstat_busy_track(in_window);
#endif
        int timeout = in_window ? 0
                    : duct_io_work_pending() ? 0
                    : duct_io_timer_due_soon() ? 0
                    : timer_ms == DUCT_TIMEOUT_INFINITE ? -1 : (int)timer_ms,
            n = 0;
        do {
            n = epoll_wait(env->epoll_fd, events, events_max_batch, timeout);
        } while (n < 0 && errno == EINTR);
        duct_do_if(n < 0, return);

        in_window = duct_spin_next(&spin, n > 0, duct_ticks_mono_ns());
        if (n == 0)
            duct_cpu_relax();
        for (int i = 0; i < n; ++i) {
            s_events_dispatch(env, &events[i]);
        }
    }
}

