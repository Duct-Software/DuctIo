/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_events.c
 *  @brief Portable @c poll() / @c WSAPoll() reactor — universal @c
 *  DUCT_EVENTS_MODEL fallback.
 *  @ref duct_events_env_t keeps a poll-set array, allocated per I/O
 *  thread by @ref duct_events_init.
 */

#include "duct_events.h"

#include "duct_listener.h"
#include "duct_pre_conn.h"
#include "duct_xport.h"

#include <assert.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include "duct_rio.h"
    typedef WSAPOLLFD   duct_pollfd_t;
    typedef int         duct_socklen_t;
#else
    #include <errno.h>
    #include <limits.h>
    #include <poll.h>
    #include <unistd.h>
    typedef struct pollfd   duct_pollfd_t;
    typedef socklen_t       duct_socklen_t;
#endif

/** Wait set capacity. */
static constexpr unsigned events_max_handles
    = duct_runtime_max_conns + duct_runtime_max_listeners + 1u;

typedef struct duct_events_slot {
    duct_io_tag_t kind;
    void         *tag;
} duct_events_slot_t;

/** @brief Dense @c fds[0..n_entries) with a parallel @c slots tag array;
 *  slot 0 is always the waker's read side. @c fds stays its own bare,
 *  contiguous array — poll()/WSAPoll()'s own argument shape — and every
 *  io_priv cache points into it: interest lives in @c .events, which
 *  rx_stall, drive_rx and drive_tx write there directly. Every move swaps both
 *  arrays in lockstep and relocates what it moved, so each part stays dense.
 */
typedef struct duct_events_env {
    void (*cancel_io)(duct_sock_t fd);
    duct_pollfd_t      fds[events_max_handles];
    duct_events_slot_t slots[events_max_handles];
    unsigned    n_entries,
                n_polled;  /**< Entries the wait takes, a prefix of @c fds.
                             *  Past it sit conns held out of the wait and
                             *  entries watched since the last one; the scan
                             *  ahead of each wait brings back every entry
                             *  with interest. */
    duct_sock_t wake_sock; /**< Same fd as @c fds[0] — a self-connected
                             * loopback UDP socket. @ref duct_events_kick
                             * sends a zero-length datagram into it,
                             * waking the poll. */
} duct_events_env_t;

/** @brief Build a self-connected loopback UDP socket for cross-thread
 *  waking.
 *  One fd doubles as both the pollable read side and the kick target;
 *  connecting it to itself allows @ref duct_events_kick to use plain
 *  send()/recv().
 */
static duct_sock_t s_make_wake_sock(void)
{
    duct_sock_t sock = socket(AF_INET, SOCK_DGRAM, 0);
    duct_do_if(sock == duct_sock_bad, return sock);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
    };
    auto a = (struct sockaddr *)&addr;
    auto alen = (duct_socklen_t)sizeof addr;
    bool bound = bind(sock, a, alen) == 0
              && getsockname(sock, a, &alen) == 0
              && connect(sock, a, alen) == 0;
    duct_do_if(!bound,
            duct_sock_close(sock);
            return duct_sock_bad;
    );
    duct_xset_nonblock(sock);
    return sock;
}

duct_events_env_t *duct_events_init(void)
{
    auto env = duct_new(duct_events_env_t);
    duct_do_if(!env, return nullptr);
    env->cancel_io = nullptr;
    duct_sock_t wake_sock = s_make_wake_sock();
    duct_do_if(wake_sock == duct_sock_bad, duct_del(env); return nullptr);
    env->wake_sock = wake_sock;
    env->fds[0] = (duct_pollfd_t){ .fd = wake_sock, .events = POLLIN };
    env->slots[0] = (duct_events_slot_t){ .kind = io_tag_wake, .tag = nullptr };
    env->n_entries = env->n_polled = 1u;
    return env;
}

void (*duct_events_cancel_io_of(duct_events_env_t *env))(duct_sock_t fd)
{
    return env->cancel_io;
}

void duct_events_fini(duct_events_env_t *env)
{
    duct_sock_close(env->wake_sock);
    duct_del(env);
}

void duct_events_rx_stall(duct_sock_t fd, void *rx_io_priv)
{
    auto p = (duct_pollfd_t *)rx_io_priv;
    duct_fatal(!p || p->fd != fd);
    p->events &= ~(short)POLLIN;
}

void duct_events_drive_rx(void *tag)
{
    duct_result_t rc = rc_again;
    duct_io_xfer_t r = { .fd = duct_sock_bad };
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
    /* Re-arm POLLIN unconditionally: reaching this function proves whatever
     * earlier cleared it via duct_events_rx_stall no longer applies,
     * regardless of what this pass itself read. r.fd is duct_sock_bad only
     * for a stale tag — a "buffer still full" reserve failure fills it in. */
    if (r.fd != duct_sock_bad) {
        auto p = (duct_pollfd_t *)r.io_priv;
        duct_fatal(!p || p->fd != r.fd);
        p->events |= POLLIN;
    }
    duct_io_rx_done(tag, rc);
}

void duct_events_drive_tx(void *tag)
{
    duct_result_t rc = rc_again;
    bool filled = false;
    duct_io_xfer_t p = { .fd = duct_sock_bad };
    while ((filled = duct_io_tx_peek(tag, &p))) {
        if (!duct_io_tx_send(tag, &p, &rc))
            break;
    }
    /* poll()/WSAPoll() is level-triggered, no EPOLLET, so each drive must
     * reconcile POLLOUT; p.fd remains duct_sock_bad for a stale tag and for a
     * close the peek itself settled, whose entry is gone; every other exit
     * reconciles. */
    if (p.fd != duct_sock_bad) {
        auto pf = (duct_pollfd_t *)p.io_priv;
        duct_fatal(!pf || pf->fd != p.fd);
        pf->events = filled ? (short)(pf->events | POLLOUT)
                             : (short)(pf->events & ~(short)POLLOUT);
        duct_io_tx_write_armed_set(tag, filled);
    }
    duct_io_tx_done(tag, rc); /* no-op unless rc is rc_fatal */
}

/** @brief Find @p fd's live slot in @p env.
 *  @return @c UINT_MAX if not registered.
 */
static inline unsigned s_find_slot(duct_events_env_t *env, duct_sock_t fd)
{
    for (unsigned i = 0u; i < env->n_entries; ++i)
        if (env->fds[i].fd == fd)
            return i;
    return UINT_MAX;
}

/** @brief Resolve @p fd's slot in @p env.
 *  Prefers the direct pointer cached in @p io_priv by @ref
 *  duct_io_on_relocate, falls back to @ref s_find_slot.
 *  @note @c UINT_MAX is a legitimate return value, @b not enforced:
 *  @ref duct_events_unwatch tolerates @p fd it never registered.
 */
static inline unsigned s_slot_lookup(duct_events_env_t *env,
                                     duct_sock_t fd, void *io_priv)
{
    auto p = (duct_pollfd_t *)io_priv;
    return p && p->fd == fd ? (unsigned)(p - env->fds) : s_find_slot(env, fd);
}

/** @brief Swap entries @p a and @p b and tell each owner its new slot. */
static void s_swap(duct_events_env_t *env, unsigned a, unsigned b)
{
    if (a == b)
        return;
    auto fd = env->fds[a];
    auto slot = env->slots[a];
    env->fds[a] = env->fds[b];
    env->slots[a] = env->slots[b];
    env->fds[b] = fd;
    env->slots[b] = slot;
    duct_io_on_relocate(env->slots[a].kind, env->slots[a].tag, &env->fds[a]);
    duct_io_on_relocate(env->slots[b].kind, env->slots[b].tag, &env->fds[b]);
}

bool duct_events_watch(duct_events_env_t *env, duct_sock_t fd,
                       duct_io_tag_t kind, void *tag_ptr,
                       duct_xport_t xport_type)
{
    duct_do_if(fd == duct_sock_bad, return false);
    duct_do_if(env->n_entries >= sizeof env->fds / sizeof env->fds[0], return false);
    short interest = 0;
    switch (kind) {
    case io_tag_listener:
        /* POLLOUT starts unarmed even for a dgram_tx_outbox listener — a
         * UDP socket is writable almost always, so leaving it on
         * unconditionally spins poll() every turn regardless of traffic;
         * @ref duct_events_dgram_tx_interest arms it reactively, only
         * while a real EAGAIN is outstanding. poll has no edge-triggered
         * mode at all, making reactive arming mandatory here. */
        interest = POLLIN;
        break;
    case io_tag_pre_conn:
        switch (((duct_pre_conn_t *)tag_ptr)->kind) {
        case pre_conn_probe: /* still dialing or probe-waiting */
            interest = POLLIN;
            break;
        case pre_conn_dial:
            interest = POLLIN | POLLOUT;
            break;
        }
        break;
    case io_tag_conn:
        duct_do_if(xport_type == x_inter, interest = POLLIN; break);
        interest = POLLOUT | POLLIN;
        /* Below x_port_share_connected the shared listener takes a per-peer
         * leg's datagrams and routes them to the leg, so its own socket is
         * watched for writes alone. */
        if (xport_type == x_udp_peer && duct_x_port_sharing < x_port_share_connected)
            interest &= ~(short)POLLIN;
        break;
    default:
        return false;
    }
    unsigned i = env->n_entries++;
    env->fds[i] = (duct_pollfd_t){ .fd = fd, .events = interest };
    env->slots[i] = (duct_events_slot_t){ .kind = kind, .tag = tag_ptr };
    duct_io_on_relocate(kind, tag_ptr, &env->fds[i]);
    return true;
}

/* Off Windows a device is a descriptor, so it goes through this backend's own
 * watch, whose io_tag_conn case narrows to POLLIN for x_inter — POLLOUT on a
 * tun descriptor is ready almost always and spins poll() every turn. Under
 * Windows a device is a waitable handle, which WSAPoll cannot take at all. */
bool duct_events_watch_device([[maybe_unused]] duct_events_env_t *env,
                              [[maybe_unused]] void *device,
                              [[maybe_unused]] void *tag_ptr)
{
#ifdef _WIN32
    return false;
#else
    return duct_events_watch(env, (duct_sock_t)(intptr_t)device,
                             io_tag_conn, tag_ptr, x_inter);
#endif
}

void duct_events_unwatch_device([[maybe_unused]] duct_events_env_t *env,
                                [[maybe_unused]] void *device)
{
#ifndef _WIN32
    duct_events_unwatch(env, (duct_sock_t)(intptr_t)device, nullptr);
#endif
}

/** @brief Set or clear POLLIN on @p fd's slot; an unwatched @p fd is left alone. */
static void s_read_interest(duct_events_env_t *env, duct_sock_t fd, bool want)
{
    unsigned i = s_find_slot(env, fd);
    duct_do_if(i == UINT_MAX, return);
    if (want)
        env->fds[i].events |= (short)POLLIN;
    else
        env->fds[i].events &= ~(short)POLLIN;
}

void duct_events_device_rx_interest([[maybe_unused]] duct_events_env_t *env,
                                    [[maybe_unused]] void *device,
                                    [[maybe_unused]] bool want)
{
#ifndef _WIN32
    s_read_interest(env, (duct_sock_t)(intptr_t)device, want);
#endif
}

void duct_events_unwatch(duct_events_env_t *env, duct_sock_t fd, void *rx_io_priv)
{
    if (fd == duct_sock_bad)
        return;
    unsigned i = s_slot_lookup(env, fd, rx_io_priv);
    if (i == UINT_MAX)
        return; /* never registered, or already removed — tolerated */
    /* A polled entry leaves the polled part first, so both parts stay dense. */
    if (i < env->n_polled) {
        s_swap(env, i, --env->n_polled);
        i = env->n_polled;
    }
    unsigned last = --env->n_entries;
    env->fds[i] = env->fds[last];
    env->slots[i] = env->slots[last];
    if (i != last)
        duct_io_on_relocate(env->slots[i].kind, env->slots[i].tag, &env->fds[i]);
}

bool duct_events_promote(duct_events_env_t *env, duct_sock_t fd, void *tag_ptr)
{
    unsigned i = s_find_slot(env, fd);
    duct_do_if(i == UINT_MAX, return false);
    /* fd is already in env->fds[]; the tag changes, and the read side is
     * widened to the full conn set — a pre_conn_probe registered POLLIN
     * alone. No x_udp_peer narrowing: a promoted conn holds a real,
     * unshared socket. POLLOUT is left exactly as it stands: s_drive_tx owns
     * that bit and keeps it in step with duct_io_tx_write_armed_set,
     * and arming it with nothing to send spins poll() every turn. */
    env->fds[i].events |= POLLIN;
    env->slots[i] = (duct_events_slot_t){ .kind = io_tag_conn, .tag = tag_ptr };
    duct_io_on_relocate(io_tag_conn, tag_ptr, &env->fds[i]);
    return true;
}

void duct_events_kick(duct_events_env_t *env)
{
    duct_discard send(env->wake_sock, nullptr, 0, 0);
}

void duct_events_dgram_tx_interest(duct_events_env_t *env, duct_listener_t *listener, bool armed)
{
    unsigned i = s_find_slot(env, listener->listen_fd);
    duct_do_if(i == UINT_MAX, return);
    env->fds[i].events = (short)((listener->rx_parked ? 0 : POLLIN) | (armed ? POLLOUT : 0));
}

void duct_events_listener_rx_interest(duct_events_env_t *env, duct_listener_t *listener, bool want)
{
    s_read_interest(env, listener->listen_fd, want);
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

#ifdef _WIN32
bool duct_events_rio_available(void)
{
    return false;
}

bool duct_events_dgram_shared_rio_capable(void)
{
    return false;
}
#endif

/** @brief Accept from @p listener until its queue is empty, an accept fails, a pace holds it or a want of descriptors parks it.
 *  Dispatches each through @ref duct_io_on_accept, which starts that pace;
 *  @ref duct_io_accept parks the listener.
 */
static inline void s_handle_accept(duct_listener_t *listener)
{
    duct_sock_t fd;
    struct sockaddr_storage addr;
    while (!duct_listener_held(listener) && duct_io_accept(listener, &fd, &addr) == rc_ok) {
        auto peer = duct_io_peer_from_sockaddr((struct sockaddr *)&addr);
        duct_io_on_accept(listener, fd, &peer);
    }
}

/** @brief Decode @c poll() / @c WSAPoll()'s @c revents.
 *
 *  @c POLLHUP means what the platform's @c duct_x_poll_hup says. A peer's FIN
 *  reads as readability, @c POLLIN or a @c POLLHUP that maps to a read: the
 *  bytes ahead of it read before @c recv's 0-byte end ends the conn's input.
 *  @c POLLNVAL counts as @c POLLERR: @c poll() answers it for a descriptor
 *  closed under the watch, and Darwin's for one its kqueue cannot watch.
 */
static inline duct_io_ev_flags_t s_events_flags(short revents)
{
    duct_io_ev_flags_t flags = 0u;
    if (revents & POLLIN)
        flags = duct_or(flags, io_ev_read);
    if (revents & POLLHUP)
        flags = duct_or(flags, duct_x_poll_hup);
    if (revents & POLLOUT)
        flags = duct_or(flags, io_ev_write);
    if (revents & (POLLERR | POLLNVAL))
        flags = duct_or(flags, io_ev_error);
    return flags;
}

/** @brief Map dial event @p revents on @p fd to the connect's outcome.
 *  No platform reports a failed connect without POLLERR or POLLHUP, so an event free
 *  of them is a connection made. Otherwise SO_ERROR decides, and a clean one fails the
 *  dial where the event decodes to an error or a hang-up: a WSAPoll POLLHUP, the FIN
 *  of a peer that accepted, decodes to neither. */
static duct_result_t s_dial_outcome(duct_sock_t fd, short revents)
{
    if (!(revents & (POLLERR | POLLHUP | POLLNVAL)))
        return rc_ok;
    auto rc = duct_xconnect_result(fd);
    return rc == rc_ok && duct_has(s_events_flags(revents), duct_or(io_ev_error, io_ev_hup)) ? rc_fatal : rc;
}

/** @brief Dispatch one signaled slot, route by tag kind. */
static inline void s_events_dispatch(duct_events_env_t *env, unsigned i)
{
    auto slot = &env->slots[i];
    switch (slot->kind) {
    case io_tag_wake:
        duct_result_t n;
        /* x_udp_peer: duct_xread's own case 0 exemption treats a
         * zero-length datagram as a real drained kick, not EOF —
         * only rc_again (would-block) stops the drain. */
        do {
            n = duct_xread(env->wake_sock, x_udp_peer,
                            (duct_view_u8){ (uint8_t[64]){ }, 64 },
                            &(size_t){}, nullptr, 0, nullptr);
        } while (n == rc_ok);
        duct_io_on_wake();
        break;
    case io_tag_listener:
        auto flags = s_events_flags(env->fds[i].revents);
        auto listener = (duct_listener_t *)env->slots[i].tag;
        if (duct_has(flags, duct_or(io_ev_error, io_ev_hup))) {
            /* UDP: POLLERR here is a per-destination async ICMP error
             * (e.g. Port Unreachable once some registered peer goes away),
             * not listener socket failure -- getsockopt(SO_ERROR) reads and
             * clears it. Left unread, poll keeps re-reporting POLLERR on
             * every pass and io_ev_read below never runs again, silently
             * refusing every future peer's registration on this listener.
             * A stream listener's own accept socket erroring here is a
             * real fault -- still bail for that case. */
            if (listener->xport_type == x_udp) {
                int sock_err = 0;
                duct_socklen_t err_len = sizeof sock_err;
                duct_discard getsockopt(listener->listen_fd, SOL_SOCKET, SO_ERROR,
                                        (char *)&sock_err, &err_len);
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
        auto pre_conn = (duct_pre_conn_t *)env->slots[i].tag;
        if (pre_conn->kind == pre_conn_probe)
            duct_io_on_pre_conn_readable(pre_conn);
        else
            duct_io_on_pre_conn_dialed(pre_conn, s_dial_outcome(pre_conn->fd, env->fds[i].revents));
        break;
    case io_tag_conn:
        auto tag = slot->tag;
        auto revents = env->fds[i].revents;
        duct_io_on_event(&(duct_io_event_t){ io_tag_conn, tag, s_events_flags(revents) });
        /* WSAPoll raises POLLHUP for a peer's FIN whatever the interest, past
         * the EOF read too, so a conn it woke for that alone and the dispatch
         * left with no interest is held out of the wait; a reset then shows
         * once the conn has interest again. Linux raises POLLHUP alone only
         * with both directions shut, which closes the conn in this dispatch,
         * and Darwin raises nothing for an entry with no interest. */
        if (revents == POLLHUP && i < env->n_polled && env->slots[i].tag == tag
            && !env->fds[i].events)
            s_swap(env, i, --env->n_polled);
        break;
    case io_tag_rio_cq:
        duct_unreachable();
    }
}

void duct_events_run_loop(duct_events_env_t *env, bool _Atomic *shutdown)
{
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
                    : timer_ms == DUCT_TIMEOUT_INFINITE ? -1 : (int)timer_ms;
        /* A held-out conn rejoins with its interest, a fresh watch with its first. */
        for (unsigned i = env->n_polled; i < env->n_entries; ++i)
            if (env->fds[i].events)
                s_swap(env, i, env->n_polled++);
        unsigned n_polled = env->n_polled;
        int n;
#ifdef _WIN32
        n = WSAPoll(env->fds, n_polled, timeout);
        duct_do_if(n == SOCKET_ERROR, return);
#else
        do {
            n = poll(env->fds, n_polled, timeout);
        } while (n < 0 && errno == EINTR);
        duct_do_if(n < 0, return);
#endif
        in_window = duct_spin_next(&spin, n > 0, duct_ticks_mono_ns());
        if (n == 0)
            duct_cpu_relax();
        for (unsigned i = 0u; i < n_polled && i < env->n_polled; ++i)
            if (env->fds[i].revents)
                s_events_dispatch(env, i);
    }
}
