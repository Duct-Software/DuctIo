/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, authors: Constantin Papizh, Dmitriy Puzyrkov, Olzhas Zharasbayev */

/** @file duct_events.c
 *  @brief @c kqueue reactor — readiness-driven admission.
 *
 *  Shared kqueue model; selected by the Darwin platform for macOS and iOS.
 *
 *  Registrations carry @c EV_CLEAR, making this backend edge-triggered:
 *  @ref duct_events_rx_stall is a no-op and neither drive reconciles interest.
 *  The three exceptions are the listener read side, a probe-waiting pre_conn
 *  and the dgram TX write filter, which are level-triggered: none
 *  of them drains to would-block.
 *
 *  Round-trips an opaque tag word through @c kevent's @c udata.
 */

#include "duct_events.h"

#include "duct_listener.h"
#include "duct_pre_conn.h"
#include "duct_xport.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/** Wait batch capacity.
 *
 *  Must be @>= @ref kq_max_changes: a @c kevent call carrying both a
 *  changelist and an eventlist reports rejected changes as @c EV_ERROR
 *  entries in that eventlist, and an eventlist too small to hold them stops
 *  the changelist short.
 */
static constexpr unsigned kq_max_events = 128u;

/** Pending-changelist capacity, flushed with the next wait.
 *  @see s_changes_push.
 */
static constexpr unsigned kq_max_changes = 64u;

static_assert(kq_max_events >= kq_max_changes,
    "eventlist must absorb a full changelist's worth of EV_ERROR receipts");

/** Waker @c ident. @c EVFILT_USER idents are user-defined values in a
 *  namespace of their own, unrelated to any descriptor, so 0 collides with
 *  nothing.
 */
static constexpr uintptr_t kq_wake_ident = 0u;

/** @name Tag pack/unpack
 *  Bits 0-1 for tag kind; 2-63 for the caller's opaque payload —
 *  a heap pointer with its alignment-low bits zero or a packed word.
 *  Same layout @c os/linux/epoll/ uses for @c epoll_event's @c data.u64.
 *  @{
 */
static constexpr uintptr_t kq_tag_mask  = 3u;
static constexpr uintptr_t kq_ptr_mask  = ~kq_tag_mask;

/** @brief Tag word of a changelist delete: no kind, no payload.
 *
 *  @ref duct_events_unwatch is handed a descriptor alone, so a receipt for its
 *  delete names nothing the engine acts on, and one carrying this word is
 *  dropped unread. It is compared as a word of its own: unpacked, it reads as
 *  the tag kind at enum 0 with a @c nullptr payload.
 *
 *  Every other word is non-zero: a real tag carries a non-null pointer, and the
 *  waker @ref kq_wake_payload.
 */
static constexpr uintptr_t kq_tag_none = 0u;

/** @brief Payload packed into the waker's tag. Arbitrary but non-zero:
 *  @ref s_events_dispatch ignores an @c io_tag_wake payload, and the value
 *  exists only to keep the waker's word out of @ref kq_tag_none.
 */
static constexpr uintptr_t kq_wake_payload = 1u << 2;

static inline uintptr_t s_tag_pack(duct_io_tag_t kind, void *ptr)
{
    assert(((uintptr_t)ptr & kq_tag_mask) == 0u);
    return ((uintptr_t)ptr & kq_ptr_mask) | (uintptr_t)kind;
}

static inline void *s_tag_unpack(uintptr_t word, duct_io_tag_t *kind)
{
    *kind = (duct_io_tag_t)(word & kq_tag_mask);
    return (void *)(word & kq_ptr_mask);
}

/** @} */

/** @brief Store a packed tag word in @p kevp's @c udata.
 *
 *  NetBSD declares that member as @c intptr_t, everyone else as @c void *.
 *  Casting through the member's type is correct for both without naming
 *  either. Reading it back needs no help: @c (uintptr_t) accepts either
 *  shape. Set after @c EV_SET because the
 *  value's type has to be known at the point of assignment.
 */
#define kq_udata_set(kevp, word) \
    ((kevp)->udata = (typeof((kevp)->udata))(uintptr_t)(word))

/** @brief Reactor state of one I/O thread: its @c kqueue descriptor and the
 *  pending changelist.
 *
 *  This backend's body of @ref duct_events_env_t, heap-allocated on the owning
 *  I/O thread, which alone writes @c changes.
 *  @ref duct_events_kick, the one downcall reachable from another thread,
 *  issues a @c kevent of its own and never touches it.
 */
typedef struct duct_events_env {
    void (*cancel_io)(duct_sock_t fd);
    int           kq;
    unsigned      n_changes;
    struct kevent changes[kq_max_changes];
} duct_events_env_t;

/** @brief Abort on a receipt that refuses a batched change. */
static inline void s_receipt_check(const struct kevent *receipt)
{
    /* A success answers 0, a delete carries kq_tag_none and ENOENT answers
     * unwatch's unconditional pair. The kernel refuses an EV_ADD on a live
     * engine socket only on an engine fault, FreeBSD registering under
     * M_WAITOK and XNU allocating the knote Z_NOFAIL, or on a descriptor past
     * an RLIMIT_NOFILE the host lowered under it. */
    duct_fatal(receipt->data && (int)receipt->data != ENOENT
               && (uintptr_t)receipt->udata != kq_tag_none);
}

/** @brief Apply every pending change now.
 *
 *  Only @ref s_changes_push's overflow path calls this; the steady state
 *  flushes the changelist as the front half of @ref duct_events_run_loop's
 *  own @c kevent, which is the whole point of batching. It dispatches
 *  nothing, so it may run between the two halves of a watch.
 *
 *  A @c nullptr eventlist is not usable here: @c kevent stops at the first
 *  rejected change and reports it through the return value, and a rejected
 *  change is routine — @ref duct_events_unwatch deletes both filters
 *  whether or not both were registered, so @c ENOENT is expected.
 *  @c EV_RECEIPT forces every change to answer with its own @c EV_ERROR
 *  entry instead, so the whole list is processed and no real event is
 *  drained into a buffer nobody dispatches.
 *
 *  Changes are idempotent — @c EV_ADD on a live registration updates it,
 *  @c EV_DELETE on a missing one is the tolerated @c ENOENT — so an
 *  @c EINTR retry may safely resubmit the whole list.
 */
static void s_changes_flush(duct_events_env_t *env)
{
    duct_do_if(!env->n_changes, return);
    struct kevent receipts[kq_max_changes];
    for (unsigned i = 0u; i < env->n_changes; ++i)
        env->changes[i].flags |= EV_RECEIPT;
    int rc;
    do {
        rc = kevent(env->kq, env->changes, (int)env->n_changes,
                    receipts, (int)env->n_changes, &(struct timespec){ 0, 0 });
    } while (rc < 0 && errno == EINTR);
    env->n_changes = 0u;
    duct_fatal(rc < 0);
    for (int i = 0; i < rc; ++i)
        s_receipt_check(&receipts[i]);
}

/** @brief Queue one change, flushing first if the list is full.
 *
 *  @note No return value: a batched change has not reached the
 *  kernel yet, so nothing truthful can be said about it here; a refusal
 *  comes back as an @c EV_ERROR receipt, which @ref s_receipt_check aborts on.
 */
static inline void s_changes_push(duct_events_env_t *env, uintptr_t ident,
                                  int filter, unsigned flags, unsigned fflags,
                                  uintptr_t word)
{
    if (env->n_changes == kq_max_changes)
        s_changes_flush(env);
    /* Slot resolved before the macro: EV_SET expands its first argument more
     * than once on some dialects, so a post-increment inside it advances the
     * changelist several times per change. */
    auto slot = &env->changes[env->n_changes++];
    EV_SET(slot, ident, filter, flags, fflags, 0, 0);
    kq_udata_set(slot, word);
}

/** @brief Drop every pending socket-filter change for @p ident.
 *
 *  Unwatch, promote and a synchronous registration call it ahead of their own
 *  changes, so a retired tag never reaches the kernel: an @c EV_ADD left
 *  pending past unwatch and close comes back @c EBADF, which
 *  @ref s_receipt_check aborts on, and a previous owner's change applied
 *  after a synchronous registration deletes or retags it. The waker's entry
 *  stays: its filter is @c EVFILT_USER.
 */
static inline void s_changes_cancel(duct_events_env_t *env, uintptr_t ident)
{
    unsigned w = 0u;
    for (unsigned r = 0u; r < env->n_changes; ++r) {
        auto c = &env->changes[r];
        if (c->ident == ident
            && (c->filter == EVFILT_READ || c->filter == EVFILT_WRITE))
            continue;
        env->changes[w++] = env->changes[r];
    }
    env->n_changes = w;
}

/** @brief Register @p ident's read filter through a @c kevent of its own and
 *  answer whether the kernel took it. */
static bool s_read_add_now(duct_events_env_t *env, uintptr_t ident,
                           unsigned flags, uintptr_t word)
{
    s_changes_cancel(env, ident);
    struct kevent change, receipt;
    EV_SET(&change, ident, EVFILT_READ, flags | EV_RECEIPT, 0, 0, 0);
    kq_udata_set(&change, word);
    int rc;
    do {
        rc = kevent(env->kq, &change, 1, &receipt, 1, &(struct timespec){ 0, 0 });
    } while (rc < 0 && errno == EINTR);
    return rc == 1 && (receipt.flags & EV_ERROR) && receipt.data == 0;
}

/** @brief Translate one @c kevent into @c duct_io_ev_flags_t.
 *
 *  kqueue reports readiness per filter, so a descriptor both readable and
 *  writable arrives as two entries, each dispatched on its own.
 *
 *  @c EV_EOF on a conn's read filter is the peer's FIN and reads as
 *  readability alone: the bytes ahead of it are read first, and @c recv's
 *  0-byte end closes the conn. Anywhere else it is a local-end hangup.
 *  @c fflags carries the socket error when there is one, which is how a
 *  failed dial surfaces.
 *
 *  @note An @c EV_ERROR receipt never reaches here: @ref s_events_dispatch
 *  hands it to @ref s_receipt_check first.
 */
static inline duct_io_ev_flags_t s_kev_flags(const struct kevent *kev,
                                             duct_io_tag_t kind)
{
    duct_io_ev_flags_t flags = 0u;
    if (kev->filter == EVFILT_READ)
        flags = duct_or(flags, io_ev_read);
    if (kev->filter == EVFILT_WRITE)
        flags = duct_or(flags, io_ev_write);
    if (kev->flags & EV_EOF) {
        if (kev->fflags)
            flags = duct_or(flags, io_ev_error);
        if (kev->filter != EVFILT_READ || kind != io_tag_conn)
            flags = duct_or(flags, io_ev_hup);
    }
    return flags;
}

duct_events_env_t *duct_events_init(void)
{
    auto env = duct_new(duct_events_env_t);
    duct_do_if(!env, return nullptr);

    env->cancel_io = nullptr;
    env->kq = kqueue();
    duct_do_if(env->kq < 0, duct_del(env); return nullptr);
    /* kqueue() predates O_CLOEXEC and has no flags argument on any dialect;
     * an I/O thread's kqueue has no business surviving into a child image. */
    int cloexec_rc = fcntl(env->kq, F_SETFD, FD_CLOEXEC);
    duct_do_if(cloexec_rc < 0,
               close(env->kq); duct_del(env); return nullptr);

    /* EV_CLEAR so a NOTE_TRIGGER self-disarms once delivered — the eventfd
     * analog, minus the read-to-drain that os/linux/epoll/ needs. */
    struct kevent kev;
    EV_SET(&kev, kq_wake_ident, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, 0);
    kq_udata_set(&kev,
        s_tag_pack(io_tag_wake, (void *)(uintptr_t)kq_wake_payload));
    int rc;
    do {
        rc = kevent(env->kq, &kev, 1, nullptr, 0, nullptr);
    } while (rc < 0 && errno == EINTR);
    duct_do_if(rc < 0, duct_events_fini(env); return nullptr);
    return env;
}

void (*duct_events_cancel_io_of(duct_events_env_t *env))(duct_sock_t fd)
{
    return env->cancel_io;
}

void duct_events_fini(duct_events_env_t *env)
{
    close(env->kq);
    duct_del(env);
}

void duct_events_rx_stall([[maybe_unused]] duct_sock_t fd,
                          [[maybe_unused]] void *rx_io_priv)
{
    /* No-op for EV_CLEAR mode, same as EPOLLET. */
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
        size_t nread = 0u, seg = 0u;
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

/* Registered at once, as a listener is: the attach acts on the answer, and a
 * host descriptor kqueue cannot watch is refused there. */
bool duct_events_watch_device(duct_events_env_t *env, void *device, void *tag_ptr)
{
    duct_sock_t fd = (duct_sock_t)(intptr_t)device;
    duct_do_if(fd == duct_sock_bad, return false);
    return s_read_add_now(env, (uintptr_t)fd, EV_ADD | EV_CLEAR,
                          s_tag_pack(io_tag_conn, tag_ptr));
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

bool duct_events_watch(duct_events_env_t *env, duct_sock_t fd,
                       duct_io_tag_t kind, void *tag_ptr,
                       [[maybe_unused]] duct_xport_t xport_type)
{
    duct_do_if(fd == duct_sock_bad, return false);
    auto word = s_tag_pack(kind, tag_ptr);
    auto ident = (uintptr_t)fd;
    switch (kind) {
    case io_tag_listener:
        /* Level-triggered on purpose, no EV_CLEAR: independent of the
         * listener's own read side, which isn't proven to drain-to-EAGAIN.
         * EVFILT_WRITE stays unregistered even for a dgram_tx_outbox
         * listener — a UDP socket is writable almost always, so an armed
         * level-triggered write filter spins the wait every turn regardless
         * of traffic; @ref duct_events_dgram_tx_interest adds it reactively,
         * only while a real EAGAIN is outstanding. */
        /* At once: bind waits on this result, and a failed registration
         * destroys the listener. */
        return s_read_add_now(env, ident, EV_ADD, word);
    case io_tag_pre_conn:
        switch (((duct_pre_conn_t *)tag_ptr)->kind) {
        case pre_conn_probe:
            /* Level-triggered, matching the listener: a read that leaves the
             * first bytes short keeps the filter armed for the rest. */
            s_changes_push(env, ident, EVFILT_READ, EV_ADD, 0, word);
            break;
        case pre_conn_dial:
            /* A dial resolves on the write filter; EV_EOF there carries the
             * failure, with the errno in fflags. Its read filter stays off:
             * the dispatch of its event frees the pre_conn, so no batch may
             * carry a second event naming it. */
            s_changes_push(env, ident, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, word);
            break;
        }
        break;
    case io_tag_conn:
        /* BSD UDP demuxes a connected per-peer socket ahead of its
         * unconnected listener, so xport_type doesn't narrow read interest
         * the way it must on Winsock. */
        s_changes_push(env, ident, EVFILT_READ,  EV_ADD | EV_CLEAR, 0, word);
        s_changes_push(env, ident, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, word);
        break;
    case io_tag_wake:
    case io_tag_rio_cq:
        duct_unreachable();
    }
    return true;
}

bool duct_events_promote(duct_events_env_t *env, duct_sock_t fd, void *tag_ptr)
{
    duct_do_if(fd == duct_sock_bad, return false);
    /* Same interest the pre_conn_dial case of duct_events_watch already
     * armed — only the tag changes. EV_ADD on a live registration updates
     * it directly without a separate modify step. */
    auto word = s_tag_pack(io_tag_conn, tag_ptr);
    auto ident = (uintptr_t)fd;
    /* Promotion retires the pre_conn tag: its pending registrations go before
     * the caller frees it. */
    s_changes_cancel(env, ident);
    s_changes_push(env, ident, EVFILT_READ,  EV_ADD | EV_CLEAR, 0, word);
    s_changes_push(env, ident, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, word);
    return true;
}

void duct_events_unwatch(duct_events_env_t *env, duct_sock_t fd,
                         [[maybe_unused]] void *rx_io_priv)
{
    duct_do_if(fd == duct_sock_bad, return);
    auto ident = (uintptr_t)fd;
    s_changes_cancel(env, ident);
    /* Both filters unconditionally: what was registered depends on the tag
     * kind, and the caller no longer knows it. A filter never added answers
     * ENOENT, which every backend's unwatch contract tolerates. A close drops
     * the registrations by itself; unwatch's contract includes no close. */
    s_changes_push(env, ident, EVFILT_READ,  EV_DELETE, 0, kq_tag_none);
    s_changes_push(env, ident, EVFILT_WRITE, EV_DELETE, 0, kq_tag_none);
}

void duct_events_kick(duct_events_env_t *env)
{
    /* Reached from another thread. kevent() itself is safe there; the
     * pending changelist is not, so this path never touches it. */
    struct kevent kev;
    EV_SET(&kev, kq_wake_ident, EVFILT_USER, 0, NOTE_TRIGGER, 0, 0);
    kq_udata_set(&kev,
        s_tag_pack(io_tag_wake, (void *)(uintptr_t)kq_wake_payload));
    int rc;
    do {
        rc = kevent(env->kq, &kev, 1, nullptr, 0, &(struct timespec){ 0, 0 });
    } while (rc < 0 && errno == EINTR);
}

void duct_events_dgram_tx_interest(duct_events_env_t *env,
                                   duct_listener_t *listener, bool armed)
{
    /* Level-triggered, like the listener's read side: the outbox drain stops
     * with work queued short of would-block, and an edge consumed then never
     * fires again. Disarming is an EV_DELETE, kqueue keeping no interest word
     * to clear, and carries kq_tag_none as every delete does. */
    if (armed)
        s_changes_push(env, (uintptr_t)listener->listen_fd, EVFILT_WRITE,
                       EV_ADD, 0, s_tag_pack(io_tag_listener, listener));
    else
        s_changes_push(env, (uintptr_t)listener->listen_fd, EVFILT_WRITE,
                       EV_DELETE, 0, kq_tag_none);
}

void duct_events_listener_rx_interest(duct_events_env_t *env,
                                      duct_listener_t *listener, bool want)
{
    if (want)
        s_changes_push(env, (uintptr_t)listener->listen_fd, EVFILT_READ,
                       EV_ADD, 0, s_tag_pack(io_tag_listener, listener));
    else
        s_changes_push(env, (uintptr_t)listener->listen_fd, EVFILT_READ,
                       EV_DELETE, 0, kq_tag_none);
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
 *  Each accepted descriptor goes to @ref duct_io_on_accept, which starts that pace;
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
}

/** @brief Dispatch one @c kevent, routed by its tag kind. */
static inline void s_events_dispatch(const struct kevent *kev)
{
    if (kev->flags & EV_ERROR) {
        s_receipt_check(kev);
        return;
    }
    duct_io_tag_t kind;
    auto tag = s_tag_unpack((uintptr_t)kev->udata, &kind);
    auto flags = s_kev_flags(kev, kind);
    switch (kind) {
    case io_tag_wake:
        /* EV_CLEAR already disarmed the trigger; the payload is a stand-in
         * and carries nothing to read. */
        duct_io_on_wake();
        break;
    case io_tag_listener:
        auto listener = (duct_listener_t *)tag;
        if (duct_has(flags, duct_or(io_ev_error, io_ev_hup))) {
            /* UDP: an error here is a per-destination async ICMP report
             * (e.g. Port Unreachable once some registered peer goes away),
             * not listener socket failure -- getsockopt(SO_ERROR) reads and
             * clears it. Left unread it can keep re-arming, and the read
             * branch below never runs again, silently refusing every future
             * peer's registration on this listener. A stream listener's own
             * accept socket erroring here is a real fault -- still bail. */
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
            duct_io_on_pre_conn_dialed(pre_conn, !(kev->flags & EV_EOF) ? rc_ok
                                                 : kev->fflags == ECONNREFUSED ? rc_conn_refused : rc_fatal);
            break;
        }
        break;
    case io_tag_conn:
        duct_io_on_event(&(duct_io_event_t){ kind, tag, flags });
        break;
    case io_tag_rio_cq:
        duct_unreachable();
    }
}

void duct_events_run_loop(duct_events_env_t *env, bool _Atomic *shutdown)
{
    struct kevent events[kq_max_events];
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
        struct timespec ts, *tsp = nullptr;
        if (timeout >= 0) {
            ts = (struct timespec){ .tv_sec = timeout / 1000,
                                    .tv_nsec = (long)(timeout % 1000) * 1000000L };
            tsp = &ts;
        }
        /* One syscall carries the pending changelist and the wait together.
         * On EINTR the man page leaves it unspecified how
         * much of the changelist was applied; resubmitting is safe because
         * every change built here is idempotent. */
        do {
            n = kevent(env->kq, env->changes, (int)env->n_changes,
                       events, kq_max_events, tsp);
        } while (n < 0 && errno == EINTR);
        env->n_changes = 0u;
        duct_do_if(n < 0, return);

        in_window = duct_spin_next(&spin, n > 0, duct_ticks_mono_ns());
        if (n == 0)
            duct_cpu_relax();

        for (int i = 0; i < n; ++i)
            s_events_dispatch(&events[i]);
    }
}
