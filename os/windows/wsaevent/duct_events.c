/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_events.c
 *  @brief Windows WSAEventSelect reactor: one WSAEVENT per registered fd,
 *  WaitForMultipleObjects + WSAEnumNetworkEvents dispatch, rotating rescan
 *  for fairness past the first signaled handle.
 *
 *  @ref events_max_handles (WSA_MAXIMUM_WAIT_EVENTS, 64) bounds one I/O
 *  thread's whole wait set shared by listeners, pre_conns and conns; slot 0
 *  is the cross-thread wake event, slot 1 the RIO completion queue's notify
 *  event once RIO resolves available; @ref duct_events_watch fails past the
 *  cap. Low-fanout deployments only (e.g. client-side apps).
 *
 *  A RIO-active @c x_udp_shared listener never reaches this reactor's
 *  WSAEventSelect path at all: its RX and TX complete through the RIO
 *  completion queue instead, dispatched off the slot-1 wake.
 */

#include "duct_events.h"
#include "duct_io.h"

#include "duct_listener.h"
#include "duct_pre_conn.h"
#include "duct_rio.h"
#include "duct_ticks.h"
#include "duct_xport.h"

#include <limits.h>
#include <winsock2.h>
#include <ws2tcpip.h>

/** @brief I/O thread's whole wait set — a hard OS ceiling on
 *  @c WaitForMultipleObjects's handle count, not tunable;
 *  independent of @c duct_runtime_max_conns.
 */
static constexpr unsigned events_max_handles = WSA_MAXIMUM_WAIT_EVENTS;

/** @brief RIO extension function table, @c nullptr where RIO is off.
 *  Set once by @ref s_events_ctor. Every RIO object of this backend, the
 *  completion queue, a ring and a pool, exists only while it is non-null.
 */
static RIO_EXTENSION_FUNCTION_TABLE *s_rio;

/** @brief A registered handle's tag and its current WSAEventSelect
 *  interest. @c handle dups @c env->handles[this slot's index]
 *  so @ref duct_events_drive_rx / @ref duct_events_drive_tx / @ref
 *  duct_events_rx_stall can re-arm through @c io_priv.
 */
typedef struct {
    duct_sock_t   fd;
    duct_io_tag_t kind;
    void         *tag;
    void         *watched_handle;
    long          interest;
    WSAEVENT      handle;
} duct_events_slot;

/** @brief One RIO-active @c x_udp_shared listener's own state — allocated
 *  only for a listener this backend actually wired RIO into, never for a
 *  TCP listener or a non-RIO UDP one.
 */
typedef struct listener_ctx {
    duct_listener_t      *listener; /**< nullptr once teardown starts —
                                      *  see @c duct_events_unwatch. */
    struct listener_ctx  *next;     /**< Intrusive @c env->rio_listeners link. */
    duct_rio_rx_t        *rio_rx;
} listener_ctx_t;

typedef struct probe_park {
    duct_sock_t        fd;
    duct_pre_conn_t   *pre_conn;
    struct probe_park *next;
} probe_park_t;

/** @brief Dense @c handles[0..n_entries) for WaitForMultipleObjects
 *  with parallel @c slots[] tag array; 0 is reserved for wake event.
 *  Removal swap-compacts with the last live entry.
 */
typedef struct duct_events_env {
    void (*cancel_io)(duct_sock_t fd);
    HANDLE handles[events_max_handles];
    duct_events_slot slots[events_max_handles];
    unsigned n_entries;
    /** @brief @c nullptr if RIO is unavailable.
     *  @see @ref duct_events_rio_cq_ready. */
    RIO_CQ   rio_cq;
    /** @brief @c rio_cq's own cumulative admission budget: @c depth is
     *  its current size, @c used is how much every RIO-active listener
     *  has claimed so far.
     *  Grown together by @ref duct_rio_cq_ensure; @c used never shrinks
     *  back down when a listener later closes. */
    DWORD    rio_cq_depth,
             rio_cq_used;
    listener_ctx_t *rio_listeners; /**< Intrusive list of this env's own
                                     *  RIO-active listener ctxs, threaded
                                     *  via @c listener_ctx::next. */
    probe_park_t *probe_parks;
    WSAEVENT      probe_event;
    unsigned      probe_slot;
} duct_events_env_t;

/** @brief Resolve the RIO extension function table. */
static void s_events_ctor(void) __attribute__((constructor(DUCT_CTOR_PRI_STATE)));
static void s_events_ctor(void)
{
    s_rio = duct_rio_resolve();
}

bool duct_events_rio_available(void)
{
    return s_rio != nullptr;
}

bool duct_events_dgram_shared_rio_capable(void)
{
    return s_rio != nullptr;
}

duct_events_env_t *duct_events_init(void)
{
    auto env = duct_new(duct_events_env_t);
    duct_do_if(!env, return nullptr);
    auto wake = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    duct_do_if(!wake, duct_del(env); return nullptr);
    env->handles[0] = wake;
    env->slots[0] = (duct_events_slot){ .fd = duct_sock_bad, .kind = io_tag_wake, .handle = wake };
    env->n_entries = 1u;
    env->rio_cq = nullptr;
    env->rio_listeners = nullptr;
    env->probe_parks = nullptr;
    env->probe_event = nullptr;
    env->probe_slot = UINT_MAX;
    env->cancel_io = nullptr;
    if (s_rio) {
        auto rio_ev = WSACreateEvent();
        if (rio_ev != WSA_INVALID_EVENT) {
            /* NotifyReset=TRUE: RIONotify both clears and re-arms rio_ev in
             * one call. Draining via RIODequeueCompletion alone never resets
             * it -- s_on_rio_completion's and s_drain_rio_completions' own
             * trailing RIONotify call re-arms for the next batch. */
            env->rio_cq = duct_rio_cq_create(s_rio,
                &(RIO_NOTIFICATION_COMPLETION){
                    .Type = RIO_EVENT_COMPLETION,
                    .Event = { .EventHandle = rio_ev, .NotifyReset = TRUE },
                },
                &env->rio_cq_depth, &env->rio_cq_used);
            if (env->rio_cq) {
                env->handles[1] = rio_ev;
                env->slots[1] = (duct_events_slot){ .fd = duct_sock_bad, .kind = io_tag_rio_cq, .handle = rio_ev };
                env->n_entries = 2u;
            } else
                WSACloseEvent(rio_ev);
        }
    }
    return env;
}

void (*duct_events_cancel_io_of(duct_events_env_t *env))(duct_sock_t fd)
{
    return env->cancel_io;
}

bool duct_events_rio_cq_ready(duct_events_env_t *env)
{
    return env->rio_cq != nullptr;
}

/** @brief Settle @p env's outstanding RIO receives before teardown proceeds
 *  without them.
 *  Repeats @ref duct_rio_cq_flush, waiting on the completion queue's own
 *  event between passes: a posted receive only aborts into a completion once
 *  its socket is closed, which @ref duct_events_fini does just before calling
 *  this.
 *
 *  @todo 500ms is expected to be enough, but maybe better to use a
 *  strict overall completion counter instead.
 */
static void s_drain_rio_completions(duct_events_env_t *env, bool owed)
{
    duct_do_if(!env->rio_cq, return);
    duct_rio_cq_flush(s_rio,env->rio_cq);
    duct_do_if(!owed, return);
    uint64_t deadline = duct_ticks_mono_ns() + 500'000'000u;
    for (;;) {
        uint64_t now = duct_ticks_mono_ns();
        if (now >= deadline
            || WaitForSingleObject(env->handles[1], (DWORD)((deadline - now + 999'999u) / 1'000'000u))
                   != WAIT_OBJECT_0)
            break;
        duct_rio_cq_flush(s_rio,env->rio_cq);
    }
}

void duct_events_fini(duct_events_env_t *env)
{
    /* Every conn/pre_conn is already unwatched by duct_io_cleanup's walk;
     * a leftover listener, RIO-active or not, can still sit here --
     * neither loop below goes through duct_events_unwatch for it. */
    bool owed = env->rio_listeners != nullptr;
    for (auto ctx = env->rio_listeners; ctx; ) {
        auto next = ctx->next;
        auto listener = ctx->listener;
        ctx->listener = nullptr;
        closesocket(listener->listen_fd);
        listener->listen_fd = duct_sock_bad; /* duct_listener_destroy closes a listen_fd still set */
        duct_discard duct_rio_rx_close(s_rio,ctx->rio_rx);
        ctx = next;
    }
    env->rio_listeners = nullptr;
    s_drain_rio_completions(env, owed);
    for (unsigned i = 1u; i < env->n_entries; ++i) {
        auto slot = &env->slots[i];
        if (slot->fd != duct_sock_bad)
            duct_discard WSAEventSelect(slot->fd, nullptr, 0);
        if (slot->handle)
            duct_discard WSACloseEvent(slot->handle);
    }
    CloseHandle(env->handles[0]);
    if (env->rio_cq)
        duct_rio_cq_close(s_rio, env->rio_cq);
    duct_del(env);
}

/** @brief Add or drop @p event in @p slot's WSAEventSelect set, reselecting only
 *  on a change. */
static void s_read_interest(duct_events_slot *slot, long event, bool want)
{
    long bits = want ? slot->interest | event : slot->interest & ~event;
    if (bits == slot->interest)
        return;
    duct_discard WSAEventSelect(slot->fd, slot->handle, bits);
    slot->interest = bits;
}

/** @brief Name the WSAEventSelect read event of @p listener's socket: @c FD_READ for a datagram
 *  listener, @c FD_ACCEPT for any other. */
static inline long s_listener_read_event(const duct_listener_t *listener)
{
    return listener->xport_type == x_udp ? FD_READ : FD_ACCEPT;
}

/** @brief Remove slot @p i from @p env, moving the last slot into its place.
 *  A moved socket slot is handed to duct_io_on_relocate; a device slot is found by its
 *  handle and needs none. A set that was full sets the event of each stream listener whose
 *  interest holds FD_ACCEPT, which a held one's lacks: a client queued while the set was full
 *  had its FD_ACCEPT enumerated with no accept, which no WSAEventSelect records again, and the
 *  dispatch's accept takes it. */
static void s_slot_drop(duct_events_env_t *env, unsigned i)
{
    unsigned last = --env->n_entries;
    env->handles[i] = env->handles[last];
    env->slots[i] = env->slots[last];
    if (env->probe_slot == last)
        env->probe_slot = i;
    if (i != last && env->slots[i].fd != duct_sock_bad)
        duct_io_on_relocate(env->slots[i].kind, env->slots[i].tag, &env->slots[i]);
    if (last != events_max_handles - 1u)
        return;
    for (unsigned k = 1u; k < env->n_entries; ++k) {
        auto slot = &env->slots[k];
        if (slot->kind == io_tag_listener && (slot->interest & FD_ACCEPT))
            duct_discard SetEvent(slot->handle);
    }
}

void duct_events_rx_stall(duct_sock_t fd, void *rx_io_priv)
{
    auto slot = (duct_events_slot *)rx_io_priv;
    duct_fatal(!slot || slot->fd != fd);
    s_read_interest(slot, FD_READ, false);
}

void duct_events_drive_rx(void *tag)
{
    duct_result_t rc = rc_again;
    duct_io_xfer_t r = { .fd = duct_sock_bad };
    while (duct_io_rx_reserve(tag, &r)) {
        size_t nread = 0u,
               seg = 0u;
        rc = duct_xread(r.fd, r.xport_type, (duct_view_u8){ .data = r.buf, .size = r.size },
                             &nread, r.ctx, 0, &seg);
        if (rc == rc_ok) {
            duct_io_rx_commit(tag, nread, seg);
            continue;
        }
        if (rc == rc_drop) {
            /* Truncated datagram, already discarded by Winsock itself
             * (WSAEMSGSIZE) — nothing to commit, keep draining. Reset rc
             * so a stale rc_drop never reaches duct_io_rx_done below. */
            rc = rc_again;
            continue;
        }
        break;
    }
    /* Re-arm FD_READ unconditionally — reaching this function proves whatever
     * earlier cleared it via duct_events_rx_stall no longer applies,
     * regardless of what this pass itself read. r.fd is duct_sock_bad only
     * for a stale tag — a "buffer still full" reserve failure fills it in. */
    if (r.fd != duct_sock_bad) {
        auto slot = (duct_events_slot *)r.io_priv;
        duct_fatal(!slot || slot->fd != r.fd);
        s_read_interest(slot, FD_READ, true);
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
    duct_io_tx_write_armed_set(tag, filled);
    duct_io_tx_done(tag, rc);
}

/** @brief Find @p fd's live slot in @p env.
 *  @return UINT_MAX if not registered.
 */
static inline unsigned s_find_slot(duct_events_env_t *env, duct_sock_t fd)
{
    for (unsigned i = 0u; i < env->n_entries; ++i)
        if (env->slots[i].fd == fd)
            return i;
    return UINT_MAX;
}

/** @brief Resolve @p fd's slot.
 *  Prefers the direct pointer @ref duct_io_on_relocate cached in
 *  @p io_priv, falls back to @ref s_find_slot.
 *  @note @c UINT_MAX is a legitimate return value, @b not enforced:
 *  @ref duct_events_unwatch tolerates @p fd it never registered.
 */
static inline unsigned
s_slot_lookup(duct_events_env_t *env, duct_sock_t fd, void *io_priv)
{
    auto p = (duct_events_slot *)io_priv;
    return p && p->fd == fd ? (unsigned)(p - env->slots)
                            : s_find_slot(env, fd);
}

/** @brief Set up @p ctx's RIO RX ring, request queue, and, when the
 *  listener has a TX outbox, its TX pool.
 *  Self-cleaning: a later step's failure frees whatever an earlier one
 *  already allocated. Called once, from @ref s_listener_create_rio, before
 *  the first post.
 */
static bool s_rio_dgram_init(duct_events_env_t *env, listener_ctx_t *ctx)
{
    auto ring = duct_rio_rx_create(s_rio,ctx, ctx->listener);
    duct_do_if(!ring, return false);
    ctx->rio_rx = ring;

    unsigned depth = duct_rio_rx_depth(ring);
    DWORD need = depth + duct_rio_tx_depth;
    /* Must match RIOCreateRequestQueue's own MaxOutstandingReceive +
     * MaxOutstandingSend below -- duct_rio_cq_ensure trusts need to
     * already reflect what that call is about to spend. */
    bool sized = duct_rio_cq_ensure(s_rio,env->rio_cq, &env->rio_cq_depth, &env->rio_cq_used, need);
    duct_do_if(!sized, goto fail);
    RIO_RQ rq = s_rio->RIOCreateRequestQueue(ctx->listener->listen_fd,
        depth, 1u, duct_rio_tx_depth, 1u, env->rio_cq, env->rio_cq, ctx);
    duct_do_if(!rq, goto fail);
    duct_rio_rx_arm(ring, rq);
    duct_do_if(!ctx->listener->dgram_tx_outbox, return true);
    bool ok = duct_rio_tx_create(s_rio, rq, ctx->listener);
    duct_do_if(!ok, goto fail);
    return true;
fail:
    duct_rio_rx_destroy(s_rio,ring);
    ctx->rio_rx = nullptr;
    return false;
}

/** @brief Allocate @p listener's RIO ctx, set it up and arm its first
 *  receive. Called only once the caller has already decided @p listener
 *  qualifies for RIO; links the ctx onto @p env's rio_listeners list on
 *  success.
 */
static bool s_listener_create_rio(duct_events_env_t *env, duct_listener_t *listener)
{
    auto ctx = duct_new(listener_ctx_t);
    duct_do_if(!ctx, return false);
    ctx->listener = listener;
    bool ok = s_rio_dgram_init(env, ctx);
    duct_do_if(!ok, duct_del(ctx); return false);
    bool posted = duct_rio_rx_prime(s_rio,ctx->rio_rx);
    duct_do_if(!posted,
        duct_rio_rx_destroy(s_rio,ctx->rio_rx);
        duct_events_dgram_tx_pool_free(listener);
        duct_del(ctx);
        return false
    );
    ctx->next = env->rio_listeners;
    env->rio_listeners = ctx;
    return true;
}

static bool s_probe_park_watch(duct_events_env_t *env, duct_sock_t fd, void *tag_ptr)
{
    bool armed = env->probe_slot != UINT_MAX;
    duct_do_if(!armed && env->n_entries >= events_max_handles, return false);
    auto ev = armed ? env->probe_event : WSACreateEvent();
    duct_do_if(!armed && ev == WSA_INVALID_EVENT, return false);
    auto park = duct_new(probe_park_t);
    duct_do_if(!park, goto fail);
    *park = (probe_park_t){ .fd = fd, .pre_conn = (duct_pre_conn_t *)tag_ptr };
    int rc = WSAEventSelect(fd, ev, FD_READ | FD_CLOSE);
    duct_do_if(rc == SOCKET_ERROR, duct_del(park); goto fail);
    park->next = env->probe_parks;
    env->probe_parks = park;
    duct_do_if(armed, return true);
    env->probe_event = ev;
    env->probe_slot = env->n_entries++;
    env->handles[env->probe_slot] = ev;
    env->slots[env->probe_slot] = (duct_events_slot){ .kind = io_tag_pre_conn,
                                                      .interest = FD_READ | FD_CLOSE,
                                                      .handle = ev };
    return true;
fail:
    if (!armed)
        WSACloseEvent(ev);
    return false;
}

static bool s_probe_park_detach(duct_events_env_t *env, duct_sock_t fd)
{
    for (probe_park_t **pp = &env->probe_parks; *pp; pp = &(*pp)->next) {
        if ((*pp)->fd != fd)
            continue;
        auto park = *pp;
        *pp = park->next;
        duct_del(park);
        duct_discard WSAEventSelect(fd, nullptr, 0);
        if (!env->probe_parks && env->probe_slot != UINT_MAX) {
            duct_discard WSACloseEvent(env->probe_event);
            s_slot_drop(env, env->probe_slot);
            env->probe_slot = UINT_MAX;
            env->probe_event = nullptr;
        }
        return true;
    }
    return false;
}

static void s_probe_park_dispatch(duct_events_env_t *env)
{
    for (auto p = env->probe_parks; p; ) {
        auto next = p->next;
        WSANETWORKEVENTS ne;
        if (WSAEnumNetworkEvents(p->fd, env->probe_event, &ne) != SOCKET_ERROR
            && (ne.lNetworkEvents & (FD_READ | FD_CLOSE)))
            duct_io_on_pre_conn_readable(p->pre_conn);
        p = next;
    }
}

bool duct_events_watch(duct_events_env_t *env, duct_sock_t fd,
                       duct_io_tag_t kind, void *tag_ptr,
                       duct_xport_t xport_type)
{
    duct_do_if(fd == duct_sock_bad, return false);
    if (kind == io_tag_listener) {
        auto listener = (duct_listener_t *)tag_ptr;
        if (listener->xport_type == x_udp && listener->dgram_tx_outbox && s_rio)
            /* Never reaches WSACreateEvent/WSAEventSelect below -- the RIO
             * completion queue dispatches this listener's RX and TX
             * instead, so it costs this env none of its events_max_handles
             * budget. */
            return s_listener_create_rio(env, listener);
    }
    if (kind == io_tag_pre_conn && ((duct_pre_conn_t *)tag_ptr)->kind == pre_conn_probe)
        return s_probe_park_watch(env, fd, tag_ptr);
    duct_do_if(env->n_entries >= events_max_handles, return false);
    long bits = 0;
    switch (kind) {
    case io_tag_listener:
        auto listener = (duct_listener_t *)tag_ptr;
        bits = s_listener_read_event(listener);
        /* FD_WRITE re-arms natively on its own (fires once at register,
         * again only after a send() actually fails WSAEWOULDBLOCK and room
         * later frees up — this reactor's io_tag_conn reconcile dance
         * further down is not needed for it).
         * Registered once here, never touched again. */
        if (listener->dgram_tx_outbox)
            bits |= FD_WRITE;
        break;
    case io_tag_pre_conn:
        switch (((duct_pre_conn_t *)tag_ptr)->kind) {
        case pre_conn_dial:
            bits = FD_CONNECT | FD_READ | FD_WRITE | FD_CLOSE;
            break;
        case pre_conn_probe:
            duct_unreachable();
        }
        break;
    case io_tag_conn:
        bits = FD_READ | FD_WRITE | FD_CLOSE;
        /* No Winsock SO_REUSEPORT equivalent demuxes a connected per-peer
         * datagram socket ahead of its shared listener; its RX arrives via
         * the listener's classification/dgram_peers path instead. Only
         * ever reaches this case for an accepted leg -- a client dial's
         * x_udp_peer
         * conn resolves through duct_events_promote instead (pre_conn_dial,
         * full conn interest, no narrowing), never here.
         */
        if (xport_type == x_udp_peer)
            bits &= ~FD_READ;
        break;
    default:
        return false;
    }
    auto hEvent = WSACreateEvent();
    duct_do_if(hEvent == WSA_INVALID_EVENT, return false);

    int rc = WSAEventSelect(fd, hEvent, bits);        
    duct_do_if(rc == SOCKET_ERROR,
        WSACloseEvent(hEvent);
        return false
        /* TODO: process WSAGetLastError() */
    );
    unsigned i = env->n_entries++;
    env->handles[i] = hEvent;
    env->slots[i] = (duct_events_slot){ .fd = fd, .kind = kind, .tag = tag_ptr, .interest = bits, .handle = hEvent };
    duct_io_on_relocate(kind, tag_ptr, &env->slots[i]);
    return true;
}

void duct_events_unwatch(duct_events_env_t *env, duct_sock_t fd, void *rx_io_priv)
{
    if (fd == duct_sock_bad)
        return;
    if (s_probe_park_detach(env, fd))
        return;
    for (listener_ctx_t **pp = &env->rio_listeners; *pp; pp = &(*pp)->next) {
        if ((*pp)->listener->listen_fd != fd)
            continue;
        /* Unlink and mark closing -- never registered in slots[]/handles[]
         * to begin with, so there is nothing here to WSAEventSelect or
         * WSACloseEvent. The eventual closesocket on this fd generates
         * the abort completion that frees ctx and, once its own sends
         * finish, the TX pool. */
        auto ctx = *pp;
        *pp = ctx->next;
        ctx->listener = nullptr;
        duct_discard duct_rio_rx_close(s_rio,ctx->rio_rx);
        return;
    }
    unsigned i = s_slot_lookup(env, fd, rx_io_priv);
    if (i == UINT_MAX)
        return; /* never registered or already removed — tolerable */
    duct_discard WSAEventSelect(fd, nullptr, 0);
    duct_discard WSACloseEvent(env->handles[i]);
    s_slot_drop(env, i);
}

/** @brief Index of the device slot watching @p handle, @c UINT_MAX if none.
 *  Skips slot 0 and matches on @c fd == @c duct_sock_bad, which the wake and
 *  RIO-CQ slots also carry — their @c watched_handle stays null, so a real
 *  device handle never collides with them.
 */
static unsigned s_device_slot(duct_events_env_t *env, const void *handle)
{
    for (unsigned i = 1u; i < env->n_entries; ++i)
        if (env->slots[i].fd == duct_sock_bad
            && env->slots[i].watched_handle == handle)
            return i;
    return UINT_MAX;
}

/* The slot takes fd = duct_sock_bad and no WSAEventSelect: the handle is
 * already waitable, and there is no socket to enumerate events on. Its own
 * WSAEVENT stays null because none was created here, and duct_events_fini
 * skips the slot on that same fd test, so the borrowed handle is never
 * closed. A duplicate is refused because unwatch matches by handle alone. */
bool duct_events_watch_device(duct_events_env_t *env, void *handle, void *tag_ptr)
{
    duct_do_if(env->n_entries >= events_max_handles, return false);
    unsigned dup = s_device_slot(env, handle);
    duct_do_if(dup != UINT_MAX, return false);
    unsigned i = env->n_entries++;
    env->handles[i] = (HANDLE)handle;
    env->slots[i] = (duct_events_slot){
        .fd = duct_sock_bad,
        .kind = io_tag_conn,
        .tag = tag_ptr,
        .watched_handle = handle,
        .handle = nullptr,
    };
    return true;
}

void duct_events_device_rx_interest([[maybe_unused]] duct_events_env_t *env,
                                    [[maybe_unused]] void *device,
                                    [[maybe_unused]] bool want)
{
}

void duct_events_unwatch_device(duct_events_env_t *env, void *handle)
{
    unsigned i = s_device_slot(env, handle);
    duct_do_if(i == UINT_MAX, return);
    s_slot_drop(env, i);
}

bool duct_events_promote(duct_events_env_t *env, duct_sock_t fd, void *tag_ptr)
{
    unsigned i = s_find_slot(env, fd);
    if (i == UINT_MAX) {
        duct_do_if(!s_probe_park_detach(env, fd), return false);
        duct_do_if(env->n_entries >= events_max_handles, return false);
        auto ev = WSACreateEvent();
        duct_do_if(ev == WSA_INVALID_EVENT, return false);
        int rc = WSAEventSelect(fd, ev, FD_READ | FD_WRITE | FD_CLOSE);
        duct_do_if(rc == SOCKET_ERROR, WSACloseEvent(ev); return false);
        i = env->n_entries++;
        env->handles[i] = ev;
        env->slots[i] = (duct_events_slot){ .fd = fd, .kind = io_tag_conn, .tag = tag_ptr,
                                            .interest = FD_READ | FD_WRITE | FD_CLOSE,
                                            .handle = ev };
        duct_io_on_relocate(io_tag_conn, tag_ptr, &env->slots[i]);
        return true;
    }
    /* Full conn interest whatever the pre_conn carried -- pre_conn_probe
     * selects FD_READ and FD_CLOSE. No x_udp_peer narrowing either: a dialed
     * x_udp_peer conn holds a real unshared socket. */
    long bits = FD_READ | FD_WRITE | FD_CLOSE;
    int rc = WSAEventSelect(fd, env->handles[i], bits);
    duct_do_if(rc == SOCKET_ERROR, return false);
    env->slots[i].kind = io_tag_conn;
    env->slots[i].tag = tag_ptr;
    env->slots[i].interest = bits;
    duct_io_on_relocate(io_tag_conn, tag_ptr, &env->slots[i]);
    return true;
}


void duct_events_kick(duct_events_env_t *env)
{
    SetEvent(env->handles[0]);
}

void duct_events_dgram_tx_interest([[maybe_unused]] duct_events_env_t *env,
                                   [[maybe_unused]] duct_listener_t *listener,
                                   [[maybe_unused]] bool armed)
{
    /* No-op: FD_WRITE re-arms natively on its own here (see the comment on
     * its bit in duct_events_watch's io_tag_listener case) — no
     * unconditional-armed busy-spin to guard against on this backend. */
}

/* A stream listener given its interest back has its event set too, and its loop accepts on any
 * signal: the reselect alone signals a client queued while it was off only where an accept since
 * its last report re-enabled FD_ACCEPT. */
void duct_events_listener_rx_interest(duct_events_env_t *env, duct_listener_t *listener, bool want)
{
    unsigned i = s_find_slot(env, listener->listen_fd);
    duct_do_if(i == UINT_MAX, return);
    long event = s_listener_read_event(listener);
    s_read_interest(&env->slots[i], event, want);
    if (want && event == FD_ACCEPT)
        duct_discard SetEvent(env->slots[i].handle);
}

bool duct_events_dgram_tx_pool_alloc(duct_listener_t *listener)
{
    if (!listener->dgram_tx_outbox || !s_rio)
        return true;
    return duct_listener_tx_slots_new(listener, sizeof(struct sockaddr_storage), duct_rio_tx_depth);
}

void duct_events_dgram_tx_pool_free(duct_listener_t *listener)
{
    if (listener->dgram_tx_rio) {
        duct_rio_tx_free(listener);
        return;
    }
    auto pools = listener->tx_slots;
    listener->tx_slots = nullptr;
    duct_do_if(!pools, return);
    duct_listener_tx_slots_free(pools);
}

bool duct_events_dgram_tx_kick([[maybe_unused]] duct_events_env_t *env,
                               duct_listener_t *listener)
{
    if (!listener->dgram_tx_rio)
        return false;
    duct_rio_tx_drain(s_rio,listener);
    return true;
}

duct_x_slot_hooks_t duct_events_x_slot_hooks(void)
{
    return s_rio ? duct_rio_slot_hooks(s_rio) : (duct_x_slot_hooks_t){};
}

/** @brief Accept from @p listener until its queue is empty, an accept fails, @p env has no room,
 *  a pace holds it or a want of descriptors parks it.
 *  Dispatches each via @ref duct_io_on_accept, which starts that pace; @ref duct_io_accept
 *  parks the listener. A conn accepted past the
 *  wait set is one @ref duct_events_watch refuses, so a full @p env leaves the queue alone until
 *  @ref s_slot_drop frees a slot and wakes the listener.
 */
static inline void s_handle_accept(duct_events_env_t *env,
                                   duct_listener_t *listener)
{
    duct_sock_t fd;
    struct sockaddr_storage addr;
    while (!duct_listener_held(listener) && env->n_entries < events_max_handles
           && duct_io_accept(listener, &fd, &addr) == rc_ok) {
        auto peer = duct_io_peer_from_sockaddr((struct sockaddr *)&addr);
        duct_io_on_accept(listener, fd, &peer);
    }
}


/** @brief Check if @p w is a signaled-index result of @c WaitForMultipleObjects;
 *  @c WAIT_TIMEOUT / @c WAIT_FAILED exceed @p count, so the range tells them apart.
 */
static inline bool s_wait_signaled(DWORD w, unsigned count)
{
    return w < count;
}
 
/** @brief One zero-timeout signaled-handle lookup scanning [base, n) and
 *  [0, base) — the two-segment shape needed because @c WaitForMultipleObjects
 *  reports the lowest signaled index of whatever range it is given.
 *  The run loop advances @p base past whatever this returns, so a hot
 *  low-index handle cannot starve a hot high one.
*
 *  @return absolute signaled slot index;
 *          @c UINT_MAX if nothing is signaled.
 */
static inline unsigned s_wait_one(duct_events_env_t *env, unsigned base)
{
    unsigned n = env->n_entries;
    if (base >= n)
        base = 0u;
    DWORD w = WaitForMultipleObjects(n - base, &env->handles[base], FALSE, 0u);
    if (s_wait_signaled(w, n - base))
        return base + w;
    if (base == 0u)
        return UINT_MAX;
    w = WaitForMultipleObjects(base, env->handles, FALSE, 0u);
    return s_wait_signaled(w, base) ? w : UINT_MAX;
}

/** @brief Dispatch one signaled slot: wake / @c WSAEnumNetworkEvents, route by tag kind. */
static inline void s_events_dispatch(duct_events_env_t *env, unsigned i)
{
    auto slot = &env->slots[i];
    if (slot->kind == io_tag_wake) {
        duct_io_on_wake();
        return;
    }
    if (slot->kind == io_tag_rio_cq) {
        duct_rio_cq_drain(s_rio,env->rio_cq);
        return;
    }
    if (i == env->probe_slot) {
        s_probe_park_dispatch(env);
        return;
    }
    /* Last of the three fd == duct_sock_bad slot kinds, so it comes after
     * both service slots and before the socket path. */
    if (slot->fd == duct_sock_bad) {
        duct_io_on_device(slot->tag);
        return;
    }
    WSANETWORKEVENTS ne;
    int rc = WSAEnumNetworkEvents(slot->fd, slot->handle, &ne);
    duct_do_if(rc == SOCKET_ERROR, return);
    switch (slot->kind) {
    case io_tag_listener:
        auto listener = (duct_listener_t *)slot->tag;
        if (ne.lNetworkEvents & FD_WRITE)
            duct_io_on_dgram_tx_writable(listener);
        /* A stream listener accepts on any signal: the SetEvent of s_slot_drop records no FD_ACCEPT. */
        if (s_listener_read_event(listener) == FD_ACCEPT)
            s_handle_accept(env, listener);
        else if (ne.lNetworkEvents & FD_READ)
            duct_io_dgram_rx_drain(listener);
        return;
    case io_tag_pre_conn:
        auto pre_conn = (duct_pre_conn_t *)slot->tag;
        /* A dial's FD_CONNECT carries the connect's error; a record without it
         * follows a connection already made. */
        if (pre_conn->kind == pre_conn_probe)
            duct_io_on_pre_conn_readable(pre_conn);
        else
            duct_io_on_pre_conn_dialed(pre_conn, duct_x_connect_rc(ne.lNetworkEvents & FD_CONNECT
                                                                   ? ne.iErrorCode[FD_CONNECT_BIT] : 0));
        return;
    case io_tag_conn:
        duct_io_ev_flags_t flags = 0u;
        /* FD_CLOSE folds into io_ev_read,
         * covering peer close and recv() 0-byte EOF. */
        if (ne.lNetworkEvents & (FD_READ | FD_CLOSE))
            flags = duct_or(flags, io_ev_read);
        if (ne.lNetworkEvents & FD_WRITE)
            flags = duct_or(flags, io_ev_write);
        duct_io_on_event(&(duct_io_event_t){ .kind = io_tag_conn, .ptr = slot->tag, .flags = flags });
        return;
    case io_tag_wake:
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
        DWORD timeout = in_window ? 0u
                      : duct_io_work_pending() ? 0u
                      : duct_io_timer_due_soon() ? 0u
                      : timer_ms == DUCT_TIMEOUT_INFINITE ? INFINITE : (DWORD)timer_ms,
              w = WaitForMultipleObjects(env->n_entries, env->handles, FALSE, timeout);
        duct_do_if(w == WAIT_FAILED, return);
        if (s_wait_signaled(w, env->n_entries)) {
            in_window = duct_spin_next(&spin, true, duct_ticks_mono_ns());
            s_events_dispatch(env, w);
            /* Drain whatever else is already signaled this turn rotating
             * the scan base, to keep the fixed-batch-per-turn shape. */
            DWORD base = w + 1u;
            for (unsigned e = 1u; e < env->n_entries; ++e) {
                auto found = s_wait_one(env, (unsigned)base);
                if (found == UINT_MAX)
                    break;
                s_events_dispatch(env, found);
                base = found + 1u;
            }
        } else {
            in_window = duct_spin_next(&spin, false, duct_ticks_mono_ns());
            duct_cpu_relax();
        }
    }
}
