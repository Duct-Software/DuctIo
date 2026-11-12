/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_events.c
 *  @brief Windows IOCP dispatcher — completion port, per-operation contexts.
 *
 *  Connect / probe ops are one-shot, heap-allocated per post.
 *  RX / TX ops are embedded in their OLB header and reused across posts.
 *  A device's op is embedded in its device record and bound again after each dispatch.
 */

#include "duct_events.h"
#include "duct_io.h"

#include "duct_listener.h"
#include "duct_olb.h"
#include "duct_pre_conn.h"
#include "duct_relay.h"
#include "duct_vmq.h"
#include "duct_rio.h"
#include "duct_wfq_msg.h"
#include "duct_xport.h"

#include <assert.h>
#include <mswsock.h>
#include <winerror.h>
#include <winsock2.h>
#include <ws2tcpip.h>

/** @brief Completions batch limit per I/O thread. */
static constexpr unsigned events_max_batch = 64u;

/** @brief NTSTATUS a completed WSARecv on a datagram socket carries when
 *  the message was larger than the posted buffer — Winsock's
 *  WSAEMSGSIZE, in the form GetQueuedCompletionStatusEx's batch entries
 *  report it. Not pulled from a header: MinGW's NTSTATUS headers
 *  conflict with Winsock on this include path; a stable, documented
 *  Windows value used directly instead.
 */
static constexpr ULONG_PTR events_status_buffer_overflow = 0x80000005UL;

/** @brief NTSTATUS of an op CancelIoEx aborted, STATUS_CANCELLED. */
static constexpr ULONG_PTR events_status_cancelled = 0xC0000120UL;

/** @brief NTSTATUS of a ConnectEx the peer refused, STATUS_CONNECTION_REFUSED. */
static constexpr ULONG_PTR events_status_connection_refused = 0xC0000236UL;

/** @brief NTSTATUS of a wait completion packet call that succeeded, STATUS_SUCCESS. */
static constexpr LONG        events_status_success = 0;

/** @brief Access mask a wait completion packet handle is created with: the one specific right its object type defines. */
static constexpr ACCESS_MASK events_wait_packet_set_state = 0x1u;

/** @name Wait completion packet calls
 *  The ntdll exports that bind a device's Event to the completion port, resolved
 *  by @ref s_events_ctor. All three are set together, or all stay null where ntdll lacks one.
 *  @{
 */
typedef LONG (NTAPI *nt_wait_packet_create_fn)(PHANDLE packet, ACCESS_MASK access, PVOID attributes);
typedef LONG (NTAPI *nt_wait_packet_associate_fn)(HANDLE packet, HANDLE port, HANDLE target, PVOID key,
                                                  PVOID context, LONG status, ULONG_PTR information,
                                                  PBOOLEAN signalled);
typedef LONG (NTAPI *nt_wait_packet_cancel_fn)(HANDLE packet, BOOLEAN remove);

static nt_wait_packet_create_fn    pfnNtCreateWaitCompletionPacket;
static nt_wait_packet_associate_fn pfnNtAssociateWaitCompletionPacket;
static nt_wait_packet_cancel_fn    pfnNtCancelWaitCompletionPacket;
/** @} */

/** @brief One kind per distinct completion shape this backend posts. */
typedef enum : uint64_t {
    iocp_op_rx,       /**< WSARecv completion on a conn's RX OLB. */
    iocp_op_tx,       /**< WSASend completion on a conn's TX OLB. */
    iocp_op_accept,   /**< AcceptEx completion, one accepted TCP conn. */
    iocp_op_connect,  /**< ConnectEx completion for an outbound dial. */
    iocp_op_dgram,    /**< WSARecvMsg or WSARecvFrom completion on a
                        *  listener's shared UDP classification socket. */
    iocp_op_probe,    /**< Posted WSARecv for a probe-wait pre_conn — see
                        *  @c duct_events_watch() @c io_tag_pre_conn /
                        *  @c pre_conn_probe case. */
    iocp_op_dial_done, /**< Synthetic completion of a @c pre_conn_dial the kernel
                        *  completes no op for, its Winsock error in the
                        *  transferred byte count, 0 for a connection made. A
                        *  @c x_udp_peer dial posts 0 right after
                        *  @c duct_xconnect resolved it, ConnectEx having no
                        *  @c SOCK_DGRAM support; a ConnectEx that failed
                        *  inline posts its error. */
    iocp_op_dgram_tx, /**< WSASendMsg completion, one send in flight of a listener's
                        *  dgram TX state — see @c iocp_dgram_tx_ctl_t. */
    iocp_op_rio,      /**< This env's RIO completion queue has entries
                        *  ready — see @c rio_notify_op. */
    iocp_op_device,   /**< Signal of a watched device handle, queued for the wait
                        *  completion packet bound to it. */
    iocp_op_tx_records, /**< WSASendMsg completion for records from an @c
                          *  x_udp_peer conn's TX OLB, one or a segmented group. */
    iocp_op_rx_msg,     /**< WSARecvMsg completion on an @c x_udp_peer
                          *  conn's RX OLB. */
    iocp_op_rx_failed,  /**< Synthetic completion of a conn read the kernel refused at once,
                          *  queued by @c duct_events_drive_rx on the read's own embedded op, so
                          *  that its close runs in the loop and never inside a registration. */
} iocp_op_kind_t;

/** @name Tag pack/unpack
 *  Bits 60-63 for kind, 0-59 for the caller's opaque payload —
 *  48-bit canonical heap pointers fit the room to spare.
 *  @{
 */
static constexpr uint64_t events_tag_shift = 60u;
static constexpr uint64_t events_tag_mask  = 15ull << events_tag_shift;
static constexpr uint64_t events_ptr_mask  = ~events_tag_mask;

static inline uint64_t s_tag_pack(iocp_op_kind_t kind, void *ptr)
{
    return ((uint64_t)kind << events_tag_shift)
         | ((uint64_t)(uintptr_t)ptr & events_ptr_mask);
}

static inline void *s_tag_unpack(uint64_t word, iocp_op_kind_t *kind)
{
    *kind = (iocp_op_kind_t)(word >> events_tag_shift);
    return (void *)(uintptr_t)(word & events_ptr_mask);
}
/** @} */

/** @brief One posted operation, reused across every re-post — embedded in
 *  its OLB's @c ext[] for RX/TX, in @c listener_ctx_t for a listener's
 *  persistent @c AcceptEx or datagram read, standalone heap-allocated for
 *  connect/probe.
 */
typedef struct {
    OVERLAPPED ov;      /**< Completion's @c lpOverlapped, must be the first member. */
    uint64_t   packed;  /**< Bits 60-63 for kind, 0-59 for the caller's payload. */
    union {
        WSABUF   buf;     /**< Data buffer of an rx, tx, dgram or probe op. */
        unsigned records; /**< Records an @c iocp_op_tx_records send carries. */
        WSAMSG  *rx_msg;  /**< An @c iocp_op_rx_msg read's message, in the RX OLB past its span. */
    };
} iocp_op_t;

static_assert(sizeof(duct_rx_msg_t) + alignof(duct_rx_msg_t) - 1u <= duct_events_rx_scratch,
    "an RX read's WSAMSG must fit the scratch duct_io_rx_reserve leaves past its span");

static_assert(sizeof(iocp_op_t) <= duct_cacheline_size - sizeof(uint64_t),
    "iocp_op_t must fit duct_olb_hdr_t::ext");
    static_assert(alignof(iocp_op_t) <= alignof(void *),
    "iocp_op_t alignment must not exceed duct_olb_hdr_t::ext's");

typedef struct iocp_dgram_tx iocp_dgram_tx_t;

typedef struct {
    OVERLAPPED         ov;
    uint64_t           packed;
    WSAMSG             wsamsg;
    WSABUF             buf;
    INT                addrlen;
    uint32_t           ref;
    iocp_dgram_tx_t   *st;
} iocp_dgram_tx_ctl_t;

static constexpr unsigned iocp_dgram_tx_pool_depth = 64u;

struct iocp_dgram_tx {
    duct_listener_t                *listener;
    duct_x_slot_pool_t             *pools;
    duct_ptr_t(iocp_dgram_tx_ctl_t) ctls;
    unsigned                       *free_stack,
                                    free_count,
                                    inflight;
    bool                            closing;
};

static void s_dgram_tx_settle(iocp_dgram_tx_ctl_t *ctl, bool redrain);

/** @brief Resolve @p op's OLB header from its embedded address. */
static inline duct_olb_hdr_t *s_op_hdr(iocp_op_t *op)
{
    return (duct_olb_hdr_t *)((char *)op - offsetof(duct_olb_hdr_t, ext));
}

/** @brief Listener's IOCP-exclusive state — persistent posted op with inline buffers. */
typedef struct listener_ctx {
    iocp_op_t            op;        /**< Async I/O op. */
    duct_listener_t     *listener;  /**< Generic listener. */
    duct_sock_t          accept_fd; /**< Accept socket of the AcceptEx in flight; @c duct_sock_bad
                                     *  for a UDP ctx and for a stream ctx with none out. */
    struct listener_ctx *next;      /**< Intrusive list. */
    duct_rio_rx_t        *rio_rx;
    duct_x_slot_pool_t   *rx_pool;
    uint8_t              *rx_priv;
    uint32_t              rx_slot;
    union {                         /**< Variant tail — strictly last member. */
        uint8_t addr_buf[2u * (sizeof(struct sockaddr_storage) + 16u)]; /**< TCP. */
        struct {                                                        /**< UDP. */
            struct sockaddr_storage from_addr;
            INT                     from_len;
            duct_rx_msg_t           rx;       /**< The message a post reads through; zeroed on
                                               *  the @c WSARecvFrom path, which reports no
                                               *  segment size. */
        } dgram;
    };
} listener_ctx_t;

/** @brief Allocate @p listener's IOCP-exclusive context. */
static listener_ctx_t *s_listener_ctx_new(duct_listener_t *listener)
{
    size_t bytes = listener->xport_type == x_udp
                 ? offsetof(listener_ctx_t, dgram)    + sizeof ((listener_ctx_t *)nullptr)->dgram
                 : offsetof(listener_ctx_t, addr_buf) + sizeof ((listener_ctx_t *)nullptr)->addr_buf;
    auto ctx = (listener_ctx_t *)duct_at(duct_new(uint8_t, bytes, alignof(listener_ctx_t)));
    duct_do_if(!ctx, return nullptr);
    ctx->listener = listener;
    ctx->accept_fd = duct_sock_bad;
    ctx->rx_pool = listener->rx_slots;
    ctx->rx_slot = treiber_empty;
    return ctx;
}

static void s_listener_ctx_del(listener_ctx_t *ctx)
{
    if (ctx->rx_slot != treiber_empty)
        duct_x_slot_release(ctx->rx_pool, ctx->rx_slot);
    duct_del(ctx->rx_priv);
    duct_del(ctx);
}

/** @brief Test whether a stream listener's @p ctx has no @c AcceptEx out, no completion left to free it. */
static inline bool s_listener_ctx_idle(const listener_ctx_t *ctx)
{
    return ctx->listener->xport_type != x_udp && ctx->accept_fd == duct_sock_bad;
}

/** @brief Phase of a device's wait packet, written and read by the owning io thread alone. */
typedef enum : uint8_t {
    device_armed,       /**< Bound to the port, the dispatch of its completion still ahead. */
    device_dispatching, /**< Completion taken and being dispatched, nothing bound. */
    device_closing,     /**< Unwatched with a dispatch still to finish or to run. @ref s_on_device_completion frees the record there. */
} iocp_device_state_t;

/** @brief Record of one watched device handle.
 *  Linked in @c duct_events_env_t::devices while watched.
 */
typedef struct iocp_device {
    iocp_op_t           op;     /**< Overlapped the completion is dequeued with, tagged @c iocp_op_device. */
    struct iocp_device *next;   /**< Next watched device of the same env. */
    HANDLE              packet; /**< Wait completion packet bound to @c ev, closed with the record. */
    HANDLE              ev;     /**< The device's waitable handle, borrowed from the caller. */
    void               *tag;    /**< Conn tag word that @c duct_io_on_device is given. */
    iocp_device_state_t state;  /**< Phase of @c packet. */
} iocp_device_t;

/** @brief A completion port, this thread's listener list, and its RIO
 *  completion queue. */
typedef struct duct_events_env {
    void (*cancel_io)(duct_sock_t fd);
    HANDLE          iocp;
    listener_ctx_t *listeners; /**< List head, threaded via ->next. */
    iocp_device_t  *devices;
    /** @brief @c nullptr if RIO is unavailable.
     *  @see @ref duct_events_rio_cq_ready. */
    RIO_CQ          rio_cq;
    /** @brief @c rio_cq's own cumulative admission budget: @c depth is
     *  its current size, @c used is how much every RIO-active listener
     *  has claimed so far.
     *  Grown together by @ref duct_rio_cq_ensure; @c used never shrinks
     *  back down when a listener later closes. */
    DWORD           rio_cq_depth,
                    rio_cq_used;
    /** @brief Persistent notification anchor for @c rio_cq, tagged @c
     *  iocp_op_rio. One fixed anchor for the whole env's life, re-armed
     *  via RIONotify after every drain. */
    iocp_op_t       rio_notify_op;
} duct_events_env_t;

static LPFN_CONNECTEX               pfnConnectEx;
static LPFN_ACCEPTEX                pfnAcceptEx;
static LPFN_GETACCEPTEXSOCKADDRS    pfnGetAcceptExSockaddrs;

/** @brief RIO extension function table, @c nullptr where RIO is off.
 *  Set once by @ref s_events_ctor. Every RIO object of this backend, the
 *  completion queue, a ring and a pool, exists only while it is non-null.
 */
static RIO_EXTENSION_FUNCTION_TABLE *s_rio;
/* The completion port of the io thread running this code, set by duct_events_init: the downcalls
 * that take no env reach it here. */
static thread_local HANDLE          s_port;

/** @brief Resolve the Winsock extension functions, the RIO table and the ntdll wait completion packet calls. */
static void s_events_ctor(void) __attribute__((constructor(DUCT_CTOR_PRI_STATE)));
static void s_events_ctor(void)
{
    auto fd = socket(AF_INET, SOCK_STREAM, 0);
    duct_fatal(fd == duct_sock_bad);
    pfnConnectEx            = (LPFN_CONNECTEX)           duct_x_wsa_ext_pfn(fd,(GUID)WSAID_CONNECTEX);
    pfnAcceptEx             = (LPFN_ACCEPTEX)            duct_x_wsa_ext_pfn(fd,(GUID)WSAID_ACCEPTEX);
    pfnGetAcceptExSockaddrs = (LPFN_GETACCEPTEXSOCKADDRS)duct_x_wsa_ext_pfn(fd,(GUID)WSAID_GETACCEPTEXSOCKADDRS);
    closesocket(fd);
    duct_fatal(!pfnConnectEx || !pfnAcceptEx || !pfnGetAcceptExSockaddrs);

    s_rio = duct_rio_resolve();

    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    auto wait_create = (nt_wait_packet_create_fn)(void *)(uintptr_t)
        GetProcAddress(ntdll, "NtCreateWaitCompletionPacket");
    auto wait_associate = (nt_wait_packet_associate_fn)(void *)(uintptr_t)
        GetProcAddress(ntdll, "NtAssociateWaitCompletionPacket");
    auto wait_cancel = (nt_wait_packet_cancel_fn)(void *)(uintptr_t)
        GetProcAddress(ntdll, "NtCancelWaitCompletionPacket");
    /* duct_events_watch_device tests the create pointer alone, so the three are set together. */
    if (wait_create && wait_associate && wait_cancel) {
        pfnNtCreateWaitCompletionPacket = wait_create;
        pfnNtAssociateWaitCompletionPacket = wait_associate;
        pfnNtCancelWaitCompletionPacket = wait_cancel;
    }
}

/** @brief Close @p d's wait packet and release the record. */
static void s_device_free(iocp_device_t *d)
{
    CloseHandle(d->packet);
    duct_del(d);
}

/** @brief Bind @p d's Event to this thread's completion port through its wait packet.
 *  One completion follows, when the Event next signals or at once where it is signalled
 *  already, so a signal that landed during a dispatch completes the next binding.
 *  @return false when the kernel refuses the binding.
 */
static bool s_device_arm(iocp_device_t *d)
{
    return pfnNtAssociateWaitCompletionPacket(d->packet, s_port, d->ev, nullptr, &d->op.ov, events_status_success,
                                              0u, nullptr) >= 0;
}

/** @brief Take @p d off the port, freeing it now or marking it for the free to come.
 *  An armed device is cancelled with its queued completion removed, and an answer of success
 *  means the port holds nothing of it: the record is freed here. Any other answer, and a
 *  device in dispatch, leave a dispatch still to finish or to run, so the record is marked
 *  @c device_closing and @ref s_on_device_completion frees it.
 */
static bool s_device_detach(iocp_device_t *d)
{
    if (d->state == device_armed && pfnNtCancelWaitCompletionPacket(d->packet, TRUE) == events_status_success) {
        s_device_free(d);
        return false;
    }
    d->state = device_closing;
    return true;
}

/** @brief Dispatch the completion of @p d's Event and bind the Event again.
 *  A device marked closing is freed in place of the dispatch. A binding the kernel refuses
 *  is reported to the conn as @c io_ev_error, whose close frees the record. The dispatch can
 *  close its own device: the record is then freed here, after @c duct_io_on_device returns.
 */
static void s_on_device_completion(iocp_device_t *d)
{
    if (d->state == device_armed) {
        d->state = device_dispatching;
        duct_io_on_device(d->tag);
        if (d->state == device_dispatching) {
            d->state = device_armed;
            if (s_device_arm(d))
                return;
            d->state = device_dispatching;
            duct_io_on_event(&(duct_io_event_t){ .kind = io_tag_conn, .ptr = d->tag, .flags = io_ev_error });
        }
    }
    if (d->state == device_closing)
        s_device_free(d);
}

bool duct_events_rio_available(void)
{
    return s_rio != nullptr;
}

bool duct_events_dgram_shared_rio_capable(void)
{
    return s_rio != nullptr;
}

static void s_cancel_io(duct_sock_t fd)
{
    if (fd != duct_sock_bad)
        CancelIoEx((HANDLE)fd, nullptr); /* cancel all inflight ops on fd */
}

duct_events_env_t *duct_events_init(void)
{
    auto env = duct_new(duct_events_env_t);
    duct_do_if(!env, return nullptr);
    env->cancel_io = s_cancel_io;
    env->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1u);
    duct_do_if(!env->iocp, duct_del(env); return nullptr);
    if (s_rio) {
        env->rio_notify_op.packed = s_tag_pack(iocp_op_rio, nullptr);
        env->rio_cq = duct_rio_cq_create(s_rio,
            &(RIO_NOTIFICATION_COMPLETION){
                .Type = RIO_IOCP_COMPLETION,
                .Iocp = { env->iocp, nullptr, &env->rio_notify_op.ov },
            },
            &env->rio_cq_depth, &env->rio_cq_used);
    }
    s_port = env->iocp;
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

/** @brief Drain all queued completions for every conn / listener op
 *  the caller has cancelled, before the port close discards their
 *  pinned @c WSABUF pages;
 *
 *  @todo 0.5s timeout is expected to be enough, but maybe better
 *  to use a strict overall op counter instead.
 */
static void s_drain_completions(duct_events_env_t *env, bool armed)
{
    OVERLAPPED_ENTRY entries[events_max_batch];
    for (ULONG n = 0u; GetQueuedCompletionStatusEx(env->iocp, entries, events_max_batch, &n,
                                                   armed ? 500u : 0u, FALSE); ) {
        armed = false;
        for (ULONG i = 0u; i < n; ++i)
            if (entries[i].lpOverlapped) {
                auto op = (iocp_op_t *)entries[i].lpOverlapped;
                iocp_op_kind_t kind;
                auto ptr = s_tag_unpack(op->packed, &kind);
                switch (kind) {
                case iocp_op_rx:
                case iocp_op_rx_msg:
                case iocp_op_rx_failed:
                case iocp_op_tx:
                case iocp_op_tx_records:
                    duct_discard duct_olb_io_done(s_op_hdr(op));
                    break;
                case iocp_op_connect:
                case iocp_op_probe:
                case iocp_op_dial_done:
                    duct_del(op);
                    break;
                case iocp_op_accept:
                case iocp_op_dgram:
                    auto ctx = (listener_ctx_t *)ptr;
                    if (!ctx->listener) {
                        if (ctx->accept_fd != duct_sock_bad)
                            closesocket(ctx->accept_fd);
                        s_listener_ctx_del(ctx);
                    }
                    break;
                case iocp_op_dgram_tx:
                    /* Pool freed by duct_listener_destroy right after this
                     * drain returns — let it land and do nothing, no
                     * re-drain (the listener is going away). */
                    s_dgram_tx_settle((iocp_dgram_tx_ctl_t *)op, false);
                    break;
                case iocp_op_rio:
                    duct_rio_cq_flush(s_rio,env->rio_cq);
                    break;
                case iocp_op_device:
                    s_on_device_completion((iocp_device_t *)ptr);
                    break;
                }
            }
    }
}

void duct_events_fini(duct_events_env_t *env)
{
    bool armed = false;
    for (auto ctx = env->listeners; ctx; ) {
        auto next = ctx->next;
        auto listener = ctx->listener;
        auto lfd = listener->listen_fd;
        bool idle = s_listener_ctx_idle(ctx);
        ctx->listener = nullptr;
        armed |= !idle;
        if (idle)
            duct_del(ctx);
        else if (ctx->rio_rx) {
            /* CancelIoEx cancels overlapped ops only; closesocket aborts a
             * RIO one, generating the completion
             * s_drain_completions below waits for. */
            closesocket(lfd);
            listener->listen_fd = duct_sock_bad; /* duct_listener_destroy closes a listen_fd still set */
            duct_discard duct_rio_rx_close(s_rio,ctx->rio_rx);
        } else
            s_cancel_io(lfd);
        ctx = next;
    }
    env->listeners = nullptr;
    for (auto d = env->devices; d; ) {
        auto next = d->next;
        armed |= s_device_detach(d);
        d = next;
    }
    env->devices = nullptr;
    s_drain_completions(env, armed);
    CloseHandle(env->iocp);
    if (env->rio_cq)
        duct_rio_cq_close(s_rio, env->rio_cq);
    duct_del(env);
}

void duct_events_rx_stall([[maybe_unused]] duct_sock_t fd,
                          [[maybe_unused]] void *rx_io_priv)
{
    /* no-op on proactive I/O */
}

/* A read the kernel refuses is queued back to this thread's port on its own op, so its close runs
 * in the loop and never inside the registration that posts a conn's first read. A port that
 * refuses the post leaves the close here, at once. */
void duct_events_drive_rx(void *tag)
{
    duct_io_xfer_t r;
    if (!duct_io_rx_reserve(tag, &r))
        return; /* OLB is full (self-repost already posted) or stale tag */
    if (duct_olb_io_begin(r.olb_hdr))
        return; /* another recv is already in flight */
    auto op = (iocp_op_t *)r.olb_hdr->ext;
    auto recvmsg_fn = duct_x_wsa_recvmsg();
    int rc;
    if (r.xport_type == x_udp_peer && recvmsg_fn) {
        /* The message lives in the scratch duct_io_rx_reserve leaves past the
         * span, which the read owns until its completion takes the segment size. */
        auto m = (duct_rx_msg_t *)duct_align_up((size_t)(r.buf + r.size), alignof(duct_rx_msg_t));
        *op = (iocp_op_t){
            .packed = s_tag_pack(iocp_op_rx_msg, tag),
            .rx_msg = duct_rx_msg(m, (duct_view_u8){ .data = r.buf, .size = r.size }, nullptr),
        };
        rc = recvmsg_fn(r.fd, op->rx_msg, nullptr, &op->ov, nullptr);
    } else {
        *op = (iocp_op_t){
            .packed = s_tag_pack(iocp_op_rx, tag),
            .buf = { r.size, (char *)r.buf },
        };
        rc = WSARecv(r.fd, &op->buf, 1u, &(DWORD){0u}, &(DWORD){0u}, &op->ov, nullptr);
    }
    if (rc != 0)
        switch (rc = WSAGetLastError()) {
        case WSA_IO_PENDING:
            break;
        default:
            duct_dbg_errf("WSA error %d", rc);
            op->packed = s_tag_pack(iocp_op_rx_failed, tag);
            if (!PostQueuedCompletionStatus(s_port, 0u, 0u, &op->ov) && !duct_olb_io_done(r.olb_hdr))
                duct_io_rx_done(tag, rc_fatal);
        }
}

/** @brief Reduce an overlapped send's return @p rc to its Winsock error.
 *  @p rc comes straight from the send, whose thread-local last error this reads.
 *  @return @c NO_ERROR once the send is posted, done or pending alike, since
 *  either completes through the port; the Winsock code otherwise. */
static int s_tx_post_err(int rc)
{
    int err = rc == 0 ? NO_ERROR : WSAGetLastError();
    return err == WSA_IO_PENDING ? NO_ERROR : err;
}

/** @brief Post one overlapped @c WSASendMsg of @p n records from @p bufs,
 *  segmented when @p n is above 1.
 *  @return @c NO_ERROR once posted, the Winsock code otherwise. */
static int s_tx_post_msg(void *tag, duct_sock_t fd, iocp_op_t *op,
                         const duct_view_u8 *bufs, unsigned n)
{
    *op = (iocp_op_t){ .packed = s_tag_pack(iocp_op_tx_records, tag), .records = n };
    /* Winsock copies the message, its spans and its cmsg at the call, so a
     * pending send needs only the record bytes, which stay in the ring until
     * its completion advances past them. */
    duct_x_gso_msg_t m;
    return s_tx_post_err(WSASendMsg(fd, duct_x_gso_msg_bufs(&m, bufs, n), 0u, nullptr, &op->ov, nullptr));
}

/** @brief Post one overlapped @c WSASend of the span @p p addresses.
 *  @return @c NO_ERROR once posted, the Winsock code otherwise. */
static int s_tx_post_stream(void *tag, const duct_io_xfer_t *p, iocp_op_t *op)
{
    *op = (iocp_op_t){ .packed = s_tag_pack(iocp_op_tx, tag), .buf = { p->size, (char *)p->buf } };
    return s_tx_post_err(WSASend(p->fd, &op->buf, 1u, &(DWORD){0u}, 0u, &op->ov, nullptr));
}

/** @brief Post the records at @p tag's ring head, a segmented group where the
 *  stack cuts one.
 *  A group refused synchronously goes again as its head record alone.
 *  @return @c NO_ERROR once posted; otherwise the refusal of the head record
 *  posted alone, which the drive judges as that one record's.
 */
static int s_tx_post_records(void *tag, const duct_io_xfer_t *p, iocp_op_t *op)
{
    duct_view_u8 bufs[duct_dgram_tx_batch];
    unsigned n = duct_io_tx_peek_bufs(tag, bufs, duct_dgram_tx_batch);
    assert(n);
    unsigned group = duct_x_has_gso() ? duct_x_gso_group(bufs, n) : 1u;
    int err = s_tx_post_msg(tag, p->fd, op, bufs, group);
    if (err != NO_ERROR && group > 1u)
        err = s_tx_post_msg(tag, p->fd, op, bufs, 1u);
    return err;
}

/* Each turn either posts one send and leaves, or drops one record the path
 * cannot carry and takes the next, which is the only reason this loops. A
 * synchronous success still completes through the port, so the chain continues
 * from s_on_tx_completion, or s_on_tx_records_completion for an x_udp_peer
 * send, and that is also where an in-flight send's duct_olb_io_done lands. A
 * send that failed outright pairs it here. */
void duct_events_drive_tx(void *tag)
{
    duct_io_xfer_t p;
    /* nothing to send, if respond-then-close is already handled, or stale tag */
    while (duct_io_tx_peek(tag, &p)) {
        if (duct_olb_io_begin(p.olb_hdr))
            return; /* a send is already in flight */
        auto op = (iocp_op_t *)p.olb_hdr->ext;
        int err = p.xport_type == x_udp_peer ? s_tx_post_records(tag, &p, op)
                                             : s_tx_post_stream(tag, &p, op);
        switch (err) {
        case NO_ERROR:
            return;
        case WSAEMSGSIZE:
            duct_dbg_errf("WSAEMSGSIZE, %zu bytes", p.size);
            if (duct_olb_io_done(p.olb_hdr))
                return;
            if (!duct_xport_delimited(p.xport_type)) {
                duct_io_tx_done(tag, rc_fatal);
                return;
            }
            duct_discard duct_io_tx_advance(tag, p.size, 0u);
            continue;
        default:
            duct_dbg_errf("WSA error %d", err);
            if (!duct_olb_io_done(p.olb_hdr))
                duct_io_tx_done(tag, rc_fatal);
            return;
        }
    }
}

/** @brief Post @c AcceptEx for @p ctx's listener.
 *  The accept socket is AF_UNIX for an @c x_local listener, IPv6 for any other,
 *  IPv4 where an IPv6 socket cannot be made.
 *  @return @c rc_ok with the @c AcceptEx out; @c rc_defer when no accept socket can be made
 *          or @c AcceptEx answers @c WSAEMFILE or @c WSAENOBUFS; @c rc_fatal on any other
 *          error, which leaves the listener with no @c AcceptEx out. */
static duct_result_t s_post_accept(listener_ctx_t *ctx)
{
    auto fd = ctx->listener->listen_fd;
    switch (ctx->listener->xport_type) {
    case x_local:
        ctx->accept_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        break;
    default:
        ctx->accept_fd = socket(AF_INET6, SOCK_STREAM, 0);
        if (ctx->accept_fd == duct_sock_bad)
            ctx->accept_fd = socket(AF_INET, SOCK_STREAM, 0);
        break;
    }
    duct_do_if(ctx->accept_fd == duct_sock_bad, return rc_defer);
    ctx->op = (iocp_op_t) {
        .packed = s_tag_pack(iocp_op_accept, ctx)
    };
    static constexpr DWORD addr_slot = sizeof(struct sockaddr_storage) + 16u;
    BOOL ok = pfnAcceptEx(fd, ctx->accept_fd, ctx->addr_buf, 0u,
                            addr_slot, addr_slot, &(DWORD){0u}, &ctx->op.ov);
    if (!ok) {
        int rc = WSAGetLastError();
        switch (rc) {
        case ERROR_IO_PENDING:
            break;
        default:
            duct_dbg_errf("WSA error %d", rc);
            closesocket(ctx->accept_fd);
            ctx->accept_fd = duct_sock_bad;
            /* TODO: handle error */
            return rc == WSAEMFILE || rc == WSAENOBUFS ? rc_defer : rc_fatal;
        }
    }
    return rc_ok;
}

/** @brief Post @p ctx's next @c AcceptEx, parking its listener when no accept socket can be made.
 *  The post is tried once more past the park, so a socket closed in between is taken; a
 *  later close puts the listener back through @ref duct_events_listener_rx_interest, which
 *  posts again. */
static void s_accept_rearm(listener_ctx_t *ctx)
{
    if (s_post_accept(ctx) != rc_defer)
        return;
    duct_io_accept_park(ctx->listener);
    if (s_post_accept(ctx) != rc_defer)
        duct_io_accept_unpark(ctx->listener);
}

/** @brief Post one read for @p ctx's listener.
 *  @c WSARecvMsg reports a coalesced read's segment size; @c WSARecvFrom
 *  serves where that extension is missing, and the listener fd then carries no
 *  coalescing. @see s_post_accept for the parallel TCP-side post. */
static bool s_post_dgram(listener_ctx_t *ctx)
{
    auto fd = ctx->listener->listen_fd;
    auto span = ctx->rx_slot != treiber_empty
              ? duct_listener_rx_span(ctx->listener, ctx->rx_pool, ctx->rx_slot)
              : (duct_view_u8){ .data = ctx->rx_priv, .size = duct_listener_dgram_span(ctx->listener) };
    ctx->op = (iocp_op_t) {
        .packed = s_tag_pack(iocp_op_dgram, ctx),
        .buf = { (ULONG)span.size, span.data },
    };
    auto recvmsg_fn = duct_x_wsa_recvmsg();
    int rc;
    if (recvmsg_fn) {
        auto msg = duct_rx_msg(&ctx->dgram.rx, span, &ctx->dgram.from_addr);
        rc = recvmsg_fn(fd, msg, nullptr, &ctx->op.ov, nullptr);
    } else {
        ctx->dgram.rx = (duct_rx_msg_t){};
        ctx->dgram.from_len = sizeof ctx->dgram.from_addr; /* reset before every post */
        rc = WSARecvFrom(fd, &ctx->op.buf, 1u, &(DWORD){0u}, &(DWORD){0u},
                         (struct sockaddr *)&ctx->dgram.from_addr, &ctx->dgram.from_len,
                         &ctx->op.ov, nullptr);
    }
    if (rc != 0)
        switch (rc = WSAGetLastError()) {
        case WSA_IO_PENDING:
            break;
        default:
            duct_dbg_errf("WSA error %d", rc);
            /* TODO: handle error */
            return false;
        }
    return true;
}

/** @brief Set up @p ctx's RIO RX ring, request queue, and, when the
 *  listener has a TX outbox, its TX pool.
 *  Self-cleaning: a later step's failure frees whatever an earlier one
 *  already allocated. Called once, from @ref s_listener_create, before
 *  the first post. */
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

/** @brief Allocate @p listener's IOCP-exclusive ctx and arm its first
 *  receive.
 *  Runs @ref s_rio_dgram_init first when @p listener qualifies for RIO,
 *  then posts @c AcceptEx, @c RIOReceiveEx or @c WSARecvFrom and links
 *  the ctx onto this thread's list.
 */
static bool s_listener_create(duct_events_env_t *env, duct_sock_t fd,
                              duct_listener_t *listener)
{
    HANDLE iocp = CreateIoCompletionPort((HANDLE)fd, env->iocp, 0, 0);
    duct_do_if(iocp == nullptr, return false);
    auto ctx = s_listener_ctx_new(listener);
    duct_do_if(!ctx, return false);
    bool use_rio = listener->xport_type == x_udp && listener->dgram_tx_outbox && s_rio;
    bool ok = !use_rio || s_rio_dgram_init(env, ctx);
    if (ok && listener->xport_type == x_udp && !use_rio) {
        ctx->rx_slot = duct_x_slot_acquire(ctx->rx_pool);
        if (ctx->rx_slot == treiber_empty) {
            ctx->rx_priv = duct_at(duct_new(uint8_t, duct_listener_dgram_span(listener)));
            ok = ctx->rx_priv != nullptr;
        }
    }
    duct_do_if(!ok,
        s_listener_ctx_del(ctx);
        return false
    );
    bool posted = listener->xport_type != x_udp ? s_post_accept(ctx) == rc_ok
                : use_rio ? duct_rio_rx_prime(s_rio,ctx->rio_rx)
                : s_post_dgram(ctx);
    duct_do_if(!posted,
        /* use_rio true means s_rio_dgram_init already succeeded — only
         * this first post failed, so its registration is released here
         * instead. */
        if (use_rio) {
            duct_rio_rx_destroy(s_rio,ctx->rio_rx);
            duct_events_dgram_tx_pool_free(listener);
        }
        s_listener_ctx_del(ctx);
        return false
    );
    ctx->next = env->listeners;
    env->listeners = ctx;
    return true;
}

/** @brief Post the synthetic completion of the dial @p tag names, @p error its
 *  Winsock error, 0 for a connection made.
 *  @return false when the op cannot be allocated or posted.
 */
static bool s_post_dial_done(duct_events_env_t *env, void *tag, DWORD error)
{
    auto op = duct_new(iocp_op_t);
    duct_do_if(!op, return false);
    op->packed = s_tag_pack(iocp_op_dial_done, tag);
    BOOL posted = PostQueuedCompletionStatus(env->iocp, error, 0u, &op->ov);
    duct_do_if(!posted, duct_del(op); return false);
    return true;
}

/** @brief Post @c ConnectEx for @p fd toward @p addr / @p addrlen.
 *  A ConnectEx that fails inline queues no completion, as one toward a missing
 *  socket path does, so its error goes out through @c s_post_dial_done.
 *  @return false when the op cannot be allocated or its completion posted.
 */
static bool s_post_connect(duct_events_env_t *env, duct_sock_t fd, void *tag,
                           const struct sockaddr *addr,
                           int addrlen)
{
    auto op = duct_new(iocp_op_t);
    duct_do_if(!op, return false);
    op->packed = s_tag_pack(iocp_op_connect, tag);
    BOOL ok = pfnConnectEx(fd, addr, addrlen, nullptr, 0u, &(DWORD){0u}, &op->ov);
    if (!ok) {
        int rc = WSAGetLastError();
        switch (rc) {
        case ERROR_IO_PENDING:
            break;
        default:
            duct_del(op);
            return s_post_dial_done(env, tag, (DWORD)rc);
        }
    }
    return true;
}

/** @brief Post a @c WSARecv for a probe-wait @p pre_conn into the free tail of its buffer.
 *  @return false when the op cannot be allocated or the post fails.
 */
static bool s_post_probe(duct_pre_conn_t *pre_conn)
{
    auto op = duct_new(iocp_op_t);
    duct_do_if(!op, return false);
    auto room = duct_pre_conn_probe_room(pre_conn);
    op->packed = s_tag_pack(iocp_op_probe, pre_conn);
    op->buf = (WSABUF){ (ULONG)room.size, (CHAR *)room.data };
    int rc = WSARecv(pre_conn->fd, &op->buf, 1u, &(DWORD){0u}, &(DWORD){0u}, &op->ov, nullptr);
    if (rc != 0)
        switch (rc = WSAGetLastError()) {
        case ERROR_IO_PENDING:
            break;
        default:
            /* TODO: handle error */
            duct_del(op);
            return false;
        }
    return true;
}

/** @brief Associate @p fd with @p env's completion port.
 *
 *  The association lasts the socket's lifetime; @ref duct_events_unwatch
 *  can only cancel inflight ops, never undo it. So an fd watched once as
 *  a @c pre_conn and re-watched as a conn — @ref s_classify_stream's
 *  async handoff round trip — comes back @c ERROR_INVALID_PARAMETER on
 *  the second call. Already ours is success: the next posted op completes
 *  on this same port either way.
 */
static bool s_iocp_assoc(duct_events_env_t *env, duct_sock_t fd)
{
    return CreateIoCompletionPort((HANDLE)fd, env->iocp, 0, 0)
        || GetLastError() == ERROR_INVALID_PARAMETER;
}

bool duct_events_watch(duct_events_env_t *env, duct_sock_t fd,
                       duct_io_tag_t kind, void *tag_ptr,
                       duct_xport_t xport_type)
{
    duct_do_if(fd == duct_sock_bad, return false);
    switch (kind) {
    case io_tag_listener:
        return s_listener_create(env, fd, (duct_listener_t *)tag_ptr);
    case io_tag_pre_conn:
        bool assoc = s_iocp_assoc(env, fd);
        duct_do_if(!assoc, return false);
        auto pre_conn = (duct_pre_conn_t *)tag_ptr;
        switch (pre_conn->kind) {
        case pre_conn_probe:
            return s_post_probe(pre_conn);
        case pre_conn_dial:
            if (xport_type == x_udp_peer)
                /* ConnectEx doesn't support SOCK_DGRAM — nothing to post.
                 * s_dial_begin still touches *pre_conn after this call
                 * returns (e.g. arms the connect timeout); resolving
                 * inline here races that, so it's deferred to the next
                 * dispatch loop turn instead. */
                return s_post_dial_done(env, tag_ptr, 0u);
            struct sockaddr_storage ss = {};
            auto addrlen = xport_type == x_local
                         ? duct_io_sockaddr_from_path(pre_conn->dial.target.path, &ss)
                         : duct_io_sockaddr_from_peer(&pre_conn->dial.target.peer, &ss);
            return s_post_connect(env, fd, tag_ptr, (struct sockaddr *)&ss, addrlen);
        }
        duct_unreachable();
    case io_tag_conn:
        assoc = s_iocp_assoc(env, fd);
        duct_do_if(!assoc, return false);
        /* No Winsock SO_REUSEPORT equivalent demuxes a connected per-peer
         * dgram socket ahead of its shared listener, so xport_type narrows
         * read interest for x_udp_peer only. */
        if (xport_type != x_udp_peer)
            duct_events_drive_rx(tag_ptr);
        return true;
    case io_tag_wake:
    case io_tag_rio_cq:
        duct_unreachable();
    }
    return false;
}

bool duct_events_promote([[maybe_unused]] duct_events_env_t *env,
                         [[maybe_unused]] duct_sock_t fd, void *tag_ptr)
{
    /* fd is already associated by duct_events_watch's io_tag_pre_conn
     * case, dial or probe alike — just post the first WSARecv, same as a
     * fresh io_tag_conn. */
    duct_events_drive_rx(tag_ptr);
    return true;
}

/** @brief Address of the link holding the device that watches @p handle,
 *  @c nullptr if none. The link, not the device, so unwatch can unhook it. */
static iocp_device_t **s_device_find(duct_events_env_t *env, const void *handle)
{
    for (iocp_device_t **pp = &env->devices; *pp; pp = &(*pp)->next)
        if ((*pp)->ev == handle)
            return pp;
    return nullptr;
}

bool duct_events_watch_device(duct_events_env_t *env, void *handle, void *tag_ptr)
{
    duct_do_if(!pfnNtCreateWaitCompletionPacket, return false);
    auto dup = s_device_find(env, handle);
    duct_do_if(dup, return false);
    auto d = duct_new(iocp_device_t);
    duct_do_if(!d, return false);
    d->ev = (HANDLE)handle;
    d->tag = tag_ptr;
    d->op.packed = s_tag_pack(iocp_op_device, d);
    auto made = pfnNtCreateWaitCompletionPacket(&d->packet, events_wait_packet_set_state, nullptr);
    duct_do_if(made < 0, duct_del(d); return false);
    d->state = device_armed;
    auto armed = s_device_arm(d);
    duct_do_if(!armed, s_device_free(d); return false);
    d->next = env->devices;
    env->devices = d;
    return true;
}

void duct_events_device_rx_interest([[maybe_unused]] duct_events_env_t *env,
                                    [[maybe_unused]] void *device,
                                    [[maybe_unused]] bool want)
{
}

void duct_events_unwatch_device(duct_events_env_t *env, void *handle)
{
    auto pp = s_device_find(env, handle);
    duct_do_if(!pp, return);
    auto d = *pp;
    *pp = d->next;
    s_device_detach(d);
}

void duct_events_unwatch(duct_events_env_t *env, duct_sock_t fd,
                         [[maybe_unused]] void *rx_io_priv)
{
    if (fd == duct_sock_bad)
        return;
    for (listener_ctx_t **pp = &env->listeners; *pp; pp = &(*pp)->next) {
        if ((*pp)->listener->listen_fd != fd)
            continue;
        auto ctx = *pp;
        *pp = ctx->next; /* unlink to make undiscoverable */
        bool idle = s_listener_ctx_idle(ctx);
        ctx->listener = nullptr; /* set closing marker */
        if (idle) {
            duct_del(ctx);
            return;
        }
        s_cancel_io(fd);
        if (ctx->rio_rx)
            duct_discard duct_rio_rx_close(s_rio,ctx->rio_rx);
        return;
    }
    /* Conn fd: duct_conn_teardown's close, at actual reclaim, may run
     * well after this call -- a worker's TX fast path can still be
     * mid-send on it. A pending overlapped WSARecv/WSASend on this fd
     * otherwise never completes once the peer is already gone --
     * nothing else forces it -- so cancel it here, same as the listener
     * case above; duct_olb_del / duct_olb_io_done at teardown still
     * settle the resulting completion. */
    s_cancel_io(fd);
}

void duct_events_kick(duct_events_env_t *env)
{
    /* lpOverlapped == nullptr prevents collision with any
     * other op completion carrying a non-null OVERLAPPED*. */
    PostQueuedCompletionStatus(env->iocp, 0u, 0u, nullptr);
}

void duct_events_dgram_tx_interest([[maybe_unused]] duct_events_env_t *env,
                                   [[maybe_unused]] duct_listener_t *listener,
                                   [[maybe_unused]] bool armed)
{
    /* No-op: dgram TX here is proactive/completion-based, driven entirely
     * through duct_events_dgram_tx_kick — there is no readiness state to
     * arm or disarm. */
}

/* A stream listener's interest is an outstanding AcceptEx: (true) posts one where none is out,
 * parking the listener again when no accept socket can be made, and a withdrawal is the
 * re-post s_on_accept_completion leaves out. */
void duct_events_listener_rx_interest(duct_events_env_t *env, duct_listener_t *listener, bool want)
{
    if (!want)
        return;
    for (auto ctx = env->listeners; ctx; ctx = ctx->next)
        if (ctx->listener == listener && s_listener_ctx_idle(ctx))
            s_accept_rearm(ctx);
}

static void s_dgram_tx_release(iocp_dgram_tx_t *st)
{
    duct_listener_tx_slots_free(st->pools);
    duct_del(st->ctls);
    duct_del(st->free_stack);
    duct_del(st);
}

bool duct_events_dgram_tx_pool_alloc(duct_listener_t *listener)
{
    if (!listener->dgram_tx_outbox)
        return true;
    bool made = duct_listener_tx_slots_new(listener, sizeof(struct sockaddr_storage),
                                           iocp_dgram_tx_pool_depth);
    duct_do_if(!made, return false);
    if (s_rio)
        return true;
    auto st = duct_new(iocp_dgram_tx_t);
    auto ctls = duct_new(iocp_dgram_tx_ctl_t, iocp_dgram_tx_pool_depth);
    auto free_stack = duct_at(duct_new(unsigned, iocp_dgram_tx_pool_depth));
    duct_do_if(!st || !ctls || !free_stack,
        duct_del(st);
        duct_del(ctls);
        duct_del(free_stack);
        duct_listener_tx_slots_free(listener->tx_slots);
        listener->tx_slots = nullptr;
        return false
    );
    for (unsigned i = 0u; i < iocp_dgram_tx_pool_depth; ++i)
        free_stack[i] = i;
    st->free_count = iocp_dgram_tx_pool_depth;
    st->listener = listener;
    st->pools = listener->tx_slots;
    st->ctls = ctls;
    st->free_stack = free_stack;
    listener->dgram_tx_pool = st;
    return true;
}

void duct_events_dgram_tx_pool_free(duct_listener_t *listener)
{
    if (listener->dgram_tx_rio) {
        duct_rio_tx_free(listener);
        return;
    }
    auto pools = listener->tx_slots;
    auto st = (iocp_dgram_tx_t *)listener->dgram_tx_pool;
    listener->tx_slots = nullptr;
    listener->dgram_tx_pool = nullptr;
    if (!pools)
        return;
    if (!st) {
        duct_listener_tx_slots_free(pools);
        return;
    }
    st->closing = true;
    st->listener = nullptr;
    if (!st->inflight)
        s_dgram_tx_release(st);
}

static bool s_dgram_tx_post(void *arg, const duct_dgram_tx_entry_t *entry)
{
    auto st = (iocp_dgram_tx_t *)arg;
    duct_do_if(!st->free_count, return false);
    auto pools = st->pools;
    unsigned at = st->free_stack[--st->free_count];
    auto ctl = &duct_at(st->ctls)[at];
    uint32_t ref = entry->slot;
    auto addr = (struct sockaddr_storage *)duct_x_slot_data(duct_x_slot_ref_pool(pools, ref),
                                                            ref & ~duct_x_slot_ref_large);
    auto data = duct_x_slot_span(pools, ref);
    *ctl = (iocp_dgram_tx_ctl_t){
        .packed = s_tag_pack(iocp_op_dgram_tx, nullptr),
        .buf = { entry->len, data.data },
        .addrlen = duct_io_sockaddr_from_peer(&entry->peer, addr),
        .ref = ref, .st = st,
    };
    ctl->wsamsg = (WSAMSG){
        .name = (LPSOCKADDR)addr,
        .namelen = ctl->addrlen,
        .lpBuffers = &ctl->buf,
        .dwBufferCount = 1u,
    };
    int rc = WSASendMsg(st->listener->listen_fd, &ctl->wsamsg, 0u, &(DWORD){0u}, &ctl->ov, nullptr);
    if (rc != 0 && WSAGetLastError() != WSA_IO_PENDING) {
        st->free_stack[st->free_count++] = at;
        duct_x_slot_put(pools, ref);
        return true;
    }
    ++st->inflight;
    return true;
}

static void s_dgram_tx_drain(iocp_dgram_tx_t *st)
{
    duct_io_dgram_send_drain(st->listener, s_dgram_tx_post, st);
}

static void s_dgram_tx_settle(iocp_dgram_tx_ctl_t *ctl, bool redrain)
{
    auto st = ctl->st;
    st->free_stack[st->free_count++] = (unsigned)(ctl - duct_at(st->ctls));
    duct_x_slot_put(st->pools, ctl->ref);
    if (--st->inflight == 0u && st->closing)
        s_dgram_tx_release(st);
    else if (redrain && !st->closing)
        s_dgram_tx_drain(st);
}

bool duct_events_dgram_tx_kick([[maybe_unused]] duct_events_env_t *env, duct_listener_t *listener)
{
    duct_do_if(!listener->dgram_tx_outbox, return true);
    if (listener->dgram_tx_rio) {
        duct_rio_tx_drain(s_rio,listener);
        return true;
    }
    auto st = (iocp_dgram_tx_t *)listener->dgram_tx_pool;
    if (st)
        s_dgram_tx_drain(st);
    return true;
}

duct_x_slot_hooks_t duct_events_x_slot_hooks(void)
{
    return s_rio ? duct_rio_slot_hooks(s_rio) : (duct_x_slot_hooks_t){};
}

/** @brief Result of a read that returned no bytes, by its @p status.
 *  Success is the peer's FIN, @c events_status_cancelled answers @p cancelled, and any other
 *  status is fatal. */
static inline duct_result_t s_empty_read_rc(ULONG_PTR status, duct_result_t cancelled)
{
    return status == 0u ? rc_closed
         : status == events_status_cancelled ? cancelled : rc_fatal;
}

/** @brief RX completion handler for a conn's @c WSARecv or @c WSARecvMsg read of kind @p kind.
 *  @p status is the completion's @c Internal NTSTATUS: @ref
 *  events_status_buffer_overflow means Winsock already discarded a datagram too
 *  large for the posted buffer, nothing to commit. @p seg is the segment size a
 *  coalesced @c WSARecvMsg read reported, 0 otherwise. A zero-byte @c iocp_op_rx read ends
 *  a stream's input, or closes the conn with an error under a failed status other than a
 *  cancel, as a reset peer leaves; a zero-byte @c iocp_op_rx_msg read is an empty datagram.
 *  Every completion chains the next read, which the reserve refuses once the input has ended
 *  or the conn is closed.
 */
static inline void s_on_rx_completion(iocp_op_kind_t kind, void *tag, DWORD bytes,
                                      ULONG_PTR status, size_t seg)
{
    if (status == events_status_buffer_overflow)
        duct_io_rx_done(tag, rc_drop);
    else if (bytes == 0u)
        duct_io_rx_done(tag, kind == iocp_op_rx ? s_empty_read_rc(status, rc_closed) : rc_closed);
    else {
        duct_io_rx_commit(tag, (size_t)bytes, seg);
        duct_io_rx_done(tag, rc_again);
    }
    duct_events_drive_rx(tag); /* chain the next read */
}

/** @brief @c WSASend completion handler. */
static inline void s_on_tx_completion(void *tag, DWORD bytes, size_t offered)
{
    duct_io_tx_advance(tag, offered, (size_t)bytes);
    duct_io_tx_done(tag, rc_again); /* no-op unless rc_fatal, kept for contract parity */
    duct_events_drive_tx(tag); /* peek returns false once genuinely drained, ending the chain */
}

/** @brief @c WSASendMsg completion handler for an @c x_udp_peer send.
 *  Advances past every record the send carried, delivered or not, then chains
 *  the next send. */
static inline void s_on_tx_records_completion(void *tag, unsigned records)
{
    duct_io_tx_advance_records(tag, records);
    duct_io_tx_done(tag, rc_again);
    duct_events_drive_tx(tag);
}

/** @brief @c AcceptEx completion handler.
 *  @p status is the completion's @c Internal NTSTATUS. A nonzero one, which a connection
 *  reset before the accept leaves, and a failed context update both close the accept socket
 *  and post the next @c AcceptEx with nothing dispatched. Otherwise the next @c AcceptEx is
 *  posted after the dispatch, unless the listener is held, which
 *  @ref duct_events_listener_rx_interest re-arms when its pause ends.
 */
static inline void s_on_accept_completion(listener_ctx_t *ctx, ULONG_PTR status)
{
    auto lst = ctx->listener;
    duct_sock_t accepted = ctx->accept_fd;
    ctx->accept_fd = duct_sock_bad;
    if (status != 0u) {
        closesocket(accepted);
        s_accept_rearm(ctx);
        return;
    }
    int rc = setsockopt(accepted, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
                        (const char *)&lst->listen_fd, sizeof lst->listen_fd);
    duct_do_if(rc != 0,
        closesocket(accepted);
        s_accept_rearm(ctx);
        return;
    );
    duct_xset_nonblock(accepted);
    if (lst->xport_type != x_local)
        duct_xset_tcp_nodelay(accepted);

    struct sockaddr *local_addr = nullptr, *remote_addr = nullptr;
    static constexpr DWORD addr_slot = sizeof(struct sockaddr_storage) + 16u;
    pfnGetAcceptExSockaddrs(ctx->addr_buf, 0u, addr_slot, addr_slot,
                            &local_addr, &(int){0}, &remote_addr, &(int){0});
    auto peer = duct_io_peer_from_sockaddr(remote_addr);
    duct_io_on_accept(lst, accepted, &peer);
    if (!duct_listener_held(lst))
        s_accept_rearm(ctx); /* re-arm */
}

/** @brief Dispatch one classified datagram, then repost. @see
 *  s_on_accept_completion for the parallel accept-side handler. */
static void s_on_dgram_completion(listener_ctx_t *ctx, DWORD bytes, ULONG_PTR status)
{
    auto lst = ctx->listener;
    if (status == 0u) {
        auto peer = duct_io_peer_from_sockaddr((const struct sockaddr *)&ctx->dgram.from_addr);
        uint32_t seg = (uint32_t)duct_x_gro_seg(ctx->dgram.rx.msg.Control);
        if (ctx->rx_slot == treiber_empty)
            duct_io_on_dgram(lst, &peer, &(duct_view_u8){ .data = ctx->rx_priv, .size = bytes }, seg);
        else {
            uint32_t next = duct_x_slot_acquire(ctx->rx_pool);
            bool lent = duct_io_on_dgram_slot(lst, &peer, ctx->rx_slot, bytes, seg,
                                              next != treiber_empty);
            if (lent)
                ctx->rx_slot = next;
            else if (next != treiber_empty)
                duct_x_slot_release(ctx->rx_pool, next);
        }
    }
    s_post_dgram(ctx); /* re-arm after dispatch to avoid mid-read overwrite */
}

static inline void s_on_completion(duct_events_env_t *env, OVERLAPPED_ENTRY *entries, ULONG i)
{
    if (!entries[i].lpOverlapped)
        return duct_io_on_wake();
    auto op = (iocp_op_t *)entries[i].lpOverlapped;
    iocp_op_kind_t kind;
    auto tag = s_tag_unpack(op->packed, &kind);
    switch (kind) {
    case iocp_op_rx:
        if (!duct_olb_io_done(s_op_hdr(op)))
            s_on_rx_completion(kind, tag, entries[i].dwNumberOfBytesTransferred, entries[i].Internal, 0u);
        break;
    case iocp_op_rx_msg:
        if (!duct_olb_io_done(s_op_hdr(op)))
            s_on_rx_completion(kind, tag, entries[i].dwNumberOfBytesTransferred, entries[i].Internal,
                               duct_x_gro_seg(op->rx_msg->Control));
        break;
    case iocp_op_rx_failed:
        /* No kernel op behind it: duct_events_drive_rx queued the refusal of a read, and the
         * close it ends in runs here. */
        if (!duct_olb_io_done(s_op_hdr(op)))
            duct_io_rx_done(tag, rc_fatal);
        break;
    case iocp_op_tx:
        if (!duct_olb_io_done(s_op_hdr(op)))
            s_on_tx_completion(tag, entries[i].dwNumberOfBytesTransferred, (size_t)op->buf.len);
        break;
    case iocp_op_tx_records:
        if (!duct_olb_io_done(s_op_hdr(op)))
            s_on_tx_records_completion(tag, op->records);
        break;
    case iocp_op_connect:
        duct_del(op);
        auto pre_conn = (duct_pre_conn_t *)tag;
        ULONG_PTR status = entries[i].Internal;
        duct_result_t rc = status == 0u ? rc_ok
                         : status == events_status_connection_refused ? rc_conn_refused : rc_fatal;
        /* A ConnectEx socket takes SO_UPDATE_CONNECT_CONTEXT ahead of the plain socket
         * calls its conn makes; the fire has already closed a timed-out dial's socket. */
        if (rc == rc_ok && !pre_conn->timed_out)
            duct_discard setsockopt(pre_conn->fd, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, nullptr, 0);
        duct_io_on_pre_conn_dialed(pre_conn, rc);
        break;
    case iocp_op_probe:
        /* No bytes with success is the peer's FIN; with events_status_cancelled it is
         * the deadline's cancel, handed up as rc_ok to resolve with the bytes held. */
        duct_del(op);
        pre_conn = (duct_pre_conn_t *)tag;
        DWORD bytes = entries[i].dwNumberOfBytesTransferred;
        status = entries[i].Internal;
        rc = bytes ? rc_ok : s_empty_read_rc(status, rc_ok);
        if (duct_io_on_pre_conn_probed(pre_conn, rc, bytes) && !s_post_probe(pre_conn))
            duct_io_on_pre_conn_probed(pre_conn, rc_fatal, 0u);
        break;
    case iocp_op_dial_done:
        /* No kernel op behind it: the byte count is the dial's Winsock error, 0 for
         * a datagram dial whose plain connect() completed in duct_xconnect. */
        duct_del(op);
        duct_io_on_pre_conn_dialed((duct_pre_conn_t *)tag,
                                   duct_x_connect_rc((int)entries[i].dwNumberOfBytesTransferred));
        break;
    case iocp_op_accept:
    case iocp_op_dgram:
        /* Both post listener_ctx_t* payload and need the same closing check. */
        auto ctx = (listener_ctx_t *)tag;
        if (!ctx->listener) {
            /* Nulled by duct_events_unwatch / thread_fini — nothing left to process. */
            if (ctx->accept_fd != duct_sock_bad)
                closesocket(ctx->accept_fd);
            s_listener_ctx_del(ctx);
        } else {
            /* Neither branch frees ctx — both rearm or reuse it in-place. */
            kind == iocp_op_dgram
                ? s_on_dgram_completion(ctx, entries[i].dwNumberOfBytesTransferred, entries[i].Internal)
                : s_on_accept_completion(ctx, entries[i].Internal);
        }
        break;
    case iocp_op_dgram_tx:
        s_dgram_tx_settle((iocp_dgram_tx_ctl_t *)op, true);
        break;
    case iocp_op_rio:
        duct_rio_cq_drain(s_rio,env->rio_cq);
        break;
    case iocp_op_device:
        s_on_device_completion((iocp_device_t *)tag);
        break;
    }
}

void duct_events_run_loop(duct_events_env_t *env, bool _Atomic *shutdown)
{
    OVERLAPPED_ENTRY entries[events_max_batch];
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
                      : timer_ms == DUCT_TIMEOUT_INFINITE ? INFINITE : (DWORD)timer_ms;
        ULONG n = 0u;
        int rc = GetQueuedCompletionStatusEx(env->iocp, entries, events_max_batch, &n, timeout, FALSE);
        if (!rc)
            switch (rc = GetLastError()) {
            case WAIT_TIMEOUT:
                break;
            default:
                /* TODO: handle error */
                return;
            }
        in_window = duct_spin_next(&spin, n > 0u, duct_ticks_mono_ns());
        if (n == 0u)
            duct_cpu_relax();
        for (ULONG i = 0u; i < n; ++i)
            s_on_completion(env, entries, i);
    }
}

