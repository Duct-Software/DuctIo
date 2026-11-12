/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_rio.h
 *  @brief Vendored Winsock Registered I/O surface, and the datagram receive
 *  ring and send pool both Windows backends run on.
 *
 *  mingw-w64 declares none of the RIO surface, so the vendored half mirrors
 *  the documented Windows SDK shapes: opaque handles, the
 *  RIO_BUF/RIORESULT layouts, the LPFN_RIO* signatures, and the
 *  RIO_EXTENSION_FUNCTION_TABLE @ref duct_rio_load fills via WSAIoctl.
 *
 *  Everything past that table is this project's own: one completion queue
 *  per io thread, and per RIO-active listener one receive ring plus, where
 *  the listener has a TX outbox, one send state. The ring reads into private
 *  cells and into slots of the listener's RX pool, and the send state posts
 *  from the slots of its TX pools; @ref duct_rio_slot_hooks registers their
 *  chunks. Both live in this module, parameterised only by the table each
 *  backend resolved — iocp and wsaevent differ in how a completion is
 *  delivered, never in what the ring and the send state do.
 */

#ifndef DUCT_RIO_H
#define DUCT_RIO_H

#include "duct_core.h"
#include "duct_events.h"
#include "duct_x_slot.h"

#include <winsock2.h>
#include <mswsock.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Opaque RIO handles: registered buffer, completion queue, request
 *  queue. */
typedef struct RIO_BUFFERID_t *RIO_BUFFERID;
typedef struct RIO_CQ_t       *RIO_CQ;
typedef struct RIO_RQ_t       *RIO_RQ;

#define DUCT_RIO_INVALID_BUFFERID ((RIO_BUFFERID)(ULONG_PTR)0xFFFFFFFFu)

static inline bool duct_rio_buf_ok(RIO_BUFFERID id)
{
    return id && id != DUCT_RIO_INVALID_BUFFERID;
}

/** @brief Registered-buffer span: offset/length into a RIORegisterBuffer
 *  region, not raw bytes. */
typedef struct _RIO_BUF {
    RIO_BUFFERID BufferId;
    ULONG        Offset;
    ULONG        Length;
} RIO_BUF, *PRIO_BUF;

/** @brief One dequeued completion. @c SocketContext/@c RequestContext echo
 *  back whatever the original RIOReceive/RIOSend call was posted with. */
typedef struct _RIORESULT {
    LONG      Status;
    ULONG     BytesTransferred;
    ULONGLONG SocketContext;
    ULONGLONG RequestContext;
} RIORESULT, *PRIORESULT;

/** @brief Header of a @c RIOReceiveEx control area. @c TotalLength counts the
 *  header and the @c WSACMSGHDR entries that follow it at
 *  @ref RIO_CMSG_BASE_SIZE. */
typedef struct _RIO_CMSG_BUFFER {
    ULONG TotalLength;
} RIO_CMSG_BUFFER, *PRIO_CMSG_BUFFER;

/** @brief Offset of the first cmsg past a @c RIO_CMSG_BUFFER header. */
#define RIO_CMSG_BASE_SIZE \
    ((sizeof(RIO_CMSG_BUFFER) + alignof(WSACMSGHDR) - 1u) & ~(alignof(WSACMSGHDR) - 1u))

/** @brief RIO completion-queue notification kind. */
typedef enum _RIO_NOTIFICATION_COMPLETION_TYPE {
    RIO_EVENT_COMPLETION = 1,
    RIO_IOCP_COMPLETION  = 2,
} RIO_NOTIFICATION_COMPLETION_TYPE;

/** @brief Where a completion queue's completions are delivered. */
typedef struct _RIO_NOTIFICATION_COMPLETION {
    RIO_NOTIFICATION_COMPLETION_TYPE Type;
    union {
        struct {
            HANDLE EventHandle;
            BOOL   NotifyReset;
        } Event;
        struct {
            HANDLE       IocpHandle;
            PVOID        CompletionKey;
            LPOVERLAPPED Overlapped;
        } Iocp;
    };
} RIO_NOTIFICATION_COMPLETION, *PRIO_NOTIFICATION_COMPLETION;

/** @brief Not declared by mingw; built from the same _WSAIORW/IOC_WS2
 *  macros Winsock already exposes. */
#define SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER _WSAIORW(IOC_WS2, 36)

/** @brief GUID identifying the multi-function RIO extension table.
 *  Passed to WSAIoctl by @ref duct_rio_load to fetch the whole table in
 *  one call. */
#define WSAID_MULTIPLE_RIO \
    {0x8509e081, 0x96dd, 0x4005, \
     {0xb1, 0x65, 0x9e, 0x2e, 0xe8, 0xc7, 0x9e, 0x3f}}

/** @brief RIOSend/RIOSendEx dwFlags values.
 *  DEFER queues a send without committing it to the NIC; a later call on
 *  the same queue without DEFER, or with COMMIT_ONLY alone, flushes
 *  everything deferred so far. DONT_NOTIFY skips waking the completion
 *  queue for that one op. */
#define RIO_MSG_DONT_NOTIFY 0x00000001
#define RIO_MSG_DEFER       0x00000002
#define RIO_MSG_COMMIT_ONLY 0x00000008

/** @brief SDK-documented RIOxxx signatures — one per
 *  RIO_EXTENSION_FUNCTION_TABLE field below, same order. */
typedef BOOL (WINAPI *LPFN_RIORECEIVE)(
    RIO_RQ SocketQueue, PRIO_BUF pData, ULONG DataBufferCount,
    DWORD dwFlags, PVOID RequestContext);

typedef INT (WINAPI *LPFN_RIORECEIVEEX)(
    RIO_RQ SocketQueue, PRIO_BUF pData, ULONG DataBufferCount,
    PRIO_BUF pLocalAddress, PRIO_BUF pRemoteAddress,
    PRIO_BUF pControlContext, PRIO_BUF pFlags,
    DWORD dwFlags, PVOID RequestContext);

typedef BOOL (WINAPI *LPFN_RIOSEND)(
    RIO_RQ SocketQueue, PRIO_BUF pData, ULONG DataBufferCount,
    DWORD dwFlags, PVOID RequestContext);

typedef BOOL (WINAPI *LPFN_RIOSENDEX)(
    RIO_RQ SocketQueue, PRIO_BUF pData, ULONG DataBufferCount,
    PRIO_BUF pLocalAddress, PRIO_BUF pRemoteAddress,
    PRIO_BUF pControlContext, PRIO_BUF pFlags,
    DWORD dwFlags, PVOID RequestContext);

typedef VOID (WINAPI *LPFN_RIOCLOSECOMPLETIONQUEUE)(RIO_CQ CQ);

typedef RIO_CQ (WINAPI *LPFN_RIOCREATECOMPLETIONQUEUE)(
    DWORD QueueSize, PRIO_NOTIFICATION_COMPLETION NotificationCompletion);

typedef RIO_RQ (WINAPI *LPFN_RIOCREATEREQUESTQUEUE)(
    SOCKET Socket,
    ULONG MaxOutstandingReceive, ULONG MaxReceiveDataBuffers,
    ULONG MaxOutstandingSend, ULONG MaxSendDataBuffers,
    RIO_CQ ReceiveCQ, RIO_CQ SendCQ, PVOID SocketContext);

typedef ULONG (WINAPI *LPFN_RIODEQUEUECOMPLETION)(
    RIO_CQ CQ, PRIORESULT Array, ULONG ArraySize);

typedef BOOL (WINAPI *LPFN_RIODEREGISTERBUFFER)(RIO_BUFFERID BufferId);

typedef INT (WINAPI *LPFN_RIONOTIFY)(RIO_CQ CQ);

typedef RIO_BUFFERID (WINAPI *LPFN_RIOREGISTERBUFFER)(
    PCHAR DataBuffer, DWORD DataLength);

typedef BOOL (WINAPI *LPFN_RIORESIZECOMPLETIONQUEUE)(
    RIO_CQ CQ, DWORD QueueSize);

typedef BOOL (WINAPI *LPFN_RIORESIZEREQUESTQUEUE)(
    RIO_RQ RQ, DWORD MaxOutstandingReceive, DWORD MaxOutstandingSend);

/** @brief The RIO extension function table, filled by @c WSAIoctl.
 *  Field order after @c cbSize must match the SDK exactly — a dropped or
 *  reordered pointer resolves silently to the wrong function, no crash at
 *  load time. See @ref duct_rio_load. */
typedef struct _RIO_EXTENSION_FUNCTION_TABLE {
    DWORD                          cbSize;
    LPFN_RIORECEIVE                RIOReceive;
    LPFN_RIORECEIVEEX              RIOReceiveEx;
    LPFN_RIOSEND                   RIOSend;
    LPFN_RIOSENDEX                 RIOSendEx;
    LPFN_RIOCLOSECOMPLETIONQUEUE   RIOCloseCompletionQueue;
    LPFN_RIOCREATECOMPLETIONQUEUE  RIOCreateCompletionQueue;
    LPFN_RIOCREATEREQUESTQUEUE     RIOCreateRequestQueue;
    LPFN_RIODEQUEUECOMPLETION      RIODequeueCompletion;
    LPFN_RIODEREGISTERBUFFER       RIODeregisterBuffer;
    LPFN_RIONOTIFY                 RIONotify;
    LPFN_RIOREGISTERBUFFER         RIORegisterBuffer;
    LPFN_RIORESIZECOMPLETIONQUEUE  RIOResizeCompletionQueue;
    LPFN_RIORESIZEREQUESTQUEUE     RIOResizeRequestQueue;
} RIO_EXTENSION_FUNCTION_TABLE, *PRIO_EXTENSION_FUNCTION_TABLE;

/** @brief Resolve and validate the RIO extension function table.
 *
 *  @param probe  Any @c WSA_FLAG_REGISTERED_IO socket, used only to fetch
 *                the table — not retained. Winsock extension pointers are
 *                provider-scoped, not socket-scoped, though this file's
 *                test only exercises the same-socket case.
 *  @param out    Contents are undefined on a false return — do not read.
 *
 *  @return true once every pointer this codebase calls is non-null.
 */
duct_nonnull(2) bool
duct_rio_load(SOCKET probe, RIO_EXTENSION_FUNCTION_TABLE *out);

/** @brief Resolve the RIO extension function table without an
 *  already-open socket to probe with.
 *  Creates and discards its own throwaway socket around @ref
 *  duct_rio_load. Shared by every backend's ctor, so the probe-socket
 *  dance lives in one place.
 *
 *  @return The table, heap-allocated and kept for the process, or @c nullptr
 *          where RIO is off: the probe socket or the allocation failed, the
 *          provider lacks a function this codebase calls, or the build sets
 *          @c DUCT_RIO_FORCE_DISABLE. A backend keeps the pointer and reads
 *          @c nullptr as RIO unavailable.
 */
[[nodiscard]] RIO_EXTENSION_FUNCTION_TABLE *
duct_rio_resolve(void);

/** @brief Pool hooks that register each chunk of a slot pool as a RIO buffer.
 *  A chunk's cookie is its buffer id, which the ring and the send state build their spans from, and a
 *  retired chunk is deregistered. A registration the system refuses answers @c rc_again, so a later take
 *  retries it.
 */
duct_nonnull(1) duct_x_slot_hooks_t
duct_rio_slot_hooks(const RIO_EXTENSION_FUNCTION_TABLE *rio);

/** @brief Initial per-env RIO completion-queue depth, a starting margin only.
 *  @ref duct_rio_cq_ensure grows a live queue past this via
 *  RIOResizeCompletionQueue as RIO-active listeners register against it.
 *  A listener claims its RX ring depth plus @ref duct_rio_tx_depth, so the
 *  very first one already resizes whenever its ring exceeds 64 slots.
 */
static constexpr DWORD duct_rio_cq_depth = 128u;

/** @brief Floor on a RIO datagram RX ring's depth, slots. */
static constexpr unsigned duct_rio_rx_ring_min = 8u;
/** @brief Ceiling on a RIO datagram RX ring's depth, slots. */
static constexpr unsigned duct_rio_rx_ring_max = 1024u;

/** @brief Slots for a RIO datagram RX ring sized to a byte budget.
 *  Returns @p budget / @p cell clamped to [@ref duct_rio_rx_ring_min,
 *  @ref duct_rio_rx_ring_max]; @p cell 0 yields the floor. RIO drops
 *  datagrams that arrive with no receive posted, so this depth is the
 *  path's whole receive-buffer budget — callers pass the same budget the
 *  reactive backends give the kernel via SO_RCVBUF. */
static inline unsigned duct_rio_rx_ring_slots(size_t budget, unsigned cell)
{
    unsigned n = cell ? (unsigned)(budget / cell) : duct_rio_rx_ring_min;
    return n < duct_rio_rx_ring_min ? duct_rio_rx_ring_min
         : n > duct_rio_rx_ring_max ? duct_rio_rx_ring_max
         : n;
}

/** @name Completion context
 *  Every request this file posts carries a slot address as its
 *  @c RequestContext, and bit 0 of that address types the completion the
 *  dequeuing backend gets back. Both slot kinds are pointer-aligned, so the
 *  bit is free; each carries a @c static_assert that keeps it free.
 *  @{ */
static constexpr ULONGLONG duct_rio_ctx_send_bit = 1u;

/** @brief Tag @p slot as a send's completion context. */
static inline void *duct_rio_ctx_send(void *slot)
{
    return (void *)((uintptr_t)slot | (uintptr_t)duct_rio_ctx_send_bit);
}

/** @brief Whether completion context @p ctx belongs to a send. */
static inline bool duct_rio_ctx_is_send(ULONGLONG ctx)
{
    return (ctx & duct_rio_ctx_send_bit) != 0u;
}

/** @brief The slot address inside completion context @p ctx. */
static inline void *duct_rio_ctx_slot(ULONGLONG ctx)
{
    return (void *)(uintptr_t)(ctx & ~duct_rio_ctx_send_bit);
}
/** @} */

/** @brief One datagram listener's RIO receive ring, opaque outside this
 *  module.
 *  RIO drops a datagram that arrives with no receive posted, so the ring's
 *  posted receives are this path's whole receive-buffer budget — the role
 *  SO_RCVBUF plays on a readiness backend.
 */
typedef struct duct_rio_rx duct_rio_rx_t;

/** @brief One posted receive's completion context, opaque outside this
 *  module.
 *  A backend casts an RX completion's context to this and passes it on;
 *  nothing outside reads a field. */
typedef struct duct_rio_rx_slot duct_rio_rx_slot_t;

/** @brief Allocate and register a receive ring for @p listener.
 *  The cell is @p listener's datagram read span, and the depth follows from it
 *  through @ref duct_rio_rx_ring_slots. As many descriptors as the listener's
 *  RX pool lends, half of it at most, read into its slots; the rest read into
 *  private cells registered here. The ring is not postable until @ref
 *  duct_rio_rx_arm hands it a request queue.
 *
 *  @param owner     The backend's own listener context, freed together with
 *                    the ring once teardown finds no receive outstanding.
 *  @return @c nullptr on any allocation or registration failure, nothing
 *          left allocated then.
 */
duct_nonnull(1, 3) duct_rio_rx_t *
duct_rio_rx_create(const RIO_EXTENSION_FUNCTION_TABLE *rio, void *owner,
                   duct_listener_t *listener);

/** @brief Slot count @p ring was sized to.
 *  The RIOCreateRequestQueue @c MaxOutstandingReceive its owner must ask
 *  for, and half the completion-queue budget it must reserve. */
duct_nonnull(1) unsigned duct_rio_rx_depth(const duct_rio_rx_t *ring);

/** @brief Hand @p ring the request queue its receives post on. */
duct_nonnull(1) void duct_rio_rx_arm(duct_rio_rx_t *ring, RIO_RQ rq);

/** @brief Deregister @p ring's buffers, return its pooled slots to the RX pool and free it.
 *  For a setup that failed before anything was posted; @c owner is left
 *  alone. A ring that has run belongs to @ref duct_rio_rx_close. */
duct_nonnull(1, 2) void
duct_rio_rx_destroy(const RIO_EXTENSION_FUNCTION_TABLE *rio, duct_rio_rx_t *ring);

/** @brief Post every slot of @p ring.
 *  @return false only when not one receive went out, nothing outstanding
 *          then and the caller still owns the ring. */
duct_nonnull(1, 2) bool
duct_rio_rx_prime(const RIO_EXTENSION_FUNCTION_TABLE *rio, duct_rio_rx_t *ring);

/** @brief Give up the owner's claim on @p ring.
 *  Marks it closing, which stops delivery and re-posting, then frees the
 *  ring and its owner outright when no receive is outstanding. Callers pair
 *  it with clearing their own listener pointer, so both markers move
 *  together.
 *
 *  @return true when it freed; on false the receive that returns the last
 *          posted slot frees both, and neither is safe to touch meanwhile.
 */
duct_nonnull(1, 2) bool
duct_rio_rx_close(const RIO_EXTENSION_FUNCTION_TABLE *rio, duct_rio_rx_t *ring);

/** @brief Handle one dequeued RX completion for @p slot.
 *  Delivers the datagram when @p status is 0 and the ring is open, through
 *  @c duct_io_on_dgram for a private cell and @c duct_io_on_dgram_slot for a
 *  pooled one, which a route may keep for a replacement. Then returns the
 *  descriptor and re-posts as much of the ring as the OS accepts. On a
 *  closing ring it delivers nothing and may free the ring and its owner, so
 *  nothing the caller derived from @p slot survives this call.
 *
 *  @param status  The completion's own @c Status, non-zero for an aborted or
 *                  failed receive.
 *  @param bytes   Datagram length, read only when @p status is 0.
 */
duct_nonnull(1, 2) void
duct_rio_rx_dispatch(const RIO_EXTENSION_FUNCTION_TABLE *rio,
                     duct_rio_rx_slot_t *slot, LONG status, ULONG bytes);

/** @brief Completions taken per RIODequeueCompletion call.
 *  Sizes the stack array both queue drains read into. */
static constexpr ULONG duct_rio_cq_batch = 64u;

/** @brief Run @p cq's pending completions, then re-arm it.
 *  @ref duct_rio_ctx_is_send routes each to @ref duct_rio_tx_complete or
 *  @ref duct_rio_rx_dispatch, which own everything past that point. Loops
 *  until the queue reads empty, since one notification can cover several
 *  completions, and calls RIONotify last — dequeuing alone leaves the
 *  notification unarmed.
 */
duct_nonnull(1, 2) void
duct_rio_cq_drain(const RIO_EXTENSION_FUNCTION_TABLE *rio, RIO_CQ cq);

/** @brief Settle @p cq's pending completions at teardown, then re-arm it.
 *  @ref duct_rio_cq_drain's teardown counterpart, differing in one way: a
 *  settled send does not re-drain its listener's outbox, since a re-drain
 *  posts fresh sends on a closing socket.
 */
duct_nonnull(1, 2) void
duct_rio_cq_flush(const RIO_EXTENSION_FUNCTION_TABLE *rio, RIO_CQ cq);

/** @brief Sends a listener's RIO send state may have in flight at once.
 *  Sizes its descriptors and the RIOCreateRequestQueue
 *  @c MaxOutstandingSend each backend asks for. */
static constexpr unsigned duct_rio_tx_depth = 64u;

/** @brief One send in flight, the context of its posted request, opaque outside this
 *  module. */
typedef struct duct_rio_tx_op duct_rio_tx_op_t;

/** @brief Make @p listener's RIO send state over its TX slot pools.
 *  Stores the state in @c listener->dgram_tx_rio on success. A send posts from the slot a worker
 *  staged, so @ref duct_rio_tx_drain commits an outbox entry as soon as it posts the send, never on
 *  completion.
 *
 *  @param rio  The backend's resolved table, kept in the state for the sends it posts.
 *  @param rq   The listener's request queue, kept in the state.
 *  @return false with nothing allocated when the listener has no TX slot pools, when the pools lack
 *          the registering hooks or a lead that holds a peer address, or on an allocation failure.
 */
duct_nonnull(1, 3) bool
duct_rio_tx_create(const RIO_EXTENSION_FUNCTION_TABLE *rio, RIO_RQ rq, duct_listener_t *listener);

/** @brief Give up @p listener's claim on its RIO send state.
 *  Frees the state with the TX slot pools outright when no send is in flight, otherwise marks it
 *  closing and leaves the last completion to free it. Clears @c dgram_tx_rio and @c tx_slots
 *  either way. Takes a @p listener whose @c dgram_tx_rio holds a state.
 */
duct_nonnull(1) void
duct_rio_tx_free(duct_listener_t *listener);

/** @brief Post as many of @p listener's queued sends as its send state has free descriptors for.
 *  Writes each entry's peer address into the lead of the slot the entry names, posts the send from
 *  that slot and commits the entry; the payload stays where the worker staged it. Starts from a
 *  rotating lane so a sustained backlog on every lane does not always favor lane 0.
 */
duct_nonnull(1, 2) void
duct_rio_tx_drain(const RIO_EXTENSION_FUNCTION_TABLE *rio, duct_listener_t *listener);

/** @brief Send @p payload to @p peer now, from a TX slot of @p listener's own send state.
 *  The direct form a synchronous answer sends through: takes a free descriptor and slot, writes
 *  @p peer into the slot's lead and @p payload into its registered span, and posts one
 *  @c RIOSendEx at once — the slot and the descriptor return on the send's completion, the
 *  same settle a drained outbox entry rides. A raw send on this listener's socket would be
 *  lost: a socket registered for RIO serves RIO calls alone, so every send off it goes here.
 *
 *  @return false when the state is closing, no descriptor or no slot is free, or the post was
 *          refused; the caller treats it as the send it never got.
 */
duct_nonnull(1, 2) bool
duct_rio_tx_send(const duct_listener_t *listener, const duct_peer_t *peer, duct_view_u8 payload);

/** @brief Settle the completed send @p op: return its descriptor and its slot.
 *  A live state re-drains its listener's outbox, so a backlog deeper than the send depth refills
 *  as each send completes. A closing one is freed here once the settled send was the last in flight.
 */
duct_nonnull(1, 2) void
duct_rio_tx_complete(const RIO_EXTENSION_FUNCTION_TABLE *rio, duct_rio_tx_op_t *op);

/** @brief Create one completion queue armed for @p notify.
 *  @param rio        This backend's resolved table.
 *  @param notify     Backend-specific completion delivery, passed straight
 *                     to @c RIOCreateCompletionQueue.
 *  @param cq_depth   Set to @ref duct_rio_cq_depth on success, left
 *                     untouched otherwise.
 *  @param cq_used    Set to 0 on success, left untouched otherwise.
 *  @return The new @ref RIO_CQ, or @c nullptr on creation failure.
 */
duct_nonnull(1, 2, 3, 4) RIO_CQ
duct_rio_cq_create(const RIO_EXTENSION_FUNCTION_TABLE *rio,
                   PRIO_NOTIFICATION_COMPLETION notify,
                   DWORD *cq_depth, DWORD *cq_used);

/** @brief Close a completion queue.
 *  Takes a queue @ref duct_rio_cq_create returned. */
duct_nonnull(1) void
duct_rio_cq_close(const RIO_EXTENSION_FUNCTION_TABLE *rio, RIO_CQ cq);

/** @brief Grow a completion queue's shared admission budget by @p need.
 *
 *  RIOCreateRequestQueue's own admission check against @p cq is
 *  cumulative across every request queue sharing it, not per-queue --
 *  each call reserves @p need more of that shared total before the
 *  caller's own RIOCreateRequestQueue spends it. Resizes @p cq via
 *  RIOResizeCompletionQueue only when the running total exceeds the
 *  current depth; the used-total only grows across calls, even past a
 *  registration whose listener later closes.
 *
 *  @param cq_depth  This @p cq's own last-known depth: unchanged on
 *                    failure, raised to the new total on success.
 *  @param cq_used   Budget already claimed: unchanged on failure,
 *                    raised by @p need on success.
 *  @return false on a RIOResizeCompletionQueue failure; both counters
 *          and @p cq itself are left at their prior values.
 */
duct_nonnull(1, 3, 4) bool
duct_rio_cq_ensure(const RIO_EXTENSION_FUNCTION_TABLE *rio, RIO_CQ cq,
                   DWORD *cq_depth, DWORD *cq_used, DWORD need);

/** @brief Whether this backend's ctor resolved RIO successfully.
 *  Resolved once at process start; the same answer for the whole
 *  process's life. Defined by whichever Windows event backend is linked,
 *  and absent from the portable events contract, since the readiness
 *  backends have no use for it. */
bool duct_events_rio_available(void);

/** @brief Whether the linked backend actually posts @c x_udp_shared RX/TX
 *  through RIO. Distinct from @ref duct_events_rio_available's plain
 *  resolve-succeeded answer — @c iocp and @c wsaevent both define this as
 *  the same value; @c poll returns false unconditionally, since it never
 *  wires RIO into this xport's dgram socket even when RIO itself
 *  resolves. */
bool duct_events_dgram_shared_rio_capable(void);

/** @brief Whether this specific env's completion queue was created.
 *  Per-@p env state — each @ref duct_events_init call configures a separate queue,
 *  since multiple io thread environments can exist concurrently. */
duct_nonnull(1) bool duct_events_rio_cq_ready(duct_events_env_t *env);

#ifdef __cplusplus
}
#endif

#endif
