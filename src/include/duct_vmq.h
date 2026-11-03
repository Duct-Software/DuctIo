/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_vmq.h
 *  @brief Variable-message shared MPSC queues, one lane per producer.
 *
 *  Each message is an 8-byte @ref duct_vmq_hdr_t followed by payload.
 *  Packed @c {generation, offset} cursors detect wrap and prevent ABA.
 *  @ref duct_vmq_ctrl_t stores lane's cursors, wait flag, wake pointer and,
 *  on a conn's inter lane, the conn's TX hold;
 *  @ref duct_vmq_lane_t pairs that ctrl with its data span and capacity.
 *
 *  When a reservation fails, the producer arms @c wait_latch as intent and
 *  resumes its run loop; the consumer claims that flag via
 *  @ref duct_vmq_ack_waiter and wakes the producer by worker id. The claim
 *  fires even on an empty drain, closing the race between "consumer found
 *  nothing" and "producer is about to arm".
 *
 *  Producer side has two shapes: the single-call @ref duct_vmq_push copies its
 *  payload in, @ref duct_vmq_reserve + @ref duct_vmq_publish fill the payload
 *  span in place. Both are single-producer-only per lane — neither has a
 *  CAS/fetch_add on the tail.
 *
 *  A producer carries two cursors: @c alloc_gen hands out slots, @c tail_gen
 *  makes them visible, and they are equal whenever no reservation is
 *  outstanding. Which one an accessor reads decides which thread may call it —
 *  @ref duct_vmq_room is the producer's, @ref duct_vmq_unread the consumer's.
 *  Splitting them lets @ref duct_vmq_reserve_held keep a slot open across a
 *  callback while later traffic reserves behind it, unrefused.
 *
 *  Consumer wake is a unified protocol — @ref duct_vmq_notify: edge-store to
 *  @c wake_latch, futex on the 0→1 transition; sources without a dedicated lane
 *  are woken by worker id without modifying the latch.
 */

#ifndef DUCT_VMQ_H
#define DUCT_VMQ_H

#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "duct_core.h"
#include "duct_olb.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Bit position of the generation inside a packed cursor.
 *  A cursor carries the generation in the upper 32 bits, the offset in the
 *  lower.
 */
static constexpr unsigned vmq_gen_shift = 32;

/** @brief Mask selecting the offset out of a packed cursor. */
static constexpr uint64_t vmq_off_mask  = (uint64_t)(uint32_t)-1;

/** @brief Pack generation @p gen and offset @p off into one cursor word. */
#define vmq_pack(gen, off) \
    (((uint64_t)(gen) << vmq_gen_shift) | (uint64_t)(off))

/** @brief Generation half of packed cursor @p value. */
#define vmq_gen(value) ((uint32_t)((value) >> vmq_gen_shift))

/** @brief Offset half of packed cursor @p value, bytes. */
#define vmq_off(value) ((size_t)((value) & vmq_off_mask))

/** @brief Packed cursor one past reservation @p pos. */
#define vmq_pos_end(pos) vmq_pack((pos)->gen, (pos)->off + (pos)->aligned)

/** @brief Per-lane byte ceiling: caps clamp down to UINT32_MAX. */
static constexpr size_t vmq_lane_cap_max = (size_t)(uint32_t)-1;

/** @brief VMQ message header — 8 bytes, precedes every payload. */
typedef struct duct_vmq_hdr {
    uint8_t  type,      /**< Opaque message type tag. */
             pri;       /**< Priority lane class the message was posted to. */
    uint32_t total_len; /**< Header + payload length, bytes. */
    alignas(8u)
    char     payload[]; /**< Inline payload data. */
} duct_vmq_hdr_t;

/** @brief Header-only overhead per message, bytes. */
static constexpr size_t duct_vmq_msg_overhead = sizeof(duct_vmq_hdr_t);

/** @brief Aligned message size, bytes. */
#define vmq_msg_aligned(payload_size) \
    duct_align_up(duct_vmq_msg_overhead + (payload_size), 8u)

static_assert(sizeof(duct_vmq_hdr_t) == 8u,
    "hdr must be 8 bytes");
static_assert(offsetof(duct_vmq_hdr_t, payload) == 8u,
    "payload must be at 8-byte boundary");

/** @brief Dispatch state of a lane whose consumer runs on someone else's queue.
 *  @c vmq_drain_scheduled is one bit: a dispatch is queued and not yet started.
 *  @c vmq_drain_running is the unit of a count in the bits above it, not a
 *  second flag — a drain schedules its successor before it returns, so two
 *  overlap by design and one bit cannot hold that.
 */
typedef enum duct_vmq_drain_state : uint8_t {
    vmq_drain_idle      = 0u,
    vmq_drain_scheduled = 1u << 0,
    vmq_drain_running   = 1u << 1,
} duct_vmq_drain_state_t;

static_assert(sizeof(duct_vmq_drain_state_t) == sizeof(uint8_t),
    "drain state must stay one byte");

/** @brief VMQ control block — per-lane cursors + wake state. */
typedef struct duct_vmq_ctrl {
    duct_cacheline_struct(
        uint64_t _Atomic  head_gen; /**< Consumer cursor.
                                      *  Packed {gen, offset}, advanced by
                                      *  @c _commit_head.
                                      */
        uint32_t _Atomic  wait_latch; /**< Producer's pending-wake flag.
                                      *  Armed to 1 by the lane's producer when a
                                      *  reserve fails; cleared by that producer on
                                      *  a later success, or by the consumer's
                                      *  @c _ack_waiter CAS. 0 means no wake is
                                      *  owed. Only a backpressure path writes
                                      *  it, so sharing this line with head_gen
                                      *  costs no contention.
                                      */
        duct_vmq_drain_state_t _Atomic drain_state; /**< Consumer dispatch
                                      *  state.
                                      *  Zero from the anonymous mapping this
                                      *  block is carved out of, like every
                                      *  cursor beside it. Rides this line's
                                      *  padding, and is written once per
                                      *  batch, so it costs no contention here
                                      *  for the same reason wait_latch does
                                      *  not. */
        duct_tx_hold_t    tx_hold;  /**< Answer to an inter conn's message
                                      *  left parked, which holds the lane's
                                      *  next message. Zero from the mapping,
                                      *  none; the consumer worker alone
                                      *  writes and reads it, and no lane but
                                      *  a conn's inter lane uses it. */
    ); /* CL-0: dominated by consumer */

    duct_cacheline_struct(
        uint64_t _Atomic  tail_gen; /**< Visibility cursor: the consumer reads
                                      *  up to here.
                                      *  Packed {gen, offset}, advanced by
                                      *  @ref duct_vmq_advance.
                                      */
        uint64_t alloc_gen;           /**< Allocation cursor: the next slot is
                                      *  carved here.
                                      *  Plain, since the lane's one producer
                                      *  both writes and reads it. Runs ahead
                                      *  of @c tail_gen only while a
                                      *  reservation is held across other code.
                                      */

        uint32_t _Atomic *wake_latch; /**< Consumer's wake latch.
                                      *  E.g. @c duct_worker_t::wake_latch;
                                      *  nullptr when wake notification is unbound.
                                      *  Bound once by @c _bind_wake before the first push;
                                      *  read by @c _notify right after
                                      *  tail_gen's write on the same thread.
                                      */
    ); /* CL-1: dominated by producer */
} duct_vmq_ctrl_t;

static_assert(sizeof(duct_vmq_ctrl_t) == 2u * duct_cacheline_size,
    "ctrl must occupy exactly two cachelines");

static_assert(offsetof(duct_vmq_ctrl_t, tail_gen) == duct_cacheline_size,
    "producer/consumer cursors must not share a cache line");

/** @brief Per-lane control-block size, bytes.
 *  @ref duct_vmq_ctrl_t must occupy exactly two cache lines.
 */
static constexpr unsigned vmq_lane_ctrl_size = sizeof(duct_vmq_ctrl_t);

/** @name Consumer dispatch, for a lane drained off another thread's queue
 *  Arm claims the right to schedule one dispatch and answers the idle-to-armed
 *  edge, so a whole batch of pushes costs one. Disarm releases that claim
 *  partway through the drain, which lets a push arriving behind it schedule
 *  the next; enter and leave bracket the drain itself, and only they
 *  say when the lane's memory is unreferenced.
 *  @{
 */
duct_nonnull(1) static inline bool duct_vmq_drain_arm(duct_vmq_ctrl_t *ctrl)
{
    return (duct_atomic_fetch(or, &ctrl->drain_state, vmq_drain_scheduled, release)
            & vmq_drain_scheduled) == 0u;
}

duct_nonnull(1) static inline void duct_vmq_drain_disarm(duct_vmq_ctrl_t *ctrl)
{
    duct_atomic_fetch(and, &ctrl->drain_state,
                      (duct_vmq_drain_state_t)~vmq_drain_scheduled, release);
}

duct_nonnull(1) static inline void duct_vmq_drain_enter(duct_vmq_ctrl_t *ctrl)
{
    duct_atomic_fetch(add, &ctrl->drain_state, vmq_drain_running, acquire);
}

duct_nonnull(1) static inline void duct_vmq_drain_leave(duct_vmq_ctrl_t *ctrl)
{
    duct_atomic_fetch(sub, &ctrl->drain_state, vmq_drain_running, release);
}

duct_nonnull(1) static inline bool duct_vmq_drain_idle(const duct_vmq_ctrl_t *ctrl)
{
    return duct_atomic_load(&ctrl->drain_state, acquire) < vmq_drain_running;
}
/** @} */

/** @brief Shared multi-producer single-consumer queue. */
typedef struct duct_vmq_mpsc {
    unsigned n_lanes;   /**< Independent lanes count. */
    size_t ctrl_offset, /**< Byte offset to lane control blocks. */
           data_offset, /**< Byte offset to lane data region. */
           total_size,  /**< Total allocation size, bytes. */
           tail_bytes,  /**< Page-rounded tail beyond the lanes, bytes. */
           lane_off[];  /**< n_lanes + 1 byte offsets into the data region:
                          *  lane i's data spans [lane_off[i], lane_off[i+1]),
                          *  so entry n_lanes ends the last lane and adjacent
                          *  differences are the lane capacities. */
} duct_vmq_mpsc_t;

/** @brief Consumer drain position snapshot for one lane. */
typedef struct duct_vmq_drain_pos {
    size_t  head,   /**< Current consumer byte offset. */
            tail,   /**< Producer byte offset captured at drain start. */
            step;   /**< Aligned size of last peeked message, bytes. */
    uint32_t gen;   /**< vmq_gen half of the tail snapshot — the wrap epoch
                      *  this pass drains; handed back to @c _commit_head so
                      *  the new head lands in that same epoch. */
} duct_vmq_drain_pos_t;

/** @brief One queue lane, as a view.
 *  Assembled by @ref duct_mpsc_lane. Mutable state is behind the pointers;
 *  the view itself is immutable and must not outlive its queue.
 */
typedef struct duct_vmq_lane {
    duct_vmq_ctrl_t *ctrl; /**< Lane cursors + wake state;
                             *  points into the parent queue. */
    size_t capacity;       /**< Payload data size, bytes. */
    char *data;             /**< Lane payload region base. */
} duct_vmq_lane_t;

/** @brief Ctrl block pointer for specified @c lane. */
duct_nonnull(1) static inline duct_vmq_ctrl_t *
duct_mpsc_ctrl(duct_vmq_mpsc_t *q, unsigned lane)
{
    return (duct_vmq_ctrl_t *)
        ((char *)q + q->ctrl_offset + (size_t)lane * vmq_lane_ctrl_size);
}

/** @brief Lane capacity, bytes. */
duct_nonnull(1) static inline size_t
duct_mpsc_cap(duct_vmq_mpsc_t *q, unsigned lane)
{
    return q->lane_off[lane + 1] - q->lane_off[lane];
}

/** @brief Lane payload pointer. */
duct_nonnull(1) static inline char *
duct_mpsc_data(duct_vmq_mpsc_t *q, unsigned lane)
{
    return (char *)q + q->data_offset + q->lane_off[lane];
}

/** @brief Get single lane at specified @c lane position. */
duct_nonnull(1) static inline duct_vmq_lane_t
duct_mpsc_lane(duct_vmq_mpsc_t *q, unsigned lane)
{
    return (duct_vmq_lane_t){
        .ctrl = duct_mpsc_ctrl(q, lane),
        .data = duct_mpsc_data(q, lane),
        .capacity = duct_mpsc_cap(q, lane),
    };
}

/** @brief Base of the tail reserve, past the last lane's data.
 *  @return nullptr when @c tail_bytes is 0.
 */
duct_nonnull(1) static inline char *
duct_mpsc_tail_reserve(duct_vmq_mpsc_t *q)
{
    return q->tail_bytes > 0
        ? (char *)q + q->data_offset + q->lane_off[q->n_lanes]
        : nullptr;
}

/** @brief Page-rounded tail reserve size, bytes. */
duct_nonnull(1) static inline size_t
duct_mpsc_tail_reserve_bytes(duct_vmq_mpsc_t *q)
{
    return q->tail_bytes;
}

/** @brief Move @p ctrl's producer cursors past a finished slot ending at @p end.
 *  Advances @c alloc_gen always, @c tail_gen only when no reservation sits ahead
 *  of this slot, so a held slot's unwritten bytes never reach the consumer.
 */
duct_nonnull(1) static inline void
duct_vmq_advance(duct_vmq_ctrl_t *ctrl, uint64_t end)
{
    bool held = ctrl->alloc_gen != duct_atomic_load(&ctrl->tail_gen, relaxed);
    ctrl->alloc_gen = end;
    if (!held)
        duct_atomic_store(&ctrl->tail_gen, end, release);
}

/** @brief Unread bytes still awaiting in @p ctrl's lane.
 *  Within one epoch that is @c tail minus @c head; once the producer has
 *  wrapped ahead, the whole span up to @c tail is unread — a lane emptied right
 *  before that wrap leaves @c head in the older epoch, so comparing the two
 *  cursors for equality reports it as full.
 *  Reads @c tail_gen for consumer inspection; @ref duct_vmq_room evaluates
 *  available space from producer-side @c alloc_gen and must be called by the
 *  producer.
 */
duct_nonnull(1) static inline size_t
duct_vmq_unread(const duct_vmq_ctrl_t *ctrl)
{
    uint64_t tg = duct_atomic_load(&ctrl->tail_gen, relaxed),
             hg = duct_atomic_load(&ctrl->head_gen, relaxed);
    size_t tail_off = vmq_off(tg),
           head_off = vmq_off(hg);
    return vmq_gen(tg) == vmq_gen(hg)
        ? (tail_off > head_off ? tail_off - head_off : 0)
        : tail_off;
}

duct_nonnull(1) static inline size_t
duct_mpsc_lane_unread(duct_vmq_mpsc_t *q, unsigned lane)
{
    return duct_vmq_unread(duct_mpsc_ctrl(q, lane));
}

/** @brief Defensive floor on an auto-sized lane's capacity; unreachable
 *  while auto-size is one page — every page size exceeds it.
 */
static constexpr size_t vmq_min_lane_cap = 256u;

/** @brief Allocate a multi-lane MPSC queue.
 *
 *  Lane i's capacity is @p caps[i], clamped to @ref vmq_lane_cap_max;
 *  @p caps[i] == 0 auto-sizes the lane to one page. A nonzero
 *  @p tail_reserve adds a page-rounded raw span after the last lane for caller
 *  use. Mapping-rounding slack grows the tail reserve if present, else adds
 *  extra space to the last lane.
 *
 *  @return nullptr on zero @p lanes, size overflow or mapping failure.
 */
duct_nonnull(2) static inline duct_vmq_mpsc_t *
duct_vmq_mpsc_create(unsigned lanes, const size_t *caps,
                     size_t tail_reserve)
{
    duct_do_if(!lanes, return nullptr);
    size_t  page_size = duct_page_size(),
            header_size = duct_align_up(
                sizeof(duct_vmq_mpsc_t) + (lanes + 1) * sizeof(size_t),
                duct_cacheline_size
            ),
            ctrl_size = duct_align_up(
                header_size + lanes * vmq_lane_ctrl_size,
                duct_cacheline_size
            ),
            fixed_size = 0,
            flex_count = 0;

    bool of;
    for (unsigned i = 0; i < lanes; ++i) {
        if (caps[i]) {
            of = duct_ckd_add(&fixed_size, fixed_size,
                              duct_min(caps[i], vmq_lane_cap_max));
            duct_do_if(of, return nullptr);
        } else
            ++flex_count;
    }

    size_t total_size = 0u;
    of = duct_ckd_add(&total_size, ctrl_size, fixed_size);
    duct_do_if(of, return nullptr);
    if (flex_count > 0u) {
        size_t spare      = total_size,
               flex_floor = 0;
        of = duct_ckd_sub(&spare, spare, ctrl_size)
          || duct_ckd_sub(&spare, spare, fixed_size)
          || duct_ckd_mul(&flex_floor, (size_t)flex_count, page_size);
        duct_do_if(of, return nullptr);
        if (spare < flex_floor) {
            size_t grow = 0;
            of = duct_ckd_sub(&grow, flex_floor, spare)
              || duct_ckd_add(&total_size, total_size, grow);
            duct_do_if(of, return nullptr);
        }
    }
    size_t tail_pad = tail_reserve > 0
        ? duct_align_up(tail_reserve, page_size)
        : 0u;
    if (tail_pad) {
        of = duct_ckd_add(&total_size, total_size, tail_pad);
        duct_do_if(of, return nullptr);
    }

    size_t remain = total_size;
    of = duct_ckd_sub(&remain, remain, ctrl_size)
      || duct_ckd_sub(&remain, remain, fixed_size)
      || duct_ckd_sub(&remain, remain, tail_pad);
    duct_do_if(of, return nullptr);

    size_t flex_each = 0;
    if (flex_count) {
        flex_each = (remain / flex_count) & ~7ull;
        duct_do_if(flex_each < vmq_min_lane_cap, return nullptr);
        if (flex_each > vmq_lane_cap_max)
            flex_each = vmq_lane_cap_max;
    }

    duct_vm_handle_t vm = duct_vm_new(total_size);
    duct_do_if(!vm.base, return nullptr);
    auto queue = (duct_vmq_mpsc_t *)vm.base;

    *queue = (duct_vmq_mpsc_t){
        .n_lanes = lanes,
        .ctrl_offset = header_size,
        .data_offset = ctrl_size,
        .total_size = vm.size,
        .tail_bytes = tail_pad,
    };

    size_t offset = 0;
    for (unsigned i = 0; i < lanes; ++i) {
        size_t cap = caps[i] != 0
            ? duct_min(caps[i], vmq_lane_cap_max)
            : flex_each;
        queue->lane_off[i] = offset;
        of = duct_ckd_add(&offset, offset, cap);
        duct_do_if(of, duct_vm_del(&vm); return nullptr);
    }
    queue->lane_off[lanes] = offset;
    if (vm.size > total_size) {
        auto slack = vm.size - total_size;
        if (tail_pad)
            queue->tail_bytes += slack;
        else
            queue->lane_off[lanes] += slack;
    }
    return queue;
}

/** @brief Create a shared MPSC queue.
 *  Optional-argument front for @ref duct_vmq_mpsc_create above.
 *
 *  @note Argument list > 3 is invalid, evaluates to nullptr.
 */
#define duct_vmq_mpsc_new(lanes, capacities, ...)                       \
    ({                                                                  \
        size_t _va[2] = { 0 __VA_OPT__(, __VA_ARGS__) },                \
               _vc = sizeof((size_t[]){ 0 __VA_OPT__(, __VA_ARGS__) })  \
                     / sizeof(size_t) - 1;                              \
        (_vc > 1) ? (duct_vmq_mpsc_t *)nullptr                          \
                   : duct_vmq_mpsc_create((lanes), (capacities),        \
                                          _vc == 0 ? 0 : _va[1]);       \
    })

/** @brief Destroy MPSC queue storage. */
duct_nonnull(1) static inline void duct_vmq_mpsc_del(duct_vmq_mpsc_t *q)
{
    duct_vm_handle_t vm = { .base = q, .size = q->total_size };
    duct_vm_del(&vm);
}

/** @brief Wake this lane's consumer, if bound to any. */
duct_nonnull(1) static inline void
duct_vmq_notify(duct_vmq_ctrl_t *ctrl)
{
    auto w = ctrl->wake_latch;
    if (w && duct_atomic_exchange(w, 1u, release) == 0u)
        duct_futex_wake((void *)w, 1);
}

/** @brief Bind lane to a wake latch once before the first push;
 *  the latch must outlive the queue.
 */
duct_nonnull(1) static inline void
duct_vmq_bind_wake(duct_vmq_ctrl_t *ctrl, uint32_t _Atomic *latch)
{
    ctrl->wake_latch = latch;
}

/** @brief Push result codes. */
typedef enum duct_vmq_push_rc : uint8_t {
    vmq_push_ok,            /**< Enqueued; for a reserve — slot carved,
                              *  publish still pending. */
    vmq_push_full,          /**< No contiguous room until the consumer
                              *  drains — transient. */
    vmq_push_rewind_fail,   /**< Wrap to offset 0 needed, but the consumer has
                              *  not reached the allocation cursor — transient.
                              */
    vmq_push_too_large,     /**< Header + payload exceeds the lane capacity
                              *  or the u32 @c total_len — permanent for
                              *  this lane. */
    vmq_push_err,           /**< Caller-side failure before the lane was
                              *  ever touched, e.g. OOM. */

    /** @note Add new codes before this one. */
    vmq_push_count          /**< Size sentinel. */
} duct_vmq_push_rc_t;

/** @brief Message type for a span its producer abandoned.
 *  Disjoint from family tag ranges, read by generic lane drains.
 */
static constexpr uint8_t vmq_msg_pad = 0xFFu;

/** @brief One in-flight reserve position.
 *  Produced by @ref duct_vmq_reserve, opaque to callers beyond handing it to
 *  @ref duct_vmq_publish.
 */
typedef struct duct_vmq_reserve_pos {
    uint32_t gen;      /**< Wrap epoch the slot was carved in; a reserve that
                         *  rewound the lane carves in the next one. */
    size_t   off,      /**< Slot offset in lane data, bytes. */
             aligned;  /**< Whole slot size: header + payload, 8-aligned;
                         *  publish advances the tail to off + aligned. */
} duct_vmq_reserve_pos_t;

/** @brief Carve @p payload_size contiguous bytes in the lane as a
 *  @p type / @p pri message, unpublished — the zero-copy producer half.
 *
 *  Single-producer only — no concurrent @c _reserve / @c _push on this lane
 *  from another thread. A second reserve before the publish is how a producer
 *  resizes a slot it has not published, and carves the same span unless the
 *  consumer caught up in between: the lane then rewinds and the slot moves to
 *  offset 0, so a resizing caller reads the returned pointer again and shifts
 *  whatever it had already written. @ref duct_vmq_reserve_held carves behind
 *  an existing reservation. The consumer sees published messages only after
 *  @ref duct_vmq_publish.
 *
 *  @return Payload span to write into, @p out_rc = @c vmq_push_ok;
 *          nullptr with the failure code in @p out_rc — @p out_pos is
 *          then untouched.
 */
duct_nonnull(1, 5, 6) static inline void *
duct_vmq_reserve(const duct_vmq_lane_t *ln,
                 uint8_t type, uint8_t pri,
                 size_t payload_size,
                 duct_vmq_reserve_pos_t *out_pos,
                 duct_vmq_push_rc_t *out_rc)
{
    size_t total = 0;
    if (duct_ckd_add(&total, sizeof(duct_vmq_hdr_t), payload_size)
        || total > (size_t)UINT32_MAX) {
        *out_rc = vmq_push_too_large;
        return nullptr;
    }
    size_t aligned = duct_align_up(total, 8u);
    if (aligned > ln->capacity) {
        *out_rc = vmq_push_too_large; /* can never fit even an empty lane */
        return nullptr;
    }
    uint64_t ag = ln->ctrl->alloc_gen;
    size_t off = vmq_off(ag);
    uint32_t gen = vmq_gen(ag);

    if (off != 0u) {
        uint64_t hg = duct_atomic_load(&ln->ctrl->head_gen, acquire);
        if (hg == ag) {
            off = 0u;
            ++gen;
            duct_vmq_advance(ln->ctrl, vmq_pack(gen, 0));
        } else if (off + aligned > ln->capacity) {
            *out_rc = vmq_push_rewind_fail;
            return nullptr;
        }
    }
    auto hdr = (duct_vmq_hdr_t *)(ln->data + off);
    hdr->type = type;
    hdr->pri = pri;
    hdr->total_len = (uint32_t)total;
    *out_pos = (duct_vmq_reserve_pos_t){ gen, off, aligned };
    *out_rc = vmq_push_ok;
    return hdr->payload;
}

/** @brief Bytes @p ln can still take from its producer.
 *  Sized for what @ref duct_vmq_reserve does next: the whole capacity once
 *  the consumer has caught up, since a reserve rewinds to zero exactly then;
 *  otherwise the contiguous span left before the lane end.
 *  Only the producer shrinks this, so a value read here holds until that
 *  same producer reserves again.
 */
duct_nonnull(1) static inline size_t
duct_vmq_room(const duct_vmq_lane_t *ln)
{
    uint64_t ag = ln->ctrl->alloc_gen,
             hg = duct_atomic_load(&ln->ctrl->head_gen, acquire);
    return hg == ag ? ln->capacity : ln->capacity - vmq_off(ag);
}

/** @brief Publish a carved slot: release-advance the tail past it, making
 *  the message visible to the consumer.
 *
 *  The payload span from @ref duct_vmq_reserve must be fully written by
 *  now: the release store orders those writes against the consumer's
 *  acquire. The producer must call @ref duct_vmq_notify
 *  once its batch is done.
 */
duct_nonnull(1, 2) static inline void
duct_vmq_publish(const duct_vmq_lane_t *ln, const duct_vmq_reserve_pos_t *pos)
{
    duct_vmq_advance(ln->ctrl, vmq_pos_end(pos));
}

/** @brief Cut @p hdr down to @p actual_payload_size bytes of payload.
 *  @return The slot's aligned size at that length — what a drain steps by.
 */
duct_nonnull(1) static inline size_t
duct_vmq_hdr_shrink(duct_vmq_hdr_t *hdr, size_t actual_payload_size)
{
    assert(sizeof(duct_vmq_hdr_t) + actual_payload_size <= hdr->total_len);
    hdr->total_len = (uint32_t)(sizeof(duct_vmq_hdr_t) + actual_payload_size);
    return duct_align_up(hdr->total_len, 8u);
}

/** @brief Publish a carved slot at less than its reserved size — e.g. a
 *  wire @c on_pack that writes fewer bytes than the worst-case bound it
 *  was sized against.
 *
 *  Updates @c total_len to the actual size and advances the tail by the
 *  re-aligned byte count, freeing unused trailing reservation bytes for
 *  subsequent allocations. Safe under the same single-producer-per-lane
 *  contract as @ref duct_vmq_reserve: nothing observes the gap between
 *  reserve and this call on the same lane.
 *
 *  @param actual_payload_size  Real payload size; must not exceed what
 *                              @ref duct_vmq_reserve originally carved.
 */
duct_nonnull(1, 2) static inline void
duct_vmq_publish_shrink(const duct_vmq_lane_t *ln, const duct_vmq_reserve_pos_t *pos,
                        size_t actual_payload_size)
{
    size_t kept = duct_vmq_hdr_shrink((duct_vmq_hdr_t *)(ln->data + pos->off),
                                      actual_payload_size);
    duct_vmq_advance(ln->ctrl, vmq_pack(pos->gen, pos->off + kept));
}

/** @brief Carve a slot and keep it invisible while other code runs.
 *
 *  Advances @c alloc_gen alone without moving @c tail_gen; subsequent
 *  reservations allocate fresh bytes after this slot and remain invisible
 *  until the hold resolves.
 *
 *  Take it on a lane with no reservation of any kind open. A second hold is
 *  caught by the entry assert; an unpublished ordinary @ref duct_vmq_reserve
 *  is not, since that one moves neither cursor — and the hold then carves the
 *  same span it did.
 *
 *  Close it with @ref duct_vmq_publish_held or @ref duct_vmq_abandon_held.
 *  Until the hold resolves, lane wrapping is inhibited; nested reservations
 *  requiring a wrap return @c vmq_push_rewind_fail to protect the held span.
 *
 *  @return Payload span to write into as @ref duct_vmq_reserve;
 *          @c nullptr with the failure code in @p out_rc.
 */
duct_nonnull(1, 5, 6) static inline void *
duct_vmq_reserve_held(const duct_vmq_lane_t *ln,
                      uint8_t type, uint8_t pri,
                      size_t payload_size,
                      duct_vmq_reserve_pos_t *out_pos,
                      duct_vmq_push_rc_t *out_rc)
{
    assert(ln->ctrl->alloc_gen == duct_atomic_load(&ln->ctrl->tail_gen, relaxed));
    auto span = duct_vmq_reserve(ln, type, pri, payload_size, out_pos, out_rc);
    if (span)
        ln->ctrl->alloc_gen = vmq_pos_end(out_pos);
    return span;
}

/** @brief Publish the held slot @p pos at the @p actual_payload_size it carries,
 *  together with everything reserved behind it.
 *
 *  With nothing behind it the slot shrinks and both cursors land on the shrunk
 *  end, so the unused tail is spendable before any drain, which bounds how
 *  many worst-case reservations a lane holds at once. With traffic behind
 *  it those bytes are already spoken for, so the freed tail becomes a
 *  @ref vmq_msg_pad the drain steps over.
 *
 *  Pair with @ref duct_vmq_notify, as @ref duct_vmq_publish is.
 */
duct_nonnull(1, 2) static inline void
duct_vmq_publish_held(const duct_vmq_lane_t *ln, const duct_vmq_reserve_pos_t *pos,
                      size_t actual_payload_size)
{
    size_t kept = duct_vmq_hdr_shrink((duct_vmq_hdr_t *)(ln->data + pos->off),
                                      actual_payload_size);
    if (ln->ctrl->alloc_gen == vmq_pos_end(pos)) {
        uint64_t end = vmq_pack(pos->gen, pos->off + kept);
        ln->ctrl->alloc_gen = end;
        duct_atomic_store(&ln->ctrl->tail_gen, end, release);
        return;
    }
    size_t gap = pos->aligned - kept;
    if (gap) {
        auto pad = (duct_vmq_hdr_t *)(ln->data + pos->off + kept);
        pad->type = vmq_msg_pad;
        pad->total_len = (uint32_t)gap;
    }
    duct_atomic_store(&ln->ctrl->tail_gen, ln->ctrl->alloc_gen, release);
}

/** @brief Close the held slot @p pos without publishing its payload.
 *  With nothing reserved behind it the span returns to the producer whole.
 *  Otherwise those later bytes are already spoken for, so the held header
 *  becomes @ref vmq_msg_pad and the rest publishes;
 *  @ref duct_vmq_drain_peek steps over the pad, so no lane callback sees it.
 */
duct_nonnull(1, 2) static inline void
duct_vmq_abandon_held(const duct_vmq_lane_t *ln, const duct_vmq_reserve_pos_t *pos)
{
    assert(ln->ctrl->alloc_gen != duct_atomic_load(&ln->ctrl->tail_gen, relaxed));
    if (ln->ctrl->alloc_gen == vmq_pos_end(pos)) {
        ln->ctrl->alloc_gen = duct_atomic_load(&ln->ctrl->tail_gen, relaxed);
        return;
    }
    auto hdr = (duct_vmq_hdr_t *)(ln->data + pos->off);
    hdr->type = vmq_msg_pad;
    duct_atomic_store(&ln->ctrl->tail_gen, ln->ctrl->alloc_gen, release);
}

/** @brief Single-attempt enqueue: reserve + payload copy + publish in one
 *  call.
 *
 *  Same single-producer contract and result codes as @ref duct_vmq_reserve.
 *  Does not wake the consumer — pair with @ref duct_vmq_notify.
 */
duct_nonnull(1) static inline duct_vmq_push_rc_t
duct_vmq_push(const duct_vmq_lane_t *ln,
              uint8_t type,
              uint8_t pri,
              const void *payload,
              size_t payload_size)
{
    duct_vmq_reserve_pos_t pos;
    duct_vmq_push_rc_t rc;
    auto dst = duct_vmq_reserve(ln, type, pri, payload_size, &pos, &rc);
    duct_do_if(!dst, return rc);
    if (payload_size)
        memcpy(dst, payload, payload_size);
    duct_vmq_publish(ln, &pos);
    return vmq_push_ok;
}

/** @brief Claim the lane's pending-wake flag: CAS @c wait_latch from 1 to 0.
 *
 *  The caller issues the actual wake notification when this function returns
 *  true. Evaluates even on an empty drain; the @c seq_cst fence against the
 *  producer arm-then-recheck sequence closes the race between empty inspection
 *  and producer arming.
 *
 *  @return true when this call claimed the flag.
 */
duct_nonnull(1) static inline bool
duct_vmq_ack_waiter(duct_vmq_ctrl_t *ctrl)
{
    uint32_t expected = 1;
    atomic_thread_fence(memory_order_seq_cst);
    if (!duct_atomic_load(&ctrl->wait_latch, relaxed))
        return false;
    return duct_atomic_cas(strong, &ctrl->wait_latch, &expected,
                           0, seq_cst, acquire);
}

/** @brief Reserve @p payload_size bytes, arming @c wait_latch before a second
 *  attempt when the first finds no room.
 *  The fence between the arm and that attempt pairs with the one
 *  @ref duct_vmq_ack_waiter runs first: either the attempt sees the
 *  consumer's drain, or the consumer claims the latch and wakes this producer.
 *  A landed attempt clears the latch; @c vmq_push_too_large never arms.
 *  @return the stage, or null with @p out_rc carrying the failing attempt's
 *  cause.
 */
duct_nonnull(1, 5, 6) static inline void *
duct_vmq_reserve_armed(const duct_vmq_lane_t *ln,
                       uint8_t type, uint8_t pri,
                       size_t payload_size,
                       duct_vmq_reserve_pos_t *out_pos,
                       duct_vmq_push_rc_t *out_rc)
{
    void *stage = duct_vmq_reserve(ln, type, pri, payload_size, out_pos, out_rc);
    if (stage || *out_rc == vmq_push_too_large)
        return stage;
    duct_atomic_store(&ln->ctrl->wait_latch, 1, relaxed);
    atomic_thread_fence(memory_order_seq_cst);
    stage = duct_vmq_reserve(ln, type, pri, payload_size, out_pos, out_rc);
    if (stage)
        duct_atomic_store(&ln->ctrl->wait_latch, 0, relaxed);
    return stage;
}

/** @brief Publish the consumer position: release-store packed {gen, head},
 *  returning the drained span to the producer.
 *
 *  Does not touch @c wait_latch — a producer's pending wake is claimed
 *  separately, by @ref duct_vmq_ack_waiter.
 */
duct_nonnull(1) static inline void
duct_vmq_commit_head(const duct_vmq_lane_t *ln,
                     uint32_t gen, size_t head)
{
    duct_atomic_store(&ln->ctrl->head_gen, vmq_pack(gen, head), release);
}

/** @brief Snapshot tail/head into a drain position.
 *
 *  A producer wrap since the last pass — tail epoch ahead of head's —
 *  resyncs: head restarts at 0 in the new epoch and is then committed,
 *  so the producer's next rewind check sees the caught-up epoch.
 */
duct_nonnull(1) static inline duct_vmq_drain_pos_t
duct_vmq_drain_begin(const duct_vmq_lane_t *ln)
{
    uint64_t tg = duct_atomic_load(&ln->ctrl->tail_gen, acquire),
             hg = duct_atomic_load(&ln->ctrl->head_gen, relaxed);
    uint32_t gen = vmq_gen(tg);
    size_t head = vmq_off(hg);

    if (gen != vmq_gen(hg)) {
        head = 0;
        duct_vmq_commit_head(ln, gen, 0);
    }
    return (duct_vmq_drain_pos_t){
        .head = head,
        .tail = vmq_off(tg),
        .step = 0,
        .gen = gen
    };
}

/** @brief Next message of the pass.
 *
 *  Sets @c pos->step to the message's aligned size — the caller advances
 *  @c pos->head by it after dispatch. A zero or snapshot-overrunning
 *  @c total_len ending the pass is a corrupt-header guard.
 *
 *  @ref vmq_msg_pad spans are stepped over here, so a pass returns fewer
 *  messages than the producer published whenever a hold was abandoned.
 *
 *  @return message header;
 *          @c nullptr if the snapshot is exhausted.
 */
duct_nonnull(1, 2) static inline duct_vmq_hdr_t *
duct_vmq_drain_peek(const duct_vmq_lane_t *ln,
                    duct_vmq_drain_pos_t *pos)
{
    for (;;) {
        if (pos->head >= pos->tail)
            return nullptr;
        auto hdr = (duct_vmq_hdr_t *)(ln->data + pos->head);
        pos->step = duct_align_up(hdr->total_len, 8u);
        duct_do_if(!pos->step || pos->head + pos->step > pos->tail,
            return nullptr
        );
        if (hdr->type != vmq_msg_pad) {
            duct_prefetch_read(ln->data + pos->head + pos->step);
            return hdr;
        }
        pos->head += pos->step;
    }
}

/** @brief Drain one lane snapshot: begin, peek loop, a single commit at
 *  pass end.
 *
 *  @p cb runs per message and must finish with the bytes — the commit
 *  returns them to the producer.
 *
 *  @return Number of messages dispatched.
 */
duct_nonnull(1, 2) static inline size_t
duct_vmq_drain(const duct_vmq_lane_t *ln,
               void (*cb)(duct_vmq_hdr_t *, void *),
               void *arg)
{
    auto pos = duct_vmq_drain_begin(ln);
    size_t count = 0;
    duct_vmq_hdr_t *hdr = nullptr;
    while ((hdr = duct_vmq_drain_peek(ln, &pos)) != nullptr) {
        cb(hdr, arg);
        pos.head += pos.step;
        ++count;
    }
    if (count)
        duct_vmq_commit_head(ln, pos.gen, pos.head);
    return count;
}

/** @brief Drain one lane while @p cb keeps taking messages.
 *
 *  A message refused by @p cb remains on the lane without advancing the read head,
 *  providing backpressure to the producer.
 *
 *  @param out_stopped true once @p cb refused one. A lane still holding bytes
 *         is a different fact: a producer can add during the pass.
 *  @return Number of messages dispatched.
 */
duct_nonnull(1, 2, 4) static inline size_t
duct_vmq_drain_while(const duct_vmq_lane_t *ln,
                     bool (*cb)(duct_vmq_hdr_t *, void *),
                     void *arg, bool *out_stopped)
{
    auto pos = duct_vmq_drain_begin(ln);
    size_t count = 0;
    duct_vmq_hdr_t *hdr = nullptr;
    *out_stopped = false;
    while ((hdr = duct_vmq_drain_peek(ln, &pos)) != nullptr) {
        if (!cb(hdr, arg)) {
            *out_stopped = true;
            break;
        }
        pos.head += pos.step;
        ++count;
    }
    if (count)
        duct_vmq_commit_head(ln, pos.gen, pos.head);
    return count;
}

/** @brief Drain every lane in index order.
 *
 *  @return total messages dispatched across all lanes.
 */
duct_nonnull(1) static inline size_t
duct_vmq_mpsc_drain(duct_vmq_mpsc_t *q,
                    void (*cb)(duct_vmq_hdr_t *, void *),
                    void *arg)
{
    size_t total = 0;
    for (unsigned i = 0; i < q->n_lanes; ++i) {
        auto ln = duct_mpsc_lane(q, i);
        total += duct_vmq_drain(&ln, cb, arg);
    }
    return total;
}

/** @brief Drain lanes in index order until @p cb refuses a message.
 *  Refusal terminates the drain pass across all subsequent lanes.
 *  @return total messages dispatched across the lanes reached.
 */
duct_nonnull(1, 2, 4) static inline size_t
duct_vmq_mpsc_drain_while(duct_vmq_mpsc_t *q,
                          bool (*cb)(duct_vmq_hdr_t *, void *),
                          void *arg, bool *out_stopped)
{
    size_t total = 0;
    *out_stopped = false;
    for (unsigned i = 0; i < q->n_lanes && !*out_stopped; ++i) {
        auto ln = duct_mpsc_lane(q, i);
        total += duct_vmq_drain_while(&ln, cb, arg, out_stopped);
    }
    return total;
}

#ifdef __cplusplus
}
#endif

#endif /* DUCT_VMQ_H */
