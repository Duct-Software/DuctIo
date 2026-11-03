/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_wfq_msg.h
 *  @brief Built-in WFQ message payloads, type tags (X-macro list), priority lanes.
 *
 *  The callback payload embeds @c duct_msg_t as its first member via
 *  @ref duct_msg_decl; the frame batch is a raw descriptor dispatched by its
 *  type tag. Public exec trampolines bridge the io → worker boundary.
 */

#ifndef DUCT_WFQ_MSG_H
#define DUCT_WFQ_MSG_H

#include "duct_core.h"
#include "duct_msg.h"
#include "duct_timer.h"
#include "duct_types.h"

#include <stdatomic.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Single source of truth for built-in WFQ message types.
 *
 *  X(val, suffix, type) — val is the enum discriminant, suffix names helpers,
 *  type is the payload struct.
 *
 *  Adding a new type is one line here, everything else auto-syncs.
 */
#define wfq_msg_list(X) \
    X(msg_callback,     callback,     duct_msg_callback) \
    X(msg_frame_batch,  frame_batch,  duct_msg_frame_batch)
    /* Add new types here */

/** @brief WFQ message type identifiers. Generated from @ref wfq_msg_list. */
typedef enum duct_wfq_msg_type : uint8_t {
#define wfq_msg_enum(val, suffix, type) val,
    wfq_msg_list(wfq_msg_enum)
#undef wfq_msg_enum
    msg_type_count
} duct_wfq_msg_type_t;

static_assert(sizeof(duct_wfq_msg_type_t) == sizeof(uint8_t),
    "duct_wfq_msg_type_t width must be 8 bits");

/** @brief One parsed frame inside a batch. */
typedef struct duct_msg_frame {
    uint32_t           offset,       /**< Byte offset into the conn's RX OLB. */
                       len;          /**< Frame length, bytes. */
    duct_stream_id_t   stream_id;    /**< Target stream. */
    duct_frame_flags_t flags;        /**< Frame flags. @c fl_frame_fin and
                                       *  @c fl_frame_rst close the stream after
                                       *  this frame; @c duct_frame_pad and
                                       *  @c duct_frame_end mark a descriptor
                                       *  carrying no frame. */
    uint8_t sealed_epoch;   /**< The @c conn->wire_epoch snapshot at parse time.
                              *  0 under a plain wire, nonzero under a sealed wire.
                              *  Dispatch compares it to the conn's current epoch —
                              *  bumped by @ref duct_conn_bind_wire on every rebind —
                              *  to detect a stale replay. */
    uint16_t header_size;   /**< Wire header width, fixed at parse time so a
                              *  replayed frame keeps the value it was parsed with. */
} duct_msg_frame_t;

/** @brief Descriptor flag for ring bytes that carry no frame: a padded record's
 *  unit remainder, or a whole void unit.
 *  The worker acks the descriptor's span and dispatches nothing, and the WFQ
 *  charges it neither frame quota nor bytes. Only the io parse sets it. */
static constexpr duct_frame_flags_t duct_frame_pad = (duct_frame_flags_t)(1u << 7);
static_assert(!(duct_frame_pad & (fl_frame_fin | fl_frame_rst | fl_frame_gso)),
    "duct_frame_pad must not collide with a wire-set frame flag");

/** @brief Descriptor flag for the end of a conn's input.
 *  Posted once, behind every frame the conn posted ahead of its peer's end of
 *  stream or a parse error, and covering no bytes; the worker closes the leg
 *  there behind the answers ahead of it, with @c close_protocol_error after a
 *  parse error and @c close_peer otherwise. Only @ref duct_frame_rx_end sets
 *  it. */
static constexpr duct_frame_flags_t duct_frame_end = (duct_frame_flags_t)(1u << 6);
static_assert(!(duct_frame_end & (fl_frame_fin | fl_frame_rst | fl_frame_gso | duct_frame_pad)),
    "duct_frame_end must not collide with a wire-set frame flag or duct_frame_pad");

/** @brief Batch of frames parsed from one @c duct_xread() on the same conn. */
typedef struct duct_msg_frame_batch {
    duct_handle_t      conn;        /**< Owning conn. */
    uint32_t           n;           /**< Frame count in @c frames[].
                                      *  Capped by
                                      *  @ref duct_frame_rx_ctx_t::frame_ceiling. */
    duct_msg_frame_t   frames[];    /**< Payload: sizeof(base) + n ×
                                      *  sizeof(duct_msg_frame_t). */
} duct_msg_frame_batch_t;

/** @brief One host-pushed inter packet. */
typedef struct duct_msg_inter_pkt {
    uint32_t           offset,       /**< Byte offset from whichever base the
                                       *  batch's @c rx_pool selects. */
                       len;          /**< Packet length, bytes. */
    duct_stream_id_t   stream_id;    /**< Target stream. */
    duct_frame_flags_t flags;        /**< @c fl_frame_fin / @c fl_frame_rst
                                       *  close the stream after this packet. */
} duct_msg_inter_pkt_t;

/** @brief Batch of host-pushed inter packets on one conn's dedicated
 *  @c inter_lane.
 *  Tagged @ref inter_msg_batch.
 */
typedef struct duct_msg_inter_batch {
    duct_handle_t          conn;   /**< Owning conn. */
    uint32_t               n;      /**< Packet count in the descriptor array. */
    /** @brief Classified source address.
     *  @c x_udp_shared only; unused for an ordinary @c x_inter batch.
     *  The worker drains it into @c conn->ctx's peer — the same thread
     *  that reads it back in @c s_commit_response, so the field stays
     *  single-thread-owned.
     */
    duct_peer_t            peer;
    /** @brief Where the payload bytes live.
     *  An RX slot when set, inline in this batch's own lane slot when null;
     *  each packet's @c offset counts from whichever of the two it selects.
     */
    struct duct_x_slot_pool *rx_pool;
    uint32_t                  rx_slot;

    /** @brief Byte offset from this batch to its descriptor array.
     *  Varies because @c s_dgram_shared_route learns its packet count only
     *  after parsing, so it places the payload first and grows the descriptors
     *  onto the tail; every other producer puts them straight after this
     *  header.
     */
    uint32_t               pkts_off;

    /** @brief Byte offset from this batch to its array of @c n device-owned
     *  payload pointers, or zero when the payload is addressed by
     *  @c rx_pool and @c offset instead.
     *  When devices provide dedicated read buffers, they remain valid until
     *  @c duct_device_ops_t::release_read; the batch carries direct pointers.
     */
    uint32_t               holds_off;
} duct_msg_inter_batch_t;

/** @brief @p b's descriptor array. */
duct_nonnull(1) static inline duct_msg_inter_pkt_t *
duct_msg_inter_pkts(duct_msg_inter_batch_t *b)
{
    return (duct_msg_inter_pkt_t *)((char *)b + b->pkts_off);
}

/** @brief @p b's device-owned payload pointers; @c nullptr when it has none. */
duct_nonnull(1) static inline void **
duct_msg_inter_holds(duct_msg_inter_batch_t *b)
{
    return b->holds_off ? (void **)((char *)b + b->holds_off) : nullptr;
}

/** @brief Lane tag for a host-pushed inter batch.
 *  The @c duct_vmq_hdr_t::type @ref duct_vmq_reserve carries when
 *  pushing a @ref duct_msg_inter_batch_t onto a conn's @c inter_lane.
 */
static constexpr uint8_t inter_msg_batch = 0u;

/** @brief One queued send in a listener's @c dgram_tx_outbox.
 *  Worker-filled, drained by that listener's I/O thread.
 */
typedef struct duct_dgram_tx_entry {
    duct_peer_t peer;       /**< Destination address. */
    uint32_t    len;        /**< Payload length, bytes. */
    uint32_t    slot;       /**< Reference of the TX slot holding the payload; @c treiber_empty when the
                              *  payload follows in @c data. */
    alignas(8) uint8_t data[]; /**< Inline datagram payload bytes, present only when @c slot is @c treiber_empty. */
} duct_dgram_tx_entry_t;

/** @brief Outbox tag for a datagram TX entry.
 *  The @c duct_vmq_hdr_t::type @ref duct_vmq_reserve carries when pushing a
 *  @ref duct_dgram_tx_entry_t onto a listener's @c dgram_tx_outbox.
 */
static constexpr uint8_t dgram_tx_msg = 0u;

/** @brief Callback message.
 *  Producer fills @c msg.exec_fn and @c msg.arg; dispatch calls @c exec_fn(self).
 */
duct_msg_decl(duct_msg_callback);

/** @brief Executor for a frame batch, dispatched from its VMQ slot.
 *  Runs @ref duct_msg_frame_batch on the target worker.
 */
duct_exec_rc_t duct_msg_exec_frame_batch(void *self);

/** @brief Context for an async cancel routed through a WFQ callback lane. */
typedef struct {
    duct_timers_t      *tl;  /**< Owning timer list. */
    duct_timer_handle_t h;   /**< Timer to cancel. */
} duct_timer_cancel_ctx_t;

/** @brief Cancel callback for WFQ callback lane.
 *  Reads @c self->arg as @c duct_timer_cancel_ctx_t *, calls
 *  @c duct_timer_cancel, then frees @c ctx.
 */
static inline duct_exec_rc_t duct_timer_cancel_fn(void *self)
{
    auto c = (duct_timer_cancel_ctx_t *)((duct_msg_t *)self)->arg;
    duct_timer_cancel(c->tl, c->h);
    duct_del(c);
    return exec_done;
}

/** @brief WFQ priority lane class: high > norm > low. */
typedef enum duct_wfq_pri : uint8_t {
    wfq_pri_lo,     /**< Lowest priority. */
    wfq_pri_norm,   /**< Default priority. */
    wfq_pri_hi,     /**< Highest priority. */

    wfq_pri_count   /**< Class count sentinel. */
} duct_wfq_pri_t;

static_assert(sizeof(duct_wfq_pri_t) == sizeof(uint8_t),
    "duct_wfq_pri_t width exceeds 8 bits");

/** @brief Resolve the flat MPSC lane id.
 *
 *  @ref wfq_pri_hi maps to block 0, matching @ref duct_wfq_new's own
 *  HI-first capacity-argument order. Each (@p pri, @p worker_id) owns
 *  @p n_io consecutive lanes, one per producer @p io_id; @p io_id 0
 *  is the range's base, so callers draining the whole range pass 0
 *  and iterate @p n_io lanes from the result.
 */
static inline unsigned duct_wfq_pri_lane(duct_wfq_pri_t pri,
                                         unsigned worker_id,
                                         unsigned n_workers,
                                         unsigned io_id,
                                         unsigned n_io)
{
    return ((wfq_pri_count - pri - 1) * n_workers + worker_id) * n_io
        + io_id;
}

/** @brief Bit per @c io_id blocked pushing into one worker's normal WFQ lane
 *  range.
 *
 *  The worker exchanges this word with zero after draining that range
 *  and wakes every claimed @c io_id.
 *  @note Hardcaps reverse wake at 64 I/O threads.
 */
typedef uint64_t _Atomic duct_wfq_io_waiters_t;

/** @brief Upper bound on @c io_id representable as a waiter bit.
 *  The width of @ref duct_wfq_io_waiters_t.
 */
static constexpr unsigned duct_wfq_io_waiters_max = 64u;

#ifdef __cplusplus
}
#endif

#endif /* DUCT_WFQ_MSG_H */
