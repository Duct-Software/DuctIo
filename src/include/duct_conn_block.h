/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_conn_block.h
 *  @brief The conn's half-megabyte block: resident page 0, the transport
 *  union over the tail, and the regions carved behind it.
 *
 *  One 512 KB block carries one conn slot; the block number is the slot
 *  index, and @c duct_conn_t sits at offset 0. Page 0 is the fixed resident
 *  head — the body, the generation word, the request node, the rx and tx OLB
 *  headers, the inter lane header with its control block, the tx sequence
 *  pair, the datagram context, the stats triple and the TX retry maps —
 *  bounded by @c conn_page0_hard and page-aligned at runtime by
 *  @ref duct_conn_page0.
 *
 *  The tail is a union by transport: the OLB branch reserves the rx region
 *  up to @c conn_rx_region_max, the tx region up to @c conn_tx_region_max,
 *  two wire parser slots and the codec slot, the engine park, the batch
 *  retry node and the TX retry region; the lane branch places the inter lane
 *  and the device leg over those same bytes. Ring data pointers are computed
 *  from the header addresses, never stored; the OLB write surface over the
 *  carved regions lives here with the geometry it needs.
 */

#ifndef DUCT_CONN_BLOCK_H
#define DUCT_CONN_BLOCK_H

#include "duct_build_config.h"
#include "duct_conn.h"
#include "duct_dgram_out.h"
#include "duct_dgram_rec.h"
#include "duct_events.h"
#include "duct_olb_rx.h"
#include "duct_olb_tx.h"
#include "duct_protocol.h"
#include "duct_relay.h"
#include "duct_span.h"
#include "duct_vmq.h"
#include "duct_vnet.h"
#include "duct_wire.h"
#include "duct_wfq_msg.h"
#include "duct_x_slot.h"
#include "duct_xport.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct duct_block_pool duct_block_pool_t;

static_assert(sizeof(duct_msg_conn_req) == 32u,
              "the gen word and the request node take their forty bytes of page 0");
static_assert(sizeof(duct_olb_rx_t) == 8u * duct_cacheline_size,
              "the rx header is the common three lines, three io/compaction/cold"
              " lines, the worker's ack line, and the span-pin line C");
static_assert(offsetof(duct_olb_tx_t, drained)
                  == sizeof(duct_olb_hdr_t) + duct_cacheline_size,
              "the tx header is the common three lines, the staging worker's"
              " own single line — the platform's sock-stats members padded"
              " within it — ahead of io's completion line pair of"
              " duct-zerocopy §5.2");

/** @brief Bytes of one conn block: a power of two, whole pages. */
static constexpr uint32_t conn_block_size = kbytes(512u);
/** @brief Hard ceiling of page 0's fixed head, whatever the runtime page is. */
static constexpr uint32_t conn_page0_hard = kbytes(16u);

/** @brief The conn's worker-exclusive tx sequence & send-done frontier state. */
typedef struct duct_conn_tx_seq {
    uint32_t next,
             serve,
             done_skip,     /* cancelled fl_send_done retries awaiting carry */
             done_ctl;      /* empty control-only fl_send_done awaiting earlier drain */
    uint64_t done_posted,   /* accepted fl_send_done responses on this conn */
             done_reported; /* highest frontier delivered to on_send_done */
} duct_conn_tx_seq_t;

/** @brief Cache-line-isolated monotonic counter of wire-drained fl_send_done deltas. */
typedef struct duct_conn_tx_done {
    alignas(duct_cacheline_size) uint64_t _Atomic seq;
} duct_conn_tx_done_t;

/** @name Page-0 offsets
 *  The fixed resident head in first-reach order: the body's two cache lines,
 *  the generation word, the request node, the rx and tx OLB headers, the
 *  inter lane header and control block, the tx sequence state, the datagram
 *  context, the stats triple, the isolated tx_done line, the TX retry maps.
 *  @{
 */
static constexpr uint32_t conn_off_body = 0u;
static constexpr uint32_t conn_off_gen = sizeof(duct_conn_t);
static constexpr uint32_t conn_off_req = conn_off_gen + sizeof(uint64_t);
static constexpr uint32_t conn_off_rx = 3u * duct_cacheline_size;
static constexpr uint32_t conn_off_tx = conn_off_rx + sizeof(duct_olb_rx_t);
static constexpr uint32_t conn_off_lane = conn_off_tx + sizeof(duct_olb_tx_t);
static constexpr uint32_t conn_off_lane_ctrl = conn_off_lane + duct_cacheline_size;
static constexpr uint32_t conn_off_tx_seq = conn_off_lane_ctrl + vmq_lane_ctrl_size;
static constexpr uint32_t conn_off_ctx = conn_off_tx_seq + sizeof(duct_conn_tx_seq_t);
static constexpr uint32_t conn_off_stats = conn_off_ctx + sizeof(duct_dgram_shared_ctx_t);
static constexpr uint32_t conn_off_tx_done =
    (conn_off_stats + 32u + duct_cacheline_size - 1u) & ~(uint32_t)(duct_cacheline_size - 1u);
/** @} */

/** @brief Fixed tail of page 0 past the tx_done line, 8-aligned: the TX retry
 *  region's allocation maps. */
static constexpr uint32_t conn_off_retry_maps =
    conn_off_tx_done + sizeof(duct_conn_tx_done_t);

/** @brief Ceiling of the rx region: the ring cap plus the larger of the GRO
 *  group shape and the vnet cut, which never coexist. */
static constexpr size_t conn_rx_gro_shape =
    sizeof(duct_dgram_rec_hdr_t) + duct_x_gro_max + duct_events_rx_scratch;
static constexpr size_t conn_rx_region_max =
    duct_conn_rx_olb_cap + (conn_rx_gro_shape > (size_t)duct_vnet_cut_max
                                ? conn_rx_gro_shape : (size_t)duct_vnet_cut_max);
/** @brief Framing slack the tx region carries over its ring cap: alignment
 *  of the descriptor array's base inside the region, one wire header a
 *  standalone ring's page rounding absorbed. */
static constexpr size_t conn_tx_slack = 2u * wire_tx_hdr_max;

/** @brief Ceiling of the tx region: the ring cap plus its framing slack. */
static constexpr size_t conn_tx_region_max = duct_conn_tx_olb_cap + conn_tx_slack;

/** @brief Ceiling of the wire region: two parser slots — the conn's own and
 *  the codec's inner parser — then the codec slot. */
static constexpr size_t conn_wire_region_max =
    2u * duct_wire_parser_slot + duct_wire_codec_slot;

static_assert(conn_off_stats + 32u <= conn_page0_hard,
              "page 0's fixed part fits the hard page ceiling");

/** @brief The conn's TX retry region allocation maps, page 0's cold tail:
 *  one bit per node slot and per copy unit, a set bit taken. Page 0's
 *  acquire reset zeroes them, so a fresh conn reads all-free. The owning
 *  worker alone takes and frees — plain words, no atomics; the io-to-worker
 *  handoff's own release/acquire edge publishes the zeroing. */
typedef struct duct_conn_tx_retry_maps {
    uint64_t nodes[(duct_conn_retry_tx_nodes + 63u) / 64u];
    uint64_t copies[(duct_conn_retry_tx_copies + 63u) / 64u];
} duct_conn_tx_retry_maps_t;

static_assert(conn_off_retry_maps + sizeof(duct_conn_tx_retry_maps_t)
                  <= (size_t)conn_page0_hard,
              "the TX retry maps fit page 0's fixed part");
static_assert((size_t)conn_page0_hard + conn_rx_region_max + conn_tx_region_max
                  + conn_wire_region_max <= conn_block_size,
              "the OLB branch of the union tail fits the block");

/** @brief Arena capacity of one @c x_inter or @c x_udp_shared conn's ingress
 *  lane, the bound the lane branch of the union tail serves. */
static constexpr size_t duct_inter_lane_cap = kbytes(144u);

static_assert(duct_inter_lane_cap <= conn_rx_region_max + conn_tx_region_max,
              "the lane branch of the union tail fits the rx and tx ceilings it shares");

/** @brief Packets one @c read call of a device may hand back; also the buffers
 *  one device rx slot serves. */
static constexpr uint32_t duct_device_rx_batch = 32u;

/** @brief Packets a lending device leg may hold out at once: one drive's
 *  @c duct_dgram_rx_max_passes passes of one @c duct_device_rx_batch batch,
 *  which is also the most that can ever be outstanding, for the drive reads
 *  only on a lane @c duct_vmq_room reports whole. */
static constexpr uint32_t duct_device_hold_cap =
    duct_device_rx_batch * duct_dgram_rx_max_passes;

/** @brief A device leg's region, carved in the lane branch of the union tail
 *  behind the inter lane: the caller's op table, the io thread's device list
 *  links, and what the engine holds lent from that device.
 *  @c ops leads the struct, so a reader wanting the table alone casts the
 *  region straight to @ref duct_device_ops_t. The leg carries no rx slots of
 *  its own: every leg an io thread carries reads into that thread's one
 *  device rx pool. */
typedef struct duct_device_leg {
    duct_device_ops_t   ops;
    struct duct_device_leg *prev, /**< Previous leg on the io thread's device list. */
                          *next;  /**< Next leg on the io thread's device list. */
    uint32_t            n_held;   /**< Entries of @c held in use, at most
                                    *  @c duct_device_hold_cap. */
    duct_view_u8        held[duct_device_hold_cap]; /**< Packets read out of the
                                    *  device and not yet handed back through
                                    *  @c ops.release_read. */
} duct_device_leg_t;

static_assert(duct_inter_lane_cap + sizeof(duct_device_leg_t)
                  <= conn_rx_region_max + conn_tx_region_max,
              "the device leg fits the lane branch behind the lane it serves");

/** @brief End of page 0's fixed head, aligned to the runtime page: the tail
 *  a sweep drops starts here, and every carved region's data offset counts
 *  from here. */
static inline uint32_t duct_conn_page0(void)
{
    return (uint32_t)duct_align_up(conn_off_retry_maps + sizeof(duct_conn_tx_retry_maps_t),
                                   duct_page_size());
}

/** @brief The conn's rx OLB header in page 0, @c nullptr on a lane conn. */
duct_nonnull(1) static inline duct_olb_rx_t *duct_conn_rx_olb(const duct_conn_t *conn)
{
    return duct_conn_has_olb(conn)
        ? (duct_olb_rx_t *)((uintptr_t)conn + conn_off_rx) : nullptr;
}

/** @brief The conn's rx OLB header in page 0 — resident for every conn,
 *  ring or lane.
 *  Only the header itself is fixed in page 0; a lane conn's ring data words
 *  are inert zeros, but the worker-written ack-line bits (the author's RX
 *  suspend) park there for lane conns too — a device leg's io gate reads
 *  them while its packets ride the lane instead of a ring.
 */
duct_nonnull(1) static inline duct_olb_rx_t *duct_conn_rx_hdr(const duct_conn_t *conn)
{
    return (duct_olb_rx_t *)((uintptr_t)conn + conn_off_rx);
}

/** @brief The conn's tx OLB header in page 0, @c nullptr on a lane conn. */
duct_nonnull(1) static inline duct_olb_tx_t *duct_conn_tx_olb(const duct_conn_t *conn)
{
    return duct_conn_has_olb(conn)
        ? (duct_olb_tx_t *)((uintptr_t)conn + conn_off_tx) : nullptr;
}

/** @brief The conn's tx OLB header in page 0 — resident for every conn,
 *  ring or lane.
 *  The worker's TX-room wait target parks on the staging line for lane
 *  conns too: a lane conn's ring words read zero, so its wait target takes
 *  the "wake on the next signal" form while nothing io-side ever advances a
 *  head against it.
 */
duct_nonnull(1) static inline duct_olb_tx_t *duct_conn_tx_hdr(const duct_conn_t *conn)
{
    return (duct_olb_tx_t *)((uintptr_t)conn + conn_off_tx);
}

/** @brief The conn's inter lane header in page 0, @c nullptr on an OLB conn. */
duct_nonnull(1) static inline duct_vmq_mpsc_t *duct_conn_lane(const duct_conn_t *conn)
{
    return duct_conn_has_olb(conn)
        ? nullptr : (duct_vmq_mpsc_t *)((uintptr_t)conn + conn_off_lane);
}

/** @brief The conn's device leg, carved in the lane branch behind the inter
 *  lane it serves. */
duct_nonnull(1) static inline duct_device_leg_t *
duct_conn_device_leg(const duct_conn_t *conn)
{
    return (duct_device_leg_t *)((uint8_t *)conn + duct_conn_page0() + duct_inter_lane_cap);
}

/** @brief The conn's tx ticket & send-done frontier state in page 0. */
duct_nonnull(1) static inline duct_conn_tx_seq_t *duct_conn_tx_seq(const duct_conn_t *conn)
{
    return (duct_conn_tx_seq_t *)((uintptr_t)conn + conn_off_tx_seq);
}

/** @brief The conn's drain-completion frontier atomic in page 0. */
duct_nonnull(1) static inline duct_conn_tx_done_t *duct_conn_tx_done(const duct_conn_t *conn)
{
    return (duct_conn_tx_done_t *)((uintptr_t)conn + conn_off_tx_done);
}

/** @brief Base of the conn's rx ring data, right past page 0. */
duct_nonnull(1) static inline uint8_t *duct_conn_rx_data(const duct_conn_t *conn)
{
    return (uint8_t *)conn + duct_conn_page0();
}

/** @brief Base of the conn's tx ring data, past the rx region's ceiling. */
duct_nonnull(1) static inline uint8_t *duct_conn_tx_data(const duct_conn_t *conn)
{
    return (uint8_t *)conn + duct_conn_page0() + conn_rx_region_max;
}

/** @brief Base of @p rx's ring data, derived from the header's fixed page-0
 *  offset. */
duct_nonnull(1) static inline uint8_t *duct_olb_rx_data(const duct_olb_rx_t *rx)
{
    return duct_conn_rx_data((const duct_conn_t *)((const uint8_t *)rx - conn_off_rx));
}

/** @brief The conn whose rx OLB header @p hdr is, derived from the header's
 *  fixed page-0 offset. */
duct_nonnull(1) static inline duct_conn_t *
duct_conn_of_olb_rx(duct_olb_hdr_t *hdr)
{
    return (duct_conn_t *)((uint8_t *)hdr - conn_off_rx);
}

/** @brief The conn whose tx OLB header @p hdr is, derived from the header's
 *  fixed page-0 offset. */
duct_nonnull(1) static inline duct_conn_t *
duct_conn_of_olb_tx(duct_olb_hdr_t *hdr)
{
    return (duct_conn_t *)((uint8_t *)hdr - conn_off_tx);
}

/** @brief Base of @p tx's ring data, derived from the header's fixed page-0
 *  offset. */
duct_nonnull(1) static inline uint8_t *duct_olb_tx_data(const duct_olb_tx_t *tx)
{
    return duct_conn_tx_data((const duct_conn_t *)((const uint8_t *)tx - conn_off_tx));
}

/** @brief Wire parser slot @p idx of the conn: index 0 the conn's own parser,
 *  index 1 the codec's inner one. */
duct_nonnull(1) static inline duct_wire_parser_t *
duct_conn_wire_parser_slot(const duct_conn_t *conn, unsigned idx)
{
    return (duct_wire_parser_t *)((uint8_t *)conn + duct_conn_page0() + conn_rx_region_max
                                  + conn_tx_region_max + (size_t)idx * duct_wire_parser_slot);
}

/** @brief The conn's wire codec slot, behind the two parser slots. */
duct_nonnull(1) static inline duct_wire_codec_t *
duct_conn_codec_slot(const duct_conn_t *conn)
{
    return (duct_wire_codec_t *)((uint8_t *)conn + duct_conn_page0() + conn_rx_region_max
                                 + conn_tx_region_max + 2u * duct_wire_parser_slot);
}

/** @brief The conn's engine-egress park region, behind the wire slots of the
 *  union tail: @c duct_conn_park_cap bytes a codec's @c engine_park_len
 *  counts into, flushed whole into the TX ring. */
duct_nonnull(1) static inline uint8_t *
duct_conn_engine_park(const duct_conn_t *conn)
{
    return (uint8_t *)conn + duct_conn_page0() + conn_rx_region_max
           + conn_tx_region_max + conn_wire_region_max;
}

/** @brief The conn's WFQ-full batch retry region: one @c batch_retry_node_t
 *  with @c duct_wfq_quota_norm frame slots, the largest batch the frame
 *  ceiling admits. */
static constexpr size_t conn_retry_region =
    (sizeof(batch_retry_node_t)
     + (size_t)duct_wfq_quota_norm * sizeof(duct_msg_frame_t)
     + alignof(batch_retry_node_t) - 1u)
    & ~(alignof(batch_retry_node_t) - 1u);

/** @brief The conn's WFQ-full batch retry node, behind the engine park. */
duct_nonnull(1) static inline batch_retry_node_t *
duct_conn_retry_node(const duct_conn_t *conn)
{
    return (batch_retry_node_t *)(duct_conn_engine_park(conn) + duct_conn_park_cap);
}

/** @brief One TX retry node slot's stride, bytes: the worker's private
 *  @c retry_node_t, pinned from outside by a static_assert in
 *  @c duct_worker.c so the two cannot drift apart. */
static constexpr size_t conn_retry_tx_node_span = 264u;

/** @brief The conn's TX retry region, behind the batch retry node of the
 *  union tail: @c duct_conn_retry_tx_nodes fixed-stride node slots for the
 *  backpressure classes that die with their conn (frame, fin, engine, close,
 *  dgram_tx), then @c duct_conn_retry_tx_copies copy units of
 *  @c duct_conn_retry_tx_copy_max bytes each for the variable-width frame
 *  copies and packed datagrams a park must own — a copy that fits a unit
 *  takes one, a wider copy spans the consecutive units it needs. The
 *  stream-owned emit and session-owned timer nodes stay heap — the map's
 *  "1b tail 2" amendment directs both to the session block, never the conn
 *  block. */
static constexpr size_t conn_retry_tx_region =
    (size_t)duct_conn_retry_tx_nodes * conn_retry_tx_node_span
    + (size_t)duct_conn_retry_tx_copies * duct_conn_retry_tx_copy_max;

/** @brief Base of @p conn's TX retry node slots; slot @p idx sits at
 *  @c idx * conn_retry_tx_node_span. */
duct_nonnull(1) static inline uint8_t *
duct_conn_tx_retry_node_slot(const duct_conn_t *conn, uint32_t idx)
{
    return (uint8_t *)conn + duct_conn_page0() + conn_rx_region_max
           + conn_tx_region_max + conn_wire_region_max + duct_conn_park_cap
           + conn_retry_region + (size_t)idx * conn_retry_tx_node_span;
}

/** @brief Base of @p conn's TX retry copy unit @p idx,
 *  @c duct_conn_retry_tx_copy_max bytes; a spanned copy's release derives
 *  its unit count from its length, the same ceil its take took. */
duct_nonnull(1) static inline uint8_t *
duct_conn_tx_retry_copy_slot(const duct_conn_t *conn, uint32_t idx)
{
    return duct_conn_tx_retry_node_slot(conn, duct_conn_retry_tx_nodes)
           + (size_t)idx * duct_conn_retry_tx_copy_max;
}

/** @brief The conn's TX retry region allocation maps in page 0. */
duct_nonnull(1) static inline duct_conn_tx_retry_maps_t *
duct_conn_tx_retry_maps(const duct_conn_t *conn)
{
    return (duct_conn_tx_retry_maps_t *)((uintptr_t)conn + conn_off_retry_maps);
}

static_assert((size_t)conn_page0_hard + conn_rx_region_max + conn_tx_region_max
                  + conn_wire_region_max + duct_conn_park_cap
                  + conn_retry_region + conn_retry_tx_region <= conn_block_size,
              "the engine park, the batch retry node and the TX retry region fit the block");

/** @brief The conn's page-0 context region: the datagram shared context's
 *  shape, its first word reading as a plain link for the pointer users. */
typedef union duct_conn_ctx {
    duct_dgram_shared_ctx_t dgram;
    void                   *link;
} duct_conn_ctx_t;

static_assert(sizeof(duct_conn_ctx_t) == sizeof(duct_dgram_shared_ctx_t),
              "the ctx region is the dgram shape, the pointer shapes its first word");

/** @brief The conn's context region in page 0. */
duct_nonnull(1) static inline duct_conn_ctx_t *duct_conn_ctx(const duct_conn_t *conn)
{
    return (duct_conn_ctx_t *)((uintptr_t)conn + conn_off_ctx);
}

/** @brief The conn's datagram shared context, an @c x_udp_shared conn's shape. */
duct_nonnull(1) static inline duct_dgram_shared_ctx_t *
duct_conn_dgram_ctx(const duct_conn_t *conn)
{
    return &duct_conn_ctx(conn)->dgram;
}

/** @brief The device op table an @c x_inter conn's leg was attached under. */
duct_nonnull(1) static inline duct_device_ops_t *
duct_conn_device_ops(const duct_conn_t *conn)
{
    return duct_conn_ctx(conn)->link;
}

/** @brief The listener pointer slot of page 0's context region. */
duct_nonnull(1) static inline duct_listener_t **
duct_conn_listener_ref(const duct_conn_t *conn)
{
    return (duct_listener_t **)duct_conn_ctx(conn);
}

/** @brief Cumulative staged bytes of the conn's regions and the touched
 *  high-water, page 0's cold tail.
 *  The totals count every byte the rings and lane ever took, the release
 *  reads them for @c touched, min'd at the region ceilings.
 */
typedef struct duct_conn_stats {
    uint64_t rx_total,
             tx_total,
             lane_total;
    uint16_t touched;
} duct_conn_stats_t;

/** @brief The conn's stats triple in page 0. */
duct_nonnull(1) static inline duct_conn_stats_t *
duct_conn_stats(const duct_conn_t *conn)
{
    return (duct_conn_stats_t *)((uintptr_t)conn + conn_off_stats);
}

/** @brief Count @p n bytes staged into the conn's rx region. */
duct_nonnull(1) static inline void duct_conn_rx_staged(duct_conn_t *conn, size_t n)
{
    duct_conn_stats(conn)->rx_total += n;
}

/** @brief Count @p n bytes staged into the conn's tx region. */
duct_nonnull(1) static inline void duct_conn_tx_staged(duct_conn_t *conn, size_t n)
{
    duct_conn_stats(conn)->tx_total += n;
}

/** @brief Count @p n bytes staged into the conn's inter lane. */
duct_nonnull(1) static inline void duct_conn_lane_staged(duct_conn_t *conn, size_t n)
{
    duct_conn_stats(conn)->lane_total += n;
}

/** @brief Set the conn's touched high-water from its cumulative counters,
 *  min'd at the region ceilings and cut to whole pages.
 *  Run at the block's release; the counters read zero afterwards.
 */
duct_nonnull(1) static inline void duct_conn_touched_update(duct_conn_t *conn)
{
    auto st = duct_conn_stats(conn);
    size_t bytes = duct_conn_has_olb(conn)
        ? duct_min(st->rx_total, conn_rx_region_max)
          + duct_min(st->tx_total, conn_tx_region_max)
        : duct_min(st->lane_total, duct_inter_lane_cap);
    st->touched = (uint16_t)duct_min(bytes / duct_page_size(), (size_t)UINT16_MAX);
}

/** @brief Carve the conn's rx and tx OLB headers over pre-zeroed page-0
 *  storage, at @p rx_cap bytes of rx ring data and a @p tx_cap protocol
 *  TX capacity.
 *  The rx ring's data base is the computed region base; the tx region holds
 *  the fixed descriptor array and materialize arena, its byte budget the
 *  carve's per-conn capacity names (§2.2: the protocol's @c tx_olb_cap
 *  honoured as the ring's own ceiling) over the same slack the byte ring
 *  kept — a response of exactly the named capacity still stages, its wire
 *  prefix and record header riding the slack. The caller's re-carve guard
 *  stands ahead of a second call on a live carve.
 */
duct_nonnull(1) static inline void
duct_conn_carve_olb(duct_conn_t *conn, size_t rx_cap, size_t tx_cap)
{
    uint8_t *base = (uint8_t *)conn;
    auto rx = (duct_olb_rx_t *)(base + conn_off_rx);
    memset(rx, 0, sizeof *rx);
    rx->h.buf_size = rx_cap;
    duct_olb_rx_cold_init(rx);
    auto tx = (duct_olb_tx_t *)(base + conn_off_tx);
    memset(tx, 0, sizeof *tx);
    tx->h.buf_size = (size_t)duct_conn_tx_mat_cap
                   + (size_t)duct_conn_tx_desc_n * sizeof(duct_tx_desc_t);
    tx->byte_cap = (uint32_t)(tx_cap + conn_tx_slack);
}

/** @brief Carve the conn's inter lane header and control block over
 *  pre-zeroed page-0 storage: one lane of @c duct_inter_lane_cap bytes whose
 *  data starts at page 0's end.
 *  The queue is torn down by draining, never deleted — the block owns the
 *  storage.
 */
duct_nonnull(1) static inline void duct_conn_carve_lane(duct_conn_t *conn)
{
    auto q = duct_conn_lane(conn);
    memset(q, 0, (size_t)duct_cacheline_size + vmq_lane_ctrl_size);
    q->n_lanes = 1u;
    q->ctrl_offset = (size_t)conn_off_lane_ctrl - conn_off_lane;
    q->data_offset = (size_t)duct_conn_page0() - conn_off_lane;
    q->lane_off[0] = 0u;
    q->lane_off[1] = duct_inter_lane_cap;
}

/** @brief Compact @p rx's buffer.
 *  Discards everything before @p boundary and slides the rest down. Every
 *  byte before @p boundary is consumed, as @ref duct_olb_rx_consumed answers,
 *  and @p boundary is at or before @c posted_off, so no relocated byte is
 *  still referenced. The pass accounting restarts as one pass at the current
 *  ack total. @p out_ptr is set to the write position after compaction.
 *
 *  @return Free bytes available at @p out_ptr.
 */
duct_nonnull(1, 3) static inline size_t
duct_olb_rx_compact(duct_olb_rx_t *rx, uint64_t boundary, uint8_t **out_ptr)
{
    auto h = &rx->h;
    uint8_t *data = duct_olb_rx_data(rx);
    uint32_t stage0 = duct_atomic_load(&h->stage, relaxed);
    size_t partial = stage0 > boundary ? (size_t)(stage0 - boundary) : 0u;
    if (partial && boundary) {
        memmove(data, data + (size_t)boundary, partial);
        duct_rtstat_inc(rx->memmove_compacts, 1u);
    }
    duct_atomic_store(&h->stage, (uint32_t)partial, relaxed);
    rx->recv_hint = 0u;
    rx->posted_off = 0u;
    /* group_off slides by boundary distance. */
    if (rx->group_bytes)
        rx->group_off -= (uint32_t)boundary;
    rx->pass_base = duct_atomic_load(&h->head, relaxed);
    rx->pass_end = 0u;
    rx->skip = 0u;
    duct_atomic_store(&rx->dispatch_frontier, 0u, relaxed);
    duct_atomic_store(&h->tail, partial, release);
    *out_ptr = data + partial;
    return h->buf_size - partial; /* partial <= stage <= buf_size always */
}

/** @brief Find room in @p rx's buffer for the io thread's next read.
 *
 *  Low free space compacts the buffer once every posted frame is
 *  acknowledged, unheld and dispatched, and @p restart otherwise opens a
 *  second pass at offset 0 once the worker has released @p min_avail bytes
 *  from the front and every staged byte is posted; while two passes are live,
 *  only the room below the older pass's release point counts.
 *
 *  @p min_avail is the span the caller cannot proceed without. No success
 *  answer falls below it, the pending-frame hint and the relaxed
 *  half-threshold included.
 *
 *  @return @c olb_rx_ok when the free span sufficed,
 *          @c olb_rx_compacted when compaction or a new pass produced it,
 *          @c olb_rx_full when neither did. @p out_avail is written on every
 *  path; @p out_ptr, the stage cursor, on every path but the early
 *  @c olb_rx_full taken when @c buf_size minus @c stage underflows.
 */
duct_nonnull(1, 4, 5) static inline duct_olb_rx_result_t
duct_olb_rx_try_space(duct_olb_rx_t *rx, size_t min_avail, bool restart,
                      uint8_t **out_ptr, size_t *out_avail)
{
    assert(min_avail);
    auto h = &rx->h;
    uint8_t *data = duct_olb_rx_data(rx);
    uint32_t stage = duct_atomic_load(&h->stage, relaxed);
    if (!rx->pass_end) {
        size_t threshold = duct_max(duct_olb_rx_threshold_get(rx), min_avail);
        *out_avail = 0u;
        if (duct_ckd_sub(out_avail, h->buf_size, stage))
            return olb_rx_full;
        *out_ptr = data + stage;
        if (*out_avail >= threshold)
            return olb_rx_ok;

        if (stage && duct_olb_rx_consumed(rx)) {
            *out_avail = duct_olb_rx_compact(rx, rx->posted_off, out_ptr);
            duct_rtstat_inc(rx->early_compacts, 1u);
            return *out_avail >= min_avail ? olb_rx_compacted : olb_rx_full;
        }

        size_t hint = duct_olb_rx_recv_hint_get(rx);
        if (hint && *out_avail >= duct_max(hint, min_avail))
            return olb_rx_ok;

        if (*out_avail >= duct_max(threshold / olb_rx_relax_div, min_avail))
            return olb_rx_ok;

        size_t done = 0u;
        if (restart && duct_olb_rx_done(rx, &done) && done >= min_avail
            && stage == rx->posted_off && !rx->group_bytes) {
            rx->pass_end = stage;
            rx->pass_free = (uint32_t)done;
            duct_atomic_store(&h->stage, 0u, relaxed);
            rx->posted_off = 0u;
            rx->recv_hint = 0u;
            duct_atomic_store(&h->tail, 0u, release);
            *out_ptr = data;
            *out_avail = done;
            return olb_rx_compacted;
        }
        return olb_rx_full;
    }
    size_t done = 0u;
    if (duct_olb_rx_done(rx, &done) && done > rx->pass_free)
        rx->pass_free = (uint32_t)done;
    *out_ptr = data + stage;
    *out_avail = duct_olb_rx_room(rx);
    return *out_avail >= min_avail ? olb_rx_ok : olb_rx_full;
}

/** @brief Return @p rx's fully consumed buffer to offset 0.
 *  Acts only once every staged byte is posted and the worker is done with all
 *  of them, so no byte moves. A record-framed reserve calls it before each
 *  read, which keeps the whole buffer free for the next burst whenever the
 *  worker keeps up.
 */
duct_nonnull(1) static inline void
duct_olb_rx_rewind(duct_olb_rx_t *rx)
{
    auto h = &rx->h;
    uint32_t stage_r = duct_atomic_load(&h->stage, relaxed);
    if (!stage_r || rx->posted_off != stage_r || !duct_olb_rx_consumed(rx))
        return;
    uint8_t *ptr = nullptr;
    duct_discard duct_olb_rx_compact(rx, rx->posted_off, &ptr);
}

/** @brief Append @p len raw bytes at @p rx's stage cursor.
 *
 *  Carries bytes captured during accept-time protocol sniffing, which must
 *  be replayed into the buffer. The caller verifies the space beforehand
 *  through @ref duct_olb_rx_try_space; @ref duct_dgram_rx_append builds on
 *  this to add datagram framing.
 */
duct_nonnull(1) static inline void
duct_olb_rx_append_raw(duct_olb_rx_t *rx, const void *data, size_t len)
{
    if (!len)
        return;
    auto h = &rx->h;
    uint32_t staged4 = duct_atomic_load(&h->stage, relaxed);
    memcpy(duct_olb_rx_data(rx) + staged4, data, len);
    duct_atomic_store(&h->tail, staged4 + len, release);
    duct_atomic_store(&h->stage, staged4 + (uint32_t)len, relaxed);
}

/** @brief Stage bytes into @p tx, opening the next pass first when this one is
 *  out of room.
 *
 *  Copies @p hdr (if non-null) immediately followed by @p data (if
 *  @p len is nonzero) as one all-or-nothing span.
 */
/** @brief Base of the conn's tx materialize arena: the tx region's front. */
duct_nonnull(1) static inline uint8_t *duct_conn_tx_mat(const duct_conn_t *conn)
{
    return duct_conn_tx_data(conn);
}

/** @brief The conn's tx descriptor array, behind the materialize arena,
 *  32-byte aligned so two descriptors fill one cache line. */
duct_nonnull(1) static inline duct_tx_desc_t *
duct_conn_tx_desc(const duct_conn_t *conn, uint32_t idx)
{
    return (duct_tx_desc_t *)(duct_conn_tx_data(conn)
                              + duct_conn_tx_mat_cap) + idx;
}

static_assert(duct_conn_tx_mat_cap % (2u * (uint32_t)sizeof(duct_span_t)) == 0u,
              "the descriptor array starts 32-byte aligned inside the region");
static_assert((size_t)duct_conn_tx_mat_cap
                  + (size_t)duct_conn_tx_desc_n * sizeof(duct_tx_desc_t)
                  <= conn_tx_region_max,
              "the descriptor area and the materialize arena fit the tx region");

/** @brief Open the next staging descriptor.
 *  The one slot past the staged count; the caller fills its span and inline
 *  header and stages its wire bytes through @c duct_olb_tx_staged_bytes_add.
 *  @return null when the descriptor ring is full — backpressure, not loss. */
duct_nonnull(1) static inline duct_tx_desc_t *
duct_olb_tx_desc_open(duct_olb_tx_t *tx)
{
    if (duct_olb_tx_descs_held(tx) >= duct_conn_tx_desc_n)
        return nullptr;
    uint32_t staged = duct_atomic_load(&tx->h.stage, relaxed);
    uint64_t at = duct_olb_tx_unrolled(duct_atomic_load(&tx->h.tail, relaxed))
                + staged;
    duct_atomic_store(&tx->h.stage, staged + 1u, relaxed);
    return duct_conn_tx_desc(duct_conn_of_olb_tx(&tx->h),
                             (uint32_t)(at % duct_conn_tx_desc_n));
}

/** @brief Contiguous @p len bytes of the materialize arena at its write
 *  position.
 *
 *  The §2.1 classes that cannot ride a reference write here: sealed
 *  ciphertext (the encrypt destination a codec's seal writes into),
 *  sub-threshold copies and foreign buffers. The arena frees in record
 *  completion order, FIFO, so the returned span stays valid until its record
 *  completes. A run that would cross the arena's end wraps to offset zero
 *  when the gap plus the run fit within the remaining budget.
 *
 *  @return The span's arena offset, @c SIZE_MAX when no contiguous free run
 *          of @p len exists. */
duct_nonnull(1) static inline size_t
duct_olb_tx_mat_open(duct_olb_tx_t *tx, size_t len)
{
    if (len > duct_conn_tx_mat_cap)
        return SIZE_MAX;
    uint64_t tail = tx->mat_tail,
             head = duct_atomic_load(&tx->mat_head, acquire);
    size_t off = (size_t)(tail % duct_conn_tx_mat_cap);
    size_t gap = off + len > duct_conn_tx_mat_cap
               ? duct_conn_tx_mat_cap - off : 0u;
    if (tail - head + gap + len > duct_conn_tx_mat_cap)
        return SIZE_MAX;
    off = gap ? 0u : off;
    tx->mat_tail = tail + gap + len;
    return off;
}

/** @brief The materialize arena's bytes at arena offset @p off. */
duct_nonnull(1) static inline uint8_t *
duct_olb_tx_mat_at(duct_olb_tx_t *tx, size_t off)
{
    return duct_conn_tx_mat(duct_conn_of_olb_tx(&tx->h)) + off;
}

/** @brief Stage bytes into @p tx as one whole materialize record.
 *
 *  Copies @p hdr (if non-null) into the record's inline header and
 *  @p data (if @p len is nonzero) into the arena, as one all-or-nothing
 *  record: the engine park's flush and the sealed handshake egress, the
 *  callers whose bytes exist only to be copied.
 */
duct_nonnull(1) static inline duct_olb_tx_result_t
duct_olb_tx_stage(duct_olb_tx_t *tx, const uint8_t *hdr,
                  size_t hdr_size, const void *data, size_t len)
{
    size_t total = (hdr ? hdr_size : 0u) + len;
    if (total > tx->byte_cap)
        return olb_tx_too_large;
    if (!duct_olb_tx_room_contig(tx, total))
        return olb_tx_full;
    uint64_t mat_was = tx->mat_tail;
    size_t off = duct_olb_tx_mat_open(tx, len);
    if (off == SIZE_MAX)
        return len > duct_conn_tx_mat_cap ? olb_tx_too_large : olb_tx_full;
    auto d = duct_olb_tx_desc_open(tx);
    if (!d) {
        tx->mat_tail = mat_was;
        return olb_tx_full;
    }
    d->span = duct_span_of_mat(duct_conn_tx_mat(duct_conn_of_olb_tx(&tx->h)),
                               (uint32_t)off, (uint32_t)len);
    if (hdr) {
        memcpy(d->hdr, hdr, hdr_size);
        duct_span_meta_set(&d->span, (uint32_t)hdr_size, false);
    }
    if (len)
        memcpy(duct_olb_tx_mat_at(tx, off), data, len);
    duct_olb_tx_staged_bytes_add(tx, (uint32_t)total);
    return olb_tx_ok;
}

/** @brief Reserve writable space in @p tx's materialize arena.
 *
 *  The sealed codecs' encrypt destination: the ciphertext does not exist
 *  before staging (§2.1), so @c on_pack opens the span and the engine writes
 *  it. The caller records the span through its own descriptor once written.
 *
 *  @return The span; null when no contiguous free run of @p len exists. */
duct_nonnull(1) static inline void *
duct_olb_tx_span_open(duct_olb_tx_t *tx, size_t len)
{
    size_t off = duct_olb_tx_mat_open(tx, len);
    return off == SIZE_MAX ? nullptr : duct_olb_tx_mat_at(tx, off);
}

/** @brief Write the record header for a payload already in place at @p rx's
 *  tail (caller recv()s straight past the header gap), then advance past
 *  both. Caller has verified the space.
 */
duct_nonnull(1) static inline void
duct_dgram_rx_header_commit(duct_olb_rx_t *rx, size_t len)
{
    auto h = &rx->h;
    auto dst = duct_olb_rx_data(rx) + h->stage;
    duct_dgram_rec_hdr_t rhdr;
    duct_dgram_rec_hdr_encode(rhdr.octets, len);
    memcpy(dst, &rhdr, sizeof(rhdr));
    size_t total = sizeof(rhdr) + len;
    uint32_t staged = duct_atomic_load(&h->stage, relaxed);
    duct_atomic_store(&h->tail, staged + total, release);
    duct_atomic_store(&h->stage, staged + (uint32_t)total, relaxed);
}

/** @brief Append one @c [len][payload] record at @p rx's tail, copying
 *  @p data in.
 *
 *  For a classification or injection path whose payload lives in a separate
 *  buffer; @ref duct_dgram_rx_header_commit takes the in-place recv() case.
 *  Caller has already verified @c sizeof(duct_dgram_rec_hdr_t) + @p len
 *  bytes of space.
 */
duct_nonnull(1) static inline void
duct_dgram_rx_append(duct_olb_rx_t *rx, const void *data, size_t len)
{
    if (len)
        memcpy(duct_olb_rx_data(rx) + duct_atomic_load(&rx->h.stage, relaxed)
               + sizeof(duct_dgram_rec_hdr_t), data, len);
    duct_dgram_rx_header_commit(rx, len);
}

/** @brief The span's payload view: its bytes where they live.
 *
 *  The one resolver every descriptor site shares — the worker's stage, the
 *  io thread's gather, a park's replay — each reading the same 16 bytes into
 *  the window the send posts. A @c span_rx names the conn block itself, its
 *  data region reached through the fixed page-0 geometry this header owns.
 */
duct_nonnull(1) static inline duct_view_u8
duct_span_body(duct_span_t *span)
{
    const uint8_t *base;
    if (duct_span_kind_of(span) == span_rx)
        base = duct_conn_rx_data((duct_conn_t *)duct_span_base(span));
    else
        base = (const uint8_t *)duct_span_base(span);
    return (duct_view_u8){
        .data = (void *)(uintptr_t)(base + duct_span_off(span)),
        .size = duct_span_len(span),
    };
}

/** @brief Drop a span's payload reference at whichever point resolved it —
 *  send, lane copy, a park's takeover or a terminal discard.
 *
 *  The §5.1 matrix unpin with the one substrate whose lifetime authority is
 *  not the alloc header special-cased: a slot-object @c span_ptr's drop is
 *  the claim it took (@c duct_io_rx_slot_drop), never a @c duct_del — the
 *  slot's free list answers its pool's claim counter, and a plain delete
 *  would push it back past every claim.
 */
duct_nonnull(1) static inline void
duct_span_payload_drop(duct_span_t *span)
{
    if (duct_span_kind_of(span) == span_rx) {
        auto conn = (duct_conn_t *)duct_span_base(span);
        duct_span_unpin(span, duct_conn_rx_hdr(conn));
        return;
    }
    if (duct_span_kind_of(span) == span_ptr) {
        auto base = duct_span_base(span);
        if (duct_x_slot_obj_is(base)) {
            auto pool = duct_x_slot_pool_of(base);
            duct_io_rx_slot_drop(pool, duct_x_slot_index(pool, base), true);
            return;
        }
    }
    duct_span_unpin(span, nullptr);
}

/** @brief Io's gather source: the queued records' spans, from the head.
 *
 *  §5.2's stepper view over the conn's descriptor ring: the head record's
 *  remaining bytes — its inline header first, then the span's payload,
 *  @c cursor_off already sent — plus the whole records behind it, up to
 *  @p max_recs of them, two spans each (an empty header or body leaves its
 *  span zero, the sender skips it). A record-framed leg (@p rec true)
 *  answers its head record alone: a datagram ships whole or not at all.
 *  The caller sends what it got and hands the byte count to
 *  @c duct_olb_tx_advance.
 *
 *  @param out_iov the caller's span array, @c 2 * max_recs wide.
 *  @return Spans filled, always even — twice the records addressed; 0 when
 *          nothing is queued. */
duct_nonnull(1, 4) static inline unsigned
duct_olb_tx_peek_iov(duct_olb_tx_t *tx, bool rec, unsigned max_recs,
                     duct_view_u8 *out_iov)
{
    uint64_t head = duct_olb_tx_unrolled(duct_atomic_load(&tx->h.head, acquire)),
             tail = duct_olb_tx_unrolled(duct_atomic_load(&tx->h.tail, acquire));
    uint32_t off = duct_atomic_load(&tx->cursor_off, relaxed);
    unsigned n = 0u;
    while (head < tail && n < max_recs) {
        auto d = duct_conn_tx_desc(duct_conn_of_olb_tx(&tx->h),
                                   (uint32_t)(head % duct_conn_tx_desc_n));
        uint32_t hdr = duct_span_hdr_len(&d->span);
        duct_view_u8 body = duct_span_body(&d->span);
        out_iov[2u * n] = off < hdr
            ? (duct_view_u8){ .data = d->hdr + off, .size = hdr - off }
            : (duct_view_u8){};
        out_iov[2u * n + 1u] = off <= hdr
            ? body
            : (duct_view_u8){ .data = (uint8_t *)body.data + (off - hdr),
                              .size = body.size - (off - hdr) };
        if (off > hdr + body.size)
            out_iov[2u * n + 1u] = (duct_view_u8){};
        ++n;
        if (rec)
            break;
        off = 0u;
        ++head;
    }
    return n ? 2u * n : 0u;
}

/** @brief The worker's gather source: this ring's staged, unpublished
 *  records, whole — the spans a train's own direct send reads and completes
 *  through @c duct_olb_tx_advance_worker.
 *
 *  @param out_iov the caller's span array, @c 2 * max_recs wide.
 *  @return Spans filled, always even; 0 while nothing is staged. */
duct_nonnull(1, 3) static inline unsigned
duct_olb_tx_peek_staged_iov(duct_olb_tx_t *tx, unsigned max_recs,
                            duct_view_u8 *out_iov)
{
    uint64_t at = duct_olb_tx_unrolled(duct_atomic_load(&tx->h.tail, relaxed));
    auto conn = duct_conn_of_olb_tx(&tx->h);
    uint32_t staged = duct_atomic_load(&tx->h.stage, relaxed);
    unsigned n = 0u;
    while (n < max_recs && (uint32_t)n < staged) {
        auto d = duct_conn_tx_desc(conn, (uint32_t)((at + n) % duct_conn_tx_desc_n));
        out_iov[2u * n] = duct_span_hdr_len(&d->span)
            ? (duct_view_u8){ .data = d->hdr,
                              .size = duct_span_hdr_len(&d->span) }
            : (duct_view_u8){};
        out_iov[2u * n + 1u] = duct_span_body(&d->span);
        ++n;
    }
    return n ? 2u * n : 0u;
}

/** @brief The worker's staged records as the grouped send's record view.
 *  @return Records filled; 0 while nothing is staged. */
duct_nonnull(1, 2) static inline unsigned
duct_olb_tx_peek_staged_recs(duct_olb_tx_t *tx, duct_tx_rec_t *recs, unsigned max)
{
    uint64_t at = duct_olb_tx_unrolled(duct_atomic_load(&tx->h.tail, relaxed));
    auto conn = duct_conn_of_olb_tx(&tx->h);
    uint32_t staged = duct_atomic_load(&tx->h.stage, relaxed);
    unsigned n = 0u;
    while (n < max && (uint32_t)n < staged) {
        auto d = duct_conn_tx_desc(conn, (uint32_t)((at + n) % duct_conn_tx_desc_n));
        recs[n] = (duct_tx_rec_t){
            .hdr = duct_span_hdr_len(&d->span)
                ? (duct_view_u8){ .data = d->hdr,
                                  .size = duct_span_hdr_len(&d->span) }
                : (duct_view_u8){},
            .body = duct_span_body(&d->span),
        };
        ++n;
    }
    return n;
}

/** @brief Drop the head record's payload reference and move the ring past it.
 *
 *  The §5.2 rule: a span unpins only at its record's full completion — the
 *  rx pin's §2.3 step, the block holder's release, the slot claim's return —
 *  the materialize arena's bytes return in the same order, and the drained
 *  position takes the record's wire bytes whoever completed them. Callers
 *  reach this through the advance steppers and the close-path purge, never
 *  directly, so the wake and the socket accounting ride the same
 *  completion.
 *  @return the completed record's wire bytes. */
duct_nonnull(1) static inline uint32_t
duct_olb_tx_complete_one_done(duct_olb_tx_t *tx, bool *out_done)
{
    uint64_t head = duct_olb_tx_unrolled(duct_atomic_load(&tx->h.head, relaxed));
    auto conn = duct_conn_of_olb_tx(&tx->h);
    auto d = duct_conn_tx_desc(conn, (uint32_t)(head % duct_conn_tx_desc_n));
    uint32_t wire = duct_span_wire_len(&d->span);
    uint32_t done_d = duct_span_done_delta(&d->span);
    if (duct_span_kind_of(&d->span) == span_mat) {
        uint64_t mhead = duct_atomic_load(&tx->mat_head, relaxed);
        uint32_t h_off = (uint32_t)(mhead % duct_conn_tx_mat_cap);
        uint32_t s_off = duct_span_off(&d->span);
        uint64_t step = (s_off < h_off ? duct_conn_tx_mat_cap - h_off : 0u)
                      + duct_span_len(&d->span);
        duct_atomic_fetch(add, &tx->mat_head, step, release);
    }
    duct_span_payload_drop(&d->span);
    d->span = (duct_span_t){};
    if (done_d) {
        duct_atomic_fetch(add, &duct_conn_tx_done(conn)->seq, done_d, release);
        if (out_done)
            *out_done = true;
    }
    duct_atomic_fetch(add, &tx->drained, wire, release);
    duct_atomic_store(&tx->h.head, duct_olb_tx_packed(head + 1u), release);
    return wire;
}

duct_nonnull(1) static inline uint32_t
duct_olb_tx_complete_one(duct_olb_tx_t *tx)
{
    return duct_olb_tx_complete_one_done(tx, nullptr);
}

/** @brief Complete every record the ring still holds — published or staged —
 *  without sending anything.
 *
 *  The slot's return path: a timeout or a lost conn leaves records no socket
 *  will ever take, and their payload references must not outlive the block
 *  into its next occupant. Runs where the conn's last unit is spent — the
 *  free-list push — the one point the refs discipline proves no commit,
 *  completion or staging can hold the ring open. */
duct_nonnull(1) static inline void
duct_olb_tx_purge(duct_olb_tx_t *tx)
{
    auto h = &tx->h;
    /* The staged records' bytes never passed a publish: fold them into the
     * stream end here, so the completions' drained advances stay within it
     * and the held metrics read an empty ring, not an underflow. */
    tx->stream_end += tx->staged_bytes;
    tx->staged_bytes = 0u;
    while (duct_olb_tx_descs_held(tx))
        duct_discard duct_olb_tx_complete_one(tx);
    duct_atomic_store(&h->stage, 0u, relaxed);
    /* The staged records the loop completed past tail retire it too, onto
     * the head the completions left. */
    duct_atomic_store(&h->tail,
                      duct_atomic_load(&h->head, acquire), release);
    duct_atomic_store(&tx->cursor_off, 0u, relaxed);
}

/** @brief Advance io's completion position by @p n sent bytes (§5.2).
 *
 *  The bytes walk record by record: the head record's remainder first, its
 *  cursor moving without any tail copy, and each record that reaches its end
 *  completes — span unpin, arena return, drained advance — before the next
 *  one's bytes count. A record-framed leg completes whole or not at all.
 *  A record of zero wire bytes (an empty datagram) completes without moving
 *  the drained position; the caller's wake answers that by signal.
 *
 *  @return true when a zero-wire completion happened — an armed waiter
 *          cannot wait for a byte that never comes; false otherwise. */
duct_nonnull(1) static inline bool
duct_olb_tx_advance_done(duct_olb_tx_t *tx, size_t n, bool rec, bool *out_done)
{
    bool zero = false;
    while (n) {
        uint64_t head = duct_olb_tx_unrolled(duct_atomic_load(&tx->h.head, relaxed));
        uint64_t tail = duct_olb_tx_unrolled(duct_atomic_load(&tx->h.tail, acquire));
        if (head == tail)
            break;
        auto d = duct_conn_tx_desc(duct_conn_of_olb_tx(&tx->h),
                                   (uint32_t)(head % duct_conn_tx_desc_n));
        uint32_t wire = duct_span_wire_len(&d->span);
        size_t rest = wire - duct_atomic_load(&tx->cursor_off, relaxed);
        if (n < rest) {
            if (!rec) /* a stream keeps its place inside the record */
                duct_atomic_store(&tx->cursor_off,
                                  (uint32_t)(wire - rest + n), release);
            /* A record-framed leg ships whole or not at all: a short count
             * means the datagram never left, and its bytes are not spent. */
            return false;
        }
        duct_discard duct_olb_tx_complete_one_done(tx, out_done);
        duct_atomic_store(&tx->cursor_off, 0u, relaxed);
        n -= rest;
        if (!wire)
            zero = true; /* the slot freed though no byte moved */
    }
    return zero;
}

duct_nonnull(1) static inline bool
duct_olb_tx_advance(duct_olb_tx_t *tx, size_t n, bool rec)
{
    return duct_olb_tx_advance_done(tx, n, rec, nullptr);
}

/** @brief Account for the worker sending its whole staged, unpublished span
 *  itself, and rewind staging onto tail.
 *  Completes every staged record — unpins with them — and moves
 *  @c stream_end past their bytes; nothing reaches io. Each completion's
 *  retirement lands tail on the advanced head: across the pair io's
 *  [head, tail) window reads empty, never a record already unpinned. */
duct_nonnull(1) static inline void
duct_olb_tx_sent_staged(duct_olb_tx_t *tx)
{
    auto h = &tx->h;
    tx->stream_end += tx->staged_bytes;
    tx->staged_bytes = 0u;
    uint64_t tail = duct_olb_tx_unrolled(duct_atomic_load(&h->tail, relaxed));
    uint32_t staged;
    while ((staged = duct_atomic_load(&h->stage, relaxed)) != 0u) {
        duct_atomic_store(&h->stage, staged - 1u, relaxed);
        /* The worker completes its own staged records: io has never seen
         * them, so head's two writers stay past one another's values. */
        duct_discard duct_olb_tx_complete_one(tx);
        duct_atomic_store(&h->tail, duct_olb_tx_packed(++tail), release);
    }
    duct_atomic_store(&tx->cursor_off, 0u, relaxed);
}

/** @brief Account for @p sent bytes the worker sent itself off the front of
 *  its own staged, still-unpublished records.
 *
 *  The worker-side counterpart of @c duct_olb_tx_advance. Records the socket
 *  took whole complete here — unpin included — and the cursor rests inside
 *  the first record the socket refused; @c duct_olb_tx_publish after this
 *  hands that remainder to io. Only records io has never seen advance here,
 *  so head's two writers never collide: no compare-exchange remains.
 *
 *  Caller must hold: every published record completed when its commit began,
 *  so io has no queued span, and no other advance can interleave. */
duct_nonnull(1) static inline void
duct_olb_tx_advance_worker(duct_olb_tx_t *tx, size_t sent)
{
    auto h = &tx->h;
    uint64_t tail = duct_olb_tx_unrolled(duct_atomic_load(&h->tail, relaxed));
    uint32_t staged;
    while ((staged = duct_atomic_load(&h->stage, relaxed)) != 0u && sent) {
        /* The staged window's front: head, which the entry contract left at
         * tail and each completion below advances onto the next record. */
        uint64_t first = duct_olb_tx_unrolled(
            duct_atomic_load(&h->head, relaxed));
        auto d = duct_conn_tx_desc(duct_conn_of_olb_tx(&tx->h),
                                   (uint32_t)(first % duct_conn_tx_desc_n));
        uint32_t wire = duct_span_wire_len(&d->span);
        size_t rest = wire - duct_atomic_load(&tx->cursor_off, relaxed);
        if (sent < rest) {
            duct_atomic_store(&tx->cursor_off,
                              (uint32_t)(wire - rest + sent), release);
            return;
        }
        sent -= rest;
        duct_atomic_store(&tx->cursor_off, 0u, relaxed);
        duct_atomic_store(&h->stage, staged - 1u, relaxed);
        duct_discard duct_olb_tx_complete_one(tx);
        duct_atomic_store(&h->tail, duct_olb_tx_packed(++tail), release);
    }
    if (!duct_atomic_load(&h->stage, relaxed))
        duct_atomic_store(&tx->cursor_off, 0u, relaxed);
}

/** @brief Block index of @p conn: its offset into the pool's range. */
duct_nonnull(1) uint32_t duct_conn_block_idx(const duct_conn_t *conn);

/** @brief Address of conn block @p idx, unchecked: for a raw page-0 reader
 *  that holds its own liveness proof. @ref duct_conn_by_idx is the guarded
 *  resolver. */
duct_conn_t *duct_conn_block_at(uint32_t idx);

/** @brief Test whether conn block @p idx is @c blk_active. */
bool duct_conn_block_live(uint32_t idx);

/** @brief Spend @p budget of the conn pool's sweep work; the io tick's step. */
bool duct_conn_pool_sweep(uint32_t budget);

/** @brief The engine's conn block pool. */
duct_block_pool_t *duct_conn_pool_blocks(void);

#ifdef __cplusplus
}
#endif

#endif /* DUCT_CONN_BLOCK_H */
