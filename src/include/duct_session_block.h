/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_session_block.h
 *  @brief The session's 64 KB block: resident page 0 with the defer region,
 *  the streams region, and the session-owned retry regions.
 *
 *  One block carries one session slot; the block number is the slot index,
 *  @c duct_session_t at offset 0. Page 0 is the fixed resident head — the
 *  body, the per-leg counters, the keyed-timer slots, the timer hold, the
 *  session-owned retry maps, the touched word, the defer maps and the whole
 *  defer region under @c duct_session_defer_bytes — bounded by
 *  @c session_page0_hard and page-aligned at runtime by
 *  @ref duct_session_page0. Behind page 0 sit the streams region — the
 *  stream table, its buckets and one handler context slot per table slot —
 *  and the two session-owned retry regions, emit first.
 *
 *  Residency is first-touch: a session that never multiplexes never faults
 *  the tail pages in, and @c touched, a page count grown one @c max at a
 *  stream claim, names what a sweep of the block returns.
 */

#ifndef DUCT_SESSION_BLOCK_H
#define DUCT_SESSION_BLOCK_H

#include "duct_build_config.h"
#include "duct_session.h"
#include "duct_stream_ctx.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Bytes of one session block: a power of two, whole pages. */
static constexpr uint32_t session_block_size = kbytes(64u);
/** @brief Hard ceiling of page 0's fixed head, whatever the runtime page is. */
static constexpr uint32_t session_page0_hard = kbytes(16u);

/** @name Page-0 offsets
 *  The fixed resident head in first-reach order: the body, the per-leg
 *  counters, the keyed-timer slots, the timer hold, the session-owned retry
 *  maps, the touched word, the defer maps, the defer region.
 *  @{
 */
static constexpr uint32_t session_off_body = 0u;
static constexpr uint32_t session_off_counters = sizeof(duct_session_t);
static constexpr uint32_t session_off_timer_keys =
    session_off_counters + duct_session_max_legs * sizeof(duct_conn_counters_t);
static constexpr uint32_t session_off_timer_hold =
    session_off_timer_keys + session_timer_keys * sizeof(duct_session_timer_key_t);
/** @} */

/** @brief The session-owned retry regions' allocation maps in page 0: one
 *  bit per node slot, a set bit taken. The pool's acquire reset zeroes
 *  them, and the owning worker alone takes and frees.
 */
typedef struct duct_session_retry_maps {
    uint64_t emit[(duct_session_retry_emit_nodes + 63u) / 64u];
    uint64_t timer[(duct_session_retry_timer_nodes + 63u) / 64u];
} duct_session_retry_maps_t;

/** @brief Offset of the retry maps in page 0, past the timer hold. */
static constexpr uint32_t session_off_retry_maps =
    session_off_timer_hold + sizeof(duct_tx_hold_t);

/** @brief The session's touched high-water, whole pages. */
typedef struct duct_session_stats {
    uint16_t touched;
} duct_session_stats_t;

/** @brief Offset of the touched word in page 0, past the retry maps. */
static constexpr uint32_t session_off_stats =
    session_off_retry_maps + sizeof(duct_session_retry_maps_t);

/** @brief Grain of the defer region's allocation units, bytes. */
static constexpr uint32_t session_defer_grain = 64u;
/** @brief Defer units the region divides into. */
static constexpr uint32_t duct_session_defer_units =
    duct_session_defer_bytes / session_defer_grain;

/** @brief The defer region's allocation maps in page 0: one bit per grain
 *  unit, a set bit taken. */
typedef struct duct_session_defer_maps {
    uint64_t units[(duct_session_defer_units + 63u) / 64u];
} duct_session_defer_maps_t;

static constexpr uint32_t session_off_defer_maps =
    (session_off_stats + sizeof(duct_session_stats_t) + 7u) & ~(uint32_t)7u;
static_assert(session_off_defer_maps % 8u == 0u,
              "session defer maps require 8-byte alignment for uint64 words");
/** @brief Offset of the defer region itself, the fixed head's last part. */
static constexpr uint32_t session_off_defer =
    session_off_defer_maps + sizeof(duct_session_defer_maps_t);

static_assert(duct_session_defer_bytes % session_defer_grain == 0u,
              "the defer budget is a whole number of grain units");
static_assert(session_off_defer + duct_session_defer_bytes <= session_page0_hard,
              "page 0's fixed part fits the hard page ceiling");

/** @brief Bytes of the stream table, one slot per @c duct_session_max_streams. */
static constexpr size_t session_streams_span =
    duct_session_max_streams * sizeof(duct_stream_t);
/** @brief Bytes of the stream table's bucket array. */
static constexpr size_t session_buckets_span =
    duct_session_max_streams * sizeof(duct_hash_handle_t *);
/** @brief Bytes of the handler-context table, one slot per table slot. */
static constexpr size_t session_ctxs_span =
    duct_session_max_streams * sizeof(duct_stream_ctx_t);
/** @brief Bytes of the whole streams region behind page 0. */
static constexpr size_t session_streams_region =
    session_streams_span + session_buckets_span + session_ctxs_span;

/** @brief One retry node slot's stride, bytes, pinned to the worker's own
 *  @c retry_node_t by a static_assert there. */
static constexpr size_t session_retry_node_span = 264u;
/** @brief Bytes of the stream-owned emit nodes' region. */
static constexpr size_t session_emit_region =
    duct_session_retry_emit_nodes * session_retry_node_span;
/** @brief Bytes of the session-owned timer nodes' region, behind the emit one. */
static constexpr size_t session_timer_region =
    duct_session_retry_timer_nodes * session_retry_node_span;

static_assert((size_t)session_page0_hard + session_streams_region
                  + session_emit_region + session_timer_region <= session_block_size,
              "the streams region and both session-owned retry regions fit the block");

/** @brief End of page 0's fixed head, aligned to the runtime page: the
 *  streams region starts here, and the tail a sweep drops begins at this
 *  boundary. */
static inline uint32_t duct_session_page0(void)
{
    return (uint32_t)duct_align_up(session_off_defer + duct_session_defer_bytes,
                                   duct_page_size());
}

/** @brief The session's retry region allocation maps in page 0. */
duct_nonnull(1) static inline duct_session_retry_maps_t *
duct_session_retry_maps(const duct_session_t *s)
{
    return (duct_session_retry_maps_t *)((uintptr_t)s + session_off_retry_maps);
}

/** @brief The session's touched word in page 0. */
duct_nonnull(1) static inline duct_session_stats_t *
duct_session_stats(const duct_session_t *s)
{
    return (duct_session_stats_t *)((uintptr_t)s + session_off_stats);
}

/** @brief The session's defer region allocation maps in page 0. */
duct_nonnull(1) static inline duct_session_defer_maps_t *
duct_session_defer_maps(const duct_session_t *s)
{
    return (duct_session_defer_maps_t *)((uintptr_t)s + session_off_defer_maps);
}

/** @brief Base of the session's defer region, inside page 0's fixed tail. */
duct_nonnull(1) static inline uint8_t *
duct_session_defer_region(const duct_session_t *s)
{
    return (uint8_t *)s + session_off_defer;
}

/** @brief The session's timer hold word in page 0. */
duct_nonnull(1) static inline duct_tx_hold_t *
duct_session_timer_hold(const duct_session_t *s)
{
    return (duct_tx_hold_t *)((uintptr_t)s + session_off_timer_hold);
}

/** @brief Base of the session's stream table, right past page 0. */
duct_nonnull(1) static inline duct_stream_t *
duct_session_streams(const duct_session_t *s)
{
    return (duct_stream_t *)((uint8_t *)s + duct_session_page0());
}

/** @brief Base of the stream table's bucket array, behind the table itself. */
duct_nonnull(1) static inline duct_hash_handle_t **
duct_session_stream_buckets(const duct_session_t *s)
{
    return (duct_hash_handle_t **)((uint8_t *)s + duct_session_page0()
                                   + session_streams_span);
}

/** @brief Base of the handler-context table, behind the buckets. */
duct_nonnull(1) static inline duct_stream_ctx_t *
duct_session_stream_ctx_table(const duct_session_t *s)
{
    return (duct_stream_ctx_t *)((uint8_t *)s + duct_session_page0()
                                + session_streams_span + session_buckets_span);
}

/** @brief The handler-context slot paired one-to-one with table slot @p slot. */
duct_nonnull(1, 2) static inline duct_stream_ctx_t *
duct_session_stream_ctx_slot(const duct_session_t *s, const duct_stream_t *slot)
{
    uint32_t idx = (uint32_t)(((uintptr_t)slot
                               - (uintptr_t)duct_session_streams(s))
                              / sizeof(duct_stream_t));
    return duct_session_stream_ctx_table(s) + idx;
}

/** @brief Raise the session's touched high-water to the pages its newest
 *  claimed stream slot reaches.
 *  One @c max at a claim, owner-run; the release hands the word to the pool.
 */
duct_nonnull(1) static inline void
duct_session_touched_update(duct_session_t *s, const duct_stream_t *slot)
{
    uint32_t idx = (uint32_t)(((uintptr_t)slot
                               - (uintptr_t)duct_session_streams(s))
                              / sizeof(duct_stream_t));
    size_t bytes = duct_session_page0() + session_streams_span + session_buckets_span
                 + (size_t)(idx + 1u) * sizeof(duct_stream_ctx_t);
    size_t pages = duct_min(bytes / duct_page_size(), (size_t)UINT16_MAX);
    auto st = duct_session_stats(s);
    if (pages > st->touched)
        st->touched = (uint16_t)pages;
}

/** @brief Base of the session's emit retry node slots; slot @p idx sits at
 *  @c idx * session_retry_node_span. */
duct_nonnull(1) static inline uint8_t *
duct_session_retry_emit_slot(const duct_session_t *s, uint32_t idx)
{
    return (uint8_t *)s + duct_session_page0() + session_streams_region
           + (size_t)idx * session_retry_node_span;
}

/** @brief Base of the session's timer retry node slots, behind the emit ones. */
duct_nonnull(1) static inline uint8_t *
duct_session_retry_timer_slot(const duct_session_t *s, uint32_t idx)
{
    return duct_session_retry_emit_slot(s, duct_session_retry_emit_nodes)
           + (size_t)idx * session_retry_node_span;
}

#ifdef __cplusplus
}
#endif

#endif /* DUCT_SESSION_BLOCK_H */
