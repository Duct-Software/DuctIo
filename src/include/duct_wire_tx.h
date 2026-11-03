/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_wire_tx.h
 *  @brief Full definition of the public, opaque @c duct_wire_tx_t.
 *
 *  Three staging targets share one @c on_pack contract via
 *  @c duct_wire_tx_stage: the per-conn @ref duct_olb_tx_t ring, the common
 *  case; a one-shot flat view over a buffer the caller already sized, which
 *  the datagram fast paths use to skip the ring-then-copy double-buffer; and
 *  a gather view, which records the payload span for an in-place vectored send.
 *  @c on_pack authors never see this file — they only receive an
 *  already-constructed @c duct_wire_tx_t* through the public,
 *  opaque-pointer wire contract.
 */

#ifndef DUCT_WIRE_TX_H
#define DUCT_WIRE_TX_H

#include "duct_olb_tx.h"
#include "duct_wire.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Open @p n contiguous writable bytes in @p stage.
 *
 *  Lets a sealed wire write ciphertext straight where the send reads from,
 *  without branching on the tag itself. The span is already claimed on
 *  return: a second call continues after it.
 *
 *  @return The span; @c nullptr when the target has no room for @p n, and
 *  always for a gather target, which carries immutable spans.
 */
duct_nonnull(1) void *duct_wire_tx_span_open(duct_wire_tx_t *stage, size_t n);

/** @brief One-shot staging view over a flat buffer the caller already sized.
 *  No ring and no wrap, so overflow past @c capacity is terminal. Two of its
 *  three users hand it a @c duct_tx_pool_acquire block and the third a
 *  datagram lane reservation; the view itself reads neither.
 */
typedef struct duct_vmq_tx_view {
    uint8_t *data;    /**< The caller's buffer, written from offset 0. */
    size_t stage;     /**< Bytes written so far. */
    size_t capacity;  /**< Bytes @c data holds, set by whoever sized it. */
} duct_vmq_tx_view_t;

/** @brief Header bytes one @c pack_header call can write, the width of the
 *  @c uint8_t[16] every one of them takes. */
static constexpr size_t wire_tx_hdr_max = 16u;

/** @brief Which member of @c duct_wire_tx_t's union is live. */
typedef enum : uint8_t {
    wire_tx_olb,      /**< Per-conn TX ring. */
    wire_tx_vmq_view, /**< One-shot flat view over a caller-sized buffer. */
    wire_tx_gather,   /**< Span pair for a vectored send, moving no bytes
                        *  but the header's. */
} duct_wire_tx_kind_t;

struct duct_wire_tx {
    duct_wire_tx_kind_t kind;
    bool                gathered;  /**< A gather target's span pair is taken.
                                     *  Spends the padding behind @c kind. The
                                     *  pair holds one whole frame, so a second
                                     *  stage call onto the same target answers
                                     *  @c olb_tx_too_large. */
    union {
        duct_olb_tx_t      *olb;
        duct_vmq_tx_view_t  vmq_view;
        duct_view_u8         *gather;  /**< Caller's two-entry span array.
                                       *  Slot 0 arrives pre-pointed at
                                       *  @ref wire_tx_hdr_max scratch bytes to
                                       *  copy the header into, slot 1 takes
                                       *  the payload buffer verbatim. The
                                       *  caller sends both before it returns,
                                       *  which keeps the payload alive that
                                       *  long. */
    };
};

#ifdef __cplusplus
}
#endif

#endif /* DUCT_WIRE_TX_H */
