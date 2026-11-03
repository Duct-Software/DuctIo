/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_stream_ctx.h
 *  @brief Full layout backing the opaque duct_stream_ctx_t.
 *
 *  The public stream API exposes this type to protocol authors as an
 *  opaque pointer plus accessor functions; this header is for the runtime.
 */

#ifndef DUCT_STREAM_CTX_H
#define DUCT_STREAM_CTX_H

#include "duct_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Which member of duct_frame_ack_t's union is live. */
typedef enum duct_frame_ack_kind : uint8_t {
    ack_ring,  /**< RX ring byte span. */
    ack_ct,    /**< Sealed connection's decrypted record span. */
    ack_owned, /**< Handler-owned copy, not aliased into any ring; freed
                 *  via duct_del. */
    ack_slot,  /**< Claim on a datagram RX slot, dropped through
                 *  duct_io_rx_slot_drop. */
    ack_count, /**< Not a valid kind — array sizing, loop bounds. */
} duct_frame_ack_kind_t;

/** @brief Acknowledgment record for the held frame's bytes. */
typedef struct duct_frame_ack {
    duct_frame_ack_kind_t kind;
    union {
        struct {
            size_t   task_len; /**< Bytes to release from the RX buf. */
            uint32_t end_off;  /**< RX buf offset where the acknowledged
                                 *  span ends. */
        } ring;
        duct_view_u8 ct; /**< Acknowledged span of a sealed record's cleartext.
                         *  @c data is the codec's cleartext buffer, never an
                         *  address inside it; @c size is the decrypted bytes
                         *  acknowledged. */
        struct {
            void *ptr; /**< Handler-owned copy. */
        } owned;
        struct {
            struct duct_x_slot_pool *pool; /**< Pool of the claimed slot. */
            uint32_t                  idx; /**< Index of the claimed slot. */
        } slot;
    };
} duct_frame_ack_t;

/** @brief Context for one running stream handler. */
typedef struct duct_stream_ctx {
    duct_session_t  *s;         /**< Owning session. */
    duct_stream_id_t stream_id; /**< The stream this context runs for. */
    duct_conn_id_t   conn_id;   /**< Leg the current frame arrived on. */

    duct_frame_t frame; /**< The frame currently being handled. Payload
                          *  points into the RX buf, a sealed connection's
                          *  decrypted buffer, a datagram RX slot the frame
                          *  holds a claim on (@c ack.kind == ack_slot), or
                          *  (@c ack.kind == ack_owned) a private copy owned
                          *  by this hctx, and stays valid only until @c ack
                          *  releases it. */

    /** @brief How to release @c frame's bytes: which pool they came from —
     *  the RX buf, a sealed connection's decrypted buffer, a claimed RX
     *  slot, or a private copy this hctx owns outright. Set once, when the frame is
     *  dispatched to the handler, mirrors whichever memory
     *  @c frame.payload actually points into.
     */
    duct_frame_ack_t ack;

    /** @brief True once @c ack has been applied for flow control while
     *  @c frame is still pinned. This happens when the handler emits a
     *  response that still points at the frame's own bytes but staging
     *  it hits TX backpressure: the response is parked for retry, so the
     *  frame cannot be released yet, but the RX ring still needs the
     *  bytes accounted as consumed. Stops those bytes from being
     *  acknowledged a second time if the handler is cancelled before
     *  that retry resolves.
     */
    bool frame_acked;

    void *stream_state; /**< State the author keeps for this stream. */
    duct_async_t *au;   /**< Stackless coroutine running this handler,
                         *  or nullptr. */
    duct_coro_t  *co;   /**< Stackful coroutine running this handler,
                         *  or nullptr. */

    duct_response_t out; /**< Response to send. Resets to the framework
                           *  default before every handler invocation. */
} duct_stream_ctx_t;

#ifdef __cplusplus
}
#endif

#endif /* DUCT_STREAM_CTX_H */
