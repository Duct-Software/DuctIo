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
#include "duct_span.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Context for one running stream handler. */
typedef struct duct_stream_ctx {
    duct_session_t  *s;         /**< Owning session. */
    duct_stream_id_t stream_id; /**< The stream this context runs for. */
    duct_conn_id_t   conn_id;   /**< Leg the current frame arrived on. */

    duct_frame_t frame; /**< The frame currently being handled. Payload
                          * points where @c span names — the conn's RX
                          * ring, a sealed record's cleartext chunk, a
                          * datagram RX slot the span holds a claim on, or
                          * a private copy this hctx owns outright — and
                          * stays valid only until @c span releases it. */

    /** @brief The held frame's payload reference, §1.1's one span per held
     *  payload: the substrate named by @c tagged_base pinned for the
     *  handler's hold — an RX ring span through @c rx->pins and the §2.3
     *  refs unit, a cleartext chunk through its pool's record holders, a
     *  claimed RX slot, an owned block — released at the frame's ack or
     *  cancel, whichever comes first.
     *
     *  The span's window closes as the ack applies: @c len reads 0 once
     *  the frame's bytes are accounted, the substrate staying named for
     *  the pin's release alone. A parked answer aliasing the frame keeps
     *  the span past its ack; the cancel paths release it whole. */
    duct_span_t span;

    void *stream_state; /**< State the author keeps for this stream. */
    duct_async_t *au;   /**< Stackless coroutine running this handler,
                         *  or nullptr. */
    duct_coro_t  *co;   /**< Stackful coroutine running this handler,
                         *  or nullptr. */

    duct_response_t out; /**< Response to send. Resets to the framework
                           * default before every handler invocation. */
} duct_stream_ctx_t;

#ifdef __cplusplus
}
#endif

#endif /* DUCT_STREAM_CTX_H */
