/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_stream.h
 *  @brief Helpers for stream coroutine handlers.
 *
 *  A multiplexed protocol delegates per-stream execution to coroutines by
 *  setting @c handler_kind on @c duct_proto_cfg_t to @c handler_async or
 *  @c handler_coro. Non-zero streams run in dedicated coroutines reading
 *  incoming frames and emitting responses; stream zero dispatches through
 *  @c on_frame.
 *
 *  Stackless handler:
 *  @code{.c}
 *  static duct_async_rc_t on_stream(void *state) {
 *      auto ctx = (duct_stream_ctx_t *)state;
 *      duct_stream_emit_response(ctx, &resp);
 *      return async_wait;
 *  }
 *  @endcode
 *
 *  Stackful handler:
 *  @code{.c}
 *  static void on_stream(void *arg) {
 *      auto ctx = (duct_stream_ctx_t *)arg;
 *      duct_stream_emit_and_wait(ctx, &resp);
 *  }
 *  @endcode
 */

#ifndef DUCT_STREAM_H
#define DUCT_STREAM_H

#include "duct_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct duct_stream_ctx duct_stream_ctx_t;

/** @brief Get the frame currently being handled.
 *
 *  Payload is a non-owning view into runtime memory, live for the whole
 *  handler turn: across an @c async_yield, and across an internal park the
 *  runtime takes when TX has no room. It dies once the turn ends — the
 *  handler returning @c async_wait or @c async_done, or the stream being
 *  cancelled — and the runtime may reuse the memory from there on.
 */
duct_nonnull(1) duct_frame_t *duct_stream_frame(duct_stream_ctx_t *ctx);

/** @brief Get the stream this context is running for. */
duct_nonnull(1) duct_stream_id_t duct_stream_id(duct_stream_ctx_t *ctx);

/** @brief Get the session this stream's handler is running on -- e.g. to
 *  pass to @ref duct_session_nth_live_leg from inside the handler itself. */
duct_nonnull(1) duct_session_t *duct_stream_session(duct_stream_ctx_t *ctx);

/** @brief Get the state the author keeps for this stream.
 *
 *  Persists between this stream's handler invocations.
 *
 *  @return The last value @c duct_stream_ctx_state_set stored, falling back
 *  to the one @c create_stream_state populated when the stream was claimed.
 */
duct_nonnull(1) void *duct_stream_ctx_state(duct_stream_ctx_t *ctx);

/** @brief Set the state the author keeps for this stream, across frames.
 *
 *  Scoped to this handler context: @ref duct_stream_ctx_state reads it back,
 *  while @c duct_stream_state, @c on_stream_close and @c destroy_stream_state
 *  keep seeing the pointer @c create_stream_state produced. Replacing an
 *  allocation here leaves the original one for the teardown callbacks to
 *  free.
 */
duct_nonnull(1) void
duct_stream_ctx_state_set(duct_stream_ctx_t *ctx, void *state);

/** @brief Set the response to send.
 *
 *  Stores the response and returns to the handler, which then picks the turn:
 *  @c async_yield sends it and runs again immediately, @c async_wait sends it
 *  and waits for the next frame, @c async_done sends it and closes the
 *  stream. A stackful handler uses this call right before returning to end
 *  the stream, and @ref duct_stream_emit_and_yield /
 *  @ref duct_stream_emit_and_wait for the turns that suspend it.
 */
duct_nonnull(1, 2) void
duct_stream_emit_response(duct_stream_ctx_t *ctx, const duct_response_t *resp);

/** @brief Set the response to send, then suspend and run again immediately.
 *
 *  Stackful handlers only — the turn @c async_yield gives a stackless handler.
 */
duct_nonnull(1, 2) void
duct_stream_emit_and_yield(duct_stream_ctx_t *ctx, const duct_response_t *resp);

/** @brief Set the response to send, then suspend until the next frame arrives.
 *
 *  Stackful handlers only — the turn @c async_wait gives a stackless handler.
 */
duct_nonnull(1, 2) void
duct_stream_emit_and_wait(duct_stream_ctx_t *ctx, const duct_response_t *resp);

#ifdef __cplusplus
}
#endif

#endif /* DUCT_STREAM_H */
