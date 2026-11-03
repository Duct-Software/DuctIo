/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_stream.c
 *  @brief Out-of-line bodies for the public stream-handler accessors.
 */

#include "duct_stream.h"
#include "duct_stream_ctx.h"
#include "duct_coro.h"

duct_frame_t *duct_stream_frame(duct_stream_ctx_t *ctx)
{
    return &ctx->frame;
}

duct_stream_id_t duct_stream_id(duct_stream_ctx_t *ctx)
{
    return ctx->stream_id;
}

duct_session_t *duct_stream_session(duct_stream_ctx_t *ctx)
{
    return ctx->s;
}

void *duct_stream_ctx_state(duct_stream_ctx_t *ctx)
{
    return ctx->stream_state;
}

void duct_stream_ctx_state_set(duct_stream_ctx_t *ctx, void *state)
{
    ctx->stream_state = state;
}

void duct_stream_emit_response(duct_stream_ctx_t *ctx, const duct_response_t *resp)
{
    ctx->out = *resp;
}

void duct_stream_emit_and_yield(duct_stream_ctx_t *ctx, const duct_response_t *resp)
{
    ctx->out = *resp;
    duct_coro_yield();
}

void duct_stream_emit_and_wait(duct_stream_ctx_t *ctx, const duct_response_t *resp)
{
    ctx->out = *resp;
    duct_coro_wait();
}
