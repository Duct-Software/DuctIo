/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file stream_slot_test.c
 * @brief Step 2a litmus: per-stream claim/close/state machinery.
 *
 * Exercises duct_session_stream_claim / _close / duct_stream_state directly on
 * a live multiplexed session opened through the production duct_session_open
 * path (so the streams table allocation gate on fl_proto_multiplexed is real).
 * Verifies: create_stream_state + on_stream_open fire once per claim (idempotent
 * re-claim), stream 0 never claims, duct_stream_state lookup, on_stream_close +
 * destroy_stream_state fire once per close (idempotent re-close), and terminal
 * session close tears down the remaining live streams. A non-multiplexed proto
 * keeps streams NULL (zero overhead) and claim returns nullptr.
 *
 * Each claim also checks the duct_stream_admit_t it reports, which is the
 * white-box half of the refusal contract: the engine-level half, a full table
 * answered with an RST, lives in mux_wire_test.c.
 */

#include "duct_session.h"
#include "duct_conn.h"
#include "duct_protocol.h"
#include "duct_core.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

static unsigned s_create_calls;
static unsigned s_open_calls;
static unsigned s_close_calls;
static unsigned s_destroy_calls;

static duct_result_t s_on_frame([[maybe_unused]] duct_session_t *s,
                                [[maybe_unused]] duct_conn_id_t cid,
                                [[maybe_unused]] const duct_frame_t *fr,
                                [[maybe_unused]] duct_response_t *out,
                                [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

static duct_result_t s_on_session_open([[maybe_unused]] duct_session_t *s,
                                       [[maybe_unused]] duct_handle_t tok,
                                       [[maybe_unused]] void *user_ctx,
                                       [[maybe_unused]] duct_response_t *out,
                                       [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

static void s_on_session_close([[maybe_unused]] duct_session_t *s,
                               [[maybe_unused]] duct_close_reason_t reason,
                               [[maybe_unused]] void *proto_state)
{
}

static duct_result_t s_create_stream_state([[maybe_unused]] duct_session_t *s,
                                           duct_stream_id_t stream_id,
                                           [[maybe_unused]] void *ctx,
                                           void **out)
{
    ++s_create_calls;
    auto st = duct_new(int);
    duct_do_if(!st, return rc_no_memory);
    *st = (int)stream_id;
    *out = st;
    return rc_ok;
}

static void s_destroy_stream_state([[maybe_unused]] duct_session_t *s,
                                   [[maybe_unused]] duct_stream_id_t stream_id,
                                   [[maybe_unused]] void *ctx,
                                   void *state)
{
    ++s_destroy_calls;
    duct_del(state);
}

static duct_result_t s_on_stream_open([[maybe_unused]] duct_session_t *s,
                                      duct_stream_id_t stream_id,
                                      [[maybe_unused]] duct_response_t *out,
                                      [[maybe_unused]] void *stream_state)
{
    ++s_open_calls;
    assert(stream_id != 0u);
    return rc_ok;
}

static void s_on_stream_close([[maybe_unused]] duct_session_t *s,
                              duct_stream_id_t stream_id,
                              [[maybe_unused]] duct_close_reason_t reason,
                              [[maybe_unused]] void *stream_state)
{
    ++s_close_calls;
    assert(stream_id != 0u);
}

static duct_proto_t *s_make_proto(bool multiplexed)
{
    return duct_proto_create(&(duct_proto_cfg_t){
        .name = multiplexed ? "mux" : "plain",
        .on_frame = s_on_frame,
        .on_session_open = s_on_session_open,
        .on_session_close = s_on_session_close,
        .create_stream_state = multiplexed ? s_create_stream_state : nullptr,
        .destroy_stream_state = multiplexed ? s_destroy_stream_state : nullptr,
        .on_stream_open = multiplexed ? s_on_stream_open : nullptr,
        .on_stream_close = multiplexed ? s_on_stream_close : nullptr,
        .flags = multiplexed ? fl_proto_multiplexed : fl_proto_none,
        .max_response = 4096u,
    });
}

int main(void)
{
    /* ── Multiplexed session ─────────────────────────────────────── */
    auto proto = s_make_proto(true);
    assert(proto);

    auto conn = duct_conn_acquire();
    assert(conn);
    duct_conn_handle_t handle = duct_conn_handle_get(conn);

    duct_response_t out = {};
    auto s = duct_session_open(proto, duct_conn_id_primary,
                               handle, nullptr, 0u, &out);
    assert(s);
    assert(s->streams); /* fl_proto_multiplexed → table allocated */

    duct_stream_admit_t why = stream_admit_unusable;

    /* claim 1 → create + open fire once */
    duct_stream_t *st1 = duct_session_stream_claim(s, 1u, &out, &why);
    assert(st1 && why == stream_admit_ok);
    assert(s_create_calls == 1u && s_open_calls == 1u);
    assert(duct_stream_state(s, 1u) == st1->proto_state);

    /* re-claim 1 → idempotent, no second create/open */
    auto reclaim = duct_session_stream_claim(s, 1u, &out, &why);
    assert(reclaim == st1 && why == stream_admit_ok);
    assert(s_create_calls == 1u && s_open_calls == 1u);

    /* stream 0 never claims */
    auto claim0 = duct_session_stream_claim(s, 0u, &out, &why);
    assert(!claim0 && why == stream_admit_unusable);
    assert(s_create_calls == 1u && s_open_calls == 1u);

    /* claim 2 → second create + open */
    duct_stream_t *st2 = duct_session_stream_claim(s, 2u, &out, &why);
    assert(st2 && st2 != st1);
    assert(s_create_calls == 2u && s_open_calls == 2u);
    assert(s->stream_count == 2u);

    /* close 1 → close + destroy fire once */
    duct_session_stream_close(s, 1u, close_normal);
    assert(s_close_calls == 1u && s_destroy_calls == 1u);
    assert(!duct_stream_state(s, 1u));
    assert(s->stream_count == 1u);

    /* re-close 1 → idempotent */
    duct_session_stream_close(s, 1u, close_normal);
    assert(s_close_calls == 1u && s_destroy_calls == 1u);

    /* close 0 → no-op */
    duct_session_stream_close(s, 0u, close_normal);
    assert(s_close_calls == 1u && s_destroy_calls == 1u);

    /* claim 3 reuses a free slot (close 1 returned one); stream 2 still
     * resolves — guards the bucket-chain unlink + free-list reuse path. */
    duct_stream_t *st3 = duct_session_stream_claim(s, 3u, &out, &why);
    assert(st3 && st3 != st2);
    assert(s_create_calls == 3u && s_open_calls == 3u);
    assert(duct_stream_state(s, 2u) == st2->proto_state);
    assert(duct_stream_state(s, 3u) == st3->proto_state);
    assert(s->stream_count == 2u);

    /* close 3 → stream 2 still resolves (chain integrity after 3's unlink). */
    duct_session_stream_close(s, 3u, close_normal);
    assert(s_close_calls == 2u && s_destroy_calls == 2u);
    assert(duct_stream_state(s, 2u) == st2->proto_state);
    assert(s->stream_count == 1u);

    /* terminal session close tears down the remaining live stream (2) */
    auto s_detached = duct_session_detach_leg(s, duct_conn_id_primary, close_normal);
    assert(s_detached);
    assert(s_close_calls == 3u && s_destroy_calls == 3u);

    duct_conn_release(conn);
    duct_proto_destroy(proto);

    /* ── Non-multiplexed session: zero overhead, no stream table ─── */
    auto plain = s_make_proto(false);
    assert(plain);
    auto conn2 = duct_conn_acquire();
    assert(conn2);
    duct_conn_handle_t h2 = duct_conn_handle_get(conn2);
    auto s2 = duct_session_open(plain, duct_conn_id_primary,
                                h2, nullptr, 0u, &out);
    assert(s2);
    assert(!s2->streams); /* no table → claim returns nullptr */
    auto claim_notable = duct_session_stream_claim(s2, 5u, &out, &why);
    assert(!claim_notable && why == stream_admit_unusable);
    assert(!duct_stream_state(s2, 5u));
    auto detached = duct_session_detach_leg(s2, duct_conn_id_primary, close_normal);
    assert(detached);
    duct_conn_release(conn2);
    duct_proto_destroy(plain);

    printf("stream_slot_test OK (create=%u open=%u close=%u destroy=%u)\n",
           s_create_calls, s_open_calls, s_close_calls, s_destroy_calls);
    return 0;
}
