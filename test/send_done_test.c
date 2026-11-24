/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file send_done_test.c
 * @brief RW-SD litmus: on_send_done (drain-completion frontier) tests.
 *
 *   T1  send_done_basic             — echo + fl_send_done, frontier=1, rc_ok
 *   T2  send_done_handler           — handler coro path fires on_send_done
 *   T3  send_done_oversized         — oversized payload → rc_invalid_arg, frontier=0
 *   T4  send_done_no_cb             — fl_send_done + NULL on_send_done: no crash
 *   T5  send_done_frontier_seq      — multiple sends advance frontier monotonically
 *   T6  send_done_control_only      — empty payload + fl_send_done → frontier=1, rc_ok
 *   T7  send_done_invalid_target    — conn_id out of range → rc_invalid_arg, frontier=0
 *   T8  send_done_tx_closed         — unattached target conn → rc_closed, frontier=0
 *   T9  send_done_switch_from_cb    — proto_switch inside on_send_done
 *   T10 send_done_drain_backpressure — frontier held back while SO_SNDBUF full, completes on drain
 *   T11 send_done_close_force       — conn close settles unfinished responses once with rc_closed
 *   T12 send_done_stream_cancel_skip — cancelled parked retry folds into next frontier jump
 */

#include "duct.h"
#include "duct_wire.h"
#include "duct_stream_ctx.h"
#include "test_helpers.h"

#include <stdatomic.h>
#include <stdlib.h>

static uint16_t th_port = 0;

/* ── Atomic counters ─────────────────────────────────────────────── */

static atomic_int       g_open_count      = 0;
static atomic_int       g_frame_count     = 0;
static atomic_int       g_send_done_count = 0;
static atomic_int       g_closed_done_cnt = 0;
static atomic_int       g_close_count     = 0;
static atomic_int       g_enter_count     = 0;
static atomic_int       g_error_count     = 0;
static atomic_int       g_last_error      = 0;

static _Atomic uint64_t g_last_frontier   = 0u;
static atomic_bool      g_frontier_bad    = false;
static atomic_int       g_last_result     = 0;

static duct_wire_t     *t9_wire           = nullptr;

static void s_counters_reset(void)
{
    duct_atomic_store(&g_open_count, 0, seq_cst);
    duct_atomic_store(&g_frame_count, 0, seq_cst);
    duct_atomic_store(&g_send_done_count, 0, seq_cst);
    duct_atomic_store(&g_closed_done_cnt, 0, seq_cst);
    duct_atomic_store(&g_close_count, 0, seq_cst);
    duct_atomic_store(&g_enter_count, 0, seq_cst);
    duct_atomic_store(&g_error_count, 0, seq_cst);
    duct_atomic_store(&g_last_error, 0, seq_cst);
    duct_atomic_store(&g_last_frontier, 0u, seq_cst);
    duct_atomic_store(&g_frontier_bad, false, seq_cst);
    duct_atomic_store(&g_last_result, 0, seq_cst);
}

static duct_result_t
s_on_error([[maybe_unused]] duct_session_t *s,
          duct_result_t code,
          [[maybe_unused]] duct_response_t *out,
          [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_error_count, 1, relaxed);
    duct_atomic_store(&g_last_error, (int)code, relaxed);
    return rc_ok;
}

/* ── Common callbacks ────────────────────────────────────────────── */

static duct_result_t
s_on_session_open([[maybe_unused]] duct_session_t *s,
                  [[maybe_unused]] duct_handle_t tok,
                  [[maybe_unused]] void *user_ctx,
                  [[maybe_unused]] duct_response_t *out,
                  [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_open_count, 1, relaxed);
    return rc_ok;
}

static void
s_on_session_close([[maybe_unused]] duct_session_t *s,
                   [[maybe_unused]] duct_close_reason_t reason,
                   [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_close_count, 1, relaxed);
}

static duct_result_t
s_on_send_done([[maybe_unused]] duct_session_t *s,
              const duct_send_done_info_t *info,
              [[maybe_unused]] duct_response_t *out,
              [[maybe_unused]] void *proto_state)
{
    uint64_t prev = duct_atomic_load(&g_last_frontier, relaxed);
    if (info->frontier < prev)
        duct_atomic_store(&g_frontier_bad, true, release);
    duct_atomic_store(&g_last_frontier, info->frontier, release);
    duct_atomic_store(&g_last_result, (int)info->result, relaxed);
    if (info->result == rc_closed)
        duct_atomic_fetch(add, &g_closed_done_cnt, 1, relaxed);
    duct_atomic_fetch(add, &g_send_done_count, 1, release);
    return rc_ok;
}

static bool s_wait_frontier(uint64_t target, unsigned timeout_ms)
{
    for (unsigned i = 0u; i < timeout_ms; ++i) {
        if (duct_atomic_load(&g_last_frontier, acquire) >= target)
            return true;
        th_sleep_ms(1u);
    }
    return duct_atomic_load(&g_last_frontier, acquire) >= target;
}

/* ── Test mux wire: [4 sid][1 flags][4 len][payload] ─────────────── */
/*  LP wire carries no stream_id, so handler dispatch (stream != 0) is
 *  unreachable over LP. Mux wire encodes stream_id in the header, exercising
 *  s_dispatch_frame → handler claim → s_hctx_async_done →
 *  s_worker_process_response → s_fire_send_done (T2 handler path). */

static constexpr size_t mux_hdr_size = 9u;
static constexpr uint8_t mux_fl_fin = 1u;
static constexpr uint8_t mux_fl_rst = 2u;

typedef struct {
    uint8_t  hdr_buf[9];
    uint32_t partial_len;
    bool     hdr_done;
} mux_parser_t;

typedef struct { duct_wire_t base; } mux_wire_t;

static duct_result_t
mux_parse([[maybe_unused]] const duct_wire_t *self,
          duct_view_u8 input, duct_frame_t *out, duct_wire_parser_t *parser,
          size_t *consumed, size_t *needed)
{
    auto st = (mux_parser_t *)parser;
    *consumed = 0u;
    *needed = 0u;
    uint8_t *p = (uint8_t *)input.data;
    uint8_t *end = p + input.size;

    if (!st->hdr_done) {
        if (st->partial_len > 0u) {
            p += st->partial_len;
            uint32_t want = (uint32_t)mux_hdr_size - st->partial_len;
            uint32_t copy = (uint32_t)(end - p) < want ? (uint32_t)(end - p) : want;
            memcpy(st->hdr_buf + st->partial_len, p, copy);
            st->partial_len += copy;
            p += copy;
            if (st->partial_len < (uint32_t)mux_hdr_size) {
                *needed = mux_hdr_size - st->partial_len;
                return rc_again;
            }
            st->hdr_done = true;
        } else if ((size_t)(end - p) >= mux_hdr_size) {
            memcpy(st->hdr_buf, p, mux_hdr_size);
            p += mux_hdr_size;
            st->hdr_done = true;
        } else {
            memcpy(st->hdr_buf, p, (size_t)(end - p));
            st->partial_len = (uint32_t)(end - p);
            *needed = mux_hdr_size - st->partial_len;
            return rc_again;
        }
    } else {
        p += mux_hdr_size;
    }

    uint32_t sid = ((uint32_t)st->hdr_buf[0] << 24u) | ((uint32_t)st->hdr_buf[1] << 16u)
                 | ((uint32_t)st->hdr_buf[2] <<  8u) |  (uint32_t)st->hdr_buf[3];
    uint8_t  flg = st->hdr_buf[4];
    uint32_t len = ((uint32_t)st->hdr_buf[5] << 24u) | ((uint32_t)st->hdr_buf[6] << 16u)
                 | ((uint32_t)st->hdr_buf[7] <<  8u) |  (uint32_t)st->hdr_buf[8];
    st->hdr_done = false;
    st->partial_len = 0u;

    if (len > (1u << 20u)) {
        *consumed = (size_t)(p - (uint8_t *)input.data);
        return rc_invalid_arg;
    }
    if ((size_t)(end - p) < len) {
        st->hdr_done = true;
        *consumed = (size_t)(p - (uint8_t *)input.data);
        *needed = len;
        return rc_again;
    }
    duct_frame_flags_t ff = fl_frame_none;
    if (flg & mux_fl_fin) ff |= fl_frame_fin;
    if (flg & mux_fl_rst) ff |= fl_frame_rst;
    *out = (duct_frame_t){ .stream_id = sid, .flags = ff,
                           .payload = { .data = p, .size = len } };
    *consumed = (size_t)((p + len) - (uint8_t *)input.data);
    return rc_ok;
}

static duct_result_t
mux_pack([[maybe_unused]] const duct_wire_t *self, [[maybe_unused]] duct_session_t *s,
         const duct_frame_t *frame, duct_wire_tx_t *stage,
         [[maybe_unused]] duct_wire_codec_t *codec)
{
    uint32_t sid = (uint32_t)frame->stream_id;
    uint32_t len = (uint32_t)frame->payload.size;
    uint8_t  flg = 0u;
    if (frame->flags & fl_frame_fin) flg |= mux_fl_fin;
    if (frame->flags & fl_frame_rst) flg |= mux_fl_rst;
    uint8_t hdr[mux_hdr_size] = {
        (uint8_t)(sid >> 24u), (uint8_t)(sid >> 16u),
        (uint8_t)(sid >>  8u), (uint8_t)(sid),
        flg,
        (uint8_t)(len >> 24u), (uint8_t)(len >> 16u),
        (uint8_t)(len >>  8u), (uint8_t)(len),
    };
    return duct_wire_tx_stage(stage,
        duct_view(duct_view_u8, hdr, mux_hdr_size), frame->payload);
}

static_assert(sizeof(mux_parser_t) <= duct_wire_parser_slot,
              "the test wire's parser exceeds the conn block's parser slot");

static void mux_init_parser([[maybe_unused]] const duct_wire_t *self,
                            [[maybe_unused]] duct_wire_parser_t *storage)
{
}

static void mux_destroy(duct_wire_t *self) { duct_del(self); }

static duct_wire_t *mux_wire_create(void)
{
    auto w = duct_new(mux_wire_t);
    duct_do_if(!w, return nullptr);
    w->base = (duct_wire_t){
        .name          = "send-done-mux",
        .flags         = (duct_wire_flags_t)(fl_wire_frame_flags | fl_wire_stream_ids),
        .header_size   = mux_hdr_size,
        .destroy       = mux_destroy,
        .on_parse      = mux_parse,
        .on_pack       = mux_pack,
        .parser_max    = sizeof(mux_parser_t),
        .init_parser   = mux_init_parser,
    };
    return &w->base;
}

static int s_send_mux(duct_sock_t fd, uint32_t sid, uint8_t flg, const void *data, size_t len)
{
    uint8_t hdr[mux_hdr_size] = {
        (uint8_t)(sid >> 24u), (uint8_t)(sid >> 16u),
        (uint8_t)(sid >>  8u), (uint8_t)(sid),
        flg,
        (uint8_t)(len >> 24u), (uint8_t)(len >> 16u),
        (uint8_t)(len >>  8u), (uint8_t)(len),
    };
    struct iovec iov[2] = {
        { .iov_base = hdr, .iov_len = mux_hdr_size },
        { .iov_base = (void *)data, .iov_len = len },
    };
    return writev(fd, iov, 2) == (ssize_t)(mux_hdr_size + len) ? 0 : -1;
}

static ssize_t s_recv_mux(duct_sock_t fd, uint32_t *out_sid, uint8_t *out_flg,
                          char *buf, size_t bufsize)
{
    uint8_t hdr[mux_hdr_size] = {};
    size_t got = 0u;
    while (got < mux_hdr_size) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, 3000) <= 0)
            return -1;
        ssize_t n = read(fd, hdr + got, mux_hdr_size - got);
        if (n <= 0)
            return -1;
        got += (size_t)n;
    }
    uint32_t sid = ((uint32_t)hdr[0] << 24u) | ((uint32_t)hdr[1] << 16u)
                 | ((uint32_t)hdr[2] <<  8u) |  (uint32_t)hdr[3];
    uint8_t  flg = hdr[4];
    uint32_t len = ((uint32_t)hdr[5] << 24u) | ((uint32_t)hdr[6] << 16u)
                 | ((uint32_t)hdr[7] <<  8u) |  (uint32_t)hdr[8];
    if (len > bufsize)
        return -1;
    *out_sid = sid;
    *out_flg = flg;
    got = 0u;
    while (got < len) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, 3000) <= 0)
            return -1;
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0)
            return -1;
        got += (size_t)n;
    }
    return (ssize_t)len;
}

/* ── T1: send_done_basic ─────────────────────────────────────────── */

static duct_result_t
t1_frame([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_conn_id_t conn_id,
         [[maybe_unused]] const duct_frame_t *frame,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_frame_count, 1, relaxed);
    *out = (duct_response_t){
        .payload = frame->payload,
        .flags = duct_or(fl_send_copy, fl_send_done),
        .conn_id = duct_conn_id_same,
        .stream_id = duct_stream_id_same,
    };
    return rc_ok;
}

static const char *test_send_done_basic(void)
{
    s_counters_reset();
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    if (th_send(fd, "hello", 5u) != 0) { close(fd); return "send failed"; }
    if (th_recv_eq(fd, "hello", 5u) != 0) { close(fd); return "no echo"; }

    if (!th_wait_int(&g_send_done_count, 1, 2000u)) { close(fd); return "send_done not fired"; }
    if (duct_atomic_load(&g_last_frontier, seq_cst) != 1u) { close(fd); return "wrong frontier"; }
    if (duct_atomic_load(&g_last_result, seq_cst) != (int)rc_ok) { close(fd); return "wrong result"; }

    close(fd);
    return nullptr;
}

/* ── T2: send_done_handler — handler coro path funnels through the same
 *  s_worker_process_response site as on_frame. Uses a multiplexed wire so
 *  frames on stream != 0 reach the stackless handler; the handler emits the
 *  echo + fl_send_done response and returns async_done, which drives
 *  s_hctx_async_done → s_worker_process_response → s_fire_send_done.
 *  Requires duct_coro_sl_slots > 0 (worker coro runtime open). */

static duct_result_t
t2_on_frame([[maybe_unused]] duct_session_t *s,
            [[maybe_unused]] duct_conn_id_t conn_id,
            [[maybe_unused]] const duct_frame_t *frame,
            [[maybe_unused]] duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    /* Stream 0 fallback — not reached by this litmus (frames go to stream 5). */
    return rc_drop;
}

static unsigned t2_step = 0u;

static duct_async_rc_t t2_handler(void *state)
{
    auto hctx = (duct_stream_ctx_t *)state;
    hctx->out = (duct_response_t){
        .payload = hctx->frame.payload,
        .flags = duct_or(fl_send_copy, fl_send_done),
        .conn_id = duct_conn_id_same,
        .stream_id = duct_stream_id_same,
    };
    if (t2_step == 0u) {
        t2_step = 1u;
        return async_yield;
    }
    t2_step = 0u;
    return async_done;
}

static const char *test_send_done_handler(void)
{
    s_counters_reset();
    t2_step = 0u;
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    /* Wait for session open. */
    if (!th_wait_int(&g_open_count, 1, 2000u)) { close(fd); return "session not opened"; }

    /* Frame on stream 5 → handler claim + step → echo on stream 5. */
    if (s_send_mux(fd, 5u, 0u, "hdl", 3u) != 0) { close(fd); return "send failed"; }
    uint32_t sid = 0u; uint8_t flg = 0u; char buf[64] = {};
    ssize_t got = s_recv_mux(fd, &sid, &flg, buf, sizeof(buf));
    if (got < 0) { close(fd); return "no echo"; }
    if (sid != 5u || (size_t)got != 3u || memcmp(buf, "hdl", 3u) != 0) { close(fd); return "echo: wrong sid/payload"; }

    if (!th_wait_int(&g_send_done_count, 1, 2000u)) { close(fd); return "send_done not fired"; }
    if (duct_atomic_load(&g_last_frontier, seq_cst) != 1u) { close(fd); return "wrong frontier"; }
    if (duct_atomic_load(&g_last_result, seq_cst) != (int)rc_ok) { close(fd); return "wrong result"; }

    close(fd);
    return nullptr;
}

/* ── T3: send_done_oversized ─────────────────────────────────────── */

static duct_result_t
t3_frame([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_conn_id_t conn_id,
         [[maybe_unused]] const duct_frame_t *frame,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_frame_count, 1, relaxed);
    /* Payload larger than max_response (which defaults to wire max_frame). */
    static uint8_t big[8192] = {};
    *out = (duct_response_t){
        .payload = { .data = big, .size = sizeof(big) },
        .flags = duct_or(fl_send_copy, fl_send_done),
        .conn_id = duct_conn_id_same,
        .stream_id = duct_stream_id_same,
    };
    return rc_ok;
}

static const char *test_send_done_oversized(void)
{
    s_counters_reset();
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    if (th_send(fd, "big", 3u) != 0) { close(fd); return "send failed"; }
    /* No echo expected — oversized is rejected before stage: frontier stays 0. */
    if (!th_wait_int(&g_send_done_count, 1, 2000u)) { close(fd); return "send_done not fired"; }
    if (duct_atomic_load(&g_last_frontier, seq_cst) != 0u) { close(fd); return "frontier advanced on refusal"; }
    if (duct_atomic_load(&g_last_result, seq_cst) != (int)rc_invalid_arg) { close(fd); return "wrong result"; }

    close(fd);
    return nullptr;
}

/* ── T4: send_done_no_cb ─────────────────────────────────────────── */

static duct_result_t
t4_frame([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    *out = (duct_response_t){
        .payload = frame->payload,
        .flags = duct_or(fl_send_copy, fl_send_done),
        .conn_id = duct_conn_id_same,
        .stream_id = duct_stream_id_same,
    };
    return rc_ok;
}

static const char *test_send_done_no_cb(void)
{
    s_counters_reset();
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    if (th_send(fd, "nocb", 4u) != 0) { close(fd); return "send failed"; }
    if (th_recv_eq(fd, "nocb", 4u) != 0) { close(fd); return "no echo"; }
    /* send_done_count stays 0 — no callback registered. No crash. */
    if (duct_atomic_load(&g_send_done_count, seq_cst) != 0) { close(fd); return "unexpected fire"; }

    close(fd);
    return nullptr;
}

/* ── T5: send_done_frontier_seq ──────────────────────────────────── */

static duct_result_t
t5_frame([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    *out = (duct_response_t){
        .payload = frame->payload,
        .flags = duct_or(fl_send_copy, fl_send_done),
        .conn_id = duct_conn_id_same,
        .stream_id = duct_stream_id_same,
    };
    return rc_ok;
}

static const char *test_send_done_frontier_seq(void)
{
    s_counters_reset();
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    for (unsigned i = 0u; i < 3u; ++i) {
        if (th_send(fd, "seq", 3u) != 0) { close(fd); return "send failed"; }
        if (th_recv_eq(fd, "seq", 3u) != 0) { close(fd); return "no echo"; }
    }

    if (!s_wait_frontier(3u, 2000u)) { close(fd); return "frontier did not reach 3"; }
    if (duct_atomic_load(&g_frontier_bad, seq_cst)) { close(fd); return "frontier regressed"; }
    if (duct_atomic_load(&g_last_result, seq_cst) != (int)rc_ok) { close(fd); return "wrong result"; }

    close(fd);
    return nullptr;
}

/* ── T6: send_done_control_only ──────────────────────────────────── */

static duct_result_t
t6_frame([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_conn_id_t conn_id,
         [[maybe_unused]] const duct_frame_t *frame,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_frame_count, 1, relaxed);
    /* No payload — control-only response with fl_send_done. */
    *out = (duct_response_t){
        .flags = fl_send_done,
        .conn_id = duct_conn_id_same,
        .stream_id = duct_stream_id_same,
    };
    return rc_ok;
}

static const char *test_send_done_control_only(void)
{
    s_counters_reset();
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    if (th_send(fd, "ctrl", 4u) != 0) { close(fd); return "send failed"; }
    /* No echo expected — empty payload. */
    if (!th_wait_int(&g_send_done_count, 1, 2000u)) { close(fd); return "send_done not fired"; }
    if (duct_atomic_load(&g_last_frontier, seq_cst) != 1u) { close(fd); return "wrong frontier"; }
    if (duct_atomic_load(&g_last_result, seq_cst) != (int)rc_ok) { close(fd); return "wrong result"; }

    close(fd);
    return nullptr;
}

/* ── T7: send_done_invalid_target ────────────────────────────────── */

static duct_result_t
t7_frame([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    *out = (duct_response_t){
        .payload = frame->payload,
        .flags = duct_or(fl_send_copy, fl_send_done),
        .conn_id = duct_session_max_legs, /* out of range */
        .stream_id = duct_stream_id_same,
    };
    return rc_ok;
}

static const char *test_send_done_invalid_target(void)
{
    s_counters_reset();
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    if (th_send(fd, "inv", 3u) != 0) { close(fd); return "send failed"; }
    /* No echo — invalid target: frontier stays 0. */
    if (!th_wait_int(&g_send_done_count, 1, 2000u)) { close(fd); return "send_done not fired"; }
    if (duct_atomic_load(&g_last_frontier, seq_cst) != 0u) { close(fd); return "frontier advanced on invalid target"; }
    if (duct_atomic_load(&g_last_result, seq_cst) != (int)rc_invalid_arg) { close(fd); return "wrong result"; }

    close(fd);
    return nullptr;
}

/* ── T8: send_done_tx_closed ─────────────────────────────────────── */

static duct_result_t
t8_frame([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    *out = (duct_response_t){
        .payload = frame->payload,
        .flags = duct_or(fl_send_copy, fl_send_done),
        .conn_id = 1u, /* conn 1 not attached → conn == NULL → rc_closed */
        .stream_id = duct_stream_id_same,
    };
    return rc_ok;
}

static const char *test_send_done_tx_closed(void)
{
    s_counters_reset();
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    if (th_send(fd, "cls", 3u) != 0) { close(fd); return "send failed"; }
    /* No echo — target conn not attached: frontier stays 0. */
    if (!th_wait_int(&g_send_done_count, 1, 2000u)) { close(fd); return "send_done not fired"; }
    if (duct_atomic_load(&g_last_frontier, seq_cst) != 0u) { close(fd); return "frontier advanced on closed target"; }
    if (duct_atomic_load(&g_last_result, seq_cst) != (int)rc_closed) { close(fd); return "wrong result"; }

    close(fd);
    return nullptr;
}

/* ── T9: send_done_switch_from_cb ────────────────────────────────── */

static duct_proto_t *t9_next_proto = nullptr;

static duct_result_t
t9_frame([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_frame_count, 1, relaxed);
    *out = (duct_response_t){
        .payload = frame->payload,
        .flags = duct_or(fl_send_copy, fl_send_done),
        .conn_id = duct_conn_id_same,
        .stream_id = duct_stream_id_same,
    };
    return rc_ok;
}

static duct_result_t
t9_on_send_done(duct_session_t *s,
                const duct_send_done_info_t *info,
                [[maybe_unused]] duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_last_frontier, info->frontier, release);
    duct_atomic_fetch(add, &g_send_done_count, 1, release);
    return t9_next_proto ? duct_proto_switch(s, t9_next_proto, nullptr) : rc_ok;
}

static duct_result_t
t9_next_frame([[maybe_unused]] duct_session_t *s,
              [[maybe_unused]] duct_conn_id_t conn_id,
              const duct_frame_t *frame,
              duct_response_t *out,
              [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_enter_count, 1, relaxed);
    *out = (duct_response_t){
        .payload = frame->payload,
        .flags = fl_send_copy,
        .conn_id = duct_conn_id_same,
        .stream_id = duct_stream_id_same,
    };
    return rc_ok;
}

static duct_result_t
t9_next_open([[maybe_unused]] duct_session_t *s,
             [[maybe_unused]] duct_handle_t tok,
             [[maybe_unused]] void *user_ctx,
             [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

static const char *test_send_done_switch_from_cb(void)
{
    s_counters_reset();
    duct_atomic_store(&g_enter_count, 0, seq_cst);

    /* Create the "next" proto for the switch target, sharing the same wire. */
    t9_next_proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "t8_next",
        .wire = t9_wire,
        .on_frame = t9_next_frame,
        .on_session_open = t9_next_open,
    });
    if (!t9_next_proto) return "next proto create failed";

    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) { return "connect failed"; }

    /* First frame: echo + fl_send_done → on_send_done switches proto. */
    if (th_send(fd, "sw1", 3u) != 0) { close(fd); return "send failed"; }
    if (th_recv_eq(fd, "sw1", 3u) != 0) { close(fd); return "no echo"; }

    if (!th_wait_int(&g_send_done_count, 1, 2000u)) { close(fd); return "send_done not fired"; }
    if (duct_atomic_load(&g_last_frontier, seq_cst) != 1u) { close(fd); return "wrong frontier"; }

    /* Second frame: dispatched on next proto (g_enter_count increments). */
    struct timespec ts = { .tv_nsec = 100L * 1000L * 1000L };
    nanosleep(&ts, nullptr);
    if (th_send(fd, "sw2", 3u) != 0) { close(fd); return "send2 failed"; }
    if (th_recv_eq(fd, "sw2", 3u) != 0) { close(fd); return "no echo2"; }

    if (!th_wait_int(&g_enter_count, 1, 2000u)) { close(fd); return "switch not applied"; }

    close(fd);
    return nullptr;
}

/* ── T10 / T11: drain backpressure & close-force ────────────────── */

#ifdef _WIN32
static constexpr unsigned t10_batch_n = 512u;
#else
static constexpr unsigned t10_batch_n = 64u;
#endif
static constexpr size_t   t10_chunk_sz = 16384u;
static uint8_t            t10_big[t10_chunk_sz];
static uint8_t            t12_big[24576u];

static duct_sock_t s_connect_rcvbuf(uint16_t port, int rcvbuf)
{
    duct_sock_t fd = (duct_sock_t)socket(AF_INET, SOCK_STREAM, 0);
    if (fd == duct_sock_bad)
        return duct_sock_bad;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&rcvbuf, sizeof rcvbuf);
    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
    };
    if (connect(fd, (const struct sockaddr *)&sa, (socklen_t)sizeof sa) != 0) {
        close(fd);
        return duct_sock_bad;
    }
    return fd;
}

static bool s_wait_frames_ge(int target, unsigned timeout_ms)
{
    for (unsigned i = 0u; i < timeout_ms; ++i) {
        if (duct_atomic_load(&g_frame_count, acquire) >= target)
            return true;
        th_sleep_ms(1u);
    }
    return duct_atomic_load(&g_frame_count, acquire) >= target;
}

static duct_result_t
t10_frame([[maybe_unused]] duct_session_t *s,
          [[maybe_unused]] duct_conn_id_t conn_id,
          [[maybe_unused]] const duct_frame_t *frame,
          duct_response_t *out,
          [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_frame_count, 1, relaxed);
    *out = (duct_response_t){
        .payload = duct_view(duct_view_u8, t10_big, sizeof t10_big),
        .flags = duct_or(fl_send_static, fl_send_done),
        .conn_id = duct_conn_id_same,
        .stream_id = duct_stream_id_same,
    };
    return rc_ok;
}

static int s_send_lp_burst(duct_sock_t fd, unsigned n)
{
    for (unsigned i = 0u; i < n; ++i) {
        if (th_send(fd, "p", 1u) != 0)
            return -1;
    }
    return 0;
}

static const char *test_send_done_drain_backpressure(void)
{
    s_counters_reset();
    memset(t10_big, 0x5Au, sizeof t10_big);
    duct_sock_t fd = s_connect_rcvbuf(th_port, 4096);
    if (fd == duct_sock_bad) return "connect failed";

    if (s_send_lp_burst(fd, t10_batch_n) != 0) { close(fd); return "burst send failed"; }
    if (!s_wait_frames_ge(2, 2000u)) { close(fd); return "server stalled before dispatch"; }
    th_sleep_ms(40u);

    uint64_t f_pre = duct_atomic_load(&g_last_frontier, acquire);
    if (f_pre >= t10_batch_n) {
        close(fd);
        return "frontier reached end before client drained";
    }

    char *rx = malloc(t10_chunk_sz);
    if (!rx) { close(fd); return "oom"; }
    for (unsigned i = 0u; i < t10_batch_n; ++i) {
        int64_t got = th_recv(fd, rx, t10_chunk_sz);
        if (got != (int64_t)t10_chunk_sz) {
            free(rx);
            close(fd);
            return "recv chunk mismatch";
        }
    }
    free(rx);

    if (!s_wait_frontier(t10_batch_n, 4000u)) { close(fd); return "frontier did not catch up"; }
    if (duct_atomic_load(&g_frontier_bad, seq_cst)) { close(fd); return "frontier regressed"; }
    if (duct_atomic_load(&g_last_result, seq_cst) != (int)rc_ok) { close(fd); return "wrong result"; }

    close(fd);
    return nullptr;
}

static const char *test_send_done_close_force(void)
{
    s_counters_reset();
    memset(t10_big, 0x3Cu, sizeof t10_big);
    duct_sock_t fd = s_connect_rcvbuf(th_port, 4096);
    if (fd == duct_sock_bad) return "connect failed";

    if (s_send_lp_burst(fd, t10_batch_n) != 0) { close(fd); return "burst send failed"; }
    if (!s_wait_frames_ge(2, 2000u)) { close(fd); return "server stalled before dispatch"; }
    th_sleep_ms(40u);

    uint64_t f_pre = duct_atomic_load(&g_last_frontier, acquire);
    uint64_t posted_pre = (uint64_t)duct_atomic_load(&g_frame_count, acquire);
    if (f_pre >= posted_pre) { close(fd); return "nothing undrained before close"; }

    close(fd);
    if (!th_wait_int(&g_close_count, 1, 2000u)) return "session close not observed";
    th_sleep_ms(20u);

    uint64_t posted = (uint64_t)duct_atomic_load(&g_frame_count, seq_cst);
    if (duct_atomic_load(&g_last_frontier, seq_cst) != posted) return "close did not force frontier to end";
    if (duct_atomic_load(&g_last_result, seq_cst) != (int)rc_closed) return "wrong close-force result";
    if (duct_atomic_load(&g_closed_done_cnt, seq_cst) != 1) return "close-force fired more than once";
    return nullptr;
}

/* ── T12: send_done_stream_cancel_skip ───────────────────────────── */

static atomic_int g_t12_cancels = 0;
static atomic_int g_t12_tail_step = 0;
static atomic_int g_t12_timer = 0;

static duct_result_t
t12_on_timer([[maybe_unused]] duct_session_t *s,
             duct_response_t *out,
             [[maybe_unused]] void *proto_state,
             [[maybe_unused]] uint64_t token)
{
    duct_atomic_store(&g_t12_timer, 1, release);
    out->control.stream_op = stream_op_reset;
    out->control.stream_op_stream_id = 2u;
    out->control.stream_op_conn_id = duct_conn_id_same;
    return rc_ok;
}

static duct_result_t
t12_on_frame([[maybe_unused]] duct_session_t *s,
             [[maybe_unused]] duct_conn_id_t conn_id,
             [[maybe_unused]] const duct_frame_t *frame,
             duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_frame_count, 1, relaxed);
    if (frame->payload.size == 1u && ((const uint8_t *)frame->payload.data)[0] == 'B') {
        *out = (duct_response_t){
            .payload = duct_view(duct_view_u8, t10_big, sizeof t10_big),
            .flags = duct_or(fl_send_static, fl_send_done),
            .conn_id = duct_conn_id_same,
            .stream_id = duct_stream_id_same,
        };
        return rc_ok;
    }
    *out = (duct_response_t){
        .payload = frame->payload,
        .flags = duct_or(fl_send_copy, fl_send_done),
        .conn_id = duct_conn_id_same,
        .stream_id = duct_stream_id_same,
    };
    return rc_ok;
}

static duct_async_rc_t t12_handler(void *state)
{
    auto hctx = (duct_stream_ctx_t *)state;
    if (hctx->frame.stream_id == 2u) {
        if (duct_atomic_exchange(&g_t12_cancels, 1, acq_rel) == 0) {
            hctx->out = (duct_response_t){
                .payload = duct_view(duct_view_u8, t12_big, sizeof t12_big),
                .flags = duct_or(fl_send_static, fl_send_done),
                .conn_id = duct_conn_id_same,
                .stream_id = duct_stream_id_same,
            };
            hctx->out.control.timer.delay_ms = 40u;
            hctx->out.control.timer.arg = 2u;
            return async_yield;
        }
        return async_yield; /* stay alive on cancel path until timer resets stream 2 */
    }
    if (duct_atomic_exchange(&g_t12_tail_step, 1, acq_rel) == 0) {
        hctx->out = (duct_response_t){
            .payload = hctx->frame.payload,
            .flags = duct_or(fl_send_copy, fl_send_done),
            .conn_id = duct_conn_id_same,
            .stream_id = duct_stream_id_same,
        };
        return async_yield;
    }
    return async_done;
}

static const char *test_send_done_stream_cancel_skip(void)
{
    s_counters_reset();
    duct_atomic_store(&g_t12_cancels, 0, release);
    duct_atomic_store(&g_t12_tail_step, 0, release);
    duct_atomic_store(&g_t12_timer, 0, release);
    memset(t10_big, 0x42u, sizeof t10_big);
    memset(t12_big, 0x43u, sizeof t12_big);
    duct_sock_t fd = s_connect_rcvbuf(th_port, 4096);
    if (fd == duct_sock_bad) return "connect failed";
    if (!th_wait_int(&g_open_count, 1, 2000u)) { close(fd); return "session not opened"; }

    /* Fill TX OLB with 3 x 16 KiB on stream 0 (stays below 64 KiB OLB cap so RX stays open). */
    for (unsigned i = 0u; i < 3u; ++i)
        if (s_send_mux(fd, 0u, 0u, "B", 1u) != 0) { close(fd); return "send B failed"; }
    if (!s_wait_frames_ge(3, 2000u)) { close(fd); return "stream 0 did not advance"; }

    /* Now stream 2 emits 24 KiB -> exceeds remaining TX OLB room -> parks in retry_emit, arms timer. */
    if (s_send_mux(fd, 2u, 0u, "can2", 4u) != 0) { close(fd); return "send 2 failed"; }
    if (!th_wait_int(&g_t12_cancels, 1, 2000u)) { close(fd); return "handler 2 did not emit"; }
    if (!th_wait_int(&g_t12_timer, 1, 2000u)) { close(fd); return "cancel timer did not fire"; }

    /* Drain stream 0 replies (and stream 2 RST if sent) and send stream 3 follow-up. */
    if (s_send_mux(fd, 3u, 0u, "tail", 4u) != 0) { close(fd); return "send 3 failed"; }

    size_t rx_cap = sizeof t12_big + 16u;
    char *rx = malloc(rx_cap);
    if (!rx) { close(fd); return "oom"; }
    bool got_tail = false;
    for (;;) {
        uint32_t sid = 0u; uint8_t flg = 0u;
        ssize_t n = s_recv_mux(fd, &sid, &flg, rx, rx_cap);
        if (n < 0) { free(rx); close(fd); return "mux recv error"; }
        if (sid == 3u && n == 4 && memcmp(rx, "tail", 4u) == 0) {
            got_tail = true;
            break;
        }
    }
    free(rx);
    if (!got_tail) { close(fd); return "missing tail"; }

    /* 3 on stream 0 + 1 skipped on stream 2 + 1 on stream 3 = 5. */
    uint64_t expected = (uint64_t)duct_atomic_load(&g_frame_count, seq_cst) + 1u;
    if (!s_wait_frontier(expected, 2000u)) { close(fd); return "frontier did not jump skipped cancel"; }
    if (duct_atomic_load(&g_frontier_bad, seq_cst)) { close(fd); return "frontier regressed"; }

    close(fd);
    return nullptr;
}

/* ── Proto factories ─────────────────────────────────────────────── */

typedef const char *(*test_fn)(void);

typedef struct {
    const char *name;
    test_fn     fn;
    duct_frame_fn on_frame;
    duct_send_done_fn on_send_done;
    duct_async_step_t handler;
    bool        use_mux;   /* true: mux wire (handler coro path); false: LP wire. */
} test_spec_t;

static test_spec_t s_tests[] = {
    { "send_done_basic",              test_send_done_basic,              t1_frame,     s_on_send_done, nullptr,     false },
    { "send_done_handler",            test_send_done_handler,            t2_on_frame,  s_on_send_done, t2_handler,  true  },
    { "send_done_oversized",          test_send_done_oversized,          t3_frame,     s_on_send_done, nullptr,     false },
    { "send_done_no_cb",              test_send_done_no_cb,              t4_frame,     nullptr,        nullptr,     false },
    { "send_done_frontier_seq",       test_send_done_frontier_seq,       t5_frame,     s_on_send_done, nullptr,     false },
    { "send_done_control_only",       test_send_done_control_only,       t6_frame,     s_on_send_done, nullptr,     false },
    { "send_done_invalid_target",     test_send_done_invalid_target,     t7_frame,     s_on_send_done, nullptr,     false },
    { "send_done_tx_closed",          test_send_done_tx_closed,          t8_frame,     s_on_send_done, nullptr,     false },
    { "send_done_switch_from_cb",     test_send_done_switch_from_cb,     t9_frame,     t9_on_send_done,nullptr,     false },
    { "send_done_drain_backpressure", test_send_done_drain_backpressure, t10_frame,    s_on_send_done, nullptr,     false },
    { "send_done_close_force",        test_send_done_close_force,        t10_frame,    s_on_send_done, nullptr,     false },
    { "send_done_stream_cancel_skip", test_send_done_stream_cancel_skip, t12_on_frame, s_on_send_done, t12_handler, true  },
};

/* ── Main ────────────────────────────────────────────────────────── */

int main(void)
{
    unsigned n_tests = sizeof(s_tests) / sizeof(s_tests[0]);
    unsigned passed = 0u;

    for (unsigned i = 0u; i < n_tests; ++i) {
        auto spec = &s_tests[i];

        duct_wire_t *wire = spec->use_mux ? mux_wire_create() : duct_wire_create_length_prefix(0u);
        if (!wire) { printf("FAIL %s: wire create\n", spec->name); continue; }
        t9_wire = wire;

        auto proto = duct_proto_create(&(duct_proto_cfg_t){
            .name = spec->name,
            .wire = wire,
            .on_frame = spec->on_frame,
            .on_session_open = s_on_session_open,
            .on_session_close = s_on_session_close,
            .on_send_done = spec->on_send_done,
            .on_timer = (spec->fn == test_send_done_stream_cancel_skip) ? t12_on_timer : nullptr,
            .on_error = s_on_error,
            .handler_kind = spec->handler ? handler_async : handler_none,
            .handler_async = spec->handler,
            .flags = spec->handler ? fl_proto_multiplexed : fl_proto_none,
            .max_response = (spec->fn == test_send_done_oversized) ? 64u : 0u,
        });
        if (!proto) { printf("FAIL %s: proto create\n", spec->name); duct_wire_destroy(wire); continue; }

        auto io = duct_engine_launch(&(duct_engine_cfg_t){
            .io_threads = 1u,
            .workers = 1u,
        });
        if (!io) { printf("FAIL %s: io create\n", spec->name); duct_proto_destroy(proto); duct_wire_destroy(wire); continue; }

        uint16_t port = 0u;
        bool small_buf = spec->fn == test_send_done_drain_backpressure
                      || spec->fn == test_send_done_close_force
                      || spec->fn == test_send_done_stream_cancel_skip;
        if (small_buf) {
            const duct_proto_t *protos[1] = { proto };
            duct_sock_t lfd = duct_sock_bad;
            unsigned nf = 0u;
            if (duct_listener_bind(io, &(duct_listener_cfg_t){
                    .kind = listener_stream, .addr = "127.0.0.1",
                    .n_protos = 1u, .protos = protos }, &port, &lfd, 1u, &nf) != rc_ok || nf != 1u) {
                printf("FAIL %s: listen_fd\n", spec->name);
                duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(wire);
                continue;
            }
#ifdef _WIN32
            int sz = 16384;
#else
            int sz = 4096;
#endif
            setsockopt(lfd, SOL_SOCKET, SO_SNDBUF, (const char *)&sz, sizeof sz);
            setsockopt(lfd, SOL_SOCKET, SO_RCVBUF, (const char *)&sz, sizeof sz);
        } else if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok) {
            printf("FAIL %s: listen\n", spec->name);
            duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(wire);
            continue;
        }

        th_port = port;
        pthread_t io_thread;
        pthread_create(&io_thread, nullptr, th_run, io);

        /* Close fd before IO destroy to avoid stale conn. */
        const char *err = spec->fn();

        duct_engine_stop(io);
        pthread_join(io_thread, nullptr);
        duct_engine_destroy(io);
        if (t9_next_proto) {
            duct_proto_destroy(t9_next_proto);
            t9_next_proto = nullptr;
        }
        duct_proto_destroy(proto);
        duct_wire_destroy(wire);

        if (err) {
            printf("FAIL %s: %s\n", spec->name, err);
        } else {
            printf("PASS %s\n", spec->name);
            ++passed;
        }
    }

    printf("\nsend_done_test: %u/%u passed\n", passed, n_tests);
    return passed == n_tests ? 0 : 1;
}
