/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file send_done_test.c
 * @brief RW-SD litmus: on_send_done (pack/enqueue completion) tests.
 *
 *   T1  send_done_basic           — echo + fl_send_done, token carried, rc_ok
 *   T2  send_done_handler         — handler coro path fires on_send_done
 *   T3  send_done_oversized       — oversized payload → rc_invalid_arg
 *   T4  send_done_no_cb           — fl_send_done + NULL on_send_done: no crash
 *   T5  send_done_token_zero      — send_token=0 is valid
 *   T6  send_done_control_only    — empty payload + fl_send_done → rc_ok
 *   T7  send_done_invalid_target  — conn_id out of range → rc_invalid_arg
 *   T8  send_done_switch_from_cb  — proto_switch inside on_send_done
 */

#include "duct.h"
#include "duct_wire.h"
#include "duct_stream_ctx.h"
#include "test_helpers.h"

#include <stdatomic.h>

static uint16_t th_port = 0;

/* ── Atomic counters ─────────────────────────────────────────────── */

static atomic_int       g_open_count     = 0;
static atomic_int       g_frame_count    = 0;
static atomic_int       g_send_done_count = 0;
static atomic_int       g_close_count    = 0;
static atomic_int       g_enter_count    = 0;
static atomic_int       g_error_count    = 0;
static atomic_int       g_last_error     = 0;

static atomic_uintptr_t g_last_token     = 0;
static atomic_int       g_last_result    = 0;

static duct_wire_t     *t9_wire          = nullptr;

static void s_counters_reset(void)
{
    duct_atomic_store(&g_open_count, 0, seq_cst);
    duct_atomic_store(&g_frame_count, 0, seq_cst);
    duct_atomic_store(&g_send_done_count, 0, seq_cst);
    duct_atomic_store(&g_close_count, 0, seq_cst);
    duct_atomic_store(&g_enter_count, 0, seq_cst);
    duct_atomic_store(&g_error_count, 0, seq_cst);
    duct_atomic_store(&g_last_error, 0, seq_cst);
    duct_atomic_store(&g_last_token, 0, seq_cst);
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
    duct_atomic_fetch(add, &g_send_done_count, 1, relaxed);
    duct_atomic_store(&g_last_token, info->send_token, relaxed);
    duct_atomic_store(&g_last_result, (int)info->result, relaxed);
    return rc_ok;
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

static duct_wire_parser_t *
mux_create_parser([[maybe_unused]] const duct_wire_t *self)
{
    auto st = duct_new(mux_parser_t);
    duct_do_if(!st, return nullptr);
    return (duct_wire_parser_t *)st;
}

static void mux_destroy_parser([[maybe_unused]] const duct_wire_t *self, duct_wire_parser_t *parser)
{
    auto st = (mux_parser_t *)parser;
    duct_del(st);
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
        .create_parser  = mux_create_parser,
        .destroy_parser = mux_destroy_parser,
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
        .send_token = 42u,
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
    if (duct_atomic_load(&g_last_token, seq_cst) != 42u) { close(fd); return "wrong token"; }
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
        .send_token = 7u,
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
    if (duct_atomic_load(&g_last_token, seq_cst) != 7u) { close(fd); return "wrong token"; }
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
        .send_token = 9u,
    };
    return rc_ok;
}

static const char *test_send_done_oversized(void)
{
    s_counters_reset();
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    if (th_send(fd, "big", 3u) != 0) { close(fd); return "send failed"; }
    /* No echo expected — oversized is rejected. */
    if (!th_wait_int(&g_send_done_count, 1, 2000u)) { close(fd); return "send_done not fired"; }
    if (duct_atomic_load(&g_last_token, seq_cst) != 9u) { close(fd); return "wrong token"; }
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
        .send_token = 99u,
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

/* ── T5: send_done_token_zero ────────────────────────────────────── */

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
        .send_token = 0u,
    };
    return rc_ok;
}

static const char *test_send_done_token_zero(void)
{
    s_counters_reset();
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    if (th_send(fd, "zero", 4u) != 0) { close(fd); return "send failed"; }
    if (th_recv_eq(fd, "zero", 4u) != 0) { close(fd); return "no echo"; }

    if (!th_wait_int(&g_send_done_count, 1, 2000u)) { close(fd); return "send_done not fired"; }
    if (duct_atomic_load(&g_last_token, seq_cst) != 0u) { close(fd); return "token should be 0"; }

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
        .send_token = 5u,
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
    if (duct_atomic_load(&g_last_token, seq_cst) != 5u) { close(fd); return "wrong token"; }
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
        .send_token = 11u,
    };
    return rc_ok;
}

static const char *test_send_done_invalid_target(void)
{
    s_counters_reset();
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    if (th_send(fd, "inv", 3u) != 0) { close(fd); return "send failed"; }
    /* No echo — invalid target. */
    if (!th_wait_int(&g_send_done_count, 1, 2000u)) { close(fd); return "send_done not fired"; }
    if (duct_atomic_load(&g_last_token, seq_cst) != 11u) { close(fd); return "wrong token"; }
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
        .send_token = 13u,
    };
    return rc_ok;
}

static const char *test_send_done_tx_closed(void)
{
    s_counters_reset();
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    if (th_send(fd, "cls", 3u) != 0) { close(fd); return "send failed"; }
    /* No echo — target conn not attached. */
    if (!th_wait_int(&g_send_done_count, 1, 2000u)) { close(fd); return "send_done not fired"; }
    if (duct_atomic_load(&g_last_token, seq_cst) != 13u) { close(fd); return "wrong token"; }
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
        .send_token = 22u,
    };
    return rc_ok;
}

static duct_result_t
t9_on_send_done(duct_session_t *s,
                const duct_send_done_info_t *info,
                [[maybe_unused]] duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_send_done_count, 1, relaxed);
    duct_atomic_store(&g_last_token, info->send_token, relaxed);
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
    if (duct_atomic_load(&g_last_token, seq_cst) != 22u) { close(fd); return "wrong token"; }

    /* Second frame: dispatched on next proto (g_enter_count increments). */
    struct timespec ts = { .tv_nsec = 100L * 1000L * 1000L };
    nanosleep(&ts, nullptr);
    if (th_send(fd, "sw2", 3u) != 0) { close(fd); return "send2 failed"; }
    if (th_recv_eq(fd, "sw2", 3u) != 0) { close(fd); return "no echo2"; }

    if (!th_wait_int(&g_enter_count, 1, 2000u)) { close(fd); return "switch not applied"; }

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
    { "send_done_basic",          test_send_done_basic,          t1_frame, s_on_send_done, nullptr, false },
    { "send_done_handler",        test_send_done_handler,        t2_on_frame, s_on_send_done, t2_handler, true },
    { "send_done_oversized",      test_send_done_oversized,      t3_frame, s_on_send_done, nullptr, false },
    { "send_done_no_cb",          test_send_done_no_cb,          t4_frame, nullptr,        nullptr, false },
    { "send_done_token_zero",     test_send_done_token_zero,     t5_frame, s_on_send_done, nullptr, false },
    { "send_done_control_only",   test_send_done_control_only,   t6_frame, s_on_send_done, nullptr, false },
    { "send_done_invalid_target", test_send_done_invalid_target, t7_frame, s_on_send_done, nullptr, false },
    { "send_done_tx_closed",      test_send_done_tx_closed,      t8_frame, s_on_send_done, nullptr, false },
    { "send_done_switch_from_cb", test_send_done_switch_from_cb, t9_frame, t9_on_send_done, nullptr, false },
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
        if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok) {
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
