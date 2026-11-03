/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file stream_test.c
 * @brief Step 2b litmus tests: stream claim/close, server push, route, proto switch.
 *
 * Uses a custom multiplexing wire [4 sid][1 flags][4 len][payload] so the
 * io-thread parse loop yields frame.stream_id + frame.flags, exercising the
 * worker claim/close path end-to-end through the runtime.
 *   1. stream_claim_rx    — lazy-claim on first RX frame, idempotent re-claim
 *   2. stream_close_fin   — FIN flag closes the stream, slot re-claimable
 *   3. stream_server_push — response stream_id override claims + emits push
 *   4. route_override     — route resolves same fields; explicit fields kept
 *   5. proto_switch_teardown — switch tears down live streams; leave+enter fire
 *   6. stream_open_control — on_stream_open answering with a timer alone starts it
 */

#include "duct.h"
#include "duct_wire.h"
#include "test_helpers.h"

#include <stdatomic.h>

static constexpr unsigned connect_retry_ms = 1000u;
static constexpr int roundtrip_timeout_ms = 3000;
static uint16_t test_port = 0;

/* ── Test mux wire: [4 sid][1 flags][4 len][payload] ─────────────── */
/*  flags bit 0 = FIN, bit 1 = RST. */

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

    /* Phase 1: obtain the full 9-byte header into hdr_buf. hdr_done means
     * hdr_buf holds a complete header awaiting payload. The io-thread does not
     * advance parse_off on rc_again, so a replay re-offers the already-seen
     * bytes — skip them (p += partial_len) before appending. */
    if (!st->hdr_done) {
        if (st->partial_len > 0u) {
            p += st->partial_len; /* skip replayed already-buffered bytes */
            uint32_t want = (uint32_t)mux_hdr_size - st->partial_len;
            uint32_t copy = (uint32_t)(end - p) < want ? (uint32_t)(end - p) : want;
            memcpy(st->hdr_buf + st->partial_len, p, copy);
            st->partial_len += copy;
            p += copy;
            if (st->partial_len < (uint32_t)mux_hdr_size) {
                *needed = mux_hdr_size - st->partial_len;
                return rc_again;
            }
            st->hdr_done = true; /* p is past the header in the input */
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
        /* Payload-partial replay: header is in the replayed input at p. */
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
        /* Payload partial: re-buffer the header for the next replay. */
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
        duct_view(duct_view_u8, (void *)hdr, mux_hdr_size), frame->payload);
}

static duct_wire_parser_t *
mux_create_parser([[maybe_unused]] const duct_wire_t *self)
{
    auto st = duct_new(mux_parser_t);
    duct_do_if(!st, return nullptr);
    *st = (mux_parser_t){};
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
        .name          = "test-mux",
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

/* ── Helpers ─────────────────────────────────────────────────────── */

static duct_sock_t s_client_connect(void)
{
    for (unsigned waited = 0u; waited < connect_retry_ms; waited += 10u) {
        duct_sock_t fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == duct_sock_bad)
            return duct_sock_bad;
        struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(test_port) };
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            th_sleep_ms(100u);
            return fd;
        }
        close(fd);
        th_sleep_ms(10u);
    }
    return duct_sock_bad;
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
        if (poll(&pfd, 1, roundtrip_timeout_ms) <= 0)
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
        if (poll(&pfd, 1, roundtrip_timeout_ms) <= 0)
            return -1;
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0)
            return -1;
        got += (size_t)n;
    }
    return (ssize_t)len;
}

static void *s_run_thread(void *arg) { (void)duct_engine_wait((duct_engine_t *)arg); return nullptr; }

/* ── Hook counters ───────────────────────────────────────────────── */
static atomic_int g_open_count = 0, g_close_count = 0, g_create_count = 0, g_destroy_count = 0;
static atomic_int g_enter_count = 0, g_leave_count = 0;
static atomic_int g_last_open_sid = 0, g_last_close_sid = 0;
static atomic_int g_switch_defer_phase = 0; /* 0 = first call (defer), 1 = replay (commit) */
static atomic_uint g_last_stream_op_conn_id = 0; /* F1a regression: duct_response_echo
                                                   * must not clobber control.stream_op_conn_id's
                                                   * framework default when the author layers a
                                                   * manual stream_op on top. */

static void s_counters_reset(void)
{
    duct_atomic_store(&g_open_count, 0, seq_cst); duct_atomic_store(&g_close_count, 0, seq_cst);
    duct_atomic_store(&g_create_count, 0, seq_cst); duct_atomic_store(&g_destroy_count, 0, seq_cst);
    duct_atomic_store(&g_enter_count, 0, seq_cst); duct_atomic_store(&g_leave_count, 0, seq_cst);
    duct_atomic_store(&g_last_open_sid, 0, seq_cst); duct_atomic_store(&g_last_close_sid, 0, seq_cst);
    duct_atomic_store(&g_switch_defer_phase, 0, seq_cst);
}

static duct_result_t
s_create_stream_state([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_stream_id_t sid,
                      [[maybe_unused]] void *ctx, void **out)
{
    duct_atomic_fetch(add, &g_create_count, 1, seq_cst);
    *out = (void *)(uintptr_t)0xDEAD;
    return rc_ok;
}
static void
s_destroy_stream_state([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_stream_id_t sid,
                       [[maybe_unused]] void *ctx, [[maybe_unused]] void *state)
{ duct_atomic_fetch(add, &g_destroy_count, 1, seq_cst); }

/* Quiet open: counts, emits no push (so claim/close tests aren't drowned in
 * push frames). server_push uses s_on_stream_open_push. */
static duct_result_t
s_on_stream_open_quiet([[maybe_unused]] duct_session_t *s, duct_stream_id_t sid,
                       duct_response_t *out, [[maybe_unused]] void *stream_state)
{
    duct_atomic_fetch(add, &g_open_count, 1, seq_cst);
    duct_atomic_store(&g_last_open_sid, (int)sid, seq_cst);
    *out = (duct_response_t){};
    return rc_ok;
}

static duct_result_t
s_on_stream_open_push([[maybe_unused]] duct_session_t *s, duct_stream_id_t sid,
                      duct_response_t *out, [[maybe_unused]] void *stream_state)
{
    duct_atomic_fetch(add, &g_open_count, 1, seq_cst);
    duct_atomic_store(&g_last_open_sid, (int)sid, seq_cst);
    static const char marker[] = "PUSH";
    *out = (duct_response_t){ .payload = { .data = (void *)marker, .size = sizeof(marker) - 1u },
                              .flags = fl_send_copy,
                              .conn_id = duct_conn_id_same, .stream_id = sid };
    return rc_ok;
}

static void
s_on_stream_close([[maybe_unused]] duct_session_t *s, duct_stream_id_t sid,
                  [[maybe_unused]] duct_close_reason_t reason, [[maybe_unused]] void *stream_state)
{
    duct_atomic_fetch(add, &g_close_count, 1, seq_cst);
    duct_atomic_store(&g_last_close_sid, (int)sid, seq_cst);
}

static duct_leave_t
on_leave([[maybe_unused]] duct_session_t *s, [[maybe_unused]] void *ctx,
         [[maybe_unused]] void *proto_state)
{ duct_atomic_fetch(add, &g_leave_count, 1, seq_cst); return leave_destroy; }

static duct_result_t
on_enter([[maybe_unused]] duct_session_t *s, [[maybe_unused]] void *ctx,
         [[maybe_unused]] void *proto_state)
{ duct_atomic_fetch(add, &g_enter_count, 1, seq_cst); return rc_ok; }

/* ── Frame callbacks ─────────────────────────────────────────────── */

static duct_result_t
on_frame_echo_sid([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t cid,
                  const duct_frame_t *frame, duct_response_t *out,
                  [[maybe_unused]] void *proto_state)
{
    duct_response_t r = { .payload = frame->payload, .flags = fl_send_copy,
        .conn_id = duct_conn_id_same, .stream_id = frame->stream_id };
    *out = r;
    return rc_ok;
}

/* Route test: stream 5 → echo same (route shifts to 105); stream 0 → explicit 200. */
static duct_result_t
on_frame_route_test([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t cid,
                    const duct_frame_t *frame, duct_response_t *out,
                    [[maybe_unused]] void *proto_state)
{
    if (frame->stream_id == 5u) {
        duct_response_echo(out, frame); /* same → route resolves */
        return rc_ok;
    }
    static const char msg[] = "explicit";
    *out = (duct_response_t){ .payload = { .data = (void *)msg, .size = sizeof(msg) - 1u },
                              .flags = fl_send_copy,
                              .conn_id = duct_conn_id_same, .stream_id = 200u };
    return rc_ok;
}

/* Server push: on_frame on stream 0 returns a response on stream 7. */
static duct_result_t
on_frame_push_sid7([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t cid,
                   [[maybe_unused]] const duct_frame_t *frame, duct_response_t *out,
                   [[maybe_unused]] void *proto_state)
{
    static const char push[] = "server-push-7";
    *out = (duct_response_t){ .payload = { .data = (void *)push, .size = sizeof(push) - 1u },
                              .flags = fl_send_copy,
                              .conn_id = duct_conn_id_same, .stream_id = 7u };
    return rc_ok;
}

/* Proto switch: echo + request switch to proto B. */
static duct_proto_t *g_proto_b = nullptr;
static duct_result_t
on_frame_switch([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t cid,
                const duct_frame_t *frame, duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_response_t r = { .payload = frame->payload, .flags = fl_send_copy,
        .conn_id = duct_conn_id_same, .stream_id = frame->stream_id };
    *out = r;
    duct_discard duct_proto_switch(s, g_proto_b, nullptr);
    return rc_ok;
}

/* Proto switch via rc_defer: first call records the switch and defers (no ack,
 * no apply_switch); the replay echoes and lets apply_switch commit. Verifies
 * that a pending switch survives a defer and is not re-requested on replay. */
static duct_result_t
on_frame_switch_defer(duct_session_t *s, [[maybe_unused]] duct_conn_id_t cid,
                      const duct_frame_t *frame, duct_response_t *out,
                      [[maybe_unused]] void *proto_state)
{
    if (duct_atomic_exchange(&g_switch_defer_phase, 1, seq_cst) == 0) {
        duct_discard duct_proto_switch(s, g_proto_b, nullptr);
        return rc_defer;
    }
    duct_response_t r = { .payload = frame->payload, .flags = fl_send_copy,
        .conn_id = duct_conn_id_same, .stream_id = frame->stream_id };
    *out = r;
    return rc_ok; /* switch already pending from the deferred call */
}

/* Declarative close: a bare FIN with no data response via out->control.stream_op
 * — the imperative duct_stream_close it backs is internal now (PD4), no
 * direct author call site to compare against. "data + FIN" would use
 * out->frame_flags |= fl_frame_fin instead. */
static duct_result_t
on_frame_declarative_close([[maybe_unused]] duct_session_t *s,
                           [[maybe_unused]] duct_conn_id_t cid,
                           const duct_frame_t *frame,
                           duct_response_t *out,
                           [[maybe_unused]] void *proto_state)
{
    *out = (duct_response_t){ .control = {
        .stream_op = stream_op_fin,
        .stream_op_stream_id = frame->stream_id,
    } };
    return rc_ok;
}

/* F1a regression: duct_response_echo fills *out first (must set
 * control.stream_op_conn_id = duct_conn_id_same, not zero it), then the
 * callback layers a manual FIN on top — exactly the "helper + manual
 * control tweak" combination T31 A.1 flags. */
static duct_result_t
on_frame_echo_then_fin([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t cid,
                       const duct_frame_t *frame, duct_response_t *out,
                       [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    out->control.stream_op = stream_op_fin;
    out->control.stream_op_stream_id = frame->stream_id;
    duct_atomic_store(&g_last_stream_op_conn_id, out->control.stream_op_conn_id, seq_cst);
    return rc_ok;
}

/* ── Test 1: stream_claim_rx ─────────────────────────────────────── */

static const char *test_stream_claim_rx(duct_engine_t *io, duct_proto_t *proto)
{
    (void)io; (void)proto;
    s_counters_reset();
    duct_sock_t fd = s_client_connect();
    if (fd == duct_sock_bad)
        return "client connect failed";

    const char *msg = "claim-rx";
    if (s_send_mux(fd, 42u, 0u, msg, strlen(msg)) != 0) { close(fd); return "send failed"; }
    uint32_t sid = 0u; uint8_t flg = 0u; char buf[64] = {};
    ssize_t got = s_recv_mux(fd, &sid, &flg, buf, sizeof(buf));
    if (got < 0) { close(fd); return "no echo"; }
    if (sid != 42u || (size_t)got != strlen(msg) || memcmp(buf, msg, got) != 0)
        { close(fd); return "echo: wrong sid/payload"; }

    /* Second frame on the same stream — must NOT re-open. */
    if (s_send_mux(fd, 42u, 0u, msg, strlen(msg)) != 0) { close(fd); return "send2 failed"; }
    got = s_recv_mux(fd, &sid, &flg, buf, sizeof(buf));
    if (got < 0) { close(fd); return "no echo2"; }

    close(fd);
    th_sleep_ms(100u);
    if (duct_atomic_load(&g_open_count, seq_cst) != 1)
        return "claim_rx: on_stream_open fired != 1";
    if (duct_atomic_load(&g_create_count, seq_cst) != 1)
        return "claim_rx: create_stream_state fired != 1";
    if (duct_atomic_load(&g_last_open_sid, seq_cst) != 42)
        return "claim_rx: last open sid != 42";
    return nullptr;
}

/* ── Test 2: stream_close_fin — FIN flag closes the stream ───────── */

static const char *test_stream_close_fin(duct_engine_t *io, duct_proto_t *proto)
{
    (void)io; (void)proto;
    s_counters_reset();
    duct_sock_t fd = s_client_connect();
    if (fd == duct_sock_bad)
        return "client connect failed";

    /* Frame on stream 5 with FIN flag → claim (open) + echo + FIN close. */
    const char *msg = "close-fin";
    if (s_send_mux(fd, 5u, mux_fl_fin, msg, strlen(msg)) != 0) { close(fd); return "send failed"; }
    uint32_t sid = 0u; uint8_t flg = 0u; char buf[64] = {};
    ssize_t got = s_recv_mux(fd, &sid, &flg, buf, sizeof(buf));
    if (got < 0) { close(fd); return "no echo"; }
    if (sid != 5u || (size_t)got != strlen(msg)) { close(fd); return "echo: wrong"; }

    close(fd);
    th_sleep_ms(150u);
    if (duct_atomic_load(&g_open_count, seq_cst) != 1)
        return "close_fin: on_stream_open != 1";
    if (duct_atomic_load(&g_close_count, seq_cst) != 1)
        return "close_fin: on_stream_close != 1";
    if (duct_atomic_load(&g_destroy_count, seq_cst) != 1)
        return "close_fin: destroy_stream_state != 1";
    if (duct_atomic_load(&g_last_close_sid, seq_cst) != 5)
        return "close_fin: last close sid != 5";
    return nullptr;
}

/* ── Test 3: stream_server_push — response stream_id override ───── */

static const char *test_stream_server_push(duct_engine_t *io, duct_proto_t *proto)
{
    (void)io; (void)proto;
    s_counters_reset();
    duct_sock_t fd = s_client_connect();
    if (fd == duct_sock_bad)
        return "client connect failed";

    /* Frame on stream 0 (no inbound claim). on_frame returns stream_id=7 →
     * claim 7 (push) + the response on 7. */
    const char *msg = "trigger";
    if (s_send_mux(fd, 0u, 0u, msg, strlen(msg)) != 0) { close(fd); return "send failed"; }
    uint32_t sid = 0u; uint8_t flg = 0u; char buf[64] = {};
    /* First: on_stream_open's push on stream 7. */
    ssize_t got = s_recv_mux(fd, &sid, &flg, buf, sizeof(buf));
    if (got < 0) { close(fd); return "no open push"; }
    if (sid != 7u || strncmp(buf, "PUSH", 4u) != 0) { close(fd); return "open push wrong"; }
    /* Second: on_frame's response on stream 7. */
    got = s_recv_mux(fd, &sid, &flg, buf, sizeof(buf));
    if (got < 0) { close(fd); return "no frame push"; }
    if (sid != 7u || strncmp(buf, "server-push-7", 13u) != 0) { close(fd); return "frame push wrong"; }

    close(fd);
    th_sleep_ms(100u);
    if (duct_atomic_load(&g_open_count, seq_cst) != 1)
        return "server_push: on_stream_open != 1";
    if (duct_atomic_load(&g_last_open_sid, seq_cst) != 7)
        return "server_push: open sid != 7";
    return nullptr;
}

/* ── Test 4: route_override — route resolves same; explicit kept ── */

static void
route_shift_stream([[maybe_unused]] duct_conn_id_t in_conn, duct_stream_id_t in_stream,
                   [[maybe_unused]] void *proto_state,
                   [[maybe_unused]] duct_conn_id_t *out_conn, duct_stream_id_t *out_stream)
{
    *out_stream = in_stream + 100u;
    *out_conn = in_conn;
}

static const char *test_route_override(duct_engine_t *io, duct_proto_t *proto)
{
    (void)io; (void)proto;
    s_counters_reset();
    duct_sock_t fd = s_client_connect();
    if (fd == duct_sock_bad)
        return "client connect failed";

    /* (a) stream 5: echo same → route shifts to 105. Inbound claim on 5 is
     *   quiet (no push). The echo response lands on 105 (route-resolved). */
    const char *msg = "route-same";
    if (s_send_mux(fd, 5u, 0u, msg, strlen(msg)) != 0) { close(fd); return "send a failed"; }
    uint32_t sid = 0u; uint8_t flg = 0u; char buf[64] = {};
    ssize_t got = s_recv_mux(fd, &sid, &flg, buf, sizeof(buf));
    if (got < 0) { close(fd); return "a: no response"; }
    if (sid != 105u) { close(fd); return "a: route did not shift stream to 105"; }
    if ((size_t)got != strlen(msg) || memcmp(buf, msg, got) != 0) { close(fd); return "a: payload"; }

    /* (b) stream 0: on_frame returns explicit stream_id=200 → route must NOT
     *   override (route is called for conn=same, but stream=200 is kept). */
    if (s_send_mux(fd, 0u, 0u, "x", 1u) != 0) { close(fd); return "send b failed"; }
    got = s_recv_mux(fd, &sid, &flg, buf, sizeof(buf));
    if (got < 0) { close(fd); return "b: no response"; }
    if (sid != 200u) { close(fd); return "b: explicit stream overridden by route"; }
    if (strncmp(buf, "explicit", 8u) != 0) { close(fd); return "b: payload"; }

    /* P2 guard: only the inbound claim on 5 and the explicit push on 200 fire
     * on_stream_open. With the route-resolved-claim bug, part (a) would also
     * open 105 → open_count == 3. */
    if (duct_atomic_load(&g_open_count, seq_cst) != 2)
        { close(fd); return "open_count != 2 (route-resolved stream wrongly claimed)"; }
    close(fd);
    return nullptr;
}

/* ── Test 5: proto_switch_teardown ──────────────────────────────── */

static const char *test_proto_switch_teardown(duct_engine_t *io, duct_proto_t *proto_a)
{
    (void)io; (void)proto_a;
    s_counters_reset();
    duct_sock_t fd = s_client_connect();
    if (fd == duct_sock_bad)
        return "client connect failed";

    /* Claim stream 3, echo, then switch to B. The switch fires after the
     * response: on_stream_close(3) + on_proto_leave(A) + on_proto_enter(B). */
    const char *msg = "switch";
    if (s_send_mux(fd, 3u, 0u, msg, strlen(msg)) != 0) { close(fd); return "send failed"; }
    uint32_t sid = 0u; uint8_t flg = 0u; char buf[64] = {};
    if (s_recv_mux(fd, &sid, &flg, buf, sizeof(buf)) < 0) { close(fd); return "no echo"; }
    if (sid != 3u) { close(fd); return "echo: wrong sid"; }

    /* Behavioral check after proto_switch: streams_destroy must leave the
     * table usable — re-claim stream 3 on proto B (now active) and echo.
     * The switch has applied on the worker by the time the echo is received.
     * (Does not exhaust the 128-slot table, so it does not catch a slow slot
     * leak; the slot-return in streams_destroy is verified by code inspection
     * to mirror duct_session_stream_close.) */
    const char *again = "again";
    if (s_send_mux(fd, 3u, 0u, again, strlen(again)) != 0) { close(fd); return "re-claim send failed"; }
    if (s_recv_mux(fd, &sid, &flg, buf, sizeof(buf)) < 0) { close(fd); return "re-claim: no echo (slot not reclaimed)"; }
    if (sid != 3u) { close(fd); return "re-claim: wrong sid"; }

    close(fd);
    th_sleep_ms(200u);

    if (duct_atomic_load(&g_close_count, seq_cst) < 1)
        return "proto_switch: on_stream_close did not fire on teardown";
    if (duct_atomic_load(&g_leave_count, seq_cst) != 1)
        return "proto_switch: on_proto_leave != 1";
    if (duct_atomic_load(&g_enter_count, seq_cst) != 1)
        return "proto_switch: on_proto_enter != 1";
    if (duct_atomic_load(&g_last_close_sid, seq_cst) != 3)
        return "proto_switch: teardown closed wrong stream";
    return nullptr;
}

/* ── Test 6: proto_switch_defer — switch requested, then rc_defer ── */

static const char *test_proto_switch_defer(duct_engine_t *io, duct_proto_t *proto_a)
{
    (void)io; (void)proto_a;
    s_counters_reset();
    duct_sock_t fd = s_client_connect();
    if (fd == duct_sock_bad)
        return "client connect failed";

    /* First on_frame call records the switch and returns rc_defer (no ack, no
     * apply_switch). The worker replays; the second call echoes and the switch
     * commits via apply_switch. Client sees one echo on stream 3. */
    const char *msg = "defer-sw";
    if (s_send_mux(fd, 3u, 0u, msg, strlen(msg)) != 0) { close(fd); return "send failed"; }
    uint32_t sid = 0u; uint8_t flg = 0u; char buf[64] = {};
    if (s_recv_mux(fd, &sid, &flg, buf, sizeof(buf)) < 0) { close(fd); return "no echo after replay"; }
    if (sid != 3u) { close(fd); return "echo: wrong sid"; }
    if ((size_t)strlen(msg) != (size_t)strnlen(buf, sizeof(buf)) || memcmp(buf, msg, strlen(msg)) != 0)
        { close(fd); return "echo: payload"; }

    close(fd);
    th_sleep_ms(200u);

    if (duct_atomic_load(&g_leave_count, seq_cst) != 1)
        return "defer_switch: on_proto_leave != 1";
    if (duct_atomic_load(&g_enter_count, seq_cst) != 1)
        return "defer_switch: on_proto_enter != 1";
    return nullptr;
}

/* ── Test: stream_close_declarative — control.stream_op sends a FIN ── */

static const char *test_stream_close_declarative(duct_engine_t *io, duct_proto_t *proto)
{
    (void)io; (void)proto;
    s_counters_reset();
    duct_sock_t fd = s_client_connect();
    if (fd == duct_sock_bad)
        return "client connect failed";

    /* Frame on stream 11 → claim (quiet) + declarative close (bare FIN, no data). */
    const char *msg = "decl-close";
    if (s_send_mux(fd, 11u, 0u, msg, strlen(msg)) != 0) { close(fd); return "send failed"; }
    uint32_t sid = 0u; uint8_t flg = 0u; char buf[64] = {};
    ssize_t got = s_recv_mux(fd, &sid, &flg, buf, sizeof(buf));
    if (got < 0) { close(fd); return "no FIN frame"; }
    if (sid != 11u || got != 0 || !(flg & mux_fl_fin)) { close(fd); return "FIN frame wrong"; }

    close(fd);
    th_sleep_ms(150u);
    if (duct_atomic_load(&g_close_count, seq_cst) != 1)
        return "decl_close: on_stream_close != 1";
    if (duct_atomic_load(&g_last_close_sid, seq_cst) != 11)
        return "decl_close: close sid != 11";
    return nullptr;
}

/* ── Test: echo_helper_stream_op_default — F1a regression ────────── */

static const char *test_echo_helper_stream_op_default(duct_engine_t *io, duct_proto_t *proto)
{
    (void)io; (void)proto;
    s_counters_reset();
    duct_atomic_store(&g_last_stream_op_conn_id, 0u, seq_cst);
    duct_sock_t fd = s_client_connect();
    if (fd == duct_sock_bad)
        return "client connect failed";

    /* Frame on stream 9 (no FIN in the wire flags) → echo via the helper,
     * then a manual FIN on top: two frames back — the echo, then the FIN. */
    const char *msg = "echo-then-fin";
    if (s_send_mux(fd, 9u, 0u, msg, strlen(msg)) != 0) { close(fd); return "send failed"; }
    uint32_t sid = 0u; uint8_t flg = 0u; char buf[64] = {};
    ssize_t got = s_recv_mux(fd, &sid, &flg, buf, sizeof(buf));
    if (got < 0) { close(fd); return "no echo"; }
    if (sid != 9u || (size_t)got != strlen(msg) || memcmp(buf, msg, got) != 0)
        { close(fd); return "echo: wrong sid/payload"; }

    got = s_recv_mux(fd, &sid, &flg, buf, sizeof(buf));
    if (got < 0) { close(fd); return "no FIN frame"; }
    if (sid != 9u || got != 0 || !(flg & mux_fl_fin)) { close(fd); return "FIN frame wrong"; }

    close(fd);
    th_sleep_ms(150u);
    if (duct_atomic_load(&g_last_stream_op_conn_id, seq_cst) != duct_conn_id_same)
        return "echo_then_fin: control.stream_op_conn_id clobbered by duct_response_echo (F1a regression)";
    if (duct_atomic_load(&g_close_count, seq_cst) != 1)
        return "echo_then_fin: on_stream_close != 1";
    if (duct_atomic_load(&g_last_close_sid, seq_cst) != 9)
        return "echo_then_fin: close sid != 9";
    return nullptr;
}

/* ── Proto switch from timer ──────────────────────────────────────── */

static atomic_int g_timer_count = 0;

static duct_result_t
s_on_open_start_timer([[maybe_unused]] duct_session_t *s,
                      [[maybe_unused]] duct_handle_t tok,
                      [[maybe_unused]] void *user_ctx,
                      duct_response_t *out,
                      [[maybe_unused]] void *proto_state)
{
    out->control.timer.delay_ms = 50u;
    out->control.timer.arg = 0xDEADu;
    return rc_ok;
}

static duct_result_t
s_on_timer_switch(duct_session_t *s, duct_response_t *out,
                  [[maybe_unused]] void *proto_state,
                  [[maybe_unused]] uint64_t arg)
{
    duct_atomic_fetch(add, &g_timer_count, 1, seq_cst);
    /* Emit a ping response through the old wire, then switch (sugar over
     * duct_proto_switch — same defer-survival semantics as a bare call). */
    static const uint8_t ping[] = "ping";
    return duct_response_respond_then_switch(out, s,
        duct_view(duct_view_u8, (void *)ping, sizeof(ping) - 1u),
        fl_send_copy, fl_frame_none, g_proto_b, nullptr);
}

static const char *test_proto_switch_from_timer(duct_engine_t *io, duct_proto_t *proto)
{
    (void)io; (void)proto;
    s_counters_reset();
    duct_atomic_store(&g_timer_count, 0, seq_cst);
    duct_sock_t fd = s_client_connect();
    if (fd == duct_sock_bad)
        return "client connect failed";

    /* Wait for the timer ping to arrive on the old wire (mux framing). */
    uint32_t sid = 0u; uint8_t flg = 0u; char buf[64] = {};
    ssize_t got = s_recv_mux(fd, &sid, &flg, buf, sizeof(buf));
    if (got < 0) { close(fd); return "no ping from timer"; }
    if (sid != 0u || (size_t)got != 4u || memcmp(buf, "ping", 4u) != 0)
        { close(fd); return "ping payload wrong"; }

    /* Send a frame on stream 5 — should be dispatched on proto_b now. */
    const char *msg = "after";
    if (s_send_mux(fd, 5u, 0u, msg, strlen(msg)) != 0) { close(fd); return "send failed"; }
    if (s_recv_mux(fd, &sid, &flg, buf, sizeof(buf)) < 0) { close(fd); return "no echo on proto_b"; }
    if (sid != 5u) { close(fd); return "echo: wrong sid"; }

    close(fd);
    th_sleep_ms(200u);

    if (duct_atomic_load(&g_timer_count, seq_cst) < 1)
        return "timer_switch: on_timer not fired";
    if (duct_atomic_load(&g_leave_count, seq_cst) != 1)
        return "timer_switch: on_proto_leave != 1";
    if (duct_atomic_load(&g_enter_count, seq_cst) != 1)
        return "timer_switch: on_proto_enter != 1";
    return nullptr;
}

/* ── Proto switch from open ──────────────────────────────────────── */

static duct_result_t
s_on_open_switch([[maybe_unused]] duct_session_t *s,
                 [[maybe_unused]] duct_handle_t tok,
                 [[maybe_unused]] void *user_ctx,
                 duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    /* Emit a welcome response through the old wire, then switch. */
    static const char welcome[] = "welcome";
    *out = (duct_response_t){
        .payload = { .data = (void *)welcome, .size = sizeof(welcome) - 1u },
        .flags = fl_send_copy,
        .conn_id = duct_conn_id_same,
        .stream_id = duct_stream_id_same,
    };
    duct_discard duct_proto_switch(s, g_proto_b, nullptr);
    return rc_ok;
}

static const char *test_proto_switch_from_open(duct_engine_t *io, duct_proto_t *proto)
{
    (void)io; (void)proto;
    s_counters_reset();
    duct_sock_t fd = s_client_connect();
    if (fd == duct_sock_bad)
        return "client connect failed";

    /* Welcome arrives on the old wire (mux framing). */
    uint32_t sid = 0u; uint8_t flg = 0u; char buf[64] = {};
    ssize_t got = s_recv_mux(fd, &sid, &flg, buf, sizeof(buf));
    if (got < 0) { close(fd); return "no welcome"; }
    if (sid != 0u || (size_t)got != 7u || memcmp(buf, "welcome", 7u) != 0)
        { close(fd); return "welcome payload wrong"; }

    /* Send a frame on stream 3 — should be dispatched on proto_b. */
    const char *msg = "after-open";
    if (s_send_mux(fd, 3u, 0u, msg, strlen(msg)) != 0) { close(fd); return "send failed"; }
    if (s_recv_mux(fd, &sid, &flg, buf, sizeof(buf)) < 0) { close(fd); return "no echo on proto_b"; }
    if (sid != 3u) { close(fd); return "echo: wrong sid"; }

    close(fd);
    th_sleep_ms(200u);

    if (duct_atomic_load(&g_leave_count, seq_cst) != 1)
        return "open_switch: on_proto_leave != 1";
    if (duct_atomic_load(&g_enter_count, seq_cst) != 1)
        return "open_switch: on_proto_enter != 1";
    return nullptr;
}

static constexpr uint32_t open_ctl_sid = 11u;

static duct_result_t
s_on_stream_open_timer([[maybe_unused]] duct_session_t *s, duct_stream_id_t sid,
                       duct_response_t *out, [[maybe_unused]] void *stream_state)
{
    duct_atomic_fetch(add, &g_open_count, 1, seq_cst);
    out->control.timer.delay_ms = 1u;
    out->control.timer.arg = sid;
    return rc_ok;
}

static duct_result_t
s_on_timer_count([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_response_t *out,
                 [[maybe_unused]] void *proto_state, uint64_t arg)
{
    if (arg == open_ctl_sid)
        duct_atomic_fetch(add, &g_timer_count, 1, seq_cst);
    return rc_ok;
}

/** @brief on_stream_open answering with a timer alone, no payload and no close,
 *  starts that timer. */
static const char *test_stream_open_control([[maybe_unused]] duct_engine_t *io,
                                            [[maybe_unused]] duct_proto_t *proto)
{
    s_counters_reset();
    duct_atomic_store(&g_timer_count, 0, seq_cst);
    duct_sock_t fd = s_client_connect();
    if (fd == duct_sock_bad)
        return "client connect failed";
    const char *msg = "open-control";
    if (s_send_mux(fd, open_ctl_sid, 0u, msg, strlen(msg)) != 0) { close(fd); return "send failed"; }
    uint32_t sid = 0u; uint8_t flg = 0u; char buf[64] = {};
    if (s_recv_mux(fd, &sid, &flg, buf, sizeof(buf)) < 0) { close(fd); return "no echo"; }
    if (!th_wait_int(&g_timer_count, 1, 2000u)) {
        close(fd);
        return "open_control: a timer on_stream_open answered alone never started";
    }
    close(fd);
    th_sleep_ms(100u);
    if (duct_atomic_load(&g_open_count, seq_cst) != 1)
        return "open_control: on_stream_open != 1";
    return nullptr;
}

/* ── Main ────────────────────────────────────────────────────────── */

typedef const char *(*test_fn)(duct_engine_t *, duct_proto_t *);

static struct { const char *name; test_fn fn; } s_tests[] = {
    { "stream_claim_rx",          test_stream_claim_rx },
    { "stream_close_fin",         test_stream_close_fin },
    { "stream_close_declarative", test_stream_close_declarative },
    { "echo_helper_stream_op_default", test_echo_helper_stream_op_default },
    { "stream_server_push",       test_stream_server_push },
    { "route_override",           test_route_override },
    { "proto_switch_teardown",    test_proto_switch_teardown },
    { "proto_switch_defer",       test_proto_switch_defer },
    { "proto_switch_from_timer",  test_proto_switch_from_timer },
    { "proto_switch_from_open",   test_proto_switch_from_open },
    { "stream_open_control",      test_stream_open_control },
};

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    int pass = 1;

    for (unsigned t = 0u; t < sizeof(s_tests) / sizeof(s_tests[0]); ++t) {
        auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
        if (!io) { fprintf(stderr, "stream_test: %s: io create failed\n", s_tests[t].name); pass = 0; continue; }
        auto mux_wire = mux_wire_create();
        if (!mux_wire) { fprintf(stderr, "stream_test: %s: wire create failed\n", s_tests[t].name); duct_engine_destroy(io); pass = 0; continue; }

        bool is_close_fin = (s_tests[t].fn == test_stream_close_fin);
        bool is_close_decl = (s_tests[t].fn == test_stream_close_declarative);
        bool is_echo_then_fin = (s_tests[t].fn == test_echo_helper_stream_op_default);
        bool is_server_push = (s_tests[t].fn == test_stream_server_push);
        bool is_route = (s_tests[t].fn == test_route_override);
        bool is_switch = (s_tests[t].fn == test_proto_switch_teardown
                          || s_tests[t].fn == test_proto_switch_defer
                          || s_tests[t].fn == test_proto_switch_from_timer
                          || s_tests[t].fn == test_proto_switch_from_open);
        bool is_timer_switch = (s_tests[t].fn == test_proto_switch_from_timer);
        bool is_open_switch = (s_tests[t].fn == test_proto_switch_from_open);

        duct_frame_fn  frame_cb = on_frame_echo_sid;
        duct_route_fn  route_cb = nullptr;
        duct_stream_open_fn open_cb = s_on_stream_open_quiet;
        duct_session_open_fn session_open_cb = nullptr;
        duct_timer_fn timer_cb = nullptr;
        if (is_close_fin)      frame_cb = on_frame_echo_sid;       /* FIN via wire flags */
        else if (is_close_decl) frame_cb = on_frame_declarative_close;
        else if (is_echo_then_fin) frame_cb = on_frame_echo_then_fin;
        else if (is_server_push) { frame_cb = on_frame_push_sid7; open_cb = s_on_stream_open_push; }
        else if (is_route)     frame_cb = on_frame_route_test;
        else if (is_switch)    frame_cb = (s_tests[t].fn == test_proto_switch_defer)
                                          ? on_frame_switch_defer : on_frame_switch;
        if (is_route)
            route_cb = route_shift_stream;
        if (is_timer_switch) {
            session_open_cb = s_on_open_start_timer;
            timer_cb = s_on_timer_switch;
        } else if (is_open_switch) {
            session_open_cb = s_on_open_switch;
        } else if (s_tests[t].fn == test_stream_open_control) {
            open_cb = s_on_stream_open_timer;
            timer_cb = s_on_timer_count;
        }

        auto proto = duct_proto_create(&(duct_proto_cfg_t){
            .name = "stream-test-a",
            .wire = mux_wire,
            .on_frame = frame_cb,
            .route = route_cb,
            .create_stream_state = s_create_stream_state,
            .destroy_stream_state = s_destroy_stream_state,
            .on_session_open = session_open_cb,
            .on_stream_open = open_cb,
            .on_stream_close = s_on_stream_close,
            .on_timer = timer_cb,
            .on_proto_leave = is_switch ? on_leave : nullptr,
            .flags = fl_proto_multiplexed,
        });
        if (!proto) { fprintf(stderr, "stream_test: %s: proto create failed\n", s_tests[t].name); duct_engine_destroy(io); duct_wire_destroy(mux_wire); pass = 0; continue; }

        duct_proto_t *proto_b = nullptr;
        if (is_switch) {
            proto_b = duct_proto_create(&(duct_proto_cfg_t){
                .name = "stream-test-b",
                .wire = mux_wire,
                .on_frame = on_frame_echo_sid,
                .create_stream_state = s_create_stream_state,
                .destroy_stream_state = s_destroy_stream_state,
                .on_stream_open = s_on_stream_open_quiet,
                .on_stream_close = s_on_stream_close,
                .on_proto_enter = on_enter,
                .flags = fl_proto_multiplexed,
            });
            if (!proto_b) { fprintf(stderr, "stream_test: %s: proto B failed\n", s_tests[t].name); duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(mux_wire); pass = 0; continue; }
            g_proto_b = proto_b;
        }

        test_port = 0;
        if (duct_io_listen(io, "127.0.0.1", &test_port, proto) != rc_ok) {
            fprintf(stderr, "stream_test: %s: listen failed\n", s_tests[t].name);
            duct_engine_destroy(io); duct_proto_destroy(proto);
            if (proto_b) duct_proto_destroy(proto_b);
            duct_wire_destroy(mux_wire);
            pass = 0; continue;
        }
        pthread_t th;
        if (pthread_create(&th, nullptr, s_run_thread, io) != 0) {
            fprintf(stderr, "stream_test: %s: thread failed\n", s_tests[t].name);
            duct_engine_destroy(io); duct_proto_destroy(proto);
            if (proto_b) duct_proto_destroy(proto_b);
            duct_wire_destroy(mux_wire);
            pass = 0; continue;
        }

        const char *err = s_tests[t].fn(io, proto);

        duct_engine_stop(io);
        pthread_join(th, nullptr);
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        if (proto_b) duct_proto_destroy(proto_b);
        duct_wire_destroy(mux_wire);

        if (err) { fprintf(stderr, "stream_test: %s: FAIL: %s\n", s_tests[t].name, err); pass = 0; }
        else printf("stream_test: %s: OK\n", s_tests[t].name);
    }

    return pass ? 0 : 1;
}
