/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file defer_stream_test.c
 * @brief rc_defer on a multiplexed stream frame: stream state survives defer,
 *        replay echoes on the correct stream_id.
 *
 * Uses the same mux wire as stream_test: [4 sid][1 flags][4 len][payload].
 */

#include "duct.h"
#include "duct_wire.h"
#include "test_helpers.h"

#include <stdatomic.h>

/* ── Mux wire (same as stream_test) ──────────────────────────────── */

static constexpr size_t mux_hdr_size = 9u;

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
    *out = (duct_frame_t){ .stream_id = sid, .payload = { .data = p, .size = len } };
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
    uint8_t hdr[mux_hdr_size] = {
        (uint8_t)(sid >> 24u), (uint8_t)(sid >> 16u),
        (uint8_t)(sid >>  8u), (uint8_t)(sid),
        0u,
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
    *st = (mux_parser_t){};
    return (duct_wire_parser_t *)st;
}

static void mux_destroy_parser([[maybe_unused]] const duct_wire_t *self, duct_wire_parser_t *parser)
{
    auto st = (mux_parser_t *)parser;
    duct_del(st);
}

static void mux_destroy(duct_wire_t *self)
{
    auto w = (mux_wire_t *)self;
    duct_del(w);
}

static duct_wire_t *mux_wire_create(void)
{
    auto w = duct_new(mux_wire_t);
    duct_do_if(!w, return nullptr);
    w->base = (duct_wire_t){
        .name = "test-mux",
        .header_size = mux_hdr_size,
        .destroy = mux_destroy, .on_parse = mux_parse, .on_pack = mux_pack,
        .create_parser = mux_create_parser, .destroy_parser = mux_destroy_parser,
    };
    return &w->base;
}

/* ── Mux send/recv helpers ──────────────────────────────────────── */

static uint16_t th_port = 0;

static int s_send_mux(duct_sock_t fd, uint32_t sid, const void *data, size_t len)
{
    uint8_t hdr[mux_hdr_size] = {
        (uint8_t)(sid >> 24u), (uint8_t)(sid >> 16u),
        (uint8_t)(sid >>  8u), (uint8_t)(sid),
        0u,
        (uint8_t)(len >> 24u), (uint8_t)(len >> 16u),
        (uint8_t)(len >>  8u), (uint8_t)(len),
    };
    struct iovec iov[2] = {
        { .iov_base = hdr, .iov_len = mux_hdr_size },
        { .iov_base = (void *)data, .iov_len = len },
    };
    return writev(fd, iov, 2) == (ssize_t)(mux_hdr_size + len) ? 0 : -1;
}

static ssize_t s_recv_mux(duct_sock_t fd, uint32_t *out_sid, char *buf, size_t bufsize)
{
    uint8_t hdr[mux_hdr_size] = {};
    size_t got = 0u;
    while (got < mux_hdr_size) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, TH_ROUNDTRIP_TIMEOUT_MS) <= 0) return -1;
        ssize_t n = read(fd, hdr + got, mux_hdr_size - got);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    uint32_t sid = ((uint32_t)hdr[0] << 24u) | ((uint32_t)hdr[1] << 16u)
                 | ((uint32_t)hdr[2] <<  8u) |  (uint32_t)hdr[3];
    uint32_t len = ((uint32_t)hdr[5] << 24u) | ((uint32_t)hdr[6] << 16u)
                 | ((uint32_t)hdr[7] <<  8u) |  (uint32_t)hdr[8];
    if (len > bufsize) return -1;
    *out_sid = sid;
    got = 0u;
    while (got < len) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, TH_ROUNDTRIP_TIMEOUT_MS) <= 0) return -1;
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return (ssize_t)len;
}

/* ── Test state ──────────────────────────────────────────────────── */

static atomic_int g_defer_phase = 0;
static atomic_int g_frame_count = 0;

static duct_result_t
on_frame_defer([[maybe_unused]] duct_session_t *s,
               [[maybe_unused]] duct_conn_id_t cid,
               const duct_frame_t *frame,
               duct_response_t *out,
               [[maybe_unused]] void *proto_state)
{
    int phase = duct_atomic_fetch(add, &g_defer_phase, 1, relaxed);
    if (phase == 0)
        return rc_defer;
    duct_atomic_fetch(add, &g_frame_count, 1, relaxed);
    /* Echo on the same stream. */
    out->payload = frame->payload;
    out->flags = fl_send_copy;
    out->conn_id = duct_conn_id_same;
    out->stream_id = frame->stream_id;
    return rc_ok;
}

static duct_result_t
on_stream_open([[maybe_unused]] duct_session_t *s,
               [[maybe_unused]] duct_stream_id_t sid,
               [[maybe_unused]] duct_response_t *out,
               [[maybe_unused]] void *stream_state)
{
    return rc_ok;
}

static duct_result_t
s_create_stream_state([[maybe_unused]] duct_session_t *s,
                      [[maybe_unused]] duct_stream_id_t sid,
                      [[maybe_unused]] void *ctx, void **out)
{
    *out = (void *)(uintptr_t)0xCAFE;
    return rc_ok;
}

/* ── Test ────────────────────────────────────────────────────────── */

static const char *test_defer_stream(duct_engine_t *io, duct_proto_t *proto)
{
    (void)io; (void)proto;
    duct_atomic_store(&g_defer_phase, 0, seq_cst);
    duct_atomic_store(&g_frame_count, 0, seq_cst);

    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    /* Send a frame on stream 7. First on_frame returns rc_defer (phase 0),
     * second call (replay) echoes on stream 7. */
    const char *msg = "defer-stream";
    if (s_send_mux(fd, 7u, msg, strlen(msg)) != 0) { close(fd); return "send failed"; }

    uint32_t sid = 0u;
    char buf[128] = {};
    ssize_t got = s_recv_mux(fd, &sid, buf, sizeof(buf));
    close(fd);

    if (got < 0) return "no echo (defer replay broken)";
    if (sid != 7u) return "echo on wrong stream_id";
    if ((size_t)got != strlen(msg) || memcmp(buf, msg, got) != 0)
        return "echo payload mismatch";

    struct timespec ts = { .tv_nsec = 200L * 1000L * 1000L };
    nanosleep(&ts, nullptr);

    if (duct_atomic_load(&g_frame_count, seq_cst) != 1) return "frame_count != 1";
    if (duct_atomic_load(&g_defer_phase, seq_cst) < 2) return "defer_phase < 2 (no replay)";
    return nullptr;
}

/* ── Main ────────────────────────────────────────────────────────── */

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) { fprintf(stderr, "defer_stream: io failed\n"); return 1; }
    auto wire = mux_wire_create();
    if (!wire) { duct_engine_destroy(io); return 1; }

    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "defer-stream", .wire = wire,
        .on_frame = on_frame_defer,
        .on_stream_open = on_stream_open,
        .create_stream_state = s_create_stream_state,
        .flags = fl_proto_multiplexed,
    });
    if (!proto) { duct_engine_destroy(io); duct_wire_destroy(wire); return 1; }

    if (duct_io_listen(io, "127.0.0.1", &th_port, proto) != rc_ok) {
        duct_proto_destroy(proto); duct_engine_destroy(io); duct_wire_destroy(wire);
        return 1;
    }
    pthread_t th;
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        duct_proto_destroy(proto); duct_engine_destroy(io); duct_wire_destroy(wire);
        return 1;
    }

    const char *err = test_defer_stream(io, proto);

    duct_engine_stop(io);
    pthread_join(th, nullptr);
    duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(wire);

    if (err) { fprintf(stderr, "defer_stream: FAIL: %s\n", err); return 1; }
    printf("defer_stream: OK\n");
    return 0;
}
