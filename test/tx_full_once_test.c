/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file tx_full_once_test.c
 * @brief Callback-exactly-once litmus under TX OLB backpressure.
 *
 * Sends 80 frames on each of two streams while a reader thread takes the
 * echoes back; a frame TX backpressure defers replays exactly once after the
 * peer drains TX. Verifies that:
 *   - direct on_frame on stream 0 fires once per frame;
 *   - stackless handler on stream 1 fires once per frame;
 *   - every echo is received.
 */

#include "duct.h"
#include "duct_wire.h"
#include "duct_stream.h"
#include "test_helpers.h"

#include <stdatomic.h>
#include <stdlib.h>

/* ── Mux wire (same as tx_full_batch_test) ───────────────────────── */

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
        .max_frame   = 1024u,
        .destroy = mux_destroy, .on_parse = mux_parse, .on_pack = mux_pack,
        .create_parser = mux_create_parser, .destroy_parser = mux_destroy_parser,
    };
    return &w->base;
}

/* ── Send/recv helpers ───────────────────────────────────────────── */

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

static ssize_t s_recv_mux_timeout(duct_sock_t fd, uint32_t *out_sid, char *buf,
                                   size_t bufsize, int timeout_ms)
{
    uint8_t hdr[mux_hdr_size] = {};
    size_t got = 0u;
    while (got < mux_hdr_size) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, timeout_ms) <= 0) return -1;
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
        if (poll(&pfd, 1, timeout_ms) <= 0) return -1;
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return (ssize_t)len;
}

static constexpr unsigned n_frames = 80u;
static constexpr unsigned payload_sz = 1024u;

/* ── Callbacks ───────────────────────────────────────────────────── */

static atomic_int g_onframe_count = 0;
static atomic_int g_handler_count = 0;
static bool g_handler_phase = false;

/* Handler-path fl_send_owned coverage (SYNC_AUDIT R4, handler flavor):
 * s_retry_emit_save now saves a zero-copy reference into the retry list
 * instead of copying the payload out, so an owned author buffer must
 * survive untouched until s_retry_drain (or cancel) actually releases it —
 * exactly once, never early (UAF into an author-freed buffer) and never
 * skipped (leak). own_ctx_t is a side channel, not the wire payload itself,
 * so it does not disturb the '1'-byte pattern recv_thread already checks. */
typedef struct { uint8_t *buf; uint32_t idx; } owned_ctx_t;
static atomic_uint g_owned_next_idx = 0;
static atomic_uint g_owned_release_count = 0;
static atomic_bool g_owned_double_release = false;
static atomic_int  g_owned_released[n_frames];

static void release_owned_handler(void *arg)
{
    auto oc = (owned_ctx_t *)arg;
    if (oc->idx < n_frames && duct_atomic_fetch(add, &g_owned_released[oc->idx], 1, relaxed) != 0)
        duct_atomic_store(&g_owned_double_release, true, relaxed);
    duct_atomic_fetch(add, &g_owned_release_count, 1, relaxed);
    free(oc->buf);
    free(oc);
}

static duct_result_t
on_frame_echo([[maybe_unused]] duct_session_t *s,
              [[maybe_unused]] duct_conn_id_t cid,
              const duct_frame_t *frame,
              duct_response_t *out,
              [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_onframe_count, 1, relaxed);
    out->payload = frame->payload;
    out->flags = fl_send_copy;
    out->conn_id = duct_conn_id_same;
    out->stream_id = duct_stream_id_same;
    return rc_ok;
}

static duct_async_rc_t handler_echo(void *state)
{
    auto ctx = (duct_stream_ctx_t *)state;
    auto frame = duct_stream_frame(ctx);
    if (!g_handler_phase) {
        duct_atomic_fetch(add, &g_handler_count, 1, relaxed);
        /* fl_send_owned instead of fl_send_copy: exercises s_retry_emit_save's
         * zero-copy path (buf must outlive an eventual retry) rather than the
         * framework's own copy-on-stage. */
        auto buf = (uint8_t *)malloc(frame->payload.size);
        memcpy(buf, frame->payload.data, frame->payload.size);
        auto oc = (owned_ctx_t *)malloc(sizeof(owned_ctx_t));
        *oc = (owned_ctx_t){
            .buf = buf,
            .idx = duct_atomic_fetch(add, &g_owned_next_idx, 1, relaxed),
        };
        duct_response_t r = {
            .payload = { .data = buf, .size = frame->payload.size },
            .flags = fl_send_owned,
            .release = release_owned_handler,
            .release_arg = oc,
            .conn_id = duct_conn_id_same,
            .stream_id = duct_stream_id_same,
        };
        duct_stream_emit_response(ctx, &r);
        g_handler_phase = true;
        return async_yield;
    }
    g_handler_phase = false;
    return async_wait;
}

/* ── Test ────────────────────────────────────────────────────────── */

typedef struct {
    duct_sock_t fd;
    unsigned expect0;
    unsigned expect1;
} recv_args_t;

static void *recv_thread(void *arg)
{
    auto a = (recv_args_t *)arg;
    char buf[payload_sz + 64];
    char p0[payload_sz];
    char p1[payload_sz];
    memset(p0, '0', payload_sz);
    memset(p1, '1', payload_sz);

    unsigned got0 = 0u,
             got1 = 0u;
    for (unsigned i = 0u; i < a->expect0 + a->expect1; ++i) {
        uint32_t sid = 0u;
        ssize_t n = s_recv_mux_timeout(a->fd, &sid, buf, sizeof(buf), 30000);
        if (n < 0) return "recv timeout";
        if ((size_t)n != payload_sz) return "payload size mismatch";
        if (sid == 0u) {
            if (memcmp(buf, p0, payload_sz) != 0) return "stream 0 payload mismatch";
            ++got0;
        } else if (sid == 1u) {
            if (memcmp(buf, p1, payload_sz) != 0) return "stream 1 payload mismatch";
            ++got1;
        } else {
            return "unexpected stream id";
        }
    }
    if (got0 != a->expect0 || got1 != a->expect1)
        return "recv stream count mismatch";
    return nullptr;
}

static const char *test_tx_full_once(duct_engine_t *io, duct_proto_t *proto)
{
    (void)io; (void)proto;
    duct_atomic_store(&g_onframe_count, 0, relaxed);
    duct_atomic_store(&g_handler_count, 0, relaxed);
    duct_atomic_store(&g_owned_next_idx, 0, relaxed);
    duct_atomic_store(&g_owned_release_count, 0, relaxed);
    duct_atomic_store(&g_owned_double_release, false, relaxed);
    for (unsigned i = 0u; i < n_frames; ++i)
        duct_atomic_store(&g_owned_released[i], 0, relaxed);

    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    recv_args_t rargs = { .fd = fd, .expect0 = n_frames, .expect1 = n_frames };
    pthread_t rth;
    if (pthread_create(&rth, nullptr, recv_thread, &rargs) != 0) {
        close(fd);
        return "recv thread create failed";
    }

    char p0[payload_sz];
    char p1[payload_sz];
    memset(p0, '0', payload_sz);
    memset(p1, '1', payload_sz);
    for (unsigned i = 0u; i < n_frames; ++i) {
        if (s_send_mux(fd, 0u, p0, payload_sz) != 0) {
            pthread_join(rth, nullptr);
            close(fd);
            return "send stream 0 failed";
        }
        if (s_send_mux(fd, 1u, p1, payload_sz) != 0) {
            pthread_join(rth, nullptr);
            close(fd);
            return "send stream 1 failed";
        }
    }

    void *rerr = nullptr;
    pthread_join(rth, &rerr);
    close(fd);
    if (rerr) return (const char *)rerr;

    int c0 = duct_atomic_load(&g_onframe_count, relaxed);
    int c1 = duct_atomic_load(&g_handler_count, relaxed);
    if (c0 != (int)n_frames || c1 != (int)n_frames) {
        static char msg[128];
        snprintf(msg, sizeof(msg),
                 "callback counts: on_frame=%d handler=%d, expected %u/%u",
                 c0, c1, n_frames, n_frames);
        return msg;
    }
    if (duct_atomic_load(&g_owned_double_release, relaxed))
        return "owned handler payload released twice";
    unsigned rc = duct_atomic_load(&g_owned_release_count, relaxed);
    if (rc != n_frames) {
        static char msg2[128];
        snprintf(msg2, sizeof(msg2),
                 "owned handler payload releases: %u, expected %u (leak or early free)",
                 rc, n_frames);
        return msg2;
    }
    return nullptr;
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) { fprintf(stderr, "tx_full_once: io failed\n"); return 1; }
    auto wire = mux_wire_create();
    if (!wire) { duct_engine_destroy(io); return 1; }

    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "tx-full-once", .wire = wire,
        .on_frame = on_frame_echo,
        .handler_kind = handler_async,
        .handler_async = handler_echo,
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

    const char *err = test_tx_full_once(io, proto);
    duct_engine_stop(io);
    pthread_join(th, nullptr);
    /* commit_internal and retry_saved show whether the run reached TX
     * backpressure at all; duct_engine_stats answers false when the library
     * was built with stats off. */
    duct_rt_stats_t stats;
    if (duct_engine_stats(io, &stats))
        printf("tx_full_once: commit_internal=%llu retry_saved=%llu\n",
               (unsigned long long)stats.commit_internal,
               (unsigned long long)stats.retry_saved);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    duct_wire_destroy(wire);

    if (err) {
        fprintf(stderr, "tx_full_once: %s\n", err);
        return 1;
    }
    return 0;
}
