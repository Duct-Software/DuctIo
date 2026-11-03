/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file owned_retry_test.c
 * @brief SYNC_AUDIT R4 litmus: fl_send_owned response driven into
 * transient TX-full (commit_internal) must release its payload exactly
 * once — not on s_commit_response's own cleanup (a stale read/double
 * release once the retry-save path also touches it) and not zero times
 * (a leak) — regardless of whether the save lands on the first attempt or
 * after a retry once TX drains.
 *
 * Floods on_frame-echoed, heap-owned responses on one connection while a
 * concurrent reader thread deliberately delays its first read: the client
 * sends continuously and the server keeps draining/acking RX regardless of
 * TX state (retry-save is exactly what lets RX progress continue while TX
 * is backed up), so backlog builds past the 64 KiB TX OLB during the delay
 * window and some responses genuinely hit commit_internal →
 * s_retry_frame_save. The reader always starts eventually, so this cannot
 * deadlock the way a "send everything, then read" design can if the server
 * ever needs read-side progress to keep accepting writes.
 *
 * Each response's payload embeds its own index; the release callback
 * checks that index has not already been released (catches a double
 * release even without ASAN) and counts total releases. Intended to also
 * be run under ASAN to catch any use-after-free directly.
 *
 * A second, independent scenario (test_owned_retry_push) covers SYNC_AUDIT
 * R4a: a nested server-push commit hitting commit_internal must not leak
 * into the main response's own, separately-succeeding outcome. See its
 * own comment for the exact construction.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>
#include <stdlib.h>

static uint16_t th_port = 0;

static constexpr unsigned n_frames = 4000u;
static constexpr size_t payload_sz = 4096u; /* 4000 * 4096 = ~15.6 MiB, sent as fast as the
                                              * client can while the reader below sleeps —
                                              * comfortably past the 64 KiB TX OLB within
                                              * that window. */
static constexpr unsigned reader_delay_ms = 1500u;

static atomic_uint g_release_count = 0;
static atomic_bool g_double_release = false;
static atomic_int  g_released[n_frames];

static void release_owned(void *arg)
{
    auto buf = (uint8_t *)arg;
    uint32_t idx = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16)
                 | ((uint32_t)buf[2] << 8)  |  (uint32_t)buf[3];
    if (idx < n_frames && duct_atomic_fetch(add, &g_released[idx], 1, relaxed) != 0)
        duct_atomic_store(&g_double_release, true, relaxed);
    duct_atomic_fetch(add, &g_release_count, 1, relaxed);
    free(buf);
}

static duct_result_t
on_frame_owned([[maybe_unused]] duct_session_t *s,
              [[maybe_unused]] duct_conn_id_t conn_id,
              const duct_frame_t *frame,
              duct_response_t *out,
              [[maybe_unused]] void *proto_state)
{
    auto buf = (uint8_t *)malloc(frame->payload.size);
    if (!buf)
        return rc_no_memory;
    memcpy(buf, frame->payload.data, frame->payload.size);
    out->payload = duct_view(duct_view_u8, buf, frame->payload.size);
    out->flags = fl_send_owned;
    out->release = release_owned;
    out->release_arg = buf;
    out->conn_id = duct_conn_id_same;
    out->stream_id = duct_stream_id_same;
    return rc_ok;
}

typedef struct {
    duct_sock_t fd;
    unsigned    expect;
    atomic_int *seen;
} recv_args_t;

static void *recv_thread(void *arg)
{
    auto a = (recv_args_t *)arg;
    /* Deliberate delay: gives the sender below a head start to build up a
     * real backlog past the TX OLB before anything drains it, without ever
     * refusing to read at all (see @file — this is what keeps the test
     * deadlock-free even if the server needs read-side progress to keep
     * accepting more input). */
    th_sleep_ms(reader_delay_ms);
    char buf[payload_sz];
    for (unsigned i = 0u; i < a->expect; ++i) {
        int64_t n = th_recv(a->fd, buf, sizeof(buf));
        if (n != (int64_t)payload_sz)
            return "recv size mismatch";
        uint32_t idx = ((uint32_t)(uint8_t)buf[0] << 24) | ((uint32_t)(uint8_t)buf[1] << 16)
                     | ((uint32_t)(uint8_t)buf[2] << 8)  |  (uint32_t)(uint8_t)buf[3];
        if (idx >= a->expect)
            return "echoed index out of range";
        if (duct_atomic_fetch(add, &a->seen[idx], 1, relaxed) != 0)
            return "same index echoed twice";
    }
    return nullptr;
}

static const char *test_owned_retry(void)
{
    duct_atomic_store(&g_release_count, 0u, relaxed);
    duct_atomic_store(&g_double_release, false, relaxed);
    for (unsigned i = 0u; i < n_frames; ++i)
        duct_atomic_store(&g_released[i], 0, relaxed);

    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    atomic_int seen[n_frames];
    for (unsigned i = 0u; i < n_frames; ++i)
        duct_atomic_store(&seen[i], 0, relaxed);
    recv_args_t rargs = { .fd = fd, .expect = n_frames, .seen = seen };
    pthread_t rth;
    if (pthread_create(&rth, nullptr, recv_thread, &rargs) != 0) {
        duct_sock_close(fd);
        return "recv thread create failed";
    }

    char payload[payload_sz];
    memset(payload, 'x', sizeof payload);
    for (unsigned i = 0u; i < n_frames; ++i) {
        payload[0] = (char)(i >> 24); payload[1] = (char)(i >> 16);
        payload[2] = (char)(i >> 8);  payload[3] = (char)i;
        if (th_send(fd, payload, sizeof payload) != 0) {
            pthread_join(rth, nullptr);
            duct_sock_close(fd);
            return "send failed";
        }
    }

    void *rerr = nullptr;
    pthread_join(rth, &rerr);
    duct_sock_close(fd);
    if (rerr) return (const char *)rerr;

    if (duct_atomic_load(&g_double_release, relaxed))
        return "double release detected";
    unsigned released = duct_atomic_load(&g_release_count, relaxed);
    if (released != n_frames) {
        static char msg[96];
        snprintf(msg, sizeof msg, "release count %u != %u frames", released, n_frames);
        return msg;
    }
    for (unsigned i = 0u; i < n_frames; ++i)
        if (duct_atomic_load(&seen[i], relaxed) != 1)
            return "an index was never echoed back";
    return nullptr;
}

/* SYNC_AUDIT R4a litmus: a multiplexed on_frame response that also does a
 * server push (explicit new stream_id) recurses into s_commit_response for
 * the pushed stream's own on_stream_open response before staging the main
 * payload. If that nested commit hits commit_internal (its own TX OLB is
 * full) while the main payload goes on to succeed on its own (here: an
 * empty payload, which always succeeds regardless of OLB state), the main
 * response's own commit_ok must not be morphed into commit_internal —
 * doing so made the caller re-consume (double-release) a response that
 * had already been fully committed and released.
 *
 * The 64 KiB ductio TX OLB drains into kernel socket buffers that this WSL2
 * environment auto-tunes into the multi-MB range, so a single fill-then-
 * trigger burst does not reliably catch the OLB genuinely saturated at the
 * exact instant of one push attempt — same class of obstacle documented at
 * the top of this file for the plain R4 scenario, and empirically
 * reconfirmed while building this one (a single trailing trigger, and even
 * 30 trailing triggers, landed zero commit_internal hits). Instead, every
 * push_trigger_stride'th frame throughout the whole burst is itself a
 * trigger attempt (own fresh stream id), spreading push_trigger_frames
 * attempts across the entire backpressure window instead of only its tail
 * — the OLB's free space oscillates as the worker's retry-drain
 * opportunistically refills any gap the I/O thread's own drain frees, so
 * spreading attempts throughout is what actually catches it saturated. */

/* +1 past the last multiple of push_trigger_stride: with an exact multiple
 * (e.g. 4000), the 40th trigger attempt IS the very last frame in the
 * stream, and the receiver's own completion (all fill echoes received)
 * only proves frames up through the second-to-last were processed — the
 * last trigger's own commit chain (including its nested release) could
 * still be mid-flight on the single worker thread at that exact instant,
 * an intermittent race the fixed grace sleep below only narrows, not
 * closes. One extra trailing fill frame turns "receiver done" into a real
 * proof: this worker is strictly single-threaded and sequential, so
 * receiving *this* frame's echo means the prior (last trigger) frame's
 * entire commit chain already ran to completion. */
static constexpr unsigned         push_total_frames = 4001u;
static constexpr size_t           push_fill_payload_sz = 4096u;
static constexpr unsigned         push_trigger_stride = 100u;
static constexpr unsigned         push_trigger_frames = push_total_frames / push_trigger_stride;
static constexpr unsigned         push_fill_frames = push_total_frames - push_trigger_frames;
static constexpr duct_stream_id_t push_stream_id_base = 1000u;

/* Nested push payload is full-size (matches push_fill_payload_sz), not a
 * few bytes: a tiny nested payload only needs a sliver of free space to
 * stage, so it rarely lands while the OLB is genuinely saturated. A
 * full-size one needs a real gap, making commit_internal far more likely
 * to actually reproduce across the push_trigger_frames attempts below. */
static uint8_t g_push_nested_payload[push_fill_payload_sz];

static atomic_uint g_push_seen = 0;
static atomic_uint g_push_trigger_seen = 0;
static atomic_uint g_main_release_count = 0;
static atomic_uint g_nested_release_count = 0;

static void release_main_push([[maybe_unused]] void *arg)
{
    duct_atomic_fetch(add, &g_main_release_count, 1, relaxed);
}

static void release_nested_push([[maybe_unused]] void *arg)
{
    duct_atomic_fetch(add, &g_nested_release_count, 1, relaxed);
}

static duct_result_t
on_stream_open_push([[maybe_unused]] duct_session_t *s,
                    [[maybe_unused]] duct_stream_id_t stream_id,
                    duct_response_t *out,
                    [[maybe_unused]] void *stream_state)
{
    out->payload = duct_view(duct_view_u8, g_push_nested_payload, sizeof g_push_nested_payload);
    out->flags = fl_send_owned;
    out->release = release_nested_push;
    out->release_arg = nullptr;
    out->conn_id = duct_conn_id_same;
    out->stream_id = duct_stream_id_same;
    return rc_ok;
}

static duct_result_t
on_frame_push_trigger([[maybe_unused]] duct_session_t *s,
                      [[maybe_unused]] duct_conn_id_t cid,
                      const duct_frame_t *frame,
                      duct_response_t *out,
                      [[maybe_unused]] void *proto_state)
{
    unsigned seen = duct_atomic_fetch(add, &g_push_seen, 1u, relaxed);
    if ((seen + 1u) % push_trigger_stride != 0u) {
        out->payload = frame->payload;
        out->flags = fl_send_copy;
        out->conn_id = duct_conn_id_same;
        out->stream_id = duct_stream_id_same;
        return rc_ok;
    }
    /* Trigger: empty main response (always commit_ok, bypasses the OLB)
     * plus a server push to a fresh stream id, expected to hit
     * commit_internal on its own, still-saturated OLB write. Each of the
     * push_trigger_frames attempts targets a distinct stream id so every
     * one actually reaches duct_session_stream_claim (a repeat id would
     * find it already claimed and skip the push branch entirely). */
    unsigned idx = duct_atomic_fetch(add, &g_push_trigger_seen, 1u, relaxed);
    out->payload = (duct_view_u8){};
    out->flags = fl_send_owned;
    out->release = release_main_push;
    out->release_arg = nullptr;
    out->conn_id = duct_conn_id_same;
    out->stream_id = push_stream_id_base + (duct_stream_id_t)idx;
    return rc_ok;
}

typedef struct {
    duct_sock_t fd;
    unsigned    expect;
} push_recv_args_t;

/** @brief Drain exactly @p a->expect fill echoes ('Y'-filled), tolerating
 * and discarding any interleaved successful-nested-push echoes: a trigger
 * whose own nested push does *not* hit commit_internal stages and
 * publishes it for real, onto this same conn — a same-size ('Z'-filled)
 * frame the receiver would otherwise miscount as a fill echo (both are
 * exactly push_fill_payload_sz bytes), finishing early while genuine fill
 * echoes are still in flight and reintroducing the exact race this design
 * exists to close. */
static void *push_recv_thread(void *arg)
{
    auto a = (push_recv_args_t *)arg;
    th_sleep_ms(reader_delay_ms);
    char buf[push_fill_payload_sz];
    unsigned got = 0u;
    while (got < a->expect) {
        int64_t n = th_recv(a->fd, buf, sizeof(buf));
        if (n != (int64_t)push_fill_payload_sz)
            return "push recv size mismatch";
        if (buf[0] == 'Y')
            ++got;
        else if (buf[0] != 'Z')
            return "push recv unexpected payload tag";
    }
    return nullptr;
}

/** @brief SYNC_AUDIT R4a acceptance: every trigger's owned marker (main and
 * nested) must be released exactly once, whatever the nested push's own
 * outcome — success, or commit_internal followed by either a retry-save or
 * s_commit_release_unconsumed. The receiver only drains the push_fill_frames
 * fill echoes; any bytes a trigger's own successful push produces are left
 * unread on the socket (irrelevant here, discarded with the connection). */
static const char *test_owned_retry_push(void)
{
    duct_atomic_store(&g_push_seen, 0u, relaxed);
    duct_atomic_store(&g_push_trigger_seen, 0u, relaxed);
    duct_atomic_store(&g_main_release_count, 0u, relaxed);
    duct_atomic_store(&g_nested_release_count, 0u, relaxed);
    memset(g_push_nested_payload, 'Z', sizeof g_push_nested_payload);

    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "push: connect failed";

    push_recv_args_t rargs = { .fd = fd, .expect = push_fill_frames };
    pthread_t rth;
    if (pthread_create(&rth, nullptr, push_recv_thread, &rargs) != 0) {
        duct_sock_close(fd);
        return "push: recv thread create failed";
    }

    char payload[push_fill_payload_sz];
    memset(payload, 'Y', sizeof payload);
    for (unsigned i = 0u; i < push_total_frames; ++i) {
        if (th_send(fd, payload, sizeof payload) != 0) {
            pthread_join(rth, nullptr);
            duct_sock_close(fd);
            return "push: send failed";
        }
    }

    void *rerr = nullptr;
    pthread_join(rth, &rerr);
    duct_sock_close(fd);
    if (rerr) return (const char *)rerr;

    /* Grace window: the push_trigger_frames attempts are dispatched right
     * after the last fill echo the receiver waited for, but its own
     * pthread_join only proves the fill echoes landed, not that the worker
     * has finished every trigger's own commit chain yet. */
    th_sleep_ms(200u);

    unsigned nested = duct_atomic_load(&g_nested_release_count, relaxed);
    if (nested != push_trigger_frames) {
        static char msg[96];
        snprintf(msg, sizeof msg, "push: nested release count %u != %u", nested, push_trigger_frames);
        return msg;
    }
    unsigned main_rel = duct_atomic_load(&g_main_release_count, relaxed);
    if (main_rel != push_trigger_frames) {
        static char msg[112];
        snprintf(msg, sizeof msg, "push: main release count %u != %u (SYNC_AUDIT R4a)",
                 main_rel, push_trigger_frames);
        return msg;
    }
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    /* Scenario 1: SYNC_AUDIT R4 (owned-payload double-release/UAF via the
     * frame-retry path). */
    {
        auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
        if (!io) { fprintf(stderr, "owned_retry: io create failed\n"); return 1; }

        auto wire = duct_wire_create_length_prefix(0u);
        if (!wire) { fprintf(stderr, "owned_retry: wire create failed\n"); duct_engine_destroy(io); return 1; }
        auto proto = duct_proto_create(&(duct_proto_cfg_t){
            .name = "owned-retry", .wire = wire, .on_frame = on_frame_owned,
        });
        if (!proto) { fprintf(stderr, "owned_retry: proto create failed\n"); duct_engine_destroy(io); duct_wire_destroy(wire); return 1; }

        if (duct_io_listen(io, "127.0.0.1", &th_port, proto) != rc_ok) {
            fprintf(stderr, "owned_retry: listen failed\n");
            duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(wire);
            return 1;
        }
        pthread_t th;
        if (pthread_create(&th, nullptr, th_run, io) != 0) {
            fprintf(stderr, "owned_retry: thread create failed\n");
            duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(wire);
            return 1;
        }

        const char *err = test_owned_retry();
        duct_engine_stop(io);
        pthread_join(th, nullptr);
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        duct_wire_destroy(wire);

        if (err) {
            fprintf(stderr, "owned_retry: %s\n", err);
            return 1;
        }
        printf("owned_retry: OK (%u frames, exactly-once release, no double release)\n", n_frames);
    }

    /* Scenario 2: SYNC_AUDIT R4a (nested server-push commit_internal must
     * not leak into the main response's own outcome). */
    {
        auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
        if (!io) { fprintf(stderr, "owned_retry_push: io create failed\n"); return 1; }

        auto wire = duct_wire_create_length_prefix(0u);
        if (!wire) { fprintf(stderr, "owned_retry_push: wire create failed\n"); duct_engine_destroy(io); return 1; }
        auto proto = duct_proto_create(&(duct_proto_cfg_t){
            .name = "owned-retry-push", .wire = wire,
            .on_frame = on_frame_push_trigger,
            .on_stream_open = on_stream_open_push,
            .flags = fl_proto_multiplexed,
        });
        if (!proto) { fprintf(stderr, "owned_retry_push: proto create failed\n"); duct_engine_destroy(io); duct_wire_destroy(wire); return 1; }

        if (duct_io_listen(io, "127.0.0.1", &th_port, proto) != rc_ok) {
            fprintf(stderr, "owned_retry_push: listen failed\n");
            duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(wire);
            return 1;
        }
        pthread_t th;
        if (pthread_create(&th, nullptr, th_run, io) != 0) {
            fprintf(stderr, "owned_retry_push: thread create failed\n");
            duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(wire);
            return 1;
        }

        const char *err = test_owned_retry_push();
        duct_engine_stop(io);
        pthread_join(th, nullptr);
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        duct_wire_destroy(wire);

        if (err) {
            fprintf(stderr, "owned_retry_push: %s\n", err);
            return 1;
        }
        printf("owned_retry_push: OK (%u fill frames, %u push attempts, nested+main released exactly once each)\n",
               push_fill_frames, push_trigger_frames);
    }

    return 0;
}
