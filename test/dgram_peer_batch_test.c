/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file dgram_peer_batch_test.c
 * @brief Batched reads on a peer datagram conn: one datagram per read unit,
 * padded and void units stepped over in order.
 *
 * Bursts of 48 datagrams on a framed wire arrive faster than one read each, so
 * receive calls take several at once. Sizes cover a datagram filling its unit
 * exactly, shorter ones padded out to the unit's end, and two kinds that void
 * their unit: one with no flags byte and one past max_frame. Every valid
 * datagram arrives whole, once and in order; neither void kind arrives at all.
 *
 * The wire's parse sets bit 7 on every frame, a flag outside duct_frame_flags_t
 * that the engine's own descriptors use to mark padding; every valid datagram
 * still reaches on_frame.
 */

#include "duct.h"
#include "duct_wire.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "test_helpers.h"
#include "dgram_test_helpers.h"

static constexpr size_t   pb_max_dgram = 512u;
static constexpr size_t   pb_lead = 1u + sizeof(uint32_t);
static constexpr unsigned pb_chunk = 48u;
static constexpr unsigned pb_chunks = 60u;
static constexpr unsigned pb_total = pb_chunk * pb_chunks;

typedef enum : uint8_t { dg_ok, dg_headless, dg_oversize } dg_kind_t;

static dg_kind_t s_kind(uint32_t seq)
{
    if (seq && seq % 7u == 3u)
        return dg_headless;
    if (seq && seq % 11u == 5u)
        return dg_oversize;
    return dg_ok;
}

static size_t s_len(uint32_t seq)
{
    switch (s_kind(seq)) {
    case dg_headless: return 0u;
    case dg_oversize: return pb_max_dgram + 88u;
    case dg_ok:       break;
    }
    return seq % 5u == 2u ? pb_max_dgram : pb_lead + (seq * 37u) % 300u;
}

static atomic_uint g_got = 0u;
static atomic_uint g_bad = 0u;
static uint32_t    g_seq[pb_total];

static constexpr duct_frame_flags_t pb_stray_flag = (duct_frame_flags_t)(1u << 7);
static duct_result_t (*g_parse_inner)(const duct_wire_t *, duct_view_u8, duct_frame_t *,
                                      duct_wire_parser_t *, size_t *, size_t *);

static duct_result_t
s_parse_stray(const duct_wire_t *self, duct_view_u8 input, duct_frame_t *out,
              duct_wire_parser_t *parser, size_t *consumed, size_t *needed)
{
    auto rc = g_parse_inner(self, input, out, parser, consumed, needed);
    if (rc == rc_ok)
        out->flags = duct_or(out->flags, pb_stray_flag);
    return rc;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    auto p = (const uint8_t *)frame->payload.data;
    size_t n = frame->payload.size;
    unsigned i = duct_atomic_load(&g_got, relaxed);
    if (n < sizeof(uint32_t) || i >= pb_total) {
        duct_atomic_fetch(add, &g_bad, 1u, relaxed);
        return rc_ok;
    }
    uint32_t seq = ((uint32_t)p[0] << 24u) | ((uint32_t)p[1] << 16u)
                 | ((uint32_t)p[2] <<  8u) |  (uint32_t)p[3];
    bool ok = s_kind(seq) == dg_ok && n + 1u == s_len(seq);
    for (size_t j = sizeof(uint32_t); ok && j < n; ++j)
        ok = p[j] == (uint8_t)(seq + j);
    if (!ok)
        duct_atomic_fetch(add, &g_bad, 1u, relaxed);
    g_seq[i] = seq;
    duct_atomic_fetch(add, &g_got, 1u, release);
    return rc_ok;
}

static int s_send_seq(duct_sock_t fd, uint32_t seq)
{
    uint8_t buf[pb_max_dgram + 128u];
    size_t len = s_len(seq);
    if (len >= pb_lead) {
        buf[0] = 0u;
        buf[1] = (uint8_t)(seq >> 24u); buf[2] = (uint8_t)(seq >> 16u);
        buf[3] = (uint8_t)(seq >>  8u); buf[4] = (uint8_t)(seq);
        for (size_t j = pb_lead; j < len; ++j)
            buf[j] = (uint8_t)(seq + j - 1u);
    }
    return uc_send(fd, buf, len);
}

static bool s_wait_got(unsigned target, unsigned timeout_ms)
{
    for (unsigned waited = 0u; waited < timeout_ms; ++waited) {
        if (duct_atomic_load(&g_got, acquire) >= target)
            return true;
        th_sleep_ms(1u);
    }
    return duct_atomic_load(&g_got, acquire) >= target;
}

/** @brief Send the bursts and check every valid datagram arrived whole, once
 *  and in order.
 *  @return nullptr on success, else what went wrong. */
static const char *test_batch(uint16_t port)
{
    duct_sock_t fd = uc_connect(port);
    if (fd == duct_sock_bad)
        return "client connect failed";
    unsigned want = 0u;
    if (s_send_seq(fd, 0u) != 0) {
        close(fd);
        return "primer send failed";
    }
    ++want;
    if (!s_wait_got(want, 3000u)) {
        close(fd);
        return "primer never reached on_frame";
    }
    for (uint32_t seq = 1u; seq < pb_total; ) {
        uint32_t end = seq + pb_chunk < pb_total ? seq + pb_chunk : pb_total;
        for (; seq < end; ++seq) {
            if (s_send_seq(fd, seq) != 0) {
                close(fd);
                return "burst send failed";
            }
            if (s_kind(seq) == dg_ok)
                ++want;
        }
        if (!s_wait_got(want, 3000u)) {
            close(fd);
            return "a burst never fully arrived";
        }
    }
    th_sleep_ms(50u);
    close(fd);
    if (duct_atomic_load(&g_bad, acquire))
        return "a frame arrived with the wrong length or bytes";
    if (duct_atomic_load(&g_got, acquire) != want)
        return "more frames arrived than valid datagrams were sent";
    unsigned k = 0u;
    for (uint32_t seq = 0u; seq < pb_total; ++seq) {
        if (s_kind(seq) != dg_ok)
            continue;
        if (g_seq[k++] != seq)
            return "frames arrived out of order or with a gap";
    }
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto wire = duct_wire_create_dgram_batch(pb_max_dgram, true);
    if (!wire) {
        fprintf(stderr, "dgram_peer_batch: wire create failed\n");
        return 1;
    }
    g_parse_inner = wire->on_parse;
    wire->on_parse = s_parse_stray;
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) {
        fprintf(stderr, "dgram_peer_batch: io create failed\n");
        duct_wire_destroy(wire);
        return 1;
    }
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "dgram-peer-batch", .wire = wire, .on_frame = on_frame,
    });
    if (!proto) {
        fprintf(stderr, "dgram_peer_batch: proto create failed\n");
        duct_engine_destroy(io);
        duct_wire_destroy(wire);
        return 1;
    }
    const duct_proto_t *protos[1] = { proto };
    uint16_t port = 0u;
    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
            .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
        }, &port, nullptr, 0u, nullptr) != rc_ok) {
        fprintf(stderr, "dgram_peer_batch: bind failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        duct_wire_destroy(wire);
        return 1;
    }
    pthread_t th;
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        fprintf(stderr, "dgram_peer_batch: thread create failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        duct_wire_destroy(wire);
        return 1;
    }
    const char *err = test_batch(port);
    duct_engine_stop(io);
    pthread_join(th, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    duct_wire_destroy(wire);
    if (err) {
        fprintf(stderr, "dgram_peer_batch: %s\n", err);
        return 1;
    }
    printf("dgram_peer_batch: OK (%u datagrams, headless and oversize dropped, order kept)\n",
           pb_total);
    return 0;
}
