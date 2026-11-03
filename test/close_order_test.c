/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file close_order_test.c
 * @brief A normal close, and a close the peer's FIN starts, wait for the
 *  output parked ahead of them on their leg.
 *
 * A raw client with a small receive buffer reads nothing while frame_count
 * frames of frame_size bytes go out to it: more than the TX ring and both
 * socket buffers hold, pinned small on the listening socket for the accepted
 * one to inherit, so the later frames park. Once the ring holds still, a close
 * comes in, and only then does the client read:
 * - leg: the host posts the frames, then an invoke closes the leg with
 *   close_normal. The session stays, its parked frames are the leg's output
 *   ahead of the close, and the client receives every frame in order, then the
 *   close;
 * - session: the host posts the frames, then duct_session_close. The closing
 *   session's parked frames are dropped in their turn, and the client receives
 *   a prefix of the run in order, then the close: a dropped frame's ticket
 *   never holds the close;
 * - peer: the client sends frame_count requests, each answered with a frame,
 *   then shuts its write side. The FIN reaches the server behind requests
 *   whose answers wait parked, and the client receives every answer in order,
 *   then the close; the leg is lost with close_peer;
 * - malformed: the same requests, then a header whose count no frame bound
 *   admits. The parse error ends the input behind them, and the client receives
 *   every answer in order, then the close; the leg is lost with
 *   close_protocol_error.
 *
 * Every frame carries its index. A close that never comes fails the scenario
 * at read_ms.
 */

#include "duct.h"
#include "duct_ticks.h"
#include "test_helpers.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static constexpr uint32_t frame_count = 64u;
static constexpr size_t   frame_size  = 16384u;
static constexpr int      sock_buf    = 16384;
static constexpr unsigned wait_ms     = 5000u;
static constexpr int      read_ms     = 5000;
static constexpr uint64_t still_ns    = 200'000'000u;
static constexpr unsigned request_rounds = 12u;

typedef enum : uint8_t { scope_leg, scope_session, scope_peer, scope_malformed } scope_t;

static atomic_int    g_opened;
static atomic_int    g_lost;
static duct_handle_t g_tok;
static uint8_t       g_scratch[frame_size];

static uint8_t s_fill_byte(uint32_t i)
{
    return (uint8_t)(i * 13u + 5u);
}

/** @brief Frame @p i of the run into @p out; the commit copies the shared
 *  scratch before the next frame is built. */
static void s_frame(duct_response_t *out, uint32_t i)
{
    memcpy(g_scratch, &i, sizeof i);
    memset(g_scratch + sizeof i, s_fill_byte(i), frame_size - sizeof i);
    duct_response_same(out, duct_view(duct_view_u8, g_scratch, frame_size),
                       fl_send_copy, 0);
}

static duct_result_t
s_on_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok, [[maybe_unused]] void *user_ctx,
          [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    /* One worker opens every session, so the first open alone writes g_tok. */
    if (duct_atomic_load(&g_opened, relaxed) == 0)
        g_tok = tok;
    duct_atomic_fetch(add, &g_opened, 1, release);
    return rc_ok;
}

/** @brief Answer a request, which carries the index of its frame. */
static duct_result_t
s_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
           const duct_frame_t *frame, duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    uint32_t i;
    if (frame->payload.size != sizeof i)
        return rc_ok;
    memcpy(&i, frame->payload.data, sizeof i);
    s_frame(out, i);
    return rc_ok;
}

static void
s_on_lost([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
          duct_close_reason_t reason, [[maybe_unused]] duct_response_t *out,
          [[maybe_unused]] void *proto_state)
{
    /* The scenario's own leg is lost first; the idle client's comes after. */
    int none = -1;
    duct_discard duct_atomic_cas(strong, &g_lost, &none, (int)reason, release, relaxed);
}

/** @brief One frame of the run, its index in @p ctx. */
static duct_result_t
s_post([[maybe_unused]] duct_session_t *s, duct_response_t *out, void *ctx)
{
    s_frame(out, (uint32_t)(uintptr_t)ctx);
    return rc_ok;
}

static duct_result_t
s_close_leg([[maybe_unused]] duct_session_t *s, duct_response_t *out, [[maybe_unused]] void *ctx)
{
    duct_response_close_conn(out, duct_conn_id_primary, close_normal);
    return rc_ok;
}

static duct_result_t
s_probe(duct_session_t *s, [[maybe_unused]] duct_response_t *out, void *ctx)
{
    duct_tx_pos_t end = {};
    duct_discard duct_conn_tx_end(s, duct_conn_id_primary, &end, (size_t *)ctx);
    return rc_ok;
}

/** @brief Wait for the server's TX ring to hold bytes and stop moving. */
static bool s_ring_still(duct_engine_t *io)
{
    size_t last = 0u;
    uint64_t since = duct_ticks_mono_ns();
    for (unsigned waited = 0u; waited < wait_ms; waited += 10u) {
        size_t queued = 0u;
        if (duct_session_invoke_sync(io, g_tok, s_probe, &queued) != rc_ok)
            return false;
        uint64_t now = duct_ticks_mono_ns();
        if (queued != last) {
            last = queued;
            since = now;
        } else if (queued && now - since >= still_ns)
            return true;
        th_sleep_ms(10u);
    }
    return false;
}

/** @brief Connect to @p port with the receive buffer pinned at sock_buf. */
static duct_sock_t s_connect_small(uint16_t port)
{
    duct_sock_t fd = (duct_sock_t)socket(AF_INET, SOCK_STREAM, 0);
    if (fd == duct_sock_bad)
        return duct_sock_bad;
    int size = sock_buf;
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&size, sizeof size) != 0
        || connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        duct_sock_close(fd);
        return duct_sock_bad;
    }
    return fd;
}

/** @brief Read frames off @p fd until the peer closes, checking each index.
 *  @return frames read in order; -1 on a timeout, a damaged frame or one out
 *  of order. */
static int s_read_to_close(duct_sock_t fd)
{
    static char buf[frame_size];
    uint32_t want = 0u;
    for (;;) {
        uint8_t hdr[4];
        size_t got = 0u;
        while (got < sizeof hdr) {
            struct pollfd pfd = { .fd = fd, .events = POLLIN };
            if (poll(&pfd, 1, read_ms) <= 0)
                return -1;
            int r = recv(fd, (char *)hdr + got, (int)(sizeof hdr - got), 0);
            if (r == 0 && got == 0u)
                return (int)want;
            if (r <= 0)
                return -1;
            got += (size_t)r;
        }
        uint32_t len = ((uint32_t)hdr[0] << 24u) | ((uint32_t)hdr[1] << 16u)
                     | ((uint32_t)hdr[2] << 8u) | (uint32_t)hdr[3];
        uint32_t i;
        if (len != frame_size || th_read_exact(fd, buf, len) != 0)
            return -1;
        memcpy(&i, buf, sizeof i);
        if (i != want || (uint8_t)buf[sizeof i] != s_fill_byte(i)
            || (uint8_t)buf[frame_size - 1u] != s_fill_byte(i))
            return -1;
        ++want;
    }
}

static duct_proto_t *s_proto(void)
{
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "close-order", .wire = wire, .on_frame = s_on_frame,
        .on_session_open = s_on_open, .on_conn_lost = s_on_lost,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    return proto;
}

/** @brief What a client read before its close, or why it read nothing. */
typedef struct {
    const char *err;
    int         frames;
} outcome_t;

/** @brief Start the run of @p scope: the client's requests on @p fd under
 *  scope_peer and scope_malformed, the host's invokes otherwise. */
static bool s_run(duct_engine_t *io, scope_t scope, duct_sock_t fd)
{
    bool asks = scope == scope_peer || scope == scope_malformed;
    for (uint32_t i = 0u; i < frame_count; ++i)
        if (asks ? th_send(fd, &i, sizeof i) != 0
                 : duct_session_invoke(io, g_tok, s_post, (void *)(uintptr_t)i) != rc_ok)
            return false;
    return true;
}

/** @brief Bring in the close of @p scope; scope_peer shuts the client's write
 *  side of @p fd, scope_malformed sends a header whose count exceeds every
 *  frame bound. */
static bool s_close(duct_engine_t *io, scope_t scope, duct_sock_t fd)
{
    static const uint8_t malformed[4] = { 0x1fu, 0xffu, 0xffu, 0xffu };
    switch (scope) {
    case scope_leg:
        return duct_session_invoke(io, g_tok, s_close_leg, nullptr) == rc_ok;
    case scope_session:
        return duct_session_close(io, g_tok, close_normal) == rc_ok;
    case scope_peer:
        return shutdown(fd, SHUT_WR) == 0;
    case scope_malformed:
        return send(fd, (const char *)malformed, (int)sizeof malformed, 0) == (int)sizeof malformed;
    }
    return false;
}

/** @brief Park the tail of a run behind a client that reads nothing, close
 *  under @p scope, then read to the close.
 *  An idle second client connects behind the first, so the scenario's conn is
 *  no reactor's last entry: a close inside a TX drive on a poll set then moves
 *  that idle conn into the closed one's slot. */
static outcome_t s_park_and_close(duct_engine_t *io, uint16_t port, scope_t scope)
{
    duct_sock_t fd = s_connect_small(port);
    outcome_t o = { .frames = -1 };
    if (fd == duct_sock_bad)
        return (outcome_t){ .err = "connect failed" };
    duct_sock_t idle = duct_sock_bad;
    if (!th_wait_int(&g_opened, 1, wait_ms))
        o.err = "the session never opened";
    else if ((idle = th_connect(port)) == duct_sock_bad || !th_wait_int(&g_opened, 2, wait_ms))
        o.err = "the idle client's session never opened";
    else if (!s_run(io, scope, fd))
        o.err = "a request or an invoke was refused";
    else if (!s_ring_still(io))
        o.err = "the ring never filled behind a client that reads nothing";
    else if (!s_close(io, scope, fd))
        o.err = "the close was refused";
    else
        o.frames = s_read_to_close(fd);
    duct_sock_close(fd);
    if (idle != duct_sock_bad)
        duct_sock_close(idle);
    return o;
}

static const char *const s_scope_names[] = {
    [scope_leg] = "leg", [scope_session] = "session", [scope_peer] = "peer",
    [scope_malformed] = "malformed",
};

/** @brief Run one scenario on an engine of its own.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *s_scenario(scope_t scope, bool say)
{
    auto proto = s_proto();
    auto io = proto ? duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 })
                    : nullptr;
    if (!io) {
        duct_proto_destroy(proto);
        return "engine or proto create failed";
    }
    duct_atomic_store(&g_opened, 0, relaxed);
    duct_atomic_store(&g_lost, -1, relaxed);
    const duct_proto_t *protos[] = { proto };
    duct_sock_t lfd = duct_sock_bad;
    unsigned n = 0u;
    uint16_t port = 0u;
    int size = sock_buf;
    const char *err = nullptr;
    pthread_t th;
    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .addr = "127.0.0.1", .n_protos = 1u,
                               .protos = protos }, &port, &lfd, 1u, &n) != rc_ok || n != 1u
        || setsockopt(lfd, SOL_SOCKET, SO_SNDBUF, (const char *)&size, sizeof size) != 0)
        err = "listen failed";
    else if (pthread_create(&th, nullptr, th_run, io) != 0)
        err = "thread create failed";
    else {
        outcome_t o = s_park_and_close(io, port, scope);
        err = o.err ? o.err
            : o.frames < 0 ? "the close never came, or a frame came damaged or out of order"
            : scope != scope_session && o.frames != (int)frame_count
                ? "a leg's close came ahead of output parked before it"
            : scope == scope_session && o.frames >= (int)frame_count
                ? "nothing parked: the run fit the ring and the socket buffers"
            : scope == scope_peer && !th_wait_int(&g_lost, (int)close_peer, wait_ms)
                ? "the leg the peer's FIN closed was not lost with close_peer"
            : scope == scope_malformed && !th_wait_int(&g_lost, (int)close_protocol_error, wait_ms)
                ? "the leg a malformed frame closed was not lost with close_protocol_error"
            : nullptr;
        if (!err && say)
            printf("close_order: %s close after %d of %u frames\n",
                   s_scope_names[scope], o.frames, (unsigned)frame_count);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return err;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    for (unsigned i = 0u; i < sizeof s_scope_names / sizeof s_scope_names[0]; ++i) {
        /* The requests of the peer and malformed scopes are answered from the dispatch batch, where a train can open
         * on the leg between two looks at the ring; the order it breaks shows in one run of about fifty. */
        unsigned rounds = i == scope_peer || i == scope_malformed ? request_rounds : 1u;
        for (unsigned r = 0u; r < rounds; ++r) {
            auto err = s_scenario((scope_t)i, r == 0u);
            if (err) {
                fprintf(stderr, "close_order: %s: %s\n", s_scope_names[i], err);
                return 1;
            }
        }
    }
    printf("close_order: OK (a normal close, the peer's FIN and a malformed frame follow the output parked ahead of them)\n");
    return 0;
}
