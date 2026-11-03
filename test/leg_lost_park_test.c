/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file leg_lost_park_test.c
 * @brief An answer read on one leg and parked on another outlives the leg it
 * was read on.
 *
 * The hub session forwards each frame the driver sends on conn 0 to conn 1 with
 * the frame's own bytes, so the answer aliases conn 0's RX ring. Conn 1 dials a
 * raw target that reads nothing, its receive buffer pinned small on the
 * listening socket, so once conn 1's ring is full a forwarded frame parks and
 * conn 0 holds its next frame. The driver sends until that hold stops it; the
 * hub then closes conn 0, whose rings io frees once the loss has run, and only
 * then does the target read. It must receive every forwarded frame in order
 * and intact, the parked one last: the loss copies that answer off conn 0's
 * ring before the ring goes.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static constexpr size_t   frame_size = 16384u;
static constexpr uint32_t frame_cap  = 4096u;
static constexpr int      sock_buf   = 16384;
static constexpr unsigned wait_ms    = 5000u;
static constexpr int      stall_ms   = 300;
static constexpr int      quiet_ms   = 1000;
static constexpr unsigned teardown_ms = 100u;

static atomic_int    g_opened;
static atomic_int    g_joined;
static atomic_int    g_lost;
static duct_handle_t g_tok;
static char          g_target_addr[64];

static uint8_t s_fill_byte(uint32_t i)
{
    return (uint8_t)(i * 29u + 3u);
}

static duct_result_t
s_on_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok, [[maybe_unused]] void *user_ctx,
          duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    g_tok = tok;
    out->control.open_leg.kind = leg_kind_connect;
    out->control.open_leg.conn_id = 1u;
    out->control.open_leg.connect_addr = g_target_addr;
    duct_atomic_fetch(add, &g_opened, 1, release);
    return rc_ok;
}

static duct_result_t
s_on_join([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
          [[maybe_unused]] const duct_peer_t *peer, [[maybe_unused]] duct_response_t *out,
          [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_joined, 1, release);
    return rc_ok;
}

static void
s_on_lost([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
          [[maybe_unused]] duct_close_reason_t reason, [[maybe_unused]] duct_response_t *out,
          [[maybe_unused]] void *proto_state)
{
    if (conn_id == duct_conn_id_primary)
        duct_atomic_fetch(add, &g_lost, 1, release);
}

/** @brief Forward a conn 0 frame to conn 1 with its own bytes. */
static duct_result_t
s_on_frame([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id, const duct_frame_t *frame,
           duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    if (conn_id == duct_conn_id_primary)
        *out = (duct_response_t){
            .payload = frame->payload, .flags = fl_send_copy,
            .conn_id = 1u, .stream_id = duct_stream_id_default,
        };
    return rc_ok;
}

static duct_result_t
s_close_primary([[maybe_unused]] duct_session_t *s, duct_response_t *out,
                [[maybe_unused]] void *ctx)
{
    duct_response_close_conn(out, duct_conn_id_primary, close_normal);
    return rc_ok;
}

/** @brief Bind a raw listener on loopback whose accepted socket inherits a
 *  receive buffer pinned at sock_buf; its address lands in g_target_addr. */
static duct_sock_t s_target_listen(void)
{
    duct_sock_t fd = (duct_sock_t)socket(AF_INET, SOCK_STREAM, 0);
    if (fd == duct_sock_bad)
        return duct_sock_bad;
    int size = sock_buf;
    struct sockaddr_in addr = { .sin_family = AF_INET };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    socklen_t len = sizeof addr;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&size, sizeof size) != 0
        || bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(fd, 1) != 0
        || getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
        duct_sock_close(fd);
        return duct_sock_bad;
    }
    snprintf(g_target_addr, sizeof g_target_addr, "127.0.0.1:%u", (unsigned)ntohs(addr.sin_port));
    return fd;
}

/** @brief Send frames on @p fd until stall_ms pass with no room for more.
 *  @return frames sent whole before the stall; -1 on an error, or when
 *  frame_cap frames went out with no stall. */
static int s_send_until_held(duct_sock_t fd)
{
    static uint8_t frame[4u + frame_size];
    th_set_nonblock(fd);
    for (uint32_t i = 0u; i < frame_cap; ++i) {
        frame[0] = (uint8_t)(frame_size >> 24u);
        frame[1] = (uint8_t)(frame_size >> 16u);
        frame[2] = (uint8_t)(frame_size >> 8u);
        frame[3] = (uint8_t)frame_size;
        memcpy(frame + 4u, &i, sizeof i);
        memset(frame + 4u + sizeof i, s_fill_byte(i), frame_size - sizeof i);
        for (size_t off = 0u; off < sizeof frame; ) {
            int r = send(fd, (const char *)frame + off, (int)(sizeof frame - off), 0);
            if (r > 0) {
                off += (size_t)r;
                continue;
            }
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            int ready = poll(&pfd, 1, stall_ms);
            if (ready == 0)
                return (int)i;
            if (ready < 0 || (pfd.revents & (POLLERR | POLLHUP)))
                return -1;
        }
    }
    return -1;
}

/** @brief Read frames off @p fd until quiet_ms pass with none, checking each
 *  index and its bytes.
 *  @return frames read in order; -1 on a damaged frame or one out of order. */
static int s_read_quiet(duct_sock_t fd)
{
    static char buf[frame_size];
    uint32_t want = 0u;
    for (;;) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, quiet_ms) <= 0)
            return (int)want;
        uint8_t hdr[4];
        if (th_read_exact(fd, hdr, sizeof hdr) != 0)
            return -1;
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
        .name = "leg-lost-park", .wire = wire, .on_frame = s_on_frame,
        .on_session_open = s_on_open, .on_conn_join = s_on_join, .on_conn_lost = s_on_lost,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    return proto;
}

/** @brief Park a forwarded frame behind the target, lose the leg it was read
 *  on, then read the target dry.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *s_run(duct_engine_t *io, uint16_t hub_port, duct_sock_t target_lfd)
{
    duct_sock_t driver = th_connect(hub_port);
    if (driver == duct_sock_bad)
        return "driver connect failed";
    int size = sock_buf;
    duct_sock_t target = duct_sock_bad;
    const char *err = nullptr;
    int sent = -1,
        got = -1;
    if (setsockopt(driver, SOL_SOCKET, SO_SNDBUF, (const char *)&size, sizeof size) != 0)
        err = "driver buffer pin failed";
    else if (!th_wait_int(&g_opened, 1, wait_ms))
        err = "the hub session never opened";
    else if ((target = th_accept(target_lfd, (int)wait_ms)) == duct_sock_bad)
        err = "the hub never dialed the target";
    else if (!th_wait_int(&g_joined, 1, wait_ms))
        err = "the target leg never joined";
    else if ((sent = s_send_until_held(driver)) < 0)
        err = "the hub never held conn 0 behind a parked answer";
    else if (duct_session_invoke(io, g_tok, s_close_primary, nullptr) != rc_ok)
        err = "the conn 0 close was refused";
    else if (!th_wait_int(&g_lost, 1, wait_ms))
        err = "conn 0 was never lost";
    else {
        th_sleep_ms(teardown_ms);
        got = s_read_quiet(target);
        err = got < 0 ? "a forwarded frame came damaged or out of order"
            : got == 0 ? "nothing was forwarded"
            : got > sent ? "more frames forwarded than the driver sent"
            : nullptr;
    }
    if (!err)
        printf("leg_lost_park: %d frames sent, %d forwarded intact\n", sent, got);
    if (target != duct_sock_bad)
        duct_sock_close(target);
    duct_sock_close(driver);
    return err;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto proto = s_proto();
    auto io = proto ? duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 })
                    : nullptr;
    if (!io) {
        duct_proto_destroy(proto);
        fprintf(stderr, "leg_lost_park: engine or proto create failed\n");
        return 1;
    }
    duct_sock_t target_lfd = s_target_listen();
    const duct_proto_t *protos[] = { proto };
    duct_sock_t lfd = duct_sock_bad;
    unsigned n = 0u;
    uint16_t port = 0u;
    int size = sock_buf;
    const char *err = nullptr;
    pthread_t th;
    if (target_lfd == duct_sock_bad)
        err = "target listen failed";
    else if (duct_listener_bind(io, &(duct_listener_cfg_t){ .addr = "127.0.0.1", .n_protos = 1u,
                                    .protos = protos }, &port, &lfd, 1u, &n) != rc_ok || n != 1u
             || setsockopt(lfd, SOL_SOCKET, SO_RCVBUF, (const char *)&size, sizeof size) != 0)
        err = "hub listen failed";
    else if (pthread_create(&th, nullptr, th_run, io) != 0)
        err = "thread create failed";
    else {
        err = s_run(io, port, target_lfd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    if (target_lfd != duct_sock_bad)
        duct_sock_close(target_lfd);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    if (err) {
        fprintf(stderr, "leg_lost_park: %s\n", err);
        return 1;
    }
    printf("leg_lost_park: OK (an answer parked on one leg outlives the leg it was read on)\n");
    return 0;
}
