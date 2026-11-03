/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file packet_fd_test.c
 *  @brief Packet boundaries survive a round trip through an @c x_raw_packet leg's
 *  own rings, in both directions.
 *
 *  A @c SOCK_DGRAM socketpair stands in for a tun: every @c read() yields one
 *  whole packet, which is the property the transport is built around. One end
 *  is attached as conn 1, the other drives the test.
 *
 *  Lengths vary across the run and each body is derived from its own sequence
 *  number, so a record header off by any amount surfaces as a body mismatch
 *  rather than a length that happens to agree. The protocol echoes every frame
 *  back onto conn 1, so one run covers all four record sites: the header the
 *  RX side writes and the wire strips, and the one the TX side writes, reads
 *  back and steps over.
 */

#include "duct.h"
#include "test_helpers.h"

#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdatomic.h>

static constexpr unsigned wait_ms   = 15000u;
static constexpr unsigned pkt_total = 200u;
static constexpr unsigned pkt_min   = 64u;
static constexpr unsigned pkt_spread = 1400u;
static constexpr size_t   max_dgram = 2048u;

static atomic_int g_attach_rc = -1;
static atomic_int g_frames    = 0;
static atomic_int g_bad_size  = 0;
static atomic_int g_bad_body  = 0;
static atomic_int g_bad_conn  = 0;

static duct_sock_t g_peer_fd = duct_sock_bad;

static unsigned s_len_of(unsigned seq) { return pkt_min + seq % pkt_spread; }

static void s_fill(unsigned char *p, unsigned seq, unsigned len)
{
    memcpy(p, &seq, sizeof seq);
    for (unsigned i = (unsigned)sizeof seq; i < len; ++i)
        p[i] = (unsigned char)(seq + i);
}

static bool s_check(const unsigned char *p, unsigned seq, unsigned len)
{
    for (unsigned i = (unsigned)sizeof seq; i < len; ++i)
        if (p[i] != (unsigned char)(seq + i))
            return false;
    return true;
}

static duct_result_t
on_session_open([[maybe_unused]] duct_session_t *s,
                [[maybe_unused]] duct_handle_t tok,
                [[maybe_unused]] void *user_ctx,
                [[maybe_unused]] duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_sock_t sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) {
        duct_atomic_store(&g_attach_rc, (int)rc_no_memory, release);
        return rc_ok;
    }
    g_peer_fd = sv[0];
    auto rc = duct_conn_attach_packet_fd(s, 1u, sv[1], nullptr);
    duct_atomic_store(&g_attach_rc, (int)rc, release);
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
         const duct_frame_t *frame, duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    if (conn_id != 1u) {
        duct_discard duct_atomic_fetch(add, &g_bad_conn, 1, release);
        return rc_ok;
    }
    unsigned seq = 0u;
    if (frame->payload.size >= sizeof seq)
        memcpy(&seq, frame->payload.data, sizeof seq);
    unsigned len = s_len_of(seq);
    if (frame->payload.size != len)
        duct_discard duct_atomic_fetch(add, &g_bad_size, 1, release);
    else if (!s_check((const unsigned char *)frame->payload.data, seq, len))
        duct_discard duct_atomic_fetch(add, &g_bad_body, 1, release);
    duct_discard duct_atomic_fetch(add, &g_frames, 1, release);

    *out = (duct_response_t){
        .payload = frame->payload, .flags = fl_send_copy,
        .conn_id = 1u, .stream_id = duct_stream_id_default,
    };
    return rc_ok;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) {
        fprintf(stderr, "packet_fd: io create failed\n");
        return 1;
    }
    auto wire = duct_wire_create_dgram_batch(max_dgram, false);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "packet-fd", .wire = wire, .on_frame = on_frame,
        .on_session_open = on_session_open, .max_response = max_dgram,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!proto) {
        fprintf(stderr, "packet_fd: proto create failed\n");
        duct_engine_destroy(io);
        return 1;
    }
    uint16_t port = 0u;
    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok) {
        fprintf(stderr, "packet_fd: listen failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }
    pthread_t thread;
    if (pthread_create(&thread, nullptr, th_run, io) != 0) {
        fprintf(stderr, "packet_fd: thread create failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }

    auto driver = th_connect(port);
    const char *error = nullptr;
    unsigned sent = 0u,
             echoed = 0u;
    if (driver == duct_sock_bad)
        error = "driver connect failed";
    else if (!th_wait_int(&g_attach_rc, (int)rc_ok, wait_ms))
        error = "duct_conn_attach_packet_fd did not return rc_ok";

    if (!error) {
        struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
        duct_discard setsockopt(g_peer_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        unsigned char tx[pkt_min + pkt_spread],
                      rx[pkt_min + pkt_spread];
        for (unsigned seq = 0u; seq < pkt_total && !error; ++seq) {
            unsigned len = s_len_of(seq);
            s_fill(tx, seq, len);
            if (write(g_peer_fd, tx, len) != (ssize_t)len) {
                error = "write to the packet fd failed";
                break;
            }
            ++sent;
            ssize_t n = read(g_peer_fd, rx, sizeof rx);
            if (n < 0) {
                error = "no echo came back: TX record framing lost the boundary";
                break;
            }
            if ((unsigned)n != len) {
                error = "echo arrived with the wrong length: TX record boundary is wrong";
                break;
            }
            if (!s_check(rx, seq, len)) {
                error = "echo body differs: TX record payload is misplaced";
                break;
            }
            ++echoed;
        }
    }
    if (!error && !th_wait_int(&g_frames, (int)pkt_total, wait_ms))
        error = "packets lost between the packet fd and the protocol";
    if (!error && duct_atomic_load(&g_bad_size, acquire) != 0)
        error = "frame size did not match the datagram written";
    if (!error && duct_atomic_load(&g_bad_body, acquire) != 0)
        error = "frame body differs: RX record offsets are wrong";
    if (!error && duct_atomic_load(&g_bad_conn, acquire) != 0)
        error = "a frame arrived on the wrong leg";

    if (driver != duct_sock_bad)
        close(driver);
    duct_engine_stop(io);
    pthread_join(thread, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    if (g_peer_fd != duct_sock_bad)
        close(g_peer_fd);

    if (error) {
        fprintf(stderr, "packet_fd: %s (sent=%u echoed=%u frames=%d of %u, "
                        "bad size=%d body=%d leg=%d)\n",
                error, sent, echoed, duct_atomic_load(&g_frames, acquire), pkt_total,
                duct_atomic_load(&g_bad_size, acquire),
                duct_atomic_load(&g_bad_body, acquire),
                duct_atomic_load(&g_bad_conn, acquire));
        return 1;
    }
    printf("packet_fd: OK (%u datagrams in and echoed back, sizes and bodies intact)\n",
           pkt_total);
    return 0;
}
