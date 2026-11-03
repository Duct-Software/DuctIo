/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file sealed_packet_fd_test.c
 *  @brief What wire an @c x_raw_packet leg binds: the session's, or its own.
 *
 *  Three scenarios, one gate each.
 *
 *  A datagram-framed sealed wire on a datagram listener: the session's second
 *  leg is a packet fd, and sealed bytes written into it arrive at @c on_frame as
 *  cleartext. @c duct_conn_sealed_ctx is what admits the leg: an xport it
 *  answers nullptr for cannot carry the wire at all.
 *
 *  A stream-framed sealed wire: the same attach is refused with
 *  @c rc_invalid_arg, while @c duct_conn_attach_fd on the same session still
 *  succeeds — @c x_raw does fit that wire, so the refusal is the framing answer
 *  rather than a blanket one.
 *
 *  That same stream-framed wire, with the attach carrying a wire of its own:
 *  admitted, and packets written back to back arrive one frame each with their
 *  sizes intact. It differs from the scenario above by that one argument, so
 *  the leg wire is what lifts the refusal.
 *
 *  A @c SOCK_DGRAM socketpair stands in for a tun, the shape
 *  @c packet_fd_test.c uses. Records are built by hand because the driving side
 *  is the peer end of that pair, not a duct client.
 */

#include "duct.h"
#include "tls_engine_null.h"
#include "test_helpers.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdatomic.h>

static constexpr unsigned wait_ms      = 15000u;
static constexpr size_t   max_response = 4096u;
static constexpr unsigned payload_len  = 32u;

static atomic_int g_attach_rc = -1;
static atomic_int g_raw_rc    = -1;
static atomic_int g_frames    = 0;
static atomic_int g_bad_body  = 0;

static duct_sock_t g_peer_fd     = duct_sock_bad;
static duct_sock_t g_raw_peer_fd = duct_sock_bad;

static void s_reset(void)
{
    duct_atomic_store(&g_attach_rc, -1, relaxed);
    duct_atomic_store(&g_raw_rc, -1, relaxed);
    duct_atomic_store(&g_frames, 0, relaxed);
    duct_atomic_store(&g_bad_body, 0, relaxed);
    g_peer_fd = duct_sock_bad;
    g_raw_peer_fd = duct_sock_bad;
}

static void s_fill(uint8_t *p, unsigned len)
{
    for (unsigned i = 0u; i < len; ++i)
        p[i] = (uint8_t)(i * 7u + 1u);
}

static bool s_check(const uint8_t *p, unsigned len)
{
    for (unsigned i = 0u; i < len; ++i)
        if (p[i] != (uint8_t)(i * 7u + 1u))
            return false;
    return true;
}

static duct_sock_t s_udp_connect(uint16_t port)
{
    duct_sock_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == duct_sock_bad)
        return duct_sock_bad;
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port) };
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (const struct sockaddr *)&sa, sizeof sa) != 0) {
        close(fd);
        return duct_sock_bad;
    }
    return fd;
}

static int s_attach_packet_leg(duct_session_t *s)
{
    duct_sock_t sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0)
        return (int)rc_no_memory;
    g_peer_fd = sv[0];
    return (int)duct_conn_attach_packet_fd(s, 1u, sv[1], nullptr);
}

static duct_result_t
on_session_open_dgram(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                      [[maybe_unused]] void *user_ctx,
                      [[maybe_unused]] duct_response_t *out,
                      [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_attach_rc, s_attach_packet_leg(s), release);
    return rc_ok;
}

static duct_result_t
on_session_open_stream(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                       [[maybe_unused]] void *user_ctx,
                       [[maybe_unused]] duct_response_t *out,
                       [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_attach_rc, s_attach_packet_leg(s), release);
    duct_sock_t sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        duct_atomic_store(&g_raw_rc, (int)rc_no_memory, release);
        return rc_ok;
    }
    g_raw_peer_fd = sv[0];
    auto rc = duct_conn_attach_fd(s, 2u, sv[1]);
    duct_atomic_store(&g_raw_rc, (int)rc, release);
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
         const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    if (conn_id != 1u)
        return rc_ok;
    bool ok = frame->payload.size == payload_len
           && s_check((const uint8_t *)frame->payload.data, payload_len);
    if (!ok)
        duct_discard duct_atomic_fetch(add, &g_bad_body, 1, release);
    duct_discard duct_atomic_fetch(add, &g_frames, 1, release);
    return rc_ok;
}

static const char *sc_sealed_dgram_leg(void)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return "io create failed";
    auto wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .inner = nullptr, .engine = tls_null_vtbl(),
        .role = seal_role_responder, .framing = seal_framing_datagram });
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "sealed-packet-dgram", .wire = wire, .on_frame = on_frame,
        .on_session_open = on_session_open_dgram, .max_response = max_response,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!proto) {
        duct_engine_destroy(io);
        return "proto create failed";
    }
    uint16_t port = 0u;
    const duct_proto_t *protos[1] = { proto };
    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
            .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
        }, &port, nullptr, 0u, nullptr) != rc_ok) {
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return "dgram bind refused a datagram-framed sealed wire";
    }
    pthread_t thread;
    if (pthread_create(&thread, nullptr, th_run, io) != 0) {
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return "thread create failed";
    }

    const char *error = nullptr;
    auto driver = s_udp_connect(port);
    uint8_t rec[duct_tls_record_hdr_size + payload_len + 2u],
            clear[payload_len],
            sealed[payload_len + 2u];
    if (driver == duct_sock_bad)
        error = "udp connect failed";
    if (!error) {
        s_fill(clear, payload_len);
        size_t n = tls_null_record(rec, 1u, clear, 4u);
        if (send(driver, rec, n, 0) != (ssize_t)n)
            error = "handshake datagram send failed";
    }
    if (!error && !th_wait_int(&g_attach_rc, (int)rc_ok, wait_ms))
        error = "attach_packet_fd refused a datagram-framed sealed wire";
    if (!error) {
        size_t n = tls_null_record(rec, 1u, clear, 4u);
        if (write(g_peer_fd, rec, n) != (ssize_t)n)
            error = "handshake write to the packet fd failed";
    }
    if (!error) {
        size_t len = tls_null_seal(clear, payload_len, sealed, sizeof sealed);
        size_t n = len ? tls_null_record(rec, 2u, sealed, len) : 0u;
        if (!len || write(g_peer_fd, rec, n) != (ssize_t)n)
            error = "sealed write to the packet fd failed";
    }
    if (!error && !th_wait_int(&g_frames, 1, wait_ms))
        error = "no unsealed frame from the packet-fd leg: it resolved no sealed ctx";
    if (!error && duct_atomic_load(&g_bad_body, acquire) != 0)
        error = "the unsealed payload differs from what was sealed";

    if (driver != duct_sock_bad)
        close(driver);
    duct_engine_stop(io);
    pthread_join(thread, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    if (g_peer_fd != duct_sock_bad)
        close(g_peer_fd);
    return error;
}

static const char *sc_stream_wire_refused(void)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return "io create failed";
    auto wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .inner = nullptr, .engine = tls_null_vtbl(),
        .role = seal_role_responder, .framing = seal_framing_stream });
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "sealed-packet-stream", .wire = wire, .on_frame = on_frame,
        .on_session_open = on_session_open_stream, .max_response = max_response,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!proto) {
        duct_engine_destroy(io);
        return "proto create failed";
    }
    uint16_t port = 0u;
    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok) {
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return "listen failed";
    }
    pthread_t thread;
    if (pthread_create(&thread, nullptr, th_run, io) != 0) {
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return "thread create failed";
    }

    const char *error = nullptr;
    auto driver = th_connect(port);
    if (driver == duct_sock_bad)
        error = "driver connect failed";
    if (!error && !th_wait_int(&g_attach_rc, (int)rc_invalid_arg, wait_ms))
        error = "a packet-fd leg was admitted onto a stream-framed sealed wire";
    if (!error && !th_wait_int(&g_raw_rc, (int)rc_ok, wait_ms))
        error = "the guard also refused x_raw, which does fit a stream-framed wire";

    if (driver != duct_sock_bad)
        close(driver);
    duct_engine_stop(io);
    pthread_join(thread, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    if (g_peer_fd != duct_sock_bad)
        close(g_peer_fd);
    if (g_raw_peer_fd != duct_sock_bad)
        close(g_raw_peer_fd);
    return error;
}

static constexpr unsigned leg_packets = 3u;
static const unsigned leg_sizes[leg_packets] = { 1u, 37u, 1400u };

static duct_wire_t *g_leg_wire;

/* g_leg_slot hands out the seen[] index, g_leg_frames publishes: main waits on
 * the second, so a size must be stored before the count that admits it. One
 * counter for both puts the store after the wait it is read under. */
static atomic_int g_leg_slot   = 0;
static atomic_int g_leg_frames = 0;
static unsigned g_leg_seen[leg_packets];

static duct_result_t
on_session_open_leg_wire(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
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
    auto rc = duct_conn_attach_packet_fd(s, 1u, sv[1], g_leg_wire);
    duct_atomic_store(&g_attach_rc, (int)rc, release);
    return rc_ok;
}

static duct_result_t
on_frame_leg_wire([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
                  const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
                  [[maybe_unused]] void *proto_state)
{
    if (conn_id != 1u)
        return rc_ok;
    auto at = (unsigned)duct_atomic_fetch(add, &g_leg_slot, 1, acq_rel);
    if (at < leg_packets)
        g_leg_seen[at] = (unsigned)frame->payload.size;
    if (!s_check((const uint8_t *)frame->payload.data,
                 (unsigned)frame->payload.size))
        duct_discard duct_atomic_fetch(add, &g_bad_body, 1, relaxed);
    duct_discard duct_atomic_fetch(add, &g_leg_frames, 1, release);
    return rc_ok;
}

static const char *sc_leg_wire_on_stream_proto(void)
{
    s_reset();
    duct_atomic_store(&g_leg_slot, 0, relaxed);
    duct_atomic_store(&g_leg_frames, 0, relaxed);
    for (unsigned i = 0u; i < leg_packets; ++i)
        g_leg_seen[i] = 0u;
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return "io create failed";
    g_leg_wire = duct_wire_create_dgram_batch(2048u, false);
    auto wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .inner = nullptr, .engine = tls_null_vtbl(),
        .role = seal_role_responder, .framing = seal_framing_stream });
    auto proto = (wire && g_leg_wire) ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "leg-wire-stream", .wire = wire, .on_frame = on_frame_leg_wire,
        .on_session_open = on_session_open_leg_wire, .max_response = max_response,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!proto) {
        if (g_leg_wire)
            duct_wire_destroy(g_leg_wire);
        g_leg_wire = nullptr;
        duct_engine_destroy(io);
        return "proto create failed";
    }
    uint16_t port = 0u;
    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok) {
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        duct_wire_destroy(g_leg_wire);
        g_leg_wire = nullptr;
        return "listen failed";
    }
    pthread_t thread;
    if (pthread_create(&thread, nullptr, th_run, io) != 0) {
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        duct_wire_destroy(g_leg_wire);
        g_leg_wire = nullptr;
        return "thread create failed";
    }

    const char *error = nullptr;
    auto driver = th_connect(port);
    if (driver == duct_sock_bad)
        error = "driver connect failed";
    if (!error && !th_wait_int(&g_attach_rc, (int)rc_ok, wait_ms))
        error = "a leg wire did not admit a packet fd under a stream-framed proto";
    if (!error) {
        uint8_t packet[2048];
        for (unsigned i = 0u; i < leg_packets && !error; ++i) {
            s_fill(packet, leg_sizes[i]);
            if (write(g_peer_fd, packet, leg_sizes[i]) != (ssize_t)leg_sizes[i])
                error = "write to the packet fd failed";
        }
    }
    if (!error && !th_wait_int(&g_leg_frames, (int)leg_packets, wait_ms))
        error = "the leg wire did not deliver one frame per packet";
    if (!error && duct_atomic_load(&g_bad_body, acquire) != 0)
        error = "a frame body differs from the packet written";
    for (unsigned i = 0u; i < leg_packets && !error; ++i)
        if (g_leg_seen[i] != leg_sizes[i])
            error = "packet boundaries did not survive: a frame size differs";

    if (driver != duct_sock_bad)
        close(driver);
    duct_engine_stop(io);
    pthread_join(thread, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    duct_wire_destroy(g_leg_wire);
    g_leg_wire = nullptr;
    if (g_peer_fd != duct_sock_bad)
        close(g_peer_fd);
    return error;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto error = sc_sealed_dgram_leg();
    if (error) {
        fprintf(stderr, "sealed_packet_fd: sealed dgram leg: %s\n", error);
        return 1;
    }
    error = sc_stream_wire_refused();
    if (error) {
        fprintf(stderr, "sealed_packet_fd: stream wire refused: %s\n", error);
        return 1;
    }
    error = sc_leg_wire_on_stream_proto();
    if (error) {
        fprintf(stderr, "sealed_packet_fd: leg wire: %s\n", error);
        return 1;
    }
    printf("sealed_packet_fd: OK (sealed traffic on a packet-fd leg; "
           "a mismatched wire refused at attach; a leg wire admitting it)\n");
    return 0;
}
