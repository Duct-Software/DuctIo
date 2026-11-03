/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file attach_packet_fd_test.c
 *  @brief @c duct_io_attach_packet_fd opens a session over a caller's packet fd.
 *
 *  On a @c SOCK_DGRAM socketpair end the session opens with the call's @c user_ctx,
 *  a datagram crosses each way as one frame, datagrams of every size up to the
 *  packet wire's bound keep their boundaries, a protocol with no wire is refused
 *  with the fd closed, and a stopped engine refuses the call with the fd closed.
 *  A session still open when the engine stops is destroyed with it.
 *
 *  A Windows build answers @c rc_not_supported and closes the fd.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

/** @brief Longest wait for a session event, milliseconds. */
static constexpr unsigned wait_ms     = 15000u;
/** @brief Largest datagram the size scenario sends, the packet wire's bound. */
static constexpr size_t   packet_max  = 65535u;

/** @brief What one session saw, written by its worker and read by the test. */
typedef struct {
    char       first[64];    /**< Leading bytes of the first frame. */
    atomic_int first_len;    /**< Bytes of the first frame, -1 before it. */
    atomic_int opened;       /**< @c on_session_open ran with this context. */
    atomic_int frames;       /**< Frames @c on_frame took. */
    atomic_int bad_conn;     /**< Frames that arrived on a leg other than 0. */
    atomic_int whole;        /**< Frames whose size and body are those the test wrote. */
    atomic_int mismatched;   /**< Frames that are not. */
    atomic_int closed;       /**< @c on_session_close ran. */
} probe_t;

/** @brief Per-session protocol state: the context the open took. */
typedef struct {
    probe_t *probe;
} state_t;

static duct_result_t create_state([[maybe_unused]] duct_session_t *s, [[maybe_unused]] void *ctx, void **out)
{
    *out = duct_new(state_t);
    return *out ? rc_ok : rc_no_memory;
}

static void destroy_state([[maybe_unused]] duct_session_t *s, [[maybe_unused]] void *ctx, void *state)
{
    auto st = (state_t *)state;
    duct_del(st);
}

/** @brief Take the context, and stage "hello" as the first datagram. */
static duct_result_t on_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                             void *user_ctx, duct_response_t *out, void *state)
{
    auto probe = (probe_t *)user_ctx;
    ((state_t *)state)->probe = probe;
    duct_atomic_store(&probe->opened, 1, release);
    *out = (duct_response_t){
        .payload = duct_view_bytes((duct_view_cc){ "hello", 5u }),
        .flags = fl_send_copy, .conn_id = 0u, .stream_id = duct_stream_id_default,
    };
    return rc_ok;
}

static void on_close([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_close_reason_t reason, void *state)
{
    duct_atomic_store(&((state_t *)state)->probe->closed, 1, release);
}

/** @brief Byte @p i of the datagram of @p len bytes the size scenario sends. */
static unsigned char s_byte(size_t len, size_t i)
{
    return (unsigned char)(len * 31u + i);
}

static duct_result_t on_frame([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
                              const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out, void *state)
{
    auto probe = ((state_t *)state)->probe;
    if (conn_id != 0u)
        duct_discard duct_atomic_fetch(add, &probe->bad_conn, 1, release);
    if (duct_atomic_fetch(add, &probe->frames, 1, acq_rel) == 0) {
        size_t n = frame->payload.size < sizeof probe->first ? frame->payload.size : sizeof probe->first;
        memcpy(probe->first, frame->payload.data, n);
        duct_atomic_store(&probe->first_len, (int)frame->payload.size, release);
    }
    if (frame->payload.size > 4u && memcmp(frame->payload.data, "size", 4u) == 0) {
        bool whole = true;
        auto bytes = (const unsigned char *)frame->payload.data;
        for (size_t i = 4u; i < frame->payload.size; ++i)
            whole = whole && bytes[i] == s_byte(frame->payload.size, i);
        if (whole)
            duct_discard duct_atomic_fetch(add, &probe->whole, 1, release);
        else
            duct_discard duct_atomic_fetch(add, &probe->mismatched, 1, release);
    }
    return rc_ok;
}

static duct_proto_t *s_proto(const duct_wire_t *wire)
{
    return duct_proto_create(&(duct_proto_cfg_t){
        .name = "attach-packet-fd", .wire = wire, .on_frame = on_frame,
        .create_state = create_state, .destroy_state = destroy_state,
        .on_session_open = on_open, .on_session_close = on_close,
    });
}

static void s_reset(probe_t *probe)
{
    *probe = (probe_t){};
    duct_atomic_store(&probe->first_len, -1, relaxed);
}

#ifdef _WIN32

int main(void)
{
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    auto proto = s_proto(duct_wire_packet());
    if (!io || !proto) {
        fprintf(stderr, "attach_packet_fd: engine or protocol create failed\n");
        return 1;
    }
    duct_sock_t fd = (duct_sock_t)socket(AF_INET, SOCK_DGRAM, 0);
    auto rc = duct_io_attach_packet_fd(io, fd, proto, nullptr);
    duct_engine_stop(io);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    if (rc != rc_not_supported) {
        fprintf(stderr, "attach_packet_fd: a Windows build answered %d, not rc_not_supported\n", (int)rc);
        return 1;
    }
    puts("attach_packet_fd: OK (rc_not_supported on Windows)");
    return 0;
}

#else

/** @brief Whether the other end of @p peer is closed: a write to it is refused. */
static bool s_peer_gone(duct_sock_t peer)
{
    return send(peer, "x", 1u, MSG_DONTWAIT | MSG_NOSIGNAL) < 0;
}

static const char *sc_pair(duct_engine_t *io, duct_proto_t *proto, probe_t *probe)
{
    s_reset(probe);
    duct_sock_t sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0)
        return "socketpair failed";
    if (duct_io_attach_packet_fd(io, sv[1], proto, probe) != rc_ok)
        return "a socketpair end was refused";
    struct timeval tv = { .tv_sec = 5 };
    duct_discard setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    char buf[64];
    ssize_t n = recv(sv[0], buf, sizeof buf, 0);
    const char *error = nullptr;
    if (!th_wait_int(&probe->opened, 1, wait_ms))
        error = "the session did not open";
    else if (n != 5 || memcmp(buf, "hello", 5u) != 0)
        error = "the datagram staged at the open did not reach the peer";
    else if (send(sv[0], "ping", 4u, 0) != 4)
        error = "the peer could not write";
    else if (!th_wait_int(&probe->frames, 1, wait_ms))
        error = "the peer's datagram did not arrive as a frame";
    else if (duct_atomic_load(&probe->first_len, acquire) != 4 || memcmp(probe->first, "ping", 4u) != 0)
        error = "the frame is not the datagram the peer wrote";
    else if (duct_atomic_load(&probe->bad_conn, acquire) != 0)
        error = "the frame arrived on a leg other than 0";
    close(sv[0]);
    return error;
}

static const char *sc_sizes(duct_engine_t *io, duct_proto_t *proto, probe_t *probe)
{
    s_reset(probe);
    duct_sock_t sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0)
        return "socketpair failed";
    int big = 1 << 20;
    duct_discard setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
    if (duct_io_attach_packet_fd(io, sv[1], proto, probe) != rc_ok)
        return "a socketpair end was refused";
    if (!th_wait_int(&probe->opened, 1, wait_ms))
        return "the session did not open";
    static const size_t sizes[] = { 5u, 255u, 256u, 257u, 4096u, 33000u, packet_max };
    static unsigned char datagram[packet_max];
    int sent = 0;
    const char *error = nullptr;
    for (size_t k = 0u; k < sizeof sizes / sizeof sizes[0] && !error; ++k) {
        memcpy(datagram, "size", 4u);
        for (size_t i = 4u; i < sizes[k]; ++i)
            datagram[i] = s_byte(sizes[k], i);
        if (send(sv[0], datagram, sizes[k], 0) != (ssize_t)sizes[k])
            error = "a datagram was not written whole";
        else
            ++sent;
    }
    if (!error && !th_wait_int(&probe->frames, sent, wait_ms))
        error = "a datagram of some size did not arrive as a frame";
    else if (!error && duct_atomic_load(&probe->mismatched, acquire) != 0)
        error = "a frame lost its boundary or its body";
    else if (!error && duct_atomic_load(&probe->whole, acquire) != sent)
        error = "a frame of some size is missing";
    close(sv[0]);
    return error;
}

static const char *sc_refusals(duct_engine_t *io)
{
    duct_sock_t sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0)
        return "socketpair failed";
    auto raw = duct_proto_create(&(duct_proto_cfg_t){
        .name = "attach-packet-fd-raw", .on_frame = on_frame, .max_response = 2048u,
    });
    if (!raw)
        return "raw protocol create failed";
    auto rc = duct_io_attach_packet_fd(io, sv[1], raw, nullptr);
    const char *error = nullptr;
    if (rc != rc_invalid_arg)
        error = "a protocol with no wire was not refused with rc_invalid_arg";
    else if (!s_peer_gone(sv[0]))
        error = "the fd of a refused call stayed open";
    close(sv[0]);
    duct_proto_destroy(raw);
    if (error)
        return error;
    if (duct_io_attach_packet_fd(nullptr, duct_sock_bad, nullptr, nullptr) != rc_invalid_arg)
        return "null arguments were not refused with rc_invalid_arg";
    return nullptr;
}

static const char *sc_stopped(duct_engine_t *io, duct_proto_t *proto)
{
    duct_sock_t sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0)
        return "socketpair failed";
    duct_engine_stop(io);
    auto rc = duct_io_attach_packet_fd(io, sv[1], proto, nullptr);
    const char *error = rc != rc_invalid_order ? "a stopped engine did not answer rc_invalid_order"
                      : !s_peer_gone(sv[0]) ? "the fd of a call a stopped engine refused stayed open"
                      : nullptr;
    close(sv[0]);
    return error;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    auto proto = s_proto(duct_wire_packet());
    if (!io || !proto) {
        fprintf(stderr, "attach_packet_fd: engine or protocol create failed\n");
        return 1;
    }
    static probe_t kept, sized;
    struct {
        const char *name;
        const char *error;
    } results[4] = {};
    unsigned n = 0u;
    results[n++] = (typeof(results[0])){ "pair", sc_pair(io, proto, &kept) };
    results[n++] = (typeof(results[0])){ "sizes", sc_sizes(io, proto, &sized) };
    results[n++] = (typeof(results[0])){ "refusals", sc_refusals(io) };
    results[n++] = (typeof(results[0])){ "stopped", sc_stopped(io, proto) };
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    int failed = 0;
    for (unsigned i = 0u; i < n; ++i) {
        if (results[i].error) {
            fprintf(stderr, "attach_packet_fd: %s: %s\n", results[i].name, results[i].error);
            failed = 1;
        }
    }
    if (failed)
        return 1;
    printf("attach_packet_fd: OK (%u scenarios)\n", n);
    return 0;
}

#endif /* _WIN32 */
