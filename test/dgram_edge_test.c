/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file dgram_edge_test.c
 * @brief RW-DG edge cases: both ends of the datagram size range and
 * worker-initiated respond-then-close on a xport_udp_peer leg.
 *
 * Zero-length: recvfrom() on UDP legitimately returns n==0 for an empty
 * datagram; the record-framing wire must encode/decode a 0-length record
 * without desyncing the next one in the same RX OLB, and the protocol must see
 * it as an empty frame. A peer's first datagram is classified on the listener
 * socket while every later one arrives on its own per-peer socket, so the two
 * reach that code by different routes and both are driven here.
 *
 * Max-length: an RX slot carries a record header ahead of the payload, so a
 * slot sized at the datagram maximum leaves the last few bytes off — and only
 * when a slot was free, which makes the loss intermittent and size-dependent.
 *
 * Oversize: a datagram past the wire's max_frame is dropped alone, both as a
 * peer's first datagram and on its own socket, and the session lives on.
 *
 * Queued burst: several datagrams waiting in the kernel when the io thread
 * starts arrive from one batched read, and every one of them must reach the
 * protocol.
 *
 * Respond-then-close: duct_response_respond_then_close drives the same
 * fl_conn_closing + TX-drain-then-quiesce path introduced for Phase F
 * previously only exercised
 * for xport_tcp legs. on_session_close confirms the terminal callback still
 * fires for a per-peer UDP conn.
 */

#include "duct.h"
#include "duct_conn.h"
#include "duct_session.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#endif

#include "test_helpers.h"
#include "dgram_test_helpers.h"

static constexpr unsigned close_wait_ms = 3000u;
static constexpr char close_trigger[] = "closeme";

static atomic_int g_open_count = 0;
static atomic_int g_close_count = 0;
static atomic_int g_close_reason = -1;
static atomic_int g_frames = 0;
static _Atomic uint64_t g_primary_conn = 0;
#ifndef _WIN32
static atomic_int g_primary_fd = -1;
#endif

static duct_result_t
on_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
        [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
        [[maybe_unused]] void *proto_state)
{
    auto handle = duct_session_conn_at(s, duct_conn_id_primary);
#ifndef _WIN32
    auto conn = duct_conn_by_handle(handle);
    duct_atomic_store(&g_primary_fd, conn ? conn->fd : -1, relaxed);
#endif
    duct_atomic_store(&g_primary_conn, handle.word, release);
    duct_atomic_fetch(add, &g_open_count, 1, relaxed);
    return rc_ok;
}

static void
on_close([[maybe_unused]] duct_session_t *s, duct_close_reason_t reason,
         [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_close_reason, (int)reason, relaxed);
    duct_atomic_fetch(add, &g_close_count, 1, relaxed);
}

static duct_result_t
on_dgram([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame, duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    auto data = frame->payload;
    duct_atomic_fetch(add, &g_frames, 1, relaxed);
    if (data.size == sizeof close_trigger - 1u
        && memcmp(data.data, close_trigger, data.size) == 0) {
        duct_response_respond_then_close(out, data, fl_send_copy, 0, close_normal);
        return rc_ok;
    }
    duct_response_same(out, data, fl_send_copy, 0);
    return rc_ok;
}

static void s_reset(void)
{
    duct_atomic_store(&g_open_count, 0, relaxed);
    duct_atomic_store(&g_close_count, 0, relaxed);
    duct_atomic_store(&g_close_reason, -1, relaxed);
    duct_atomic_store(&g_frames, 0, relaxed);
    duct_atomic_store(&g_primary_conn, 0u, relaxed);
#ifndef _WIN32
    duct_atomic_store(&g_primary_fd, -1, relaxed);
#endif
}

/** The session-close callback precedes the I/O-side reclaim of the conn. A
 * datagram sent before it reaches the closing conn, or its connected
 * SO_REUSEPORT socket where the platform has one, and is swallowed with the
 * peer's entry left in place: the listener prunes a dead entry on the first
 * datagram that finds it, and drops that datagram, so the reconnect after
 * it would be the one dropped. The reclaim bumps the generation ahead of the
 * socket close; wait for both before testing the dead-peer prune and the
 * same-address reconnect. */
static bool s_wait_primary_conn_reclaimed(void)
{
    duct_conn_handle_t handle = { .word = duct_atomic_load(&g_primary_conn, acquire) };
    if (!handle.word) {
        fprintf(stderr, "dgram_edge: on_open recorded no primary conn\n");
        return false;
    }
#ifndef _WIN32
    int fd = duct_atomic_load(&g_primary_fd, relaxed);
    if (fd < 0) {
        fprintf(stderr, "dgram_edge: on_open recorded no primary socket\n");
        return false;
    }
#endif
    bool live = true, sock_open = false;
    for (unsigned waited = 0u; waited <= close_wait_ms; ++waited) {
        live = duct_conn_by_handle(handle) != nullptr;
#ifndef _WIN32
        sock_open = fcntl(fd, F_GETFD) >= 0 || errno != EBADF;
#endif
        if (!live && !sock_open)
            return true;
        th_sleep_ms(1u);
    }
    fprintf(stderr, "dgram_edge: primary %s after %u ms\n",
            live ? "conn still resolves" : "socket still open", close_wait_ms);
    return false;
}

static duct_engine_t *s_make_engine_proto(size_t max_dgram, duct_proto_t **out_proto,
                                          uint16_t *out_port)
{
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return nullptr;
    auto wire = duct_wire_create_dgram_batch(max_dgram, false);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "udp-edge", .wire = wire,
        .on_frame = on_dgram, .on_session_open = on_open, .on_session_close = on_close,
        .max_response = 65535u,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    if (!proto) { duct_engine_destroy(io); return nullptr; }

    const duct_proto_t *protos[1] = { proto };
    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
            .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
        }, out_port, nullptr, 0u, nullptr) != rc_ok) {
        duct_proto_destroy(proto);
        duct_engine_destroy(io);
        return nullptr;
    }
    *out_proto = proto;
    return io;
}

/** @brief An empty datagram as the peer's first, then a normal one after it. */
static bool sc_zero_byte(void)
{
    s_reset();
    duct_proto_t *proto = nullptr;
    uint16_t port = 0u;
    auto io = s_make_engine_proto(0u, &proto, &port);
    if (!io) return false;

    pthread_t th;
    bool ok = pthread_create(&th, nullptr, th_run, io) == 0;
    duct_sock_t fd = ok ? uc_connect(port) : duct_sock_bad;
    ok = ok && fd != duct_sock_bad;

    /* Empty datagram: recvfrom() legitimately returns n==0. duct_response_same
     * treats payload.size==0 as "no response" (see duct_response_t doc), so
     * nothing comes back for this send — the frame count below is what shows it
     * reached the protocol at all. */
    ok = ok && uc_send(fd, "", 0u) == 0;

    static const char m[] = "after-empty";
    ok = ok && uc_send(fd, m, sizeof m - 1u) == 0
            && uc_recv_eq(fd, m, sizeof m - 1u) == 0;

    if (fd != duct_sock_bad) close(fd);
    duct_engine_stop(io);
    pthread_join(th, nullptr);

    ok = ok && duct_atomic_load(&g_open_count, acquire) == 1;
    ok = ok && duct_atomic_load(&g_frames, acquire) == 2;
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return ok;
}

/** @brief The same empty datagram, arriving once the per-peer socket exists.
 *
 *  A peer's first datagram is what spins that socket off, so @ref sc_zero_byte's
 *  own empty one is classified on the listener and never reaches it. The primer
 *  here is what moves this peer across, and its echo is what proves the move.
 */
static bool sc_zero_byte_established(void)
{
    s_reset();
    duct_proto_t *proto = nullptr;
    uint16_t port = 0u;
    auto io = s_make_engine_proto(0u, &proto, &port);
    if (!io) return false;

    pthread_t th;
    bool ok = pthread_create(&th, nullptr, th_run, io) == 0;
    duct_sock_t fd = ok ? uc_connect(port) : duct_sock_bad;
    ok = ok && fd != duct_sock_bad;

    static const char up[] = "up", m[] = "after-empty";
    ok = ok && uc_send(fd, up, sizeof up - 1u) == 0
            && uc_recv_eq(fd, up, sizeof up - 1u) == 0;
    ok = ok && uc_send(fd, "", 0u) == 0;
    ok = ok && uc_send(fd, m, sizeof m - 1u) == 0
            && uc_recv_eq(fd, m, sizeof m - 1u) == 0;

    if (fd != duct_sock_bad) close(fd);
    duct_engine_stop(io);
    pthread_join(th, nullptr);

    ok = ok && duct_atomic_load(&g_frames, acquire) == 3;
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return ok;
}

/** @brief Queue a burst in the kernel before the io thread exists, so the
 *  first drain reads several datagrams in one call and has to dispatch every
 *  one of them — the case a loopback client cannot produce once the reader is
 *  running, because it never falls behind. */
static bool sc_burst_before_start(void)
{
    s_reset();
    duct_proto_t *proto = nullptr;
    uint16_t port = 0u;
    auto io = s_make_engine_proto(0u, &proto, &port);
    if (!io) return false;

    static constexpr unsigned burst = 8u;
    duct_sock_t fd = uc_connect(port);
    bool ok = fd != duct_sock_bad;
    for (unsigned i = 0u; ok && i < burst; ++i) {
        char msg[16];
        int len = snprintf(msg, sizeof msg, "burst-%u", i);
        ok = uc_send(fd, msg, (size_t)len) == 0;
    }

    pthread_t th;
    ok = ok && pthread_create(&th, nullptr, th_run, io) == 0;

    for (unsigned i = 0u; ok && i < burst; ++i) {
        char want[16];
        int len = snprintf(want, sizeof want, "burst-%u", i);
        ok = uc_recv_eq(fd, want, (size_t)len) == 0;
    }

    if (fd != duct_sock_bad) close(fd);
    duct_engine_stop(io);
    if (ok) pthread_join(th, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return ok;
}

/** @brief Echo the largest datagram IPv4 UDP carries and compare it byte for
 *  byte, so a payload area short of one whole datagram shows up as a mismatch
 *  rather than as a shorter reply nobody checks. */
static bool sc_max_datagram(void)
{
    s_reset();
    duct_proto_t *proto = nullptr;
    uint16_t port = 0u;
    auto io = s_make_engine_proto(0u, &proto, &port);
    if (!io) return false;

    pthread_t th;
    bool ok = pthread_create(&th, nullptr, th_run, io) == 0;
    duct_sock_t fd = ok ? uc_connect(port) : duct_sock_bad;
    ok = ok && fd != duct_sock_bad;

    static constexpr size_t max_payload = 65507u;
    auto sent = duct_at(duct_new(char, max_payload));
    auto back = duct_at(duct_new(char, max_payload));
    ok = ok && sent && back;
    if (ok)
        for (size_t i = 0u; i < max_payload; ++i)
            sent[i] = (char)(i & 0xFFu);

    ok = ok && uc_send(fd, sent, max_payload) == 0;
    if (ok) {
        ssize_t got = uc_recv(fd, back, max_payload);
        ok = got == (ssize_t)max_payload && memcmp(back, sent, max_payload) == 0;
    }

    if (fd != duct_sock_bad) close(fd);
    duct_engine_stop(io);
    pthread_join(th, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    duct_del(sent);
    duct_del(back);
    return ok;
}

/** @brief A datagram past max_frame as the peer's first, then again on its own
 *  socket, each followed by one that must echo on the same session. */
static bool sc_oversize(void)
{
    s_reset();
    duct_proto_t *proto = nullptr;
    uint16_t port = 0u;
    static constexpr size_t max_dgram = 512u;
    auto io = s_make_engine_proto(max_dgram, &proto, &port);
    if (!io) return false;

    pthread_t th;
    bool ok = pthread_create(&th, nullptr, th_run, io) == 0;
    duct_sock_t fd = ok ? uc_connect(port) : duct_sock_bad;
    ok = ok && fd != duct_sock_bad;

    static const char big[max_dgram + 88u] = { 'x' }, up[] = "up", m[] = "after-oversize";
    ok = ok && uc_send(fd, big, sizeof big) == 0;
    ok = ok && uc_send(fd, up, sizeof up - 1u) == 0
            && uc_recv_eq(fd, up, sizeof up - 1u) == 0;
    ok = ok && uc_send(fd, big, sizeof big) == 0;
    ok = ok && uc_send(fd, m, sizeof m - 1u) == 0
            && uc_recv_eq(fd, m, sizeof m - 1u) == 0;
    ok = ok && duct_atomic_load(&g_close_count, acquire) == 0;

    if (fd != duct_sock_bad) close(fd);
    duct_engine_stop(io);
    pthread_join(th, nullptr);

    ok = ok && duct_atomic_load(&g_open_count, acquire) == 1;
    ok = ok && duct_atomic_load(&g_frames, acquire) == 2;
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return ok;
}

/* ── Scenario 2: worker-initiated respond-then-close on a udp_peer leg ──── */
static bool sc_respond_then_close(void)
{
    s_reset();
    duct_proto_t *proto = nullptr;
    uint16_t port = 0u;
    auto io = s_make_engine_proto(0u, &proto, &port);
    if (!io) return false;

    pthread_t th;
    bool ok = pthread_create(&th, nullptr, th_run, io) == 0;
    duct_sock_t fd = ok ? uc_connect(port) : duct_sock_bad;
    ok = ok && fd != duct_sock_bad;

    static const char m[] = "hello";
    ok = ok && uc_send(fd, m, sizeof m - 1u) == 0
            && uc_recv_eq(fd, m, sizeof m - 1u) == 0;

    /* Respond-then-close: the echo of close_trigger must still land (TX
     * drains before the I/O thread quiesces the conn). */
    ok = ok && uc_send(fd, close_trigger, sizeof close_trigger - 1u) == 0
            && uc_recv_eq(fd, close_trigger, sizeof close_trigger - 1u) == 0;
    ok = ok && th_wait_int(&g_close_count, 1, close_wait_ms);
    ok = ok && s_wait_primary_conn_reclaimed();

    /* Session is gone: a further datagram from the same peer must not echo
     * (the old per-peer socket is closed; nothing revives the session). */
    static const char m2[] = "post-close";
    ok = ok && uc_send(fd, m2, sizeof m2 - 1u) == 0
            && uc_recv_none(fd, 300) == 0;

    /* T14: the datagram just dropped above pruned
     * this peer's dead dgram_peers entry on the spot — the *next* one
     * from the same 5-tuple must resolve as a brand new session, not stay
     * blocked until some unrelated peer's traffic happens to sweep it. */
    static const char m3[] = "reconnect";
    ok = ok && uc_send(fd, m3, sizeof m3 - 1u) == 0
            && uc_recv_eq(fd, m3, sizeof m3 - 1u) == 0;
    ok = ok && duct_atomic_load(&g_open_count, acquire) == 2;

    if (fd != duct_sock_bad) close(fd);
    duct_engine_stop(io);
    pthread_join(th, nullptr);

    ok = ok && duct_atomic_load(&g_close_reason, relaxed) == (int)close_normal;
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return ok;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    int pass = 1;

    if (!sc_zero_byte()) { fprintf(stderr, "dgram_edge: zero_byte failed\n"); pass = 0; }
    if (!sc_zero_byte_established()) { fprintf(stderr, "dgram_edge: zero_byte_established failed\n"); pass = 0; }
#ifndef __APPLE__
    /* Darwin's loopback MTU, 16384, is under a 65,507-byte datagram, and the
     * engine's echo carries DF. */
    if (!sc_max_datagram()) { fprintf(stderr, "dgram_edge: max-size datagram failed\n"); pass = 0; }
#endif
    if (!sc_oversize()) { fprintf(stderr, "dgram_edge: oversize datagram failed\n"); pass = 0; }
    if (!sc_burst_before_start()) { fprintf(stderr, "dgram_edge: queued burst failed\n"); pass = 0; }
    if (!sc_respond_then_close()) { fprintf(stderr, "dgram_edge: respond_then_close failed\n"); pass = 0; }

    if (pass) {
        printf("dgram_edge: OK (zero-length and max-size datagrams, queued burst, "
               "respond-then-close)\n");
        return 0;
    }
    return 1;
}
