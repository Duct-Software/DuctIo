/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file listener_close_test.c
 * @brief Acceptance test: mid-life @ref duct_listener_close, stream and
 * datagram. Exercises the IOCP-exclusive cancel path that previously could race a
 * still-pending @c AcceptEx / @c WSARecvFrom completion into memory the
 * portable side had already freed.
 *
 * Both cases: revoke the listener while it still has live traffic riding
 * through it, and confirm the listener itself is genuinely gone. The stream
 * case additionally confirms an already-accepted conn is unaffected — true
 * on every platform. The datagram case's post-close expectation instead
 * diverges by platform (`#ifdef _WIN32` inside @ref s_test_dgram): Linux
 * keeps echoing (a per-peer conn's own connected socket has independent RX,
 * `SO_REUSEPORT`), Windows expects the round-trip to fail cleanly (every
 * spun-off conn loses its only RX path — the listener's own classification
 * socket — the instant it closes, so revocation cascades into closing them
 * too; 2a).
 */

#define TH_CONNECT_RETRY_MS 500u

#include "duct.h"
#include "test_helpers.h"
#include "dgram_test_helpers.h"

#include <stdio.h>

static duct_result_t
on_frame_echo([[maybe_unused]] duct_session_t *s,
              [[maybe_unused]] duct_conn_id_t conn_id,
              const duct_frame_t *frame,
              duct_response_t *out,
              [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

static duct_result_t
on_dgram_echo([[maybe_unused]] duct_session_t *s,
              [[maybe_unused]] duct_conn_id_t conn_id,
              const duct_frame_t *frame,
              duct_response_t *out,
              [[maybe_unused]] void *proto_state)
{
    duct_response_same(out, frame->payload, fl_send_copy, 0);
    return rc_ok;
}

/** @brief Plain, non-retrying connect attempt — used only to prove a port
 *  now refuses, where @ref th_connect's own retry loop would instead spend
 *  its whole budget waiting for a listener that is never coming back. */
static int s_expect_connect_refused(uint16_t port)
{
    duct_sock_t fd = (duct_sock_t)socket(AF_INET, SOCK_STREAM, 0);
    if (fd == duct_sock_bad)
        return -1;
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof addr);
    duct_sock_close(fd);
    return rc == 0 ? -1 : 0;
}

static int s_test_stream(void)
{
    int pass = 1;
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) { fprintf(stderr, "listener_close/stream: io create failed\n"); return 0; }

    auto wire = duct_wire_create_length_prefix(0u);
    if (!wire) { fprintf(stderr, "listener_close/stream: wire create failed\n"); duct_engine_destroy(io); return 0; }
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "listener-close-stream", .wire = wire, .on_frame = on_frame_echo,
    });
    if (!proto) {
        fprintf(stderr, "listener_close/stream: proto create failed\n");
        duct_engine_destroy(io); duct_wire_destroy(wire);
        return 0;
    }

    uint16_t port = 0u;
    duct_sock_t fds[4] = {};
    unsigned n_fds = 0u;
    const duct_proto_t *protos[1] = { proto };
    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_stream,
            .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
        }, &port, fds, 4u, &n_fds) != rc_ok || n_fds != 1u) {
        fprintf(stderr, "listener_close/stream: bind failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(wire);
        return 0;
    }
    pthread_t th;
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        fprintf(stderr, "listener_close/stream: thread create failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(wire);
        return 0;
    }

    duct_sock_t fd = th_connect(port);
    if (fd == duct_sock_bad) { fprintf(stderr, "listener_close/stream: connect failed\n"); pass = 0; goto stop; }

    static const char m1[] = "before-close";
    if (th_send(fd, m1, sizeof m1 - 1u) != 0 || th_recv_eq(fd, m1, sizeof m1 - 1u) != 0) {
        fprintf(stderr, "listener_close/stream: round-trip before close failed\n");
        pass = 0;
    }

    if (duct_listener_close(io, fds[0]) != rc_ok) {
        fprintf(stderr, "listener_close/stream: duct_listener_close failed\n");
        pass = 0;
    }

    /* Revocation must not touch the already-accepted conn. */
    static const char m2[] = "after-close-still-alive";
    if (th_send(fd, m2, sizeof m2 - 1u) != 0 || th_recv_eq(fd, m2, sizeof m2 - 1u) != 0) {
        fprintf(stderr, "listener_close/stream: round-trip after close failed\n");
        pass = 0;
    }

    if (s_expect_connect_refused(port) != 0) {
        fprintf(stderr, "listener_close/stream: fresh connect to closed listener unexpectedly succeeded\n");
        pass = 0;
    }

    duct_sock_close(fd);

stop:
    duct_engine_stop(io);
    pthread_join(th, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    duct_wire_destroy(wire);
    return pass;
}

static int s_test_dgram(void)
{
    int pass = 1;
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) { fprintf(stderr, "listener_close/dgram: io create failed\n"); return 0; }

    auto wire = duct_wire_create_dgram_batch(0u, false);
    if (!wire) { fprintf(stderr, "listener_close/dgram: wire create failed\n"); duct_engine_destroy(io); return 0; }
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "listener-close-dgram", .wire = wire, .on_frame = on_dgram_echo,
        .max_response = 65535u,
    });
    if (proto)
        proto->owned_wire = wire;
    else
        duct_wire_destroy(wire);
    if (!proto) { fprintf(stderr, "listener_close/dgram: proto create failed\n"); duct_engine_destroy(io); return 0; }

    uint16_t port = 0u;
    duct_sock_t fds[4] = {};
    unsigned n_fds = 0u;
    const duct_proto_t *protos[1] = { proto };
    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
            .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
        }, &port, fds, 4u, &n_fds) != rc_ok || n_fds != 1u) {
        fprintf(stderr, "listener_close/dgram: bind failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto);
        return 0;
    }
    pthread_t th;
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        fprintf(stderr, "listener_close/dgram: thread create failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto);
        return 0;
    }

    duct_sock_t fd = uc_connect(port);
    if (fd == duct_sock_bad) { fprintf(stderr, "listener_close/dgram: client connect failed\n"); pass = 0; goto stop; }

    /* First round-trip spins off the per-peer socket + session (same as
     * dgram_test.c) — the listener is revoked only after this exists. */
    static const char m1[] = "before-close-dgram";
    if (uc_send(fd, m1, sizeof m1 - 1u) != 0 || uc_recv_eq(fd, m1, sizeof m1 - 1u) != 0) {
        fprintf(stderr, "listener_close/dgram: round-trip before close failed\n");
        pass = 0;
    }

    if (duct_listener_close(io, fds[0]) != rc_ok) {
        fprintf(stderr, "listener_close/dgram: duct_listener_close failed\n");
        pass = 0;
    }

    static const char m2[] = "after-close-dgram-still-alive";
#ifdef _WIN32
    /* Windows platform limitation, not a bug: an x_udp_peer conn has no RX
     * of its own there (2a) — every one of them
     * loses its only RX path the instant the listener's own classification
     * socket closes, so the listener's own revocation cascades into closing
     * every conn it ever spun off (s_msg_exec_listener_close, src/duct_io.c)
     * rather than leaving unreachable zombies. Expect the round-trip to
     * fail cleanly here — a connected UDP client sees the server-side close
     * as a deferred ICMP-derived error on its next recv() — not to succeed
     * the way it does on Linux, where a live per-peer conn keeps its own
     * independent RX regardless of the listener's own lifecycle. */
    char buf[64];
    if (uc_send(fd, m2, sizeof m2 - 1u) != 0) {
        fprintf(stderr, "listener_close/dgram: send after close unexpectedly failed\n");
        pass = 0;
    } else if (uc_recv(fd, buf, sizeof buf) >= 0) {
        fprintf(stderr, "listener_close/dgram: unexpected reply after close\n");
        pass = 0;
    }
#else
    /* The spun-off per-peer conn is independent of the classification
     * socket the close just cancelled — it must keep echoing. */
    if (uc_send(fd, m2, sizeof m2 - 1u) != 0 || uc_recv_eq(fd, m2, sizeof m2 - 1u) != 0) {
        fprintf(stderr, "listener_close/dgram: round-trip after close failed\n");
        pass = 0;
    }
#endif

    close(fd);

stop:
    duct_engine_stop(io);
    pthread_join(th, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return pass;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    int pass = 1;

    if (!s_test_stream()) {
        fprintf(stderr, "listener_close: stream case failed\n");
        pass = 0;
    } else {
        printf("listener_close: stream OK (live conn survives close, fresh connect refused)\n");
    }

    if (!s_test_dgram()) {
        fprintf(stderr, "listener_close: dgram case failed\n");
        pass = 0;
    } else {
        printf("listener_close: dgram OK (spun-off peer survives classification-socket close)\n");
    }

    return pass ? 0 : 1;
}
