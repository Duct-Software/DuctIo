/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file wire_test.c
 * @brief Wire layer litmus tests.
 *
 *   1. split_frame  — partial frame across two reads
 *   2. header_split — partial 4-byte header across reads
 *   3. multi_frame  — multiple frames coalesced in one read
 *   4. tx_full      — no dangling header on TX full
 *   5. defer        — no double-queue on defer
 *   6. malformed    — malformed frame triggers on_error
 *   7. malformed_pipeline — a valid frame pipelined right before a
 *      malformed one still gets its response delivered (graceful close)
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>

static uint16_t th_port = 0;
static atomic_int s_error_count = 0;

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
on_error_count([[maybe_unused]] duct_session_t *s,
              [[maybe_unused]] duct_result_t error,
              [[maybe_unused]] duct_response_t *out,
              [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &s_error_count, 1, relaxed);
    return rc_ok;
}

/* ── Tests ───────────────────────────────────────────────────────── */

static const char *test_split_frame(duct_engine_t *io, duct_proto_t *proto)
{
    (void)io; (void)proto;
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    const char *msg = "hello-split-frame-test";
    size_t len = strlen(msg);
    uint8_t hdr[4] = {
        (uint8_t)(len >> 24u), (uint8_t)(len >> 16u),
        (uint8_t)(len >>  8u), (uint8_t)(len),
    };
    /* Send header only, then payload after a delay. */
    if (write(fd, hdr, 4u) != 4) { close(fd); return "short header write"; }
    struct timespec ts = { .tv_nsec = 50L * 1000L * 1000L };
    nanosleep(&ts, nullptr);
    if (write(fd, msg, len) != (ssize_t)len) { close(fd); return "short payload write"; }

    char buf[128] = {};
    ssize_t got = th_recv(fd, buf, sizeof(buf));
    close(fd);
    if (got != (ssize_t)len || memcmp(buf, msg, len) != 0)
        return "split frame: mismatch";
    return nullptr;
}

static const char *test_header_split(duct_engine_t *io, duct_proto_t *proto)
{
    (void)io; (void)proto;
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    const char *msg = "header-split-probe";
    size_t len = strlen(msg);
    uint8_t hdr[4] = {
        (uint8_t)(len >> 24u), (uint8_t)(len >> 16u),
        (uint8_t)(len >>  8u), (uint8_t)(len),
    };
    struct timespec ts = { .tv_nsec = 50L * 1000L * 1000L };
    if (write(fd, hdr, 2u) != 2) { close(fd); return "short write 1"; }
    nanosleep(&ts, nullptr);
    if (write(fd, hdr + 2, 2u) != 2) { close(fd); return "short write 2"; }
    nanosleep(&ts, nullptr);
    if (write(fd, msg, len) != (ssize_t)len) { close(fd); return "short payload"; }

    char buf[128] = {};
    ssize_t got = th_recv(fd, buf, sizeof(buf));
    close(fd);
    if (got != (ssize_t)len || memcmp(buf, msg, len) != 0)
        return "header split: mismatch";
    return nullptr;
}

static const char *test_multi_frame(duct_engine_t *io, duct_proto_t *proto)
{
    (void)io; (void)proto;
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    static const char *msgs[] = { "frame-one", "frame-two", "frame-three" };
    static constexpr unsigned n = sizeof(msgs) / sizeof(msgs[0]);

    uint8_t buf[512];
    size_t off = 0u;
    for (unsigned i = 0u; i < n; ++i) {
        size_t len = strlen(msgs[i]);
        buf[off++] = (uint8_t)(len >> 24u); buf[off++] = (uint8_t)(len >> 16u);
        buf[off++] = (uint8_t)(len >>  8u); buf[off++] = (uint8_t)(len);
        memcpy(buf + off, msgs[i], len);
        off += len;
    }
    if (write(fd, buf, off) != (ssize_t)off) { close(fd); return "coalesced write"; }

    char rbuf[128] = {};
    for (unsigned i = 0u; i < n; ++i) {
        ssize_t got = th_recv(fd, rbuf, sizeof(rbuf));
        if (got != (ssize_t)strlen(msgs[i]) || memcmp(rbuf, msgs[i], got) != 0) {
            close(fd);
            return "multi frame: mismatch";
        }
    }
    close(fd);
    return nullptr;
}

static const char *test_tx_full(duct_engine_t *io, duct_proto_t *proto)
{
    (void)io; (void)proto;
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    const char *msg = "tx-full-probe-1234567890";
    size_t len = strlen(msg);
    unsigned sent = 0u;
    for (unsigned i = 0u; i < 5000u; ++i) {
        if (th_send(fd, msg, len) != 0) break;
        ++sent;
    }
    char rbuf[128] = {};
    unsigned received = 0u;
    for (unsigned i = 0u; i < sent; ++i) {
        ssize_t got = th_recv(fd, rbuf, sizeof(rbuf));
        if (got < 0) break;
        if ((size_t)got != len) { close(fd); return "tx full: corrupted frame"; }
        ++received;
    }
    close(fd);
    return received > 0u ? nullptr : "tx full: no responses";
}

static const char *test_defer(duct_engine_t *io, duct_proto_t *proto)
{
    (void)io; (void)proto;
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    static const char *msgs[] = { "defer-a", "defer-b", "defer-c", "defer-d", "defer-e" };
    static constexpr unsigned n = sizeof(msgs) / sizeof(msgs[0]);
    for (unsigned i = 0u; i < n; ++i) {
        if (th_send(fd, msgs[i], strlen(msgs[i])) != 0) { close(fd); return "send failed"; }
    }
    char rbuf[128] = {};
    for (unsigned i = 0u; i < n; ++i) {
        ssize_t got = th_recv(fd, rbuf, sizeof(rbuf));
        if (got != (ssize_t)strlen(msgs[i]) || memcmp(rbuf, msgs[i], got) != 0) {
            close(fd);
            return "defer: mismatch";
        }
    }
    close(fd);
    return nullptr;
}

static const char *test_malformed(duct_engine_t *io, duct_proto_t *proto)
{
    (void)io; (void)proto;
    duct_atomic_store(&s_error_count, 0, relaxed);

    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    /* Give session_open a chance to bind before the malformed header lands;
     * a conn still fence_unbound on close is dropped silently, no on_error
     *. */
    struct timespec pre_ts = { .tv_nsec = 50L * 1000L * 1000L };
    nanosleep(&pre_ts, nullptr);

    uint8_t bad_hdr[4] = { 0x00, 0x20, 0x00, 0x00 }; /* 2 MiB */
    if (write(fd, bad_hdr, 4u) != 4) { close(fd); return "short write"; }

    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    if (poll(&pfd, 1, TH_ROUNDTRIP_TIMEOUT_MS) > 0) {
        char tmp[4] = {};
        read(fd, tmp, sizeof(tmp));
    }
    struct timespec ts = { .tv_nsec = 200L * 1000L * 1000L };
    nanosleep(&ts, nullptr);
    close(fd);

    return duct_atomic_load(&s_error_count, acquire) >= 1
           ? nullptr : "malformed: on_error did not fire";
}

/** @brief A valid frame pipelined right before a malformed one, in
 *  the same write() (so both land in one recv()/parse pass), must still get
 *  its echoed response delivered — the conn closes gracefully (TX drains)
 *  rather than dropping already-computed responses (fatal close). */
static const char *test_malformed_pipeline(duct_engine_t *io, duct_proto_t *proto)
{
    (void)io; (void)proto;
    duct_atomic_store(&s_error_count, 0, relaxed);

    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) return "connect failed";

    struct timespec pre_ts = { .tv_nsec = 50L * 1000L * 1000L };
    nanosleep(&pre_ts, nullptr);

    const char *msg = "pipeline-before-error";
    size_t len = strlen(msg);
    uint8_t buf[64];
    size_t off = 0u;
    buf[off++] = (uint8_t)(len >> 24u); buf[off++] = (uint8_t)(len >> 16u);
    buf[off++] = (uint8_t)(len >>  8u); buf[off++] = (uint8_t)(len);
    memcpy(buf + off, msg, len);
    off += len;
    buf[off++] = 0x00; buf[off++] = 0x20; buf[off++] = 0x00; buf[off++] = 0x00; /* 2 MiB: malformed */
    if (write(fd, buf, off) != (ssize_t)off) { close(fd); return "pipeline write failed"; }

    char rbuf[128] = {};
    ssize_t got = th_recv(fd, rbuf, sizeof(rbuf));
    if (got != (ssize_t)len || memcmp(rbuf, msg, (size_t)got) != 0) {
        close(fd);
        return "pipeline: valid frame's response missing or corrupted";
    }

    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    bool closed = false;
    if (poll(&pfd, 1, TH_ROUNDTRIP_TIMEOUT_MS) > 0) {
        ssize_t n = read(fd, rbuf, sizeof(rbuf));
        closed = (n == 0);
    }
    close(fd);
    if (!closed)
        return "pipeline: conn did not close after the malformed frame";

    /* The socket close observed above lands in s_conn_close ahead of the
     * conn_lost fence it publishes — on_error fires only once the worker
     * later drains that fence, same asynchronous gap test_malformed waits
     * out below. */
    struct timespec post_ts = { .tv_nsec = 200L * 1000L * 1000L };
    nanosleep(&post_ts, nullptr);
    return duct_atomic_load(&s_error_count, acquire) >= 1
           ? nullptr : "pipeline: on_error did not fire";
}

/* ── Main ────────────────────────────────────────────────────────── */

typedef const char *(*test_fn)(duct_engine_t *, duct_proto_t *);

static struct { const char *name; test_fn fn; } s_tests[] = {
    { "split_frame",  test_split_frame },
    { "header_split", test_header_split },
    { "multi_frame",  test_multi_frame },
    { "tx_full",      test_tx_full },
    { "defer",        test_defer },
    { "malformed",    test_malformed },
    { "malformed_pipeline", test_malformed_pipeline },
};

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    int pass = 1;

    for (unsigned t = 0u; t < sizeof(s_tests) / sizeof(s_tests[0]); ++t) {
        auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
        if (!io) { fprintf(stderr, "wire_test: %s: io failed\n", s_tests[t].name); pass = 0; continue; }
        auto wire = duct_wire_create_length_prefix(0u);
        if (!wire) { duct_engine_destroy(io); fprintf(stderr, "wire_test: %s: wire failed\n", s_tests[t].name); pass = 0; continue; }
        bool need_err = (s_tests[t].fn == test_malformed || s_tests[t].fn == test_malformed_pipeline);
        auto proto = duct_proto_create(&(duct_proto_cfg_t){
            .name = "wire-test", .wire = wire,
            .on_frame = on_frame_echo,
            .on_error = need_err ? on_error_count : nullptr,
        });
        if (!proto) { duct_engine_destroy(io); duct_wire_destroy(wire); pass = 0; continue; }

        th_port = 0;
        if (duct_io_listen(io, "127.0.0.1", &th_port, proto) != rc_ok) {
            duct_proto_destroy(proto); duct_engine_destroy(io); duct_wire_destroy(wire);
            pass = 0; continue;
        }
        pthread_t th;
        if (pthread_create(&th, nullptr, th_run, io) != 0) {
            duct_proto_destroy(proto); duct_engine_destroy(io); duct_wire_destroy(wire);
            pass = 0; continue;
        }

        const char *err = s_tests[t].fn(io, proto);

        duct_engine_stop(io);
        pthread_join(th, nullptr);
        duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(wire);

        if (err) { fprintf(stderr, "wire_test: %s: FAIL: %s\n", s_tests[t].name, err); pass = 0; }
        else printf("wire_test: %s: OK\n", s_tests[t].name);
    }
    return pass ? 0 : 1;
}
