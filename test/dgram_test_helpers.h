/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file dgram_test_helpers.h
 * @brief Shared UDP client helpers for duct_listener_bind tests. Include after
 * "duct.h" and "test_helpers.h" (the latter for th_run / th_wait_int).
 *
 * Tunables (define before include, or accept defaults):
 *   TH_DGRAM_RECV_TIMEOUT_MS — poll timeout for uc_recv (default 2000)
 */

#ifndef DUCT_DGRAM_TEST_HELPERS_H
#define DUCT_DGRAM_TEST_HELPERS_H

/* Socket/poll headers, close()/read()/write() redirects, and struct pollfd
 * itself all come from test_helpers.h, required to be included first (see
 * @file) — nothing further needed here on either platform. */
#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifndef TH_DGRAM_RECV_TIMEOUT_MS
#define TH_DGRAM_RECV_TIMEOUT_MS 2000
#endif

/** @brief Portable "last socket error" accessor — Winsock does not reliably
 *  populate errno, so poll()/recv() failures must read WSAGetLastError() on
 *  Windows instead. */
static inline int uc_last_error(void)
{
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

static inline bool uc_is_eintr(int err)
{
#ifdef _WIN32
    return err == WSAEINTR;
#else
    return err == EINTR;
#endif
}

/** @brief Connected UDP client socket to the IPv4 address @p ip, port @p port;
 *  plain send/recv, no address needed per call. Returns the socket or
 *  duct_sock_bad. */
static inline duct_sock_t uc_connect_to(const char *ip, uint16_t port)
{
    duct_sock_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == duct_sock_bad)
        return duct_sock_bad;
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, ip, &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return duct_sock_bad;
    }
    return fd;
}

/** @brief Connected UDP client socket to 127.0.0.1:@p port. Returns the socket
 *  or duct_sock_bad. */
static inline duct_sock_t uc_connect(uint16_t port)
{
    return uc_connect_to("127.0.0.1", port);
}

/** @brief UDP socket bound to an ephemeral port on 127.0.0.1, the port in
 *  @p out_port. Returns the socket or duct_sock_bad. */
static inline duct_sock_t uc_bind(uint16_t *out_port)
{
    duct_sock_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == duct_sock_bad)
        return duct_sock_bad;
    struct sockaddr_in a = { .sin_family = AF_INET };
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    socklen_t alen = sizeof a;
    if (bind(fd, (struct sockaddr *)&a, alen) != 0
        || getsockname(fd, (struct sockaddr *)&a, &alen) != 0) {
        close(fd);
        return duct_sock_bad;
    }
    *out_port = ntohs(a.sin_port);
    return fd;
}

/** @brief Send one whole datagram. 0 on success. */
static inline int uc_send(duct_sock_t fd, const void *data, size_t len)
{
    return send(fd, (const char *)data, (int)len, 0) == (ssize_t)len ? 0 : -1;
}

/** @brief Recv one datagram into @p buf (max @p bufsize), bounded by
 *  TH_DGRAM_RECV_TIMEOUT_MS. Returns payload size or -1 on timeout/error —
 *  classifies and logs which of three distinct outcomes actually happened
 *  instead of collapsing them into one blind -1: poll() timeout, an
 *  error-class poll() event (POLLERR/POLLHUP — a pending ICMP-derived socket
 *  error on a connected UDP socket surfaces exactly this way, with no
 *  datagram queued at all), or poll() itself failing (retried internally on
 *  EINTR; anything else is logged and reported as -1). */
static inline ssize_t uc_recv(duct_sock_t fd, char *buf, size_t bufsize)
{
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int rc;
    for (;;) {
        rc = poll(&pfd, 1, TH_DGRAM_RECV_TIMEOUT_MS);
        if (rc >= 0)
            break;
        int err = uc_last_error();
        if (uc_is_eintr(err))
            continue;
        fprintf(stderr, "uc_recv: poll() failed, err=%d\n", err);
        return -1;
    }
    if (rc == 0) {
        fprintf(stderr, "uc_recv: poll() timeout\n");
        return -1;
    }
    if (pfd.revents & (POLLERR | POLLHUP)) {
        fprintf(stderr, "uc_recv: error-class poll() event, revents=0x%x\n", (unsigned)pfd.revents);
        return -1;
    }
    ssize_t got = recv(fd, buf, (int)bufsize, 0);
    if (got < 0)
        fprintf(stderr, "uc_recv: recv() failed after POLLIN, err=%d\n", uc_last_error());
    return got;
}

/** @brief Receive one datagram and assert exact match with @p expected. */
static inline int uc_recv_eq(duct_sock_t fd, const char *expected, size_t elen)
{
    char buf[1024] = {};
    ssize_t got = uc_recv(fd, buf, sizeof(buf));
    return got >= 0 && (size_t)got == elen && memcmp(buf, expected, elen) == 0 ? 0 : -1;
}

/** @brief Assert no datagram arrives within @p timeout_ms. Returns 0 (pass)
 *  only on a genuine poll() timeout; any readiness at all — real data, or an
 *  error-class event (POLLERR/POLLHUP) — is -1, classified and logged so a
 *  catch can tell "peer actually replied" apart from "pending socket-level
 *  error, nothing queued" (see uc_recv's own doc). poll() failing outright
 *  is retried on EINTR, logged and reported as -1 otherwise. */
static inline int uc_recv_none(duct_sock_t fd, int timeout_ms)
{
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int rc;
    for (;;) {
        rc = poll(&pfd, 1, timeout_ms);
        if (rc >= 0)
            break;
        int err = uc_last_error();
        if (uc_is_eintr(err))
            continue;
        fprintf(stderr, "uc_recv_none: poll() failed, err=%d\n", err);
        return -1;
    }
    if (rc == 0)
        return 0;
    if (pfd.revents & (POLLERR | POLLHUP)) {
        fprintf(stderr, "uc_recv_none: unexpected error-class event, revents=0x%x\n", (unsigned)pfd.revents);
        return -1;
    }
    char buf[1024] = {};
    ssize_t got = recv(fd, buf, sizeof buf, 0);
    if (got < 0)
        fprintf(stderr, "uc_recv_none: unexpected readiness, recv() failed, err=%d\n", uc_last_error());
    else
        fprintf(stderr, "uc_recv_none: unexpected reply: %zd bytes: '%.*s'\n",
                got, (int)(got > 0 ? got : 0), buf);
    return -1;
}

#endif /* DUCT_DGRAM_TEST_HELPERS_H */
