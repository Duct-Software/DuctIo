/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file test_helpers.h
 * @brief Shared test helpers: io thread, LP wire framing, connect, polling.
 *
 * Each test TU keeps its own callbacks and globals; this header supplies the
 * boilerplate that was duplicated across 7+ files. Include after "duct.h".
 *
 * Tunables (define before include, or accept defaults):
 *   TH_CONNECT_RETRY_MS  — client connect retry budget (default 1500)
 *   TH_ROUNDTRIP_TIMEOUT_MS — poll timeout for recv (default 3000)
 */

#ifndef DUCT_TEST_HELPERS_H
#define DUCT_TEST_HELPERS_H

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    /* winsock2.h's own WSAPOLLFD is `typedef struct pollfd { SOCKET fd;
     * short events; short revents; } WSAPOLLFD` — struct pollfd already
     * exists under that exact tag with matching field names, no redirect
     * needed for it. Only the function name differs from POSIX. */
    #define poll(fds, n, timeout) WSAPoll((fds), (n), (timeout))
    /* Test files call these on sockets only (never a real file), so a
     * direct redirect to the Winsock equivalents is safe here — narrower
     * than a true POSIX read()/write()/close(), but this codebase's tests
     * never rely on the difference. */
    #define close(fd) closesocket(fd)
    #define read(fd, buf, n) recv((fd), (char *)(buf), (int)(n), 0)
    #define write(fd, buf, n) send((fd), (const char *)(buf), (int)(n), 0)
    #ifndef SHUT_RDWR
    #define SHUT_RDWR SD_BOTH
    #endif
    #ifndef SHUT_WR
    #define SHUT_WR SD_SEND
    #endif
    /* No writev() on Windows — same two-send shape as th_send's own body,
     * generalized to iov_len == 0 entries (a la POSIX). Returns the total
     * sent, or -1 on any short/failed send, same contract as real writev(). */
    struct iovec { void *iov_base; size_t iov_len; };
    static inline ssize_t writev(duct_sock_t fd, const struct iovec *iov, int iovcnt)
    {
        ssize_t total = 0;
        for (int i = 0; i < iovcnt; ++i) {
            if (iov[i].iov_len == 0u)
                continue;
            int sent = send(fd, (const char *)iov[i].iov_base, (int)iov[i].iov_len, 0);
            if (sent != (int)iov[i].iov_len)
                return -1;
            total += sent;
        }
        return total;
    }
    #include <afunix.h>
    #ifndef AF_UNIX
    #define AF_UNIX 1
    #endif
    /**
     * @brief POSIX socketpair(AF_UNIX, SOCK_STREAM, 0, sv) has no Windows
     * equivalent — approximate it with a connected loopback TCP pair (connect
     * back to an ephemeral listener on 127.0.0.1, accept, drop the listener),
     * the same technique libuv/CPython use for their own Windows socketpair()
     * shims. Behaviorally equivalent for these tests' purposes (a
     * bidirectional, pollable byte stream); not a real AF_UNIX socket, so
     * nothing AF_UNIX-specific (credential passing, etc.) would be. @p domain
     * / @p protocol are ignored — @p type is always SOCK_STREAM in this
     * codebase's tests. Returns 0 on success, -1 on failure, matching
     * socketpair's own contract.
     */
    static inline int th_socketpair(int domain, int type, int protocol, duct_sock_t sv[2])
    {
        duct_discard domain;
        duct_discard type;
        duct_discard protocol;
        duct_sock_t listener = socket(AF_INET, SOCK_STREAM, 0);
        if (listener == duct_sock_bad)
            return -1;
        struct sockaddr_in addr = { .sin_family = AF_INET };
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        if (bind(listener, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(listener, 1) != 0) {
            closesocket(listener);
            return -1;
        }
        int alen = sizeof addr;
        if (getsockname(listener, (struct sockaddr *)&addr, &alen) != 0) {
            closesocket(listener);
            return -1;
        }
        duct_sock_t client = socket(AF_INET, SOCK_STREAM, 0);
        if (client == duct_sock_bad) {
            closesocket(listener);
            return -1;
        }
        if (connect(client, (struct sockaddr *)&addr, sizeof addr) != 0) {
            closesocket(listener);
            closesocket(client);
            return -1;
        }
        duct_sock_t server = accept(listener, nullptr, nullptr);
        closesocket(listener);
        if (server == duct_sock_bad) {
            closesocket(client);
            return -1;
        }
        sv[0] = server;
        sv[1] = client;
        return 0;
    }
    #define socketpair(domain, type, protocol, sv) th_socketpair((domain), (type), (protocol), (sv))
#else
    #include <arpa/inet.h>
    #include <fcntl.h>
    #include <netinet/in.h>
    #include <poll.h>
    #include <sys/socket.h>
    #include <sys/uio.h>
    #include <sys/un.h>
    #include <unistd.h>
#endif

/** @brief Set @p fd non-blocking — portable substitute for Linux's
 *  SOCK_NONBLOCK socket() flag (a Linux-only extension, no BSD/Windows
 *  equivalent at all). */
static inline void th_set_nonblock(duct_sock_t fd)
{
#ifdef _WIN32
    u_long one = 1u;
    ioctlsocket(fd, FIONBIO, &one);
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#ifndef TH_CONNECT_RETRY_MS
#define TH_CONNECT_RETRY_MS 1500u
#endif

#ifndef TH_ROUNDTRIP_TIMEOUT_MS
#define TH_ROUNDTRIP_TIMEOUT_MS 3000
#endif

#ifdef _WIN32
/**
 * @brief Defensive, idempotent Winsock init for this test binary.
 *
 * The library's own os/windows/duct_core.c constructor already calls
 * WSAStartup for any test linking ductio (that TU defines duct_vm_new /
 * duct_futex_wait, pulled in by essentially every code path, so it is never
 * dropped by the linker) — but a header-level constructor here means this
 * header's own raw Winsock calls (socket/connect/WSAPoll) never depend on
 * link order or on the test happening to touch a duct_* symbol first.
 * WSAStartup is reference-counted; calling it again when already
 * initialized is harmless — see duct_core.c's own duct_ctor.
 */
static void th_wsa_ctor(void) __attribute__((constructor));
static void th_wsa_ctor(void)
{
    WSADATA wsa;
    int rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    duct_discard rc;
}
#endif

/* ── Thread helpers ──────────────────────────────────────────────── */

static inline void *th_run(void *arg)
{
    (void)duct_engine_wait((duct_engine_t *)arg);
    return nullptr;
}

/* ── Portable sleep ──────────────────────────────────────────────── */

static inline void th_sleep_ms(unsigned ms)
{
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec ts = { .tv_sec = (time_t)(ms / 1000u), .tv_nsec = (long)(ms % 1000u) * 1000000L };
    nanosleep(&ts, nullptr);
#endif
}

/* ── Client connect ──────────────────────────────────────────────── */

/** @brief Connect a stream socket of @p family to @p addr with retry, for @c TH_CONNECT_RETRY_MS.
 *  Returns the socket or @c duct_sock_bad. */
static inline duct_sock_t th_connect_addr(int family, const struct sockaddr *addr, int addrlen)
{
    for (unsigned waited = 0u; waited < TH_CONNECT_RETRY_MS; waited += 10u) {
        duct_sock_t fd = (duct_sock_t)socket(family, SOCK_STREAM, 0);
        if (fd == duct_sock_bad)
            return duct_sock_bad;
        if (connect(fd, addr, addrlen) == 0)
            return fd;
        duct_sock_close(fd);
        th_sleep_ms(10u);
    }
    return duct_sock_bad;
}

/** @brief Connect to 127.0.0.1:@p port with retry. Returns the socket or @c duct_sock_bad. */
static inline duct_sock_t th_connect(uint16_t port)
{
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    return th_connect_addr(AF_INET, (struct sockaddr *)&addr, (int)sizeof addr);
}

/** @brief Bytes that hold any socket path a test names, the NUL included. */
static constexpr size_t th_local_path_max = 108u;

/** @brief Name a socket file in the temp directory after @p tag and this process, into @p out of @p cap bytes. */
static inline void th_local_path(char *out, size_t cap, const char *tag)
{
#ifdef _WIN32
    char dir[MAX_PATH];
    DWORD n = GetTempPathA(sizeof dir, dir);
    snprintf(out, cap, "%.*sduct_local_%lu_%s.sock", (int)n, dir,
             (unsigned long)GetCurrentProcessId(), tag);
#else
    snprintf(out, cap, "/tmp/duct_local_%d_%s.sock", (int)getpid(), tag);
#endif
}

/** @brief Fill @p sa with the AF_UNIX address of @p path. */
static inline void th_local_fill(struct sockaddr_un *sa, const char *path)
{
    *sa = (struct sockaddr_un){ .sun_family = AF_UNIX };
    snprintf(sa->sun_path, sizeof sa->sun_path, "%s", path);
}

/** @brief Connect to the AF_UNIX stream socket at @p path with retry. Returns the socket or @c duct_sock_bad. */
static inline duct_sock_t th_local_connect(const char *path)
{
    struct sockaddr_un sa;
    th_local_fill(&sa, path);
    return th_connect_addr(AF_UNIX, (struct sockaddr *)&sa, (int)sizeof sa);
}

/** @brief Close @p fd with a zero linger and no shutdown ahead of it, so the peer sees a reset and no
 *  FIN: duct_sock_close shuts the send side first. */
static inline void th_reset(duct_sock_t fd)
{
    struct linger lg = { .l_onoff = 1, .l_linger = 0 };
    duct_discard setsockopt(fd, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg);
    close(fd);
}

/** @brief Start an outbound connection to @p addr, retrying while the engine answers @c rc_invalid_order.
 *  The engine gives that answer until it is running. Retries run in 5 ms steps
 *  for @c TH_CONNECT_RETRY_MS.
 *  @return the first other result; @c rc_invalid_order once the budget has run out.
 */
static inline duct_result_t th_connect_retry(duct_engine_t *io, const char *addr,
                                             duct_proto_t *proto, duct_xport_t xport)
{
    duct_result_t rc = rc_invalid_order;
    for (unsigned waited = 0u; waited < TH_CONNECT_RETRY_MS; waited += 5u) {
        rc = duct_io_connect(io, addr, proto, nullptr, xport);
        if (rc != rc_invalid_order)
            return rc;
        th_sleep_ms(5u);
    }
    return rc;
}

/* ── Atomic wait ─────────────────────────────────────────────────── */

/** @brief Spin until *@p p == @p target or @p timeout_ms expires. */
static inline bool th_wait_int(atomic_int *p, int target, unsigned timeout_ms)
{
    for (unsigned waited = 0u; waited < timeout_ms; waited += 10u) {
        if (duct_atomic_load(p, acquire) == target)
            return true;
        th_sleep_ms(10u);
    }
    return duct_atomic_load(p, acquire) == target;
}

/* ── Park ────────────────────────────────────────────────────────── */

/** @brief States of a park: the test arms with @c th_hold_off, a callback answers @c th_hold_parked once it
 *  holds, and @c th_hold_released lets it return. */
enum { th_hold_off = 0, th_hold_parked, th_hold_released };

/** @brief Park the calling callback on @p h until the test releases it.
 *  The first caller to find @p h at @c th_hold_off answers @c th_hold_parked and blocks on it; later callers
 *  return at once. The block ends by itself after @p bound_ms, so a test that never releases fails instead of
 *  hanging. */
static inline void th_hold_park(atomic_int *h, unsigned bound_ms)
{
    int expected = th_hold_off;
    if (!duct_atomic_cas(strong, h, &expected, th_hold_parked, acq_rel, acquire))
        return;
    while (duct_atomic_load(h, acquire) == th_hold_parked)
        if (!duct_futex_wait(h, th_hold_parked, bound_ms))
            break;
}

/** @brief Release the callback parked on @p h and wake it. */
static inline void th_hold_release(atomic_int *h)
{
    duct_atomic_store(h, th_hold_released, release);
    duct_futex_wake(h, duct_futex_wake_all);
}

/* ── LP wire framing ─────────────────────────────────────────────── */

/** @brief Send one length-prefix frame carrying @p flags. 0 on success.
 *
 *  @p flags ride the header's top three bits and @p len the rest, as the wire's
 *  own s_lp_pack_header writes it. A nonzero @p pause_ms lands the header and
 *  the payload in separate reads, which is what drives the parser's
 *  payload-partial replay; 0 sends them back to back.
 */
static constexpr uint32_t th_lp_bit_fin  = 1u << 31;
static constexpr uint32_t th_lp_bit_rst  = 1u << 30;
static constexpr uint32_t th_lp_bit_gso  = 1u << 29;
static constexpr uint32_t th_lp_len_mask = th_lp_bit_gso - 1u;

static inline int th_send_flags(duct_sock_t fd, const void *data, size_t len,
                                uint8_t flags, unsigned pause_ms)
{
    uint32_t word = (uint32_t)len;
    if (flags & (uint8_t)fl_frame_fin) word |= th_lp_bit_fin;
    if (flags & (uint8_t)fl_frame_rst) word |= th_lp_bit_rst;
    if (flags & (uint8_t)fl_frame_gso) word |= th_lp_bit_gso;
    uint8_t hdr[4] = {
        (uint8_t)(word >> 24u), (uint8_t)(word >> 16u),
        (uint8_t)(word >>  8u), (uint8_t)(word),
    };
    if (send(fd, (const char *)hdr, (int)sizeof hdr, 0) != (int)sizeof hdr)
        return -1;
    if (len == 0u)
        return 0;
    if (pause_ms)
        th_sleep_ms(pause_ms);
    return send(fd, (const char *)data, (int)len, 0) == (int)len ? 0 : -1;
}

/** @brief Send a 4-byte BE length-prefix + payload. 0 on success. */
static inline int th_send(duct_sock_t fd, const void *data, size_t len)
{
    return th_send_flags(fd, data, len, 0u, 0u);
}

/** @brief Read exactly @p n bytes, each wait bounded by @c TH_ROUNDTRIP_TIMEOUT_MS.
 *  @return 0, or -1 on timeout, error or a peer close before @p n arrive.
 */
static inline int th_read_exact(duct_sock_t fd, void *dst, size_t n)
{
    for (size_t got = 0u; got < n; ) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, TH_ROUNDTRIP_TIMEOUT_MS) <= 0)
            return -1;
        int r = recv(fd, (char *)dst + got, (int)(n - got), 0);
        if (r <= 0)
            return -1;
        got += (size_t)r;
    }
    return 0;
}

/** @brief Read one length-prefix frame into @p buf, max @p bufsize.
 *  @param out_flags  Receives the frame's flags byte; null to ignore it.
 *  @return Payload size, which a bare control frame leaves at 0, or -1.
 */
static inline int64_t th_recv_flags(duct_sock_t fd, char *buf, size_t bufsize,
                                    uint8_t *out_flags)
{
    uint8_t hdr[4] = {};
    if (th_read_exact(fd, hdr, sizeof hdr) != 0)
        return -1;
    uint32_t word = ((uint32_t)hdr[0] << 24u) | ((uint32_t)hdr[1] << 16u)
                  | ((uint32_t)hdr[2] <<  8u) |  (uint32_t)hdr[3];
    uint8_t flags = 0u;
    if (word & th_lp_bit_fin) flags |= (uint8_t)fl_frame_fin;
    if (word & th_lp_bit_rst) flags |= (uint8_t)fl_frame_rst;
    if (word & th_lp_bit_gso) flags |= (uint8_t)fl_frame_gso;
    uint32_t plen = word & th_lp_len_mask;
    if (plen > bufsize || th_read_exact(fd, buf, plen) != 0)
        return -1;
    if (out_flags)
        *out_flags = flags;
    return (int64_t)plen;
}

/** @brief Read one LP frame into @p buf (max @p bufsize). Returns payload size or -1. */
static inline int64_t th_recv(duct_sock_t fd, char *buf, size_t bufsize)
{
    return th_recv_flags(fd, buf, bufsize, nullptr);
}

/** @brief Receive one LP frame and assert exact match with @p expected. */
static inline int th_recv_eq(duct_sock_t fd, const char *expected, size_t elen)
{
    char buf[1024] = {};
    int64_t got = th_recv(fd, buf, sizeof(buf));
    if (got < 0 || (size_t)got != elen || memcmp(buf, expected, elen) != 0)
        return -1;
    return 0;
}

/** @brief Assert no data arrives within @p timeout_ms. */
static inline int th_recv_none(duct_sock_t fd, int timeout_ms)
{
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    return poll(&pfd, 1, timeout_ms) == 0 ? 0 : -1;
}

/** @brief Report whether the peer of @p fd closed it within @p timeout_ms.
 *  A read that returns no byte or fails counts as closed; a timeout does not. */
static inline bool th_peer_closed(duct_sock_t fd, int timeout_ms)
{
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    char byte;
    return poll(&pfd, 1, timeout_ms) > 0 && recv(fd, &byte, 1, 0) <= 0;
}

/** @brief Accept one connection on listener @p lfd within @p timeout_ms.
 *  @return the accepted socket, or @c duct_sock_bad on a timeout or a failure. */
static inline duct_sock_t th_accept(duct_sock_t lfd, int timeout_ms)
{
    struct pollfd pfd = { .fd = lfd, .events = POLLIN };
    if (poll(&pfd, 1, timeout_ms) <= 0)
        return duct_sock_bad;
    return (duct_sock_t)accept(lfd, nullptr, nullptr);
}

#endif /* DUCT_TEST_HELPERS_H */
