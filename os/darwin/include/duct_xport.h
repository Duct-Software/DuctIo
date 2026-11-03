/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, authors: Constantin Papizh, Dmitriy Puzyrkov, Olzhas Zharasbayev */

/** @file duct_xport.h
 *  @brief Darwin transport operations dispatch by transport kind;
 *  portable across all DUCT_EVENTS_MODEL variants.
 */

#ifndef DUCT_XPORT_H
#define DUCT_XPORT_H

#include "duct_core.h"
#include "duct_dgram_out.h"
#include "duct_events.h"
#include "duct_ticks.h"
#include "duct_types.h"
#include "duct_xsock.h"

#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

/** @brief Events a @c poll() @c POLLHUP stands for: a read and a write.
 *  XNU raises it for the end of either direction and then withholds
 *  @c POLLOUT: a send side ended under armed @c POLLOUT shows as @c POLLHUP,
 *  and the send it drives fails and closes the conn. */
static constexpr duct_io_ev_flags_t duct_x_poll_hup = (duct_io_ev_flags_t)(io_ev_read | io_ev_write);

/** @brief One message of a batched send or receive, with the bytes the call moved.
 *  Darwin has no @c sendmmsg / @c recvmmsg: @ref duct_xsendmmsg and
 *  @ref duct_xrecvmmsg make one call per message. */
typedef struct duct_x_mmsg {
    struct msghdr msg_hdr;
    unsigned      msg_len;
} duct_x_mmsg_t;

/** @brief Send up to @p n messages from @p msgs, one @c sendmsg each.
 *  Each sent message's @c msg_len takes its byte count.
 *  @return messages sent; -1 when the first send fails, with its @c errno. */
static inline int duct_xsendmmsg(int fd, duct_x_mmsg_t *msgs, unsigned n, int flags)
{
    unsigned sent = 0;
    for (; sent < n; ++sent) {
        ssize_t size = sendmsg(fd, &msgs[sent].msg_hdr, flags);
        if (size < 0)
            return sent ? (int)sent : -1;
        msgs[sent].msg_len = (unsigned)size;
    }
    return (int)sent;
}

/** @brief Receive up to @p n messages into @p msgs, one @c recvmsg each.
 *  Each received message's @c msg_len takes its byte count.
 *  @return messages received; -1 when the first receive fails, with its @c errno. */
static inline int duct_xrecvmmsg(int fd, duct_x_mmsg_t *msgs, unsigned n, int flags)
{
    unsigned received = 0;
    for (; received < n; ++received) {
        ssize_t size = recvmsg(fd, &msgs[received].msg_hdr, flags);
        if (size < 0)
            return received ? (int)received : -1;
        msgs[received].msg_len = (unsigned)size;
    }
    return (int)received;
}

static inline void duct_xset_fd_flags(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        duct_discard fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(fd, F_GETFD, 0);
    if (flags >= 0)
        duct_discard fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    duct_discard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &(int){ 1 }, sizeof(int));
}

/** @brief Make @p fd non-blocking; a refused @c fcntl leaves it as it was. */
static inline void duct_xset_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        duct_discard fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/** @brief Disable Nagle's algorithm on a stream socket. Best-effort: harmless
 *  if @p fd's protocol family does not support @c TCP_NODELAY. Without this,
 *  small frequent writes under sustained backpressure interact with delayed
 *  ACK to stall tens to hundreds of ms per write.
 */
static inline void duct_xset_tcp_nodelay(int fd)
{
    duct_discard setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                            &(int){ 1 }, sizeof(int));
}

/** @brief Set a stream socket's @c TCP_NOTSENT_LOWAT.
 *  Best-effort: 0 leaves the kernel's default, and so does a refusal.
 *  @return The lowat now in force, 0 where none was asked or the kernel refused
 *          it. */
static inline uint32_t duct_xset_tcp_lowat([[maybe_unused]] int fd,
                                           [[maybe_unused]] uint32_t notsent_lowat)
{
#ifdef TCP_NOTSENT_LOWAT
    if (notsent_lowat && setsockopt(fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT,
                                    &(int){ (int)notsent_lowat }, sizeof(int)) == 0)
        return notsent_lowat;
#endif
    return 0u;
}

/** @brief Largest read a coalescing datagram socket can answer with, bytes.
 *  Zero: Darwin's UDP coalesces no receives, so every read span resolves to the
 *  wire's own frame.
 */
static constexpr size_t duct_x_gro_max = 0u;

/** @brief Ask @p fd's kernel to hand back several same-source datagrams of one
 *  size as a single read.
 *  @return 0 always: Darwin's UDP has no receive coalescing, and a conn sizes
 *  its read spans to one frame.
 */
static inline size_t duct_xset_dgram_gro([[maybe_unused]] int fd, [[maybe_unused]] size_t max)
{
    return 0u;
}

/** @brief Report the @c virtio_net_hdr length @p fd frames every packet with,
 *  bytes.
 *  Non-zero only for a tun, @c IFF_TUN, opened with @c IFF_VNET_HDR. */
size_t duct_x_vnet_hdr_len(int fd);

/** @brief Enable the offloads of vnet tun @p fd, always @c rc_not_supported on
 *  macOS, whose conns carry no vnet header. */
duct_result_t duct_x_vnet_offload(int fd);

/** @brief Estimate of what one datagram of a TX batch charges its socket,
 *  bytes: a 1500-byte path's datagram and its share of the skb, rounded up to
 *  a power of two. */
static constexpr int duct_x_dgram_truesize = 2048;

/** @brief Prepare an @c x_udp_peer dial's socket of @p family: buffer sizes and
 *  no IP fragmentation.
 *  RX takes @c duct_dgram_sock_rcvbuf, the slack that absorbs io-thread
 *  scheduling gaps, or the @c DUCT_DGRAM_RCVBUF environment variable's figure.
 *  TX asks @c duct_x_dgram_truesize per datagram of a @c duct_dgram_tx_batch
 *  batch; the rest of a backlog stays in the TX ring, where
 *  @c duct_conn_tx_end counts it. @c IP_DONTFRAG or @c IPV6_DONTFRAG by
 *  @p family turns an oversized send into @c EMSGSIZE.
 */
static inline void duct_xset_dgram_bufs(int fd, [[maybe_unused]] int family)
{
    static thread_local int rcvbuf_env = -1; /* per-thread resolve: no shared write */
    if (rcvbuf_env < 0) {
        const char *s = getenv("DUCT_DGRAM_RCVBUF");
        rcvbuf_env = s ? atoi(s) : 0;
    }
    duct_discard setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                            &(int){ rcvbuf_env > 0 ? rcvbuf_env : (int)duct_dgram_sock_rcvbuf }, sizeof(int));
    duct_discard setsockopt(fd, SOL_SOCKET, SO_SNDBUF,
                            &(int){ (int)duct_dgram_tx_batch * duct_x_dgram_truesize }, sizeof(int));
#ifdef IP_DONTFRAG
    /* Never let IP fragment a datagram. A protocol that sizes its
     * datagrams to the path already treats fragmentation as a bug --
     * it multiplies the loss probability of one message by the fragment
     * count -- and silent fragmentation also defeats any attempt to probe
     * the path by sending a large datagram and seeing whether it lands.
     * With DF set an oversized send fails loudly (EMSGSIZE) instead. */
    if (family == AF_INET)
        duct_discard setsockopt(fd, IPPROTO_IP, IP_DONTFRAG,
                                &(int){ 1 }, sizeof(int));
#endif
#ifdef IPV6_DONTFRAG
    /* IPv6 keeps a mode of its own, which the kernel defaults to letting the
     * host fragment. */
    if (family == AF_INET6)
        duct_discard setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG,
                                &(int){ 1 }, sizeof(int));
#endif
}

/** @brief Read the send buffer the kernel granted @p fd, bytes.
 *  @return 0 where the kernel answers none. */
static inline uint32_t duct_xget_sndbuf(int fd)
{
    int size = 0;
    return getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, &(socklen_t){ sizeof size }) == 0 && size > 0
         ? (uint32_t)size : 0u;
}

/** @brief Read connected socket @p fd's path MTU, bytes.
 *  @return false always: this backend reads none, @p out untouched. */
static inline bool duct_xget_path_mtu([[maybe_unused]] int fd,
                                      [[maybe_unused]] uint16_t *out)
{
    return false;
}

/** @brief Read the congestion control a TCP socket runs.
 *  @return false always: this backend reads none, @p out untouched. */
static inline bool duct_xget_tcp_congestion([[maybe_unused]] int fd,
                                            [[maybe_unused]] char out[duct_tcp_cc_name_max])
{
    return false;
}

/** @brief Read TCP socket @p fd's transfer figures.
 *  @return false always: this backend reads none, @p out untouched. */
duct_nonnull(3) static inline bool
duct_xget_tcp_stats([[maybe_unused]] void *x,
                    [[maybe_unused]] int fd,
                    [[maybe_unused]] duct_tcp_stats_t *out)
{
    return false;
}

/** @brief Read TCP socket @p fd's unsent bytes.
 *  @return @c duct_tx_unsent_unread always: this backend reads no figure. */
static inline uint64_t duct_xget_tx_unsent([[maybe_unused]] int fd)
{
    return duct_tx_unsent_unread;
}

/** @brief Bound how long TCP socket @p fd retransmits unanswered before the
 *  stack ends it, @p ms rounded up to whole seconds.
 *  0 restores the stack's own bound. @c TCP_RXT_CONNDROPTIME carries it, and
 *  @c PERSIST_TIMEOUT applies the same figure to a window held shut.
 *  @return false where the stack refuses @c TCP_RXT_CONNDROPTIME. */
static inline bool duct_xset_tcp_ack_timeout([[maybe_unused]] int fd,
                                              [[maybe_unused]] uint32_t ms)
{
#ifdef TCP_RXT_CONNDROPTIME
    int sec = (int)(((uint64_t)ms + 999u) / 1000u);
    bool ok = setsockopt(fd, IPPROTO_TCP, TCP_RXT_CONNDROPTIME, &sec, sizeof sec) == 0;
#ifdef PERSIST_TIMEOUT
    if (ok)
        duct_discard setsockopt(fd, IPPROTO_TCP, PERSIST_TIMEOUT, &sec, sizeof sec);
#endif
    return ok;
#else
    return false;
#endif
}

/** @brief A socket option follow step, shared with the engine. */
typedef enum duct_x_follow : uint8_t {
    x_follow_none,
    x_follow_read,
    x_follow_set,
} duct_x_follow_t;

/** @brief Apply a new conn's send options to its socket @p fd and record in @p x
 *  the bound it was created with.
 *  A connected UDP socket records its granted send buffer, a TCP socket the
 *  @c TCP_NOTSENT_LOWAT it took, 0 where none was asked or the stack refused
 *  it. The lowat stays fixed and the congestion control is the stack's, so
 *  @p lowat_us and @p congestion go unused. */
duct_nonnull(1) static inline void
duct_xset_sock_tx(duct_x_sock_tx_t *x, int fd, duct_xport_t xport,
                  uint32_t notsent_lowat,
                  [[maybe_unused]] uint32_t lowat_us,
                  [[maybe_unused]] const char *congestion)
{
    if (xport == x_udp_peer)
        x->lowat_max = duct_xget_sndbuf(fd);
    else if (xport == x_tcp)
        x->lowat_max = duct_xset_tcp_lowat(fd, notsent_lowat);
}

duct_nonnull(1) static inline duct_x_follow_t
duct_x_sock_tx_follow([[maybe_unused]] duct_x_sock_tx_t *x,
                      [[maybe_unused]] int fd)
{
    return x_follow_none;
}

static inline void
duct_xset_sock_rx([[maybe_unused]] void *x,
                  [[maybe_unused]] int fd,
                  [[maybe_unused]] duct_xport_t xport)
{
}

static inline duct_x_follow_t
duct_x_sock_rx_follow([[maybe_unused]] void *x,
                      [[maybe_unused]] int fd,
                      [[maybe_unused]] uint64_t consumed)
{
    return x_follow_none;
}

/** @brief True when @p err says to send these same bytes again later.
 *  @c ENOBUFS joins the two would-block codes: the kernel is out of buffer
 *  space this instant, which the next drive finds cleared. Other codes
 *  indicate a permanent message error; repeating the send repeats
 *  the failure.
 */
static inline bool duct_x_send_retryable(int err)
{
    switch (err) {
    case EAGAIN:
    case ENOBUFS:
        return true;
    default:
        return false;
    }
}

/** @brief Verdict on one datagram send whose result is @p n: true once the
 *  caller may move past those bytes, false to leave them queued.
 *  A send that failed for good answers true — the bytes go nowhere, and a
 *  queue that keeps them stops every datagram behind them too. The guard
 *  names that spot, since nothing downstream sees the errno.
 */
static inline bool duct_x_send_consumed(ssize_t n)
{
    if (n >= 0)
        return true;
    bool drop = !duct_x_send_retryable(errno);
    duct_do_if(drop, return true);
    return false;
}

/** @brief Send @p n whole datagrams out the connected socket @p fd, one span
 *  each.
 *
 *  One @c sendmmsg, no retry loop over the remainder: the caller owns a single
 *  conn's TX ring and re-peeks it on the next drive, so a prefix answer needs
 *  no second submission here. @p n is at most @c duct_dgram_tx_batch, the
 *  stack arrays' width.
 *
 *  @param out_sent datagrams the kernel took, 0 on every outcome but @c rc_ok.
 *  @return @c rc_ok with @p out_sent up to @p n; @c rc_again on a code worth
 *  repeating; @c rc_drop for a first datagram too large for the path;
 *  @c rc_fatal for a socket to close.
 */
duct_nonnull(2, 4) static inline duct_result_t
duct_xsend_bufs(int fd, const duct_view_u8 *bufs, unsigned n, unsigned *out_sent)
{
    *out_sent = 0u;
    assert(n && n <= duct_dgram_tx_batch);
    struct iovec   iov[duct_dgram_tx_batch];
    duct_x_mmsg_t msgs[duct_dgram_tx_batch] = {};
    for (unsigned i = 0u; i < n; ++i) {
        iov[i] = (struct iovec){ .iov_base = bufs[i].data,
                                 .iov_len = bufs[i].size };
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1u;
    }
    int r;
    do
        r = duct_xsendmmsg(fd, msgs, n, MSG_NOSIGNAL);
    while (r < 0 && errno == EINTR);
    if (r >= 0) {
        *out_sent = (unsigned)r;
        return rc_ok;
    }
    if (duct_x_send_retryable(errno))
        return rc_again;
    switch (errno) {
    case EMSGSIZE:
        duct_dbg_errf("EMSGSIZE, %zu bytes", bufs[0].size);
        return rc_drop;
    default:
        duct_dbg_errf("errno %d", errno);
        return rc_fatal;
    }
}

duct_nonnull(4) static inline duct_result_t
duct_xread(int fd, duct_xport_t t, duct_view_u8 dst, size_t *out_read, void *ctx, int flags,
           size_t *out_seg)
{
    ssize_t n = 0;
    *out_read = 0;
    if (out_seg)
        *out_seg = 0u;
    switch (t) {
    case x_raw_packet:
    case x_raw: /* attach_fd: caller-owned fd, not necessarily a socket */
        do
            n = read(fd, dst.data, dst.size);
        while (n < 0 && errno == EINTR);
    break;
    case x_tcp: case x_bt: case x_can: case x_local:
        do
            n = recv(fd, dst.data, dst.size, flags);
        while (n < 0 && errno == EINTR);
    break;
    case x_udp_peer: {
        /* Darwin reports the copied length; recvmsg output flag identifies a
         * consumed oversized packet. */
        struct iovec iov = { .iov_base = dst.data, .iov_len = dst.size };
        struct msghdr mh = {
            .msg_iov = &iov, .msg_iovlen = 1,
        };
        do
            n = recvmsg(fd, &mh, flags);
        while (n < 0 && errno == EINTR);
        if (n >= 0 && (mh.msg_flags & MSG_TRUNC))
            return rc_drop;
    } break;
    case x_udp:
        duct_do_if(!ctx, return rc_invalid_arg);
        do
            n = recvfrom(fd, dst.data, dst.size, flags, ctx,
                         &(socklen_t){ sizeof(struct sockaddr_storage) });
        while (n < 0 && errno == EINTR);
    break;
    case x_inter: /* push-mode: ingress arrives via duct_io_inter_batch */
    case x_udp_shared: /* no owned fd: RX arrives via the listener's socket */
        return rc_invalid_arg;
    }
    switch (n) {
    case -1:
        switch (errno) {
        case EAGAIN:
            return rc_again;
        default:
            duct_dbg_errf("errno %d", errno);
            return rc_fatal;
        }
    case 0:
        if (t != x_udp && t != x_udp_peer && t != x_inter && t != x_raw_packet)
            return rc_closed;
    default:
        break;
    }
    duct_do_if(t == x_udp_peer && (size_t)n > dst.size,
               return rc_drop); /* MSG_TRUNC: real size exceeded dst.size, kernel already dequeued the rest */
    *out_read = n;
    return rc_ok;
}

/** @brief Write @p src out @p fd for transport @p t.
 *
 *  @param ctx  Destination @c sockaddr for @c x_udp; unread for every other
 *              transport.
 *  @return @c rc_ok with @p out_written set, below @p src.size on a short
 *  write; @c rc_again on a @ref duct_x_send_retryable code and on a stream
 *  write that moved nothing; @c rc_drop for a message too large for the path
 *  on a transport that delimits its own, @ref duct_xport_delimited deciding
 *  which — that message is unsendable, the conn is not; @c rc_fatal otherwise;
 *  @c rc_invalid_arg for a transport with no descriptor of its own to write.
 *  @p out_written is 0 on every outcome but @c rc_ok.
 */
duct_nonnull(4) static inline duct_result_t
duct_xwrite(int fd, duct_xport_t t, duct_view_u8 src, size_t *out_written, void *ctx, int flags)
{
    ssize_t n = 0;
    *out_written = 0;
    switch (t) {
    case x_raw_packet:
    case x_raw: /* attach_fd: caller-owned fd, not necessarily a socket */
        do
            n = write(fd, src.data, src.size);
        while (n < 0 && errno == EINTR);
        break;
    case x_tcp: case x_bt: case x_can: case x_udp_peer: case x_local:
        do
            n = send(fd, src.data, src.size, flags | MSG_NOSIGNAL);
        while (n < 0 && errno == EINTR);
        break;
    case x_udp:
        do
            n = sendto(fd, src.data, src.size, flags | MSG_NOSIGNAL,
                       ctx, (socklen_t)sizeof(struct sockaddr_storage));
        while (n < 0 && errno == EINTR);
        break;
    case x_inter: /* push-mode, egress goes through on_packet_out */
    case x_udp_shared: /* no owned fd, TX goes through listener's outbox */
        return rc_invalid_arg;
    }
    switch (n) {
    case -1:
        if (duct_x_send_retryable(errno))
            return rc_again;
        switch (errno) {
        case EMSGSIZE:
            duct_dbg_errf("EMSGSIZE, %zu bytes", src.size);
            return duct_xport_delimited(t) ? rc_drop : rc_fatal;
        default:
            duct_dbg_errf("errno %d", errno);
            return rc_fatal;
        }
    case 0:
        if (t != x_udp && t != x_udp_peer && t != x_inter)
            return rc_again;
    default:
        break;
    }
    *out_written = n;
    return rc_ok;
}

/** @brief Write @p n spans out @p fd in one call, joining them nowhere first.
 *
 *  @c x_raw and @c x_raw_packet go through @c writev, their descriptor being
 *  an attached file descriptor. The socket kinds go through @c sendmsg, whose
 *  flags argument carries @c MSG_NOSIGNAL, turning a write to a departed peer
 *  into @c rc_fatal without delivering SIGPIPE. A single span skips both and
 *  takes @ref duct_xwrite, which needs no vector built for it.
 *
 *  @return @c rc_ok with @p out_written set, below the spans' total on a short
 *  write; @c rc_again on would-block; @c rc_drop for a lone span too large for
 *  a delimited transport, which only @ref duct_xwrite reaches; @c rc_fatal on
 *  any other failure; @c rc_invalid_arg for @p n of 0 and for a transport with
 *  no underlying descriptor to write. @p out_written is 0 on every outcome but
 *  @c rc_ok.
 */
duct_nonnull(3, 5) static inline duct_result_t
duct_xwritev(int fd, duct_xport_t t, const duct_view_u8 *bufs, unsigned n,
             size_t *out_written, int flags)
{
    ssize_t r = 0;
    *out_written = 0;
    duct_do_if(!n, return rc_invalid_arg);
    if (n == 1u)
        return duct_xwrite(fd, t, bufs[0], out_written, nullptr, flags);
    struct iovec iov[n];
    for (unsigned i = 0u; i < n; ++i)
        iov[i] = (struct iovec){ .iov_base = bufs[i].data, .iov_len = bufs[i].size };
    switch (t) {
    case x_raw_packet:
    case x_raw:
        do
            r = writev(fd, iov, (int)n);
        while (r < 0 && errno == EINTR);
        break;
    case x_tcp: case x_bt: case x_can: case x_udp_peer: case x_local: {
        struct msghdr msg = { .msg_iov = iov, .msg_iovlen = n };
        do
            r = sendmsg(fd, &msg, flags | MSG_NOSIGNAL);
        while (r < 0 && errno == EINTR);
        break;
    }
    case x_udp:
    case x_inter:
    case x_udp_shared:
        return rc_invalid_arg;
    }
    switch (r) {
    case -1:
        switch (errno) {
        case EAGAIN:
            return rc_again;
        default:
            duct_dbg_errf("errno %d", errno);
            return rc_fatal;
        }
    case 0:
        if (t != x_udp_peer)
            return rc_again;
    default:
        break;
    }
    *out_written = (size_t)r;
    return rc_ok;
}

/** @brief Send one already-framed datagram out @p fd to @p addr.
 *
 *  A plain synchronous sendto: a non-blocking UDP send never blocks
 *  on a handshake/ACK the way stream I/O can.
 *
 *  @return true once the caller may move past these bytes: handed to the
 *  kernel, or failed for a reason repeating the send repeats. false for a
 *  @ref duct_x_send_retryable code, meaning leave it queued and send it again
 *  once the socket is writable.
 */
duct_nonnull(2) static inline bool
duct_xsend_dgram(int fd, const struct sockaddr *addr, socklen_t addrlen, duct_view_u8 payload)
{
    ssize_t n;
    do
        n = sendto(fd, payload.data, payload.size, MSG_NOSIGNAL, addr, addrlen);
    while (n < 0 && errno == EINTR);
    return duct_x_send_consumed(n);
}

/** @brief Batch-write @p n already-framed buffers out @p fd for @p t.
 *  Only @c x_udp (sendmmsg) is implemented — connected/stream batching
 *  has no caller yet, same explicit-reject pattern @ref duct_xwrite uses
 *  for @c x_inter / @c x_udp_shared.
 *
 *  Absorbs sendmmsg's own two-layer contract into plain @ref duct_result_t,
 *  same shape as @ref duct_xwrite: a clean @c UIO_MAXIOV cap, the kernel
 *  taking at most 1024 per call, reports a non-negative count, so this loops
 *  on the remainder; a genuine failure only ever reports @c -1 with a real
 *  @c errno, and a later failure after some messages already went folds into
 *  the count instead. Every caller treats @p out_resolved entries as
 *  genuinely delivered, and @ref duct_x_send_consumed draws the line: a code
 *  worth retrying leaves the failed entry in place, anything else counts it
 *  resolved, so everything queued behind it keeps moving.
 *
 *  @return @c rc_ok once every entry resolved, undeliverable ones included;
 *  @c rc_again on a retryable code, with the remainder from @p out_resolved
 *  still queued; @c rc_invalid_arg for an unsupported @p t. @p out_resolved
 *  always set.
 */
duct_nonnull(3, 5) static inline duct_result_t
duct_xwrite_batch(int fd, duct_xport_t t, duct_x_mmsg_t *msgs, unsigned n, unsigned *out_resolved)
{
    duct_do_if(t != x_udp, *out_resolved = 0u; return rc_invalid_arg);
    unsigned resolved = 0u;
    duct_result_t rc = rc_ok;
    while (resolved < n) {
        errno = 0;
        int r;
        do
            r = duct_xsendmmsg(fd, msgs + resolved, n - resolved, MSG_NOSIGNAL);
        while (r < 0 && errno == EINTR);
        if (r >= 0) {
            resolved += (unsigned)r;
            continue;
        }
        if (!duct_x_send_consumed(r)) {
            rc = rc_again;
            break;
        }
        ++resolved;
    }
    *out_resolved = resolved;
    return rc;
}

/** @brief Send @p n datagrams out connected socket @p fd as one segmented
 *  write.
 *  @return @c rc_not_supported always: Darwin's UDP has no segmentation
 *  offload, and the caller sends the group unsegmented.
 */
duct_nonnull(2) static inline duct_result_t
duct_xsend_gso_bufs([[maybe_unused]] int fd,
                    [[maybe_unused]] const duct_view_u8 *bufs,
                    [[maybe_unused]] unsigned n)
{
    return rc_not_supported;
}

/** @brief Send @p n datagrams to @p msgs[0]'s peer as one segmented write.
 *  @return @c rc_not_supported always: Darwin's UDP has no segmentation
 *  offload, and the caller sends the group unsegmented.
 */
duct_nonnull(2) static inline duct_result_t
duct_xsend_gso_peers([[maybe_unused]] int fd,
                     [[maybe_unused]] const duct_dgram_out_t *msgs,
                     [[maybe_unused]] unsigned n)
{
    return rc_not_supported;
}

/** @brief Send @p n already wire-packed datagrams to @p fd, each from its own
 *  descriptor's two spans, unsegmented.
 *
 *  One @c sendmmsg through @ref duct_xwrite_batch, or one @c sendmsg for a
 *  single datagram. A descriptor's header and payload become two iovecs of one
 *  message, so the payload reaches the kernel from wherever it already lies;
 *  an empty header contributes no iovec.
 *
 *  @param out_sent how many of the first @p n the caller may move past, which
 *         counts a datagram no send will ever carry alongside those the kernel
 *         took. The answer is a prefix: the first @ref duct_x_send_retryable
 *         code stops the run and leaves the rest queued.
 *  @return @c rc_ok on every path, so a shared socket never closes over one
 *  batch.
 */
duct_nonnull(2, 4) static inline duct_result_t
duct_xsend_peers(int fd, const duct_dgram_out_t *msgs_in, unsigned n, unsigned *out_sent)
{
    assert(n);
    struct sockaddr_storage addrs[n];
    struct iovec            iovs[2u * n];
    duct_x_mmsg_t           msgs[n];
    unsigned iv = 0u;
    for (unsigned i = 0u; i < n; ++i) {
        socklen_t len = (socklen_t)duct_io_sockaddr_from_peer(&msgs_in[i].peer, &addrs[i]);
        unsigned start = iv;
        if (msgs_in[i].hdr.size)
            iovs[iv++] = (struct iovec){ .iov_base = msgs_in[i].hdr.data,
                                         .iov_len = msgs_in[i].hdr.size };
        iovs[iv++] = (struct iovec){ .iov_base = msgs_in[i].body.data,
                                     .iov_len = msgs_in[i].body.size };
        msgs[i] = (duct_x_mmsg_t){
            .msg_hdr = {
                .msg_name = &addrs[i], .msg_namelen = len,
                .msg_iov = &iovs[start], .msg_iovlen = iv - start,
            },
        };
    }

    if (n > 1u) {
        duct_discard duct_xwrite_batch(fd, x_udp, msgs, n, out_sent);
        return rc_ok;
    }
    ssize_t sent;
    do
        sent = sendmsg(fd, &msgs[0].msg_hdr, MSG_NOSIGNAL);
    while (sent < 0 && errno == EINTR);
    *out_sent = duct_x_send_consumed(sent) ? 1u : 0u;
    return rc_ok;
}

/** @brief Fill up to @p n of @p bufs from @p fd, reporting each datagram's
 *  length in @p out_lens.
 *  One @c recvmsg each, through @ref duct_xrecvmmsg. @p out_peers takes each
 *  source and @p out_segs a segment size, 0 on Darwin, which coalesces no
 *  receives; @c nullptr skips either report. A datagram too large for its
 *  buffer reports @ref duct_dgram_len_truncated as its length and still takes
 *  its entry.
 *
 *  @return @c rc_ok with @p out_n >= 1; @c rc_again when the socket is empty;
 *  @c rc_fatal otherwise. @p out_n < @p n means the socket ran dry mid-batch.
 */
duct_nonnull(2, 5, 7) static inline duct_result_t
duct_xrecv_peers(int fd, const duct_view_u8 *bufs, uint32_t n,
                 duct_peer_t *out_peers, uint32_t *out_lens, uint32_t *out_segs,
                 uint32_t *out_n)
{
    *out_n = 0u;
    duct_do_if(!n, return rc_again);
    struct sockaddr_storage addrs[n];
    struct iovec            iovs[n];
    duct_x_mmsg_t           msgs[n];
    for (uint32_t i = 0u; i < n; ++i) {
        iovs[i] = (struct iovec){ .iov_base = bufs[i].data, .iov_len = bufs[i].size };
        msgs[i] = (duct_x_mmsg_t){ .msg_hdr = { .msg_iov = &iovs[i], .msg_iovlen = 1 } };
        if (out_peers) {
            msgs[i].msg_hdr.msg_name = &addrs[i];
            msgs[i].msg_hdr.msg_namelen = sizeof addrs[i];
        }
    }
    int r;
    do
        r = duct_xrecvmmsg(fd, msgs, n, MSG_DONTWAIT);
    while (r < 0 && errno == EINTR);
    if (r < 0)
        switch (errno) {
        case EAGAIN:
            return rc_again;
        default:
            duct_dbg_errf("errno %d", errno);
            return rc_fatal;
        }
    for (int i = 0; i < r; ++i) {
        out_lens[i] = (msgs[i].msg_hdr.msg_flags & MSG_TRUNC)
                    ? duct_dgram_len_truncated : msgs[i].msg_len;
        if (out_peers)
            out_peers[i] = duct_io_peer_from_sockaddr((struct sockaddr *)&addrs[i]);
        if (out_segs)
            out_segs[i] = 0u;
    }
    *out_n = (uint32_t)r;
    return r > 0 ? rc_ok : rc_again;
}

/** @brief Most datagrams one receive call takes: @c duct_dgram_rx_batch, through
 *  @c recvmmsg. */
static constexpr uint32_t duct_x_recv_batch_max = duct_dgram_rx_batch;

/** @brief Division of one bound port's traffic among the sockets bound to it.
 *  Ordered: each value keeps every guarantee of the one before, and readers
 *  compare by order. */
typedef enum duct_x_port_share : uint8_t {
    x_port_share_first,     /**< The first socket bound takes all of it. */
    x_port_share_connected, /**< A connected socket takes its own peer's
                              *  datagrams; the rest goes to one socket. */
    x_port_share_spread,    /**< The rest is spread across the sockets by
                              *  address hash, accepts and datagrams alike. */
} duct_x_port_share_t;

/** @brief Connected peers take their traffic; other traffic uses one listener. */
static constexpr duct_x_port_share_t duct_x_port_sharing = x_port_share_connected;

/** @brief Availability of AF_UNIX stream listeners on this platform: always. */
static constexpr bool duct_x_local_floor = true;

/** @brief Availability of sessions opened over a caller's packet fd on this platform: always. */
static constexpr bool duct_x_packet_fd_session = true;

/** @brief Accept one connection on @p listener_fd, non-blocking, close-on-exec and free of SIGPIPE.
 *  @p ctx receives the peer address as a @c sockaddr_storage. A socket whose family is not
 *  AF_UNIX gets @c TCP_NODELAY.
 *  @retval rc_ok     @p out_fd set.
 *  @retval rc_again  Nothing is queued.
 *  @retval rc_defer  @c EMFILE: the process holds every descriptor its limit allows, and
 *                    the client stays queued.
 *  @retval rc_fatal  Any other failure.
 */
duct_nonnull(2, 3) static inline duct_result_t
duct_xaccept(int listener_fd, int *out_fd, void *ctx)
{
    int fd = *out_fd = duct_sock_bad;
    do
        fd = accept(listener_fd, ctx,
                    &(socklen_t){ sizeof(struct sockaddr_storage) });
    while (fd == duct_sock_bad && errno == EINTR);
    if (fd == duct_sock_bad)
        switch (errno) {
        case EAGAIN:
            return rc_again;
        case EMFILE:
            return rc_defer;
        default:
            duct_dbg_errf("errno %d", errno);
            return rc_fatal;
        }
    duct_xset_fd_flags(fd);
    if (((const struct sockaddr *)ctx)->sa_family != AF_UNIX)
        duct_xset_tcp_nodelay(fd);
    *out_fd = fd;
    return rc_ok;
}

/** @brief Map @p err, the @c errno connect() left, to the outcome of a dial of @p xport.
 *  @c ECONNREFUSED is a refusal on every xport. @c x_local reads @c ENOENT, a path
 *  with no socket file behind it, as one too, and @c EAGAIN, a full listen backlog,
 *  as @c rc_again. Any other @p err is @c rc_fatal.
 */
static inline duct_result_t duct_x_connect_errno(duct_xport_t xport, int err)
{
    switch (err) {
    case ECONNREFUSED:
        return rc_conn_refused;
    case ENOENT:
        return xport == x_local ? rc_conn_refused : rc_fatal;
    case EAGAIN:
        return xport == x_local ? rc_again : rc_fatal;
    default:
        return rc_fatal;
    }
}

/** @brief Create a dial's unconnected socket: the socket type @p xport picks,
 *  non-blocking and close-on-exec, a bind to a nonzero @p egress_if through
 *  @c IP_BOUND_IF or @c IPV6_BOUND_IF, and the per-xport socket options.
 *  @p congestion goes unused: the congestion control is the stack's.
 *  Nothing connects here.
 *  @return The descriptor, or @c duct_sock_bad when @c socket() or the
 *          @p egress_if bind fails.
 */
static inline duct_sock_t
duct_xsocket(int family, duct_xport_t xport, uint32_t egress_if,
             [[maybe_unused]] const char *congestion)
{
    int type = xport == x_udp_peer ? SOCK_DGRAM : SOCK_STREAM;
    duct_sock_t fd = socket(family, type, 0);
    if (fd == duct_sock_bad)
        return fd;
    duct_xset_fd_flags(fd);
    if (egress_if) {
        int level = family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
        int option = family == AF_INET ? IP_BOUND_IF : IPV6_BOUND_IF;
        bool bound = setsockopt(fd, level, option, &egress_if, sizeof egress_if) == 0;
        duct_do_if(!bound, close(fd); return duct_sock_bad);
    }
    switch (xport) {
    case x_udp_peer:
        duct_xset_dgram_bufs(fd, family);
        break;
    case x_local:
        break;
    default:
        duct_xset_tcp_nodelay(fd);
        break;
    }
    return fd;
}

/** @brief Non-blocking connect() of @p fd to @p addr, the socket type already
 *  set. A datagram connect is a local-only op and a local stream one lands in
 *  the listener's backlog or fails, so @c errno never becomes @c EINPROGRESS
 *  for either. @p fd is consumed: closed on failure, kept on success and on
 *  EINPROGRESS.
 *  @retval rc_ok            Connected, or EINPROGRESS on a stream dial.
 *  @retval rc_conn_refused  Connection-refused error, and for @c x_local a path
 *                           with no socket file behind it.
 *  @retval rc_again         @c x_local only: @c EAGAIN from connect().
 *  @retval rc_fatal         Any other failure.
 */
duct_nonnull(3) static inline duct_result_t
duct_xconnect(duct_xport_t xport, duct_sock_t fd, const struct sockaddr *addr, socklen_t addrlen)
{
    int rc = connect(fd, addr, addrlen) != 0 && errno != EINPROGRESS;
    if (rc != 0) {
        auto err = duct_x_connect_errno(xport, errno);
        close(fd);
        duct_do_if(err == rc_fatal, return rc_fatal);
        return err;
    }
    return rc_ok;
}

/** @brief getsockopt(SO_ERROR) on a still-connecting @p fd once
 *  its readiness event fires.
 *
 *  @retval rc_ok            Clean connect.
 *  @retval rc_conn_refused  Connection-refused error.
 *  @retval rc_fatal         Any other failure.
 */
static inline duct_result_t duct_xconnect_result(int fd)
{
    int err = 0;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err,
                   &(socklen_t){ sizeof err }) != 0)
        err = errno;
    return err == 0
        ? rc_ok
        : err == ECONNREFUSED ? rc_conn_refused : rc_fatal;
}

/** @brief Point an already-open per-peer datagram socket at @p peer_addr.
 *
 *  Repeatable on a socket @ref duct_xopen_dgram_peer already connected: the
 *  binding and the reactor registration both survive, so the conn behind @p fd
 *  keeps its rings, its session and its worker across the change.
 *
 *  @retval rc_ok     Send and receive both follow @p peer_addr from here.
 *  @retval rc_fatal  The socket still points where it did.
 */
duct_nonnull(2) static inline duct_result_t
duct_xconnect_dgram_peer(int fd, const struct sockaddr *peer_addr, socklen_t peer_len)
{
    return connect(fd, peer_addr, peer_len) == 0 ? rc_ok : rc_fatal;
}

/** @brief Open a connected per-peer datagram socket: SO_REUSEPORT-bound to
 *  @p listen_fd's local address, connected to @p peer_addr — the UDP analog
 *  of accept() handing back a dedicated per-connection fd.
 *
 *  @retval rc_ok     @p out_fd set.
 *  @retval rc_fatal  Any step's failure.
 */
duct_nonnull(2, 4) static inline duct_result_t
duct_xopen_dgram_peer(int listen_fd,
                      const struct sockaddr *peer_addr,
                      socklen_t peer_len, int *out_fd)
{
    *out_fd = duct_sock_bad;
    struct sockaddr_storage local = {};
    socklen_t local_len = sizeof local;
    int rc = getsockname(listen_fd, (struct sockaddr *)&local, &local_len);
    duct_do_if(rc != 0, return rc_fatal);

    int fd = socket(local.ss_family, SOCK_DGRAM, 0);
    duct_do_if(fd == duct_sock_bad, return rc_fatal);
    duct_xset_fd_flags(fd);

    rc = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &(int){ 1 }, sizeof(int));
    duct_do_if(rc != 0, goto fail);
    rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
    duct_do_if(rc != 0, goto fail);

    rc = bind(fd, (struct sockaddr *)&local, local_len);
    duct_do_if(rc != 0, goto fail);

    rc = connect(fd, peer_addr, peer_len);
    duct_do_if(rc != 0, goto fail);

    *out_fd = fd;
    return rc_ok;
fail:
    close(fd);
    return rc_fatal;
}

#endif /* DUCT_XPORT_H */
