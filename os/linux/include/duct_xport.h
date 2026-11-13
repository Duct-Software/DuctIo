/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_xport.h
 *  @brief Linux transport operations dispatch by transport kind;
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
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

/** @brief Event a @c poll() @c POLLHUP stands for: the local end hanging up,
 *  as @c EPOLLHUP does. */
static constexpr duct_io_ev_flags_t duct_x_poll_hup = io_ev_hup;

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
 *
 *  A coalesced read is one unit to @c MSG_TRUNC: a buffer short of the whole
 *  group loses every datagram in it, not the tail. Zero where the kernel has no
 *  @c UDP_GRO at all; every size below then resolves to the wire's own frame.
 */
#ifdef UDP_GRO
static constexpr size_t duct_x_gro_max = 65536u;
#else
static constexpr size_t duct_x_gro_max = 0u;
#endif

/** @brief Ask @p fd's kernel to hand back several same-source datagrams of one
 *  size as a single read, its per-packet work done once for the group.
 *
 *  Every read of @p fd must then take the segment size back, or it reads a
 *  group of datagrams as one. The kernel takes no size cap, so @p max goes unused.
 *
 *  @return @ref duct_x_gro_max once the kernel has taken the option, 0 when it
 *  refused or the build carries none. A conn sizes its read spans against this
 *  answer; on refusal spans cover a single frame.
 */
static inline size_t duct_xset_dgram_gro([[maybe_unused]] int fd, [[maybe_unused]] size_t max)
{
#ifdef UDP_GRO
    if (max < duct_udp4_payload_max)
        return 0u;
    int rc = setsockopt(fd, SOL_UDP, UDP_GRO, &(int){ 1 }, sizeof(int));
    duct_do_if(rc != 0, return 0u);
    return duct_x_gro_max;
#else
    return 0u;
#endif
}

/** @brief Report the @c virtio_net_hdr length @p fd frames every packet with,
 *  bytes.
 *  Non-zero only for a tun, @c IFF_TUN, opened with @c IFF_VNET_HDR. */
size_t duct_x_vnet_hdr_len(int fd);

/** @brief Enable the checksum and segmentation offloads of vnet tun @p fd.
 *  The set is what @c duct_vnet_cut handles on reads and @c duct_vnet_gro_offer
 *  on writes: partial checksums, TCP over IPv4 and IPv6, ECN, and UDP
 *  segmentation. A kernel that refuses the UDP flags is asked again for the
 *  rest; one that refuses that too logs a @c duct: line and leaves every read
 *  a single packet.
 *  @return @c rc_ok when the kernel took the UDP flags with the rest;
 *          @c rc_not_supported when it took the rest alone; @c rc_fatal when it
 *          took nothing.
 */
duct_result_t duct_x_vnet_offload(int fd);

/** @brief Estimate of what one datagram of a TX batch charges its socket,
 *  bytes: a 1500-byte path's datagram and its share of the skb, rounded up to
 *  a power of two. */
static constexpr int duct_x_dgram_truesize = 2048;

/** @brief Prepare an @c x_udp_peer dial's socket of @p family: kernel buffer
 *  sizes, no IP fragmentation, and the optional busy-poll opt-in.
 *  RX takes @c duct_dgram_sock_rcvbuf, the slack that absorbs io-thread
 *  scheduling gaps. The @c DUCT_DGRAM_RCVBUF environment variable overrides
 *  it per run: a host whose consumer bounds delivery age wants the kernel
 *  queue bounded to match.
 *  TX asks @c duct_x_dgram_truesize per datagram of a @c duct_dgram_tx_batch
 *  batch. The kernel doubles that and reports the socket writable under the
 *  request itself, so io refills while a full batch at a 1500-byte path still
 *  waits at the device; the rest of a backlog stays in the TX ring, where
 *  @c duct_conn_tx_end counts it.
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
    int sndbuf = (int)duct_dgram_tx_batch * duct_x_dgram_truesize;
    if (duct_x_has_gso() && sndbuf < 131072)
        sndbuf = 131072;
    duct_discard setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(int));
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO)
    /* Never let IP fragment a datagram. A protocol that sizes its
     * datagrams to the path already treats fragmentation as a bug --
     * it multiplies the loss probability of one message by the fragment
     * count -- and silent fragmentation also defeats any attempt to probe
     * the path by sending a large datagram and seeing whether it lands.
     * With DF set an oversized send fails loudly (EMSGSIZE) instead. */
    duct_discard setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER,
                            &(int){ IP_PMTUDISC_DO }, sizeof(int));
#endif
#if defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_DO)
    /* IPv6 keeps a mode of its own, which the kernel defaults to letting the
     * host fragment. */
    if (family == AF_INET6)
        duct_discard setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER,
                                &(int){ IPV6_PMTUDISC_DO }, sizeof(int));
#endif
#ifdef SO_BUSY_POLL
    /* Same @c DUCT_BUSY_POLL_US opt-in the epoll model arms per epoll
     * instance, here as the per-socket option the kernel consults from
     * @c poll()/blocking receives (a socket reporting @c POLL_BUSY_LOOP
     * makes @c do_poll spin the device's NAPI queue). Unprivileged and
     * per-socket either way -- never the global @c net.core.busy_poll
     * sysctl, which changes every socket on the host. Harmless where
     * nothing polls this socket that way. */
    static thread_local int busy_poll_env = -1;
    if (busy_poll_env < 0) {
        const char *bp = getenv("DUCT_BUSY_POLL_US");
        busy_poll_env = bp ? atoi(bp) : 0;
    }
    if (busy_poll_env > 0)
        duct_discard setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, &(int){ busy_poll_env }, sizeof(int));
#endif
}

/** @brief Read the send buffer the kernel granted @p fd, bytes.
 *  The doubled figure Linux keeps, twice the request it took.
 *  @return 0 where the kernel answers none. */
static inline uint32_t duct_xget_sndbuf(int fd)
{
    int size = 0;
    return getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, &(socklen_t){ sizeof size }) == 0 && size > 0
         ? (uint32_t)size : 0u;
}

/** @brief Read connected socket @p fd's path MTU, bytes.
 *  @c IP_MTU or @c IPV6_MTU by the socket's own family; a figure past 65535,
 *  loopback's 65536 among them, clamps to 65535.
 *  @return false for an unconnected socket or any refusal, @p out untouched.
 */
static inline bool duct_xget_path_mtu(int fd, uint16_t *out)
{
    int family = 0, mtu = 0;
    socklen_t len = sizeof family;
    if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &family, &len) < 0)
        return false;
    len = sizeof mtu;
    int rc = family == AF_INET6 ? getsockopt(fd, IPPROTO_IPV6, IPV6_MTU, &mtu, &len)
                                : getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu, &len);
    if (rc < 0 || mtu <= 0)
        return false;
    *out = mtu > UINT16_MAX ? UINT16_MAX : (uint16_t)mtu;
    return true;
}

/** @brief Read the congestion control a TCP socket runs.
 *  @return false on a refusal or a build without the option, @p out untouched.
 */
static inline bool duct_xget_tcp_congestion([[maybe_unused]] int fd,
                                            [[maybe_unused]] char out[duct_tcp_cc_name_max])
{
#ifdef TCP_CONGESTION
    char name[duct_tcp_cc_name_max] = {};
    socklen_t len = sizeof name - 1u;
    if (getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, name, &len) < 0)
        return false;
    memcpy(out, name, sizeof name);
    return true;
#else
    return false;
#endif
}

/** @brief Byte offset of @c tcpi_pacing_rate in the kernel's @c struct tcp_info.
 *  glibc's own struct stops before it; the kernel only appends fields. */
static constexpr size_t duct_x_tcp_info_pacing_at = 104u;

/** @brief Read the pacing rate a TCP socket runs at, bytes per second.
 *  @return false on a refusal or a @c tcp_info too short to hold the rate,
 *          @p out untouched.
 */
static inline bool duct_xget_tcp_pacing_rate(int fd, uint64_t *out)
{
    uint8_t info[duct_x_tcp_info_pacing_at + sizeof(uint64_t)];
    socklen_t len = sizeof info;
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, info, &len) < 0 || len < sizeof info)
        return false;
    memcpy(out, info + duct_x_tcp_info_pacing_at, sizeof *out);
    return true;
}

/** @brief Byte offset of @c tcpi_bytes_acked in the kernel's @c struct tcp_info. */
static constexpr size_t duct_x_tcp_info_bytes_acked_at    = 120u;

/** @brief Byte offset of @c tcpi_min_rtt in the kernel's @c struct tcp_info. */
static constexpr size_t duct_x_tcp_info_min_rtt_at        = 148u;

/** @brief Byte offset of @c tcpi_total_rto_recoveries in the kernel's
 *  @c struct tcp_info.
 *  A kernel before 6.7 ends the struct short of it. */
static constexpr size_t duct_x_tcp_info_rto_recoveries_at = 242u;

/** @brief Read a TCP socket's congestion figures off @c TCP_INFO.
 *  The window is @c tcpi_snd_cwnd segments of @c tcpi_snd_mss bytes, clamped to
 *  32 bits, and the bytes unacknowledged @c tcpi_unacked segments of it, clamped
 *  alike. Timeouts count @c tcpi_total_rto_recoveries; a kernel before 6.7
 *  reports none, and there they count the entries into @c TCP_CA_Loss the
 *  reads through @p x saw, so an episode that starts and ends between two
 *  reads goes uncounted.
 *  Bytes outstanding with @c tcpi_bytes_acked unmoved for twice @c tcpi_rto
 *  count one more, once per stretch, timed from the read that last saw it move
 *  or, past a read finding nothing outstanding, from the newest send. Each new
 *  send re-arms the kernel's loss probe past an expired RTO, so a socket fed
 *  faster than the probe fires times out only once its window fills. A kernel
 *  timeout in a stretch already counted adds nothing.
 *  @return false on a refusal or a report too short to hold @c tcpi_min_rtt,
 *          @p out and @p x untouched.
 */
duct_nonnull(1, 3) static inline bool
duct_xget_tcp_stats(duct_x_sock_stats_t *x, int fd, duct_tcp_stats_t *out)
{
    union {
        struct tcp_info head;
        uint8_t         raw[duct_x_tcp_info_rto_recoveries_at + sizeof(uint16_t)];
    } info;
    socklen_t len = sizeof info.raw;
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, info.raw, &len) < 0
        || len < duct_x_tcp_info_min_rtt_at + sizeof(uint32_t))
        return false;
    out->cwnd = (uint32_t)duct_min((uint64_t)info.head.tcpi_snd_cwnd * info.head.tcpi_snd_mss,
                                   (uint64_t)UINT32_MAX);
    out->rtt_us = info.head.tcpi_rtt;
    out->unacked = (uint32_t)duct_min((uint64_t)info.head.tcpi_unacked * info.head.tcpi_snd_mss,
                                      (uint64_t)UINT32_MAX);
    memcpy(&out->min_rtt_us, info.raw + duct_x_tcp_info_min_rtt_at, sizeof out->min_rtt_us);
    uint32_t rose = 0u;
    if (len == sizeof info.raw) {
        uint16_t rto = 0u;
        memcpy(&rto, info.raw + duct_x_tcp_info_rto_recoveries_at, sizeof rto);
        rose = (uint16_t)(rto - x->seen);
        x->seen = rto;
    } else {
        uint32_t in_loss = info.head.tcpi_ca_state == TCP_CA_Loss;
        rose = in_loss && !(x->seen & 1u);
        x->seen += in_loss != (x->seen & 1u);
    }
    bool counted = x->wait_from == duct_x_wait_counted;
    x->timeouts += rose - (rose && counted);
    uint64_t acked = 0u, now = duct_ticks_mono_ns();
    memcpy(&acked, info.raw + duct_x_tcp_info_bytes_acked_at, sizeof acked);
    if (!info.head.tcpi_unacked)
        x->wait_from = 0u;
    else if (!x->wait_from || acked != x->acked) {
        uint64_t sent = x->wait_from ? 0u : (uint64_t)info.head.tcpi_last_data_sent * 1'000'000u;
        x->acked = acked;
        x->wait_from = now - sent;
    } else if (rose)
        x->wait_from = duct_x_wait_counted;
    else if (!counted && now - x->wait_from >= 2u * 1000u * (uint64_t)info.head.tcpi_rto) {
        ++x->timeouts;
        x->wait_from = duct_x_wait_counted;
    }
    out->timeouts = x->timeouts;
    return true;
}

/** @brief Read TCP socket @p fd's unsent bytes.
 *  @return @c duct_tx_unsent_unread always: Linux reads no figure. */
static inline uint64_t duct_xget_tx_unsent([[maybe_unused]] int fd)
{
    return duct_tx_unsent_unread;
}

/** @brief Set socket @p fd's @c TCP_USER_TIMEOUT to @p ms, 0 restoring the
 *  kernel's own bound.
 *  The kernel ends the socket with @c ETIMEDOUT at a retransmission timeout once
 *  its bytes have gone unacknowledged @p ms since their first retransmission,
 *  and once zero-window probing has lasted that long; 1 ends it at its first
 *  timeout.
 *  @return false where the kernel refuses the value. */
static inline bool
duct_xset_tcp_ack_timeout(int fd, uint32_t ms)
{
    return setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &ms, sizeof ms) == 0;
}

/** @brief Least time between two pacing-rate reads of one socket, 50 ms. */
static constexpr uint64_t duct_x_lowat_poll_ns = 50'000'000u;
/** @brief Least lowat a following one takes, bytes. */
static constexpr uint64_t duct_x_lowat_min     = 4096u;

/** @brief Apply a new conn's send options to its socket @p fd and record in @p x
 *  what took.
 *  A TCP socket takes @p notsent_lowat and @p congestion, both best-effort,
 *  Linux taking @c TCP_CONGESTION after connect as well; the lowat it took is
 *  the ceiling a following one stays under, and @p lowat_us applies only under
 *  a lowat. A connected UDP socket records its granted send buffer. Runs on io
 *  before the conn reaches a worker. */
duct_nonnull(1) static inline void
duct_xset_sock_tx(duct_x_sock_tx_t *x, int fd, duct_xport_t xport, uint32_t notsent_lowat,
                  uint32_t lowat_us, [[maybe_unused]] const char *congestion)
{
    if (xport == x_udp_peer) {
        x->lowat_max = duct_xget_sndbuf(fd);
        return;
    }
    if (xport != x_tcp)
        return;
    uint32_t set = duct_xset_tcp_lowat(fd, notsent_lowat);
#ifdef TCP_CONGESTION
    if (congestion)
        duct_discard setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION,
                                congestion, (socklen_t)strlen(congestion));
#endif
    duct_atomic_store(&x->notsent_lowat, set, relaxed);
    x->lowat_max = set;
    x->lowat_us = set ? lowat_us : 0u;
}

/** @brief Outcome of one follow step, a lowat's or a receive buffer's. */
typedef enum duct_x_follow : uint8_t {
    x_follow_none, /**< Nothing due: no bound follows, or too little has passed
                     *  since the last step. */
    x_follow_read, /**< Socket figures read, or tried, with the bound kept. */
    x_follow_set,  /**< Socket figures read and a new bound set. */
} duct_x_follow_t;

/** @brief Set @p x's socket lowat to @c lowat_us of its pacing rate, at most once
 *  per @c duct_x_lowat_poll_ns.
 *  At least @c duct_x_lowat_min; 3/4 of @c lowat_max or more, an overflow among
 *  them, takes @c lowat_max, where the lowat cap lifts. A lowat under the
 *  ceiling within [3/4, 4/3] of the one in force is not set, and a refused set
 *  keeps it. io steps it on a drive the socket refused.
 *  @return @c x_follow_set for a new lowat, @c x_follow_none with nothing due,
 *          @c x_follow_read otherwise. */
duct_nonnull(1) static inline duct_x_follow_t duct_x_sock_tx_follow(duct_x_sock_tx_t *x, int fd)
{
    if (!x->lowat_us)
        return x_follow_none;
    uint64_t now = duct_ticks_mono_ns();
    if (now < x->lowat_at)
        return x_follow_none;
    x->lowat_at = now + duct_x_lowat_poll_ns;
    uint64_t rate = 0u;
    if (!duct_xget_tcp_pacing_rate(fd, &rate) || !rate)
        return x_follow_read;
    uint64_t want = 0u;
    if (duct_ckd_mul(&want, rate / 1000u, (uint64_t)x->lowat_us))
        want = UINT64_MAX;
    want = duct_max(want / 1000u, duct_x_lowat_min);
    if (want * 4u >= (uint64_t)x->lowat_max * 3u)
        want = x->lowat_max;
    uint64_t cur = duct_atomic_load(&x->notsent_lowat, relaxed);
    if (want == cur || (want != x->lowat_max && want * 4u >= cur * 3u && want * 3u <= cur * 4u))
        return x_follow_read;
    uint32_t set = duct_xset_tcp_lowat(fd, (uint32_t)want);
    if (!set)
        return x_follow_read;
    duct_atomic_store(&x->notsent_lowat, set, relaxed);
    return x_follow_set;
}

/** @brief Hand a new TCP conn's receive buffer to the follow, at the size the
 *  kernel opened its socket with.
 *  @c SO_RCVBUFFORCE locks the buffer at that size, which keeps the kernel's
 *  own tuning off it, and the window is clamped to half of it, its floor from
 *  then on. A refusal, a process without @c CAP_NET_ADMIN among them, leaves
 *  the socket to the kernel and @p x zero; any other transport is left alone.
 *  Runs on io before the conn reaches a worker. */
duct_nonnull(1) static inline void duct_xset_sock_rx(duct_x_sock_rx_t *x, int fd, duct_xport_t xport)
{
    int granted = 0;
    socklen_t len = sizeof granted;
    if (xport != x_tcp || getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &granted, &len) < 0 || granted <= 1)
        return;
    int window = granted / 2;
    if (setsockopt(fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &window, sizeof window) != 0
        || setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &window, sizeof window) != 0)
        return;
    x->floor = x->window = x->buf = (uint32_t)window;
    x->at = duct_ticks_mono_ns();
}

/** @brief Step @p x's socket to what its conn consumes, once @c window bytes
 *  have been consumed since the last step.
 *  @p consumed is the conn's running total. The new window is twice the bytes
 *  consumed per round trip, the larger of the socket's smoothed and
 *  receive-side RTT, held between half and twice the last one and never under
 *  @c floor; @c TCP_WINDOW_CLAMP takes it at once. The buffer takes the larger
 *  of the new window and the last, so a shrink reaches it one step late and
 *  the window the peer was last shown still fits whole. A grow sets the buffer
 *  first, a shrink the clamp. Called with the socket's receive queue empty: a
 *  buffer shrunk under queued bytes has the kernel prune them.
 *  @return @c x_follow_set for a new window or buffer, @c x_follow_none with
 *          nothing due, @c x_follow_read otherwise. */
duct_nonnull(1) static inline duct_x_follow_t
duct_x_sock_rx_follow(duct_x_sock_rx_t *x, int fd, uint64_t consumed)
{
    if (!x->at)
        return x_follow_none;
    uint64_t bytes = consumed - x->mark;
    if (bytes < x->window)
        return x_follow_none;
    uint64_t now = duct_ticks_mono_ns(),
             span = now - x->at;
    x->at = now;
    x->mark = consumed;
    struct tcp_info info;
    socklen_t len = sizeof info;
    if (!span || getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &len) < 0)
        return x_follow_read;
    uint64_t rtt_ns = (uint64_t)duct_max(info.tcpi_rtt, info.tcpi_rcv_rtt) * 1000u,
             want = 0u;
    if (!rtt_ns)
        return x_follow_read;
    if (duct_ckd_mul(&want, bytes, rtt_ns))
        want = UINT64_MAX;
    uint32_t prev = x->window;
    want = duct_min(duct_max(want / span * 2u, (uint64_t)duct_max(x->floor, prev / 2u)),
                    duct_min(2u * (uint64_t)prev, (uint64_t)INT32_MAX / 2u));
    uint32_t buf = duct_max((uint32_t)want, prev);
    x->window = (uint32_t)want;
    if (x->window == prev && buf == x->buf)
        return x_follow_read;
    int clamp = (int)x->window,
        req = (int)buf;
    bool grow = buf > x->buf,
         ok = grow ? setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &req, sizeof req) == 0
                     && setsockopt(fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &clamp, sizeof clamp) == 0
                   : setsockopt(fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &clamp, sizeof clamp) == 0
                     && (buf == x->buf
                         || setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &req, sizeof req) == 0);
    if (!ok)
        return x_follow_read;
    x->buf = buf;
    return x_follow_set;
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
#if EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
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
    struct mmsghdr msgs[duct_dgram_tx_batch] = {};
    for (unsigned i = 0u; i < n; ++i) {
        iov[i] = (struct iovec){ .iov_base = bufs[i].data,
                                 .iov_len = bufs[i].size };
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1u;
    }
    int r;
    do
        r = sendmmsg(fd, msgs, n, MSG_NOSIGNAL);
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

/** @brief Read from @p fd into @p dst, one whole datagram or packet per call on a delimited transport.
 *
 *  @c x_udp_peer reads with @c MSG_TRUNC: a datagram longer than @p dst is
 *  dequeued whole and answers @c rc_drop.
 *
 *  @param ctx  Read argument keyed by @p t. @c x_udp: the buffer for the
 *              sender's @c sockaddr, required. @c x_raw_packet: an optional
 *              @c duct_view_u8 span of exactly a vnet tun's header length, which
 *              one @c readv fills ahead of @p dst. Unread for every other
 *              transport.
 *  @param flags  @c recv flags, unread by @c x_raw and @c x_raw_packet.
 *  @param out_seg  Segment size of a coalesced @c x_udp_peer read, 0 for every
 *                  other read; @c nullptr skips the query.
 *  @return @c rc_ok with @p out_read set, 0 for an empty datagram or packet;
 *          @c rc_again on would-block; @c rc_closed for a zero-length read on
 *          any transport but a datagram or packet one; @c rc_drop as above;
 *          @c rc_fatal on any other failure; @c rc_invalid_arg for @c x_udp
 *          without @p ctx and for a transport with no descriptor of its own.
 *          @p out_read is 0 on every outcome but @c rc_ok.
 */
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
        if (ctx) {
            auto head = (const duct_view_u8 *)ctx;
            struct iovec iov[] = {
                { .iov_base = head->data, .iov_len = head->size },
                { .iov_base = dst.data, .iov_len = dst.size },
            };
            do
                n = readv(fd, iov, 2);
            while (n < 0 && errno == EINTR);
            break;
        }
        [[fallthrough]];
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
        /* MSG_TRUNC reports the real datagram size even when it exceeds
         * dst.size, and the check past the switch below turns an oversized n
         * into rc_drop. A coalesced read is one unit to that rule,
         * so a caller sizing the buffer covers a whole group, not one frame:
         * duct_olb_rx_t::read_unit carries that size. The control buffer is
         * recvmsg's cost over recv, so it rides only where a segment size can
         * both arrive and be reported. */
        struct iovec iov = { .iov_base = dst.data, .iov_len = dst.size };
        union {
            struct cmsghdr align;
            char           bytes[CMSG_SPACE(sizeof(uint16_t))];
        } ctl;
        if (!duct_x_gro_max || !out_seg) {
            do
                n = recv(fd, dst.data, dst.size, flags | MSG_TRUNC);
            while (n < 0 && errno == EINTR);
            break;
        }
        struct msghdr mh = {
            .msg_iov = &iov, .msg_iovlen = 1,
            .msg_control = ctl.bytes, .msg_controllen = sizeof ctl.bytes,
        };
        do
            n = recvmsg(fd, &mh, flags | MSG_TRUNC);
        while (n < 0 && errno == EINTR);
#ifdef UDP_GRO
        if (n > 0 && out_seg)
            for (auto cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm))
                if (cm->cmsg_level == SOL_UDP && cm->cmsg_type == UDP_GRO) {
                    uint16_t seg = 0u;
                    memcpy(&seg, CMSG_DATA(cm), sizeof seg);
                    *out_seg = seg;
                }
#endif
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
#if EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:
#endif
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
 *  @p bufs goes to the kernel as it lies, which takes 1024 spans at most: more
 *  answer @c rc_fatal.
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
    static_assert(sizeof(duct_view_u8) == sizeof(struct iovec)
                  && offsetof(duct_view_u8, data) == offsetof(struct iovec, iov_base)
                  && offsetof(duct_view_u8, size) == offsetof(struct iovec, iov_len),
                  "duct_view_u8 lays out as struct iovec, so the spans go to the kernel as they are");
    /* writev and sendmsg read the array and never write it, so the cast drops const safely. */
    auto iov = (struct iovec *)(uintptr_t)bufs;
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
#if EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:
#endif
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
duct_xwrite_batch(int fd, duct_xport_t t, struct mmsghdr *msgs, unsigned n, unsigned *out_resolved)
{
    duct_do_if(t != x_udp, *out_resolved = 0u; return rc_invalid_arg);
    unsigned resolved = 0u;
    duct_result_t rc = rc_ok;
    while (resolved < n) {
        errno = 0;
        int r;
        do
            r = sendmmsg(fd, msgs + resolved, n - resolved, MSG_NOSIGNAL);
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

#ifdef UDP_SEGMENT
/** @brief Hand the @p cnt iovecs from @p base to the kernel as one payload it
 *  slices into @p seg-byte datagrams, sent to @p addr, or to the connected peer
 *  when @p addr is null.
 *  @return true once the kernel has them; false leaves them unsent, with
 *          @c errno still holding the refusal @ref duct_x_gso_result classifies.
 */
duct_nonnull(2) static inline bool
duct_xsend_gso_iov(int fd, struct iovec *base, size_t cnt, size_t seg,
                   struct sockaddr_storage *addr, socklen_t addrlen)
{
    union {
        struct cmsghdr align;
        char           bytes[CMSG_SPACE(sizeof(uint16_t))];
    } ctl = {};
    struct msghdr mh = {
        .msg_name = addr, .msg_namelen = addrlen,
        .msg_iov = base, .msg_iovlen = cnt,
        .msg_control = ctl.bytes, .msg_controllen = sizeof ctl.bytes,
    };
    auto cm = CMSG_FIRSTHDR(&mh);
    cm->cmsg_level = SOL_UDP;
    cm->cmsg_type = UDP_SEGMENT;
    cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
    uint16_t size = (uint16_t)seg;
    memcpy(CMSG_DATA(cm), &size, sizeof size);

    ssize_t sent;
    do
        sent = sendmsg(fd, &mh, MSG_NOSIGNAL);
    while (sent < 0 && errno == EINTR);
    return sent >= 0;
}
#endif

/** @brief Classify a @c UDP_SEGMENT write the kernel took, @p took, or refused
 *  with @c errno.
 *  @return @c rc_ok once taken; @c rc_again for a code worth repeating;
 *  @c rc_not_supported for every other code, which sends the group unsegmented. */
static inline duct_result_t duct_x_gso_result(bool took)
{
    if (took)
        return rc_ok;
    switch (errno) {
    case EAGAIN:
#if EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
    case ENOBUFS:
        return rc_again;
    case EMSGSIZE:
    case EINVAL:
    case EIO:
    default:
        duct_dbg_errf("errno %d", errno);
        return rc_not_supported;
    }
}

/** @brief Send @p n datagrams out connected socket @p fd as one @c UDP_SEGMENT
 *  write cut at @p bufs[0]'s length.
 *  @p n is at most @ref duct_x_gso_segs_max, the cut @ref duct_x_gso_group makes.
 *  @return @c rc_ok with all @p n taken; @c rc_again for a code worth
 *  repeating; @c rc_not_supported for every other code, which sends the group
 *  unsegmented, and always in a build whose headers lack @c UDP_SEGMENT.
 */
duct_nonnull(2) static inline duct_result_t
duct_xsend_gso_bufs(int fd, const duct_view_u8 *bufs, unsigned n)
{
#ifdef UDP_SEGMENT
    struct iovec iov[duct_x_gso_segs_max];
    for (unsigned i = 0u; i < n; ++i)
        iov[i] = (struct iovec){ .iov_base = bufs[i].data, .iov_len = bufs[i].size };
    return duct_x_gso_result(duct_xsend_gso_iov(fd, iov, n, bufs[0].size, nullptr, 0));
#else
    return rc_not_supported;
#endif
}

/** @brief Send @p n datagrams to @p msgs[0]'s peer as one @c UDP_SEGMENT write
 *  cut at that datagram's length, each from its header and payload spans.
 *  @p n is at most @ref duct_x_gso_segs_max, and every entry shares that peer:
 *  both are the cut @ref duct_x_gso_group makes.
 *  @return @c rc_ok with all @p n taken; @c rc_again for a code worth
 *  repeating; @c rc_not_supported for every other code, and always in a build
 *  whose headers lack @c UDP_SEGMENT.
 */
duct_nonnull(2) static inline duct_result_t
duct_xsend_gso_peers(int fd, const duct_dgram_out_t *msgs, unsigned n)
{
#ifdef UDP_SEGMENT
    struct sockaddr_storage ss;
    socklen_t len = (socklen_t)duct_io_sockaddr_from_peer(&msgs[0].peer, &ss);
    struct iovec iov[2u * duct_x_gso_segs_max];
    size_t cnt = 0u;
    for (unsigned i = 0u; i < n; ++i) {
        if (msgs[i].hdr.size)
            iov[cnt++] = (struct iovec){ .iov_base = msgs[i].hdr.data,
                                         .iov_len = msgs[i].hdr.size };
        iov[cnt++] = (struct iovec){ .iov_base = msgs[i].body.data,
                                     .iov_len = msgs[i].body.size };
    }
    return duct_x_gso_result(duct_xsend_gso_iov(fd, iov, cnt, duct_x_dgram_len_out(&msgs[0]),
                                                &ss, len));
#else
    return rc_not_supported;
#endif
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
    struct mmsghdr          msgs[n];
    unsigned iv = 0u;
    for (unsigned i = 0u; i < n; ++i) {
        socklen_t len = (socklen_t)duct_io_sockaddr_from_peer(&msgs_in[i].peer, &addrs[i]);
        unsigned start = iv;
        if (msgs_in[i].hdr.size)
            iovs[iv++] = (struct iovec){ .iov_base = msgs_in[i].hdr.data,
                                         .iov_len = msgs_in[i].hdr.size };
        iovs[iv++] = (struct iovec){ .iov_base = msgs_in[i].body.data,
                                     .iov_len = msgs_in[i].body.size };
        msgs[i] = (struct mmsghdr){
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

/** @brief Fill up to @p n of @p bufs from @p fd in one @c recvmmsg, reporting
 *  each datagram's length in @p out_lens.
 *  @p out_peers takes each source and @p out_segs a coalesced read's segment
 *  size; @c nullptr skips either report. Receive counterpart of
 *  @ref duct_xsend_peers: the buf -> mmsghdr translation stays in this header
 *  so the portable read loops carry no platform case. A datagram too large for
 *  its buffer reports @ref duct_dgram_len_truncated as its length; it still
 *  occupies its entry, so the dry-socket count below keeps counting what the
 *  kernel handed back.
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
    struct mmsghdr          msgs[n];
    union {
        struct cmsghdr align;
        char           bytes[CMSG_SPACE(sizeof(uint16_t))];
    } ctls[n];
    for (uint32_t i = 0u; i < n; ++i) {
        iovs[i] = (struct iovec){ .iov_base = bufs[i].data, .iov_len = bufs[i].size };
        msgs[i] = (struct mmsghdr){ .msg_hdr = { .msg_iov = &iovs[i], .msg_iovlen = 1 } };
        if (out_peers) {
            msgs[i].msg_hdr.msg_name = &addrs[i];
            msgs[i].msg_hdr.msg_namelen = sizeof addrs[i];
        }
        if (out_segs) {
            msgs[i].msg_hdr.msg_control = ctls[i].bytes;
            msgs[i].msg_hdr.msg_controllen = sizeof ctls[i].bytes;
        }
    }
    int r;
    do
        r = recvmmsg(fd, msgs, n, MSG_DONTWAIT, nullptr);
    while (r < 0 && errno == EINTR);
    if (r < 0)
        switch (errno) {
        case EAGAIN:
#if EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:
#endif
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
        if (!out_segs)
            continue;
        out_segs[i] = 0u;
#ifdef UDP_GRO
        for (auto cm = CMSG_FIRSTHDR(&msgs[i].msg_hdr); cm;
             cm = CMSG_NXTHDR(&msgs[i].msg_hdr, cm))
            if (cm->cmsg_level == SOL_UDP && cm->cmsg_type == UDP_GRO) {
                uint16_t seg = 0u;
                memcpy(&seg, CMSG_DATA(cm), sizeof seg);
                out_segs[i] = seg;
                break;
            }
#endif
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

/** @brief This platform's division of a bound port: @c SO_REUSEPORT spreads it. */
static constexpr duct_x_port_share_t duct_x_port_sharing = x_port_share_spread;

/** @brief Availability of AF_UNIX stream listeners on this platform: always. */
static constexpr bool duct_x_local_floor = true;

/** @brief Availability of sessions opened over a caller's packet fd on this platform: always. */
static constexpr bool duct_x_packet_fd_session = true;

/** @brief Accept one connection on @p listener_fd, non-blocking and close-on-exec.
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
        fd = accept4(listener_fd, ctx,
                     &(socklen_t){ sizeof(struct sockaddr_storage) },
                     SOCK_NONBLOCK | SOCK_CLOEXEC);
    while (fd == duct_sock_bad && errno == EINTR);
    if (fd == duct_sock_bad)
        switch (errno) {
        case EAGAIN:
#if EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:
#endif
            return rc_again;
        case EMFILE:
            return rc_defer;
        default:
            duct_dbg_errf("errno %d", errno);
            return rc_fatal;
        }
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
 *  @c SOCK_NONBLOCK | @c SOCK_CLOEXEC, an @c SO_BINDTODEVICE bind to a nonzero
 *  @p egress_if — so the dial leaves and is answered through it alone — and
 *  the per-xport socket options. Nothing connects here.
 *  @p congestion goes unused: Linux takes @c TCP_CONGESTION on a connected
 *  socket too, which @c duct_xset_sock_tx sets once the conn exists.
 *  @return The descriptor, or @c duct_sock_bad when @c socket() or the
 *          @p egress_if bind fails.
 */
static inline duct_sock_t
duct_xsocket(int family, duct_xport_t xport, uint32_t egress_if,
             [[maybe_unused]] const char *congestion)
{
    int type = xport == x_udp_peer ? SOCK_DGRAM : SOCK_STREAM;
    duct_sock_t fd = socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd == duct_sock_bad)
        return fd;
    if (egress_if) {
        char device[IF_NAMESIZE];
        bool bound = if_indextoname(egress_if, device)
                  && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device, strlen(device) + 1u) == 0;
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
 *  @retval rc_again         @c x_local only: the listener's backlog is full.
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

    int fd = socket(local.ss_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    duct_do_if(fd == duct_sock_bad, return rc_fatal);

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
