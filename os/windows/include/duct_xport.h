/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_xport.h
 *  @brief Winsock transport operations dispatch by transport kind;
 *  portable across all DUCT_EVENTS_MODEL variants.
 */

#ifndef DUCT_XPORT_H
#define DUCT_XPORT_H

#include "duct_core.h"
#include "duct_dgram_out.h"
#include "duct_events.h"
#include "duct_types.h"
#include "duct_xsock.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mswsock.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif

/** @brief Event a @c WSAPoll() @c POLLHUP stands for: a read. A graceful peer
 *  FIN raises it without @c POLLIN, and @c recv's own 0-byte end then
 *  classifies the close. */
static constexpr duct_io_ev_flags_t duct_x_poll_hup = io_ev_read;

static inline void duct_xset_nonblock(SOCKET fd)
{
    duct_discard ioctlsocket(fd, FIONBIO, &(u_long){ 1 });
}

/** @brief Disable Nagle's algorithm on a stream socket. Best-effort: harmless
 *  if @p fd's protocol family does not support @c TCP_NODELAY. Without this,
 *  small frequent writes under sustained backpressure interact with delayed
 *  ACK to stall tens to hundreds of ms per write.
 */
static inline void duct_xset_tcp_nodelay(SOCKET fd)
{
    duct_discard setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                            (const char *)&(int){ 1 }, sizeof(int));
}

/** @brief The congestion controls Winsock offers, by the number
 *  @c TCP_CONGESTION_ALGORITHM takes for each, the numbering of
 *  @c MSFT_NetTCPSetting.CongestionProvider. */
static const struct {
    DWORD id;       /**< Winsock's number for it. */
    char  name[8];  /**< Its name, the one a readback answers. */
    char  alias[8]; /**< The Linux name a protocol asks by, bbr standing for
                      *  the one BBR Winsock offers; empty for none. */
} duct_x_tcp_cc_ids[] = {
    { 1u, "newreno", "reno" }, { 2u, "ctcp", "" }, { 3u, "dctcp", "" },
    { 4u, "ledbat", "" }, { 5u, "cubic", "" }, { 6u, "bbr2", "bbr" },
};

/** @brief Set stream socket @p fd's congestion control to the one
 *  @p congestion names.
 *  Winsock takes the option only before connect and refuses it after with
 *  @c WSAEINVAL. A name the table lacks, @c nullptr and a refusal all leave
 *  the host's default. */
static inline void duct_xset_tcp_congestion(SOCKET fd, const char *congestion)
{
    if (!congestion)
        return;
    for (size_t i = 0u; i < sizeof duct_x_tcp_cc_ids / sizeof duct_x_tcp_cc_ids[0]; ++i)
        if (strcmp(congestion, duct_x_tcp_cc_ids[i].name) == 0
            || (duct_x_tcp_cc_ids[i].alias[0] && strcmp(congestion, duct_x_tcp_cc_ids[i].alias) == 0)) {
            duct_discard setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION_ALGORITHM,
                                    (const char *)&duct_x_tcp_cc_ids[i].id, sizeof(DWORD));
            return;
        }
}

/** @brief Prepare an @c x_udp_peer dial's socket of @p family: kernel buffer
 *  sizes and no IP fragmentation.
 *  RX takes @c duct_dgram_sock_rcvbuf, the slack that absorbs io-thread
 *  scheduling gaps; TX takes @c duct_dgram_sock_sndbuf, the slack that
 *  carries a stall in the NIC taking packets. The @c DUCT_DGRAM_RCVBUF
 *  environment variable overrides the RX size per run: a host whose consumer
 *  bounds delivery age wants the kernel queue bounded to match.
 */
static inline void duct_xset_dgram_bufs(SOCKET fd, [[maybe_unused]] int family)
{
    static thread_local int rcvbuf_env = -1; /* per-thread resolve: no shared write */
    if (rcvbuf_env < 0) {
        const char *s = getenv("DUCT_DGRAM_RCVBUF");
        rcvbuf_env = s ? atoi(s) : 0;
    }
    duct_discard setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                            (const char *)&(int){ rcvbuf_env > 0 ? rcvbuf_env : (int)duct_dgram_sock_rcvbuf }, sizeof(int));
    duct_discard setsockopt(fd, SOL_SOCKET, SO_SNDBUF,
                            (const char *)&(int){ (int)duct_dgram_sock_sndbuf }, sizeof(int));
#ifdef IP_DONTFRAGMENT
    /* Never let IP fragment a datagram. Fragmentation multiplies one
     * message's loss probability by its fragment count, and it defeats
     * probing the path by sending a large datagram and seeing whether it
     * lands: fragments arrive and reassemble whatever the path carries
     * whole, so an oversized probe reports success. */
    duct_discard setsockopt(fd, IPPROTO_IP, IP_DONTFRAGMENT,
                            (const char *)&(DWORD){ TRUE }, sizeof(DWORD));
#endif
#ifdef IPV6_DONTFRAG
    /* IP_DONTFRAGMENT reaches IPv4 alone; IPv6 uses a separate option. */
    if (family == AF_INET6)
        duct_discard setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG,
                                (const char *)&(DWORD){ TRUE }, sizeof(DWORD));
#endif
}

/** @brief Read connected socket @p fd's path MTU, bytes.
 *  @c IP_MTU or @c IPV6_MTU by the family @c getsockname reports; a figure
 *  past 65535 clamps to 65535.
 *  @return false for an unconnected socket or any refusal, @p out untouched.
 */
static inline bool duct_xget_path_mtu(SOCKET fd, uint16_t *out)
{
    struct sockaddr_storage ss;
    int slen = sizeof ss;
    if (getsockname(fd, (struct sockaddr *)&ss, &slen) != 0)
        return false;
    DWORD mtu = 0u;
    int len = sizeof mtu;
    int rc = ss.ss_family == AF_INET6
           ? getsockopt(fd, IPPROTO_IPV6, IPV6_MTU, (char *)&mtu, &len)
           : getsockopt(fd, IPPROTO_IP, IP_MTU, (char *)&mtu, &len);
    if (rc != 0 || mtu == 0u)
        return false;
    *out = mtu > UINT16_MAX ? UINT16_MAX : (uint16_t)mtu;
    return true;
}

/** @brief Read the congestion control stream socket @p fd runs, by name.
 *  A connected socket reads what its dial set before connect, else the host's
 *  default.
 *  @return false on a refusal or a number the table lacks, the 0 an
 *          unconnected socket reads among them, @p out untouched. */
static inline bool duct_xget_tcp_congestion(SOCKET fd, char out[duct_tcp_cc_name_max])
{
    DWORD id = 0u;
    int len = sizeof id;
    if (getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION_ALGORITHM, (char *)&id, &len) != 0)
        return false;
    for (size_t i = 0u; i < sizeof duct_x_tcp_cc_ids / sizeof duct_x_tcp_cc_ids[0]; ++i)
        if (duct_x_tcp_cc_ids[i].id == id) {
            memcpy(out, duct_x_tcp_cc_ids[i].name, sizeof duct_x_tcp_cc_ids[i].name);
            return true;
        }
    return false;
}

/** @brief Winsock's @c TCP_INFO_v0, the reply @c SIO_TCP_INFO gives for version 0.
 *  Declared here: the SDK's own sits behind @c NTDDI_WIN10_RS2, past this build's
 *  @c _WIN32_WINNT. */
typedef struct {
    DWORD   State;
    ULONG   Mss;
    ULONG64 ConnectionTimeMs;
    BOOLEAN TimestampsEnabled;
    ULONG   RttUs;
    ULONG   MinRttUs;
    ULONG   BytesInFlight;
    ULONG   Cwnd;
    ULONG   SndWnd;
    ULONG   RcvWnd;
    ULONG   RcvBuf;
    ULONG64 BytesOut;
    ULONG64 BytesIn;
    ULONG   BytesReordered;
    ULONG   BytesRetrans;
    ULONG   FastRetrans;
    ULONG   DupAcksIn;
    ULONG   TimeoutEpisodes;
    UCHAR   SynRetrans;
} duct_x_tcp_info_v0_t;

static_assert(offsetof(duct_x_tcp_info_v0_t, RttUs) == 20u
              && offsetof(duct_x_tcp_info_v0_t, Cwnd) == 32u
              && offsetof(duct_x_tcp_info_v0_t, TimeoutEpisodes) == 80u,
              "duct_x_tcp_info_v0_t must lay out as TCP_INFO_v0");

/** @brief Read a TCP socket's congestion figures off @c SIO_TCP_INFO.
 *  Timeouts are @c TimeoutEpisodes, and the bytes unacknowledged
 *  @c BytesInFlight.
 *  @return false where Winsock refuses the ioctl or answers short of
 *          @c TimeoutEpisodes, @p out untouched.
 */
duct_nonnull(3) static inline bool
duct_xget_tcp_stats([[maybe_unused]] void *x, SOCKET fd, duct_tcp_stats_t *out)
{
    DWORD version = 0u, got = 0u;
    duct_x_tcp_info_v0_t info;
    if (WSAIoctl(fd, _WSAIORW(IOC_VENDOR, 39), &version, sizeof version, &info, sizeof info,
                 &got, nullptr, nullptr) != 0
        || got < offsetof(duct_x_tcp_info_v0_t, TimeoutEpisodes) + sizeof info.TimeoutEpisodes)
        return false;
    *out = (duct_tcp_stats_t){ .cwnd = info.Cwnd, .rtt_us = info.RttUs,
                               .min_rtt_us = info.MinRttUs, .timeouts = info.TimeoutEpisodes,
                               .unacked = info.BytesInFlight };
    return true;
}

/** @brief Read TCP socket @p fd's unsent bytes off its connection's ESTATS,
 *  @c CurAppWQueue.
 *  The stack keeps the statistics per connection and turns them on for an
 *  elevated process alone: the first reading of a connection turns them on and
 *  answers unread, as does every reading by a process the stack refuses.
 *  Defined in @c duct_estats.c, the one engine file that includes
 *  @c iphlpapi.h.
 *  @return the bytes, or @ref duct_tx_unsent_unread where there are none to read. */
uint64_t duct_xget_tx_unsent(SOCKET fd);

/** @brief Set socket @p fd's unacknowledged-data bound to @p ms, 0 restoring the
 *  system's own.
 *  Winsock resets the connection on a timer of its own once its oldest
 *  unacknowledged segment has waited @p ms since its first send. A bound goes
 *  through @c TCP_MAXRTMS, which refuses 0 and anything under 20 ms, and 0
 *  through @c TCP_MAXRT, which clears both.
 *  @return false where Winsock refuses the value. */
static inline bool
duct_xset_tcp_ack_timeout(SOCKET fd, uint32_t ms)
{
    return setsockopt(fd, IPPROTO_TCP, ms ? TCP_MAXRTMS : TCP_MAXRT,
                      (const char *)&(DWORD){ ms }, sizeof(DWORD)) == 0;
}

/** @brief Leave a new conn's socket send options as Winsock set them.
 *  Winsock takes @c TCP_CONGESTION_ALGORITHM only before connect, which a dial
 *  sets in @ref duct_xconnect. */
static inline void
duct_xset_sock_tx([[maybe_unused]] duct_x_sock_tx_t *x, [[maybe_unused]] SOCKET fd,
                  [[maybe_unused]] duct_xport_t xport, [[maybe_unused]] uint32_t notsent_lowat,
                  [[maybe_unused]] uint32_t lowat_us, [[maybe_unused]] const char *congestion)
{
}

/** @brief Outcome of one follow step, a lowat's or a receive buffer's. */
typedef enum duct_x_follow : uint8_t {
    x_follow_none, /**< Nothing due. */
    x_follow_read, /**< Socket figures read, or tried, with the bound kept. */
    x_follow_set,  /**< Socket figures read and a new bound set. */
} duct_x_follow_t;

/** @brief Skip the lowat follow step.
 *  No lowat runs on Winsock, so every step answers @c x_follow_none. */
static inline duct_x_follow_t
duct_x_sock_tx_follow([[maybe_unused]] void *x, [[maybe_unused]] SOCKET fd)
{
    return x_follow_none;
}

/** @brief Leave a new conn's receive buffer to Winsock's own tuning. */
static inline void
duct_xset_sock_rx([[maybe_unused]] void *x, [[maybe_unused]] SOCKET fd,
                  [[maybe_unused]] duct_xport_t xport)
{
}

/** @brief Skip the receive follow step.
 *  No receive state is kept on Winsock, so every step answers
 *  @c x_follow_none. */
static inline duct_x_follow_t
duct_x_sock_rx_follow([[maybe_unused]] void *x, [[maybe_unused]] SOCKET fd,
                      [[maybe_unused]] uint64_t consumed)
{
    return x_follow_none;
}

/** @brief True when @p err says to send these same bytes again later.
 *  @c WSAENOBUFS joins would-block: Winsock is out of buffer space this
 *  instant, which the next drive finds cleared. Other codes
 *  indicate a permanent message error; repeating the send repeats the failure.
 */
static inline bool duct_x_send_retryable(int err)
{
    switch (err) {
    case WSAEWOULDBLOCK:
    case WSAENOBUFS:
        return true;
    default:
        return false;
    }
}

/** @brief Verdict on one datagram send whose result is @p n: true once the
 *  caller may move past those bytes, false to leave them queued.
 *  A send that failed for good answers true — the bytes go nowhere, and a
 *  queue that keeps them stops every datagram behind them too. The guard
 *  names that spot, since nothing downstream sees the error code.
 */
static inline bool duct_x_send_consumed(int n)
{
    if (n != SOCKET_ERROR)
        return true;
    bool drop = !duct_x_send_retryable(WSAGetLastError());
    duct_do_if(drop, return true);
    return false;
}

/** @name UDP send segmentation and receive coalescing, as the Windows stack numbers them
 *  MinGW declares none of the three. @c UDP_SEND_MSG_SIZE and
 *  @c UDP_RECV_MAX_COALESCED_SIZE are options at @c IPPROTO_UDP;
 *  @c UDP_COALESCED_INFO is the cmsg type carrying a coalesced read's segment
 *  size.
 *  @{ */
#ifndef UDP_SEND_MSG_SIZE
#define UDP_SEND_MSG_SIZE 2
#endif
#ifndef UDP_RECV_MAX_COALESCED_SIZE
#define UDP_RECV_MAX_COALESCED_SIZE 3
#endif
#ifndef UDP_COALESCED_INFO
#define UDP_COALESCED_INFO 3
#endif
/** @} */

/** @brief Room for one cmsg carrying a @c DWORD, aligned for the
 *  @c WSA_CMSG macros that walk it. */
typedef union duct_x_cmsg_dword {
    WSACMSGHDR align;
    char       bytes[WSA_CMSG_SPACE(sizeof(DWORD))];
} duct_x_cmsg_dword_t;

/** @brief One @c WSASendMsg message for up to @c duct_x_gso_segs_max datagrams,
 *  with room for a destination and the segment-size cmsg. */
typedef struct duct_x_gso_msg {
    WSAMSG msg;                     /**< The message, pointing into the fields below. */
    WSABUF iov[2u * duct_x_gso_segs_max]; /**< Spans: one per record, or a header
                                           *  and a payload per addressed datagram. */
    duct_x_cmsg_dword_t ctl;        /**< Segment-size cmsg, aligned as @c WSACMSGHDR. */
    struct sockaddr_storage addr;   /**< Destination an addressed message names. */
} duct_x_gso_msg_t;

/** @brief Point @p m at its first @p cnt spans, cut at @p seg bytes when its
 *  @p n datagrams are more than one.
 *  The segment size rides per message, which leaves the socket's plain sends
 *  unsegmented.
 *  @return @p m's message. */
duct_nonnull(1) static inline WSAMSG *
duct_x_gso_msg_seg(duct_x_gso_msg_t *m, DWORD cnt, unsigned n, size_t seg)
{
    m->msg.lpBuffers = m->iov;
    m->msg.dwBufferCount = cnt;
    if (n < 2u)
        return &m->msg;
    m->ctl = (duct_x_cmsg_dword_t){};
    m->msg.Control = (WSABUF){ sizeof m->ctl.bytes, m->ctl.bytes };
    auto cm = WSA_CMSG_FIRSTHDR(&m->msg);
    cm->cmsg_level = IPPROTO_UDP;
    cm->cmsg_type = UDP_SEND_MSG_SIZE;
    cm->cmsg_len = WSA_CMSG_LEN(sizeof(DWORD));
    DWORD size = (DWORD)seg;
    memcpy(WSA_CMSG_DATA(cm), &size, sizeof size);
    return &m->msg;
}

/** @brief Fill @p m to send @p n records from @p bufs out a connected socket,
 *  cut at @p bufs[0]'s length when @p n is above 1.
 *  @p n is at most @ref duct_x_gso_segs_max.
 *  @return @p m's message. */
duct_nonnull(1, 2) static inline WSAMSG *
duct_x_gso_msg_bufs(duct_x_gso_msg_t *m, const duct_view_u8 *bufs, unsigned n)
{
    m->msg = (WSAMSG){};
    for (unsigned i = 0u; i < n; ++i)
        m->iov[i] = (WSABUF){ (ULONG)bufs[i].size, (char *)bufs[i].data };
    return duct_x_gso_msg_seg(m, n, n, bufs[0].size);
}

/** @brief Fill @p m to send @p n datagrams to @p msgs[0]'s peer, each from its
 *  header and payload spans, cut at that datagram's length when @p n is above 1.
 *  @p n is at most @ref duct_x_gso_segs_max, and every entry shares that peer.
 *  @return @p m's message. */
duct_nonnull(1, 2) static inline WSAMSG *
duct_x_gso_msg_peers(duct_x_gso_msg_t *m, const duct_dgram_out_t *msgs, unsigned n)
{
    int len = duct_io_sockaddr_from_peer(&msgs[0].peer, &m->addr);
    m->msg = (WSAMSG){ .name = (LPSOCKADDR)&m->addr, .namelen = len };
    DWORD cnt = 0u;
    for (unsigned i = 0u; i < n; ++i) {
        if (msgs[i].hdr.size)
            m->iov[cnt++] = (WSABUF){ (ULONG)msgs[i].hdr.size, (char *)msgs[i].hdr.data };
        m->iov[cnt++] = (WSABUF){ (ULONG)msgs[i].body.size, (char *)msgs[i].body.data };
    }
    return duct_x_gso_msg_seg(m, cnt, n, duct_x_dgram_len_out(&msgs[0]));
}

/** @brief Classify a @c WSASendMsg return @p r, reading the Winsock code of a
 *  refusal.
 *  @return @c rc_ok once sent; @c rc_again for a code worth repeating;
 *  @c rc_not_supported for every other code, which sends the group unsegmented. */
static inline duct_result_t duct_x_gso_result(int r)
{
    if (r != SOCKET_ERROR)
        return rc_ok;
    int err = WSAGetLastError();
    switch (err) {
    case WSAEWOULDBLOCK:
    case WSAENOBUFS:
        return rc_again;
    case WSAEMSGSIZE:
    case WSAEINVAL:
    default:
        duct_dbg_errf("WSA error %d", err);
        return rc_not_supported;
    }
}

/** @brief Send @p n datagrams out connected socket @p fd as one USO write cut
 *  at @p bufs[0]'s length.
 *  @return @c rc_ok with all @p n taken; @c rc_again for a code worth
 *  repeating; @c rc_not_supported for every other code, which sends the group
 *  unsegmented. */
duct_nonnull(2) static inline duct_result_t
duct_xsend_gso_bufs(SOCKET fd, const duct_view_u8 *bufs, unsigned n)
{
    duct_x_gso_msg_t m;
    return duct_x_gso_result(WSASendMsg(fd, duct_x_gso_msg_bufs(&m, bufs, n), 0,
                                        &(DWORD){ 0 }, nullptr, nullptr));
}

/** @brief Send @p n datagrams to @p msgs[0]'s peer as one USO write cut at that
 *  datagram's length.
 *  @return @c rc_ok with all @p n taken; @c rc_again for a code worth
 *  repeating; @c rc_not_supported for every other code, which sends the group
 *  unsegmented. */
duct_nonnull(2) static inline duct_result_t
duct_xsend_gso_peers(SOCKET fd, const duct_dgram_out_t *msgs, unsigned n)
{
    duct_x_gso_msg_t m;
    return duct_x_gso_result(WSASendMsg(fd, duct_x_gso_msg_peers(&m, msgs, n), 0,
                                        &(DWORD){ 0 }, nullptr, nullptr));
}

/** @brief Send @p n whole datagrams out the connected socket @p fd, one span
 *  each.
 *
 *  One @c send per datagram, stopping at the first code worth repeating;
 *  @p n is at most @c duct_dgram_tx_batch.
 *
 *  @param out_sent datagrams Winsock took, a prefix of @p bufs.
 *  @return @c rc_ok with @p out_sent up to @p n, short of it once the socket
 *  fills; @c rc_drop for a first datagram too large for the path; @c rc_fatal
 *  for a socket to close.
 */
duct_nonnull(2, 4) static inline duct_result_t
duct_xsend_bufs(SOCKET fd, const duct_view_u8 *bufs, unsigned n, unsigned *out_sent)
{
    *out_sent = 0u;
    assert(n && n <= duct_dgram_tx_batch);
    for (unsigned i = 0u; i < n; ++i) {
        int r = send(fd, (const char *)bufs[i].data, (int)bufs[i].size, 0);
        if (r != SOCKET_ERROR) {
            ++*out_sent;
            continue;
        }
        int send_err = WSAGetLastError();
        if (duct_x_send_retryable(send_err))
            return rc_ok;
        switch (send_err) {
        case WSAEMSGSIZE:
            duct_dbg_errf("WSAEMSGSIZE, %zu bytes", bufs[i].size);
            return i ? rc_ok : rc_drop;
        default:
            duct_dbg_errf("WSA error %d", send_err);
            return rc_fatal;
        }
    }
    return rc_ok;
}

/** @brief The Winsock extension @p guid names, resolved through @p fd.
 *  @return nullptr where the lookup finds nothing. */
static inline void *duct_x_wsa_ext_pfn(SOCKET fd, GUID guid)
{
    void *fn = nullptr;
    duct_discard WSAIoctl(fd, SIO_GET_EXTENSION_FUNCTION_POINTER,
                          &guid, sizeof guid, &fn, sizeof fn,
                          &(DWORD){ 0 }, nullptr, nullptr);
    return fn;
}

/** @brief @c WSARecvMsg, resolved once at startup by @c os/windows/duct_core.c.
 *  @return nullptr where that lookup found nothing, which keeps every read on
 *          plain @c recv. */
LPFN_WSARECVMSG duct_x_wsa_recvmsg(void);

/** @brief One @c WSARecvMsg message over a single span, with room for the
 *  segment-size cmsg. */
typedef struct duct_rx_msg {
    WSAMSG              msg; /**< The message, pointing into @c iov and @c ctl. */
    WSABUF              iov; /**< The read span. */
    duct_x_cmsg_dword_t ctl; /**< Control area a coalesced read reports its segment size in. */
} duct_rx_msg_t;

/** @brief Fill @p m to read into @p dst, naming the source in @p name when
 *  that is not null.
 *  The control area starts zeroed: an aborted read leaves it untouched, and
 *  zeroes read as no header at all.
 *  @return @p m's message. */
duct_nonnull(1) static inline WSAMSG *
duct_rx_msg(duct_rx_msg_t *m, duct_view_u8 dst, struct sockaddr_storage *name)
{
    m->iov = (WSABUF){ (ULONG)dst.size, (char *)dst.data };
    m->ctl = (duct_x_cmsg_dword_t){};
    m->msg = (WSAMSG){
        .name = (LPSOCKADDR)name, .namelen = name ? (INT)sizeof *name : 0,
        .lpBuffers = &m->iov, .dwBufferCount = 1u,
        .Control = { sizeof m->ctl.bytes, m->ctl.bytes },
    };
    return &m->msg;
}

/** @brief Find the coalesced segment size in control area @p ctl.
 *  The walk stops at a header shorter than a header, which is how a zeroed
 *  area reads: a zero @c cmsg_len holds @c WSA_CMSG_NXTHDR on the same header
 *  forever.
 *  @return the segment size, 0 for a read that coalesced nothing. */
static inline size_t duct_x_gro_seg(WSABUF ctl)
{
    WSAMSG view = { .Control = ctl };
    for (auto cm = WSA_CMSG_FIRSTHDR(&view); cm && cm->cmsg_len >= sizeof *cm;
         cm = WSA_CMSG_NXTHDR(&view, cm)) {
        if (cm->cmsg_level != IPPROTO_UDP || cm->cmsg_type != UDP_COALESCED_INFO)
            continue;
        DWORD seg = 0u;
        memcpy(&seg, WSA_CMSG_DATA(cm), sizeof seg);
        return seg;
    }
    return 0u;
}

/** @brief Largest read a coalescing datagram socket can answer with, bytes.
 *
 *  This stack accepts any size the option carries, so the figure is a choice.
 *  It matches the epoll build's, which keeps both platforms sizing an RX buffer
 *  alike. A coalesced read counts as one unit for truncation, so a reader
 *  covers a whole group. @c duct_olb_rx_t::read_unit carries that span. */
static constexpr size_t duct_x_gro_max = 65536u;

/** @brief Most datagrams one receive call takes: one, the granularity Winsock
 *  receives at. It keeps every peer conn on single reads. */
static constexpr uint32_t duct_x_recv_batch_max = 1u;

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

/** @brief This platform's division of a bound port: Winsock balances nothing
 *  across sockets sharing one address, so one socket takes it all. */
static constexpr duct_x_port_share_t duct_x_port_sharing = x_port_share_first;

/** @brief Availability of AF_UNIX stream listeners on this platform: a build
 *  targeting Windows 10 1803 or later, the first release with AF_UNIX sockets.
 *  Below it a path bind answers @c rc_not_supported. */
static constexpr bool duct_x_local_floor = NTDDI_VERSION >= NTDDI_WIN10_RS4;

/** @brief Availability of sessions opened over a caller's packet fd on this platform: never.
 *  The @c x_raw_packet read answers @c rc_invalid_arg here: a Windows tunnel is a device leg. */
static constexpr bool duct_x_packet_fd_session = false;

/** @brief Ask @p fd's stack to hand back several same-source datagrams of one
 *  size as a single read of at most @p max bytes.
 *
 *  The segment size arrives as a control message, so coalescing needs
 *  @c WSARecvMsg as much as it needs the option, and every read of @p fd must
 *  take the segment size back.
 *
 *  @return the cap set, @p max bounded by @ref duct_x_gro_max, once the stack
 *  has taken the option; 0 where it refused or the lookup found no
 *  @c WSARecvMsg. A conn sizes its read spans from this answer, so a 0 keeps
 *  them at one frame. */
static inline size_t duct_xset_dgram_gro(SOCKET fd, size_t max)
{
    auto recvmsg_fn = duct_x_wsa_recvmsg();
    duct_do_if(!recvmsg_fn, return 0u);
    size_t span = duct_min(max, duct_x_gro_max);
    DWORD want = (DWORD)span;
    int rc = setsockopt(fd, IPPROTO_UDP, UDP_RECV_MAX_COALESCED_SIZE,
                        (const char *)&want, sizeof want);
    duct_do_if(rc != 0, return 0u);
    return span;
}

/** @brief Report the @c virtio_net_hdr length of @p fd, always 0 on Windows. */
static inline size_t duct_x_vnet_hdr_len([[maybe_unused]] SOCKET fd)
{
    return 0u;
}

/** @brief Enable the offloads of vnet tun @p fd, always @c rc_not_supported on
 *  Windows, whose conns carry no vnet header. */
static inline duct_result_t duct_x_vnet_offload([[maybe_unused]] SOCKET fd)
{
    return rc_not_supported;
}

duct_nonnull(4) static inline duct_result_t
duct_xread(SOCKET fd, duct_xport_t t, duct_view_u8 dst,
           size_t *out_read, void *ctx, int flags, size_t *out_seg)
{
    int n = 0;
    *out_read = 0;
    if (out_seg)
        *out_seg = 0u;
    switch (t) {
    case x_udp_peer:
    case x_udp: {
        /* Both UDP kinds read through WSARecvMsg wherever a segment size can
         * arrive and be reported, x_udp naming the source as well. A flagged
         * read keeps the recv form: WSARecvMsg takes dwFlags as output alone. */
        duct_do_if(t == x_udp && !ctx, return rc_invalid_arg);
        auto name = t == x_udp ? (struct sockaddr_storage *)ctx : nullptr;
        auto recvmsg_fn = duct_x_wsa_recvmsg();
        if (recvmsg_fn && out_seg && flags == 0) {
            duct_rx_msg_t m;
            DWORD got = 0u;
            n = recvmsg_fn(fd, duct_rx_msg(&m, dst, name), &got, nullptr, nullptr);
            if (n == 0) {
                *out_seg = duct_x_gro_seg(m.msg.Control);
                *out_read = (size_t)got;
                return rc_ok;
            }
            break;
        }
        n = name ? recvfrom(fd, (char *)dst.data, (int)dst.size, flags,
                            (struct sockaddr *)name, &(int){ sizeof *name })
                 : recv(fd, (char *)dst.data, (int)dst.size, flags);
        break;
    }
    case x_raw:
    case x_tcp: case x_bt: case x_can: case x_local:
        n = recv(fd, (char *)dst.data, (int)dst.size, flags);
        break;
    case x_raw_packet:  /* no packet-delimited descriptor here: a Windows tunnel is a device leg */
    case x_inter:       /* push-mode: ingress arrives via duct_io_inter_batch */
    case x_udp_shared:  /* RX arrives on the listener's socket, leaving this case no fd */
        return rc_invalid_arg;
    }

    switch (n) {
    case SOCKET_ERROR:
        int err = WSAGetLastError();
        switch (err) {
        case WSAEWOULDBLOCK:
            return rc_again;
        /* A buffer shorter than the incoming message costs the whole
         * datagram and answers WSAEMSGSIZE: the excess is gone by the time
         * this returns. An x_udp_peer conn drops that one record and stays. */
        case WSAEMSGSIZE:
            duct_dbg_errf("WSAEMSGSIZE, %zu-byte span", dst.size);
            return t == x_udp_peer ? rc_drop : rc_fatal;
        default:
            duct_dbg_errf("WSA error %d", err);
            return rc_fatal;
        }
    case 0:
        if (t != x_udp && t != x_udp_peer && t != x_inter) return rc_closed;
    default:
        break;
    }
    *out_read = n;
    return rc_ok;
}

/** @brief Write @p src out @p fd for transport @p t.
 *
 *  @param ctx  Destination @c sockaddr for @c x_udp; unread for every other
 *              transport.
 *  @return @c rc_ok with @p out_written set, below @p src.size on a short
 *  write; @c rc_again on a @ref duct_x_send_retryable code and on a stream
 *  write that moved nothing; @c rc_drop where the message is too large for a
 *  transport that delimits its messages, @ref duct_xport_delimited deciding
 *  which, the message being unsendable while the conn stands; @c rc_fatal
 *  otherwise; @c rc_invalid_arg for a transport carrying no descriptor to
 *  write.
 *  @p out_written is 0 on every outcome but @c rc_ok.
 */
duct_nonnull(4) static inline duct_result_t
duct_xwrite(SOCKET fd, duct_xport_t t, duct_view_u8 src,
            size_t *out_written, void *ctx, int flags)
{
    int n = 0;
    *out_written = 0;
    switch (t) {
    case x_raw:
    case x_tcp: case x_bt: case x_can: case x_udp_peer: case x_local:
        n = send(fd, (const char *)src.data, (int)src.size, flags);
        break;
    case x_udp:
        n = sendto(fd, (const char *)src.data, (int)src.size, flags,
                   ctx, (int)sizeof(struct sockaddr_storage));
        break;
    case x_raw_packet:  /* no packet-delimited descriptor here: a Windows tunnel is a device leg */
    case x_inter:       /* egress goes through on_packet_out */
    case x_udp_shared:  /* TX goes through the listener's outbox, leaving this case no fd */
        return rc_invalid_arg;
    }

    switch (n) {
    case SOCKET_ERROR:
        int send_err = WSAGetLastError();
        if (duct_x_send_retryable(send_err))
            return rc_again;
        switch (send_err) {
        case WSAEMSGSIZE:
            duct_dbg_errf("WSAEMSGSIZE, %zu bytes", src.size);
            return duct_xport_delimited(t) ? rc_drop : rc_fatal;
        default:
            duct_dbg_errf("WSA error %d", send_err);
            return rc_fatal;
        }
    case 0:
        if (t != x_udp && t != x_udp_peer && t != x_inter) return rc_again;
    default:
        break;
    }
    *out_written = n;
    return rc_ok;
}

/** @brief Write @p n spans out @p fd in one @c WSASend, joining them nowhere
 *  first.
 *
 *  One call covers @c x_raw alongside the stream kinds, an attached
 *  descriptor being a socket on this platform. A single span skips the
 *  @c WSABUF vector and takes @ref duct_xwrite. @c x_raw_packet is a device
 *  leg with no socket behind it, and @c x_udp needs a destination per call,
 *  which is @c WSASendMsg's job.
 *
 *  @return @c rc_ok with @p out_written set, below the spans' total on a short
 *  write; @c rc_again on would-block; @c rc_drop for a lone span too large for
 *  a delimited transport, which only @ref duct_xwrite reaches; @c rc_fatal on
 *  any other failure; @c rc_invalid_arg for @p n of 0 and for a transport
 *  listed above as having no path here. @p out_written is 0 on every outcome
 *  but @c rc_ok.
 */
duct_nonnull(3, 5) static inline duct_result_t
duct_xwritev(SOCKET fd, duct_xport_t t, const duct_view_u8 *bufs, unsigned n,
             size_t *out_written, int flags)
{
    *out_written = 0;
    duct_do_if(!n, return rc_invalid_arg);
    switch (t) {
    case x_raw:
    case x_tcp: case x_bt: case x_can: case x_udp_peer: case x_local:
        if (n == 1u)
            return duct_xwrite(fd, t, bufs[0], out_written, nullptr, flags);
        break;
    case x_udp:
    case x_raw_packet:
    case x_inter:
    case x_udp_shared:
        return rc_invalid_arg;
    }
    WSABUF wbufs[n];
    for (unsigned i = 0u; i < n; ++i)
        wbufs[i] = (WSABUF){ .len = (ULONG)bufs[i].size, .buf = (CHAR *)bufs[i].data };
    DWORD sent = 0;
    if (WSASend(fd, wbufs, n, &sent, (DWORD)flags, nullptr, nullptr) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        switch (err) {
        case WSAEWOULDBLOCK:
            return rc_again;
        default:
            duct_dbg_errf("WSA error %d", err);
            return rc_fatal;
        }
    }
    if (!sent && t != x_udp_peer)
        return rc_again;
    *out_written = sent;
    return rc_ok;
}

/** @brief Send one already-framed datagram out @p fd to @p addr.
 *
 *  A plain synchronous sendto: a non-blocking UDP send doesn't block on a
 *  handshake/ACK the way stream I/O can.
 *
 *  @return true once the caller may move past these bytes: handed to Winsock,
 *  or failed for a reason repeating the send repeats. false for a
 *  @ref duct_x_send_retryable code, meaning leave it queued and send it again
 *  once the socket is writable.
 */
duct_nonnull(2) static inline bool
duct_xsend_dgram(SOCKET fd, const struct sockaddr *addr,
                 int addrlen, duct_view_u8 payload)
{
    int n = sendto(fd, (const char *)payload.data, (int)payload.size,
                   0, addr, addrlen);
    return duct_x_send_consumed(n);
}

/** @brief Send @p n already wire-packed datagrams to @p fd, each from its own
 *  descriptor's two spans, unsegmented.
 *
 *  One @c WSASendTo per descriptor, its header and payload passed as two
 *  @c WSABUF entries of one datagram, so the payload goes from wherever it
 *  already lies; an empty header contributes no entry.
 *
 *  @param out_sent how many of the first @p n the caller may move past, which
 *         counts a datagram no send will ever carry alongside those Winsock
 *         took. A @ref duct_x_send_retryable code stops the run: the socket has
 *         just gone write-blocked or run out of buffers, and every entry behind
 *         it meets the same state.
 *  @return @c rc_ok on every path, so a shared socket never closes over one
 *  batch.
 */
duct_nonnull(2, 4) static inline duct_result_t
duct_xsend_peers(SOCKET fd, const duct_dgram_out_t *msgs, unsigned n, unsigned *out_sent)
{
    unsigned resolved = 0u;
    for (; resolved < n; ++resolved) {
        struct sockaddr_storage ss;
        auto ss_len = duct_io_sockaddr_from_peer(&msgs[resolved].peer, &ss);
        WSABUF wb[2];
        DWORD cnt = 0u;
        if (msgs[resolved].hdr.size)
            wb[cnt++] = (WSABUF){ .len = (ULONG)msgs[resolved].hdr.size,
                                  .buf = (CHAR *)msgs[resolved].hdr.data };
        wb[cnt++] = (WSABUF){ .len = (ULONG)msgs[resolved].body.size,
                              .buf = (CHAR *)msgs[resolved].body.data };
        DWORD sent = 0u;
        int r = WSASendTo(fd, wb, cnt, &sent, 0, (struct sockaddr *)&ss, ss_len,
                          nullptr, nullptr);
        if (!duct_x_send_consumed(r))
            break;
    }
    *out_sent = resolved;
    return rc_ok;
}

/** @brief Fill up to @p n of @p bufs from @p fd, reporting each datagram's
 *  length in @p out_lens.
 *  @p out_peers takes each source and @p out_segs a coalesced read's segment
 *  size; @c nullptr skips either report. One @ref duct_xread fills each buffer,
 *  the granularity Winsock receives at. Receive counterpart of
 *  @ref duct_xsend_peers.
 *
 *  @return @c rc_ok with @p out_n >= 1; the first read's own result when
 *  nothing was received. A failure past the first read still answers @c rc_ok
 *  for what already arrived, and @p out_n < @p n tells the read loop to stop.
 */
duct_nonnull(2, 5, 7) static inline duct_result_t
duct_xrecv_peers(SOCKET fd, const duct_view_u8 *bufs, uint32_t n,
                 duct_peer_t *out_peers, uint32_t *out_lens, uint32_t *out_segs,
                 uint32_t *out_n)
{
    *out_n = 0u;
    duct_do_if(!n, return rc_again);
    for (uint32_t i = 0u; i < n; ++i) {
        struct sockaddr_storage addr;
        size_t got = 0u,
               seg = 0u;
        auto rc = duct_xread(fd, x_udp, bufs[i], &got, &addr, 0, &seg);
        if (rc != rc_ok)
            return *out_n ? rc_ok : rc;
        if (out_peers)
            out_peers[i] = duct_io_peer_from_sockaddr((struct sockaddr *)&addr);
        out_lens[i] = (uint32_t)got;
        if (out_segs)
            out_segs[i] = (uint32_t)seg;
        *out_n = i + 1u;
    }
    return rc_ok;
}

/** @brief Accept one connection on @p listener_fd and make it non-blocking.
 *  @p ctx receives the peer address as a @c sockaddr_storage. A socket whose family is not
 *  AF_UNIX gets @c TCP_NODELAY.
 *  @retval rc_ok     @p out_fd set.
 *  @retval rc_again  Nothing is queued.
 *  @retval rc_defer  @c WSAEMFILE: no socket descriptor is left, and the client stays queued.
 *  @retval rc_fatal  Any other failure.
 */
duct_nonnull(2, 3) static inline duct_result_t
duct_xaccept(SOCKET listener_fd, SOCKET *out_fd, void *ctx)
{
    *out_fd = duct_sock_bad;
    SOCKET fd = accept(listener_fd, ctx,
                       &(int){ sizeof(struct sockaddr_storage) });
    if (fd == duct_sock_bad) {
        int err = WSAGetLastError();
        switch (err) {
        case WSAEWOULDBLOCK:
            return rc_again;
        case WSAEMFILE:
            return rc_defer;
        default:
            duct_dbg_errf("WSA error %d", err);
            return rc_fatal;
        }
    }
    duct_xset_nonblock(fd);
    if (((const struct sockaddr *)ctx)->sa_family != AF_UNIX)
        duct_xset_tcp_nodelay(fd);
    *out_fd = fd;
    return rc_ok;
}

/** @brief Connect outcome of Winsock error @p err, 0 meaning a connection made. */
static inline duct_result_t duct_x_connect_rc(int err)
{
    return err == 0 ? rc_ok : err == WSAECONNREFUSED ? rc_conn_refused : rc_fatal;
}

/** @brief Create a dial's unconnected socket: the socket type @p xport picks,
 *  non-blocking and close-on-exec, @c IP_UNICAST_IF (@c IPV6_UNICAST_IF for
 *  IPv6) for a nonzero @p egress_if — the IPv4 index in network byte order —
 *  and the per-xport socket options. A TCP socket takes the congestion
 *  control @p congestion names here, the one point Winsock takes it; @c nullptr
 *  leaves the host's default. An @c x_local socket takes no TCP option.
 *  Nothing connects here.
 *  @return The descriptor, or @c duct_sock_bad when @c socket() fails or
 *          Winsock refuses the @p egress_if or the TCP options.
 */
static inline duct_sock_t
duct_xsocket(int family, duct_xport_t xport, uint32_t egress_if,
             const char *congestion)
{
    duct_sock_t fd = socket(family, xport == x_udp_peer ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (fd == duct_sock_bad)
        return fd;
    if (egress_if) {
        bool v6 = family == AF_INET6;
        DWORD index = v6 ? egress_if : htonl(egress_if);
        bool bound = setsockopt(fd, v6 ? IPPROTO_IPV6 : IPPROTO_IP, v6 ? IPV6_UNICAST_IF : IP_UNICAST_IF,
                                (const char *)&index, sizeof index) == 0;
        duct_do_if(!bound, duct_sock_close(fd); return duct_sock_bad);
    }
    duct_xset_nonblock(fd);
    switch (xport) {
    case x_udp_peer:
        duct_xset_dgram_bufs(fd, family);
        break;
    case x_local:
        break;
    default:
        duct_xset_tcp_nodelay(fd);
        duct_xset_tcp_congestion(fd, congestion);
        break;
    }
    return fd;
}

/** @brief Non-blocking connect of @p fd to @p addr, the socket type already
 *  set. @c x_udp_peer always takes the plain synchronous @c connect(): that
 *  call is local only and completes in place, IOCP included. Under @c IOCP,
 *  a stream dial runs through a posted @c ConnectEx;
 *  this step binds the wildcard address and port — the family alone for
 *  @c x_local, which @c ConnectEx requires — and the connection is made by
 *  the @c duct_events_watch @c ConnectEx post in the @c pre_conn_dial case.
 *  @p fd is consumed: closed on failure, kept otherwise.
 *  @retval rc_ok            Connected, or the bind a ConnectEx dial needs.
 *  @retval rc_conn_refused  Conn-refused error.
 *  @retval rc_fatal         Any other failure.
 */
duct_nonnull(3) static inline duct_result_t
duct_xconnect([[maybe_unused]] duct_xport_t xport, duct_sock_t fd, const struct sockaddr *addr, int addrlen)
{
    int rc = 0;
#if DUCT_EVENTS_MODEL_IOCP
    if (xport == x_udp_peer) {
        rc = connect(fd, addr, addrlen) != 0 && WSAGetLastError() != WSAEWOULDBLOCK;
        duct_do_if(rc != 0,
            auto err = duct_x_connect_rc(WSAGetLastError());
            duct_sock_close(fd);
            return err;
        );
    } else {
        /* ConnectEx requires an already-bound socket
         * — bind to the wildcard address/port, letting the OS pick both. */
        int wildcard_len = (int)sizeof(struct sockaddr_in);
        switch (addr->sa_family) {
        case AF_INET6:
            wildcard_len = (int)sizeof(struct sockaddr_in6);
            break;
        case AF_UNIX:
            wildcard_len = (int)sizeof(ADDRESS_FAMILY);
            break;
        }
        rc = bind(fd, (struct sockaddr *)&(struct sockaddr_storage){ .ss_family = (ADDRESS_FAMILY)addr->sa_family },
                  wildcard_len);
        duct_do_if(rc != 0, duct_sock_close(fd); return rc_fatal);
    }
#else
    rc = connect(fd, addr, addrlen) != 0 && WSAGetLastError() != WSAEWOULDBLOCK;
    duct_do_if(rc != 0,
        auto err = duct_x_connect_rc(WSAGetLastError());
        duct_sock_close(fd);
        return err;
    );
#endif
    return rc_ok;
}

/** @brief Read still-connecting @p fd's outcome off its @c SO_ERROR once its readiness event fires.
 *
 *  @retval rc_ok            Clean connect.
 *  @retval rc_conn_refused  Connection-refused error.
 *  @retval rc_fatal         Any other failure.
 */
static inline duct_result_t
duct_xconnect_result(SOCKET fd)
{
    int err = 0;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &(int){ sizeof err }) != 0)
        err = WSAGetLastError();
    return duct_x_connect_rc(err);
}

/** @brief Point an already-open per-peer datagram socket at @p peer_addr.
 *
 *  Repeatable on a socket @ref duct_xopen_dgram_peer already connected, and it
 *  is where that socket's replies go from here. Receive is unaffected: this
 *  platform's per-peer socket is TX-only, and the listener's own
 *  @c dgram_peers path carries a peer's datagrams in.
 *
 *  @retval rc_ok     Sends follow @p peer_addr from here.
 *  @retval rc_fatal  The socket still points where it did.
 */
duct_nonnull(2) static inline duct_result_t
duct_xconnect_dgram_peer(SOCKET fd, const struct sockaddr *peer_addr, int peer_len)
{
    return connect(fd, peer_addr, peer_len) == 0 ? rc_ok : rc_fatal;
}

/** @brief Open a connected per-peer datagram socket, bound to @p listen_fd's
 *  local address, connected to @p peer_addr — the UDP analog of accept()
 *  handing back a dedicated per-connection fd.
 *
 *  TX-only on Windows: Winsock leaves inbound demux with the shared listener
 *  whatever a connected socket binds to, so the @c SO_REUSEADDR bind here
 *  serves @c send() alone. A reply then leaves from the listener's local
 *  address and port.
 *  RX for that peer arrives through the listener's own classification/
 *  @c dgram_peers path instead.
 *
 *  @retval rc_ok     @p out_fd set.
 *  @retval rc_fatal  Any step's failure.
 */
duct_nonnull(2, 4) static inline duct_result_t
duct_xopen_dgram_peer(SOCKET listen_fd,
                      const struct sockaddr *peer_addr,
                      int peer_len, SOCKET *out_fd)
{
    *out_fd = duct_sock_bad;
    struct sockaddr_storage local = {};
    int local_len = sizeof local;
    int named = getsockname(listen_fd, (struct sockaddr *)&local, &local_len);
    duct_do_if(named != 0,
        return rc_fatal
    );

    SOCKET fd = socket(local.ss_family, SOCK_DGRAM, 0);
    duct_do_if(fd == duct_sock_bad, return rc_fatal);
    duct_xset_nonblock(fd);
    int rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                        (const char *)&(int){ 1 }, sizeof(int));
    duct_do_if(rc != 0, goto fail); 
    /* TODO: log setsockopt errno */
    rc = bind(fd, (struct sockaddr *)&local, local_len);
    duct_do_if(rc != 0, goto fail); 
    /* TODO: log bind errno */
    rc = connect(fd, peer_addr, peer_len);
    duct_do_if(rc != 0, goto fail); 
    /* TODO: log connect errno */
    *out_fd = fd;
    return rc_ok;
fail:
    duct_sock_close(fd);
    return rc_fatal;
}

#endif /* DUCT_XPORT_H */
