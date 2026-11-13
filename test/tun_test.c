/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file tun_test.c
 *  @brief Packet-fd legs on a socketpair and on a real vnet tun: the packet
 *  wire, the tests' own @c tun_open, @c duct_conn_gso_max and the attach's offloads.
 *
 *  @c sc_wire attaches one end of a @c SOCK_DGRAM socketpair at leg 1 on
 *  @c duct_wire_packet and echoes packets of 1, 1500, 9000 and 65535 bytes,
 *  each wanted back whole. The leg carries no vnet header, so
 *  @c duct_conn_gso_max answers 0 and @c duct_conn_set_gso refuses it.
 *
 *  @c sc_read and @c sc_tun run in a user and network namespace the test enters
 *  before any thread exists.
 *
 *  @c sc_read runs no engine. It opens a tun, sends it a probe datagram and
 *  reads that back through spans of chosen lengths, once on the kernel's default
 *  vnet header and once on one of 12 bytes, and asserts what the engine's tun
 *  read rests on: the header and the packet are one stream laid over the spans in
 *  order, the two pad bytes of the longer header are skipped and not written, a
 *  span shorter than the packet clamps the return value with no sign but the
 *  packet's own length field, and a read under the header length fails with
 *  @c EINVAL and takes its packet with it. Last, it offers the tun the offloads
 *  with the USO flags, which the kernel takes from 6.2 and which come off when it
 *  refuses, and sends four datagrams in one @c UDP_SEGMENT write: they read back as
 *  one GSO type 5 packet where the flags were taken, as four datagrams where not.
 *
 *  @c sc_tun opens tuns through @c tun_open: the name asked for, a template,
 *  an empty hint, a held name answering @c rc_again, a hint with no room for
 *  its terminator. The first tun has no offload until it is attached at leg 1.
 *  There @c duct_conn_gso_max
 *  answers 65535, @c duct_conn_set_gso takes that bound, the TCP offload is on,
 *  the UDP segmentation offload is on where the kernel took the USO flags, and a
 *  UDP datagram sent into the tun reaches the protocol as one bare IPv4
 *  packet, which it echoes back with addresses and ports swapped. A burst of four
 *  datagrams in one @c UDP_SEGMENT write follows and comes back as four echoes in
 *  order, whichever way the kernel hands it over. The scenario
 *  runs twice, on the kernel's default vnet header and on one of 12 bytes,
 *  whose two pad bytes the read skips.
 *
 *  A host that refuses the namespace or has no tun device skips @c sc_tun
 *  with a note and passes.
 */

#define _GNU_SOURCE

#include "duct.h"
#include "tun_open.h"
#include "netns_helpers.h"
#include "test_helpers.h"
#include "dgram_test_helpers.h"

#include <errno.h>
#include <linux/ethtool.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>

/** @brief Longest wait for a session event, milliseconds. */
static constexpr unsigned       wait_ms     = 15000u;
/** @brief UDP port of the probe datagram sent into the tun. */
static constexpr uint16_t       probe_port  = 9000u;
/** @brief UDP payload of the probe datagram, bytes. */
static constexpr unsigned       probe_bytes = 20u;
/** @brief IPv4 header without options, bytes. */
static constexpr size_t         ip_hdr_len  = 20u;
/** @brief UDP header, bytes. */
static constexpr size_t         udp_hdr_len = 8u;
/** @brief Slot the packet fd is attached at. */
static constexpr duct_conn_id_t packet_leg  = 1u;
/** @brief Flags a tun from @c tun_open reports. */
static constexpr short          tun_flags   = IFF_TUN | IFF_NO_PI | IFF_VNET_HDR;
/** @brief Longer vnet header a tun takes, bytes: the default and two pad bytes. */
static constexpr int            vnet_hdr_long = 12;
/** @brief Vnet header a tun carries by default, bytes: a @c struct virtio_net_hdr, which a longer
 *  header pads. */
static constexpr size_t         vnet_hdr_min  = 10u;
/** @brief Packet the probe datagram makes in the tun, bytes. */
static constexpr size_t         probe_len   = ip_hdr_len + udp_hdr_len + probe_bytes;
/** @brief Byte a span holds before a read, to tell what the read left alone. */
static constexpr uint8_t        span_fill   = 0xeeu;
/** @brief Longest wait for the tun to hold a packet, milliseconds. */
static constexpr int            hold_ms     = 2000;
/** @brief Datagrams of the burst one @c UDP_SEGMENT write sends, each of @c probe_bytes. */
static constexpr unsigned       burst_n     = 4u;
/** @brief @c TUN_F_USO4 and @c TUN_F_USO6, which a kernel from 6.2 takes together or not at all. */
static constexpr unsigned       tun_f_uso   = 0x20u | 0x40u;

/** @brief Interface name asked of the scenario's tun. */
static const char tun_name[] = "dtun-l1";
/** @brief Address the scenario gives its tun, and the one in its subnet the probe is sent to. */
static const char tun_addr[] = "10.77.0.1",
                  tun_peer[] = "10.77.0.2";

/** @brief What the gso query and setter said about the legs as the packet leg joined. */
typedef struct {
    uint16_t      leg0,   /**< Query of leg 0, the TCP primary. */
                  leg1,   /**< Query of the joined packet leg. */
                  empty,  /**< Query of the slot after it, empty. */
                  past;   /**< Query of slot @c duct_session_max_legs, past the legs. */
    duct_result_t set;    /**< Setter on the joined leg with the bound the query gave. */
    bool          has_uso;
    duct_result_t set_uso;
} gso_t;

/** @brief Result of the packet-fd attach, -1 until it runs. */
static atomic_int  g_attach_rc = -1;
/** @brief Legs @c on_conn_join has seen. */
static atomic_int  g_joined    = 0;
/** @brief Probe packets the tun protocol saw. */
static atomic_int  g_probes    = 0;
/** @brief Size of the last probe packet seen, bytes. */
static atomic_int  g_probe_len = 0;
/** @brief Descriptor the session attaches at the packet leg. */
static duct_sock_t g_attach_fd = duct_sock_bad;
/** @brief Test's end of the socketpair. */
static duct_sock_t g_peer_fd   = duct_sock_bad;
/** @brief Tun the tun scenario opened first. */
static tun_opened_t  g_tun;
/** @brief Snapshot taken as the packet leg joined. */
static gso_t       g_gso;
/** @brief Reason the tun scenario did not run, nullptr when it did. */
static const char *g_skip;
/** @brief 1 when the host kernel took @c tun_f_uso, 0 when it refused, -1 until @c sc_read asks. */
static int         g_uso = -1;

/** @brief Attach @c g_attach_fd at the packet leg on the packet wire and record the result. */
static duct_result_t on_session_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                                     [[maybe_unused]] void *user_ctx,
                                     [[maybe_unused]] duct_response_t *out,
                                     [[maybe_unused]] void *proto_state)
{
    auto rc = duct_conn_attach_packet_fd(s, packet_leg, g_attach_fd, duct_wire_packet());
    duct_atomic_store(&g_attach_rc, (int)rc, release);
    return rc_ok;
}

/** @brief Snapshot what the gso query and setter say about the legs as the packet leg joins. */
static duct_result_t on_conn_join(duct_session_t *s, duct_conn_id_t conn_id,
                                  [[maybe_unused]] const duct_peer_t *peer,
                                  [[maybe_unused]] duct_response_t *out,
                                  [[maybe_unused]] void *proto_state)
{
    g_gso = (gso_t){
        .leg0 = duct_conn_gso_max(s, 0u), .leg1 = duct_conn_gso_max(s, conn_id),
        .empty = duct_conn_gso_max(s, packet_leg + 1u),
        .past = duct_conn_gso_max(s, duct_session_max_legs),
        .set = duct_conn_set_gso(s, conn_id, duct_conn_gso_max(s, conn_id)),
        .has_uso = duct_conn_has_vnet_uso(s, conn_id),
        .set_uso = duct_conn_set_uso(s, conn_id, duct_conn_has_vnet_uso(s, conn_id)),
    };
    if (g_gso.set_uso == rc_ok)
        g_gso.set_uso = duct_conn_set_uso(s, conn_id, false);
    duct_atomic_fetch(add, &g_joined, 1, release);
    return rc_ok;
}

/** @brief Echo each packet back out of the packet leg. */
static duct_result_t wire_on_frame([[maybe_unused]] duct_session_t *s,
                                   [[maybe_unused]] duct_conn_id_t conn_id,
                                   const duct_frame_t *frame, duct_response_t *out,
                                   [[maybe_unused]] void *proto_state)
{
    duct_response_forward(out, frame, packet_leg);
    return rc_ok;
}

/** @brief Whether the @p n bytes at @p p open with the probe datagram: IPv4 without options, UDP, the probe port. */
static bool is_probe(const uint8_t *p, size_t n)
{
    return n >= ip_hdr_len + 4u && p[0] == 0x45u && p[9] == IPPROTO_UDP
        && ((unsigned)p[ip_hdr_len + 2u] << 8u | p[ip_hdr_len + 3u]) == probe_port;
}

/** @brief Echo a probe packet to the tun with addresses and ports swapped, and count it.
 *  Any other packet the tun carries gets no answer. */
static duct_result_t tun_on_frame([[maybe_unused]] duct_session_t *s,
                                  [[maybe_unused]] duct_conn_id_t conn_id,
                                  const duct_frame_t *frame, duct_response_t *out,
                                  [[maybe_unused]] void *proto_state)
{
    static uint8_t reply[2048];
    auto p = (const uint8_t *)frame->payload.data;
    size_t size = frame->payload.size;
    bool probe = size > ip_hdr_len + udp_hdr_len && size <= sizeof reply && is_probe(p, size);
    if (probe) {
        memcpy(reply, p, size);
        memcpy(reply + 12u, p + 16u, 4u);
        memcpy(reply + 16u, p + 12u, 4u);
        memcpy(reply + ip_hdr_len, p + ip_hdr_len + 2u, 2u);
        memcpy(reply + ip_hdr_len + 2u, p + ip_hdr_len, 2u);
        duct_atomic_store(&g_probe_len, (int)size, relaxed);
        duct_atomic_fetch(add, &g_probes, 1, release);
        duct_response_forward(out, &(duct_frame_t){ .payload = { .data = reply, .size = size } },
                              packet_leg);
    }
    return rc_ok;
}

/** @brief Serve protocol @p name on a length-prefix wire, run @p client against it, tear the engine down.
 *  @return the text of the first failed step, nullptr when all hold. */
static const char *serve(const char *name, duct_frame_fn on_frame,
                         const char *(*client)(uint16_t port))
{
    duct_atomic_store(&g_attach_rc, -1, relaxed);
    duct_atomic_store(&g_joined, 0, relaxed);
    g_gso = (gso_t){};
    duct_proto_cfg_t cfg = {
        .name = name, .on_frame = on_frame,
        .on_session_open = on_session_open, .on_conn_join = on_conn_join,
    };
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1u, .workers = 1u });
    if (!io)
        return "engine launch failed";
    auto proto = duct_proto_create_owning(&cfg, duct_wire_create_length_prefix(0u));
    uint16_t port = 0u;
    const char *err = !proto ? "proto create failed"
                    : duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok ? "listen failed"
                    : nullptr;
    if (!err) {
        pthread_t th;
        if (pthread_create(&th, nullptr, th_run, io) == 0) {
            err = client(port);
            duct_engine_stop(io);
            pthread_join(th, nullptr);
        } else
            err = "thread create failed";
    }
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return err;
}

/** @brief Write packets of rising size to @p peer and read each echo back whole.
 *  @return the text of the first failed check, nullptr when every echo matches. */
static const char *wire_traffic(duct_sock_t peer)
{
    static const size_t sizes[] = { 1u, 1500u, 9000u, duct_ipv4_len_max };
    static uint8_t tx[duct_ipv4_len_max],
                   rx[duct_ipv4_len_max];
    struct timeval tv = { .tv_sec = 5 };
    duct_discard setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    for (size_t i = 0u; i < sizeof sizes / sizeof sizes[0]; ++i) {
        for (size_t j = 0u; j < sizes[i]; ++j)
            tx[j] = (uint8_t)(j * 31u + i);
        if (write(peer, tx, sizes[i]) != (ssize_t)sizes[i])
            return "write to the packet fd failed";
        ssize_t n = read(peer, rx, sizeof rx);
        if (n != (ssize_t)sizes[i])
            return "an echo came back with another length: the packet wire lost a boundary";
        if (memcmp(tx, rx, sizes[i]) != 0)
            return "an echo differs from the packet written: the packet wire added or lost bytes";
    }
    return nullptr;
}

/** @brief Connect to @p port, wait for the packet leg, check what the gso calls say of it and run the traffic. */
static const char *wire_client(uint16_t port)
{
    duct_sock_t fd = th_connect(port);
    if (fd == duct_sock_bad)
        return "connect failed";
    auto err = !th_wait_int(&g_attach_rc, (int)rc_ok, wait_ms)
                   ? "duct_conn_attach_packet_fd refused the packet wire"
             : !th_wait_int(&g_joined, 1, wait_ms) ? "the packet leg never joined the session"
             : g_gso.leg1 != 0u ? "duct_conn_gso_max answers for a packet fd that carries no vnet header"
             : g_gso.set != rc_not_supported ? "duct_conn_set_gso takes a packet fd that carries no vnet header"
             : g_gso.has_uso ? "duct_conn_has_vnet_uso answers for a packet fd"
             : g_gso.set_uso != rc_not_supported ? "duct_conn_set_uso takes a packet fd"
             : wire_traffic(g_peer_fd);
    duct_sock_close(fd);
    return err;
}

/** @brief Run the socketpair scenario. */
static const char *sc_wire(void)
{
    duct_sock_t sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0)
        return "socketpair failed";
    g_peer_fd = sv[0];
    g_attach_fd = sv[1];
    auto err = serve("packet-wire", wire_on_frame, wire_client);
    close(g_peer_fd);
    return err;
}

/** @brief Report whether interface @p name has feature @p feature on, by the name `ethtool -k` gives it.
 *  @return 1 on, 0 off, -1 when the query fails or the kernel has no such feature. */
static int feature_of(const char *name, const char *feature)
{
    struct ifreq ifr = {};
    snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", name);
    struct ethtool_sset_info *sset = calloc(1u, sizeof *sset + sizeof(uint32_t));
    if (!sset)
        return -1;
    sset->cmd = ETHTOOL_GSSET_INFO;
    sset->sset_mask = 1ull << ETH_SS_FEATURES;
    ifr.ifr_data = (void *)sset;
    size_t n = th_ifreq_ioctl(SIOCETHTOOL, &ifr) && sset->sset_mask ? sset->data[0] : 0u;
    free(sset);
    if (!n)
        return -1;
    struct ethtool_gstrings *names = calloc(1u, sizeof *names + n * ETH_GSTRING_LEN);
    struct ethtool_gfeatures *bits = calloc(1u, sizeof *bits + (n + 31u) / 32u * sizeof bits->features[0]);
    int on = -1;
    if (names && bits) {
        names->cmd = ETHTOOL_GSTRINGS;
        names->string_set = ETH_SS_FEATURES;
        names->len = (uint32_t)n;
        bits->cmd = ETHTOOL_GFEATURES;
        bits->size = (uint32_t)((n + 31u) / 32u);
        ifr.ifr_data = (void *)names;
        bool got = th_ifreq_ioctl(SIOCETHTOOL, &ifr);
        ifr.ifr_data = (void *)bits;
        got = got && th_ifreq_ioctl(SIOCETHTOOL, &ifr);
        for (size_t i = 0u; got && i < n; ++i)
            if (!strncmp((const char *)names->data + i * ETH_GSTRING_LEN, feature, ETH_GSTRING_LEN))
                on = !!(bits->features[i / 32u].active & (1u << (i % 32u)));
    }
    free(names);
    free(bits);
    return on;
}

/** @brief Report the @c IFF_ flags of tun @p fd, 0 when the query fails. */
static short flags_of(duct_sock_t fd)
{
    struct ifreq ifr = {};
    return ioctl(fd, TUNGETIFF, &ifr) == 0 ? ifr.ifr_flags : 0;
}

/** @brief Report the vnet header length of tun @p fd, bytes, 0 when the query fails. */
static size_t hdr_of(duct_sock_t fd)
{
    int size = 0;
    return ioctl(fd, TUNGETVNETHDRSZ, &size) == 0 && size > 0 ? (size_t)size : 0u;
}

/** @brief Send a probe datagram on the connected socket @p udp, whose payload is zeros. */
static bool probe_send(duct_sock_t udp)
{
    static const char payload[probe_bytes];
    return uc_send(udp, payload, sizeof payload) == 0;
}

/** @brief Send the @c burst_n datagrams of @c probe_bytes at @p burst in one @c UDP_SEGMENT write on @p udp. */
static bool burst_send(duct_sock_t udp, const void *burst)
{
    return setsockopt(udp, SOL_UDP, UDP_SEGMENT, &(int){ (int)probe_bytes }, sizeof(int)) == 0
        && uc_send(udp, burst, burst_n * probe_bytes) == 0;
}

/** @brief Count the packets written into interface @p name, the receive packets of its line in
 *  @c /proc/net/dev, which the namespace the test entered keeps of its own. A superpacket the tun takes in
 *  one write counts once.
 *  @return the count, -1 where the line is not found. */
static long written_to(const char *name)
{
    FILE *f = fopen("/proc/net/dev", "r");
    if (!f)
        return -1;
    char line[512];
    long packets = -1;
    size_t n = strlen(name);
    while (packets < 0 && fgets(line, sizeof line, f)) {
        const char *at = line + strspn(line, " ");
        unsigned long long bytes, count;
        if (!strncmp(at, name, n) && at[n] == ':' && sscanf(at + n + 1u, "%llu %llu", &bytes, &count) == 2)
            packets = (long)count;
    }
    fclose(f);
    return packets;
}

/** @brief Send @c burst_n datagrams in one @c UDP_SEGMENT write on @p udp, and wait for the echo of each,
 *  in order. The echoes go into the tun fewer than @c burst_n writes where the kernel took the USO flags, as
 *  trains of datagrams, and as one write each where it did not.
 *  @return the text of the first failed step, nullptr when every echo matches. */
static const char *tun_burst(duct_sock_t udp)
{
    char burst[burst_n * probe_bytes],
         echo[probe_bytes + 1u];
    for (size_t i = 0u; i < sizeof burst; ++i)
        burst[i] = (char)('a' + i / probe_bytes);
    long before = written_to(tun_name);
    if (!burst_send(udp, burst))
        return "the burst did not go into the tun";
    for (unsigned i = 0u; i < burst_n; ++i)
        if (recv(udp, echo, sizeof echo, 0) != (ssize_t)probe_bytes
            || memcmp(echo, burst + i * probe_bytes, probe_bytes) != 0)
            return "a datagram of the burst did not come back whole and in order";
    long writes = written_to(tun_name) - before;
    return before < 0 ? "the tun's packet count is unreadable"
         : (writes < (long)burst_n) != (g_uso == 1)
               ? "the echoes of the burst did not go into the tun as a train exactly where the kernel took the USO flags"
         : nullptr;
}

/** @brief Send the probe datagram into the tun and wait for its echo, then the burst.
 *  @return the text of the first failed step, nullptr when the echoes match. */
static const char *tun_traffic(void)
{
    char payload[probe_bytes],
         echo[probe_bytes + 1u];
    memset(payload, 'q', sizeof payload);
    duct_sock_t udp = uc_connect_to(tun_peer, probe_port);
    struct timeval tv = { .tv_sec = 5 };
    const char *err = udp == duct_sock_bad ? "no udp socket routed into the tun"
                    : uc_send(udp, payload, sizeof payload) != 0 ? "send into the tun failed"
                    : nullptr;
    if (!err) {
        duct_discard setsockopt(udp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        ssize_t n = recv(udp, echo, sizeof echo, 0);
        err = n != (ssize_t)sizeof payload ? "no echo came back through the tun"
            : memcmp(echo, payload, sizeof payload) != 0 ? "the echo differs from the datagram sent"
            : tun_burst(udp);
    }
    if (udp != duct_sock_bad)
        close(udp);
    return err;
}

/** @brief Connect to @p port, wait for the tun leg, check its gso answers and offload, then run the traffic.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *tun_client(uint16_t port)
{
    duct_sock_t fd = th_connect(port);
    if (fd == duct_sock_bad)
        return "connect failed";
    auto err = !th_wait_int(&g_joined, 1, wait_ms) ? "the tun leg never joined the session"
        : g_gso.leg0 != 0u || g_gso.empty != 0u || g_gso.past != 0u
              ? "duct_conn_gso_max answers for a leg that is no vnet tun"
        : g_gso.leg1 != duct_ipv4_len_max ? "duct_conn_gso_max does not answer the packet wire's size for the vnet tun"
        : g_gso.set != rc_ok ? "duct_conn_set_gso refuses what duct_conn_gso_max reports"
        : g_gso.has_uso != (g_uso == 1) ? "duct_conn_has_vnet_uso disagrees with the kernel"
        : g_gso.set_uso != rc_ok ? "duct_conn_set_uso failed on a vnet tun"
        : feature_of(tun_name, "tx-tcp-segmentation") != 1 ? "the attach did not set the tun's segmentation offload"
        : (feature_of(tun_name, "tx-udp-segmentation") == 1) != (g_uso == 1)
              ? "the attach did not set the tun's UDP segmentation offload to what the kernel takes"
        : !th_ifup(tun_name, tun_addr, 0) ? "the tun refused its address"
        : tun_traffic();
    if (!err && (duct_atomic_load(&g_probes, acquire) != (int)(1u + burst_n)
                 || duct_atomic_load(&g_probe_len, relaxed) != (int)(ip_hdr_len + udp_hdr_len + probe_bytes)))
        err = "the protocol did not see the datagram as one bare IPv4 packet";
    duct_sock_close(fd);
    return err;
}

/** @brief Check @c g_tun, then open more tuns and check each answer.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *tun_opens(void)
{
    char over_long[duct_ifname_max + 1u];
    memset(over_long, 'x', duct_ifname_max);
    over_long[duct_ifname_max] = '\0';
    tun_opened_t more[] = {
        tun_open(tun_name), tun_open("dt%d"), tun_open(nullptr),
        tun_open(over_long),
    };
    const char *err = strcmp(g_tun.name, tun_name) != 0 ? "the device is not named as asked"
        : (flags_of(g_tun.fd) & tun_flags) != tun_flags ? "the device is not a tun carrying the vnet header"
        : hdr_of(g_tun.fd) < vnet_hdr_min ? "the vnet header has no size"
        : feature_of(tun_name, "tx-tcp-segmentation") != 0 ? "the device has segmentation offload before the attach"
        : more[0].rc != rc_again || more[0].fd != duct_sock_bad ? "a taken name is not rc_again"
        : more[1].rc != rc_ok || strncmp(more[1].name, "dt", 2u) != 0 ? "a templated name was refused"
        : more[2].rc != rc_ok || more[2].name[0] == '\0' ? "an empty hint did not get a name from the kernel"
        : more[3].rc != rc_invalid_arg ? "a hint with no room for its terminator was accepted"
        : nullptr;
    for (size_t i = 0u; i < sizeof more / sizeof more[0]; ++i)
        duct_sock_close(more[i].fd);
    return err;
}

/** @brief Read tun @p fd through a first span of @p head_n bytes and a second of @p body_n, until a read
 *  holds the probe where a header of @p hs bytes puts it. Packets of other kinds are read and dropped.
 *  Both spans are filled with @c span_fill ahead of each read.
 *  @return bytes the read returned, 0 where no probe came. */
static size_t read_probe(duct_sock_t fd, uint8_t *head, size_t head_n, uint8_t *body, size_t body_n,
                         size_t hs)
{
    struct pollfd pf = { .fd = fd, .events = POLLIN };
    for (unsigned tries = 0u; tries < 8u && poll(&pf, 1, hold_ms) == 1; ++tries) {
        memset(head, span_fill, head_n);
        memset(body, span_fill, body_n);
        struct iovec iov[] = {
            { .iov_base = head, .iov_len = head_n },
            { .iov_base = body, .iov_len = body_n },
        };
        ssize_t n = readv(fd, iov, 2);
        if (n > (ssize_t)hs && is_probe(body + (hs - head_n), (size_t)n - hs))
            return (size_t)n;
    }
    return 0u;
}

/** @brief Read the probe through a first span of 4 bytes, of the default header and of @p hs in turn, and a
 *  second span after each, and check the stream the kernel lays over them: the header and the whole packet
 *  returned, the packet where a header of @p hs bytes puts it, and the pad of a longer header skipped, not
 *  written.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *read_spans(duct_sock_t fd, duct_sock_t udp, size_t hs)
{
    uint8_t head[vnet_hdr_long],
            body[2u * probe_len];
    const size_t firsts[] = { 4u, vnet_hdr_min, hs };
    for (size_t i = 0u; i < sizeof firsts / sizeof firsts[0]; ++i) {
        size_t first = firsts[i];
        if (!probe_send(udp))
            return "send into the tun failed";
        if (read_probe(fd, head, first, body, sizeof body, hs) != hs + probe_len)
            return "a read over two spans does not return the header and the whole packet";
        for (size_t pos = vnet_hdr_min; pos < hs; ++pos)
            if ((pos < first ? head[pos] : body[pos - first]) != span_fill)
                return "the pad of a longer header was written";
    }
    return nullptr;
}

/** @brief Read the probe through a first span of the header's size and a second that fits it exactly, then
 *  one a byte short, and check the return value follows the spans: the cut-off tail leaves no sign but the
 *  packet's own length field.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *read_clamp(duct_sock_t fd, duct_sock_t udp, size_t hs)
{
    uint8_t head[vnet_hdr_long],
            body[probe_len];
    const size_t rooms[] = { probe_len, probe_len - 1u };
    for (size_t i = 0u; i < sizeof rooms / sizeof rooms[0]; ++i) {
        if (!probe_send(udp))
            return "send into the tun failed";
        if (read_probe(fd, head, hs, body, rooms[i], hs) != hs + rooms[i])
            return "a read does not return what its spans hold";
        if (((unsigned)body[2] << 8u | body[3]) != probe_len)
            return "a packet cut short by its span lost its length field";
    }
    return nullptr;
}

/** @brief Read @p fd, whose header is @p hs bytes, until it is empty.
 *  @return whether the probe was among the packets. */
static bool drain_has_probe(duct_sock_t fd, size_t hs)
{
    uint8_t buf[2048];
    bool found = false;
    for (ssize_t n; (n = read(fd, buf, sizeof buf)) > 0; )
        found = found || (n > (ssize_t)hs && is_probe(buf + hs, (size_t)n - hs));
    return found;
}

/** @brief Read the probe into one span a byte short of the header, and check the kernel refuses it with
 *  EINVAL and takes the packet with it. A packet of another kind queued ahead of the probe takes the refusal
 *  in its place and leaves the probe in the drain, so the check runs again, a few times, before it fails.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *read_under(duct_sock_t fd, duct_sock_t udp, size_t hs)
{
    uint8_t span[vnet_hdr_long];
    struct pollfd pf = { .fd = fd, .events = POLLIN };
    for (unsigned tries = 0u; tries < 3u; ++tries) {
        drain_has_probe(fd, hs);
        if (!probe_send(udp) || poll(&pf, 1, hold_ms) != 1)
            return "the probe did not reach the tun";
        ssize_t n = read(fd, span, hs - 1u);
        int err = errno;
        if (n != -1 || err != EINVAL)
            return "a read under the header length is not refused with EINVAL";
        if (!drain_has_probe(fd, hs))
            return nullptr;
    }
    return "a read refused under the header length left its packet queued";
}

/** @brief Offer the tun the checksum and TCP offloads with the USO flags, without them where the kernel
 *  refuses, send the burst of @c burst_n datagrams in one @c UDP_SEGMENT write and read it back: one
 *  GSO type 5 packet of the burst's whole size where the flags were taken, @c burst_n datagrams where
 *  not. Sets @c g_uso.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *read_uso(duct_sock_t fd, duct_sock_t udp, size_t hs)
{
    constexpr unsigned tcp = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_TSO_ECN;
    uint8_t head[vnet_hdr_long],
            body[256],
            burst[burst_n * probe_bytes] = {};
    g_uso = ioctl(fd, TUNSETOFFLOAD, tcp | tun_f_uso) == 0;
    if (!g_uso && ioctl(fd, TUNSETOFFLOAD, tcp) != 0)
        return "the tun refused the checksum and TCP offloads";
    if (!burst_send(udp, burst))
        return "the burst did not go into the tun";
    if (!g_uso) {
        for (unsigned i = 0u; i < burst_n; ++i)
            if (read_probe(fd, head, hs, body, sizeof body, hs) != hs + probe_len)
                return "a burst the kernel cuts does not read as datagrams of its own";
        return nullptr;
    }
    if (read_probe(fd, head, hs, body, sizeof body, hs)
        != hs + ip_hdr_len + udp_hdr_len + sizeof burst)
        return "a burst under the USO flags does not read as one packet";
    uint16_t size, start, off;
    memcpy(&size, head + 4u, sizeof size);
    memcpy(&start, head + 6u, sizeof start);
    memcpy(&off, head + 8u, sizeof off);
    return !(head[0] & 1u) || head[1] != 5u ? "the burst's header is no segmented write needing its checksum"
         : size != probe_bytes ? "the burst's segment size is not the sender's"
         : start != ip_hdr_len || off != 6u ? "the burst's checksum start and offset are not the UDP header's"
         : nullptr;
}

/** @brief Open the scenario's tun into @p tun with a vnet header of @p hdr_sz bytes, the kernel's own where 0.
 *  Sets @c g_skip where the host has no tun device.
 *  @return the text of the first failed step, nullptr when the tun is open or the host skips. */
static const char *tun_open_sized(tun_opened_t *tun, int hdr_sz)
{
    *tun = tun_open(tun_name);
    if (tun->rc == rc_not_supported) {
        g_skip = "the host has no tun device";
        return nullptr;
    }
    return tun->rc != rc_ok ? "tun_open refused a free name"
         : hdr_sz && ioctl(tun->fd, TUNSETVNETHDRSZ, &hdr_sz) != 0 ? "the tun refused its vnet header size"
         : nullptr;
}

/** @brief Open a tun with a vnet header of @p hdr_sz bytes, the kernel's own where 0, bring it up, and check
 *  on the host kernel the facts the engine's read of it rests on: the stream over two spans, the pad of a
 *  longer header, the clamp of a short span and the refusal under the header length. No engine runs. Sets
 *  @c g_skip where the host has no tun device.
 *  @return the text of the first failed check, nullptr when all hold or the host skips. */
static const char *sc_read(int hdr_sz)
{
    tun_opened_t tun;
    auto err = tun_open_sized(&tun, hdr_sz);
    if (g_skip)
        return nullptr;
    size_t hs = hdr_of(tun.fd);
    if (!err)
        err = hs < vnet_hdr_min || hs > vnet_hdr_long ? "the vnet header has no size"
            : !th_ifup(tun_name, tun_addr, 0) ? "the tun refused its address"
            : nullptr;
    duct_sock_t udp = err ? duct_sock_bad : uc_connect_to(tun_peer, probe_port);
    if (!err && udp == duct_sock_bad)
        err = "no udp socket routed into the tun";
    if (!err)
        err = read_spans(tun.fd, udp, hs);
    if (!err)
        err = read_clamp(tun.fd, udp, hs);
    if (!err)
        err = read_under(tun.fd, udp, hs);
    if (!err)
        err = read_uso(tun.fd, udp, hs);
    if (udp != duct_sock_bad)
        close(udp);
    duct_sock_close(tun.fd);
    return err;
}

/** @brief Run the tun scenario with a vnet header of @p hdr_sz bytes, the kernel's own where 0, or set
 *  @c g_skip where the host has no tun device. */
static const char *sc_tun(int hdr_sz)
{
    auto err = tun_open_sized(&g_tun, hdr_sz);
    if (g_skip)
        return nullptr;
    if (!err)
        err = tun_opens();
    if (err) {
        duct_sock_close(g_tun.fd);
        return err;
    }
    duct_atomic_store(&g_probes, 0, relaxed);
    g_attach_fd = g_tun.fd;
    return serve("tun-leg", tun_on_frame, tun_client);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    g_skip = th_enter_netns();
    auto err = sc_wire();
    if (!err && !g_skip)
        err = sc_read(0);
    if (!err && !g_skip)
        err = sc_read(vnet_hdr_long);
    if (!err && !g_skip)
        err = sc_tun(0);
    if (!err && !g_skip)
        err = sc_tun(vnet_hdr_long);
    if (err)
        fprintf(stderr, "tun: %s\n", err);
    else if (g_skip)
        printf("tun: OK, the tun scenario skipped: %s\n", g_skip);
    else
        printf("tun: OK\n");
    return err != nullptr;
}
