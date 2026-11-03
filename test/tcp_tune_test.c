/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file tcp_tune_test.c
 * @brief A protocol's TCP send options, the TX-position calls and a leg's
 * addresses over loopback.
 *
 * On Linux both the accepted and the dialed socket carry the lowat and the
 * congestion control the protocol asked for, keep the kernel's defaults when it
 * asked for none, and keep the default controller when it named one the kernel
 * refuses; @ref duct_conn_tcp_congestion reads back the controller in force.
 * On Windows the dialed socket reads back the controller its dial set before
 * connect under Winsock's name, newreno for reno, and the host's default where
 * the protocol named none or one Winsock lacks.
 * A leg dialled with its own controller, reno, runs it while the session's
 * first leg runs the protocol's cubic. A stream leg answers its TCP figures, a
 * fresh loopback one with a window and no retransmission timeout, and refuses a
 * slot past the legs and an empty one. It takes an acknowledgment bound, read
 * back off its socket on Linux, and refuses one past @c INT32_MAX, a slot past
 * the legs and an empty one; a datagram leg takes none.
 * An idle stream leg answers its TX end with nothing queued and an end already
 * sent, and refuses an argument, an empty slot and a response past its ring. A
 * shared datagram leg, which has no TX ring, answers not supported, sent and
 * fits; a connected datagram leg answers its TX end and names no controller
 * and no TCP figures.
 * The two ends of one connection, a stream or a datagram one, name the same
 * dialing address and the listener's, the shared datagram leg through its
 * listener and its peer; a dialed leg names its own address and the
 * listener's, and a slot past the legs and an empty one are refused.
 * A stream leg's unsent bytes read back unread on Linux, and unread or under
 * 1 MiB on Windows, where the first reading turns the statistics on and answers
 * unread; a datagram leg, a slot past the legs and an empty one answer unread.
 * A dial a joined leg declares onto its own held slot is refused, and on Linux
 * the refusal leaves a line on stderr.
 *
 * On Linux a protocol asking for a lowat that follows the pacing rate gets
 * one: its dialed socket, paced at 256 KB/s under a timer streaming 32 KB
 * responses, drops its lowat to the 4 KB floor, holds no more than that lowat
 * and one capped write unsent, and @ref duct_conn_tx_quantum reports the 8 KB
 * write cap; paced at 14 MB/s under the same load, it takes back its 32 KB
 * ceiling and the quantum half of it.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#ifdef __linux__
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

static atomic_int g_opened = 0;
static atomic_int g_end_rc = -1;
static atomic_int g_queued = -1;
static atomic_int g_sent_live = -1;
static atomic_int g_sent_other = -1;
static atomic_int g_fits_small = -1;
static atomic_int g_fits_huge = -1;
static atomic_int g_range_rc = -1;
static atomic_int g_empty_rc = -1;
static atomic_int g_shared_rc = -1;
static atomic_int g_shared_sent = -1;
static atomic_int g_shared_fits = -1;
static atomic_int g_cc_rc = -1;
static char g_cc[duct_tcp_cc_name_max];
static atomic_int g_open_stats_rc = -1;
static atomic_int g_joined = 0;
static atomic_int g_join_cc_rc = -1;
static char g_join_cc[duct_tcp_cc_name_max];
static atomic_int g_stats_rc = -1;
static duct_tcp_stats_t g_stats;
static atomic_int g_stats_range_rc = -1;
static atomic_int g_stats_empty_rc = -1;
static atomic_int g_open_ack_rc = -1;
static atomic_int g_ack_rc = -1;
static atomic_int g_ack_range_rc = -1;
static atomic_int g_ack_empty_rc = -1;
static atomic_int g_ack_big_rc = -1;
static char g_dial_addr[64];

typedef struct {
    atomic_int  rc;
    duct_peer_t local, remote;
} s_addrs_t;

static s_addrs_t g_srv_addrs, g_cli_addrs, g_shared_addrs, g_join_addrs;
static atomic_int g_addrs_range_rc = -1;
static atomic_int g_addrs_empty_rc = -1;
static _Atomic uint64_t g_unsent_open, g_unsent_shared, g_unsent_join, g_unsent_again,
                        g_unsent_range, g_unsent_empty;
#ifdef __linux__
static atomic_int g_follow_quantum = -1;
static duct_timer_id_t g_follow_timer;
static const uint8_t s_chunk[32768];
#endif

static const char ping[] = "tcp-tune-ping";

static void s_reset(void)
{
    duct_atomic_store(&g_opened, 0, relaxed);
    duct_atomic_store(&g_end_rc, -1, relaxed);
    duct_atomic_store(&g_queued, -1, relaxed);
    duct_atomic_store(&g_sent_live, -1, relaxed);
    duct_atomic_store(&g_sent_other, -1, relaxed);
    duct_atomic_store(&g_fits_small, -1, relaxed);
    duct_atomic_store(&g_fits_huge, -1, relaxed);
    duct_atomic_store(&g_range_rc, -1, relaxed);
    duct_atomic_store(&g_empty_rc, -1, relaxed);
    duct_atomic_store(&g_shared_rc, -1, relaxed);
    duct_atomic_store(&g_shared_sent, -1, relaxed);
    duct_atomic_store(&g_shared_fits, -1, relaxed);
    duct_atomic_store(&g_cc_rc, -1, relaxed);
    memset(g_cc, 0, sizeof g_cc);
    duct_atomic_store(&g_open_stats_rc, -1, relaxed);
    duct_atomic_store(&g_joined, 0, relaxed);
    duct_atomic_store(&g_join_cc_rc, -1, relaxed);
    memset(g_join_cc, 0, sizeof g_join_cc);
    duct_atomic_store(&g_stats_rc, -1, relaxed);
    g_stats = (duct_tcp_stats_t){};
    duct_atomic_store(&g_stats_range_rc, -1, relaxed);
    duct_atomic_store(&g_stats_empty_rc, -1, relaxed);
    duct_atomic_store(&g_open_ack_rc, -1, relaxed);
    duct_atomic_store(&g_ack_rc, -1, relaxed);
    duct_atomic_store(&g_ack_range_rc, -1, relaxed);
    duct_atomic_store(&g_ack_empty_rc, -1, relaxed);
    duct_atomic_store(&g_ack_big_rc, -1, relaxed);
    s_addrs_t *all[] ={ &g_srv_addrs, &g_cli_addrs, &g_shared_addrs, &g_join_addrs };
    for (size_t i = 0u; i < sizeof all / sizeof all[0]; ++i) {
        all[i]->local = all[i]->remote = (duct_peer_t){};
        duct_atomic_store(&all[i]->rc, -1, relaxed);
    }
    duct_atomic_store(&g_addrs_range_rc, -1, relaxed);
    duct_atomic_store(&g_addrs_empty_rc, -1, relaxed);
    duct_atomic_store(&g_unsent_open, 0u, relaxed);
    duct_atomic_store(&g_unsent_shared, 0u, relaxed);
    duct_atomic_store(&g_unsent_join, 0u, relaxed);
    duct_atomic_store(&g_unsent_again, 0u, relaxed);
    duct_atomic_store(&g_unsent_range, 0u, relaxed);
    duct_atomic_store(&g_unsent_empty, 0u, relaxed);
}

/** @brief True when @p v is a reading of a stream leg's unsent bytes this
 *  platform may give: unread on Linux, unread or under 1 MiB on Windows. */
static bool s_unsent_plausible(uint64_t v)
{
#ifdef __linux__
    return v == duct_tx_unsent_unread;
#else
    return v == duct_tx_unsent_unread || v < (1u << 20);
#endif
}

static void s_addrs_take(duct_session_t *s, duct_conn_id_t conn_id, s_addrs_t *out)
{
    duct_peer_t local = {}, remote = {};
    auto rc = duct_conn_addrs(s, conn_id, &local, &remote);
    out->local = local;
    out->remote = remote;
    duct_atomic_store(&out->rc, (int)rc, release);
}

static bool s_peer_same(const duct_peer_t *a, const duct_peer_t *b)
{
    size_t n = a->family == AF_INET6 ? sizeof a->addr.v6 : sizeof a->addr.v4;
    return a->family == b->family && a->port == b->port && memcmp(&a->addr, &b->addr, n) == 0;
}

static bool s_peer_is_listener(const duct_peer_t *peer, uint16_t port)
{
    static const uint8_t loopback[4] = { 127u, 0u, 0u, 1u };
    return peer->family == AF_INET && peer->port == port
        && memcmp(peer->addr.v4, loopback, sizeof loopback) == 0;
}

static const char *s_addrs_paired(const s_addrs_t *dialer, const s_addrs_t *accepted,
                                  uint16_t port)
{
    if (duct_atomic_load(&dialer->rc, acquire) != (int)rc_ok
        || duct_atomic_load(&accepted->rc, acquire) != (int)rc_ok)
        return "a leg did not answer its addresses";
    if (!s_peer_is_listener(&dialer->remote, port) || !s_peer_is_listener(&accepted->local, port))
        return "a leg's addresses did not name the listening address";
    if (!s_peer_same(&dialer->local, &accepted->remote))
        return "the two ends of one connection named different dialing addresses";
    return nullptr;
}

static duct_result_t
srv_on_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    s_addrs_take(s, duct_conn_id_primary, &g_srv_addrs);
    duct_atomic_fetch(add, &g_opened, 1, release);
    return rc_ok;
}

static duct_result_t
shared_on_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
               [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
               [[maybe_unused]] void *proto_state)
{
    duct_tx_pos_t pos = {};
    size_t queued = 0u;
    duct_atomic_store(&g_shared_rc,
                      (int)duct_conn_tx_end(s, duct_conn_id_primary, &pos, &queued), relaxed);
    duct_atomic_store(&g_shared_sent, duct_conn_tx_sent(s, duct_conn_id_primary, pos), relaxed);
    duct_atomic_store(&g_shared_fits,
                      duct_conn_tx_fits(s, duct_conn_id_primary, (size_t)1u << 20u), relaxed);
    duct_atomic_store(&g_unsent_shared, duct_conn_tx_unsent(s, duct_conn_id_primary), relaxed);
    s_addrs_take(s, duct_conn_id_primary, &g_shared_addrs);
    duct_atomic_fetch(add, &g_opened, 1, release);
    return rc_ok;
}

static duct_result_t
cli_on_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    duct_tx_pos_t pos = {}, unused = {};
    size_t queued = 99u, spare = 0u;
    duct_atomic_store(&g_end_rc,
                      (int)duct_conn_tx_end(s, duct_conn_id_primary, &pos, &queued), relaxed);
    duct_atomic_store(&g_queued, (int)queued, relaxed);
    duct_atomic_store(&g_sent_live, duct_conn_tx_sent(s, duct_conn_id_primary, pos), relaxed);
    duct_atomic_store(&g_sent_other,
                      duct_conn_tx_sent(s, duct_conn_id_primary + 1u, pos), relaxed);
    duct_atomic_store(&g_fits_small, duct_conn_tx_fits(s, duct_conn_id_primary, 1u), relaxed);
    duct_atomic_store(&g_fits_huge, duct_conn_tx_fits(s, duct_conn_id_primary, SIZE_MAX),
                      relaxed);
    duct_atomic_store(&g_range_rc,
                      (int)duct_conn_tx_end(s, duct_session_max_legs, &unused, &spare), relaxed);
    duct_atomic_store(&g_empty_rc,
                      (int)duct_conn_tx_end(s, duct_conn_id_primary + 1u, &unused, &spare),
                      relaxed);
    duct_atomic_store(&g_cc_rc, (int)duct_conn_tcp_congestion(s, duct_conn_id_primary, g_cc),
                      relaxed);
    duct_atomic_store(&g_open_stats_rc,
                      (int)duct_conn_tcp_stats(s, duct_conn_id_primary, &(duct_tcp_stats_t){}),
                      relaxed);
    duct_atomic_store(&g_open_ack_rc,
                      (int)duct_conn_set_ack_timeout(s, duct_conn_id_primary, 0u), relaxed);
    duct_atomic_store(&g_unsent_open, duct_conn_tx_unsent(s, duct_conn_id_primary), relaxed);
    s_addrs_take(s, duct_conn_id_primary, &g_cli_addrs);
    duct_atomic_fetch(add, &g_opened, 1, release);
    duct_response_same(out, duct_view(duct_view_u8, (void *)ping, sizeof ping - 1u),
                       fl_send_static, 0);
    return rc_ok;
}

static duct_result_t
dial_on_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
             [[maybe_unused]] void *user_ctx, duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_cc_rc, (int)duct_conn_tcp_congestion(s, duct_conn_id_primary, g_cc),
                      relaxed);
    out->control.open_leg.kind = leg_kind_connect;
    out->control.open_leg.conn_id = 1u;
    out->control.open_leg.connect_addr = g_dial_addr;
    out->control.open_leg.tcp_congestion = "reno";
    duct_atomic_fetch(add, &g_opened, 1, release);
    return rc_ok;
}

static duct_result_t
dial_on_join(duct_session_t *s, duct_conn_id_t conn_id, [[maybe_unused]] const duct_peer_t *peer,
             duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_join_cc_rc, (int)duct_conn_tcp_congestion(s, conn_id, g_join_cc),
                      relaxed);
    duct_atomic_store(&g_stats_rc, (int)duct_conn_tcp_stats(s, conn_id, &g_stats), relaxed);
    duct_atomic_store(&g_stats_range_rc,
                      (int)duct_conn_tcp_stats(s, duct_session_max_legs, &(duct_tcp_stats_t){}),
                      relaxed);
    duct_atomic_store(&g_stats_empty_rc,
                      (int)duct_conn_tcp_stats(s, conn_id + 1u, &(duct_tcp_stats_t){}), relaxed);
    s_addrs_take(s, conn_id, &g_join_addrs);
    duct_atomic_store(&g_addrs_range_rc,
                      (int)duct_conn_addrs(s, duct_session_max_legs, nullptr, nullptr), relaxed);
    duct_atomic_store(&g_addrs_empty_rc, (int)duct_conn_addrs(s, conn_id + 1u, nullptr, nullptr),
                      relaxed);
    duct_atomic_store(&g_ack_rc, (int)duct_conn_set_ack_timeout(s, conn_id, 1234u), relaxed);
    duct_atomic_store(&g_ack_range_rc,
                      (int)duct_conn_set_ack_timeout(s, duct_session_max_legs, 1u), relaxed);
    duct_atomic_store(&g_ack_empty_rc, (int)duct_conn_set_ack_timeout(s, conn_id + 1u, 1u),
                      relaxed);
    duct_atomic_store(&g_ack_big_rc,
                      (int)duct_conn_set_ack_timeout(s, conn_id, (uint32_t)INT32_MAX + 1u),
                      relaxed);
    duct_atomic_store(&g_unsent_join, duct_conn_tx_unsent(s, conn_id), relaxed);
    duct_atomic_store(&g_unsent_again, duct_conn_tx_unsent(s, conn_id), relaxed);
    duct_atomic_store(&g_unsent_range, duct_conn_tx_unsent(s, duct_session_max_legs), relaxed);
    duct_atomic_store(&g_unsent_empty, duct_conn_tx_unsent(s, conn_id + 1u), relaxed);
    out->control.open_leg.kind = leg_kind_connect;
    out->control.open_leg.conn_id = conn_id;
    out->control.open_leg.connect_addr = g_dial_addr;
    duct_atomic_fetch(add, &g_joined, 1, release);
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
         [[maybe_unused]] const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

#ifdef __linux__
static duct_result_t
follow_on_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
               [[maybe_unused]] void *user_ctx, duct_response_t *out,
               [[maybe_unused]] void *proto_state)
{
    out->control.timer.delay_ms = 1u;
    out->control.timer.interval_ms = 1u;
    out->control.timer.id_out = &g_follow_timer;
    duct_atomic_fetch(add, &g_opened, 1, release);
    return rc_ok;
}

static duct_result_t
follow_on_timer(duct_session_t *s, duct_response_t *out, [[maybe_unused]] void *proto_state,
                [[maybe_unused]] uint64_t arg)
{
    duct_atomic_store(&g_follow_quantum, (int)duct_conn_tx_quantum(s, duct_conn_id_primary),
                      relaxed);
    duct_response_same(out, duct_view(duct_view_u8, (void *)s_chunk, sizeof s_chunk),
                       fl_send_static, 0);
    return rc_ok;
}
#endif

static duct_result_t
s_connect_retry(duct_engine_t *io, const char *addr, duct_proto_t *proto, duct_xport_t xport)
{
    duct_result_t rc = rc_invalid_order;
    for (unsigned waited = 0u; waited < 3000u; waited += 5u) {
        rc = duct_io_connect(io, addr, proto, nullptr, xport);
        if (rc != rc_invalid_order)
            return rc;
        struct timespec ts = { .tv_nsec = 5L * 1000L * 1000L };
        nanosleep(&ts, nullptr);
    }
    return rc;
}

typedef struct {
    uint32_t    lowat;
    const char *cc;
} s_tune_t;

static duct_proto_t *s_proto(const char *name, duct_wire_t *wire, duct_proto_flags_t flags,
                             duct_session_open_fn on_open, s_tune_t tune)
{
    if (!wire)
        return nullptr;
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = name, .wire = wire, .flags = flags,
        .on_frame = on_frame, .on_session_open = on_open,
        .max_response = 1024u,
        .tcp_notsent_lowat = tune.lowat, .tcp_congestion = tune.cc,
    });
    if (proto)
        proto->owned_wire = wire;
    else
        duct_wire_destroy(wire);
    return proto;
}

#ifdef __linux__
static void s_default_cc(char out[16])
{
    out[0] = '\0';
    auto f = fopen("/proc/sys/net/ipv4/tcp_congestion_control", "r");
    if (!f)
        return;
    if (fscanf(f, "%15s", out) != 1)
        out[0] = '\0';
    fclose(f);
}

static int s_tcp_conns_matching(int lowat, const char *cc)
{
    int n = 0;
    for (int fd = 3; fd < 1024; ++fd) {
        int type = 0, listening = 0, domain = 0, got = -1;
        socklen_t len = sizeof type;
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) != 0 || type != SOCK_STREAM)
            continue;
        len = sizeof listening;
        if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &listening, &len) != 0 || listening)
            continue;
        len = sizeof domain;
        if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &len) != 0 || domain != AF_INET)
            continue;
        char name[16] = {};
        socklen_t name_len = sizeof name;
        len = sizeof got;
        if (getsockopt(fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &got, &len) != 0
            || getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, name, &name_len) != 0)
            continue;
        n += got == lowat && strcmp(name, cc) == 0;
    }
    return n;
}

/** @brief Find the first IPv4 stream socket not listening whose local port is
 *  @p port where @p at holds and another where it does not; -1 for none. */
static int s_stream_fd(uint16_t port, bool at)
{
    for (int fd = 3; fd < 1024; ++fd) {
        int type = 0, listening = 0, domain = 0;
        socklen_t len = sizeof type;
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) != 0 || type != SOCK_STREAM)
            continue;
        len = sizeof listening;
        if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &listening, &len) != 0 || listening)
            continue;
        len = sizeof domain;
        if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &len) != 0 || domain != AF_INET)
            continue;
        struct sockaddr_in local = {};
        len = sizeof local;
        if (getsockname(fd, (struct sockaddr *)&local, &len) == 0
            && (ntohs(local.sin_port) == port) == at)
            return fd;
    }
    return -1;
}

/** @brief Read @c TCP_USER_TIMEOUT off the stream socket at local port @p port,
 *  -1 where none reads. */
static int s_user_timeout_at(uint16_t port)
{
    int fd = s_stream_fd(port, true);
    unsigned got = 0u;
    socklen_t len = sizeof got;
    return fd >= 0 && getsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &got, &len) == 0 ? (int)got
                                                                                       : -1;
}

static int s_lowat_of(int fd)
{
    int got = -1;
    socklen_t len = sizeof got;
    return getsockopt(fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &got, &len) == 0 ? got : -1;
}

static uint32_t s_notsent_of(int fd)
{
    uint8_t info[148];
    socklen_t len = sizeof info;
    uint32_t notsent = 0u;
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, info, &len) == 0 && len >= sizeof info)
        memcpy(&notsent, info + 144u, sizeof notsent);
    return notsent;
}

static void s_sleep_ms(long ms)
{
    struct timespec ts = { .tv_sec = ms / 1000L, .tv_nsec = (ms % 1000L) * 1000000L };
    nanosleep(&ts, nullptr);
}

static const char *s_follow_check(uint16_t port)
{
    int fd = s_stream_fd(port, false);
    if (fd < 0)
        return "no dialed socket to pace";
    if (setsockopt(fd, SOL_SOCKET, SO_MAX_PACING_RATE, &(unsigned){ 262144u }, sizeof(unsigned)))
        return "the kernel refused a pacing cap";
    int lowat = -1;
    for (int i = 0; i < 300 && (lowat = s_lowat_of(fd)) != 4096; ++i)
        s_sleep_ms(10L);
    if (lowat != 4096)
        return "the lowat did not follow a 256 KB/s pacing rate down to its 4 KB floor";
    s_sleep_ms(800L);
    uint32_t most = 0u;
    for (int i = 0; i < 150; ++i) {
        uint32_t now = s_notsent_of(fd);
        most = now > most ? now : most;
        s_sleep_ms(2L);
    }
    if (most > 3u * 4096u)
        return "unsent bytes ran past the lowat and the write cap";
    if (duct_atomic_load(&g_follow_quantum, relaxed) != 2 * 4096)
        return "duct_conn_tx_quantum did not report the write cap in force";
    if (setsockopt(fd, SOL_SOCKET, SO_MAX_PACING_RATE, &(unsigned){ 14u << 20 }, sizeof(unsigned)))
        return "the kernel refused a raised pacing cap";
    for (int i = 0; i < 300 && (lowat = s_lowat_of(fd)) != 32768; ++i)
        s_sleep_ms(10L);
    if (lowat != 32768)
        return "the lowat did not rise to its ceiling under a pacing rate calling for it";
    for (int i = 0; i < 100 && duct_atomic_load(&g_follow_quantum, relaxed) != 32768 / 2; ++i)
        s_sleep_ms(2L);
    if (duct_atomic_load(&g_follow_quantum, relaxed) != 32768 / 2)
        return "duct_conn_tx_quantum did not return to half the ceiling";
    return nullptr;
}

static const char *s_run_follow(void)
{
    s_reset();
    duct_atomic_store(&g_follow_quantum, -1, relaxed);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return "io create failed";
    auto srv = s_proto("tcp-follow-srv", duct_wire_create_length_prefix(0u),
                       (duct_proto_flags_t)0, srv_on_open, (s_tune_t){});
    auto wire = duct_wire_create_length_prefix(0u);
    auto cli = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "tcp-follow-cli", .wire = wire,
        .on_frame = on_frame, .on_session_open = follow_on_open, .on_timer = follow_on_timer,
        .max_response = sizeof s_chunk,
        .tcp_notsent_lowat = 32768u, .tcp_notsent_lowat_us = 2000u,
    }) : nullptr;
    if (cli)
        cli->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!srv || !cli) {
        duct_proto_destroy(srv);
        duct_proto_destroy(cli);
        duct_engine_destroy(io);
        return "proto create failed";
    }

    const char *err = nullptr;
    uint16_t port = 0u;
    pthread_t th;
    if (duct_io_listen(io, "127.0.0.1", &port, srv) != rc_ok)
        err = "listen failed";
    else if (pthread_create(&th, nullptr, th_run, io) != 0)
        err = "thread create failed";
    else {
        char addr[64];
        snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)port);
        if (s_connect_retry(io, addr, cli, x_tcp) != rc_ok)
            err = "connect failed";
        else if (!th_wait_int(&g_opened, 2, 3000u))
            err = "both sessions did not open";
        else
            err = s_follow_check(port);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(srv);
    duct_proto_destroy(cli);
    return err;
}
#endif

static const char *s_run_tcp(s_tune_t tune, [[maybe_unused]] int want_lowat,
                             [[maybe_unused]] const char *want_cc)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return "io create failed";
    auto srv = s_proto("tcp-tune-srv", duct_wire_create_length_prefix(0u),
                       (duct_proto_flags_t)0, srv_on_open, tune);
    auto cli = s_proto("tcp-tune-cli", duct_wire_create_length_prefix(0u),
                       (duct_proto_flags_t)0, cli_on_open, tune);
    if (!srv || !cli) {
        duct_proto_destroy(srv);
        duct_proto_destroy(cli);
        duct_engine_destroy(io);
        return "proto create failed";
    }

    const char *err = nullptr;
    uint16_t port = 0u;
    pthread_t th;
    if (duct_io_listen(io, "127.0.0.1", &port, srv) != rc_ok)
        err = "listen failed";
    else if (pthread_create(&th, nullptr, th_run, io) != 0)
        err = "thread create failed";
    else {
        char addr[64];
        snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)port);
        if (s_connect_retry(io, addr, cli, x_tcp) != rc_ok)
            err = "connect failed";
        else if (!th_wait_int(&g_opened, 2, 3000u))
            err = "both sessions did not open";
#ifdef __linux__
        else if (s_tcp_conns_matching(want_lowat, want_cc) != 2)
            err = "the accepted and the dialed socket do not both carry the options asked for";
#endif
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(srv);
    duct_proto_destroy(cli);
    if (err)
        return err;

    if (duct_atomic_load(&g_end_rc, acquire) != (int)rc_ok)
        return "a live stream leg did not answer its TX end";
    if (duct_atomic_load(&g_queued, acquire) != 0)
        return "a leg with nothing staged reported bytes queued";
    if (duct_atomic_load(&g_sent_live, acquire) != 1)
        return "the end of an empty ring did not read as sent";
    if (duct_atomic_load(&g_sent_other, acquire) != 1)
        return "a position read against another leg did not read as sent";
    if (duct_atomic_load(&g_fits_small, acquire) != 1)
        return "an idle ring refused a one-byte response";
    if (duct_atomic_load(&g_fits_huge, acquire) != 0)
        return "a ring admitted a response past its size";
    if (duct_atomic_load(&g_range_rc, acquire) != (int)rc_invalid_arg)
        return "a leg id past the session's legs was not refused as an argument";
    if (duct_atomic_load(&g_empty_rc, acquire) != (int)rc_invalid_order)
        return "an empty leg slot was not refused as an order";
#ifdef __linux__
    if (duct_atomic_load(&g_cc_rc, acquire) != (int)rc_ok || strcmp(g_cc, want_cc) != 0)
        return "a stream leg did not read back the congestion control in force";
#else
    /* Winsock's name contains the Linux one asked for, newreno holding reno;
     * an empty want accepts the host's default. */
    if (duct_atomic_load(&g_cc_rc, acquire) != (int)rc_ok || !strstr(g_cc, want_cc))
        return "a stream leg did not read back the congestion control in force";
#endif
    if (duct_atomic_load(&g_open_stats_rc, acquire) != (int)rc_ok)
        return "a stream leg did not answer its TCP figures";
    if (duct_atomic_load(&g_open_ack_rc, acquire) != (int)rc_ok)
        return "a stream leg refused the system's acknowledgment bound";
    if (!s_unsent_plausible(duct_atomic_load(&g_unsent_open, acquire)))
        return "a stream leg's first reading of its unsent bytes was neither unread nor small";
    return s_addrs_paired(&g_cli_addrs, &g_srv_addrs, port);
}

static const char *s_run_dial_cc(void)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return "io create failed";
    auto srv = s_proto("tcp-dial-cc-srv", duct_wire_create_length_prefix(0u),
                       (duct_proto_flags_t)0, srv_on_open, (s_tune_t){});
    auto wire = duct_wire_create_length_prefix(0u);
    auto cli = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "tcp-dial-cc-cli", .wire = wire,
        .on_frame = on_frame, .on_session_open = dial_on_open, .on_conn_join = dial_on_join,
        .max_response = 1024u, .tcp_congestion = "cubic",
    }) : nullptr;
    if (cli)
        cli->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!srv || !cli) {
        duct_proto_destroy(srv);
        duct_proto_destroy(cli);
        duct_engine_destroy(io);
        return "proto create failed";
    }

    const char *err = nullptr;
    uint16_t port = 0u;
    pthread_t th;
    if (duct_io_listen(io, "127.0.0.1", &port, srv) != rc_ok)
        err = "listen failed";
    else if (pthread_create(&th, nullptr, th_run, io) != 0)
        err = "thread create failed";
    else {
        snprintf(g_dial_addr, sizeof g_dial_addr, "127.0.0.1:%u", (unsigned)port);
        if (s_connect_retry(io, g_dial_addr, cli, x_tcp) != rc_ok)
            err = "connect failed";
        else if (!th_wait_int(&g_joined, 1, 3000u))
            err = "the leg dialled with its own controller never joined";
#ifdef __linux__
        else if (s_user_timeout_at(g_join_addrs.local.port) != 1234)
            err = "the joined leg's socket did not take its acknowledgment bound";
#endif
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(srv);
    duct_proto_destroy(cli);
    if (err)
        return err;

    if (duct_atomic_load(&g_cc_rc, acquire) != (int)rc_ok || !strstr(g_cc, "cubic"))
        return "the session's own leg did not run the protocol's controller";
    if (duct_atomic_load(&g_join_cc_rc, acquire) != (int)rc_ok || !strstr(g_join_cc, "reno"))
        return "a leg dialled with reno did not run it";
    if (duct_atomic_load(&g_stats_rc, acquire) != (int)rc_ok)
        return "a joined stream leg did not answer its TCP figures";
    if (g_stats.cwnd == 0u || g_stats.timeouts != 0u)
        return "a fresh loopback leg reported no window or a retransmission timeout";
    if (duct_atomic_load(&g_stats_range_rc, acquire) != (int)rc_invalid_arg)
        return "TCP figures past the session's legs were not refused as an argument";
    if (duct_atomic_load(&g_stats_empty_rc, acquire) != (int)rc_invalid_order)
        return "TCP figures of an empty leg slot were not refused as an order";
    if (duct_atomic_load(&g_join_addrs.rc, acquire) != (int)rc_ok
        || !s_peer_is_listener(&g_join_addrs.remote, port) || g_join_addrs.local.port == 0u)
        return "a dialed leg did not name its own address and the one it dialed";
    if (duct_atomic_load(&g_addrs_range_rc, acquire) != (int)rc_invalid_arg)
        return "addresses past the session's legs were not refused as an argument";
    if (duct_atomic_load(&g_addrs_empty_rc, acquire) != (int)rc_invalid_order)
        return "addresses of an empty leg slot were not refused as an order";
    if (duct_atomic_load(&g_ack_rc, acquire) != (int)rc_ok)
        return "a joined stream leg refused an acknowledgment bound";
    if (duct_atomic_load(&g_ack_range_rc, acquire) != (int)rc_invalid_arg)
        return "an acknowledgment bound past the session's legs was not refused as an argument";
    if (duct_atomic_load(&g_ack_empty_rc, acquire) != (int)rc_invalid_order)
        return "an acknowledgment bound on an empty leg slot was not refused as an order";
    if (duct_atomic_load(&g_ack_big_rc, acquire) != (int)rc_invalid_arg)
        return "an acknowledgment bound past INT32_MAX was not refused as an argument";
    if (!s_unsent_plausible(duct_atomic_load(&g_unsent_join, acquire))
        || !s_unsent_plausible(duct_atomic_load(&g_unsent_again, acquire)))
        return "a joined stream leg's unsent bytes were neither unread nor small";
    if (duct_atomic_load(&g_unsent_range, acquire) != duct_tx_unsent_unread
        || duct_atomic_load(&g_unsent_empty, acquire) != duct_tx_unsent_unread)
        return "a slot past the legs or an empty one answered a figure for its unsent bytes";
    return nullptr;
}

#ifdef __linux__
/** @brief Stderr redirected into a temporary file: the file, the saved
 *  descriptor and the file's path. */
typedef struct {
    int  file,
         saved;
    char path[32];
} s_held_t;

/** @brief Redirect stderr into a fresh temporary file.
 *  @return false when no file is to be had. */
static bool s_stderr_hold(s_held_t *held)
{
    memcpy(held->path, "/tmp/tcp_tune_XXXXXX", sizeof "/tmp/tcp_tune_XXXXXX");
    held->file = mkstemp(held->path);
    if (held->file < 0)
        return false;
    fflush(stderr);
    held->saved = dup(STDERR_FILENO);
    duct_discard dup2(held->file, STDERR_FILENO);
    return true;
}

/** @brief Restore stderr, copy what it held into the @p cap bytes at @p text,
 *  cut to fit and terminated, and remove the file. */
static void s_stderr_take(s_held_t *held, char *text, size_t cap)
{
    fflush(stderr);
    duct_discard dup2(held->saved, STDERR_FILENO);
    close(held->saved);
    ssize_t n = pread(held->file, text, cap - 1u, 0);
    text[n > 0 ? n : 0] = '\0';
    close(held->file);
    unlink(held->path);
}

/** @brief Run the dial scenario with stderr held, and check that the dial
 *  onto a held slot left its line there. */
static const char *s_run_dial_cc_said(void)
{
    s_held_t held;
    if (!s_stderr_hold(&held))
        return "no file to hold stderr in";
    const char *err = s_run_dial_cc();
    char said[4096];
    s_stderr_take(&held, said, sizeof said);
    if (err)
        return err;
    return strstr(said, "at conn 1 refused: slot taken") ? nullptr
                                                          : "a dial onto a held slot left no line on stderr";
}
#endif

static const char *s_run_shared(void)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return "io create failed";
    s_tune_t none = {};
    auto srv = s_proto("tcp-tune-shared", duct_wire_create_dgram_batch(0u, false),
                       fl_proto_dgram_shared, shared_on_open, none);
    auto cli = s_proto("tcp-tune-peer", duct_wire_create_dgram_batch(0u, false),
                       (duct_proto_flags_t)0, cli_on_open, none);
    if (!srv || !cli) {
        duct_proto_destroy(srv);
        duct_proto_destroy(cli);
        duct_engine_destroy(io);
        return "proto create failed";
    }

    const char *err = nullptr;
    uint16_t port = 0u;
    pthread_t th;
    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
            .addr = "127.0.0.1", .n_protos = 1,
            .protos = (const duct_proto_t *[]){ srv },
        }, &port, nullptr, 0u, nullptr) != rc_ok)
        err = "bind failed";
    else if (pthread_create(&th, nullptr, th_run, io) != 0)
        err = "thread create failed";
    else {
        char addr[64];
        snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)port);
        if (s_connect_retry(io, addr, cli, x_udp_peer) != rc_ok)
            err = "connect failed";
        else if (!th_wait_int(&g_opened, 2, 3000u))
            err = "both sessions did not open";
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(srv);
    duct_proto_destroy(cli);
    if (err)
        return err;

    if (duct_atomic_load(&g_shared_rc, acquire) != (int)rc_not_supported)
        return "a shared datagram leg answered a TX end it has no ring for";
    if (duct_atomic_load(&g_shared_sent, acquire) != 1)
        return "a position on a leg without a ring did not read as sent";
    if (duct_atomic_load(&g_shared_fits, acquire) != 1)
        return "a leg without a ring refused a response";
    if (duct_atomic_load(&g_end_rc, acquire) != (int)rc_ok)
        return "a connected datagram leg did not answer its TX end";
    if (duct_atomic_load(&g_cc_rc, acquire) != (int)rc_not_supported)
        return "a datagram leg named a congestion control";
    if (duct_atomic_load(&g_open_stats_rc, acquire) != (int)rc_not_supported)
        return "a datagram leg answered TCP figures";
    if (duct_atomic_load(&g_open_ack_rc, acquire) != (int)rc_not_supported)
        return "a datagram leg took an acknowledgment bound";
    if (duct_atomic_load(&g_unsent_open, acquire) != duct_tx_unsent_unread
        || duct_atomic_load(&g_unsent_shared, acquire) != duct_tx_unsent_unread)
        return "a datagram leg answered a figure for unsent bytes of a socket it has no queue in";
    return s_addrs_paired(&g_cli_addrs, &g_shared_addrs, port);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    char dflt[16] = "";
#ifdef __linux__
    s_default_cc(dflt);
#endif
    int pass = 1;
    auto err = s_run_tcp((s_tune_t){ .lowat = 32768u, .cc = "reno" }, 32768, "reno");
    if (err) { fprintf(stderr, "tcp_tune: set: %s\n", err); pass = 0; }
    err = s_run_tcp((s_tune_t){}, 0, dflt);
    if (err) { fprintf(stderr, "tcp_tune: unset: %s\n", err); pass = 0; }
    err = s_run_tcp((s_tune_t){ .lowat = 16384u, .cc = "no-such-cc" }, 16384, dflt);
    if (err) { fprintf(stderr, "tcp_tune: refused cc: %s\n", err); pass = 0; }
    err = s_run_shared();
    if (err) { fprintf(stderr, "tcp_tune: shared: %s\n", err); pass = 0; }
#ifdef __linux__
    err = s_run_dial_cc_said();
#else
    err = s_run_dial_cc();
#endif
    if (err) { fprintf(stderr, "tcp_tune: dial cc: %s\n", err); pass = 0; }
#ifdef __linux__
    err = s_run_follow();
    if (err) { fprintf(stderr, "tcp_tune: follow: %s\n", err); pass = 0; }
#endif
    if (!pass)
        return 1;
    printf("tcp_tune: OK (default cc %s, a joined leg's unsent bytes %s)\n", dflt[0] ? dflt : "-",
           duct_atomic_load(&g_unsent_again, acquire) == duct_tx_unsent_unread ? "unread" : "read");
    return 0;
}
