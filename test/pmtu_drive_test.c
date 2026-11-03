/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file pmtu_drive_test.c
 *  @brief The path-MTU drive: probe waits, sends and echoes on a synthetic
 *  clock, and the search cut to the kernel's figure on real legs.
 *
 *  @c sc_wait expects a probe's wait to be four round trips, at least 50 ms,
 *  doubled per try and held at 2 s, whatever the try count. @c sc_sent expects
 *  a send to be recorded and to answer the wait for the try the search is on.
 *  @c sc_echo expects only the probe out to be confirmed, once, and only a
 *  probe answered on its first try to set the round trip.
 *
 *  @c sc_loopback opens the drive on a connected datagram leg, which reports
 *  65535, and on a shared datagram leg, which reports none and takes the
 *  default: ceilings, a base over its ceiling, three unanswered tries failing a
 *  size and a loss with no probe out counting nothing. @c sc_kernel, Linux only
 *  and run in a user and network namespace the test enters before any thread
 *  exists, lowers an interface to 1400 and expects the ceiling to follow the
 *  kernel, a probe over it to reopen the search under it keeping a confirmed
 *  size that fits and falling to the floor otherwise, and a probe at the
 *  figure to be judged as an ordinary loss. A host that refuses the namespace
 *  skips @c sc_kernel with a note.
 */

#define _GNU_SOURCE

#include "duct.h"
#include "duct_pmtu.h"
#include "test_helpers.h"

#ifdef __linux__
#include "tun_open.h"
#include "netns_helpers.h"
#endif

#include <limits.h>
#include <stdatomic.h>

/** @brief Return @p msg from the calling check when @p cond fails. */
#define expect(cond, msg) do { if (!(cond)) return msg; } while (0)

/** @brief Synthetic clock origin, nanoseconds. */
static constexpr uint64_t t0     = 1'000'000'000'000u;
/** @brief One millisecond, nanoseconds. */
static constexpr uint64_t ms     = 1'000'000u;
/** @brief Longest wait for a session to open, milliseconds. */
static constexpr unsigned wait_ms = 5000u;

/** @brief A drive over @p base to @p max with round trip @p rtt, no probe out. */
static duct_pmtu_drive_t s_drive(uint16_t base, uint16_t max, uint64_t rtt)
{
    duct_pmtu_drive_t d = { .floor = base, .rtt = rtt };
    duct_pmtu_init(&d.search, base, max);
    return d;
}

/** @brief Read the wait of each try on a floor, a measured, a short and a long round trip.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_wait(void)
{
    static const uint64_t floor_wait[] = { 50u, 100u, 200u, 400u, 800u, 1600u, 2000u, 2000u };
    auto d = s_drive(1280u, 1500u, 0u);
    for (unsigned tries = 0u; tries < sizeof floor_wait / sizeof floor_wait[0]; ++tries)
        expect(duct_pmtu_drive_wait_ms(&d, tries) == floor_wait[tries],
               "the wait of a probe on no measured trip is not 50 ms doubled per try to 2 s");
    expect(duct_pmtu_drive_wait_ms(&d, UINT_MAX) == 2000u, "a probe tried without end waits past the ceiling");
    d.rtt = 100u * ms;
    expect(duct_pmtu_drive_wait_ms(&d, 0u) == 400u && duct_pmtu_drive_wait_ms(&d, 1u) == 800u
               && duct_pmtu_drive_wait_ms(&d, 2u) == 1600u && duct_pmtu_drive_wait_ms(&d, 3u) == 2000u,
           "the wait of a probe is not four round trips doubled per try to 2 s");
    d.rtt = 10u * ms;
    expect(duct_pmtu_drive_wait_ms(&d, 0u) == 50u, "four short round trips wait under the floor");
    d.rtt = 5'000u * ms;
    expect(duct_pmtu_drive_wait_ms(&d, 0u) == 2000u, "four long round trips wait past the ceiling");
    return nullptr;
}

/** @brief Send a probe on the first and on a later try and read the record and the wait.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_sent(void)
{
    auto d = s_drive(1280u, 1500u, 100u * ms);
    expect(duct_pmtu_drive_sent(&d, 1500u, t0) == 400u, "a probe's first wait is not the first try's");
    expect(d.probing == 1500u && d.probe_at == t0, "a sent probe is not recorded");
    d.search.unanswered = 2u;
    expect(duct_pmtu_drive_sent(&d, 1500u, t0 + 5u * ms) == 1600u,
           "a probe's wait does not follow the unanswered tries");
    expect(d.probe_at == t0 + 5u * ms, "a second send does not date the probe afresh");
    return nullptr;
}

/** @brief Echo with no probe out, a wrong size, the right size twice and a retried probe.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_echo(void)
{
    auto d = s_drive(1280u, 1500u, 100u * ms);
    expect(!duct_pmtu_drive_echo(&d, 1500u, t0) && d.search.good == 1280u,
           "an echo is confirmed with no probe out");
    duct_discard duct_pmtu_drive_sent(&d, 1500u, t0);
    expect(!duct_pmtu_drive_echo(&d, 1400u, t0 + 30u * ms) && d.probing == 1500u && d.rtt == 100u * ms,
           "an echo of another size confirms the probe out");
    expect(duct_pmtu_drive_echo(&d, 1500u, t0 + 30u * ms), "the echo of the probe out is not confirmed");
    expect(d.search.good == 1500u && !d.probing && d.rtt == 30u * ms,
           "a confirmed echo does not raise the size, clear the probe and take the round trip");
    expect(!duct_pmtu_drive_echo(&d, 1500u, t0 + 60u * ms) && d.rtt == 30u * ms,
           "an echo is confirmed twice");
    d = s_drive(1280u, 1500u, 100u * ms);
    duct_discard duct_pmtu_drive_sent(&d, 1500u, t0);
    d.search.unanswered = 1u;
    expect(duct_pmtu_drive_echo(&d, 1500u, t0 + 30u * ms) && d.rtt == 100u * ms,
           "a probe that took a second try measures the round trip");
    return nullptr;
}

/** @brief Check the client session runs in its @c on_session_open. */
static const char *(*g_client_check)(duct_session_t *s);
/** @brief Check the shared-leg server session runs in its @c on_session_open. */
static const char *(*g_server_check)(duct_session_t *s);
/** @brief What the client check answered. */
static const char *g_client_err;
/** @brief What the server check answered. */
static const char *g_server_err;
/** @brief Sessions whose check has run. */
static atomic_int  g_done = 0;

/** @brief Open the drive on a connected datagram leg and drive it through opens, losses and a failed size.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *client_check(duct_session_t *s)
{
    duct_pmtu_drive_t d;
    duct_pmtu_drive_open(&d, s, duct_conn_id_primary, 1280u, 1500u, 7u * ms);
    expect(d.search.base == 1280u && d.search.max == 1500u && d.search.good == 1280u && d.floor == 1280u
               && d.rtt == 7u * ms && !d.probing,
           "a search over a connected leg does not open at the bounds it was given");
    duct_pmtu_drive_open(&d, s, duct_conn_id_primary, 1500u, 1400u, 0u);
    expect(d.search.max == 1500u, "a search opens under its own base");
    duct_pmtu_drive_open(&d, s, duct_conn_id_primary, 1280u, 1500u, 0u);
    expect(!duct_pmtu_drive_lost(&d, s, duct_conn_id_primary) && d.search.unanswered == 0u,
           "a loss with no probe out counts");
    for (unsigned i = 0u; i < duct_pmtu_unanswered_max; ++i) {
        duct_discard duct_pmtu_drive_sent(&d, 1500u, t0);
        bool moved = duct_pmtu_drive_lost(&d, s, duct_conn_id_primary);
        expect(moved == (i + 1u == duct_pmtu_unanswered_max), "a size does not fail at its last unanswered try");
        expect(!d.probing, "a lost probe stays out");
    }
    expect(d.search.failed == 1500u && d.search.good == 1280u && d.search.max == 1500u,
           "a failed size does not bound the search");
    return nullptr;
}

/** @brief Open the drive on a shared datagram leg, which reports no path MTU, and lose a probe.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *server_check(duct_session_t *s)
{
    duct_pmtu_drive_t d;
    duct_pmtu_drive_open(&d, s, duct_conn_id_primary, 1280u, 9000u, 0u);
    expect(d.search.max == 1500u, "a leg with no kernel figure does not search up to the default");
    duct_pmtu_drive_open(&d, s, duct_conn_id_primary, 1280u, 1400u, 0u);
    expect(d.search.max == 1400u, "a ceiling under the default is raised to it");
    duct_discard duct_pmtu_drive_sent(&d, 1400u, t0);
    expect(!duct_pmtu_drive_lost(&d, s, duct_conn_id_primary) && d.search.unanswered == 1u && !d.probing,
           "a leg with no kernel figure does not count a loss against the search");
    return nullptr;
}

/** @brief Run the client check as the session opens and send one datagram, which opens the server's session. */
static duct_result_t cli_on_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                                 [[maybe_unused]] void *user_ctx, duct_response_t *out,
                                 [[maybe_unused]] void *proto_state)
{
    g_client_err = g_client_check(s);
    duct_atomic_fetch(add, &g_done, 1, release);
    static const char ping[] = "pmtu-drive-ping";
    duct_response_same(out, duct_view(duct_view_u8, (void *)ping, sizeof ping - 1u),
                       fl_send_static, 0);
    return rc_ok;
}

/** @brief Run the server check as the shared-leg session opens. */
static duct_result_t srv_on_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                                 [[maybe_unused]] void *user_ctx,
                                 [[maybe_unused]] duct_response_t *out,
                                 [[maybe_unused]] void *proto_state)
{
    g_server_err = g_server_check(s);
    duct_atomic_fetch(add, &g_done, 1, release);
    return rc_ok;
}

/** @brief Take every frame and answer none. */
static duct_result_t on_frame([[maybe_unused]] duct_session_t *s,
                              [[maybe_unused]] duct_conn_id_t conn_id,
                              [[maybe_unused]] const duct_frame_t *frame,
                              [[maybe_unused]] duct_response_t *out,
                              [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

/** @brief A datagram-batch protocol @p name with @p flags and @p on_open, owning its wire.
 *  @return nullptr when the wire or the protocol is not built.
 */
static duct_proto_t *s_proto(const char *name, duct_proto_flags_t flags, duct_session_open_fn on_open)
{
    auto wire = duct_wire_create_dgram_batch(0u, false);
    if (!wire)
        return nullptr;
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = name, .wire = wire, .flags = flags, .on_frame = on_frame,
        .on_session_open = on_open, .max_response = 1024u,
    });
    if (proto)
        proto->owned_wire = wire;
    else
        duct_wire_destroy(wire);
    return proto;
}

/** @brief Run an engine until @p sessions sessions have opened and run their checks.
 *  The client dials @p host over a connected datagram leg. With @p serve the
 *  engine also binds a shared datagram listener on @p host for it to reach;
 *  without, the client dials port 9 and no peer answers.
 *  @return the engine's failure, else the client check's, else the server's;
 *          nullptr when all hold.
 */
static const char *s_run(const char *host, bool serve, int sessions)
{
    duct_atomic_store(&g_done, 0, relaxed);
    g_client_err = g_server_err = nullptr;
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return "engine launch failed";
    auto srv = serve ? s_proto("pmtu-drive-srv", fl_proto_dgram_shared, srv_on_open) : nullptr;
    auto cli = s_proto("pmtu-drive-cli", 0, cli_on_open);
    const char *err = !cli || (serve && !srv) ? "proto create failed" : nullptr;
    uint16_t port = serve ? 0u : 9u;
    pthread_t th;
    bool running = false;
    if (!err && serve
        && duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram, .addr = host,
                                  .n_protos = 1, .protos = (const duct_proto_t *[]){ srv } },
                              &port, nullptr, 0u, nullptr) != rc_ok)
        err = "listener bind failed";
    if (!err)
        err = pthread_create(&th, nullptr, th_run, io) != 0 ? "thread create failed" : nullptr;
    running = !err;
    if (!err) {
        char addr[64];
        snprintf(addr, sizeof addr, "%s:%u", host, (unsigned)port);
        if (th_connect_retry(io, addr, cli, x_udp_peer) != rc_ok)
            err = "connect failed";
        else if (!th_wait_int(&g_done, sessions, wait_ms))
            err = "the sessions did not open";
    }
    if (running) {
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(srv);
    duct_proto_destroy(cli);
    return err ? err : g_client_err ? g_client_err : g_server_err;
}

/** @brief Run the connected-leg check and the shared-leg check over loopback.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_loopback(void)
{
    g_client_check = client_check;
    g_server_check = server_check;
    return s_run("127.0.0.1", true, 2);
}

#ifdef __linux__

/** @brief Hold the kernel's 1400 against the drive's open, a probe over it, a confirmed size on each side of it and a probe at it.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *kernel_check(duct_session_t *s)
{
    uint16_t path = 0u;
    expect(duct_conn_path_mtu(s, duct_conn_id_primary, &path) == rc_ok && path == 1400u,
           "the kernel does not hold the interface's size for the leg");
    duct_pmtu_drive_t d;
    duct_pmtu_drive_open(&d, s, duct_conn_id_primary, 1280u, 1500u, 0u);
    expect(d.search.max == 1400u && d.search.good == 1280u, "a search is not cut to the kernel's figure");

    duct_discard duct_pmtu_drive_sent(&d, 1500u, t0);
    expect(duct_pmtu_drive_lost(&d, s, duct_conn_id_primary), "a probe over the kernel's figure does not move the size");
    expect(d.search.max == 1400u && d.search.good == 1280u && d.search.base == 1280u && !d.search.failed
               && !d.probing,
           "a probe over the kernel's figure does not reopen the search under it");

    duct_pmtu_ack(&d.search, 1350u);
    duct_discard duct_pmtu_drive_sent(&d, 1500u, t0);
    expect(duct_pmtu_drive_lost(&d, s, duct_conn_id_primary), "the second probe over the kernel's figure does not move the size");
    expect(d.search.max == 1400u && d.search.good == 1350u && d.search.base == 1350u,
           "a confirmed size under the kernel's figure is not kept");

    duct_pmtu_ack(&d.search, 1450u);
    duct_discard duct_pmtu_drive_sent(&d, 1500u, t0);
    expect(duct_pmtu_drive_lost(&d, s, duct_conn_id_primary), "a probe over a lowered figure does not move the size");
    expect(d.search.max == 1400u && d.search.good == 1280u && d.search.base == 1280u,
           "a confirmed size over the kernel's figure is not dropped to the floor");

    duct_discard duct_pmtu_drive_sent(&d, 1400u, t0);
    expect(!duct_pmtu_drive_lost(&d, s, duct_conn_id_primary) && d.search.unanswered == 1u,
           "a probe at the kernel's figure is judged by it");
    return nullptr;
}

/** @brief Open a tun at 1400, dial through it and run the kernel check on that leg.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_kernel(void)
{
    auto tun = tun_open("dpm-l6");
    if (tun.rc != rc_ok)
        return "the tun was refused";
    const char *err = th_ifup("dpm-l6", "10.77.0.1", 1400) ? nullptr : "the tun refused its address and size";
    if (!err) {
        g_client_check = kernel_check;
        err = s_run("10.77.0.2", false, 1);
    }
    close(tun.fd);
    return err;
}

#endif

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    bool netns = false;
#ifdef __linux__
    netns = !th_enter_netns();
#endif
    static const struct { const char *name; const char *(*fn)(void); } cases[] = {
        { "wait",     sc_wait },
        { "sent",     sc_sent },
        { "echo",     sc_echo },
        { "loopback", sc_loopback },
#ifdef __linux__
        { "kernel",   sc_kernel },
#endif
    };
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
#ifdef __linux__
        if (!netns && cases[i].fn == sc_kernel) {
            printf("pmtu_drive: kernel skipped, no namespace to lower an interface in\n");
            continue;
        }
#endif
        auto err = cases[i].fn();
        if (err) {
            fprintf(stderr, "pmtu_drive: %s: %s\n", cases[i].name, err);
            return 1;
        }
    }
    printf("pmtu_drive: OK\n");
    return 0;
}
