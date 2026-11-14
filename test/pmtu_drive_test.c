/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

#define _GNU_SOURCE

#include "duct.h"
#include "duct_pmtu.h"
#include "test_helpers.h"

#ifdef __linux__
#include "tun_open.h"
#include "netns_helpers.h"
#endif

#include <stdatomic.h>

#define expect(cond, msg) do { if (!(cond)) return msg; } while (0)

static constexpr uint64_t t0      = 1'000'000'000'000u;
static constexpr uint64_t ms      = 1'000'000u;
static constexpr unsigned wait_ms = 5000u;

static duct_pmtu_drive_t s_drive(uint16_t base, uint16_t max, uint64_t rtt)
{
    duct_pmtu_drive_t d = { .floor = base, .rtt = rtt };
    duct_pmtu_init(&d.search, base, max);
    return d;
}

static const char *sc_wait(void)
{
    auto d = s_drive(duct_pmtu_base_min, 1500u, 0u);
    expect(duct_pmtu_drive_wait_ms(&d) == 50u,
           "the wait on zero rtt does not clamp to 50 ms");
    d.rtt = 100u * ms;
    expect(duct_pmtu_drive_wait_ms(&d) == 400u,
           "the wait is not four round trips");
    d.rtt = 10u * ms;
    expect(duct_pmtu_drive_wait_ms(&d) == 50u,
           "four short round trips wait under the floor");
    d.rtt = 5'000u * ms;
    expect(duct_pmtu_drive_wait_ms(&d) == 2000u,
           "four long round trips wait past the ceiling");
    return nullptr;
}

static const char *sc_burst_and_close(void)
{
    auto d = s_drive(duct_pmtu_base_min, 1500u, 100u * ms);
    uint8_t n = duct_pmtu_drive_burst(&d, t0);
    expect(n == 4u && d.burst_count == 4u && d.burst_acked == 0u && d.burst_at == t0,
           "drive_burst did not open an active 4-rung burst");
    expect(duct_pmtu_drive_echo(&d, 1400u, t0 + 10u * ms) == pmtu_echo_none,
           "echo outside the current burst did not return none");
    expect(duct_pmtu_drive_echo(&d, d.rungs[3], t0 + 20u * ms) == pmtu_echo_rung,
           "first valid rung echo did not return pmtu_echo_rung");
    expect(duct_pmtu_drive_echo(&d, d.rungs[3], t0 + 25u * ms) == pmtu_echo_none,
           "duplicate rung echo did not return none");
    expect(duct_pmtu_drive_echo(&d, d.rungs[2], t0 + 30u * ms) == pmtu_echo_rung,
           "second rung echo did not leave burst open");
    expect(duct_pmtu_drive_echo(&d, d.rungs[0], t0 + 40u * ms) == pmtu_echo_closed,
           "ceiling echo did not close burst early");
    expect(d.burst_count == 0u && d.burst_acked == 0u && duct_pmtu_mtu(&d.search) == 1500u,
           "early close did not clear burst state or confirm ceiling");
    expect(duct_pmtu_drive_echo(&d, d.rungs[1], t0 + 50u * ms) == pmtu_echo_none,
           "echo after closed burst did not return none");
    return nullptr;
}

static const char *sc_rtt_hygiene(void)
{
    auto d = s_drive(duct_pmtu_base_min, 1500u, 100u * ms);
    d.search.good = 1232u;
    d.search.failed = 1433u;
    d.search.failed_strikes = 1u;

    uint8_t n = duct_pmtu_drive_burst(&d, t0);
    expect(n == 4u && d.rungs[3] == 1433u, "refine burst did not include failed rung");
    expect(duct_pmtu_drive_echo(&d, d.rungs[3], t0 + 250u * ms) == pmtu_echo_rung,
           "failed rung echo did not advance D1");
    expect(d.rtt == 100u * ms,
           "failed rung polluted rtt sample");
    expect(duct_pmtu_drive_echo(&d, d.rungs[2], t0 + 300u * ms) == pmtu_echo_rung,
           "second rung in D1 burst did not return rung");
    expect(d.rtt == 100u * ms,
           "second echo overwrote rtt");

    d.burst_count = 0u;
    d.burst_acked = 0u;
    n = duct_pmtu_drive_burst(&d, t0 + 1000u * ms);
    expect(n > 0u, "coarse burst after D1 returned empty");
    expect(duct_pmtu_drive_echo(&d, d.rungs[n - 1u], t0 + 1015u * ms) != pmtu_echo_none,
           "clean lower rung did not echo");
    expect(d.rtt == 15u * ms, "first clean non-failed rung did not update rtt");
    if (n > 1u) {
        duct_discard duct_pmtu_drive_echo(&d, d.rungs[0], t0 + 1200u * ms);
        expect(d.rtt == 15u * ms, "larger congested rung polluted rtt after first echo");
    }
    return nullptr;
}

static const char *(*g_client_check)(duct_session_t *);
static const char *(*g_server_check)(duct_session_t *);
static const char *g_client_err,
                  *g_server_err;
static _Atomic int g_done;

static const char *client_check(duct_session_t *s)
{
    duct_pmtu_drive_t d;
    duct_pmtu_drive_open(&d, s, duct_conn_id_primary, duct_pmtu_base_min, 1500u, 7u * ms);
    expect(d.search.base == duct_pmtu_base_min && d.search.max == 1500u
               && d.search.good == duct_pmtu_base_min && d.floor == duct_pmtu_base_min
               && d.rtt == 7u * ms && d.burst_count == 0u,
           "a search over a connected leg does not open at the bounds it was given");
    expect(duct_pmtu_drive_settle(&d, s, duct_conn_id_primary) == false && d.burst_count == 0u,
           "settle with no active burst changed search state");

    duct_discard duct_pmtu_drive_burst(&d, t0);
    expect(duct_pmtu_drive_echo(&d, 1232u, t0 + 5u * ms) == pmtu_echo_rung,
           "floor rung echo failed");
    bool done = duct_pmtu_drive_settle(&d, s, duct_conn_id_primary);
    expect(!done && d.search.failed == 1366u && d.search.failed_strikes == 1u && !d.burst_count,
           "first settle did not bracket failed rung with strike");

    for (unsigned b = 0u; b < 3u && !done; ++b) {
        expect(duct_pmtu_drive_burst(&d, t0 + (uint64_t)(b + 1u) * 100u * ms) > 0u,
               "refine burst stopped early");
        done = duct_pmtu_drive_settle(&d, s, duct_conn_id_primary);
    }
    expect(done && duct_pmtu_mtu(&d.search) == duct_pmtu_base_min,
           "silent drops did not settle search at floor");
    return nullptr;
}

static const char *server_check(duct_session_t *s)
{
    duct_pmtu_drive_t d;
    duct_pmtu_drive_open(&d, s, duct_conn_id_primary, duct_pmtu_base_min, 9000u, 0u);
    expect(d.search.max == 1500u, "a leg with no kernel figure does not search up to the default");
    duct_pmtu_drive_open(&d, s, duct_conn_id_primary, duct_pmtu_base_min, 1400u, 0u);
    expect(d.search.max == 1400u, "a ceiling under the default is raised to it");
    expect(duct_pmtu_drive_burst(&d, t0) == 4u, "shared leg did not emit burst");
    expect(!duct_pmtu_drive_settle(&d, s, duct_conn_id_primary) && d.search.failed == 0u,
           "total blackout with no confirmed rungs falsely narrowed search");
    return nullptr;
}

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

static duct_result_t srv_on_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                                 [[maybe_unused]] void *user_ctx,
                                 [[maybe_unused]] duct_response_t *out,
                                 [[maybe_unused]] void *proto_state)
{
    g_server_err = g_server_check(s);
    duct_atomic_fetch(add, &g_done, 1, release);
    return rc_ok;
}

static duct_result_t on_frame([[maybe_unused]] duct_session_t *s,
                              [[maybe_unused]] duct_conn_id_t conn_id,
                              [[maybe_unused]] const duct_frame_t *frame,
                              [[maybe_unused]] duct_response_t *out,
                              [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

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

static const char *sc_loopback(void)
{
    g_client_check = client_check;
    g_server_check = server_check;
    return s_run("127.0.0.1", true, 2);
}

#ifdef __linux__

static const char *kernel_check(duct_session_t *s)
{
    uint16_t path = 0u;
    expect(duct_conn_path_mtu(s, duct_conn_id_primary, &path) == rc_ok && path == 1400u,
           "the kernel does not hold the interface's size for the leg");
    duct_pmtu_drive_t d;
    duct_pmtu_drive_open(&d, s, duct_conn_id_primary, duct_pmtu_base_min, 1500u, 0u);
    expect(d.search.max == 1400u && d.search.good == duct_pmtu_base_min,
           "a search is not cut to the kernel's figure");

    duct_pmtu_init(&d.search, duct_pmtu_base_min, 1500u);
    expect(duct_pmtu_drive_burst(&d, t0) > 0u, "burst failed");
    expect(!duct_pmtu_drive_settle(&d, s, duct_conn_id_primary),
           "cut below 1500 collapsed the search unexpectedly");
    expect(d.search.max == 1400u && d.search.good == duct_pmtu_base_min && d.search.base == duct_pmtu_base_min
               && !d.search.failed && !d.burst_count,
           "settle under kernel figure did not reopen the search under it");

    duct_pmtu_ack(&d.search, 1350u);
    duct_pmtu_init(&d.search, 1350u, 1500u);
    duct_discard duct_pmtu_drive_burst(&d, t0);
    expect(!duct_pmtu_drive_settle(&d, s, duct_conn_id_primary),
           "second kernel cut did not keep open range");
    expect(d.search.max == 1400u && d.search.good == 1350u && d.search.base == 1350u,
           "confirmed size under kernel figure was not kept");

    duct_pmtu_init(&d.search, duct_pmtu_base_min, 1500u);
    duct_pmtu_ack(&d.search, 1450u);
    duct_discard duct_pmtu_drive_burst(&d, t0);
    expect(!duct_pmtu_drive_settle(&d, s, duct_conn_id_primary),
           "cut below confirmed size collapsed range");
    expect(d.search.max == 1400u && d.search.good == duct_pmtu_base_min && d.search.base == duct_pmtu_base_min,
           "confirmed size over kernel figure did not fall back to floor");
    return nullptr;
}

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
        { "wait",            sc_wait },
        { "burst and close", sc_burst_and_close },
        { "rtt hygiene",     sc_rtt_hygiene },
        { "loopback",        sc_loopback },
#ifdef __linux__
        { "kernel",          sc_kernel },
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
