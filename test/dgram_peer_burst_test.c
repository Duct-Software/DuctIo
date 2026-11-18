/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file dgram_peer_burst_test.c
 * @brief A datagram storm staged on one conn leaves whole behind a peer that
 * reads nothing until the storm is over.
 *
 * 200 invocations each answer a 1400-byte payload back to back, one datagram
 * each. The raw peer's receive buffer is cut to 64 KB first, so the socket
 * refuses mid-storm the way a congested radio interface refuses: the ring
 * holds the tail, the io arms write interest and waits. The peer then drains
 * everything, the writable edge fires, and the drain must deliver every staged
 * datagram — none parked short, none dropped, none lost behind the refusal.
 * The engine's TX counters print alongside the verdict.
 */

#include "duct.h"
#include "test_helpers.h"
#include "dgram_test_helpers.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static constexpr unsigned wait_ms  = 5000u;
static constexpr size_t   ring_cap = (size_t)1u << 20u;
static constexpr size_t   payload  = 1400u;
static constexpr unsigned storm_n  = 200u;

static uint8_t       g_payload[payload];
static atomic_int    g_opened = 0;
static atomic_int    g_errors = 0;
static duct_handle_t g_tok;

static duct_result_t
cli_on_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    g_tok = tok;
    duct_atomic_store(&g_opened, 1, release);
    return rc_ok;
}

static duct_result_t
cli_on_error([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_result_t err,
             [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    atomic_fetch_add_explicit(&g_errors, 1, memory_order_release);
    return rc_ok;
}

static duct_result_t
cli_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             [[maybe_unused]] const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

/** @brief One storm step: a 1400-byte response on the transport leg. */
static duct_result_t
storm_fn([[maybe_unused]] duct_session_t *s, duct_response_t *out,
         [[maybe_unused]] void *ctx)
{
    duct_response_same(out, duct_view(duct_view_u8, g_payload, payload), fl_send_static, 0);
    return rc_ok;
}

/** @brief Drain @p fd without blocking, counting whole datagrams. */
static long storm_count(duct_sock_t fd)
{
    static uint8_t buf[4096];
    long n = 0;
    for (;;) {
        ssize_t got = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
        if (got < 0)
            break;
        ++n;
    }
    return n;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) {
        fprintf(stderr, "dgram_peer_burst: io create failed\n");
        return 1;
    }
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "dgram-peer-burst", .wire = wire,
        .on_session_open = cli_on_open, .on_error = cli_on_error,
        .on_frame = cli_on_frame,
        .max_response = 2048u, .tx_olb_cap = ring_cap,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!proto) {
        duct_engine_destroy(io);
        fprintf(stderr, "dgram_peer_burst: proto create failed\n");
        return 1;
    }

    const char *err = nullptr;
    duct_sock_t fd = duct_sock_bad;
    pthread_t th;
    long received = 0;

    /* The raw storm peer: rcvbuf 64 KB so the loopback refuses mid-storm. */
    uint16_t port = 0u;
    fd = uc_bind(&port);
    if (fd == duct_sock_bad) {
        err = "raw socket failed";
        goto done;
    }
    {
        int rcvbuf = 64 * 1024;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);
        char addr[64];
        snprintf(addr, sizeof addr, "%s:%u", host, (unsigned)port);
        if (pthread_create(&th, nullptr, th_run, io) != 0) {
            err = "thread create failed";
            goto done;
        }
        if (duct_io_connect(io, addr, proto, nullptr, x_udp_peer) != rc_ok) {
            err = "connect failed";
            goto done;
        }
        if (!th_wait_int(&g_opened, 1, wait_ms)) {
            err = "the session never opened";
            goto done;
        }

        /* The storm: every invocation stages one datagram back to back. */
        for (unsigned i = 0u; i < storm_n; ++i)
            if (duct_session_invoke(io, g_tok, storm_fn, nullptr) != rc_ok) {
                err = "an invocation was refused";
                goto done;
            }

        /* Hold off reading: the peer's rcvbuf fills, the socket refuses, the
         * ring holds the tail behind write interest. */
        th_sleep_ms(300u);

        received += storm_count(fd);
        th_sleep_ms(1000u);
        received += storm_count(fd);
        th_sleep_ms(1000u);
        received += storm_count(fd);

        duct_rt_stats_t stats;
        if (duct_engine_stats(io, &stats))
            printf("dgram_peer_burst: tx_drain_posts=%llu tx_drain_deduped=%llu "
                   "retry_saved=%llu drops rx=%llu tx=%llu errors=%d\n",
                   (unsigned long long)stats.tx_drain_posts,
                   (unsigned long long)stats.tx_drain_deduped,
                   (unsigned long long)stats.retry_saved,
                   (unsigned long long)stats.dgram_shared_rx_drop,
                   (unsigned long long)stats.dgram_shared_tx_drop,
                   duct_atomic_load(&g_errors, acquire));

        if (received != (long)storm_n) {
            static char msg[128];
            snprintf(msg, sizeof msg,
                     "the storm left %ld of %u datagrams behind the refusal",
                     received, storm_n);
            err = msg;
        }
    }

done:
    if (fd != duct_sock_bad)
        duct_sock_close(fd);
    duct_engine_stop(io);
    pthread_join(th, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);

    if (err) {
        fprintf(stderr, "dgram_peer_burst: %s\n", err);
        return 1;
    }
    printf("dgram_peer_burst: OK (%u datagrams left whole behind a mid-storm refusal)\n",
           storm_n);
    return 0;
}
