/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file redial_test.c
 *  @brief The redial curve, an attempt's deadline per transport and the two
 *  response fills.
 *
 *  @c sc_curve expects 250 ms doubled five times and then level, the attempt
 *  count held at the cap, and a reset to start the curve over. @c sc_deadline
 *  expects a datagram attempt's deadline to run 1, 2, 4 s and level at 4 s
 *  with the attempts counted, and a stream attempt's to stay 4 s. @c sc_fill
 *  expects the redial response to hold the next delay and the caller's token
 *  and the dial response the kind, leg, address and prefix, each touching no
 *  other control field.
 */

#include "duct.h"
#include "duct_redial.h"

#include <stdio.h>
#include <string.h>

/** @brief Return @p msg from the calling check when @p cond fails. */
#define expect(cond, msg) do { if (!(cond)) return msg; } while (0)

/** @brief Walk the delays through the cap and a reset.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_curve(void)
{
    static const uint64_t want[] = { 250u, 500u, 1000u, 2000u, 4000u, 8000u, 8000u, 8000u };
    duct_redial_t r = { .xport = x_udp_peer };
    for (size_t i = 0u; i < sizeof want / sizeof want[0]; ++i)
        expect(duct_redial_next_ms(&r) == want[i], "the delay is not 250 ms doubled to the cap, then level");
    expect(r.attempts == duct_redial_cap, "the attempt count passes the cap");
    duct_redial_reset(&r);
    expect(r.attempts == 0u && duct_redial_next_ms(&r) == duct_redial_base_ms,
           "a reset does not start the curve over");
    expect(r.xport == x_udp_peer, "a reset forgets the transport of the sequence");
    return nullptr;
}

/** @brief Read the deadline of each attempt count on both transports.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_deadline(void)
{
    static const uint64_t dgram[] = { 1000u, 2000u, 4000u, 4000u, 4000u, 4000u };
    for (uint8_t i = 0u; i < sizeof dgram / sizeof dgram[0]; ++i) {
        duct_redial_t r = { .attempts = i, .xport = x_udp_peer };
        expect(duct_redial_deadline_ms(&r) == dgram[i],
               "a datagram attempt's deadline is not 1 s doubled per attempt to 4 s");
        r.xport = x_tcp;
        expect(duct_redial_deadline_ms(&r) == 4000u,
               "a stream attempt's deadline is not 4 s at every attempt");
    }
    return nullptr;
}

/** @brief Fill a response with a redial and with a dial and read back what was set.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_fill(void)
{
    static const char addr[] = "host.example:4000";
    static uint8_t prefix[3] = { 1, 2, 3 };
    duct_redial_t r = { .attempts = 2u };
    duct_response_t out = {};
    duct_response_redial(&out, &r, 7u);
    expect(out.control.timer.delay_ms == 1000u && out.control.timer.arg == 7u && r.attempts == 3u,
           "a redial response does not hold the next delay and the caller's token");
    expect(!out.control.timer.interval_ms && !out.control.timer.key && !out.control.open_leg.kind,
           "a redial response sets more than its delay and token");
    out = (duct_response_t){};
    duct_response_dial(&out, leg_kind_connect_dgram, 3u, addr,
                       duct_view(duct_view_u8, prefix, sizeof prefix));
    auto leg = &out.control.open_leg;
    expect(leg->kind == leg_kind_connect_dgram && leg->conn_id == 3u && leg->connect_addr == addr
               && leg->tx_prefix.data == prefix && leg->tx_prefix.size == sizeof prefix,
           "a dial response does not hold the kind, leg, address and prefix it was given");
    expect(!out.control.timer.delay_ms && !leg->tcp_congestion,
           "a dial response sets more than the leg");
    return nullptr;
}

int main(void)
{
    static const struct { const char *name; const char *(*fn)(void); } cases[] = {
        { "curve",    sc_curve },
        { "deadline", sc_deadline },
        { "fill",     sc_fill },
    };
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        auto err = cases[i].fn();
        if (err) {
            fprintf(stderr, "redial: %s: %s\n", cases[i].name, err);
            return 1;
        }
    }
    printf("redial: OK\n");
    return 0;
}
