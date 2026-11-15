/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

#include "duct_pmtu.h"

void duct_pmtu_drive_open(duct_pmtu_drive_t *d, duct_session_t *s, duct_conn_id_t conn_id,
                          uint16_t base, uint16_t top, uint64_t rtt)
{
    uint16_t path = duct_pmtu_path_default;
    duct_discard duct_conn_path_mtu(s, conn_id, &path);
    *d = (duct_pmtu_drive_t){ .rtt = rtt };
    /* A ceiling under base is raised to it by duct_pmtu_init; store clamped floor after init. */
    duct_pmtu_init(&d->search, base, (uint16_t)duct_min(path, top));
    d->floor = d->search.base;
}

uint64_t duct_pmtu_drive_wait_ms(const duct_pmtu_drive_t *d)
{
    uint64_t wait = duct_max(duct_pmtu_rto_rtts * d->rtt, duct_pmtu_rto_min_ns);
    return duct_min(wait, duct_pmtu_rto_max_ns) / 1'000'000u;
}

uint8_t duct_pmtu_drive_burst(duct_pmtu_drive_t *d, uint64_t now)
{
    d->burst_count = duct_pmtu_burst(&d->search, d->rungs);
    d->burst_acked = 0u;
    d->burst_at = now;
    return d->burst_count;
}

duct_pmtu_echo_t duct_pmtu_drive_echo(duct_pmtu_drive_t *d, uint16_t wire, uint64_t now)
{
    for (uint8_t i = 0u; i < d->burst_count; ++i) {
        if (d->rungs[i] != wire)
            continue;
        uint8_t bit = (uint8_t)(1u << i);
        if (d->burst_acked & bit)
            return pmtu_echo_none;
        if (!d->burst_acked && now >= d->burst_at && wire != d->search.failed)
            d->rtt = now - d->burst_at;
        d->burst_acked |= bit;
        duct_pmtu_ack(&d->search, wire);
        uint8_t full = (uint8_t)((1u << d->burst_count) - 1u);
        if (d->burst_acked != full && !duct_pmtu_done(&d->search))
            return pmtu_echo_rung;
        d->burst_count = 0u;
        d->burst_acked = 0u;
        return pmtu_echo_closed;
    }
    return pmtu_echo_none;
}

bool duct_pmtu_drive_settle(duct_pmtu_drive_t *d, duct_session_t *s, duct_conn_id_t conn_id)
{
    if (!d->burst_count)
        return duct_pmtu_done(&d->search);
    uint16_t path = 0u;
    duct_result_t rc = duct_conn_path_mtu(s, conn_id, &path);
    if (rc == rc_ok && path > 0u && path < d->search.max) {
        uint16_t good = duct_pmtu_mtu(&d->search);
        duct_pmtu_init(&d->search, path >= good ? good : d->floor, path);
        d->burst_count = 0u;
        d->burst_acked = 0u;
        return duct_pmtu_done(&d->search);
    }
    uint16_t smallest_silent = 0u;
    for (uint8_t i = 0u; i < d->burst_count; ++i) {
        uint8_t bit = (uint8_t)(1u << i);
        if (!(d->burst_acked & bit) && d->rungs[i] > d->search.good
            && (!smallest_silent || d->rungs[i] < smallest_silent))
            smallest_silent = d->rungs[i];
    }
    if (smallest_silent && (d->burst_acked || d->search.failed)) {
        bool lower_echo = false;
        for (uint8_t i = 0u; i < d->burst_count; ++i)
            if ((d->burst_acked & (uint8_t)(1u << i)) && d->rungs[i] < smallest_silent)
                lower_echo = true;
        if (!d->search.failed || smallest_silent < d->search.failed) {
            d->search.failed = smallest_silent;
            d->search.failed_strikes = lower_echo ? 1u : 0u;
        } else if (smallest_silent == d->search.failed && lower_echo
                   && d->search.failed_strikes < duct_pmtu_fail_strikes_max)
            ++d->search.failed_strikes;
    }
    d->burst_count = 0u;
    d->burst_acked = 0u;
    return duct_pmtu_done(&d->search);
}
