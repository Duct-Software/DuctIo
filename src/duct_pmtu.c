/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

#include "duct_pmtu.h"

void duct_pmtu_drive_open(duct_pmtu_drive_t *d, duct_session_t *s, duct_conn_id_t conn_id,
                          uint16_t base, uint16_t top, uint64_t rtt)
{
    uint16_t path = duct_pmtu_path_default;
    duct_discard duct_conn_path_mtu(s, conn_id, &path);
    *d = (duct_pmtu_drive_t){ .floor = base, .rtt = rtt };
    /* A ceiling under base is raised to it by duct_pmtu_init. */
    duct_pmtu_init(&d->search, base, (uint16_t)duct_min(path, top));
}

uint64_t duct_pmtu_drive_wait_ms(const duct_pmtu_drive_t *d, unsigned tries)
{
    uint64_t wait = duct_max(duct_pmtu_rto_rtts * d->rtt, duct_pmtu_rto_min_ns);
    for (; tries && wait < duct_pmtu_rto_max_ns; --tries)
        wait <<= 1u;
    return duct_min(wait, duct_pmtu_rto_max_ns) / 1'000'000u;
}

uint64_t duct_pmtu_drive_sent(duct_pmtu_drive_t *d, uint16_t wire, uint64_t now)
{
    d->probing = wire;
    d->probe_at = now;
    return duct_pmtu_drive_wait_ms(d, d->search.unanswered);
}

bool duct_pmtu_drive_echo(duct_pmtu_drive_t *d, uint16_t wire, uint64_t now)
{
    if (!d->probing || wire != d->probing)
        return false;
    if (!d->search.unanswered)
        d->rtt = now - d->probe_at;
    duct_pmtu_ack(&d->search, d->probing);
    d->probing = 0u;
    return true;
}

bool duct_pmtu_drive_lost(duct_pmtu_drive_t *d, duct_session_t *s, duct_conn_id_t conn_id)
{
    uint16_t path = 0u;
    duct_result_t rc = duct_conn_path_mtu(s, conn_id, &path);
    bool moved = rc == rc_ok && path < d->probing;
    if (moved) {
        uint16_t good = duct_pmtu_mtu(&d->search);
        /* A reopened search takes the confirmed size as its base, so the first
         * base survives in floor for the next fall. */
        duct_pmtu_init(&d->search, path >= good ? good : d->floor, path);
    } else
        moved = duct_pmtu_lost(&d->search, d->probing);
    d->probing = 0u;
    return moved;
}
