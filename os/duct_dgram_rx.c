/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_dgram_rx.c
 *  @brief The datagram read loops every readiness-driven backend runs: a
 *  listener's drain and a peer conn's batched read.
 */

#include "duct_events.h"
#include "duct_listener.h"
#include "duct_wire.h"
#include "duct_xport.h"

/* Every pass releases whatever slots it still holds. A datagram routed by
 * reference already moved its slot to the lane and is skipped there; an unknown
 * peer, a full lane and a parse yielding no frame all leave theirs held, and
 * skipping the release retires one slot per such datagram.
 *
 * Fewer datagrams than buffers offered means the socket ran dry. A dry pool
 * ends the drain before any read, the listener parked by
 * duct_io_dgram_rx_stall. */
void duct_io_dgram_rx_drain(duct_listener_t *listener)
{
    uint8_t     sink = 0u;
    duct_view_u8  bufs[duct_dgram_rx_batch];
    duct_peer_t peers[duct_dgram_rx_batch];
    uint32_t    lens[duct_dgram_rx_batch];
    uint32_t    segs[duct_dgram_rx_batch];

    for (unsigned pass = 0u; pass < duct_dgram_rx_max_passes; ++pass) {
        uint32_t want = duct_io_rx_slots_acquire(listener, bufs);
        if (!want) {
            if (duct_io_dgram_rx_stall(listener))
                return;
            want = duct_io_rx_slots_acquire(listener, bufs);
        }
        if (!want) {
            /* A pool with no slots, or one a held lane pins: one datagram into
             * the io thread's scratch block, which the route then copies.
             * Where the block cannot be made the read still happens, into one
             * byte: the datagram is reported truncated and dropped, where a
             * return ahead of the read leaves it queued and the level-triggered
             * listener re-notifies at once. */
            bufs[0] = duct_io_dgram_rx_scratch();
            if (!bufs[0].data)
                bufs[0] = (duct_view_u8){ .data = &sink, .size = sizeof sink };
            bufs[0].size = duct_min(bufs[0].size, duct_listener_dgram_span(listener));
            want = 1u;
        }

        uint32_t got = 0u;
        auto rc = duct_xrecv_peers(listener->listen_fd, bufs, want,
                                   peers, lens, segs, &got);
        for (uint32_t i = 0u; i < got; ++i) {
            /* A truncated read holds no whole datagram: a coalesced one loses
             * every segment in the group, and a lone one loses its tail with
             * nothing on the wire saying so. */
            duct_do_if(lens[i] == duct_dgram_len_truncated, continue);
            duct_io_on_dgram(listener, &peers[i],
                             &(duct_view_u8){ .data = bufs[i].data, .size = lens[i] },
                             segs[i]);
        }
        duct_io_rx_slots_release();
        if (rc != rc_ok || got < want)
            return;
    }
}

/* Units sit one read_unit apart, a record header gap ahead of each span: the
 * stride duct_io_rx_commit_units and the parse walk the ring at. */
duct_result_t duct_io_dgram_rx_units(void *tag, const duct_io_xfer_t *r)
{
    duct_view_u8 bufs[duct_x_recv_batch_max];
    uint32_t   lens[duct_x_recv_batch_max],
               got = 0u;
    size_t stride = r->size + duct_dgram_record_hdr_size;
    for (uint32_t i = 0u; i < r->units; ++i)
        bufs[i] = (duct_view_u8){ .data = r->buf + (size_t)i * stride, .size = r->size };
    auto rc = duct_xrecv_peers(r->fd, bufs, r->units, nullptr, lens, nullptr, &got);
    if (rc != rc_ok)
        return rc;
    duct_io_rx_commit_units(tag, lens, got);
    return got < r->units ? rc_again : rc_ok;
}
