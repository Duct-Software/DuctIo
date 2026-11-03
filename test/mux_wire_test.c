/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file mux_wire_test.c
 * @brief The built-in multiplexed wires carry a stream id, so a FIN closes the
 * stream it names.
 *
 * fin_closes_slot is the case that fails on every other built-in: they leave
 * duct_frame_t::stream_id at zero, which duct_session_stream_close refuses, so
 * a FIN reaches on_frame as a signal and tears down nothing. Here a FIN on
 * stream 5 must close 5 and leave 7 alone.
 *
 * split_header drives the 8-byte header through the parser's replay at every
 * interior offset, and pauses again before the payload. The header grew from
 * four bytes, so a replay still skipping the old width shifts every frame after
 * it — and arrives intact in any single-read test.
 *
 * table_full holds the refusal contract: the 129th concurrent stream comes back
 * as an RST carrying stream_err_refused with rc_again at on_error, the conn
 * survives, and closing one stream admits the id that was refused. It ends on
 * the rule that keeps two engines from looping — an RST for a stream this side
 * never opened is answered with nothing at all.
 *
 * The datagram member spends five bytes where the stream member spends eight,
 * its length coming from the record prefix: dgram covers the round trip and
 * dgram_runt the two edges of that, a record too short to hold the header, and
 * one holding nothing else.
 */

#include "duct.h"
#include "duct_wire.h"

#include <stdatomic.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

#include "test_helpers.h"
#include "dgram_test_helpers.h"

duct_wire_t *duct_wire_create_mux(size_t max_frame);
duct_wire_t *duct_wire_create_mux_dgram(size_t max_dgram);

static constexpr size_t mux_hdr = 8u;
static constexpr size_t mux_dgram_hdr = 5u;

static uint16_t g_mux_port = 0;
static uint16_t g_mdg_port = 0;

static atomic_int g_seen_sid   = -1;
static atomic_int g_seen_flags = -1;
static atomic_int g_frames     = 0;
static atomic_int g_closed_sid = -1;
static atomic_int g_closes     = 0;
static atomic_int g_error_rc   = -1;

static void s_reset(void)
{
    duct_atomic_store(&g_seen_sid, -1, release);
    duct_atomic_store(&g_seen_flags, -1, release);
    duct_atomic_store(&g_frames, 0, release);
    duct_atomic_store(&g_closed_sid, -1, release);
    duct_atomic_store(&g_closes, 0, release);
    duct_atomic_store(&g_error_rc, -1, release);
}

static duct_result_t
on_error([[maybe_unused]] duct_session_t *s, duct_result_t error,
         [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_error_rc, (int)error, release);
    return rc_ok;
}

static void s_put_mux(uint8_t h[mux_hdr], uint32_t sid, uint32_t len, uint8_t flags)
{
    h[0] = flags;
    h[1] = (uint8_t)(len >> 16u); h[2] = (uint8_t)(len >> 8u); h[3] = (uint8_t)(len);
    h[4] = (uint8_t)(sid >> 24u); h[5] = (uint8_t)(sid >> 16u);
    h[6] = (uint8_t)(sid >>  8u); h[7] = (uint8_t)(sid);
}

static int s_send_mux(duct_sock_t fd, uint32_t sid, const void *data, size_t len,
                      uint8_t flags, size_t split_at, unsigned pause_ms)
{
    uint8_t h[mux_hdr];
    s_put_mux(h, sid, (uint32_t)len, flags);
    size_t first = split_at ? split_at : mux_hdr;
    if (send(fd, (const char *)h, (int)first, 0) != (int)first)
        return -1;
    if (first < mux_hdr) {
        if (pause_ms)
            th_sleep_ms(pause_ms);
        size_t rest = mux_hdr - first;
        if (send(fd, (const char *)h + first, (int)rest, 0) != (int)rest)
            return -1;
    }
    if (len == 0u)
        return 0;
    if (pause_ms)
        th_sleep_ms(pause_ms);
    return send(fd, (const char *)data, (int)len, 0) == (int)len ? 0 : -1;
}

static int64_t s_recv_mux(duct_sock_t fd, char *buf, size_t bufsize,
                          uint32_t *out_sid, uint8_t *out_flags)
{
    uint8_t h[mux_hdr] = {};
    if (th_read_exact(fd, h, sizeof h) != 0)
        return -1;
    uint32_t len = ((uint32_t)h[1] << 16u) | ((uint32_t)h[2] << 8u) | (uint32_t)h[3];
    if (len > bufsize || th_read_exact(fd, buf, len) != 0)
        return -1;
    if (out_sid)
        *out_sid = ((uint32_t)h[4] << 24u) | ((uint32_t)h[5] << 16u)
                 | ((uint32_t)h[6] <<  8u) |  (uint32_t)h[7];
    if (out_flags)
        *out_flags = h[0];
    return (int64_t)len;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t cid,
         const duct_frame_t *frame, duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_seen_sid, (int)frame->stream_id, release);
    duct_atomic_store(&g_seen_flags, (int)frame->flags, release);
    duct_atomic_fetch(add, &g_frames, 1, relaxed);
    duct_response_echo(out, frame);
    return rc_ok;
}

static void
on_stream_close([[maybe_unused]] duct_session_t *s, duct_stream_id_t stream_id,
                [[maybe_unused]] duct_close_reason_t reason,
                [[maybe_unused]] void *stream_state)
{
    duct_atomic_store(&g_closed_sid, (int)stream_id, release);
    duct_atomic_fetch(add, &g_closes, 1, relaxed);
}

static int s_report(const char *name, const char *err)
{
    printf("mux_wire: %s: %s%s\n", name, err ? "FAIL: " : "OK", err ? err : "");
    return err == nullptr;
}

static const char *sc_roundtrip(uint32_t sid, duct_frame_flags_t sent)
{
    s_reset();
    auto fd = th_connect(g_mux_port);
    if (fd == duct_sock_bad) return "connect failed";

    static const char m[] = "mux-payload";
    const char *err = nullptr;
    char buf[64] = {};
    uint32_t back_sid = 0u;
    uint8_t back_flags = 0xffu;

    if (s_send_mux(fd, sid, m, sizeof m - 1u, (uint8_t)sent, 0u, 0u) != 0)
        err = "send failed";
    else if (s_recv_mux(fd, buf, sizeof buf, &back_sid, &back_flags)
                 != (int64_t)(sizeof m - 1u)
             || memcmp(buf, m, sizeof m - 1u) != 0)
        err = "echo lost or corrupted";
    else if (duct_atomic_load(&g_frames, acquire) != 1)
        err = "inbound: the frame did not arrive exactly once";
    else if ((uint32_t)duct_atomic_load(&g_seen_sid, acquire) != sid)
        err = "inbound: on_frame saw a stream id other than the one sent";
    else if (duct_atomic_load(&g_seen_flags, acquire) != (int)sent)
        err = "inbound: on_frame saw flags other than the ones sent";
    else if (back_sid != sid)
        err = "outbound: the echoed stream id differs from the one sent";
    else if (back_flags != (uint8_t)sent)
        err = "outbound: the echoed flags differ from the ones sent";

    duct_sock_close(fd);
    return err;
}

static const char *sc_split_header(size_t at)
{
    s_reset();
    auto fd = th_connect(g_mux_port);
    if (fd == duct_sock_bad) return "connect failed";

    static const char m[] = "split";
    const char *err = nullptr;
    char buf[64] = {};
    uint32_t back_sid = 0u;

    if (s_send_mux(fd, 9u, m, sizeof m - 1u, 0u, at, 40u) != 0)
        err = "send failed";
    else if (s_recv_mux(fd, buf, sizeof buf, &back_sid, nullptr)
                 != (int64_t)(sizeof m - 1u)
             || memcmp(buf, m, sizeof m - 1u) != 0)
        err = "a header split across reads desynced the parse";
    else if (back_sid != 9u)
        err = "a header split across reads lost the stream id";

    duct_sock_close(fd);
    return err;
}

static const char *sc_fin_closes_slot(void)
{
    s_reset();
    auto fd = th_connect(g_mux_port);
    if (fd == duct_sock_bad) return "connect failed";

    const char *err = nullptr;
    char buf[64] = {};
    int before = 0;

    if (s_send_mux(fd, 5u, "a", 1u, 0u, 0u, 0u) != 0
        || s_recv_mux(fd, buf, sizeof buf, nullptr, nullptr) != 1)
        err = "stream 5 did not open";
    else if (s_send_mux(fd, 7u, "b", 1u, 0u, 0u, 0u) != 0
             || s_recv_mux(fd, buf, sizeof buf, nullptr, nullptr) != 1)
        err = "stream 7 did not open";
    else if (before = duct_atomic_load(&g_closes, acquire),
             s_send_mux(fd, 5u, "c", 1u, (uint8_t)fl_frame_fin, 0u, 0u) != 0)
        err = "FIN send failed";
    else if (!th_wait_int(&g_closes, before + 1, 3000u))
        err = "a FIN naming stream 5 closed nothing";
    else if (duct_atomic_load(&g_closed_sid, acquire) != 5)
        err = "the FIN closed a stream other than the one it named";
    else {
        th_sleep_ms(200u);
        if (duct_atomic_load(&g_closes, acquire) != before + 1)
            err = "a FIN on one stream closed another";
    }

    duct_sock_close(fd);
    return err;
}

static const char *sc_table_full(void)
{
    s_reset();
    auto fd = th_connect(g_mux_port);
    if (fd == duct_sock_bad) return "connect failed";

    const char *err = nullptr;
    char buf[64] = {};
    uint32_t back_sid = 0u;
    uint8_t back_flags = 0u;
    int closes_before = 0;
    int64_t got = 0;
    duct_stream_id_t over = (duct_stream_id_t)duct_session_max_streams + 1u;

    for (duct_stream_id_t sid = 1u; sid <= duct_session_max_streams; ++sid) {
        if (s_send_mux(fd, sid, "x", 1u, 0u, 0u, 0u) != 0
            || s_recv_mux(fd, buf, sizeof buf, nullptr, nullptr) != 1) {
            err = "filling the stream table stalled before it was full";
            goto out;
        }
    }
    if (s_send_mux(fd, over, "x", 1u, 0u, 0u, 0u) != 0) {
        err = "overflow send failed";
        goto out;
    }
    if (s_recv_mux(fd, buf, sizeof buf, &back_sid, &back_flags) != 4) {
        err = "the refused stream got no RST carrying a reason";
        goto out;
    }
    if (back_sid != over)
        err = "the RST named a stream other than the refused one";
    else if (!duct_has((duct_frame_flags_t)back_flags, fl_frame_rst))
        err = "the refusal frame carried no fl_frame_rst";
    else if (((uint32_t)(uint8_t)buf[3]) != (uint32_t)stream_err_refused)
        err = "the RST's reason was not stream_err_refused";
    else if (!th_wait_int(&g_error_rc, (int)rc_again, 3000u))
        err = duct_atomic_load(&g_error_rc, acquire) == (int)rc_no_memory
            ? "a full stream table still reports rc_no_memory"
            : "a full stream table did not report rc_again";
    else if (closes_before = duct_atomic_load(&g_closes, acquire),
             s_send_mux(fd, 1u, "y", 1u, (uint8_t)fl_frame_fin, 0u, 0u) != 0)
        err = "FIN send failed";
    else if (s_recv_mux(fd, buf, sizeof buf, &back_sid, &back_flags) != 1)
        err = "the FIN frame was not echoed";
    else if (back_sid != 1u)
        err = "the FIN echo came back under a different id";
    else if (!th_wait_int(&g_closes, closes_before + 1, 3000u))
        err = "the FIN did not free its slot";
    else if (duct_atomic_load(&g_closed_sid, acquire) != 1)
        err = "the FIN freed a slot other than the one it named";
    else if (s_send_mux(fd, over, "z", 1u, 0u, 0u, 0u) != 0
             || s_recv_mux(fd, buf, sizeof buf, &back_sid, &back_flags) != 1)
        err = "the freed slot did not admit the stream that was refused";
    else if (back_sid != over)
        err = "the retried stream came back under a different id";
    else if (s_send_mux(fd, over + 70u, nullptr, 0u, (uint8_t)fl_frame_rst, 0u, 0u) != 0)
        err = "ghost RST send failed";
    else if (s_send_mux(fd, 2u, "q", 1u, 0u, 0u, 0u) != 0)
        err = "probe send failed";
    else if ((got = s_recv_mux(fd, buf, sizeof buf, &back_sid, nullptr)) < 0)
        err = "the conn stopped serving after an RST on an unopened stream";
    else if (got != 1 || back_sid != 2u)
        err = "an RST on an unopened stream was answered with a frame";

out:
    duct_sock_close(fd);
    return err;
}

static const char *sc_dgram(void)
{
    s_reset();
    duct_sock_t fd = uc_connect(g_mdg_port);
    if (fd == duct_sock_bad) return "connect failed";

    const char *err = nullptr;
    uint8_t sent[mux_dgram_hdr + 4u] = {
        (uint8_t)fl_frame_fin, 0u, 0u, 0u, 42u, 'p', 'i', 'n', 'g',
    };
    char back[64] = {};

    if (uc_send(fd, sent, sizeof sent) != 0)
        err = "send failed";
    else {
        ssize_t got = uc_recv(fd, back, sizeof back);
        if (got != (ssize_t)sizeof sent)
            err = "echo lost across a mux datagram";
        else if (memcmp(back, sent, sizeof sent) != 0)
            err = "the mux datagram header or payload changed in flight";
        else if (duct_atomic_load(&g_seen_sid, acquire) != 42)
            err = "inbound: on_frame did not see the datagram's stream id";
        else if (duct_atomic_load(&g_seen_flags, acquire) != (int)fl_frame_fin)
            err = "inbound: on_frame did not see the datagram's flags";
    }

    close(fd);
    return err;
}

static const char *sc_dgram_runt(void)
{
    s_reset();
    duct_sock_t fd = uc_connect(g_mdg_port);
    if (fd == duct_sock_bad) return "connect failed";

    const char *err = nullptr;
    uint8_t runt[mux_dgram_hdr - 1u] = { (uint8_t)fl_frame_fin, 0u, 0u, 0u };
    uint8_t bare[mux_dgram_hdr] = { (uint8_t)fl_frame_fin, 0u, 0u, 0u, 8u };
    uint8_t good[mux_dgram_hdr + 2u] = { 0u, 0u, 0u, 0u, 3u, 'h', 'i' };
    char back[64] = {};

    if (uc_send(fd, runt, sizeof runt) != 0)
        err = "runt send failed";
    else if (uc_send(fd, bare, sizeof bare) != 0)
        err = "bare header send failed";
    else if (!th_wait_int(&g_frames, 1, 2000u))
        err = "a header-only datagram did not arrive as an empty frame";
    else if (duct_atomic_load(&g_seen_sid, acquire) != 8)
        err = "a header-only datagram lost its stream id";
    else if (duct_atomic_load(&g_seen_flags, acquire) != (int)fl_frame_fin)
        err = "a header-only datagram lost its flags";
    else if (uc_recv_none(fd, 200) != 0)
        err = "an empty frame produced a response";
    else if (uc_send(fd, good, sizeof good) != 0)
        err = "follow-up send failed";
    else if (uc_recv(fd, back, sizeof back) != (ssize_t)sizeof good)
        err = "a datagram too short for the header cost the conn, not itself";
    else if (duct_atomic_load(&g_seen_sid, acquire) != 3)
        err = "the follow-up datagram's stream id was lost";
    else if (duct_atomic_load(&g_frames, acquire) != 2)
        err = "the runt datagram reached on_frame";

    close(fd);
    return err;
}

static const char *sc_bounds(void)
{
    auto too_big = duct_wire_create_mux(0x1000000u);
    if (too_big) {
        duct_wire_destroy(too_big);
        return "a max_frame past the 24-bit length field was accepted";
    }
    auto ok = duct_wire_create_mux(0xFFFFFFu);
    if (!ok)
        return "the largest encodable max_frame was refused";
    duct_wire_destroy(ok);

    auto no_room = duct_wire_create_mux_dgram(mux_dgram_hdr);
    if (no_room) {
        duct_wire_destroy(no_room);
        return "a max_dgram leaving no room for the header was accepted";
    }
    return nullptr;
}


int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) { fprintf(stderr, "mux_wire: io create failed\n"); return 1; }

    auto mux_wire = duct_wire_create_mux(0u);
    auto mdg_wire = duct_wire_create_mux_dgram(0u);
    duct_proto_t *mux = nullptr, *mdg = nullptr;
    if (mux_wire && mdg_wire) {
        mux = duct_proto_create(&(duct_proto_cfg_t){
            .name = "mux", .wire = mux_wire, .flags = fl_proto_multiplexed,
            .on_frame = on_frame, .on_stream_close = on_stream_close,
            .on_error = on_error,
        });
        mdg = duct_proto_create(&(duct_proto_cfg_t){
            .name = "mux-dgram", .wire = mdg_wire, .flags = fl_proto_multiplexed,
            .on_frame = on_frame, .on_stream_close = on_stream_close,
            .on_error = on_error,
            .max_response = 65535u,
        });
    }
    if (mux) mux->owned_wire = mux_wire; else duct_wire_destroy(mux_wire);
    if (mdg) mdg->owned_wire = mdg_wire; else duct_wire_destroy(mdg_wire);
    if (!mux || !mdg) {
        fprintf(stderr, "mux_wire: proto create failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(mux); duct_proto_destroy(mdg);
        return 1;
    }

    const char *err = nullptr;
    pthread_t th;
    bool running = false;
    int pass = 1;

    pass &= s_report("bounds", sc_bounds());

    if (duct_io_listen(io, "127.0.0.1", &g_mux_port, mux) != rc_ok) {
        err = "stream listen failed";
        goto done;
    }
    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
            .addr = "127.0.0.1", .n_protos = 1,
            .protos = (const duct_proto_t *[]){ mdg },
        }, &g_mdg_port, nullptr, 0u, nullptr) != rc_ok) {
        err = "mux datagram bind failed";
        goto done;
    }
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        err = "engine thread create failed";
        goto done;
    }
    running = true;

    pass &= s_report("roundtrip_plain", sc_roundtrip(1u, fl_frame_none));
    pass &= s_report("roundtrip_high_id", sc_roundtrip(0xFFFFFFFFu, fl_frame_none));
    pass &= s_report("roundtrip_flags",
                     sc_roundtrip(3u, duct_or(fl_frame_fin, fl_frame_rst)));
    pass &= s_report("fin_closes_slot", sc_fin_closes_slot());
    for (size_t at = 1u; at < mux_hdr; ++at) {
        char name[32];
        snprintf(name, sizeof name, "split_header_%zu", at);
        pass &= s_report(name, sc_split_header(at));
    }
    pass &= s_report("table_full", sc_table_full());
    pass &= s_report("dgram", sc_dgram());
    pass &= s_report("dgram_runt", sc_dgram_runt());
    if (!pass)
        err = "one or more cases failed";

done:
    if (running) {
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(mux);
    duct_proto_destroy(mdg);

    if (err) {
        fprintf(stderr, "mux_wire: %s\n", err);
        return 1;
    }
    printf("mux_wire: OK (stream ids cross both built-in mux wires; "
           "a FIN closes the stream it names)\n");
    return 0;
}
