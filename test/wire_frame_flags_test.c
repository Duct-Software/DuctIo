/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file wire_frame_flags_test.c
 * @brief Frame flags reach the peer, or the protocol hears why they did not.
 *
 * A length-prefix frame keeps its flags in the header's top bits, so the
 * round-trip cases send each combination and require the same bits back, in
 * on_frame and on the echo, with on_error quiet. fl_frame_none is the control,
 * failing any wire that hardcodes the flags. split_fin pauses between the
 * header and the payload, the only case reaching the parser's payload-partial
 * replay.
 *
 * The declarative stream ops cover the other producer, a control frame with no
 * payload of the protocol's own. An RST carries its four-byte
 * duct_stream_error_t, so standalone_rst proves a reason code crosses a wire
 * whose header has no spare bit. zero_count holds a header with no flags to a
 * bare length prefix, a length of zero staying the empty frame.
 *
 * A datagram has no length field to lend, so its flags cost a byte:
 * dgram_framed and dgram_framed_bare carry them with a payload and without one.
 * On the transparent wire dgram_reports requires an on_error for a FIN, and
 * dgram_data_fin a FIN's payload delivered without the flag.
 *
 * fl_frame_gso round-trips over length-prefix and the framed datagram wire. On
 * the transparent one dgram_gso requires the commit refused whole, an on_error
 * and nothing sent, and dgram_record_gso reads the flag off a vnet record
 * prefix through the parse. lp_bound holds max_frame under the 29 bits the
 * three flags leave. on_error keeps the first error since a reset: a refused
 * commit reports its own code ahead of the dispatcher's.
 *
 * sealed_inherits is one row per inner wire: whether the pair builds — a wire
 * leaning on the io thread's record prefix does not, no PDU carrying one — and
 * which capabilities the sealed wire carries.
 */

#include "duct.h"
#include "duct_wire.h"
#include "duct_dgram_rec.h"
#include "tls_engine_null.h"
#include "test_helpers.h"

#include <stdatomic.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

#include "dgram_test_helpers.h"

duct_wire_t *duct_wire_create_dgram_batch(size_t max_dgram, bool framed);
duct_wire_t *duct_wire_create_mux(size_t max_frame);
duct_wire_t *duct_wire_create_mux_dgram(size_t max_dgram);

static uint16_t g_lp_port = 0;
static uint16_t g_dg_port = 0;
static uint16_t g_dgf_port = 0;

static constexpr size_t sane_payload_max = 4096u;

static atomic_int g_seen_flags = -1;
static atomic_int g_frames     = 0;
static atomic_int g_bad_size   = 0;
static atomic_int g_error_rc   = -1;

static void s_reset(void)
{
    duct_atomic_store(&g_seen_flags, -1, release);
    duct_atomic_store(&g_frames, 0, release);
    duct_atomic_store(&g_bad_size, 0, release);
    duct_atomic_store(&g_error_rc, -1, release);
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t cid,
         const duct_frame_t *frame, duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_seen_flags, (int)frame->flags, release);
    duct_atomic_fetch(add, &g_frames, 1, relaxed);

    auto p = frame->payload;
    if (p.size > sane_payload_max) {
        duct_atomic_fetch(add, &g_bad_size, 1, relaxed);
        *out = (duct_response_t){ .control.stream_op_conn_id = duct_conn_id_same };
        return rc_ok;
    }
    if (p.size == 4u && memcmp(p.data, "sfin", 4u) == 0) {
        out->control.stream_op = stream_op_fin;
        out->control.stream_op_stream_id = frame->stream_id;
        return rc_ok;
    }
    if (p.size == 4u && memcmp(p.data, "srst", 4u) == 0) {
        out->control.stream_op = stream_op_reset;
        out->control.stream_op_stream_id = frame->stream_id;
        out->control.stream_op_error = stream_err_rejected;
        return rc_ok;
    }
    duct_response_echo(out, frame);
    if (p.size == 4u && memcmp(p.data, "dfin", 4u) == 0)
        out->frame_flags = duct_or(out->frame_flags, fl_frame_fin);
    if (p.size == 4u && memcmp(p.data, "dgso", 4u) == 0)
        out->frame_flags = duct_or(out->frame_flags, fl_frame_gso);
    return rc_ok;
}

static duct_result_t
on_error([[maybe_unused]] duct_session_t *s, duct_result_t error,
         [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    int none = -1;
    duct_discard duct_atomic_cas(strong, &g_error_rc, &none, (int)error, acq_rel, acquire);
    return rc_ok;
}

static int s_report(const char *name, const char *err)
{
    printf("wire_frame_flags: %s: %s%s\n", name, err ? "FAIL: " : "OK", err ? err : "");
    return err == nullptr;
}

static const char *sc_roundtrip(duct_frame_flags_t sent, unsigned split_pause_ms)
{
    s_reset();
    auto fd = th_connect(g_lp_port);
    if (fd == duct_sock_bad) return "connect failed";

    static const char m[] = "data-and-flags";
    const char *err = nullptr;
    char buf[64] = {};
    uint8_t back = 0xffu;

    if (th_send_flags(fd, m, sizeof m - 1u, (uint8_t)sent, split_pause_ms) != 0)
        err = "send failed";
    else if (th_recv_flags(fd, buf, sizeof buf, &back) != (int64_t)(sizeof m - 1u)
             || memcmp(buf, m, sizeof m - 1u) != 0)
        err = "echo lost or corrupted";
    else if (duct_atomic_load(&g_seen_flags, acquire) != (int)sent)
        err = "inbound: on_frame saw flags other than the ones sent";
    else if (back != (uint8_t)sent)
        err = "outbound: the echoed flags byte differs from the one sent";
    else if (duct_atomic_load(&g_error_rc, acquire) != -1)
        err = "a wire that carries the flags reported anyway";

    duct_sock_close(fd);
    return err;
}

static const char *sc_standalone(const char *op, duct_frame_flags_t want,
                                 duct_stream_error_t want_err, const char *what)
{
    s_reset();
    auto fd = th_connect(g_lp_port);
    if (fd == duct_sock_bad) return "connect failed";

    const char *err = nullptr;
    char buf[64] = {};
    uint8_t back = 0u;
    bool is_rst = duct_has(want, fl_frame_rst);
    int64_t want_len = is_rst ? 4 : 0;

    int64_t got = th_send(fd, op, 4u) != 0
                ? -1 : th_recv_flags(fd, buf, sizeof buf, &back);
    if (got < 0)
        err = "no control frame arrived";
    else if (got != want_len)
        err = is_rst ? "an RST arrived without its 4-byte reason code"
                     : "a FIN arrived carrying a payload";
    else if (!duct_has((duct_frame_flags_t)back, want))
        err = what;
    else if (is_rst) {
        uint32_t code = ((uint32_t)(uint8_t)buf[0] << 24u)
                      | ((uint32_t)(uint8_t)buf[1] << 16u)
                      | ((uint32_t)(uint8_t)buf[2] <<  8u)
                      |  (uint32_t)(uint8_t)buf[3];
        if (code != (uint32_t)want_err)
            err = "the RST's reason code did not survive the wire";
    }

    duct_sock_close(fd);
    return err;
}

static const char *sc_sealed_inherits(void)
{
    auto lp  = duct_wire_create_length_prefix(0u);
    auto dg  = duct_wire_create_dgram_batch(0u, false);
    auto dgf = duct_wire_create_dgram_batch(0u, true);
    auto mux = duct_wire_create_mux(0u);
    auto mdg = duct_wire_create_mux_dgram(0u);
    struct { duct_wire_t *inner; bool build, flags, ids; const char *what; } cases[] = {
        { lp,  true,  true,  false,
          "a sealed wire over length-prefix dropped fl_wire_frame_flags" },
        { mux, true,  true,  true,
          "a sealed wire over mux dropped a capability its inner wire has" },
        { nullptr, true, false, false,
          "a sealed wire with no inner wire claimed a capability" },
        { dgf, false, false, false,
          "a sealed wire accepted a framed dgram inner, whose parse wants a "
          "record prefix no PDU carries" },
        { dg,  false, false, false,
          "a sealed wire accepted a transparent dgram inner" },
        { mdg, false, false, false,
          "a sealed wire accepted a mux dgram inner" },
    };

    const char *err = lp && dg && dgf && mux && mdg ? nullptr : "inner wire create failed";
    for (size_t i = 0u; !err && i < sizeof cases / sizeof cases[0]; ++i) {
        auto sealed = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = cases[i].inner, .engine = tls_null_vtbl(),
            .role = seal_role_responder, .framing = seal_framing_stream });
        if ((sealed != nullptr) != cases[i].build
            || (sealed
                && (duct_has(sealed->flags, fl_wire_frame_flags) != cases[i].flags
                    || duct_has(sealed->flags, fl_wire_stream_ids) != cases[i].ids)))
            err = cases[i].what;
        if (sealed)
            duct_wire_destroy(sealed);
    }
    if (mdg) duct_wire_destroy(mdg);
    if (mux) duct_wire_destroy(mux);
    if (dgf) duct_wire_destroy(dgf);
    if (dg) duct_wire_destroy(dg);
    if (lp) duct_wire_destroy(lp);
    return err;
}

static const char *sc_zero_count(void)
{
    s_reset();
    auto fd = th_connect(g_lp_port);
    if (fd == duct_sock_bad) return "connect failed";

    th_sleep_ms(50u);
    const char *err = nullptr;
    uint8_t zero4[4] = {};

    if (send(fd, (const char *)zero4, 4, 0) != 4)
        err = "send failed";
    else {
        th_sleep_ms(300u);
        if (duct_atomic_load(&g_bad_size, acquire) != 0)
            err = "a bare zero count reached on_frame as an out-of-bounds payload";
        else if (duct_atomic_load(&g_frames, acquire) != 1)
            err = "a bare zero count did not arrive as one empty frame";
        else if (duct_atomic_load(&g_seen_flags, acquire) != (int)fl_frame_none)
            err = "an empty frame arrived carrying flags";
    }

    duct_sock_close(fd);
    return err;
}

static const char *sc_dgram_reports(void)
{
    s_reset();
    duct_sock_t fd = uc_connect(g_dg_port);
    if (fd == duct_sock_bad) return "connect failed";

    const char *err = nullptr;
    if (uc_send(fd, "sfin", 4u) != 0)
        err = "send failed";
    else if (!th_wait_int(&g_error_rc, (int)rc_not_supported, 3000u))
        err = duct_atomic_load(&g_error_rc, acquire) == -1
            ? "a flags-blind wire swallowed the FIN with no on_error"
            : "on_error fired with the wrong result code";
    else if (uc_recv_none(fd, 300) != 0)
        err = "a flags-blind wire put a frame on the wire anyway";

    close(fd);
    return err;
}

static const char *sc_dgram_data_fin(void)
{
    s_reset();
    duct_sock_t fd = uc_connect(g_dg_port);
    if (fd == duct_sock_bad) return "connect failed";

    const char *err = nullptr;
    char back[64] = {};

    if (uc_send(fd, "dfin", 4u) != 0)
        err = "send failed";
    else if (!th_wait_int(&g_error_rc, (int)rc_not_supported, 3000u))
        err = duct_atomic_load(&g_error_rc, acquire) == -1
            ? "a flags-blind wire swallowed a data frame's FIN with no on_error"
            : "on_error fired with the wrong result code";
    else if (uc_recv(fd, back, sizeof back) != 4
             || memcmp(back, "dfin", 4u) != 0)
        err = "the payload was dropped along with the flags it could not carry";

    close(fd);
    return err;
}

static const char *sc_dgram_framed(duct_frame_flags_t flags)
{
    s_reset();
    duct_sock_t fd = uc_connect(g_dgf_port);
    if (fd == duct_sock_bad) return "connect failed";

    const char *err = nullptr;
    uint8_t sent[5] = { (uint8_t)flags, 'p', 'i', 'n', 'g' };
    char back[64] = {};

    if (uc_send(fd, sent, sizeof sent) != 0)
        err = "send failed";
    else {
        ssize_t got = uc_recv(fd, back, sizeof back);
        if (got != (ssize_t)sizeof sent)
            err = "echo lost across a framed datagram";
        else if ((uint8_t)back[0] != (uint8_t)flags)
            err = "outbound: the datagram's own flags byte lost a flag";
        else if (memcmp(back + 1, sent + 1, sizeof sent - 1u) != 0)
            err = "payload corrupted across a framed datagram";
        else if (duct_atomic_load(&g_seen_flags, acquire) != (int)flags)
            err = "inbound: on_frame did not see the datagram's flags byte";
    }

    close(fd);
    return err;
}

static const char *sc_dgram_gso(void)
{
    s_reset();
    duct_sock_t fd = uc_connect(g_dg_port);
    if (fd == duct_sock_bad) return "connect failed";

    const char *err = nullptr;
    if (uc_send(fd, "dgso", 4u) != 0)
        err = "send failed";
    else if (!th_wait_int(&g_error_rc, (int)rc_not_supported, 3000u))
        err = duct_atomic_load(&g_error_rc, acquire) == -1
            ? "a flags-blind wire took a GSO record with no on_error"
            : "on_error fired with the wrong result code";
    else if (uc_recv_none(fd, 300) != 0)
        err = "a flags-blind wire put a GSO record on the wire as a plain datagram";

    close(fd);
    return err;
}

static const char *sc_dgram_record_gso(void)
{
    auto w = duct_wire_create_dgram_batch(0u, false);
    if (!w) return "wire create failed";
    auto parser = duct_wire_parser_create(w);
    uint8_t buf[duct_dgram_record_hdr_size + 5u] = { 0u, 0u, 0u, 0u, 'r', 'e', 'c', 'o', 'r' };
    duct_dgram_rec_hdr_encode(buf, 5u | duct_dgram_rec_gso);
    duct_frame_t frame = {};
    size_t consumed = 0u,
           needed = 0u;
    const char *err = nullptr;
    if (w->on_parse(w, (duct_view_u8){ buf, sizeof buf }, &frame, parser, &consumed, &needed) != rc_ok
        || consumed != sizeof buf || frame.payload.size != 5u)
        err = "a record prefix carrying the GSO bit did not parse as its own length";
    else if (frame.flags != fl_frame_gso)
        err = "the record prefix's GSO bit did not reach the frame";
    duct_wire_parser_destroy(w, parser);
    duct_wire_destroy(w);
    return err;
}

static const char *sc_lp_bound(void)
{
    auto top = duct_wire_create_length_prefix(((size_t)1u << 29) - 1u);
    auto past = duct_wire_create_length_prefix((size_t)1u << 29);
    const char *err = !top ? "length-prefix refused the largest length its header holds"
                    : past ? "length-prefix took a max_frame reaching into its flag bits"
                           : nullptr;
    if (top) duct_wire_destroy(top);
    if (past) duct_wire_destroy(past);
    return err;
}

static const char *sc_dgram_framed_bare(void)
{
    s_reset();
    duct_sock_t fd = uc_connect(g_dgf_port);
    if (fd == duct_sock_bad) return "connect failed";

    const char *err = nullptr;
    uint8_t bare = (uint8_t)fl_frame_fin;
    char back[64] = {};

    if (uc_send(fd, &bare, 0u) != 0)
        err = "empty datagram send failed";
    else if (uc_send(fd, &bare, 1u) != 0)
        err = "bare flags datagram send failed";
    else if (!th_wait_int(&g_frames, 1, 2000u))
        err = "inbound: a one-byte datagram did not arrive as a frame";
    else if (duct_atomic_load(&g_seen_flags, acquire) != (int)fl_frame_fin)
        err = "inbound: a one-byte datagram lost its flags";
    else if (uc_send(fd, &bare, 0u) != 0)
        err = "second empty datagram send failed";
    else if (uc_send(fd, "\x00sfin", 5u) != 0)
        err = "control datagram send failed";
    else {
        ssize_t got = uc_recv(fd, back, sizeof back);
        if (got != 1)
            err = "outbound: no bare control datagram arrived";
        else if ((uint8_t)back[0] != (uint8_t)fl_frame_fin)
            err = "outbound: a bare control datagram lost fl_frame_fin";
    }

    close(fd);
    return err;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) { fprintf(stderr, "wire_frame_flags: io create failed\n"); return 1; }

    auto lp_wire = duct_wire_create_length_prefix(0u);
    auto dg_wire = duct_wire_create_dgram_batch(0u, false);
    auto dgf_wire = duct_wire_create_dgram_batch(0u, true);
    duct_proto_t *lp = nullptr, *dg = nullptr, *dgf = nullptr;
    if (lp_wire && dg_wire && dgf_wire) {
        lp = duct_proto_create(&(duct_proto_cfg_t){
            .name = "lp-flags", .wire = lp_wire,
            .on_frame = on_frame, .on_error = on_error,
        });
        dg = duct_proto_create(&(duct_proto_cfg_t){
            .name = "dg-flags", .wire = dg_wire,
            .on_frame = on_frame, .on_error = on_error,
            .max_response = 65535u,
        });
        dgf = duct_proto_create(&(duct_proto_cfg_t){
            .name = "dgf-flags", .wire = dgf_wire,
            .on_frame = on_frame, .on_error = on_error,
            .max_response = 65535u,
        });
    }
    if (lp) lp->owned_wire = lp_wire; else duct_wire_destroy(lp_wire);
    if (dg) dg->owned_wire = dg_wire; else duct_wire_destroy(dg_wire);
    if (dgf) dgf->owned_wire = dgf_wire; else duct_wire_destroy(dgf_wire);
    if (!lp || !dg || !dgf) {
        fprintf(stderr, "wire_frame_flags: proto create failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(lp); duct_proto_destroy(dg); duct_proto_destroy(dgf);
        return 1;
    }

    const char *err = nullptr;
    pthread_t th;
    bool running = false;
    int pass = 1;

    if (duct_io_listen(io, "127.0.0.1", &g_lp_port, lp) != rc_ok) {
        err = "stream listen failed";
        goto done;
    }
    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
            .addr = "127.0.0.1", .n_protos = 1,
            .protos = (const duct_proto_t *[]){ dg },
        }, &g_dg_port, nullptr, 0u, nullptr) != rc_ok) {
        err = "datagram bind failed";
        goto done;
    }
    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
            .addr = "127.0.0.1", .n_protos = 1,
            .protos = (const duct_proto_t *[]){ dgf },
        }, &g_dgf_port, nullptr, 0u, nullptr) != rc_ok) {
        err = "framed datagram bind failed";
        goto done;
    }
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        err = "engine thread create failed";
        goto done;
    }
    running = true;

    pass &= s_report("roundtrip_none", sc_roundtrip(fl_frame_none, 0u));
    pass &= s_report("roundtrip_fin",  sc_roundtrip(fl_frame_fin, 0u));
    pass &= s_report("roundtrip_rst",  sc_roundtrip(fl_frame_rst, 0u));
    pass &= s_report("roundtrip_both",
                     sc_roundtrip(duct_or(fl_frame_fin, fl_frame_rst), 0u));
    pass &= s_report("roundtrip_gso", sc_roundtrip(fl_frame_gso, 0u));
    pass &= s_report("roundtrip_all",
                     sc_roundtrip(duct_or(fl_frame_fin, fl_frame_rst, fl_frame_gso), 0u));
    pass &= s_report("split_fin", sc_roundtrip(fl_frame_fin, 60u));
    pass &= s_report("standalone_fin",
                     sc_standalone("sfin", fl_frame_fin, stream_err_none,
                        "a standalone FIN reached the peer without fl_frame_fin"));
    pass &= s_report("standalone_rst",
                     sc_standalone("srst", fl_frame_rst, stream_err_rejected,
                        "a standalone RST reached the peer without fl_frame_rst"));
    pass &= s_report("zero_count", sc_zero_count());
    pass &= s_report("sealed_inherits", sc_sealed_inherits());
    pass &= s_report("dgram_reports", sc_dgram_reports());
    pass &= s_report("dgram_data_fin", sc_dgram_data_fin());
    pass &= s_report("dgram_framed", sc_dgram_framed(fl_frame_fin));
    pass &= s_report("dgram_framed_gso", sc_dgram_framed(fl_frame_gso));
    pass &= s_report("dgram_framed_bare", sc_dgram_framed_bare());
    pass &= s_report("dgram_gso", sc_dgram_gso());
    pass &= s_report("dgram_record_gso", sc_dgram_record_gso());
    pass &= s_report("lp_bound", sc_lp_bound());
    if (!pass)
        err = "one or more cases failed";

done:
    if (running) {
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(lp);
    duct_proto_destroy(dg);
    duct_proto_destroy(dgf);

    if (err) {
        fprintf(stderr, "wire_frame_flags: %s\n", err);
        return 1;
    }
    printf("wire_frame_flags: OK (fin/rst cross a length-prefix wire both ways; "
           "a flags-blind wire reports instead of going silent)\n");
    return 0;
}
