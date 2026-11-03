/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file seal_prefix_test.c
 * @brief Cleartext prefix widths a sealed datagram wire carries, one per
 * direction.
 *
 * The run that matters is asymmetric: the client emits four leading bytes and
 * expects none back, the server strips four and emits none. A single shared
 * width cannot express that configuration at all, and a width applied to the
 * wrong direction puts one side's full-PDU datagram past the other's ingress
 * bound, where it vanishes as oversize — which is what the bulk payload below
 * is sized to catch and the small one never reaches.
 *
 * A zero-width run gives the check its teeth: without a prefix those four
 * bytes open with a Noise PDU's own length, which is not zero, and the test
 * fails if it ever is. With one they are the bytes the client's wire starts
 * every conn with, until its peer names it. That run also confirms duct_conn_set_tx_prefix refuses a wire
 * emitting no prefix, and the asymmetric run that it refuses a width other
 * than the wire's.
 *
 * The asymmetric run also dials a second leg through open_leg.tx_prefix: its
 * message 1 leads with those bytes in place of the wire's own. A third run
 * names a prefix on the first dial, duct_io_connect_via's, with the same effect
 * on that conn's message 1.
 *
 * Two configurations are refused at construction rather than in a run: a
 * prefix past duct_seal_prefix_max, and any prefix on stream framing.
 *
 * What a tag looks like arriving from an address the listener holds no conn
 * for is dgram_prefix_roam_test's; here the preparse only ever sees the first
 * datagram of a session.
 */

#include "duct.h"
#include "duct_noise.h"
#include "test_helpers.h"
#ifdef __APPLE__
#include "duct_conn.h"
#include "duct_session.h"
#endif

#include <stdatomic.h>

static constexpr unsigned wait_ms = 3000u;
static constexpr uint8_t  probe_prefix[4] = { 0xc0, 0xff, 0xee, 0x01 };
static constexpr uint8_t  dial_prefix[4]  = { 0xd1, 0xa1, 0x1e, 0xad };

static atomic_int       g_preparse_hits = 0;
static _Atomic uint32_t g_first_lead = 0u;
static atomic_int       g_set_rc = -1;
static atomic_int       g_short_rc = -1;
static atomic_int       g_roundtrip = 0;
static atomic_int       g_bulk_ok = 0;
static atomic_int       g_dial_seen = 0;
static uint8_t          g_width;
static char             g_addr[64];

static const char ping[] = "seal-prefix-ping";

static uint8_t g_bulk[16384];

static duct_resolve_disposition_t
srv_preparse([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer,
             duct_view_u8 peek, [[maybe_unused]] duct_handle_t *out_tok,
             [[maybe_unused]] duct_conn_id_t *out_conn_id,
             void **out_user_ctx, [[maybe_unused]] size_t *out_lead)
{
    if (peek.size >= sizeof probe_prefix) {
        auto at = (const uint8_t *)peek.data;
        uint32_t v = 0u;
        for (unsigned i = 0u; i < sizeof probe_prefix; ++i)
            v = (v << 8u) | at[i];
        if (duct_atomic_fetch(add, &g_preparse_hits, 1, acq_rel) == 0)
            duct_atomic_store(&g_first_lead, v, release);
        if (memcmp(at, dial_prefix, sizeof dial_prefix) == 0)
            duct_atomic_store(&g_dial_seen, 1, release);
    }
    *out_user_ctx = nullptr;
    return resolve_new;
}

static duct_result_t
srv_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             const duct_frame_t *frame, duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

static duct_result_t
cli_on_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
#ifdef __APPLE__
    /* Full-PDU framing is the oracle, independent of path MTU. Darwin's
     * loopback MTU is smaller than this 16 KiB PDU plus Noise/IP headers.
     * Permit fragmentation only on this fixture's client socket. */
    auto conn = duct_conn_by_handle(duct_session_conn_at(s, duct_conn_id_primary));
    if (!conn || setsockopt(conn->fd, IPPROTO_IP, IP_DONTFRAG,
                            &(int){ 0 }, sizeof(int)) != 0)
        return rc_fatal;
#endif
    duct_atomic_store(&g_short_rc,
                      (int)duct_conn_set_tx_prefix(s, duct_conn_id_primary,
                          (duct_view_u8){ .data = (void *)probe_prefix,
                                          .size = sizeof probe_prefix - 1u }),
                      release);
    duct_atomic_store(&g_set_rc,
                      (int)duct_conn_set_tx_prefix(s, duct_conn_id_primary,
                          (duct_view_u8){ .data = (void *)probe_prefix,
                                          .size = sizeof probe_prefix }),
                      release);
    duct_response_same(out, duct_view_bytes((duct_view_cc){ ping, sizeof ping - 1u }),
                       fl_send_static, 0);
    return rc_ok;
}

static duct_result_t
cli_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             const duct_frame_t *frame, duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    if (frame->payload.size == sizeof ping - 1u
        && memcmp(frame->payload.data, ping, frame->payload.size) == 0) {
        duct_atomic_fetch(add, &g_roundtrip, 1, release);
        duct_response_same(out, (duct_view_u8){ .data = g_bulk,
                                                .size = sizeof g_bulk },
                           fl_send_static, 0);
        return rc_ok;
    }
    if (frame->payload.size == sizeof g_bulk
        && memcmp(frame->payload.data, g_bulk, frame->payload.size) == 0) {
        duct_atomic_store(&g_bulk_ok, 1, release);
        if (g_width) {
            out->control.open_leg.kind = leg_kind_connect_dgram;
            out->control.open_leg.conn_id = 1u;
            out->control.open_leg.connect_addr = g_addr;
            out->control.open_leg.tx_prefix = (duct_view_u8){ .data = (void *)dial_prefix,
                                                              .size = sizeof dial_prefix };
        }
    }
    return rc_ok;
}

static duct_proto_t *s_proto_make(duct_proto_cfg_t proto_cfg,
                                  duct_seal_role_t role,
                                  duct_noise_cfg_t *noise_cfg,
                                  uint8_t tx_prefix_len, uint8_t rx_prefix_len)
{
    duct_sealed_wire_cfg_t sealed = {
        .engine = duct_noise_vtbl(), .engine_cfg = noise_cfg,
        .role = role, .framing = seal_framing_datagram,
        .tx_prefix_len = tx_prefix_len, .rx_prefix_len = rx_prefix_len };
    memcpy(sealed.tx_prefix, probe_prefix, sizeof probe_prefix);
    auto wire = duct_wire_create_sealed(&sealed);
    duct_do_if(!wire, return nullptr);
    proto_cfg.wire = wire;
    auto proto = duct_proto_create(&proto_cfg);
    if (!proto) {
        duct_wire_destroy(wire);
        return nullptr;
    }
    proto->owned_wire = wire;
    return proto;
}

static duct_result_t
s_connect_retry(duct_engine_t *io, const char *addr, duct_proto_t *proto,
                duct_view_u8 prefix, unsigned timeout_ms)
{
    duct_result_t rc = rc_invalid_order;
    for (unsigned waited = 0u; waited < timeout_ms; waited += 5u) {
        rc = duct_io_connect_via(io, addr, proto, nullptr, x_udp_peer, 0u, prefix);
        if (rc != rc_invalid_order)
            return rc;
        struct timespec ts = { .tv_nsec = 5L * 1000L * 1000L };
        nanosleep(&ts, nullptr);
    }
    return rc;
}

/** @brief Whether the first dial names its prefix, over the wire's own. */
typedef enum : uint8_t { first_dial_plain, first_dial_led } first_dial_t;

static const char *sc_prefix(uint8_t width, first_dial_t first_dial,
                             const duct_noise_keypair_t *srv_kp,
                             const duct_noise_keypair_t *cli_kp)
{
    duct_atomic_store(&g_preparse_hits, 0, relaxed);
    duct_atomic_store(&g_first_lead, 0u, relaxed);
    duct_atomic_store(&g_set_rc, -1, relaxed);
    duct_atomic_store(&g_short_rc, -1, relaxed);
    duct_atomic_store(&g_roundtrip, 0, relaxed);
    duct_atomic_store(&g_bulk_ok, 0, relaxed);
    duct_atomic_store(&g_dial_seen, 0, relaxed);
    g_width = width;

    duct_noise_cfg_t srv_cfg = {}, cli_cfg = {};
    srv_cfg.local_static = *srv_kp;
    cli_cfg.local_static = *cli_kp;
    memcpy(cli_cfg.remote_static_pub, srv_kp->pub, duct_noise_key_size);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return "io create failed";

    auto srv = s_proto_make((duct_proto_cfg_t){
        .name = "seal-prefix-srv", .on_frame = srv_on_frame,
        .preparse = srv_preparse, .preparse_mode = resolve_sync,
        .flags = fl_proto_dgram_shared,
        .max_response = duct_noise_vtbl()->pdu_ct_max,
    }, seal_role_responder, &srv_cfg, 0u, width);
    auto cli = s_proto_make((duct_proto_cfg_t){
        .name = "seal-prefix-cli", .on_frame = cli_on_frame,
        .on_session_open = cli_on_open,
    }, seal_role_initiator, &cli_cfg, width, 0u);
    if (!srv || !cli) {
        duct_proto_destroy(srv); duct_proto_destroy(cli); duct_engine_destroy(io);
        return "proto create failed";
    }

    const char *err = nullptr;
    uint16_t port = 0u;
    pthread_t th;
    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
            .addr = "127.0.0.1", .n_protos = 1,
            .protos = (const duct_proto_t *[]){ srv },
        }, &port, nullptr, 0u, nullptr) != rc_ok)
        err = "listen failed";
    else if (pthread_create(&th, nullptr, th_run, io) != 0)
        err = "thread create failed";
    else {
        snprintf(g_addr, sizeof g_addr, "127.0.0.1:%u", (unsigned)port);
        duct_view_u8 prefix = first_dial == first_dial_led
                          ? (duct_view_u8){ .data = (void *)dial_prefix, .size = sizeof dial_prefix }
                          : (duct_view_u8){};
        if (s_connect_retry(io, g_addr, cli, prefix, 3000u) != rc_ok)
            err = "connect failed";
        else if (!th_wait_int(&g_roundtrip, 1, wait_ms))
            err = "the sealed datagram did not round-trip";
        else if (!th_wait_int(&g_bulk_ok, 1, wait_ms))
            err = "a datagram carrying one whole PDU never came back";
        else if (duct_atomic_load(&g_preparse_hits, acquire) == 0)
            err = "preparse never saw a datagram";
        else if (width && !th_wait_int(&g_dial_seen, 1, wait_ms))
            err = "a leg dialled with its own prefix did not lead its message 1 with it";

        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }

    duct_engine_destroy(io);
    duct_proto_destroy(srv);
    duct_proto_destroy(cli);
    return err;
}

static int s_refused_cfgs(void)
{
    duct_noise_cfg_t cfg = {};
    int pass = 1;
    auto too_wide = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .engine = duct_noise_vtbl(), .engine_cfg = &cfg,
        .role = seal_role_initiator, .framing = seal_framing_datagram,
        .tx_prefix_len = (uint8_t)(duct_seal_prefix_max + 1u) });
    if (too_wide) {
        fprintf(stderr, "seal_prefix: a prefix past duct_seal_prefix_max built "
                        "a wire\n");
        duct_wire_destroy(too_wide);
        pass = 0;
    }
    auto on_stream = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .engine = duct_noise_vtbl(), .engine_cfg = &cfg,
        .role = seal_role_initiator, .framing = seal_framing_stream,
        .tx_prefix_len = (uint8_t)sizeof probe_prefix });
    if (on_stream) {
        fprintf(stderr, "seal_prefix: a stream-framed wire accepted a prefix\n");
        duct_wire_destroy(on_stream);
        pass = 0;
    }
    return pass;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    duct_noise_keypair_t srv_kp, cli_kp;
    if (!duct_noise_keypair_generate(&srv_kp)
        || !duct_noise_keypair_generate(&cli_kp)) {
        fprintf(stderr, "seal_prefix: keypair generation failed\n");
        return 1;
    }

    for (size_t i = 0u; i < sizeof g_bulk; ++i)
        g_bulk[i] = (uint8_t)(i * 31u + 7u);

    int pass = s_refused_cfgs();

    auto err = sc_prefix(0u, first_dial_plain, &srv_kp, &cli_kp);
    uint32_t bare = duct_atomic_load(&g_first_lead, acquire);
    int bare_set_rc = duct_atomic_load(&g_set_rc, acquire);
    if (err) { fprintf(stderr, "seal_prefix: bare: %s\n", err); pass = 0; }
    else if (bare_set_rc != (int)rc_invalid_arg) {
        fprintf(stderr, "seal_prefix: a wire emitting no prefix answered %d to "
                        "duct_conn_set_tx_prefix\n", bare_set_rc);
        pass = 0;
    }
    else if (bare == 0u) {
        fprintf(stderr, "seal_prefix: an unprefixed datagram opened with four "
                        "zero bytes, so the check below proves nothing\n");
        pass = 0;
    }

    err = sc_prefix((uint8_t)sizeof probe_prefix, first_dial_plain, &srv_kp, &cli_kp);
    int set_rc = duct_atomic_load(&g_set_rc, acquire);
    int short_rc = duct_atomic_load(&g_short_rc, acquire);
    uint32_t seen = duct_atomic_load(&g_first_lead, acquire);
    if (err) { fprintf(stderr, "seal_prefix: asymmetric: %s\n", err); pass = 0; }
    else if (set_rc != (int)rc_ok) {
        fprintf(stderr, "seal_prefix: duct_conn_set_tx_prefix answered %d\n", set_rc);
        pass = 0;
    } else if (short_rc != (int)rc_invalid_arg) {
        fprintf(stderr, "seal_prefix: a prefix narrower than the wire's answered "
                        "%d\n", short_rc);
        pass = 0;
    } else if (seen != 0xc0ffee01u) {
        fprintf(stderr, "seal_prefix: the first datagram led with %08lx, not the "
                        "prefix its wire starts every conn with\n", (unsigned long)seen);
        pass = 0;
    }

    err = sc_prefix((uint8_t)sizeof probe_prefix, first_dial_led, &srv_kp, &cli_kp);
    seen = duct_atomic_load(&g_first_lead, acquire);
    if (err) { fprintf(stderr, "seal_prefix: first dial led: %s\n", err); pass = 0; }
    else if (seen != 0xd1a11eadu) {
        fprintf(stderr, "seal_prefix: the first dial named its prefix and message 1 led with "
                        "%08lx\n", (unsigned long)seen);
        pass = 0;
    }

    if (!pass)
        return 1;
    printf("seal_prefix: OK (four cleartext bytes lead every datagram the client "
           "sends, none lead the server's replies, a full PDU clears both ingress "
           "bounds either way, and a first dial's own prefix leads its message 1 in "
           "place of the wire's)\n");
    return 0;
}
