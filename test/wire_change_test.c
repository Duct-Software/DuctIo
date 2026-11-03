/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file wire_change_test.c
 * @brief MJ-WC / TP-H2 acceptance: duct_proto_switch across a wire change.
 *
 * One engine hosts both ends of each scenario (mirrors
 * test/open_leg_connect_test.c's shape). Each scenario carries its own detail;
 * what they divide between them is which part of a switch is under test.
 *
 * Wire change itself:
 *   1. raw_to_lp      — a proto with no wire switches into one that frames.
 *   2. lp_resize      — same wire kind, different instance and bound; a partial
 *                       header buffered under the old wire is discarded.
 *   2b. lp_resize_fin — the rebind waits on an old-wire frame whose header
 *                       arrived whole; the peer's FIN ends that frame unfinished,
 *                       which lets the switch land and the leg close.
 *   2a. lp_to_mux     — the upgrade shape: the header widens 4 → 8 and the
 *                       session gains the stream table it opened without.
 *   3. multi_leg      — two wired legs: enter fires once, after both fences,
 *                       and a frame racing the fan-out replays rather than
 *                       reaching the old proto.
 *
 * The sealed side, with the null engine
 * (tls_engine_null.h/.c):
 *   4. plain_to_tls   — handshake and application data flow post-switch.
 *   5. tls_to_plain_drop — a sealed record raced into the switch's own batch is
 *                       deferred, then dropped once its retry finds the wire
 *                       generation moved past it; the codec frees at the
 *                       fence, not at some later teardown.
 *   6. midhandshake_peer_close / midhandshake_protocol_close — the peer
 *                       disconnects, and the protocol refuses the switch:
 *                       both tear an unhandshook codec down cleanly.
 *   7. tls_close_notify — a graceful close still stages close_notify, here with
 *                       a codec built by a switch rather than from the start.
 */

#include "duct.h"
#include "duct_wire.h"
#include "duct_tls.h"
#include "tls_engine_null.h"
#include "test_helpers.h"

#include <stdatomic.h>

static constexpr unsigned wait_ms = 3000u;

/* ── Shared hook counters ────────────────────────────────────────── */

static atomic_int g_enter_count = 0,
                   g_leave_count = 0,
                   g_v1_frame_count = 0,
                   g_v2_frame_count = 0;

static void s_counters_reset(void)
{
    duct_atomic_store(&g_enter_count, 0, relaxed);
    duct_atomic_store(&g_leave_count, 0, relaxed);
    duct_atomic_store(&g_v1_frame_count, 0, relaxed);
    duct_atomic_store(&g_v2_frame_count, 0, relaxed);
}

static duct_leave_t
s_on_leave([[maybe_unused]] duct_session_t *s, [[maybe_unused]] void *ctx,
          [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_leave_count, 1, release);
    return leave_destroy;
}

static duct_result_t
s_on_enter([[maybe_unused]] duct_session_t *s, [[maybe_unused]] void *ctx,
          [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_enter_count, 1, release);
    return rc_ok;
}

/* ── TLS raw-record socket helpers (tls_null_test.c's own pattern) ───
 * Scenarios 4-7 sit a null-engine TLS wire on one side of a switch, so the
 * client side needs to speak its 5-byte [type][reserved(2)][len(2 BE)]
 * record framing directly, same as tls_null_test.c — th_send/th_recv (this
 * file's own LP helpers, above) do not apply once conn->wire is the TLS
 * wire. inner == nullptr throughout ("raw bytes over TLS"): one
 * record's cleartext is one whole frame, no further inner framing needed. */

static int s_recv_exact(duct_sock_t fd, void *buf, size_t n)
{
    size_t got = 0u;
    while (got < n) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, TH_ROUNDTRIP_TIMEOUT_MS) <= 0)
            return -1;
        int r = recv(fd, (char *)buf + got, (int)(n - got), 0);
        if (r <= 0)
            return -1;
        got += (size_t)r;
    }
    return 0;
}

static int s_send_record(duct_sock_t fd, uint8_t type, const void *body, size_t body_len)
{
    uint8_t hdr[5] = { type, 0u, 0u, (uint8_t)(body_len >> 8u), (uint8_t)(body_len) };
    if (send(fd, (const char *)hdr, 5, 0) != 5)
        return -1;
    if (body_len && send(fd, (const char *)body, (int)body_len, 0) != (int)body_len)
        return -1;
    return 0;
}

static int s_recv_record(duct_sock_t fd, uint8_t *type_out, uint8_t *body, size_t body_cap, size_t *body_len_out)
{
    uint8_t hdr[5];
    if (s_recv_exact(fd, hdr, sizeof hdr) != 0)
        return -1;
    size_t len = ((size_t)hdr[3] << 8u) | (size_t)hdr[4];
    if (len > body_cap || s_recv_exact(fd, body, len) != 0)
        return -1;
    *type_out = hdr[0];
    *body_len_out = len;
    return 0;
}

/** @brief Client-side handshake: the null engine treats any first record on
 *  a fresh codec as the handshake, regardless of content, and replies
 *  unencrypted with tls_null_server_hello (tls_engine_null.c's own s_unseal). */
static int s_tls_handshake(duct_sock_t fd)
{
    static const uint8_t client_hello[4] = { 'C', 'L', 'N', 'T' };
    if (s_send_record(fd, 1u, client_hello, sizeof client_hello) != 0)
        return -1;
    uint8_t type = 0u, body[64] = {};
    size_t blen = 0u;
    if (s_recv_record(fd, &type, body, sizeof body, &blen) != 0)
        return -1;
    if (type != 1u || blen != sizeof tls_null_server_hello
        || memcmp(body, tls_null_server_hello, blen) != 0)
        return -1;
    return 0;
}

/** @brief Seal @p ct as one application-data record's full bytes (header
 *  included) into @p out, without sending it — scenario 5's own way to
 *  combine two records into a single send(). Returns bytes written, or 0
 *  if @p out_cap is too small. */
static size_t s_build_app_record(uint8_t *out, size_t out_cap, const void *ct, size_t ct_len)
{
    uint8_t sealed[512];
    size_t sealed_len = tls_null_seal(ct, ct_len, sealed, sizeof sealed);
    if (!sealed_len || out_cap < 5u + sealed_len)
        return 0u;
    out[0] = 2u; out[1] = 0u; out[2] = 0u;
    out[3] = (uint8_t)(sealed_len >> 8u); out[4] = (uint8_t)(sealed_len);
    memcpy(out + 5u, sealed, sealed_len);
    return 5u + sealed_len;
}

static int s_send_app(duct_sock_t fd, const void *ct, size_t ct_len)
{
    uint8_t record[512];
    size_t len = s_build_app_record(record, sizeof record, ct, ct_len);
    if (!len || send(fd, (const char *)record, (int)len, 0) != (int)len)
        return -1;
    return 0;
}

/** @brief Read one application-data record and fake-unseal its body — the
 *  single-record counterpart of tls_null_test.c's own multi-record
 *  s_recv_app_records (pdu_ct_max is 4096; every payload these scenarios
 *  send is far smaller, so one record always suffices). */
static int s_recv_app(duct_sock_t fd, uint8_t *ct_out, size_t ct_cap, size_t *ct_len_out)
{
    uint8_t type = 0u, body[512] = {};
    size_t blen = 0u;
    if (s_recv_record(fd, &type, body, sizeof body, &blen) != 0 || type != 2u)
        return -1;
    size_t got = tls_null_unseal_body(body, blen, ct_out, ct_cap);
    if (got == SIZE_MAX)
        return -1;
    *ct_len_out = got;
    return 0;
}

/** @brief Poll tls_null_destroy_calls() until it reaches @p target — the
 *  codec's own teardown is worker-side and asynchronous relative to
 *  whatever triggered it (a peer disconnect, a protocol-rejected switch),
 *  unlike the in-scenario counters above (g_enter_count's own release
 *  store already orders everything s_session_finish_switch did before
 *  it, including an earlier codec free at the same fence — no separate
 *  wait needed there; see scenario 5). */
static bool s_wait_destroy_count(unsigned target, unsigned timeout_ms)
{
    for (unsigned waited = 0u; waited < timeout_ms; waited += 10u) {
        if (tls_null_destroy_calls() >= target)
            return true;
        th_sleep_ms(10u);
    }
    return tls_null_destroy_calls() >= target;
}

/* ── Scenario 1: raw -> LP ────────────────────────────────────────── */

static _Atomic(const duct_proto_t *) g_sc1_target;

static duct_result_t
sc1_v1_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                [[maybe_unused]] const duct_frame_t *frame, duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_v1_frame_count, 1, release);
    auto next = duct_atomic_load(&g_sc1_target, acquire);
    return duct_response_switch(out, s, next, nullptr);
}

static duct_result_t
sc1_v2_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                const duct_frame_t *frame, duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_v2_frame_count, 1, release);
    duct_response_echo(out, frame);
    return rc_ok;
}

static bool sc_raw_to_lp(void)
{
    s_counters_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto lp_wire = duct_wire_create_length_prefix(0u);
    auto v1 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "wire-raw", .wire = nullptr, .on_frame = sc1_v1_on_frame,
        .on_proto_leave = s_on_leave, .max_response = 4096u,
    });
    auto v2 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "wire-lp", .wire = lp_wire, .on_frame = sc1_v2_on_frame,
        .on_proto_enter = s_on_enter,
    });
    if (v2) v2->owned_wire = lp_wire; else duct_wire_destroy(lp_wire);
    if (!v1 || !v2) {
        duct_proto_destroy(v1); duct_proto_destroy(v2); duct_engine_destroy(io);
        return false;
    }
    duct_atomic_store(&g_sc1_target, v2, release);

    uint16_t port = 0u;
    bool ok = duct_io_listen(io, "127.0.0.1", &port, v1) == rc_ok;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        duct_sock_t fd = th_connect(port);
        ok = fd != duct_sock_bad;

        /* Raw trigger: one unframed write is posted as a single frame under
         * v1's null wire (the raw path, src/duct_frame_rx.c). */
        static const char trigger[] = "switch-me";
        ok = ok && write(fd, trigger, sizeof trigger - 1u) == (ssize_t)(sizeof trigger - 1u);
        ok = ok && th_wait_int(&g_enter_count, 1, wait_ms);
        ok = ok && duct_atomic_load(&g_v1_frame_count, acquire) == 1
                && duct_atomic_load(&g_leave_count, acquire) == 1;

        /* Next write is parsed length-prefixed: v2's wire, not v1's, is live. */
        static const char msg[] = "hello-on-the-new-wire";
        ok = ok && th_send(fd, msg, sizeof msg - 1u) == 0
                && th_recv_eq(fd, msg, sizeof msg - 1u) == 0;
        ok = ok && duct_atomic_load(&g_v2_frame_count, acquire) == 1
                && duct_atomic_load(&g_enter_count, acquire) == 1;

        if (fd != duct_sock_bad) close(fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(v1);
    duct_proto_destroy(v2);
    return ok;
}

/* ── Scenario 2: LP(A) -> LP(B), partial discard proof ───────────── */

static constexpr size_t sc2_max_a = 64u;
static constexpr size_t sc2_max_b = 512u;

static _Atomic(const duct_proto_t *) g_sc2_target;

static duct_result_t
sc2_v1_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                [[maybe_unused]] const duct_frame_t *frame, duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_v1_frame_count, 1, release);
    auto next = duct_atomic_load(&g_sc2_target, acquire);
    return duct_response_switch(out, s, next, nullptr);
}

static duct_result_t
sc2_v2_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                const duct_frame_t *frame, duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_v2_frame_count, 1, release);
    duct_response_echo(out, frame);
    return rc_ok;
}

static bool sc_lp_resize(void)
{
    s_counters_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto wire_a = duct_wire_create_length_prefix(sc2_max_a);
    auto wire_b = duct_wire_create_length_prefix(sc2_max_b);
    auto v1 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "wire-lp-a", .wire = wire_a, .on_frame = sc2_v1_on_frame,
        .on_proto_leave = s_on_leave,
    });
    auto v2 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "wire-lp-b", .wire = wire_b, .on_frame = sc2_v2_on_frame,
        .on_proto_enter = s_on_enter,
    });
    if (v1) v1->owned_wire = wire_a; else duct_wire_destroy(wire_a);
    if (v2) v2->owned_wire = wire_b; else duct_wire_destroy(wire_b);
    if (!v1 || !v2) {
        duct_proto_destroy(v1); duct_proto_destroy(v2); duct_engine_destroy(io);
        return false;
    }
    duct_atomic_store(&g_sc2_target, v2, release);

    uint16_t port = 0u;
    bool ok = duct_io_listen(io, "127.0.0.1", &port, v1) == rc_ok;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        duct_sock_t fd = th_connect(port);
        ok = fd != duct_sock_bad;

        /* Trigger frame under v1 (LP, max_frame=A) immediately followed by 2
         * of a next frame's 4-byte length-prefix, both in one send() so the
         * two can never land in separate TCP segments/completions — v1's
         * wire_parser must buffer the stray pair as a partial header awaiting
         * completion, not have it arrive after the switch already ran. */
        uint8_t combined[] = { 0x00u, 0x00u, 0x00u, 0x02u, 'g', 'o', 0x00u, 0x00u };
        ok = ok && send(fd, (const char *)combined, sizeof combined, 0) == (int)sizeof combined;
        ok = ok && th_wait_int(&g_enter_count, 1, wait_ms);
        ok = ok && duct_atomic_load(&g_v1_frame_count, acquire) == 1
                && duct_atomic_load(&g_leave_count, acquire) == 1;

        /* A payload > A but <= B: only accepted if v2 (not v1) is live. If
         * the 2 stray bytes above had leaked into v2's fresh wire_parser
         * instead of being discarded, this frame's header would misalign
         * and the echo below would never arrive. */
        char payload[200];
        memset(payload, 'x', sizeof payload);
        ok = ok && sizeof payload > sc2_max_a && sizeof payload <= sc2_max_b;
        ok = ok && th_send(fd, payload, sizeof payload) == 0
                && th_recv_eq(fd, payload, sizeof payload) == 0;
        ok = ok && duct_atomic_load(&g_v2_frame_count, acquire) == 1;

        if (fd != duct_sock_bad) close(fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(v1);
    duct_proto_destroy(v2);
    return ok;
}

/* ── Scenario 2b: LP(A) -> LP(B), rebind released by the peer's FIN ── */

/* Long enough for the switch request to reach io and find the frame it waits
 * on: a rebind that did not wait lands within it. */
static constexpr unsigned sc2b_settle_ms = 200u;

static bool sc_lp_resize_fin(void)
{
    s_counters_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto wire_a = duct_wire_create_length_prefix(sc2_max_a);
    auto wire_b = duct_wire_create_length_prefix(sc2_max_b);
    auto v1 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "wire-lp-a", .wire = wire_a, .on_frame = sc2_v1_on_frame,
        .on_proto_leave = s_on_leave,
    });
    auto v2 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "wire-lp-b", .wire = wire_b, .on_frame = sc2_v2_on_frame,
        .on_proto_enter = s_on_enter,
    });
    if (v1) v1->owned_wire = wire_a; else duct_wire_destroy(wire_a);
    if (v2) v2->owned_wire = wire_b; else duct_wire_destroy(wire_b);
    if (!v1 || !v2) {
        duct_proto_destroy(v1); duct_proto_destroy(v2); duct_engine_destroy(io);
        return false;
    }
    duct_atomic_store(&g_sc2_target, v2, release);

    uint16_t port = 0u;
    bool ok = duct_io_listen(io, "127.0.0.1", &port, v1) == rc_ok;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        duct_sock_t fd = th_connect(port);
        ok = fd != duct_sock_bad;

        /* The trigger frame, then a whole v1 header promising 10 bytes and 3
         * of them: a frame in flight under the old wire, which the rebind
         * waits for. */
        uint8_t combined[] = { 0x00u, 0x00u, 0x00u, 0x02u, 'g', 'o',
                               0x00u, 0x00u, 0x00u, 0x0au, 'a', 'b', 'c' };
        ok = ok && send(fd, (const char *)combined, sizeof combined, 0) == (int)sizeof combined;
        ok = ok && th_wait_int(&g_v1_frame_count, 1, wait_ms);
        th_sleep_ms(sc2b_settle_ms);
        ok = ok && duct_atomic_load(&g_enter_count, acquire) == 0;

        /* The FIN ends that frame unfinished: the switch lands on the drained
         * input, and the end of input closes the leg behind it. */
        ok = ok && shutdown(fd, SHUT_WR) == 0;
        ok = ok && th_wait_int(&g_enter_count, 1, wait_ms);
        ok = ok && th_peer_closed(fd, (int)wait_ms);
        ok = ok && duct_atomic_load(&g_v2_frame_count, acquire) == 0;

        if (fd != duct_sock_bad) close(fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(v1);
    duct_proto_destroy(v2);
    return ok;
}

static atomic_int g_mux_sid = -1;
static atomic_int g_mux_open = 0;
static atomic_int g_mux_closed = -1;

static duct_result_t
sc_mux_on_stream_open([[maybe_unused]] duct_session_t *s, duct_stream_id_t stream_id,
                      [[maybe_unused]] duct_response_t *out,
                      [[maybe_unused]] void *stream_state)
{
    duct_atomic_store(&g_mux_open, (int)stream_id, release);
    return rc_ok;
}

static void
sc_mux_on_stream_close([[maybe_unused]] duct_session_t *s, duct_stream_id_t stream_id,
                       [[maybe_unused]] duct_close_reason_t reason,
                       [[maybe_unused]] void *stream_state)
{
    duct_atomic_store(&g_mux_closed, (int)stream_id, release);
}

static duct_result_t
sc_mux_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                const duct_frame_t *frame, duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_mux_sid, (int)frame->stream_id, release);
    duct_atomic_fetch(add, &g_v2_frame_count, 1, release);
    duct_response_echo(out, frame);
    return rc_ok;
}

static bool sc_lp_to_mux(void)
{
    s_counters_reset();
    duct_atomic_store(&g_mux_sid, -1, release);
    duct_atomic_store(&g_mux_open, 0, release);
    duct_atomic_store(&g_mux_closed, -1, release);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto wire_lp = duct_wire_create_length_prefix(0u);
    auto wire_mux = duct_wire_create_mux(0u);
    auto v1 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "wc-lp", .wire = wire_lp, .on_frame = sc2_v1_on_frame,
        .on_proto_leave = s_on_leave,
    });
    auto v2 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "wc-mux", .wire = wire_mux, .flags = fl_proto_multiplexed,
        .on_frame = sc_mux_on_frame, .on_proto_enter = s_on_enter,
        .on_stream_open = sc_mux_on_stream_open,
        .on_stream_close = sc_mux_on_stream_close,
    });
    if (v1) v1->owned_wire = wire_lp; else duct_wire_destroy(wire_lp);
    if (v2) v2->owned_wire = wire_mux; else duct_wire_destroy(wire_mux);
    if (!v1 || !v2) {
        duct_proto_destroy(v1); duct_proto_destroy(v2); duct_engine_destroy(io);
        return false;
    }
    duct_atomic_store(&g_sc2_target, v2, release);

    uint16_t port = 0u;
    bool ok = duct_io_listen(io, "127.0.0.1", &port, v1) == rc_ok;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        duct_sock_t fd = th_connect(port);
        ok = fd != duct_sock_bad;

        /* Trigger frame plus 2 bytes of a next length prefix in one send(), so
         * the strays are buffered as a partial header before the switch runs.
         * Carried into the 8-byte wire's fresh parser they glue to the front
         * of its header instead: the length field then reads 4096 rather than
         * 16, and the echo below never arrives. */
        uint8_t combined[] = { 0x00u, 0x00u, 0x00u, 0x02u, 'g', 'o', 0x00u, 0x00u };
        ok = ok && send(fd, (const char *)combined, sizeof combined, 0) == (int)sizeof combined;
        ok = ok && th_wait_int(&g_enter_count, 1, wait_ms);
        ok = ok && duct_atomic_load(&g_v1_frame_count, acquire) == 1
                && duct_atomic_load(&g_leave_count, acquire) == 1;

        static const char body[] = "after-the-switch";
        uint8_t hdr[8] = {
            0u, 0u, 0u, (uint8_t)(sizeof body - 1u),
            0u, 0u, 0u, 77u,
        };
        uint8_t back[8] = {};
        char buf[64] = {};
        ok = ok && send(fd, (const char *)hdr, 8, 0) == 8
                && send(fd, body, (int)(sizeof body - 1u), 0) == (int)(sizeof body - 1u);
        ok = ok && th_read_exact(fd, back, sizeof back) == 0;
        ok = ok && back[3] == (uint8_t)(sizeof body - 1u) && back[7] == 77u;
        ok = ok && th_read_exact(fd, buf, sizeof body - 1u) == 0
                && memcmp(buf, body, sizeof body - 1u) == 0;
        ok = ok && duct_atomic_load(&g_mux_sid, acquire) == 77;
        ok = ok && duct_atomic_load(&g_v2_frame_count, acquire) == 1;
        ok = ok && duct_atomic_load(&g_mux_open, acquire) == 77;

        uint8_t fin_hdr[8] = { (uint8_t)fl_frame_fin, 0u, 0u, 0u, 0u, 0u, 0u, 77u };
        ok = ok && send(fd, (const char *)fin_hdr, 8, 0) == 8;
        ok = ok && th_wait_int(&g_mux_closed, 77, wait_ms);

        if (fd != duct_sock_bad) close(fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(v1);
    duct_proto_destroy(v2);
    return ok;
}

/* ── Scenario 3: multi-leg (TCP + attach_fd), both rebind ────────── */

static atomic_int  g_join_count = 0;
static atomic_int  g_attach_rc = -1;
static _Atomic(duct_sock_t) g_attached_fd = duct_sock_bad;
static _Atomic(const duct_proto_t *) g_sc3_target;

static duct_result_t
sc3_on_session_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                    [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
                    [[maybe_unused]] void *proto_state)
{
    duct_sock_t sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        duct_atomic_store(&g_attach_rc, (int)rc_no_memory, release);
        return rc_ok;
    }
    /* duct_conn_attach_fd takes ownership of sv[0] on this call regardless of
     * outcome (closes it itself on any failure); only sv[1] is ours to release. */
    auto rc = duct_conn_attach_fd(s, 1u, sv[0]);
    duct_atomic_store(&g_attach_rc, (int)rc, release);
    if (rc != rc_ok) {
        close(sv[1]);
        return rc_ok;
    }
    duct_atomic_store(&g_attached_fd, sv[1], release);
    return rc_ok;
}

static duct_result_t
sc3_on_conn_join([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                 [[maybe_unused]] const duct_peer_t *peer, [[maybe_unused]] duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_join_count, 1, release);
    return rc_ok;
}

static duct_result_t
sc3_v1_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                const duct_frame_t *frame, duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_v1_frame_count, 1, release);
    if (frame->payload.size == 5u && memcmp(frame->payload.data, "trig!", 5u) == 0) {
        auto next = duct_atomic_load(&g_sc3_target, acquire);
        return duct_response_switch(out, s, next, nullptr);
    }
    duct_response_echo(out, frame);
    return rc_ok;
}

static duct_result_t
sc3_v2_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                const duct_frame_t *frame, duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_v2_frame_count, 1, release);
    duct_response_echo(out, frame);
    return rc_ok;
}

static bool sc_multi_leg(void)
{
    s_counters_reset();
    duct_atomic_store(&g_join_count, 0, relaxed);
    duct_atomic_store(&g_attach_rc, -1, relaxed);
    duct_atomic_store(&g_attached_fd, duct_sock_bad, relaxed);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto wire_v1 = duct_wire_create_length_prefix(0u);
    auto wire_v2 = duct_wire_create_length_prefix(0u); /* distinct instance, same kind/size */
    auto v1 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "wire-multi-v1", .wire = wire_v1, .on_frame = sc3_v1_on_frame,
        .on_session_open = sc3_on_session_open, .on_conn_join = sc3_on_conn_join,
        .on_proto_leave = s_on_leave,
    });
    auto v2 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "wire-multi-v2", .wire = wire_v2, .on_frame = sc3_v2_on_frame,
        .on_proto_enter = s_on_enter,
    });
    if (v1) v1->owned_wire = wire_v1; else duct_wire_destroy(wire_v1);
    if (v2) v2->owned_wire = wire_v2; else duct_wire_destroy(wire_v2);
    if (!v1 || !v2) {
        duct_proto_destroy(v1); duct_proto_destroy(v2); duct_engine_destroy(io);
        return false;
    }
    duct_atomic_store(&g_sc3_target, v2, release);

    uint16_t port = 0u;
    bool ok = duct_io_listen(io, "127.0.0.1", &port, v1) == rc_ok;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        duct_sock_t primary_fd = th_connect(port);
        ok = primary_fd != duct_sock_bad;
        ok = ok && th_wait_int(&g_join_count, 1, wait_ms);
        ok = ok && duct_atomic_load(&g_attach_rc, acquire) == (int)rc_ok;
        duct_sock_t peer_fd = duct_atomic_load(&g_attached_fd, acquire);
        ok = ok && peer_fd != duct_sock_bad;

        /* Both legs live under v1 before the switch. */
        static const char p0[] = "primary-v1", a0[] = "attach-v1";
        ok = ok && th_send(primary_fd, p0, sizeof p0 - 1u) == 0
                && th_recv_eq(primary_fd, p0, sizeof p0 - 1u) == 0;
        ok = ok && th_send(peer_fd, a0, sizeof a0 - 1u) == 0
                && th_recv_eq(peer_fd, a0, sizeof a0 - 1u) == 0;
        ok = ok && duct_atomic_load(&g_v1_frame_count, acquire) == 2;

        /* Trigger the switch from the primary leg, then immediately race a
         * frame in on the attach_fd leg. Whether that frame lands before the
         * trigger is even processed (ordinary v1 dispatch), or after (must
         * be deferred by s_dispatch_frame's wire_rebind_next gate instead of
         * reaching v1 with new-side timing or getting lost), either outcome
         * is correct — only the invariants below must hold regardless of
         * which one the scheduler actually produced this run. */
        static const char trigger[] = "trig!";
        ok = ok && th_send(primary_fd, trigger, sizeof trigger - 1u) == 0;
        static const char raced[] = "raced-frame";
        ok = ok && th_send(peer_fd, raced, sizeof raced - 1u) == 0;

        ok = ok && th_recv_eq(peer_fd, raced, sizeof raced - 1u) == 0;
        ok = ok && th_wait_int(&g_enter_count, 1, wait_ms);
        ok = ok && duct_atomic_load(&g_leave_count, acquire) == 1
                && duct_atomic_load(&g_enter_count, acquire) == 1;
        /* Accounted for exactly once each: p0, a0, trig!, raced — no loss,
         * no duplication, regardless of which proto ended up processing raced. */
        int v2_before = duct_atomic_load(&g_v2_frame_count, acquire);
        ok = ok && duct_atomic_load(&g_v1_frame_count, acquire)
                 + v2_before == 4;

        /* Both legs now route through v2, deterministically — the switch is
         * long complete by this point. */
        static const char p1[] = "primary-v2", a1[] = "attach-v2";
        ok = ok && th_send(primary_fd, p1, sizeof p1 - 1u) == 0
                && th_recv_eq(primary_fd, p1, sizeof p1 - 1u) == 0;
        ok = ok && th_send(peer_fd, a1, sizeof a1 - 1u) == 0
                && th_recv_eq(peer_fd, a1, sizeof a1 - 1u) == 0;
        ok = ok && duct_atomic_load(&g_v2_frame_count, acquire) == v2_before + 2;

        if (primary_fd != duct_sock_bad) close(primary_fd);
        if (peer_fd != duct_sock_bad) close(peer_fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(v1);
    duct_proto_destroy(v2);
    return ok;
}

/* ── Scenario 4: cleartext -> TLS (STARTTLS forward switch) ──── */

static _Atomic(const duct_proto_t *) g_sc4_target;

static duct_result_t
sc4_v1_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                [[maybe_unused]] const duct_frame_t *frame, duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_v1_frame_count, 1, release);
    auto next = duct_atomic_load(&g_sc4_target, acquire);
    return duct_response_switch(out, s, next, nullptr);
}

static duct_result_t
sc4_v2_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                const duct_frame_t *frame, duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_v2_frame_count, 1, release);
    duct_response_echo(out, frame);
    return rc_ok;
}

static bool sc_plain_to_tls(void)
{
    s_counters_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto lp_wire = duct_wire_create_length_prefix(0u);
    auto tls_wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = nullptr, .engine = tls_null_vtbl(),
            .engine_cfg = nullptr, .role = seal_role_responder,
            .framing = seal_framing_stream });
    auto v1 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "wire-plain4", .wire = lp_wire, .on_frame = sc4_v1_on_frame,
        .on_proto_leave = s_on_leave,
    });
    auto v2 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "wire-tls4", .wire = tls_wire, .on_frame = sc4_v2_on_frame,
        .on_proto_enter = s_on_enter,
    });
    if (v1) v1->owned_wire = lp_wire; else duct_wire_destroy(lp_wire);
    if (v2) v2->owned_wire = tls_wire; else duct_wire_destroy(tls_wire);
    if (!v1 || !v2) {
        duct_proto_destroy(v1); duct_proto_destroy(v2); duct_engine_destroy(io);
        return false;
    }
    duct_atomic_store(&g_sc4_target, v2, release);

    uint16_t port = 0u;
    bool ok = duct_io_listen(io, "127.0.0.1", &port, v1) == rc_ok;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        duct_sock_t fd = th_connect(port);
        ok = fd != duct_sock_bad;

        static const char trigger[] = "go-tls";
        ok = ok && th_send(fd, trigger, sizeof trigger - 1u) == 0;
        ok = ok && th_wait_int(&g_enter_count, 1, wait_ms);
        ok = ok && duct_atomic_load(&g_v1_frame_count, acquire) == 1
                && duct_atomic_load(&g_leave_count, acquire) == 1;

        /* Wire is now v2's TLS wire: LP framing no longer applies. */
        ok = ok && s_tls_handshake(fd) == 0;

        static const char app[] = "post-switch-app";
        ok = ok && s_send_app(fd, app, sizeof app - 1u) == 0;
        uint8_t decoded[64];
        size_t declen = 0u;
        ok = ok && s_recv_app(fd, decoded, sizeof decoded, &declen) == 0;
        ok = ok && declen == sizeof app - 1u && memcmp(decoded, app, declen) == 0;
        ok = ok && duct_atomic_load(&g_v2_frame_count, acquire) == 1
                && duct_atomic_load(&g_enter_count, acquire) == 1;

        if (fd != duct_sock_bad) close(fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(v1);
    duct_proto_destroy(v2);
    return ok;
}

/* ── Scenario 5: TLS -> cleartext, deferred-record drop ──── */

static atomic_int g_sc5_raced_seen = 0;
static _Atomic(const duct_proto_t *) g_sc5_target;

static duct_result_t
sc5_v1_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                const duct_frame_t *frame, duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_v1_frame_count, 1, release);
    static const char trigger[] = "switch2plain";
    if (frame->payload.size == sizeof trigger - 1u
        && memcmp(frame->payload.data, trigger, sizeof trigger - 1u) == 0) {
        auto next = duct_atomic_load(&g_sc5_target, acquire);
        return duct_response_switch(out, s, next, nullptr);
    }
    duct_atomic_store(&g_sc5_raced_seen, 1, release);
    duct_response_echo(out, frame);
    return rc_ok;
}

static duct_result_t
sc5_v2_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                const duct_frame_t *frame, duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_v2_frame_count, 1, release);
    duct_response_echo(out, frame);
    return rc_ok;
}

/** @brief The reverse STARTTLS switch (TLS -> cleartext), racing a second
 *  sealed record into the same io-thread batch as the switch trigger.
 *
 *  Both records are parsed together (one recv(), one duct_frame_rx_post
 *  pass), so both are tagged with the same sealed_epoch (duct_frame_rx.c's
 *  once-per-batch snapshot) and posted as one WFQ batch. The trigger's own
 *  dispatch runs duct_session_apply_switch synchronously — before
 *  s_dispatch_batch_frames's loop ever reaches the second frame — so the
 *  raced record is *guaranteed* to see s->wire_rebind_next already set and
 *  defer there (s_dispatch_frame's own in-flight-switch gate), never a
 *  timing race the way scenario 3's multi-leg one is. Once the switch's
 *  fence lands (bumping conn's wire_epoch) and the deferred record retries,
 *  it is stale by generation and is ack-and-dropped —
 *  never reaches sc5_v1_on_frame, never misrouted to sc5_v2_on_frame either.
 *  handler_dispatch_test.c's T15/T16/T18 already prove the ack byte-count
 *  precisely at the white-box level; this scenario proves the same outcome
 *  actually happens end to end, through a real proto_switch and real
 *  sockets, and that the conn survives with the new wire's traffic intact. */
static bool sc_tls_to_plain_drop(void)
{
    s_counters_reset();
    duct_atomic_store(&g_sc5_raced_seen, 0, relaxed);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto tls_wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = nullptr, .engine = tls_null_vtbl(),
            .engine_cfg = nullptr, .role = seal_role_responder,
            .framing = seal_framing_stream });
    auto lp_wire = duct_wire_create_length_prefix(0u);
    auto v1 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "wire-tls5", .wire = tls_wire, .on_frame = sc5_v1_on_frame,
        .on_proto_leave = s_on_leave,
    });
    auto v2 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "wire-plain5", .wire = lp_wire, .on_frame = sc5_v2_on_frame,
        .on_proto_enter = s_on_enter,
    });
    if (v1) v1->owned_wire = tls_wire; else duct_wire_destroy(tls_wire);
    if (v2) v2->owned_wire = lp_wire; else duct_wire_destroy(lp_wire);
    if (!v1 || !v2) {
        duct_proto_destroy(v1); duct_proto_destroy(v2); duct_engine_destroy(io);
        return false;
    }
    duct_atomic_store(&g_sc5_target, v2, release);

    unsigned create_before = tls_null_create_calls();
    unsigned destroy_before = tls_null_destroy_calls();

    uint16_t port = 0u;
    bool ok = duct_io_listen(io, "127.0.0.1", &port, v1) == rc_ok;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        duct_sock_t fd = th_connect(port);
        ok = fd != duct_sock_bad;
        ok = ok && s_tls_handshake(fd) == 0;

        uint8_t combined[512];
        static const char trigger[] = "switch2plain";
        static const char raced[] = "raced-payload";
        size_t len1 = s_build_app_record(combined, sizeof combined, trigger, sizeof trigger - 1u);
        size_t len2 = len1 ? s_build_app_record(combined + len1, sizeof combined - len1,
                                                raced, sizeof raced - 1u) : 0u;
        ok = ok && len1 > 0u && len2 > 0u
                && send(fd, (const char *)combined, (int)(len1 + len2), 0) == (int)(len1 + len2);

        ok = ok && th_wait_int(&g_enter_count, 1, wait_ms);
        /* Only the trigger ever reached v1's on_frame — the raced record,
         * deferred by the in-flight-switch gate, was dropped once its
         * retry found the generation already stale, never dispatched to
         * either proto. */
        ok = ok && duct_atomic_load(&g_v1_frame_count, acquire) == 1
                && duct_atomic_load(&g_sc5_raced_seen, acquire) == 0
                && duct_atomic_load(&g_leave_count, acquire) == 1;

        /* Conn survives, ring not stalled: ordinary traffic on the new
         * (cleartext) wire still flows. */
        static const char post[] = "post-switch-plain";
        ok = ok && th_send(fd, post, sizeof post - 1u) == 0
                && th_recv_eq(fd, post, sizeof post - 1u) == 0;
        ok = ok && duct_atomic_load(&g_v2_frame_count, acquire) == 1;

        if (fd != duct_sock_bad) close(fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(v1);
    duct_proto_destroy(v2);

    /* The old (TLS) codec: created for the handshake above, freed at the
     * wire fence once the switch lands (duct_session_exec_wire_fence) —
     * codec free at fence, leak-checked. */
    ok = ok && tls_null_create_calls() == create_before + 1u
            && tls_null_destroy_calls() == destroy_before + 1u;
    return ok;
}

/* ── Scenario 6: mid-handshake close, both directions ───────── */

static _Atomic(const duct_proto_t *) g_sc6a_target;

static duct_result_t
sc6a_v1_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                 [[maybe_unused]] const duct_frame_t *frame, duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_v1_frame_count, 1, release);
    auto next = duct_atomic_load(&g_sc6a_target, acquire);
    return duct_response_switch(out, s, next, nullptr);
}

static duct_result_t
sc6a_v2_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                 const duct_frame_t *frame, duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_v2_frame_count, 1, release);
    duct_response_echo(out, frame);
    return rc_ok;
}

/** @brief Peer-initiated direction: the client disconnects right after the
 *  switch lands, before ever sending its own handshake record. The codec
 *  exists by then (created eagerly at the wire fence, duct_worker_tls_ensure_started)
 *  but is unhandshook — conn_lost must free it cleanly, and the
 *  engine/worker must stay healthy for the next connection. */
static bool sc_tls_midhandshake_peer_close(void)
{
    s_counters_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto lp_wire = duct_wire_create_length_prefix(0u);
    auto tls_wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = nullptr, .engine = tls_null_vtbl(),
            .engine_cfg = nullptr, .role = seal_role_responder,
            .framing = seal_framing_stream });
    auto v1 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "wire-plain6a", .wire = lp_wire, .on_frame = sc6a_v1_on_frame,
        .on_proto_leave = s_on_leave,
    });
    auto v2 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "wire-tls6a", .wire = tls_wire, .on_frame = sc6a_v2_on_frame,
        .on_proto_enter = s_on_enter,
    });
    if (v1) v1->owned_wire = lp_wire; else duct_wire_destroy(lp_wire);
    if (v2) v2->owned_wire = tls_wire; else duct_wire_destroy(tls_wire);
    if (!v1 || !v2) {
        duct_proto_destroy(v1); duct_proto_destroy(v2); duct_engine_destroy(io);
        return false;
    }
    duct_atomic_store(&g_sc6a_target, v2, release);

    unsigned destroy_before = tls_null_destroy_calls();

    uint16_t port = 0u;
    bool ok = duct_io_listen(io, "127.0.0.1", &port, v1) == rc_ok;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        static const char trigger[] = "go-tls-mh1";

        duct_sock_t fd = th_connect(port);
        ok = fd != duct_sock_bad;
        ok = ok && th_send(fd, trigger, sizeof trigger - 1u) == 0;
        ok = ok && th_wait_int(&g_enter_count, 1, wait_ms);

        if (fd != duct_sock_bad) close(fd);
        ok = ok && s_wait_destroy_count(destroy_before + 1u, wait_ms);

        /* A fresh connection through the same switch must still work —
         * proves the abrupt mid-handshake peer close left the engine and
         * worker healthy, not wedged. */
        duct_sock_t fd2 = th_connect(port);
        ok = ok && fd2 != duct_sock_bad;
        ok = ok && th_send(fd2, trigger, sizeof trigger - 1u) == 0;
        ok = ok && th_wait_int(&g_enter_count, 2, wait_ms);
        ok = ok && s_tls_handshake(fd2) == 0;
        if (fd2 != duct_sock_bad) close(fd2);

        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(v1);
    duct_proto_destroy(v2);
    return ok;
}

static _Atomic(const duct_proto_t *) g_sc6b_target;

static duct_result_t
sc6b_v1_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                 [[maybe_unused]] const duct_frame_t *frame, duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_v1_frame_count, 1, release);
    auto next = duct_atomic_load(&g_sc6b_target, acquire);
    return duct_response_switch(out, s, next, nullptr);
}

static duct_result_t
sc6b_v2_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                 const duct_frame_t *frame, duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_v2_frame_count, 1, release);
    duct_response_echo(out, frame);
    return rc_ok;
}

/** @brief Protocol/server-initiated direction: on_proto_enter rejects the
 *  switch outright, forcing s_session_finish_switch's own error path
 *  (duct_session_close_walk, close_protocol_error) right as the TLS wire
 *  lands and its codec is created — before the peer ever gets a chance to
 *  send a handshake record. */
static duct_result_t
sc6b_v2_on_proto_enter([[maybe_unused]] duct_session_t *s, [[maybe_unused]] void *ctx,
                       [[maybe_unused]] void *proto_state)
{
    return rc_invalid_arg;
}

static bool sc_tls_midhandshake_protocol_close(void)
{
    s_counters_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto lp_wire = duct_wire_create_length_prefix(0u);
    auto tls_wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = nullptr, .engine = tls_null_vtbl(),
            .engine_cfg = nullptr, .role = seal_role_responder,
            .framing = seal_framing_stream });
    auto v1 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "wire-plain6b", .wire = lp_wire, .on_frame = sc6b_v1_on_frame,
        .on_proto_leave = s_on_leave,
    });
    auto v2 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "wire-tls6b", .wire = tls_wire, .on_frame = sc6b_v2_on_frame,
        .on_proto_enter = sc6b_v2_on_proto_enter,
    });
    if (v1) v1->owned_wire = lp_wire; else duct_wire_destroy(lp_wire);
    if (v2) v2->owned_wire = tls_wire; else duct_wire_destroy(tls_wire);
    if (!v1 || !v2) {
        duct_proto_destroy(v1); duct_proto_destroy(v2); duct_engine_destroy(io);
        return false;
    }
    duct_atomic_store(&g_sc6b_target, v2, release);

    unsigned destroy_before = tls_null_destroy_calls();

    uint16_t port = 0u;
    bool ok = duct_io_listen(io, "127.0.0.1", &port, v1) == rc_ok;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        duct_sock_t fd = th_connect(port);
        ok = fd != duct_sock_bad;
        static const char trigger[] = "go-tls-mh2";
        ok = ok && th_send(fd, trigger, sizeof trigger - 1u) == 0;

        /* on_proto_enter's rejection closes the session before the client
         * ever gets a chance to send a handshake record — expect a clean
         * disconnect (EOF), not a hang. */
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        ok = ok && poll(&pfd, 1, (int)wait_ms) > 0;
        char buf[4];
        ok = ok && recv(fd, buf, sizeof buf, 0) == 0;
        ok = ok && s_wait_destroy_count(destroy_before + 1u, wait_ms);
        /* v1's own leave phase still ran (s_session_finish_switch tears
         * down old streams / disposes old proto_state before the enter
         * call that rejected it); the switch itself never commits. */
        ok = ok && duct_atomic_load(&g_leave_count, acquire) == 1
                && duct_atomic_load(&g_enter_count, acquire) == 0;

        if (fd != duct_sock_bad) close(fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(v1);
    duct_proto_destroy(v2);
    return ok;
}

/* ── Scenario 7: close_notify observed by peer, after STARTTLS ── */

static _Atomic(const duct_proto_t *) g_sc7_target;

static duct_result_t
sc7_v1_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                [[maybe_unused]] const duct_frame_t *frame, duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_v1_frame_count, 1, release);
    auto next = duct_atomic_load(&g_sc7_target, acquire);
    return duct_response_switch(out, s, next, nullptr);
}

static duct_result_t
sc7_v2_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
                const duct_frame_t *frame, duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_v2_frame_count, 1, release);
    static const char bye[] = "bye";
    if (frame->payload.size == sizeof bye - 1u
        && memcmp(frame->payload.data, bye, sizeof bye - 1u) == 0) {
        duct_response_close_session(out, close_normal);
        return rc_ok;
    }
    duct_response_echo(out, frame);
    return rc_ok;
}

static bool sc_tls_close_notify(void)
{
    s_counters_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto lp_wire = duct_wire_create_length_prefix(0u);
    auto tls_wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = nullptr, .engine = tls_null_vtbl(),
            .engine_cfg = nullptr, .role = seal_role_responder,
            .framing = seal_framing_stream });
    auto v1 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "wire-plain7", .wire = lp_wire, .on_frame = sc7_v1_on_frame,
        .on_proto_leave = s_on_leave,
    });
    auto v2 = duct_proto_create(&(duct_proto_cfg_t){
        .name = "wire-tls7", .wire = tls_wire, .on_frame = sc7_v2_on_frame,
        .on_proto_enter = s_on_enter,
    });
    if (v1) v1->owned_wire = lp_wire; else duct_wire_destroy(lp_wire);
    if (v2) v2->owned_wire = tls_wire; else duct_wire_destroy(tls_wire);
    if (!v1 || !v2) {
        duct_proto_destroy(v1); duct_proto_destroy(v2); duct_engine_destroy(io);
        return false;
    }
    duct_atomic_store(&g_sc7_target, v2, release);

    unsigned close_notify_before = tls_null_close_notify_calls();

    uint16_t port = 0u;
    bool ok = duct_io_listen(io, "127.0.0.1", &port, v1) == rc_ok;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        duct_sock_t fd = th_connect(port);
        ok = fd != duct_sock_bad;
        static const char trigger[] = "go-tls-cn";
        ok = ok && th_send(fd, trigger, sizeof trigger - 1u) == 0;
        ok = ok && th_wait_int(&g_enter_count, 1, wait_ms);
        ok = ok && s_tls_handshake(fd) == 0;

        static const char bye[] = "bye";
        ok = ok && s_send_app(fd, bye, sizeof bye - 1u) == 0;

        uint8_t type = 0u, body[8] = {};
        size_t blen = 0u;
        ok = ok && s_recv_record(fd, &type, body, sizeof body, &blen) == 0;
        ok = ok && type == 3u && blen == 1u && body[0] == tls_null_close_notify_marker;
        ok = ok && tls_null_close_notify_calls() == close_notify_before + 1u;

        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        ok = ok && poll(&pfd, 1, (int)wait_ms) > 0;
        char buf[4];
        ok = ok && recv(fd, buf, sizeof buf, 0) == 0;

        if (fd != duct_sock_bad) close(fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    duct_engine_destroy(io);
    duct_proto_destroy(v1);
    duct_proto_destroy(v2);
    return ok;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    int pass = 1;

    if (!sc_raw_to_lp())  { fprintf(stderr, "wire_change: raw_to_lp failed\n"); pass = 0; }
    if (!sc_lp_resize())  { fprintf(stderr, "wire_change: lp_resize failed\n"); pass = 0; }
    if (!sc_lp_resize_fin()) { fprintf(stderr, "wire_change: lp_resize_fin failed\n"); pass = 0; }
    if (!sc_lp_to_mux())  { fprintf(stderr, "wire_change: lp_to_mux failed\n"); pass = 0; }
    if (!sc_multi_leg())  { fprintf(stderr, "wire_change: multi_leg failed\n"); pass = 0; }
    if (!sc_plain_to_tls())                   { fprintf(stderr, "wire_change: plain_to_tls failed\n"); pass = 0; }
    if (!sc_tls_to_plain_drop())               { fprintf(stderr, "wire_change: tls_to_plain_drop failed\n"); pass = 0; }
    if (!sc_tls_midhandshake_peer_close())     { fprintf(stderr, "wire_change: tls_midhandshake_peer_close failed\n"); pass = 0; }
    if (!sc_tls_midhandshake_protocol_close()) { fprintf(stderr, "wire_change: tls_midhandshake_protocol_close failed\n"); pass = 0; }
    if (!sc_tls_close_notify())                { fprintf(stderr, "wire_change: tls_close_notify failed\n"); pass = 0; }

    /* codec free at fence, leak-checked
     * across every scenario above, not just the one that names it. */
    if (tls_null_create_calls() != tls_null_destroy_calls()) {
        fprintf(stderr, "wire_change: tls codec create/destroy mismatch (create=%u destroy=%u)\n",
                tls_null_create_calls(), tls_null_destroy_calls());
        pass = 0;
    }

    if (pass) {
        printf("wire_change: OK (raw->LP switch, LP resize + partial discard, "
               "multi-leg fan-out with race-safe dispatch gate, STARTTLS both "
               "directions with deferred-record drop, mid-handshake close both "
               "directions, close_notify after switch)\n");
        return 0;
    }
    return 1;
}
