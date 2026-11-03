/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file dgram_peer_roam_test.c
 * @brief A per-peer UDP leg follows its client to a new address, on the
 * protocol's word and nobody else's.
 *
 * A preparse joins any source address to the one live session — on a CID for
 * the plain wire, on the session alone for the sealed one, where nothing is
 * readable under seal — so a second socket reaches an existing leg by design.
 * What the engine owes is the split: the new address routes inbound at once,
 * while the socket replies leave on moves only once on_frame accepts a frame
 * whose ring span reaches the datagram that proposed the address.
 *
 * rejected_does_not_move is the case that pins it. A datagram the protocol
 * rejects leaves a candidate address recorded; the legitimate client then
 * sends from where it always was, and its acceptance must not be what adopts
 * the rejected address.
 *
 * The two earlier_accept cases pin the ordering the span comparison exists
 * for: a handler parked inside on_frame holds an accepted frame while a probe
 * from the second address plants its candidate behind it, and on release that
 * older accept must not carry the candidate. The sealed one runs the same
 * shape over a datagram-framed sealed wire with a broken-tag record as the
 * probe — there the unseal acks the ring before on_frame runs at all, so the
 * ring frontier proves nothing and the accepted record's own offset decides.
 * sealed_roam_follows is that pair's positive control.
 *
 * The move is eventual rather than immediate: a compaction of the RX ring
 * resets the dispatch frontier io confirms against, which costs a retry on the
 * next accepted frame. Each case therefore drives several exchanges and
 * requires the reply to arrive at the new address within them.
 */

#include "duct.h"
#include "duct_wire.h"
#include "tls_engine_null.h"

#include <stdatomic.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "test_helpers.h"
#include "dgram_test_helpers.h"

static constexpr uint32_t k_cid     = 0x0DDBA11u;
static constexpr unsigned wait_ms   = 5000u;
static constexpr int      settle_ms = 100;
static constexpr size_t   msg_size  = 8u;

static atomic_bool g_open       = false;
static atomic_int  g_open_count = 0;
static atomic_int  g_join_count = 0;
static atomic_int  g_rejected   = 0;
static atomic_int  g_errors     = 0;
static _Atomic duct_handle_t g_tok;

/** @brief Handshake between a test and the worker it parks inside on_frame.
 *  The test arms with @c hold_off, the handler answers @c hold_parked once it
 *  holds the frame, and @c hold_released lets it return.
 */
enum {
    hold_off = 0,
    hold_parked,
    hold_released,
};

static atomic_int g_hold = hold_off;

static void s_reset(void)
{
    duct_atomic_store(&g_open, false, release);
    duct_atomic_store(&g_open_count, 0, release);
    duct_atomic_store(&g_join_count, 0, release);
    duct_atomic_store(&g_rejected, 0, release);
    duct_atomic_store(&g_errors, 0, release);
    duct_atomic_store(&g_hold, hold_off, release);
}

static duct_result_t
on_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok,
        [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
        [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_tok, tok, release);
    duct_atomic_store(&g_open, true, release);
    duct_atomic_fetch(add, &g_open_count, 1, relaxed);
    return rc_ok;
}

static duct_result_t
on_join([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
        [[maybe_unused]] const duct_peer_t *peer, [[maybe_unused]] duct_response_t *out,
        [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_join_count, 1, release);
    return rc_ok;
}

static duct_result_t
on_dgram([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame, duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    auto body = (const char *)frame->payload.data;
    if (frame->payload.size > sizeof(uint32_t) && body[sizeof(uint32_t)] == 'h') {
        duct_atomic_store(&g_hold, hold_parked, release);
        for (unsigned waited = 0u;
             waited < wait_ms && duct_atomic_load(&g_hold, acquire) != hold_released;
             waited += 10u)
            th_sleep_ms(10u);
        return rc_ok;
    }
    if (frame->payload.size > sizeof(uint32_t) && body[sizeof(uint32_t)] == 's') {
        duct_atomic_fetch(add, &g_rejected, 1, release);
        return rc_invalid_arg;
    }
    duct_response_same(out, frame->payload, fl_send_copy, 0);
    return rc_ok;
}

static duct_resolve_disposition_t
preparse([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer,
         duct_view_u8 peek, duct_handle_t *out_tok,
         duct_conn_id_t *out_conn_id, [[maybe_unused]] void **out_user_ctx,
         [[maybe_unused]] size_t *out_lead)
{
    if (peek.size < sizeof(uint32_t))
        return resolve_reject;
    uint32_t cid;
    memcpy(&cid, peek.data, sizeof cid);
    if (cid != k_cid)
        return resolve_reject;
    if (!duct_atomic_load(&g_open, acquire))
        return resolve_new;
    *out_tok = duct_atomic_load(&g_tok, acquire);
    *out_conn_id = duct_conn_id_primary;
    return resolve_join;
}

static duct_resolve_disposition_t
preparse_sealed([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer,
                [[maybe_unused]] duct_view_u8 peek, duct_handle_t *out_tok,
                duct_conn_id_t *out_conn_id, [[maybe_unused]] void **out_user_ctx,
                [[maybe_unused]] size_t *out_lead)
{
    if (!duct_atomic_load(&g_open, acquire))
        return resolve_new;
    *out_tok = duct_atomic_load(&g_tok, acquire);
    *out_conn_id = duct_conn_id_primary;
    return resolve_join;
}

static duct_result_t
on_error([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_result_t error,
         [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_errors, 1, release);
    return rc_ok;
}

static void s_msg(uint8_t *out, char kind)
{
    memcpy(out, &k_cid, sizeof k_cid);
    memset(out + sizeof k_cid, kind, msg_size - sizeof k_cid);
}

/** @brief One tls_null record carrying @p ct, sent on @p fd.
 *  @p forge flips a tag bit, which is the shape that reaches the engine's
 *  unseal and fails it — the leg is past its handshake by then, so the record
 *  is application data and the tag is checked for real.
 */
static int s_send_sealed(duct_sock_t fd, const void *ct, size_t ct_len, bool forge)
{
    uint8_t sealed[128],
            rec[duct_tls_record_hdr_size + sizeof sealed];
    size_t len = tls_null_seal(ct, ct_len, sealed, sizeof sealed);
    if (!len)
        return -1;
    if (forge)
        sealed[len - 1u] ^= 0xFFu;
    size_t n = tls_null_record(rec, 2u, sealed, len);
    return uc_send(fd, rec, n);
}

static int s_recv_sealed_eq(duct_sock_t fd, const void *expected, size_t elen)
{
    char buf[512];
    ssize_t n = uc_recv(fd, buf, sizeof buf);
    if (n < (ssize_t)duct_tls_record_hdr_size)
        return -1;
    uint8_t ct[256];
    size_t got = tls_null_unseal_body((const uint8_t *)buf + duct_tls_record_hdr_size,
                                      (size_t)n - duct_tls_record_hdr_size, ct, sizeof ct);
    if (got == SIZE_MAX || got != elen)
        return -1;
    return memcmp(ct, expected, elen) == 0 ? 0 : -1;
}

typedef struct {
    duct_engine_t *io;
    duct_proto_t  *proto;
    pthread_t      th;
    bool           running;
    uint16_t       port;
} s_fixture_t;

static const char *s_fixture_up(s_fixture_t *f, unsigned n_threads, bool sealed)
{
    s_reset();
    *f = (s_fixture_t){};
    f->io = duct_engine_launch(&(duct_engine_cfg_t){
        .io_threads = n_threads, .workers = n_threads });
    if (!f->io)
        return "io create failed";
    auto wire = sealed
        ? duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
              .inner = nullptr, .engine = tls_null_vtbl(),
              .role = seal_role_responder, .framing = seal_framing_datagram })
        : duct_wire_create_dgram_batch(0u, false);
    f->proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "dgram-roam", .wire = wire,
        .on_frame = on_dgram, .on_session_open = on_open, .on_conn_join = on_join,
        .on_error = sealed ? on_error : nullptr,
        .preparse = sealed ? preparse_sealed : preparse,
        .preparse_mode = resolve_sync,
        .max_response = 4096u,
    }) : nullptr;
    if (f->proto)
        f->proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!f->proto)
        return "proto create failed";
    const duct_proto_t *protos[1] = { f->proto };
    if (duct_listener_bind(f->io, &(duct_listener_cfg_t){ .kind = listener_dgram,
            .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
        }, &f->port, nullptr, 0u, nullptr) != rc_ok)
        return "bind failed";
    if (pthread_create(&f->th, nullptr, th_run, f->io) != 0)
        return "thread create failed";
    f->running = true;
    return nullptr;
}

static void s_fixture_down(s_fixture_t *f)
{
    if (f->running) {
        duct_engine_stop(f->io);
        pthread_join(f->th, nullptr);
    }
    if (f->io)
        duct_engine_destroy(f->io);
    if (f->proto)
        duct_proto_destroy(f->proto);
}

static const char *s_open_session(duct_sock_t fd)
{
    uint8_t msg[msg_size];
    s_msg(msg, 'g');
    if (uc_send(fd, msg, sizeof msg) != 0
        || uc_recv_eq(fd, (const char *)msg, sizeof msg) != 0)
        return "the first address was not echoed";
    if (!th_wait_int(&g_open_count, 1, wait_ms))
        return "no session opened";
    return nullptr;
}

/** @brief Frames one roam takes. The accepting frame's own reply still leaves
 *  on the old address, so the move shows from the next frame on — measured,
 *  not guessed: one round never completes a roam and two always do. */
static constexpr int roam_rounds = 2;

/** @brief Source addresses sc_foreign_io_thread_drops samples, enough that the
 *  kernel's SO_REUSEPORT hash reaches both io threads. */
static constexpr int probe_ports = 8;

static const char *s_roam_to(duct_sock_t fd, uint8_t *msg, const char *stuck)
{
    char back[64];
    for (int round = 0; round < roam_rounds; ++round) {
        s_msg(msg, 'g');
        if (uc_send(fd, msg, msg_size) != 0)
            return "roaming send failed";
        if (uc_recv(fd, back, sizeof back) == (ssize_t)msg_size
            && memcmp(back, msg, msg_size) == 0)
            return nullptr;
    }
    return stuck;
}

static const char *sc_roam_follows(void)
{
    s_fixture_t f;
    auto err = s_fixture_up(&f, 1u, false);
    duct_sock_t fd1 = duct_sock_bad, fd2 = duct_sock_bad;
    uint8_t msg[msg_size];

    if (!err && (fd1 = uc_connect(f.port)) == duct_sock_bad)
        err = "first socket connect failed";
    if (!err)
        err = s_open_session(fd1);
    if (!err && (fd2 = uc_connect(f.port)) == duct_sock_bad)
        err = "second socket connect failed";
    if (!err)
        err = s_roam_to(fd2, msg, "the reply path never followed the client to its new address");
    if (!err && duct_atomic_load(&g_open_count, acquire) != 1)
        err = "the roaming client opened a second session";
    if (!err && duct_atomic_load(&g_join_count, acquire) != 0)
        err = "the roaming client joined a second leg";

    if (fd1 != duct_sock_bad) close(fd1);
    if (fd2 != duct_sock_bad) close(fd2);
    s_fixture_down(&f);
    return err;
}

static const char *sc_rejected_does_not_move(void)
{
    s_fixture_t f;
    auto err = s_fixture_up(&f, 1u, false);
    duct_sock_t fd1 = duct_sock_bad, fd2 = duct_sock_bad;
    uint8_t msg[msg_size];

    if (!err && (fd1 = uc_connect(f.port)) == duct_sock_bad)
        err = "first socket connect failed";
    if (!err)
        err = s_open_session(fd1);
    if (!err && (fd2 = uc_connect(f.port)) == duct_sock_bad)
        err = "second socket connect failed";

    if (!err) {
        s_msg(msg, 's');
        if (uc_send(fd2, msg, sizeof msg) != 0)
            err = "spoofed send failed";
        else if (!th_wait_int(&g_rejected, 1, wait_ms))
            err = "the spoofed datagram never reached the session";
    }
    if (!err) {
        s_msg(msg, 'g');
        if (uc_send(fd1, msg, sizeof msg) != 0)
            err = "send from the original address failed";
        else if (uc_recv_eq(fd1, (const char *)msg, sizeof msg) != 0)
            err = "a rejected datagram redirected the session's replies";
    }
    if (!err && uc_recv_none(fd2, 300) != 0)
        err = "the rejecting path answered the spoofed address";

    if (fd1 != duct_sock_bad) close(fd1);
    if (fd2 != duct_sock_bad) close(fd2);
    s_fixture_down(&f);
    return err;
}

static const char *sc_roam_back(void)
{
    s_fixture_t f;
    auto err = s_fixture_up(&f, 1u, false);
    duct_sock_t fd1 = duct_sock_bad, fd2 = duct_sock_bad;
    uint8_t msg[msg_size];

    if (!err && (fd1 = uc_connect(f.port)) == duct_sock_bad)
        err = "first socket connect failed";
    if (!err)
        err = s_open_session(fd1);
    if (!err && (fd2 = uc_connect(f.port)) == duct_sock_bad)
        err = "second socket connect failed";
    if (!err)
        err = s_roam_to(fd2, msg, "the reply path never reached the second address");
    if (!err)
        err = s_roam_to(fd1, msg, "the reply path never came back to the first address");
    if (!err && duct_atomic_load(&g_open_count, acquire) != 1)
        err = "roaming back and forth opened more than one session";

    if (fd1 != duct_sock_bad) close(fd1);
    if (fd2 != duct_sock_bad) close(fd2);
    s_fixture_down(&f);
    return err;
}

/** @brief Two io threads, so a datagram from a fresh source address reaches
 *  whichever listener the kernel's SO_REUSEPORT hash picks — half of them the
 *  one that does not own the leg. Probes are the rejected kind, so no roam
 *  completes and the original address stays the session's: what this pins is
 *  that a foreign-thread probe changes nothing at all, and the case is the
 *  TSAN vehicle for the cross-thread ring write it used to cause. */
static const char *sc_rejected_rides_no_earlier_accept(void)
{
    s_fixture_t f;
    auto err = s_fixture_up(&f, 1u, false);
    duct_sock_t fd1 = duct_sock_bad, fd2 = duct_sock_bad;
    uint8_t good[msg_size], spoof[msg_size];

    if (!err && (fd1 = uc_connect(f.port)) == duct_sock_bad)
        err = "first socket connect failed";
    if (!err)
        err = s_open_session(fd1);
    if (!err && (fd2 = uc_connect(f.port)) == duct_sock_bad)
        err = "second socket connect failed";

    s_msg(good, 'g');
    s_msg(spoof, 's');
    for (int round = 0; !err && round < probe_ports; ++round) {
        if (uc_send(fd1, good, sizeof good) != 0
            || uc_send(fd2, spoof, sizeof spoof) != 0) {
            err = "paired send failed";
            break;
        }
        if (uc_recv_eq(fd1, (const char *)good, sizeof good) != 0)
            err = "a rejected address took the reply an earlier accept paid for";
        else if (uc_recv_none(fd2, 100) != 0)
            err = "the rejected address was answered";
    }

    if (fd1 != duct_sock_bad) close(fd1);
    if (fd2 != duct_sock_bad) close(fd2);
    s_fixture_down(&f);
    return err;
}

/** @brief The accepted frame that precedes a candidate must not adopt it.
 *  A kind-'h' frame parks the single worker inside on_frame, so the probe
 *  lands in the ring behind a frame already accepted; the reply path must
 *  still be the first address once both are dispatched.
 */
static const char *sc_earlier_accept_does_not_ride_a_candidate(void)
{
    s_fixture_t f;
    auto err = s_fixture_up(&f, 1u, false);
    duct_sock_t fd1 = duct_sock_bad, fd2 = duct_sock_bad;
    uint8_t held[msg_size], spoof[msg_size], good[msg_size];

    if (!err && (fd1 = uc_connect(f.port)) == duct_sock_bad)
        err = "first socket connect failed";
    if (!err)
        err = s_open_session(fd1);
    if (!err && (fd2 = uc_connect(f.port)) == duct_sock_bad)
        err = "second socket connect failed";

    s_msg(held, 'h');
    s_msg(spoof, 's');
    s_msg(good, 'g');
    for (int round = 0; !err && round < probe_ports; ++round) {
        duct_atomic_store(&g_hold, hold_off, release);
        if (uc_send(fd1, held, sizeof held) != 0)
            err = "the held send from the original address failed";
        else if (!th_wait_int(&g_hold, hold_parked, wait_ms))
            err = "the frame from the original address never reached the handler";
        else if (uc_send(fd2, spoof, sizeof spoof) != 0)
            err = "spoofed send failed";
        else if (uc_recv_none(fd2, settle_ms) != 0)
            err = "the candidate address was answered before any accept";
        if (err)
            break;
        duct_atomic_store(&g_hold, hold_released, release);
        if (!th_wait_int(&g_rejected, round + 1, wait_ms))
            err = "the spoofed datagram never reached the session";
        else if (uc_recv_none(fd2, settle_ms) != 0)
            err = "the rejected address was answered";
        else if (uc_send(fd1, good, sizeof good) != 0
                 || uc_recv_eq(fd1, (const char *)good, sizeof good) != 0)
            err = "an accept from before the candidate carried it";
    }

    duct_atomic_store(&g_hold, hold_released, release);
    if (fd1 != duct_sock_bad) close(fd1);
    if (fd2 != duct_sock_bad) close(fd2);
    s_fixture_down(&f);
    return err;
}

static const char *sc_foreign_io_thread_drops(void)
{
    s_fixture_t f;
    auto err = s_fixture_up(&f, 2u, false);
    duct_sock_t fd1 = duct_sock_bad,
                probes[probe_ports];
    uint8_t msg[msg_size];

    for (int i = 0; i < probe_ports; ++i)
        probes[i] = duct_sock_bad;
    if (!err && (fd1 = uc_connect(f.port)) == duct_sock_bad)
        err = "first socket connect failed";
    if (!err)
        err = s_open_session(fd1);

    for (int i = 0; !err && i < probe_ports; ++i) {
        if ((probes[i] = uc_connect(f.port)) == duct_sock_bad) {
            err = "probe socket connect failed";
            break;
        }
        s_msg(msg, 's');
        if (uc_send(probes[i], msg, sizeof msg) != 0)
            err = "probe send failed";
    }
    for (int i = 0; !err && i < probe_ports; ++i)
        if (uc_recv_none(probes[i], 100) != 0)
            err = "a rejected probe was answered at its own address";
    if (!err) {
        s_msg(msg, 'g');
        if (uc_send(fd1, msg, sizeof msg) != 0)
            err = "send from the original address failed";
        else if (uc_recv_eq(fd1, (const char *)msg, sizeof msg) != 0)
            err = "the session stopped answering its original address";
    }
    if (!err && duct_atomic_load(&g_open_count, acquire) != 1)
        err = "a probe opened a second session";

    for (int i = 0; i < probe_ports; ++i)
        if (probes[i] != duct_sock_bad) close(probes[i]);
    if (fd1 != duct_sock_bad) close(fd1);
    s_fixture_down(&f);
    return err;
}

static const char *s_open_sealed_session(duct_sock_t fd)
{
    uint8_t rec[duct_tls_record_hdr_size + 4u];
    size_t n = tls_null_record(rec, 1u, "helo", 4u);
    if (uc_send(fd, rec, n) != 0)
        return "the handshake datagram send failed";
    if (!th_wait_int(&g_open_count, 1, wait_ms))
        return "no sealed session opened";
    char buf[64];
    ssize_t got = uc_recv(fd, buf, sizeof buf);
    if (got != (ssize_t)(duct_tls_record_hdr_size + sizeof tls_null_server_hello)
        || memcmp(buf + duct_tls_record_hdr_size, tls_null_server_hello,
                  sizeof tls_null_server_hello) != 0)
        return "the handshake reply did not reach the first address";
    return nullptr;
}

static const char *s_sealed_roam_to(duct_sock_t fd, const char *stuck)
{
    uint8_t good[msg_size];
    s_msg(good, 'g');
    for (int round = 0; round < roam_rounds; ++round) {
        if (s_send_sealed(fd, good, sizeof good, false) != 0)
            return "roaming sealed send failed";
        if (s_recv_sealed_eq(fd, good, sizeof good) == 0)
            return nullptr;
    }
    return stuck;
}

/** @brief A sealed leg follows its client, the unseal being the acceptance.
 *  Same two-round shape as sc_roam_follows, over tls_null under
 *  seal_framing_datagram.
 */
static const char *sc_sealed_roam_follows(void)
{
    s_fixture_t f;
    auto err = s_fixture_up(&f, 1u, true);
    duct_sock_t fd1 = duct_sock_bad, fd2 = duct_sock_bad;

    if (!err && (fd1 = uc_connect(f.port)) == duct_sock_bad)
        err = "first socket connect failed";
    if (!err)
        err = s_open_sealed_session(fd1);
    if (!err && (fd2 = uc_connect(f.port)) == duct_sock_bad)
        err = "second socket connect failed";
    if (!err)
        err = s_sealed_roam_to(fd2, "the reply path never followed the sealed client "
                                    "to its new address");
    if (!err && duct_atomic_load(&g_open_count, acquire) != 1)
        err = "the roaming sealed client opened a second session";

    if (fd1 != duct_sock_bad) close(fd1);
    if (fd2 != duct_sock_bad) close(fd2);
    s_fixture_down(&f);
    return err;
}

/** @brief The sealed half of the same ordering.
 *  The probe fails its tag check, so it never reaches on_frame at all and
 *  on_error is what says it was processed — the ring is acked either way, at
 *  unseal, which is why the record's own offset is the only thing left to
 *  compare.
 */
static const char *sc_sealed_earlier_accept_does_not_ride_a_candidate(void)
{
    s_fixture_t f;
    auto err = s_fixture_up(&f, 1u, true);
    duct_sock_t fd1 = duct_sock_bad, fd2 = duct_sock_bad;
    uint8_t held[msg_size], good[msg_size];

    if (!err && (fd1 = uc_connect(f.port)) == duct_sock_bad)
        err = "first socket connect failed";
    if (!err)
        err = s_open_sealed_session(fd1);
    if (!err && (fd2 = uc_connect(f.port)) == duct_sock_bad)
        err = "second socket connect failed";

    s_msg(held, 'h');
    s_msg(good, 'g');
    for (int round = 0; !err && round < probe_ports; ++round) {
        duct_atomic_store(&g_hold, hold_off, release);
        if (s_send_sealed(fd1, held, sizeof held, false) != 0)
            err = "the held sealed send from the original address failed";
        else if (!th_wait_int(&g_hold, hold_parked, wait_ms))
            err = "the sealed frame from the original address never reached the handler";
        else if (s_send_sealed(fd2, good, sizeof good, true) != 0)
            err = "forged sealed send failed";
        else if (uc_recv_none(fd2, settle_ms) != 0)
            err = "the candidate address was answered before any unseal";
        if (err)
            break;
        duct_atomic_store(&g_hold, hold_released, release);
        if (!th_wait_int(&g_errors, round + 1, wait_ms))
            err = "the forged record never reached the unseal";
        else if (uc_recv_none(fd2, settle_ms) != 0)
            err = "the forged address was answered";
        else if (s_send_sealed(fd1, good, sizeof good, false) != 0
                 || s_recv_sealed_eq(fd1, good, sizeof good) != 0)
            err = "an unseal from before the candidate carried it";
    }

    duct_atomic_store(&g_hold, hold_released, release);
    if (fd1 != duct_sock_bad) close(fd1);
    if (fd2 != duct_sock_bad) close(fd2);
    s_fixture_down(&f);
    return err;
}

static int s_report(const char *name, const char *err)
{
    printf("dgram_peer_roam: %s: %s%s\n", name, err ? "FAIL: " : "OK", err ? err : "");
    return err == nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    int pass = 1;
    pass &= s_report("roam_follows", sc_roam_follows());
    pass &= s_report("rejected_does_not_move", sc_rejected_does_not_move());
    pass &= s_report("roam_back", sc_roam_back());
    pass &= s_report("rejected_rides_no_earlier_accept", sc_rejected_rides_no_earlier_accept());
    pass &= s_report("earlier_accept_does_not_ride_a_candidate",
                     sc_earlier_accept_does_not_ride_a_candidate());
    pass &= s_report("foreign_io_thread_drops", sc_foreign_io_thread_drops());
    pass &= s_report("sealed_roam_follows", sc_sealed_roam_follows());
    pass &= s_report("sealed_earlier_accept_does_not_ride_a_candidate",
                     sc_sealed_earlier_accept_does_not_ride_a_candidate());

    if (!pass) {
        fprintf(stderr, "dgram_peer_roam: one or more cases failed\n");
        return 1;
    }
    printf("dgram_peer_roam: OK (a per-peer leg follows its client, on the protocol's word)\n");
    return 0;
}
