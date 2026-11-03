/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file dgram_shared_test.c
 * @brief a CID-keyed protocol whose peer address
 * changes mid-session (connection migration). Two scenarios share one
 * preparse (CID lookup, `resolve_new` the first time a CID is seen,
 * `resolve_join` at the session's own primary conn_id every time after):
 *
 * - `fl_proto_dgram_shared` unset (2a, plain per-peer socket): migration is
 *   expected to FAIL — the second address's `resolve_join` targets an
 *   already-occupied primary slot, which `duct_session_exec_conn_join`
 *   rejects outright (src/session/duct_session.c). Proves the scenario is
 *   real, not a test artifact that would pass regardless.
 * - `fl_proto_dgram_shared` set (2b, `x_udp_shared`): the same "occupied
 *   slot" case is handled in `s_classify_dgram` as the migration path —
 *   routes into the already-live conn, re-aliases the new address in
 *   dgram_peers, and TX (via the conn's own dgram_tx_outbox) follows the
 *   peer's latest known address. Migration succeeds, and a stale first
 *   address gets no further replies.
 *
 * Also covers the review findings fixed alongside this test:
 * bind-time rejection of a max_response
 * that cannot fit one dgram_tx_outbox reserve, listener-close tearing
 * down a live x_udp_shared conn on every platform, not Windows-only,
 * and — test_mux_shared below — a multiplexed wire yielding several
 * frames from one datagram (folded in here rather than a separate file,
 * same as the migration scenarios above already share this file's
 * proto/preparse plumbing).
 *
 * @ref sc_queued_burst_order joins them for the RX slot pool: several
 * datagrams with no drain between them is the one traffic shape that runs the
 * io side out of slots and makes it fall back to copying mid-burst.
 */

#include "duct.h"
#include "duct_wire.h"

#include <stdatomic.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "test_helpers.h"
#include "dgram_test_helpers.h"

static constexpr uint32_t k_cid = 0xC1D0BEEFu;
static constexpr int migrate_wait_ms = 300;

static _Atomic(duct_handle_t) g_tok;
static atomic_bool g_open = false;
static atomic_int g_open_count = 0;
static atomic_int g_close_count = 0;

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

/** @brief Terminal-close counter — the direct signal that an x_udp_shared
 * conn was actually torn down (fence cascade ran, on_session_close fired),
 * as opposed to merely "the client sees no more replies," which is equally
 * true for a genuinely closed conn and for a zombie the R-4 bug used to
 * leave behind on Linux: once the listener's own socket is gone, nothing
 * ever reaches a zombie conn either, so silence alone cannot tell the two
 * apart (@ref sc_listener_close_orphans_shared). */
static void
on_close([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_close_reason_t reason,
         [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_close_count, 1, relaxed);
}

static duct_result_t
on_dgram([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame, duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_response_same(out, frame->payload, fl_send_copy, 0);
    return rc_ok;
}

/** @brief CID-keyed identity, independent of source address by design: the
 * first datagram carrying k_cid opens a session; every later one, from any
 * address, joins the same session's own primary leg — deliberately not
 * inferred from anything but this explicit lookup. */
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

static void s_reset(void)
{
    duct_atomic_store(&g_open, false, relaxed);
    duct_atomic_store(&g_open_count, 0, relaxed);
    duct_atomic_store(&g_close_count, 0, relaxed);
    duct_handle_t zero = {};
    duct_atomic_store(&g_tok, zero, relaxed);
}

/** @brief One run of the migration scenario: fd1 opens the session, fd2
 * ("migrated" — a distinct source address, same CID) continues it. @p shared
 * selects `fl_proto_dgram_shared` (2b, expected to succeed) vs plain (2a,
 * expected to fail — the occupied-slot join is rejected). */
static bool s_run(bool shared, bool *out_migrated_ok)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto wire = duct_wire_create_dgram_batch(0u, false);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "dgram-shared", .wire = wire,
        .on_frame = on_dgram, .on_session_open = on_open, .on_session_close = on_close,
        .preparse = preparse, .preparse_mode = resolve_sync,
        /* fl_proto_dgram_shared must fit one dgram_tx_outbox reserve
         * (R-2) — well under that ceiling is plenty for this test's own
         * tiny payloads; the plain-2a run reuses the same value for an
         * apples-to-apples comparison. */
        .max_response = 4096u,
        .flags = shared ? fl_proto_dgram_shared : fl_proto_none,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    if (!proto) { duct_engine_destroy(io); return false; }

    const duct_proto_t *protos[1] = { proto };
    uint16_t port = 0u;
    bool ok = duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
                  .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
              }, &port, nullptr, 0u, nullptr) == rc_ok;

    pthread_t th;
    duct_sock_t fd1 = duct_sock_bad, fd2 = duct_sock_bad;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        fd1 = uc_connect(port);
        uint8_t m1[8];
        memcpy(m1, &k_cid, 4u); memcpy(m1 + 4, "aaaa", 4u);
        ok = fd1 != duct_sock_bad && uc_send(fd1, m1, sizeof m1) == 0
                      && uc_recv_eq(fd1, (const char *)m1, sizeof m1) == 0;
        ok = ok && th_wait_int(&g_open_count, 1, 3000u);

        /* fd2: a distinct client socket = a distinct (address, port) 4-tuple
         * as far as dgram_peers/s_classify_dgram's own classification is
         * concerned — this IS what "the peer's address changed" means at the
         * demux layer, independent of both sockets happening to share
         * 127.0.0.1 as their IP. */
        fd2 = ok ? uc_connect(port) : duct_sock_bad;
        uint8_t m2[8];
        memcpy(m2, &k_cid, 4u); memcpy(m2 + 4, "bbbb", 4u);
        bool migrated_ok = ok && fd2 != duct_sock_bad && uc_send(fd2, m2, sizeof m2) == 0
                                && uc_recv_eq(fd2, (const char *)m2, sizeof m2) == 0;
        if (migrated_ok)
            /* Reply must follow the peer: fd1 (the stale address) gets
             * nothing further once fd2 has taken over the session's TX
             * target. */
            migrated_ok = uc_recv_none(fd1, migrate_wait_ms) == 0;
        *out_migrated_ok = migrated_ok;

        if (fd1 != duct_sock_bad) close(fd1);
        if (fd2 != duct_sock_bad) close(fd2);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else {
        ok = false;
        *out_migrated_ok = false;
    }

    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return ok;
}

/** @brief 2b: migration must succeed end to end. */
static bool sc_shared_migrates(void)
{
    bool migrated_ok = false;
    bool ok = s_run(/* shared */ true, &migrated_ok);
    return ok && migrated_ok;
}

/** @brief 2a: the same scenario must fail — proves sc_shared_migrates is
 * exercising a real gap, not a test that would pass either way. */
static bool sc_plain_rejects_migration(void)
{
    bool migrated_ok = false;
    bool ok = s_run(/* shared */ false, &migrated_ok);
    return ok && !migrated_ok;
}

/** @brief Several datagrams from one peer with no drain between them, which is
 *  the only shape that makes the io side run out of RX slots and fall back to
 *  copying mid-burst — a request/response test returns every slot before the
 *  next datagram and never leaves the fast path.
 *
 *  What is asserted is order among whatever arrives. UDP promises no delivery,
 *  and a burst this deep genuinely loses datagrams on some backends, so a count
 *  measures the transport rather than the routing this covers. Two is the
 *  floor because one datagram exhibits no order at all.
 */
static bool sc_queued_burst_order(void)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto wire = duct_wire_create_dgram_batch(0u, false);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "dgram-burst", .wire = wire,
        .on_frame = on_dgram, .on_session_open = on_open, .on_session_close = on_close,
        .preparse = preparse, .preparse_mode = resolve_sync,
        .max_response = 4096u,
        .flags = fl_proto_dgram_shared,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    if (!proto) { duct_engine_destroy(io); return false; }

    const duct_proto_t *protos[1] = { proto };
    uint16_t port = 0u;
    bool ok = duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
                  .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
              }, &port, nullptr, 0u, nullptr) == rc_ok;

    static constexpr unsigned burst = 12u;
    duct_sock_t fd = ok ? uc_connect(port) : duct_sock_bad;
    ok = ok && fd != duct_sock_bad;

    pthread_t th;
    bool running = ok && pthread_create(&th, nullptr, th_run, io) == 0;
    ok = running;
    uint8_t m[8];
    memcpy(m, &k_cid, 4u);
    memcpy(m + 4, "aaaa", 4u);
    for (unsigned i = 0u; ok && i < burst; ++i) {
        m[7] = (uint8_t)i;
        ok = uc_send(fd, m, sizeof m) == 0;
    }
    int prev = -1,
        seen = 0;
    for (unsigned i = 0u; ok && i < burst; ++i) {
        uint8_t got[8];
        ssize_t n = uc_recv(fd, (char *)got, sizeof got);
        if (n != (ssize_t)sizeof got)
            break;
        ok = (int)got[7] > prev;
        prev = (int)got[7];
        ++seen;
    }
    ok = ok && seen >= 2;

    if (fd != duct_sock_bad) close(fd);
    duct_engine_stop(io);
    if (running) pthread_join(th, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return ok;
}

/** @brief R-2: fl_proto_dgram_shared's own max_response must fit one
 * dgram_tx_outbox reserve — bind must reject both an unset (0, "no cap")
 * and an oversized (bigger than the lane could ever hold) value outright,
 * rather than letting either misconfiguration reach a guaranteed
 * vmq_push_too_large the first time a real response needs the room. */
static bool sc_bind_rejects_bad_max_response(void)
{
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;
    bool ok = true;

    auto wire_zero = duct_wire_create_dgram_batch(0u, false);
    auto p_zero = duct_proto_create(&(duct_proto_cfg_t){
        .name = "dgram-shared-zero", .wire = wire_zero, .on_frame = on_dgram,
        .flags = fl_proto_dgram_shared, .max_response = 0u,
    });
    if (p_zero) p_zero->owned_wire = wire_zero; else duct_wire_destroy(wire_zero);
    if (!p_zero) {
        ok = false;
    } else {
        const duct_proto_t *protos[1] = { p_zero };
        uint16_t port = 0u;
        if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
                .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
            }, &port, nullptr, 0u, nullptr) == rc_ok) {
            fprintf(stderr, "dgram_shared: bind unexpectedly accepted max_response=0\n");
            ok = false;
        }
        duct_proto_destroy(p_zero);
    }

    auto wire_big = duct_wire_create_dgram_batch(0u, false);
    auto p_big = duct_proto_create(&(duct_proto_cfg_t){
        .name = "dgram-shared-big", .wire = wire_big, .on_frame = on_dgram,
        .flags = fl_proto_dgram_shared, .max_response = (size_t)mbytes(1u),
    });
    if (p_big) p_big->owned_wire = wire_big; else duct_wire_destroy(wire_big);
    if (!p_big) {
        ok = false;
    } else {
        const duct_proto_t *protos[1] = { p_big };
        uint16_t port = 0u;
        if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
                .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
            }, &port, nullptr, 0u, nullptr) == rc_ok) {
            fprintf(stderr, "dgram_shared: bind unexpectedly accepted a 1 MiB max_response\n");
            ok = false;
        }
        duct_proto_destroy(p_big);
    }

    duct_engine_destroy(io);
    return ok;
}

/** @brief R-4: revoking the listener while a session's x_udp_shared conn is
 * still live must actually tear that conn down — on every platform, not
 * Windows-only — since it has no socket of its own anywhere; the listener's
 * own listen_fd was always its sole RX/TX path. Asserted via on_session_close
 * actually firing (@ref on_close), not via "the client sees no more
 * replies": that silence is equally true for a genuinely closed conn and
 * for the zombie the pre-fix Linux-only gate used to leave behind — once
 * listen_fd is gone, nothing reaches either one, so client-visible silence
 * cannot tell them apart. */
static bool sc_listener_close_orphans_shared(void)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto wire = duct_wire_create_dgram_batch(0u, false);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "dgram-shared-close", .wire = wire,
        .on_frame = on_dgram, .on_session_open = on_open, .on_session_close = on_close,
        .preparse = preparse, .preparse_mode = resolve_sync,
        .max_response = 4096u, .flags = fl_proto_dgram_shared,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    if (!proto) { duct_engine_destroy(io); return false; }

    duct_sock_t fds[4] = {};
    unsigned n_fds = 0u;
    const duct_proto_t *protos[1] = { proto };
    uint16_t port = 0u;
    bool ok = duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
                  .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
              }, &port, fds, 4u, &n_fds) == rc_ok && n_fds == 1u;

    pthread_t th;
    duct_sock_t fd = duct_sock_bad;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        fd = uc_connect(port);
        uint8_t m[8];
        memcpy(m, &k_cid, 4u); memcpy(m + 4, "cccc", 4u);
        ok = fd != duct_sock_bad && uc_send(fd, m, sizeof m) == 0 && uc_recv_eq(fd, (const char *)m, sizeof m) == 0;
        ok = ok && th_wait_int(&g_open_count, 1, 3000u);

        ok = ok && duct_listener_close(io, fds[0]) == rc_ok;

        /* Immediate rebind while the orphaned x_udp_shared conn from the
         * just-closed listener is still alive (pre_conn_refs > 0, its node
         * floating off every list) — regression check for the old
         * shared-list races: the new bind's registry insert and its owning
         * io thread's own list must not see the floating node at all. */
        duct_sock_t fds2[4] = {};
        unsigned n_fds2 = 0u;
        uint16_t port2 = 0u;
        ok = ok && duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
                      .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
                  }, &port2, fds2, 4u, &n_fds2) == rc_ok && n_fds2 == 1u;
        ok = ok && duct_listener_close(io, fds2[0]) == rc_ok;

        ok = ok && th_wait_int(&g_close_count, 1, 3000u);

        if (fd != duct_sock_bad) close(fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else {
        ok = false;
    }

    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return ok;
}

/* ── Multiplexed wire: several frames from one datagram ──
 * Same [stream_id:4][pad:1][len:4] shape as mux_dgram_test.c's own wire —
 * s_dgram_shared_route's own parse loop must
 * split one datagram carrying two such records into two independent
 * frames, each dispatched (and replied to) on its own, not merged or
 * dropped. */

static constexpr size_t mux_hdr_size = 9u;

typedef struct {
    uint8_t  hdr_buf[mux_hdr_size];
    uint32_t partial_len;
    bool     hdr_done;
    /* duct_dgram_record_hdr_size's own [len:4] prefix (duct_wire.h) wraps
     * the whole datagram exactly once — s_dgram_shared_route synthesizes it
     * ahead of the raw bytes before its own on_parse loop starts, the
     * same shape x_udp_peer's OLB already has. Skipped once, tracked here
     * rather than folded into mux_hdr_size the way mux_dgram_test.c's own
     * single-record-per-datagram wire does: unlike that wire, this one must
     * survive being called again, past the first mux record, for a SECOND
     * one in the same datagram — with no second [len:4] of its own to skip.
     * hdr_done/partial_len reset every mux record; this does not. */
    bool     reclen_skipped;
} mux_parser_t;

typedef struct { duct_wire_t base; } mux_wire_t;

static duct_result_t
mux_parse([[maybe_unused]] const duct_wire_t *self,
          duct_view_u8 input, duct_frame_t *out, duct_wire_parser_t *parser,
          size_t *consumed, size_t *needed)
{
    auto st = (mux_parser_t *)parser;
    *consumed = 0u;
    *needed = 0u;
    uint8_t *p = (uint8_t *)input.data;
    uint8_t *end = p + input.size;

    if (!st->reclen_skipped) {
        if ((size_t)(end - p) < duct_dgram_record_hdr_size) {
            *needed = duct_dgram_record_hdr_size - (size_t)(end - p);
            return rc_again;
        }
        p += duct_dgram_record_hdr_size;
        st->reclen_skipped = true;
    }

    if (!st->hdr_done) {
        if ((size_t)(end - p) < mux_hdr_size) {
            memcpy(st->hdr_buf, p, (size_t)(end - p));
            st->partial_len = (uint32_t)(end - p);
            *needed = mux_hdr_size - st->partial_len;
            return rc_again;
        }
        memcpy(st->hdr_buf, p, mux_hdr_size);
        p += mux_hdr_size;
        st->hdr_done = true;
    } else {
        p += mux_hdr_size;
    }

    uint32_t sid = ((uint32_t)st->hdr_buf[0] << 24u) | ((uint32_t)st->hdr_buf[1] << 16u)
                 | ((uint32_t)st->hdr_buf[2] <<  8u) |  (uint32_t)st->hdr_buf[3];
    uint32_t len = ((uint32_t)st->hdr_buf[5] << 24u) | ((uint32_t)st->hdr_buf[6] << 16u)
                 | ((uint32_t)st->hdr_buf[7] <<  8u) |  (uint32_t)st->hdr_buf[8];
    st->hdr_done = false;
    st->partial_len = 0u;

    if ((size_t)(end - p) < len) {
        st->hdr_done = true;
        *consumed = (size_t)(p - (uint8_t *)input.data);
        *needed = len;
        return rc_again;
    }
    *out = (duct_frame_t){ .stream_id = sid, .payload = { .data = p, .size = len } };
    *consumed = (size_t)((p + len) - (uint8_t *)input.data);
    /* Nothing left in this call's own buffer: a datagram is always handed
     * to on_parse whole in one loop (never replenished mid-datagram), so
     * "no bytes remain" means the next call, whenever it comes, starts a
     * brand new datagram with its own fresh [len:4] prefix to skip again. */
    if ((size_t)(end - (p + len)) == 0u)
        st->reclen_skipped = false;
    return rc_ok;
}

static duct_result_t
mux_pack([[maybe_unused]] const duct_wire_t *self, [[maybe_unused]] duct_session_t *s,
         const duct_frame_t *frame, duct_wire_tx_t *stage,
         [[maybe_unused]] duct_wire_codec_t *codec)
{
    uint32_t sid = (uint32_t)frame->stream_id;
    uint32_t len = (uint32_t)frame->payload.size;
    uint8_t hdr[mux_hdr_size] = {
        (uint8_t)(sid >> 24u), (uint8_t)(sid >> 16u),
        (uint8_t)(sid >>  8u), (uint8_t)(sid),
        0u,
        (uint8_t)(len >> 24u), (uint8_t)(len >> 16u),
        (uint8_t)(len >>  8u), (uint8_t)(len),
    };
    return duct_wire_tx_stage(stage,
        duct_view(duct_view_u8, hdr, mux_hdr_size), frame->payload);
}

static duct_wire_parser_t *mux_create_parser([[maybe_unused]] const duct_wire_t *self)
{
    auto st = duct_new(mux_parser_t);
    duct_do_if(!st, return nullptr);
    *st = (mux_parser_t){};
    return (duct_wire_parser_t *)st;
}

static void mux_destroy_parser([[maybe_unused]] const duct_wire_t *self, duct_wire_parser_t *parser)
{
    auto st = (mux_parser_t *)parser;
    duct_del(st);
}

static void mux_destroy(duct_wire_t *self)
{
    auto w = (mux_wire_t *)self;
    duct_del(w);
}

static duct_wire_t *mux_wire_create(void)
{
    auto w = duct_new(mux_wire_t);
    duct_do_if(!w, return nullptr);
    w->base = (duct_wire_t){
        .name = "test-mux-dgram-shared",
        .header_size = mux_hdr_size,
        .max_frame   = 1024u,
        .destroy = mux_destroy, .on_parse = mux_parse, .on_pack = mux_pack,
        .create_parser = mux_create_parser, .destroy_parser = mux_destroy_parser,
    };
    return &w->base;
}

static int uc_send_mux2(duct_sock_t fd, duct_stream_id_t sid_a, const char *pa, size_t la,
                                 duct_stream_id_t sid_b, const char *pb, size_t lb)
{
    uint8_t buf[256];
    size_t off = 0u;
    uint8_t hdr_a[mux_hdr_size] = {
        (uint8_t)(sid_a >> 24u), (uint8_t)(sid_a >> 16u), (uint8_t)(sid_a >> 8u), (uint8_t)(sid_a), 0u,
        (uint8_t)(la >> 24u), (uint8_t)(la >> 16u), (uint8_t)(la >> 8u), (uint8_t)(la),
    };
    memcpy(buf + off, hdr_a, mux_hdr_size); off += mux_hdr_size;
    memcpy(buf + off, pa, la); off += la;
    uint8_t hdr_b[mux_hdr_size] = {
        (uint8_t)(sid_b >> 24u), (uint8_t)(sid_b >> 16u), (uint8_t)(sid_b >> 8u), (uint8_t)(sid_b), 0u,
        (uint8_t)(lb >> 24u), (uint8_t)(lb >> 16u), (uint8_t)(lb >> 8u), (uint8_t)(lb),
    };
    memcpy(buf + off, hdr_b, mux_hdr_size); off += mux_hdr_size;
    memcpy(buf + off, pb, lb); off += lb;
    return uc_send(fd, buf, off);
}

static duct_result_t
mux_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             const duct_frame_t *frame, duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_response_same(out, frame->payload, fl_send_copy, 0);
    return rc_ok;
}

/** @brief One datagram, two multiplexed records (stream_id 7 and 11):
 * s_dgram_shared_route must parse both out of the same scratch buffer and
 * deliver two independent frames — verified by two independent replies,
 * each carrying the right stream_id/payload back. */
static bool sc_shared_multiplexed(void)
{
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto wire = mux_wire_create();
    if (!wire) { duct_engine_destroy(io); return false; }
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "dgram-shared-mux", .wire = wire, .on_frame = mux_on_frame,
        .flags = fl_proto_dgram_shared, .max_response = 4096u,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    if (!proto) { duct_engine_destroy(io); return false; }

    const duct_proto_t *protos[1] = { proto };
    uint16_t port = 0u;
    bool ok = duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
                  .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
              }, &port, nullptr, 0u, nullptr) == rc_ok;

    pthread_t th;
    duct_sock_t fd = duct_sock_bad;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        fd = uc_connect(port);
        static const char p7[] = "mux-stream-7", p11[] = "mux-stream-11";
        ok = fd != duct_sock_bad && uc_send_mux2(fd, 7u, p7, sizeof p7 - 1u, 11u, p11, sizeof p11 - 1u) == 0;

        bool got7 = false, got11 = false;
        for (unsigned i = 0u; ok && i < 2u; ++i) {
            uint8_t buf[64];
            ssize_t n = uc_recv(fd, (char *)buf, sizeof buf);
            if (n < (ssize_t)mux_hdr_size) { ok = false; break; }
            uint32_t sid = ((uint32_t)buf[0] << 24u) | ((uint32_t)buf[1] << 16u)
                         | ((uint32_t)buf[2] <<  8u) |  (uint32_t)buf[3];
            uint32_t len = ((uint32_t)buf[5] << 24u) | ((uint32_t)buf[6] << 16u)
                         | ((uint32_t)buf[7] <<  8u) |  (uint32_t)buf[8];
            if ((size_t)n != mux_hdr_size + len) { ok = false; break; }
            if (sid == 7u && len == sizeof p7 - 1u && memcmp(buf + mux_hdr_size, p7, len) == 0)
                got7 = true;
            else if (sid == 11u && len == sizeof p11 - 1u && memcmp(buf + mux_hdr_size, p11, len) == 0)
                got11 = true;
            else
                ok = false;
        }
        ok = ok && got7 && got11;

        if (fd != duct_sock_bad) close(fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else {
        ok = false;
    }

    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return ok;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    int pass = 1;

    if (!sc_shared_migrates()) {
        fprintf(stderr, "dgram_shared: fl_proto_dgram_shared migration failed\n");
        pass = 0;
    } else {
        printf("dgram_shared: fl_proto_dgram_shared OK (session follows migrated peer)\n");
    }

    if (!sc_plain_rejects_migration()) {
        fprintf(stderr, "dgram_shared: plain 2a unexpectedly tolerated migration\n");
        pass = 0;
    } else {
        printf("dgram_shared: plain 2a OK (migration correctly rejected, confirms the gate is real)\n");
    }

    if (!sc_queued_burst_order()) {
        fprintf(stderr, "dgram_shared: queued burst lost or reordered a datagram\n");
        pass = 0;
    } else {
        printf("dgram_shared: burst OK (queued datagrams keep order across slot and copy paths)\n");
    }

    if (!sc_bind_rejects_bad_max_response()) {
        fprintf(stderr, "dgram_shared: bind did not reject a bad max_response (R-2)\n");
        pass = 0;
    } else {
        printf("dgram_shared: R-2 OK (bind rejects max_response=0 and an oversized cap)\n");
    }

    if (!sc_listener_close_orphans_shared()) {
        fprintf(stderr, "dgram_shared: listener close did not tear down a live x_udp_shared conn (R-4)\n");
        pass = 0;
    } else {
        printf("dgram_shared: R-4 OK (listener close tears down live x_udp_shared conns on this platform)\n");
    }

    if (!sc_shared_multiplexed()) {
        fprintf(stderr, "dgram_shared: multiplexed wire (2 frames, 1 datagram) failed\n");
        pass = 0;
    } else {
        printf("dgram_shared: multiplexed OK (one datagram split into two independent frames/replies)\n");
    }

    return pass ? 0 : 1;
}
