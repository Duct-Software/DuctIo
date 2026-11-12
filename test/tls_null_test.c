/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file tls_null_test.c
 * @brief Sealed RX and TX pipelines end to
 * end over a real TCP conn, using the deterministic null engine
 * (tls_engine_null.h/.c).
 *
 * Inner wire is a private "mux" framing (9-byte [sid][flags][len] header +
 * payload) so multiplexed stream dispatch — the whole point of the parked-
 * handler scenario — is reachable; the built-in length-prefix wire carries
 * no stream_id (see send_done_test.c's own comment on the same tradeoff).
 *
 * Six scenarios on the primary connection, one handshake, run in sequence:
 *   sc_gate       — handshake round-trip, then one application-data record
 *                   verified through a g_records[] log.
 *   sc_parked     — a stream-5 frame parks its handler (async_yield) while
 *                   a stream-7 frame on the same record dispatches and
 *                   completes; stream 5's second step re-reads its own
 *                   frame.payload and must see the identical bytes — proof
 *                   the hold the handler takes on ct_buf actually blocks compaction.
 *   sc_replay     — two mux frames for the *same* stream in one record: the
 *                   second's dispatch collides with the still-fresh (not
 *                   yet parked) handler from the first and defers the whole
 *                   task. Verifies the record is unsealed exactly once
 *                   (head_unsealed, not an offset, is what makes replay
 *                   resume correctly) and both frames are eventually
 *                   delivered exactly once each.
 *   sc_echo       — a single-record response round-trips through
 *                   on_pack/seal_size/seal and decodes back to exactly the
 *                   sent bytes.
 *   sc_chunked    — a response bigger than one record forces the
 *                   engine's internal segmentation; several records
 *                   decode and concatenate back to the fixed payload.
 *   sc_auth_fail  — a tampered fake-tag closes the conn (close_protocol_error)
 *                   instead of being dropped and continued.
 *
 * A second connection then covers what the primary one cannot without
 * disturbing its own sequence (sc_auth_fail already ends it):
 *   sc_server_first_and_close — its own handshake; first verifies the
 *                   greeting s_on_session_open committed before any client
 *                   byte arrived (parked via duct_response_commit's own
 *                   retry-save) is still delivered once the
 *                   handshake establishes the engine; then triggers a
 *                   protocol-initiated graceful close
 *                   (duct_response_close_session) and verifies
 *                   duct_worker_conn_close staged a close_notify
 *                   record before the socket actually closed.
 */

#include "duct.h"
#include "duct_tls.h"
#include "duct_stream_ctx.h"
#include "tls_engine_null.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "test_helpers.h"

/* ── Private "mux" inner wire: [sid(4 BE)][flags(1)][len(4 BE)] + payload —
 * same shape as send_done_test.c's own, minus on_pack (RX-only). */

static constexpr size_t mux_hdr_size = 9u;

typedef struct {
    uint8_t  hdr_buf[9];
    uint32_t partial_len;
    bool     hdr_done;
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

    if (!st->hdr_done) {
        if (st->partial_len > 0u) {
            p += st->partial_len;
            uint32_t want = (uint32_t)mux_hdr_size - st->partial_len;
            uint32_t copy = (uint32_t)(end - p) < want ? (uint32_t)(end - p) : want;
            memcpy(st->hdr_buf + st->partial_len, p, copy);
            st->partial_len += copy;
            p += copy;
            if (st->partial_len < (uint32_t)mux_hdr_size) {
                *needed = mux_hdr_size - st->partial_len;
                return rc_again;
            }
            st->hdr_done = true;
        } else if ((size_t)(end - p) >= mux_hdr_size) {
            memcpy(st->hdr_buf, p, mux_hdr_size);
            p += mux_hdr_size;
            st->hdr_done = true;
        } else {
            memcpy(st->hdr_buf, p, (size_t)(end - p));
            st->partial_len = (uint32_t)(end - p);
            *needed = mux_hdr_size - st->partial_len;
            return rc_again;
        }
    } else {
        p += mux_hdr_size;
    }

    uint32_t sid = ((uint32_t)st->hdr_buf[0] << 24u) | ((uint32_t)st->hdr_buf[1] << 16u)
                 | ((uint32_t)st->hdr_buf[2] <<  8u) |  (uint32_t)st->hdr_buf[3];
    uint32_t len = ((uint32_t)st->hdr_buf[5] << 24u) | ((uint32_t)st->hdr_buf[6] << 16u)
                 | ((uint32_t)st->hdr_buf[7] <<  8u) |  (uint32_t)st->hdr_buf[8];
    st->hdr_done = false;
    st->partial_len = 0u;

    if (len > (1u << 16u)) {
        *consumed = (size_t)(p - (uint8_t *)input.data);
        return rc_invalid_arg;
    }
    if ((size_t)(end - p) < len) {
        st->hdr_done = true;
        *consumed = (size_t)(p - (uint8_t *)input.data);
        *needed = len;
        return rc_again;
    }
    *out = (duct_frame_t){ .stream_id = sid, .flags = fl_frame_none,
                           .payload = { .data = p, .size = len } };
    *consumed = (size_t)((p + len) - (uint8_t *)input.data);
    return rc_ok;
}

static size_t
mux_pack_header([[maybe_unused]] const duct_wire_t *self,
               const duct_frame_t *frame, uint8_t buf[16])
{
    uint32_t sid = frame->stream_id;
    uint32_t len = (uint32_t)frame->payload.size;
    buf[0] = (uint8_t)(sid >> 24u); buf[1] = (uint8_t)(sid >> 16u);
    buf[2] = (uint8_t)(sid >>  8u); buf[3] = (uint8_t)(sid);
    buf[4] = 0u;
    buf[5] = (uint8_t)(len >> 24u); buf[6] = (uint8_t)(len >> 16u);
    buf[7] = (uint8_t)(len >>  8u); buf[8] = (uint8_t)(len);
    return mux_hdr_size;
}

static duct_result_t
mux_pack(const duct_wire_t *self, [[maybe_unused]] duct_session_t *s,
        const duct_frame_t *frame, duct_wire_tx_t *stage,
        [[maybe_unused]] duct_wire_codec_t *codec)
{
    uint8_t hdr[16];
    mux_pack_header(self, frame, hdr);
    return duct_wire_tx_stage(stage,
        duct_view(duct_view_u8, hdr, mux_hdr_size), frame->payload);
}

static duct_wire_parser_t *mux_create_parser([[maybe_unused]] const duct_wire_t *self)
{
    auto st = duct_new(mux_parser_t);
    duct_do_if(!st, return nullptr);
    return (duct_wire_parser_t *)st;
}

static void mux_destroy_parser([[maybe_unused]] const duct_wire_t *self, duct_wire_parser_t *parser)
{
    auto st = (mux_parser_t *)parser;
    duct_del(st);
}

static void mux_destroy(duct_wire_t *self) { duct_del(self); }

static duct_wire_t *mux_wire_create(void)
{
    auto w = duct_new(mux_wire_t);
    duct_do_if(!w, return nullptr);
    w->base = (duct_wire_t){
        .name = "tls-null-mux", .header_size = mux_hdr_size,
        .destroy = mux_destroy, .on_parse = mux_parse, .on_pack = mux_pack,
        .pack_header = mux_pack_header,
        .create_parser = mux_create_parser, .destroy_parser = mux_destroy_parser,
    };
    return &w->base;
}

static size_t s_mux_frame(uint8_t *out, size_t cap, uint32_t sid, const void *payload, size_t len)
{
    if (cap < mux_hdr_size + len)
        return 0u;
    out[0] = (uint8_t)(sid >> 24u); out[1] = (uint8_t)(sid >> 16u);
    out[2] = (uint8_t)(sid >>  8u); out[3] = (uint8_t)(sid);
    out[4] = 0u;
    out[5] = (uint8_t)(len >> 24u); out[6] = (uint8_t)(len >> 16u);
    out[7] = (uint8_t)(len >>  8u); out[8] = (uint8_t)(len);
    memcpy(out + mux_hdr_size, payload, len);
    return mux_hdr_size + len;
}

/* ── Raw TLS-record socket helpers ───────────────────────────────── */

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

static int s_send_app(duct_sock_t fd, const void *ct, size_t ct_len)
{
    uint8_t sealed[4224];
    size_t sealed_len = tls_null_seal(ct, ct_len, sealed, sizeof sealed);
    if (!sealed_len)
        return -1;
    return s_send_record(fd, 2u, sealed, sealed_len);
}

/** @brief How many records @c s_tls_tx_bound/@c s_seal_size expect
 *  a @p ct_total-byte cleartext to segment into -- the test-side mirror of
 *  that same ceil-with-a-floor-of-one rule, so a receiver knows exactly how
 *  many records to read for a response of known cleartext size. */
static size_t s_expected_records(size_t ct_total)
{
    static constexpr size_t pdu_ct_max = 4096u; /* tls_null_vtbl()'s own */
    size_t n = ct_total / pdu_ct_max;
    if (ct_total % pdu_ct_max != 0u || n == 0u)
        ++n;
    return n;
}

/** @brief Read exactly @p n_records application-data records, fake-unseal
 *  each body and concatenate the cleartext into @p ct (@p ct_cap bytes).
 *  @return total cleartext bytes, or SIZE_MAX on any record/tag mismatch. */
static size_t s_recv_app_records(duct_sock_t fd, size_t n_records, uint8_t *ct, size_t ct_cap)
{
    size_t ct_off = 0u;
    for (size_t i = 0u; i < n_records; ++i) {
        uint8_t type = 0u, body[4224];
        size_t body_len = 0u;
        if (s_recv_record(fd, &type, body, sizeof body, &body_len) != 0 || type != 2u)
            return SIZE_MAX;
        if (ct_off > ct_cap)
            return SIZE_MAX;
        size_t got = tls_null_unseal_body(body, body_len, ct + ct_off, ct_cap - ct_off);
        if (got == SIZE_MAX)
            return SIZE_MAX;
        ct_off += got;
    }
    return ct_off;
}

/* ── g_records log (inter_conn_test.c's own pattern) ─────────────── */

typedef struct { duct_stream_id_t stream_id; size_t len; char data[64]; } record_t;
static constexpr unsigned max_records = 32u;
static record_t g_records[max_records];
static atomic_uint g_next_idx = 0u;
static atomic_uint g_published = 0u;
static atomic_int  g_open_count = 0;
static atomic_int  g_error_count = 0;

static void s_log(duct_stream_id_t sid, duct_view_u8 data)
{
    unsigned i = atomic_fetch_add(&g_next_idx, 1u);
    if (i < max_records) {
        g_records[i].stream_id = sid;
        g_records[i].len = data.size < sizeof(g_records[i].data) ? data.size : sizeof(g_records[i].data);
        memcpy(g_records[i].data, data.data, g_records[i].len);
    }
    atomic_store(&g_published, i + 1u);
}

static bool s_wait_uint(atomic_uint *p, unsigned target, unsigned timeout_ms)
{
    for (unsigned waited = 0u; waited < timeout_ms; waited += 10u) {
        if (atomic_load(p) >= target)
            return true;
        th_sleep_ms(10u);
    }
    return atomic_load(p) >= target;
}

/* ── Protocol callbacks ───────────────────────────────────────────── */

/** @brief Set if stream 5's second step ever sees different bytes than its
 *  first — proof the hold on ct_buf failed to block a compaction. */
static bool s_stream5_mismatch = false;
static unsigned s_yield_step = 0u;

/** @brief Stream-0 fallback, required by duct_proto_create even for a fully
 *  multiplexed proto — never reached, every frame this test sends targets
 *  a non-zero stream. */
static duct_result_t
s_on_frame([[maybe_unused]] duct_session_t *s,
          [[maybe_unused]] duct_conn_id_t conn_id,
          [[maybe_unused]] const duct_frame_t *frame,
          [[maybe_unused]] duct_response_t *out,
          [[maybe_unused]] void *proto_state)
{
    return rc_drop;
}

/**
 * @brief One handler for every multiplexed stream this test uses.
 *
 * A brand-new handler's first step runs synchronously, inline with the
 * frame that created it (this codebase's own coop scheduler) — so a
 * plain "complete on first call" stream (1, 7) never collides with a
 * second frame for the same stream in one record. Every other stream
 * yields once before completing, parking its hctx runnable-but-not-done
 * across that first return — the shape both scenarios need: stream 5
 * (sc_parked) uses it to prove the parked frame.payload is untouched by
 * the time its second step runs; stream 9 (sc_replay) uses it to force a
 * second same-stream frame in the same record to collide with the still-
 * live (not parked) hctx and defer the whole sealed task.
 *
 * Logs to g_records only once per frame, on the completing step — a
 * yield never logs, so g_published counts frames, not handler steps.
 */
/** @brief Echo stream: whatever arrives on stream @c echo_stream_id
 *  is staged straight back out through the same sealed wire's @c on_pack —
 *  proof of the seal/seal_size/chunking path, independent of @c s_log
 *  (which only proves RX). Always completes on its first step (added to
 *  the synchronous set below) so a response payload borrowed from
 *  @c hctx->frame stays valid through this same step's commit. */
static constexpr duct_stream_id_t echo_stream_id = 20u;
/** @brief Chunking trigger: any (small) frame here gets @ref
 *  s_big_payload back, several records' worth of cleartext -- decoupled
 *  from what the client sent so the client side never needs its own
 *  multi-record seal (tls_null_seal has none). */
static constexpr duct_stream_id_t big_echo_stream_id = 21u;
static constexpr size_t big_payload_len = 8692u; /* ceil((9+8692)/4096) = 3 records */
static uint8_t s_big_payload[big_payload_len];
/** @brief Close-notify trigger: closes its own conn gracefully
 *  instead of responding — proof @ref duct_worker_conn_close actually
 *  fires from a protocol-initiated close, not just engine teardown. */
static constexpr duct_stream_id_t close_stream_id = 30u;

static duct_async_rc_t s_handler(void *state)
{
    auto hctx = (duct_stream_ctx_t *)state;
    duct_view_u8 p = hctx->frame.payload;
    duct_response_reset(&hctx->out);
    if (hctx->stream_id == 5u
        && (p.size != 5u || memcmp(p.data, "PARK1", 5u) != 0))
        s_stream5_mismatch = true;
    if (hctx->stream_id != 1u && hctx->stream_id != 7u
        && hctx->stream_id != echo_stream_id && hctx->stream_id != big_echo_stream_id
        && hctx->stream_id != close_stream_id && s_yield_step == 0u) {
        s_yield_step = 1u;
        return async_yield;
    }
    s_yield_step = 0u;
    /* handler_event_emit (duct_worker.c's s_hctx_async_done) only fires on
     * async_yield, never async_done -- a done step's hctx->out is never
     * committed (s_hctx_complete's handler_event_done case: ack + stream
     * teardown only). So every branch below that must actually put bytes
     * (or a control effect) on the wire emits once via async_yield, marks
     * hctx->stream_state so the run it gets rescheduled for is a no-op
     * async_done instead of emitting a second time. */
    if (hctx->stream_id == close_stream_id) {
        if (!hctx->stream_state) {
            hctx->stream_state = (void *)(uintptr_t)1;
            duct_response_close_session(&hctx->out, close_normal);
            return async_yield;
        }
        return async_done;
    }
    if (hctx->stream_id == echo_stream_id) {
        if (!hctx->stream_state) {
            hctx->stream_state = (void *)(uintptr_t)1;
            hctx->out.payload = p;
            hctx->out.flags = fl_send_copy;
            hctx->out.conn_id = duct_conn_id_same;
            hctx->out.stream_id = duct_stream_id_same;
            return async_yield;
        }
        return async_done;
    }
    if (hctx->stream_id == big_echo_stream_id) {
        if (!hctx->stream_state) {
            hctx->stream_state = (void *)(uintptr_t)1;
            hctx->out.payload = duct_view(duct_view_u8, s_big_payload, sizeof s_big_payload);
            hctx->out.flags = fl_send_copy;
            hctx->out.conn_id = duct_conn_id_same;
            hctx->out.stream_id = duct_stream_id_same;
            return async_yield;
        }
        return async_done;
    }
    s_log(hctx->stream_id, p);
    return async_done;
}

/** @brief The server's fixed, deterministic server-first greeting payload,
 *  sent unprompted from the second conn's on_session_open and verified by
 *  sc_server_first_and_close. */
static const uint8_t s_greeting[] = "GREET";

static duct_result_t
s_on_session_open([[maybe_unused]] duct_session_t *s,
                  [[maybe_unused]] duct_handle_t tok,
                  [[maybe_unused]] void *user_ctx,
                  duct_response_t *out,
                  [[maybe_unused]] void *proto_state)
{
    int n = atomic_fetch_add(&g_open_count, 1);
    /* The second conn this test ever opens (n == 1,
     * atomic_fetch_add returns the pre-increment value) gets a greeting
     * committed here, before any client byte has arrived. codec now
     * exists eagerly by this point (duct_worker_tls_ensure_started,
     * called from duct_session_exec_open before this callback runs) but
     * is not yet established (this null engine's own start is nullptr;
     * establishment only happens on the first real unseal), so on_pack
     * still returns rc_again -- exactly the case duct_response_commit's
     * retry-save exists for. */
    if (n == 1) {
        out->payload = duct_view(duct_view_u8, (void *)s_greeting, sizeof(s_greeting) - 1u);
        out->flags = fl_send_copy;
    }
    return rc_ok;
}

static duct_result_t
s_on_error([[maybe_unused]] duct_session_t *s,
          [[maybe_unused]] duct_result_t err,
          [[maybe_unused]] duct_response_t *out,
          [[maybe_unused]] void *proto_state)
{
    atomic_fetch_add(&g_error_count, 1);
    return rc_ok;
}

/* ── Scenarios ────────────────────────────────────────────────────── */

static const char *sc_gate(duct_sock_t fd)
{
    static const uint8_t client_hello[4] = { 'C', 'L', 'N', 'T' };
    if (s_send_record(fd, 1u, client_hello, sizeof client_hello) != 0)
        return "handshake send failed";
    uint8_t type = 0u, body[64] = {};
    size_t blen = 0u;
    if (s_recv_record(fd, &type, body, sizeof body, &blen) != 0)
        return "handshake reply not received";
    if (type != 1u || blen != sizeof tls_null_server_hello
        || memcmp(body, tls_null_server_hello, blen) != 0)
        return "handshake reply mismatch";

    unsigned before = atomic_load(&g_published);
    uint8_t plain[32];
    size_t plen = s_mux_frame(plain, sizeof plain, 1u, "hello-tls", 9u);
    if (!plen || s_send_app(fd, plain, plen) != 0)
        return "app-data send failed";
    if (!s_wait_uint(&g_published, before + 1u, 3000u))
        return "app-data frame never logged";
    if (g_records[before].stream_id != 1u || g_records[before].len != 9u
        || memcmp(g_records[before].data, "hello-tls", 9u) != 0)
        return "app-data content mismatch";

    /* The context the unseal ran in names the conn's peer: this client's own
     * endpoint, as its socket's local name states it. */
    struct sockaddr_storage mine;
    socklen_t mlen = sizeof mine;
    if (getsockname(fd, (struct sockaddr *)&mine, &mlen) != 0)
        return "the client's own endpoint cannot be read";
    duct_peer_t seen;
    tls_null_last_peer(&seen);
    auto in4 = (const struct sockaddr_in *)&mine;
    if (seen.family != AF_INET || seen.port != ntohs(in4->sin_port)
        || memcmp(seen.addr.v4, &in4->sin_addr, 4u) != 0)
        return "the unseal context does not name the conn's peer";
    return nullptr;
}

static const char *sc_parked(duct_sock_t fd)
{
    unsigned before = atomic_load(&g_published);
    uint8_t plain[64];
    size_t off = 0u;
    off += s_mux_frame(plain + off, sizeof plain - off, 5u, "PARK1", 5u);
    off += s_mux_frame(plain + off, sizeof plain - off, 7u, "OTHR1", 5u);
    if (s_send_app(fd, plain, off) != 0)
        return "parked-test send failed";
    /* Stream 5's completing (second) step runs on a later coop pass, once
     * stream 7 (dispatched in the same record) has already been created,
     * stepped, and released its own pin — exactly the "other stream's
     * unseal/ack activity happens while stream 5 is still parked" window
     * s_stream5_mismatch is watching. */
    if (!s_wait_uint(&g_published, before + 2u, 3000u))
        return "parked-test records never fully logged";
    if (s_stream5_mismatch)
        return "stream 5 payload changed between its yield and done steps -- "
               "ct_buf compaction corrupted a parked frame";
    bool saw5 = false, saw7 = false;
    for (unsigned i = before; i < before + 2u; ++i) {
        if (g_records[i].stream_id == 5u) {
            if (g_records[i].len != 5u || memcmp(g_records[i].data, "PARK1", 5u) != 0)
                return "stream 5 content mismatch";
            saw5 = true;
        } else if (g_records[i].stream_id == 7u) {
            if (g_records[i].len != 5u || memcmp(g_records[i].data, "OTHR1", 5u) != 0)
                return "stream 7 content mismatch";
            saw7 = true;
        }
    }
    if (!saw5 || !saw7)
        return "parked-test did not log both streams";
    return nullptr;
}

static const char *sc_replay(duct_sock_t fd)
{
    unsigned before = atomic_load(&g_published);
    unsigned unseal_before = tls_null_unseal_calls();
    uint8_t plain[64];
    size_t off = 0u;
    off += s_mux_frame(plain + off, sizeof plain - off, 9u, "FIRST", 5u);
    off += s_mux_frame(plain + off, sizeof plain - off, 9u, "SECND", 5u);
    if (s_send_app(fd, plain, off) != 0)
        return "replay-test send failed";
    if (!s_wait_uint(&g_published, before + 2u, 3000u))
        return "replay-test records never fully logged (mid-record defer never resolved)";
    if (tls_null_unseal_calls() - unseal_before != 1u)
        return "unseal ran more than once for one TLS record across its mid-record defer/replay";
    bool saw_first = false, saw_second = false;
    for (unsigned i = before; i < before + 2u; ++i) {
        if (g_records[i].stream_id != 9u)
            return "replay-test wrong stream_id";
        if (g_records[i].len == 5u && memcmp(g_records[i].data, "FIRST", 5u) == 0)
            saw_first = true;
        else if (g_records[i].len == 5u && memcmp(g_records[i].data, "SECND", 5u) == 0)
            saw_second = true;
    }
    if (!saw_first || !saw_second)
        return "replay-test lost or duplicated a frame across the mid-record defer";
    return nullptr;
}

/** @brief Verify on_pack/seal_size/seal round-trip a single-record
 *  response. The server echoes hctx->frame.payload verbatim (same stream,
 *  same mux header the client itself built), so the whole re-packed,
 *  re-sealed record must decode back to exactly the bytes sent — the only
 *  thing that could make this fail is on_pack, tx_bound, or duct_wire_codec_t
 *  wiring, since RX already has its own dedicated coverage above. */
static const char *sc_echo(duct_sock_t fd)
{
    uint8_t plain[32];
    size_t plen = s_mux_frame(plain, sizeof plain, echo_stream_id, "echo-me!", 8u);
    if (!plen || s_send_app(fd, plain, plen) != 0)
        return "echo send failed";
    uint8_t decoded[32];
    size_t got = s_recv_app_records(fd, s_expected_records(plen), decoded, sizeof decoded);
    if (got != plen)
        return "echo response size mismatch";
    if (memcmp(decoded, plain, plen) != 0)
        return "echo response content mismatch";
    return nullptr;
}

/** @brief Verify a response bigger than one record forces the
 *  engine's own internal segmentation (s_seal_size/s_seal, mirroring
 *  s_tls_tx_bound's own ceil-with-floor-of-one rule) — s_big_payload is
 *  sized so this is never satisfiable by one record (pdu_ct_max=4096).
 *  Decoupled from what the client sends (a one-byte trigger) since
 *  tls_null_seal, the client test side's own fake-seal, has no chunking of
 *  its own to send a matching multi-record request. */
static const char *sc_chunked(duct_sock_t fd)
{
    uint8_t trigger[16];
    size_t tlen = s_mux_frame(trigger, sizeof trigger, big_echo_stream_id, "x", 1u);
    if (!tlen || s_send_app(fd, trigger, tlen) != 0)
        return "chunked trigger send failed";
    size_t ct_total = mux_hdr_size + big_payload_len;
    size_t n = s_expected_records(ct_total);
    if (n < 2u)
        return "chunked test payload too small to exercise multi-record chunking";
    static uint8_t decoded[mux_hdr_size + big_payload_len];
    size_t got = s_recv_app_records(fd, n, decoded, sizeof decoded);
    if (got != ct_total)
        return "chunked response size mismatch";
    uint32_t sid = ((uint32_t)decoded[0] << 24u) | ((uint32_t)decoded[1] << 16u)
                 | ((uint32_t)decoded[2] <<  8u) |  (uint32_t)decoded[3];
    uint32_t len = ((uint32_t)decoded[5] << 24u) | ((uint32_t)decoded[6] << 16u)
                 | ((uint32_t)decoded[7] <<  8u) |  (uint32_t)decoded[8];
    if (sid != big_echo_stream_id || len != big_payload_len)
        return "chunked response header mismatch";
    if (memcmp(decoded + mux_hdr_size, s_big_payload, big_payload_len) != 0)
        return "chunked response content mismatch";
    return nullptr;
}

/** @brief Verify on a dedicated second conn (fd2, so
 *  the primary conn's own sequence never has to read past an unrelated
 *  close): (1) the greeting s_on_session_open committed before any client
 *  byte arrived (codec exists eagerly by then, but is not
 *  established) parks via duct_response_commit's own commit_internal ->
 *  s_retry_frame_save fallback and must still arrive once the handshake
 *  below establishes the engine, through the ordinary retry-emit drain
 * ; (2) duct_worker_conn_close actually
 *  fires on a protocol-initiated graceful close
 *  (duct_response_close_session) and rides the same TX-drain-then-close
 *  path as the socket's own shutdown. */
static const char *sc_server_first_and_close(duct_sock_t fd2)
{
    static const uint8_t client_hello[4] = { 'C', 'L', 'N', 'T' };
    if (s_send_record(fd2, 1u, client_hello, sizeof client_hello) != 0)
        return "server-first: handshake send failed";
    uint8_t type = 0u, body[64] = {};
    size_t blen = 0u;
    if (s_recv_record(fd2, &type, body, sizeof body, &blen) != 0)
        return "server-first: handshake reply not received";
    if (type != 1u || blen != sizeof tls_null_server_hello
        || memcmp(body, tls_null_server_hello, blen) != 0)
        return "server-first: handshake reply mismatch";

    size_t ct_total = mux_hdr_size + sizeof(s_greeting) - 1u;
    uint8_t decoded[32];
    size_t got = s_recv_app_records(fd2, s_expected_records(ct_total), decoded, sizeof decoded);
    if (got != ct_total)
        return "server-first: greeting size mismatch";
    if (memcmp(decoded + mux_hdr_size, s_greeting, sizeof(s_greeting) - 1u) != 0)
        return "server-first: greeting content mismatch";

    unsigned close_before = tls_null_close_notify_calls();
    uint8_t trigger[16];
    size_t tlen = s_mux_frame(trigger, sizeof trigger, close_stream_id, "bye", 3u);
    if (!tlen || s_send_app(fd2, trigger, tlen) != 0)
        return "close-notify trigger send failed";
    uint8_t ctype = 0u, cbody[8] = {};
    size_t cblen = 0u;
    if (s_recv_record(fd2, &ctype, cbody, sizeof cbody, &cblen) != 0)
        return "close_notify record not received";
    if (ctype != 3u || cblen != 1u || cbody[0] != tls_null_close_notify_marker)
        return "close_notify record mismatch";
    if (tls_null_close_notify_calls() != close_before + 1u)
        return "close_notify engine hook did not fire exactly once";
    struct pollfd pfd = { .fd = fd2, .events = POLLIN };
    if (poll(&pfd, 1, 2000) <= 0)
        return "conn was not closed after close_notify";
    char buf[4];
    if (recv(fd2, buf, sizeof buf, 0) > 0)
        return "conn still delivering data after close_notify";
    return nullptr;
}

static const char *sc_auth_fail(duct_sock_t fd)
{
    int before_err = atomic_load(&g_error_count);
    uint8_t plain[16];
    size_t plen = s_mux_frame(plain, sizeof plain, 1u, "x", 1u);
    uint8_t sealed[64];
    size_t slen = tls_null_seal(plain, plen, sealed, sizeof sealed);
    if (!slen)
        return "auth-fail seal failed";
    sealed[slen - 1u] ^= 0xFFu; /* corrupt the fake tag */
    if (s_send_record(fd, 2u, sealed, slen) != 0)
        return "auth-fail send failed";
    /* >= , not th_wait_int's own ==: rule (f) fires on_error twice for one
     * failure by design (s_fire_error immediately, then again through the
     * conn-lost close_protocol_error path once duct_io_post_close_request
     * lands) — both increments can land between two polls of this loop. */
    bool fired = false;
    for (unsigned waited = 0u; waited < 3000u; waited += 10u) {
        if (atomic_load(&g_error_count) >= before_err + 1) { fired = true; break; }
        th_sleep_ms(10u);
    }
    if (!fired)
        return "on_error did not fire for a corrupted record";
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    if (poll(&pfd, 1, 2000) <= 0)
        return "conn was not closed after an auth failure";
    char buf[4];
    if (recv(fd, buf, sizeof buf, 0) > 0)
        return "conn still delivering data after an auth failure";
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    for (size_t i = 0u; i < sizeof s_big_payload; ++i)
        s_big_payload[i] = (uint8_t)(i * 7u + 3u);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) { fprintf(stderr, "tls_null: io create failed\n"); return 1; }

    auto inner = mux_wire_create();
    if (!inner) { fprintf(stderr, "tls_null: inner wire create failed\n"); duct_engine_destroy(io); return 1; }
    auto tls_wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
            .inner = inner, .engine = tls_null_vtbl(),
            .engine_cfg = nullptr, .role = seal_role_responder,
            .framing = seal_framing_stream });
    if (!tls_wire) {
        fprintf(stderr, "tls_null: tls wire create failed\n");
        duct_engine_destroy(io); duct_wire_destroy(inner);
        return 1;
    }
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "tls-null", .wire = tls_wire,
        .flags = fl_proto_multiplexed,
        .on_frame = s_on_frame,
        .handler_kind = handler_async, .handler_async = s_handler,
        .on_session_open = s_on_session_open,
        .on_error = s_on_error,
    });
    if (!proto) {
        fprintf(stderr, "tls_null: proto create failed\n");
        duct_engine_destroy(io); duct_wire_destroy(tls_wire); duct_wire_destroy(inner);
        return 1;
    }

    uint16_t port = 0u;
    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok) {
        fprintf(stderr, "tls_null: listen failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto);
        return 1;
    }
    pthread_t th;
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        fprintf(stderr, "tls_null: thread create failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto);
        return 1;
    }

    const char *err = nullptr;
    duct_sock_t fd = th_connect(port);
    if (fd == duct_sock_bad) {
        err = "connect failed";
    } else {
        if (!th_wait_int(&g_open_count, 1, 2000u)) err = "session not opened";
        if (!err) err = sc_gate(fd);
        if (!err) err = sc_parked(fd);
        if (!err) err = sc_replay(fd);
        if (!err) err = sc_echo(fd);
        if (!err) err = sc_chunked(fd);
        if (!err) err = sc_auth_fail(fd);
        duct_sock_close(fd);
    }

    if (!err) {
        duct_sock_t fd2 = th_connect(port);
        if (fd2 == duct_sock_bad) {
            err = "second connect failed";
        } else {
            if (!th_wait_int(&g_open_count, 2, 2000u)) err = "second session not opened";
            if (!err) err = sc_server_first_and_close(fd2);
            duct_sock_close(fd2);
        }
    }

    duct_engine_stop(io);
    pthread_join(th, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    duct_wire_destroy(tls_wire);
    duct_wire_destroy(inner);

    if (err) {
        fprintf(stderr, "tls_null: %s\n", err);
        return 1;
    }
    /* Two conns (fd's auth-fail close, fd2's close_notify close), two
     * codecs, each one's whole lifetime spent inside this run: proves
     * duct_wire_codec_t/engine teardown neither leaks the engine instance
     * nor double-frees it, on either close path. */
    if (tls_null_create_calls() != 2u || tls_null_destroy_calls() != 2u) {
        fprintf(stderr, "tls_null: engine create/destroy mismatch (create=%u destroy=%u)\n",
                tls_null_create_calls(), tls_null_destroy_calls());
        return 1;
    }
    if (tls_null_close_notify_calls() != 1u) {
        fprintf(stderr, "tls_null: close_notify call count mismatch (%u)\n",
                tls_null_close_notify_calls());
        return 1;
    }
    printf("tls_null: OK (handshake+gate, parked-handler ct_buf stability, "
           "mid-record defer/replay, auth-failure close, echo/chunked TX, "
           "server-first retry-save, close_notify)\n");
    return 0;
}
