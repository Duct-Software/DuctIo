/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file probe_wait_test.c
 * @brief probe_wait_ms acceptance: a sync
 * preparse that needs real bytes gets a second chance on a client that
 * delays its first send, instead of the immediate-empty-peek fallback
 * committing right away; a client that never sends within the window still
 * falls back exactly as today; one that closes having sent nothing is dropped.
 *
 * peek_min: a listener whose first read has to reach the bytes a lead needs
 * asks nothing of a shorter one. The lead and a frame behind it written in
 * two pieces reach the preparse whole, with the frame intact behind the lead
 * the preparse consumed; a peer that stops short of the lead, or drips it a
 * byte at a time, is cut at probe_wait_ms and what it sent is classified as it
 * stands; a peer that closes short is classified at its close, a FIN right
 * behind its bytes included; one that resets is dropped unclassified; the bind
 * refuses a minimum that can never be met.
 *
 * resolve_hold: a preparse that frames its first read asks the wait for the
 * frame's remaining bytes. A record dripped a byte at a time is held at every
 * short read and resolves whole; a drip that never completes is cut at the
 * deadline the wait armed at the accept, no byte pushing it; a peer that stops
 * and closes resolves at its close, a hold asking an open stream for bytes and
 * never a closed one; a record wider than the listener's read span is never
 * held past the full span. At the largest span a listener takes the boundary
 * sits as anywhere: a hold cut at its last byte closes beyond any fallback,
 * one byte short of it still waits, and a record exactly the span wide
 * resolves whole. A hold cut at the deadline, closed short or past
 * the full span closes the connection: the bytes the holding protocol owned
 * are never offered to the fallback, and no session opens.
 *
 * The reply of an admitted dial, and the park bound: a preparse_reply leaves
 * ahead of the session it admits, the socket's first bytes; a listener full of
 * parked probes classifies the next dial at once instead of parking it, and
 * the parks it holds end at their deadline. A hold the full bound refuses
 * closes unanswered: the reply it staged is held back with the park it could
 * not take, no answer promising a retry the close forbids. A hold answers at
 * its park, once, and the bytes that follow re-classify the connection whole;
 * a dial parked before its first byte is answered on the probe retry those
 * bytes wake.
 */

#include "duct.h"
#include "duct_listener.h"
#include "duct_ticks.h"
#include "test_helpers.h"

#include <signal.h>
#include <stdatomic.h>

static constexpr uint8_t  lead_tag[] = { 'd', 'u', 'c', 't', '-', 'l', 'e', 'a', 'd', '-', 't', 'a', 'g', '-', '1', '6' };
static constexpr uint8_t  frame_hi[] = { 0, 0, 0, 2, 'h', 'i' };
static constexpr size_t   stream_len = sizeof lead_tag + sizeof frame_hi;
static constexpr uint32_t min_wait_ms = 400u;
static constexpr uint64_t min_wait_ns = (uint64_t)min_wait_ms * 1'000'000u;
/* A wait a closing peer must end well ahead of. */
static constexpr uint32_t long_wait_ms = 2000u;
/* The wait is armed at the accept, which can land ahead of the client's own connect returning. */
static constexpr uint64_t cut_lo_ns = min_wait_ns - 50'000'000u;
static constexpr uint64_t cut_hi_ns = min_wait_ns + 600'000'000u;
/* A counter s_counts leaves unchecked. */
static constexpr int any = -1;

static atomic_int       g_content_open  = 0;
static atomic_int       g_fallback_open = 0;
static atomic_int       g_short_asks    = 0;
static atomic_int       g_lead_seen     = 0;
static atomic_int       g_holds         = 0;
static _Atomic uint64_t g_fallback_at;

static duct_result_t
on_content_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_content_open, 1, relaxed);
    return rc_ok;
}

static duct_result_t
on_fallback_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                 [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_fallback_at, duct_ticks_mono_ns(), release);
    duct_atomic_fetch(add, &g_fallback_open, 1, release);
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t cid,
         const duct_frame_t *frame, duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

/** @brief Matches only once real bytes have arrived — resolve_not_me on a
 *  literally empty peek is exactly the condition probe_wait_ms waits out. */
static duct_resolve_disposition_t
content_preparse([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer, duct_view_u8 peek,
                 [[maybe_unused]] duct_handle_t *out_tok, [[maybe_unused]] duct_conn_id_t *out_conn_id,
                 [[maybe_unused]] void **out_user_ctx, [[maybe_unused]] size_t *out_lead)
{
    return peek.size > 0u ? resolve_new : resolve_not_me;
}

/** @brief Takes a read that leads with @c lead_tag and consumes the lead; every
 *  read shorter than the lead is counted, which a listener holding its first
 *  read to the lead's width never lets happen before its deadline. */
static duct_resolve_disposition_t
lead_preparse([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer, duct_view_u8 peek,
              [[maybe_unused]] duct_handle_t *out_tok, [[maybe_unused]] duct_conn_id_t *out_conn_id,
              [[maybe_unused]] void **out_user_ctx, size_t *out_lead)
{
    if (peek.size < sizeof lead_tag) {
        duct_atomic_fetch(add, &g_short_asks, 1, relaxed);
        return resolve_not_me;
    }
    if (memcmp(peek.data, lead_tag, sizeof lead_tag) != 0)
        return resolve_not_me;
    duct_atomic_fetch(add, &g_lead_seen, 1, relaxed);
    *out_lead = sizeof lead_tag;
    return resolve_new;
}

static void s_reset(void)
{
    duct_atomic_store(&g_content_open, 0, relaxed);
    duct_atomic_store(&g_fallback_open, 0, relaxed);
    duct_atomic_store(&g_short_asks, 0, relaxed);
    duct_atomic_store(&g_lead_seen, 0, relaxed);
    duct_atomic_store(&g_holds, 0, relaxed);
    duct_atomic_store(&g_fallback_at, 0u, relaxed);
}

/** @brief Whether the counters hold the given values, in the order short asks, leads seen, content opens,
 *  fallback opens; a value of @c any is not checked. */
static bool s_counts(const char *name, int shorts, int leads, int contents, int fallbacks)
{
    const int got[]  = { duct_atomic_load(&g_short_asks, acquire), duct_atomic_load(&g_lead_seen, acquire),
                         duct_atomic_load(&g_content_open, acquire), duct_atomic_load(&g_fallback_open, acquire) };
    const int want[] = { shorts, leads, contents, fallbacks };
    for (size_t i = 0u; i < sizeof got / sizeof *got; ++i)
        if (want[i] != any && got[i] != want[i]) {
            fprintf(stderr, "probe_wait: %s: short=%d lead=%d content=%d fallback=%d, wanted %d %d %d %d\n",
                    name, got[0], got[1], got[2], got[3], want[0], want[1], want[2], want[3]);
            return false;
        }
    return true;
}

/** @brief Whether the fallback opened between @p lo_ns and @p hi_ns after @p t0. */
static bool s_fallback_between(const char *name, uint64_t t0, uint64_t lo_ns, uint64_t hi_ns)
{
    uint64_t at = duct_atomic_load(&g_fallback_at, acquire);
    if (at >= t0 + lo_ns && at <= t0 + hi_ns)
        return true;
    fprintf(stderr, "probe_wait: %s: the fallback opened %lld ms after the connect, wanted %llu to %llu ms\n",
            name, (long long)((int64_t)(at - t0) / 1'000'000),
            (unsigned long long)(lo_ns / 1'000'000), (unsigned long long)(hi_ns / 1'000'000));
    return false;
}

/** @brief The monotonic ns at which @p fd's peer closed it, polled every 10 ms
 *  for @p bound_ms; 0 when it stayed open the whole bound. */
static uint64_t s_closed_at(duct_sock_t fd, unsigned bound_ms)
{
    for (unsigned waited = 0u; waited < bound_ms; waited += 10u) {
        if (th_peer_closed(fd, 0))
            return duct_ticks_mono_ns();
        th_sleep_ms(10u);
    }
    return th_peer_closed(fd, 0) ? duct_ticks_mono_ns() : 0u;
}

/** @brief Whether the close @p closed_at landed between @p lo_ns and @p hi_ns after @p t0. */
static bool s_closed_between(const char *name, uint64_t closed_at, uint64_t t0,
                             uint64_t lo_ns, uint64_t hi_ns)
{
    if (closed_at >= t0 + lo_ns && closed_at <= t0 + hi_ns)
        return true;
    fprintf(stderr, "probe_wait: %s: the connection closed %lld ms after the connect, wanted %llu to %llu ms\n",
            name, (long long)((int64_t)(closed_at - t0) / 1'000'000),
            (unsigned long long)(lo_ns / 1'000'000), (unsigned long long)(hi_ns / 1'000'000));
    return false;
}

/** @brief One engine on a thread of its own behind a two-proto listener:
 *  @c content (the given sync preparse) tried first, @c fallback
 *  (preparse == nullptr) second; @c client is the connection a scenario dialed. */
typedef struct {
    duct_engine_t *io;
    duct_proto_t  *content, *fallback;
    pthread_t      th;
    uint16_t       port;
    duct_sock_t    client;
    bool           running;
} rig_t;

/** @brief Launch @p rig with a listener that waits @p probe_wait_ms for a first read and holds it to
 *  @p peek_min bytes, reading no more than @p peek_cap of them. @p reply, when set, answers the
 *  content protocol's holds and admissions. @return false on any setup failure;
 *  @c rig_stop releases what exists. */
static bool rig_start_cap(rig_t *rig, uint32_t probe_wait_ms, uint8_t peek_min, size_t peek_cap,
                          duct_preparse_fn preparse, duct_preparse_reply_fn reply)
{
    s_reset();
    *rig = (rig_t){ .client = duct_sock_bad };
    rig->io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!rig->io)
        return false;

    auto content_wire = duct_wire_create_length_prefix(0u);
    auto fallback_wire = duct_wire_create_length_prefix(0u);
    rig->content = duct_proto_create(&(duct_proto_cfg_t){
        .name = "content", .wire = content_wire, .on_frame = on_frame,
        .on_session_open = on_content_open,
        .preparse = preparse, .preparse_reply = reply, .preparse_mode = resolve_sync,
        .max_response = 4096u,
    });
    rig->fallback = duct_proto_create(&(duct_proto_cfg_t){
        .name = "fallback", .wire = fallback_wire, .on_frame = on_frame,
        .on_session_open = on_fallback_open,
        .max_response = 4096u,
    });
    if (rig->content) rig->content->owned_wire = content_wire; else duct_wire_destroy(content_wire);
    if (rig->fallback) rig->fallback->owned_wire = fallback_wire; else duct_wire_destroy(fallback_wire);
    if (!rig->content || !rig->fallback)
        return false;

    if (duct_listener_bind(rig->io, &(duct_listener_cfg_t){
            .addr = "127.0.0.1",
            .n_protos = 2u,
            .protos = (const duct_proto_t *[]){ rig->content, rig->fallback },
            .probe_wait_ms = probe_wait_ms,
            .peek_min = peek_min,
            .peek_cap = peek_cap,
        }, &rig->port, nullptr, 0u, nullptr) != rc_ok)
        return false;
    rig->running = pthread_create(&rig->th, nullptr, th_run, rig->io) == 0;
    return rig->running;
}

/** @brief rig_start_cap at the engine's default read cap. */
static bool rig_start(rig_t *rig, uint32_t probe_wait_ms, uint8_t peek_min, duct_preparse_fn preparse)
{
    return rig_start_cap(rig, probe_wait_ms, peek_min, 0u, preparse, nullptr);
}

static bool rig_dial(rig_t *rig)
{
    rig->client = th_connect(rig->port);
    return rig->client != duct_sock_bad;
}

static void rig_hangup(rig_t *rig)
{
    if (rig->client != duct_sock_bad)
        duct_sock_close(rig->client);
    rig->client = duct_sock_bad;
}

static void rig_reset(rig_t *rig)
{
    th_reset(rig->client);
    rig->client = duct_sock_bad;
}

static void rig_stop(rig_t *rig)
{
    rig_hangup(rig);
    if (rig->running) {
        duct_engine_stop(rig->io);
        pthread_join(rig->th, nullptr);
    }
    if (rig->io)
        duct_engine_destroy(rig->io);
    duct_proto_destroy(rig->content);
    duct_proto_destroy(rig->fallback);
}

static bool rig_put(const rig_t *rig, const uint8_t *data, size_t n)
{
    return send(rig->client, (const char *)data, (int)n, 0) == (int)n;
}

/** @brief The lead with one length-prefix frame, "hi", behind it. */
static void s_stream_fill(uint8_t out[stream_len])
{
    memcpy(out, lead_tag, sizeof lead_tag);
    memcpy(out + sizeof lead_tag, frame_hi, sizeof frame_hi);
}

/* ── Scenario 1: delayed send lands inside the wait window ──────────── */

static bool sc_wait_succeeds(void)
{
    rig_t rig;
    bool ok = rig_start(&rig, 300u, 0u, content_preparse) && rig_dial(&rig);
    if (ok) {
        th_sleep_ms(100u); /* well inside the 300ms probe_wait_ms window */
        ok = th_send(rig.client, "hi", 2u) == 0 && th_wait_int(&g_content_open, 1, 3000u);
    }
    rig_stop(&rig);
    return s_counts("wait_succeeds", any, any, any, 0) && ok;
}

/* ── Scenario 2: nothing ever arrives — today's fallback still applies ── */

static bool sc_wait_times_out(void)
{
    rig_t rig;
    bool ok = rig_start(&rig, 150u, 0u, content_preparse) && rig_dial(&rig);
    /* Deliberately never sent: probe_wait_ms must expire and fall
     * through to today's exact fallback dispatch. */
    ok = ok && th_wait_int(&g_fallback_open, 1, 3000u);
    rig_stop(&rig);
    return s_counts("wait_times_out", any, any, 0, any) && ok;
}

/** @brief A peer that never sends and closes is dropped at its close: no protocol opens, then or at the
 *  deadline, where a silent peer still connected falls back (wait_times_out). */
static bool sc_wait_peer_closes(void)
{
    rig_t rig;
    bool ok = rig_start(&rig, min_wait_ms, 0u, content_preparse) && rig_dial(&rig);
    th_sleep_ms(50u);
    rig_hangup(&rig);
    th_sleep_ms(min_wait_ms + 600u);
    rig_stop(&rig);
    return s_counts("wait_peer_closes", 0, 0, 0, 0) && ok;
}

/* ── Scenario 3: the lead and a frame in two pieces under peek_min ───── */

/** @brief The first piece's width and how long the connection idles before it. */
typedef struct { size_t first; unsigned lag_ms; } split_t;

/** @brief Each split is written to one fresh connection: @c first bytes after @c lag_ms, a pause, the rest.
 *  The preparse is asked once, of the whole lead, never of a shorter read, and the frame behind the lead
 *  echoes whole. */
static bool sc_min_pieces(void)
{
    static const split_t splits[] = {
        { 1u, 0u }, { 3u, 0u }, { 14u, 0u }, { 15u, 0u }, { 16u, 0u }, { 17u, 0u },
        { 1u, 50u }, { 3u, 50u }, { 14u, 50u }, { 15u, 50u }, { 16u, 50u }, { 17u, 50u },
    };
    rig_t rig;
    bool ok = rig_start(&rig, 3000u, sizeof lead_tag, lead_preparse);
    uint8_t stream[stream_len];
    s_stream_fill(stream);
    for (size_t i = 0u; ok && i < sizeof splits / sizeof *splits; ++i) {
        s_reset();
        ok = rig_dial(&rig);
        if (ok) {
            th_sleep_ms(splits[i].lag_ms);
            ok = rig_put(&rig, stream, splits[i].first);
            th_sleep_ms(60u);
            ok = ok && rig_put(&rig, stream + splits[i].first, stream_len - splits[i].first)
                    && th_recv_eq(rig.client, "hi", 2u) == 0;
        }
        rig_hangup(&rig);
        if (!ok || !s_counts("min_pieces", 0, 1, 1, 0)) {
            fprintf(stderr, "probe_wait: min_pieces: first=%zu lag=%u\n", splits[i].first, splits[i].lag_ms);
            ok = false;
        }
    }
    rig_stop(&rig);
    return ok;
}

/** @brief The lead one byte at a time, a pause between, the whole inside the wait. */
static bool sc_min_drip_whole(void)
{
    rig_t rig;
    bool ok = rig_start(&rig, 3000u, sizeof lead_tag, lead_preparse) && rig_dial(&rig);
    uint8_t stream[stream_len];
    s_stream_fill(stream);
    for (size_t i = 0u; ok && i < stream_len; ++i) {
        ok = rig_put(&rig, stream + i, 1u);
        th_sleep_ms(10u);
    }
    ok = ok && th_recv_eq(rig.client, "hi", 2u) == 0;
    rig_stop(&rig);
    return s_counts("min_drip_whole", 0, 1, 1, 0) && ok;
}

/** @brief A peer that stops 3 bytes short of the lead is not resolved before the wait ends, and then the
 *  fallback takes what it sent; the preparse is asked once, of the short read, at the deadline. */
static bool sc_min_short(void)
{
    rig_t rig;
    bool ok = rig_start(&rig, min_wait_ms, sizeof lead_tag, lead_preparse) && rig_dial(&rig);
    uint64_t t0 = duct_ticks_mono_ns();
    ok = ok && rig_put(&rig, lead_tag, sizeof lead_tag - 3u);
    th_sleep_ms(min_wait_ms / 2u);
    ok = ok && s_counts("min_short before the wait ended", 0, any, any, 0)
            && th_wait_int(&g_fallback_open, 1, 3000u)
            && s_fallback_between("min_short", t0, cut_lo_ns, cut_hi_ns);
    rig_stop(&rig);
    return s_counts("min_short", 1, 0, 0, 1) && ok;
}

/** @brief A peer that sends part of the lead and closes is classified at its close, a long way ahead of the wait. */
static bool sc_min_close(void)
{
    rig_t rig;
    bool ok = rig_start(&rig, long_wait_ms, sizeof lead_tag, lead_preparse) && rig_dial(&rig);
    uint64_t t0 = duct_ticks_mono_ns();
    ok = ok && rig_put(&rig, lead_tag, sizeof lead_tag - 3u);
    th_sleep_ms(50u);
    rig_hangup(&rig);
    ok = ok && th_wait_int(&g_fallback_open, 1, 3 * long_wait_ms)
            && s_fallback_between("min_close", t0, 0u, (uint64_t)long_wait_ms * 1'000'000u / 2u);
    rig_stop(&rig);
    return s_counts("min_close", 1, 0, 0, 1) && ok;
}

/** @brief Part of the lead with the close right behind it, in one flight: the FIN read past the last bytes
 *  classifies them at once, a long way ahead of the wait. */
static bool sc_min_close_behind(void)
{
    rig_t rig;
    bool ok = rig_start(&rig, long_wait_ms, sizeof lead_tag, lead_preparse) && rig_dial(&rig);
    uint64_t t0 = duct_ticks_mono_ns();
    ok = ok && rig_put(&rig, lead_tag, sizeof lead_tag - 3u);
    rig_hangup(&rig);
    ok = ok && th_wait_int(&g_fallback_open, 1, 3 * long_wait_ms)
            && s_fallback_between("min_close_behind", t0, 0u, (uint64_t)long_wait_ms * 1'000'000u / 2u);
    rig_stop(&rig);
    return s_counts("min_close_behind", 1, 0, 0, 1) && ok;
}

/** @brief A peer that sends part of the lead and resets is dropped at its reset: nothing is asked of what
 *  it sent and no protocol opens, then or at the deadline. */
static bool sc_min_reset(void)
{
    rig_t rig;
    bool ok = rig_start(&rig, min_wait_ms, sizeof lead_tag, lead_preparse) && rig_dial(&rig);
    ok = ok && rig_put(&rig, lead_tag, sizeof lead_tag - 3u);
    th_sleep_ms(50u);
    rig_reset(&rig);
    th_sleep_ms(min_wait_ms + 600u);
    rig_stop(&rig);
    return s_counts("min_reset", 0, 0, 0, 0) && ok;
}

/** @brief A peer dripping the lead a byte at a time, slower than the wait could ever see it whole, is cut at
 *  the same deadline as a silent one: each byte it sends leaves the deadline where it was. */
static bool sc_min_drip_cut(void)
{
    rig_t rig;
    bool ok = rig_start(&rig, min_wait_ms, sizeof lead_tag, lead_preparse) && rig_dial(&rig);
    uint64_t t0 = duct_ticks_mono_ns();
    for (size_t i = 0u; ok && i < sizeof lead_tag && duct_atomic_load(&g_fallback_open, acquire) == 0; ++i) {
        ok = rig_put(&rig, lead_tag + i, 1u);
        th_sleep_ms(100u);
    }
    ok = ok && th_wait_int(&g_fallback_open, 1, 3000u)
            && s_fallback_between("min_drip_cut", t0, cut_lo_ns, cut_hi_ns);
    rig_stop(&rig);
    return s_counts("min_drip_cut", any, 0, 0, 1) && ok;
}

/* ── Scenario 4: resolve_hold — a preparse that frames its first read ───── */

/** @brief Fill @p out with a record @c n bytes wide: its own width in the first
 *  byte, the rest 'R'. */
static void s_record_fill(uint8_t out[], size_t n)
{
    out[0] = (uint8_t)n;
    memset(out + 1u, 'R', n - 1u);
}

/** @brief Holds for the whole of a self-sized record, the width in its first
 *  byte: @c resolve_hold for any read the record has not filled, resolve_new
 *  consuming it once whole, resolve_not_me for anything a record never was.
 *  Every hold is counted. */
static duct_resolve_disposition_t
record_preparse([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer, duct_view_u8 peek,
                [[maybe_unused]] duct_handle_t *out_tok, [[maybe_unused]] duct_conn_id_t *out_conn_id,
                [[maybe_unused]] void **out_user_ctx, size_t *out_lead)
{
    if (peek.size == 0u)
        return resolve_not_me;
    size_t want = peek.data[0];
    if (want < 4u || want > 64u)
        return resolve_not_me;
    if (peek.size < want) {
        duct_atomic_fetch(add, &g_holds, 1, relaxed);
        return resolve_hold;
    }
    for (size_t i = 1u; i < want; ++i)
        if (peek.data[i] != 'R')
            return resolve_not_me;
    *out_lead = want;
    return resolve_new;
}

/** @brief A record and a frame behind it dripped a byte at a time: every short read holds, the
 *  record resolves whole and the frame behind it echoes intact. */
static bool sc_hold_drip(void)
{
    uint8_t stream[24u + sizeof frame_hi];
    s_record_fill(stream, 24u);
    memcpy(stream + 24u, frame_hi, sizeof frame_hi);
    rig_t rig;
    bool ok = rig_start(&rig, 3000u, 4u, record_preparse) && rig_dial(&rig);
    for (size_t i = 0u; ok && i < sizeof stream; ++i) {
        ok = rig_put(&rig, stream + i, 1u);
        th_sleep_ms(5u);
    }
    ok = ok && th_recv_eq(rig.client, "hi", 2u) == 0;
    rig_stop(&rig);
    return ok && duct_atomic_load(&g_holds, acquire) > 0
              && s_counts("hold_drip", any, any, 1, 0);
}

/** @brief A record whose drip never completes is cut at the deadline the wait armed at the accept:
 *  no held byte pushes it, and the hold closes the connection there — the bytes the holding
 *  protocol owned are never offered past it, no fallback opens. */
static bool sc_hold_cut(void)
{
    uint8_t rec[24];
    s_record_fill(rec, sizeof rec);
    rig_t rig;
    bool ok = rig_start(&rig, min_wait_ms, 4u, record_preparse) && rig_dial(&rig);
    uint64_t t0 = duct_ticks_mono_ns();
    uint64_t closed_at = 0u;
    for (size_t i = 0u; i < sizeof rec - 2u && !closed_at; ++i) {
        if (!rig_put(&rig, rec + i, 1u)) {
            /* The cut's close can beat the next byte out the door: only a peer
             * still standing that refuses one fails the drip. */
            closed_at = th_peer_closed(rig.client, 100u) ? duct_ticks_mono_ns() : 0u;
            break;
        }
        th_sleep_ms(100u);
        if (th_peer_closed(rig.client, 0))
            closed_at = duct_ticks_mono_ns();
    }
    ok = ok && closed_at && s_closed_between("hold_cut", closed_at, t0, cut_lo_ns, cut_hi_ns);
    rig_stop(&rig);
    return ok && s_counts("hold_cut", any, any, 0, 0);
}

/** @brief A record stopped short of whole and closed resolves at the close, long ahead of the
 *  deadline: a hold asks an open stream for its bytes, never a closed one — and the close is the
 *  resolution, the held bytes never offered to the fallback. */
static bool sc_hold_close(void)
{
    uint8_t rec[24];
    s_record_fill(rec, sizeof rec);
    rig_t rig;
    bool ok = rig_start(&rig, long_wait_ms, 4u, record_preparse) && rig_dial(&rig);
    uint64_t t0 = duct_ticks_mono_ns();
    ok = ok && rig_put(&rig, rec, 12u);
    th_sleep_ms(50u);
    ok = ok && shutdown(rig.client, SHUT_WR) == 0;
    uint64_t closed_at = s_closed_at(rig.client, 3u * long_wait_ms);
    ok = ok && closed_at
      && s_closed_between("hold_close", closed_at, t0, 0u, (uint64_t)long_wait_ms * 1'000'000u / 2u);
    rig_stop(&rig);
    return ok && s_counts("hold_close", any, any, 0, 0);
}

/** @brief A record wider than the listener's read span is never held past the full span: the hold
 *  ends where the span does and the connection closes there, long ahead of the deadline, the held
 *  bytes never offered to the fallback. */
static bool sc_hold_span(void)
{
    uint8_t rec[40];
    s_record_fill(rec, sizeof rec);
    rig_t rig;
    bool ok = rig_start_cap(&rig, long_wait_ms, 4u, 32u, record_preparse, nullptr) && rig_dial(&rig);
    uint64_t t0 = duct_ticks_mono_ns();
    ok = ok && rig_put(&rig, rec, sizeof rec);
    uint64_t closed_at = s_closed_at(rig.client, 3u * long_wait_ms);
    ok = ok && closed_at
      && s_closed_between("hold_span", closed_at, t0, 0u, (uint64_t)long_wait_ms * 1'000'000u / 2u);
    rig_stop(&rig);
    return ok && s_counts("hold_span", any, any, 0, 0);
}

/** @brief Fill @p out, @c len bytes, with the head of a self-sized wide record:
 *  its full width in the first two bytes, big-endian, the rest 'R'. */
static void s_wide_record_fill(uint8_t out[], size_t len, size_t width)
{
    out[0] = (uint8_t)(width >> 8);
    out[1] = (uint8_t)width;
    memset(out + 2u, 'R', len - 2u);
}

/** @brief Holds for the whole of a self-sized wide record, its width in the
 *  first two bytes: @c resolve_hold for any read short of the width,
 *  resolve_new consuming it once whole, resolve_not_me for anything a record
 *  never was. Every hold is counted. */
static duct_resolve_disposition_t
wide_record_preparse([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer,
                     duct_view_u8 peek, [[maybe_unused]] duct_handle_t *out_tok,
                     [[maybe_unused]] duct_conn_id_t *out_conn_id,
                     [[maybe_unused]] void **out_user_ctx, size_t *out_lead)
{
    if (peek.size == 0u)
        return resolve_not_me;
    if (peek.size < 2u) {
        duct_atomic_fetch(add, &g_holds, 1, relaxed);
        return resolve_hold;
    }
    size_t want = (size_t)peek.data[0] << 8 | peek.data[1];
    if (want < 4u || want > 4096u)
        return resolve_not_me;
    if (peek.size < want) {
        duct_atomic_fetch(add, &g_holds, 1, relaxed);
        return resolve_hold;
    }
    for (size_t i = 2u; i < want; ++i)
        if (peek.data[i] != 'R')
            return resolve_not_me;
    *out_lead = want;
    return resolve_new;
}

/** @brief The hold boundary at the largest span a listener takes: a record one
 *  byte past it holds at the full span and closes there, beyond any fallback,
 *  long ahead of the deadline; the same record one byte short of the span still
 *  has room and waits the deadline out; a record exactly the span wide resolves
 *  whole, the frame behind it echoing intact. */
static bool sc_hold_span_max(void)
{
    uint8_t rec[DUCT_LISTENER_PEEK_MAX];
    rig_t rig;
    bool ok = rig_start_cap(&rig, min_wait_ms, 4u, DUCT_LISTENER_PEEK_MAX,
                            wide_record_preparse, nullptr);
    if (ok) {
        s_wide_record_fill(rec, sizeof rec, DUCT_LISTENER_PEEK_MAX + 1u);
        ok = rig_dial(&rig);
        uint64_t t0 = duct_ticks_mono_ns();
        ok = ok && rig_put(&rig, rec, sizeof rec);
        uint64_t closed_at = s_closed_at(rig.client, 3u * min_wait_ms);
        ok = ok && closed_at
          && s_closed_between("hold_span_max cut", closed_at, t0, 0u,
                              (uint64_t)min_wait_ms * 1'000'000u / 2u)
          && s_counts("hold_span_max cut", any, any, 0, 0)
          && duct_atomic_load(&g_holds, acquire) > 0;
        rig_hangup(&rig);
    }
    if (ok) {
        s_reset();
        s_wide_record_fill(rec, sizeof rec, DUCT_LISTENER_PEEK_MAX + 1u);
        ok = rig_dial(&rig);
        uint64_t t0 = duct_ticks_mono_ns();
        ok = ok && rig_put(&rig, rec, sizeof rec - 1u)
          && !th_peer_closed(rig.client, 150); /* still waiting, no span close */
        uint64_t closed_at = s_closed_at(rig.client, 3u * min_wait_ms);
        ok = ok && closed_at
          && s_closed_between("hold_span_max wait", closed_at, t0, cut_lo_ns, cut_hi_ns)
          && s_counts("hold_span_max wait", any, any, 0, 0)
          && duct_atomic_load(&g_holds, acquire) > 0;
        rig_hangup(&rig);
    }
    if (ok) {
        s_reset();
        s_wide_record_fill(rec, sizeof rec, DUCT_LISTENER_PEEK_MAX);
        ok = rig_dial(&rig)
          && rig_put(&rig, rec, sizeof rec)
          && rig_put(&rig, frame_hi, sizeof frame_hi)
          && th_recv_eq(rig.client, "hi", 2u) == 0;
        rig_hangup(&rig);
        ok = ok && s_counts("hold_span_max whole", any, any, 1, 0);
    }
    rig_stop(&rig);
    return ok;
}

/* ── Scenario 4b: a hold answers at its park, the re-classified bytes resolve ── */

static atomic_int g_hold_replies;

/** @brief The answer a holding record writes when the wait parks its connection. */
static bool hold_answer([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer,
                        duct_view_u8 *out)
{
    duct_atomic_fetch(add, &g_hold_replies, 1, relaxed);
    *out = (duct_view_u8){ .data = (uint8_t *)"held", .size = 4u };
    return true;
}

/** @brief Holds a short record the way @c record_preparse does, its reply staged for the park. */
static duct_resolve_disposition_t
answer_hold_preparse([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer, duct_view_u8 peek,
                     [[maybe_unused]] duct_handle_t *out_tok, [[maybe_unused]] duct_conn_id_t *out_conn_id,
                     [[maybe_unused]] void **out_user_ctx, size_t *out_lead)
{
    if (peek.size == 0u)
        return resolve_not_me;
    size_t want = peek.data[0];
    if (want < 4u || want > 64u)
        return resolve_not_me;
    if (peek.size < want) {
        duct_atomic_fetch(add, &g_holds, 1, relaxed);
        return resolve_hold;
    }
    for (size_t i = 1u; i < want; ++i)
        if (peek.data[i] != 'R')
            return resolve_not_me;
    *out_lead = want;
    return resolve_new;
}

/** @brief A record stopped short is answered at the park: the reply is the socket's first
 *  write, the record's remaining bytes re-classify it whole, and the admission answers
 *  once more ahead of the session — a hold's answer and an admission's are two writes,
 *  the shape the dance's refusal and its success ride. No fallback opens. */
static bool sc_hold_answer(void)
{
    uint8_t rec[24];
    s_record_fill(rec, sizeof rec);
    duct_atomic_store(&g_hold_replies, 0, relaxed);
    rig_t rig;
    bool ok = rig_start_cap(&rig, 3000u, 4u, 0u, answer_hold_preparse, hold_answer) && rig_dial(&rig);
    ok = ok && rig_put(&rig, rec, 8u);
    char held[4];
    ok = ok && th_read_exact(rig.client, held, sizeof held) == 0
            && memcmp(held, "held", sizeof held) == 0;
    if (!ok) { fprintf(stderr, "hold_answer: first reply missing\n"); goto done; }
    ok = ok && rig_put(&rig, rec + 8u, sizeof rec - 8u);
    ok = ok && th_wait_int(&g_content_open, 1, 3000u);
    if (!ok) { fprintf(stderr, "hold_answer: content did not open\n"); goto done; }
    ok = th_read_exact(rig.client, held, sizeof held) == 0
      && memcmp(held, "held", sizeof held) == 0;
    if (!ok) { fprintf(stderr, "hold_answer: second reply missing\n"); goto done; }
    ok = th_recv_none(rig.client, 150u) == 0;
    if (!ok) { fprintf(stderr, "hold_answer: bytes follow the answers\n"); goto done; }
    ok = duct_atomic_load(&g_hold_replies, acquire) == 2
      && duct_atomic_load(&g_holds, acquire) > 0
      && s_counts("hold_answer", any, any, 1, 0);
    if (!ok) { fprintf(stderr, "hold_answer: counters off (replies=%d holds=%d)\n",
                      duct_atomic_load(&g_hold_replies, acquire), duct_atomic_load(&g_holds, acquire)); }
done:
    rig_stop(&rig);
    return ok;
}

/* ── Scenario 4c: a hold answers on the probe path, the park made before its first byte ── */

/** @brief A hold answered only on the probe path: the accept read finds nothing to
 *  ask of a dial that stays silent, so the listener parks it on its minimum, and
 *  the record's first bytes reach it as a probe retry whose hold writes its answer
 *  before waiting on — the race a first flight sharing its connect's moment runs.
 *  The record's remaining bytes re-classify the connection whole, the admission
 *  answering once more ahead of the session, and no fallback opens. */
static bool sc_hold_park_answer(void)
{
    uint8_t rec[24];
    s_record_fill(rec, sizeof rec);
    duct_atomic_store(&g_hold_replies, 0, relaxed);
    rig_t rig;
    bool ok = rig_start_cap(&rig, 3000u, 4u, 0u, answer_hold_preparse, hold_answer) && rig_dial(&rig);
    th_sleep_ms(200u); /* the accept read gets nothing and parks the dial on peek_min */
    ok = ok && rig_put(&rig, rec, 8u);
    char held[4];
    ok = ok && th_read_exact(rig.client, held, sizeof held) == 0
            && memcmp(held, "held", sizeof held) == 0;
    if (!ok) { fprintf(stderr, "hold_park_answer: first reply missing\n"); goto done; }
    ok = ok && rig_put(&rig, rec + 8u, sizeof rec - 8u);
    ok = ok && th_wait_int(&g_content_open, 1, 3000u);
    if (!ok) { fprintf(stderr, "hold_park_answer: content did not open\n"); goto done; }
    ok = th_read_exact(rig.client, held, sizeof held) == 0
      && memcmp(held, "held", sizeof held) == 0;
    if (!ok) { fprintf(stderr, "hold_park_answer: second reply missing\n"); goto done; }
    ok = duct_atomic_load(&g_hold_replies, acquire) == 2
      && duct_atomic_load(&g_holds, acquire) > 0
      && s_counts("hold_park_answer", any, any, 1, 0);
    if (!ok) { fprintf(stderr, "hold_park_answer: counters off (replies=%d holds=%d)\n",
                      duct_atomic_load(&g_hold_replies, acquire), duct_atomic_load(&g_holds, acquire)); }
done:
    rig_stop(&rig);
    return ok;
}

/* ── Scenario 5: a retry's answer leaves on the stranger's own stream ─── */

static atomic_int g_retried;

/** @brief Answers a stream that opens on the probe byte with @c resolve_retry;
 *  anything else is none of this protocol's. */
static duct_resolve_disposition_t
probe_preparse([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer, duct_view_u8 peek,
               [[maybe_unused]] duct_handle_t *out_tok, [[maybe_unused]] duct_conn_id_t *out_conn_id,
               [[maybe_unused]] void **out_user_ctx, [[maybe_unused]] size_t *out_lead)
{
    if (peek.size < 1u || peek.data[0] != 'P')
        return resolve_not_me;
    duct_atomic_fetch(add, &g_retried, 1, relaxed);
    return resolve_retry;
}

/** @brief The stateless answer a retried stranger's probe earns. */
static bool probe_reply([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer,
                        duct_view_u8 *out)
{
    *out = (duct_view_u8){ .data = (uint8_t *)"pong", .size = 4u };
    return true;
}

/** @brief A stranger that probes is answered on its own connection and the connection
 *  goes, the listener staying open for the next one: no conn, no session, one write. */
static bool sc_retry_answer(void)
{
    s_reset();
    duct_atomic_store(&g_retried, 0, relaxed);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return false;
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "probe", .wire = wire, .on_frame = on_frame,
        .preparse = probe_preparse, .preparse_reply = probe_reply,
        .preparse_mode = resolve_sync, .max_response = 4096u,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    const duct_proto_t *protos[] = { proto };
    uint16_t port = 0u;
    bool ok = proto && duct_listener_bind(io, &(duct_listener_cfg_t){
            .addr = "127.0.0.1", .n_protos = 1u, .protos = protos, .probe_wait_ms = 500u,
        }, &port, nullptr, 0u, nullptr) == rc_ok;
    pthread_t th;
    bool running = ok && pthread_create(&th, nullptr, th_run, io) == 0;
    if (ok) {
        duct_sock_t first = th_connect(port);
        duct_sock_t second = th_connect(port);
        char pong[4];
        ok = first != duct_sock_bad && second != duct_sock_bad
          && send(first, "P", 1, 0) == 1
          && th_read_exact(first, pong, sizeof pong) == 0
          && memcmp(pong, "pong", sizeof pong) == 0
          && th_peer_closed(first, 1000)
          && send(second, "P", 1, 0) == 1
          && th_read_exact(second, pong, sizeof pong) == 0
          && memcmp(pong, "pong", sizeof pong) == 0
          && th_peer_closed(second, 1000);
        if (first != duct_sock_bad)
            close(first);
        if (second != duct_sock_bad)
            close(second);
    }
    if (running) {
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return ok && duct_atomic_load(&g_retried, acquire) == 2
              && s_counts("retry_answer", any, any, 0, 0);
}

/* ── Scenario 6: an admitted stream's answer leaves ahead of its session ── */

static atomic_int g_new_opens;

/** @brief Admits any non-empty read as a new session, naming a user ctx the open sees. */
static duct_resolve_disposition_t
admit_preparse([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer, duct_view_u8 peek,
               [[maybe_unused]] duct_handle_t *out_tok, [[maybe_unused]] duct_conn_id_t *out_conn_id,
               void **out_user_ctx, [[maybe_unused]] size_t *out_lead)
{
    if (peek.size < 1u)
        return resolve_not_me;
    *out_user_ctx = (void *)1;
    return resolve_new;
}

/** @brief Counts the opens that carried the preparse's user ctx. */
static duct_result_t
on_admit_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
              void *user_ctx, [[maybe_unused]] duct_response_t *out,
              [[maybe_unused]] void *proto_state)
{
    if (user_ctx == (void *)1)
        duct_atomic_fetch(add, &g_new_opens, 1, relaxed);
    return rc_ok;
}

/** @brief The fixed answer an admitted dial reads ahead of the session's own bytes. */
static bool admit_reply([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer,
                        duct_view_u8 *out)
{
    *out = (duct_view_u8){ .data = (uint8_t *)"welc", .size = 4u };
    return true;
}

/** @brief A dial the preparse admits is answered first: the reply's bytes are the
 *  socket's first, the session then opens with the preparse's user ctx and its echo
 *  follows the reply. */
static bool sc_new_answer(void)
{
    s_reset();
    duct_atomic_store(&g_new_opens, 0, relaxed);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return false;
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "admit", .wire = wire, .on_frame = on_frame,
        .on_session_open = on_admit_open,
        .preparse = admit_preparse, .preparse_reply = admit_reply,
        .preparse_mode = resolve_sync, .max_response = 4096u,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    const duct_proto_t *protos[] = { proto };
    uint16_t port = 0u;
    bool ok = proto && duct_listener_bind(io, &(duct_listener_cfg_t){
            .addr = "127.0.0.1", .n_protos = 1u, .protos = protos, .probe_wait_ms = 500u,
        }, &port, nullptr, 0u, nullptr) == rc_ok;
    pthread_t th;
    bool running = ok && pthread_create(&th, nullptr, th_run, io) == 0;
    if (ok) {
        duct_sock_t client = th_connect(port);
        ok = client != duct_sock_bad;
        if (ok) {
            th_sleep_ms(100u); /* the frame lands as one read */
            char head[4];
            ok = th_send(client, "hi", 2u) == 0
              && th_read_exact(client, head, sizeof head) == 0
              && memcmp(head, "welc", sizeof head) == 0
              && th_recv_eq(client, "hi", 2u) == 0;
        }
        if (client != duct_sock_bad)
            close(client);
    }
    if (running) {
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return ok && duct_atomic_load(&g_new_opens, acquire) == 1;
}

/* ── Scenario 7: the probe parks one listener holds are bounded ───────── */

/** @brief The over-cap dial of a listener whose parks are full: it is classified at
 *  once, its short read asked of the preparse and its fd closed long ahead of the
 *  wait, while every parked connection stays open to the deadline that ends it. */
static bool sc_park_cap(void)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return false;
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "parked", .wire = wire, .on_frame = on_frame,
        .preparse = lead_preparse, .preparse_mode = resolve_sync, .max_response = 4096u,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    const duct_proto_t *protos[] = { proto };
    uint16_t port = 0u;
    bool ok = proto && duct_listener_bind(io, &(duct_listener_cfg_t){
            .addr = "127.0.0.1", .n_protos = 1u, .protos = protos,
            .probe_wait_ms = long_wait_ms, .peek_min = sizeof lead_tag,
        }, &port, nullptr, 0u, nullptr) == rc_ok;
    pthread_t th;
    bool running = ok && pthread_create(&th, nullptr, th_run, io) == 0;
    duct_sock_t held[DUCT_LISTENER_PROBE_PARK_MAX + 1u] = {};
    if (ok) {
        size_t partial = sizeof lead_tag - 3u;
        for (size_t i = 0u; ok && i < DUCT_LISTENER_PROBE_PARK_MAX; ++i) {
            held[i] = th_connect(port);
            ok = held[i] != duct_sock_bad
              && send(held[i], (const char *)lead_tag, (int)partial, 0) == (int)partial;
        }
        th_sleep_ms(300u); /* the parks settle ahead of the over-cap dial */
        held[DUCT_LISTENER_PROBE_PARK_MAX] = th_connect(port);
        ok = ok && held[DUCT_LISTENER_PROBE_PARK_MAX] != duct_sock_bad
              && send(held[DUCT_LISTENER_PROBE_PARK_MAX], (const char *)lead_tag, (int)partial, 0)
                     == (int)partial
              && th_peer_closed(held[DUCT_LISTENER_PROBE_PARK_MAX], 1500)
              && !th_peer_closed(held[0], 100)
              && !th_peer_closed(held[DUCT_LISTENER_PROBE_PARK_MAX / 2u], 100)
              && s_counts("park_cap", 1, 0, 0, 0)
              && th_peer_closed(held[0], (int)long_wait_ms + 3000);
    }
    for (size_t i = 0u; i < sizeof held / sizeof *held; ++i)
        if (held[i] != duct_sock_bad)
            close(held[i]);
    if (running) {
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return ok;
}

/* ── Scenario 7b: a hold the full park bound refuses closes unanswered ── */

/** @brief The over-cap hold of a listener whose parks are full: no reply
 *  strands ahead of the close that forbids the retry it promised, the staged
 *  answer held back with the park it could not take — while the one park of
 *  room to spare is answered and holds. An accept read ahead of the dial's
 *  bytes closes past the hold the same silent way, so the over-cap dial is
 *  retried until its bytes reach the preparse. */
static bool sc_hold_park_refused(void)
{
    s_reset();
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return false;
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "held-full", .wire = wire, .on_frame = on_frame,
        .preparse = answer_hold_preparse, .preparse_reply = hold_answer,
        .preparse_mode = resolve_sync, .max_response = 4096u,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    const duct_proto_t *protos[] = { proto };
    uint16_t port = 0u;
    bool ok = proto && duct_listener_bind(io, &(duct_listener_cfg_t){
            .addr = "127.0.0.1", .n_protos = 1u, .protos = protos,
            .probe_wait_ms = long_wait_ms, .peek_min = 4u,
        }, &port, nullptr, 0u, nullptr) == rc_ok;
    pthread_t th;
    bool running = ok && pthread_create(&th, nullptr, th_run, io) == 0;
    duct_sock_t held[DUCT_LISTENER_PROBE_PARK_MAX] = {};
    duct_sock_t over = duct_sock_bad;
    if (ok) {
        uint8_t rec[24];
        s_record_fill(rec, sizeof rec);
        char answer[4];
        /* The one park of room to spare: its hold is answered and holds. */
        held[0] = th_connect(port);
        ok = held[0] != duct_sock_bad
          && send(held[0], (const char *)rec, 8, 0) == 8
          && th_read_exact(held[0], answer, sizeof answer) == 0
          && memcmp(answer, "held", sizeof answer) == 0
          && !th_peer_closed(held[0], 150);
        for (size_t i = 1u; ok && i < DUCT_LISTENER_PROBE_PARK_MAX; ++i) {
            held[i] = th_connect(port);
            ok = held[i] != duct_sock_bad
              && send(held[i], (const char *)rec, 8, 0) == 8;
        }
        th_sleep_ms(300u); /* the parks settle ahead of the over-cap dial */
        int holds0 = duct_atomic_load(&g_holds, acquire);
        bool pinned = false;
        for (unsigned attempt = 0u; ok && !pinned && attempt < 5u; ++attempt) {
            over = th_connect(port);
            ok = over != duct_sock_bad
              && send(over, (const char *)rec, 8, 0) == 8
              && th_read_exact(over, answer, sizeof answer) != 0
              && th_peer_closed(over, 1500);
            pinned = ok && duct_atomic_load(&g_holds, acquire) > holds0;
            if (over != duct_sock_bad) {
                close(over);
                over = duct_sock_bad;
            }
        }
        ok = ok && pinned && !th_peer_closed(held[1], 100)
              && s_counts("hold_park_refused", any, any, 0, 0);
    }
    if (over != duct_sock_bad)
        close(over);
    for (size_t i = 0u; i < sizeof held / sizeof *held; ++i)
        if (held[i] != duct_sock_bad)
            close(held[i]);
    if (running) {
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return ok;
}

/* ── Scenario 8: a minimum that can never be met is refused at the bind ── */

static bool sc_min_args(void)
{
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return false;
    auto stream_wire = duct_wire_create_length_prefix(0u);
    auto dgram_wire = duct_wire_create_dgram_batch(0u, false);
    auto stream_proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "args-stream", .wire = stream_wire, .on_frame = on_frame, .max_response = 4096u });
    auto dgram_proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "args-dgram", .wire = dgram_wire, .on_frame = on_frame, .max_response = 4096u });
    if (stream_proto) stream_proto->owned_wire = stream_wire; else duct_wire_destroy(stream_wire);
    if (dgram_proto) dgram_proto->owned_wire = dgram_wire; else duct_wire_destroy(dgram_wire);

    const char *err = !stream_proto || !dgram_proto ? "proto create failed" : nullptr;
    const duct_proto_t *stream_protos[] = { stream_proto };
    const duct_proto_t *dgram_protos[] = { dgram_proto };
    struct { const char *what; duct_listener_cfg_t cfg; duct_result_t want; } cases[] = {
        { "a minimum within the default read cap",
          { .addr = "127.0.0.1", .n_protos = 1u, .protos = stream_protos, .probe_wait_ms = 100u,
            .peek_min = 32u }, rc_ok },
        { "a minimum past the default read cap, within an explicit one",
          { .addr = "127.0.0.1", .n_protos = 1u, .protos = stream_protos, .probe_wait_ms = 100u,
            .peek_min = 255u, .peek_cap = 512u }, rc_ok },
        { "a minimum equal to the largest read cap a listener takes",
          { .addr = "127.0.0.1", .n_protos = 1u, .protos = stream_protos, .probe_wait_ms = 100u,
            .peek_cap = 4096u, .peek_min = DUCT_LISTENER_PEEK_MAX }, rc_ok },
        { "a minimum past the largest read cap a listener takes",
          { .addr = "127.0.0.1", .n_protos = 1u, .protos = stream_protos, .probe_wait_ms = 100u,
            .peek_cap = 4096u, .peek_min = DUCT_LISTENER_PEEK_MAX + 1u }, rc_invalid_arg },
        { "a minimum equal to the read cap",
          { .addr = "127.0.0.1", .n_protos = 1u, .protos = stream_protos, .probe_wait_ms = 100u,
            .peek_cap = 8u, .peek_min = 8u }, rc_ok },
        { "a minimum past the read cap",
          { .addr = "127.0.0.1", .n_protos = 1u, .protos = stream_protos, .probe_wait_ms = 100u,
            .peek_cap = 8u, .peek_min = 9u }, rc_invalid_arg },
        { "a minimum with no wait to hold it",
          { .addr = "127.0.0.1", .n_protos = 1u, .protos = stream_protos, .peek_min = 4u }, rc_invalid_arg },
        { "a datagram listener without a minimum",
          { .kind = listener_dgram, .addr = "127.0.0.1", .n_protos = 1u, .protos = dgram_protos }, rc_ok },
        { "a datagram listener with a minimum",
          { .kind = listener_dgram, .addr = "127.0.0.1", .n_protos = 1u, .protos = dgram_protos,
            .probe_wait_ms = 100u, .peek_min = 4u }, rc_invalid_arg },
    };
    for (size_t i = 0u; !err && i < sizeof cases / sizeof *cases; ++i) {
        uint16_t port = 0u;
        if (duct_listener_bind(io, &cases[i].cfg, &port, nullptr, 0u, nullptr) != cases[i].want)
            err = cases[i].what;
    }
    if (err)
        fprintf(stderr, "probe_wait: min_args: %s\n", err);

    duct_engine_destroy(io);
    duct_proto_destroy(stream_proto);
    duct_proto_destroy(dgram_proto);
    return !err;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif
    int pass = 1;

    if (!sc_wait_succeeds())  { fprintf(stderr, "probe_wait: wait_succeeds failed\n");  pass = 0; }
    if (!sc_wait_times_out()) { fprintf(stderr, "probe_wait: wait_times_out failed\n"); pass = 0; }
    if (!sc_wait_peer_closes()) { fprintf(stderr, "probe_wait: wait_peer_closes failed\n"); pass = 0; }
    if (!sc_min_pieces())     { fprintf(stderr, "probe_wait: min_pieces failed\n");     pass = 0; }
    if (!sc_min_drip_whole()) { fprintf(stderr, "probe_wait: min_drip_whole failed\n"); pass = 0; }
    if (!sc_min_short())      { fprintf(stderr, "probe_wait: min_short failed\n");      pass = 0; }
    if (!sc_min_close())      { fprintf(stderr, "probe_wait: min_close failed\n");      pass = 0; }
    if (!sc_min_close_behind()) { fprintf(stderr, "probe_wait: min_close_behind failed\n"); pass = 0; }
    if (!sc_min_reset())      { fprintf(stderr, "probe_wait: min_reset failed\n");      pass = 0; }
    if (!sc_min_drip_cut())   { fprintf(stderr, "probe_wait: min_drip_cut failed\n");   pass = 0; }
    if (!sc_hold_drip())      { fprintf(stderr, "probe_wait: hold_drip failed\n");      pass = 0; }
    if (!sc_hold_cut())       { fprintf(stderr, "probe_wait: hold_cut failed\n");       pass = 0; }
    if (!sc_hold_close())     { fprintf(stderr, "probe_wait: hold_close failed\n");     pass = 0; }
    if (!sc_hold_span())      { fprintf(stderr, "probe_wait: hold_span failed\n");      pass = 0; }
    if (!sc_hold_span_max())  { fprintf(stderr, "probe_wait: hold_span_max failed\n");  pass = 0; }
    if (!sc_retry_answer())   { fprintf(stderr, "probe_wait: retry_answer failed\n");   pass = 0; }
    if (!sc_new_answer())     { fprintf(stderr, "probe_wait: new_answer failed\n");     pass = 0; }
    if (!sc_hold_answer())    { fprintf(stderr, "probe_wait: hold_answer failed\n");    pass = 0; }
    if (!sc_hold_park_answer()) { fprintf(stderr, "probe_wait: hold_park_answer failed\n"); pass = 0; }
    if (!sc_park_cap())       { fprintf(stderr, "probe_wait: park_cap failed\n");       pass = 0; }
    if (!sc_hold_park_refused()) { fprintf(stderr, "probe_wait: hold_park_refused failed\n"); pass = 0; }
    if (!sc_min_args())       { fprintf(stderr, "probe_wait: min_args failed\n");       pass = 0; }

    if (pass) {
        printf("probe_wait: OK (delayed-send match inside window, timeout falls back, "
               "peek_min holds a short first read to the lead and cuts it at the deadline, "
               "resolve_hold holds a framing preparse to its whole frame "
               "and ends one at the largest span a listener takes, "
               "a retry's reply leaves on the stranger's own stream, "
               "an admitted dial's reply leaves ahead of its session, "
               "a full park bound classifies the next dial at once, its refused hold "
               "closing unanswered)\n");
        return 0;
    }
    return 1;
}
