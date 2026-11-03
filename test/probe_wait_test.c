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
 */

#include "duct.h"
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
 *  @p peek_min bytes. @return false on any setup failure; @c rig_stop releases what exists. */
static bool rig_start(rig_t *rig, uint32_t probe_wait_ms, uint8_t peek_min, duct_preparse_fn preparse)
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
        .preparse = preparse, .preparse_mode = resolve_sync,
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
        }, &rig->port, nullptr, 0u, nullptr) != rc_ok)
        return false;
    rig->running = pthread_create(&rig->th, nullptr, th_run, rig->io) == 0;
    return rig->running;
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

/* ── Scenario 4: a minimum that can never be met is refused at the bind ── */

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
        { "a minimum past the default read cap",
          { .addr = "127.0.0.1", .n_protos = 1u, .protos = stream_protos, .probe_wait_ms = 100u,
            .peek_min = 255u }, rc_invalid_arg },
        { "a minimum past the largest read cap a listener takes",
          { .addr = "127.0.0.1", .n_protos = 1u, .protos = stream_protos, .probe_wait_ms = 100u,
            .peek_cap = 4096u, .peek_min = 255u }, rc_invalid_arg },
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
    if (!sc_min_args())       { fprintf(stderr, "probe_wait: min_args failed\n");       pass = 0; }

    if (pass) {
        printf("probe_wait: OK (delayed-send match inside window, timeout falls back, "
               "peek_min holds a short first read to the lead and cuts it at the deadline)\n");
        return 0;
    }
    return 1;
}
