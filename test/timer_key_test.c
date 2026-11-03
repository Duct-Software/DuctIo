/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file timer_key_test.c
 *  @brief Keyed session timers on a live engine: replacement, cancel, the
 *  eight-slot table, an interval, and a fire waiting behind a full TX ring.
 *
 *  A client sends length-prefixed commands over TCP; the protocol turns each
 *  into the timer fields of one response, or into a 64 KB send that fills the
 *  ring, and its timer callback logs the token of every fire. Each scenario
 *  runs on a fresh connection to one engine.
 *
 *  @c sc_replace expects a timer armed under a live key to cancel the holder,
 *  so only the replacement fires, once. @c sc_keys expects timers under two
 *  keys to fire once each. @c sc_cancel expects a zero delay to cancel the
 *  timer under its key, a key with no holder to arm nothing, and a cancelled
 *  key to arm again. @c sc_cancel_id expects a timer cancelled by its id to
 *  free its key, so that a ninth key arms beside seven live ones.
 *  @c sc_unkeyed expects timers with no key never to replace
 *  one another. @c sc_chain expects a fire to arm a timer under the key it
 *  fired under. @c sc_full expects a ninth key to be refused while eight are
 *  live, a live key to be replaceable when the table is full, and a key to be
 *  free once its timer has fired. @c sc_interval expects a keyed interval timer
 *  to repeat, to be replaced by one under its key with no fire of the old one
 *  after the new, and to stop on a cancel under its key.
 *
 *  @c sc_parked and @c sc_pinned fill the ring behind a peer that reads
 *  nothing. A fire that sends runs all the same and its chunk parks, and every
 *  later fire of the session waits until that chunk leaves. @c sc_parked
 *  expects a waiting fire to run once the ring drains and a fire cancelled
 *  under its key meanwhile to be dropped. @c sc_pinned expects a waiting fire
 *  to hold its key's slot, so that a ninth key is refused around it, and to run
 *  once the ring drains.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>

/** @brief Return @p msg from the calling check when @p cond fails. */
#define expect(cond, msg) do { if (!(cond)) return msg; } while (0)

/** @brief Longest wait for an event, milliseconds. */
static constexpr unsigned wait_ms = 5000u;
/** @brief Token bit asking @c on_timer to arm the next step of a chain. */
static constexpr uint32_t chain   = 1u << 16;
/** @brief Token bit asking @c on_timer to send the chunk. */
static constexpr uint32_t sends   = 1u << 17;
/** @brief Fill commands a parked scenario sends ahead of its timers: their
 *  replies outgrow the ring and a 4 MB kernel send buffer together, so one parks. */
static constexpr unsigned fills   = 128u;
/** @brief TX ring capacity the protocol asks of a conn, bytes. */
static constexpr size_t   ring_cap = (size_t)1u << 20u;

/** @brief One command, the payload of a client frame. */
typedef struct {
    uint8_t  op;        /**< Command: 'a' arm, 'u' arm with no key, 'i' arm an interval timer,
                          *  'n' arm and note the timer's id, 'x' cancel the noted id, 'c' cancel
                          *  the key, 'f' send a chunk back to fill the ring. */
    uint32_t key,       /**< Timer key, 0 for none. */
             delay,     /**< Delay before the first fire, milliseconds. */
             interval,  /**< Period of an 'i' timer, milliseconds. */
             arg;       /**< Token the fire carries. */
} cmd_t;

/** @brief The primary leg's TX ring as @c ring_fn read it. */
typedef struct {
    size_t queued,      /**< Bytes io has not yet passed to the kernel. */
           cap;         /**< Capacity, bytes. */
} ring_t;

/** @brief Sessions opened since the scenario began. */
static atomic_int    g_opened = 0;
/** @brief Timer fires since the scenario began. */
static atomic_int    g_fires  = 0;
/** @brief Token of each of the first 64 fires, in order. */
static atomic_uint   g_log[64];
/** @brief Handle of the session the scenario runs on. */
static duct_handle_t g_tok;
/** @brief Payload of the reply an 'f' command asks for. */
static uint8_t       g_chunk[65536];
/** @brief Id of the timer the last 'n' command started; the worker writes and reads it. */
static duct_timer_id_t g_id;

/** @brief Keep the session's handle and count it open. */
static duct_result_t on_session_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok,
                                     [[maybe_unused]] void *user_ctx,
                                     [[maybe_unused]] duct_response_t *out,
                                     [[maybe_unused]] void *proto_state)
{
    g_tok = tok;
    duct_atomic_fetch(add, &g_opened, 1, release);
    return rc_ok;
}

/** @brief Set @p out to carry command @p c.
 *  An 'f' command sends the chunk; any other fills the timer fields, a 'u'
 *  dropping the key, a 'c' the delay and all but an 'i' the interval. An 'n'
 *  asks for the timer's id and an 'x' cancels the id noted.
 */
static void s_apply(duct_response_t *out, const cmd_t *c)
{
    if (c->op == 'f') {
        duct_response_same(out, duct_view(duct_view_u8, g_chunk, sizeof g_chunk),
                           fl_send_static, 0);
        return;
    }
    out->control.timer.key = c->op == 'u' ? 0u : c->key;
    out->control.timer.delay_ms = c->op == 'c' ? 0u : c->delay;
    out->control.timer.interval_ms = c->op == 'i' ? c->interval : 0u;
    out->control.timer.arg = c->arg;
    out->control.timer.id_out = c->op == 'n' ? &g_id : nullptr;
    out->control.timer.cancel_id = c->op == 'x' ? g_id : 0u;
}

/** @brief Apply the command a frame carries to @p out.
 *  @retval rc_invalid_arg  The payload is not one command.
 */
static duct_result_t on_frame([[maybe_unused]] duct_session_t *s,
                              [[maybe_unused]] duct_conn_id_t conn_id,
                              const duct_frame_t *frame, duct_response_t *out,
                              [[maybe_unused]] void *proto_state)
{
    cmd_t c;
    if (frame->payload.size != sizeof c)
        return rc_invalid_arg;
    memcpy(&c, frame->payload.data, sizeof c);
    s_apply(out, &c);
    return rc_ok;
}

/** @brief Log the fire's token, send the chunk for a send token and, for a
 *  chain token with steps left, arm the next one.
 *  The next step comes 30 ms later under the key in bits 8 to 15, its token one
 *  less; the steps left are the token's low byte.
 */
static duct_result_t on_timer([[maybe_unused]] duct_session_t *s, duct_response_t *out,
                              [[maybe_unused]] void *proto_state, uint64_t arg)
{
    int at = duct_atomic_load(&g_fires, relaxed);
    if (at < (int)(sizeof g_log / sizeof g_log[0]))
        duct_atomic_store(&g_log[at], (unsigned)arg, relaxed);
    duct_atomic_fetch(add, &g_fires, 1, release);
    if (arg & sends)
        duct_response_same(out, duct_view(duct_view_u8, g_chunk, sizeof g_chunk),
                           fl_send_static, 0);
    unsigned left = (unsigned)arg & 0xffu;
    if ((arg & chain) && left) {
        out->control.timer.key = ((unsigned)arg >> 8u) & 0xffu;
        out->control.timer.delay_ms = 30u;
        out->control.timer.arg = arg - 1u;
    }
    return rc_ok;
}

/** @brief Apply the command @p ctx points at, from inside the session. */
static duct_result_t apply_fn([[maybe_unused]] duct_session_t *s, duct_response_t *out, void *ctx)
{
    s_apply(out, (const cmd_t *)ctx);
    return rc_ok;
}

/** @brief Read the primary leg's ring into the @c ring_t @p ctx points at, from inside the session. */
static duct_result_t ring_fn(duct_session_t *s, [[maybe_unused]] duct_response_t *out, void *ctx)
{
    auto r = (ring_t *)ctx;
    duct_tx_pos_t end = {};
    r->queued = 0u;
    duct_discard duct_conn_tx_end(s, duct_conn_id_primary, &end, &r->queued);
    r->cap = duct_conn_tx_cap(s, duct_conn_id_primary);
    return rc_ok;
}

/** @brief Clear the counts and the log between scenarios. */
static void s_reset(void)
{
    duct_atomic_store(&g_opened, 0, relaxed);
    duct_atomic_store(&g_fires, 0, relaxed);
    for (size_t i = 0u; i < sizeof g_log / sizeof g_log[0]; ++i)
        duct_atomic_store(&g_log[i], 0u, relaxed);
}

/** @brief Send one command over @p fd as a length-prefixed frame.
 *  @return whether the whole frame went.
 */
static bool s_send(duct_sock_t fd, char op, uint32_t key, uint32_t delay, uint32_t interval,
                   uint32_t arg)
{
    cmd_t c = { .op = (uint8_t)op, .key = key, .delay = delay, .interval = interval, .arg = arg };
    return th_send(fd, &c, sizeof c) == 0;
}

/** @brief Count the logged fires whose token is @p arg. */
static unsigned s_count(unsigned arg)
{
    unsigned n = 0u;
    int fires = duct_atomic_load(&g_fires, acquire);
    for (int i = 0; i < fires && i < (int)(sizeof g_log / sizeof g_log[0]); ++i)
        n += duct_atomic_load(&g_log[i], relaxed) == arg;
    return n;
}

/** @brief What a scenario runs on. */
typedef struct {
    duct_engine_t *io;  /**< The engine. */
    duct_sock_t    fd;  /**< Client socket connected to the engine's listener. */
} link_t;

/** @brief A scenario run on @p link.
 *  @return the text of the first failed check, nullptr when all hold.
 */
typedef const char *(*scenario_t)(link_t *link);

/** @brief Arm key 1 twice and expect the second timer to replace the first.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_replace(link_t *link)
{
    expect(s_send(link->fd, 'a', 1u, 300u, 0u, 11u) && s_send(link->fd, 'a', 1u, 100u, 0u, 22u), "send failed");
    expect(th_wait_int(&g_fires, 1, wait_ms), "the replacing timer never fired");
    th_sleep_ms(500u);
    expect(duct_atomic_load(&g_fires, acquire) == 1 && s_count(22u) == 1u,
           "a timer replaced under its key fired, or the replacing one fired twice");
    return nullptr;
}

/** @brief Arm keys 1 and 2 and expect one fire each.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_keys(link_t *link)
{
    expect(s_send(link->fd, 'a', 1u, 100u, 0u, 1u) && s_send(link->fd, 'a', 2u, 100u, 0u, 2u), "send failed");
    expect(th_wait_int(&g_fires, 2, wait_ms), "a timer under another key replaced the first");
    th_sleep_ms(300u);
    expect(duct_atomic_load(&g_fires, acquire) == 2 && s_count(1u) == 1u && s_count(2u) == 1u,
           "the two keys did not fire once each");
    return nullptr;
}

/** @brief Arm key 3, cancel it and a key with no holder, then arm key 3 again.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_cancel(link_t *link)
{
    expect(s_send(link->fd, 'a', 3u, 300u, 0u, 3u) && s_send(link->fd, 'c', 3u, 0u, 0u, 0u)
               && s_send(link->fd, 'c', 99u, 0u, 0u, 0u),
           "send failed");
    th_sleep_ms(700u);
    expect(duct_atomic_load(&g_fires, acquire) == 0, "a timer cancelled under its key fired");
    expect(s_send(link->fd, 'a', 3u, 50u, 0u, 4u) && th_wait_int(&g_fires, 1, wait_ms),
           "a key cancelled and armed again never fired");
    return nullptr;
}

/** @brief Fill the table with eight keys, cancel the first by its id and arm a ninth key.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_cancel_id(link_t *link)
{
    expect(s_send(link->fd, 'n', 1u, 300u, 0u, 1u), "send failed");
    for (uint32_t k = 2u; k < 9u; ++k)
        expect(s_send(link->fd, 'a', k, 60'000u, 0u, k), "send failed");
    expect(s_send(link->fd, 'x', 0u, 0u, 0u, 0u) && s_send(link->fd, 'a', 9u, 50u, 0u, 9u), "send failed");
    expect(th_wait_int(&g_fires, 1, wait_ms), "a key was refused once the timer holding a slot was cancelled by its id");
    th_sleep_ms(500u);
    expect(duct_atomic_load(&g_fires, acquire) == 1 && s_count(9u) == 1u,
           "the timer cancelled by its id fired, or the ninth key fired twice");
    return nullptr;
}

/** @brief Arm two timers with no key and expect both to fire.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_unkeyed(link_t *link)
{
    expect(s_send(link->fd, 'u', 0u, 100u, 0u, 5u) && s_send(link->fd, 'u', 0u, 100u, 0u, 6u), "send failed");
    expect(th_wait_int(&g_fires, 2, wait_ms), "a timer with no key replaced another");
    return nullptr;
}

/** @brief Arm a chain of three steps under key 4 and expect each step once.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_chain(link_t *link)
{
    uint32_t arg = chain | (4u << 8u) | 2u;
    expect(s_send(link->fd, 'a', 4u, 50u, 0u, arg), "send failed");
    expect(th_wait_int(&g_fires, 3, wait_ms), "a keyed timer re-armed from its own fire did not fire again");
    th_sleep_ms(300u);
    expect(duct_atomic_load(&g_fires, acquire) == 3 && s_count(arg) == 1u && s_count(arg - 1u) == 1u
               && s_count(arg - 2u) == 1u,
           "the chain did not fire its three steps once each");
    return nullptr;
}

/** @brief Fill the eight slots, replace one, offer a ninth key, and offer it again once the table has emptied.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_full(link_t *link)
{
    for (uint32_t k = 10u; k < 18u; ++k)
        expect(s_send(link->fd, 'a', k, 400u, 0u, k), "send failed");
    expect(s_send(link->fd, 'a', 10u, 100u, 0u, 99u), "send failed");
    expect(s_send(link->fd, 'a', 18u, 100u, 0u, 18u), "send failed");
    expect(th_wait_int(&g_fires, 8, wait_ms), "the eight keys did not fire");
    th_sleep_ms(500u);
    expect(duct_atomic_load(&g_fires, acquire) == 8 && s_count(18u) == 0u,
           "a ninth key was taken while eight were live");
    expect(s_count(10u) == 0u && s_count(99u) == 1u,
           "a key replaced while the table was full fired its old timer, or not its new one");
    expect(s_send(link->fd, 'a', 18u, 50u, 0u, 18u) && th_wait_int(&g_fires, 9, wait_ms),
           "a key was refused once every slot's timer had fired");
    return nullptr;
}

/** @brief Arm an interval timer under key 5, replace it, then cancel it by its key.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_interval(link_t *link)
{
    expect(s_send(link->fd, 'i', 5u, 50u, 50u, 7u), "send failed");
    /* An interval keeps increasing this counter while the test thread may
     * be descheduled. Reaching four must not make an exact-three poll fail. */
    for (unsigned waited = 0u; waited < wait_ms
         && duct_atomic_load(&g_fires, acquire) < 3; waited += 10u)
        th_sleep_ms(10u);
    expect(duct_atomic_load(&g_fires, acquire) >= 3, "a keyed interval timer did not repeat");
    expect(s_send(link->fd, 'i', 5u, 50u, 50u, 8u), "send failed");
    int mark = duct_atomic_load(&g_fires, acquire);
    th_sleep_ms(500u);
    int fires = duct_atomic_load(&g_fires, acquire);
    expect(fires > mark + 2, "a keyed interval timer replaced did not repeat");
    bool seen_new = false;
    for (int i = 0; i < fires && i < (int)(sizeof g_log / sizeof g_log[0]); ++i) {
        unsigned arg = duct_atomic_load(&g_log[i], relaxed);
        expect(arg == 7u || arg == 8u, "a fire carries another token than the two armed");
        expect(!(seen_new && arg == 7u), "the replaced interval timer fired after its replacement");
        seen_new = seen_new || arg == 8u;
    }
    expect(seen_new, "the replacing interval timer never fired");
    expect(s_send(link->fd, 'c', 5u, 0u, 0u, 0u), "send failed");
    th_sleep_ms(150u);
    int stopped = duct_atomic_load(&g_fires, acquire);
    th_sleep_ms(400u);
    expect(duct_atomic_load(&g_fires, acquire) == stopped, "a keyed interval timer cancelled by its key fired");
    return nullptr;
}

/** @brief Wait until the primary leg's ring has stayed over half full, unmoved, for 100 ms.
 *  @return false when the session cannot be reached or the ring does not hold within the wait.
 */
static bool s_ring_holds(duct_engine_t *io)
{
    ring_t r = {};
    size_t last = SIZE_MAX;
    unsigned still = 0u;
    for (unsigned waited = 0u; waited < wait_ms && still < 100u; waited += 10u) {
        if (duct_session_invoke_sync(io, g_tok, ring_fn, &r) != rc_ok)
            return false;
        still = r.queued == last && r.queued > r.cap / 2u ? still + 10u : 0u;
        last = r.queued;
        th_sleep_ms(10u);
    }
    return still >= 100u;
}

/** @brief Drain @p n chunks, proving the ring really released room. */
static bool s_drain(duct_sock_t fd, unsigned n)
{
#ifndef __linux__
    /* The small window establishes the blocked fixture. Restore a large
     * window before draining; zero-window probes can otherwise make the
     * 8 MB of queued fixture data take longer than the timer deadline. */
    int cap = 2 * 1024 * 1024;
    duct_discard setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&cap, sizeof cap);
#endif
    char buf[65536];
    for (unsigned i = 0u; i < n; ++i)
        if (th_recv(fd, buf, sizeof buf) != (int64_t)sizeof buf)
            return false;
    return true;
}

/** @brief Fill the ring and let a key-20 fire park its chunk behind the fill replies.
 *  Its ticket comes after the fill reply that parked, so the chunk parks however
 *  much room the ring has left.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *s_park_timer_chunk(link_t *link)
{
    for (unsigned i = 0u; i < fills; ++i)
        expect(s_send(link->fd, 'f', 0u, 0u, 0u, 0u), "send failed");
    expect(s_ring_holds(link->io), "the ring never filled behind a peer that reads nothing");
    cmd_t chunk = { .op = 'a', .key = 20u, .delay = 50u, .arg = sends | 20u };
    expect(duct_session_invoke_sync(link->io, g_tok, apply_fn, &chunk) == rc_ok, "the timer was not armed");
    expect(th_wait_int(&g_fires, 1, wait_ms), "a timer waited for room in a full ring");
    return nullptr;
}

/** @brief Park a timer's chunk, arm keys 21 and 22, cancel 21, drain, and expect 22 alone to fire.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_parked(link_t *link)
{
    auto err = s_park_timer_chunk(link);
    if (err)
        return err;
    cmd_t armed[2] = { { .op = 'a', .key = 21u, .delay = 50u, .arg = 21u },
                       { .op = 'a', .key = 22u, .delay = 50u, .arg = 22u } };
    expect(duct_session_invoke_sync(link->io, g_tok, apply_fn, &armed[0]) == rc_ok
               && duct_session_invoke_sync(link->io, g_tok, apply_fn, &armed[1]) == rc_ok,
           "the timers were not armed");
    th_sleep_ms(300u);
    expect(duct_atomic_load(&g_fires, acquire) == 1,
           "a timer fired while the session's last timer chunk waited parked");
    cmd_t cancel = { .op = 'c', .key = 21u };
    expect(duct_session_invoke_sync(link->io, g_tok, apply_fn, &cancel) == rc_ok, "the timer was not cancelled");
    expect(s_drain(link->fd, fills + 1u), "the chunks did not all drain");
    for (unsigned waited = 0u; waited < wait_ms && !s_count(22u); waited += 10u)
        th_sleep_ms(10u);
    expect(s_count(22u) == 1u, "a waiting timer did not fire once the parked chunk left");
    th_sleep_ms(300u);
    expect(duct_atomic_load(&g_fires, acquire) == 2 && s_count(sends | 20u) == 1u
               && s_count(22u) == 1u && s_count(21u) == 0u,
           "a waiting timer cancelled under its key fired");
    return nullptr;
}

/** @brief Park a timer's chunk, let a key-21 fire wait, take the other seven slots with long timers and offer a ninth key.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_pinned(link_t *link)
{
    auto err = s_park_timer_chunk(link);
    if (err)
        return err;
    cmd_t held = { .op = 'a', .key = 21u, .delay = 50u, .arg = 21u };
    expect(duct_session_invoke_sync(link->io, g_tok, apply_fn, &held) == rc_ok, "the timer was not armed");
    th_sleep_ms(200u);
    expect(duct_atomic_load(&g_fires, acquire) == 1,
           "a timer fired while the session's last timer chunk waited parked");
    for (uint32_t k = 31u; k < 38u; ++k) {
        cmd_t distant = { .op = 'a', .key = k, .delay = 60'000u, .arg = k };
        expect(duct_session_invoke_sync(link->io, g_tok, apply_fn, &distant) == rc_ok,
               "a long timer was not armed");
    }
    cmd_t extra = { .op = 'a', .key = 40u, .delay = 50u, .arg = 40u };
    expect(duct_session_invoke_sync(link->io, g_tok, apply_fn, &extra) == rc_ok, "the ninth timer was not armed");
    expect(s_drain(link->fd, fills + 1u), "the chunks did not all drain");
    for (unsigned waited = 0u; waited < wait_ms && !s_count(21u); waited += 10u)
        th_sleep_ms(10u);
    th_sleep_ms(300u);
    expect(s_count(21u) == 1u, "a waiting timer lost its fire to a key taken meanwhile");
    expect(s_count(40u) == 0u, "a ninth key was taken while a waiting fire held its slot");
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    static const struct { const char *name; scenario_t fn; } cases[] = {
        { "replace",  sc_replace },
        { "keys",     sc_keys },
        { "cancel",   sc_cancel },
        { "cancel_id", sc_cancel_id },
        { "unkeyed",  sc_unkeyed },
        { "chain",    sc_chain },
        { "full",     sc_full },
        { "interval", sc_interval },
        { "parked",   sc_parked },
        { "pinned",   sc_pinned },
    };
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "timer-key", .wire = wire, .on_frame = on_frame, .on_timer = on_timer,
        .on_session_open = on_session_open, .max_response = ring_cap / 2u, .tx_olb_cap = ring_cap,
    }) : nullptr;
    if (!proto) {
        fprintf(stderr, "timer_key: proto create failed\n");
        return 1;
    }
    proto->owned_wire = wire;
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    uint16_t port = 0u;
    pthread_t th;
    if (!io || duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok
        || pthread_create(&th, nullptr, th_run, io) != 0) {
        fprintf(stderr, "timer_key: engine setup failed\n");
        return 1;
    }
    int failed = 0;
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        s_reset();
        link_t link = { .io = io, .fd = th_connect(port) };
#ifndef __linux__
        /* Bound Apple's/Windows' unread-peer window. On Linux, leave receive
         * autotuning enabled: locking a tiny buffer after connect can stall
         * zero-window recovery even after SO_RCVBUF is enlarged. */
        if (link.fd != duct_sock_bad) {
            int cap = 4096;
            duct_discard setsockopt(link.fd, SOL_SOCKET, SO_RCVBUF, (const char *)&cap, sizeof cap);
        }
#endif
        const char *err = link.fd == duct_sock_bad ? "connect failed"
                        : !th_wait_int(&g_opened, 1, wait_ms) ? "the session never opened"
                        : cases[i].fn(&link);
        if (link.fd != duct_sock_bad)
            close(link.fd);
        if (err) {
            fprintf(stderr, "timer_key: %s: %s\n", cases[i].name, err);
            ++failed;
        }
        th_sleep_ms(100u);
    }
    duct_engine_stop(io);
    pthread_join(th, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    if (failed)
        return 1;
    printf("timer_key: OK\n");
    return 0;
}
