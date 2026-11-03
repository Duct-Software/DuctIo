/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file timer_start_test.c
 *  @brief The timer that belongs to no session, @c duct_timer_start, on a live
 *  engine of two workers.
 *
 *  @c sc_once expects a timer to fire once, near its delay, on a thread other
 *  than the caller's, with a null session, the caller's context and its token.
 *  @c sc_zero expects a delay of 0 to fire without waiting. @c sc_chain expects
 *  a timer started from a fire to fire in turn, the four steps once each and in
 *  order. @c sc_owned expects the payload a fire stages with @c fl_send_owned
 *  to be released once. @c sc_args expects a null engine, a null protocol, a
 *  delay that overflows microseconds and a protocol with no @c on_timer to be
 *  refused as arguments. @c sc_stop expects a stopped engine to refuse a timer
 *  as out of order.
 */

#include "duct.h"
#include "duct_ticks.h"
#include "test_helpers.h"

#include <stdatomic.h>

/** @brief Return @p msg from the calling check when @p cond fails. */
#define expect(cond, msg) do { if (!(cond)) return msg; } while (0)

/** @brief Longest wait for an event, milliseconds. */
static constexpr unsigned wait_ms = 3000u;
/** @brief One millisecond, nanoseconds. */
static constexpr uint64_t ms      = 1'000'000u;
/** @brief Token that makes @c on_timer stage an owned payload. */
static constexpr uintptr_t owned  = 0xfeedu;

/** @brief What one fire saw. */
typedef struct {
    void     *session,  /**< Session the fire ran with, null for a timer of no session. */
             *state;    /**< The @c proto_state the fire was given. */
    pthread_t thread;   /**< Thread the fire ran on. */
    uint64_t  at;       /**< Time of the fire on the tick clock, nanoseconds. */
    uintptr_t arg;      /**< Token the fire carried. */
} fire_t;

/** @brief The engine. */
static duct_engine_t *g_io;
/** @brief The protocol the timers start against. */
static duct_proto_t  *g_proto;
/** @brief Context handed to every timer; its address is the state a fire must see. */
static int            g_ctx;
/** @brief What each of the first 16 fires saw, in order. */
static fire_t         g_log[16];
/** @brief Fires since the scenario began. */
static atomic_int     g_fires    = 0;
/** @brief Releases of the owned payload since the scenario began. */
static atomic_int     g_released = 0;
/** @brief 1 while a fire with a token under 3 starts its successor. */
static atomic_int     g_chain    = 0;

/** @brief Count one release of the owned payload. */
static void s_release(void *arg)
{
    duct_discard arg;
    duct_atomic_fetch(add, &g_released, 1, release);
}

/** @brief Take every frame and answer none. */
static duct_result_t on_frame([[maybe_unused]] duct_session_t *s,
                              [[maybe_unused]] duct_conn_id_t conn_id,
                              [[maybe_unused]] const duct_frame_t *frame,
                              [[maybe_unused]] duct_response_t *out,
                              [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

/** @brief Log the fire, stage an owned payload for the @c owned token, and under @c g_chain start the next step.
 *  The next step comes 20 ms later with the token one more, while the token is under 3.
 */
static duct_result_t on_timer(duct_session_t *s, duct_response_t *out, void *proto_state,
                              uint64_t arg)
{
    int at = duct_atomic_load(&g_fires, relaxed);
    if (at < (int)(sizeof g_log / sizeof g_log[0]))
        g_log[at] = (fire_t){ .session = s, .state = proto_state, .thread = pthread_self(),
                              .at = duct_ticks_mono_ns(), .arg = (uintptr_t)arg };
    duct_atomic_fetch(add, &g_fires, 1, release);
    if (arg == owned) {
        static uint8_t bytes[4];
        out->payload = duct_view(duct_view_u8, bytes, sizeof bytes);
        out->flags = fl_send_owned;
        out->release = s_release;
    }
    if (duct_atomic_load(&g_chain, relaxed) && arg < 3u)
        duct_discard duct_timer_start(g_io, g_proto, &g_ctx, 20u, (uintptr_t)arg + 1u);
    return rc_ok;
}

/** @brief Clear the counts between scenarios. */
static void s_reset(void)
{
    duct_atomic_store(&g_fires, 0, relaxed);
    duct_atomic_store(&g_released, 0, relaxed);
    duct_atomic_store(&g_chain, 0, relaxed);
}

/** @brief Start a timer of @p delay_ms with token @p arg, retrying while the engine answers @c rc_invalid_order.
 *  @return the first other result; @c rc_invalid_order once @c wait_ms has run out.
 */
static duct_result_t s_start(uint64_t delay_ms, uintptr_t arg)
{
    duct_result_t rc = rc_invalid_order;
    for (unsigned waited = 0u; waited < wait_ms; waited += 5u) {
        rc = duct_timer_start(g_io, g_proto, &g_ctx, delay_ms, arg);
        if (rc != rc_invalid_order)
            return rc;
        th_sleep_ms(5u);
    }
    return rc;
}

/** @brief Start one timer of 100 ms and read its fire.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_once(void)
{
    uint64_t began = duct_ticks_mono_ns();
    expect(s_start(100u, 77u) == rc_ok, "a timer was refused on a running engine");
    expect(th_wait_int(&g_fires, 1, wait_ms), "the timer never fired");
    expect(g_log[0].at - began >= 90u * ms && g_log[0].at - began < 1000u * ms,
           "the timer fired far from its delay");
    expect(!g_log[0].session && g_log[0].state == &g_ctx && g_log[0].arg == 77u,
           "the fire did not carry a null session, the caller's context and its token");
    expect(!pthread_equal(g_log[0].thread, pthread_self()), "the timer fired on the thread that started it");
    th_sleep_ms(300u);
    expect(duct_atomic_load(&g_fires, acquire) == 1, "a one-shot timer fired twice");
    return nullptr;
}

/** @brief Start a timer of no delay and time its fire.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_zero(void)
{
    uint64_t began = duct_ticks_mono_ns();
    expect(s_start(0u, 5u) == rc_ok, "a timer of no delay was refused");
    expect(th_wait_int(&g_fires, 1, wait_ms), "a timer of no delay never fired");
    expect(g_log[0].at - began < 200u * ms, "a timer of no delay waited");
    return nullptr;
}

/** @brief Start a timer whose fires start the next three and read their order.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_chain(void)
{
    duct_atomic_store(&g_chain, 1, release);
    expect(s_start(20u, 0u) == rc_ok, "a timer was refused on a running engine");
    expect(th_wait_int(&g_fires, 4, wait_ms), "a timer started from a fire did not fire");
    th_sleep_ms(200u);
    expect(duct_atomic_load(&g_fires, acquire) == 4, "the chain fired more than its four steps");
    for (unsigned i = 0u; i < 4u; ++i)
        expect(g_log[i].arg == i, "the chain's tokens are out of order");
    return nullptr;
}

/** @brief Start a timer whose fire stages an owned payload and count the releases.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_owned(void)
{
    expect(s_start(0u, owned) == rc_ok, "a timer was refused on a running engine");
    expect(th_wait_int(&g_fires, 1, wait_ms), "the timer never fired");
    th_sleep_ms(100u);
    expect(duct_atomic_load(&g_released, acquire) == 1, "the payload the fire staged was not released once");
    return nullptr;
}

/** @brief Offer arguments the call refuses.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_args(void)
{
    expect(duct_timer_start(nullptr, g_proto, &g_ctx, 10u, 0u) == rc_invalid_arg, "a null engine was taken");
    expect(duct_timer_start(g_io, nullptr, &g_ctx, 10u, 0u) == rc_invalid_arg, "a null protocol was taken");
    expect(duct_timer_start(g_io, g_proto, &g_ctx, UINT64_MAX, 0u) == rc_invalid_arg,
           "a delay that overflows was taken");
    auto bare = duct_proto_create(&(duct_proto_cfg_t){ .name = "timer-start-bare", .on_frame = on_frame,
                                                       .max_response = 64u });
    expect(bare, "proto create failed");
    auto rc = duct_timer_start(g_io, bare, &g_ctx, 10u, 0u);
    duct_proto_destroy(bare);
    expect(rc == rc_invalid_arg, "a protocol with no on_timer was taken");
    return nullptr;
}

/** @brief Leave a timer of 60 s pending, stop the engine and start another.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_stop(void)
{
    expect(s_start(60'000u, 1u) == rc_ok, "a timer was refused on a running engine");
    duct_engine_stop(g_io);
    expect(duct_timer_start(g_io, g_proto, &g_ctx, 10u, 0u) == rc_invalid_order,
           "a timer was taken by a stopped engine");
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    g_proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "timer-start", .on_frame = on_frame, .on_timer = on_timer, .max_response = 64u,
    });
    g_io = g_proto ? duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 2 }) : nullptr;
    if (!g_io) {
        fprintf(stderr, "timer_start: setup failed\n");
        return 1;
    }
    static const struct { const char *name; const char *(*fn)(void); } cases[] = {
        { "once",  sc_once },
        { "zero",  sc_zero },
        { "chain", sc_chain },
        { "owned", sc_owned },
        { "args",  sc_args },
        { "stop",  sc_stop },
    };
    int failed = 0;
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        s_reset();
        auto err = cases[i].fn();
        if (err) {
            fprintf(stderr, "timer_start: %s: %s\n", cases[i].name, err);
            ++failed;
        }
    }
    duct_engine_stop(g_io);
    duct_engine_destroy(g_io);
    duct_proto_destroy(g_proto);
    if (failed)
        return 1;
    printf("timer_start: OK\n");
    return 0;
}
