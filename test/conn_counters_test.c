/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file conn_counters_test.c
 *  @brief Per-leg traffic tallies over live sessions, read at @c on_conn_lost
 *  and at @c on_session_close.
 *
 *  Each scenario snapshots legs 0 and 1 and the slot past the session's legs
 *  at both callbacks and wants the two snapshots equal to the traffic sent.
 *
 *  @c sc_stream drives a length-prefixed echo with @c max_response 64: echoes
 *  within the cap; a frame over it, refused and reported once as
 *  @c rc_invalid_arg; a frame routed to a leg that is not there, refused on
 *  that slot with no report; a frame the protocol defers once, counted once, at
 *  its replay; and a fence frame behind them.
 *
 *  @c sc_relay, built where device legs exist, relays between a TCP leg and a
 *  device leg that refuses every fourth reservation. Both legs' tallies equal
 *  the traffic of known size, and a response that parks counts once, at the
 *  replay that takes it. The device also reports every fifth commit lost with
 *  @c rc_drop and answers the seventh with a code the contract does not name:
 *  each is refused on the device leg's tally, the first reaches @c on_error as
 *  @c rc_drop, the second as @c rc_invalid_arg, and the leg stays up.
 */

#include "duct.h"
#include "test_helpers.h"

#ifdef CONN_COUNTERS_DEVICE
#include "device_signal.h"
#endif
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/** @brief Longest wait for a session event, milliseconds. */
static constexpr unsigned wait_ms = 15000u;

/** @brief Tallies of legs 0 and 1 and of the slot past the session's legs. */
typedef struct {
    duct_conn_counters_t leg0,  /**< Leg 0, the primary. */
                         leg1,  /**< Leg 1. */
                         past;  /**< Slot @c duct_session_max_legs. */
} snapshot_t;

/** @brief Snapshots one session's callbacks took, and their arrival flags.
 *  The session carries it as @c proto_state. */
typedef struct {
    snapshot_t lost,        /**< Taken as the primary leg is lost. */
               closed;      /**< Taken at session close. */
    atomic_int lost_seen,   /**< 1 once @c lost is written. */
               closed_seen; /**< 1 once @c closed is written. */
} capture_t;

/** @brief Snapshot legs 0 and 1 and the slot past the legs of @p s into @p out. */
static void take(duct_session_t *s, snapshot_t *out)
{
    *out = (snapshot_t){
        .leg0 = duct_conn_counters(s, duct_conn_id_primary),
        .leg1 = duct_conn_counters(s, 1u),
        .past = duct_conn_counters(s, duct_session_max_legs),
    };
}

/** @brief Hand the session @p ctx as its @c proto_state. */
static duct_result_t keep([[maybe_unused]] duct_session_t *s, void *ctx, void **out)
{
    *out = ctx;
    return rc_ok;
}

/** @brief Snapshot the tallies as the primary leg is lost, then close the session. */
static void on_conn_lost(duct_session_t *s, duct_conn_id_t conn_id,
                         [[maybe_unused]] duct_close_reason_t reason, duct_response_t *out,
                         void *proto_state)
{
    if (conn_id == duct_conn_id_primary) {
        auto capture = (capture_t *)proto_state;
        take(s, &capture->lost);
        duct_atomic_store(&capture->lost_seen, 1, release);
        duct_response_close_session(out, close_normal);
    }
}

/** @brief Snapshot the tallies at session close. */
static void on_session_close(duct_session_t *s, [[maybe_unused]] duct_close_reason_t reason,
                             void *proto_state)
{
    auto capture = (capture_t *)proto_state;
    take(s, &capture->closed);
    duct_atomic_store(&capture->closed_seen, 1, release);
}

/** @brief Compare tally @p got of @p leg with @p want, printing both when they differ.
 *  @p when names the callback the snapshot came from. */
static bool tally(const char *when, const char *leg, const duct_conn_counters_t *got,
                  const duct_conn_counters_t *want)
{
    bool same = memcmp(got, want, sizeof *got) == 0;
    if (!same)
        fprintf(stderr, "conn_counters: %s, %s: rx %llu frames %llu bytes, tx %llu frames "
                        "%llu bytes, refused %llu; wanted rx %llu / %llu, tx %llu / %llu, "
                        "refused %llu\n",
                when, leg, (unsigned long long)got->rx_frames,
                (unsigned long long)got->rx_bytes, (unsigned long long)got->tx_frames,
                (unsigned long long)got->tx_bytes, (unsigned long long)got->tx_refused,
                (unsigned long long)want->rx_frames, (unsigned long long)want->rx_bytes,
                (unsigned long long)want->tx_frames, (unsigned long long)want->tx_bytes,
                (unsigned long long)want->tx_refused);
    return same;
}

/** @brief Compare snapshot @p got with @p want leg by leg. */
static bool matches(const char *when, const snapshot_t *got, const snapshot_t *want)
{
    return tally(when, "leg 0", &got->leg0, &want->leg0)
        && tally(when, "leg 1", &got->leg1, &want->leg1)
        && tally(when, "past the legs", &got->past, &want->past);
}

/** @brief Check both snapshots of @p capture against @p want.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *verdict(capture_t *capture, const snapshot_t *want)
{
    return !duct_atomic_load(&capture->lost_seen, acquire) ? "on_conn_lost never fired"
         : !matches("at on_conn_lost", &capture->lost, want)
               ? "the counts at on_conn_lost differ"
         : !matches("at on_session_close", &capture->closed, want)
               ? "the counts at on_session_close differ"
         : nullptr;
}

/** @brief Wait for the session of @p capture to close.
 *  @return nullptr once it has, the failure text on timeout. */
static const char *closed(capture_t *capture)
{
    return th_wait_int(&capture->closed_seen, 1, wait_ms) ? nullptr : "the session never closed";
}

/** @brief Serve @p cfg on a length-prefix wire, run @p client against it, tear the engine down.
 *  @return the text of the first failed step, nullptr when all hold. */
static const char *serve(duct_proto_cfg_t *cfg, const char *(*client)(uint16_t port))
{
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1u, .workers = 1u });
    if (!io)
        return "engine launch failed";
    auto proto = duct_proto_create_owning(cfg, duct_wire_create_length_prefix(0u));
    uint16_t port = 0u;
    const char *err = !proto ? "proto create failed"
                    : duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok ? "listen failed"
                    : nullptr;
    if (!err) {
        pthread_t th;
        if (pthread_create(&th, nullptr, th_run, io) == 0) {
            err = client(port);
            duct_engine_stop(io);
            pthread_join(th, nullptr);
        } else
            err = "thread create failed";
    }
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return err;
}

/** @brief Response cap of the stream protocol, bytes. */
static constexpr size_t cap         = 64u;
/** @brief Frames echoed within the cap. */
static constexpr size_t echo_count  = 4u;
/** @brief Size of each echoed frame, bytes. */
static constexpr size_t echo_size   = 20u;
/** @brief Size of the frame whose echo is over the cap, bytes. */
static constexpr size_t over_size   = 100u;
/** @brief Size of the frame the protocol routes to a leg that is not there, bytes. */
static constexpr size_t stray_size  = 7u;
/** @brief Size of the frame the protocol defers once, bytes. */
static constexpr size_t defer_size  = 9u;
/** @brief Size of the fence frame behind the others, bytes. */
static constexpr size_t fence_size  = 5u;
/** @brief Frames the protocol answers with nothing: the over-cap one and the stray one. */
static constexpr size_t unanswered  = 2u;
/** @brief Echoes that come back after the defer: the deferred frame's and the fence's. */
static constexpr size_t late_echoes = 2u;
/** @brief Pause ahead of the fence, so it arrives after the deferred frame has parked, milliseconds. */
static constexpr unsigned replay_ms = 50u;

/** @brief Snapshots of the stream scenario's session. */
static capture_t g_stream;
/** @brief @c rc_invalid_arg reports the stream protocol received. */
static atomic_int g_refusals = 0;

/** @brief Echo a frame, route the stray size to leg 1, and defer the deferred size once. */
static duct_result_t stream_on_frame([[maybe_unused]] duct_session_t *s,
                                     [[maybe_unused]] duct_conn_id_t conn_id,
                                     const duct_frame_t *frame, duct_response_t *out,
                                     [[maybe_unused]] void *proto_state)
{
    static bool deferred = false;
    if (frame->payload.size == defer_size && !deferred) {
        deferred = true;
        return rc_defer;
    }
    duct_response_forward(out, frame, frame->payload.size == stray_size ? 1u : duct_conn_id_same);
    return rc_ok;
}

/** @brief Count the @c rc_invalid_arg reports. */
static duct_result_t stream_on_error([[maybe_unused]] duct_session_t *s, duct_result_t error,
                                     [[maybe_unused]] duct_response_t *out,
                                     [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_refusals, error == rc_invalid_arg, relaxed);
    return rc_ok;
}

/** @brief Send the stream scenario's frames over @p fd and read the echoes that come back.
 *  @return the text of the first failure, nullptr when all echoes arrive. */
static const char *stream_traffic(duct_sock_t fd)
{
    char frame[128];
    memset(frame, 'x', sizeof frame);
    for (size_t i = 0u; i < echo_count; ++i)
        if (th_send(fd, frame, echo_size) != 0 || th_recv_eq(fd, frame, echo_size) != 0)
            return "an echo within the cap did not come back";
    if (th_send(fd, frame, over_size) != 0 || th_send(fd, frame, stray_size) != 0
        || th_send(fd, frame, defer_size) != 0)
        return "send failed";
    th_sleep_ms(replay_ms);
    return th_send(fd, frame, fence_size) != 0 ? "send failed"
         : th_recv_eq(fd, frame, defer_size) != 0 || th_recv_eq(fd, frame, fence_size) != 0
               ? "the frames behind the refused ones did not come back"
         : nullptr;
}

/** @brief Connect to @p port, run the stream traffic and wait for the session to close. */
static const char *stream_client(uint16_t port)
{
    duct_sock_t fd = th_connect(port);
    if (fd == duct_sock_bad)
        return "connect failed";
    auto err = stream_traffic(fd);
    duct_sock_close(fd);
    return err ? err : closed(&g_stream);
}

/** @brief Run the stream scenario.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_stream(void)
{
    static const snapshot_t want = {
        .leg0 = {
            .rx_frames = echo_count + unanswered + late_echoes,
            .rx_bytes = echo_count * echo_size + over_size + stray_size + defer_size + fence_size,
            .tx_frames = echo_count + late_echoes,
            .tx_bytes = echo_count * echo_size + defer_size + fence_size,
            .tx_refused = 1u,
        },
        .leg1 = { .tx_refused = 1u },
    };
    duct_proto_cfg_t cfg = {
        .name = "counters-stream", .on_frame = stream_on_frame, .on_error = stream_on_error,
        .on_conn_lost = on_conn_lost, .on_session_close = on_session_close,
        .create_state = keep, .create_state_ctx = &g_stream, .max_response = cap,
    };
    auto err = serve(&cfg, stream_client);
    return err ? err
         : duct_atomic_load(&g_refusals, relaxed) != 1
               ? "the oversize response did not reach on_error as rc_invalid_arg once"
         : verdict(&g_stream, &want);
}

#ifdef CONN_COUNTERS_DEVICE

/** @brief Size of each packet the device produces, bytes. */
static constexpr unsigned up_bytes   = 300u;
/** @brief Packets the device produces. */
static constexpr unsigned up_total   = 64u;
/** @brief Size of each frame the peer sends toward the device, bytes. */
static constexpr unsigned down_bytes = 200u;
/** @brief Frames the peer sends toward the device. */
static constexpr unsigned down_total = 30u;
/** @brief Send slots the device holds. */
static constexpr unsigned ring_slots = 4u;
/** @brief Most packets one device read produces. */
static constexpr unsigned read_batch = 32u;
/** @brief Conn id of the device leg. */
static constexpr unsigned device_leg = 1u;
/** @brief The device reports every this-many-th commit lost. */
static constexpr unsigned drop_every = 5u;
/** @brief The one commit the device answers with a code the contract does not name. */
static constexpr unsigned strange_at = 7u;
/** @brief Commits the device reports lost. */
static constexpr unsigned lost_total = down_total / drop_every;

static_assert(strange_at <= down_total && strange_at % drop_every != 0u,
              "the unnamed code answers a commit that is not also a loss");

/** @brief Snapshots of the relay scenario's session. */
static capture_t  g_relay;
static atomic_int g_attach_rc = -1,  /**< Result of the device attach, -1 before it ran. */
                  g_committed = 0,   /**< Frames the device committed. */
                  g_bad_write = 0,   /**< Commits of a size other than @c down_bytes. */
                  g_refused   = 0,   /**< Reservations the device refused. */
                  g_said_drop = 0,   /**< Reports of @c rc_drop that reached @c on_error. */
                  g_said_bad  = 0,   /**< Reports of @c rc_invalid_arg that reached @c on_error. */
                  g_released  = 0;   /**< Times the engine released the device. */

/** @brief Packets the device has yet to produce. */
static unsigned g_left = up_total;
/** @brief Memory the device lends for the packets it produces. */
static uint8_t g_pkt[read_batch][up_bytes];
/** @brief The device's send slots. */
static char     g_ring[ring_slots][down_bytes];
static unsigned g_ring_next = 0u,  /**< Next send slot to hand out. */
                g_reserves  = 0u;  /**< Reservations asked of the device. */

/** @brief The device's readiness handle. */
static th_signal_t g_device_event = 0;

/** @brief Produce up to @p max of the device's packets, @c rc_again once none are left. */
static duct_result_t device_read([[maybe_unused]] void *ctx, duct_view_u8 *out,
                                 unsigned max, unsigned *n)
{
    unsigned produced = 0u;
    for (; produced < max && produced < read_batch && g_left > 0u; ++produced, --g_left) {
        memset(g_pkt[produced], 'u', up_bytes);
        out[produced] = duct_view(duct_view_u8, g_pkt[produced], up_bytes);
    }
    *n = produced;
    return produced ? rc_ok : rc_again;
}

/** @brief Hand out a send slot, refusing every fourth reservation. */
static void *device_write_reserve([[maybe_unused]] void *ctx, size_t size)
{
    if (size > down_bytes)
        return nullptr;
    if (++g_reserves % 4u == 0u) {
        duct_atomic_fetch(add, &g_refused, 1, relaxed);
        return nullptr;
    }
    auto slot = g_ring[g_ring_next];
    g_ring_next = (g_ring_next + 1u) % ring_slots;
    return slot;
}

/** @brief Count a committed frame and a commit of the wrong size, and report the lost ones lost. */
static duct_result_t device_write_commit([[maybe_unused]] void *ctx, [[maybe_unused]] void *buf,
                                         size_t len)
{
    duct_atomic_fetch(add, &g_bad_write, len != down_bytes, release);
    unsigned nth = (unsigned)duct_atomic_fetch(add, &g_committed, 1, release) + 1u;
    return nth % drop_every == 0u ? rc_drop : nth == strange_at ? rc_fatal : rc_ok;
}

/** @brief Count the commits the engine reports through @c on_error. */
static duct_result_t relay_on_error([[maybe_unused]] duct_session_t *s, duct_result_t error,
                                    [[maybe_unused]] duct_response_t *out,
                                    [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_said_drop, error == rc_drop, relaxed);
    duct_atomic_fetch(add, &g_said_bad, error == rc_invalid_arg, relaxed);
    return rc_ok;
}

/** @brief Count a release of the device. */
static void device_release([[maybe_unused]] void *ctx)
{
    duct_atomic_fetch(add, &g_released, 1, release);
}

/** @brief Attach the device as leg 1 and record the attach result. */
static duct_result_t relay_on_session_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                                           [[maybe_unused]] void *user_ctx,
                                           [[maybe_unused]] duct_response_t *out,
                                           [[maybe_unused]] void *proto_state)
{
    g_device_event = th_signal_open();
    duct_device_ops_t ops = {
        .wait_handle = (void *)(intptr_t)g_device_event,
        .read = device_read,
        .write_reserve = device_write_reserve,
        .write_commit = device_write_commit,
        .release = device_release,
        .ctx = (void *)(intptr_t)g_device_event,
    };
    auto rc = g_device_event ? duct_conn_attach_device(s, device_leg, &ops) : rc_no_memory;
    duct_atomic_store(&g_attach_rc, (int)rc, release);
    if (rc != rc_ok && g_device_event) {
        th_signal_close(g_device_event);
        g_device_event = 0;
    }
    return rc_ok;
}

/** @brief Forward a frame from the primary leg to the device and the reverse. */
static duct_result_t relay_on_frame([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
                                    const duct_frame_t *frame, duct_response_t *out,
                                    [[maybe_unused]] void *proto_state)
{
    duct_response_forward(out, frame, conn_id == duct_conn_id_primary ? device_leg
                                                                       : duct_conn_id_primary);
    return rc_ok;
}

/** @brief Let the device produce its packets, read them from @p fd, send the frames toward the device.
 *  @return the text of the first failure, nullptr once the device has committed them all. */
static const char *relay_traffic(duct_sock_t fd)
{
    char buf[up_bytes],
         frame[down_bytes];
    memset(frame, 'd', sizeof frame);
    if (!th_signal_raise(g_device_event))
        return "device signal failed";
    for (unsigned i = 0u; i < up_total; ++i)
        if (th_recv(fd, buf, sizeof buf) != (int64_t)up_bytes)
            return "a packet the device produced did not reach the peer";
    for (unsigned i = 0u; i < down_total; ++i)
        if (th_send(fd, frame, sizeof frame) != 0)
            return "send failed";
    return th_wait_int(&g_committed, (int)down_total, wait_ms) ? nullptr
         : "the peer's frames did not all reach the device";
}

/** @brief Connect to @p port, wait for the device attach, run the relay and wait for the close. */
static const char *relay_client(uint16_t port)
{
    duct_sock_t fd = th_connect(port);
    if (fd == duct_sock_bad)
        return "connect failed";
    auto err = th_wait_int(&g_attach_rc, (int)rc_ok, wait_ms) ? relay_traffic(fd)
             : "duct_conn_attach_device refused the device";
    duct_sock_close(fd);
    return err ? err : closed(&g_relay);
}

/** @brief Run the relay scenario.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_relay(void)
{
    static const snapshot_t want = {
        .leg0 = {
            .rx_frames = down_total, .rx_bytes = down_total * down_bytes,
            .tx_frames = up_total,   .tx_bytes = up_total * up_bytes,
        },
        .leg1 = {
            .rx_frames = up_total,   .rx_bytes = up_total * up_bytes,
            .tx_frames = down_total - lost_total - 1u,
            .tx_bytes = (down_total - lost_total - 1u) * down_bytes,
            .tx_refused = lost_total + 1u,
        },
    };
    duct_proto_cfg_t cfg = {
        .name = "counters-device", .on_frame = relay_on_frame, .on_error = relay_on_error,
        .on_session_open = relay_on_session_open, .on_conn_lost = on_conn_lost,
        .on_session_close = on_session_close, .create_state = keep, .create_state_ctx = &g_relay,
    };
    auto err = serve(&cfg, relay_client);
    if (g_device_event)
        th_signal_close(g_device_event);
    return err ? err
         : duct_atomic_load(&g_refused, acquire) == 0
               ? "no reservation was refused: the retry path never ran"
         : duct_atomic_load(&g_bad_write, acquire) != 0
               ? "the device committed a frame of the wrong size"
         : duct_atomic_load(&g_released, acquire) != 1 ? "the device leg was not released once"
         : duct_atomic_load(&g_said_drop, acquire) != (int)lost_total
               ? "the lost commits did not each reach on_error as rc_drop"
         : duct_atomic_load(&g_said_bad, acquire) != 1
               ? "the commit with an unnamed code did not reach on_error as rc_invalid_arg once"
         : verdict(&g_relay, &want);
}

#endif

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    static const struct { const char *name; const char *(*fn)(void); } cases[] = {
        { "stream", sc_stream },
#ifdef CONN_COUNTERS_DEVICE
        { "relay",  sc_relay },
#endif
    };
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        auto err = cases[i].fn();
        if (err) {
            fprintf(stderr, "conn_counters: %s: %s\n", cases[i].name, err);
            return 1;
        }
    }
    printf("conn_counters: OK\n");
    return 0;
}
