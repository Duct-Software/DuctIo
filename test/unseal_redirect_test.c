/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file unseal_redirect_test.c
 * @brief Decrypt straight into the destination leg's egress memory.
 *
 * A Noise responder on a datagram listener carries two outbound legs: conn 1 is
 * host-driven, conn 2 a device, and route sends the client's frames to whichever
 * the scenario picks. Either way the worker reserves on that leg before the
 * unseal and hands the engine that span, so the AEAD writes the plaintext once,
 * where it will be sent from.
 *
 * The proof is pointer identity: on_frame records the address its plaintext
 * arrived at, and on_packet_out and the device's write_commit compare the
 * address they are handed.
 *
 * Three more payloads cover what a reservation must survive. One the handler
 * drops, one it answers from a static buffer of its own, one it answers with the
 * head of the held span alone; all leave the reservation unsent, and an echo
 * after each proves the destination came back whole — an unclosed one holds the
 * producer's cursors apart and silences that leg for good.
 *
 * Both wires carry a cleartext prefix, eight bytes out of the client and eight
 * off the server's ingress, which puts the reservation's own sizing under test.
 * The last device scenario caps write_reserve at exactly what its payload
 * unseals to: an answer that counts the prefix in asks for more than the
 * destination holds, write_reserve refuses, and the redirect degrades to a copy
 * with nothing else to show for it. Every payload before it is small enough to
 * clear the cap on either sizing, which is why the cap is what separates them.
 *
 * The device half is skipped where duct_conn_attach_device has no waitable form,
 * which is Windows under poll; the closing line says which halves ran.
 */

#include "duct.h"
#include "duct_tls.h"
#include "duct_noise.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/eventfd.h>
#include <unistd.h>
#endif

#include "test_helpers.h"

static constexpr unsigned wait_ms = 5000u;
static constexpr duct_conn_id_t ur_host_leg = 1u;
static constexpr duct_conn_id_t ur_dev_leg  = 2u;

/** Cleartext bytes the client leads every PDU with and the server strips off
 *  every one it receives. Nothing ever sets the content, so they are zeros —
 *  the width alone is what the sizing has to account for. */
static constexpr uint8_t ur_prefix_len = 8u;

static const char ur_echo[]   = "redirect-me";
static const char ur_drop[]   = "drop-me";
static const char ur_static[] = "static-me";
static const char ur_short[]  = "head-then-tail";
static constexpr size_t ur_short_keep = 4u;
static const char ur_reply[]  = "from-a-static-buffer";

static _Atomic(const void *) g_frame_at;
static _Atomic(const void *) g_out_at;
static atomic_int g_out_count = 0;
static atomic_int g_srv_frames = 0;
static atomic_int g_srv_errors = 0;
static atomic_int g_out_len = 0;
static char g_out_data[64];

#ifdef _WIN32
typedef HANDLE ur_signal_t;
static ur_signal_t ur_signal_open(void) { return CreateEventW(nullptr, FALSE, FALSE, nullptr); }
static void ur_signal_close(ur_signal_t d) { CloseHandle(d); }
#else
typedef int ur_signal_t;
static ur_signal_t ur_signal_open(void)
{
    int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    return fd < 0 ? 0 : fd;
}
static void ur_signal_close(ur_signal_t d) { close(d); }
#endif

static ur_signal_t g_dev_event = 0;
static constexpr unsigned ur_dev_slots = 4u;
static constexpr unsigned ur_dev_slot_bytes = 2048u;
static char g_dev_ring[ur_dev_slots][ur_dev_slot_bytes];
static unsigned g_dev_next = 0u;
static _Atomic(const void *) g_dev_at;
static atomic_int g_dev_commits = 0;
static atomic_int g_dev_abandons = 0;
static atomic_int g_dev_len = 0;
static atomic_int g_dev_joined = 0;
static char g_dev_data[64];

static duct_result_t ur_dev_read([[maybe_unused]] void *ctx,
                                 [[maybe_unused]] duct_view_u8 *out,
                                 [[maybe_unused]] unsigned max, unsigned *n)
{
    *n = 0u;
    return rc_again;
}

/** Largest reservation @ref ur_dev_reserve answers, bytes. @ref ur_device_exact
 *  lowers it to one payload and restores it, leaving every other scenario at
 *  the ring slot's own size. */
static _Atomic(size_t) g_dev_cap = ur_dev_slot_bytes;

/** @brief Hand out the next ring slot, under two bounds of different kinds.
 *  @c ur_dev_slot_bytes is what a slot physically holds; @c g_dev_cap is what
 *  the running scenario allows, and only the second ever moves. */
static void *ur_dev_reserve([[maybe_unused]] void *ctx, size_t size)
{
    if (size > ur_dev_slot_bytes || size > duct_atomic_load(&g_dev_cap, acquire))
        return nullptr;
    auto slot = g_dev_ring[g_dev_next];
    g_dev_next = (g_dev_next + 1u) % ur_dev_slots;
    return slot;
}

static duct_result_t ur_dev_commit([[maybe_unused]] void *ctx, void *buf, size_t len)
{
    if (len == 0u) {
        duct_atomic_fetch(add, &g_dev_abandons, 1, release);
        return rc_ok;
    }
    duct_atomic_store(&g_dev_at, buf, release);
    size_t n = len < sizeof g_dev_data ? len : sizeof g_dev_data;
    memcpy(g_dev_data, buf, n);
    duct_atomic_store(&g_dev_len, (int)n, release);
    duct_atomic_fetch(add, &g_dev_commits, 1, release);
    return rc_ok;
}

static void ur_dev_release([[maybe_unused]] void *ctx) {}

static duct_result_t
ur_srv_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    if (g_dev_event)
        duct_discard duct_conn_attach_device(s, ur_dev_leg, &(duct_device_ops_t){
            .wait_handle = (void *)(uintptr_t)g_dev_event,
            .read = ur_dev_read,
            .write_reserve = ur_dev_reserve,
            .write_commit = ur_dev_commit,
            .release = ur_dev_release,
        });
    out->control.open_leg.kind = leg_kind_inter;
    out->control.open_leg.conn_id = ur_host_leg;
    return rc_ok;
}

static duct_result_t
ur_srv_join([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
            [[maybe_unused]] const duct_peer_t *peer,
            [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    if (conn_id == ur_dev_leg)
        duct_atomic_fetch(add, &g_dev_joined, 1, release);
    return rc_ok;
}

static _Atomic(unsigned) g_route_to = ur_host_leg;

static void ur_route([[maybe_unused]] duct_conn_id_t in_conn,
                     [[maybe_unused]] duct_stream_id_t in_stream,
                     [[maybe_unused]] void *proto_state,
                     duct_conn_id_t *out_conn,
                     [[maybe_unused]] duct_stream_id_t *out_stream)
{
    *out_conn = (duct_conn_id_t)duct_atomic_load(&g_route_to, acquire);
}

static duct_result_t
ur_srv_error([[maybe_unused]] duct_session_t *s, duct_result_t err,
             [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_srv_errors, 1, release);
    return rc_ok;
}

static bool ur_is(const duct_frame_t *frame, const char *lit, size_t len)
{
    return frame->payload.size == len && memcmp(frame->payload.data, lit, len) == 0;
}

static duct_result_t
ur_srv_frame([[maybe_unused]] duct_session_t *s,
             [[maybe_unused]] duct_conn_id_t conn_id,
             const duct_frame_t *frame, duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_frame_at, frame->payload.data, release);
    duct_atomic_fetch(add, &g_srv_frames, 1, release);
    if (ur_is(frame, ur_drop, sizeof ur_drop - 1u))
        return rc_drop;
    if (ur_is(frame, ur_static, sizeof ur_static - 1u)) {
        out->payload = (duct_view_u8){ (void *)ur_reply, sizeof ur_reply - 1u };
        out->flags = fl_send_static;
        out->conn_id = ur_host_leg;
        return rc_ok;
    }
    if (ur_is(frame, ur_short, sizeof ur_short - 1u)) {
        duct_response_echo(out, frame);
        out->payload.size = ur_short_keep;
        return rc_ok;
    }
    duct_response_echo(out, frame);
    return rc_ok;
}

static void ur_run(void (*fn)(void *ctx), void *ctx, [[maybe_unused]] void *queue_ctx)
{
    fn(ctx);
}

static void ur_packet_out([[maybe_unused]] void *app_ctx,
                          [[maybe_unused]] duct_handle_t tok,
                          [[maybe_unused]] duct_conn_id_t conn_id, duct_view_u8 pkt)
{
    duct_atomic_store(&g_out_at, pkt.data, release);
    size_t n = pkt.size < sizeof g_out_data ? pkt.size : sizeof g_out_data;
    memcpy(g_out_data, pkt.data, n);
    duct_atomic_store(&g_out_len, (int)n, release);
    duct_atomic_fetch(add, &g_out_count, 1, release);
}

static _Atomic(duct_handle_t) g_cli_tok;

static duct_result_t
ur_cli_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_cli_tok, tok, release);
    out->payload = (duct_view_u8){ (void *)ur_echo, sizeof ur_echo - 1u };
    out->flags = fl_send_copy;
    return rc_ok;
}

static duct_result_t
ur_send([[maybe_unused]] duct_session_t *s, duct_response_t *out, void *ctx)
{
    out->payload = *(const duct_view_u8 *)ctx;
    out->flags = fl_send_copy;
    return rc_ok;
}

static duct_result_t
ur_cli_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             [[maybe_unused]] const duct_frame_t *frame,
             [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

static const char *ur_push(duct_engine_t *io, const char *lit, size_t len)
{
    duct_view_u8 buf = { (void *)lit, len };
    auto tok = duct_atomic_load(&g_cli_tok, acquire);
    if (!tok)
        return "client session never opened";
    return duct_session_invoke_sync(io, tok, ur_send, &buf) == rc_ok
         ? nullptr : "client send failed";
}

static const char *ur_round(duct_engine_t *io, const char *lit, size_t len)
{
    int before = duct_atomic_load(&g_out_count, acquire);
    auto err = ur_push(io, lit, len);
    if (err) return err;
    if (!th_wait_int(&g_out_count, before + 1, wait_ms))
        return "on_packet_out never fired";
    return nullptr;
}

/** @brief The zero-copy claim on the host leg: the plaintext on_frame saw and
 *  the bytes on_packet_out delivers are one buffer at one address.
 */
static const char *ur_direct(duct_engine_t *io)
{
    auto err = ur_round(io, ur_echo, sizeof ur_echo - 1u);
    if (err) return err;
    if (duct_atomic_load(&g_out_len, acquire) != (int)(sizeof ur_echo - 1u)
        || memcmp(g_out_data, ur_echo, sizeof ur_echo - 1u) != 0)
        return "echoed payload did not survive the redirect";
    if (duct_atomic_load(&g_out_at, acquire) != duct_atomic_load(&g_frame_at, acquire))
        return "plaintext was copied: on_frame and on_packet_out saw two addresses";
    return nullptr;
}

/** @brief rc_drop leaves the reservation unsent; the echo that follows proves
 *  the lane's producer cursors came back together.
 */
static const char *ur_dropped(duct_engine_t *io)
{
    int before = duct_atomic_load(&g_out_count, acquire);
    auto err = ur_push(io, ur_drop, sizeof ur_drop - 1u);
    if (err) return err;
    th_sleep_ms(200u);
    if (duct_atomic_load(&g_out_count, acquire) != before)
        return "a dropped frame still reached on_packet_out";
    return ur_direct(io);
}

/** @brief A response the handler owns instead of the held span: the commit
 *  copies it the old way, the reservation is abandoned, delivery continues.
 */
static const char *ur_fallback(duct_engine_t *io)
{
    auto err = ur_round(io, ur_static, sizeof ur_static - 1u);
    if (err) return err;
    if (duct_atomic_load(&g_out_len, acquire) != (int)(sizeof ur_reply - 1u)
        || memcmp(g_out_data, ur_reply, sizeof ur_reply - 1u) != 0)
        return "static response did not reach on_packet_out";
    if (duct_atomic_load(&g_out_at, acquire) == duct_atomic_load(&g_frame_at, acquire))
        return "static response was mistaken for the held span";
    return ur_direct(io);
}

/** @brief An answer that is only the head of the held span goes out as a packet of its own.
 *
 *  The head is copied into a new lane slot, so on_packet_out sees an address other than the
 *  plaintext's, and the held slot is abandoned: the echo after it proves the lane came back whole.
 */
static const char *ur_host_short(duct_engine_t *io)
{
    auto err = ur_round(io, ur_short, sizeof ur_short - 1u);
    if (err) return err;
    if (duct_atomic_load(&g_out_len, acquire) != (int)ur_short_keep
        || memcmp(g_out_data, ur_short, ur_short_keep) != 0)
        return "the host did not get the head of the frame alone";
    if (duct_atomic_load(&g_out_at, acquire) == duct_atomic_load(&g_frame_at, acquire))
        return "a short answer was published from the held span";
    return ur_direct(io);
}

/** @brief The same claim against a device leg, whose reservation is its own
 *  send memory rather than a lane slot.
 */
static const char *ur_device(duct_engine_t *io)
{
    int before = duct_atomic_load(&g_dev_commits, acquire);
    duct_atomic_store(&g_route_to, ur_dev_leg, release);
    auto err = ur_push(io, ur_echo, sizeof ur_echo - 1u);
    if (err) return err;
    if (!th_wait_int(&g_dev_commits, before + 1, wait_ms))
        return "device write_commit never fired";
    if (duct_atomic_load(&g_dev_len, acquire) != (int)(sizeof ur_echo - 1u)
        || memcmp(g_dev_data, ur_echo, sizeof ur_echo - 1u) != 0)
        return "device payload did not survive the redirect";
    if (duct_atomic_load(&g_dev_at, acquire) != duct_atomic_load(&g_frame_at, acquire))
        return "plaintext was copied on its way to the device";
    return nullptr;
}

/** @brief Reservation sizing where the destination holds exactly one payload.
 *
 *  The cap is what this payload unseals to, so an answer counting the conn's RX
 *  prefix asks for more than the device has and @c write_reserve refuses, which
 *  leaves the packet on the copy path and breaks the pointer identity every
 *  device scenario checks. The cap is restored on every exit, including a failed
 *  push, so a scenario added after this one starts from the ring slot again.
 */
static const char *ur_device_exact(duct_engine_t *io)
{
    size_t len = sizeof ur_echo - 1u;
    int before = duct_atomic_load(&g_dev_commits, acquire);
    duct_atomic_store(&g_route_to, ur_dev_leg, release);
    duct_atomic_store(&g_dev_cap, len, release);
    auto err = ur_push(io, ur_echo, len);
    const char *fail = nullptr;
    if (err)
        fail = err;
    else if (!th_wait_int(&g_dev_commits, before + 1, wait_ms))
        fail = "nothing reached the device at its exact cap";
    else if (duct_atomic_load(&g_dev_at, acquire)
             != duct_atomic_load(&g_frame_at, acquire))
        fail = "the redirect fell back to a copy at the device's exact cap";
    duct_atomic_store(&g_dev_cap, (size_t)ur_dev_slot_bytes, release);
    return fail;
}

/** @brief An answer that is only the head of the held span is not committed in place.
 *
 *  A device whose packets keep the size they were reserved at, as a Wintun send packet does, would
 *  send the whole reservation. The engine copies the head into a reservation of its own size, commits
 *  that, and hands the held one back as a zero-length commit.
 */
static const char *ur_device_short(duct_engine_t *io)
{
    int commits = duct_atomic_load(&g_dev_commits, acquire),
        abandons = duct_atomic_load(&g_dev_abandons, acquire);
    duct_atomic_store(&g_route_to, ur_dev_leg, release);
    auto err = ur_push(io, ur_short, sizeof ur_short - 1u);
    if (err) return err;
    if (!th_wait_int(&g_dev_commits, commits + 1, wait_ms))
        return "device write_commit never fired for a short answer";
    if (duct_atomic_load(&g_dev_len, acquire) != (int)ur_short_keep
        || memcmp(g_dev_data, ur_short, ur_short_keep) != 0)
        return "the device did not get the head of the frame alone";
    if (duct_atomic_load(&g_dev_at, acquire) == duct_atomic_load(&g_frame_at, acquire))
        return "a short answer was committed from the held span";
    if (!th_wait_int(&g_dev_abandons, abandons + 1, wait_ms))
        return "the held reservation was not handed back";
    return nullptr;
}

/** @brief A dropped frame reaches the device as a zero-length commit, its
 *  contract for a reservation that sends nothing.
 */
static const char *ur_device_dropped(duct_engine_t *io)
{
    int before = duct_atomic_load(&g_dev_abandons, acquire);
    duct_atomic_store(&g_route_to, ur_dev_leg, release);
    auto err = ur_push(io, ur_drop, sizeof ur_drop - 1u);
    if (err) return err;
    if (!th_wait_int(&g_dev_abandons, before + 1, wait_ms))
        return "a dropped frame left the device reservation open";
    return ur_device(io);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    duct_noise_keypair_t srv_kp, cli_kp;
    if (!duct_noise_keypair_generate(&srv_kp)
        || !duct_noise_keypair_generate(&cli_kp)) {
        fprintf(stderr, "unseal_redirect: keypair generation failed\n");
        return 1;
    }
    g_dev_event = ur_signal_open();
    duct_noise_cfg_t srv_cfg = { .local_static = srv_kp };
    duct_noise_cfg_t cli_cfg = { .local_static = cli_kp };
    memcpy(cli_cfg.remote_static_pub, srv_kp.pub, duct_noise_key_size);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){
        .io_threads = 1, .workers = 1,
        .host = { .on_packet_out = ur_packet_out, .run = ur_run },
    });
    if (!io) {
        fprintf(stderr, "unseal_redirect: io create failed\n");
        return 1;
    }

    duct_proto_t *proto = nullptr, *cli_proto = nullptr;
    duct_wire_t *wire = nullptr, *cli_wire = nullptr;
    const char *err = nullptr;
    pthread_t th;
    bool running = false;
    bool dev_ran = false;
    uint16_t port = 0u;
    char addr[64];

    wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .engine = duct_noise_vtbl(), .engine_cfg = &srv_cfg,
        .role = seal_role_responder, .framing = seal_framing_datagram,
        .rx_prefix_len = ur_prefix_len });
    if (!wire) { err = "server sealed wire create failed"; goto done; }
    proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "unseal-redirect", .wire = wire,
        .on_frame = ur_srv_frame,
        .on_session_open = ur_srv_open,
        .on_conn_join = ur_srv_join,
        .on_error = ur_srv_error,
        .route = ur_route,
        .max_response = 2048u,
        .flags = fl_proto_dgram_shared,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    wire = nullptr;
    if (!proto) { err = "server proto create failed"; goto done; }

    if (duct_listener_bind(io, &(duct_listener_cfg_t){
            .kind = listener_dgram, .addr = "127.0.0.1",
            .n_protos = 1, .protos = (const duct_proto_t *[]){ proto },
        }, &port, nullptr, 0u, nullptr) != rc_ok) {
        err = "listener bind failed";
        goto done;
    }
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        err = "engine thread create failed";
        goto done;
    }
    running = true;

    cli_wire = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .engine = duct_noise_vtbl(), .engine_cfg = &cli_cfg,
        .role = seal_role_initiator, .framing = seal_framing_datagram,
        .tx_prefix_len = ur_prefix_len });
    if (!cli_wire) { err = "client sealed wire create failed"; goto done; }
    cli_proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "unseal-redirect-cli", .wire = cli_wire,
        .on_frame = ur_cli_frame,
        .on_session_open = ur_cli_open,
        .max_response = 2048u,
    });
    if (cli_proto) cli_proto->owned_wire = cli_wire; else duct_wire_destroy(cli_wire);
    cli_wire = nullptr;
    if (!cli_proto) { err = "client proto create failed"; goto done; }

    snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)port);
    if (duct_io_connect(io, addr, cli_proto, nullptr, x_udp_peer) != rc_ok) {
        err = "client connect failed";
        goto done;
    }
    if (!th_wait_int(&g_out_count, 1, wait_ms)) {
        err = "the client's opening payload never reached on_packet_out";
        goto done;
    }
    err = ur_direct(io);
    if (!err) err = ur_dropped(io);
    if (!err) err = ur_fallback(io);
    if (!err) err = ur_host_short(io);
    if (!err && duct_atomic_load(&g_dev_joined, acquire) > 0) {
        dev_ran = true;
        err = ur_device(io);
        if (!err) err = ur_device_dropped(io);
        if (!err) err = ur_device_exact(io);
        if (!err) err = ur_device_short(io);
        duct_atomic_store(&g_route_to, ur_host_leg, release);
        if (!err) err = ur_direct(io);
    }

done:
    if (running) {
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    if (proto) duct_proto_destroy(proto);
    if (cli_proto) duct_proto_destroy(cli_proto);
    if (wire) duct_wire_destroy(wire);
    if (cli_wire) duct_wire_destroy(cli_wire);
    if (g_dev_event) ur_signal_close(g_dev_event);

    if (err) {
        fprintf(stderr, "unseal_redirect: %s (srv_frames=%d out=%d errors=%d)\n", err,
                duct_atomic_load(&g_srv_frames, acquire),
                duct_atomic_load(&g_out_count, acquire),
                duct_atomic_load(&g_srv_errors, acquire));
        return 1;
    }
    printf("unseal_redirect: OK (host lane by pointer identity, abandon on "
           "drop, copy fallback on an owned response and on a short answer; device leg %s)\n",
           dev_ran ? "same, sized past the RX prefix at its exact cap, and a short answer copied"
                   : "not reachable on this events model");
    return 0;
}
