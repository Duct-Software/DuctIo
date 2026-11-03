/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file accept_seed_order_test.c
 * @brief The peek bytes a classified TCP conn is seeded with survive its first
 * read.
 *
 * A proactive backend posts that read when the conn registers, against the ring
 * as it stands right then. Seeding afterwards puts the peek exactly where the
 * pending read will land, so the peer's next bytes overwrite it and the commit
 * accounts them past it — bytes nobody wrote reach the parser as received data.
 * Ordering the seed ahead of the registration is what prevents it, and this
 * holds every admission path to that order.
 *
 * Two protos put the listener past the single-proto fast path, and a preparse
 * that matches on any bytes takes the classification branch. The client waits
 * inside the probe-wait window before its first send, so the peek is non-empty
 * whichever side of the accept race the bytes fall on.
 *
 * The guards matter as much as the comparison: a run whose classification saw
 * an empty peek, or whose fallback proto admitted the conn, reports that it
 * missed rather than passing. A pass that never reached the branch says
 * nothing.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static constexpr size_t first_len  = 32u;
static constexpr size_t second_len = 900u;

static atomic_int g_peek_seen     = 0;
static atomic_int g_content_open  = 0;
static atomic_int g_fallback_open = 0;

static duct_resolve_disposition_t
content_preparse([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer,
                 duct_view_u8 peek, [[maybe_unused]] duct_handle_t *out_tok,
                 [[maybe_unused]] duct_conn_id_t *out_conn_id,
                 [[maybe_unused]] void **out_user_ctx,
                 [[maybe_unused]] size_t *out_lead)
{
    if ((int)peek.size > duct_atomic_load(&g_peek_seen, acquire))
        duct_atomic_store(&g_peek_seen, (int)peek.size, release);
    return peek.size > 0u ? resolve_new : resolve_not_me;
}

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
    duct_atomic_fetch(add, &g_fallback_open, 1, relaxed);
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t cid,
         const duct_frame_t *frame, duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

static bool s_listen(duct_engine_t *io, uint16_t *port,
                     duct_proto_t **out_content, duct_proto_t **out_fallback)
{
    auto content_wire  = duct_wire_create_length_prefix(0u);
    auto fallback_wire = duct_wire_create_length_prefix(0u);
    auto content = duct_proto_create(&(duct_proto_cfg_t){
        .name = "content", .wire = content_wire, .on_frame = on_frame,
        .on_session_open = on_content_open,
        .preparse = content_preparse, .preparse_mode = resolve_sync,
        .max_response = 4096u,
    });
    auto fallback = duct_proto_create(&(duct_proto_cfg_t){
        .name = "fallback", .wire = fallback_wire, .on_frame = on_frame,
        .on_session_open = on_fallback_open,
        .max_response = 4096u,
    });
    if (!content || !fallback) {
        duct_proto_destroy(content);
        duct_proto_destroy(fallback);
        duct_wire_destroy(content_wire);
        duct_wire_destroy(fallback_wire);
        *out_content = nullptr;
        *out_fallback = nullptr;
        return false;
    }
    content->owned_wire = content_wire;
    fallback->owned_wire = fallback_wire;
    *out_content = content;
    *out_fallback = fallback;

    return duct_listener_bind(io, &(duct_listener_cfg_t){
        .addr = "127.0.0.1",
        .n_protos = 2u,
        .protos = (const duct_proto_t *[]){ content, fallback },
        .probe_wait_ms = 500u,
    }, port, nullptr, 0u, nullptr) == rc_ok;
}

static const char *sc_seed_survives(uint16_t port)
{
    char first[first_len], second[second_len];
    memset(first, 'A', sizeof first);
    memset(second, 'B', sizeof second);

    auto fd = th_connect(port);
    if (fd == duct_sock_bad)
        return "connect failed";

    th_sleep_ms(120u);
    const char *err = nullptr;
    if (th_send(fd, first, first_len) != 0)
        err = "first send failed";
    else if (th_recv_eq(fd, first, first_len) != 0)
        err = "first frame never echoed";

    if (!err && duct_atomic_load(&g_peek_seen, acquire) == 0)
        err = "probe missed: classification ran on an empty peek";
    if (!err && duct_atomic_load(&g_content_open, acquire) != 1)
        err = "probe missed: the preparse proto did not admit this conn";
    if (!err && duct_atomic_load(&g_fallback_open, acquire) != 0)
        err = "probe missed: the fallback proto admitted this conn";

    if (!err && th_send(fd, second, second_len) != 0)
        err = "second send failed";
    else if (!err && th_recv_eq(fd, second, second_len) != 0)
        err = "second frame corrupted or lost";

    duct_sock_close(fd);
    return err;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) {
        fprintf(stderr, "accept_seed_order: io create failed\n");
        return 1;
    }

    duct_proto_t *content = nullptr, *fallback = nullptr;
    uint16_t port = 0u;
    const char *err = nullptr;
    pthread_t th;
    bool running = false;

    if (!s_listen(io, &port, &content, &fallback)) {
        err = "listener bind failed";
        goto done;
    }
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        err = "engine thread create failed";
        goto done;
    }
    running = true;
    err = sc_seed_survives(port);

done:
    if (running) {
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(content);
    duct_proto_destroy(fallback);

    if (err) {
        fprintf(stderr, "accept_seed_order: %s (peek=%d open=%d fallback=%d)\n", err,
                duct_atomic_load(&g_peek_seen, acquire),
                duct_atomic_load(&g_content_open, acquire),
                duct_atomic_load(&g_fallback_open, acquire));
        return 1;
    }
    printf("accept_seed_order: OK (peek %d bytes seeded before the first read, "
           "both frames byte-exact)\n", duct_atomic_load(&g_peek_seen, acquire));
    return 0;
}
