/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file dgram_join_refused_test.c
 * @brief A join the worker refuses on a shared datagram socket leaves no trace.
 *
 * A session on an x_udp_shared proto is closed while its worker is parked inside on_frame. A datagram
 * naming that session then reaches io, which still resolves the token: it makes the leg's conn, posts
 * the join and routes the datagram onto the conn's inter lane, arming the worker's bit. Once released,
 * the worker runs the close, refuses the join and hands the conn back to io in one pass, and the armed
 * bit meets a conn it no longer holds. The datagram must never reach on_frame, on_conn_join must never
 * fire, and the lane the bit names is io's to free: under ThreadSanitizer a read of it from the worker
 * after the hand-back is the race, and under AddressSanitizer the use after free.
 *
 * Two events stand in for the time the posts and the pass would otherwise be given. A datagram from a
 * second peer, opening a second session, reaches preparse after the join datagram's whole admission:
 * the listener's io thread classifies the datagrams of its socket in the order they were queued, so
 * its preparse count shows the join and its datagram posted behind the parked worker. After the
 * release, the second session's open runs behind the join in the worker's ctrl queue, and a sync
 * invoke on that session runs in a pass after the one that ran both: it returns once the join has
 * been refused and the armed bit met. The test's engine runs one worker, so the second session is
 * the parked worker's.
 */

#include "duct.h"
#include "duct_wire.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "test_helpers.h"
#include "dgram_test_helpers.h"

static constexpr unsigned wait_ms = 3000u;
static constexpr uint8_t  tag_new = 'N';
static constexpr uint8_t  tag_join = 'J';

static atomic_int g_hold = th_hold_off;
static atomic_int g_open_count = 0;
static atomic_int g_join_count = 0;
static atomic_int g_frames_join = 0;
static atomic_int g_preparse_new = 0;
static atomic_int g_preparse_join = 0;
static _Atomic(duct_handle_t) g_tok;
static _Atomic(duct_handle_t) g_tok_second;

static duct_resolve_disposition_t
preparse([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer, duct_view_u8 peek,
         duct_handle_t *out_tok, duct_conn_id_t *out_conn_id, [[maybe_unused]] void **out_user_ctx,
         [[maybe_unused]] size_t *out_lead)
{
    if (peek.size < 1u)
        return resolve_reject;
    auto tag = *(const uint8_t *)peek.data;
    if (tag == tag_new) {
        duct_atomic_fetch(add, &g_preparse_new, 1, release);
        return resolve_new;
    }
    auto tok = duct_atomic_load(&g_tok, acquire);
    if (tag != tag_join || tok == handle_null)
        return resolve_reject;
    *out_tok = tok;
    *out_conn_id = 1u;
    duct_atomic_fetch(add, &g_preparse_join, 1, release);
    return resolve_join;
}

static duct_result_t
on_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok, [[maybe_unused]] void *user_ctx,
        [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    int opened = duct_atomic_load(&g_open_count, relaxed);
    auto slot = opened == 0 ? &g_tok : &g_tok_second;
    duct_atomic_store(slot, tok, release);
    duct_atomic_store(&g_open_count, opened + 1, release);
    return rc_ok;
}

static duct_result_t
barrier([[maybe_unused]] duct_session_t *s, duct_response_t *out, [[maybe_unused]] void *ctx)
{
    *out = (duct_response_t){};
    return rc_ok;
}

static duct_result_t
on_join([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t cid,
        [[maybe_unused]] const duct_peer_t *peer, [[maybe_unused]] duct_response_t *out,
        [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_join_count, 1, release);
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t cid,
         const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    if (frame->payload.size < 1u)
        return rc_ok;
    if (*(const uint8_t *)frame->payload.data == tag_join) {
        duct_atomic_fetch(add, &g_frames_join, 1, release);
        return rc_ok;
    }
    th_hold_park(&g_hold, wait_ms);
    return rc_ok;
}

static const char *sc_join_refused(void)
{
    static const char hello[] = "Nhello", behind[] = "Jbehind-a-refused-join";

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return "engine launch failed";
    auto wire = duct_wire_create_dgram_batch(0u, false);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "dgram-join-refused", .wire = wire,
        .on_frame = on_frame, .on_session_open = on_open, .on_conn_join = on_join,
        .preparse = preparse, .preparse_mode = resolve_sync,
        .max_response = 4096u, .flags = fl_proto_dgram_shared,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!proto) {
        duct_engine_destroy(io);
        return "proto create failed";
    }
    const duct_proto_t *protos[1] = { proto };
    uint16_t port = 0u;
    pthread_t th = {};
    bool running = false;
    const char *error = nullptr;
    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
            .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
        }, &port, nullptr, 0u, nullptr) != rc_ok)
        error = "bind failed";
    else if (!(running = pthread_create(&th, nullptr, th_run, io) == 0))
        error = "thread create failed";

    duct_sock_t opener = duct_sock_bad,
                joiner = duct_sock_bad,
                second = duct_sock_bad;
    if (!error) {
        opener = uc_connect(port);
        joiner = uc_connect(port);
        second = uc_connect(port);
        if (opener == duct_sock_bad || joiner == duct_sock_bad || second == duct_sock_bad)
            error = "client connect failed";
    }
    if (!error && uc_send(opener, hello, sizeof hello - 1u) != 0)
        error = "opening datagram send failed";
    if (!error && !th_wait_int(&g_hold, th_hold_parked, wait_ms))
        error = "the worker never parked in on_frame";
    if (!error && duct_session_close(io, duct_atomic_load(&g_tok, acquire), close_peer) != rc_ok)
        error = "session close refused";
    if (!error && uc_send(joiner, behind, sizeof behind - 1u) != 0)
        error = "joining datagram send failed";
    if (!error && uc_send(second, hello, sizeof hello - 1u) != 0)
        error = "second opening datagram send failed";
    if (!error && !th_wait_int(&g_preparse_new, 2, wait_ms))
        error = "the second opening datagram never reached preparse";
    if (!error && duct_atomic_load(&g_preparse_join, acquire) != 1)
        error = "the joining datagram did not resolve to a join";
    th_hold_release(&g_hold);

    if (!error && !th_wait_int(&g_open_count, 2, wait_ms))
        error = "the second session never opened";
    if (!error && duct_session_invoke_sync(io, duct_atomic_load(&g_tok_second, acquire), barrier,
                                           nullptr) != rc_ok)
        error = "the worker never reached the barrier";
    if (!error) {
        if (duct_atomic_load(&g_open_count, acquire) != 2)
            error = "the sessions did not open exactly twice";
        else if (duct_atomic_load(&g_join_count, acquire) != 0)
            error = "on_conn_join fired for a join of a closed session";
        else if (duct_atomic_load(&g_frames_join, acquire) != 0)
            error = "a datagram behind a refused join reached on_frame";
    }

    if (opener != duct_sock_bad)
        close(opener);
    if (joiner != duct_sock_bad)
        close(joiner);
    if (second != duct_sock_bad)
        close(second);
    if (running) {
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    return error;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto error = sc_join_refused();
    if (error) {
        fprintf(stderr, "dgram_join_refused: %s\n", error);
        return 1;
    }
    printf("dgram_join_refused: OK (a refused shared-datagram join, its first datagram in flight)\n");
    return 0;
}
