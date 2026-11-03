/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file dgram_shared_ctl_test.c
 * @brief A standalone fin reaches its own client on a shared datagram listener.
 *
 * The shape a server uses for many clients on one socket is the one with no
 * per-leg TX ring: every leg fans out through the listener's outbox. That is
 * exactly the leg a server needs to tell one client "this stream is finished",
 * and the control path had nowhere to stage such a frame on it.
 *
 * Two clients share the listener, so the test asks not only that the fin
 * arrives but that it arrives at one of them. flagless_wire_refuses holds the
 * other half: a wire that cannot carry frame flags still answers
 * rc_not_supported and puts nothing on the socket, which is a separate refusal
 * that had to survive the fix.
 *
 * data_then_fin_order covers the ordering the two queues make possible —
 * batched data drains at the end of the worker's pass, a lane entry on the io
 * thread's own kick. It asserts the outcome rather than reproducing the race,
 * which needs the io thread to win a wake the worker normally finishes first.
 *
 * pool_payload_gathers answers a separate question on the same listener: a
 * response built in a duct_tx_pool_acquire region, under a wire that writes a
 * header, goes out as two spans of one datagram with the payload never copied.
 * Nothing else in the suite produces a pool-owned payload on a shared
 * listener, so this case is what keeps that fork honest.
 *
 * defer_reports_loss covers the one disposition this listener cannot honour:
 * a frame is off the inter_lane before on_frame runs, so rc_defer has no
 * replay to give and the packet is lost. The case asserts the loss is
 * reported through on_error rather than left for the protocol to infer.
 *
 * send_done_fin_no_recurse pins the re-entrancy that same control path opens.
 * on_send_done may answer with a control op, and a fin on this listener
 * flushes the batch first, so the flush reaches itself from inside its own
 * send-done walk. One echo, then the fin, then nothing, and on_send_done seen
 * once, is what says the second pass found the pass already taken.
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

static constexpr size_t   mux_lead    = 5u;
static constexpr uint32_t sid_under   = 7u;
static constexpr uint32_t sid_recurse = 9u;
static constexpr unsigned wait_ms     = 5000u;

static atomic_int g_open_count = 0;
static atomic_int g_error_rc   = -1;
static atomic_int g_done_fins  = 0;
static _Atomic duct_handle_t g_tok_a;
static _Atomic duct_handle_t g_tok_b;
static atomic_bool g_have_a = false;
static atomic_bool g_have_b = false;

static void s_reset(void)
{
    duct_atomic_store(&g_open_count, 0, release);
    duct_atomic_store(&g_error_rc, -1, release);
    duct_atomic_store(&g_done_fins, 0, release);
    duct_atomic_store(&g_have_a, false, release);
    duct_atomic_store(&g_have_b, false, release);
}

static void s_put(uint8_t *out, uint8_t flags, uint32_t sid, char tag)
{
    out[0] = flags;
    out[1] = (uint8_t)(sid >> 24u); out[2] = (uint8_t)(sid >> 16u);
    out[3] = (uint8_t)(sid >>  8u); out[4] = (uint8_t)(sid);
    out[5] = (uint8_t)tag;
}

static duct_result_t
on_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok, void *user_ctx,
        [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    if ((char)(intptr_t)user_ctx == 'A') {
        duct_atomic_store(&g_tok_a, tok, release);
        duct_atomic_store(&g_have_a, true, release);
    } else {
        duct_atomic_store(&g_tok_b, tok, release);
        duct_atomic_store(&g_have_b, true, release);
    }
    duct_atomic_fetch(add, &g_open_count, 1, relaxed);
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t cid,
         const duct_frame_t *frame, duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    auto body = (const char *)frame->payload.data;
    char kind = frame->payload.size ? body[frame->payload.size - 1u] : 0;
    if (kind == 'x')
        return rc_defer;
    if (kind == 'p') {
        auto p = (char *)duct_tx_pool_acquire(frame->payload.size);
        if (!p)
            return rc_again;
        memcpy(p, body, frame->payload.size);
        out->payload = duct_view(duct_view_u8, (void *)p, frame->payload.size);
        out->stream_id = frame->stream_id;
        out->send_token = (uintptr_t)p;
        return rc_ok;
    }
    if (kind == 'o' || kind == 'i') {
        size_t lead = kind == 'i' ? 3u : 0u;
        auto block = duct_at(duct_new(uint8_t, lead + frame->payload.size));
        if (!block)
            return rc_again;
        memcpy(block + lead, body, frame->payload.size);
        out->payload = duct_view(duct_view_u8, block + lead, frame->payload.size);
        out->flags = fl_send_owned;
        out->release_arg = block;
        out->stream_id = frame->stream_id;
        return rc_ok;
    }
    if (kind != 'f')
        duct_response_same(out, frame->payload,
                           frame->stream_id == sid_recurse
                               ? duct_or(fl_send_copy, fl_send_done) : fl_send_copy, 0);
    if (kind == 'f' || kind == 'd') {
        out->control.stream_op = stream_op_fin;
        out->control.stream_op_stream_id = frame->stream_id;
        out->control.stream_op_conn_id = duct_conn_id_same;
    }
    return rc_ok;
}

static duct_result_t
on_error([[maybe_unused]] duct_session_t *s, duct_result_t error,
         [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_error_rc, (int)error, release);
    return rc_ok;
}

static duct_result_t
on_send_done([[maybe_unused]] duct_session_t *s, const duct_send_done_info_t *info,
             [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    if (info->stream_id == sid_recurse) {
        duct_atomic_fetch(add, &g_done_fins, 1, relaxed);
        out->control.stream_op = stream_op_fin;
        out->control.stream_op_stream_id = (duct_stream_id_t)sid_recurse;
        out->control.stream_op_conn_id = duct_conn_id_same;
    }
    return rc_ok;
}

static duct_resolve_disposition_t
preparse([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer,
         duct_view_u8 peek, duct_handle_t *out_tok,
         duct_conn_id_t *out_conn_id, void **out_user_ctx,
         [[maybe_unused]] size_t *out_lead)
{
    if (peek.size < mux_lead + 1u)
        return resolve_reject;
    char tag = ((const char *)peek.data)[mux_lead];
    if (tag != 'A' && tag != 'B')
        return resolve_reject;
    bool have = tag == 'A' ? duct_atomic_load(&g_have_a, acquire)
                           : duct_atomic_load(&g_have_b, acquire);
    if (!have) {
        *out_user_ctx = (void *)(intptr_t)tag;
        return resolve_new;
    }
    *out_tok = tag == 'A' ? duct_atomic_load(&g_tok_a, acquire)
                          : duct_atomic_load(&g_tok_b, acquire);
    *out_conn_id = duct_conn_id_primary;
    return resolve_join;
}

typedef struct {
    duct_engine_t *io;
    duct_proto_t  *proto;
    pthread_t      th;
    bool           running;
    uint16_t       port;
} s_fixture_t;

static const char *s_fixture_up(s_fixture_t *f, bool flagged)
{
    s_reset();
    *f = (s_fixture_t){};
    f->io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!f->io)
        return "io create failed";
    auto wire = flagged ? duct_wire_create_mux_dgram(0u)
                        : duct_wire_create_dgram_batch(0u, false);
    f->proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "dgram-shared-ctl", .wire = wire,
        .on_frame = on_frame, .on_session_open = on_open, .on_error = on_error,
        .on_send_done = on_send_done,
        .preparse = preparse, .preparse_mode = resolve_sync,
        .max_response = 4096u,
        .flags = duct_or(fl_proto_dgram_shared, fl_proto_multiplexed),
    }) : nullptr;
    if (f->proto)
        f->proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!f->proto)
        return "proto create failed";
    const duct_proto_t *protos[1] = { f->proto };
    if (duct_listener_bind(f->io, &(duct_listener_cfg_t){ .kind = listener_dgram,
            .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
        }, &f->port, nullptr, 0u, nullptr) != rc_ok)
        return "bind failed";
    if (pthread_create(&f->th, nullptr, th_run, f->io) != 0)
        return "thread create failed";
    f->running = true;
    return nullptr;
}

static void s_fixture_down(s_fixture_t *f)
{
    if (f->running) {
        duct_engine_stop(f->io);
        pthread_join(f->th, nullptr);
    }
    if (f->io)
        duct_engine_destroy(f->io);
    if (f->proto)
        duct_proto_destroy(f->proto);
}

static const char *s_greet(duct_sock_t fd, char tag, uint32_t sid)
{
    uint8_t msg[mux_lead + 2u];
    s_put(msg, 0u, sid, tag);
    msg[mux_lead + 1u] = 'g';
    if (uc_send(fd, msg, sizeof msg) != 0)
        return "greeting send failed";
    char back[64];
    if (uc_recv(fd, back, sizeof back) != (ssize_t)sizeof msg)
        return "greeting was not echoed";
    return nullptr;
}

static const char *sc_fin_reaches_its_client(void)
{
    s_fixture_t f;
    auto err = s_fixture_up(&f, true);
    duct_sock_t fa = duct_sock_bad, fb = duct_sock_bad;
    uint8_t msg[mux_lead + 2u];

    if (!err && (fa = uc_connect(f.port)) == duct_sock_bad)
        err = "client A connect failed";
    if (!err)
        err = s_greet(fa, 'A', sid_under);
    if (!err && (fb = uc_connect(f.port)) == duct_sock_bad)
        err = "client B connect failed";
    if (!err)
        err = s_greet(fb, 'B', sid_under);
    if (!err && !th_wait_int(&g_open_count, 2, wait_ms))
        err = "two clients did not open two sessions";

    if (!err) {
        s_put(msg, 0u, sid_under, 'A');
        msg[mux_lead + 1u] = 'f';
        if (uc_send(fa, msg, sizeof msg) != 0)
            err = "fin trigger send failed";
    }
    if (!err) {
        uint8_t back[64];
        ssize_t got = uc_recv(fa, (char *)back, sizeof back);
        if (got < (ssize_t)mux_lead)
            err = "no standalone control frame reached the client";
        else if (!duct_has((duct_frame_flags_t)back[0], fl_frame_fin))
            err = "the frame that arrived carried no fl_frame_fin";
        else if ((((uint32_t)back[1] << 24u) | ((uint32_t)back[2] << 16u)
                | ((uint32_t)back[3] <<  8u) |  (uint32_t)back[4]) != sid_under)
            err = "the fin named a stream other than the one closed";
    }
    if (!err && uc_recv_none(fb, 300) != 0)
        err = "the other client on the same listener received it too";
    if (!err && duct_atomic_load(&g_error_rc, acquire) != -1)
        err = "on_error fired on a leg that could carry the frame";

    if (fa != duct_sock_bad) close(fa);
    if (fb != duct_sock_bad) close(fb);
    s_fixture_down(&f);
    return err;
}

static const char *sc_data_then_fin_order(void)
{
    s_fixture_t f;
    auto err = s_fixture_up(&f, true);
    duct_sock_t fa = duct_sock_bad;
    uint8_t msg[mux_lead + 2u];
    uint8_t back[64];

    if (!err && (fa = uc_connect(f.port)) == duct_sock_bad)
        err = "client A connect failed";
    if (!err)
        err = s_greet(fa, 'A', sid_under);

    if (!err) {
        s_put(msg, 0u, sid_under, 'A');
        msg[mux_lead + 1u] = 'd';
        if (uc_send(fa, msg, sizeof msg) != 0)
            err = "data-plus-fin send failed";
    }
    if (!err) {
        ssize_t got = uc_recv(fa, (char *)back, sizeof back);
        if (got != (ssize_t)sizeof msg)
            err = "the data half did not arrive first";
        else if (duct_has((duct_frame_flags_t)back[0], fl_frame_fin))
            err = "the fin overtook the data it terminates";
        else if (memcmp(back + mux_lead, msg + mux_lead, 2u) != 0)
            err = "the data half arrived altered";
    }
    if (!err) {
        ssize_t got = uc_recv(fa, (char *)back, sizeof back);
        if (got < (ssize_t)mux_lead)
            err = "the fin did not follow the data";
        else if (!duct_has((duct_frame_flags_t)back[0], fl_frame_fin))
            err = "the frame following the data carried no fl_frame_fin";
    }

    if (fa != duct_sock_bad) close(fa);
    s_fixture_down(&f);
    return err;
}

static const char *sc_pool_payload_gathers(void)
{
    s_fixture_t f;
    auto err = s_fixture_up(&f, true);
    duct_sock_t fa = duct_sock_bad;
    uint8_t msg[mux_lead + 2u];
    uint8_t back[64];

    if (!err && (fa = uc_connect(f.port)) == duct_sock_bad)
        err = "client A connect failed";
    if (!err)
        err = s_greet(fa, 'A', sid_under);

    for (int round = 0; !err && round < 3; ++round) {
        s_put(msg, 0u, sid_under, 'A');
        msg[mux_lead + 1u] = 'p';
        if (uc_send(fa, msg, sizeof msg) != 0)
            err = "pool-payload send failed";
        else if (uc_recv(fa, (char *)back, sizeof back) != (ssize_t)sizeof msg)
            err = "the pool-backed reply did not come back whole";
        else if ((((uint32_t)back[1] << 24u) | ((uint32_t)back[2] << 16u)
                | ((uint32_t)back[3] <<  8u) |  (uint32_t)back[4]) != sid_under)
            err = "the gathered header named the wrong stream";
        else if (memcmp(back + mux_lead, msg + mux_lead, 2u) != 0)
            err = "the gathered payload differs from what was sent";
    }
    if (!err && duct_atomic_load(&g_error_rc, acquire) != -1)
        err = "a pool-backed response reported an error";

    if (fa != duct_sock_bad) close(fa);
    s_fixture_down(&f);
    return err;
}

static const char *sc_owned_payload_gathers(void)
{
    s_fixture_t f;
    auto err = s_fixture_up(&f, true);
    duct_sock_t fa = duct_sock_bad;
    uint8_t msg[mux_lead + 2u];
    uint8_t back[64];

    if (!err && (fa = uc_connect(f.port)) == duct_sock_bad)
        err = "client A connect failed";
    if (!err)
        err = s_greet(fa, 'A', sid_under);

    for (int round = 0; !err && round < 6; ++round) {
        s_put(msg, 0u, sid_under, 'A');
        msg[mux_lead + 1u] = round & 1 ? 'i' : 'o';
        if (uc_send(fa, msg, sizeof msg) != 0)
            err = "owned-payload send failed";
        else if (uc_recv(fa, (char *)back, sizeof back) != (ssize_t)sizeof msg)
            err = "the owned reply did not come back whole";
        else if ((((uint32_t)back[1] << 24u) | ((uint32_t)back[2] << 16u)
                | ((uint32_t)back[3] <<  8u) |  (uint32_t)back[4]) != sid_under)
            err = "the gathered header named the wrong stream";
        else if (memcmp(back + mux_lead, msg + mux_lead, 2u) != 0)
            err = "the owned payload differs from what was sent";
    }
    if (!err && duct_atomic_load(&g_error_rc, acquire) != -1)
        err = "an owned response reported an error";

    if (fa != duct_sock_bad) close(fa);
    s_fixture_down(&f);
    return err;
}

static const char *sc_send_done_fin_no_recurse(void)
{
    s_fixture_t f;
    auto err = s_fixture_up(&f, true);
    duct_sock_t fa = duct_sock_bad;
    uint8_t msg[mux_lead + 2u];
    uint8_t back[64];

    if (!err && (fa = uc_connect(f.port)) == duct_sock_bad)
        err = "client A connect failed";
    if (!err)
        err = s_greet(fa, 'A', sid_under);

    if (!err) {
        s_put(msg, 0u, sid_recurse, 'A');
        msg[mux_lead + 1u] = 'e';
        if (uc_send(fa, msg, sizeof msg) != 0)
            err = "send_done-fin probe send failed";
    }
    if (!err) {
        ssize_t got = uc_recv(fa, (char *)back, sizeof back);
        if (got != (ssize_t)sizeof msg)
            err = "the echo did not come back whole";
        else if (memcmp(back + mux_lead, msg + mux_lead, 2u) != 0)
            err = "the echo arrived altered";
    }
    if (!err) {
        ssize_t got = uc_recv(fa, (char *)back, sizeof back);
        if (got < (ssize_t)mux_lead)
            err = "the send_done-requested fin never arrived";
        else if (!duct_has((duct_frame_flags_t)back[0], fl_frame_fin))
            err = "the frame following the echo carried no fl_frame_fin";
    }
    if (!err && uc_recv_none(fa, 300) != 0)
        err = "the echo was delivered more than once";
    if (!err && duct_atomic_load(&g_done_fins, acquire) != 1)
        err = "on_send_done ran more than once for a single response";

    if (fa != duct_sock_bad) close(fa);
    s_fixture_down(&f);
    return err;
}

static const char *sc_defer_reports_loss(void)
{
    s_fixture_t f;
    auto err = s_fixture_up(&f, true);
    duct_sock_t fa = duct_sock_bad;
    uint8_t msg[mux_lead + 2u];

    if (!err && (fa = uc_connect(f.port)) == duct_sock_bad)
        err = "client A connect failed";
    if (!err)
        err = s_greet(fa, 'A', sid_under);

    if (!err) {
        s_put(msg, 0u, sid_under, 'A');
        msg[mux_lead + 1u] = 'x';
        if (uc_send(fa, msg, sizeof msg) != 0)
            err = "defer probe send failed";
    }
    if (!err && !th_wait_int(&g_error_rc, (int)rc_again, wait_ms))
        err = "a deferred frame with no replay path reported no loss";
    if (!err && uc_recv_none(fa, 300) != 0)
        err = "a deferred frame produced a reply";

    if (fa != duct_sock_bad) close(fa);
    s_fixture_down(&f);
    return err;
}

static const char *sc_flagless_wire_refuses(void)
{
    s_fixture_t f;
    auto err = s_fixture_up(&f, false);
    duct_sock_t fa = duct_sock_bad;
    uint8_t msg[mux_lead + 2u];

    if (!err && (fa = uc_connect(f.port)) == duct_sock_bad)
        err = "client A connect failed";
    if (!err) {
        s_put(msg, 0u, 0u, 'A');
        msg[mux_lead + 1u] = 'g';
        if (uc_send(fa, msg, sizeof msg) != 0)
            err = "greeting send failed";
        else if (uc_recv_eq(fa, (const char *)msg, sizeof msg) != 0)
            err = "greeting was not echoed";
    }
    if (!err) {
        s_put(msg, 0u, 0u, 'A');
        msg[mux_lead + 1u] = 'f';
        if (uc_send(fa, msg, sizeof msg) != 0)
            err = "fin trigger send failed";
        else if (!th_wait_int(&g_error_rc, (int)rc_not_supported, wait_ms))
            err = "a wire that cannot carry flags did not report rc_not_supported";
    }
    if (!err && uc_recv_none(fa, 300) != 0)
        err = "a flagless wire put a control frame on the peer's socket";

    if (fa != duct_sock_bad) close(fa);
    s_fixture_down(&f);
    return err;
}

static int s_report(const char *name, const char *err)
{
    printf("dgram_shared_ctl: %s: %s%s\n", name, err ? "FAIL: " : "OK", err ? err : "");
    return err == nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    int pass = 1;
    pass &= s_report("fin_reaches_its_client", sc_fin_reaches_its_client());
    pass &= s_report("data_then_fin_order", sc_data_then_fin_order());
    pass &= s_report("pool_payload_gathers", sc_pool_payload_gathers());
    pass &= s_report("owned_payload_gathers", sc_owned_payload_gathers());
    pass &= s_report("send_done_fin_no_recurse", sc_send_done_fin_no_recurse());
    pass &= s_report("defer_reports_loss", sc_defer_reports_loss());
    pass &= s_report("flagless_wire_refuses", sc_flagless_wire_refuses());

    if (!pass) {
        fprintf(stderr, "dgram_shared_ctl: one or more cases failed\n");
        return 1;
    }
    printf("dgram_shared_ctl: OK (a standalone fin reaches its own client on a shared listener)\n");
    return 0;
}
