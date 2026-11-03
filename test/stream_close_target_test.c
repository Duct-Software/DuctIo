/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file stream_close_target_test.c
 * @brief R4-MC-T: a FIN goes to the leg it names, or nobody is left guessing.
 *
 * pinned_leg is the case no other test reaches: two live legs, and
 * control.stream_op_conn_id pointing at the one the frame did not arrive on.
 * The second leg is an AF_UNIX socketpair attached through duct_conn_attach_fd,
 * so the test holds the peer end and can require the FIN there; a probe frame
 * then round-trips on the primary, which is how "leg 0 was left untouched" gets
 * asserted rather than assumed.
 *
 * absent_leg and no_wire cover the other half of the same search — a target
 * that resolves to nothing, and a proto whose legs carry no wire at all. Both
 * used to end the leg walk in silence; both now answer rc_not_supported, and
 * no_wire additionally requires that not one byte reached the peer.
 *
 * The wire is the built-in mux, which is what makes a stream-targeted FIN
 * expressible here at all: a length-prefix leg drops the id.
 */

#include "duct.h"
#include "duct_wire.h"

#include <stdatomic.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

#include "test_helpers.h"

duct_wire_t *duct_wire_create_mux(size_t max_frame);

static constexpr size_t mux_hdr = 8u;
static constexpr duct_stream_id_t sid_under_test = 5u;

static uint16_t g_port = 0;
static atomic_int g_attach_rc = -1;
static _Atomic(duct_sock_t) g_attached_fd = duct_sock_bad;
static atomic_int g_join_count = 0;
static atomic_int g_error_rc = -1;
static _Atomic(duct_conn_id_t) g_fin_target = 0;

static void s_reset(void)
{
    duct_atomic_store(&g_attach_rc, -1, release);
    duct_atomic_store(&g_attached_fd, duct_sock_bad, release);
    duct_atomic_store(&g_join_count, 0, release);
    duct_atomic_store(&g_error_rc, -1, release);
}

static void s_put_mux(uint8_t h[mux_hdr], uint32_t sid, uint32_t len, uint8_t flags)
{
    h[0] = flags;
    h[1] = (uint8_t)(len >> 16u); h[2] = (uint8_t)(len >> 8u); h[3] = (uint8_t)(len);
    h[4] = (uint8_t)(sid >> 24u); h[5] = (uint8_t)(sid >> 16u);
    h[6] = (uint8_t)(sid >>  8u); h[7] = (uint8_t)(sid);
}

static duct_result_t
on_open(duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
        [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
        [[maybe_unused]] void *proto_state)
{
    duct_sock_t sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        duct_atomic_store(&g_attach_rc, (int)rc_no_memory, release);
        return rc_ok;
    }
    auto rc = duct_conn_attach_fd(s, 1u, sv[0]);
    duct_atomic_store(&g_attach_rc, (int)rc, release);
    if (rc != rc_ok) {
        close(sv[0]);
        close(sv[1]);
        return rc_ok;
    }
    duct_atomic_store(&g_attached_fd, sv[1], release);
    return rc_ok;
}

static duct_result_t
on_join([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
        [[maybe_unused]] const duct_peer_t *peer, [[maybe_unused]] duct_response_t *out,
        [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_join_count, 1, release);
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t cid,
         const duct_frame_t *frame, duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    out->control.stream_op = stream_op_fin;
    out->control.stream_op_stream_id = frame->stream_id;
    out->control.stream_op_conn_id = duct_atomic_load(&g_fin_target, acquire);
    return rc_ok;
}

static duct_result_t
on_error([[maybe_unused]] duct_session_t *s, duct_result_t error,
         [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_error_rc, (int)error, release);
    return rc_ok;
}

static int s_report(const char *name, const char *err)
{
    printf("stream_close_target: %s: %s%s\n", name, err ? "FAIL: " : "OK", err ? err : "");
    return err == nullptr;
}

static const char *s_recv_fin(duct_sock_t fd, uint32_t want_sid)
{
    uint8_t h[mux_hdr] = {};
    if (th_read_exact(fd, h, sizeof h) != 0)
        return "no FIN frame arrived on the leg it was pinned to";
    uint32_t got = ((uint32_t)h[4] << 24u) | ((uint32_t)h[5] << 16u)
                 | ((uint32_t)h[6] <<  8u) |  (uint32_t)h[7];
    if (!duct_has((duct_frame_flags_t)h[0], fl_frame_fin))
        return "the frame on that leg carried no fl_frame_fin";
    if (got != want_sid)
        return "the FIN named a stream other than the one closed";
    return nullptr;
}

static const char *s_primary_silent(duct_sock_t fd)
{
    uint8_t h[mux_hdr];
    s_put_mux(h, sid_under_test + 1u, 0u, 0u);
    duct_atomic_store(&g_fin_target, duct_conn_id_primary, release);
    if (send(fd, (const char *)h, (int)mux_hdr, 0) != (int)mux_hdr)
        return "probe send failed";
    return s_recv_fin(fd, sid_under_test + 1u);
}

static const char *sc_pinned_leg(void)
{
    s_reset();
    duct_atomic_store(&g_fin_target, 1u, release);
    auto fd = th_connect(g_port);
    if (fd == duct_sock_bad) return "connect failed";

    const char *err = nullptr;
    uint8_t h[mux_hdr];
    s_put_mux(h, sid_under_test, 0u, 0u);

    if (!th_wait_int(&g_join_count, 1, 3000u))
        err = "the attached leg never joined";
    else if (duct_atomic_load(&g_attach_rc, acquire) != (int)rc_ok)
        err = "duct_conn_attach_fd refused";
    else if (send(fd, (const char *)h, (int)mux_hdr, 0) != (int)mux_hdr)
        err = "trigger send failed";
    else {
        duct_sock_t leg1 = duct_atomic_load(&g_attached_fd, acquire);
        err = s_recv_fin(leg1, sid_under_test);
        if (!err)
            err = s_primary_silent(fd);
    }

    duct_sock_close(fd);
    return err;
}

static const char *sc_absent_leg(void)
{
    s_reset();
    duct_atomic_store(&g_fin_target, 2u, release);
    auto fd = th_connect(g_port);
    if (fd == duct_sock_bad) return "connect failed";

    const char *err = nullptr;
    uint8_t h[mux_hdr];
    s_put_mux(h, sid_under_test, 0u, 0u);

    if (!th_wait_int(&g_join_count, 1, 3000u))
        err = "the attached leg never joined";
    else if (send(fd, (const char *)h, (int)mux_hdr, 0) != (int)mux_hdr)
        err = "trigger send failed";
    else if (!th_wait_int(&g_error_rc, (int)rc_not_supported, 3000u))
        err = duct_atomic_load(&g_error_rc, acquire) == -1
            ? "a FIN pinned to a leg that does not exist was swallowed"
            : "on_error fired with the wrong result code";
    else {
        duct_atomic_store(&g_fin_target, duct_conn_id_primary, release);
        err = s_primary_silent(fd);
    }

    duct_sock_close(fd);
    return err;
}

static uint16_t g_raw_port = 0;

static const char *sc_no_wire(void)
{
    s_reset();
    duct_atomic_store(&g_fin_target, duct_conn_id_same, release);
    auto fd = th_connect(g_raw_port);
    if (fd == duct_sock_bad) return "connect failed";

    const char *err = nullptr;
    char back[16] = {};

    if (send(fd, "x", 1, 0) != 1)
        err = "trigger send failed";
    else if (!th_wait_int(&g_error_rc, (int)rc_not_supported, 3000u))
        err = duct_atomic_load(&g_error_rc, acquire) == -1
            ? "a leg with no wire swallowed the FIN with no on_error"
            : "on_error fired with the wrong result code";
    else if (th_read_exact(fd, back, 1u) == 0)
        err = "a leg with no wire put bytes on the peer's stream anyway";

    duct_sock_close(fd);
    return err;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) { fprintf(stderr, "stream_close_target: io create failed\n"); return 1; }

    auto wire = duct_wire_create_mux(0u);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "close-target", .wire = wire, .flags = fl_proto_multiplexed,
        .on_frame = on_frame, .on_error = on_error,
        .on_session_open = on_open, .on_conn_join = on_join,
    }) : nullptr;
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    if (!proto) {
        fprintf(stderr, "stream_close_target: proto create failed\n");
        duct_engine_destroy(io);
        return 1;
    }

    auto raw = duct_proto_create(&(duct_proto_cfg_t){
        .name = "close-target-raw", .wire = nullptr, .max_response = 4096u,
        .on_frame = on_frame, .on_error = on_error,
    });
    if (!raw) {
        fprintf(stderr, "stream_close_target: raw proto create failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }

    const char *err = nullptr;
    pthread_t th;
    bool running = false;
    int pass = 1;

    if (duct_io_listen(io, "127.0.0.1", &g_port, proto) != rc_ok) {
        err = "listen failed";
        goto done;
    }
    if (duct_io_listen(io, "127.0.0.1", &g_raw_port, raw) != rc_ok) {
        err = "raw listen failed";
        goto done;
    }
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        err = "engine thread create failed";
        goto done;
    }
    running = true;

    pass &= s_report("pinned_leg", sc_pinned_leg());
    pass &= s_report("absent_leg", sc_absent_leg());
    pass &= s_report("no_wire", sc_no_wire());
    if (!pass)
        err = "one or more cases failed";

done:
    if (running) {
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    duct_proto_destroy(raw);

    if (err) {
        fprintf(stderr, "stream_close_target: %s\n", err);
        return 1;
    }
    printf("stream_close_target: OK (a pinned FIN lands on the named leg)\n");
    return 0;
}
