/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file dgram_join_test.c
 * @brief RW-DG classify-loop coverage: sync-preparse join and the full
 * async pre-parse path (resolve_new, resolve_join, resolve_reject) for
 * datagram listeners.
 *
 * dgram_test.c only exercises the single-proto, preparse==NULL fast path of
 * s_classify_dgram. This file drives the multi-proto classify loop
 * (sync preparse → resolve_join) and the async hand-off through
 * s_preparse_post / s_preparse_exec / s_preparse_exec_result,
 * mirroring join_edge_test.c's async scenarios but for xport_udp_peer legs.
 */

#include "duct.h"

#include <stdatomic.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#include "test_helpers.h"
#include "dgram_test_helpers.h"

static constexpr unsigned join_wait_ms = 3000u;
static constexpr int none_wait_ms = 300;

static atomic_int g_open_count = 0;
static atomic_int g_join_count = 0;
static _Atomic(duct_handle_t) g_ctrl_tok;

static uint32_t s_tok_gen(duct_handle_t w)
{
    return (uint32_t)(w >> 32u);
}

enum pp_mode { pp_join, pp_always_new, pp_reject };
static atomic_int g_pp_mode = 0;

static duct_result_t
on_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok,
        [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
        [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_ctrl_tok, tok, release);
    duct_atomic_fetch(add, &g_open_count, 1, relaxed);
    return rc_ok;
}

static duct_result_t
on_dgram([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame, duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_response_same(out, frame->payload, fl_send_copy, 0);
    return rc_ok;
}

static duct_result_t
on_join([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t cid,
        [[maybe_unused]] const duct_peer_t *peer, [[maybe_unused]] duct_response_t *out,
        [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_join_count, 1, relaxed);
    return rc_ok;
}

/** @brief Shared preparse for both the sync-join and async scenarios below;
 *  behavior selected by g_pp_mode so one callback covers all three
 *  dispositions. pp_join reads the ctrl leg's token stashed by on_open. */
static duct_resolve_disposition_t
preparse([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer,
         [[maybe_unused]] duct_view_u8 peek, duct_handle_t *out_tok,
         duct_conn_id_t *out_conn_id, [[maybe_unused]] void **out_user_ctx,
         [[maybe_unused]] size_t *out_lead)
{
    switch ((enum pp_mode)duct_atomic_load(&g_pp_mode, relaxed)) {
    case pp_join:
        *out_tok = duct_atomic_load(&g_ctrl_tok, acquire);
        *out_conn_id = 1u;
        return s_tok_gen(*out_tok) ? resolve_join : resolve_reject;
    case pp_always_new:
        return resolve_new;
    case pp_reject:
        return resolve_reject;
    }
    return resolve_reject;
}

static void s_reset(enum pp_mode mode)
{
    duct_atomic_store(&g_pp_mode, (int)mode, relaxed);
    duct_atomic_store(&g_open_count, 0, relaxed);
    duct_atomic_store(&g_join_count, 0, relaxed);
    duct_handle_t zero = {};
    duct_atomic_store(&g_ctrl_tok, zero, relaxed);
}

static duct_proto_t *
s_make_proto(const char *name, duct_wire_t *wire, duct_preparse_fn pp,
             duct_resolve_mode_t mode, bool with_join)
{
    return duct_proto_create(&(duct_proto_cfg_t){
        .name = name, .wire = wire,
        .on_frame = on_dgram, .on_session_open = on_open,
        .on_conn_join = with_join ? on_join : nullptr,
        .preparse = pp, .preparse_mode = mode,
        .max_response = 65535u,
    });
}

/* ── Scenario 1: sync preparse → resolve_join ────────────────────────
 * Two listeners: ctrl (preparse==nullptr, always new) and data (sync
 * preparse, joins the ctrl session). Exercises the multi-proto classify
 * loop's resolve_sync branch and the dgram resolve_join fast path in
 * s_classify_dgram (wire bind + on_conn_join + payload inject, all
 * inline on the I/O thread, no worker round-trip). */
static bool sc_sync_join(void)
{
    s_reset(pp_join);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;

    auto ctrl_wire = duct_wire_create_dgram_batch(0u, false);
    auto data_wire = duct_wire_create_dgram_batch(0u, false);
    auto ctrl = s_make_proto("ctrl", ctrl_wire, nullptr, resolve_sync, true);
    auto data = s_make_proto("data", data_wire, preparse, resolve_sync, false);
    if (ctrl) ctrl->owned_wire = ctrl_wire; else duct_wire_destroy(ctrl_wire);
    if (data) data->owned_wire = data_wire; else duct_wire_destroy(data_wire);
    if (!ctrl || !data) {
        duct_proto_destroy(ctrl); duct_proto_destroy(data); duct_engine_destroy(io);
        return false;
    }

    const duct_proto_t *ctrl_protos[1] = { ctrl };
    const duct_proto_t *data_protos[1] = { data };
    uint16_t pc = 0u, pd = 0u;
    bool ok = duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
                  .addr = "127.0.0.1", .n_protos = 1, .protos = ctrl_protos,
              }, &pc, nullptr, 0u, nullptr) == rc_ok
           && duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
                  .addr = "127.0.0.1", .n_protos = 1, .protos = data_protos,
              }, &pd, nullptr, 0u, nullptr) == rc_ok;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        duct_sock_t cfd = uc_connect(pc);
        static const char cm[] = "ctrl-hello";
        ok = cfd != duct_sock_bad && uc_send(cfd, cm, sizeof cm - 1u) == 0
                      && uc_recv_eq(cfd, cm, sizeof cm - 1u) == 0;

        duct_sock_t dfd = ok ? uc_connect(pd) : duct_sock_bad;
        static const char dm1[] = "join-1";
        static const char dm2[] = "join-2";
        /* Back-to-back sends before either reply: exercises the dgram_peers
         * dedup table so the second datagram lands on the just-created
         * per-peer conn instead of re-classifying. */
        ok = ok && dfd != duct_sock_bad && uc_send(dfd, dm1, sizeof dm1 - 1u) == 0
                            && uc_send(dfd, dm2, sizeof dm2 - 1u) == 0;
        ok = ok && uc_recv_eq(dfd, dm1, sizeof dm1 - 1u) == 0
                && uc_recv_eq(dfd, dm2, sizeof dm2 - 1u) == 0;
        ok = ok && th_wait_int(&g_join_count, 1, join_wait_ms);

        if (cfd != duct_sock_bad) close(cfd);
        if (dfd != duct_sock_bad) close(dfd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    ok = ok && duct_atomic_load(&g_open_count, acquire) == 1;
    duct_engine_destroy(io);
    duct_proto_destroy(ctrl);
    duct_proto_destroy(data);
    return ok;
}

/* ── Scenario 2: async preparse → resolve_new ────────────────────────
 * Single proto, preparse set (so the fast path is skipped) with
 * preparse_mode=resolve_async: forces s_preparse_post →
 * worker s_preparse_exec → resolve_new pre-parse result with
 * payload injection, all off the I/O thread. */
static bool sc_async_new(void)
{
    s_reset(pp_always_new);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;
    auto wire = duct_wire_create_dgram_batch(0u, false);
    auto p = s_make_proto("an", wire, preparse, resolve_async, false);
    if (p) p->owned_wire = wire; else duct_wire_destroy(wire);
    if (!p) { duct_engine_destroy(io); return false; }

    const duct_proto_t *protos[1] = { p };
    uint16_t port = 0u;
    bool ok = duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
                  .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
              }, &port, nullptr, 0u, nullptr) == rc_ok;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        duct_sock_t fd = uc_connect(port);
        static const char m[] = "async-new";
        ok = fd != duct_sock_bad && uc_send(fd, m, sizeof m - 1u) == 0
                     && uc_recv_eq(fd, m, sizeof m - 1u) == 0;
        if (fd != duct_sock_bad) close(fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    ok = ok && duct_atomic_load(&g_open_count, acquire) == 1;
    duct_engine_destroy(io);
    duct_proto_destroy(p);
    return ok;
}

/* ── Scenario 3: async preparse → resolve_join ───────────────────────
 * ctrl proto opens synchronously; data proto's async preparse joins the
 * ctrl session. Exercises the resolve_join branch of s_preparse_exec_result
 * for a datagram listener (per-peer socket opened after the worker
 * round-trip, wire bound, payload injected, on_conn_join fired before the
 * first frame). */
static bool sc_async_join(void)
{
    s_reset(pp_join);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;
    auto ctrl_wire = duct_wire_create_dgram_batch(0u, false);
    auto data_wire = duct_wire_create_dgram_batch(0u, false);
    auto ctrl = s_make_proto("ctrl2", ctrl_wire, nullptr, resolve_sync, true);
    auto data = s_make_proto("data2", data_wire, preparse, resolve_async, false);
    if (ctrl) ctrl->owned_wire = ctrl_wire; else duct_wire_destroy(ctrl_wire);
    if (data) data->owned_wire = data_wire; else duct_wire_destroy(data_wire);
    if (!ctrl || !data) {
        duct_proto_destroy(ctrl); duct_proto_destroy(data); duct_engine_destroy(io);
        return false;
    }

    const duct_proto_t *ctrl_protos[1] = { ctrl };
    const duct_proto_t *data_protos[1] = { data };
    uint16_t pc = 0u, pd = 0u;
    bool ok = duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
                  .addr = "127.0.0.1", .n_protos = 1, .protos = ctrl_protos,
              }, &pc, nullptr, 0u, nullptr) == rc_ok
           && duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
                  .addr = "127.0.0.1", .n_protos = 1, .protos = data_protos,
              }, &pd, nullptr, 0u, nullptr) == rc_ok;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        duct_sock_t cfd = uc_connect(pc);
        static const char cm[] = "ctrl-hello-2";
        ok = cfd != duct_sock_bad && uc_send(cfd, cm, sizeof cm - 1u) == 0
                      && uc_recv_eq(cfd, cm, sizeof cm - 1u) == 0;

        duct_sock_t dfd = ok ? uc_connect(pd) : duct_sock_bad;
        static const char dm[] = "async-join";
        ok = ok && dfd != duct_sock_bad && uc_send(dfd, dm, sizeof dm - 1u) == 0
                            && uc_recv_eq(dfd, dm, sizeof dm - 1u) == 0;
        ok = ok && th_wait_int(&g_join_count, 1, join_wait_ms);

        if (cfd != duct_sock_bad) close(cfd);
        if (dfd != duct_sock_bad) close(dfd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    ok = ok && duct_atomic_load(&g_open_count, acquire) == 1;
    duct_engine_destroy(io);
    duct_proto_destroy(ctrl);
    duct_proto_destroy(data);
    return ok;
}

/* ── Scenario 4: async preparse → resolve_reject ─────────────────────
 * s_preparse_exec must close(-noop for dgram)+free the injected
 * peek buffer and never create a conn/session; the client sees no reply. */
static bool sc_async_reject(void)
{
    s_reset(pp_reject);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) return false;
    auto wire = duct_wire_create_dgram_batch(0u, false);
    auto p = s_make_proto("ar", wire, preparse, resolve_async, false);
    if (p) p->owned_wire = wire; else duct_wire_destroy(wire);
    if (!p) { duct_engine_destroy(io); return false; }

    const duct_proto_t *protos[1] = { p };
    uint16_t port = 0u;
    bool ok = duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
                  .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
              }, &port, nullptr, 0u, nullptr) == rc_ok;

    pthread_t th;
    if (ok && pthread_create(&th, nullptr, th_run, io) == 0) {
        duct_sock_t fd = uc_connect(port);
        static const char m[] = "x";
        ok = fd != duct_sock_bad && uc_send(fd, m, sizeof m - 1u) == 0
                     && uc_recv_none(fd, none_wait_ms) == 0;
        if (fd != duct_sock_bad) close(fd);
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    } else ok = false;

    ok = ok && duct_atomic_load(&g_open_count, acquire) == 0;
    duct_engine_destroy(io);
    duct_proto_destroy(p);
    return ok;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    int pass = 1;

    if (!sc_sync_join()) { fprintf(stderr, "dgram_join: sync_join failed\n"); pass = 0; }
    if (!sc_async_new()) { fprintf(stderr, "dgram_join: async_new failed\n"); pass = 0; }
    if (!sc_async_join()) { fprintf(stderr, "dgram_join: async_join failed\n"); pass = 0; }
    if (!sc_async_reject()) { fprintf(stderr, "dgram_join: async_reject failed\n"); pass = 0; }

    if (pass) {
        printf("dgram_join: OK (sync join, async new/join/reject)\n");
        return 0;
    }
    return 1;
}
