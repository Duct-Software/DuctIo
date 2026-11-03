/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file inter_egress_shutdown_test.c
 *  @brief Host-egress lane against engine teardown, and the batching that
 *  makes one host dispatch cover many packets.
 *
 *  The host queue here records the callback instead of running it, which is
 *  what the rest of the suite cannot do: with the drain withheld, packets
 *  really sit on the worker's lane with a dispatch owed, and the coalescing is
 *  observable — eight echoes produce one @c run.
 *
 *  Two teardowns. One never runs the recorded callback at all, standing in for
 *  a host that tore its queue down first: the quiesce has to give up on its
 *  deadline and abandon the lane instead of hanging or freeing memory a
 *  pending callback still points at. The other runs it from another thread
 *  while destroy is under way, which is the case the in-drain count exists
 *  for; every queued packet must still arrive. Run this one under a sanitiser
 *  — a plain build stays quiet about the use-after-free it guards.
 */

#include "duct.h"
#include "test_helpers.h"
#include "dgram_test_helpers.h"

#include <stdatomic.h>

static constexpr unsigned wait_ms = 5000u;
static constexpr unsigned n_pkts  = 8u;
static const char s_marker[] = "egress-shutdown";

static atomic_uint g_join_count;
static atomic_uint g_out_count;
static atomic_uint g_run_count;
static duct_handle_t _Atomic g_tok;

static void (* _Atomic g_fn)(void *);
static void * _Atomic g_ctx;

static void s_run_defer(void (*fn)(void *ctx), void *ctx,
                        [[maybe_unused]] void *queue_ctx)
{
    duct_atomic_store(&g_ctx, ctx, relaxed);
    duct_atomic_store(&g_fn, fn, release);
    duct_atomic_fetch(add, &g_run_count, 1u, release);
}


static void *s_flush_thread(void *arg)
{
    th_sleep_ms((unsigned)(uintptr_t)arg);
    auto fn = duct_atomic_exchange(&g_fn, nullptr, acquire);
    if (fn)
        fn(duct_atomic_load(&g_ctx, relaxed));
    return nullptr;
}

static void s_on_packet_out([[maybe_unused]] void *app_ctx,
                            [[maybe_unused]] duct_handle_t tok,
                            [[maybe_unused]] duct_conn_id_t conn_id,
                            [[maybe_unused]] duct_view_u8 pkt)
{
    duct_atomic_fetch(add, &g_out_count, 1u, release);
}

static duct_result_t
on_session_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok,
                [[maybe_unused]] void *user_ctx, duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_tok, tok, release);
    out->control.open_leg.kind = leg_kind_inter;
    out->control.open_leg.conn_id = 1u;
    return rc_ok;
}

static duct_result_t
on_conn_join([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
             [[maybe_unused]] const duct_peer_t *peer,
             [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    if (conn_id == 1u)
        duct_atomic_fetch(add, &g_join_count, 1u, release);
    return rc_ok;
}

static duct_result_t
on_dgram([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame, duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

static bool s_wait_uint(atomic_uint *p, unsigned target, unsigned timeout_ms)
{
    for (unsigned waited = 0u; waited < timeout_ms; waited += 1u) {
        if (duct_atomic_load(p, acquire) >= target)
            return true;
        th_sleep_ms(1u);
    }
    return duct_atomic_load(p, acquire) >= target;
}

typedef struct {
    duct_engine_t *io;
    duct_proto_t  *proto;
    pthread_t      th;
    uint16_t       port;
    bool           running;
} rig_t;

static const char *s_rig_up(rig_t *r)
{
    duct_atomic_store(&g_join_count, 0u, release);
    duct_atomic_store(&g_out_count, 0u, release);
    duct_atomic_store(&g_run_count, 0u, release);
    duct_atomic_store(&g_fn, nullptr, release);

    r->io = duct_engine_launch(&(duct_engine_cfg_t){
        .io_threads = 1, .workers = 1,
        .host = { .on_packet_out = s_on_packet_out, .run = s_run_defer },
    });
    if (!r->io)
        return "engine launch failed";
    auto wire = duct_wire_create_dgram_batch(0u, false);
    if (!wire)
        return "wire create failed";
    r->proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "egress_shutdown", .wire = wire, .on_frame = on_dgram,
        .on_session_open = on_session_open, .on_conn_join = on_conn_join,
        .max_response = 4096u,
    });
    if (r->proto)
        r->proto->owned_wire = wire;
    else
        duct_wire_destroy(wire);
    if (!r->proto)
        return "proto create failed";
    const duct_proto_t *protos[1] = { r->proto };
    if (duct_listener_bind(r->io, &(duct_listener_cfg_t){ .kind = listener_dgram,
            .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
        }, &r->port, nullptr, 0u, nullptr) != rc_ok)
        return "bind failed";
    if (pthread_create(&r->th, nullptr, th_run, r->io) != 0)
        return "thread create failed";
    r->running = true;
    return nullptr;
}

static const char *s_queue_packets(rig_t *r)
{
    duct_sock_t fd = uc_connect(r->port);
    if (fd == duct_sock_bad)
        return "udp connect failed";
    if (uc_send(fd, s_marker, sizeof s_marker - 1u) != 0) {
        close(fd);
        return "udp send failed";
    }
    if (!s_wait_uint(&g_join_count, 1u, wait_ms)) {
        close(fd);
        return "inter leg never joined";
    }
    auto tok = duct_atomic_load(&g_tok, acquire);
    for (unsigned i = 0u; i < n_pkts; ++i)
        duct_discard duct_io_inter_packet(r->io, tok, 1u,
            duct_view(duct_view_u8, (void *)s_marker, sizeof s_marker - 1u));
    close(fd);
    return s_wait_uint(&g_run_count, 1u, wait_ms)
         ? nullptr : "no egress drain was ever scheduled";
}

static void s_rig_down(rig_t *r)
{
    if (!r->running)
        return;
    duct_engine_stop(r->io);
    pthread_join(r->th, nullptr);
    duct_engine_destroy(r->io);
    duct_proto_destroy(r->proto);
    r->running = false;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    const char *err = nullptr;

    {
        rig_t r = {};
        err = s_rig_up(&r);
        if (!err)
            err = s_queue_packets(&r);
        if (!err && duct_atomic_load(&g_run_count, acquire) != 1u)
            err = "egress drain scheduled more than once for one batch";
        s_rig_down(&r);
        if (!err && duct_atomic_load(&g_out_count, acquire) != 0u)
            err = "packets reached the host with its queue never running";
    }

    if (!err) {
        rig_t r = {};
        err = s_rig_up(&r);
        if (!err)
            err = s_queue_packets(&r);
        pthread_t fl;
        bool spawned = false;
        if (!err)
            spawned = pthread_create(&fl, nullptr, s_flush_thread,
                                     (void *)(uintptr_t)20u) == 0;
        s_rig_down(&r);
        if (spawned)
            pthread_join(fl, nullptr);
        if (!err && !spawned)
            err = "flush thread create failed";
        if (!err && duct_atomic_load(&g_out_count, acquire) != n_pkts)
            err = "drain racing teardown did not deliver every queued packet";
    }

    if (err) {
        fprintf(stderr, "inter_egress_shutdown: %s (run=%u out=%u)\n", err,
                duct_atomic_load(&g_run_count, acquire),
                duct_atomic_load(&g_out_count, acquire));
        return 1;
    }
    printf("inter_egress_shutdown: OK (one dispatch per batch, abandon on a "
           "dead host queue, full delivery on flush)\n");
    return 0;
}
