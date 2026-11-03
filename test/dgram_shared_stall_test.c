/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file dgram_shared_stall_test.c
 * @brief A shared datagram socket waits on a worker that holds its RX slots
 * instead of losing what it cannot place.
 *
 * @ref sc_held_worker_loses_nothing holds the one worker inside on_frame while
 * a peer sends the pool's worth of datagrams and then a tail past it; once
 * released, every datagram reaches the protocol in order. The tail outgrows
 * the inter lane the copy path falls into, and waits inside the socket's
 * kernel queue.
 *
 * @ref sc_held_worker_stalls_its_socket_alone holds one of two workers the same
 * way while a session on the other keeps sending: one socket per worker means
 * the held worker's stall leaves the other's reading.
 *
 * Linux only: one socket per worker needs SO_REUSEPORT.
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

#ifndef _WIN32

static constexpr unsigned k_clients = 16u;
static constexpr unsigned k_tail = 160u;
static constexpr unsigned k_side = 50u;
static constexpr size_t   k_tail_size = 1000u;

typedef struct {
    atomic_int  frames;
    atomic_int  order_bad;
    atomic_bool opened;
    int         last;
    pthread_t   thread;
} client_t;

static client_t   g_clients[k_clients];
static atomic_int g_hold = -1;

static void s_reset(void)
{
    for (unsigned i = 0u; i < k_clients; ++i) {
        auto c = &g_clients[i];
        duct_atomic_store(&c->frames, 0, relaxed);
        duct_atomic_store(&c->order_bad, 0, relaxed);
        duct_atomic_store(&c->opened, false, relaxed);
        c->last = -1;
    }
    duct_atomic_store(&g_hold, -1, relaxed);
}

static duct_resolve_disposition_t
preparse([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer,
         duct_view_u8 peek, [[maybe_unused]] duct_handle_t *out_tok,
         [[maybe_unused]] duct_conn_id_t *out_conn_id, void **out_user_ctx,
         [[maybe_unused]] size_t *out_lead)
{
    if (peek.size < 8u)
        return resolve_reject;
    uint32_t id;
    memcpy(&id, peek.data, sizeof id);
    if (id >= k_clients)
        return resolve_reject;
    *out_user_ctx = &g_clients[id];
    return resolve_new;
}

static duct_result_t
on_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
        void *user_ctx, [[maybe_unused]] duct_response_t *out,
        [[maybe_unused]] void *proto_state)
{
    auto c = (client_t *)user_ctx;
    c->thread = pthread_self();
    duct_atomic_store(&c->opened, true, release);
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    if (frame->payload.size < 8u)
        return rc_ok;
    uint32_t id, seq;
    memcpy(&id, frame->payload.data, sizeof id);
    memcpy(&seq, (const uint8_t *)frame->payload.data + 4u, sizeof seq);
    if (id >= k_clients)
        return rc_ok;
    auto c = &g_clients[id];
    while (duct_atomic_load(&g_hold, acquire) == (int)id)
        th_sleep_ms(1u);
    if ((int)seq != c->last + 1)
        duct_atomic_fetch(add, &c->order_bad, 1, relaxed);
    c->last = (int)seq;
    duct_atomic_fetch(add, &c->frames, 1, release);
    return rc_ok;
}

static bool s_send(duct_sock_t fd, uint32_t id, uint32_t seq, size_t size)
{
    uint8_t buf[k_tail_size + k_tail];
    memset(buf, 0x5a, size);
    memcpy(buf, &id, sizeof id);
    memcpy(buf + 4u, &seq, sizeof seq);
    return uc_send(fd, buf, size) == 0;
}

static bool s_send_run(duct_sock_t fd, uint32_t id, uint32_t *seq, unsigned n, size_t size, size_t step)
{
    for (unsigned i = 0u; i < n; ++i)
        if (!s_send(fd, id, (*seq)++, size + (size_t)i * step))
            return false;
    return true;
}

typedef struct {
    duct_engine_t *io;
    duct_proto_t  *proto;
    pthread_t      th;
    uint16_t       port;
    unsigned       n_fds;
    bool           running;
} rig_t;

static bool s_rig_up(rig_t *r, unsigned workers)
{
    *r = (rig_t){};
    r->io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = workers });
    if (!r->io)
        return false;
    auto wire = duct_wire_create_dgram_batch(0u, false);
    r->proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "dgram-stall", .wire = wire,
        .on_frame = on_frame, .on_session_open = on_open,
        .preparse = preparse, .preparse_mode = resolve_sync,
        .max_response = 4096u, .flags = fl_proto_dgram_shared,
    });
    if (r->proto)
        r->proto->owned_wire = wire;
    else
        duct_wire_destroy(wire);
    if (!r->proto)
        return false;
    const duct_proto_t *protos[1] = { r->proto };
    duct_sock_t fds[8] = {};
    if (duct_listener_bind(r->io, &(duct_listener_cfg_t){ .kind = listener_dgram,
                               .addr = "127.0.0.1", .n_protos = 1, .protos = protos,
                           }, &r->port, fds, 8u, &r->n_fds) != rc_ok)
        return false;
    r->running = pthread_create(&r->th, nullptr, th_run, r->io) == 0;
    return r->running;
}

static void s_rig_down(rig_t *r)
{
    duct_atomic_store(&g_hold, -1, release);
    if (r->running) {
        duct_engine_stop(r->io);
        pthread_join(r->th, nullptr);
    }
    if (r->io)
        duct_engine_destroy(r->io);
    if (r->proto)
        duct_proto_destroy(r->proto);
}

/** @brief Hold the one worker past its slot pool, then count every datagram. */
static bool sc_held_worker_loses_nothing(void)
{
    s_reset();
    rig_t r;
    bool ok = s_rig_up(&r, 1u);
    duct_sock_t fd = ok ? uc_connect(r.port) : duct_sock_bad;
    ok = ok && fd != duct_sock_bad;
    duct_atomic_store(&g_hold, 0, release);
    uint32_t seq = 0u;
    ok = ok && s_send_run(fd, 0u, &seq, duct_dgram_rx_slots, 8u, 1u);
    th_sleep_ms(100u);
    ok = ok && s_send_run(fd, 0u, &seq, k_tail, k_tail_size, 1u);
    th_sleep_ms(200u);
    duct_atomic_store(&g_hold, -1, release);
    int want = (int)(duct_dgram_rx_slots + k_tail);
    ok = ok && th_wait_int(&g_clients[0].frames, want, 5000u);
    if (!ok)
        fprintf(stderr, "dgram_shared_stall: held worker got %d of %d datagrams\n",
                duct_atomic_load(&g_clients[0].frames, acquire), want);
    ok = ok && duct_atomic_load(&g_clients[0].order_bad, acquire) == 0;
    if (fd != duct_sock_bad)
        close(fd);
    s_rig_down(&r);
    return ok;
}

/** @brief Hold one of two workers past its pool while the other's session keeps
 *  reading.
 *  The two sessions are picked by the worker thread their open ran on, so the
 *  check holds whatever the SO_REUSEPORT hash did with the client ports.
 */
static bool sc_held_worker_stalls_its_socket_alone(void)
{
    s_reset();
    rig_t r;
    bool ok = s_rig_up(&r, 2u) && r.n_fds == 2u;
    duct_sock_t fds[k_clients];
    uint32_t seqs[k_clients] = {};
    for (unsigned i = 0u; i < k_clients; ++i)
        fds[i] = duct_sock_bad;
    for (unsigned i = 0u; ok && i < k_clients; ++i) {
        fds[i] = uc_connect(r.port);
        ok = fds[i] != duct_sock_bad && s_send_run(fds[i], i, &seqs[i], 1u, 8u, 0u)
          && th_wait_int(&g_clients[i].frames, 1, 3000u);
    }
    int x = -1, y = -1;
    for (unsigned i = 1u; ok && i < k_clients && y < 0; ++i)
        if (!pthread_equal(g_clients[i].thread, g_clients[0].thread)) {
            x = 0;
            y = (int)i;
        }
    ok = ok && y >= 0;
    if (ok) {
        duct_atomic_store(&g_hold, x, release);
        ok = s_send_run(fds[x], (uint32_t)x, &seqs[x], duct_dgram_rx_slots, 8u, 1u);
        th_sleep_ms(100u);
        ok = ok && s_send_run(fds[x], (uint32_t)x, &seqs[x], k_tail, k_tail_size, 1u);
        th_sleep_ms(100u);
        ok = ok && s_send_run(fds[y], (uint32_t)y, &seqs[y], k_side, 8u, 1u)
                && th_wait_int(&g_clients[y].frames, (int)(1u + k_side), 3000u);
        if (!ok)
            fprintf(stderr, "dgram_shared_stall: the other worker's session got %d of %u\n",
                    duct_atomic_load(&g_clients[y].frames, acquire), 1u + k_side);
        duct_atomic_store(&g_hold, -1, release);
        int want = (int)(1u + duct_dgram_rx_slots + k_tail);
        ok = ok && th_wait_int(&g_clients[x].frames, want, 5000u);
        ok = ok && duct_atomic_load(&g_clients[x].order_bad, acquire) == 0
                && duct_atomic_load(&g_clients[y].order_bad, acquire) == 0;
    }
    for (unsigned i = 0u; i < k_clients; ++i)
        if (fds[i] != duct_sock_bad)
            close(fds[i]);
    s_rig_down(&r);
    return ok;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    int pass = 1;
    if (!sc_held_worker_loses_nothing()) {
        fprintf(stderr, "dgram_shared_stall: a held worker lost datagrams past its slot pool\n");
        pass = 0;
    } else {
        printf("dgram_shared_stall: held worker OK (the socket waits, nothing lost, order kept)\n");
    }
    if (!sc_held_worker_stalls_its_socket_alone()) {
        fprintf(stderr, "dgram_shared_stall: a held worker stalled another worker's socket\n");
        pass = 0;
    } else {
        printf("dgram_shared_stall: isolation OK (the other worker's socket keeps reading)\n");
    }
    return pass ? 0 : 1;
}

#else

int main(void)
{
    printf("dgram_shared_stall: skipped, one shared socket and no slot pool path here\n");
    return 0;
}

#endif
