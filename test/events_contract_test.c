/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file events_contract_test.c
 * @brief Contract test for the @ref DUCT_EVENTS_MODEL backend, whichever one
 * was configured.
 *
 * @c duct_events_* has five independent implementations — epoll, poll, iocp,
 * wsaevent, kqueue — and, like @c duct_futex_wait before
 * @c core_futex_test.c, no direct coverage of its own. The rest of the suite
 * exercises the backend only incidentally, so the properties below are the
 * ones a backend can get wrong while every other test still passes:
 *
 *  1. A parked run loop is woken by a cross-thread completion. Every echo
 *     here is staged by a worker thread and needs @c duct_events_kick to
 *     reach the socket. With the loop deliberately idle first, a waker that
 *     does not deliver shows up as a hang rather than as a slow test — this
 *     is the one property whose failure mode is total.
 *  2. Read and write readiness on the same descriptor at the same time
 *     resolve to one coherent conn state. A backend that reports per filter
 *     (kqueue) can deliver two events for one descriptor in a single batch,
 *     where epoll delivers one; if the first is allowed to tear the conn
 *     down, the second is a use-after-free.
 *  3. A registration burst larger than any backend's internal batch still
 *     registers every descriptor — kqueue's changelist, poll's array,
 *     wsaevent's event table.
 *  4. Descriptor numbers recycled through unwatch → close → accept never
 *     carry a stale registration into their next life.
 *
 * Deliberately public-API only, so it runs unmodified on every backend and
 * platform. Pass: every round-trip completes and every session opens.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>
#ifndef _WIN32
#include <sys/resource.h>
#endif

static uint16_t th_port = 0;
static atomic_int s_open_count = 0;

/** Read/write-overlap volume. Enough frames in flight that the conn is
 *  readable and writable at the same instant, while total un-drained echo
 *  bytes stay inside half the TX OLB — past that a response no longer fits
 *  its reservation and the frame stops arriving, which is a backpressure
 *  property, not an events-backend one. Derived from the cap rather than
 *  hardcoded: duct_conn_tx_olb_cap is CMake-tunable. */
static constexpr size_t   rw_payload = 1024u;
static constexpr size_t   wire_frame = 8192u;
static constexpr unsigned rw_frames  =
    duct_conn_tx_olb_cap / (rw_payload * 2u) < 8u
        ? 8u : (unsigned)(duct_conn_tx_olb_cap / (rw_payload * 2u));

/* wsaevent clamps duct_runtime_max_conns to 63 (see its own @file doc), so a
 * fixed burst would ask for more conns than that backend can hold. Scale with
 * the pool the way conn_churn_test does, keeping the burst comfortably above
 * every backend's internal registration batch either way. */
static constexpr bool     small_pool  = duct_runtime_max_conns < 256u;
static constexpr unsigned burst_max = small_pool ? 24u : 160u;
static unsigned burst_conns = burst_max;
static constexpr unsigned reuse_rounds = small_pool ? 40u : 120u;

static duct_result_t
on_session_open([[maybe_unused]] duct_session_t *s,
                [[maybe_unused]] duct_handle_t tok,
                [[maybe_unused]] void *user_ctx,
                [[maybe_unused]] duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &s_open_count, 1, relaxed);
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s,
         [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame,
         duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

/* ── 1. parked loop, cross-thread wake ───────────────────────────── */

/** Idle long enough that the I/O thread's busy-spin budget
 *  (duct_busy_spin_ns) is spent and its wait is a real block, then prove a
 *  worker-staged response still gets out. A backend whose waker never fires
 *  fails here by timing out, not by returning wrong data.
 */
static int case_idle_wake(void)
{
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) {
        fprintf(stderr, "events_contract: idle_wake connect failed\n");
        return 1;
    }
    static const char msg[] = "wake-a-parked-loop";
    int rc = 0;
    for (unsigned i = 0u; i < 3u && !rc; ++i) {
        th_sleep_ms(400u); /* park */
        if (th_send(fd, msg, sizeof msg - 1u) != 0
            || th_recv_eq(fd, msg, sizeof msg - 1u) != 0) {
            fprintf(stderr, "events_contract: idle_wake round %u lost\n", i);
            rc = 1;
        }
    }
    duct_sock_close(fd);
    if (!rc)
        printf("events_contract: idle_wake OK (3 round-trips off a parked loop)\n");
    return rc;
}

/* ── 2. simultaneous read + write readiness ──────────────────────── */

typedef struct {
    duct_sock_t fd;
    unsigned    got;
} rw_reader_t;

/** Drain echoes concurrently with the sender below. Without a separate
 *  reader the two directions deadlock on socket buffers long before both
 *  filters are hot, which is the state this case exists to produce.
 */
static void *rw_reader(void *arg)
{
    auto r = (rw_reader_t *)arg;
    static char buf[wire_frame];
    for (unsigned i = 0u; i < rw_frames; ++i) {
        int64_t n = th_recv(r->fd, buf, sizeof buf);
        if (n != (int64_t)rw_payload)
            break;
        if ((unsigned char)buf[0] != (unsigned char)i
            || (unsigned char)buf[rw_payload - 1u] != (unsigned char)(i ^ 0xffu))
            break;
        ++r->got;
    }
    return nullptr;
}

static int case_rw_overlap(void)
{
    duct_sock_t fd = th_connect(th_port);
    if (fd == duct_sock_bad) {
        fprintf(stderr, "events_contract: rw_overlap connect failed\n");
        return 1;
    }
    rw_reader_t r = { .fd = fd, .got = 0u };
    pthread_t rd;
    if (pthread_create(&rd, nullptr, rw_reader, &r) != 0) {
        fprintf(stderr, "events_contract: rw_overlap reader thread failed\n");
        duct_sock_close(fd);
        return 1;
    }
    static char payload[rw_payload];
    int rc = 0;
    for (unsigned i = 0u; i < rw_frames; ++i) {
        memset(payload, (int)(unsigned char)i, sizeof payload);
        payload[0] = (char)(unsigned char)i;
        payload[rw_payload - 1u] = (char)(unsigned char)(i ^ 0xffu);
        if (th_send(fd, payload, sizeof payload) != 0) {
            fprintf(stderr, "events_contract: rw_overlap send %u failed\n", i);
            rc = 1;
            break;
        }
    }
    pthread_join(rd, nullptr);
    duct_sock_close(fd);
    if (!rc && r.got != rw_frames) {
        fprintf(stderr, "events_contract: rw_overlap echoed %u/%u frames\n",
                r.got, rw_frames);
        rc = 1;
    }
    if (!rc)
        printf("events_contract: rw_overlap OK (%u frames, both directions hot)\n",
               rw_frames);
    return rc;
}

/* ── 3. registration burst ───────────────────────────────────────── */

/** Open every conn before exchanging anything, so the accepts land as one
 *  burst of registrations rather than a trickle. Larger than kqueue's
 *  changelist and every other backend's batch.
 */
static int case_burst(void)
{
    static duct_sock_t fds[burst_max];
    unsigned opened = 0u;
    for (unsigned i = 0u; i < burst_conns; ++i) {
        fds[i] = th_connect(th_port);
        if (fds[i] == duct_sock_bad)
            break;
        ++opened;
    }
    int rc = 0;
    if (opened != burst_conns) {
        fprintf(stderr, "events_contract: burst opened %u/%u conns\n",
                opened, burst_conns);
        rc = 1;
    }
    static const char msg[] = "burst";
    unsigned ok = 0u;
    for (unsigned i = 0u; i < opened; ++i)
        if (th_send(fds[i], msg, sizeof msg - 1u) == 0)
            ++ok;
    unsigned echoed = 0u;
    for (unsigned i = 0u; i < opened; ++i)
        if (th_recv_eq(fds[i], msg, sizeof msg - 1u) == 0)
            ++echoed;
    for (unsigned i = 0u; i < opened; ++i)
        duct_sock_close(fds[i]);
    if (echoed != opened) {
        fprintf(stderr, "events_contract: burst echoed %u/%u (sent %u)\n",
                echoed, opened, ok);
        rc = 1;
    }
    if (!rc)
        printf("events_contract: burst OK (%u simultaneous registrations)\n", opened);
    return rc;
}

/* ── 4. descriptor-number reuse ──────────────────────────────────── */

/** Strictly sequential: each close frees a descriptor number the next accept
 *  is very likely to be handed straight back. A backend that lets an
 *  unwatch's pending state outlive the descriptor delivers the new conn's
 *  events under the old conn's tag.
 */
static int case_fd_reuse(void)
{
    static const char msg[] = "reuse";
    for (unsigned i = 0u; i < reuse_rounds; ++i) {
        duct_sock_t fd = th_connect(th_port);
        if (fd == duct_sock_bad) {
            fprintf(stderr, "events_contract: fd_reuse connect failed at %u\n", i);
            return 1;
        }
        if (th_send(fd, msg, sizeof msg - 1u) != 0
            || th_recv_eq(fd, msg, sizeof msg - 1u) != 0) {
            fprintf(stderr, "events_contract: fd_reuse round-trip failed at %u\n", i);
            duct_sock_close(fd);
            return 1;
        }
        duct_sock_close(fd);
    }
    printf("events_contract: fd_reuse OK (%u sequential open/close rounds)\n",
           reuse_rounds);
    return 0;
}

/* ── driver ──────────────────────────────────────────────────────── */

int main(void)
{
#ifndef _WIN32
    /* iOS processes may have a 256-fd ceiling. Leave room for engine/control
     * descriptors and count both ends of every loopback connection. */
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur != RLIM_INFINITY) {
        unsigned room = limit.rlim_cur > 32u ? (unsigned)((limit.rlim_cur - 32u) / 2u) : 1u;
        if (burst_conns > room) burst_conns = room;
    }
#endif
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 2 });
    if (!io) { fprintf(stderr, "events_contract: io create failed\n"); return 1; }

    auto wire = duct_wire_create_length_prefix(wire_frame);
    if (!wire) {
        fprintf(stderr, "events_contract: wire create failed\n");
        duct_engine_destroy(io);
        return 1;
    }
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "events_contract", .wire = wire,
        .on_frame = on_frame, .on_session_open = on_session_open,
    });
    if (!proto) {
        fprintf(stderr, "events_contract: proto create failed\n");
        duct_engine_destroy(io); duct_wire_destroy(wire);
        return 1;
    }
    if (duct_io_listen(io, "127.0.0.1", &th_port, proto) != rc_ok) {
        fprintf(stderr, "events_contract: listen failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(wire);
        return 1;
    }
    pthread_t th;
    if (pthread_create(&th, nullptr, th_run, io) != 0) {
        fprintf(stderr, "events_contract: thread create failed\n");
        duct_engine_destroy(io); duct_proto_destroy(proto); duct_wire_destroy(wire);
        return 1;
    }

    int fails = 0;
    fails += case_idle_wake();
    fails += case_rw_overlap();
    fails += case_burst();
    fails += case_fd_reuse();

    duct_engine_stop(io);
    pthread_join(th, nullptr);

    /* One session per conn opened across all four cases; a backend that
     * dropped a registration outright would come up short here even if every
     * surviving round-trip looked fine. */
    int opens = duct_atomic_load(&s_open_count, acquire);
    int expect = 1 + 1 + (int)burst_conns + (int)reuse_rounds;
    if (opens != expect) {
        fprintf(stderr, "events_contract: on_session_open=%d, expected %d\n",
                opens, expect);
        ++fails;
    }

    duct_engine_destroy(io);
    duct_proto_destroy(proto);
    duct_wire_destroy(wire);

    if (fails) {
        fprintf(stderr, "events_contract: FAILED (%d)\n", fails);
        return 1;
    }
    printf("events_contract: OK (4 cases, %d sessions)\n", opens);
    return 0;
}
