/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file join_edge_test.c
 * @brief Join edge cases: reject, stale token, occupied slot, on_conn_join
 *        non-rc_ok, multi-proto sync+fallback, resolve_new with out_user_ctx,
 *        and workers>1 join routing.
 *
 * Each scenario spins a fresh engine, drives its client conns, asserts the
 * callback accounting, then stops + destroys. Validates the on_conn_join
 * return-code contract (non-rc_ok → detach leg + tear down new conn, session
 * intact), that bytes sent behind a refused join never reach on_frame, and the
 * accept-path edge handling.
 *
 * stale_held parks the worker, closes the session and joins a leg to it, so the
 * join, which retires its conn before bind, and the bytes behind it reach the
 * worker in one pass. The worker must not read or ack the retired conn's rings
 * then; ThreadSanitizer reports the race against io's teardown otherwise. The
 * data listener holds a connection until its first byte is in, and io admits a
 * listener's connections one after another: a second connection reaching
 * preparse after the join's shows the join and its bytes posted behind the
 * parked worker.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>

static constexpr unsigned connect_retry_ms = 1500u;
static constexpr unsigned join_wait_ms = 3000u;   /* ASAN CI headroom for cross-worker join */
static constexpr int echo_timeout_ms = 2000;
static constexpr int eof_timeout_ms = 2000;

static uint32_t s_tok_gen(duct_handle_t w)
{
    return (uint32_t)(w >> 32u);
}

static atomic_int g_open_count = 0;
static atomic_int g_join_count = 0;
static atomic_int g_join_reject_count = 0;
/** @brief @c on_frame calls that carried a conn_id past the session's legs. */
static atomic_int g_stray = 0;
static _Atomic(duct_handle_t) g_ctrl_tok;
static atomic_uintptr_t g_seen_user_ctx = 0;
/* Timeout diagnostics: distinguish a slow cross-worker join from a genuine
 * race/refusal. g_preparse_* captures whether the data leg's preparse ran and
 * what it saw/returned; combined with ctrl_gen + join_count it tells us:
 *   ctrl_gen==0                  → ctrl session never opened (upstream)
 *   preparse_disp==reject        → token not visible at preparse time (race)
 *   preparse_disp==join, jc==0   → runtime refusal (resolve/post/session_join)
 *   jc==target                   → not a timeout (helper not called) */
static atomic_int g_preparse_calls = 0;
static atomic_int g_preparse_disp = 0;     /* (int)duct_resolve_disposition_t */
static atomic_uint g_preparse_gen = 0;     /* generation preparse loaded from g_ctrl_tok */

enum s_scenario {
    sc_reject,
    sc_stale,
    sc_stale_held,
    sc_occupied,
    sc_join_reject,
    sc_multi_fallback,
    sc_new_user_ctx,
    sc_two_workers,
    sc_async_new,
    sc_async_join,
    sc_async_reject,
    sc_ipv6,
};
static atomic_int g_scenario = 0;

/* The worker's park in sc_stale_held: its timer fire parks and returns once the test releases it. */
static atomic_int g_hold = th_hold_off;

/* ── Protocol callbacks ───────────────────────────────────────────── */

static duct_result_t
on_open([[maybe_unused]] duct_session_t *s, duct_handle_t tok,
        void *user_ctx, [[maybe_unused]] duct_response_t *out,
        [[maybe_unused]] void *proto_state)
{
    auto sc = (enum s_scenario)duct_atomic_load(&g_scenario, relaxed);
    if (sc == sc_new_user_ctx)
        duct_atomic_store(&g_seen_user_ctx, (uintptr_t)user_ctx, release);
    else
        duct_atomic_store(&g_ctrl_tok, tok, release);
    duct_atomic_fetch(add, &g_open_count, 1, relaxed);
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, duct_conn_id_t cid,
         const duct_frame_t *frame, duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_stray, cid >= duct_session_max_legs, relaxed);
    duct_response_echo(out, frame);
    return rc_ok;
}

static duct_result_t
on_join([[maybe_unused]] duct_session_t *s, duct_conn_id_t cid,
        [[maybe_unused]] const duct_peer_t *peer, [[maybe_unused]] duct_response_t *out,
        [[maybe_unused]] void *proto_state)
{
    int prev = duct_atomic_fetch(add, &g_join_count, 1, relaxed);
    auto sc = (enum s_scenario)duct_atomic_load(&g_scenario, relaxed);
    /* sc_join_reject: the FIRST join returns rc_drop (F1: leg detached, session
     * intact); a retry to the same conn_id must succeed — proving the detach. */
    if (sc == sc_join_reject && prev == 0) {
        duct_atomic_fetch(add, &g_join_reject_count, 1, relaxed);
        return rc_drop;
    }
    (void)cid;
    return rc_ok;
}

static duct_result_t
on_timer_hold([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_response_t *out,
              [[maybe_unused]] void *proto_state, [[maybe_unused]] uint64_t arg)
{
    th_hold_park(&g_hold, join_wait_ms);
    return rc_ok;
}

/* ── Pre-parse ────────────────────────────────────────────────────── */

enum pp_mode { pp_reject, pp_not_me, pp_join_held, pp_join_real, pp_join_stale, pp_join_occupied, pp_new_ctx };

static duct_resolve_disposition_t
preparse(void *ctx, [[maybe_unused]] const duct_peer_t *peer,
         [[maybe_unused]] duct_view_u8 peek, duct_handle_t *out_tok,
         duct_conn_id_t *out_conn_id, void **out_user_ctx,
         [[maybe_unused]] size_t *out_lead)
{
    auto mode = (enum pp_mode)(uintptr_t)ctx;
    duct_resolve_disposition_t disp = resolve_reject;
    switch (mode) {
    case pp_reject:
        disp = resolve_reject;
        break;
    case pp_not_me:
        disp = resolve_not_me;
        break;
    case pp_join_held:
        /* The first connection joins; every later one is the test's marker, whatever its read held. */
        if (duct_atomic_load(&g_preparse_calls, acquire) != 0) {
            disp = resolve_reject;
            break;
        }
        [[fallthrough]];
    case pp_join_real: {
        auto tok = duct_atomic_load(&g_ctrl_tok, acquire);
        duct_atomic_store(&g_preparse_gen, (unsigned)s_tok_gen(tok), relaxed);
        *out_tok = tok;
        *out_conn_id = 1u;
        disp = s_tok_gen(tok) ? resolve_join : resolve_reject;
        break;
    }
    case pp_join_stale:
        *out_tok = (duct_handle_t)(((uint64_t)999u << 32) | 999u);
        *out_conn_id = 1u;
        disp = resolve_join;
        break;
    case pp_join_occupied: {
        auto tok = duct_atomic_load(&g_ctrl_tok, acquire);
        duct_atomic_store(&g_preparse_gen, (unsigned)s_tok_gen(tok), relaxed);
        *out_tok = tok;
        *out_conn_id = 0u;   /* conn 0 is the control leg — occupied */
        disp = s_tok_gen(tok) ? resolve_join : resolve_reject;
        break;
    }
    case pp_new_ctx:
        *out_user_ctx = (void *)0xC0FFEEu;
        disp = resolve_new;
        break;
    }
    duct_atomic_fetch(add, &g_preparse_calls, 1, relaxed);
    duct_atomic_store(&g_preparse_disp, (int)disp, relaxed);
    return disp;
}

/* ── Harness ──────────────────────────────────────────────────────── */

static void *s_run_thread(void *arg)
{
    (void)duct_engine_wait((duct_engine_t *)arg);
    return nullptr;
}

static duct_sock_t s_connect(uint16_t port)
{
    for (unsigned waited = 0u; waited < connect_retry_ms; waited += 10u) {
        duct_sock_t fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == duct_sock_bad)
            return duct_sock_bad;
        struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port) };
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0)
            return fd;
        close(fd);
        th_sleep_ms(10u);
    }
    return duct_sock_bad;
}

static duct_sock_t s_connect_ipv6(uint16_t port)
{
    for (unsigned waited = 0u; waited < connect_retry_ms; waited += 10u) {
        duct_sock_t fd = socket(AF_INET6, SOCK_STREAM, 0);
        if (fd == duct_sock_bad)
            return duct_sock_bad;
        struct sockaddr_in6 addr = {};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
        inet_pton(AF_INET6, "::1", &addr.sin6_addr);
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0)
            return fd;
        close(fd);
        th_sleep_ms(10u);
    }
    return duct_sock_bad;
}

static bool s_echo_roundtrip(duct_sock_t fd, const char *msg)
{
    size_t len = strlen(msg);
    if (write(fd, msg, len) != (ssize_t)len)
        return false;
    char buf[64] = {};
    size_t got = 0u;
    while (got < len) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, echo_timeout_ms) <= 0)
            return false;
        ssize_t n = read(fd, buf + got, sizeof buf - got - 1u);
        if (n <= 0)
            return false;
        got += (size_t)n;
    }
    return memcmp(buf, msg, len) == 0;
}

/* Bounded EOF probe: true if the peer closed (read <= 0) within the timeout,
 * false on timeout or error. Prevents a stalled runtime from hanging the suite. */
static bool s_read_eof(duct_sock_t fd)
{
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    if (poll(&pfd, 1, eof_timeout_ms) <= 0)
        return false;
    char buf[4];
    return read(fd, buf, sizeof buf) <= 0;
}

static bool s_wait_atomic(atomic_int *p, int target, unsigned timeout_ms)
{
    for (unsigned w = 0u; w < timeout_ms; w += 10u) {
        if (duct_atomic_load(p, acquire) == target)
            return true;
        th_sleep_ms(10u);
    }
    return duct_atomic_load(p, acquire) == target;
}

/* Emit timeout diagnostics: distinguishes a slow cross-worker join (timing) from
 * a genuine race/refusal. See g_preparse_* comment for the decision table. */
static void s_diag_timeout(const char *scenario)
{
    auto tok = duct_atomic_load(&g_ctrl_tok, acquire);
    fprintf(stderr,
            "join_edge/%s TIMEOUT: open=%d ctrl_gen=%llu preparse_calls=%d "
            "preparse_disp=%d preparse_gen=%u join=%d reject=%d\n",
            scenario,
            duct_atomic_load(&g_open_count, acquire),
            (unsigned long long)s_tok_gen(tok),
            duct_atomic_load(&g_preparse_calls, relaxed),
            duct_atomic_load(&g_preparse_disp, relaxed),
            duct_atomic_load(&g_preparse_gen, relaxed),
            duct_atomic_load(&g_join_count, acquire),
            duct_atomic_load(&g_join_reject_count, relaxed));
}

/* Wait for g_join_count to reach target, logging diagnostics on timeout. */
static bool s_wait_join(int target, unsigned timeout_ms, const char *scenario)
{
    bool ok = s_wait_atomic(&g_join_count, target, timeout_ms);
    if (!ok)
        s_diag_timeout(scenario);
    return ok;
}

/* Per-scenario reset of the shared accounting. */
static void s_reset(enum s_scenario sc)
{
    duct_atomic_store(&g_scenario, (int)sc, relaxed);
    duct_atomic_store(&g_open_count, 0, relaxed);
    duct_atomic_store(&g_join_count, 0, relaxed);
    duct_atomic_store(&g_join_reject_count, 0, relaxed);
    duct_atomic_store(&g_stray, 0, relaxed);
    duct_handle_t zero = {};
    duct_atomic_store(&g_ctrl_tok, zero, relaxed);
    duct_atomic_store(&g_seen_user_ctx, 0u, relaxed);
    duct_atomic_store(&g_preparse_calls, 0, relaxed);
    duct_atomic_store(&g_preparse_disp, 0, relaxed);
    duct_atomic_store(&g_preparse_gen, 0u, relaxed);
    duct_atomic_store(&g_hold, th_hold_off, relaxed);
}

static duct_engine_t *s_engine(unsigned workers)
{
    return duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = workers });
}

/* ── Scenarios ────────────────────────────────────────────────────── */

static bool sc_run_reject(void)
{
    s_reset(sc_reject);
    auto io = s_engine(1);
    if (!io) return false;
    auto p = duct_proto_create(&(duct_proto_cfg_t){
        .name = "r", .on_frame = on_frame, .on_session_open = on_open,
        .preparse = preparse, .preparse_mode = resolve_sync,
        .max_response = 4096u,
    });
    if (!p) { duct_engine_destroy(io); duct_proto_destroy(p); return false; }
    uint16_t port = 0u;
    bool ok = (duct_io_listen(io, "127.0.0.1", &port, p) == rc_ok);
    pthread_t th;
    if (ok && pthread_create(&th, nullptr, s_run_thread, io) == 0) {
        duct_sock_t fd = s_connect(port);
        if (fd != duct_sock_bad) {
            /* preparse rejects → server closes fd; client write/read sees EOF. */
            static const char m[] = "x";
            (void)!write(fd, m, 1);
            ok = s_read_eof(fd);
            close(fd);
        } else ok = false;
        duct_engine_stop(io); pthread_join(th, nullptr);
    } else ok = false;
    duct_engine_destroy(io);
    duct_proto_destroy(p);
    return ok && duct_atomic_load(&g_open_count, acquire) == 0;
}

/* Dedicated stale-token scenario: data listener built with pp_join_stale ctx. */
static bool sc_run_stale_dedicated(void)
{
    s_reset(sc_stale);
    auto io = s_engine(1);
    if (!io) return false;
    auto ctrl = duct_proto_create(&(duct_proto_cfg_t){
        .name = "c", .on_frame = on_frame, .on_session_open = on_open,
        .max_response = 4096u,
    });
    auto data = duct_proto_create(&(duct_proto_cfg_t){
        .name = "d", .on_frame = on_frame,
        .preparse = preparse, .preparse_mode = resolve_sync,
        .preparse_ctx = (void *)pp_join_stale,
        .max_response = 4096u,
    });
    if (!ctrl || !data) { duct_engine_destroy(io); duct_proto_destroy(ctrl); duct_proto_destroy(data); return false; }
    uint16_t pc = 0u, pd = 0u;
    bool ok = (duct_io_listen(io, "127.0.0.1", &pc, ctrl) == rc_ok
               && duct_io_listen(io, "127.0.0.1", &pd, data) == rc_ok);
    pthread_t th;
    if (ok && pthread_create(&th, nullptr, s_run_thread, io) == 0) {
        duct_sock_t cfd = s_connect(pc);
        if (cfd != duct_sock_bad) { ok = s_echo_roundtrip(cfd, "ctrl"); close(cfd); }
        else ok = false;
        duct_sock_t dfd = s_connect(pd);   /* preparse → stale join → fd closed */
        if (dfd != duct_sock_bad) {
            static const char m[] = "y";
            (void)!write(dfd, m, 1);
            ok = ok && s_read_eof(dfd);
            close(dfd);
        }
        duct_engine_stop(io); pthread_join(th, nullptr);
    } else ok = false;
    duct_engine_destroy(io);
    duct_proto_destroy(ctrl);
    duct_proto_destroy(data);
    /* ctrl opened 1 session; stale join must not fire on_conn_join. */
    return ok
        && duct_atomic_load(&g_open_count, acquire) == 1
        && duct_atomic_load(&g_join_count, acquire) == 0;
}

/* A join whose session closes before the worker reaches it: the close, the join and the bytes behind
 * the join queue behind a parked worker, so one pass runs the close, then the join, which retires the
 * conn, and then the bytes. Nothing may touch the conn's rings from there on: io frees them as soon
 * as it takes the retire request, and under ThreadSanitizer the touch is the race. */
static bool sc_run_stale_held(void)
{
    s_reset(sc_stale_held);
    auto io = s_engine(1);
    if (!io) return false;
    auto ctrl = duct_proto_create(&(duct_proto_cfg_t){
        .name = "c", .on_frame = on_frame, .on_session_open = on_open,
        .on_conn_join = on_join, .on_timer = on_timer_hold,
        .max_response = 4096u,
    });
    auto data = duct_proto_create(&(duct_proto_cfg_t){
        .name = "d", .on_frame = on_frame,
        .preparse = preparse, .preparse_mode = resolve_sync,
        .preparse_ctx = (void *)pp_join_held,
        .max_response = 4096u,
    });
    if (!ctrl || !data) { duct_engine_destroy(io); duct_proto_destroy(ctrl); duct_proto_destroy(data); return false; }
    uint16_t pc = 0u, pd = 0u;
    /* The data listener holds each connection until its first byte is in, so the join's seeded bytes are
     * posted with the join itself and not by a later read; join_wait_ms bounds that wait. */
    bool ok = (duct_io_listen(io, "127.0.0.1", &pc, ctrl) == rc_ok
               && duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_stream,
                      .addr = "127.0.0.1", .n_protos = 1,
                      .protos = (const duct_proto_t *[]){ data },
                      .probe_wait_ms = join_wait_ms, .peek_min = 1u,
                  }, &pd, nullptr, 0u, nullptr) == rc_ok);
    pthread_t th;
    duct_sock_t cfd = duct_sock_bad;
    if (ok && pthread_create(&th, nullptr, s_run_thread, io) == 0) {
        cfd = s_connect(pc);
        ok = cfd != duct_sock_bad && s_echo_roundtrip(cfd, "ctrl")
             && duct_timer_start(io, ctrl, nullptr, 0u, 1u) == rc_ok
             && s_wait_atomic(&g_hold, th_hold_parked, join_wait_ms)
             && duct_session_close(io, duct_atomic_load(&g_ctrl_tok, acquire), close_peer) == rc_ok;
        duct_sock_t dfd = ok ? s_connect(pd) : duct_sock_bad;
        if (dfd != duct_sock_bad) {
            static const char m[] = "behind-a-join-of-a-closed-session";
            (void)!write(dfd, m, sizeof m - 1u);
            ok = s_wait_atomic(&g_preparse_calls, 1, join_wait_ms);
            duct_sock_t mfd = ok ? s_connect(pd) : duct_sock_bad;
            if (mfd != duct_sock_bad) {
                (void)!write(mfd, "M", 1u);
                ok = s_wait_atomic(&g_preparse_calls, 2, join_wait_ms);
                close(mfd);
            } else ok = false;
            th_hold_release(&g_hold);
            ok = ok && s_read_eof(dfd);
            close(dfd);
        } else ok = false;
        th_hold_release(&g_hold);
        if (cfd != duct_sock_bad) close(cfd);
        duct_engine_stop(io); pthread_join(th, nullptr);
    } else ok = false;
    duct_engine_destroy(io);
    duct_proto_destroy(ctrl);
    duct_proto_destroy(data);
    return ok
        && duct_atomic_load(&g_open_count, acquire) == 1
        && duct_atomic_load(&g_join_count, acquire) == 0;
}

static bool sc_run_occupied(void)
{
    s_reset(sc_occupied);
    auto io = s_engine(1);
    if (!io) return false;
    auto ctrl = duct_proto_create(&(duct_proto_cfg_t){
        .name = "c", .on_frame = on_frame, .on_session_open = on_open,
        .on_conn_join = on_join,
        .max_response = 4096u,
    });
    auto data = duct_proto_create(&(duct_proto_cfg_t){
        .name = "d", .on_frame = on_frame,
        .preparse = preparse, .preparse_mode = resolve_sync,
        .preparse_ctx = (void *)pp_join_occupied,
        .max_response = 4096u,
    });
    if (!ctrl || !data) { duct_engine_destroy(io); duct_proto_destroy(ctrl); duct_proto_destroy(data); return false; }
    uint16_t pc = 0u, pd = 0u;
    bool ok = (duct_io_listen(io, "127.0.0.1", &pc, ctrl) == rc_ok
               && duct_io_listen(io, "127.0.0.1", &pd, data) == rc_ok);
    pthread_t th;
    if (ok && pthread_create(&th, nullptr, s_run_thread, io) == 0) {
        duct_sock_t cfd = s_connect(pc);
        if (cfd != duct_sock_bad) { ok = s_echo_roundtrip(cfd, "ctrl"); }
        else ok = false;
        duct_sock_t dfd = s_connect(pd);  /* join to occupied conn 0 → rejected */
        if (dfd != duct_sock_bad) {
            ok = ok && s_wait_atomic(&g_join_count, 0, 500u);
            close(dfd);
        }
        if (cfd != duct_sock_bad) close(cfd);
        duct_engine_stop(io); pthread_join(th, nullptr);
    } else ok = false;
    duct_engine_destroy(io);
    duct_proto_destroy(ctrl);
    duct_proto_destroy(data);
    /* Occupied slot: duct_session_exec_conn_join retires the conn before firing on_conn_join. */
    return ok
        && duct_atomic_load(&g_open_count, acquire) == 1
        && duct_atomic_load(&g_join_count, acquire) == 0;
}

static bool sc_run_join_reject(void)
{
    s_reset(sc_join_reject);
    auto io = s_engine(1);
    if (!io) return false;
    auto ctrl = duct_proto_create(&(duct_proto_cfg_t){
        .name = "c", .on_frame = on_frame, .on_session_open = on_open,
        .on_conn_join = on_join,
        .max_response = 4096u,
    });
    auto data = duct_proto_create(&(duct_proto_cfg_t){
        .name = "d", .on_frame = on_frame,
        .preparse = preparse, .preparse_mode = resolve_sync,
        .preparse_ctx = (void *)pp_join_real,
        .max_response = 4096u,
    });
    if (!ctrl || !data) { duct_engine_destroy(io); duct_proto_destroy(ctrl); duct_proto_destroy(data); return false; }
    uint16_t pc = 0u, pd = 0u;
    bool ok = (duct_io_listen(io, "127.0.0.1", &pc, ctrl) == rc_ok
               && duct_io_listen(io, "127.0.0.1", &pd, data) == rc_ok);
    pthread_t th;
    if (ok && pthread_create(&th, nullptr, s_run_thread, io) == 0) {
        duct_sock_t cfd = s_connect(pc);
        if (cfd != duct_sock_bad) ok = s_echo_roundtrip(cfd, "ctrl");
        else ok = false;
        /* First data leg: on_conn_join returns rc_drop → detached, conn torn down.
         * The bytes written behind the connect reach the worker with the leg
         * detached and the conn still bound; none of them reaches on_frame. */
        duct_sock_t d1 = s_connect(pd);
        if (d1 != duct_sock_bad) {
            static const char m[] = "behind-a-rejected-join";
            (void)!write(d1, m, sizeof m - 1u);
            ok = ok && s_wait_join(1, join_wait_ms, "join_reject");
            /* Time for the bytes to reach dispatch before the client closes. */
            th_sleep_ms(30u);
            close(d1);
        }
        /* Second data leg to the same conn_id=1: must succeed — the rejected leg
         * was detached, so the slot is free again (F1 contract). */
        duct_sock_t d2 = s_connect(pd);
        if (d2 != duct_sock_bad) {
            ok = ok && s_wait_join(2, join_wait_ms, "join_reject");
            close(d2);
        }
        if (cfd != duct_sock_bad) close(cfd);
        duct_engine_stop(io); pthread_join(th, nullptr);
    } else ok = false;
    duct_engine_destroy(io);
    duct_proto_destroy(ctrl);
    duct_proto_destroy(data);
    return ok
        && duct_atomic_load(&g_open_count, acquire) == 1
        && duct_atomic_load(&g_join_count, acquire) == 2
        && duct_atomic_load(&g_join_reject_count, acquire) == 1
        && duct_atomic_load(&g_stray, acquire) == 0;
}

static bool sc_run_multi_fallback(void)
{
    s_reset(sc_multi_fallback);
    auto io = s_engine(1);
    if (!io) return false;
    auto classifier = duct_proto_create(&(duct_proto_cfg_t){
        .name = "cls", .on_frame = on_frame, .on_session_open = on_open,
        .preparse = preparse, .preparse_mode = resolve_sync,
        .preparse_ctx = (void *)pp_not_me,
        .max_response = 4096u,
    });
    auto plain = duct_proto_create(&(duct_proto_cfg_t){
        .name = "pln", .on_frame = on_frame, .on_session_open = on_open,
        .max_response = 4096u,
    });
    if (!classifier || !plain) { duct_engine_destroy(io); duct_proto_destroy(classifier); duct_proto_destroy(plain); return false; }
    uint16_t port = 0u;
    bool ok = (duct_listener_bind(io, &(duct_listener_cfg_t){
        .addr = "127.0.0.1",
        .n_protos = 2u,
        .protos = (const duct_proto_t *[]){ classifier, plain },
        .peek_cap = 0u,
    }, &port, nullptr, 0u, nullptr) == rc_ok);
    pthread_t th;
    if (ok && pthread_create(&th, nullptr, s_run_thread, io) == 0) {
        duct_sock_t fd = s_connect(port);
        if (fd != duct_sock_bad) {
            ok = s_echo_roundtrip(fd, "fallback");
            close(fd);
        } else ok = false;
        duct_engine_stop(io); pthread_join(th, nullptr);
    } else ok = false;
    duct_engine_destroy(io);
    duct_proto_destroy(classifier);
    duct_proto_destroy(plain);
    /* classifier rejects → fallback to plain → one new session. */
    return ok && duct_atomic_load(&g_open_count, acquire) == 1;
}

static bool sc_run_new_user_ctx(void)
{
    s_reset(sc_new_user_ctx);
    auto io = s_engine(1);
    if (!io) return false;
    auto p = duct_proto_create(&(duct_proto_cfg_t){
        .name = "n", .on_frame = on_frame, .on_session_open = on_open,
        .preparse = preparse, .preparse_mode = resolve_sync,
        .preparse_ctx = (void *)pp_new_ctx,
        .max_response = 4096u,
    });
    if (!p) { duct_engine_destroy(io); duct_proto_destroy(p); return false; }
    uint16_t port = 0u;
    bool ok = (duct_io_listen(io, "127.0.0.1", &port, p) == rc_ok);
    pthread_t th;
    if (ok && pthread_create(&th, nullptr, s_run_thread, io) == 0) {
        duct_sock_t fd = s_connect(port);
        if (fd != duct_sock_bad) {
            ok = s_echo_roundtrip(fd, "new-ctx");
            close(fd);
        } else ok = false;
        duct_engine_stop(io); pthread_join(th, nullptr);
    } else ok = false;
    duct_engine_destroy(io);
    duct_proto_destroy(p);
    return ok
        && duct_atomic_load(&g_open_count, acquire) == 1
        && duct_atomic_load(&g_seen_user_ctx, acquire) == 0xC0FFEEu;
}

static bool sc_run_two_workers(void)
{
    s_reset(sc_two_workers);
    auto io = s_engine(2);
    if (!io) return false;
    auto ctrl = duct_proto_create(&(duct_proto_cfg_t){
        .name = "c", .on_frame = on_frame, .on_session_open = on_open,
        .on_conn_join = on_join,
        .max_response = 4096u,
    });
    auto data = duct_proto_create(&(duct_proto_cfg_t){
        .name = "d", .on_frame = on_frame,
        .preparse = preparse, .preparse_mode = resolve_sync,
        .preparse_ctx = (void *)pp_join_real,
        .max_response = 4096u,
    });
    if (!ctrl || !data) { duct_engine_destroy(io); duct_proto_destroy(ctrl); duct_proto_destroy(data); return false; }
    uint16_t pc = 0u, pd = 0u;
    bool ok = (duct_io_listen(io, "127.0.0.1", &pc, ctrl) == rc_ok
               && duct_io_listen(io, "127.0.0.1", &pd, data) == rc_ok);
    pthread_t th;
    if (ok && pthread_create(&th, nullptr, s_run_thread, io) == 0) {
        duct_sock_t cfd = s_connect(pc);
        if (cfd != duct_sock_bad) ok = s_echo_roundtrip(cfd, "ctrl-w2");
        else ok = false;
        duct_sock_t dfd = s_connect(pd);
        if (dfd != duct_sock_bad) {
            ok = ok && s_wait_join(1, join_wait_ms, "two_workers");
            close(dfd);
        }
        if (cfd != duct_sock_bad) close(cfd);
        duct_engine_stop(io); pthread_join(th, nullptr);
    } else ok = false;
    duct_engine_destroy(io);
    duct_proto_destroy(ctrl);
    duct_proto_destroy(data);
    return ok
        && duct_atomic_load(&g_open_count, acquire) == 1
        && duct_atomic_load(&g_join_count, acquire) == 1;
}

/* ── Async pre-parse (step 1b.2) + IPv6 accept ────────────────────── */

static bool sc_run_async_new(void)
{
    s_reset(sc_async_new);
    auto io = s_engine(1);
    if (!io) return false;
    auto p = duct_proto_create(&(duct_proto_cfg_t){
        .name = "an", .on_frame = on_frame, .on_session_open = on_open,
        .preparse = preparse, .preparse_mode = resolve_async,
        .preparse_ctx = (void *)pp_new_ctx,
        .max_response = 4096u,
    });
    if (!p) { duct_engine_destroy(io); duct_proto_destroy(p); return false; }
    uint16_t port = 0u;
    bool ok = (duct_io_listen(io, "127.0.0.1", &port, p) == rc_ok);
    pthread_t th;
    if (ok && pthread_create(&th, nullptr, s_run_thread, io) == 0) {
        duct_sock_t fd = s_connect(port);
        if (fd != duct_sock_bad) {
            ok = s_echo_roundtrip(fd, "async-new");
            close(fd);
        } else ok = false;
        duct_engine_stop(io); pthread_join(th, nullptr);
    } else ok = false;
    duct_engine_destroy(io);
    duct_proto_destroy(p);
    /* async preparse → resolve_new → reverse kick → conn + session open + echo. */
    return ok && duct_atomic_load(&g_open_count, acquire) == 1;
}

static bool sc_run_async_join(void)
{
    s_reset(sc_async_join);
    auto io = s_engine(1);
    if (!io) return false;
    auto ctrl = duct_proto_create(&(duct_proto_cfg_t){
        .name = "c", .on_frame = on_frame, .on_session_open = on_open,
        .on_conn_join = on_join,
        .max_response = 4096u,
    });
    auto data = duct_proto_create(&(duct_proto_cfg_t){
        .name = "d", .on_frame = on_frame,
        .preparse = preparse, .preparse_mode = resolve_async,
        .preparse_ctx = (void *)pp_join_real,
        .on_conn_join = on_join,
        .max_response = 4096u,
    });
    if (!ctrl || !data) { duct_engine_destroy(io); duct_proto_destroy(ctrl); duct_proto_destroy(data); return false; }
    uint16_t pc = 0u, pd = 0u;
    bool ok = (duct_io_listen(io, "127.0.0.1", &pc, ctrl) == rc_ok
               && duct_io_listen(io, "127.0.0.1", &pd, data) == rc_ok);
    pthread_t th;
    if (ok && pthread_create(&th, nullptr, s_run_thread, io) == 0) {
        duct_sock_t cfd = s_connect(pc);
        if (cfd != duct_sock_bad) ok = s_echo_roundtrip(cfd, "ctrl-aj");
        else ok = false;
        duct_sock_t dfd = s_connect(pd);   /* async preparse → join */
        if (dfd != duct_sock_bad) {
            ok = ok && s_wait_join(1, join_wait_ms, "async_join");
            close(dfd);
        }
        if (cfd != duct_sock_bad) close(cfd);
        duct_engine_stop(io); pthread_join(th, nullptr);
    } else ok = false;
    duct_engine_destroy(io);
    duct_proto_destroy(ctrl);
    duct_proto_destroy(data);
    return ok
        && duct_atomic_load(&g_open_count, acquire) == 1
        && duct_atomic_load(&g_join_count, acquire) == 1;
}

static bool sc_run_async_reject(void)
{
    s_reset(sc_async_reject);
    auto io = s_engine(1);
    if (!io) return false;
    auto p = duct_proto_create(&(duct_proto_cfg_t){
        .name = "ar", .on_frame = on_frame, .on_session_open = on_open,
        .preparse = preparse, .preparse_mode = resolve_async,
        .preparse_ctx = (void *)pp_reject,
        .max_response = 4096u,
    });
    if (!p) { duct_engine_destroy(io); duct_proto_destroy(p); return false; }
    uint16_t port = 0u;
    bool ok = (duct_io_listen(io, "127.0.0.1", &port, p) == rc_ok);
    pthread_t th;
    if (ok && pthread_create(&th, nullptr, s_run_thread, io) == 0) {
        duct_sock_t fd = s_connect(port);
        if (fd != duct_sock_bad) {
            static const char m[] = "x";
            (void)!write(fd, m, 1);
            ok = s_read_eof(fd);
            close(fd);
        } else ok = false;
        duct_engine_stop(io); pthread_join(th, nullptr);
    } else ok = false;
    duct_engine_destroy(io);
    duct_proto_destroy(p);
    return ok && duct_atomic_load(&g_open_count, acquire) == 0;
}

static bool sc_run_ipv6(void)
{
    s_reset(sc_ipv6);
    auto io = s_engine(1);
    if (!io) return false;
    auto p = duct_proto_create(&(duct_proto_cfg_t){
        .name = "v6", .on_frame = on_frame, .on_session_open = on_open,
        .max_response = 4096u,
    });
    if (!p) { duct_engine_destroy(io); duct_proto_destroy(p); return false; }
    uint16_t port = 0u;
    bool ok = (duct_io_listen(io, "::1", &port, p) == rc_ok);
    pthread_t th;
    if (ok && pthread_create(&th, nullptr, s_run_thread, io) == 0) {
        duct_sock_t fd = s_connect_ipv6(port);
        if (fd != duct_sock_bad) {
            ok = s_echo_roundtrip(fd, "ipv6");
            close(fd);
        } else ok = false;
        duct_engine_stop(io); pthread_join(th, nullptr);
    } else ok = false;
    duct_engine_destroy(io);
    duct_proto_destroy(p);
    return ok && duct_atomic_load(&g_open_count, acquire) == 1;
}

/* ── Driver ───────────────────────────────────────────────────────── */

static struct { const char *name; bool (*fn)(void); } s_tests[] = {
    { "reject",         sc_run_reject },
    { "stale",          sc_run_stale_dedicated },
    { "stale_held",     sc_run_stale_held },
    { "occupied",       sc_run_occupied },
    { "join_reject",    sc_run_join_reject },
    { "multi_fallback", sc_run_multi_fallback },
    { "new_user_ctx",   sc_run_new_user_ctx },
    { "two_workers",    sc_run_two_workers },
    { "async_new",      sc_run_async_new },
    { "async_join",     sc_run_async_join },
    { "async_reject",   sc_run_async_reject },
    { "ipv6",           sc_run_ipv6 },
};

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    int fail = 0;
    for (unsigned i = 0u; i < sizeof s_tests / sizeof s_tests[0]; ++i) {
        bool ok = s_tests[i].fn();
        printf("join_edge/%-14s %s\n", s_tests[i].name, ok ? "OK" : "FAIL");
        if (!ok) ++fail;
    }
    if (fail) {
        printf("join_edge: %d scenario(s) FAILED\n", fail);
        return 1;
    }
    printf("join_edge: OK (all %zu scenarios passed)\n",
           sizeof s_tests / sizeof s_tests[0]);
    return 0;
}
