/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file retry_frame_ordering_test.c
 * @brief Regression for the ordering gate in 
 * a later, smaller response must never publish ahead of an
 * earlier, larger one still parked as a retry_frame node on TX
 * backpressure. Before the OLB-ticket sequencer (s_commit_response), a
 * later frame's on_frame ran and its response staged/published
 * unconditionally once dispatched, regardless of an older, still-stuck
 * sibling response on the same conn — a smaller payload had an easy time
 * finding room where a larger one didn't.
 *
 * White-box, deterministic, no network timing: includes duct_worker.c
 * directly (same technique as handler_dispatch_test.c) and reuses that
 * file's own s_tiny_pair_open — a real loopback pair whose kernel send
 * buffer is genuinely, permanently saturated (send() until real EAGAIN,
 * not just a requested SO_SNDBUF, since the kernel enforces its own
 * minimum regardless of what was asked for). With the kernel send buffer
 * never draining and a small fixed OLB cap, staging arithmetic alone makes
 * commit_internal exact and reproducible on every run — no reader timing
 * or flood volume to tune against an auto-tuned kernel buffer.
 */

#include "../src/duct_worker.c"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <ws2tcpip.h>
typedef int         duct_socklen_t;
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
typedef socklen_t   duct_socklen_t;
#endif

/* ── Fixture (trimmed from handler_dispatch_test.c's own s_fixture_t) ── */

static unsigned s_on_frame_calls;

static duct_result_t
s_on_frame_echo([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t cid,
               const duct_frame_t *frame, duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    ++s_on_frame_calls;
    out->payload = frame->payload;
    out->conn_id = duct_conn_id_same;
    out->stream_id = duct_stream_id_same;
    return rc_ok;
}

static duct_proto_t *s_make_proto(void)
{
    /* duct_proto_create_tcp bundles a real length-prefix wire, tracked as
     * proto->owned_wire and freed automatically by duct_proto_destroy --
     * needed because duct_proto_create itself rejects wire-less,
     * max_response-less configs. */
    return duct_proto_create_tcp("retry-frame-ordering", s_on_frame_echo);
}

/** @brief Loopback TCP pair, @p out_a's kernel send buffer genuinely and
 *  permanently saturated -- identical technique to handler_dispatch_test.c's
 *  own s_tiny_pair_open, not shared via a header since each white-box test
 *  file already compiles duct_worker.c standalone.
 */
static void s_tiny_pair_open(duct_sock_t *out_a, duct_sock_t *out_b)
{
    duct_sock_t listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener != duct_sock_bad);
    struct sockaddr_in addr = { .sin_family = AF_INET };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    [[maybe_unused]] int brc = bind(listener, (struct sockaddr *)&addr, sizeof addr);
    assert(brc == 0);
    [[maybe_unused]] int lrc = listen(listener, 1);
    assert(lrc == 0);
    duct_socklen_t alen = sizeof addr;
    [[maybe_unused]] int grc = getsockname(listener, (struct sockaddr *)&addr, &alen);
    assert(grc == 0);

    duct_sock_t a = socket(AF_INET, SOCK_STREAM, 0);
    assert(a != duct_sock_bad);
    [[maybe_unused]] int crc = connect(a, (struct sockaddr *)&addr, sizeof addr);
    assert(crc == 0);
    duct_sock_t b = accept(listener, nullptr, nullptr);
    assert(b != duct_sock_bad);
    duct_sock_close(listener);

    int tiny = 1;
    duct_discard setsockopt(a, SOL_SOCKET, SO_SNDBUF, (const char *)&tiny, sizeof tiny);
#ifdef _WIN32
    u_long one = 1u;
    ioctlsocket(a, FIONBIO, &one);
#else
    int flags = fcntl(a, F_GETFL, 0);
    if (flags >= 0)
        duct_discard fcntl(a, F_SETFL, flags | O_NONBLOCK);
#endif
    /* b is never read, so this terminates once the kernel's actual
     * (possibly clamped-up) send buffer is genuinely full. */
    char filler[kbytes(64u)];
    for (;;) {
        int n = send(a, filler, sizeof filler, 0);
        if (n < 0)
            break; /* EAGAIN/EWOULDBLOCK -- saturated */
    }
    *out_a = a;
    *out_b = b;
}

typedef struct {
    duct_proto_t        *proto;
    duct_conn_t         *conn;
    duct_session_t      *s;
    duct_conn_handle_t   handle;
    duct_worker_t        w;
    duct_sock_t          peer_fd;
} s_fixture_t;

static constexpr size_t s_tx_olb_cap = kbytes(8u);
/* Generous vs. s_tx_olb_cap: this fixture writes every test frame's raw
 * bytes back to back into one RX ring with no wraparound (s_post_frame's
 * own contract, matching handler_dispatch_test.c's own), so it must fit
 * the whole test's total request volume, not just one frame. */
static constexpr size_t s_rx_olb_cap = kbytes(64u);

static void s_fixture_init(s_fixture_t *f)
{
    *f = (s_fixture_t){};
    s_on_frame_calls = 0u;
    f->proto = s_make_proto();

    f->conn = duct_conn_acquire();
    assert(f->conn);
    f->handle = duct_conn_handle_get(f->conn);

    duct_sock_t conn_fd;
    s_tiny_pair_open(&conn_fd, &f->peer_fd);
    f->conn->fd = conn_fd;
    f->conn->xport_type = x_tcp;
    /* Model the IO-side EAGAIN latch explicitly. A transient kernel EAGAIN
     * can clear during fixture setup as ACKs arrive, even without a reader. */
    duct_conn_state_set(f->conn, fl_conn_write_armed);

    f->conn->rx_buf = duct_olb_rx_new(s_rx_olb_cap);
    assert(f->conn->rx_buf);
    f->conn->tx_buf = duct_olb_tx_new(s_tx_olb_cap);
    assert(f->conn->tx_buf);

    duct_response_t out = {};
    f->s = duct_session_open(f->proto, duct_conn_id_primary,
                             f->handle, nullptr, 0u, &out);
    assert(f->s);
    auto live = duct_session_handle_from_live(f->s);
    duct_conn_session_bind(f->conn, *(duct_handle_t *)&live);

    duct_timers_init(&f->w.timers);
    s_this_worker = &f->w;
}

/** @brief Drop what a still-parked retry node holds, before the conn goes.
 *  This test ends with the big frame's own node stuck on @c w.retry_head:
 *  the backpressure it parked on never clears, the peer socket never being
 *  read. The real route to that list is @c s_shutdown_drain, which returns
 *  at once without a WFQ this fixture has none of, so @c s_retry_clear runs
 *  straight — and ahead of @c duct_conn_teardown, which nulls the @c rx_buf
 *  the ring pin is dropped through. */
static void s_fixture_release_parked_retry(s_fixture_t *f)
{
    s_retry_clear(&f->w);
}

static void s_fixture_fini(s_fixture_t *f)
{
    s_fixture_release_parked_retry(f);
    duct_timers_destroy(&f->w.timers);
    s_this_worker = nullptr;
    duct_conn_teardown(f->conn);
    duct_sock_close(f->peer_fd);
    duct_session_detach_leg(f->s, duct_conn_id_primary, close_normal);
    duct_conn_release(f->conn);
    duct_proto_destroy(f->proto);
}

/** @brief Write @p len bytes into the conn's RX OLB and dispatch them as
 *  one frame -- same technique as handler_dispatch_test.c's own
 *  s_post_frame.
 */
static duct_exec_rc_t s_post_frame(s_fixture_t *f, const char *payload, size_t len)
{
    auto rx = f->conn->rx_buf;
    auto h = &rx->h;
    uint64_t prev = duct_atomic_load(&h->tail, relaxed);
    uint8_t *dst = rx->data + prev;
    memcpy(dst, payload, len);
    uint64_t new_tail = prev + (uint64_t)len;
    h->stage = (uint32_t)new_tail;
    duct_atomic_store(&h->tail, new_tail, release);

    duct_msg_frame_t task = {
        .stream_id = 0u, .offset = (uint32_t)prev, .len = (uint32_t)len,
    };
    return s_dispatch_frame(&f->w, f->handle, &task);
}

/* ── The test itself ─────────────────────────────────────────────────── */

static const char *run(void)
{
    s_fixture_t f;
    s_fixture_init(&f);

    /* duct_olb_tx_new's requested capacity is a floor, not the literal
     * buf_size -- the underlying duct_vm_new mapping rounds up to its own
     * granularity. Query the real, empty-OLB space instead of assuming
     * s_tx_olb_cap itself is exactly what's available, so filler/big/tiny
     * stay correctly proportioned regardless of that rounding. */
    size_t total_cap = duct_olb_tx_space(f.conn->tx_buf);
    if (total_cap < kbytes(4u)) {
        s_fixture_fini(&f);
        return "fixture: TX OLB smaller than this test's own assumptions need";
    }
    size_t leave_free = 2000u;
    size_t filler_sz = total_cap - leave_free;

    static char payload[s_tx_olb_cap * 2u];
    memset(payload, 'x', sizeof payload);

    /* Filler: fits cleanly, leaves exactly leave_free bytes free -- enough
     * room for the tiny frame below, not enough for the big one. */
    if (s_post_frame(&f, payload, filler_sz) != exec_done) {
        s_fixture_fini(&f);
        return "filler frame: unexpected dispatch outcome";
    }
    if (s_on_frame_calls != 1u) {
        s_fixture_fini(&f);
        return "filler frame: on_frame not called exactly once";
    }
    size_t after_filler = duct_olb_tx_published(f.conn->tx_buf);
    if (after_filler == 0u) {
        s_fixture_fini(&f);
        return "filler frame: nothing published (fixture not saturating as expected)";
    }

    /* Big: sized to exceed leave_free, so it genuinely does not fit in
     * what's left -- must hit commit_internal and park as a retry_frame
     * node, not fail some other way. */
    size_t big_sz = leave_free + 500u;
    if (s_post_frame(&f, payload, big_sz) != exec_done) {
        s_fixture_fini(&f);
        return "big frame: unexpected dispatch outcome";
    }
    if (s_on_frame_calls != 2u) {
        s_fixture_fini(&f);
        return "big frame: on_frame not called exactly once";
    }
    if (!f.w.retry_head || f.w.retry_head->kind != retry_frame) {
        s_fixture_fini(&f);
        return "big frame: did not park as a retry_frame node (commit_internal not reached)";
    }
    size_t after_big = duct_olb_tx_published(f.conn->tx_buf);
    if (after_big != after_filler) {
        s_fixture_fini(&f);
        return "big frame: published bytes changed despite commit_internal";
    }

    /* Tiny: would easily fit in the room the big one couldn't use. Without
     * the ordering gate, s_dispatch_one_frame would run on_frame for it and
     * its response would stage and publish immediately -- ahead of the
     * still-parked big one. */
    constexpr size_t tiny_sz = 16u;
    auto tiny_rc = s_post_frame(&f, payload, tiny_sz);
    if (tiny_rc != exec_defer) {
        s_fixture_fini(&f);
        return "tiny frame: gate did not defer it while the big one is still parked";
    }
    if (s_on_frame_calls != 2u) {
        s_fixture_fini(&f);
        return "tiny frame: on_frame ran despite the gate -- it must not, or its response "
               "could publish ahead of the still-parked big one";
    }
    size_t after_tiny = duct_olb_tx_published(f.conn->tx_buf);
    if (after_tiny != after_filler) {
        s_fixture_fini(&f);
        return "tiny frame: published bytes changed -- it published ahead of the still-parked big one";
    }

    /* Simulate the I/O thread draining the saturated ring. The parked big
     * frame must publish on the next TX-room wake, exactly once. */
    duct_olb_tx_advance(f.conn->tx_buf, after_filler);
    if (!s_retry_drain(&f.w) || f.w.retry_head ||
        duct_olb_tx_published(f.conn->tx_buf) == 0u) {
        s_fixture_fini(&f);
        return "big frame: retry did not resume after TX room became available";
    }

    s_fixture_fini(&f);
    return nullptr;
}

/* A full, just-over-full, and multi-quota list of permanently blocked tickets
 * must receive one attempt each, then let the worker wait for TX room. */
static const char *run_blocked_retry_case(unsigned count)
{
    s_fixture_t f;
    s_fixture_init(&f);
    f.conn->tx_buf->tx_seq_serve = 0u;
    for (unsigned i = 0u; i < count; ++i) {
        auto node = duct_new(retry_node_t);
        assert(node);
        *node = (retry_node_t){
            .kind = retry_frame,
            .frame = { .handle = f.handle, .ticket = 1u },
        };
        s_retry_enqueue(&f.w, node);
    }
    unsigned passes = (count + retry_drain_quota - 1u) / retry_drain_quota;
    for (unsigned pass = 0u; pass < passes; ++pass) {
        bool must_continue = pass + 1u < passes;
        if (s_retry_drain(&f.w) != must_continue) {
            s_fixture_fini(&f);
            return "blocked retry list missed a first attempt or kept the worker spinning";
        }
    }
    for (auto node = f.w.retry_head; node; node = node->next)
        if (!node->attempt_epoch) {
            s_fixture_fini(&f);
            return "blocked retry list skipped a first attempt";
        }
    /* All nodes were previously blocked. A TX-room wake must still revisit
     * the entire list, even when the serving ticket lies beyond one quota. */
    duct_atomic_fetch(add, &f.w.retry_epoch, 1u, release);
    for (unsigned pass = 0u; pass < passes; ++pass) {
        if (s_retry_drain(&f.w) != (pass + 1u < passes)) {
            s_fixture_fini(&f);
            return "room wake did not permit exactly one fresh bounded retry lap";
        }
    }
    for (auto node = f.w.retry_head; node; node = node->next)
        if (node->attempt_epoch != s_retry_lap(duct_atomic_load(&f.w.retry_epoch, relaxed))) {
            s_fixture_fini(&f);
            return "room wake skipped an already attempted retry";
        }
    auto fresh = duct_new(retry_node_t);
    assert(fresh);
    *fresh = (retry_node_t){ .kind = retry_frame,
                               .frame = { .handle = f.handle, .ticket = 1u } };
    s_retry_enqueue(&f.w, fresh);
    bool reached_fresh = false;
    for (unsigned pass = 0u; pass < passes + 1u; ++pass) {
        bool continued = s_retry_drain(&f.w);
        reached_fresh = fresh->attempt_epoch != 0u;
        if (reached_fresh) {
            if (continued) {
                s_fixture_fini(&f);
                return "fresh blocked retry kept the worker spinning after its first attempt";
            }
            break;
        }
        if (!continued) {
            s_fixture_fini(&f);
            return "fresh retry did not force a continuation past the quota";
        }
    }
    if (!reached_fresh) {
        s_fixture_fini(&f);
        return "fresh retry was not attempted";
    }
    s_fixture_fini(&f);
    return nullptr;
}

/* Quota rotation may place the serving ticket behind two whole quotas.
 * Releasing its predecessor must wake that ticket even after every node
 * has armed its wake source during an earlier blocked lap. */
static const char *run_serving_ticket_after_room_wake(void)
{
    s_fixture_t f;
    s_fixture_init(&f);
    f.conn->tx_buf->tx_seq_serve = 0u;
    for (unsigned i = 0u; i <= retry_drain_quota * 2u; ++i) {
        auto node = duct_new(retry_node_t);
        assert(node);
        *node = (retry_node_t){ .kind = retry_frame,
            .frame = { .handle = f.handle,
                       .ticket = retry_drain_quota * 2u + 1u - i } };
        s_retry_enqueue(&f.w, node);
    }
    while (s_retry_drain(&f.w)) {}
    f.conn->tx_buf->tx_seq_serve = 1u;
    duct_atomic_fetch(add, &f.w.retry_epoch, 1u, release);
    for (unsigned pass = 0u; pass < 3u; ++pass) {
        if (!s_retry_drain(&f.w)) {
            s_fixture_fini(&f);
            return "room wake parked before reaching the serving ticket beyond the quota";
        }
    }
    const char *error = f.conn->tx_buf->tx_seq_serve < 2u
        ? "serving ticket was not resolved after its predecessor released" : nullptr;
    /* Resolving the first ticket must also revisit earlier blocked nodes;
     * no new IO event is needed for the now-serving next ticket. */
    for (unsigned pass = 0u; !error && f.w.retry_head && pass < retry_drain_quota * 4u; ++pass)
        if (!s_retry_drain(&f.w))
            error = "ticket progress parked before revisiting an earlier blocked ticket";
    if (!error && f.w.retry_head)
        error = "reversed ticket queue did not finish within bounded passes";
    s_fixture_fini(&f);
    return error;
}

static const char *run_new_arrival_during_lap(void)
{
    s_fixture_t f;
    s_fixture_init(&f);
    f.conn->tx_buf->tx_seq_serve = 0u;
    for (unsigned i = 0u; i < retry_drain_quota + 1u; ++i) {
        auto node = duct_new(retry_node_t);
        assert(node);
        *node = (retry_node_t){ .kind = retry_frame,
                                   .frame = { .handle = f.handle, .ticket = 1u } };
        s_retry_enqueue(&f.w, node);
    }
    if (!s_retry_drain(&f.w)) {
        s_fixture_fini(&f);
        return "multi-quota retry list parked before attempting its tail";
    }
    auto fresh = duct_new(retry_node_t);
    assert(fresh);
    *fresh = (retry_node_t){ .kind = retry_frame,
                               .frame = { .handle = f.handle, .ticket = 1u } };
    s_retry_enqueue(&f.w, fresh);
    if (!s_retry_drain(&f.w) || fresh->attempt_epoch != 0u || s_retry_drain(&f.w) ||
        fresh->attempt_epoch == 0u) {
        s_fixture_fini(&f);
        return "new retry inserted during a quota lap was lost or caused busy spin";
    }
    s_fixture_fini(&f);
    return nullptr;
}

static duct_result_t s_sink([[maybe_unused]] duct_session_t *s,
                            [[maybe_unused]] duct_conn_id_t cid,
                            [[maybe_unused]] const duct_frame_t *frame,
                            [[maybe_unused]] duct_response_t *out,
                            [[maybe_unused]] void *state)
{
    ++s_on_frame_calls;
    return rc_ok;
}

/* A host's pending output must never stop a callback that answers nothing. */
static const char *run_sink_with_pending_host_ticket(void)
{
    s_fixture_t f;
    s_fixture_init(&f);
    f.proto->cfg.on_frame = s_sink;
    auto seq = s_tx_seq_of(f.conn);
    uint32_t held = duct_tx_ticket_fresh;
    assert(s_tx_ticket_take(seq, &held));
    s_on_frame_calls = 0u;
    const char bytes[] = "inbound-with-own-tx-blocked";
    auto result = s_post_frame(&f, bytes, sizeof bytes);
    const char *error = result != exec_done || s_on_frame_calls != 1u || f.w.retry_head
                      ? "a sink's RX waited on its host's pending send" : nullptr;
    s_tx_ticket_resolve(seq);
    s_fixture_fini(&f);
    return error;
}

int main(void)
{
    const char *err = run_sink_with_pending_host_ticket();
    if (!err) err = run();
    if (!err)
        err = run_blocked_retry_case(retry_drain_quota);
    if (!err)
        err = run_blocked_retry_case(retry_drain_quota + 1u);
    if (!err)
        err = run_blocked_retry_case(retry_drain_quota * 2u + 2u);
    if (!err)
        err = run_serving_ticket_after_room_wake();
    if (!err)
        err = run_new_arrival_during_lap();
    if (err) {
        fprintf(stderr, "retry_frame_ordering: %s\n", err);
        return 1;
    }
    printf("retry_frame_ordering: OK (later, smaller response deferred behind an earlier, "
           "still-parked larger one)\n");
    return 0;
}
