/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file tx_hold_multi_leg_test.c
 * @brief An inbound conn's hold stands until every answer its dispatch parked
 * is served, whichever leg each one parked on.
 *
 * The hold is one {leg, ticket} pair, so a dispatch that parks answers on two
 * legs, the packets of one inter message routed to different legs being the
 * case, names only the later one. When that leg serves first the hold used to
 * clear with the other answer still parked, and the conn's next message
 * dispatched ahead of it. s_hold_adopt hands the hold to a parked answer of
 * the same conn instead.
 *
 * White-box and deterministic: includes duct_worker.c directly, same technique
 * as retry_frame_ordering_test.c, and plays the drain's part by serving a
 * leg's ticket and unlinking the node by hand. No socket and no thread: the
 * legs are conns without an OLB, whose ticket counters live in the conn.
 */

#include "../src/duct_worker.c"

#include <assert.h>
#include <stdio.h>

typedef struct {
    duct_proto_t       *proto;
    duct_session_t     *s;
    duct_conn_t        *x, *a, *c, *y;
    duct_conn_handle_t  xh;
    duct_worker_t       w;
} fixture_t;

enum : duct_conn_id_t { leg_a = 1u, leg_c = 2u };

static duct_result_t on_frame([[maybe_unused]] duct_session_t *s,
                              [[maybe_unused]] duct_conn_id_t conn_id,
                              [[maybe_unused]] const duct_frame_t *frame,
                              [[maybe_unused]] duct_response_t *out,
                              [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

static duct_conn_t *conn_new(duct_xport_t xport)
{
    auto conn = duct_conn_acquire();
    assert(conn);
    conn->xport_type = xport;
    return conn;
}

static void fixture_init(fixture_t *f)
{
    *f = (fixture_t){};
    f->proto = duct_proto_create_tcp("tx-hold-multi-leg", on_frame);
    assert(f->proto);
    f->x = conn_new(x_tcp);
    f->x->rx_buf = duct_olb_rx_new(kbytes(4u));
    assert(f->x->rx_buf);
    f->a = conn_new(x_udp);
    f->c = conn_new(x_udp);
    f->y = conn_new(x_tcp);
    f->xh = duct_conn_handle_get(f->x);

    duct_response_t out = {};
    f->s = duct_session_open(f->proto, duct_conn_id_primary, f->xh, nullptr, 0u, &out);
    assert(f->s);
    duct_result_t arc = duct_session_attach_conn(f->s, leg_a, duct_conn_handle_get(f->a));
    assert(arc == rc_ok);
    arc = duct_session_attach_conn(f->s, leg_c, duct_conn_handle_get(f->c));
    assert(arc == rc_ok);
    duct_discard arc;

    duct_timers_init(&f->w.timers);
    s_this_worker = &f->w;
}

static void fixture_fini(fixture_t *f)
{
    s_retry_clear(&f->w);
    duct_timers_destroy(&f->w.timers);
    s_this_worker = nullptr;
    duct_discard duct_session_detach_leg(f->s, leg_c, close_normal);
    duct_discard duct_session_detach_leg(f->s, leg_a, close_normal);
    duct_discard duct_session_detach_leg(f->s, duct_conn_id_primary, close_normal);
    duct_conn_t *conns[] = { f->x, f->a, f->c, f->y };
    for (unsigned i = 0u; i < sizeof conns / sizeof conns[0]; ++i) {
        duct_conn_teardown(conns[i]);
        duct_conn_release(conns[i]);
    }
    duct_proto_destroy(f->proto);
}

static uint32_t ticket_take(duct_conn_t *leg)
{
    uint32_t ticket = duct_tx_ticket_fresh;
    bool serving = s_tx_ticket_take(s_tx_seq_of(leg), &ticket);
    assert(serving);
    duct_discard serving;
    return ticket;
}

/** @brief Park one answer on @p leg the way a dispatch of @p owner does: its
 *  hold slot and the conn named for the length of the save. */
static retry_node_t *park_frame(fixture_t *f, duct_conn_t *leg, duct_conn_id_t leg_id,
                                  duct_tx_hold_t *hold, const duct_conn_t *owner)
{
    duct_response_t out;
    duct_response_reset(&out);
    out.conn_id = leg_id;
    f->w.hold_into = hold;
    f->w.hold_conn = owner;
    bool saved = s_retry_frame_save(&f->w, f->s, duct_conn_id_primary, duct_stream_id_default,
                                    fl_frame_none, &out, ticket_take(leg));
    f->w.hold_into = nullptr;
    f->w.hold_conn = nullptr;
    assert(saved);
    duct_discard saved;
    return f->w.retry_tail;
}

static retry_node_t *park_fin(fixture_t *f, duct_conn_t *leg, duct_tx_hold_t *hold,
                                const duct_conn_t *owner)
{
    f->w.hold_into = hold;
    f->w.hold_conn = owner;
    bool saved = s_retry_fin_save(&f->w, leg, duct_stream_id_default, fl_frame_fin,
                                  stream_err_none, ticket_take(leg));
    f->w.hold_into = nullptr;
    f->w.hold_conn = nullptr;
    assert(saved);
    duct_discard saved;
    return f->w.retry_tail;
}

/** @brief Park an emit node of the stream @p hctx, answering on @p leg, with the
 *  hold write s_retry_emit_save makes. */
static retry_node_t *park_emit(fixture_t *f, duct_stream_ctx_t *hctx, duct_conn_t *leg,
                                 duct_conn_id_t leg_id, duct_tx_hold_t *hold)
{
    auto node = duct_new(retry_node_t);
    assert(node);
    uint32_t ticket = ticket_take(leg);
    *node = (retry_node_t){
        .kind = retry_emit,
        .emit = { .hctx = hctx, .out = { .conn_id = leg_id }, .ticket = ticket },
    };
    s_retry_enqueue(&f->w, node);
    *hold = (duct_tx_hold_t){ duct_conn_handle_get(leg).word, ticket };
    return node;
}

static void unlink_node(fixture_t *f, retry_node_t *node)
{
    retry_node_t *prev = nullptr;
    for (auto n = f->w.retry_head; n; prev = n, n = n->next) {
        if (n != node)
            continue;
        if (prev)
            prev->next = n->next;
        else
            f->w.retry_head = n->next;
        if (f->w.retry_tail == n)
            f->w.retry_tail = prev;
        duct_del(n);
        return;
    }
    assert(false);
}

/** @brief The drain's part for one node: serve @p leg's ticket, unlink and free. */
static void serve(fixture_t *f, duct_conn_t *leg, retry_node_t *node)
{
    s_tx_ticket_resolve(s_tx_seq_of(leg));
    unlink_node(f, node);
}

static const char *expect_held(fixture_t *f, duct_tx_hold_t *hold, duct_conn_t *on,
                               const char *what)
{
    if (!s_tx_held(f->s, hold, f->x))
        return what;
    if (on && hold->leg != duct_conn_handle_get(on).word)
        return "the hold stands on a leg whose answer is not the one still parked";
    return nullptr;
}

static const char *expect_released(fixture_t *f, duct_tx_hold_t *hold)
{
    return s_tx_held(f->s, hold, f->x) || hold->leg != handle_null
         ? "hold stands with every answer served" : nullptr;
}

/** @brief Two answers of one dispatch on two legs, served in either order. */
static const char *frames_across_legs(fixture_t *f, bool c_first)
{
    auto hold = &f->x->rx_buf->tx_hold;
    auto pa = park_frame(f, f->a, leg_a, hold, f->x);
    auto pc = park_frame(f, f->c, leg_c, hold, f->x);
    auto error = expect_held(f, hold, nullptr, "hold cleared with both answers parked");
    if (error)
        return error;

    duct_conn_t *first = c_first ? f->c : f->a,
                *second = c_first ? f->a : f->c;
    serve(f, first, c_first ? pc : pa);
    error = expect_held(f, hold, second, "hold cleared with the other leg's answer still parked");
    if (error)
        return error;

    serve(f, second, c_first ? pa : pc);
    return expect_released(f, hold);
}

/** @brief A fin and a frame answer of one dispatch, the frame served first. */
static const char *frame_then_fin(fixture_t *f)
{
    auto hold = &f->x->rx_buf->tx_hold;
    auto pfin = park_fin(f, f->a, hold, f->x);
    auto pframe = park_frame(f, f->c, leg_c, hold, f->x);
    serve(f, f->c, pframe);
    auto error = expect_held(f, hold, f->a, "hold cleared with the fin still parked");
    if (error)
        return error;
    serve(f, f->a, pfin);
    return expect_released(f, hold);
}

/** @brief An emit node and a frame answer of one conn, the frame served first. */
static const char *frame_then_emit(fixture_t *f)
{
    auto hold = &f->x->rx_buf->tx_hold;
    duct_stream_ctx_t hctx = { .s = f->s, .conn_id = duct_conn_id_primary };
    auto pemit = park_emit(f, &hctx, f->a, leg_a, hold);
    auto pframe = park_frame(f, f->c, leg_c, hold, f->x);
    serve(f, f->c, pframe);
    auto error = expect_held(f, hold, f->a, "hold cleared with the emit still parked");
    if (error)
        return error;
    serve(f, f->a, pemit);
    return expect_released(f, hold);
}

/** @brief An answer parked by another conn's dispatch is not this conn's to wait on. */
static const char *other_owner(fixture_t *f)
{
    auto hold = &f->x->rx_buf->tx_hold;
    duct_tx_hold_t other = {};
    auto theirs = park_frame(f, f->a, leg_a, &other, f->y);
    auto mine = park_frame(f, f->c, leg_c, hold, f->x);
    serve(f, f->c, mine);
    auto error = expect_released(f, hold);
    serve(f, f->a, theirs);
    return error;
}

/** @brief A node whose ticket is already served, still on the list, is not waited on. */
static const char *served_node_skipped(fixture_t *f)
{
    auto hold = &f->x->rx_buf->tx_hold;
    auto stale = park_frame(f, f->a, leg_a, hold, f->x);
    auto live = park_frame(f, f->c, leg_c, hold, f->x);
    s_tx_ticket_resolve(s_tx_seq_of(f->a));
    serve(f, f->c, live);
    auto error = expect_released(f, hold);
    unlink_node(f, stale);
    return error;
}

static constexpr unsigned case_count = 6u;

static const char *case_names[case_count] = {
    "later leg serves first", "earlier leg serves first", "frame and fin",
    "frame and emit", "other conn's answer", "served node on the list",
};

static const char *run_case(fixture_t *f, unsigned which)
{
    switch (which) {
    case 0u: return frames_across_legs(f, true);
    case 1u: return frames_across_legs(f, false);
    case 2u: return frame_then_fin(f);
    case 3u: return frame_then_emit(f);
    case 4u: return other_owner(f);
    case 5u: return served_node_skipped(f);
    }
    return "no such case";
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    for (unsigned i = 0u; i < case_count; ++i) {
        fixture_t f;
        fixture_init(&f);
        const char *error = run_case(&f, i);
        if (!error && f.w.retry_head)
            error = "a node is still parked at the end of the case";
        fixture_fini(&f);
        if (error) {
            fprintf(stderr, "tx_hold_multi_leg: %s: %s\n", case_names[i], error);
            return 1;
        }
    }
    printf("tx_hold_multi_leg: OK (%u cases: the hold follows the parked answers of its conn "
           "across legs; another conn's answer and a served node are not waited on)\n",
           case_count);
    return 0;
}
