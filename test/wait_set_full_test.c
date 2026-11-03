/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file wait_set_full_test.c
 *  @brief A wsaevent listener whose wait set is full takes the clients queued behind it as slots free.
 *
 *  Clients are dialed one at a time until a session no longer opens for the last of
 *  them: the set is full and that client waits in the kernel's queue. One more client
 *  joins it. Each served client closed then frees a slot, and the next queued client
 *  must open a session with no later arrival to wake the listener. wsaevent alone has a
 *  bounded wait set; the test is built for that model.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>
#include <stdio.h>

/** @brief Return @p msg from the calling check when @p cond fails. */
#define expect(cond, msg) do { if (!(cond)) return msg; } while (0)

/** @brief Most clients dialed; past the 64 handles of a wait set. */
static constexpr unsigned dial_max = 70u;

static atomic_int s_opened,
                  s_closed;

static duct_result_t on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t id,
                              [[maybe_unused]] const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
                              [[maybe_unused]] void *ps)
{
    return rc_ok;
}

static duct_result_t on_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                             [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
                             [[maybe_unused]] void *ps)
{
    atomic_fetch_add(&s_opened, 1);
    return rc_ok;
}

static void on_close([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_close_reason_t reason,
                     [[maybe_unused]] void *ps)
{
    atomic_fetch_add(&s_closed, 1);
}

static duct_sock_t s_clients[dial_max];
static unsigned    s_dialed;

/** @brief Dial clients until one opens no session within a second, and still none half a second
 *  later, then one more behind it. A session that opens late only continues the dialing.
 *  @return the sessions open with the set full, 0 when every dial opened one.
 */
static int s_fill(uint16_t port)
{
    while (s_dialed < dial_max) {
        int before = atomic_load(&s_opened);
        s_clients[s_dialed] = th_connect(port);
        if (s_clients[s_dialed] == duct_sock_bad)
            return 0;
        ++s_dialed;
        if (th_wait_int(&s_opened, before + 1, 1000u))
            continue;
        th_sleep_ms(500u);
        if (atomic_load(&s_opened) != before)
            continue;
        s_clients[s_dialed] = th_connect(port);
        s_dialed += s_clients[s_dialed] != duct_sock_bad;
        return before;
    }
    return 0;
}

static const char *sc_drain(uint16_t port)
{
    int full = s_fill(port);
    expect(full > 0, "every dial opened a session: the wait set never filled");
    printf("wait_set_full: the set holds %d sessions, %u clients dialed\n", full, s_dialed);
    for (int freed = 1; freed <= 2; ++freed) {
        closesocket(s_clients[freed - 1]);
        s_clients[freed - 1] = duct_sock_bad;
        expect(th_wait_int(&s_closed, freed, 3000u), "a served client closed and its session did not");
        expect(th_wait_int(&s_opened, full + freed, 2000u),
               "a slot freed and the client queued behind the full set opened no session");
    }
    th_sleep_ms(200u);
    expect(atomic_load(&s_opened) == full + 2, "more sessions opened than slots freed");
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto engine = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1u, .workers = 1u });
    auto proto = duct_proto_create(&(duct_proto_cfg_t){ .name = "wait-set-full", .on_frame = on_frame,
                                                        .on_session_open = on_open,
                                                        .on_session_close = on_close, .max_response = 16u });
    if (!engine || !proto) {
        fprintf(stderr, "wait_set_full: engine or protocol create failed\n");
        return 1;
    }
    uint16_t port = 0u;
    duct_result_t rc = rc_invalid_order;
    for (unsigned waited = 0u; waited < 2000u && rc == rc_invalid_order; waited += 5u) {
        rc = duct_io_listen(engine, "127.0.0.1", &port, proto);
        if (rc == rc_invalid_order)
            th_sleep_ms(5u);
    }
    const char *err = rc == rc_ok ? sc_drain(port) : "listen failed";
    for (unsigned i = 0u; i < s_dialed; ++i)
        if (s_clients[i] != duct_sock_bad)
            closesocket(s_clients[i]);
    duct_engine_destroy(engine);
    duct_proto_destroy(proto);
    if (err) {
        fprintf(stderr, "wait_set_full: drain: %s\n", err);
        return 1;
    }
    printf("wait_set_full: OK\n");
    return 0;
}
