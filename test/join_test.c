/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file join_test.c
 * @brief Step 1b.1 acceptance: sync pre-parse + leg join end-to-end.
 *
 * Control listener (preparse == NULL, always new) accepts a client; its
 * @c on_session_open records the session token. A second client connects to
 * the data listener, whose sync @c preparse resolves the peer to the control
 * session token and returns @c resolve_join with @c conn_id=1. The framework
 * attaches the data leg to the control session and fires @c on_conn_join on
 * the control session's worker. Asserts: exactly one @c on_session_open, one
 * @c on_conn_join with @c conn_id=1.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>

static uint16_t ctrl_port = 0;    /* OS-assigned via duct_io_listen */
static uint16_t data_port = 0;
static constexpr unsigned connect_retry_ms = 1000u;
static constexpr int echo_timeout_ms = 2000;

static uint32_t s_tok_gen(duct_handle_t w)
{
    return (uint32_t)(w >> 32u);
}

static atomic_int s_open_count = 0;
static atomic_int s_join_count = 0;
static atomic_uint s_join_conn_id = 0u;
static _Atomic(duct_handle_t) g_ctrl_tok;

static duct_result_t
on_ctrl_open([[maybe_unused]] duct_session_t *s,
             duct_handle_t tok,
             [[maybe_unused]] void *user_ctx,
             [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_ctrl_tok, tok, release);
    duct_atomic_fetch(add, &s_open_count, 1, relaxed);
    return rc_ok;
}

static duct_result_t
on_ctrl_frame([[maybe_unused]] duct_session_t *s,
              [[maybe_unused]] duct_conn_id_t conn_id,
              const duct_frame_t *frame,
              duct_response_t *out,
              [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

static duct_resolve_disposition_t
data_preparse([[maybe_unused]] void *ctx,
              [[maybe_unused]] const duct_peer_t *peer,
              [[maybe_unused]] duct_view_u8 peek,
              duct_handle_t *out_tok,
              duct_conn_id_t *out_conn_id,
              [[maybe_unused]] void **out_user_ctx,
              [[maybe_unused]] size_t *out_lead)
{
    auto tok = duct_atomic_load(&g_ctrl_tok, acquire);
    if (s_tok_gen(tok) != 0u) {
        *out_tok = tok;
        *out_conn_id = 1u;
        return resolve_join;
    }
    return resolve_reject;
}

static duct_result_t
on_data_join([[maybe_unused]] duct_session_t *s,
             duct_conn_id_t conn_id,
             [[maybe_unused]] const duct_peer_t *peer,
             [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&s_join_conn_id, (unsigned)conn_id, release);
    duct_atomic_fetch(add, &s_join_count, 1, relaxed);
    return rc_ok;
}

static void *s_run_thread(void *arg)
{
    (void)duct_engine_wait((duct_engine_t *)arg);
    return nullptr;
}

static duct_sock_t s_client_connect(uint16_t port)
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

static bool s_wait_atomic_int(atomic_int *p, int target, unsigned timeout_ms)
{
    for (unsigned waited = 0u; waited < timeout_ms; waited += 10u) {
        if (duct_atomic_load(p, acquire) == target)
            return true;
        th_sleep_ms(10u);
    }
    return duct_atomic_load(p, acquire) == target;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    int pass = 1;
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) {
        fprintf(stderr, "join: duct_engine_launch failed\n");
        return 1;
    }

    auto ctrl = duct_proto_create(&(duct_proto_cfg_t){
        .name = "ctrl",
        .on_frame = on_ctrl_frame,
        .on_session_open = on_ctrl_open,
        .on_conn_join = on_data_join,
        .max_response = 4096u,
    });
    auto data = duct_proto_create(&(duct_proto_cfg_t){
        .name = "data",
        .on_frame = on_ctrl_frame,
        .preparse = data_preparse,
        .preparse_mode = resolve_sync,
        .max_response = 4096u,
    });
    if (!ctrl || !data) {
        fprintf(stderr, "join: duct_proto_create failed\n");
        pass = 0;
        goto cleanup;
    }

    if (duct_io_listen(io, "127.0.0.1", &ctrl_port, ctrl) != rc_ok
        || duct_io_listen(io, "127.0.0.1", &data_port, data) != rc_ok) {
        fprintf(stderr, "join: duct_io_listen failed\n");
        pass = 0;
        goto cleanup;
    }

    pthread_t th;
    if (pthread_create(&th, nullptr, s_run_thread, io) != 0) {
        fprintf(stderr, "join: pthread_create failed\n");
        pass = 0;
        goto cleanup;
    }

    /* Control leg: connect, echo a frame so on_session_open has run + stored tok. */
    duct_sock_t cfd = s_client_connect(ctrl_port);
    if (cfd == duct_sock_bad) {
        fprintf(stderr, "join: ctrl connect failed\n");
        pass = 0;
        goto stop;
    }
    static const char msg[] = "join-ctrl";
    if (write(cfd, msg, sizeof msg - 1u) != (ssize_t)(sizeof msg - 1u)) {
        fprintf(stderr, "join: ctrl write failed\n");
        pass = 0;
        close(cfd);
        goto stop;
    }
    char buf[64] = {};
    size_t got = 0u;
    while (got < sizeof msg - 1u) {
        struct pollfd pfd = { .fd = cfd, .events = POLLIN };
        if (poll(&pfd, 1, echo_timeout_ms) <= 0)
            break;
        ssize_t n = read(cfd, buf + got, sizeof buf - got - 1u);
        if (n <= 0)
            break;
        got += (size_t)n;
    }
    if (got != sizeof msg - 1u || memcmp(buf, msg, got) != 0) {
        fprintf(stderr, "join: ctrl echo mismatch\n");
        pass = 0;
        close(cfd);
        goto stop;
    }

    /* Data leg: preparse resolves join → on_conn_join fires on the ctrl worker. */
    duct_sock_t dfd = s_client_connect(data_port);
    if (dfd == duct_sock_bad) {
        fprintf(stderr, "join: data connect failed\n");
        pass = 0;
        close(cfd);
        goto stop;
    }
    if (!s_wait_atomic_int(&s_join_count, 1, connect_retry_ms)) {
        fprintf(stderr, "join: on_conn_join did not fire\n");
        pass = 0;
    }
    close(dfd);
    close(cfd);

stop:
    duct_engine_stop(io);
    pthread_join(th, nullptr);

cleanup:
    duct_engine_destroy(io);
    duct_proto_destroy(ctrl);
    duct_proto_destroy(data);

    int opens = duct_atomic_load(&s_open_count, acquire);
    int joins = duct_atomic_load(&s_join_count, acquire);
    unsigned jcid = duct_atomic_load(&s_join_conn_id, acquire);
    if (opens != 1) {
        fprintf(stderr, "join: on_session_open fired %d times (expected 1)\n", opens);
        pass = 0;
    }
    if (joins != 1) {
        fprintf(stderr, "join: on_conn_join fired %d times (expected 1)\n", joins);
        pass = 0;
    } else if (jcid != 1u) {
        fprintf(stderr, "join: on_conn_join conn_id=%u (expected 1)\n", jcid);
        pass = 0;
    }

    if (pass) {
        printf("join: OK (sync preparse + leg join, on_conn_join fired once at conn_id=1)\n");
        return 0;
    }
    return 1;
}
