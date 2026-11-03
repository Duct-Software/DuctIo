/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/**
 * @file noise_register_service.c
 * @brief UDP service secured by the Noise_IKpsk2 handshake
 * carrying a small in-memory named-register
 * store as its payload: PING/GET/SET/INCR against int64 counters.
 *
 * main() starts the engine and binds the listener; duct_engine_launch
 * already runs the I/O and worker threads once it returns. A second
 * thread plays an external client: it holds the server's static public
 * key and the shared PSK out of band (WireGuard's own trust model), opens
 * a connected UDP socket, drives the handshake, then issues commands over
 * the resulting encrypted channel.
 *
 * Noise is DuctIO's internal crypto core; this example links against it
 * through src/include the same way the engine's own test suite does.
 */

#include "duct.h"
#include "duct_noise_internal.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

/* One-byte message-type prefix, nothing else — per-peer conn demux makes
 * a receiver_index unnecessary here. */
static constexpr uint8_t msg_type_handshake = 1u;
static constexpr uint8_t msg_type_command   = 2u;

static constexpr unsigned register_slots_max = 8u;
static constexpr size_t   register_name_max  = 15u;

typedef struct {
    char    name[register_name_max + 1u];
    int64_t value;
} register_entry_t;

/** @brief One session's own set of named int64 registers. */
typedef struct {
    register_entry_t entries[register_slots_max];
    unsigned         count;
} register_store_t;

static register_entry_t *
s_register_find(register_store_t *store, const char *name)
{
    for (unsigned i = 0u; i < store->count; ++i)
        if (strcmp(store->entries[i].name, name) == 0)
            return &store->entries[i];
    return nullptr;
}

static register_entry_t *
s_register_touch(register_store_t *store, const char *name)
{
    auto e = s_register_find(store, name);
    if (e || store->count >= register_slots_max)
        return e;
    e = &store->entries[store->count++];
    strncpy(e->name, name, register_name_max);
    e->name[register_name_max] = '\0';
    e->value = 0;
    return e;
}

/** @brief Execute one plaintext command line against @p store; write the
 *  reply into @p reply (bounded by @p reply_cap), return its length. */
static size_t
s_register_execute(register_store_t *store, const char *cmd, size_t cmd_len,
                   char *reply, size_t reply_cap)
{
    char line[128];
    size_t n = cmd_len < sizeof(line) - 1u ? cmd_len : sizeof(line) - 1u;
    memcpy(line, cmd, n);
    line[n] = '\0';

    char verb[16] = {},
         name[register_name_max + 1u] = {};
    long long arg = 0;
    int fields = sscanf(line, "%15s %15s %lld", verb, name, &arg);

    if (fields >= 1 && strcmp(verb, "PING") == 0)
        return (size_t)snprintf(reply, reply_cap, "PONG");

    if (fields >= 2 && strcmp(verb, "GET") == 0) {
        auto e = s_register_find(store, name);
        return (size_t)snprintf(reply, reply_cap, "%lld", e ? (long long)e->value : 0LL);
    }

    if (fields >= 3 && strcmp(verb, "SET") == 0) {
        auto e = s_register_touch(store, name);
        if (!e)
            return (size_t)snprintf(reply, reply_cap, "ERR store full");
        e->value = (int64_t)arg;
        return (size_t)snprintf(reply, reply_cap, "OK");
    }

    if (fields >= 2 && strcmp(verb, "INCR") == 0) {
        auto e = s_register_touch(store, name);
        if (!e)
            return (size_t)snprintf(reply, reply_cap, "ERR store full");
        e->value += fields >= 3 ? (int64_t)arg : 1;
        return (size_t)snprintf(reply, reply_cap, "%lld", (long long)e->value);
    }

    return (size_t)snprintf(reply, reply_cap, "ERR unknown command");
}

/** @brief Server static keypair and shared PSK, passed to every session's
 *  create_state. */
typedef struct {
    duct_noise_keypair_t server_kp;
    uint8_t              psk[32];
} server_ctx_t;

/** @brief Per-session state: in-flight or completed Noise handshake, plus
 *  that peer's register store once established. */
typedef struct {
    bool             established;
    register_store_t store;
    union {
        duct_noise_hs_t        *hs;        /**< Valid while !established. */
        duct_noise_transport_t  transport; /**< Valid once established. */
    };
} session_state_t;

static duct_result_t
s_create_state([[maybe_unused]] duct_session_t *s, void *ctx, void **out)
{
    auto sctx = (const server_ctx_t *)ctx;
    auto st = duct_new(session_state_t);
    duct_do_if(!st, return rc_no_memory);

    st->hs = duct_noise_hs_create(&sctx->server_kp, nullptr, sctx->psk, false);
    if (!st->hs) {
        duct_del(st);
        return rc_no_memory;
    }
    *out = st;
    return rc_ok;
}

static void
s_destroy_state([[maybe_unused]] duct_session_t *s, [[maybe_unused]] void *ctx, void *state)
{
    auto st = (session_state_t *)state;
    if (st->established)
        duct_noise_transport_destroy(&st->transport);
    else
        duct_noise_hs_destroy(st->hs);
    duct_del(st);
}

/** @brief Hand the first @p len bytes of the @c duct_new block @p buf to the
 *  framework as the response. @c fl_send_owned: staging reads @p buf after
 *  the callback returns, so the framework frees it with @c duct_del once it
 *  is staged. */
static void
s_respond_owned(duct_response_t *out, void *buf, size_t len)
{
    *out = (duct_response_t){
        .payload = { buf, len },
        .flags = fl_send_owned,
        .conn_id = duct_conn_id_same,
        .stream_id = duct_stream_id_same,
        .control.stream_op_conn_id = duct_conn_id_same,
    };
}

/** @brief Responder side of the handshake: message 1 in, message 2 out. */
static duct_result_t
s_handle_handshake(session_state_t *st, const duct_frame_t *frame, duct_response_t *out)
{
    duct_view_u8 msg1 = { frame->payload.data + 1u, frame->payload.size - 1u };

    uint8_t remote_static[32],
            payload[64];
    size_t payload_len = 0u;
    bool read = duct_noise_hs_read_msg1(st->hs, msg1, remote_static, payload, sizeof payload, &payload_len);
    duct_do_if(!read, return rc_drop);

    auto resp = duct_at(duct_new(uint8_t, 1u + duct_noise_msg2_size));
    duct_do_if(!resp, return rc_drop);
    resp[0] = msg_type_handshake;
    size_t msg2_len = 0u;
    if (!duct_noise_hs_write_msg2(st->hs, (duct_view_u8){}, resp + 1u, duct_noise_msg2_size, &msg2_len)) {
        duct_del(resp);
        return rc_drop;
    }

    duct_noise_transport_t transport = {};
    bool split_ok = duct_noise_hs_split(st->hs, &transport);
    duct_noise_hs_destroy(st->hs);
    if (!split_ok) {
        duct_del(resp);
        return rc_drop;
    }

    st->transport = transport;
    st->established = true;
    s_respond_owned(out, resp, 1u + msg2_len);
    return rc_ok;
}

/** @brief Established peer: unseal one command, execute it against the
 *  session's register store, seal the reply back. */
static duct_result_t
s_handle_command(session_state_t *st, const duct_frame_t *frame, duct_response_t *out)
{
    duct_view_u8 sealed_in = { frame->payload.data + 1u, frame->payload.size - 1u };

    char cmd[128];
    size_t cmd_len = 0u;
    bool opened = duct_noise_transport_unseal(&st->transport, sealed_in,
                                              (uint8_t *)cmd, sizeof cmd, &cmd_len);
    duct_do_if(!opened, return rc_drop);

    char reply[128];
    size_t reply_len = s_register_execute(&st->store, cmd, cmd_len, reply, sizeof reply);

    size_t sealed_cap = duct_noise_transport_seal_size(reply_len);
    auto sealed = duct_at(duct_new(uint8_t, 1u + sealed_cap));
    duct_do_if(!sealed, return rc_drop);
    sealed[0] = msg_type_command;
    duct_view_u8 plain = duct_view_bytes((duct_view_cc){ reply, reply_len });
    size_t sealed_len = duct_noise_transport_seal(&st->transport, &plain, 1u,
                                                  sealed + 1u, sealed_cap);
    if (!sealed_len) {
        duct_del(sealed);
        return rc_drop;
    }

    s_respond_owned(out, sealed, 1u + sealed_len);
    return rc_ok;
}

static duct_result_t
s_on_dgram([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
          const duct_frame_t *frame, duct_response_t *out, void *proto_state)
{
    auto st = (session_state_t *)proto_state;
    duct_do_if(frame->payload.size < 1u, return rc_drop);
    auto type = ((const uint8_t *)frame->payload.data)[0];

    if (type == msg_type_handshake)
        return st->established ? rc_drop : s_handle_handshake(st, frame, out);
    if (type == msg_type_command)
        return st->established ? s_handle_command(st, frame, out) : rc_drop;
    return rc_drop;
}

/** @brief Arguments for s_client_thread; owned by main() for the
 *  pthread_join's duration. */
typedef struct {
    uint16_t                    port;
    const duct_noise_keypair_t *client_kp;
    const uint8_t              *server_pub;
    const uint8_t              *psk;
} client_args_t;

/** @brief Shared failure path for the handshake below: log, destroy
 *  @p hs — never reused after a failed step. */
static bool
s_client_fail(duct_noise_hs_t *hs, const char *why)
{
    duct_noise_hs_destroy(hs);
    fprintf(stderr, "client: %s\n", why);
    return false;
}

static bool
s_client_handshake(duct_sock_t fd, duct_noise_hs_t *hs, duct_noise_transport_t *out_transport)
{
    uint8_t msg1[256];
    msg1[0] = msg_type_handshake;
    size_t msg1_len = 0u;
    if (!duct_noise_hs_write_msg1(hs, (duct_view_u8){}, msg1 + 1u, sizeof(msg1) - 1u, &msg1_len))
        return s_client_fail(hs, "write_msg1 failed");
    if (send(fd, (const char *)msg1, (int)(1u + msg1_len), 0) != (int)(1u + msg1_len))
        return s_client_fail(hs, "send msg1 failed");

    uint8_t rbuf[256];
    ssize_t got = recv(fd, (char *)rbuf, sizeof rbuf, 0);
    if (got < 1 || rbuf[0] != msg_type_handshake)
        return s_client_fail(hs, "recv msg2 failed");
    if (!duct_noise_hs_read_msg2(hs, (duct_view_u8){ rbuf + 1u, (size_t)got - 1u }))
        return s_client_fail(hs, "read_msg2 failed (mutual auth)");

    bool ok = duct_noise_hs_split(hs, out_transport);
    duct_noise_hs_destroy(hs);
    if (!ok)
        fprintf(stderr, "client: split failed\n");
    return ok;
}

static bool
s_client_command(duct_sock_t fd, duct_noise_transport_t *t, const char *cmd)
{
    size_t cmd_len = strlen(cmd);
    uint8_t sealed[1u + 128u];
    sealed[0] = msg_type_command;
    duct_view_u8 plain = duct_view_bytes((duct_view_cc){ cmd, cmd_len });
    size_t sealed_len = duct_noise_transport_seal(t, &plain, 1u,
                                                  sealed + 1u, sizeof(sealed) - 1u);
    if (!sealed_len) {
        fprintf(stderr, "client: seal failed for '%s'\n", cmd);
        return false;
    }
    if (send(fd, (const char *)sealed, (int)(1u + sealed_len), 0) != (int)(1u + sealed_len)) {
        fprintf(stderr, "client: send failed for '%s'\n", cmd);
        return false;
    }

    uint8_t rbuf[256];
    ssize_t got = recv(fd, (char *)rbuf, sizeof rbuf, 0);
    if (got < 1 || rbuf[0] != msg_type_command) {
        fprintf(stderr, "client: recv failed for '%s'\n", cmd);
        return false;
    }

    char reply[128];
    size_t reply_len = 0u;
    if (!duct_noise_transport_unseal(t, (duct_view_u8){ rbuf + 1u, (size_t)got - 1u },
                                     (uint8_t *)reply, sizeof reply, &reply_len)) {
        fprintf(stderr, "client: unseal failed for '%s'\n", cmd);
        return false;
    }

    printf("client: %-20s -> %.*s\n", cmd, (int)reply_len, reply);
    return true;
}

static void *
s_client_thread(void *arg)
{
    auto a = (const client_args_t *)arg;
    auto fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == duct_sock_bad) {
        fprintf(stderr, "client: socket failed\n");
        return nullptr;
    }
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(a->port) };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        fprintf(stderr, "client: connect failed\n");
        duct_sock_close(fd);
        return nullptr;
    }
    printf("client: connected to 127.0.0.1:%u, starting Noise handshake\n", a->port);

    auto hs = duct_noise_hs_create(a->client_kp, a->server_pub, a->psk, true);
    if (!hs) {
        fprintf(stderr, "client: handshake state create failed\n");
        duct_sock_close(fd);
        return nullptr;
    }

    duct_noise_transport_t transport = {};
    if (!s_client_handshake(fd, hs, &transport)) {
        duct_sock_close(fd);
        return nullptr;
    }
    printf("client: handshake established, session secured\n");

    s_client_command(fd, &transport, "PING");
    s_client_command(fd, &transport, "SET balance 100");
    s_client_command(fd, &transport, "GET balance");
    s_client_command(fd, &transport, "INCR balance 25");
    s_client_command(fd, &transport, "INCR balance");
    s_client_command(fd, &transport, "GET missing-key");
    s_client_command(fd, &transport, "STATUS");

    duct_noise_transport_destroy(&transport);
    duct_sock_close(fd);
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    duct_engine_t *io    = nullptr;
    duct_wire_t   *wire  = nullptr;
    duct_proto_t  *proto = nullptr;
    pthread_t      client_th;
    const char    *err = nullptr;
    uint16_t       port = 0u;

    duct_noise_keypair_t server_kp = {},
                         client_kp = {};
    uint8_t       psk[32]      = {};
    server_ctx_t  server_ctx  = {};
    client_args_t client_args = {};

    if (!duct_noise_keypair_generate(&server_kp) || !duct_noise_keypair_generate(&client_kp)) {
        err = "keypair generation failed";
        goto cleanup;
    }
    RAND_bytes(psk, sizeof psk);
    /* One process stands in for both sides of key provisioning here: a
     * real client reads server_kp.pub from its own config, a real server
     * an allowlist of client keys (WireGuard's own peer-config model). */

    io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) { err = "engine launch failed"; goto cleanup; }

    wire = duct_wire_create_dgram_batch(0u, false);
    if (!wire) { err = "wire create failed"; goto cleanup; }

    server_ctx.server_kp = server_kp;
    memcpy(server_ctx.psk, psk, sizeof psk);
    proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "noise-register", .wire = wire,
        .on_frame = s_on_dgram,
        .create_state_ctx = &server_ctx,
        .create_state = s_create_state,
        .destroy_state = s_destroy_state,
        .max_response = 512u,
    });
    if (proto)
        proto->owned_wire = wire;
    else
        duct_wire_destroy(wire);
    if (!proto) { err = "proto create failed"; goto cleanup; }

    if (duct_listener_bind(io, &(duct_listener_cfg_t){
            .kind = listener_dgram, .addr = "127.0.0.1",
            .n_protos = 1, .protos = (const duct_proto_t *[]){ proto },
        }, &port, nullptr, 0u, nullptr) != rc_ok) {
        err = "listener bind failed";
        goto cleanup;
    }
    printf("server: listening on 127.0.0.1:%u (Noise-secured register service)\n", port);

    client_args = (client_args_t){ .port = port, .client_kp = &client_kp,
                                   .server_pub = server_kp.pub, .psk = psk };
    if (pthread_create(&client_th, nullptr, s_client_thread, &client_args) != 0) {
        err = "client thread create failed";
        goto cleanup;
    }
    pthread_join(client_th, nullptr);

cleanup:
    if (io) {
        duct_engine_stop(io);
        duct_engine_destroy(io);
    }
    duct_proto_destroy(proto);
    OPENSSL_cleanse(&server_ctx, sizeof server_ctx);
    OPENSSL_cleanse(psk, sizeof psk);
    OPENSSL_cleanse(&client_kp, sizeof client_kp);
    OPENSSL_cleanse(&server_kp, sizeof server_kp);

    if (err) {
        fprintf(stderr, "noise_register: %s\n", err);
        return 1;
    }
    printf("noise_register: done\n");
    return 0;
}
