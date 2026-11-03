/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file dgram_lead_test.c
 *  @brief The lead of a sealed datagram, from the codec that writes it to the
 *  listener that resolves it.
 *
 *  `cfg` holds the config a lead needs: a stream wire, an engine without derive
 *  and a prefix narrower than the lead are refused, a prefix of the lead's width
 *  or more is admitted, and only a responder's wire built with the lead raises
 *  @c fl_wire_join_lead and carries its @c rx_prefix_len and its cover key.
 *  `codec` runs two real Noise wires through the handshake by hand: a datagram
 *  the initiator seals afterwards leads with the session's name, covered, and a
 *  MAC over the first PDU bytes behind its prefix, which the responder's engine
 *  derives alike; two datagrams lead with different bytes and both unseal.
 *
 *  `roam` is the whole path over sockets. A duct client dials a shared datagram
 *  listener through a relay, so what the server sees is the relay's address; mid-
 *  session the relay moves the client's datagrams to a second socket. The
 *  listener holds no conn at that address, resolves the lead the codec wrote to
 *  the session, and the echo keeps coming back, now through the new address, with
 *  no second session opened. The relay also keeps the first 10 bytes of every
 *  datagram the client sent: the first is the dial prefix the wire was built
 *  with, and the keyed ones after it each differ from every other, the name in
 *  them is not one value along the session.
 *
 *  `codec` and `roam` run twice, behind a prefix exactly as wide as the lead and
 *  behind one four bytes wider, so a PDU offset taken from anywhere but the
 *  prefix's own width fails one of the two.
 */

#include "duct.h"
#include "duct_dgram_lead.h"
#include "duct_join.h"
#include "duct_noise.h"
#include "duct_seal_engine.h"
#include "duct_wire.h"
#include "duct_wire_codec.h"
#include "duct_wire_tx.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "test_helpers.h"
#include "dgram_test_helpers.h"

static constexpr size_t  dl_lead  = duct_seal_lead_size;
static constexpr size_t  dl_cap   = 2048u;
static constexpr size_t  dl_log   = 512u;

/** @brief The key both ends of the deployment hold to cover the lead's name. */
static const uint8_t dl_cover[duct_wire_cover_key_size] = {
    0x5e, 0x13, 0xa9, 0x40, 0xd2, 0x77, 0x08, 0xcb, 0x36, 0xf1, 0x6a, 0x94, 0x2c, 0x85, 0xe0, 0x1d,
};

/** @brief Width of the prefix a client leads its datagrams with: the lead alone,
 *  or the lead and bytes behind it. */
static size_t g_width = dl_lead;

/** @brief Bytes a dial leads with before the handshake has keyed the wire, as
 *  many as the prefix is wide. */
static const uint8_t dl_dial[duct_seal_prefix_max] = {
    0xd1, 0xa1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
};

static duct_noise_keypair_t g_srv_kp, g_cli_kp;
static duct_noise_cfg_t     g_srv_cfg, g_cli_cfg;

/** @brief Build a sealed datagram wire of @p role over @p engine: the initiator's
 *  prefix leads its datagrams and takes nothing back, the responder's is the one
 *  it strips. */
static duct_wire_t *dl_wire(const duct_seal_engine_vtbl_t *engine, duct_noise_cfg_t *cfg,
                            duct_seal_role_t role, bool join_lead)
{
    bool init = role == seal_role_initiator;
    duct_sealed_wire_cfg_t wc = {
        .engine = engine, .engine_cfg = cfg, .role = role,
        .framing = seal_framing_datagram, .join_lead = join_lead,
        .tx_prefix_len = init ? (uint8_t)g_width : 0u,
        .rx_prefix_len = init ? 0u : (uint8_t)g_width,
    };
    memcpy(wc.cover_key, dl_cover, sizeof wc.cover_key);
    if (init)
        memcpy(wc.tx_prefix, dl_dial, sizeof dl_dial);
    return duct_wire_create_sealed(&wc);
}

static const char *dl_cfg(void)
{
    auto vt = duct_noise_vtbl_dgram();
    auto resp = dl_wire(vt, &g_srv_cfg, seal_role_responder, true);
    auto init = dl_wire(vt, &g_cli_cfg, seal_role_initiator, true);
    auto plain = dl_wire(vt, &g_srv_cfg, seal_role_responder, false);
    const char *err = nullptr;
    if (!resp || !init || !plain)
        err = "a datagram wire with a join lead was refused";
    else if (!duct_has(resp->flags, fl_wire_join_lead) || duct_has(init->flags, fl_wire_join_lead)
             || duct_has(plain->flags, fl_wire_join_lead))
        err = "only the responder's wire built with a join lead raises fl_wire_join_lead";
    else if (resp->rx_prefix_len != g_width || init->rx_prefix_len != 0u
             || memcmp(resp->cover_key, dl_cover, sizeof dl_cover) != 0)
        err = "a wire does not carry the width of the prefix it strips or its cover key";
    if (resp)
        duct_wire_destroy(resp);
    if (init)
        duct_wire_destroy(init);
    if (plain)
        duct_wire_destroy(plain);
    if (err)
        return err;

    auto stream = duct_wire_create_sealed(&(duct_sealed_wire_cfg_t){
        .engine = duct_noise_vtbl(), .engine_cfg = &g_cli_cfg, .role = seal_role_initiator,
        .framing = seal_framing_stream, .join_lead = true });
    if (stream) {
        duct_wire_destroy(stream);
        return "a join lead was admitted on a stream wire";
    }
    duct_seal_engine_vtbl_t bare = *vt;
    bare.derive = nullptr;
    if (dl_wire(&bare, &g_cli_cfg, seal_role_initiator, true))
        return "a join lead was admitted for an engine that cannot derive its key";
    for (size_t width = 0u; width <= duct_seal_prefix_max; ++width) {
        bool holds = width >= dl_lead;
        duct_sealed_wire_cfg_t wc = {
            .engine = vt, .engine_cfg = &g_cli_cfg, .role = seal_role_initiator,
            .framing = seal_framing_datagram, .join_lead = true,
            .tx_prefix_len = (uint8_t)width };
        auto built = duct_wire_create_sealed(&wc);
        bool admitted = built != nullptr;
        if (built)
            duct_wire_destroy(built);
        if (admitted != holds)
            return holds ? "a join lead was refused for an initiator whose prefix holds it"
                         : "a join lead was admitted behind a prefix narrower than it";
        wc.role = seal_role_responder;
        wc.tx_prefix_len = 0u;
        wc.rx_prefix_len = (uint8_t)width;
        built = duct_wire_create_sealed(&wc);
        admitted = built != nullptr;
        if (built)
            duct_wire_destroy(built);
        if (admitted != holds)
            return holds ? "a join lead was refused for a responder whose prefix holds it"
                         : "a join lead was admitted for a responder reading a prefix narrower than it";
    }
    return nullptr;
}

/** @brief Engine context of one side, its egress collected into @c tx. */
typedef struct {
    duct_unseal_ctx_t base;
    uint8_t           tx[dl_cap];
    size_t            tx_len;
} dl_ctx_t;

typedef struct {
    duct_wire_t       *wire;
    duct_wire_codec_t *codec;
    uint8_t            prefix[duct_seal_prefix_max];
    size_t             prefix_len;
} dl_side_t;

static void *dl_reserve(duct_unseal_ctx_t *self, size_t *out_cap)
{
    auto c = self->codec;
    *out_cap = duct_byte_len(c->ct_buf) - c->ct_len;
    return duct_at(c->ct_buf) + c->ct_len;
}

static bool dl_commit(duct_unseal_ctx_t *self, size_t len)
{
    auto c = self->codec;
    if (len > duct_byte_len(c->ct_buf) - c->ct_len)
        return false;
    c->ct_len += (uint32_t)len;
    return true;
}

static bool dl_append(duct_unseal_ctx_t *self, duct_view_u8 bytes)
{
    auto t = (dl_ctx_t *)self;
    if (t->tx_len + bytes.size > dl_cap)
        return false;
    memcpy(t->tx + t->tx_len, bytes.data, bytes.size);
    t->tx_len += bytes.size;
    return true;
}

static void dl_ctx(dl_ctx_t *t, duct_wire_codec_t *codec)
{
    *t = (dl_ctx_t){ .base = { .codec = codec, .reserve = dl_reserve, .commit = dl_commit,
                               .tx_append = dl_append } };
}

/** @brief Lay out the datagram @p from puts on the wire for @p t's egress: its
 *  static prefix, then the engine's bytes. */
static size_t dl_dgram(const dl_side_t *from, const dl_ctx_t *t, uint8_t *out)
{
    memcpy(out, from->prefix, from->prefix_len);
    memcpy(out + from->prefix_len, t->tx, t->tx_len);
    return from->prefix_len + t->tx_len;
}

static duct_result_t dl_unseal(dl_side_t *to, const uint8_t *d, size_t len, dl_ctx_t *t)
{
    dl_ctx(t, to->codec);
    to->codec->ct_len = 0u;
    to->codec->ct_parse_off = 0u;
    return to->wire->unseal(to->wire, to->codec, duct_view(duct_view_u8, (void *)d, len),
                            &t->base);
}

static bool dl_build(dl_side_t *s, void *cfg, duct_seal_role_t role)
{
    s->wire = dl_wire(duct_noise_vtbl_dgram(), cfg, role, true);
    if (!s->wire)
        return false;
    s->codec = s->wire->create_codec(s->wire, x_udp_peer);
    bool init = role == seal_role_initiator;
    memset(s->prefix, 0, sizeof s->prefix);
    if (init)
        memcpy(s->prefix, dl_dial, sizeof dl_dial);
    s->prefix_len = init ? g_width : 0u;
    return s->codec != nullptr;
}

static void dl_free(dl_side_t *s)
{
    if (s->codec)
        s->codec->destroy(s->codec);
    if (s->wire)
        duct_wire_destroy(s->wire);
    *s = (dl_side_t){};
}

/** @brief Seal @p payload from @p from into @p out as the worker packs a frame.
 *  @return the datagram's length, 0 where the pack fails. */
static size_t dl_send(dl_side_t *from, const uint8_t *payload, size_t n, uint8_t *out)
{
    duct_frame_t f = { .payload = { .data = (void *)payload, .size = n } };
    size_t size = from->wire->tx_bound(from->wire, n);
    auto stage = (duct_wire_tx_t){ .kind = wire_tx_vmq_view,
        .vmq_view = { .data = (char *)out, .stage = 0u, .capacity = size } };
    if (from->wire->on_pack(from->wire, nullptr, &f, &stage, from->codec) != rc_ok)
        return 0u;
    return stage.vmq_view.stage;
}

static const char *dl_codec(void)
{
    dl_side_t cli = {}, srv = {};
    const char *err = nullptr;
    if (!dl_build(&cli, &g_cli_cfg, seal_role_initiator)
        || !dl_build(&srv, &g_srv_cfg, seal_role_responder)) {
        err = "wire construction failed";
        goto done;
    }
    {
        auto vt = duct_noise_vtbl_dgram();
        static dl_ctx_t c, s;
        uint8_t d[dl_cap];
        size_t n;
        dl_ctx(&c, cli.codec);
        vt->start(cli.codec->engine, &c.base);
        n = dl_dgram(&cli, &c, d);
        dl_ctx(&s, srv.codec);
        if (dl_unseal(&srv, d, n, &s) != rc_ok) { err = "responder rejected message 1"; goto done; }
        n = dl_dgram(&srv, &s, d);
        if (dl_unseal(&cli, d, n, &c) != rc_ok) { err = "initiator rejected message 2"; goto done; }
        n = dl_dgram(&cli, &c, d);
        if (dl_unseal(&srv, d, n, &s) != rc_ok) { err = "responder rejected the confirmation"; goto done; }

        uint8_t key[duct_siphash_key_size], name[2];
        if (!duct_join_derive(vt, srv.codec->engine, key, name)) {
            err = "the responder's engine derived no join key";
            goto done;
        }
        uint8_t pa[24], pb[24], da[dl_cap], db[dl_cap];
        memset(pa, 0xa1, sizeof pa);
        memset(pb, 0xa2, sizeof pb);
        size_t la = dl_send(&cli, pa, sizeof pa, da),
               lb = dl_send(&cli, pb, sizeof pb, db);
        if (!la || !lb || !duct_dgram_lead_fits(g_width, la)) {
            err = "the initiator sealed no datagram after the handshake";
            goto done;
        }
        for (unsigned i = 0u; i < 2u; ++i) {
            const uint8_t *dg = i ? db : da;
            uint64_t mac = duct_sip_le64(dg + 2u, 8u);
            uint8_t on_wire[2] = { dg[0], dg[1] };
            duct_dgram_lead_cover(on_wire, dl_cover, mac);
            if (memcmp(on_wire, name, 2u) != 0
                || mac != duct_dgram_lead_mac(key, name, dg + g_width)) {
                err = "a datagram's lead is not the session's covered name and the MAC the responder derives";
                goto done;
            }
        }
        if (memcmp(da, db, dl_lead) == 0) {
            err = "two datagrams of one session led with the same bytes";
            goto done;
        }
        /* The name goes out covered, so it is not the session's name and it
         * differs along the session. */
        unsigned same_as_first = 0u, plain = memcmp(da, name, 2u) == 0;
        for (unsigned i = 0u; i < 8u; ++i) {
            uint8_t extra[24], dx[dl_cap];
            memset(extra, (int)(0xb0u + i), sizeof extra);
            size_t lx = dl_send(&cli, extra, sizeof extra, dx);
            if (!lx) {
                err = "the initiator stopped sealing";
                goto done;
            }
            same_as_first += memcmp(dx, da, 2u) == 0;
            plain += memcmp(dx, name, 2u) == 0;
        }
        if (same_as_first > 1u || plain > 1u) {
            err = "the session's name crossed the wire plain or the same in every datagram";
            goto done;
        }
        if (dl_unseal(&srv, da, la, &s) != rc_ok || srv.codec->ct_len != sizeof pa
            || memcmp(duct_at(srv.codec->ct_buf), pa, sizeof pa) != 0
            || dl_unseal(&srv, db, lb, &s) != rc_ok || srv.codec->ct_len != sizeof pb
            || memcmp(duct_at(srv.codec->ct_buf), pb, sizeof pb) != 0)
            err = "a datagram led with its own lead did not unseal on the responder";
    }
done:
    dl_free(&cli);
    dl_free(&srv);
    return err;
}

/** @brief The server's sessions, and the echoes the client has read. */
static atomic_int g_dl_sessions = 0;
static atomic_int g_dl_echo     = 0;

static const char dl_ping[] = "lead-ping";

static duct_result_t
dl_srv_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    atomic_fetch_add_explicit(&g_dl_sessions, 1, memory_order_release);
    return rc_ok;
}

static duct_result_t
dl_srv_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             const duct_frame_t *frame, duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    duct_response_same(out, frame->payload, fl_send_copy, fl_frame_none);
    return rc_ok;
}

/** @brief The client's first ping, and a repeating timer for the rest. */
static duct_result_t
dl_cli_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    out->payload = (duct_view_u8){ (void *)dl_ping, sizeof dl_ping - 1u };
    out->flags = fl_send_copy;
    out->control.timer.delay_ms = 20u;
    out->control.timer.interval_ms = 20u;
    out->control.timer.arg = 1u;
    return rc_ok;
}

static duct_result_t
dl_cli_timer([[maybe_unused]] duct_session_t *s, duct_response_t *out,
             [[maybe_unused]] void *proto_state, [[maybe_unused]] uint64_t arg)
{
    out->payload = (duct_view_u8){ (void *)dl_ping, sizeof dl_ping - 1u };
    out->flags = fl_send_copy;
    return rc_ok;
}

static duct_result_t
dl_cli_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    if (frame->payload.size == sizeof dl_ping - 1u
        && memcmp(frame->payload.data, dl_ping, sizeof dl_ping - 1u) == 0)
        atomic_fetch_add_explicit(&g_dl_echo, 1, memory_order_release);
    return rc_ok;
}

/** @brief A relay between a client and a server, with two sockets towards the
 *  server so the client can be moved to another source address. */
typedef struct {
    duct_sock_t        pfd,         /**< Faces the client. */
                       up_fd[2];    /**< Face the server, one source address each. */
    struct sockaddr_in srv,
                       cli;
    bool               have_cli;
    atomic_int         up;          /**< Index of the socket the client's datagrams
                                     *  leave by. */
    atomic_bool        stop;
    atomic_int         to_srv[2],   /**< Datagrams sent towards the server, per
                                     *  socket. */
                       from_srv[2]; /**< Datagrams the server sent back, per socket. */
    uint8_t            leads[dl_log][dl_lead]; /**< First bytes of each client
                                                *  datagram. */
    size_t             n_leads;
} dl_relay_t;

static void *dl_relay_run(void *arg)
{
    auto px = (dl_relay_t *)arg;
    uint8_t buf[dl_cap];
    while (!atomic_load_explicit(&px->stop, memory_order_acquire)) {
        struct pollfd pf[3] = { { .fd = px->pfd, .events = POLLIN },
                                { .fd = px->up_fd[0], .events = POLLIN },
                                { .fd = px->up_fd[1], .events = POLLIN } };
        if (poll(pf, 3, 20) <= 0)
            continue;
        if (pf[0].revents & POLLIN) {
            struct sockaddr_in from;
            socklen_t flen = sizeof from;
            ssize_t n = recvfrom(px->pfd, (char *)buf, sizeof buf, 0,
                                 (struct sockaddr *)&from, &flen);
            if (n > 0) {
                px->cli = from;
                px->have_cli = true;
                int up = atomic_load_explicit(&px->up, memory_order_acquire);
                if ((size_t)n >= dl_lead && px->n_leads < dl_log)
                    memcpy(px->leads[px->n_leads++], buf, dl_lead);
                sendto(px->up_fd[up], (char *)buf, (int)n, 0, (struct sockaddr *)&px->srv,
                       sizeof px->srv);
                atomic_fetch_add_explicit(&px->to_srv[up], 1, memory_order_relaxed);
            }
        }
        for (int i = 0; i < 2; ++i) {
            if (!(pf[1 + i].revents & POLLIN))
                continue;
            ssize_t n = recv(px->up_fd[i], (char *)buf, sizeof buf, 0);
            if (n > 0 && px->have_cli) {
                sendto(px->pfd, (char *)buf, (int)n, 0, (struct sockaddr *)&px->cli,
                       sizeof px->cli);
                atomic_fetch_add_explicit(&px->from_srv[i], 1, memory_order_relaxed);
            }
        }
    }
    return nullptr;
}

/** @brief Build the protocol @p pcfg describes over @p wire, the protocol owning
 *  the wire from then on.
 *  @return the protocol, or nullptr with the wire already destroyed. */
static duct_proto_t *dl_proto(duct_wire_t *wire, duct_proto_cfg_t pcfg)
{
    if (!wire)
        return nullptr;
    pcfg.wire = wire;
    auto proto = duct_proto_create(&pcfg);
    if (proto)
        proto->owned_wire = wire;
    else
        duct_wire_destroy(wire);
    return proto;
}

static const char *dl_roam(void)
{
    static dl_relay_t px;
    px = (dl_relay_t){ .pfd = duct_sock_bad, .up_fd = { duct_sock_bad, duct_sock_bad } };
    uint16_t port = 0u, relay_port = 0u, up_port = 0u;
    const char *err = nullptr;
    duct_proto_t *srv = nullptr, *cli = nullptr;
    pthread_t th_io, th_relay;
    bool io_running = false, relay_running = false;
    char addr[64];
    int before = 0, tried = 0;

    atomic_store_explicit(&g_dl_sessions, 0, memory_order_release);
    atomic_store_explicit(&g_dl_echo, 0, memory_order_release);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io)
        return "engine launch failed";
    srv = dl_proto(dl_wire(duct_noise_vtbl_dgram(), &g_srv_cfg, seal_role_responder, true),
                   (duct_proto_cfg_t){ .name = "dgram-lead-srv", .on_frame = dl_srv_frame,
                                       .on_session_open = dl_srv_open, .max_response = 2048u,
                                       .flags = fl_proto_dgram_shared });
    cli = dl_proto(dl_wire(duct_noise_vtbl_dgram(), &g_cli_cfg, seal_role_initiator, true),
                   (duct_proto_cfg_t){ .name = "dgram-lead-cli", .on_frame = dl_cli_frame,
                                       .on_session_open = dl_cli_open, .on_timer = dl_cli_timer,
                                       .max_response = 2048u });
    if (!srv || !cli) {
        err = "protocols did not build";
        goto done;
    }
    if (duct_listener_bind(io, &(duct_listener_cfg_t){
            .kind = listener_dgram, .addr = "127.0.0.1",
            .n_protos = 1, .protos = (const duct_proto_t *[]){ srv },
        }, &port, nullptr, 0u, nullptr) != rc_ok) {
        err = "the sealed datagram wire was refused on a datagram listener";
        goto done;
    }
    px.pfd = uc_bind(&relay_port);
    px.up_fd[0] = uc_bind(&up_port);
    px.up_fd[1] = uc_bind(&up_port);
    if (px.pfd == duct_sock_bad || px.up_fd[0] == duct_sock_bad
        || px.up_fd[1] == duct_sock_bad) {
        err = "relay sockets failed";
        goto done;
    }
    px.srv = (struct sockaddr_in){ .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, "127.0.0.1", &px.srv.sin_addr);
    if (pthread_create(&th_io, nullptr, th_run, io) != 0) {
        err = "engine thread create failed";
        goto done;
    }
    io_running = true;
    if (pthread_create(&th_relay, nullptr, dl_relay_run, &px) != 0) {
        err = "relay thread create failed";
        goto done;
    }
    relay_running = true;

    snprintf(addr, sizeof addr, "127.0.0.1:%u", (unsigned)relay_port);
    if (duct_io_connect(io, addr, cli, nullptr, x_udp_peer) != rc_ok) {
        err = "client connect failed";
        goto done;
    }
    for (unsigned waited = 0u; waited < 5000u
         && atomic_load_explicit(&g_dl_echo, memory_order_acquire) < 3; waited += 10u)
        th_sleep_ms(10u);
    if (atomic_load_explicit(&g_dl_echo, memory_order_acquire) < 3) {
        err = "the client never got its echo back through the relay";
        goto done;
    }

    /* The client moves: its datagrams reach the server from another source
     * address, with nothing but the lead the codec wrote to say whose they are. */
    atomic_store_explicit(&px.up, 1, memory_order_release);
    before = atomic_load_explicit(&g_dl_echo, memory_order_acquire);
    for (unsigned waited = 0u; waited < 8000u; waited += 10u) {
        if (atomic_load_explicit(&g_dl_echo, memory_order_acquire) >= before + 3
            && atomic_load_explicit(&px.from_srv[1], memory_order_acquire) >= 1)
            break;
        th_sleep_ms(10u);
    }
    tried = atomic_load_explicit(&g_dl_echo, memory_order_acquire) - before;
    if (tried < 3) {
        err = "the session did not follow its client to a new address";
        goto done;
    }
    if (atomic_load_explicit(&px.from_srv[1], memory_order_acquire) < 1) {
        err = "the server never answered at the client's new address";
        goto done;
    }
    if (atomic_load_explicit(&g_dl_sessions, memory_order_acquire) != 1)
        err = "the datagrams from the new address opened a session of their own";

done:
    duct_engine_stop(io);
    if (io_running)
        pthread_join(th_io, nullptr);
    atomic_store_explicit(&px.stop, true, memory_order_release);
    if (relay_running)
        pthread_join(th_relay, nullptr);
    duct_engine_destroy(io);
    for (int i = 0; i < 3; ++i) {
        duct_sock_t fd = i ? px.up_fd[i - 1] : px.pfd;
        duct_sock_close(fd);
    }
    duct_proto_destroy(cli);
    duct_proto_destroy(srv);
    if (err)
        return err;

    /* What an observer between the two ends saw of the lead. */
    if (px.n_leads < 6u)
        return "the relay saw too few datagrams to judge their leads";
    if (memcmp(px.leads[0], dl_dial, dl_lead) != 0)
        return "the first datagram did not lead with the dial prefix the wire was built with";
    size_t keyed = 0u,
           first = 0u,
           shared = 0u;
    for (size_t i = 1u; i < px.n_leads; ++i) {
        if (memcmp(px.leads[i], dl_dial, dl_lead) == 0)
            continue;
        if (++keyed == 1u)
            first = i;
        else
            shared += memcmp(px.leads[i], px.leads[first], 2u) == 0;
        for (size_t j = 1u; j < i; ++j)
            if (memcmp(px.leads[i], px.leads[j], dl_lead) == 0)
                return "two datagrams of the session led with the same bytes";
    }
    if (keyed < 5u)
        return "the datagrams after the handshake did not lead with a lead of their own";
    if (shared + 1u >= keyed)
        return "the session's name crossed the wire the same in every datagram";
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    if (!duct_noise_keypair_generate(&g_srv_kp) || !duct_noise_keypair_generate(&g_cli_kp)) {
        fprintf(stderr, "dgram_lead: keypair generation failed\n");
        return 1;
    }
    g_srv_cfg.local_static = g_srv_kp;
    g_cli_cfg.local_static = g_cli_kp;
    memcpy(g_cli_cfg.remote_static_pub, g_srv_kp.pub, duct_noise_key_size);

    static constexpr size_t widths[] = { dl_lead, dl_lead + 4u };
    auto err = dl_cfg();
    for (size_t i = 0u; !err && i < sizeof widths / sizeof widths[0]; ++i) {
        g_width = widths[i];
        err = dl_codec();
        if (!err)
            err = dl_roam();
        if (err)
            fprintf(stderr, "dgram_lead: behind a prefix %zu bytes wide\n", g_width);
    }
    if (err) {
        fprintf(stderr, "dgram_lead: %s\n", err);
        return 1;
    }
    printf("dgram_lead: OK (config refusals, the codec's lead agrees with the responder's "
           "derivation and differs per datagram, a session follows its client to a new "
           "address on the lead alone, behind a prefix as wide as the lead and a wider one)\n");
    return 0;
}
