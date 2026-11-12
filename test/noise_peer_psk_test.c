/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file noise_peer_psk_test.c
 *  @brief A responder's wire key, the PSK it takes per peer and the hello of message 1,
 *  driven through both Noise vtbls without a socket.
 *
 *  Three peers, each with its own PSK and one wire key between them, complete against a
 *  responder whose own PSK is zero, so the mask over the leading key cannot be keyed by a
 *  PSK. A wrong PSK fails at message 2, an unknown peer draws no message 2, and a responder
 *  with another wire key cannot read message 1 in a masking build. The hello arrives at
 *  @c peer_psk byte for byte, names the responder's view of its peer beside the key, and
 *  rides every rekey; a peer withdrawn mid-session fails its next rekey while the keys in
 *  use carry on. A message 1 with an empty payload is refused without asking, a shorter
 *  non-empty one is the peer's callback to judge where it stands, and a hello over the
 *  maximum fails @c create. Each case runs with no hello, one of 22 bytes
 *  and one of the maximum. A peer of an older build carries a hello shorter than the
 *  config's: the payload whole reaches the callbacks, the responder's naming zero-fills
 *  the tail, and the rekey asks again with the payload whole.
 *
 *  Every case runs under IKpsk2 and under XKpsk3. XKpsk3 asks the peer and the PSK of
 *  message 3, so a wrong PSK and an unknown peer draw message 2 and are refused at message 3;
 *  the hello of its message 1 goes to @c hello_ok, whose refusal draws no message 2.
 */

#include "duct_noise_internal.h"
#include "duct_session.h"

#include <stdio.h>
#include <string.h>

static constexpr size_t port_cap = 4096u;
static constexpr unsigned peers = 3u;
/** @brief Longest hello the staging of a world holds, a length past the old
 *  fixed cap and past the padding bound both ends build with. */
static constexpr size_t hello_stage_max = 256u;

typedef struct {
    duct_unseal_ctx_t base;
    uint8_t           ct[port_cap];
    size_t            ct_len;
    uint8_t           tx[port_cap];
    size_t            tx_len;
} port_t;

static void *s_reserve(duct_unseal_ctx_t *self, size_t *cap)
{
    auto p = (port_t *)self;
    *cap = sizeof p->ct - p->ct_len;
    return p->ct + p->ct_len;
}

static bool s_commit(duct_unseal_ctx_t *self, size_t len)
{
    auto p = (port_t *)self;
    if (len > sizeof p->ct - p->ct_len)
        return false;
    p->ct_len += len;
    return true;
}

static bool s_tx_append(duct_unseal_ctx_t *self, duct_view_u8 bytes)
{
    auto p = (port_t *)self;
    if (bytes.size > sizeof p->tx - p->tx_len)
        return false;
    memcpy(p->tx + p->tx_len, bytes.data, bytes.size);
    p->tx_len += bytes.size;
    return true;
}

static void s_clear(port_t *p)
{
    *p = (port_t){ .base = { .reserve = s_reserve, .commit = s_commit, .tx_append = s_tx_append } };
}

static duct_view_u8 s_wire(const port_t *p)
{
    return duct_view(duct_view_u8, (void *)p->tx, p->tx_len);
}

typedef struct {
    uint8_t pub[duct_noise_key_size];
    uint8_t psk[duct_noise_key_size];
    bool    withdrawn;
} peer_t;

typedef struct {
    peer_t   peer[peers];
    unsigned asked;
    size_t   hello_len;
    uint8_t  hello[hello_stage_max];
    unsigned xk_asked;                   /**< Asks of @c hello_ok, the scenario's own. */
    size_t   xk_len;                     /**< The payload whole @c hello_ok last saw. */
    uint8_t  xk_hello[hello_stage_max];
} book_t;

static bool s_peer_psk(void *ctx, const uint8_t pub[duct_noise_key_size], duct_view_u8 hello,
                       uint8_t out[duct_noise_key_size])
{
    auto book = (book_t *)ctx;
    ++book->asked;
    book->hello_len = hello.size;
    memcpy(book->hello, hello.data, hello.size);
    for (unsigned i = 0u; i < peers; ++i)
        if (!book->peer[i].withdrawn && memcmp(book->peer[i].pub, pub, duct_noise_key_size) == 0) {
            memcpy(out, book->peer[i].psk, duct_noise_key_size);
            return true;
        }
    return false;
}

static bool s_hello_seen(void *ctx, duct_view_u8 hello)
{
    auto book = (book_t *)ctx;
    ++book->xk_asked;
    book->xk_len = hello.size;
    size_t take = hello.size < sizeof book->xk_hello ? hello.size : sizeof book->xk_hello;
    memcpy(book->xk_hello, hello.data, take);
    return true;
}

typedef struct {
    duct_noise_cfg_t server,
                     client[peers];
    book_t           book;
    uint8_t client_hello[peers][hello_stage_max]; /** The hello each client's
                              *  config names, its own fill of @c hello_len bytes. */
} world_t;

static void s_fill(uint8_t *p, size_t n, unsigned seed)
{
    for (size_t i = 0u; i < n; ++i)
        p[i] = (uint8_t)(seed + i);
}

static bool s_world(world_t *w, size_t hello_len, duct_noise_pattern_t pattern)
{
    *w = (world_t){};
    uint8_t wire_key[duct_noise_key_size];
    s_fill(wire_key, sizeof wire_key, 0x70u);
    auto server = &w->server;
    if (!duct_noise_keypair_generate(&server->local_static))
        return false;
    server->suite.pattern = pattern;
    server->peer_psk = s_peer_psk;
    server->verify_ctx = &w->book;
    server->hello_len = hello_len;
    memcpy(server->wire_key, wire_key, sizeof wire_key);
    for (unsigned i = 0u; i < peers; ++i) {
        auto peer = &w->book.peer[i];
        auto client = &w->client[i];
        if (!duct_noise_keypair_generate(&client->local_static))
            return false;
        client->suite.pattern = pattern;
        memcpy(peer->pub, client->local_static.pub, duct_noise_key_size);
        s_fill(peer->psk, sizeof peer->psk, 0x10u * (i + 1u));
        client->hello_len = hello_len;
        client->hello = w->client_hello[i];
        memcpy(client->remote_static_pub, server->local_static.pub, duct_noise_key_size);
        memcpy(client->psk, peer->psk, sizeof client->psk);
        memcpy(client->wire_key, wire_key, sizeof wire_key);
        s_fill(w->client_hello[i], hello_len, 0xa0u + 0x10u * i);
    }
    return true;
}

typedef struct {
    const duct_seal_engine_vtbl_t *vt;
    duct_seal_engine_t            *ini, *rsp;
    port_t                        *ip, *rp;
} pair_t;

static port_t g_ini_port, g_rsp_port;

static void s_close(pair_t *p)
{
    if (p->ini)
        p->vt->destroy(p->ini);
    if (p->rsp)
        p->vt->destroy(p->rsp);
}

static bool s_open(pair_t *p, const duct_seal_engine_vtbl_t *vt,
                   duct_noise_cfg_t *rsp, duct_noise_cfg_t *ini)
{
    *p = (pair_t){ .vt = vt, .ip = &g_ini_port, .rp = &g_rsp_port };
    p->rsp = vt->create(vt,rsp, seal_role_responder);
    p->ini = vt->create(vt,ini, seal_role_initiator);
    if (p->rsp && p->ini)
        return true;
    s_close(p);
    return false;
}

typedef enum { hs_refused_m1, hs_refused_m2, hs_broken, hs_done } hs_t;

static hs_t s_handshake(pair_t *p)
{
    s_clear(p->ip);
    s_clear(p->rp);
    p->vt->start(p->ini, &p->ip->base);
    if (p->vt->unseal(p->rsp, s_wire(p->ip), &p->rp->base) != rc_ok)
        return hs_refused_m1;
    s_clear(p->ip);
    if (p->vt->unseal(p->ini, s_wire(p->rp), &p->ip->base) != rc_ok)
        return hs_refused_m2;
    duct_view_u8 confirm = s_wire(p->ip);
    s_clear(p->rp);
    return p->vt->unseal(p->rsp, confirm, &p->rp->base) == rc_ok ? hs_done : hs_broken;
}

static hs_t s_rekey(pair_t *p)
{
    s_clear(p->ip);
    s_clear(p->rp);
    if (p->vt->rekey(p->ini, &p->ip->base) != rc_ok || p->ip->tx_len == 0u)
        return hs_broken;
    if (p->vt->unseal(p->rsp, s_wire(p->ip), &p->rp->base) != rc_ok)
        return hs_refused_m1;
    s_clear(p->ip);
    return p->vt->unseal(p->ini, s_wire(p->rp), &p->ip->base) == rc_ok ? hs_done : hs_refused_m2;
}

static bool s_carries_one_way(const pair_t *p, duct_seal_engine_t *from, duct_seal_engine_t *to,
                              port_t *to_port)
{
    static const uint8_t text[] = "ping";
    duct_view_u8 span = { .data = (void *)text, .size = sizeof text - 1u };
    uint8_t    wire[port_cap];
    size_t     need = p->vt->seal_size(from, span.size);
    if (need == 0u || need > sizeof wire)
        return false;
    p->vt->seal(from, &span, 1u, wire);
    s_clear(to_port);
    return p->vt->unseal(to, duct_view(duct_view_u8, wire, need), &to_port->base) == rc_ok
        && to_port->ct_len == span.size && memcmp(to_port->ct, text, span.size) == 0;
}

static bool s_carries(const pair_t *p)
{
    return s_carries_one_way(p, p->ini, p->rsp, p->rp) && s_carries_one_way(p, p->rsp, p->ini, p->ip);
}

static bool s_named(const pair_t *p, const world_t *w, unsigned peer)
{
    auto at_rsp = p->vt->peer_identity(p->rsp);
    auto at_ini = p->vt->peer_identity(p->ini);
    auto hello_len = w->server.hello_len;
    return at_rsp.size == duct_noise_key_size + hello_len
        && memcmp(at_rsp.data, w->book.peer[peer].pub, duct_noise_key_size) == 0
        && memcmp((const uint8_t *)at_rsp.data + duct_noise_key_size, w->client[peer].hello, hello_len) == 0
        && at_ini.size == duct_noise_key_size
        && memcmp(at_ini.data, w->server.local_static.pub, duct_noise_key_size) == 0;
}

static bool s_asked_with(const world_t *w, unsigned times, unsigned peer)
{
    /* The ask carries the payload whole — the hello, then its zero padding — so
     * the hello is read at the lead, never by the view's length. */
    size_t lead = w->server.hello_len < w->book.hello_len ? w->server.hello_len : w->book.hello_len;
    return w->book.asked == times && w->book.hello_len >= w->server.hello_len
        && memcmp(w->book.hello, w->client[peer].hello, lead) == 0;
}

static const char *s_each_peer(const duct_seal_engine_vtbl_t *vt, world_t *w)
{
    for (unsigned i = 0u; i < peers; ++i) {
        pair_t p;
        if (!s_open(&p, vt, &w->server, &w->client[i]))
            return "engine create failed";
        bool ok = s_handshake(&p) == hs_done && s_named(&p, w, i) && s_asked_with(w, i + 1u, i)
               && s_carries(&p);
        s_close(&p);
        if (!ok)
            return "a peer with its own PSK did not complete, or was not named with its hello";
    }
    return nullptr;
}

static bool s_xk(const world_t *w)
{
    return w->server.suite.pattern == noise_pattern_xkpsk3;
}

static const char *s_wrong_psk(const duct_seal_engine_vtbl_t *vt, world_t *w)
{
    duct_noise_cfg_t cli = w->client[0];
    cli.psk[0] ^= 1u;
    pair_t p;
    if (!s_open(&p, vt, &w->server, &cli))
        return "engine create failed";
    hs_t got = s_handshake(&p);
    bool refused = s_xk(w) ? got == hs_broken && vt->peer_identity(p.rsp).size == 0u
                           : got == hs_refused_m2 && p.rp->tx_len != 0u;
    s_close(&p);
    return refused ? nullptr : "a wrong PSK was not refused at its message";
}

static const char *s_unknown_peer(const duct_seal_engine_vtbl_t *vt, world_t *w)
{
    duct_noise_cfg_t cli = w->client[0];
    if (!duct_noise_keypair_generate(&cli.local_static))
        return "keypair generation failed";
    pair_t p;
    if (!s_open(&p, vt, &w->server, &cli))
        return "engine create failed";
    hs_t got = s_handshake(&p);
    bool refused = s_xk(w) ? got == hs_broken && vt->peer_identity(p.rsp).size == 0u
                           : got == hs_refused_m1 && p.rp->tx_len == 0u;
    s_close(&p);
    return refused ? nullptr : "an unknown peer was not refused where its pattern asks for the key";
}

static const char *s_other_wire_key(const duct_seal_engine_vtbl_t *vt, world_t *w)
{
    duct_noise_cfg_t srv = w->server;
    srv.wire_key[0] ^= 1u;
    pair_t p;
    if (!s_open(&p, vt, &srv, &w->client[0]))
        return "engine create failed";
    hs_t got = s_handshake(&p);
    bool as_built = duct_handshake_mask ? got == hs_refused_m1 && p.rp->tx_len == 0u : got == hs_done;
    s_close(&p);
    return as_built ? nullptr : "the wire key does not decide whether message 1 reads";
}

static bool s_refuse([[maybe_unused]] void *ctx, [[maybe_unused]] const uint8_t peer[duct_noise_key_size])
{
    return false;
}

static const char *s_verify_first(const duct_seal_engine_vtbl_t *vt, world_t *w)
{
    duct_noise_cfg_t srv = w->server;
    srv.verify_peer = s_refuse;
    pair_t p;
    if (!s_open(&p, vt, &srv, &w->client[0]))
        return "engine create failed";
    hs_t got = s_handshake(&p);
    bool refused = s_xk(w) ? got == hs_broken : got == hs_refused_m1 && p.rp->tx_len == 0u;
    s_close(&p);
    return refused && w->book.asked == 0u ? nullptr : "peer_psk was asked for a peer verify_peer refused";
}

static bool s_refuse_hello([[maybe_unused]] void *ctx, [[maybe_unused]] duct_view_u8 hello)
{
    return false;
}

static const char *s_hello_refused(const duct_seal_engine_vtbl_t *vt, world_t *w)
{
    if (!s_xk(w))
        return nullptr;
    duct_noise_cfg_t srv = w->server;
    srv.hello_ok = s_refuse_hello;
    pair_t p;
    if (!s_open(&p, vt, &srv, &w->client[0]))
        return "engine create failed";
    hs_t got = s_handshake(&p);
    bool silent = got == hs_refused_m1 && p.rp->tx_len == 0u && w->book.asked == 0u;
    s_close(&p);
    return silent ? nullptr : "a hello that hello_ok refused drew message 2 or reached peer_psk";
}

static const char *s_rekey_carries_hello(const duct_seal_engine_vtbl_t *vt, world_t *w)
{
    pair_t p;
    if (!s_open(&p, vt, &w->server, &w->client[1]))
        return "engine create failed";
    bool ok = s_handshake(&p) == hs_done && s_rekey(&p) == hs_done && s_asked_with(w, 2u, 1u)
           && s_named(&p, w, 1u) && s_carries(&p);
    s_close(&p);
    return ok ? nullptr : "a rekey did not carry the hello, or changed the peer's name";
}

static const char *s_withdrawn(const duct_seal_engine_vtbl_t *vt, world_t *w)
{
    pair_t p;
    if (!s_open(&p, vt, &w->server, &w->client[1]))
        return "engine create failed";
    bool ok = s_handshake(&p) == hs_done;
    w->book.peer[1].withdrawn = true;
    ok = ok && s_rekey(&p) == hs_refused_m1 && p.rp->tx_len == 0u && s_carries(&p);
    s_close(&p);
    return ok ? nullptr : "a withdrawn peer's rekey was not refused, or the keys in use stopped";
}

static const char *s_short_hello(const duct_seal_engine_vtbl_t *vt, world_t *w)
{
    size_t hello_len = w->server.hello_len;
    if (hello_len == 0u)
        return nullptr;
    /* The world's peer_psk stands and its hello_ok does not: an empty payload is
     * refused without asking, a shorter non-empty one is the callback's to judge,
     * and XKpsk3 without hello_ok keeps the config's hello whole as its gate. */
    const size_t lens[] = { 0u, hello_len - 1u, hello_len };
    for (unsigned i = 0u; i < 3u; ++i) {
        size_t len = lens[i];
        auto hs = duct_noise_hs_create_for(w->server.suite.pattern, &w->client[0].local_static,
                                           w->server.local_static.pub, w->server.wire_key, true,
                                           (duct_view_u8){});
        if (!hs)
            return "handshake state failed";
        duct_noise_hs_set_psk(hs, w->book.peer[0].psk);
        uint8_t zeros[hello_stage_max] = {};
        uint8_t framed[port_cap];
        size_t  hdr = vt->pdu_hdr_size, n = 0u;
        duct_view_u8 payload = { .data = zeros, .size = len };
        bool    wrote = s_xk(w) ? duct_noise_hs_write_msg1_xk(hs, payload, framed + hdr, sizeof framed - hdr, &n)
                                : duct_noise_hs_write_msg1(hs, payload, framed + hdr, sizeof framed - hdr, &n);
        duct_noise_hs_destroy(hs);
        if (!wrote)
            return "crafting message 1 failed";
        if (hdr)
            duct_store_be16(framed, (uint16_t)n);
        auto rsp = vt->create(vt,&w->server, seal_role_responder);
        if (!rsp)
            return "engine create failed";
        s_clear(&g_rsp_port);
        duct_result_t rc = vt->unseal(rsp, duct_view(duct_view_u8, framed, hdr + n), &g_rsp_port.base);
        vt->destroy(rsp);
        bool went = rc == rc_ok && g_rsp_port.tx_len != 0u;
        bool right = s_xk(w) ? (len < hello_len ? !went : went)
                             : (len == 0u ? !went : went);
        if (!right)
            return "the length gate answered where its callback should, or an empty payload drew a reply";
    }
    return nullptr;
}

/** @brief A peer of an older build: its hello runs short of the config's, the
 *  payload whole still reaches the callbacks, the naming zero-fills, and the
 *  rekey asks again. */
static const char *s_older_peer(const duct_seal_engine_vtbl_t *vt, world_t *w)
{
    /* The older hello reads short of the config's, never past it: the
     * responder's rooms follow its own hello length. */
    size_t sl = w->server.hello_len,
           cl = sl < 24u ? sl : 24u;
    w->server.hello_ok = s_hello_seen;
    w->client[0].hello_len = cl;
    s_fill(w->client_hello[0], cl, 0xa0u);
    uint8_t want[hello_stage_max] = {};
    memcpy(want, w->client_hello[0], cl < sl ? cl : sl);
    pair_t p;
    if (!s_open(&p, vt, &w->server, &w->client[0]))
        return "engine create failed";
    bool ok = s_handshake(&p) == hs_done;
    /* hello_ok saw the payload whole: at least the peer's hello, at most it plus
     * the padding bound, led by the peer's hello bytes. An IKpsk2 responder
     * never asks it. */
    ok = ok && (!s_xk(w) || (w->book.xk_asked == 1u && w->book.xk_len >= cl
        && w->book.xk_len <= cl + 128u
        && (cl == 0u || memcmp(w->book.xk_hello, w->client_hello[0], cl) == 0)));
    /* The responder names its peer by the key then its own hello length, the
     * tail zero where the peer's hello ran out. */
    auto id = p.vt->peer_identity(p.rsp);
    ok = ok && id.size == duct_noise_key_size + sl
        && memcmp(id.data, w->book.peer[0].pub, duct_noise_key_size) == 0
        && memcmp((const uint8_t *)id.data + duct_noise_key_size, want, sl) == 0;
    /* peer_psk's first ask: the zero-filled naming under XKpsk3, the payload
     * whole under IKpsk2. */
    ok = ok && w->book.asked == 1u;
    ok = ok && (s_xk(w) ? w->book.hello_len == sl && memcmp(w->book.hello, want, sl) == 0
                        : w->book.hello_len >= cl && w->book.hello_len <= cl + 128u
                       && (cl == 0u || memcmp(w->book.hello, w->client_hello[0], cl) == 0));
    /* The rekey asks again with the payload whole, led by the short hello. */
    ok = ok && s_rekey(&p) == hs_done && w->book.asked == 2u
        && w->book.hello_len >= cl && w->book.hello_len <= cl + 128u
        && (cl == 0u || memcmp(w->book.hello, w->client_hello[0], cl) == 0);
    ok = ok && s_carries(&p);
    s_close(&p);
    return ok ? nullptr : "an older peer's shorter hello did not open, name, rekey or carry";
}

static const struct {
    const char *name;
    const char *(*run)(const duct_seal_engine_vtbl_t *vt, world_t *w);
} k_scenarios[] = {
    { "each peer its own PSK",    s_each_peer },
    { "wrong PSK",                s_wrong_psk },
    { "unknown peer",             s_unknown_peer },
    { "other wire key",           s_other_wire_key },
    { "verify_peer first",        s_verify_first },
    { "hello_ok refuses",         s_hello_refused },
    { "rekey carries the hello",  s_rekey_carries_hello },
    { "withdrawn peer",           s_withdrawn },
    { "payload shorter than hello", s_short_hello },
    { "an older peer's shorter hello", s_older_peer },
};

int main(void)
{
    static world_t w;
    const duct_seal_engine_vtbl_t *vts[] = { duct_noise_vtbl(), duct_noise_vtbl_dgram() };
    const size_t hellos[] = { 0u, 22u, 48u, 64u, 128u, 129u, 200u };
    const duct_noise_pattern_t patterns[] = { noise_pattern_ikpsk2, noise_pattern_xkpsk3 };
    for (size_t p = 0u; p < sizeof patterns / sizeof *patterns; ++p)
        for (size_t v = 0u; v < sizeof vts / sizeof *vts; ++v)
            for (size_t h = 0u; h < sizeof hellos / sizeof *hellos; ++h)
                for (size_t s = 0u; s < sizeof k_scenarios / sizeof *k_scenarios; ++s) {
                    const char *err = s_world(&w, hellos[h], patterns[p]) ? k_scenarios[s].run(vts[v], &w)
                                                                          : "keypair generation failed";
                    if (err) {
                        fprintf(stderr, "noise_peer_psk: pattern %u, %s, hello %zu, %s: %s\n",
                                (unsigned)patterns[p], vts[v]->name, hellos[h], k_scenarios[s].name, err);
                        return 1;
                    }
                }
    printf("noise_peer_psk: OK (IKpsk2 and XKpsk3, stream and datagram vtbls, %s, "
           "hello 0, 22, 48, 64, 128, 129 and 200 bytes)\n", duct_handshake_mask ? "masked" : "raw");
    return 0;
}
