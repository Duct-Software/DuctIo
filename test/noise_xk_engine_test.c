/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file noise_xk_engine_test.c
 *  @brief The Noise seal engine over XKpsk3, driven without a socket.
 *
 *  Both ends run in this process against a stand-in @c duct_unseal_ctx_t, on the
 *  stream vtbl and on the datagram vtbl alike. `exchange` runs the three messages with
 *  the sizes they take, the responder naming its peer only at message 3 and asking
 *  for its password once, and transport both ways after. `hello` has @c hello_ok
 *  refuse a hello, which draws no message 2. `peer` has the responder refuse the
 *  peer at message 3 and take the same message once the policy admits it. `password`
 *  refuses a message 3 made under another password. `forged` changes every bit of
 *  each message in turn and still reads the genuine one. `reorder` drops a data PDU
 *  that overtakes message 3 and takes it once message 3 has read. `repeat` answers a
 *  repeated message 1 with message 2 and a repeated message 2 with message 3, each
 *  at most @c 4 times, and takes a repeat after the end of the exchange without a
 *  word; the first authentic PDU of the peer ends that, and a stream recognises no
 *  repeat. `rekey` runs the IKpsk2 rekey over keys an XKpsk3 exchange made. `create`
 *  refuses a pattern past the last and frees every stage of the exchange.
 */

#include "duct_crypto.h"
#include "duct_noise.h"
#include "duct_seal_engine.h"

#include <stdio.h>
#include <string.h>

static constexpr size_t   k_cap = 4096u;
static constexpr unsigned k_hello_len = 24u;
static constexpr unsigned k_tries = 4u;
static constexpr uint16_t k_rto_ms = 250u;

typedef struct {
    duct_unseal_ctx_t base;
    uint8_t           ct[k_cap],
                      tx[k_cap];
    size_t            ct_len,
                      tx_len;
    unsigned          appends,
                      arms;
    uint32_t          armed_ms;
} fake_t;

static void *f_reserve(duct_unseal_ctx_t *self, size_t *cap)
{
    auto f = (fake_t *)self;
    *cap = k_cap - f->ct_len;
    return f->ct + f->ct_len;
}

static bool f_commit(duct_unseal_ctx_t *self, size_t len)
{
    auto f = (fake_t *)self;
    if (len > k_cap - f->ct_len)
        return false;
    f->ct_len += len;
    return true;
}

static bool f_append(duct_unseal_ctx_t *self, duct_view_u8 bytes)
{
    auto f = (fake_t *)self;
    if (bytes.size > k_cap - f->tx_len)
        return false;
    memcpy(f->tx + f->tx_len, bytes.data, bytes.size);
    f->tx_len += bytes.size;
    ++f->appends;
    return true;
}

static duct_result_t f_arm(duct_unseal_ctx_t *self, uint32_t delay_ms)
{
    auto f = (fake_t *)self;
    ++f->arms;
    f->armed_ms = delay_ms;
    return rc_ok;
}

static void fake_reset(fake_t *f)
{
    *f = (fake_t){ .base = { .reserve = f_reserve, .commit = f_commit, .tx_append = f_append } };
}

/** @brief The keys, the password and the policy both ends are built from. */
typedef struct {
    duct_noise_keypair_t kc,
                         ks;
    uint8_t              psk[duct_noise_key_size];
    duct_noise_cfg_t     cli,
                         srv;
    unsigned             hello_asked,
                         verify_asked,
                         psk_asked;
    bool                 hello_good,
                         peer_good;
    uint8_t              hello_seen[k_hello_len],
                         hello_stage[k_hello_len]; /**< The client config's own
                              *  storage: the cfg names it by pointer now. */
} setup_t;

static bool cb_hello_ok(void *ctx, duct_view_u8 hello)
{
    auto s = (setup_t *)ctx;
    ++s->hello_asked;
    /* The view is the payload whole: the hello, then its zero padding. */
    if (hello.size >= k_hello_len && memcmp(hello.data, s->cli.hello, k_hello_len) == 0)
        memcpy(s->hello_seen, hello.data, k_hello_len);
    return s->hello_good;
}

static bool cb_verify(void *ctx, [[maybe_unused]] const uint8_t peer[duct_noise_key_size])
{
    auto s = (setup_t *)ctx;
    ++s->verify_asked;
    return s->peer_good;
}

static bool cb_psk(void *ctx, [[maybe_unused]] const uint8_t peer[duct_noise_key_size],
                   duct_view_u8 hello, uint8_t out[duct_noise_key_size])
{
    auto s = (setup_t *)ctx;
    ++s->psk_asked;
    /* The first ask reads the zero-filled naming, a rekey's the payload whole;
     * the hello leads either. */
    bool known = hello.size >= k_hello_len && memcmp(hello.data, s->cli.hello, k_hello_len) == 0;
    if (known)
        memcpy(out, s->psk, duct_noise_key_size);
    return known;
}

static bool setup_open(setup_t *s)
{
    *s = (setup_t){ .hello_good = true, .peer_good = true };
    if (!duct_noise_keypair_generate(&s->kc) || !duct_noise_keypair_generate(&s->ks)
        || !duct_random_bytes(s->psk, sizeof s->psk) || !duct_random_bytes(s->hello_stage, k_hello_len))
        return false;
    s->cli.local_static = s->kc;
    memcpy(s->cli.remote_static_pub, s->ks.pub, duct_noise_key_size);
    memcpy(s->cli.psk, s->psk, sizeof s->psk);
    s->cli.hello_len = k_hello_len;
    s->cli.hello = s->hello_stage;
    s->cli.suite.pattern = noise_pattern_xkpsk3;
    s->srv.local_static = s->ks;
    memcpy(s->srv.psk, s->psk, sizeof s->psk);
    s->srv.hello_len = k_hello_len;
    s->srv.suite.pattern = noise_pattern_xkpsk3;
    s->srv.verify_peer = cb_verify;
    s->srv.peer_psk = cb_psk;
    s->srv.hello_ok = cb_hello_ok;
    s->srv.verify_ctx = s;
    if (!duct_random_bytes(s->cli.wire_key, duct_noise_key_size))
        return false;
    memcpy(s->srv.wire_key, s->cli.wire_key, duct_noise_key_size);
    return true;
}

typedef struct {
    const duct_seal_engine_vtbl_t *vt;
    duct_seal_engine_t            *cli,
                                  *srv;
} pair_t;

static bool pair_open(pair_t *p, const duct_seal_engine_vtbl_t *vt, setup_t *s)
{
    *p = (pair_t){ .vt = vt, .cli = vt->create(&s->cli, seal_role_initiator),
                   .srv = vt->create(&s->srv, seal_role_responder) };
    return p->cli && p->srv;
}

static void pair_close(pair_t *p)
{
    if (p->cli)
        p->vt->destroy(p->cli);
    if (p->srv)
        p->vt->destroy(p->srv);
}

static duct_result_t deliver(const duct_seal_engine_vtbl_t *vt, duct_seal_engine_t *e, fake_t *f,
                             const uint8_t *bytes, size_t n)
{
    fake_reset(f);
    return vt->unseal(e, duct_view(duct_view_u8, (void *)bytes, n), &f->base);
}

typedef struct {
    uint8_t bytes[1024];
    size_t  n;
} msg_t;

static msg_t take(const fake_t *f)
{
    msg_t m = { .n = f->tx_len };
    memcpy(m.bytes, f->tx, f->tx_len);
    return m;
}

static bool same(const msg_t *a, const fake_t *f)
{
    return a->n == f->tx_len && memcmp(a->bytes, f->tx, a->n) == 0;
}

/** @brief The three messages of one exchange and the ends that made them. */
typedef struct {
    pair_t pair;
    msg_t  m1,
           m2,
           m3;
} flow_t;

static fake_t g_c, g_s;

static const char *flow_m1(flow_t *w)
{
    fake_reset(&g_c);
    g_c.base.arm = f_arm;
    w->pair.vt->start(w->pair.cli, &g_c.base);
    if (g_c.appends != 1u)
        return "start did not emit exactly one message 1";
    w->m1 = take(&g_c);
    return nullptr;
}

static const char *flow_m2(flow_t *w)
{
    if (deliver(w->pair.vt, w->pair.srv, &g_s, w->m1.bytes, w->m1.n) != rc_ok)
        return "the responder refused message 1";
    if (g_s.appends != 1u || g_s.ct_len != 0u)
        return "message 1 did not draw exactly one message 2 and no cleartext";
    w->m2 = take(&g_s);
    return nullptr;
}

static const char *flow_m3(flow_t *w)
{
    if (deliver(w->pair.vt, w->pair.cli, &g_c, w->m2.bytes, w->m2.n) != rc_ok)
        return "the initiator refused message 2";
    if (g_c.appends != 1u || g_c.ct_len != 0u)
        return "message 2 did not draw exactly one message 3 and no cleartext";
    w->m3 = take(&g_c);
    return nullptr;
}

static const char *flow_end(flow_t *w)
{
    if (deliver(w->pair.vt, w->pair.srv, &g_s, w->m3.bytes, w->m3.n) != rc_ok)
        return "the responder refused message 3";
    return g_s.appends == 0u && g_s.ct_len == 0u ? nullptr : "message 3 drew bytes or cleartext";
}

/** @brief Run the exchange up to and including @p upto messages 1 to 3 read. */
static const char *flow_to(flow_t *w, const duct_seal_engine_vtbl_t *vt, setup_t *s, unsigned upto)
{
    *w = (flow_t){};
    if (!pair_open(&w->pair, vt, s))
        return "the engines did not open";
    const char *err = flow_m1(w);
    if (!err && upto >= 1u)
        err = flow_m2(w);
    if (!err && upto >= 2u)
        err = flow_m3(w);
    if (!err && upto >= 3u)
        err = flow_end(w);
    return err;
}

/** @brief Seal @p text on @p from and have @p to open it. */
static const char *carry(const duct_seal_engine_vtbl_t *vt, duct_seal_engine_t *from, duct_seal_engine_t *to,
                         fake_t *f, const char *text)
{
    size_t n = strlen(text);
    size_t need = vt->seal_size(from, n);
    if (need == 0u || need > k_cap)
        return "seal_size answered an unusable byte count";
    static uint8_t sealed[4096];
    vt->seal(from, &((duct_view_u8){ (void *)text, n }), 1u, sealed);
    if (deliver(vt, to, f, sealed, need) != rc_ok)
        return "a sealed message was refused";
    return f->ct_len == n && memcmp(f->ct, text, n) == 0 ? nullptr : "a sealed message did not round-trip";
}

static const char *sc_exchange(const duct_seal_engine_vtbl_t *vt)
{
    setup_t s;
    flow_t w;
    if (!setup_open(&s))
        return "the setup did not open";
    if (!pair_open(&w.pair, vt, &s))
        return "the engines did not open";
    const char *err = nullptr;
    if (vt->seal_size(w.pair.cli, 8u) != 0u || vt->seal_size(w.pair.srv, 8u) != 0u)
        err = "seal_size answered before the exchange ended";
    if (!err)
        err = flow_m1(&w);
    if (!err)
        err = flow_m2(&w);
    if (!err && w.m2.n > w.m1.n)
        err = "message 2 is larger than the message 1 it answers";
    if (!err && vt->peer_identity(w.pair.srv).size != 0u)
        err = "the responder named its peer at message 1";
    if (!err)
        err = flow_m3(&w);
    duct_view_u8 id = vt->peer_identity(w.pair.cli);
    if (!err && (id.size != duct_noise_key_size || memcmp(id.data, s.ks.pub, id.size) != 0))
        err = "the initiator did not name the responder at message 3";
    if (!err && vt->peer_identity(w.pair.srv).size != 0u)
        err = "the responder named its peer before message 3 read";
    if (!err)
        err = flow_end(&w);
    id = vt->peer_identity(w.pair.srv);
    if (!err && (id.size != duct_noise_key_size + k_hello_len || memcmp(id.data, s.kc.pub, duct_noise_key_size) != 0
                 || memcmp((const uint8_t *)id.data + duct_noise_key_size, s.cli.hello, k_hello_len) != 0))
        err = "the responder did not name its peer by the key then the hello";
    if (!err && (s.hello_asked != 1u || s.verify_asked != 1u || s.psk_asked != 1u
                 || memcmp(s.hello_seen, s.cli.hello, k_hello_len) != 0))
        err = "the hello or the peer was not asked once";
    if (!err && (vt->seal_size(w.pair.cli, 8u) == 0u || vt->seal_size(w.pair.srv, 8u) == 0u))
        err = "seal_size still parks after the exchange";
    if (!err)
        err = carry(vt, w.pair.cli, w.pair.srv, &g_s, "from the initiator");
    if (!err)
        err = carry(vt, w.pair.srv, w.pair.cli, &g_c, "from the responder");
    pair_close(&w.pair);
    return err;
}

static const char *sc_hello(const duct_seal_engine_vtbl_t *vt)
{
    setup_t s;
    flow_t w;
    if (!setup_open(&s))
        return "the setup did not open";
    s.hello_good = false;
    const char *err = flow_to(&w, vt, &s, 0u);
    if (!err && deliver(vt, w.pair.srv, &g_s, w.m1.bytes, w.m1.n) != rc_invalid_arg)
        err = "a hello that hello_ok refused was answered";
    if (!err && (g_s.appends != 0u || s.hello_asked != 1u || s.verify_asked != 0u))
        err = "a refused hello drew bytes or reached the peer policy";
    pair_close(&w.pair);
    return err;
}

static const char *sc_peer(const duct_seal_engine_vtbl_t *vt)
{
    setup_t s;
    flow_t w;
    if (!setup_open(&s))
        return "the setup did not open";
    const char *err = flow_to(&w, vt, &s, 2u);
    s.peer_good = false;
    if (!err && deliver(vt, w.pair.srv, &g_s, w.m3.bytes, w.m3.n) != rc_invalid_arg)
        err = "a peer that verify_peer refused was taken";
    if (!err && (s.psk_asked != 0u || vt->peer_identity(w.pair.srv).size != 0u))
        err = "a refused peer reached the password lookup or was named";
    s.peer_good = true;
    if (!err)
        err = flow_end(&w);
    if (!err && s.psk_asked != 1u)
        err = "the password was not asked once the peer was admitted";
    pair_close(&w.pair);
    return err;
}

static const char *sc_password(const duct_seal_engine_vtbl_t *vt)
{
    setup_t s;
    flow_t w;
    if (!setup_open(&s))
        return "the setup did not open";
    s.cli.psk[0] ^= 0x01u;
    const char *err = flow_to(&w, vt, &s, 2u);
    if (!err && deliver(vt, w.pair.srv, &g_s, w.m3.bytes, w.m3.n) != rc_invalid_arg)
        err = "a message 3 made under another password was taken";
    if (!err && (s.psk_asked != 1u || vt->peer_identity(w.pair.srv).size != 0u))
        err = "a wrong password named the peer or skipped the lookup";
    pair_close(&w.pair);
    return err;
}

/** @brief Deliver @p to a copy of @p msg with one bit changed in each byte of its body in turn. The length prefix of a
 *  stream message is the wire's, which the engine never reads. */
static const char *bent(const duct_seal_engine_vtbl_t *vt, duct_seal_engine_t *to, fake_t *f, const msg_t *msg)
{
    msg_t bad = *msg;
    for (size_t at = vt->pdu_hdr_size; at < msg->n; ++at) {
        bad.bytes[at] ^= 0x01u;
        if (deliver(vt, to, f, bad.bytes, bad.n) == rc_ok)
            return "a message with one bit changed was taken";
        bad.bytes[at] ^= 0x01u;
    }
    return nullptr;
}

static const char *sc_forged(const duct_seal_engine_vtbl_t *vt)
{
    setup_t s;
    flow_t w;
    if (!setup_open(&s))
        return "the setup did not open";
    const char *err = flow_to(&w, vt, &s, 0u);
    if (!err)
        err = bent(vt, w.pair.srv, &g_s, &w.m1);
    if (!err)
        err = flow_m2(&w);
    if (!err)
        err = flow_m3(&w);
    pair_close(&w.pair);
    if (err)
        return err;

    if (!setup_open(&s))
        return "the setup did not open";
    err = flow_to(&w, vt, &s, 1u);
    if (!err)
        err = bent(vt, w.pair.cli, &g_c, &w.m2);
    if (!err)
        err = flow_m3(&w);
    pair_close(&w.pair);
    if (err)
        return err;

    if (!setup_open(&s))
        return "the setup did not open";
    err = flow_to(&w, vt, &s, 2u);
    if (!err)
        err = bent(vt, w.pair.srv, &g_s, &w.m3);
    if (!err)
        err = flow_end(&w);
    if (!err && vt->peer_identity(w.pair.srv).size == 0u)
        err = "the genuine message 3 did not name the peer";
    pair_close(&w.pair);
    return err;
}

static const char *sc_reorder(const duct_seal_engine_vtbl_t *vt)
{
    setup_t s;
    flow_t w;
    if (!setup_open(&s))
        return "the setup did not open";
    const char *err = flow_to(&w, vt, &s, 2u);
    static const char text[] = "overtakes message 3";
    size_t n = sizeof text - 1u;
    static uint8_t sealed[4096];
    size_t need = vt->seal_size(w.pair.cli, n);
    if (!err && (need == 0u || need > sizeof sealed))
        err = "seal_size answered an unusable byte count";
    if (!err) {
        vt->seal(w.pair.cli, &((duct_view_u8){ (void *)text, n }), 1u, sealed);
        if (deliver(vt, w.pair.srv, &g_s, sealed, need) != rc_invalid_arg || g_s.ct_len != 0u)
            err = "a data PDU ahead of message 3 was taken";
    }
    if (!err)
        err = flow_end(&w);
    if (!err && (deliver(vt, w.pair.srv, &g_s, sealed, need) != rc_ok || g_s.ct_len != n))
        err = "the data PDU was refused once message 3 had read";
    pair_close(&w.pair);
    return err;
}

static const char *sc_repeat(const duct_seal_engine_vtbl_t *vt)
{
    bool dgram = vt == duct_noise_vtbl_dgram();
    setup_t s;
    flow_t w;
    if (!setup_open(&s))
        return "the setup did not open";
    const char *err = flow_to(&w, vt, &s, 1u);
    for (unsigned i = 0u; !err && i < k_tries + 2u; ++i) {
        duct_result_t rc = deliver(vt, w.pair.srv, &g_s, w.m1.bytes, w.m1.n);
        if (!dgram) {
            if (rc != rc_invalid_arg)
                err = "a stream recognised a repeat of message 1";
            break;
        }
        bool resent = i < k_tries;
        if (rc != rc_ok || g_s.ct_len != 0u || g_s.appends != (resent ? 1u : 0u) || (resent && !same(&w.m2, &g_s)))
            err = resent ? "a repeat of message 1 did not draw message 2 again"
                         : "repeats of message 1 were answered past the cap";
    }
    if (!err && s.hello_asked != 1u)
        err = "a repeat of message 1 asked the hello again";
    if (!err)
        err = flow_m3(&w);
    for (unsigned i = 0u; !err && dgram && i < k_tries + 2u; ++i) {
        duct_result_t rc = deliver(vt, w.pair.cli, &g_c, w.m2.bytes, w.m2.n);
        bool resent = i < k_tries;
        if (rc != rc_ok || g_c.ct_len != 0u || g_c.appends != (resent ? 1u : 0u) || (resent && !same(&w.m3, &g_c)))
            err = resent ? "a repeat of message 2 did not draw message 3 again"
                         : "repeats of message 2 were answered past the cap";
    }
    if (!err && !dgram && deliver(vt, w.pair.cli, &g_c, w.m2.bytes, w.m2.n) == rc_ok)
        err = "a stream initiator took message 2 twice";
    if (!err)
        err = flow_end(&w);
    if (!err && dgram) {
        if (deliver(vt, w.pair.srv, &g_s, w.m3.bytes, w.m3.n) != rc_ok || g_s.appends != 0u || g_s.ct_len != 0u)
            err = "a repeat of message 3 after the end was not taken without a word";
        else if (deliver(vt, w.pair.srv, &g_s, w.m1.bytes, w.m1.n) != rc_ok || g_s.appends != 0u)
            err = "a repeat of message 1 after the end was not taken without a word";
        else {
            msg_t bad = w.m1;
            bad.bytes[bad.n - 1u] ^= 0x01u;
            if (deliver(vt, w.pair.srv, &g_s, bad.bytes, bad.n) == rc_ok)
                err = "a forged copy of message 1 passed for a repeat";
        }
    }
    if (!err && dgram) {
        err = carry(vt, w.pair.cli, w.pair.srv, &g_s, "the first authentic PDU");
        if (!err && deliver(vt, w.pair.srv, &g_s, w.m3.bytes, w.m3.n) == rc_ok)
            err = "a repeat of message 3 was taken after the peer's first authentic PDU";
        if (!err)
            err = carry(vt, w.pair.srv, w.pair.cli, &g_c, "the responder's first");
        if (!err && deliver(vt, w.pair.cli, &g_c, w.m2.bytes, w.m2.n) == rc_ok)
            err = "a repeat of message 2 was taken after the peer's first authentic PDU";
    }
    pair_close(&w.pair);
    return err;
}

/** @brief Rekey over an XKpsk3 exchange, @p settled telling whether each end has taken a PDU of the other's first. */
static const char *rekey_after(const duct_seal_engine_vtbl_t *vt, bool settled)
{
    setup_t s;
    flow_t w;
    if (!setup_open(&s))
        return "the setup did not open";
    const char *err = flow_to(&w, vt, &s, 3u);
    if (!err && settled)
        err = carry(vt, w.pair.srv, w.pair.cli, &g_c, "settles the first exchange");
    if (!err && settled)
        err = carry(vt, w.pair.cli, w.pair.srv, &g_s, "settles the other end");
    msg_t offer, answer;
    if (!err) {
        fake_reset(&g_c);
        if (vt->rekey(w.pair.cli, &g_c.base) != rc_ok || g_c.appends != 1u)
            err = "the initiator did not offer a rekey";
        offer = take(&g_c);
    }
    if (!err && (deliver(vt, w.pair.srv, &g_s, offer.bytes, offer.n) != rc_ok || g_s.appends != 1u))
        err = "the responder did not answer the rekey offer";
    if (!err) {
        answer = take(&g_s);
        if (deliver(vt, w.pair.cli, &g_c, answer.bytes, answer.n) != rc_ok)
            err = "the initiator did not take the answer";
    }
    duct_view_u8 id = vt->peer_identity(w.pair.srv);
    if (!err && (id.size != duct_noise_key_size + k_hello_len || memcmp(id.data, s.kc.pub, duct_noise_key_size) != 0))
        err = "the rekey changed the peer's identity";
    if (!err && s.psk_asked != 2u)
        err = "the rekey did not ask the password again";
    if (!err)
        err = carry(vt, w.pair.cli, w.pair.srv, &g_s, "under the fresh keys");
    if (!err)
        err = carry(vt, w.pair.srv, w.pair.cli, &g_c, "and back");
    pair_close(&w.pair);
    return err;
}

static const char *sc_rekey(const duct_seal_engine_vtbl_t *vt)
{
    const char *err = rekey_after(vt, true);
    return err ? err : rekey_after(vt, false);
}

static const char *sc_create(const duct_seal_engine_vtbl_t *vt)
{
    setup_t s;
    flow_t w;
    if (!setup_open(&s))
        return "the setup did not open";
    s.cli.suite.pattern = noise_pattern_count;
    if (vt->create(&s.cli, seal_role_initiator))
        return "an engine was made over a pattern past the last";
    s.cli.suite.pattern = noise_pattern_xkpsk3;
    if (!pair_open(&w.pair, vt, &s))
        return "the engines did not open";
    pair_close(&w.pair);
    for (unsigned upto = 0u; upto < 4u; ++upto) {
        const char *err = flow_to(&w, vt, &s, upto);
        pair_close(&w.pair);
        if (err)
            return err;
    }
    for (unsigned i = 0u; i < 64u; ++i) {
        const char *err = flow_to(&w, vt, &s, 1u);
        bool amplified = !err && w.m2.n > w.m1.n;
        pair_close(&w.pair);
        if (err || amplified)
            return err ? err : "message 2 exceeds the message 1 it answers";
    }
    return nullptr;
}

/** @brief Fire the initiator's retry by hand, as the worker does when its timer runs. */
static void fire(flow_t *w)
{
    fake_reset(&g_c);
    g_c.base.arm = f_arm;
    w->pair.vt->retry(w->pair.cli, &g_c.base);
}

/** @brief Fire the retry and answer whether it sent exactly @p want. */
static bool resent(flow_t *w, const msg_t *want)
{
    fire(w);
    return g_c.appends == 1u && same(want, &g_c);
}

static const char *sc_retry(const duct_seal_engine_vtbl_t *vt)
{
    bool dgram = vt == duct_noise_vtbl_dgram();
    setup_t s;
    flow_t w;
    if (!setup_open(&s))
        return "the setup did not open";
    s.cli.hs_rto_ms = k_rto_ms;
    const char *err = flow_to(&w, vt, &s, 0u);
    if (!err && g_c.arms != (dgram ? 1u : 0u))
        err = dgram ? "start did not arm the first resend" : "a stream armed a resend";
    if (!err && dgram && g_c.armed_ms != k_rto_ms)
        err = "the first resend was armed for another delay than hs_rto_ms";
    if (!err && !dgram && vt->retry)
        err = "the stream vtbl carries a retry";
    for (unsigned i = 1u; !err && dgram && i <= k_tries; ++i) {
        if (!resent(&w, &w.m1))
            err = "a retry did not send message 1 again";
        else if (g_c.arms != (i < k_tries ? 1u : 0u) || (i < k_tries && g_c.armed_ms != (uint32_t)k_rto_ms << i))
            err = "the delays did not double up to the cap";
    }
    if (!err && dgram) {
        fire(&w);
        if (g_c.appends != 0u || g_c.arms != 0u)
            err = "a retry past the cap sent or armed";
    }
    if (!err) {
        fake_reset(&g_s);
        g_s.base.arm = f_arm;
        vt->start(w.pair.srv, &g_s.base);
        if (g_s.arms != 0u || g_s.appends != 0u)
            err = "a responder started a resend";
    }
    pair_close(&w.pair);
    if (!err && dgram) {
        s.cli.hs_rto_ms = 0u;
        err = flow_to(&w, vt, &s, 0u);
        if (!err && g_c.arms != 0u)
            err = "hs_rto_ms of 0 armed a resend";
        pair_close(&w.pair);
    }
    return err;
}

/** @brief The exchange over a link that loses the first @p n copies of message @p lost, the initiator's retry fired
 *  by hand to replace each, then transport both ways. */
static const char *lossy(const duct_seal_engine_vtbl_t *vt, unsigned lost, unsigned n)
{
    setup_t s;
    flow_t w;
    if (!setup_open(&s))
        return "the setup did not open";
    s.cli.hs_rto_ms = k_rto_ms;
    const char *err = flow_to(&w, vt, &s, 0u);
    for (unsigned i = 0u; !err && lost == 1u && i < n; ++i) {
        if (!resent(&w, &w.m1))
            err = "a retry after a lost message 1 was not message 1 again";
    }
    if (!err)
        err = flow_m2(&w);
    for (unsigned i = 0u; !err && lost == 2u && i < n; ++i) {
        if (!resent(&w, &w.m1)
            || deliver(vt, w.pair.srv, &g_s, w.m1.bytes, w.m1.n) != rc_ok || g_s.appends != 1u || !same(&w.m2, &g_s))
            err = "a retry after a lost message 2 did not draw message 2 again";
    }
    if (!err)
        err = flow_m3(&w);
    for (unsigned i = 0u; !err && lost == 3u && i < n; ++i) {
        if (!resent(&w, &w.m3))
            err = "a retry after a lost message 3 was not message 3 again";
    }
    if (!err)
        err = flow_end(&w);
    if (!err && vt->peer_identity(w.pair.srv).size == 0u)
        err = "the responder was not named after the exchange";
    if (!err)
        err = carry(vt, w.pair.srv, w.pair.cli, &g_c, "the responder's first");
    if (!err)
        err = carry(vt, w.pair.cli, w.pair.srv, &g_s, "the initiator's first");
    if (!err) {
        fire(&w);
        if (g_c.appends != 0u || g_c.arms != 0u)
            err = "a retry after the peer's first authentic PDU sent or armed";
    }
    pair_close(&w.pair);
    return err;
}

static const char *sc_lossy(const duct_seal_engine_vtbl_t *vt)
{
    if (vt != duct_noise_vtbl_dgram())
        return nullptr;
    for (unsigned lost = 1u; lost <= 3u; ++lost)
        for (unsigned n = 1u; n <= 2u; ++n) {
            const char *err = lossy(vt, lost, n);
            if (err) {
                fprintf(stderr, "noise_xk_engine: message %u lost %u time(s)\n", lost, n);
                return err;
            }
        }
    return nullptr;
}

static const char *sc_silent(const duct_seal_engine_vtbl_t *vt)
{
    if (vt != duct_noise_vtbl_dgram())
        return nullptr;
    setup_t s;
    flow_t w;
    if (!setup_open(&s))
        return "the setup did not open";
    s.cli.hs_rto_ms = k_rto_ms;
    const char *err = flow_to(&w, vt, &s, 3u);
    for (unsigned i = 0u; !err && i < k_tries; ++i) {
        if (!resent(&w, &w.m3))
            err = "the initiator did not send message 3 again while the peer stayed silent";
        else if (deliver(vt, w.pair.srv, &g_s, w.m3.bytes, w.m3.n) != rc_ok || g_s.appends != 0u || g_s.ct_len != 0u)
            err = "a repeat of message 3 was not taken without a word";
    }
    if (!err) {
        fire(&w);
        if (g_c.appends != 0u)
            err = "the initiator sent message 3 past the cap";
    }
    msg_t offer = {};
    if (!err) {
        fake_reset(&g_c);
        if (vt->rekey(w.pair.cli, &g_c.base) != rc_ok || g_c.appends != 1u)
            err = "the initiator did not offer a rekey";
        offer = take(&g_c);
    }
    if (!err && (deliver(vt, w.pair.srv, &g_s, offer.bytes, offer.n) != rc_ok || g_s.appends != 1u))
        err = "repeats of message 3 spent the responder's rekey budget";
    pair_close(&w.pair);
    return err;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    static const struct { const char *name; const char *(*fn)(const duct_seal_engine_vtbl_t *); } cases[] = {
        { "exchange", sc_exchange },
        { "hello",    sc_hello },
        { "peer",     sc_peer },
        { "password", sc_password },
        { "forged",   sc_forged },
        { "reorder",  sc_reorder },
        { "repeat",   sc_repeat },
        { "retry",    sc_retry },
        { "lossy",    sc_lossy },
        { "silent",   sc_silent },
        { "rekey",    sc_rekey },
        { "create",   sc_create },
    };
    const duct_seal_engine_vtbl_t *vtbls[] = { duct_noise_vtbl(), duct_noise_vtbl_dgram() };
    static const char *const vnames[] = { "stream", "datagram" };
    for (size_t v = 0u; v < sizeof vtbls / sizeof vtbls[0]; ++v)
        for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
            auto err = cases[i].fn(vtbls[v]);
            if (err) {
                fprintf(stderr, "noise_xk_engine: %s, %s: %s\n", vnames[v], cases[i].name, err);
                return 1;
            }
        }
    printf("noise_xk_engine: OK (exchange, hello, peer, password, forged, reorder, repeat, retry, lossy, silent, "
           "rekey, create; stream and datagram, mask %s)\n", duct_handshake_mask ? "on" : "off");
    return 0;
}
