/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file noise_engine_test.c
 *  @brief Noise seal-engine contract, driven without a socket.
 *
 *  Both engine instances run in this process against a stand-in @c duct_unseal_ctx_t, so the
 *  initiator under test is the shipped one.
 *
 *  Covers: seal_size parking at 0 until the handshake ends, start emitting exactly one framed
 *  message 1, led by the opening packets the config's callback supplies, whole and within the
 *  context's ceiling, the responder answering with exactly one message 2 and no cleartext,
 *  cleartext round-tripping both ways, two spans sealing as one concatenated cleartext, a
 *  cleartext of more than one PDU in three spans cut at, before and after the PDU bound doing
 *  the same, and a flipped tag byte rejected as rc_invalid_arg.
 *
 *  Then confirmation: message 1 alone names no peer to the responder, the initiator's one empty
 *  PDU does; a recorded message 1 replayed to a fresh responder draws message 2, names nobody,
 *  and a second copy is refused; a data PDU overtaking a lost confirmation confirms the
 *  responder while sized 0, and the late confirmation is still accepted.
 *
 *  Then the rekey half: a fresh key set taking over while the one it replaces still carries
 *  traffic, an ordinary transport packet surviving the offer window, a dropped message 2 leaving
 *  the initiator able to offer again, the peer identity holding across the change, and an offer
 *  under another static key refused without disturbing the keys in use. The send counter, which
 *  resets on a split and travels in the clear, witnesses the change of keys.
 *
 *  Then the responder's rekey budget: a flood of replayed offers under another key bounds what
 *  one period costs, to the point of turning away a genuine offer as well, and the responder's
 *  own @c rekey restores it. Also checked: message 2 never exceeds the message 1 it answers, a
 *  responder survives a forged message 1 and still reads the genuine one, and a corrupted
 *  message 2 in the offer window is reported invalid while the genuine answer completes the
 *  rekey; a flood of corrupted answers turns the genuine one away too.
 *
 *  Last the responder's allowed list: a table of cases offers the initiator's message 1 to
 *  responders with no list, a list holding it among others, a list without it and a list of its
 *  key one bit off, each with no @c verify_peer, one that admits and one that refuses. A peer
 *  outside the list is refused with no message 2 before @c verify_peer is asked; any other is
 *  left to @c verify_peer.
 *
 *  All of it runs once per pattern. Under XKpsk3 message 3 stands where the confirmation does,
 *  naming the peer to the responder; a data PDU ahead of it is dropped and taken once it has
 *  read; and the allowed list and @c verify_peer are asked of message 3, message 1 being
 *  answered whatever the peer is.
 */

#include "duct_noise.h"
#include "duct_seal_engine.h"

#include <stdio.h>
#include <string.h>

static constexpr size_t ct_cap = 32768u;
static constexpr size_t tx_cap = 32768u;
/** Opening packets a fake context records, and the longest it keeps whole. */
static constexpr unsigned bare_cap = 16u;
static constexpr size_t   bare_max = 1500u;

typedef struct {
    duct_unseal_ctx_t base;
    uint8_t  ct[ct_cap];
    size_t   ct_len;
    uint8_t  tx[tx_cap];
    size_t   tx_len;
    unsigned bare_n,
             bare_before_framed,
             bare_refuse_from; /**< Packet count from which the context refuses. */
    size_t   bare_len[bare_cap];
    uint8_t  bare[bare_cap][bare_max];
} fake_ctx_t;

static void *s_reserve(duct_unseal_ctx_t *self, size_t *out_cap)
{
    auto f = (fake_ctx_t *)self;
    *out_cap = ct_cap - f->ct_len;
    return f->ct + f->ct_len;
}

static bool s_commit(duct_unseal_ctx_t *self, size_t len)
{
    auto f = (fake_ctx_t *)self;
    if (len > ct_cap - f->ct_len)
        return false;
    f->ct_len += len;
    return true;
}

static bool s_tx_append(duct_unseal_ctx_t *self, duct_view_u8 bytes)
{
    auto f = (fake_ctx_t *)self;
    if (f->tx_len + bytes.size > tx_cap)
        return false;
    if (!f->tx_len)
        f->bare_before_framed = f->bare_n;
    memcpy(f->tx + f->tx_len, bytes.data, bytes.size);
    f->tx_len += bytes.size;
    return true;
}

/** @brief Record one opening packet whole, until the context's refusal
 *  point. */
static bool s_tx_append_bare(duct_unseal_ctx_t *self, duct_view_u8 bytes)
{
    auto f = (fake_ctx_t *)self;
    if (f->bare_n >= f->bare_refuse_from || f->bare_n >= bare_cap || bytes.size > bare_max)
        return false;
    f->bare_len[f->bare_n] = bytes.size;
    memcpy(f->bare[f->bare_n], bytes.data, bytes.size);
    ++f->bare_n;
    return true;
}

static void s_ctx_reset(fake_ctx_t *f)
{
    f->base = (duct_unseal_ctx_t){ .reserve = s_reserve,
                                   .commit = s_commit,
                                   .tx_append = s_tx_append };
    f->ct_len = 0u;
    f->tx_len = 0u;
    f->bare_n = 0u;
    f->bare_before_framed = 0u;
    f->bare_refuse_from = ~0u;
}

static size_t s_framed_len(const duct_seal_engine_vtbl_t *vt,
                           const uint8_t *buf, size_t avail)
{
    if (avail < vt->pdu_hdr_size)
        return 0u;
    size_t total = vt->pdu_len((duct_view_u8){ .data = (void *)buf,
                                             .size = vt->pdu_hdr_size });
    return total <= avail ? total : 0u;
}

static uint64_t s_counter_of(const duct_seal_engine_vtbl_t *vt,
                             const uint8_t *sealed)
{
    uint64_t counter = 0u;
    for (unsigned i = 0u; i < 8u; ++i)
        counter |= (uint64_t)sealed[vt->pdu_hdr_size + i] << (8u * i);
    return counter;
}

/** @brief Seal a cleartext a little over one PDU long as three spans cut at, before and after the PDU bound,
 *  and read the PDUs back whole.
 *  @return the text of the first step that failed, nullptr when all passed. */
static const char *s_chunk_cuts(const duct_seal_engine_vtbl_t *vt, duct_seal_engine_t *from,
                                duct_seal_engine_t *to, fake_ctx_t *ctx)
{
    static constexpr size_t over = 700u;
    static uint8_t clear[16384u + over],
                   sealed[sizeof clear + 128u];
    size_t bound = vt->pdu_ct_max,
           total = bound + over;
    if (total > sizeof clear)
        return "the PDU bound outgrew the buffers of the span-cut case";
    for (size_t i = 0u; i < total; ++i)
        clear[i] = (uint8_t)(i * 31u + i / 251u);
    const size_t cuts[][2] = {
        { bound - 1u, 0u }, { bound, 0u }, { bound + 1u, 0u },
        { 1u, bound - 2u }, { 1u, bound - 1u }, { 1u, bound },
        { 4u, 0u }, { 0u, 4u }, { total, 0u },
    };
    for (size_t c = 0u; c < sizeof cuts / sizeof cuts[0]; ++c) {
        size_t first = cuts[c][0],
               middle = cuts[c][1];
        duct_view_u8 spans[3] = {
            { .data = clear, .size = first },
            { .data = clear + first, .size = middle },
            { .data = clear + first + middle, .size = total - first - middle },
        };
        size_t need = vt->seal_size(from, total);
        if (need == 0u || need > sizeof sealed)
            return "seal_size answered an unusable byte count for a cleartext of more than one PDU";
        vt->seal(from, spans, 3u, sealed);
        s_ctx_reset(ctx);
        size_t off = 0u,
               pdu = s_framed_len(vt, sealed, need);
        for (; pdu != 0u; off += pdu, pdu = s_framed_len(vt, sealed + off, need - off))
            if (vt->unseal(to, duct_view(duct_view_u8, sealed + off, pdu), &ctx->base) != rc_ok)
                return "a PDU of a cleartext of more than one PDU was refused";
        if (off != need || ctx->ct_len != total || memcmp(ctx->ct, clear, total) != 0)
            return "spans cut around a PDU bound did not seal as one concatenated cleartext";
    }
    return nullptr;
}

static const char *s_run(duct_noise_pattern_t pattern)
{
    auto vt = duct_noise_vtbl();
    if (!vt || !vt->pdu_len || vt->pdu_hdr_size == 0u)
        return "vtbl is missing its framing half";

    duct_noise_keypair_t srv_kp, cli_kp;
    if (!duct_noise_keypair_generate(&srv_kp)
        || !duct_noise_keypair_generate(&cli_kp))
        return "keypair generation failed";

    duct_noise_cfg_t srv_cfg = {}, cli_cfg = {};
    srv_cfg.local_static = srv_kp;
    cli_cfg.local_static = cli_kp;
    srv_cfg.suite.pattern = cli_cfg.suite.pattern = pattern;
    memcpy(cli_cfg.remote_static_pub, srv_kp.pub, duct_noise_key_size);

    auto srv = vt->create(&srv_cfg, seal_role_responder);
    auto cli = vt->create(&cli_cfg, seal_role_initiator);
    if (!srv || !cli)
        return "engine create failed";

    const char *err = nullptr;
    static fake_ctx_t sctx, cctx;
    s_ctx_reset(&sctx);
    s_ctx_reset(&cctx);

    for (unsigned i = 0u; i < 64u; ++i) {
        auto a = vt->create(&srv_cfg, seal_role_responder);
        auto b = vt->create(&cli_cfg, seal_role_initiator);
        if (!a || !b) {
            if (a)
                vt->destroy(a);
            if (b)
                vt->destroy(b);
            err = "engine create failed";
            goto done;
        }
        static fake_ctx_t actx, bctx;
        s_ctx_reset(&actx);
        s_ctx_reset(&bctx);
        vt->start(b, &bctx.base);
        size_t m1 = s_framed_len(vt, bctx.tx, bctx.tx_len);
        bool keyed_a = m1 != 0u
            && vt->unseal(a, duct_view(duct_view_u8, bctx.tx, m1), &actx.base) == rc_ok;
        size_t m2 = keyed_a ? s_framed_len(vt, actx.tx, actx.tx_len) : 0u;
        vt->destroy(a);
        vt->destroy(b);
        if (!keyed_a || m2 == 0u) {
            err = "amplification probe handshake failed";
            goto done;
        }
        if (m2 > m1) {
            err = "message 2 can exceed the message 1 it answers (amplification)";
            goto done;
        }
    }

    if (vt->seal_size(cli, 8u) != 0u || vt->seal_size(srv, 8u) != 0u) {
        err = "seal_size answered non-zero before the handshake finished";
        goto done;
    }

    vt->start(cli, &cctx.base);
    size_t msg1 = s_framed_len(vt, cctx.tx, cctx.tx_len);
    if (msg1 == 0u || msg1 != cctx.tx_len) {
        err = "start did not emit exactly one framed message 1";
        goto done;
    }
    static uint8_t recorded[512];
    if (msg1 > sizeof recorded) {
        err = "message 1 does not fit the test's own buffer";
        goto done;
    }
    memcpy(recorded, cctx.tx, msg1);
    if (vt->unseal(srv, duct_view(duct_view_u8, cctx.tx, msg1), &sctx.base)
        != rc_ok) {
        err = "responder rejected message 1";
        goto done;
    }
    size_t msg2 = s_framed_len(vt, sctx.tx, sctx.tx_len);
    if (msg2 == 0u || msg2 != sctx.tx_len || sctx.ct_len != 0u) {
        err = "responder did not answer message 1 with exactly one message 2";
        goto done;
    }
    if (vt->peer_identity(srv).size != 0u) {
        err = "the responder named its peer on message 1 alone";
        goto done;
    }
    s_ctx_reset(&cctx);
    if (vt->unseal(cli, duct_view(duct_view_u8, sctx.tx, msg2), &cctx.base)
        != rc_ok) {
        err = "initiator rejected message 2";
        goto done;
    }
    size_t confirm = s_framed_len(vt, cctx.tx, cctx.tx_len);
    if (confirm == 0u || confirm != cctx.tx_len) {
        err = "the initiator did not confirm its keys with exactly one PDU";
        goto done;
    }
    s_ctx_reset(&sctx);
    if (vt->unseal(srv, duct_view(duct_view_u8, cctx.tx, confirm), &sctx.base)
        != rc_ok
        || sctx.ct_len != 0u || vt->peer_identity(srv).size != duct_noise_key_size) {
        err = "the initiator's confirmation did not name the peer to the responder";
        goto done;
    }

    auto replayed = vt->create(&srv_cfg, seal_role_responder);
    if (!replayed) {
        err = "engine create failed";
        goto done;
    }
    static fake_ctx_t rctx;
    s_ctx_reset(&rctx);
    bool answered = vt->unseal(replayed, duct_view(duct_view_u8, recorded, msg1),
                               &rctx.base) == rc_ok;
    s_ctx_reset(&rctx);
    bool reoffer_refused = vt->unseal(replayed, duct_view(duct_view_u8, recorded, msg1),
                                      &rctx.base) == rc_invalid_arg;
    bool named = vt->peer_identity(replayed).size != 0u;
    vt->destroy(replayed);
    if (!answered || !reoffer_refused || named) {
        err = "a replayed message 1 named its peer to a fresh responder";
        goto done;
    }

    auto hardy = vt->create(&srv_cfg, seal_role_responder);
    if (!hardy) {
        err = "engine create failed";
        goto done;
    }
    static fake_ctx_t hctx;
    static uint8_t forged1[512];
    memcpy(forged1, recorded, msg1);
    forged1[msg1 - 1u] ^= 0xFFu;
    s_ctx_reset(&hctx);
    bool forged_rejected = vt->unseal(hardy, duct_view(duct_view_u8, forged1, msg1),
                                      &hctx.base) == rc_invalid_arg;
    s_ctx_reset(&hctx);
    bool genuine_after = vt->unseal(hardy, duct_view(duct_view_u8, recorded, msg1),
                                    &hctx.base) == rc_ok
                      && s_framed_len(vt, hctx.tx, hctx.tx_len) != 0u;
    vt->destroy(hardy);
    if (!forged_rejected || !genuine_after) {
        err = "a forged message 1 left the responder unable to read the genuine one";
        goto done;
    }

    if (vt->seal_size(cli, 8u) == 0u || vt->seal_size(srv, 8u) == 0u) {
        err = "seal_size still parks after the handshake finished";
        goto done;
    }

    static const char payload[] = "noise round trip";
    size_t pt_len = sizeof payload - 1u;
    static uint8_t sealed[4096];
    size_t need = vt->seal_size(cli, pt_len);
    if (need == 0u || need > sizeof sealed) {
        err = "seal_size answered an unusable byte count";
        goto done;
    }
    vt->seal(cli, &((duct_view_u8){ (void *)payload, pt_len }), 1u,
             sealed);
    if (s_framed_len(vt, sealed, need) != need) {
        err = "seal wrote a length prefix that disagrees with seal_size";
        goto done;
    }
    s_ctx_reset(&sctx);
    if (vt->unseal(srv, duct_view(duct_view_u8, sealed, need), &sctx.base)
        != rc_ok) {
        err = "responder rejected a sealed transport message";
        goto done;
    }
    if (sctx.ct_len != pt_len || memcmp(sctx.ct, payload, pt_len) != 0) {
        err = "round-tripped cleartext does not match";
        goto done;
    }

    auto lost = vt->create(&srv_cfg, seal_role_responder);
    auto dialer = vt->create(&cli_cfg, seal_role_initiator);
    if (!lost || !dialer) {
        if (lost)
            vt->destroy(lost);
        if (dialer)
            vt->destroy(dialer);
        err = "engine create failed";
        goto done;
    }
    static fake_ctx_t lctx, dctx;
    s_ctx_reset(&dctx);
    vt->start(dialer, &dctx.base);
    s_ctx_reset(&lctx);
    bool keyed = vt->unseal(lost, duct_view(duct_view_u8, dctx.tx, dctx.tx_len),
                            &lctx.base) == rc_ok;
    s_ctx_reset(&dctx);
    keyed = keyed
         && vt->unseal(dialer, duct_view(duct_view_u8, lctx.tx, lctx.tx_len),
                       &dctx.base) == rc_ok;
    size_t first = keyed ? vt->seal_size(dialer, pt_len) : 0u;
    bool sealed_first = first != 0u && first <= sizeof sealed;
    if (sealed_first)
        vt->seal(dialer, &((duct_view_u8){ (void *)payload, pt_len }), 1u,
                 sealed);
    duct_view_u8 data_pdu = { .data = sealed, .size = first };
    bool xk = pattern == noise_pattern_xkpsk3;
    bool unsized = sealed_first && vt->unseal_size(lost, data_pdu) == 0u;
    s_ctx_reset(&lctx);
    bool carried = unsized
        && (xk ? vt->unseal(lost, data_pdu, &lctx.base) == rc_invalid_arg && lctx.ct_len == 0u
               : vt->unseal(lost, data_pdu, &lctx.base) == rc_ok
                 && lctx.ct_len == pt_len && memcmp(lctx.ct, payload, pt_len) == 0);
    bool confirmed = xk ? vt->peer_identity(lost).size == 0u
                        : vt->peer_identity(lost).size == duct_noise_key_size
                          && vt->unseal_size(lost, data_pdu) == pt_len;
    s_ctx_reset(&lctx);
    bool late_ok = vt->unseal(lost, duct_view(duct_view_u8, dctx.tx, dctx.tx_len),
                              &lctx.base) == rc_ok
                && lctx.ct_len == 0u;
    if (late_ok && xk) {
        s_ctx_reset(&lctx);
        late_ok = vt->unseal(lost, data_pdu, &lctx.base) == rc_ok
               && lctx.ct_len == pt_len && memcmp(lctx.ct, payload, pt_len) == 0;
    }
    vt->destroy(lost);
    vt->destroy(dialer);
    if (!keyed || !unsized || !carried || !confirmed || !late_ok) {
        err = xk ? "a data PDU overtaking message 3 was taken, sized early, or refused "
                   "once message 3 had read"
                 : "a data PDU overtaking a lost confirmation was sized early or did not "
                   "confirm the responder";
        goto done;
    }

    static const char hdr[] = "HDR";
    size_t hdr_len = sizeof hdr - 1u;
    duct_view_u8 two[2] = {
        { .data = (void *)hdr, .size = hdr_len },
        { .data = (void *)payload, .size = pt_len },
    };
    need = vt->seal_size(cli, hdr_len + pt_len);
    if (need == 0u || need > sizeof sealed) {
        err = "seal_size answered an unusable byte count for two spans";
        goto done;
    }
    vt->seal(cli, two, 2u, sealed);
    s_ctx_reset(&sctx);
    if (vt->unseal(srv, duct_view(duct_view_u8, sealed, need), &sctx.base)
        != rc_ok
        || sctx.ct_len != hdr_len + pt_len
        || memcmp(sctx.ct, hdr, hdr_len) != 0
        || memcmp(sctx.ct + hdr_len, payload, pt_len) != 0) {
        err = "two spans did not seal as one concatenated cleartext";
        goto done;
    }

    err = s_chunk_cuts(vt, cli, srv, &sctx);
    if (err)
        goto done;

    need = vt->seal_size(srv, pt_len);
    vt->seal(srv, &((duct_view_u8){ (void *)payload, pt_len }), 1u,
             sealed);
    s_ctx_reset(&cctx);
    if (vt->unseal(cli, duct_view(duct_view_u8, sealed, need), &cctx.base)
        != rc_ok
        || cctx.ct_len != pt_len || memcmp(cctx.ct, payload, pt_len) != 0) {
        err = "reverse-direction round trip failed";
        goto done;
    }

    sealed[need - 1u] ^= 0xFFu;
    s_ctx_reset(&cctx);
    if (vt->unseal(cli, duct_view(duct_view_u8, sealed, need), &cctx.base)
        != rc_invalid_arg) {
        err = "a tampered tag was not rejected";
        goto done;
    }

    if (!vt->rekey) {
        err = "vtbl declares no rekey";
        goto done;
    }
    uint8_t cli_seen[duct_noise_key_size], srv_seen[duct_noise_key_size];
    auto id_srv = vt->peer_identity(srv);
    auto id_cli = vt->peer_identity(cli);
    if (id_srv.size != duct_noise_key_size || id_cli.size != duct_noise_key_size) {
        err = "peer identity is not held before the rekey";
        goto done;
    }
    memcpy(cli_seen, id_srv.data, duct_noise_key_size);
    memcpy(srv_seen, id_cli.data, duct_noise_key_size);

    need = vt->seal_size(cli, pt_len);
    vt->seal(cli, &((duct_view_u8){ (void *)payload, pt_len }), 1u,
             sealed);
    uint64_t counter_before = s_counter_of(vt, sealed);
    s_ctx_reset(&sctx);
    if (counter_before == 0u
        || vt->unseal(srv, duct_view(duct_view_u8, sealed, need),
                      &sctx.base) != rc_ok) {
        err = "the pre-rekey counter is not a usable witness";
        goto done;
    }

    s_ctx_reset(&cctx);
    vt->rekey(cli, &cctx.base);
    size_t re1 = s_framed_len(vt, cctx.tx, cctx.tx_len);
    if (re1 == 0u || re1 != cctx.tx_len) {
        err = "rekey did not emit exactly one framed message 1";
        goto done;
    }
    static uint8_t offered[512];
    if (re1 > sizeof offered) {
        err = "message 1 does not fit the test's own buffer";
        goto done;
    }
    memcpy(offered, cctx.tx, re1);

    s_ctx_reset(&sctx);
    if (vt->unseal(srv, duct_view(duct_view_u8, offered, re1), &sctx.base)
        != rc_ok || s_framed_len(vt, sctx.tx, sctx.tx_len) == 0u) {
        err = "responder did not answer the offer whose answer gets dropped";
        goto done;
    }
    s_ctx_reset(&cctx);
    vt->rekey(cli, &cctx.base);
    re1 = s_framed_len(vt, cctx.tx, cctx.tx_len);
    if (re1 == 0u || re1 != cctx.tx_len) {
        err = "a lost message 2 left the initiator unable to offer again";
        goto done;
    }
    if (re1 > sizeof offered) {
        err = "message 1 does not fit the test's own buffer";
        goto done;
    }
    memcpy(offered, cctx.tx, re1);

    static const char msg2_sized[] = "twenty-four bytes here..";
    size_t decoy_len = sizeof msg2_sized - 1u;
    need = vt->seal_size(srv, decoy_len);
    vt->seal(srv, &((duct_view_u8){ (void *)msg2_sized, decoy_len }),
             1u, sealed);
    s_ctx_reset(&cctx);
    if (vt->unseal(cli, duct_view(duct_view_u8, sealed, need), &cctx.base)
        != rc_ok
        || cctx.ct_len != decoy_len
        || memcmp(cctx.ct, msg2_sized, decoy_len) != 0) {
        err = "an ordinary packet the size of message 2 broke the rekey window";
        goto done;
    }

    s_ctx_reset(&sctx);
    if (vt->unseal(srv, duct_view(duct_view_u8, offered, re1), &sctx.base)
        != rc_ok) {
        err = "responder rejected a rekey message 1 on an established session";
        goto done;
    }
    size_t re2 = s_framed_len(vt, sctx.tx, sctx.tx_len);
    if (re2 == 0u || re2 != sctx.tx_len || sctx.ct_len != 0u) {
        err = "responder did not answer a rekey with exactly one message 2";
        goto done;
    }
    static uint8_t junk2[512];
    if (re2 > sizeof junk2) {
        err = "message 2 does not fit the test's own buffer";
        goto done;
    }
    memcpy(junk2, sctx.tx, re2);
    junk2[re2 - 1u] ^= 0xFFu;
    s_ctx_reset(&cctx);
    if (vt->unseal(cli, duct_view(duct_view_u8, junk2, re2), &cctx.base)
        != rc_invalid_arg) {
        err = "a corrupted message 2 in the offer window was not reported invalid";
        goto done;
    }
    s_ctx_reset(&cctx);
    if (vt->unseal(cli, duct_view(duct_view_u8, sctx.tx, re2), &cctx.base)
        != rc_ok || cctx.ct_len != 0u) {
        err = "initiator rejected its own rekey message 2";
        goto done;
    }

    need = vt->seal_size(srv, pt_len);
    vt->seal(srv, &((duct_view_u8){ (void *)payload, pt_len }), 1u,
             sealed);
    s_ctx_reset(&cctx);
    if (vt->unseal(cli, duct_view(duct_view_u8, sealed, need), &cctx.base)
        != rc_ok
        || cctx.ct_len != pt_len || memcmp(cctx.ct, payload, pt_len) != 0) {
        err = "the keys in use before the rekey stopped carrying traffic";
        goto done;
    }

    need = vt->seal_size(cli, pt_len);
    vt->seal(cli, &((duct_view_u8){ (void *)payload, pt_len }), 1u,
             sealed);
    if (s_counter_of(vt, sealed) >= counter_before) {
        err = "the initiator kept sealing under the keys it just replaced";
        goto done;
    }
    s_ctx_reset(&sctx);
    if (vt->unseal(srv, duct_view(duct_view_u8, sealed, need), &sctx.base)
        != rc_ok
        || sctx.ct_len != pt_len || memcmp(sctx.ct, payload, pt_len) != 0) {
        err = "the fresh keys did not carry the initiator's first message";
        goto done;
    }

    need = vt->seal_size(srv, pt_len);
    vt->seal(srv, &((duct_view_u8){ (void *)payload, pt_len }), 1u,
             sealed);
    s_ctx_reset(&cctx);
    if (vt->unseal(cli, duct_view(duct_view_u8, sealed, need), &cctx.base)
        != rc_ok
        || cctx.ct_len != pt_len || memcmp(cctx.ct, payload, pt_len) != 0) {
        err = "the fresh keys did not carry the responder's first message";
        goto done;
    }

    id_srv = vt->peer_identity(srv);
    id_cli = vt->peer_identity(cli);
    if (id_srv.size != duct_noise_key_size || id_cli.size != duct_noise_key_size
        || memcmp(id_srv.data, cli_seen, duct_noise_key_size) != 0
        || memcmp(id_cli.data, srv_seen, duct_noise_key_size) != 0) {
        err = "the rekey moved the peer identity";
        goto done;
    }

    duct_noise_keypair_t evil_kp;
    if (!duct_noise_keypair_generate(&evil_kp)) {
        err = "keypair generation failed";
        goto done;
    }
    duct_noise_cfg_t evil_cfg = {};
    evil_cfg.local_static = evil_kp;
    memcpy(evil_cfg.remote_static_pub, srv_kp.pub, duct_noise_key_size);
    auto evil = vt->create(&evil_cfg, seal_role_initiator);
    if (!evil) {
        err = "engine create failed";
        goto done;
    }
    static fake_ctx_t ectx;
    s_ctx_reset(&ectx);
    vt->start(evil, &ectx.base);
    size_t evil1 = s_framed_len(vt, ectx.tx, ectx.tx_len);
    s_ctx_reset(&sctx);
    bool refused = evil1 != 0u
        && vt->unseal(srv, duct_view(duct_view_u8, ectx.tx, evil1),
                      &sctx.base) == rc_invalid_arg;
    vt->destroy(evil);
    if (!refused) {
        err = "a rekey under another static key was adopted";
        goto done;
    }

    need = vt->seal_size(cli, pt_len);
    vt->seal(cli, &((duct_view_u8){ (void *)payload, pt_len }), 1u,
             sealed);
    s_ctx_reset(&sctx);
    if (vt->unseal(srv, duct_view(duct_view_u8, sealed, need), &sctx.base)
        != rc_ok
        || sctx.ct_len != pt_len || memcmp(sctx.ct, payload, pt_len) != 0) {
        err = "a refused rekey disturbed the keys in use";
        goto done;
    }

    for (unsigned i = 0u; i < 16u; ++i) {
        s_ctx_reset(&sctx);
        if (vt->unseal(srv, duct_view(duct_view_u8, ectx.tx, evil1),
                       &sctx.base) != rc_invalid_arg) {
            err = "a replayed offer under another key was adopted";
            goto done;
        }
    }
    s_ctx_reset(&cctx);
    vt->rekey(cli, &cctx.base);
    size_t starved = s_framed_len(vt, cctx.tx, cctx.tx_len);
    s_ctx_reset(&sctx);
    if (starved == 0u
        || vt->unseal(srv, duct_view(duct_view_u8, cctx.tx, starved),
                      &sctx.base) != rc_invalid_arg) {
        err = "a flood of bad offers did not bound what one period costs";
        goto done;
    }

    s_ctx_reset(&sctx);
    vt->rekey(srv, &sctx.base);
    if (sctx.tx_len != 0u) {
        err = "a responder answered its own cadence with an offer";
        goto done;
    }
    s_ctx_reset(&cctx);
    vt->rekey(cli, &cctx.base);
    size_t again = s_framed_len(vt, cctx.tx, cctx.tx_len);
    s_ctx_reset(&sctx);
    if (again == 0u
        || vt->unseal(srv, duct_view(duct_view_u8, cctx.tx, again),
                      &sctx.base) != rc_ok) {
        err = "the next period did not restore the responder's rekey budget";
        goto done;
    }

    size_t cap_re2 = s_framed_len(vt, sctx.tx, sctx.tx_len);
    static uint8_t capjunk[512];
    if (cap_re2 == 0u || cap_re2 > sizeof capjunk) {
        err = "the rekey answer does not fit the test's own buffer";
        goto done;
    }
    for (unsigned i = 0u; i < 8u; ++i) {
        memcpy(capjunk, sctx.tx, cap_re2);
        capjunk[cap_re2 - 1u] ^= 0xFFu;
        s_ctx_reset(&cctx);
        if (vt->unseal(cli, duct_view(duct_view_u8, capjunk, cap_re2), &cctx.base)
            != rc_invalid_arg) {
            err = "a corrupted rekey answer was not refused";
            goto done;
        }
    }
    s_ctx_reset(&cctx);
    if (vt->unseal(cli, duct_view(duct_view_u8, sctx.tx, cap_re2), &cctx.base)
        != rc_invalid_arg) {
        err = "a flood of corrupted answers did not bound the initiator's msg2 budget";
        goto done;
    }

done:
    vt->destroy(srv);
    vt->destroy(cli);
    return err;
}

/** Lengths of the packets the test source hands out, in order. The longest is
 *  the room the contexts below offer, the shortest a single byte. */
static const size_t s_open_len[] = { 20u, 96u, 1u, 600u, 1452u };
static constexpr unsigned open_lens = sizeof s_open_len / sizeof *s_open_len;

/** @brief Byte @p j of the test source's packet @p idx under @p tag. */
static uint8_t s_open_byte(uint8_t tag, unsigned idx, size_t j)
{
    return (uint8_t)(tag + 41u * idx + 3u * j);
}

/** @brief What the test source was asked and how it answers. */
typedef struct {
    uint8_t  tag;   /**< Seeds the bytes it writes. */
    unsigned count, /**< Packets it hands out before the 0 that ends them. */
             calls, /**< Times the engine asked. */
             skew;  /**< Asks whose index was not the number of asks before it. */
    size_t   room;  /**< The room the last ask offered. */
} open_src_t;

static open_src_t s_src;

/** @brief The @c opening_next under test: a fixed length table, bytes from
 *  @c s_open_byte, and for a packet longer than @p cap its length alone. */
static size_t s_open_next(void *ctx, unsigned idx, uint8_t *out, size_t cap)
{
    auto src = (open_src_t *)ctx;
    src->skew += idx != src->calls;
    ++src->calls;
    src->room = cap;
    if (idx >= src->count)
        return 0u;
    size_t n = s_open_len[idx % open_lens];
    for (size_t j = 0u; j < n && n <= cap; ++j)
        out[j] = s_open_byte(src->tag, idx, j);
    return n;
}

/** @brief One start of an engine over the source, and what it must stage. */
typedef struct {
    const char       *name;
    duct_seal_role_t  role;
    size_t            ceiling;     /**< The context's @c opening_ceiling. */
    bool              bare_path,   /**< The context takes opening packets. */
                      callback;    /**< The config names the source. */
    unsigned          count,       /**< Packets the source has before its 0. */
                      refuse_from, /**< Staged count at which the context refuses. */
                      staged,      /**< Packets that must reach the context. */
                      calls;       /**< Asks the engine must make of the source. */
} open_case_t;

static const open_case_t s_open_cases[] = {
    { "a full opening",           seal_role_initiator, 1452u,  true,  true, 5u, ~0u, 5u, 6u },
    { "a room under the longest", seal_role_initiator,   96u,  true,  true, 5u, ~0u, 3u, 4u },
    { "a ceiling past the pdu",   seal_role_initiator, 65535u, true,  true, 5u, ~0u, 5u, 6u },
    { "an empty opening",         seal_role_initiator, 1452u,  true,  true, 0u, ~0u, 0u, 1u },
    { "a refusing context",       seal_role_initiator, 1452u,  true,  true, 5u,  2u, 2u, 3u },
    { "no room",                  seal_role_initiator,    0u,  true,  true, 5u, ~0u, 0u, 0u },
    { "no bare path",             seal_role_initiator, 1452u,  false, true, 5u, ~0u, 0u, 0u },
    { "no callback",              seal_role_initiator, 1452u,  true,  false, 5u, ~0u, 0u, 0u },
    { "a responder",              seal_role_responder, 1452u,  true,  true, 5u, ~0u, 0u, 0u },
};

/** @brief Check @p f holds packets 0 to @p n - 1 of a source seeded with
 *  @p tag, byte for byte, all of them staged before message 1.
 *  @return nullptr when it does, else what failed. */
static const char *s_open_staged(const fake_ctx_t *f, uint8_t tag, unsigned n)
{
    if (f->bare_n != n)
        return "the engine staged other packets than the source supplied";
    for (unsigned i = 0u; i < n; ++i) {
        if (f->bare_len[i] != s_open_len[i % open_lens])
            return "a staged packet's length changed in the engine";
        for (size_t j = 0u; j < f->bare_len[i]; ++j)
            if (f->bare[i][j] != s_open_byte(tag, i, j))
                return "a staged packet's bytes changed in the engine";
    }
    return f->bare_before_framed == f->bare_n ? nullptr : "a packet followed message 1";
}

/** @brief Start a fresh engine as @p c says and check what it staged and asked.
 *  @return nullptr when it held, else what failed. */
static const char *s_open_case(const duct_seal_engine_vtbl_t *vt, const duct_noise_cfg_t *cfg,
                               const open_case_t *c, uint8_t tag)
{
    static fake_ctx_t f;
    s_ctx_reset(&f);
    f.base.opening_ceiling = (uint16_t)c->ceiling;
    f.base.tx_append_bare = c->bare_path ? s_tx_append_bare : nullptr;
    f.bare_refuse_from = c->refuse_from;
    s_src = (open_src_t){ .tag = tag, .count = c->count };
    duct_noise_cfg_t use = *cfg;
    if (!c->callback)
        use.opening_next = nullptr;
    auto e = vt->create(&use, c->role);
    if (!e)
        return "engine create failed";
    vt->start(e, &f.base);
    vt->destroy(e);

    if (c->role == seal_role_responder) {
        if (f.tx_len)
            return "a responder emitted at start";
    } else {
        size_t msg1 = s_framed_len(vt, f.tx, f.tx_len);
        if (msg1 == 0u || msg1 != f.tx_len)
            return "start did not emit exactly one framed message 1";
    }
    size_t room = c->ceiling < vt->pdu_ct_max ? c->ceiling : vt->pdu_ct_max;
    if (s_src.calls != c->calls)
        return "the engine asked the source a number of times other than its packets plus one";
    if (s_src.skew)
        return "the engine did not number the source's packets from 0";
    if (c->calls && s_src.room != room)
        return "the engine offered the source other room than the ceiling within its buffer";
    return s_open_staged(&f, tag, c->staged);
}

/** @brief Run every opening case under two seeds, which two starts of one config
 *  differ by. */
static const char *s_opening(duct_noise_pattern_t pattern)
{
    auto vt = duct_noise_vtbl();
    duct_noise_keypair_t srv_kp, cli_kp;
    if (!duct_noise_keypair_generate(&srv_kp) || !duct_noise_keypair_generate(&cli_kp))
        return "keypair generation failed";
    duct_noise_cfg_t cfg = { .local_static = cli_kp,
                             .opening_next = s_open_next,
                             .opening_ctx = &s_src,
                             .suite.pattern = pattern };
    memcpy(cfg.remote_static_pub, srv_kp.pub, duct_noise_key_size);
    static const uint8_t tags[] = { 0x11u, 0x77u };
    for (unsigned t = 0u; t < sizeof tags; ++t)
        for (unsigned i = 0u; i < sizeof s_open_cases / sizeof *s_open_cases; ++i) {
            auto err = s_open_case(vt, &cfg, &s_open_cases[i], tags[t]);
            if (err) {
                fprintf(stderr, "noise_engine: opening case \"%s\", seed %02x\n",
                        s_open_cases[i].name, (unsigned)tags[t]);
                return err;
            }
        }
    return nullptr;
}

/** @brief What a case's @c verify_peer answers, or that it names none. */
typedef enum : uint8_t {
    verify_none,
    verify_admits,
    verify_refuses,
} verify_t;

/** @brief What the counting @c verify_peer is asked and how it answers. */
typedef struct {
    unsigned asked; /**< Times it was asked. */
    bool     admits; /**< Its answer. */
} verify_state_t;

/** @brief The @c verify_peer under test: count the ask, answer as the state says. */
static bool s_verify_counting(void *ctx, [[maybe_unused]] const uint8_t peer[duct_noise_key_size])
{
    auto state = (verify_state_t *)ctx;
    ++state->asked;
    return state->admits;
}

/** @brief One responder configuration and what it must do with the initiator's message 1. */
typedef struct {
    const char *name;
    unsigned    first,    /**< Entry of the key table the list starts at. */
                n,        /**< Entries in the list, 0 for none. */
                asked;    /**< Times @c verify_peer must be asked. */
    verify_t    verify;
    bool        admitted; /**< Whether message 1 must be answered. */
} allowed_case_t;

/** The key table: another peer's key, the initiator's, and the initiator's with
 *  its last bit flipped. */
static const allowed_case_t s_allowed_cases[] = {
    { "no list, no callback",              0u, 0u, 0u, verify_none,    true  },
    { "no list, a callback that admits",   0u, 0u, 1u, verify_admits,  true  },
    { "no list, a callback that refuses",  0u, 0u, 1u, verify_refuses, false },
    { "the peer among others",             0u, 3u, 1u, verify_admits,  true  },
    { "a peer outside the list",           0u, 1u, 0u, verify_admits,  false },
    { "a key one bit off",                 2u, 1u, 0u, verify_admits,  false },
    { "the peer, a callback that refuses", 1u, 1u, 1u, verify_refuses, false },
};

/** @brief Offer the initiator's message 1 to a responder configured as @p c says; under XKpsk3
 *  message 1 is answered whatever the peer is, and message 3 is what the case decides.
 *  @return nullptr when the offer was answered or refused as the case says and
 *          @c verify_peer was asked as often, else what failed. */
static const char *s_allowed_case(const duct_seal_engine_vtbl_t *vt, duct_noise_pattern_t pattern,
                                  const allowed_case_t *c, const duct_noise_keypair_t *srv_kp,
                                  const duct_noise_keypair_t *cli_kp, const uint8_t *keys)
{
    verify_state_t state = { .admits = c->verify == verify_admits };
    duct_noise_cfg_t srv_cfg = { .local_static = *srv_kp,
                                 .allowed = c->n ? keys + c->first * duct_noise_key_size : nullptr,
                                 .n_allowed = c->n,
                                 .verify_peer = c->verify != verify_none ? s_verify_counting : nullptr,
                                 .verify_ctx = &state,
                                 .suite.pattern = pattern },
                     cli_cfg = { .local_static = *cli_kp, .suite.pattern = pattern };
    memcpy(cli_cfg.remote_static_pub, srv_kp->pub, duct_noise_key_size);
    auto srv = vt->create(&srv_cfg, seal_role_responder);
    auto cli = vt->create(&cli_cfg, seal_role_initiator);
    if (!srv || !cli) {
        if (srv)
            vt->destroy(srv);
        if (cli)
            vt->destroy(cli);
        return "engine create failed";
    }
    static fake_ctx_t cctx, sctx;
    s_ctx_reset(&cctx);
    s_ctx_reset(&sctx);
    vt->start(cli, &cctx.base);
    duct_result_t rc = vt->unseal(srv, duct_view(duct_view_u8, cctx.tx, cctx.tx_len), &sctx.base);
    bool xk = pattern == noise_pattern_xkpsk3;
    const char *err = nullptr;
    if (xk && (rc != rc_ok || sctx.tx_len == 0u)) {
        err = "message 1 was not answered";
    } else if (xk) {
        s_ctx_reset(&cctx);
        if (vt->unseal(cli, duct_view(duct_view_u8, sctx.tx, sctx.tx_len), &cctx.base) != rc_ok
            || cctx.tx_len == 0u) {
            err = "the initiator did not answer message 2 with message 3";
        } else {
            s_ctx_reset(&sctx);
            rc = vt->unseal(srv, duct_view(duct_view_u8, cctx.tx, cctx.tx_len), &sctx.base);
        }
    }
    bool named = vt->peer_identity(srv).size != 0u;
    vt->destroy(srv);
    vt->destroy(cli);
    if (err)
        return err;
    if (xk) {
        if ((rc == rc_ok) != c->admitted || named != c->admitted || sctx.tx_len != 0u)
            return c->admitted ? "message 3 was refused" : "message 3 was taken";
    } else if ((rc == rc_ok) != c->admitted || (sctx.tx_len != 0u) != c->admitted) {
        return c->admitted ? "message 1 was refused" : "message 1 was answered";
    }
    return state.asked == c->asked ? nullptr : "verify_peer was asked another number of times";
}

/** @brief Run every allowed-list case over one key table.
 *  @return nullptr when all hold, else what failed. */
static const char *s_allowed(duct_noise_pattern_t pattern)
{
    auto vt = duct_noise_vtbl();
    duct_noise_keypair_t srv_kp,
                         cli_kp,
                         other_kp;
    if (!duct_noise_keypair_generate(&srv_kp) || !duct_noise_keypair_generate(&cli_kp)
        || !duct_noise_keypair_generate(&other_kp))
        return "keypair generation failed";
    uint8_t keys[3u * duct_noise_key_size];
    memcpy(keys, other_kp.pub, duct_noise_key_size);
    memcpy(keys + duct_noise_key_size, cli_kp.pub, duct_noise_key_size);
    memcpy(keys + 2u * duct_noise_key_size, cli_kp.pub, duct_noise_key_size);
    keys[sizeof keys - 1u] ^= 1u;
    for (unsigned i = 0u; i < sizeof s_allowed_cases / sizeof *s_allowed_cases; ++i) {
        auto err = s_allowed_case(vt, pattern, &s_allowed_cases[i], &srv_kp, &cli_kp, keys);
        if (err) {
            fprintf(stderr, "noise_engine: allowed case \"%s\"\n", s_allowed_cases[i].name);
            return err;
        }
    }
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    static const struct { duct_noise_pattern_t pattern; const char *name; } patterns[] = {
        { noise_pattern_ikpsk2, "IKpsk2" },
        { noise_pattern_xkpsk3, "XKpsk3" },
    };
    for (size_t p = 0u; p < sizeof patterns / sizeof patterns[0]; ++p) {
        auto err = s_run(patterns[p].pattern);
        if (!err)
            err = s_opening(patterns[p].pattern);
        if (!err)
            err = s_allowed(patterns[p].pattern);
        if (err) {
            fprintf(stderr, "noise_engine: %s: %s\n", patterns[p].name, err);
            return 1;
        }
    }
    printf("noise_engine: OK (IKpsk2 and XKpsk3: handshake confirmed by the initiator or its first data, "
           "a replayed message 1 unnamed, both directions, tamper reject, "
           "the allowed list ahead of verify_peer)\n");
    return 0;
}
