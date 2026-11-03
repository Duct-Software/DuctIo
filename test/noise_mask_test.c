/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file noise_mask_test.c
 *  @brief The mask over the ephemeral key leading a Noise handshake message
 *  (@c DUCT_HANDSHAKE_MASK), and the raw key a build without it sends.
 *
 *  Both ends run in memory on the library's own message functions. `kat` pins
 *  the mask derivation to fixed vectors. `roundtrip` has both ends derive one
 *  exporter, masked or not. `form` draws 4096 handshakes and measures the leading
 *  32 bytes of each message: a mask build leaves every bit balanced and about
 *  half the values on the curve, and no closing tag, the mask's nonce, repeats;
 *  an unmasked build leaves the top bit clear and every value on the curve, the
 *  structure the mask removes. `unmask` takes the mask off the leading bytes and
 *  finds a point again, on the curve with its top bit clear. `replay` answers one
 *  captured message 1 with 64 responders: no tag repeats and, masked, the
 *  answers' leading bytes do not XOR to a value with a fixed bit. `tamper` flips a
 *  bit in each byte of the leading key and of the closing tag of both messages:
 *  every one is refused and the genuine message still reads after it. `psk`
 *  offers a message 1 under another pre-shared key, refused under the mask and
 *  read without it, the initiator then refusing the answer. `raw` hands a mask
 *  build each message in its unmasked form and it refuses it.
 */

#include "duct_noise_internal.h"

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static constexpr size_t draws   = 4096u;
static constexpr size_t replays = 64u;

/** @brief The leading key and the closing tag of one handshake message. */
typedef struct {
    uint8_t key[duct_noise_key_size],
            tag[duct_noise_tag_size];
} field_t;

typedef struct {
    duct_noise_keypair_t server,
                         client;
    uint8_t              psk[duct_noise_key_size];
    duct_noise_pattern_t pattern;
} world_t;

/** @brief Both ends of one handshake and the messages between them. */
typedef struct {
    duct_noise_pattern_t pattern;
    duct_noise_hs_t *init,
                    *resp;
    uint8_t          m1[256],
                     m2[256],
                     m3[256];
    size_t           n1,
                     n2,
                     n3;
} duel_t;

static field_t g_m1[draws], g_m2[draws];

/** @brief Share of the drawn leading keys with the top bit set and on the curve,
 *  from `form`, for the closing line. */
static struct {
    double top1, top2, curve1, curve2;
} g_share;

static bool world_open(world_t *w)
{
    *w = (world_t){};
    return duct_noise_keypair_generate(&w->server) && duct_noise_keypair_generate(&w->client)
        && RAND_bytes(w->psk, (int)sizeof w->psk) == 1;
}

static void field_take(field_t *f, const uint8_t *msg, size_t n)
{
    memcpy(f->key, msg, sizeof f->key);
    memcpy(f->tag, msg + n - sizeof f->tag, sizeof f->tag);
}

static void duel_close(duel_t *d)
{
    duct_noise_hs_destroy(d->init);
    duct_noise_hs_destroy(d->resp);
    *d = (duel_t){};
}

static bool xk(const duel_t *d)
{
    return d->pattern == noise_pattern_xkpsk3;
}

/** @brief Open both ends, the responder under @p psk_resp, and write message 1
 *  around a zero payload of @p payload bytes. */
static bool duel_open(duel_t *d, const world_t *w, const uint8_t *psk_resp, size_t payload)
{
    static const uint8_t zeros[duct_noise_hs_pad_max] = {};
    *d = (duel_t){ .pattern = w->pattern };
    d->init = duct_noise_hs_create_for(w->pattern, &w->client, w->server.pub, w->psk, true, (duct_view_u8){});
    d->resp = duct_noise_hs_create_for(w->pattern, &w->server, nullptr, psk_resp, false, (duct_view_u8){});
    duct_view_u8 body = { (void *)zeros, payload };
    return d->init && d->resp
        && (xk(d) ? duct_noise_hs_write_msg1_xk(d->init, body, d->m1, sizeof d->m1, &d->n1)
                  : duct_noise_hs_write_msg1(d->init, body, d->m1, sizeof d->m1, &d->n1));
}

/** @brief Have the responder read @p n bytes of message 1 at @p m1. */
static bool duel_read1(duel_t *d, const uint8_t *m1, size_t n)
{
    uint8_t learned[duct_noise_key_size], pay[duct_noise_hs_pad_max];
    size_t got = 0u;
    duct_view_u8 msg = { (void *)m1, n };
    return xk(d) ? duct_noise_hs_read_msg1_xk(d->resp, msg, pay, sizeof pay, &got)
                 : duct_noise_hs_read_msg1(d->resp, msg, learned, pay, sizeof pay, &got);
}

/** @brief Have the responder answer with a zero payload of @p payload bytes. */
static bool duel_write2(duel_t *d, size_t payload)
{
    static const uint8_t zeros[duct_noise_hs_pad_max] = {};
    duct_view_u8 body = { (void *)zeros, payload };
    return xk(d) ? duct_noise_hs_write_msg2_xk(d->resp, body, d->m2, sizeof d->m2, &d->n2)
                 : duct_noise_hs_write_msg2(d->resp, body, d->m2, sizeof d->m2, &d->n2);
}

/** @brief Have the initiator read @p n bytes of message 2 at @p m2. */
static bool duel_read2(duel_t *d, const uint8_t *m2, size_t n)
{
    duct_view_u8 msg = { (void *)m2, n };
    return xk(d) ? duct_noise_hs_read_msg2_xk(d->init, msg) : duct_noise_hs_read_msg2(d->init, msg);
}

/** @brief The PSK of the one peer there is, @p ctx being the @ref world_t. */
static bool world_psk(void *ctx, [[maybe_unused]] const uint8_t remote[duct_noise_key_size],
                      uint8_t out[duct_noise_key_size])
{
    memcpy(out, ((const world_t *)ctx)->psk, duct_noise_key_size);
    return true;
}

/** @brief Under XKpsk3 have the initiator write message 3 around a zero payload of
 *  @p payload bytes and the responder read it, which ends the handshake; IKpsk2
 *  ends at message 2. */
static bool duel_last(duel_t *d, const world_t *w, size_t payload)
{
    static const uint8_t zeros[duct_noise_hs_pad_max] = {};
    uint8_t learned[duct_noise_key_size], pay[duct_noise_hs_pad_max];
    size_t got = 0u;
    return !xk(d)
        || (duct_noise_hs_write_msg3_xk(d->init, (duct_view_u8){ (void *)zeros, payload }, d->m3, sizeof d->m3, &d->n3)
            && duct_noise_hs_read_msg3_xk(d->resp, (duct_view_u8){ d->m3, d->n3 }, world_psk, (void *)w, learned,
                                          pay, sizeof pay, &got));
}

/** @brief Run one handshake to its end, keeping each message's leading key and
 *  tag and the exporter each end derives. */
static bool shake(const world_t *w, size_t payload, field_t *m1, field_t *m2,
                  uint8_t exp_init[duct_noise_key_size], uint8_t exp_resp[duct_noise_key_size])
{
    duel_t d;
    bool ok = duel_open(&d, w, w->psk, payload)
           && duel_read1(&d, d.m1, d.n1)
           && duel_write2(&d, payload)
           && duel_read2(&d, d.m2, d.n2)
           && duel_last(&d, w, payload)
           && duct_noise_hs_exporter(d.init, exp_init)
           && duct_noise_hs_exporter(d.resp, exp_resp);
    if (ok) {
        field_take(m1, d.m1, d.n1);
        field_take(m2, d.m2, d.n2);
    }
    duel_close(&d);
    return ok;
}

static void bits_add(unsigned ones[256], const uint8_t v[duct_noise_key_size])
{
    for (unsigned i = 0u; i < 256u; ++i)
        ones[i] += (v[i / 8u] >> (i % 8u)) & 1u;
}

/** @brief Check that every bit was set in between 45 and 55 percent of @p n
 *  draws. */
static bool bits_balanced(const unsigned ones[256], size_t n)
{
    for (unsigned i = 0u; i < 256u; ++i) {
        double share = (double)ones[i] / (double)n;
        if (share < 0.45 || share > 0.55)
            return false;
    }
    return true;
}

typedef struct {
    BN_CTX *ctx;
    BIGNUM *p,
           *half,
           *a;
} curve_t;

static void curve_close(curve_t *c)
{
    BN_free(c->p);
    BN_free(c->half);
    BN_free(c->a);
    BN_CTX_free(c->ctx);
    *c = (curve_t){};
}

/** @brief Set up Curve25519's field: p = 2^255 - 19, (p - 1) / 2 and A = 486662. */
static bool curve_open(curve_t *c)
{
    c->ctx = BN_CTX_new();
    c->p = BN_new();
    c->half = BN_new();
    c->a = BN_new();
    bool ok = c->ctx && c->p && c->half && c->a
           && BN_one(c->p) == 1 && BN_lshift(c->p, c->p, 255) == 1
           && BN_sub_word(c->p, 19) == 1
           && BN_copy(c->half, c->p) && BN_sub_word(c->half, 1) == 1 && BN_rshift1(c->half, c->half) == 1
           && BN_set_word(c->a, 486662) == 1;
    if (!ok)
        curve_close(c);
    return ok;
}

/** @brief Test whether the 32 bytes @p le, read as X25519 reads a u-coordinate,
 *  lie on the curve: u^3 + A u^2 + u is a square, by Euler's criterion.
 *  @return 1 on, 0 off, -1 where the arithmetic failed. */
static int on_curve(const curve_t *c, const uint8_t le[duct_noise_key_size])
{
    uint8_t b[duct_noise_key_size];
    memcpy(b, le, sizeof b);
    b[31] &= 0x7fu;
    BIGNUM *u = BN_lebin2bn(b, (int)sizeof b, nullptr),
           *t = BN_new(),
           *r = BN_new();
    bool ok = u && t && r
           && BN_mod(u, u, c->p, c->ctx) == 1
           && BN_mod_sqr(t, u, c->p, c->ctx) == 1
           && BN_mod_mul(r, c->a, u, c->p, c->ctx) == 1
           && BN_mod_add(t, t, r, c->p, c->ctx) == 1
           && BN_add_word(t, 1) == 1
           && BN_mod_mul(t, t, u, c->p, c->ctx) == 1
           && BN_mod_exp(r, t, c->half, c->p, c->ctx) == 1;
    int answer = !ok ? -1 : (BN_is_one(r) || BN_is_zero(r) ? 1 : 0);
    BN_free(u);
    BN_free(t);
    BN_free(r);
    return answer;
}

typedef struct {
    uint8_t b[duct_noise_tag_size];
} tag_t;

static int tag_cmp(const void *x, const void *y)
{
    return memcmp(x, y, duct_noise_tag_size);
}

/** @brief Check that no two of the @p n tags at @p f are equal. */
static bool tags_distinct(const field_t *f, size_t n)
{
    static tag_t sorted[draws];
    for (size_t i = 0u; i < n; ++i)
        memcpy(sorted[i].b, f[i].tag, sizeof sorted[i].b);
    qsort(sorted, n, sizeof sorted[0], tag_cmp);
    for (size_t i = 1u; i < n; ++i)
        if (memcmp(sorted[i - 1u].b, sorted[i].b, sizeof sorted[i].b) == 0)
            return false;
    return true;
}

static const char *sc_kat([[maybe_unused]] const world_t *w)
{
    uint8_t psk[duct_noise_key_size], tag[duct_noise_tag_size];
    for (unsigned i = 0u; i < sizeof psk; ++i)
        psk[i] = (uint8_t)i;
    for (unsigned i = 0u; i < sizeof tag; ++i)
        tag[i] = (uint8_t)(0xa0u + i);
    static const uint8_t want1[duct_noise_key_size] = {
        0x8d, 0xf2, 0x9b, 0x65, 0xff, 0x19, 0x6f, 0x16, 0x4b, 0x58, 0x9a, 0xb1, 0x31, 0x7b, 0x5b, 0x98,
        0x20, 0x4d, 0x9d, 0x30, 0x6f, 0xed, 0xe6, 0x9f, 0x14, 0x5a, 0x08, 0xc2, 0xdb, 0x92, 0x20, 0x96,
    };
    static const uint8_t want2[duct_noise_key_size] = {
        0x2e, 0x04, 0x35, 0x0c, 0xd3, 0xb9, 0x05, 0x32, 0x1a, 0x2f, 0x1b, 0x15, 0xba, 0x38, 0x7a, 0x38,
        0x56, 0x01, 0x9c, 0xa5, 0xcb, 0xb2, 0x93, 0x45, 0xe9, 0x6e, 0x9b, 0x27, 0x9e, 0x75, 0x00, 0x32,
    };
    uint8_t got1[duct_noise_key_size], got2[duct_noise_key_size], other[duct_noise_key_size];
    if (!duct_noise_ephemeral_mask(psk, duct_noise_mask_msg1, tag, got1)
        || !duct_noise_ephemeral_mask(psk, duct_noise_mask_msg2, tag, got2))
        return "the mask did not compute";
    if (memcmp(got1, want1, sizeof got1) != 0 || memcmp(got2, want2, sizeof got2) != 0)
        return "the mask is not the one an independent HMAC-BLAKE2s computes";
    psk[7] ^= 0x01u;
    if (!duct_noise_ephemeral_mask(psk, duct_noise_mask_msg1, tag, other)
        || memcmp(other, got1, sizeof other) == 0)
        return "a changed pre-shared key left the mask as it was";
    psk[7] ^= 0x01u;
    tag[3] ^= 0x01u;
    if (!duct_noise_ephemeral_mask(psk, duct_noise_mask_msg1, tag, other)
        || memcmp(other, got1, sizeof other) == 0)
        return "a changed tag left the mask as it was";
    return nullptr;
}

static const char *sc_roundtrip(const world_t *w)
{
    field_t m1, m2;
    uint8_t exp_init[duct_noise_key_size], exp_resp[duct_noise_key_size];
    for (size_t payload = 0u; payload <= duct_noise_hs_pad_max; payload += 32u)
        if (!shake(w, payload, &m1, &m2, exp_init, exp_resp)
            || memcmp(exp_init, exp_resp, sizeof exp_init) != 0)
            return "the two ends did not derive one key from the handshake";
    return nullptr;
}

static const char *sc_form(const world_t *w)
{
    curve_t curve;
    if (!curve_open(&curve))
        return "the curve arithmetic did not start";
    unsigned ones1[256] = {}, ones2[256] = {};
    size_t on1 = 0u, on2 = 0u;
    const char *err = nullptr;
    for (size_t i = 0u; !err && i < draws; ++i) {
        uint8_t exp_init[duct_noise_key_size], exp_resp[duct_noise_key_size];
        if (!shake(w, i % 37u, &g_m1[i], &g_m2[i], exp_init, exp_resp)) {
            err = "a handshake did not complete";
            break;
        }
        bits_add(ones1, g_m1[i].key);
        bits_add(ones2, g_m2[i].key);
        int a = on_curve(&curve, g_m1[i].key),
            b = on_curve(&curve, g_m2[i].key);
        if (a < 0 || b < 0) {
            err = "the curve test did not compute";
            break;
        }
        on1 += (size_t)a;
        on2 += (size_t)b;
    }
    curve_close(&curve);
    if (err)
        return err;
    if (!tags_distinct(g_m1, draws) || !tags_distinct(g_m2, draws))
        return "two handshakes closed their message with one tag";
    g_share.top1 = (double)ones1[255] / draws;
    g_share.top2 = (double)ones2[255] / draws;
    g_share.curve1 = (double)on1 / draws;
    g_share.curve2 = (double)on2 / draws;
    if (duct_handshake_mask) {
        if (!bits_balanced(ones1, draws) || !bits_balanced(ones2, draws))
            return "a bit of a masked leading key was biased";
        if (g_share.curve1 < 0.45 || g_share.curve1 > 0.55
            || g_share.curve2 < 0.45 || g_share.curve2 > 0.55)
            return "a masked leading key was on the curve more or less often than a uniform one";
        return nullptr;
    }
    if (ones1[255] != 0u || ones2[255] != 0u)
        return "a raw key had its top bit set";
    if (on1 != draws || on2 != draws)
        return "a raw key was off the curve";
    return nullptr;
}

static const char *sc_unmask(const world_t *w)
{
    if (!duct_handshake_mask)
        return nullptr;
    curve_t curve;
    if (!curve_open(&curve))
        return "the curve arithmetic did not start";
    const char *err = nullptr;
    for (size_t i = 0u; !err && i < 256u; ++i) {
        for (unsigned m = 1u; !err && m <= 2u; ++m) {
            const field_t *f = m == 1u ? &g_m1[i] : &g_m2[i];
            uint8_t mask[duct_noise_key_size], point[duct_noise_key_size];
            if (!duct_noise_ephemeral_mask(w->psk, (uint8_t)m, f->tag, mask)) {
                err = "the mask did not compute";
                break;
            }
            for (unsigned k = 0u; k < sizeof point; ++k)
                point[k] = f->key[k] ^ mask[k];
            if ((point[31] & 0x80u) != 0u || on_curve(&curve, point) != 1)
                err = "the mask taken off a leading key left something other than a point";
        }
    }
    curve_close(&curve);
    return err;
}

static const char *sc_replay(const world_t *w)
{
    duel_t d;
    uint8_t m1[sizeof d.m1];
    size_t n1 = 0u;
    if (!duel_open(&d, w, w->psk, 17u)) {
        duel_close(&d);
        return "message 1 did not start";
    }
    memcpy(m1, d.m1, d.n1);
    n1 = d.n1;
    duel_close(&d);

    static field_t answers[replays];
    for (size_t i = 0u; i < replays; ++i) {
        duel_t r = { .pattern = w->pattern };
        r.resp = duct_noise_hs_create_for(w->pattern, &w->server, nullptr, w->psk, false, (duct_view_u8){});
        bool ok = r.resp && duel_read1(&r, m1, n1) && duel_write2(&r, 0u);
        if (ok)
            field_take(&answers[i], r.m2, r.n2);
        duel_close(&r);
        if (!ok)
            return "a responder refused the replayed message 1";
    }
    if (!tags_distinct(answers, replays))
        return "two answers to one message 1 closed with the same tag";
    unsigned set = 0u;
    for (size_t i = 1u; i < replays; ++i)
        set += ((answers[i].key[31] ^ answers[0].key[31]) >> 7u) & 1u;
    if (duct_handshake_mask ? (set < 10u || set > 53u) : set != 0u)
        return duct_handshake_mask
            ? "the answers to one message 1 shared a keystream: their leading bytes XOR to a fixed bit"
            : "raw keys differed in their top bit";
    return nullptr;
}

static const char *sc_tamper(const world_t *w)
{
    duel_t d;
    const char *err = nullptr;
    if (!duel_open(&d, w, w->psk, 9u)) {
        duel_close(&d);
        return "message 1 did not start";
    }
    uint8_t bad[sizeof d.m1];
    for (size_t at = 0u; !err && at < d.n1; ++at) {
        if (at >= duct_noise_key_size && at < d.n1 - duct_noise_tag_size)
            continue;
        memcpy(bad, d.m1, d.n1);
        bad[at] ^= 0x01u;
        if (duel_read1(&d, bad, d.n1))
            err = "message 1 with a bit changed in its leading key or closing tag was read";
    }
    if (!err && !duel_read1(&d, d.m1, d.n1))
        err = "message 1 was refused after forged ones";
    if (!err && !duel_write2(&d, 5u))
        err = "message 2 did not write";
    for (size_t at = 0u; !err && at < d.n2; ++at) {
        if (at >= duct_noise_key_size && at < d.n2 - duct_noise_tag_size)
            continue;
        memcpy(bad, d.m2, d.n2);
        bad[at] ^= 0x01u;
        if (duel_read2(&d, bad, d.n2))
            err = "message 2 with a bit changed in its leading key or closing tag was read";
    }
    if (!err && !duel_read2(&d, d.m2, d.n2))
        err = "message 2 was refused after forged ones";
    duel_close(&d);
    return err;
}

static const char *sc_psk(const world_t *w)
{
    uint8_t other[duct_noise_key_size];
    if (RAND_bytes(other, (int)sizeof other) != 1)
        return "no random bytes";
    duel_t d;
    const char *err = nullptr;
    if (!duel_open(&d, w, other, 3u)) {
        duel_close(&d);
        return "message 1 did not start";
    }
    bool read = duel_read1(&d, d.m1, d.n1);
    if (duct_handshake_mask) {
        if (read)
            err = "a message 1 under another pre-shared key was read";
    } else if (!read || !duel_write2(&d, 0u)) {
        err = "an unmasked message 1 was refused over its pre-shared key, which only a later message mixes";
    } else if (xk(&d) ? !duel_read2(&d, d.m2, d.n2) : duel_read2(&d, d.m2, d.n2)) {
        err = xk(&d) ? "an unmasked XKpsk3 message 2 was refused over a pre-shared key it does not mix"
                     : "a message 2 under another pre-shared key was accepted";
    }
    duel_close(&d);
    return err;
}

static const char *sc_raw(const world_t *w)
{
    if (!duct_handshake_mask)
        return nullptr;
    duel_t d;
    const char *err = nullptr;
    if (!duel_open(&d, w, w->psk, 11u)) {
        duel_close(&d);
        return "message 1 did not start";
    }
    uint8_t raw[sizeof d.m1], mask[duct_noise_key_size];
    if (!duct_noise_ephemeral_mask(w->psk, duct_noise_mask_msg1, d.m1 + d.n1 - duct_noise_tag_size, mask))
        err = "the mask did not compute";
    memcpy(raw, d.m1, d.n1);
    for (unsigned k = 0u; !err && k < sizeof mask; ++k)
        raw[k] ^= mask[k];
    if (!err && duel_read1(&d, raw, d.n1))
        err = "a message 1 carrying the raw key was read by a mask build";
    if (!err && (!duel_read1(&d, d.m1, d.n1) || !duel_write2(&d, 0u)))
        err = "the masked message 1 was refused after the raw one";
    if (!err && !duct_noise_ephemeral_mask(w->psk, duct_noise_mask_msg2,
                                           d.m2 + d.n2 - duct_noise_tag_size, mask))
        err = "the mask did not compute";
    memcpy(raw, d.m2, d.n2);
    for (unsigned k = 0u; !err && k < sizeof mask; ++k)
        raw[k] ^= mask[k];
    if (!err && duel_read2(&d, raw, d.n2))
        err = "a message 2 carrying the raw key was read by a mask build";
    if (!err && !duel_read2(&d, d.m2, d.n2))
        err = "the masked message 2 was refused after the raw one";
    duel_close(&d);
    return err;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    world_t w;
    if (!world_open(&w)) {
        fprintf(stderr, "noise_mask: key generation failed\n");
        return 1;
    }
    static const struct { const char *name; const char *(*fn)(const world_t *); } cases[] = {
        { "kat",       sc_kat },
        { "roundtrip", sc_roundtrip },
        { "form",      sc_form },
        { "unmask",    sc_unmask },
        { "replay",    sc_replay },
        { "tamper",    sc_tamper },
        { "psk",       sc_psk },
        { "raw",       sc_raw },
    };
    static const struct { duct_noise_pattern_t pattern; const char *name; } patterns[] = {
        { noise_pattern_ikpsk2, "IKpsk2" },
        { noise_pattern_xkpsk3, "XKpsk3" },
    };
    /* A scenario named on the command line runs alone, `unmask` needing `form`'s
     * draws. */
    for (size_t p = 0u; p < sizeof patterns / sizeof patterns[0]; ++p) {
        w.pattern = patterns[p].pattern;
        for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
            if (argc > 1 && strcmp(argv[1], cases[i].name) != 0)
                continue;
            auto err = cases[i].fn(&w);
            if (err) {
                fprintf(stderr, "noise_mask: %s, %s: %s\n", patterns[p].name, cases[i].name, err);
                return 1;
            }
        }
        printf("noise_mask: OK (%s, %s build: derivation pinned, round trip, replay, tamper, other pre-shared key; "
               "of %zu handshakes the leading key of message 1 / 2 had its top bit set in %.1f%% / %.1f%% "
               "and lay on the curve in %.1f%% / %.1f%%)\n",
               patterns[p].name, duct_handshake_mask ? "mask" : "unmasked", draws, 100.0 * g_share.top1,
               100.0 * g_share.top2, 100.0 * g_share.curve1, 100.0 * g_share.curve2);
    }
    return 0;
}
