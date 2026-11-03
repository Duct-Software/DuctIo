/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file noise_xk_test.c
 *  @brief The XKpsk3 handshake of the Noise core, driven in memory.
 *
 *  `roundtrip` runs the three messages with the sizes they cost, the hello and the
 *  padding arriving whole, the responder asking for the password once, with the
 *  initiator's key, and both ends splitting to the same keys and exporter. `sizes`
 *  holds each write to its capacity, each read to the payload room it was given and
 *  to the shortest message it takes. `tamper` changes one bit of each byte of each
 *  message in turn: every one is refused, the end that read it stays ready for the
 *  genuine message, and the password is asked for only once the initiator's key has
 *  authenticated. `password` refuses a wrong password and a refusal by the resolver
 *  at message 3 and takes the genuine message afterwards. `foreign` refuses a
 *  message 1 meant for another server and a message 3 of another exchange under the
 *  same keys. `replay` refuses a message read twice. `order` refuses every call made
 *  out of its turn, for the wrong role or of the other pattern, and the exchange
 *  still completes. `prologue` binds both ends to one value. `mask` holds an end
 *  with another mask key to refuse message 1 where the build masks it.
 */

#include "duct_crypto.h"
#include "duct_noise.h"
#include "duct_noise_internal.h"

#include <stdio.h>
#include <string.h>

static constexpr size_t k_cap = 256u;

static const char k_hello[] = "hello of the first message.";
static const char k_pad2[]  = "pad 2";
static const char k_pad3[]  = "pad three";

/** @brief The key the resolver hands the responder, and what it was asked. */
typedef struct {
    const uint8_t *psk;
    unsigned       asked;
    uint8_t        peer[duct_noise_key_size];
} resolver_t;

static bool resolve(void *ctx, const uint8_t remote[duct_noise_key_size], uint8_t out[duct_noise_key_size])
{
    auto res = (resolver_t *)ctx;
    ++res->asked;
    memcpy(res->peer, remote, sizeof res->peer);
    if (!res->psk)
        return false;
    memcpy(out, res->psk, duct_noise_key_size);
    return true;
}

/** @brief One exchange: both ends, the bytes between them and what the reads returned. */
typedef struct {
    duct_noise_keypair_t    ki,
                            kr;
    uint8_t                 psk[duct_noise_key_size];
    resolver_t              res;
    duct_view_u8              p1,
                            p2,
                            p3;
    duct_noise_hs_t        *hi,
                           *hr;
    uint8_t                 m1[k_cap],
                            m2[k_cap],
                            m3[k_cap],
                            got1[k_cap],
                            got3[k_cap],
                            learned[duct_noise_key_size];
    size_t                  n1,
                            n2,
                            n3,
                            gn1,
                            gn3;
} run_t;

static duct_view_u8 s_bytes(const void *p, size_t n)
{
    return duct_view(duct_view_u8, (void *)p, n);
}

static duct_view_u8 s_text(const char *s)
{
    return s_bytes(s, strlen(s));
}

/** @brief Fresh keys, a fresh password and an XKpsk3 state for each end, under @p prologue. */
static bool run_open(run_t *r, duct_view_u8 prologue)
{
    *r = (run_t){ .p1 = s_text(k_hello), .p2 = s_text(k_pad2), .p3 = s_text(k_pad3) };
    if (!duct_noise_keypair_generate(&r->ki) || !duct_noise_keypair_generate(&r->kr)
        || !duct_random_bytes(r->psk, sizeof r->psk))
        return false;
    r->res.psk = r->psk;
    r->hi = duct_noise_hs_create_for(noise_pattern_xkpsk3, &r->ki, r->kr.pub, r->psk, true, prologue);
    r->hr = duct_noise_hs_create_for(noise_pattern_xkpsk3, &r->kr, nullptr, r->psk, false, prologue);
    return r->hi && r->hr;
}

/** @brief A second exchange under the keys and the password of @p like, its ephemeral keys its own. */
static bool run_twin(run_t *r, const run_t *like)
{
    *r = (run_t){ .ki = like->ki, .kr = like->kr, .p1 = s_text(k_hello), .p2 = s_text(k_pad2), .p3 = s_text(k_pad3) };
    memcpy(r->psk, like->psk, sizeof r->psk);
    r->res.psk = r->psk;
    r->hi = duct_noise_hs_create_for(noise_pattern_xkpsk3, &r->ki, r->kr.pub, r->psk, true, (duct_view_u8){});
    r->hr = duct_noise_hs_create_for(noise_pattern_xkpsk3, &r->kr, nullptr, r->psk, false, (duct_view_u8){});
    return r->hi && r->hr;
}

static void run_close(run_t *r)
{
    duct_noise_hs_destroy(r->hi);
    duct_noise_hs_destroy(r->hr);
}

static bool w1(run_t *r)
{
    return duct_noise_hs_write_msg1_xk(r->hi, r->p1, r->m1, sizeof r->m1, &r->n1);
}

static bool r1(run_t *r, const uint8_t *msg, size_t n)
{
    return duct_noise_hs_read_msg1_xk(r->hr, s_bytes(msg, n), r->got1, sizeof r->got1, &r->gn1);
}

static bool w2(run_t *r)
{
    return duct_noise_hs_write_msg2_xk(r->hr, r->p2, r->m2, sizeof r->m2, &r->n2);
}

static bool r2(run_t *r, const uint8_t *msg, size_t n)
{
    return duct_noise_hs_read_msg2_xk(r->hi, s_bytes(msg, n));
}

static bool w3(run_t *r)
{
    return duct_noise_hs_write_msg3_xk(r->hi, r->p3, r->m3, sizeof r->m3, &r->n3);
}

static bool r3(run_t *r, const uint8_t *msg, size_t n)
{
    return duct_noise_hs_read_msg3_xk(r->hr, s_bytes(msg, n), resolve, &r->res, r->learned, r->got3,
                                      sizeof r->got3, &r->gn3);
}

typedef enum { st_w1, st_r1, st_w2, st_r2, st_w3, st_r3, st_count } step_t;

/** @brief Run the first @p steps of write 1, read 1, write 2, read 2, write 3, read 3, each fed the bytes the
 *  one before wrote.
 *  @return the text of the first step that failed, nullptr when all passed. */
static const char *drive(run_t *r, unsigned steps)
{
    static const char *const fail[st_count] = {
        [st_w1] = "message 1 was not written", [st_r1] = "message 1 was not read",
        [st_w2] = "message 2 was not written", [st_r2] = "message 2 was not read",
        [st_w3] = "message 3 was not written", [st_r3] = "message 3 was not read",
    };
    for (step_t i = st_w1; i < steps; ++i) {
        bool ok = false;
        switch (i) {
        case st_w1: ok = w1(r); break;
        case st_r1: ok = r1(r, r->m1, r->n1); break;
        case st_w2: ok = w2(r); break;
        case st_r2: ok = r2(r, r->m2, r->n2); break;
        case st_w3: ok = w3(r); break;
        case st_r3: ok = r3(r, r->m3, r->n3); break;
        case st_count: break;
        }
        if (!ok)
            return fail[i];
    }
    return nullptr;
}

static const char *sc_roundtrip(void)
{
    run_t r;
    if (!run_open(&r, (duct_view_u8){}))
        return "the exchange did not open";
    const char *err = drive(&r, 6u);
    duct_noise_transport_t ti = {},
                           tr = {};
    uint8_t exporter_i[duct_noise_key_size],
            exporter_r[duct_noise_key_size],
            sealed[64],
            opened[64];
    size_t opened_len = 0u;
    if (!err && (r.n1 != duct_noise_xk_msg1_size(r.p1.size) || r.n2 != duct_noise_msg2_size + r.p2.size
                 || r.n3 != duct_noise_xk_msg3_size(r.p3.size)))
        err = "a message costs other than its size says";
    else if (!err && (r.gn1 != r.p1.size || memcmp(r.got1, r.p1.data, r.gn1) != 0))
        err = "the hello of message 1 did not arrive whole";
    else if (!err && (r.gn3 != r.p3.size || memcmp(r.got3, r.p3.data, r.gn3) != 0))
        err = "the padding of message 3 did not arrive whole";
    else if (!err && memcmp(r.learned, r.ki.pub, sizeof r.learned) != 0)
        err = "the responder learned another key than the initiator's";
    else if (!err && (r.res.asked != 1u || memcmp(r.res.peer, r.ki.pub, sizeof r.res.peer) != 0))
        err = "the password was not asked once, for the initiator's key";
    else if (!err && (!duct_noise_hs_split(r.hi, &ti) || !duct_noise_hs_split(r.hr, &tr)
                      || !duct_noise_hs_exporter(r.hi, exporter_i) || !duct_noise_hs_exporter(r.hr, exporter_r)))
        err = "the ends did not split";
    else if (!err && (memcmp(exporter_i, exporter_r, sizeof exporter_i) != 0
                      || memcmp(ti.send_key, tr.recv_key, sizeof ti.send_key) != 0
                      || memcmp(ti.recv_key, tr.send_key, sizeof ti.recv_key) != 0))
        err = "the ends did not agree";
    else if (!err) {
        size_t n = duct_noise_transport_seal(&ti, (duct_view_u8[]){ s_text(k_hello) }, 1u, sealed, sizeof sealed);
        if (!n || !duct_noise_transport_unseal(&tr, s_bytes(sealed, n), opened, sizeof opened, &opened_len)
            || opened_len != strlen(k_hello) || memcmp(opened, k_hello, opened_len) != 0)
            err = "the transport did not carry a message to the responder";
        n = duct_noise_transport_seal(&tr, (duct_view_u8[]){ s_text(k_hello) }, 1u, sealed, sizeof sealed);
        if (!err && (!n || !duct_noise_transport_unseal(&ti, s_bytes(sealed, n), opened, sizeof opened, &opened_len)))
            err = "the transport did not carry a message to the initiator";
    }
    duct_noise_transport_destroy(&ti);
    duct_noise_transport_destroy(&tr);
    run_close(&r);
    return err;
}

static const char *sc_sizes(void)
{
    run_t r;
    if (!run_open(&r, (duct_view_u8){}))
        return "the exchange did not open";
    const char *err = drive(&r, 1u);
    if (!err && duct_noise_hs_read_msg1_xk(r.hr, s_bytes(r.m1, r.n1), r.got1, r.p1.size - 1u, &r.gn1))
        err = "a payload was read into a buffer a byte short";
    if (!err && !r1(&r, r.m1, r.n1))
        err = "message 1 was refused after the short buffer";
    run_close(&r);
    if (err)
        return err;

    if (!run_open(&r, (duct_view_u8){}))
        return "the exchange did not open";
    r.p1 = r.p2 = r.p3 = (duct_view_u8){};
    uint8_t out[k_cap];
    size_t n = 0u;
    if (duct_noise_hs_write_msg1_xk(r.hi, r.p1, out, duct_noise_xk_msg1_size(0u) - 1u, &n))
        err = "message 1 was written into a buffer a byte short";
    else if (!w1(&r) || r.n1 != 48u)
        err = "an empty message 1 does not cost 48 bytes";
    for (size_t cut = 0u; !err && cut < duct_noise_xk_msg1_fixed_size; ++cut)
        if (r1(&r, r.m1, cut))
            err = "a message 1 shorter than a key and a tag was read";
    if (!err && !r1(&r, r.m1, r.n1))
        err = "message 1 was refused after the short ones";
    if (!err && duct_noise_hs_write_msg2_xk(r.hr, r.p2, out, duct_noise_msg2_size - 1u, &n))
        err = "message 2 was written into a buffer a byte short";
    else if (!err && (!w2(&r) || r.n2 != 48u))
        err = "an empty message 2 does not cost 48 bytes";
    for (size_t cut = 0u; !err && cut < duct_noise_msg2_size; ++cut)
        if (r2(&r, r.m2, cut))
            err = "a message 2 shorter than a key and a tag was read";
    uint8_t long2[k_cap] = {};
    memcpy(long2, r.m2, r.n2);
    if (!err && r2(&r, long2, duct_noise_msg2_size + duct_noise_hs_pad_max + 1u))
        err = "a message 2 padded past the most the engine sends was read";
    if (!err && !r2(&r, r.m2, r.n2))
        err = "message 2 was refused after the short ones";
    if (!err && duct_noise_hs_write_msg3_xk(r.hi, r.p3, out, duct_noise_xk_msg3_size(0u) - 1u, &n))
        err = "message 3 was written into a buffer a byte short";
    else if (!err && (!w3(&r) || r.n3 != 64u))
        err = "an empty message 3 does not cost 64 bytes";
    for (size_t cut = 0u; !err && cut < duct_noise_xk_msg3_fixed_size; ++cut)
        if (r3(&r, r.m3, cut))
            err = "a message 3 shorter than a key and two tags was read";
    if (!err && r.res.asked != 0u)
        err = "the password was asked for a message too short to carry a key";
    if (!err && !r3(&r, r.m3, r.n3))
        err = "message 3 was refused after the short ones";
    run_close(&r);
    return err;
}

/** @brief Feed @p read a copy of @p msg with one bit changed in each byte in turn, then the genuine bytes.
 *  @return the text of the first step that failed, nullptr when every change was refused and the genuine
 *  message was read. */
static const char *tamper(run_t *r, bool (*read)(run_t *, const uint8_t *, size_t), const uint8_t *msg,
                          size_t n)
{
    uint8_t bad[k_cap];
    for (size_t at = 0u; at < n; ++at) {
        memcpy(bad, msg, n);
        bad[at] ^= 0x01u;
        if (read(r, bad, n))
            return "a message with one bit changed was read";
    }
    return read(r, msg, n) ? nullptr : "the genuine message was refused after the forged ones";
}

static const char *sc_tamper(void)
{
    run_t r;
    if (!run_open(&r, (duct_view_u8){}))
        return "the exchange did not open";
    const char *err = drive(&r, 1u);
    if (!err)
        err = tamper(&r, r1, r.m1, r.n1);
    if (!err && !w2(&r))
        err = "message 2 was not written after the forged message 1";
    if (!err)
        err = tamper(&r, r2, r.m2, r.n2);
    if (!err && !w3(&r))
        err = "message 3 was not written after the forged message 2";
    if (!err && r.res.asked != 0u)
        err = "the password was asked before message 3";
    uint8_t bad[k_cap];
    for (size_t at = 0u; !err && at < r.n3; ++at) {
        memcpy(bad, r.m3, r.n3);
        bad[at] ^= 0x01u;
        unsigned before = r.res.asked;
        if (r3(&r, bad, r.n3))
            err = "a message 3 with one bit changed was read";
        else if (r.res.asked - before != (at < duct_noise_key_size + duct_noise_tag_size ? 0u : 1u))
            err = "the password was asked for a key that had not authenticated, or not asked for one that had";
    }
    if (!err && !r3(&r, r.m3, r.n3))
        err = "the genuine message 3 was refused after the forged ones";
    run_close(&r);
    return err;
}

static const char *sc_password(void)
{
    run_t r;
    if (!run_open(&r, (duct_view_u8){}))
        return "the exchange did not open";
    const char *err = drive(&r, 5u);
    uint8_t other[duct_noise_key_size];
    memcpy(other, r.psk, sizeof other);
    other[0] ^= 0x01u;
    if (!err) {
        r.res.psk = other;
        if (r3(&r, r.m3, r.n3))
            err = "message 3 was read under another password";
        else if (r.res.asked != 1u)
            err = "the password was not asked once";
    }
    if (!err) {
        r.res.psk = nullptr;
        if (r3(&r, r.m3, r.n3))
            err = "message 3 was read though the resolver refused the peer";
        else if (r.res.asked != 2u)
            err = "the resolver was not asked again";
    }
    if (!err) {
        r.res.psk = r.psk;
        if (!r3(&r, r.m3, r.n3))
            err = "the genuine message 3 was refused after the wrong password and the refusal";
    }
    run_close(&r);
    if (err)
        return err;

    if (!run_open(&r, (duct_view_u8){}))
        return "the exchange did not open";
    err = drive(&r, 4u);
    if (!err) {
        duct_noise_hs_set_psk(r.hi, other);
        if (!w3(&r))
            err = "message 3 was not written under another password";
        else if (r3(&r, r.m3, r.n3))
            err = "a message 3 made under another password was read";
    }
    run_close(&r);
    return err;
}

static const char *sc_foreign(void)
{
    run_t a, b;
    if (!run_open(&a, (duct_view_u8){}) || !run_open(&b, (duct_view_u8){}))
        return "the exchange did not open";
    duct_noise_hs_destroy(b.hi);
    b.hi = duct_noise_hs_create_for(noise_pattern_xkpsk3, &b.ki, b.kr.pub, a.psk, true, (duct_view_u8){});
    const char *err = nullptr;
    if (!b.hi || !w1(&b))
        err = "the initiator of another server did not write";
    else if (r1(&a, b.m1, b.n1))
        err = "a message 1 meant for another server was read";
    run_close(&b);
    if (!err)
        err = drive(&a, 2u);
    run_close(&a);
    if (err)
        return err;

    if (!run_open(&a, (duct_view_u8){}) || !run_twin(&b, &a))
        return "the exchange did not open";
    err = drive(&a, 5u);
    if (!err)
        err = drive(&b, 5u);
    if (!err && r3(&a, b.m3, b.n3))
        err = "a message 3 of another exchange was read";
    if (!err && !r3(&a, a.m3, a.n3))
        err = "the genuine message 3 was refused after the one of another exchange";
    run_close(&a);
    run_close(&b);
    return err;
}

static const char *sc_replay(void)
{
    run_t r;
    if (!run_open(&r, (duct_view_u8){}))
        return "the exchange did not open";
    const char *err = drive(&r, 2u);
    if (!err && r1(&r, r.m1, r.n1))
        err = "message 1 was read twice";
    if (!err && (!w2(&r) || !r2(&r, r.m2, r.n2)))
        err = "message 2 did not follow the replayed message 1";
    if (!err && r2(&r, r.m2, r.n2))
        err = "message 2 was read twice";
    if (!err && (!w3(&r) || !r3(&r, r.m3, r.n3)))
        err = "message 3 did not complete the exchange";
    if (!err && r3(&r, r.m3, r.n3))
        err = "message 3 was read twice";
    run_close(&r);
    return err;
}

static const char *sc_order(void)
{
    run_t r;
    if (!run_open(&r, (duct_view_u8){}))
        return "the exchange did not open";
    const char *err = nullptr;
    uint8_t out[k_cap],
            junk[k_cap] = {};
    size_t n = 0u;
    duct_noise_transport_t t = {};
    if (w2(&r) || w3(&r) || r2(&r, junk, 64u) || r3(&r, junk, 80u))
        err = "a call was taken ahead of its turn";
    else if (duct_noise_hs_write_msg1_xk(r.hr, r.p1, out, sizeof out, &n)
             || duct_noise_hs_read_msg1_xk(r.hi, s_bytes(junk, 64u), out, sizeof out, &n))
        err = "a message 1 call was taken by the wrong role";
    else if (duct_noise_hs_write_msg1(r.hi, r.p1, out, sizeof out, &n)
             || duct_noise_hs_read_msg1(r.hr, s_bytes(junk, 112u), r.learned, out, sizeof out, &n)
             || duct_noise_hs_write_msg2(r.hr, r.p2, out, sizeof out, &n)
             || duct_noise_hs_read_msg2(r.hi, s_bytes(junk, 64u)))
        err = "a call of the other pattern was taken";
    else if (duct_noise_hs_split(r.hi, &t) || duct_noise_hs_split(r.hr, &t)
             || duct_noise_hs_exporter(r.hi, out) || duct_noise_hs_exporter(r.hr, out))
        err = "the keys were taken before the exchange ended";
    if (!err && !w1(&r))
        err = "message 1 was not written after the refused calls";
    if (!err && w1(&r))
        err = "message 1 was written twice";
    if (!err && (!r1(&r, r.m1, r.n1) || !w2(&r) || !r2(&r, r.m2, r.n2)))
        err = "the exchange did not go on after the refused calls";
    if (!err && (duct_noise_hs_split(r.hi, &t) || duct_noise_hs_exporter(r.hi, out)))
        err = "the initiator split before message 3";
    if (!err && (!w3(&r) || !r3(&r, r.m3, r.n3)))
        err = "message 3 did not complete the exchange";
    if (!err && (!duct_noise_hs_split(r.hi, &t) || !duct_noise_hs_exporter(r.hr, out)))
        err = "the ends did not split after message 3";
    duct_noise_transport_destroy(&t);
    run_close(&r);
    if (err)
        return err;

    uint8_t psk[duct_noise_key_size] = {};
    duct_noise_keypair_t ki,
                         kr;
    if (!duct_noise_keypair_generate(&ki) || !duct_noise_keypair_generate(&kr))
        return "the keys did not generate";
    auto hi = duct_noise_hs_create(&ki, kr.pub, psk, true);
    if (!hi)
        return "the IK state did not open";
    if (duct_noise_hs_write_msg1_xk(hi, s_text(k_hello), out, sizeof out, &n))
        err = "a message of XKpsk3 was taken by an IKpsk2 state";
    duct_noise_hs_destroy(hi);
    if (err)
        return err;

    if (duct_noise_hs_create_for(noise_pattern_count, &ki, kr.pub, psk, true, (duct_view_u8){})
        || duct_noise_hs_create_for(noise_pattern_xkpsk3, &ki, nullptr, psk, true, (duct_view_u8){}))
        return "a state was made with a pattern past the last or an initiator knowing no server";
    return nullptr;
}

static const char *sc_prologue(void)
{
    static const char a[] = "John Galt",
                      b[] = "Dagny Taggart";
    run_t r;
    if (!run_open(&r, s_text(a)))
        return "the exchange did not open";
    const char *err = drive(&r, 1u);
    duct_noise_hs_destroy(r.hr);
    r.hr = duct_noise_hs_create_for(noise_pattern_xkpsk3, &r.kr, nullptr, r.psk, false, s_text(b));
    if (!err && (!r.hr || r1(&r, r.m1, r.n1)))
        err = "a message 1 was read under another prologue";
    duct_noise_hs_destroy(r.hr);
    r.hr = duct_noise_hs_create_for(noise_pattern_xkpsk3, &r.kr, nullptr, r.psk, false, s_text(a));
    if (!err && (!r.hr || !r1(&r, r.m1, r.n1)))
        err = "a message 1 was refused under the same prologue";
    run_close(&r);
    return err;
}

static const char *sc_mask(void)
{
    run_t r;
    if (!run_open(&r, (duct_view_u8){}))
        return "the exchange did not open";
    const char *err = drive(&r, 1u);
    uint8_t other[duct_noise_key_size];
    memcpy(other, r.psk, sizeof other);
    other[0] ^= 0x01u;
    duct_noise_hs_destroy(r.hr);
    r.hr = duct_noise_hs_create_for(noise_pattern_xkpsk3, &r.kr, nullptr, other, false, (duct_view_u8){});
    if (!err && !r.hr)
        err = "the responder did not open";
    else if (!err && r1(&r, r.m1, r.n1) == duct_handshake_mask)
        err = duct_handshake_mask ? "a message 1 was read under another mask key"
                                  : "a message 1 was refused for a mask key the build does not use";
    run_close(&r);
    return err;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    static const struct { const char *name; const char *(*fn)(void); } cases[] = {
        { "roundtrip", sc_roundtrip },
        { "sizes",     sc_sizes },
        { "tamper",    sc_tamper },
        { "password",  sc_password },
        { "foreign",   sc_foreign },
        { "replay",    sc_replay },
        { "order",     sc_order },
        { "prologue",  sc_prologue },
        { "mask",      sc_mask },
    };
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        auto err = cases[i].fn();
        if (err) {
            fprintf(stderr, "noise_xk: %s: %s\n", cases[i].name, err);
            return 1;
        }
    }
    printf("noise_xk: OK (three messages, sizes, every bit of every message, wrong password, foreign server "
           "and exchange, replay, order, prologue, mask %s)\n", duct_handshake_mask ? "on" : "off");
    return 0;
}
