/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file noise_compact_test.c
 *  @brief The compact sequence number of the datagram transport: a Noise
 *  transport pair whose counter crosses the wire covered to its low 4 bytes.
 *
 *  Both ends are split from one handshake, driven in memory, and told to send the
 *  counter compact. `size` holds what a message costs: 4 counter bytes where the
 *  full one takes 8, the bytes covered by a draw of the message's own ciphertext,
 *  which both ends rebuild. `order` takes ten
 *  messages in reverse and each once, and every replay refused. `loss` takes one
 *  message in seven from a long run. `wrap` carries the counter across 2^32 in
 *  order, and takes late messages from either side of the wrap behind a top
 *  beyond it, each rebuilt on its own side. `far` is the fail-closed case: a
 *  message sealed 2^31 and more counters ahead of the receiver's top rebuilds to
 *  a counter the sender never used, fails authentication, leaves the window as it
 *  was, and the stream behind it goes on. `forged` changes one bit of each byte of
 *  a message in turn, counter bytes included, and every one is refused with the
 *  window unmoved. `mixed` holds a compact end and a full end to refusing each
 *  other.
 */

#include "duct_noise.h"
#include "duct_noise_internal.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    duct_noise_transport_t cli,
                           srv;
} pair_t;

/** @brief Run IKpsk2 in memory and split both ends, compact or not. */
static bool pair_open(pair_t *p, bool compact)
{
    duct_noise_keypair_t kc, ks;
    uint8_t psk[duct_noise_key_size] = { 7u };
    if (!duct_noise_keypair_generate(&kc) || !duct_noise_keypair_generate(&ks))
        return false;
    auto hi = duct_noise_hs_create(&kc, ks.pub, psk, true);
    auto hr = duct_noise_hs_create(&ks, nullptr, psk, false);
    uint8_t m1[256], m2[256], learned[duct_noise_key_size], pay[64];
    size_t n1 = 0u, n2 = 0u, pn = 0u;
    *p = (pair_t){};
    bool ok = hi && hr
           && duct_noise_hs_write_msg1(hi, (duct_view_u8){}, m1, sizeof m1, &n1)
           && duct_noise_hs_read_msg1(hr, (duct_view_u8){ m1, n1 }, learned, pay, sizeof pay, &pn)
           && duct_noise_hs_write_msg2(hr, (duct_view_u8){}, m2, sizeof m2, &n2)
           && duct_noise_hs_read_msg2(hi, (duct_view_u8){ m2, n2 })
           && duct_noise_hs_split(hi, &p->cli)
           && duct_noise_hs_split(hr, &p->srv);
    duct_noise_hs_destroy(hi);
    duct_noise_hs_destroy(hr);
    if (compact)
        p->cli.counter_size = p->srv.counter_size = duct_noise_counter_compact_size;
    return ok;
}

static void pair_close(pair_t *p)
{
    duct_noise_transport_destroy(&p->cli);
    duct_noise_transport_destroy(&p->srv);
}

/** @brief Seal the pattern for message @p i on @p from. */
static size_t seal_msg(duct_noise_transport_t *from, unsigned i, uint8_t *out, size_t cap)
{
    uint8_t plain[24];
    for (unsigned k = 0u; k < sizeof plain; ++k)
        plain[k] = (uint8_t)(i * 13u + k);
    return duct_noise_transport_seal(from, &(duct_view_u8){ plain, sizeof plain }, 1u, out, cap);
}

/** @brief Check that @p sealed unseals on @p to as message @p i. */
static bool takes(duct_noise_transport_t *to, const uint8_t *sealed, size_t len, unsigned i)
{
    uint8_t plain[64], want[24];
    size_t n = 0u;
    for (unsigned k = 0u; k < sizeof want; ++k)
        want[k] = (uint8_t)(i * 13u + k);
    return duct_noise_transport_unseal(to, (duct_view_u8){ (void *)sealed, len }, plain,
                                       sizeof plain, &n)
        && n == sizeof want && memcmp(plain, want, n) == 0;
}

/** @brief Check that @p to refuses @p sealed. */
static bool refuses(duct_noise_transport_t *to, const uint8_t *sealed, size_t len)
{
    uint8_t plain[64];
    size_t n = 0u;
    return !duct_noise_transport_unseal(to, (duct_view_u8){ (void *)sealed, len }, plain,
                                        sizeof plain, &n);
}

static const char *sc_size(void)
{
    pair_t full, compact;
    if (!pair_open(&full, false) || !pair_open(&compact, true))
        return "the handshake did not run";
    const char *err = nullptr;
    uint8_t a[64], b[64];
    compact.cli.send_counter = UINT64_C(0xAABBCCDD11223344);
    full.cli.send_counter = UINT64_C(0xAABBCCDD11223344);
    size_t lc = seal_msg(&compact.cli, 1u, a, sizeof a),
           lf = seal_msg(&full.cli, 1u, b, sizeof b);
    if (lf != 8u + 24u + duct_noise_tag_size || lc != 4u + 24u + duct_noise_tag_size)
        err = "a compact message does not cost 4 counter bytes against the full 8";
    else if (duct_noise_transport_seal_size_of(&compact.cli, 24u) != lc
             || duct_noise_transport_seal_size_of(&full.cli, 24u) != lf)
        err = "the sealed size a transport reports is not the one it writes";
    else if (a[0] == 0x44u && a[1] == 0x33u && a[2] == 0x22u && a[3] == 0x11u)
        err = "the compact counter rode the wire uncovered";
    else if (b[4] == 0xDDu && b[5] == 0xCCu && b[6] == 0xBBu && b[7] == 0xAAu)
        err = "the full counter's high half rode the wire uncovered";
    uint8_t tiny[4 + duct_noise_tag_size];
    if (!err && duct_noise_transport_seal(&compact.cli, nullptr, 0u, tiny, sizeof tiny - 1u))
        err = "a compact seal wrote into a buffer a byte short of its own size";
    if (!err && !duct_noise_transport_seal(&compact.cli, nullptr, 0u, tiny, sizeof tiny))
        err = "a compact empty message did not fit the size it reports";
    pair_close(&full);
    pair_close(&compact);
    return err;
}

static const char *sc_order(void)
{
    pair_t p;
    if (!pair_open(&p, true))
        return "the handshake did not run";
    const char *err = nullptr;
    uint8_t m[10][64];
    size_t len[10];
    for (unsigned i = 0u; i < 10u; ++i)
        len[i] = seal_msg(&p.cli, i, m[i], sizeof m[i]);
    for (unsigned i = 10u; i-- > 0u;) {
        if (!takes(&p.srv, m[i], len[i], i)) {
            err = "a message arriving out of order was refused";
            break;
        }
    }
    for (unsigned i = 0u; !err && i < 10u; ++i)
        if (!refuses(&p.srv, m[i], len[i]))
            err = "a replay of a compact message was accepted";
    pair_close(&p);
    return err;
}

static const char *sc_loss(void)
{
    pair_t p;
    if (!pair_open(&p, true))
        return "the handshake did not run";
    const char *err = nullptr;
    uint8_t m[64];
    for (unsigned i = 0u; !err && i < 3000u; ++i) {
        size_t n = seal_msg(&p.cli, i, m, sizeof m);
        if (i % 7u == 3u && !takes(&p.srv, m, n, i))
            err = "a message behind a gap of lost ones was refused";
    }
    pair_close(&p);
    return err;
}

static const char *sc_wrap(void)
{
    pair_t p;
    if (!pair_open(&p, true))
        return "the handshake did not run";
    const char *err = nullptr;
    uint8_t m[8][64];
    size_t len[8];
    p.cli.send_counter = UINT64_C(0xFFFFFFFE);
    for (unsigned i = 0u; i < 8u; ++i)
        len[i] = seal_msg(&p.cli, i, m[i], sizeof m[i]);
    /* Counters 0xFFFFFFFE, 0xFFFFFFFF, then 0x100000000 up to 0x100000005. */
    for (unsigned i = 0u; !err && i < 6u; ++i)
        if (!takes(&p.srv, m[i], len[i], i))
            err = "the counter was lost crossing 2^32";
    if (!err && p.srv.replay_top != UINT64_C(0x100000003))
        err = "the receiver's top did not follow the counter past 2^32";
    if (!err && !refuses(&p.srv, m[0], len[0]))
        err = "a replay of a message from before the wrap was taken";
    if (!err && !takes(&p.srv, m[7], len[7], 7u))
        err = "a message ahead of the receiver's top was refused";
    pair_close(&p);
    if (err)
        return err;

    if (!pair_open(&p, true))
        return "the handshake did not run";
    p.cli.send_counter = UINT64_C(0xFFFFFFFD);
    for (unsigned i = 0u; i < 5u; ++i)
        len[i] = seal_msg(&p.cli, i, m[i], sizeof m[i]);
    /* 0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFF, 0x100000000, 0x100000001. */
    if (!takes(&p.srv, m[2], len[2], 2u) || !takes(&p.srv, m[4], len[4], 4u)
        || !takes(&p.srv, m[3], len[3], 3u) || !takes(&p.srv, m[1], len[1], 1u)
        || !takes(&p.srv, m[0], len[0], 0u))
        err = "a late message was not placed on its own side of the wrap";
    pair_close(&p);
    return err;
}

static const char *sc_far(void)
{
    pair_t p;
    if (!pair_open(&p, true))
        return "the handshake did not run";
    const char *err = nullptr;
    uint8_t m[64], jumped[64];
    size_t n = seal_msg(&p.cli, 0u, m, sizeof m);
    if (!takes(&p.srv, m, n, 0u)) {
        pair_close(&p);
        return "the first message was refused";
    }
    uint64_t top = p.srv.replay_top,
             resume = p.cli.send_counter;
    static const uint64_t beyond[] = {
        UINT64_C(0x80000000), UINT64_C(0x80000005), UINT64_C(0xC0000000),
        UINT64_C(0xFFFFFFFF), UINT64_C(0x100000000), UINT64_C(0x100000007),
    };
    for (size_t i = 0u; !err && i < sizeof beyond / sizeof beyond[0]; ++i) {
        p.cli.send_counter = top + beyond[i];
        size_t nf = seal_msg(&p.cli, 1u, jumped, sizeof jumped);
        if (takes(&p.srv, jumped, nf, 1u))
            err = "a message 2^31 counters or more ahead of the top was taken under a counter the sender never used";
        else if (p.srv.replay_top != top)
            err = "a refused far message moved the receiver's window";
    }
    if (!err) {
        p.cli.send_counter = resume;
        n = seal_msg(&p.cli, 2u, m, sizeof m);
        if (!takes(&p.srv, m, n, 2u))
            err = "the stream behind a refused far message was refused too";
    }
    if (!err) {
        p.cli.send_counter = p.srv.replay_top + UINT64_C(0x7FFFFFFF);
        n = seal_msg(&p.cli, 3u, m, sizeof m);
        if (!takes(&p.srv, m, n, 3u))
            err = "a message just under 2^31 counters ahead of the top was refused";
    }
    pair_close(&p);
    return err;
}

static const char *sc_forged(void)
{
    pair_t p;
    if (!pair_open(&p, true))
        return "the handshake did not run";
    const char *err = nullptr;
    uint8_t m[64], bad[64];
    size_t n = seal_msg(&p.cli, 0u, m, sizeof m);
    if (!takes(&p.srv, m, n, 0u)) {
        pair_close(&p);
        return "the first message was refused";
    }
    n = seal_msg(&p.cli, 1u, m, sizeof m);
    uint64_t top = p.srv.replay_top;
    for (size_t at = 0u; at < n && !err; ++at) {
        memcpy(bad, m, n);
        bad[at] ^= 0x01u;
        if (!refuses(&p.srv, bad, n))
            err = "a message with one bit changed was accepted";
        else if (p.srv.replay_top != top)
            err = "a forged message moved the receiver's window";
    }
    if (!err && !takes(&p.srv, m, n, 1u))
        err = "the genuine message was refused after the forged ones";
    if (!err && !refuses(&p.srv, m, n - 1u))
        err = "a truncated message was accepted";
    uint8_t shorty[3] = {};
    if (!err && !refuses(&p.srv, shorty, sizeof shorty))
        err = "a message shorter than the counter and the tag was accepted";
    pair_close(&p);
    return err;
}

static const char *sc_mixed(void)
{
    pair_t p;
    if (!pair_open(&p, true))
        return "the handshake did not run";
    uint8_t m[64];
    p.srv.counter_size = duct_noise_counter_size;
    size_t n = seal_msg(&p.cli, 0u, m, sizeof m);
    const char *err = nullptr;
    if (!refuses(&p.srv, m, n))
        err = "a full end took a compact end's message";
    pair_close(&p);
    if (err)
        return err;
    if (!pair_open(&p, false))
        return "the handshake did not run";
    p.srv.counter_size = duct_noise_counter_compact_size;
    n = seal_msg(&p.cli, 0u, m, sizeof m);
    if (!refuses(&p.srv, m, n))
        err = "a compact end took a full end's message";
    pair_close(&p);
    return err;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    static const struct { const char *name; const char *(*fn)(void); } cases[] = {
        { "size",   sc_size },
        { "order",  sc_order },
        { "loss",   sc_loss },
        { "wrap",   sc_wrap },
        { "far",    sc_far },
        { "forged", sc_forged },
        { "mixed",  sc_mixed },
    };
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        auto err = cases[i].fn();
        if (err) {
            fprintf(stderr, "noise_compact: %s: %s\n", cases[i].name, err);
            return 1;
        }
    }
    printf("noise_compact: OK (4-byte counter, reorder, loss, the wrap at 2^32, "
           "fail-closed far and forged messages, a compact and a full end refusing each other)\n");
    return 0;
}
