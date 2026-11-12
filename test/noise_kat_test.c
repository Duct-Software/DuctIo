/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file noise_kat_test.c
 *  @brief Known answers of Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s.
 *
 *  Two sets of them. The vector of the cacophony project (@c noise_kat_ikpsk2.h) was
 *  written by another implementation: the code must write its two handshake messages
 *  and four transport messages byte for byte, end on its handshake hash, and read the
 *  transport messages it is given. The record is what the four message functions write
 *  from counting-pattern keys, taken from the code before the token interpreter
 *  replaces them, so the interpreter is shown to write the same bytes: message 1,
 *  message 2, the split keys, the exporter, which no public vector carries, and one
 *  sealed transport message each way. The test compiles @c duct_noise.c itself with the
 *  ephemeral key generator swapped for a table, which fixes the two ephemeral keys the
 *  handshake mints and leaves the code under test as it is. A message is pinned with
 *  its leading key raw, as a build without @c DUCT_HANDSHAKE_MASK sends it, and with
 *  the masked key a masking build sends in its place; the vector's masked keys come
 *  from @c gen_noise_kat.py, which applies the mask construction to the vector's bytes.
 */

#include "duct_noise.h"

#include <openssl/evp.h>

#include <stdio.h>
#include <string.h>

static constexpr unsigned k_ephemerals = 2u;
static constexpr size_t   k_message_cap = 160u;

/** @brief Ephemeral private keys in the order the handshake mints them: the initiator's, then the responder's. */
static uint8_t g_ephemeral[k_ephemerals][duct_noise_key_size];
static unsigned g_minted;

static EVP_PKEY *s_minted([[maybe_unused]] OSSL_LIB_CTX *libctx, [[maybe_unused]] const char *propq,
                          [[maybe_unused]] const char *type, ...)
{
    if (g_minted >= k_ephemerals)
        return nullptr;
    return EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, g_ephemeral[g_minted++], duct_noise_key_size);
}

#define EVP_PKEY_Q_keygen s_minted
#include "../src/wire/duct_noise.c"
#undef EVP_PKEY_Q_keygen

#include "noise_kat_ikpsk2.h"
#include "noise_kat_xkpsk3.h"

static const char k_msg1_payload[] = "kat message one.";
static const char k_msg2_payload[] = "kat two";
static const char k_plain[]        = "kat transport";

static const uint8_t k_msg1[112] = {
    0x64, 0xb1, 0x01, 0xb1, 0xd0, 0xbe, 0x5a, 0x87, 0x04, 0xbd, 0x07, 0x8f,
    0x98, 0x95, 0x00, 0x1f, 0xc0, 0x3e, 0x8e, 0x9f, 0x95, 0x22, 0xf1, 0x88,
    0xdd, 0x12, 0x8d, 0x98, 0x46, 0xd4, 0x84, 0x66, 0x15, 0x8a, 0x0e, 0x4c,
    0xa2, 0x42, 0xd1, 0x51, 0xca, 0x97, 0xab, 0x90, 0x15, 0x9a, 0x98, 0xb6,
    0x7e, 0x61, 0x66, 0x25, 0xe6, 0x8b, 0x40, 0x65, 0xd3, 0x57, 0x37, 0x6b,
    0x65, 0x98, 0xe6, 0x44, 0x26, 0x99, 0x1f, 0x64, 0x57, 0x4f, 0x3d, 0x55,
    0x50, 0xf4, 0x82, 0x46, 0x6c, 0x5a, 0x7a, 0x17, 0x1d, 0x55, 0x1f, 0xda,
    0x74, 0xc2, 0xa8, 0x6b, 0x40, 0x5e, 0x9d, 0xb3, 0x4f, 0xa2, 0xd8, 0x2b,
    0xc9, 0x39, 0x1f, 0xf5, 0x6a, 0x2f, 0x5c, 0x87, 0xf4, 0x94, 0xbb, 0x24,
    0xd9, 0x5e, 0x02, 0xe0,
};
static const uint8_t k_msg1_masked_head[duct_noise_key_size] = {
    0x4b, 0xe4, 0x74, 0x48, 0xf5, 0x10, 0x8d, 0x58, 0xb0, 0xf4, 0x87, 0x8f,
    0x96, 0x55, 0x8d, 0xd6, 0x98, 0x43, 0xa7, 0x6d, 0x3f, 0x20, 0x88, 0xff,
    0x44, 0xb4, 0xf6, 0xed, 0x8e, 0xbf, 0xe6, 0xfa,
};
static const uint8_t k_msg2[55] = {
    0x24, 0x4f, 0xe3, 0xb9, 0x63, 0xe8, 0x99, 0xdd, 0x29, 0x5b, 0xaf, 0xfc,
    0xe2, 0x48, 0xd3, 0x53, 0x0f, 0x3a, 0x9a, 0x74, 0x79, 0xba, 0x06, 0x30,
    0x02, 0x68, 0x0e, 0xbf, 0xe7, 0xad, 0xad, 0x49, 0x1e, 0x58, 0x11, 0xdb,
    0x12, 0x46, 0xda, 0xd5, 0x6e, 0x10, 0x4a, 0x6e, 0x04, 0x82, 0xcb, 0xfc,
    0x75, 0xeb, 0x96, 0x84, 0x0d, 0x3f, 0x65,
};
static const uint8_t k_msg2_masked_head[duct_noise_key_size] = {
    0xed, 0x4d, 0x6b, 0xdb, 0x70, 0x07, 0x15, 0x88, 0x33, 0x65, 0x7e, 0x17,
    0xbd, 0xbc, 0x84, 0x32, 0xa9, 0x16, 0x3e, 0xa0, 0x91, 0xbb, 0xf5, 0x0a,
    0x38, 0x13, 0xd6, 0x1c, 0x25, 0x3a, 0xbc, 0x28,
};
static const uint8_t k_initiator_send[32] = {
    0x6e, 0x95, 0x3e, 0x90, 0x73, 0x9f, 0x05, 0x5c, 0x9a, 0xa2, 0x5d, 0x71,
    0xce, 0x5a, 0xcf, 0xe1, 0x18, 0xd4, 0x04, 0xec, 0xc1, 0x63, 0xf1, 0xd7,
    0xf6, 0x80, 0x63, 0x30, 0x47, 0xf8, 0x6e, 0xc4,
};
static const uint8_t k_initiator_recv[32] = {
    0x9b, 0x83, 0x9f, 0xfe, 0xc2, 0xec, 0xf2, 0xed, 0xa4, 0x1b, 0x7c, 0x2a,
    0xf3, 0x24, 0xc6, 0xa1, 0x3e, 0xe7, 0x78, 0xa7, 0xdf, 0x54, 0xdf, 0xdf,
    0x53, 0x8b, 0x35, 0x0b, 0xfc, 0xc0, 0x1b, 0x18,
};
static const uint8_t k_exporter[duct_noise_key_size] = {
    0xbf, 0x8e, 0xb8, 0x9b, 0x29, 0xe5, 0xcf, 0x7b, 0xcb, 0xad, 0x45, 0xdb,
    0x39, 0x47, 0xf4, 0x05, 0x57, 0x80, 0x29, 0x1e, 0x04, 0xb3, 0xf7, 0x40,
    0xb6, 0xbd, 0x60, 0x34, 0xdd, 0x2b, 0x8a, 0xbe,
};
static const uint8_t k_sealed_i2r[37] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3d, 0xe8, 0x8a, 0x51,
    0x1a, 0x5c, 0xb5, 0x4b, 0x0a, 0x6d, 0x28, 0x19, 0xd1, 0xb5, 0xf1, 0x79,
    0x30, 0xed, 0x09, 0xc2, 0x94, 0x11, 0x41, 0x3d, 0x46, 0xfb, 0x1c, 0x24,
    0xf1,
};
static const uint8_t k_sealed_r2i[37] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x9a, 0x90, 0xff,
    0xd4, 0xd3, 0x20, 0x1b, 0xe3, 0x03, 0xdc, 0xe7, 0x48, 0x5e, 0xf4, 0x31,
    0xac, 0xce, 0xeb, 0xfb, 0xc9, 0x02, 0xda, 0xf7, 0x56, 0xbd, 0xc6, 0xea,
    0x53,
};

static void s_fill(uint8_t *p, size_t n, uint8_t first)
{
    for (size_t i = 0u; i < n; ++i)
        p[i] = (uint8_t)(first + i);
}

static duct_view_u8 s_bytes(const uint8_t *p, size_t n)
{
    return duct_view(duct_view_u8, (void *)p, n);
}

static duct_view_u8 s_text(const char *s)
{
    return s_bytes((const uint8_t *)s, strlen(s));
}

static bool s_same(const uint8_t *got, size_t n, duct_view_u8 want)
{
    return n == want.size && memcmp(got, want.data, n) == 0;
}

static unsigned g_failed;

/** @brief Compare @p got with @p want; on a difference print @p got as the initializer that pins it. */
static void s_expect(const char *name, const uint8_t *got, const uint8_t *want, size_t n)
{
    if (memcmp(got, want, n) == 0)
        return;
    ++g_failed;
    printf("%s differs; the code wrote\nstatic const uint8_t %s[%zu] = {", name, name, n);
    for (size_t i = 0u; i < n; ++i)
        printf("%s0x%02x,", i % 12u == 0u ? "\n    " : " ", got[i]);
    printf("\n};\n");
}

/** @brief Compare a handshake message of @p n bytes: its leading key against the raw or the masked pin, the rest against @p want. */
static void s_expect_message(const char *name, const uint8_t *got, const uint8_t *want,
                             const uint8_t masked_head[duct_noise_key_size], size_t n)
{
    s_expect(duct_handshake_mask ? "head, masked" : "head, raw", got, duct_handshake_mask ? masked_head : want,
             duct_noise_key_size);
    s_expect(name, got + duct_noise_key_size, want + duct_noise_key_size, n - duct_noise_key_size);
}

/** @brief The two ends of a run: what they are given, and the bytes they write. */
typedef struct {
    duct_noise_pattern_t    pattern;
    duct_noise_keypair_t    ki,
                            kr;
    const uint8_t          *psk;
    duct_view_u8              payload[3];
    duct_noise_hs_t        *hi,
                           *hr;
    duct_noise_transport_t  ti,
                            tr;
    uint8_t                 msg[3][k_message_cap],
                            exporter[sizeof k_exporter],
                            sealed_i2r[sizeof k_sealed_i2r],
                            sealed_r2i[sizeof k_sealed_r2i];
    size_t                  len[3];
} kat_t;

/** @brief The key the psk token mixes at the responder, whichever peer is asking. */
static bool s_psk_of(void *ctx, [[maybe_unused]] const uint8_t remote[duct_noise_key_size],
                     uint8_t out[duct_noise_key_size])
{
    memcpy(out, ((kat_t *)ctx)->psk, duct_noise_key_size);
    return true;
}

/** @brief Write and read the two messages of IKpsk2 between the ends of @p k.
 *  @return the text of the first step that failed, nullptr when all passed. */
static const char *s_ik_messages(kat_t *k)
{
    uint8_t remote[duct_noise_key_size],
            payload[64];
    size_t payload_len = 0u;
    if (!duct_noise_hs_write_msg1(k->hi, k->payload[0], k->msg[0], sizeof k->msg[0], &k->len[0]))
        return "message 1 failed";
    if (!duct_noise_hs_read_msg1(k->hr, s_bytes(k->msg[0], k->len[0]), remote, payload, sizeof payload,
                                 &payload_len)
        || memcmp(remote, k->ki.pub, sizeof remote) != 0
        || !s_same(payload, payload_len, k->payload[0]))
        return "message 1 was not read";
    if (!duct_noise_hs_write_msg2(k->hr, k->payload[1], k->msg[1], sizeof k->msg[1], &k->len[1]))
        return "message 2 failed";
    if (!duct_noise_hs_read_msg2(k->hi, s_bytes(k->msg[1], k->len[1])))
        return "message 2 was not read";
    return nullptr;
}

/** @brief Write and read the three messages of XKpsk3 between the ends of @p k.
 *  @return the text of the first step that failed, nullptr when all passed. */
static const char *s_xk_messages(kat_t *k)
{
    uint8_t remote[duct_noise_key_size],
            payload[64];
    size_t payload_len = 0u;
    if (!duct_noise_hs_write_msg1_xk(k->hi, k->payload[0], k->msg[0], sizeof k->msg[0], &k->len[0]))
        return "message 1 failed";
    if (!duct_noise_hs_read_msg1_xk(k->hr, s_bytes(k->msg[0], k->len[0]), payload, sizeof payload, &payload_len)
        || !s_same(payload, payload_len, k->payload[0]))
        return "message 1 was not read";
    if (!duct_noise_hs_write_msg2_xk(k->hr, k->payload[1], k->msg[1], sizeof k->msg[1], &k->len[1]))
        return "message 2 failed";
    if (!duct_noise_hs_read_msg2_xk(k->hi, s_bytes(k->msg[1], k->len[1])))
        return "message 2 was not read";
    if (!duct_noise_hs_write_msg3_xk(k->hi, k->payload[2], k->msg[2], sizeof k->msg[2], &k->len[2]))
        return "message 3 failed";
    if (!duct_noise_hs_read_msg3_xk(k->hr, s_bytes(k->msg[2], k->len[2]), s_psk_of, k, remote, payload,
                                    sizeof payload, &payload_len)
        || memcmp(remote, k->ki.pub, sizeof remote) != 0
        || !s_same(payload, payload_len, k->payload[2]))
        return "message 3 was not read";
    return nullptr;
}

/** @brief Run the handshake between the ends of @p k, split them and take the exporter.
 *  @return the text of the first step that failed, nullptr when all passed. */
static const char *s_handshake(kat_t *k)
{
    auto err = k->pattern == noise_pattern_ikpsk2 ? s_ik_messages(k) : s_xk_messages(k);
    if (err)
        return err;
    uint8_t exporter_r[sizeof k->exporter];
    if (!duct_noise_hs_split(k->hi, &k->ti) || !duct_noise_hs_split(k->hr, &k->tr)
        || !duct_noise_hs_exporter(k->hi, k->exporter) || !duct_noise_hs_exporter(k->hr, exporter_r)
        || memcmp(k->exporter, exporter_r, sizeof exporter_r) != 0
        || memcmp(k->ti.send_key, k->tr.recv_key, sizeof k->ti.send_key) != 0
        || memcmp(k->ti.recv_key, k->tr.send_key, sizeof k->ti.recv_key) != 0)
        return "the two ends do not agree";
    return nullptr;
}

/** @brief Run the handshake of the record, then seal one message each way, into @p k.
 *  @return the text of the first step that failed, nullptr when all passed. */
static const char *s_run(kat_t *k)
{
    uint8_t si[duct_noise_key_size], sr[duct_noise_key_size], psk[duct_noise_key_size];
    g_minted = 0u;
    s_fill(g_ephemeral[0], sizeof g_ephemeral[0], 0x41u);
    s_fill(g_ephemeral[1], sizeof g_ephemeral[1], 0x61u);
    s_fill(si, sizeof si, 0x01u);
    s_fill(sr, sizeof sr, 0x21u);
    s_fill(psk, sizeof psk, 0xa1u);
    if (!duct_noise_keypair_from_priv(&k->ki, si) || !duct_noise_keypair_from_priv(&k->kr, sr))
        return "static keys failed";
    k->hi = duct_noise_hs_create(&k->ki, k->kr.pub, psk, true);
    k->hr = duct_noise_hs_create(&k->kr, nullptr, psk, false);
    if (!k->hi || !k->hr)
        return "handshake state failed";

    k->payload[0] = s_text(k_msg1_payload);
    k->payload[1] = s_text(k_msg2_payload);
    auto err = s_handshake(k);
    if (err)
        return err;
    if (k->len[0] != sizeof k_msg1 || k->len[1] != sizeof k_msg2)
        return "a message has another size";
    size_t n1 = duct_noise_transport_seal(&k->ti, (duct_view_u8[]){ s_text(k_plain) }, 1u, k->sealed_i2r, sizeof k->sealed_i2r);
    size_t n2 = duct_noise_transport_seal(&k->tr, (duct_view_u8[]){ s_text(k_plain) }, 1u, k->sealed_r2i, sizeof k->sealed_r2i);
    return n1 == sizeof k->sealed_i2r && n2 == sizeof k->sealed_r2i ? nullptr : "sealing failed";
}

/** @brief Seal the transport messages of @p v from the ends of @p k, the initiator's at even places and the
 *  responder's at odd, and open each by the other end from the bytes of the vector.
 *  @return the text of the first step that failed, nullptr when all passed. */
static const char *s_transport(kat_t *k, const vector_t *v)
{
    for (unsigned i = v->handshake_messages; i < v->messages; ++i) {
        const vector_msg_t *m = &v->message[i];
        bool from_initiator = i % 2u == 0u;
        auto from = from_initiator ? &k->ti : &k->tr;
        auto to = from_initiator ? &k->tr : &k->ti;
        uint8_t counter[duct_noise_counter_size] = { (uint8_t)((i - v->handshake_messages) / 2u) },
                wire[96],
                plain[64];
        size_t sealed_len = sizeof counter + m->ct_len,
               plain_len = 0u;
        if (duct_noise_transport_seal(from, (duct_view_u8[]){ s_bytes(m->payload, m->payload_len) }, 1u, wire, sizeof wire) != sealed_len)
            return "a transport message sealed to another size";
        uint8_t covered[duct_noise_counter_size];
        memcpy(covered, counter, sizeof counter);
        duct_noise_counter_cover(from->send_key, covered, wire + sizeof counter,
                                 from->counter_size);
        s_expect("vector transport counter", wire, covered, from->counter_size);
        s_expect("vector transport message", wire + sizeof counter, m->ct, m->ct_len);
        uint64_t used = from->send_counter - 1u;
        for (size_t cut = 0u; cut <= m->payload_len; ++cut) {
            duct_view_u8 parts[3] = { s_bytes(m->payload, cut), {}, s_bytes(m->payload + cut, m->payload_len - cut) };
            uint8_t again[sizeof wire];
            from->send_counter = used;
            if (duct_noise_transport_seal(from, parts, 3u, again, sizeof again) != sealed_len
                || memcmp(again, wire, sealed_len) != 0)
                return "a transport message cut into spans sealed to other bytes";
        }
        from->send_counter = used + 1u;
        memcpy(wire, counter, sizeof counter);
        duct_noise_counter_cover(to->recv_key, wire, wire + sizeof counter,
                                 to->counter_size);
        memcpy(wire + sizeof counter, m->ct, m->ct_len);
        if (!duct_noise_transport_unseal(to, s_bytes(wire, sealed_len), plain, sizeof plain, &plain_len)
            || !s_same(plain, plain_len, s_bytes(m->payload, m->payload_len)))
            return "a transport message was not read";
    }
    return nullptr;
}

/** @brief Run the cacophony vector @p v: the handshake messages and the hash they end on, then its transport
 *  messages.
 *  @return the text of the first step that failed, nullptr when all passed. */
static const char *s_run_vector(kat_t *k, const vector_t *v)
{
    static const char *const names[] = { "vector message 1", "vector message 2", "vector message 3" };
    g_minted = 0u;
    memcpy(g_ephemeral[0], v->init_ephemeral, duct_noise_key_size);
    memcpy(g_ephemeral[1], v->resp_ephemeral, duct_noise_key_size);
    if (!duct_noise_keypair_from_priv(&k->ki, v->init_static) || !duct_noise_keypair_from_priv(&k->kr, v->resp_static)
        || memcmp(k->kr.pub, v->resp_static_pub, sizeof k->kr.pub) != 0)
        return "static keys failed";
    duct_view_u8 prologue = s_bytes(v->prologue, v->prologue_len);
    k->pattern = v->pattern;
    k->psk = v->psk;
    k->hi = duct_noise_hs_create_for(v->pattern, &k->ki, k->kr.pub, v->psk, true, prologue);
    k->hr = duct_noise_hs_create_for(v->pattern, &k->kr, nullptr, v->psk, false, prologue);
    if (!k->hi || !k->hr)
        return "handshake state failed";
    for (unsigned i = 0u; i < v->handshake_messages; ++i)
        k->payload[i] = s_bytes(v->message[i].payload, v->message[i].payload_len);
    auto err = s_handshake(k);
    if (err)
        return err;
    for (unsigned i = 0u; i < v->handshake_messages; ++i)
        if (k->len[i] != v->message[i].ct_len)
            return "a message has another size";
    for (unsigned i = 0u; i < v->handshake_messages; ++i)
        if (i < 2u)
            s_expect_message(names[i], k->msg[i], v->message[i].ct, v->masked_head[i], k->len[i]);
        else
            s_expect(names[i], k->msg[i], v->message[i].ct, k->len[i]);
    s_expect("vector hash, initiator", k->hi->h, v->handshake_hash, duct_noise_key_size);
    s_expect("vector hash, responder", k->hr->h, v->handshake_hash, duct_noise_key_size);
    return s_transport(k, v);
}

static void s_release(kat_t *k)
{
    duct_noise_transport_destroy(&k->ti);
    duct_noise_transport_destroy(&k->tr);
    duct_noise_hs_destroy(k->hi);
    duct_noise_hs_destroy(k->hr);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    const vector_t *const vectors[] = { &v_ik, &v_xk };
    kat_t kv[sizeof vectors / sizeof vectors[0]] = {},
          k = {};
    bool failed = false;
    for (size_t i = 0u; i < sizeof vectors / sizeof vectors[0]; ++i) {
        auto err = s_run_vector(&kv[i], vectors[i]);
        if (err)
            fprintf(stderr, "noise_kat: %s: %s\n", vectors[i]->name, err);
        failed = failed || err;
        s_release(&kv[i]);
    }
    auto err = s_run(&k);
    if (err)
        fprintf(stderr, "noise_kat: the record: %s\n", err);
    else {
        s_expect_message("k_msg1", k.msg[0], k_msg1, k_msg1_masked_head, sizeof k_msg1);
        s_expect_message("k_msg2", k.msg[1], k_msg2, k_msg2_masked_head, sizeof k_msg2);
        s_expect("k_initiator_send", k.ti.send_key, k_initiator_send, sizeof k_initiator_send);
        s_expect("k_initiator_recv", k.ti.recv_key, k_initiator_recv, sizeof k_initiator_recv);
        s_expect("k_exporter", k.exporter, k_exporter, sizeof k_exporter);
        uint8_t want_i2r[sizeof k_sealed_i2r], want_r2i[sizeof k_sealed_r2i];
        memcpy(want_i2r, k_sealed_i2r, sizeof want_i2r);
        duct_noise_counter_cover(k.ti.send_key, want_i2r, want_i2r + 8u, k.ti.counter_size);
        s_expect("k_sealed_i2r", k.sealed_i2r, want_i2r, sizeof k.sealed_i2r);
        memcpy(want_r2i, k_sealed_r2i, sizeof want_r2i);
        duct_noise_counter_cover(k.tr.send_key, want_r2i, want_r2i + 8u, k.tr.counter_size);
        s_expect("k_sealed_r2i", k.sealed_r2i, want_r2i, sizeof k.sealed_r2i);
    }
    s_release(&k);
    if (failed || err || g_failed) {
        fprintf(stderr, "noise_kat: %u values differ\n", g_failed);
        return 1;
    }
    printf("noise_kat: OK (the cacophony vectors of IKpsk2 and XKpsk3, then the IK record of messages, split keys, "
           "exporter and sealed transport, %s)\n", duct_handshake_mask ? "masked" : "raw");
    return 0;
}
