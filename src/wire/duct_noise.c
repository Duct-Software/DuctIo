/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_noise.c
 *  @brief Noise_IKpsk2 and Noise_XKpsk3 over 25519, ChaChaPoly and BLAKE2s.
 *
 *  Implements the Noise Protocol Framework's generic Symmetric State
 *  (InitializeSymmetric/MixHash/MixKey/MixKeyAndHash/EncryptAndHash/
 *  DecryptAndHash/Split) plus the IKpsk2 and XKpsk3 handshake patterns exactly
 *  per spec:
 *
 *   IKpsk2              XKpsk3
 *   <- s                <- s
 *   ...                 ...
 *   -> e, es, s, ss     -> e, es
 *   <- e, ee, se, psk   <- e, ee
 *                       -> s, se, psk
 *
 *  Every DH/AEAD/hash call goes through OpenSSL EVP (X25519, ChaCha20-Poly1305,
 *  BLAKE2s-256) — no custom cryptography, only the state machine wiring them
 *  together.
 *
 *  Under @c DUCT_HANDSHAKE_MASK the ephemeral key leading message 1 and message 2
 *  is exclusive-ored with @ref duct_noise_ephemeral_mask after the message is
 *  written and again before it is read. The transcript hashes the key itself.
 *
 *  Installs the engine's allocator in OpenSSL ahead of main. The calls that load a key into an
 *  OpenSSL object run in a secret scope, so the copies OpenSSL keeps of the key come from
 *  @c duct_new_secret: locked pages where the system allows them, wiped when freed.
 *
 *  Also defines @ref duct_hmac_sha256, which shares its HMAC call with the HKDF.
 */

#include "duct_noise_internal.h"
#include "duct_core.h"
#include "duct_crypto.h"
#include "duct_hash.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <assert.h>
#include <limits.h>
#include <string.h>

/** @brief Secret blocks one outermost scope makes, at most.
 *  Past them the scope's allocations go to the heap unmarked, and the first of them prints a
 *  @c duct_diag line: the scope is building the tables of an algorithm that @ref s_ossl_mem_ctor
 *  does not fetch.
 */
static constexpr unsigned s_scope_blocks_max = 128u;

/** @brief Flag set while this thread loads a key into an OpenSSL object.
 *  @ref s_ossl_malloc answers secret blocks while it is set. A function that loads a key into an
 *  OpenSSL object runs under it from @ref s_scope_enter to the end of its block.
 */
static thread_local bool     s_secret_scope;
/** @brief Secret blocks made so far by the outermost scope of this thread. */
static thread_local unsigned s_scope_blocks;

/** @brief Open a secret scope on this thread.
 *  @return the flag as it stood, which @ref s_scope_leave restores.
 */
static bool s_scope_enter(void)
{
    bool outer = s_secret_scope;
    s_secret_scope = true;
    return outer;
}

/** @brief Close a secret scope, restoring the flag @p outer holds.
 *  The handler of the @c [[gnu::cleanup]] variable that keeps @ref s_scope_enter's answer; the
 *  close of the outermost scope also zeroes the block count.
 */
static void s_scope_leave(bool *outer)
{
    s_secret_scope = *outer;
    if (!*outer)
        s_scope_blocks = 0u;
}

/** @brief Make a zeroed block of @p n bytes for OpenSSL, a @c duct_new_secret block where @p secret.
 *  @return nullptr for an @p n of 0 or of 4 GiB or more, and where the allocation fails.
 */
static void *s_ossl_alloc(size_t n, bool secret)
{
    return duct_at(secret ? duct_new_secret(uint8_t, n) : duct_new(uint8_t, n));
}

/** @brief Allocate a block for OpenSSL: a secret one inside a scope under its cap, else a heap block. */
static void *s_ossl_malloc(size_t n, [[maybe_unused]] const char *file, [[maybe_unused]] int line)
{
    bool secret = s_secret_scope && ++s_scope_blocks <= s_scope_blocks_max;
    if (s_scope_blocks == s_scope_blocks_max + 1u)
        duct_diag("OpenSSL made over %u blocks in one secret scope; fetch its algorithms in s_ossl_mem_ctor",
                  s_scope_blocks_max);
    return s_ossl_alloc(n, secret);
}

/** @brief Move a block of OpenSSL's to a fresh one of @p n bytes and the same kind.
 *  The smaller of the two sizes is copied and @p old is released, a secret one wiped. A @p old of
 *  nullptr is a malloc and an @p n of 0 releases @p old and answers nullptr. An allocation that
 *  fails answers nullptr and leaves @p old standing.
 */
static void *s_ossl_realloc(void *old, size_t n, const char *file, int line)
{
    duct_do_if(!old, return s_ossl_malloc(n, file, line));
    if (!n) {
        duct_del(old);
        return nullptr;
    }
    const duct_alloc_hdr_t *h = duct_block_hdr(old);
    void *fresh = s_ossl_alloc(n, h->secret);
    duct_do_if(!fresh, return nullptr);
    memcpy(fresh, old, duct_min((size_t)h->size, n));
    duct_del(old);
    return fresh;
}

/** @brief Release a block of OpenSSL's, wiping a secret one. nullptr releases nothing. */
static void s_ossl_free(void *p, [[maybe_unused]] const char *file, [[maybe_unused]] int line)
{
    duct_del(p);
}

/** @brief Install the engine's allocator in OpenSSL before main, and fetch the algorithms of this file.
 *  OpenSSL refuses the install once it has allocated, and the constructor then leaves it on its own
 *  allocator. OpenSSL builds its tables at the first fetch of an algorithm and not at its
 *  initialisation, so each algorithm this file calls, and the private random source, is built here,
 *  outside any secret scope; one first used inside a scope makes its tables there, up to
 *  @ref s_scope_blocks_max of them.
 */
static void s_ossl_mem_ctor(void) __attribute__((constructor(DUCT_CTOR_PRI_CORE)));
static void s_ossl_mem_ctor(void)
{
    if (!CRYPTO_set_mem_functions(s_ossl_malloc, s_ossl_realloc, s_ossl_free))
        return;
    EVP_CIPHER_free(EVP_CIPHER_fetch(nullptr, "ChaCha20-Poly1305", nullptr));
    EVP_MD_free(EVP_MD_fetch(nullptr, "BLAKE2S-256", nullptr));
    EVP_MD_free(EVP_MD_fetch(nullptr, "SHA256", nullptr));
    EVP_MAC_free(EVP_MAC_fetch(nullptr, "HMAC", nullptr));
    EVP_KEYMGMT_free(EVP_KEYMGMT_fetch(nullptr, "X25519", nullptr));
    EVP_KEYEXCH_free(EVP_KEYEXCH_fetch(nullptr, "X25519", nullptr));
    uint8_t seed = 0u;
    duct_discard RAND_priv_bytes(&seed, 1u);
}

/** @brief Protocol name hashed into the transcript, and message count, of each pattern. */
static const struct {
    const char *name;
    uint8_t     messages;
} s_pattern[noise_pattern_count] = {
    [noise_pattern_ikpsk2] = { "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s", 2u },
    [noise_pattern_xkpsk3] = { "Noise_XKpsk3_25519_ChaChaPoly_BLAKE2s", 3u },
};

static_assert(duct_noise_key_size == 32u,
    "every raw 32 through this file is X25519's own width");
static_assert(duct_hmac_sha256_size == 32u,
    "s_hmac writes the 32 bytes both of its digests produce");

struct duct_noise_hs {
    bool     is_initiator;
    duct_noise_pattern_t pattern; /**< Pattern this state runs. */
    uint8_t  step;          /**< Messages of the exchange processed by this side.
                              *  The pattern's last one is the precondition
                              *  @ref duct_noise_hs_split gates on; @c has_key goes
                              *  true after the first MixKey, message 1's `e`, well
                              *  before the handshake finishes. */
    uint8_t  h[32];
    uint8_t  ck[32];
    uint8_t  k[32];
    bool     has_key;
    uint64_t n;             /**< AEAD nonce counter for @c k; reset to 0 by
                              *  every MixKey/MixKeyAndHash (new key). */
    duct_noise_keypair_t local_static;
    duct_noise_keypair_t local_ephemeral;
    uint8_t  remote_static_pub[32];
    uint8_t  remote_ephemeral_pub[32];
    uint8_t  psk[32];       /**< Key the `psk` token mixes. */
    uint8_t  mask_key[32];  /**< Key the mask over each ephemeral key derives from. */
    uint8_t       *ss_cache; /**< Caller's store for the static-static DH, null
                               *  where none was lent. All-zero means empty,
                               *  a real answer never being all-zero. */
    const uint8_t *ss_peer;  /**< Static public key @c ss_cache belongs to.
                               *  A presented static differing from it leaves
                               *  the store unread and unwritten. */
    EVP_PKEY_CTX *static_dh;    /**< Derive context for @c local_static, built
                                  *  on first use. That keypair is set once, at
                                  *  creation, so this one never goes stale. */
    EVP_PKEY_CTX *ephemeral_dh; /**< Derive context for @c local_ephemeral.
                                  *  Released by @ref s_ephemeral_generate
                                  *  together with the key it belongs to. */
};

/** @brief True when every one of @p n bytes at @p p is zero. */
static bool s_is_all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0u;
    for (size_t i = 0u; i < n; ++i)
        acc |= p[i];
    return acc == 0u;
}

/** @brief X25519 DH under @p ctx, rejecting an all-zero output.
 *
 *  @p ctx is bound to this side's own private key and outlives the call, so
 *  only the peer's public key is built here.
 *
 *  RFC 7748: a small-order peer public key forces that output, and it must
 *  not pass as a shared secret any observer can predict.
 */
static bool s_dh(EVP_PKEY_CTX *ctx, uint8_t out[32], const uint8_t pub[32])
{
    duct_do_if(!ctx, return false);
    auto pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, pub, 32u);
    duct_do_if(!pubkey, return false);
    size_t outlen = 32u;
    bool ok = EVP_PKEY_derive_init(ctx) == 1
           && EVP_PKEY_derive_set_peer(ctx, pubkey) == 1
           && EVP_PKEY_derive(ctx, out, &outlen) == 1
           && outlen == 32u;
    EVP_PKEY_free(pubkey);
    return ok && !s_is_all_zero(out, 32u);
}

/** @brief The derive context for @p priv, built on first use and kept at @p slot.
 *  @c EVP_PKEY_CTX_new takes a reference of its own, so the @c EVP_PKEY goes
 *  back at once and the context carries the key for as long as it lives. Both are made in
 *  the secret scope.
 *  @return nullptr where OpenSSL refused, @p slot left empty for a later try.
 */
static EVP_PKEY_CTX *s_dh_ctx(EVP_PKEY_CTX **slot, const uint8_t priv[32])
{
    if (*slot)
        return *slot;
    [[gnu::cleanup(s_scope_leave)]] bool outer = s_scope_enter();
    auto privkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv, 32u);
    duct_do_if(!privkey, return nullptr);
    *slot = EVP_PKEY_CTX_new(privkey, nullptr);
    EVP_PKEY_free(privkey);
    return *slot;
}

/** @brief DH against @p pub under this side's static key. */
static bool s_dh_static(duct_noise_hs_t *hs, uint8_t out[32], const uint8_t pub[32])
{
    return s_dh(s_dh_ctx(&hs->static_dh, hs->local_static.priv), out, pub);
}

/** @brief DH against @p pub under this side's ephemeral key. */
static bool s_dh_ephemeral(duct_noise_hs_t *hs, uint8_t out[32], const uint8_t pub[32])
{
    return s_dh(s_dh_ctx(&hs->ephemeral_dh, hs->local_ephemeral.priv), out, pub);
}

/** @brief IKpsk2's `ss`, this side's static key against the peer's,
 *  served from the lent entry where it holds this peer's.
 *  A miss computes it and fills the entry under the same pinned-key test, so
 *  the sender of a message 1 carrying an unknown static neither reads the
 *  entry nor evicts it.
 */
static bool s_dh_ss(duct_noise_hs_t *hs, uint8_t out[32])
{
    bool pinned = hs->ss_peer
               && duct_ct_equal(hs->ss_peer, hs->remote_static_pub, 32u);
    if (pinned && !s_is_all_zero(hs->ss_cache, 32u)) {
        memcpy(out, hs->ss_cache, 32u);
        return true;
    }
    bool ok = s_dh_static(hs, out, hs->remote_static_pub);
    if (ok && pinned)
        memcpy(hs->ss_cache, out, 32u);
    return ok;
}

/** @brief Mint this side's ephemeral keypair, dropping the context cached for
 *  the key it replaces.
 *
 *  The two move together because nothing compares a cached context against the
 *  key it was built from: a keypair replaced on its own leaves the next DH
 *  deriving under the old private key while the transcript carries the new
 *  public one, which no error path reports.
 */
static bool s_ephemeral_generate(duct_noise_hs_t *hs)
{
    bool made = duct_noise_keypair_generate(&hs->local_ephemeral);
    duct_do_if(!made, return false);
    EVP_PKEY_CTX_free(hs->ephemeral_dh);
    hs->ephemeral_dh = nullptr;
    return true;
}

static bool s_hash(uint8_t out[32], const void *data, size_t len)
{
    unsigned int outlen = 0u;
    return EVP_Digest(data, len, out, &outlen, EVP_blake2s256(), nullptr) == 1
        && outlen == 32u;
}

/** @brief HMAC of @p len bytes at @p data under @p key with digest @p md, 32 bytes to @p out.
 *  False unless @p md yields 32 bytes, as BLAKE2s-256 and SHA-256 do. */
static bool s_hmac(const EVP_MD *md, const void *key, size_t key_len,
                   const void *data, size_t len, uint8_t out[32])
{
    unsigned int outlen = 0u;
    return HMAC(md, key, (int)key_len, (const unsigned char *)data, len, out, &outlen) != nullptr
        && outlen == 32u;
}

static bool s_hmac_hash(uint8_t out[32], const uint8_t key[32], const void *data, size_t len)
{
    return s_hmac(EVP_blake2s256(), key, 32u, data, len, out);
}

bool duct_hmac_sha256(const void *key, size_t key_len, const void *data, size_t data_len,
                      uint8_t out[duct_hmac_sha256_size])
{
    return key_len <= INT_MAX && s_hmac(EVP_sha256(), key, key_len, data, data_len, out);
}

/** @brief Noise HKDF(chaining_key, ikm, 2 outputs). */
static bool s_hkdf2(const uint8_t ck[32], const void *ikm, size_t ikm_len,
                    uint8_t out1[32], uint8_t out2[32])
{
    duct_secret_array(uint8_t, temp_key, 32);
    bool ok = s_hmac_hash(temp_key, ck, ikm, ikm_len);
    uint8_t one = 0x01u;
    ok = ok && s_hmac_hash(out1, temp_key, &one, 1u);
    duct_secret_array(uint8_t, buf2, 33);
    memcpy(buf2, out1, 32u);
    buf2[32] = 0x02u;
    ok = ok && s_hmac_hash(out2, temp_key, buf2, sizeof buf2);
    return ok;
}

/** @brief Noise HKDF(chaining_key, ikm, 3 outputs) — used only for the
 *  `psk` token's MixKeyAndHash.
 */
static bool s_hkdf3(const uint8_t ck[32], const void *ikm, size_t ikm_len,
                    uint8_t out1[32], uint8_t out2[32], uint8_t out3[32])
{
    duct_secret_array(uint8_t, temp_key, 32);
    bool ok = s_hmac_hash(temp_key, ck, ikm, ikm_len);
    uint8_t one = 0x01u;
    ok = ok && s_hmac_hash(out1, temp_key, &one, 1u);
    duct_secret_array(uint8_t, buf2, 33);
    memcpy(buf2, out1, 32u);
    buf2[32] = 0x02u;
    ok = ok && s_hmac_hash(out2, temp_key, buf2, sizeof buf2);
    duct_secret_array(uint8_t, buf3, 33);
    memcpy(buf3, out2, 32u);
    buf3[32] = 0x03u;
    ok = ok && s_hmac_hash(out3, temp_key, buf3, sizeof buf3);
    return ok;
}

/** @brief h = HASH(h || data); @p len 0 skips the second update (a nullptr
 *  @p data is only ever passed with @p len 0 — the empty-prologue call).
 */
static bool s_mix_hash(duct_noise_hs_t *hs, const void *data, size_t len)
{
    auto mdctx = EVP_MD_CTX_new();
    duct_do_if(!mdctx, return false);
    bool ok = EVP_DigestInit_ex(mdctx, EVP_blake2s256(), nullptr) == 1
           && EVP_DigestUpdate(mdctx, hs->h, sizeof hs->h) == 1;
    if (ok && len)
        ok = EVP_DigestUpdate(mdctx, data, len) == 1;
    unsigned int outlen = 0u;
    ok = ok && EVP_DigestFinal_ex(mdctx, hs->h, &outlen) == 1 && outlen == sizeof hs->h;
    EVP_MD_CTX_free(mdctx);
    return ok;
}

/** @brief ck, k = HKDF(ck, ikm, 2); arms @c has_key, resets @c n. */
static bool s_mix_key(duct_noise_hs_t *hs, const uint8_t ikm[32])
{
    duct_secret_array(uint8_t, new_ck, 32);
    duct_secret_array(uint8_t, new_k, 32);
    bool ok = s_hkdf2(hs->ck, ikm, 32u, new_ck, new_k);
    duct_do_if(!ok, return false);
    memcpy(hs->ck, new_ck, sizeof hs->ck);
    memcpy(hs->k, new_k, sizeof hs->k);
    hs->has_key = true;
    hs->n = 0u;
    return true;
}

/** @brief ck, temp_h, k = HKDF(ck, psk, 3); MixHash(temp_h); arms @c has_key,
 *  resets @c n — the `psk` token.
 */
static bool s_mix_key_and_hash(duct_noise_hs_t *hs, const uint8_t psk[32])
{
    duct_secret_array(uint8_t, new_ck, 32);
    duct_secret_array(uint8_t, temp_h, 32);
    duct_secret_array(uint8_t, new_k, 32);
    bool ok = s_hkdf3(hs->ck, psk, 32u, new_ck, temp_h, new_k);
    duct_do_if(!ok, return false);
    memcpy(hs->ck, new_ck, sizeof hs->ck);
    ok = s_mix_hash(hs, temp_h, sizeof temp_h);
    duct_do_if(!ok, return false);
    memcpy(hs->k, new_k, sizeof hs->k);
    hs->has_key = true;
    hs->n = 0u;
    return true;
}

/** @brief Mix the ephemeral public key @p e into the hash and the chaining key, as Noise requires of the `e`
 *  token in a handshake with a psk token. */
static bool s_mix_ephemeral(duct_noise_hs_t *hs, const uint8_t e[32])
{
    return s_mix_hash(hs, e, 32u) && s_mix_key(hs, e);
}

/** @brief MixKey of the DH between this side's static key and @p pub. */
static bool s_mix_dh_static(duct_noise_hs_t *hs, const uint8_t pub[32])
{
    duct_secret_array(uint8_t, dh, 32);
    return s_dh_static(hs, dh, pub) && s_mix_key(hs, dh);
}

/** @brief MixKey of the DH between this side's ephemeral key and @p pub. */
static bool s_mix_dh_ephemeral(duct_noise_hs_t *hs, const uint8_t pub[32])
{
    duct_secret_array(uint8_t, dh, 32);
    return s_dh_ephemeral(hs, dh, pub) && s_mix_key(hs, dh);
}

/** @brief MixKey of the IKpsk2 `ss` DH. */
static bool s_mix_dh_ss(duct_noise_hs_t *hs)
{
    duct_secret_array(uint8_t, dh, 32);
    return s_dh_ss(hs, dh) && s_mix_key(hs, dh);
}

/** @brief Little-endian @c n into the 12-byte ChaCha20-Poly1305 nonce
 *  (4 zero bytes + 8-byte counter) — the Noise spec's own AEAD nonce
 *  encoding, matched again by the transport-data nonce below for the same
 *  cipher.
 */
static void s_nonce_from_counter(uint8_t nonce[12], uint64_t n)
{
    memset(nonce, 0, 4u);
    for (unsigned i = 0u; i < 8u; ++i)
        nonce[4u + i] = (uint8_t)(n >> (8u * i));
}

/** @brief EncryptAndHash(plaintext): encrypts (if @c has_key) with AD = @c h,
 *  advances @c n, then MixHash's the produced ciphertext. Writes @p pt_len
 *  @c + (@c has_key @c ? @ref duct_noise_tag_size @c : 0) bytes to @p out.
 */
static bool
s_encrypt_and_hash(duct_noise_hs_t *hs, const void *pt, size_t pt_len,
                   uint8_t *out, size_t *out_len)
{
    if (!hs->has_key) {
        if (pt_len)
            memcpy(out, pt, pt_len);
        *out_len = pt_len;
        return s_mix_hash(hs, out, pt_len);
    }

    uint8_t nonce[12];
    s_nonce_from_counter(nonce, hs->n);

    [[gnu::cleanup(s_scope_leave)]] bool outer = s_scope_enter();
    auto cctx = EVP_CIPHER_CTX_new();
    duct_do_if(!cctx, return false);
    int len = 0;
    bool ok = EVP_EncryptInit_ex(cctx, EVP_chacha20_poly1305(), nullptr, hs->k, nonce) == 1
           && EVP_EncryptUpdate(cctx, nullptr, &len, hs->h, (int)sizeof hs->h) == 1
           && EVP_EncryptUpdate(cctx, out, &len, pt, (int)pt_len) == 1;
    int written = len, fin_len = 0;
    ok = ok && EVP_EncryptFinal_ex(cctx, out + written, &fin_len) == 1;
    written += fin_len;
    ok = ok && EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_GET_TAG,
                                   (int)duct_noise_tag_size, out + written) == 1;
    EVP_CIPHER_CTX_free(cctx);
    duct_do_if(!ok, return false);

    *out_len = (size_t)written + duct_noise_tag_size;
    hs->n++;
    return s_mix_hash(hs, out, *out_len);
}

/** @brief DecryptAndHash(ciphertext).
 *
 *  MixHash over @p ct — the whole input, tag included — is deferred until
 *  after a successful decrypt, so a failed auth never mutates @c h. Same
 *  ordering as @ref s_encrypt_and_hash: mix only what was genuinely
 *  produced or consumed.
 */
static bool
s_decrypt_and_hash(duct_noise_hs_t *hs, const void *ct, size_t ct_len,
                   uint8_t *out, size_t *out_len)
{
    if (!hs->has_key) {
        if (ct_len)
            memcpy(out, ct, ct_len);
        *out_len = ct_len;
        return s_mix_hash(hs, ct, ct_len);
    }
    duct_do_if(ct_len < duct_noise_tag_size, return false);
    size_t pt_len = ct_len - duct_noise_tag_size;

    uint8_t nonce[12];
    s_nonce_from_counter(nonce, hs->n);

    [[gnu::cleanup(s_scope_leave)]] bool outer = s_scope_enter();
    auto cctx = EVP_CIPHER_CTX_new();
    duct_do_if(!cctx, return false);
    int len = 0;
    bool ok = EVP_DecryptInit_ex(cctx, EVP_chacha20_poly1305(), nullptr, hs->k, nonce) == 1
           && EVP_DecryptUpdate(cctx, nullptr, &len, hs->h, (int)sizeof hs->h) == 1
           && EVP_DecryptUpdate(cctx, out, &len, ct, (int)pt_len) == 1
           && EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_TAG, (int)duct_noise_tag_size,
                                  (void *)((const uint8_t *)ct + pt_len)) == 1;
    int fin_len = 0;
    ok = ok && EVP_DecryptFinal_ex(cctx, out + len, &fin_len) == 1;
    EVP_CIPHER_CTX_free(cctx);
    duct_do_if(!ok, return false);

    hs->n++;
    *out_len = pt_len;
    return s_mix_hash(hs, ct, ct_len);
}

bool duct_noise_keypair_generate(duct_noise_keypair_t *out)
{
    [[gnu::cleanup(s_scope_leave)]] bool outer = s_scope_enter();
    auto pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
    duct_do_if(!pkey, return false);
    size_t priv_len = sizeof out->priv, pub_len = sizeof out->pub;
    bool ok = EVP_PKEY_get_raw_private_key(pkey, out->priv, &priv_len) == 1 && priv_len == sizeof out->priv
           && EVP_PKEY_get_raw_public_key(pkey, out->pub, &pub_len) == 1 && pub_len == sizeof out->pub;
    EVP_PKEY_free(pkey);
    return ok;
}

bool duct_noise_keypair_from_priv(duct_noise_keypair_t *out, const uint8_t priv[32])
{
    [[gnu::cleanup(s_scope_leave)]] bool outer = s_scope_enter();
    auto pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv, 32u);
    duct_do_if(!pkey, return false);
    memcpy(out->priv, priv, sizeof out->priv);
    size_t pub_len = sizeof out->pub;
    bool ok = EVP_PKEY_get_raw_public_key(pkey, out->pub, &pub_len) == 1 && pub_len == sizeof out->pub;
    EVP_PKEY_free(pkey);
    return ok;
}

/** @brief Label of the key every handshake mask derives from the mask key. */
static const char s_mask_label[] = "duct handshake mask";

bool duct_noise_ephemeral_mask(const uint8_t psk[duct_noise_key_size], uint8_t msg,
                               const uint8_t tag[duct_noise_tag_size],
                               uint8_t out[duct_noise_key_size])
{
    duct_secret_array(uint8_t, key, 32);
    bool ok = s_hmac_hash(key, psk, s_mask_label, sizeof s_mask_label - 1u);
    uint8_t in[1u + duct_noise_tag_size] = { msg };
    memcpy(in + 1u, tag, duct_noise_tag_size);
    return ok && s_hmac_hash(out, key, in, sizeof in);
}

/** @brief Mask or unmask @p ephemeral, the key leading message @p which, of
 *  @p len bytes at @p msg.
 *  Exclusive-or with the value @ref duct_noise_ephemeral_mask derives from
 *  @p hs's mask key and the tag closing @p msg, so one call does either
 *  direction. @p msg holds at least a key and a tag and may be @p ephemeral
 *  itself: the tag lies behind the masked bytes. A build without
 *  @c DUCT_HANDSHAKE_MASK leaves @p ephemeral as it is.
 *  @return false on an OpenSSL failure, @p ephemeral then untouched. */
static bool s_ephemeral_mask(const duct_noise_hs_t *hs, uint8_t which, const uint8_t *msg,
                             size_t len, uint8_t ephemeral[32])
{
    if (!duct_handshake_mask)
        return true;
    duct_secret_array(uint8_t, mask, 32);
    bool ok = duct_noise_ephemeral_mask(hs->mask_key, which, msg + len - duct_noise_tag_size, mask);
    if (ok)
        for (size_t i = 0u; i < sizeof mask; ++i)
            ephemeral[i] ^= mask[i];
    return ok;
}

/** @brief Mint this side's ephemeral key, write its public half at @p out and mix it into the transcript. */
static bool s_emit_ephemeral(duct_noise_hs_t *hs, uint8_t *out)
{
    bool made = s_ephemeral_generate(hs);
    duct_do_if(!made, return false);
    memcpy(out, hs->local_ephemeral.pub, duct_noise_key_size);
    return s_mix_ephemeral(hs, hs->local_ephemeral.pub);
}

/** @brief Unmask the ephemeral key leading message @p which, of @p len bytes at @p msg, keep it as the peer's and
 *  mix it into the transcript. */
static bool s_take_ephemeral(duct_noise_hs_t *hs, uint8_t which, const uint8_t *msg, size_t len)
{
    memcpy(hs->remote_ephemeral_pub, msg, duct_noise_key_size);
    bool ok = s_ephemeral_mask(hs, which, msg, len, hs->remote_ephemeral_pub);
    return ok && s_mix_ephemeral(hs, hs->remote_ephemeral_pub);
}

duct_noise_hs_t *
duct_noise_hs_create_for(duct_noise_pattern_t pattern, const duct_noise_keypair_t *local_static,
                         const uint8_t remote_static_pub[32], const uint8_t psk[32], bool is_initiator,
                         duct_view_u8 prologue)
{
    duct_do_if(pattern >= noise_pattern_count || (is_initiator && !remote_static_pub), return nullptr);
    auto hs = duct_new_secret(duct_noise_hs_t);
    duct_do_if(!hs, return nullptr);
    *hs = (duct_noise_hs_t){ .is_initiator = is_initiator, .pattern = pattern, .local_static = *local_static };
    memcpy(hs->psk, psk, sizeof hs->psk);
    memcpy(hs->mask_key, psk, sizeof hs->mask_key);

    const char *name = s_pattern[pattern].name;
    bool ok = s_hash(hs->h, name, strlen(name));
    memcpy(hs->ck, hs->h, sizeof hs->ck);
    ok = ok && s_mix_hash(hs, prologue.data, prologue.size);

    /* Pre-message "<- s" of both patterns: both sides mix the responder's
     * static public key — the initiator already knows it (remote_static_pub);
     * the responder plays the "s" role itself (its own local_static.pub). */
    if (remote_static_pub) {
        memcpy(hs->remote_static_pub, remote_static_pub, sizeof hs->remote_static_pub);
        ok = ok && s_mix_hash(hs, hs->remote_static_pub, sizeof hs->remote_static_pub);
    } else {
        ok = ok && s_mix_hash(hs, hs->local_static.pub, sizeof hs->local_static.pub);
    }
    if (ok)
        return hs;
    duct_noise_hs_destroy(hs);
    return nullptr;
}

duct_noise_hs_t *
duct_noise_hs_create(const duct_noise_keypair_t *local_static,
                    const uint8_t remote_static_pub[32],
                    const uint8_t psk[32],
                    bool is_initiator)
{
    return duct_noise_hs_create_for(noise_pattern_ikpsk2, local_static, remote_static_pub, psk, is_initiator,
                                    (duct_view_u8){});
}

void duct_noise_hs_ss_cache(duct_noise_hs_t *hs, uint8_t cache[32],
                            const uint8_t peer[32])
{
    hs->ss_cache = cache;
    hs->ss_peer = peer;
}

void duct_noise_hs_set_psk(duct_noise_hs_t *hs, const uint8_t psk[duct_noise_key_size])
{
    memcpy(hs->psk, psk, sizeof hs->psk);
}

void duct_noise_hs_destroy(duct_noise_hs_t *hs)
{
    if (!hs)
        return;
    /* Ahead of duct_del, whose wipe zeroes these pointers along with the key
     * material and leaves nothing to release them by. */
    EVP_PKEY_CTX_free(hs->static_dh);
    EVP_PKEY_CTX_free(hs->ephemeral_dh);
    duct_del(hs);
}

bool
duct_noise_hs_write_msg1(duct_noise_hs_t *hs, duct_view_u8 payload,
                         uint8_t *out, size_t out_cap, size_t *out_len)
{
    duct_do_if(hs->pattern != noise_pattern_ikpsk2 || !hs->is_initiator, return false);
    size_t len = duct_noise_hs_msg1_size(payload.size);
    duct_do_if(out_cap < len, return false);

    /* e */
    bool ok = s_emit_ephemeral(hs, out);

    /* es */
    ok = ok && s_mix_dh_ephemeral(hs, hs->remote_static_pub);

    /* s */
    size_t static_ct_len = 0u;
    ok = ok && s_encrypt_and_hash(hs, hs->local_static.pub, duct_noise_key_size,
                                 out + duct_noise_key_size, &static_ct_len);

    /* ss */
    ok = ok && s_mix_dh_ss(hs);

    /* payload */
    size_t payload_ct_len = 0u;
    ok = ok && s_encrypt_and_hash(hs, payload.data, payload.size,
                                 out + duct_noise_key_size + static_ct_len, &payload_ct_len);
    duct_do_if(!ok, return false);

    assert(len == duct_noise_key_size + static_ct_len + payload_ct_len);
    bool masked = s_ephemeral_mask(hs, duct_noise_mask_msg1, out, len, out);
    duct_do_if(!masked, return false);
    *out_len = len;
    hs->step = 1u;
    return true;
}

/** @brief Snapshot of the handshake fields a message read mutates.
 *  Rolled back on an AEAD failure, so a forged or corrupted message leaves
 *  @c hs reusable for the genuine one. */
typedef struct {
    uint8_t  h[32];
    uint8_t  ck[32];
    uint8_t  k[32];
    uint8_t  re[32];
    uint8_t  rs[32];
    uint64_t n;
    bool     has_key;
} hs_symm_t;

/** @brief Capture the handshake fields a message read mutates. */
static void s_hs_symm_save(const duct_noise_hs_t *hs, hs_symm_t *s)
{
    memcpy(s->h, hs->h, sizeof s->h);
    memcpy(s->ck, hs->ck, sizeof s->ck);
    memcpy(s->k, hs->k, sizeof s->k);
    memcpy(s->re, hs->remote_ephemeral_pub, sizeof s->re);
    memcpy(s->rs, hs->remote_static_pub, sizeof s->rs);
    s->n = hs->n;
    s->has_key = hs->has_key;
}

/** @brief Restore the handshake's mutated fields after a failed read. */
static void s_hs_symm_restore(duct_noise_hs_t *hs, const hs_symm_t *s)
{
    memcpy(hs->h, s->h, sizeof hs->h);
    memcpy(hs->ck, s->ck, sizeof hs->ck);
    memcpy(hs->k, s->k, sizeof hs->k);
    memcpy(hs->remote_ephemeral_pub, s->re, sizeof hs->remote_ephemeral_pub);
    memcpy(hs->remote_static_pub, s->rs, sizeof hs->remote_static_pub);
    hs->n = s->n;
    hs->has_key = s->has_key;
}

bool
duct_noise_hs_read_msg1(duct_noise_hs_t *hs, duct_view_u8 msg,
                        uint8_t remote_static_out[32],
                        uint8_t *payload_out, size_t payload_cap,
                        size_t *payload_len_out)
{
    duct_do_if(hs->pattern != noise_pattern_ikpsk2 || hs->is_initiator, return false);
    size_t payload_ct_off = duct_noise_msg1_fixed_size;
    duct_do_if(msg.size < payload_ct_off + duct_noise_tag_size, return false);
    size_t payload_ct_len = msg.size - payload_ct_off;
    size_t pt_len = payload_ct_len - duct_noise_tag_size;
    duct_do_if(pt_len > payload_cap, return false);
    auto p = (const uint8_t *)msg.data;

    duct_secret(hs_symm_t, save);
    s_hs_symm_save(hs, &save);

    /* e */
    bool ok = s_take_ephemeral(hs, duct_noise_mask_msg1, p, msg.size);

    /* es: our static + their (just-received) ephemeral */
    ok = ok && s_mix_dh_static(hs, hs->remote_ephemeral_pub);

    /* s: learns + authenticates the initiator's static key */
    size_t static_len = 0u;
    ok = ok && s_decrypt_and_hash(hs, p + duct_noise_key_size,
                                 duct_noise_key_size + duct_noise_tag_size,
                                 hs->remote_static_pub, &static_len);
    duct_do_if(!ok, s_hs_symm_restore(hs, &save); return false);
    /* The e and es tokens armed the cipher key, so the static key was opened, 32 bytes. */
    assert(static_len == duct_noise_key_size);

    /* ss */
    ok = ok && s_mix_dh_ss(hs);

    /* payload */
    size_t got_len = 0u;
    ok = ok && s_decrypt_and_hash(hs, p + payload_ct_off, payload_ct_len, payload_out, &got_len);
    duct_do_if(!ok, s_hs_symm_restore(hs, &save); return false);

    memcpy(remote_static_out, hs->remote_static_pub, duct_noise_key_size);
    *payload_len_out = got_len;
    hs->step = 1u;
    return true;
}

bool
duct_noise_hs_write_msg2(duct_noise_hs_t *hs, duct_view_u8 payload,
                         uint8_t *out, size_t out_cap, size_t *out_len)
{
    duct_do_if(hs->pattern != noise_pattern_ikpsk2 || hs->is_initiator || hs->step != 1u, return false);
    duct_do_if(out_cap < duct_noise_msg2_size + payload.size, return false);

    /* e */
    bool ok = s_emit_ephemeral(hs, out);

    /* ee */
    ok = ok && s_mix_dh_ephemeral(hs, hs->remote_ephemeral_pub);

    /* se: our ephemeral + their (learned) static */
    ok = ok && s_mix_dh_ephemeral(hs, hs->remote_static_pub);

    /* psk */
    ok = ok && s_mix_key_and_hash(hs, hs->psk);

    /* payload — a real AEAD call even when empty, producing the tag */
    size_t payload_len = 0u;
    ok = ok && s_encrypt_and_hash(hs, payload.data, payload.size,
                                  out + duct_noise_key_size, &payload_len);
    duct_do_if(!ok, return false);

    size_t len = duct_noise_key_size + payload_len;
    bool masked = s_ephemeral_mask(hs, duct_noise_mask_msg2, out, len, out);
    duct_do_if(!masked, return false);
    *out_len = len;
    hs->step = 2u;
    return true;
}

bool duct_noise_hs_read_msg2(duct_noise_hs_t *hs, duct_view_u8 msg)
{
    duct_do_if(hs->pattern != noise_pattern_ikpsk2 || !hs->is_initiator, return false);
    duct_do_if(msg.size < duct_noise_msg2_size
               || msg.size - duct_noise_msg2_size > duct_noise_hs_pad_max, return false);
    auto p = (const uint8_t *)msg.data;

    duct_secret(hs_symm_t, save);
    s_hs_symm_save(hs, &save);

    /* e */
    bool ok = s_take_ephemeral(hs, duct_noise_mask_msg2, p, msg.size);

    /* ee */
    ok = ok && s_mix_dh_ephemeral(hs, hs->remote_ephemeral_pub);

    /* se: our static + their (just-received) ephemeral */
    ok = ok && s_mix_dh_static(hs, hs->remote_ephemeral_pub);

    /* psk */
    ok = ok && s_mix_key_and_hash(hs, hs->psk);

    /* payload — the auth check that completes mutual authentication */
    uint8_t discard[duct_noise_hs_pad_max];
    size_t got_len = 0u;
    ok = ok && s_decrypt_and_hash(hs, p + duct_noise_key_size,
                                  msg.size - duct_noise_key_size, discard, &got_len);
    duct_do_if(!ok, s_hs_symm_restore(hs, &save); return false);

    hs->step = 2u;
    return true;
}

bool
duct_noise_hs_write_msg1_xk(duct_noise_hs_t *hs, duct_view_u8 payload,
                            uint8_t *out, size_t out_cap, size_t *out_len)
{
    duct_do_if(hs->pattern != noise_pattern_xkpsk3 || !hs->is_initiator || hs->step != 0u, return false);
    size_t len = duct_noise_xk_msg1_size(payload.size);
    duct_do_if(out_cap < len, return false);

    /* e */
    bool ok = s_emit_ephemeral(hs, out);

    /* es */
    ok = ok && s_mix_dh_ephemeral(hs, hs->remote_static_pub);

    /* payload */
    size_t payload_ct_len = 0u;
    ok = ok && s_encrypt_and_hash(hs, payload.data, payload.size, out + duct_noise_key_size, &payload_ct_len);
    duct_do_if(!ok, return false);

    assert(len == duct_noise_key_size + payload_ct_len);
    bool masked = s_ephemeral_mask(hs, duct_noise_mask_msg1, out, len, out);
    duct_do_if(!masked, return false);
    *out_len = len;
    hs->step = 1u;
    return true;
}

bool
duct_noise_hs_read_msg1_xk(duct_noise_hs_t *hs, duct_view_u8 msg,
                           uint8_t *payload_out, size_t payload_cap, size_t *payload_len_out)
{
    duct_do_if(hs->pattern != noise_pattern_xkpsk3 || hs->is_initiator || hs->step != 0u, return false);
    duct_do_if(msg.size < duct_noise_xk_msg1_fixed_size, return false);
    size_t payload_ct_len = msg.size - duct_noise_key_size;
    duct_do_if(payload_ct_len - duct_noise_tag_size > payload_cap, return false);
    auto p = (const uint8_t *)msg.data;

    duct_secret(hs_symm_t, save);
    s_hs_symm_save(hs, &save);

    /* e */
    bool ok = s_take_ephemeral(hs, duct_noise_mask_msg1, p, msg.size);

    /* es: our static + their (just-received) ephemeral */
    ok = ok && s_mix_dh_static(hs, hs->remote_ephemeral_pub);

    /* payload */
    size_t got_len = 0u;
    ok = ok && s_decrypt_and_hash(hs, p + duct_noise_key_size, payload_ct_len, payload_out, &got_len);
    duct_do_if(!ok, s_hs_symm_restore(hs, &save); return false);

    *payload_len_out = got_len;
    hs->step = 1u;
    return true;
}

bool
duct_noise_hs_write_msg2_xk(duct_noise_hs_t *hs, duct_view_u8 payload,
                            uint8_t *out, size_t out_cap, size_t *out_len)
{
    duct_do_if(hs->pattern != noise_pattern_xkpsk3 || hs->is_initiator || hs->step != 1u, return false);
    duct_do_if(out_cap < duct_noise_msg2_size + payload.size, return false);

    /* e */
    bool ok = s_emit_ephemeral(hs, out);

    /* ee */
    ok = ok && s_mix_dh_ephemeral(hs, hs->remote_ephemeral_pub);

    /* payload — a real AEAD call even when empty, producing the tag */
    size_t payload_len = 0u;
    ok = ok && s_encrypt_and_hash(hs, payload.data, payload.size, out + duct_noise_key_size, &payload_len);
    duct_do_if(!ok, return false);

    size_t len = duct_noise_key_size + payload_len;
    bool masked = s_ephemeral_mask(hs, duct_noise_mask_msg2, out, len, out);
    duct_do_if(!masked, return false);
    *out_len = len;
    hs->step = 2u;
    return true;
}

bool duct_noise_hs_read_msg2_xk(duct_noise_hs_t *hs, duct_view_u8 msg)
{
    duct_do_if(hs->pattern != noise_pattern_xkpsk3 || !hs->is_initiator || hs->step != 1u, return false);
    duct_do_if(msg.size < duct_noise_msg2_size
               || msg.size - duct_noise_msg2_size > duct_noise_hs_pad_max, return false);
    auto p = (const uint8_t *)msg.data;

    duct_secret(hs_symm_t, save);
    s_hs_symm_save(hs, &save);

    /* e */
    bool ok = s_take_ephemeral(hs, duct_noise_mask_msg2, p, msg.size);

    /* ee */
    ok = ok && s_mix_dh_ephemeral(hs, hs->remote_ephemeral_pub);

    /* payload — the tag proves the responder holds the static key message 1 was sent to */
    uint8_t discard[duct_noise_hs_pad_max];
    size_t got_len = 0u;
    ok = ok && s_decrypt_and_hash(hs, p + duct_noise_key_size, msg.size - duct_noise_key_size, discard, &got_len);
    duct_do_if(!ok, s_hs_symm_restore(hs, &save); return false);

    hs->step = 2u;
    return true;
}

bool
duct_noise_hs_write_msg3_xk(duct_noise_hs_t *hs, duct_view_u8 payload,
                            uint8_t *out, size_t out_cap, size_t *out_len)
{
    duct_do_if(hs->pattern != noise_pattern_xkpsk3 || !hs->is_initiator || hs->step != 2u, return false);
    size_t len = duct_noise_xk_msg3_size(payload.size);
    duct_do_if(out_cap < len, return false);

    /* s */
    size_t static_ct_len = 0u;
    bool ok = s_encrypt_and_hash(hs, hs->local_static.pub, duct_noise_key_size, out, &static_ct_len);

    /* se: our static + their ephemeral */
    ok = ok && s_mix_dh_static(hs, hs->remote_ephemeral_pub);

    /* psk */
    ok = ok && s_mix_key_and_hash(hs, hs->psk);

    /* payload */
    size_t payload_ct_len = 0u;
    ok = ok && s_encrypt_and_hash(hs, payload.data, payload.size, out + static_ct_len, &payload_ct_len);
    duct_do_if(!ok, return false);

    assert(len == static_ct_len + payload_ct_len);
    *out_len = len;
    hs->step = 3u;
    return true;
}

bool
duct_noise_hs_read_msg3_xk(duct_noise_hs_t *hs, duct_view_u8 msg, duct_noise_psk_for_t psk_for, void *ctx,
                           uint8_t remote_static_out[duct_noise_key_size],
                           uint8_t *payload_out, size_t payload_cap, size_t *payload_len_out)
{
    duct_do_if(hs->pattern != noise_pattern_xkpsk3 || hs->is_initiator || hs->step != 2u, return false);
    duct_do_if(msg.size < duct_noise_xk_msg3_fixed_size, return false);
    size_t static_ct_len = duct_noise_key_size + duct_noise_tag_size;
    size_t payload_ct_len = msg.size - static_ct_len;
    duct_do_if(payload_ct_len - duct_noise_tag_size > payload_cap, return false);
    auto p = (const uint8_t *)msg.data;

    duct_secret(hs_symm_t, save);
    s_hs_symm_save(hs, &save);

    /* s: learns + authenticates the initiator's static key */
    size_t static_len = 0u;
    bool ok = s_decrypt_and_hash(hs, p, static_ct_len, hs->remote_static_pub, &static_len);
    duct_do_if(!ok, s_hs_symm_restore(hs, &save); return false);
    /* The e tokens armed the cipher key, so the static key was opened, 32 bytes. */
    assert(static_len == duct_noise_key_size);

    /* se: our ephemeral + their (just-learned) static */
    ok = s_mix_dh_ephemeral(hs, hs->remote_static_pub);

    /* psk: asked once the static key has authenticated, before the token */
    duct_secret_array(uint8_t, psk, 32);
    bool known = ok && psk_for(ctx, hs->remote_static_pub, psk);
    duct_do_if(!known, s_hs_symm_restore(hs, &save); return false);
    memcpy(hs->psk, psk, sizeof hs->psk);
    ok = s_mix_key_and_hash(hs, hs->psk);

    /* payload — the tag that proves the initiator holds the password */
    size_t got_len = 0u;
    ok = ok && s_decrypt_and_hash(hs, p + static_ct_len, payload_ct_len, payload_out, &got_len);
    duct_do_if(!ok, s_hs_symm_restore(hs, &save); return false);

    memcpy(remote_static_out, hs->remote_static_pub, duct_noise_key_size);
    *payload_len_out = got_len;
    hs->step = 3u;
    return true;
}

bool duct_noise_hs_split(duct_noise_hs_t *hs, duct_noise_transport_t *out)
{
    duct_do_if(hs->step != s_pattern[hs->pattern].messages, return false);
    duct_secret_array(uint8_t, k1, 32);
    duct_secret_array(uint8_t, k2, 32);
    bool ok = s_hkdf2(hs->ck, nullptr, 0u, k1, k2);
    duct_do_if(!ok, return false);

    *out = (duct_noise_transport_t){ .counter_size = duct_noise_counter_size };
    if (hs->is_initiator) {
        memcpy(out->send_key, k1, sizeof k1);
        memcpy(out->recv_key, k2, sizeof k2);
    } else {
        memcpy(out->send_key, k2, sizeof k2);
        memcpy(out->recv_key, k1, sizeof k1);
    }
    return true;
}

bool duct_noise_hs_exporter(const duct_noise_hs_t *hs, uint8_t out[duct_noise_key_size])
{
    duct_do_if(hs->step != s_pattern[hs->pattern].messages, return false);
    duct_secret_array(uint8_t, spare, 32);
    return s_hkdf2(hs->ck, hs->h, sizeof hs->h, out, spare);
}

bool duct_noise_derive(const uint8_t key[duct_noise_key_size], const char *label,
                       uint8_t *out, size_t len)
{
    duct_secret_array(uint8_t, okm, 64);
    duct_do_if(len == 0u || len > sizeof okm, return false);
    bool ok = s_hkdf2(key, label, strlen(label), okm, okm + 32u);
    if (ok)
        memcpy(out, okm, len);
    return ok;
}

/** @brief True if @p counter's bit is already set in the replay window.
 *
 *  The word index wraps every @c duct_noise_replay_window_words words, so a
 *  slot is reused only once the window has advanced past its previous
 *  occupant; @ref s_replay_accept clears every bit newly entering range
 *  before it can be misread as already-seen.
 */
static bool s_replay_bit_test(const duct_noise_transport_t *t, uint64_t counter)
{
    unsigned word = (unsigned)((counter / 64u) % duct_noise_replay_window_words);
    return (t->replay_bitmap[word] & (UINT64_C(1) << (counter % 64u))) != 0u;
}

static void s_replay_bit_set(duct_noise_transport_t *t, uint64_t counter)
{
    unsigned word = (unsigned)((counter / 64u) % duct_noise_replay_window_words);
    t->replay_bitmap[word] |= UINT64_C(1) << (counter % 64u);
}

static void s_replay_bit_clear(duct_noise_transport_t *t, uint64_t counter)
{
    unsigned word = (unsigned)((counter / 64u) % duct_noise_replay_window_words);
    t->replay_bitmap[word] &= ~(UINT64_C(1) << (counter % 64u));
}

/** @brief RFC 6479-style sliding-window replay check.
 *
 *  Called only after @p counter's packet has authenticated, per
 *  @ref duct_noise_transport_unseal's ordering: an unauthenticated counter
 *  must never influence this state, since a forged packet then poisons the
 *  window against a later legitimate one.
 */
static bool s_replay_accept(duct_noise_transport_t *t, uint64_t counter)
{
    if (!t->replay_started) {
        t->replay_started = true;
        t->replay_top = counter;
        s_replay_bit_set(t, counter);
        return true;
    }
    if (counter <= t->replay_top) {
        uint64_t back = t->replay_top - counter;
        duct_do_if(back >= duct_noise_replay_window_bits, return false);
        bool seen = s_replay_bit_test(t, counter);
        duct_do_if(seen, return false);
        s_replay_bit_set(t, counter);
        return true;
    }
    /* Advancing: clear every bit newly entering the window before setting
     * the new one — bounded to at most window_bits-1 iterations regardless
     * of how large the jump is (clear_from is pinned to counter-window+1). */
    uint64_t advance = counter - t->replay_top;
    uint64_t clear_from = advance > duct_noise_replay_window_bits
                        ? counter - duct_noise_replay_window_bits + 1u
                        : t->replay_top + 1u;
    for (uint64_t c = clear_from; c < counter; ++c)
        s_replay_bit_clear(t, c);
    t->replay_top = counter;
    s_replay_bit_set(t, counter);
    return true;
}

/** @brief The AEAD context cached in @p slot, built from @p key on first use.
 *
 *  The key is bound here and nowhere else: every later packet re-initialises
 *  the nonce alone, since handing the key in again rebuilds the whole context.
 *  @p encrypt picks the direction it is built for — one context does not serve
 *  both. Nothing is built until a packet actually needs it, which lets a
 *  freshly split transport still be assigned by value. The context, which holds @p key,
 *  is made in the secret scope.
 */
static EVP_CIPHER_CTX *
s_aead_ctx(void **slot, const uint8_t key[32], bool encrypt)
{
    if (*slot)
        return (EVP_CIPHER_CTX *)*slot;
    [[gnu::cleanup(s_scope_leave)]] bool outer = s_scope_enter();
    auto ctx = EVP_CIPHER_CTX_new();
    duct_do_if(!ctx, return nullptr);
    int ok = encrypt
        ? EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key, nullptr)
        : EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key, nullptr);
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }
    *slot = ctx;
    return ctx;
}

/** @brief Exclusive-or @p counter's @c wide bytes with a SipHash draw of the
 *  message's own first twelve ciphertext bytes under @p key.
 *
 *  The counter rides the wire in the clear and counts; the draw makes the four
 *  (or eight) wire bytes pseudorandom per message while both ends rebuild it
 *  from bytes the message itself carries, so loss and reordering touch
 *  nothing. The seal runs it after the AEAD wrote the ciphertext and before
 *  the message leaves, the read after the lead checked and before the counter
 *  is read.
 */
void duct_noise_counter_cover(const uint8_t key[duct_noise_key_size], uint8_t *counter,
                              const uint8_t *sample, size_t wide)
{
    uint8_t in[12], draw[8];
    memcpy(in, sample, sizeof in);
    duct_sip_put_le64(draw, sizeof draw, duct_siphash24(key, in, sizeof in));
    for (size_t i = 0u; i < wide; ++i)
        counter[i] ^= draw[i];
}

size_t
duct_noise_transport_seal(duct_noise_transport_t *t, const duct_view_u8 *spans, size_t n,
                          uint8_t *out, size_t out_cap)
{
    size_t wide = t->counter_size,
           need = duct_noise_transport_seal_size_of(t, 0u);
    for (size_t i = 0u; i < n; ++i)
        need += spans[i].size;
    duct_do_if(out_cap < need, return 0u);
    duct_do_if(t->send_counter > duct_noise_seal_counter_max, return 0u);

    uint64_t counter = t->send_counter;
    for (unsigned i = 0u; i < wide; ++i)
        out[i] = (uint8_t)(counter >> (8u * i));

    uint8_t nonce[12];
    s_nonce_from_counter(nonce, counter);

    auto cctx = s_aead_ctx(&t->send_ctx, t->send_key, true);
    duct_do_if(!cctx, return 0u);
    int len = 0,
        written = 0;
    bool ok = EVP_EncryptInit_ex(cctx, nullptr, nullptr, nullptr, nonce) == 1;
    for (size_t i = 0u; ok && i < n; ++i) {
        ok = EVP_EncryptUpdate(cctx, out + wide + written, &len, spans[i].data, (int)spans[i].size) == 1;
        written += len;
    }
    int fin_len = 0;
    ok = ok && EVP_EncryptFinal_ex(cctx, out + wide + written, &fin_len) == 1;
    written += fin_len;
    ok = ok && EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_GET_TAG,
                                   (int)duct_noise_tag_size, out + wide + written) == 1;
    duct_do_if(!ok, return 0u);

    duct_noise_counter_cover(t->send_key, out, out + wide, wide);
    t->send_counter = counter + 1u;
    return wide + (size_t)written + duct_noise_tag_size;
}

/** @brief Rebuild the counter a compact message's low 32 bits stand for.
 *
 *  Of the counters with those low bits, the one nearest the highest accepted
 *  one, which is the sender's whenever fewer than 2^31 counters separate the two.
 *  Before anything has been accepted counters count up from 0, so the bits are
 *  the counter. Nothing here is believed: the result is only the nonce the AEAD
 *  tries, and one the sender did not use fails there.
 *  @return @c UINT64_MAX for a counter below 0, the one a message far behind the
 *          top rebuilds to, and for one past 2^64; no sender seals it. */
static uint64_t s_expand_counter(const duct_noise_transport_t *t, uint32_t low)
{
    if (!t->replay_started)
        return low;
    uint32_t ahead = low - (uint32_t)t->replay_top;
    if (ahead < (UINT32_C(1) << 31u)) {
        duct_do_if(t->replay_top > UINT64_MAX - ahead, return UINT64_MAX);
        return t->replay_top + ahead;
    }
    uint32_t behind = (uint32_t)t->replay_top - low;
    duct_do_if(behind > t->replay_top, return UINT64_MAX);
    return t->replay_top - behind;
}

void duct_noise_transport_destroy(duct_noise_transport_t *t)
{
    duct_do_if(!t, return);
    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)t->send_ctx);
    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)t->recv_ctx);
    duct_secure_zero(t, sizeof *t);
}

bool
duct_noise_transport_unseal(duct_noise_transport_t *t, duct_view_u8 sealed,
                           uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t wide = t->counter_size;
    duct_do_if(sealed.size < wide + duct_noise_tag_size, return false);
    auto p = (const uint8_t *)sealed.data;

    uint8_t low[duct_noise_counter_size];
    memcpy(low, p, wide);
    duct_noise_counter_cover(t->recv_key, low, p + wide, wide);
    uint64_t counter = 0u;
    for (unsigned i = 0u; i < wide; ++i)
        counter |= (uint64_t)low[i] << (8u * i);
    if (wide == duct_noise_counter_compact_size) {
        counter = s_expand_counter(t, (uint32_t)counter);
        duct_do_if(counter == UINT64_MAX, return false);
    }

    size_t pt_len = sealed.size - wide - duct_noise_tag_size;
    duct_do_if(pt_len > out_cap, return false);

    uint8_t nonce[12];
    s_nonce_from_counter(nonce, counter);

    auto cctx = s_aead_ctx(&t->recv_ctx, t->recv_key, false);
    duct_do_if(!cctx, return false);
    int len = 0;
    bool ok = EVP_DecryptInit_ex(cctx, nullptr, nullptr, nullptr, nonce) == 1
           && EVP_DecryptUpdate(cctx, out, &len, p + wide, (int)pt_len) == 1
           && EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_TAG, (int)duct_noise_tag_size,
                                  (void *)(p + wide + pt_len)) == 1;
    int fin_len = 0;
    ok = ok && EVP_DecryptFinal_ex(cctx, out + len, &fin_len) == 1;
    duct_do_if(!ok, return false);

    /* Auth already verified above — only now may the counter influence
     * replay state (see @ref s_replay_accept). */
    ok = s_replay_accept(t, counter);
    duct_do_if(!ok, return false);
    *out_len = pt_len;
    return true;
}
