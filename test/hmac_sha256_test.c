/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file hmac_sha256_test.c
 *  @brief duct_hmac_sha256 against the HMAC-SHA256 vectors of RFC 4231: a short key, the key
 *  and data sizes the RFC pairs, a key longer than the hash's block, and the empty key and
 *  data. The empty case is the one the RFC leaves out; its value comes from Python's hmac.
 */

#include "duct_crypto.h"
#include "duct_noise.h"

#include <stdio.h>
#include <string.h>

static unsigned g_failed;

static void s_expect(const char *name, const void *key, size_t key_len,
                     const void *data, size_t data_len, const char *want)
{
    uint8_t mac[duct_hmac_sha256_size];
    char    got[2u * sizeof mac + 1u];
    bool    made = duct_hmac_sha256(key, key_len, data, data_len, mac);
    if (made)
        duct_hex_encode(mac, sizeof mac, got);
    if (made && strcmp(got, want) == 0)
        return;
    ++g_failed;
    fprintf(stderr, "hmac_sha256 %s: %s\n", name, made ? got : "refused");
}

int main(void)
{
    static const char hi[]    = "Hi There";
    static const char jefe[]  = "Jefe";
    static const char what[]  = "what do ya want for nothing?";
    static const char first[] = "Test Using Larger Than Block-Size Key - Hash Key First";
    static const char large[] = "This is a test using a larger than block-size key and a larger than "
                                "block-size data. The key needs to be hashed before being used by the "
                                "HMAC algorithm.";
    uint8_t key[131], data[50];

    memset(key, 0x0b, 20u);
    s_expect("rfc4231 case 1", key, 20u, hi, sizeof hi - 1u,
             "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    s_expect("rfc4231 case 2", jefe, sizeof jefe - 1u, what, sizeof what - 1u,
             "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    memset(key, 0xaa, 20u);
    memset(data, 0xdd, sizeof data);
    s_expect("rfc4231 case 3", key, 20u, data, sizeof data,
             "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    memset(key, 0xaa, sizeof key);
    s_expect("rfc4231 case 6", key, sizeof key, first, sizeof first - 1u,
             "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    s_expect("rfc4231 case 7", key, sizeof key, large, sizeof large - 1u,
             "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
    s_expect("empty key and data", "", 0u, "", 0u,
             "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");

    if (g_failed != 0u)
        return 1;
    printf("hmac_sha256: OK (RFC 4231 cases 1, 2, 3, 6, 7 and the empty case)\n");
    return 0;
}
