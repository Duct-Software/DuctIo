/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file crypto_test.c
 *  @brief The random draws, the erase and the compare of duct_crypto.h.
 *
 *  @c sc_random expects two draws of 64 bytes to differ and the first not to be
 *  zero, a draw of no bytes to succeed, and a draw of 8192 bytes to cover over 200
 *  of the 256 byte values. @c sc_zero erases a span inside a buffer, then the buffer
 *  whole, expects the bytes past the span untouched and a span of 0 to change
 *  nothing. @c sc_equal compares equal spans, a span with itself and spans of 0,
 *  then flips the top bit of each byte of a 32-byte span in turn and expects the
 *  compare to refuse while the equal head still holds.
 */

#include "duct_crypto.h"

#include <stdio.h>
#include <string.h>

/** @brief Draw random spans and check them.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_random(void)
{
    uint8_t a[64] = {},
            b[64] = {};
    if (!duct_random_bytes(a, sizeof a) || !duct_random_bytes(b, sizeof b))
        return "a draw of 64 bytes failed";
    if (memcmp(a, b, sizeof a) == 0)
        return "two draws of 64 bytes were equal";
    uint8_t zero[64] = {};
    if (memcmp(a, zero, sizeof a) == 0)
        return "a draw of 64 bytes was all zero";
    if (!duct_random_bytes(a, 0u))
        return "a draw of no bytes failed";

    /* Cross the POSIX draw boundary with an unaligned output and a partial
     * final draw; neither adjacent sentinel may be overwritten. */
    static constexpr size_t sizes[] = { 1u, 255u, 256u, 257u, 8193u };
    uint8_t guarded[8195];
    for (unsigned i = 0u; i < sizeof sizes / sizeof sizes[0]; ++i) {
        size_t n = sizes[i];
        memset(guarded, 0xa5, sizeof guarded);
        if (!duct_random_bytes(guarded + 1u, n))
            return "a boundary-sized draw failed";
        if (guarded[0] != 0xa5u || guarded[n + 1u] != 0xa5u)
            return "a draw overwrote its adjacent sentinel";
    }

    uint8_t big[8192] = {};
    if (!duct_random_bytes(big, sizeof big))
        return "a draw of 8192 bytes failed";
    unsigned seen[256] = {};
    for (size_t i = 0u; i < sizeof big; ++i)
        ++seen[big[i]];
    unsigned distinct = 0u;
    for (unsigned v = 0u; v < 256u; ++v)
        distinct += seen[v] != 0u;
    return distinct > 200u ? nullptr : "a draw of 8192 bytes held under 200 distinct values";
}

/** @brief Erase spans of a filled buffer and check what stayed.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_zero(void)
{
    uint8_t buf[48];
    memset(buf, 0xa5, sizeof buf);
    duct_secure_zero(buf, 16u);
    for (unsigned i = 0u; i < 16u; ++i)
        if (buf[i] != 0u)
            return "a byte inside the span stayed";
    for (unsigned i = 16u; i < sizeof buf; ++i)
        if (buf[i] != 0xa5u)
            return "a byte past the span changed";
    duct_secure_zero(buf, 0u);
    if (buf[16] != 0xa5u)
        return "a span of no bytes changed something";
    duct_secure_zero(buf, sizeof buf);
    for (unsigned i = 0u; i < sizeof buf; ++i)
        if (buf[i] != 0u)
            return "a byte of the whole buffer stayed";
    return nullptr;
}

/** @brief Compare equal and one-bit-apart spans.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_equal(void)
{
    uint8_t a[32],
            b[32];
    for (unsigned i = 0u; i < sizeof a; ++i)
        a[i] = b[i] = (uint8_t)(i * 7u + 1u);
    if (!duct_ct_equal(a, b, sizeof a))
        return "equal spans compared unequal";
    if (!duct_ct_equal(a, b, 0u) || !duct_ct_equal(a, a, sizeof a))
        return "a span of no bytes or a span with itself compared unequal";
    for (unsigned at = 0u; at < sizeof a; ++at) {
        b[at] ^= 0x80u;
        if (duct_ct_equal(a, b, sizeof a))
            return "spans differing in one bit compared equal";
        if (at > 0u && !duct_ct_equal(a, b, at))
            return "the equal head of two spans compared unequal";
        b[at] ^= 0x80u;
    }
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    const char *err = sc_random();
    if (!err)
        err = sc_zero();
    if (!err)
        err = sc_equal();
    if (err) {
        fprintf(stderr, "crypto: %s\n", err);
        return 1;
    }
    printf("crypto: OK (random draws, secure zero, constant-time compare)\n");
    return 0;
}
