/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file be_test.c
 *  @brief The big-endian field helpers of duct_core.h.
 *
 *  @c sc_load expects 16- and 32-bit fields to be read most significant byte first,
 *  at odd and even offsets of a byte string. @c sc_store expects the same order
 *  written, and the bytes beside the field left as they were. @c sc_round takes
 *  values from 0 to 0xffffffff through store and load at four alignments.
 */

#include "duct_core.h"

#include <stdio.h>
#include <string.h>

/** @brief Read 16- and 32-bit fields out of a fixed byte string.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_load(void)
{
    static const uint8_t bytes[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x80, 0xff, 0x00, 0x7f };
    if (duct_load_be16(bytes) != 0x0102u || duct_load_be16(bytes + 1) != 0x0203u
        || duct_load_be16(bytes + 5) != 0x80ffu || duct_load_be16(bytes + 6) != 0xff00u)
        return "a 16-bit field was not read big-endian";
    if (duct_load_be32(bytes) != 0x01020304u || duct_load_be32(bytes + 1) != 0x02030405u
        || duct_load_be32(bytes + 4) != 0x0580ff00u || duct_load_be32(bytes + 5) != 0x80ff007fu)
        return "a 32-bit field was not read big-endian";
    return nullptr;
}

/** @brief Write 16- and 32-bit fields into a buffer of sentinel bytes.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_store(void)
{
    static const uint8_t want16[8] = { 0xee, 0xa1, 0xb2, 0xee, 0xee, 0xee, 0xee, 0xee };
    static const uint8_t want32[8] = { 0xee, 0xee, 0xee, 0x80, 0x00, 0x00, 0x01, 0xee };
    uint8_t out[8];
    memset(out, 0xee, sizeof out);
    duct_store_be16(out + 1, 0xa1b2u);
    if (memcmp(out, want16, sizeof out) != 0)
        return "a 16-bit field was not written big-endian, or its neighbours changed";
    memset(out, 0xee, sizeof out);
    duct_store_be32(out + 3, 0x80000001u);
    if (memcmp(out, want32, sizeof out) != 0)
        return "a 32-bit field was not written big-endian, or its neighbours changed";
    return nullptr;
}

/** @brief Take edge values through store and load at four alignments.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_round(void)
{
    static const uint32_t words[] = {
        0x00000000u, 0x00000001u, 0x000000ffu, 0x00000100u, 0x00007fffu, 0x00008000u,
        0x0000ffffu, 0x00010000u, 0x12345678u, 0x7fffffffu, 0x80000000u, 0xffffffffu,
    };
    uint8_t out[8];
    for (size_t i = 0u; i < sizeof words / sizeof *words; ++i) {
        for (size_t at = 0u; at < 4u; ++at) {
            memset(out, 0xee, sizeof out);
            duct_store_be32(out + at, words[i]);
            if (duct_load_be32(out + at) != words[i])
                return "a 32-bit value did not come back through its bytes";
            if (words[i] <= UINT16_MAX) {
                memset(out, 0xee, sizeof out);
                duct_store_be16(out + at, (uint16_t)words[i]);
                if (duct_load_be16(out + at) != words[i])
                    return "a 16-bit value did not come back through its bytes";
            }
        }
    }
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    const char *err = sc_load();
    if (!err)
        err = sc_store();
    if (!err)
        err = sc_round();
    if (err) {
        fprintf(stderr, "be: %s\n", err);
        return 1;
    }
    printf("be: OK (load, store, round trip at four alignments)\n");
    return 0;
}
