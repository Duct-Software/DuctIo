/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file hex_test.c
 *  @brief The hex text helpers of duct_crypto.h, both ways.
 *
 *  @c sc_decode expects lowercase, uppercase and mixed-case digits to decode, and
 *  a view of no digits, one of an odd or an even length other than twice the bytes,
 *  and a digit outside the hex set to be refused, a space, a "0x" prefix, a newline
 *  and a NUL among them, the output untouched by a refusal. A view into a longer
 *  text decodes where it lies. @c sc_encode expects lowercase digits behind a NUL,
 *  and for no bytes the NUL alone, from the function and from the array macro.
 *  @c sc_round takes every byte value through its text and back.
 */

#include "duct_crypto.h"

#include <stdio.h>
#include <string.h>

/** @brief View of the @p len bytes at @p text, which need no terminator. */
static duct_view_cc sc_view(const char *text, size_t len)
{
    return (duct_view_cc){ .data = text, .size = len };
}

/** @brief View of the whole C string @p text. */
static duct_view_cc sc_str(const char *text)
{
    return sc_view(text, strlen(text));
}

/** @brief Decode accepted and refused views.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_decode(void)
{
    uint8_t out[3];
    static const uint8_t want[3] = { 0x00u, 0xffu, 0x7au };
    if (duct_hex_decode(sc_str("00ff7a"), out) != rc_ok || memcmp(out, want, 3u) != 0)
        return "lowercase digits did not decode";
    memset(out, 0, sizeof out);
    if (duct_hex_decode(sc_str("00FF7A"), out) != rc_ok || memcmp(out, want, 3u) != 0)
        return "uppercase digits did not decode";
    memset(out, 0, sizeof out);
    if (duct_hex_decode(sc_str("00fF7a"), out) != rc_ok || memcmp(out, want, 3u) != 0)
        return "mixed case digits did not decode";
    memset(out, 0, sizeof out);
    if (duct_hex_decode(sc_view("00ff7aXYZ", 6u), out) != rc_ok || memcmp(out, want, 3u) != 0)
        return "a view into a longer text did not decode where it lies";
    uint8_t none[1];
    if (duct_hex_decode_into(sc_str(""), none, 0u) != rc_ok)
        return "no digits for no bytes did not decode";
    if (duct_hex_decode(sc_view(nullptr, 0u), out) == rc_ok)
        return "an empty view decoded into three bytes";
    memset(out, 0x5a, sizeof out);
    if (duct_hex_decode(sc_str("00ff7"), out) == rc_ok || duct_hex_decode(sc_str("00ff7a0"), out) == rc_ok
        || duct_hex_decode(sc_str("00ff"), out) == rc_ok || duct_hex_decode(sc_str("00ff7a00"), out) == rc_ok)
        return "a text of another length than twice the bytes decoded";
    if (duct_hex_decode(sc_str("00ff7g"), out) == rc_ok || duct_hex_decode(sc_str("00ff7 "), out) == rc_ok
        || duct_hex_decode(sc_str("0x00ff"), out) == rc_ok || duct_hex_decode(sc_str("00ff7a\n"), out) == rc_ok
        || duct_hex_decode(sc_view("00ff\0a", 6u), out) == rc_ok)
        return "a text with a digit outside the hex set decoded";
    for (unsigned i = 0u; i < sizeof out; ++i)
        if (out[i] != 0x5au)
            return "a refused text touched the output";
    return nullptr;
}

/** @brief Encode three bytes and none.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_encode(void)
{
    char text[7];
    static const uint8_t bytes[3] = { 0x00u, 0xffu, 0x7au };
    memset(text, 'x', sizeof text);
    if (duct_hex_encode(bytes, 3u, text) != text || strcmp(text, "00ff7a") != 0)
        return "three bytes did not encode to six lowercase digits and a NUL";
    memset(text, 'x', sizeof text);
    duct_discard duct_hex_encode(bytes, 0u, text);
    if (text[0] != '\0' || text[1] != 'x')
        return "no bytes did not encode to a NUL alone";
    if (strcmp(duct_hex_text(bytes), "00ff7a") != 0)
        return "an array did not encode through its macro";
    struct { const uint8_t digest[2]; } held = { { 0xabu, 0x01u } };
    char line[16];
    snprintf(line, sizeof line, "%s|%s", duct_hex_text(held.digest), duct_hex_text(bytes));
    if (strcmp(line, "ab01|00ff7a") != 0)
        return "two texts in one call did not stand apart";
    return nullptr;
}

/** @brief Take all 256 byte values through encode and decode.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_round(void)
{
    uint8_t all[256],
            back[256];
    for (unsigned i = 0u; i < 256u; ++i)
        all[i] = (uint8_t)i;
    const char *text = duct_hex_text(all);
    if (strlen(text) != 512u || duct_hex_decode(sc_str(text), back) != rc_ok
        || memcmp(all, back, sizeof all) != 0)
        return "256 byte values did not come back through their text";
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    const char *err = sc_decode();
    if (!err)
        err = sc_encode();
    if (!err)
        err = sc_round();
    if (err) {
        fprintf(stderr, "hex: %s\n", err);
        return 1;
    }
    printf("hex: OK (decode, encode, every byte value round trip)\n");
    return 0;
}
