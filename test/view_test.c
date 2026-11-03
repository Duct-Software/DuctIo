/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

#include "duct_core.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static bool s_view_roundtrip(void)
{
    duct_ptr_t(uint32_t) owned = duct_new(uint32_t, 8);
    if (!owned)
        return false;
    for (size_t i = 0u; i < 8u; ++i)
        duct_at(owned)[i] = (uint32_t)(i + 1u);

    duct_view_u32 whole = duct_view_all(duct_view_u32, owned);
    if (duct_view_len(whole) != 8u || duct_view_byte_len(whole) != 32u)
        return false;
    if (duct_view_at(whole, 0u) != 1u || duct_view_at(whole, 7u) != 8u)
        return false;

    duct_view_u32 part = duct_view_slice(duct_view_u32, whole, 2u, 3u);
    if (duct_view_len(part) != 3u || duct_view_at(part, 0u) != 3u || duct_view_at(part, 2u) != 5u)
        return false;

    duct_view_cu32 frozen = duct_view_widen(duct_view_cu32, whole);
    if (duct_view_len(frozen) != 8u || duct_view_at(frozen, 3u) != 4u)
        return false;

    duct_view_u8 bytes = duct_view(duct_view_u8, (uint8_t *)duct_at(owned), 32u);
    if (duct_view_byte_len(bytes) != 32u || duct_view_at(bytes, 4u) != 2u)
        return false;

    duct_del(owned);
    return true;
}

static bool s_const_lends(void)
{
    static const uint8_t ro[6u] = { 0u, 1u, 2u, 3u, 4u, 5u };
    duct_view_cu8 v = duct_view(duct_view_cu8, ro, sizeof ro);
    return duct_view_len(v) == 6u && duct_view_at(v, 5u) == 5u
        && duct_view_byte_len(v) == sizeof ro;
}

int main(void)
{
    static const struct { const char *name; bool (*fn)(void); } cases[] = {
        { "roundtrip", s_view_roundtrip },
        { "const_lends", s_const_lends },
    };
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        if (!cases[i].fn()) {
            fprintf(stderr, "view: %s: FAILED\n", cases[i].name);
            return 1;
        }
    }
    printf("view: OK\n");
    return 0;
}
