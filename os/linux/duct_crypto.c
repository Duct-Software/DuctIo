/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software */
#include "duct_crypto.h"

#include <sys/random.h>

bool duct_random_bytes(void *out, size_t n)
{
    auto at = (uint8_t *)out;
    while (n != 0u) {
        constexpr size_t draw_max = 256u;
        size_t take = duct_min(n, draw_max);
        duct_do_if(getentropy(at, take) != 0, return false);
        at += take;
        n -= take;
    }
    return true;
}
