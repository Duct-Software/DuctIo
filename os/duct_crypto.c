/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_crypto.c
 *  @brief Constant-time compare shared by every platform.
 */

#include "duct_crypto.h"

/* The reads are volatile and the result is the OR of every difference, so no
 * compiler ends the scan at the first mismatch. */
bool duct_ct_equal(const void *a, const void *b, size_t n)
{
    auto x = (const volatile uint8_t *)a;
    auto y = (const volatile uint8_t *)b;
    uint8_t diff = 0u;
    for (size_t i = 0u; i < n; ++i)
        diff |= (uint8_t)(x[i] ^ y[i]);
    return diff == 0u;
}
