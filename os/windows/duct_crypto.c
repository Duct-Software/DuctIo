/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software */
#include "duct_crypto.h"

#include <windows.h>
#include <bcrypt.h>
#include <limits.h>

bool duct_random_bytes(void *out, size_t n)
{
    auto at = (uint8_t *)out;
    while (n != 0u) {
        ULONG take = n > ULONG_MAX ? ULONG_MAX : (ULONG)n;
        NTSTATUS st = BCryptGenRandom(nullptr, at, take, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        duct_do_if(!BCRYPT_SUCCESS(st), return false);
        at += take;
        n -= take;
    }
    return true;
}
