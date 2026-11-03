/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */
#include "duct_crypto.h"

#include <stdio.h>
#include <string.h>

static unsigned s_calls;
static bool s_failure;

/* Interpose the OS call used by the real Linux implementation. */
int getentropy(void *out, size_t n)
{
    ++s_calls;
    if (n > 256u || (s_failure && s_calls > 1u))
        return -1;
    memset(out, 0x5a, n);
    return 0;
}

int main(void)
{
    uint8_t bytes[513];
    memset(bytes, 0xa5, sizeof bytes);
    if (!duct_random_bytes(bytes, 0u) || s_calls != 0u)
        return 1;
    if (!duct_random_bytes(bytes, sizeof bytes) || s_calls != 3u)
        return 2;
    for (size_t i = 0; i < sizeof bytes; ++i)
        if (bytes[i] != 0x5a)
            return 3;
    s_calls = 0u;
    s_failure = true;
    memset(bytes, 0xa5, sizeof bytes);
    if (duct_random_bytes(bytes, sizeof bytes) || s_calls != 2u)
        return 4;
    for (size_t i = 0; i < sizeof bytes; ++i)
        if (bytes[i] != (i < 256u ? 0x5a : 0xa5))
            return 5;
    puts("crypto_random_failure: OK (zero length, chunking, partial failure)");
    return 0;
}
