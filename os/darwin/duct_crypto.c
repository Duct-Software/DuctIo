/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software */
#include "duct_crypto.h"

#include <stdlib.h>

bool duct_random_bytes(void *out, size_t n)
{
    /* Public on macOS and iOS; no sys/random.h dependency on iOS. */
    if (n != 0u)
        arc4random_buf(out, n);
    return true;
}
