/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file noise_keypair_test.c
 *  @brief duct_noise_keypair_from_priv against the keypair it must equal.
 *
 *  @c sc_from_priv expects the keypair derived from a generated private key to
 *  equal the generated one.
 */

#include "duct_noise.h"

#include <stdio.h>
#include <string.h>

/** @brief Derive a keypair from a generated private key and compare the two.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_from_priv(void)
{
    duct_noise_keypair_t made = {};
    if (!duct_noise_keypair_generate(&made))
        return "keypair generation failed";
    duct_noise_keypair_t via_priv = {};
    if (!duct_noise_keypair_from_priv(&via_priv, made.priv))
        return "keypair from a raw private key failed";
    if (memcmp(&via_priv, &made, sizeof via_priv) != 0)
        return "the keypair from the raw private key is not the generated one";
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    const char *err = sc_from_priv();
    if (err) {
        fprintf(stderr, "noise_keypair: %s\n", err);
        return 1;
    }
    printf("noise_keypair: OK (from the raw key equals the generated pair)\n");
    return 0;
}
