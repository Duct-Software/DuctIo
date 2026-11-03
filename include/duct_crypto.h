/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_crypto.h
 *  @brief Random bytes and the constant-time compare, the primitives a protocol needs around its keys.
 *
 *  The random source and the compare stand on the OS and on nothing in a crypto library, so
 *  every build has them, a build without TLS or Noise included. The hex text of bytes is the
 *  string module's, @c duct_str.h, which this header includes. The secure erase,
 *  @c duct_secure_zero, is a macro of @c duct_core.h.
 */

#ifndef DUCT_CRYPTO_H
#define DUCT_CRYPTO_H

#include "duct_core.h"
#include "duct_str.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Fill @p out with @p n bytes from the operating system's random source.
 *  Linux blocks until the kernel pool is seeded. An @p n of 0 succeeds and writes
 *  nothing.
 *  @return false when the source refuses; @p out then holds a partial draw and is
 *          not to be used.
 */
[[nodiscard]] duct_nonnull(1) bool duct_random_bytes(void *out, size_t n);

/** @brief Compare @p n bytes of @p a and @p b in time that depends on @p n alone.
 *  @return true when every byte is equal, and for an @p n of 0.
 */
[[nodiscard]] duct_nonnull(1, 2) bool duct_ct_equal(const void *a, const void *b, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* DUCT_CRYPTO_H */
