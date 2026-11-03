/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_cookie.h
 *  @brief Address proof for a shared datagram listener: a MAC over a peer's
 *  address under a secret the listener keeps to itself.
 *
 *  Checking a cookie needs no session, no key exchange and no stored state, so
 *  the check runs on the io thread ahead of everything a flood spends. Three
 *  secrets form a ring by epoch: the current one mints, the previous one still
 *  validates, and the third is the slot the next rotation writes. A rotation
 *  runs inside @ref duct_cookie_valid once @c duct_cookie_rotate_ns has passed,
 *  one step a call, so a cookie validates for at least one rotation span and
 *  lapses at the second rotation after it was minted.
 *
 *  Any number of threads mint and validate. The caller supplies the time of
 *  every call that can rotate, from one monotonic clock, nanoseconds.
 */

#ifndef DUCT_COOKIE_H
#define DUCT_COOKIE_H

#include "duct_core.h"
#include "duct_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Span one secret mints cookies for, 2 minutes in nanoseconds. */
static constexpr uint64_t duct_cookie_rotate_ns   = 120'000'000'000u;
/** @brief Cookie length, bytes: one SipHash-2-4 tag. */
static constexpr size_t   duct_cookie_size        = 8u;
/** @brief Secret length, bytes: one SipHash key. */
static constexpr size_t   duct_cookie_secret_size = 16u;

/** @brief Secrets and rotation state of one listener's cookie gate. */
typedef struct duct_cookie {
    uint8_t          secret[3][duct_cookie_secret_size]; /**< Ring by epoch modulo 3: current, previous, next. */
    uint32_t _Atomic epoch;                              /**< Rotations done; picks the current secret. */
    uint64_t _Atomic rotated_ns;                         /**< Time of the last rotation. */
} duct_cookie_t;

/** @brief Draw the secrets and start the first epoch at @p now.
 *  @return false when the system random source refuses; the gate is unusable then.
 */
[[nodiscard]] duct_nonnull(1) bool duct_cookie_init(duct_cookie_t *c, uint64_t now);

/** @brief Write @p peer's cookie under the current secret.
 *  The MAC covers the address and its family; the port stays out, so a client
 *  presenting the cookie from the new socket of its redial still validates.
 */
duct_nonnull(1, 2, 3) void duct_cookie_mint(duct_cookie_t *c, const duct_peer_t *peer,
                                            uint8_t out[duct_cookie_size]);

/** @brief Test whether @p cookie was minted for @p peer's address under the
 *  current or the previous secret.
 *  Rotates first when @p now is a span past the last rotation; a time before
 *  the last rotation rotates nothing. Both secrets are compared in constant time.
 */
[[nodiscard]] duct_nonnull(1, 2, 3) bool duct_cookie_valid(duct_cookie_t *c, const duct_peer_t *peer,
                                                           const uint8_t cookie[duct_cookie_size],
                                                           uint64_t now);

#ifdef __cplusplus
}
#endif

#endif
