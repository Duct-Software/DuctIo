/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

#include "duct_cookie.h"
#include "duct_crypto.h"
#include "duct_hash.h"

#include <string.h>

static_assert(duct_cookie_secret_size == duct_siphash_key_size,
    "a secret is a SipHash key");
static_assert(duct_cookie_size == sizeof(uint64_t),
    "a cookie is one SipHash tag");

/** @brief Write the cookie of @p peer's address, family and port under @p secret.
 *  All sixteen address bytes go in whatever the family is: an IPv4 peer's tail
 *  is zero by construction, and the family is hashed beside them so the two
 *  families never share a cookie. The port rides behind the family, so one
 *  address's endpoints never share a mint.
 */
static void s_mac(const uint8_t *secret, const duct_peer_t *peer, uint8_t *out)
{
    uint8_t msg[sizeof peer->addr.v6 + sizeof peer->family + sizeof peer->port];
    memcpy(msg, peer->addr.v6, sizeof peer->addr.v6);
    msg[sizeof peer->addr.v6] = (uint8_t)(peer->family >> 8u);
    msg[sizeof peer->addr.v6 + 1u] = (uint8_t)peer->family;
    msg[sizeof peer->addr.v6 + 2u] = (uint8_t)(peer->port >> 8u);
    msg[sizeof peer->addr.v6 + 3u] = (uint8_t)peer->port;
    uint64_t mac = duct_siphash24(secret, msg, sizeof msg);
    memcpy(out, &mac, sizeof mac);
}

/** @brief Rotate the ring when @p now is a span past the last rotation.
 *  The caller that wins the compare-exchange on @c rotated_ns draws the next
 *  secret into the slot no reader holds, the one after the current, and only
 *  then publishes the epoch: readers hold the current and the previous slot,
 *  so the write meets no read. A draw that fails restores the time and retries
 *  at the next call.
 */
static void s_rotate_if_due(duct_cookie_t *c, uint64_t now)
{
    uint64_t since = duct_atomic_load(&c->rotated_ns, acquire);
    if (now < since + duct_cookie_rotate_ns
        || !duct_atomic_cas(strong, &c->rotated_ns, &since, now, acq_rel, relaxed))
        return;
    uint32_t epoch = duct_atomic_load(&c->epoch, acquire);
    if (!duct_random_bytes(c->secret[(epoch + 1u) % 3u], duct_cookie_secret_size)) {
        duct_atomic_store(&c->rotated_ns, since, release);
        return;
    }
    duct_atomic_store(&c->epoch, epoch + 1u, release);
}

bool duct_cookie_init(duct_cookie_t *c, uint64_t now)
{
    duct_atomic_store(&c->epoch, 0u, relaxed);
    duct_atomic_store(&c->rotated_ns, now, relaxed);
    return duct_random_bytes(c->secret, sizeof c->secret);
}

void duct_cookie_mint(duct_cookie_t *c, const duct_peer_t *peer, uint8_t out[duct_cookie_size])
{
    s_mac(c->secret[duct_atomic_load(&c->epoch, acquire) % 3u], peer, out);
}

bool duct_cookie_valid(duct_cookie_t *c, const duct_peer_t *peer,
                       const uint8_t cookie[duct_cookie_size], uint64_t now)
{
    s_rotate_if_due(c, now);
    uint32_t epoch = duct_atomic_load(&c->epoch, acquire);
    uint8_t want[duct_cookie_size];
    bool ok = false;
    for (unsigned back = 0u; back < 2u; ++back) {
        s_mac(c->secret[(epoch + 3u - back) % 3u], peer, want);
        ok |= duct_ct_equal(want, cookie, duct_cookie_size);
    }
    return ok;
}
