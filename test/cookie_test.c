/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file cookie_test.c
 *  @brief The cookie gate on a driven clock: whom a cookie names, a flipped
 *  bit, the rotation of the secret and readers racing it.
 *
 *  @c sc_peer expects a cookie to validate for its peer from any port and for
 *  nobody else: not another address, not the same bytes under the other
 *  family, not zeros. @c sc_flip expects every single-bit change to a cookie
 *  to be refused. @c sc_rotate expects a cookie to outlive one rotation and not
 *  two, a rotation to write only the secret no reader holds, and a time before
 *  the last rotation to rotate nothing. @c sc_race runs four threads minting and
 *  validating across twenty rotations and expects the epoch never to run ahead
 *  of the time they presented; under ThreadSanitizer it is the race check.
 */

#include "duct.h"
#include "duct_cookie.h"
#include "test_helpers.h"

#include <stdatomic.h>

/** @brief Return @p msg from the calling check when @p cond fails. */
#define expect(cond, msg) do { if (!(cond)) return msg; } while (0)

/** @brief Synthetic clock origin, nanoseconds. */
static constexpr uint64_t t0  = 1'000'000'000'000u;
/** @brief Rotation span, nanoseconds. */
static constexpr uint64_t rot = duct_cookie_rotate_ns;

/** @brief IPv4 peer 10.0.0.@p host at @p port. */
static duct_peer_t s_v4(uint8_t host, uint16_t port)
{
    duct_peer_t peer = { .family = AF_INET, .port = port };
    memcpy(peer.addr.v4, (uint8_t[]){ 10u, 0u, 0u, host }, 4u);
    return peer;
}

/** @brief IPv6 peer sharing the first four address bytes of IPv4 peer 10.0.0.@p host, at @p port. */
static duct_peer_t s_v6(uint8_t host, uint16_t port)
{
    duct_peer_t peer = { .family = AF_INET6, .port = port };
    memcpy(peer.addr.v6, (uint8_t[]){ 10u, 0u, 0u, host }, 4u);
    return peer;
}

/** @brief Validate a cookie for its peer, another port, another address, the other family and zeros.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_peer(void)
{
    duct_cookie_t c;
    expect(duct_cookie_init(&c, t0), "the cookie gate did not start");
    auto a = s_v4(1u, 5000u);
    uint8_t ck[duct_cookie_size];
    duct_cookie_mint(&c, &a, ck);
    expect(duct_cookie_valid(&c, &a, ck, t0), "a cookie is refused for the peer it was minted for");
    auto other_port = s_v4(1u, 61000u);
    expect(duct_cookie_valid(&c, &other_port, ck, t0), "a cookie is refused from another port of its peer");
    auto other_host = s_v4(2u, 5000u);
    expect(!duct_cookie_valid(&c, &other_host, ck, t0), "a cookie is accepted for another address");
    auto same_bytes = s_v6(1u, 5000u);
    expect(!duct_cookie_valid(&c, &same_bytes, ck, t0), "a cookie is accepted across address families");
    uint8_t zero[duct_cookie_size] = {};
    expect(!duct_cookie_valid(&c, &a, zero, t0), "an all-zero cookie is accepted");
    return nullptr;
}

/** @brief Flip each bit of a cookie in turn and validate the result.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_flip(void)
{
    duct_cookie_t c;
    expect(duct_cookie_init(&c, t0), "the cookie gate did not start");
    auto a = s_v6(7u, 4000u);
    uint8_t ck[duct_cookie_size];
    duct_cookie_mint(&c, &a, ck);
    for (unsigned bit = 0u; bit < 8u * duct_cookie_size; ++bit) {
        uint8_t bad[duct_cookie_size];
        memcpy(bad, ck, sizeof bad);
        bad[bit / 8u] ^= (uint8_t)(1u << (bit % 8u));
        expect(!duct_cookie_valid(&c, &a, bad, t0), "a cookie with one bit flipped is accepted");
    }
    return nullptr;
}

/** @brief Step the clock across three rotations and a backward reading.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_rotate(void)
{
    duct_cookie_t c;
    expect(duct_cookie_init(&c, t0), "the cookie gate did not start");
    auto a = s_v4(9u, 1u);
    uint8_t first[duct_cookie_size],
            second[duct_cookie_size];
    duct_cookie_mint(&c, &a, first);
    expect(duct_cookie_valid(&c, &a, first, t0 + rot - 1u) && duct_atomic_load(&c.epoch, relaxed) == 0u,
           "the secret rotates before its span is out");
    uint8_t before[3][duct_cookie_secret_size];
    memcpy(before, c.secret, sizeof before);
    expect(duct_cookie_valid(&c, &a, first, t0 + rot) && duct_atomic_load(&c.epoch, relaxed) == 1u,
           "a cookie of the last secret is refused after one rotation");
    expect(memcmp(before[0], c.secret[0], duct_cookie_secret_size) == 0
               && memcmp(before[2], c.secret[2], duct_cookie_secret_size) == 0
               && memcmp(before[1], c.secret[1], duct_cookie_secret_size) != 0,
           "a rotation wrote a secret a reader still holds, or none");
    duct_cookie_mint(&c, &a, second);
    expect(memcmp(first, second, sizeof first) != 0, "a rotation did not change the cookie minted");
    expect(duct_cookie_valid(&c, &a, second, t0 + rot), "a cookie of the new secret is refused");
    expect(duct_cookie_valid(&c, &a, first, t0 + 2u * rot - 1u) && duct_atomic_load(&c.epoch, relaxed) == 1u,
           "the second rotation comes before its span is out");
    expect(duct_cookie_valid(&c, &a, second, t0 + 2u * rot) && duct_atomic_load(&c.epoch, relaxed) == 2u,
           "the second rotation did not come");
    expect(!duct_cookie_valid(&c, &a, first, t0 + 2u * rot), "a cookie outlives two rotations");
    expect(!duct_cookie_valid(&c, &a, second, t0 + 3u * rot) && duct_atomic_load(&c.epoch, relaxed) == 3u,
           "the third rotation did not drop the cookie of the first");
    expect(duct_cookie_valid(&c, &a, second, t0 + 3u * rot - 1u) == false,
           "a clock reading before the last rotation brought a cookie back");
    duct_cookie_mint(&c, &a, first);
    expect(duct_cookie_valid(&c, &a, first, t0) && duct_atomic_load(&c.epoch, relaxed) == 3u,
           "a clock reading before the last rotation rotated the secret");
    expect(duct_cookie_valid(&c, &a, first, t0 + 3u * rot + 1u) && duct_atomic_load(&c.epoch, relaxed) == 3u,
           "a clock reading before the last rotation moved the next one");
    return nullptr;
}

/** @brief Threads racing in @c sc_race. */
static constexpr unsigned race_threads = 4u;
/** @brief Mint and validate rounds of each racing thread, a rotation span over 2000 rounds. */
static constexpr unsigned race_steps   = 40'000u;

/** @brief 1 once the racing threads may start. */
static atomic_int g_go = 0;
/** @brief The gate the racing threads share. */
static duct_cookie_t g_race;

/** @brief Mint and validate for the peer numbered by @p arg along the shared time series.
 *  @return nullptr.
 */
static void *s_race_worker(void *arg)
{
    auto peer = s_v4((uint8_t)(uintptr_t)arg, 7u);
    while (!duct_atomic_load(&g_go, acquire))
        th_sleep_ms(1u);
    for (unsigned i = 0u; i < race_steps; ++i) {
        uint8_t ck[duct_cookie_size];
        duct_cookie_mint(&g_race, &peer, ck);
        duct_discard duct_cookie_valid(&g_race, &peer, ck, t0 + (uint64_t)i * (rot / 2000u));
    }
    return nullptr;
}

/** @brief Run the racing threads and compare the epoch with the span they covered.
 *  @return the text of the first failed check, nullptr when all hold.
 */
static const char *sc_race(void)
{
    expect(duct_cookie_init(&g_race, t0), "the cookie gate did not start");
    pthread_t th[race_threads];
    for (unsigned i = 0u; i < race_threads; ++i)
        expect(pthread_create(&th[i], nullptr, s_race_worker, (void *)(uintptr_t)(i + 1u)) == 0,
               "a thread did not start");
    duct_atomic_store(&g_go, 1, release);
    for (unsigned i = 0u; i < race_threads; ++i)
        pthread_join(th[i], nullptr);
    uint64_t span = (uint64_t)(race_steps - 1u) * (rot / 2000u),
             epoch = duct_atomic_load(&g_race.epoch, acquire);
    expect(epoch >= 1u && epoch * rot <= span, "racing readers rotated the secret more often than its span allows");
    return nullptr;
}

int main(void)
{
    static const struct { const char *name; const char *(*fn)(void); } cases[] = {
        { "peer",   sc_peer },
        { "flip",   sc_flip },
        { "rotate", sc_rotate },
        { "race",   sc_race },
    };
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        auto err = cases[i].fn();
        if (err) {
            fprintf(stderr, "cookie: %s: %s\n", cases[i].name, err);
            return 1;
        }
    }
    printf("cookie: OK\n");
    return 0;
}
