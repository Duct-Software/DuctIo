/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_hash.h
 *  @brief splitmix64 bucket hashing over an intrusive hash-chain handle.
 *
 *  Embed one @ref duct_hash_handle_t per hashable type and one
 *  @c duct_hash_handle_t* bucket array per table —
 *  a fixed embedded array or a single @c duct_new allocation, either way just
 *  a plain field on the owning type. @ref DUCT_HASH_DECLARE generates typed
 *  find/insert wrappers over that owning type, with the bucket-count mask
 *  folded in as a compile-time constant — no table/mask bookkeeping is ever
 *  visible at the call site.
 *
 *  Also SipHash-2-4, the keyed hash for input a peer controls: the MAC on a
 *  join lead, and the cover over the bytes that name a session in it.
 */

#ifndef DUCT_HASH_H
#define DUCT_HASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Splitmix64 finalizer for bucket spread. */
static inline uint64_t duct_splitmix64(uint64_t x)
{
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

/** @brief Map key to bucket index. mask = table_size - 1 for power-of-two. */
static inline unsigned duct_hash_idx(uint64_t key, unsigned mask)
{
    return (unsigned)duct_splitmix64(key) & mask;
}

/** @brief SipHash key size, bytes. */
static constexpr size_t duct_siphash_key_size = 16u;

/** @name SipHash-2-4 steps
 *  A little-endian load and store of up to 8 bytes, one rotation, one SipRound,
 *  and one 64-bit message word absorbed through two rounds, as the reference
 *  defines them.
 *  @{
 */
static inline uint64_t duct_sip_le64(const uint8_t *p, size_t n)
{
    uint64_t v = 0u;
    for (size_t i = 0u; i < n; ++i)
        v |= (uint64_t)p[i] << (8u * i);
    return v;
}

static inline void duct_sip_put_le64(uint8_t *p, size_t n, uint64_t v)
{
    for (size_t i = 0u; i < n; ++i)
        p[i] = (uint8_t)(v >> (8u * i));
}

static inline uint64_t duct_sip_rotl(uint64_t x, unsigned b)
{
    return (x << b) | (x >> (64u - b));
}

static inline void duct_sip_round(uint64_t v[4])
{
    v[0] += v[1]; v[1] = duct_sip_rotl(v[1], 13u); v[1] ^= v[0]; v[0] = duct_sip_rotl(v[0], 32u);
    v[2] += v[3]; v[3] = duct_sip_rotl(v[3], 16u); v[3] ^= v[2];
    v[0] += v[3]; v[3] = duct_sip_rotl(v[3], 21u); v[3] ^= v[0];
    v[2] += v[1]; v[1] = duct_sip_rotl(v[1], 17u); v[1] ^= v[2]; v[2] = duct_sip_rotl(v[2], 32u);
}

static inline void duct_sip_absorb(uint64_t v[4], uint64_t m)
{
    v[3] ^= m;
    duct_sip_round(v);
    duct_sip_round(v);
    v[0] ^= m;
}
/** @} */

/** @brief SipHash-2-4 of @p len bytes at @p data under @p key, a 64-bit PRF
 *  for short input. */
static inline uint64_t duct_siphash24(const uint8_t key[duct_siphash_key_size],
                                      const void *data, size_t len)
{
    uint64_t k0 = duct_sip_le64(key, 8u),
             k1 = duct_sip_le64(key + 8u, 8u);
    uint64_t v[4] = {
        UINT64_C(0x736f6d6570736575) ^ k0, UINT64_C(0x646f72616e646f6d) ^ k1,
        UINT64_C(0x6c7967656e657261) ^ k0, UINT64_C(0x7465646279746573) ^ k1,
    };
    auto p = (const uint8_t *)data;
    size_t whole = len & ~(size_t)7u;
    for (size_t i = 0u; i < whole; i += 8u)
        duct_sip_absorb(v, duct_sip_le64(p + i, 8u));
    duct_sip_absorb(v, ((uint64_t)len << 56u) | duct_sip_le64(p + whole, len - whole));
    v[2] ^= 0xffu;
    for (unsigned i = 0u; i < 4u; ++i)
        duct_sip_round(v);
    return v[0] ^ v[1] ^ v[2] ^ v[3];
}

/** @brief Cover or uncover the first @p n bytes at @p bytes, in place.
 *  They are exclusive-ored with the first @p n bytes of the SipHash-2-4 of
 *  @p salt, as 8 little-endian bytes, under @p key, so the same call does either
 *  direction. @p n is at most 8, the bytes of one SipHash output. */
static inline void duct_siphash_cover(uint8_t *bytes, size_t n,
                                      const uint8_t key[duct_siphash_key_size],
                                      uint64_t salt)
{
    uint8_t in[sizeof salt];
    duct_sip_put_le64(in, sizeof in, salt);
    uint64_t draw = duct_siphash24(key, in, sizeof in);
    for (size_t i = 0u; i < n; ++i)
        bytes[i] ^= (uint8_t)(draw >> (8u * i));
}

/** @brief Intrusive hash-chain link. Embed one as a named member (e.g. @c hh).
 *  @c pprev is the address of whichever
 *  link points at this node — a bucket head slot or a sibling's @c next —
 *  giving O(1) unlink from a bare handle pointer without walking the chain.
 */
typedef struct duct_hash_handle {
    struct duct_hash_handle  *next,
                            **pprev;
} duct_hash_handle_t;

/** @brief Recover the owning @p type from its @p member handle pointer. */
#define duct_hash_entry(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))

/** @brief Insert handle at intrusive hash bucket head. */
#define duct_hash_insert(head_ptr, h) do {  \
    (h)->next = *(head_ptr);                \
    (h)->pprev = (head_ptr);                \
    if (*(head_ptr))                        \
        (*(head_ptr))->pprev = &(h)->next;  \
    *(head_ptr) = (h);                      \
} while (0)

/** @brief Remove handle from intrusive hash chain. No-op when not linked. */
#define duct_hash_remove(h) do {            \
    if (!(h)->pprev)                        \
        break;                              \
    *(h)->pprev = (h)->next;                \
    if ((h)->next)                          \
        (h)->next->pprev = (h)->pprev;      \
    (h)->next = nullptr;                    \
    (h)->pprev = nullptr;                   \
} while (0)

/** @brief Generate typed hash-bucket find + insert wrappers over @p
 *  owner_type's own @p buckets_member array — @c find_fn(owner, key) /
 *  @c insert_fn(owner, key, h). Neither @p buckets_member nor @p mask (a
 *  compile-time constant folded straight into the generated code) ever
 *  appears at the call site: every caller outside this declaration passes
 *  the owning object directly. The handle member is fixed to @c hh — every
 *  hashable type embeds its @ref duct_hash_handle_t under that name.
 *
 *  @c find_fn walks the bucket for @p key, returning the owning @p type
 *  (recovered via its @c hh member) for the first node where @p match_expr
 *  is true, or nullptr. @p match_expr sees the candidate as @c node and the
 *  sought value as @c key — written as an ordinary loop-body test: plain
 *  @c == for a plain field, an explicit @c duct_atomic_load for an atomic
 *  one.
 */
#define DUCT_HASH_DECLARE(find_fn, insert_fn, owner_type, buckets_member,   \
                           type, key_type, match_expr, mask)                \
static inline type *find_fn(const owner_type *o, key_type key)              \
{                                                                           \
    for (auto h = (o->buckets_member)[duct_hash_idx((uint64_t)key, (mask))];\
         h; h = h->next) {                                                  \
        auto node = duct_hash_entry(h, type, hh);                           \
        if (match_expr)                                                     \
            return node;                                                    \
    }                                                                       \
    return nullptr;                                                         \
}                                                                           \
static inline void insert_fn(owner_type *o, key_type key,                   \
                              duct_hash_handle_t *h)                        \
{                                                                           \
    duct_hash_insert(                                                       \
        &(o->buckets_member)[duct_hash_idx((uint64_t)key, (mask))], h);     \
}

#ifdef __cplusplus
}
#endif

#endif /* DUCT_HASH_H */
