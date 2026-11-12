/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file join_lead_test.c
 *  @brief Join lead contract, driven without a socket.
 *
 *  SipHash-2-4 against the reference vectors for an empty and a 15-byte
 *  message. Then stream leads over pool sessions keyed through a stand-in derive
 *  that sets their names, two of them sharing one: a lead resolves once to its
 *  session, conn id and protocol; every single-byte change is refused; the name
 *  crosses the wire covered, neither plain nor the same in every lead; counters
 *  out of order within the window are each taken once, and one 32 below the top
 *  is refused; the two same-named sessions resolve their own; a listener not
 *  serving a session's protocol neither takes its lead nor spends it; a released
 *  session takes none.
 *
 *  Then the identity: the same-peer rule tells the session's own from another
 *  and from a prefix of it, an engine without derive leaves a session building
 *  no lead, and a 200-byte identity is held whole: it matches itself and nothing
 *  that differs in its last bit or in its length.
 *
 *  Then a re-key: a lead under the replaced key is refused, one under the new
 *  key resolves, and another session listed under the old name keeps its
 *  entry.
 *
 *  Last, a datagram's lead, behind a prefix as wide as the lead and behind a
 *  wider one. It resolves every time it is asked, to the session of the key and
 *  protocol it was led under, and to no session under another cover key. A byte
 *  changed in the lead or in the 16 PDU bytes it covers is refused; a byte in the
 *  prefix behind the lead or past those 16 is not held against it. The PDU read
 *  from another offset than the lead was written for, a datagram one byte short
 *  of carrying a lead and a prefix narrower than the lead are refused, and
 *  writing a lead into the last two leaves the datagram as it was.
 */

#include "duct.h"
#include "duct_dgram_lead.h"
#include "duct_hash.h"
#include "duct_join.h"
#include "duct_session.h"

#include <stdio.h>
#include <string.h>

/** @brief The stand-in engine's state: what its derive hands out. */
typedef struct {
    uint8_t  key_seed; /**< Seeds the key bytes. */
    uint16_t name;     /**< The session's name, the last two bytes derived. */
} fake_engine_t;

/** @brief The stand-in derive: for the label "duct join", a key from
 *  @c key_seed and the name behind it, filling @p len bytes.
 *  @return false for any other label or fewer than two bytes. */
static bool s_fake_derive(duct_seal_engine_t *e, const char *label, void *out, size_t len)
{
    auto f = (const fake_engine_t *)e;
    auto bytes = (uint8_t *)out;
    if (strcmp(label, "duct join") != 0 || len < 2u)
        return false;
    for (size_t i = 0u; i + 2u < len; ++i)
        bytes[i] = (uint8_t)(f->key_seed ^ (uint8_t)(i * 29u));
    bytes[len - 2u] = (uint8_t)(f->name >> 8u);
    bytes[len - 1u] = (uint8_t)f->name;
    return true;
}

/** @brief Engine vtbls with the stand-in derive and without one. */
static const duct_seal_engine_vtbl_t s_vt      = { .derive = s_fake_derive };
static const duct_seal_engine_vtbl_t s_vt_none = {};

/** @brief The two protocols' wires, each under a cover key of its own. */
static duct_wire_t s_wire_a = { .cover_key = { 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
                                               0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xa0 } };
static duct_wire_t s_wire_b = { .cover_key = { 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
                                               0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xb0 } };
static const duct_proto_t s_proto_a = { .cfg = { .wire = &s_wire_a } };
static const duct_proto_t s_proto_b = { .cfg = { .wire = &s_wire_b } };

/** @brief SipHash-2-4 against the reference vectors.
 *  @return nullptr when both held, else what failed. */
static const char *s_siphash(void)
{
    uint8_t key[duct_siphash_key_size], msg[15];
    for (unsigned i = 0u; i < sizeof key; ++i)
        key[i] = (uint8_t)i;
    for (unsigned i = 0u; i < sizeof msg; ++i)
        msg[i] = (uint8_t)i;
    if (duct_siphash24(key, msg, 0u) != UINT64_C(0x726fdb47dd0e0e31))
        return "SipHash-2-4 of the empty message disagrees with the reference";
    if (duct_siphash24(key, msg, sizeof msg) != UINT64_C(0xa129ca6149be45e5))
        return "SipHash-2-4 of 15 bytes disagrees with the reference";
    return nullptr;
}

/** @brief Acquire a session of @p proto and key it through the stand-in derive
 *  over @p engine, its 32-byte identity @p id_byte throughout.
 *  @return the session, or nullptr when the pool is exhausted. */
static duct_session_t *s_keyed(const fake_engine_t *engine, const void *proto,
                               uint8_t id_byte)
{
    auto s = duct_session_acquire();
    if (!s)
        return nullptr;
    s->proto = (const duct_proto_t *)proto;
    uint8_t id[32];
    memset(id, id_byte, sizeof id);
    duct_join_install(s, (duct_view_u8){ .data = id, .size = sizeof id }, &s_vt,
                      (duct_seal_engine_t *)engine);
    return s;
}

/** @brief The protocols a listener serves, in the order a match tries them. */
static const duct_proto_t *const s_served[] = {
    (const duct_proto_t *)&s_proto_a, (const duct_proto_t *)&s_proto_b,
};

/** @brief True when @p lead, offered by a listener serving both protocols,
 *  resolves to session @p s at conn id @p want_cid under its protocol. */
static bool s_resolves(const uint8_t *lead, const duct_session_t *s,
                       duct_conn_id_t want_cid)
{
    duct_session_handle_t tok = {};
    duct_conn_id_t cid = 0u;
    const duct_proto_t *proto = nullptr;
    return duct_join_match(lead, s_served, 2u, &tok, &cid, &proto)
        && tok.word == duct_session_handle_from_live(s).word
        && cid == want_cid && proto == s->proto;
}

/** @brief True when a listener serving the first @p n_served protocols takes
 *  @p lead for no session. */
static bool s_refused_by(const uint8_t *lead, unsigned n_served)
{
    duct_session_handle_t tok = {};
    duct_conn_id_t cid = 0u;
    const duct_proto_t *proto = nullptr;
    return !duct_join_match(lead, s_served, n_served, &tok, &cid, &proto);
}

/** @brief True when a listener serving both protocols takes @p lead for no
 *  session. */
static bool s_refused(const uint8_t *lead)
{
    return s_refused_by(lead, 2u);
}

/** @brief Stream leads over two same-named sessions, then the identity rule.
 *  @return nullptr when each held, else what failed. */
static const char *s_leads(void)
{
    const fake_engine_t ea = { .key_seed = 0x5au, .name = 0x1234u },
                        eb = { .key_seed = 0xa5u, .name = 0x1234u };
    auto a = s_keyed(&ea, &s_proto_a, 0x11u);
    auto b = s_keyed(&eb, &s_proto_b, 0x22u);
    const char *err = nullptr;
    uint8_t lead[duct_join_lead_size], first[duct_join_lead_size],
            again[duct_join_lead_size];
    if (!a || !b) {
        err = "session acquire failed";
        goto done;
    }
    if (!duct_join_lead(a, 3u, lead) || !s_resolves(lead, a, 3u)) {
        err = "a fresh lead did not resolve to its session and conn id";
        goto done;
    }
    if (!s_refused(lead)) {
        err = "a lead verified twice";
        goto done;
    }
    if (!duct_join_lead(b, 5u, lead) || !s_resolves(lead, b, 5u)) {
        err = "a second session under the same name did not resolve its own lead";
        goto done;
    }
    if (!duct_join_lead(b, 5u, lead) || !s_refused_by(lead, 1u) || !s_resolves(lead, b, 5u)) {
        err = "a listener not serving the session's protocol took or spent its lead";
        goto done;
    }
    for (unsigned at = 0u; at < duct_join_lead_size; ++at) {
        if (!duct_join_lead(a, 4u, lead)) {
            err = "lead build failed";
            goto done;
        }
        lead[at] ^= 0x40u;
        if (!s_refused(lead)) {
            err = "a lead with one byte changed verified";
            goto done;
        }
    }
    {
        unsigned plain_name = 0u,
                 distinct = 0u;
        uint16_t seen[8];
        for (unsigned i = 0u; i < 8u; ++i) {
            if (!duct_join_lead(a, 4u, lead)) {
                err = "lead build failed";
                goto done;
            }
            auto on_wire = (uint16_t)((lead[0] << 8u) | lead[1]);
            plain_name += on_wire == 0x1234u;
            bool known = false;
            for (unsigned k = 0u; k < distinct; ++k)
                known = known || seen[k] == on_wire;
            if (!known)
                seen[distinct++] = on_wire;
        }
        if (plain_name > 1u || distinct < 2u) {
            err = "a lead's name crossed the wire plain or the same in every lead";
            goto done;
        }
    }
    if (!duct_join_lead(a, 6u, first) || !duct_join_lead(a, 6u, lead)
        || !duct_join_lead(a, 6u, again)
        || !s_resolves(again, a, 6u) || !s_resolves(first, a, 6u)
        || !s_resolves(lead, a, 6u) || !s_refused(first)) {
        err = "leads out of order within the window were not each taken once";
        goto done;
    }
    if (!duct_join_lead(a, 7u, first)) {
        err = "lead build failed";
        goto done;
    }
    for (unsigned i = 0u; i < 32u; ++i) {
        if (!duct_join_lead(a, 7u, lead)) {
            err = "lead build failed";
            goto done;
        }
    }
    if (!s_resolves(lead, a, 7u) || !s_refused(first)) {
        err = "a lead older than the window verified";
        goto done;
    }
    if (duct_join_lead(a, duct_session_max_legs, lead)) {
        err = "a lead was built for a conn id past the session's legs";
        goto done;
    }
    uint8_t own[32], other[32], big[200], big_off[200];
    memset(own, 0x11u, sizeof own);
    memset(other, 0x22u, sizeof other);
    memset(big, 0x11u, sizeof big);
    memcpy(big_off, big, sizeof big);
    big_off[sizeof big_off - 1u] ^= 1u;
    if (!duct_join_same_peer(a, (duct_view_u8){ .data = own, .size = sizeof own })
        || duct_join_same_peer(a, (duct_view_u8){ .data = other, .size = sizeof other })
        || duct_join_same_peer(a, (duct_view_u8){ .data = own, .size = 31u })) {
        err = "the same-peer rule did not tell the session's own identity apart";
        goto done;
    }
    if (!duct_join_lead(a, 2u, lead)) {
        err = "lead build failed";
        goto done;
    }
    duct_session_release(a);
    a = nullptr;
    if (!s_refused(lead)) {
        err = "a released session still took a lead";
        goto done;
    }
    auto plain = duct_session_acquire();
    if (!plain) {
        err = "session acquire failed";
        goto done;
    }
    duct_join_install(plain, (duct_view_u8){ .data = big, .size = sizeof big }, &s_vt_none,
                      (duct_seal_engine_t *)&ea);
    bool unkeyed = !duct_join_lead(plain, 1u, lead);
    bool long_kept = duct_join_same_peer(plain, (duct_view_u8){ .data = big, .size = sizeof big })
                  && !duct_join_same_peer(plain, (duct_view_u8){ .data = big, .size = sizeof big - 1u })
                  && !duct_join_same_peer(plain, (duct_view_u8){ .data = big_off, .size = sizeof big_off });
    duct_session_release(plain);
    if (!unkeyed)
        err = "an engine without derive still built a lead";
    else if (!long_kept)
        err = "a 200-byte identity was not held whole by the same-peer rule";

done:
    if (a)
        duct_session_release(a);
    if (b)
        duct_session_release(b);
    return err;
}

/** @brief Re-key a session while another sits under the name it leaves.
 *  @return nullptr when each held, else what failed. */
static const char *s_rekey(void)
{
    const fake_engine_t first = { .key_seed = 0x33u, .name = 0x4444u },
                        fresh = { .key_seed = 0xccu, .name = 0x5555u },
                        other = { .key_seed = 0x66u, .name = 0x4444u };
    auto s = s_keyed(&first, &s_proto_a, 0x11u);
    auto t = s_keyed(&other, &s_proto_b, 0x22u);
    const char *err = nullptr;
    uint8_t stale[duct_join_lead_size], lead[duct_join_lead_size],
            kept[duct_join_lead_size], id[32];
    if (!s || !t) {
        err = "session acquire failed";
        goto done;
    }
    if (!duct_join_lead(s, 2u, stale) || !duct_join_lead(t, 3u, kept)) {
        err = "lead build failed";
        goto done;
    }
    memset(id, 0x11u, sizeof id);
    duct_join_install(s, (duct_view_u8){ .data = id, .size = sizeof id }, &s_vt,
                      (duct_seal_engine_t *)&fresh);
    if (!s_refused(stale)) {
        err = "a lead under the replaced key still joined";
        goto done;
    }
    if (!duct_join_lead(s, 2u, lead) || !s_resolves(lead, s, 2u)) {
        err = "a lead under the replacing key did not resolve";
        goto done;
    }
    if (!s_resolves(kept, t, 3u))
        err = "replacing one session's key dropped another's entry";

done:
    if (s)
        duct_session_release(s);
    if (t)
        duct_session_release(t);
    return err;
}

/** @brief The cover key the datagrams are led under, and one that differs from
 *  it in the last byte. */
static const uint8_t s_cover[duct_siphash_key_size] = {
    0x3c, 0x91, 0x07, 0xe4, 0x58, 0xba, 0x2d, 0x6f, 0x10, 0xc3, 0x85, 0x4a, 0xf7, 0x22, 0x9e, 0x61,
};
static const uint8_t s_cover_other[duct_siphash_key_size] = {
    0x3c, 0x91, 0x07, 0xe4, 0x58, 0xba, 0x2d, 0x6f, 0x10, 0xc3, 0x85, 0x4a, 0xf7, 0x22, 0x9e, 0x62,
};

/** @brief Give both wires a receive prefix of @p off bytes and @p cover as their
 *  cover key. */
static void s_wires_set(size_t off, const uint8_t cover[duct_siphash_key_size])
{
    duct_wire_t *const wires[] = { &s_wire_a, &s_wire_b };
    for (unsigned i = 0u; i < 2u; ++i) {
        wires[i]->rx_prefix_len = (uint8_t)off;
        memcpy(wires[i]->cover_key, cover, sizeof wires[i]->cover_key);
    }
}

/** @brief True when the @p len bytes of @p dgram, their PDU @p off bytes in,
 *  resolve to session @p s with the wires' cover key @p cover. */
static bool s_dgram_resolves_under(const uint8_t *dgram, size_t len, size_t off,
                                   const duct_session_t *s,
                                   const uint8_t cover[duct_siphash_key_size])
{
    s_wires_set(off, cover);
    return duct_join_dgram_match(dgram, len, s->proto).word
        == duct_session_handle_from_live(s).word;
}

/** @brief True when @p dgram resolves to session @p s under the cover key it
 *  was led with. */
static bool s_dgram_resolves(const uint8_t *dgram, size_t len, size_t off,
                             const duct_session_t *s)
{
    return s_dgram_resolves_under(dgram, len, off, s, s_cover);
}

/** @brief True when @p dgram resolves to no session of @p proto. */
static bool s_dgram_refused(const uint8_t *dgram, size_t len, size_t off, const void *proto)
{
    s_wires_set(off, s_cover);
    return duct_join_dgram_match(dgram, len, (const duct_proto_t *)proto).word == handle_null;
}

/** @brief Build a datagram of @p len bytes led under the key of engine @p e.
 *  The PDU starts @p off bytes in and holds a byte pattern set by @p seed; the
 *  prefix ahead of it is 0x77 apart from the lead. */
static void s_dgram_make(uint8_t *dgram, size_t off, size_t len, const fake_engine_t *e,
                         uint8_t seed)
{
    uint8_t key[duct_siphash_key_size], name[2];
    duct_discard duct_join_derive(&s_vt, (duct_seal_engine_t *)e, key, name);
    memset(dgram, 0x77u, off);
    for (size_t i = off; i < len; ++i)
        dgram[i] = (uint8_t)(seed + i * 31u);
    duct_dgram_lead_fill(dgram, off, len, key, s_cover, name);
}

/** @brief Datagram leads of two same-named sessions, behind a prefix of @p off
 *  bytes.
 *  @return nullptr when each held, else what failed. */
static const char *s_dgram_leads(size_t off)
{
    const fake_engine_t ea = { .key_seed = 0x5au, .name = 0x1234u },
                        eb = { .key_seed = 0xa5u, .name = 0x1234u };
    auto a = s_keyed(&ea, &s_proto_a, 0x11u);
    auto b = s_keyed(&eb, &s_proto_b, 0x22u);
    const char *err = nullptr;
    size_t min = off + duct_dgram_lead_bind,
           len = min + 40u;
    uint8_t d[96], e[96], key[duct_siphash_key_size], name[2], fresh[64];
    if (!a || !b || len > sizeof d || min > sizeof fresh) {
        err = "session acquire failed, or the test buffers are too small for this prefix";
        goto done;
    }
    if (!duct_join_derive(&s_vt, (duct_seal_engine_t *)&ea, key, name)
        || memcmp(key, a->join.key, sizeof key) != 0 || name[0] != 0x12u || name[1] != 0x34u
        || duct_join_derive(&s_vt_none, (duct_seal_engine_t *)&ea, key, name)) {
        err = "the derived key is not the one a session installs, or an engine without derive gave one";
        goto done;
    }
    s_dgram_make(d, off, len, &ea, 1u);
    if (!s_dgram_resolves(d, len, off, a) || !s_dgram_resolves(d, len, off, a)) {
        err = "a datagram led under its session's key did not resolve every time it was asked";
        goto done;
    }
    s_dgram_make(e, off, len, &eb, 1u);
    if (!s_dgram_resolves(e, len, off, b) || !s_dgram_resolves(d, len, off, a)) {
        err = "the two same-named sessions did not each resolve their own datagram";
        goto done;
    }
    if (!s_dgram_refused(e, len, off, &s_proto_a) || !s_dgram_refused(d, len, off, &s_proto_b)) {
        err = "a listener serving one of the sessions took a datagram of the other";
        goto done;
    }
    s_dgram_make(e, off, len, &ea, 2u);
    if (memcmp(d, e, duct_seal_lead_size) == 0) {
        err = "two datagrams of one session led with the same bytes";
        goto done;
    }
    if (s_dgram_resolves_under(d, len, off, a, s_cover_other)
        || s_dgram_resolves_under(e, len, off, a, s_cover_other)) {
        err = "a datagram resolved under another cover key than the one it was led under";
        goto done;
    }
    {
        unsigned plain = 0u, distinct = 0u;
        uint16_t seen[8];
        for (uint8_t seed = 1u; seed <= 8u; ++seed) {
            s_dgram_make(fresh, off, min, &ea, seed);
            uint16_t on_wire = (uint16_t)((fresh[0] << 8u) | fresh[1]);
            plain += on_wire == 0x1234u;
            bool known = false;
            for (unsigned i = 0u; i < distinct; ++i)
                known = known || seen[i] == on_wire;
            if (!known)
                seen[distinct++] = on_wire;
        }
        if (plain > 1u || distinct < 2u) {
            err = "the session's name crossed the wire plain or the same in every datagram";
            goto done;
        }
    }
    for (size_t at = 0u; at < min; ++at) {
        bool covered = at < duct_seal_lead_size || at >= off;
        memcpy(e, d, len);
        e[at] ^= 0x40u;
        if (s_dgram_resolves(e, len, off, a) == covered) {
            err = covered ? "a datagram with a byte of its lead or of the 16 bytes it covers changed verified"
                          : "a byte of the prefix behind the lead was held against the datagram";
            goto done;
        }
    }
    memcpy(e, d, len);
    e[min] ^= 0x40u;
    e[len - 1u] ^= 0x40u;
    if (!s_dgram_resolves(e, len, off, a)) {
        err = "a byte past the 16 the lead covers was held against the datagram";
        goto done;
    }
    if (!s_dgram_refused(d, len, off + 4u, a->proto)) {
        err = "a datagram resolved with its PDU taken from another offset than it was led at";
        goto done;
    }
    s_dgram_make(fresh, off, min, &ea, 3u);
    if (!s_dgram_resolves(fresh, min, off, a) || !s_dgram_refused(fresh, min - 1u, off, a->proto)
        || !s_dgram_refused(d, len, duct_seal_lead_size - 1u, a->proto)) {
        err = "the shortest datagram that carries a lead was refused, one byte short of it or a prefix narrower than the lead taken";
        goto done;
    }
    memset(e, 0xeeu, sizeof e);
    duct_dgram_lead_fill(e, off, min - 1u, key, s_cover, name);
    duct_dgram_lead_fill(e, duct_seal_lead_size - 1u, len, key, s_cover, name);
    for (size_t i = 0u; i < sizeof e; ++i)
        if (e[i] != 0xeeu) {
            err = "a datagram too short to carry a lead, or behind a prefix narrower than it, was written to";
            goto done;
        }
    duct_session_release(a);
    a = nullptr;
    if (!s_dgram_refused(d, len, off, &s_proto_a))
        err = "a released session still took a datagram";

done:
    if (a)
        duct_session_release(a);
    if (b)
        duct_session_release(b);
    return err;
}

/** @brief The public lead pair: build through duct_session_lead_build, resolve
 *  through duct_session_lead_resolve over the same served pair, spend once.
 *  @return nullptr when each held, else what failed. */
static const char *s_public_pair(void)
{
    const fake_engine_t ea = { .key_seed = 0x3cu, .name = 0x4321u };
    auto a = s_keyed(&ea, &s_proto_a, 0x77u);
    if (!a)
        return "session acquire failed";
    uint8_t lead[duct_session_lead_size];
    duct_handle_t tok = {};
    duct_conn_id_t cid = 0u;
    if (!duct_session_lead_build(a, 2u, lead))
        return "the public build refused a keyed session";
    if (!duct_session_lead_resolve(lead, s_served, 2u, &tok, &cid)
        || tok != duct_session_handle_from_live(a).word || cid != 2u)
        return "the public resolve did not answer the public build's session and id";
    if (duct_session_lead_resolve(lead, s_served, 2u, &tok, &cid))
        return "a publicly built lead verified twice";
    duct_session_release(a);
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto err = s_siphash();
    if (!err)
        err = s_leads();
    if (!err)
        err = s_rekey();
    if (!err)
        err = s_public_pair();
    if (!err)
        err = s_dgram_leads(duct_seal_lead_size);
    if (!err)
        err = s_dgram_leads(duct_seal_lead_size + 4u);
    if (err) {
        fprintf(stderr, "join_lead: %s\n", err);
        return 1;
    }
    printf("join_lead: OK (SipHash-2-4 reference vectors, a lead resolves once to its "
           "session, forged bytes and replays refused, window order, same-peer rule, "
           "the public build-and-resolve pair, a datagram's own lead behind a prefix "
           "as wide as the lead and a wider one)\n");
    return 0;
}
