/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_join.c
 *  @brief The join index, the lead a dial carries and the check io runs on it.
 *
 *  Contracts live on the declarations in @c duct_join.h. What is here is the
 *  index's shape and its ordering: a slot holds a session handle word, a slot
 *  whose word no longer resolves attached is free, and only a session's own
 *  re-key takes its entry out. A session's key, name and protocol are written
 *  before the CAS that lists it, and io reads them past an acquire load of the
 *  slot. The array is session pool storage, reached through
 *  @ref duct_session_join_index.
 */

#include "duct_join.h"
#include "duct_crypto.h"
#include "duct_dgram_lead.h"
#include "duct_hash.h"

#include <string.h>

/** @brief Bytes @c derive answers for a session: its key, then its name. */
static constexpr size_t   s_okm_size    = duct_siphash_key_size + 2u;
/** @brief Lead bytes the MAC covers: name, counter and conn id. */
static constexpr size_t   s_mac_input   = 7u;
/** @brief Slots a name's probe window spans. */
static constexpr unsigned s_index_probe = 16u;
/** @brief Lead counters a window remembers below its top. */
static constexpr unsigned s_window_bits = 32u;

static_assert(s_mac_input + sizeof(uint64_t) == duct_join_lead_size,
    "a lead is its MAC input and the 8-byte MAC over it");

/** @brief Read @p n big-endian bytes at @p p. */
static uint32_t s_get_be(const uint8_t *p, unsigned n)
{
    uint32_t v = 0u;
    for (unsigned i = 0u; i < n; ++i)
        v = (v << 8u) | p[i];
    return v;
}

/** @brief Write the low @p n bytes of @p v big-endian at @p p. */
static void s_put_be(uint8_t *p, uint32_t v, unsigned n)
{
    for (unsigned i = n; i > 0u; --i) {
        p[i - 1u] = (uint8_t)v;
        v >>= 8u;
    }
}

/** @brief Slot @p i of @p name's probe window in @p index. */
static duct_handle_t _Atomic *s_slot(duct_handle_t _Atomic *index, uint16_t name, unsigned i)
{
    return &index[((unsigned)name + i) % duct_session_join_index_slots];
}

/** @brief List @p s at the first free slot of its name's window.
 *  @return false with every slot of the window holding a live session. */
static bool s_index_put(duct_session_t *s)
{
    auto index = duct_session_join_index();
    auto word = duct_session_handle_from_live(s).word;
    for (unsigned i = 0u; i < s_index_probe; ++i) {
        auto slot = s_slot(index, s->join.name, i);
        auto held = duct_atomic_load(slot, acquire);
        bool live = held != handle_null
                 && duct_session_attached_by_handle((duct_session_handle_t){ .word = held });
        if (live)
            continue;
        if (duct_atomic_cas(strong, slot, &held, word, acq_rel, relaxed))
            return true;
    }
    return false;
}

/** @brief Take @p s out of its current name's window, ahead of a re-key. */
static void s_index_drop(const duct_session_t *s)
{
    auto index = duct_session_join_index();
    auto word = duct_session_handle_from_live(s).word;
    for (unsigned i = 0u; i < s_index_probe; ++i) {
        auto held = word;
        if (duct_atomic_cas(strong, s_slot(index, s->join.name, i), &held, handle_null,
                            acq_rel, relaxed))
            return;
    }
}

bool duct_join_derive(const duct_seal_engine_vtbl_t *vt, duct_seal_engine_t *engine,
                      uint8_t key[duct_siphash_key_size], uint8_t name[2])
{
    duct_secret_array(uint8_t, okm, s_okm_size);
    bool keyed = vt->derive && vt->derive(engine, "duct join", okm, sizeof okm);
    if (!keyed)
        return false;
    memcpy(key, okm, duct_siphash_key_size);
    memcpy(name, okm + duct_siphash_key_size, 2u);
    return true;
}

void duct_join_forget(duct_session_t *s)
{
    duct_del(s->join.id);
    s->join.id = nullptr;
}

bool duct_join_install(duct_session_t *s, duct_view_u8 identity,
                       const duct_seal_engine_vtbl_t *vt, duct_seal_engine_t *engine)
{
    if (s->join.sent != 0u) {
        s_index_drop(s);
        s->join.sent = 0u;
    }
    duct_join_forget(s);
    s->join.id = duct_new_secret(uint8_t, identity.size);
    duct_do_if(!s->join.id, return false);
    memcpy(duct_at(s->join.id), identity.data, identity.size);
    uint8_t name[2];
    if (!duct_join_derive(vt, engine, s->join.key, name))
        return true;
    s->join.name = (uint16_t)s_get_be(name, 2u);
    s->join.proto = s->proto;
    s->join.sent = 1u;
    duct_atomic_store(&s->join.window, 0u, relaxed);
    duct_discard s_index_put(s);
    return true;
}

bool duct_join_same_peer(const duct_session_t *s, duct_view_u8 identity)
{
    auto id = s->join.id;
    return id && identity.size == duct_len(id)
        && duct_ct_equal(identity.data, duct_at(id), identity.size);
}

/** @brief Key covering a lead's bytes on @p proto's wire.
 *  All zero for a protocol without one. */
static const uint8_t *s_cover_key(const duct_proto_t *proto)
{
    static const uint8_t none[duct_siphash_key_size] = {};
    return proto && proto->cfg.wire ? proto->cfg.wire->cover_key : none;
}

bool duct_join_lead(duct_session_t *s, duct_conn_id_t conn_id,
                    uint8_t out[duct_join_lead_size])
{
    bool usable = s->join.sent != 0u && s->join.sent != UINT32_MAX
               && conn_id < duct_session_max_legs;
    duct_do_if(!usable, return false);
    s_put_be(out, s->join.name, 2u);
    s_put_be(out + 2u, s->join.sent++, 4u);
    out[6] = (uint8_t)conn_id;
    uint64_t mac = duct_siphash24(s->join.key, out, s_mac_input);
    duct_siphash_cover(out, s_mac_input, s_cover_key(s->join.proto), mac);
    duct_sip_put_le64(out + s_mac_input, sizeof mac, mac);
    return true;
}

/** @brief Spend @p ctr in @p window, once.
 *  A counter past the top moves the top, one within @c s_window_bits below it
 *  takes its bit, and an older or a seen one is refused. A CAS loop, since the
 *  io threads of several listeners check leads of one session. */
static bool s_window_admit(uint64_t _Atomic *window, uint32_t ctr)
{
    uint64_t cur = duct_atomic_load(window, acquire);
    for (;;) {
        uint32_t top = (uint32_t)(cur >> 32u),
                 seen = (uint32_t)cur;
        uint64_t next;
        if (ctr > top) {
            uint32_t shift = ctr - top;
            uint32_t bits = shift >= s_window_bits ? 1u : (seen << shift) | 1u;
            next = ((uint64_t)ctr << 32u) | bits;
        } else {
            uint32_t back = top - ctr;
            if (back >= s_window_bits || (seen & (UINT32_C(1) << back)))
                return false;
            next = cur | (UINT32_C(1) << back);
        }
        if (duct_atomic_cas(strong, window, &cur, next, acq_rel, acquire))
            return true;
    }
}

bool duct_join_match(const uint8_t lead[duct_join_lead_size],
                     const duct_proto_t *const *protos, unsigned n_protos,
                     duct_session_handle_t *tok, duct_conn_id_t *conn_id,
                     const duct_proto_t **proto)
{
    auto index = duct_session_join_index();
    uint64_t mac = duct_sip_le64(lead + s_mac_input, sizeof mac);
    for (unsigned k = 0u; k < n_protos; ++k) {
        /* Each protocol's wire names its own cover key, so the bytes come off
         * once per candidate. */
        uint8_t plain[s_mac_input];
        memcpy(plain, lead, sizeof plain);
        duct_siphash_cover(plain, sizeof plain, s_cover_key(protos[k]), mac);
        auto name = (uint16_t)s_get_be(plain, 2u);
        uint32_t ctr = s_get_be(plain + 2u, 4u);
        duct_conn_id_t cid = plain[6];
        if (ctr == 0u || cid >= duct_session_max_legs)
            continue;
        for (unsigned i = 0u; i < s_index_probe; ++i) {
            auto h = (duct_session_handle_t){ .word = duct_atomic_load(s_slot(index, name, i), acquire) };
            auto s = h.word != handle_null ? duct_session_attached_by_handle(h) : nullptr;
            if (!s || s->join.name != name || s->join.proto != protos[k]
                || duct_siphash24(s->join.key, plain, s_mac_input) != mac)
                continue;
            bool fresh = s_window_admit(&s->join.window, ctr)
                      && duct_atomic_load(&s->generation, acquire) == h.gen;
            if (!fresh)
                return false;
            *tok = h;
            *conn_id = cid;
            *proto = protos[k];
            return true;
        }
    }
    return false;
}

duct_session_handle_t duct_join_dgram_match(const uint8_t *dgram, size_t len,
                                            const duct_proto_t *proto)
{
    size_t pdu_off = proto->cfg.wire->rx_prefix_len;
    duct_session_handle_t none = { .word = handle_null };
    if (!duct_dgram_lead_fits(pdu_off, len))
        return none;
    auto index = duct_session_join_index();
    uint64_t mac = duct_sip_le64(dgram + 2u, sizeof mac);
    uint8_t bytes[2] = { dgram[0], dgram[1] };
    duct_dgram_lead_cover(bytes, s_cover_key(proto), mac);
    auto name = (uint16_t)s_get_be(bytes, 2u);
    for (unsigned i = 0u; i < s_index_probe; ++i) {
        auto h = (duct_session_handle_t){ .word = duct_atomic_load(s_slot(index, name, i), acquire) };
        auto s = h.word != handle_null ? duct_session_attached_by_handle(h) : nullptr;
        if (!s || s->join.name != name || s->join.proto != proto
            || duct_dgram_lead_mac(s->join.key, bytes, dgram + pdu_off) != mac)
            continue;
        /* The key and name were read from a slot the pool may be recycling; the
         * generation read after the MAC refuses a handle that no longer names it. */
        return duct_atomic_load(&s->generation, acquire) == h.gen ? h : none;
    }
    return none;
}
