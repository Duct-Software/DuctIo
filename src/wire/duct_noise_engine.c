/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_noise_engine.c
 *  @brief Noise_IKpsk2 and Noise_XKpsk3 as a sealed-wire crypto engine.
 *
 *  One @ref duct_seal_engine_vtbl_t over the primitives in the internal Noise
 *  core, meeting the sealed-wire seam: framing with a 2-byte big-endian length
 *  this file writes itself, a first exchange of two messages under IKpsk2 or
 *  three under XKpsk3 driven by @c start and @c unseal, then transport AEAD both
 *  ways.
 *
 *  Message 1's payload leads with the config's hello, then zero padding of a
 *  random length. A responder passes the payload whole, with the peer's key, to
 *  @c peer_psk for the PSK that peer's message 2 mixes under IKpsk2 and its
 *  message 3 under XKpsk3, and names the peer by the key then the config's hello
 *  taken from the payload's head, zero-filled where the payload runs short — a
 *  peer of an older build may carry a shorter hello. Under XKpsk3 @c hello_ok
 *  sees the payload whole first and refuses it ahead of any answer; where no
 *  callback stands, a payload shorter than the config's hello is refused.
 *
 *  @c keys is the state every path branches on. Under IKpsk2 an initiator's
 *  exchange ends in @c key_settled, a responder's in @c key_confirming, which
 *  names no peer until a PDU authenticates under the split keys: message 1
 *  carries no freshness, and a recorded one still draws message 2. Under XKpsk3
 *  both ends settle at their last message, message 3 mixing the responder's
 *  ephemeral key. @c rekey then runs an IKpsk2 exchange over the keys still
 *  carrying traffic, so @c hs is live during a rekey as much as before an IKpsk2
 *  first split.
 *
 *  An XKpsk3 exchange lives in a handshake context, @c hc, made with the
 *  instance. On a datagram wire it outlives the split. A repeat of the peer's
 *  message, told by its length and closing tag, draws this end's last message
 *  again, and a responder that has read message 3 takes one without a word. An
 *  initiator with @c hs_rto_ms set retransmits automatically, from a timer
 *  @c start arms and @c retry re-arms; both draw on @c s_hs_tries. The first
 *  PDU of the peer that authenticates frees the context; on a stream it ends at
 *  the split.
 */

#include "duct_noise_internal.h"
#include "duct_core.h"
#include "duct_crypto.h"
#include "duct_xopening.h"

#include <string.h>

static constexpr size_t s_len_prefix = 2u;
static constexpr size_t s_pdu_ct_max = 16384u;
static constexpr size_t s_pdu_overhead = duct_noise_counter_size + duct_noise_tag_size;
static constexpr size_t s_pdu_overhead_compact = duct_noise_counter_compact_size + duct_noise_tag_size;
static constexpr size_t s_engine_hs_budget = 512u;
/** @brief Cap on resends of a handshake message, counted from the start of an
 *  exchange and again from its split. */
static constexpr uint8_t s_hs_tries = 4u;

/** @brief Counter room kept below the sealing ceiling for an offer to land in.
 *  A 100 Gbit path carrying nothing but minimum-size PDUs moves under 2^29 of
 *  them a second, so this is seconds of line-rate traffic — an exchange that
 *  loses its message 1 still has room for @ref s_rekey_fail_cap retries. */
static constexpr uint64_t s_offer_slack       = UINT64_C(1) << 32;
/** @brief Send counter at which this instance offers a fresh key set.
 *  The lifetime-driven @c rekey normally arrives long first; this stands
 *  between an instance whose lifetime is switched off and a sealer that has
 *  stopped answering. */
static constexpr uint64_t s_offer_at_messages =
    duct_noise_seal_counter_max - s_offer_slack;
/** @brief Rekey-handshake reads an instance may fail before it stops trying, per
 *  key lifetime: a responder's message 1, an initiator's message 2.
 *  Each read costs a Diffie-Hellman before anything can say whether it is
 *  genuine, so bytes that cost a sender nothing buy work here; this bounds that
 *  work. */
static constexpr uint8_t  s_rekey_fail_cap    = 4u;

static_assert(s_offer_slack < duct_noise_seal_counter_max,
    "the slack is subtracted from the ceiling and must not wrap past it");
static_assert(s_rekey_fail_cap < UINT8_MAX,
    "the budget has to stop the counter short of the wrap that reopens it");

/** @brief What this instance's keys are doing.
 *  @c key_offering and @c key_pending are the two halves of a rekey: an offer
 *  outstanding, then a fresh set awaiting its first authentic PDU. */
typedef enum : uint8_t {
    key_handshaking, /**< First exchange; no transport keys yet. */
    key_confirming,  /**< An IKpsk2 responder's first key set, which no PDU has
                       *   authenticated under yet. */
    key_settled,     /**< One key set, both directions. */
    key_offering,    /**< An offer is outstanding; the settled keys still carry
                       *   everything. */
    key_pending,     /**< Fresh keys in @c tp, the ones they replace in
                       *   @c prev. */
} key_state_t;

static_assert(sizeof(key_state_t) == sizeof(uint8_t),
    "key_state_t must be 8 bits wide");

/** @brief Where an XKpsk3 exchange stands at one end.
 *  A state names the message the end awaits, or the repeats it answers once
 *  settled. The two confirm states exist on the datagram vtbl alone: a stream
 *  frees the context at the split. */
typedef enum : uint8_t {
    hc_i_m2,      /**< Initiator awaiting message 2. */
    hc_i_confirm, /**< Initiator settled, answering repeats of message 2. */
    hc_r_m1,      /**< Responder awaiting message 1. */
    hc_r_m3,      /**< Responder awaiting message 3, answering repeats of
                    *   message 1. */
    hc_r_confirm, /**< Responder settled, taking repeats of messages 1 and 3
                    *   without a word. */
} hc_state_t;

static_assert(sizeof(hc_state_t) == sizeof(uint8_t),
    "hc_state_t must be 8 bits wide");

/** @brief Bytes of the framed room an instance works its handshake messages in:
 *  the length prefix, message 1's fixed fields, the config's hello, the padding
 *  and the tag. The config's hello length is bounded at create so that this
 *  stays inside the handshake budget and the PDU envelope, and the kept-length
 *  fields of an exchange are @c uint16_t wide. */
static size_t s_hs_frame_max(size_t hello_len)
{
    return s_len_prefix + duct_noise_msg1_fixed_size + hello_len + duct_noise_hs_pad_max
         + duct_noise_tag_size;
}

/** @brief Length and closing tag of a peer message taken, which tell a repeat of it. */
typedef struct {
    uint16_t len;                      /**< Body length, bytes; a hello past a byte's
                                        *  width is a length the config may name. */
    uint8_t tag[duct_noise_tag_size];  /**< Last @c duct_noise_tag_size bytes of the body. */
} seen_t;

/** @brief Handshake context of an XKpsk3 exchange.
 *  Made with the instance; freed when a PDU of the peer authenticates, at the
 *  split on a stream, or with the instance. */
typedef struct {
    duct_noise_hs_t *hs;                /**< Handshake state of the exchange, destroyed at
                                          *  the split. */
    duct_ptr_t(uint8_t) last;           /**< Last message this end sent, as emitted; kept
                                          *  on the datagram vtbl alone, an allocation of
                                          *  the config's frame length. */
    uint16_t         last_len;          /**< Bytes in @c last, 0 until one is kept. */
    seen_t         seen[2];           /**< Peer messages taken, in arrival order; kept on
                                          *  the datagram vtbl alone. */
    uint8_t          seen_n;            /**< Entries in @c seen. */
    hc_state_t     state;             /**< Where the exchange stands. */
    uint8_t          tries;             /**< Resends of @c last since the start or the split,
                                          *  at most @c s_hs_tries. */
} hs_ctx_t;

/** @brief Outcome of the handshake context's step on one PDU. */
typedef enum : uint8_t {
    hc_out_pass,    /**< Not the context's PDU: the key states take it. */
    hc_out_ok,      /**< Taken, with nothing to commit. */
    hc_out_refused, /**< Refused: unseal answers @c rc_invalid_arg. */
} hc_out_t;

typedef struct {
    duct_noise_hs_t        *hs;
    hs_ctx_t             *hc; /**< Handshake context of an XKpsk3 first exchange.
                                  *  Null under IKpsk2 and once the exchange has
                                  *  ended. */
    duct_noise_transport_t  tp,
                            prev;
    const duct_noise_cfg_t *cfg;
    const duct_seal_engine_vtbl_t *vt; /**< The vtbl that created this instance.
                              *  Its @c pdu_hdr_size and @c pdu_overhead are the
                              *  length prefix and the per-PDU overhead this
                              *  instance writes. */
    duct_ptr_t(uint8_t)     peer_id; /**< The peer's naming, duct_noise_key_size
                              *  bytes of static public key, then on a responder
                              *  the hello its message 1 carried: an allocation
                              *  of the config's key and hello lengths together,
                              *  made when the instance is and freed when it
                              *  ends. An IKpsk2 responder copies
                              *  both out of message 1 once the allowed list,
                              *  verify_peer and the PSK lookup pass; an XKpsk3
                              *  responder copies the hello out of message 1 and
                              *  the key out of message 3, those checks passing
                              *  inside its read. An initiator copies the key out
                              *  of its config, where reading message 2
                              *  proves the peer holds the private half. */
    duct_ptr_t(uint8_t)     hs_payload; /**< Work room of message 1's payload:
                              *  the config's hello and the padding, hello_len +
                              *  duct_noise_hs_pad_max bytes. Written by the send
                              *  and the read paths of the handshake, which never
                              *  run together on one instance. */
    duct_ptr_t(uint8_t)     hs_frame; /**< Work room of a framed handshake
                              *  message, s_hs_frame_max bytes. */
    key_state_t           keys;
    uint8_t                 rekey_fails; /**< Rekey-handshake reads refused since
                              *  this instance's last @c rekey: message 1 on a
                              *  responder, message 2 on an initiator. A
                              *  successful read costs nothing here, so no peer
                              *  spends another's budget. */
    bool                    is_initiator;
    uint8_t                 ss_cache[duct_noise_key_size]; /**< Diffie-Hellman
                              *  between this instance's static key and the
                              *  peer's, `ss` to the handshake pattern. Spent
                              *  once and read by every rekey after, both
                              *  statics outliving them all.
                              *  Empty until a handshake runs under a settled
                              *  peer key in @c peer_id, which a responder first
                              *  has at the first rekey. */
    uint8_t                 exporter[duct_noise_key_size]; /**< Exporter of
                              *  the first exchange, which @c derive answers
                              *  from; no rekey replaces it. */
} noise_engine_t;

/** @brief Check whether @p e runs the datagram vtbl. */
static bool s_is_dgram(const noise_engine_t *e)
{
    return e->vt == duct_noise_vtbl_dgram();
}

/** @brief Split @p hs into @p out, whose counter then crosses the wire as wide as
 *  @p e's vtbl sends it. */
static bool s_split(const noise_engine_t *e, duct_noise_hs_t *hs, duct_noise_transport_t *out)
{
    if (!duct_noise_hs_split(hs, out))
        return false;
    if (s_is_dgram(e))
        out->counter_size = duct_noise_counter_compact_size;
    return true;
}

/** @brief The key set this instance seals under.
 *  A responder with a pending set seals under @c prev until a PDU proves the
 *  peer holds the fresh one, since message 2 may have been lost. An
 *  initiator switches at once: the responder minted that set before
 *  answering. */
static duct_noise_transport_t *s_tx(noise_engine_t *e)
{
    return e->keys == key_pending && !e->is_initiator ? &e->prev : &e->tp;
}

/** @brief Key the handshake's masks derive from.
 *  The config's wire key, or its PSK where the wire key is all-zero. */
static const uint8_t *s_mask_key(const duct_noise_cfg_t *cfg)
{
    static const uint8_t zero[duct_noise_key_size];
    return duct_ct_equal(cfg->wire_key, zero, sizeof zero) ? cfg->psk : cfg->wire_key;
}

/** @brief New handshake state of @p pattern for one exchange, a first handshake
 *  or a rekey.
 *  A responder carries no remote static key into one; an initiator carries the
 *  one it already holds. The masks run on @ref s_mask_key and the psk token on
 *  the config's PSK, which a responder with @c peer_psk replaces once its peer
 *  is named, by message 1 under IKpsk2 and by message 3 under XKpsk3.
 *  @return nullptr on allocation failure. */
static duct_noise_hs_t *s_hs_new(noise_engine_t *e, duct_noise_pattern_t pattern)
{
    auto hs = duct_noise_hs_create_for(pattern, &e->cfg->local_static,
                                       e->is_initiator ? duct_at(e->peer_id) : nullptr,
                                       s_mask_key(e->cfg), e->is_initiator, (duct_view_u8){});
    duct_do_if(!hs, return nullptr);
    duct_noise_hs_set_psk(hs, e->cfg->psk);
    duct_noise_hs_ss_cache(hs, e->ss_cache, duct_at(e->peer_id));
    return hs;
}

/** @brief Make @p e's XKpsk3 handshake context, its state set by @p e's role.
 *  @return nullptr on allocation failure. */
static hs_ctx_t *s_hc_new(noise_engine_t *e)
{
    duct_auto_del auto hc = duct_new(hs_ctx_t);
    duct_do_if(!hc, return nullptr);
    hc->last = duct_new(uint8_t, s_hs_frame_max(e->cfg->hello_len));
    duct_do_if(!hc->last, return nullptr);
    hc->hs = s_hs_new(e, noise_pattern_xkpsk3);
    duct_do_if(!hc->hs, { duct_del(hc->last); return nullptr; });
    hc->state = e->is_initiator ? hc_i_m2 : hc_r_m1;
    return duct_move(hc);
}

/** @brief Release @p e's handshake context and the handshake state in it, if it holds one. */
static void s_hc_free(noise_engine_t *e)
{
    auto hc = e->hc;
    if (!hc)
        return;
    duct_noise_hs_destroy(hc->hs);
    duct_del(hc->last);
    duct_del(hc);
    e->hc = nullptr;
}

/** @brief Framed PDU length: 2-byte big-endian body count plus the prefix.
 *  0 on a zero body, which no Noise PDU has — the shortest carries an 8-byte
 *  counter and a 16-byte tag.
 */
static size_t s_pdu_len(duct_view_u8 hdr)
{
    auto h = (const uint8_t *)hdr.data;
    size_t body = duct_load_be16(h);
    return body == 0u ? 0u : s_len_prefix + body;
}

/** @brief Per-conn instance over the caller's borrowed static keys.
 *  @p cfg is a @ref duct_noise_cfg_t.
 *  A responder passes no remote static key — it learns the peer's from
 *  message 1 under IKpsk2 and from message 3 under XKpsk3 — while an initiator
 *  must already hold it. @p role naming neither side is refused here too, not
 *  only at wire construction, since this vtbl is reachable without one. @p vt is
 *  the vtbl the instance takes its framing from. The config's pattern decides
 *  what the first exchange lives in: IKpsk2 a handshake state, XKpsk3 a
 *  handshake context.
 *  @return nullptr for a missing config, a pattern at or past
 *          @c noise_pattern_count, a role naming neither side, or an
 *          allocation failure.
 */
static duct_seal_engine_t *s_create_framed(void *cfg, duct_seal_role_t role,
                                           const duct_seal_engine_vtbl_t *vt)
{
    auto c = (const duct_noise_cfg_t *)cfg;
    /* The config names the hello length, and the engine handshake budget
     * bounds it: message 1 carries the hello, the padding and the tag inside the
     * budget, prefix included. A length past that cannot send, and create returns
     * nullptr on validation failure. */
    duct_do_if(!c || c->suite.pattern >= noise_pattern_count, return nullptr);
    duct_do_if(c->hello_len + duct_noise_hs_pad_max
                   > s_engine_hs_budget - (s_len_prefix + duct_noise_msg1_fixed_size
                                           + duct_noise_tag_size),
               return nullptr);
    bool role_ok = duct_seal_role_valid(role);
    duct_do_if(!role_ok, return nullptr);
    bool initiator = role == seal_role_initiator;
    duct_auto_del auto e = duct_new_secret(noise_engine_t);
    duct_do_if(!e, return nullptr);
    e->cfg = c;
    e->is_initiator = initiator;
    e->vt = vt;
    e->keys = key_handshaking;
    e->peer_id = duct_new_secret(uint8_t, duct_noise_key_size + c->hello_len);
    duct_do_if(!e->peer_id, return nullptr);
    e->hs_payload = duct_new_secret(uint8_t, c->hello_len + duct_noise_hs_pad_max);
    e->hs_frame = duct_new_secret(uint8_t, s_hs_frame_max(c->hello_len));
    if (!e->hs_payload || !e->hs_frame) {
        duct_del(e->peer_id);
        duct_del(e->hs_payload);
        duct_del(e->hs_frame);
        return nullptr;
    }
    if (initiator)
        memcpy(duct_at(e->peer_id), c->remote_static_pub, duct_noise_key_size);
    if (c->suite.pattern == noise_pattern_xkpsk3)
        e->hc = s_hc_new(e);
    else
        e->hs = s_hs_new(e, noise_pattern_ikpsk2);
    duct_do_if(!e->hs && !e->hc, { duct_del(e->peer_id); return nullptr; });
    return (duct_seal_engine_t *)duct_move(e);
}

static duct_seal_engine_t *s_create(void *cfg, duct_seal_role_t role)
{
    return s_create_framed(cfg, role, duct_noise_vtbl());
}

static duct_seal_engine_t *s_create_dgram(void *cfg, duct_seal_role_t role)
{
    return s_create_framed(cfg, role, duct_noise_vtbl_dgram());
}

/** @brief Release the instance, a handshake state or context still live included.
 *  The block is wiped whole: the transport keys, the exporter and the Diffie-Hellman cache
 *  go with it. */
static void s_destroy(duct_seal_engine_t *eng)
{
    auto e = (noise_engine_t *)eng;
    duct_noise_hs_destroy(e->hs);
    s_hc_free(e);
    duct_noise_transport_destroy(&e->tp);
    duct_noise_transport_destroy(&e->prev);
    duct_del(e->peer_id);
    duct_del(e->hs_payload);
    duct_del(e->hs_frame);
    duct_del(e);
}

/** @brief Backfill @p framed's @p hdr bytes of length prefix and hand the whole
 *  PDU to @c tx_append. The body is already written at @p hdr, so no copy
 *  happens here.
 */
static bool s_emit(duct_unseal_ctx_t *ctx, uint8_t *framed, size_t hdr, size_t len)
{
    duct_do_if(len == 0u, return false);
    if (hdr)
        duct_store_be16(framed, (uint16_t)len);
    return ctx->tx_append(ctx, (duct_view_u8){ .data = framed, .size = hdr + len });
}

/** @brief Pad the payload in @p out behind its first @p lead bytes with a random
 *  run of zeros, @p room being the bytes @p out holds.
 *  The run is a handshake message's padding; the bytes are zero, since the
 *  handshake AEAD makes the ciphertext pseudorandom whatever they are. The run
 *  stays within @p room behind the lead, so the whole stays within the room the
 *  caller sized from its config. */
static size_t s_hs_pad(uint8_t *out, size_t room, size_t lead)
{
    uint32_t draw = 0u;
    duct_discard duct_random_bytes(&draw, sizeof draw);
    size_t n = draw % (room - lead + 1u);
    memset(out + lead, 0, n);
    return lead + n;
}

/** @brief Draw the random zero padding of a message 2 answering a message 1 of
 *  @p msg1_body bytes, short enough that message 2 is no larger than that
 *  message 1 and no longer than the padding bound both ends build with.
 *  @return the padding, a payload over @p pad. */
static duct_view_u8 s_answer_pad(uint8_t *pad, size_t msg1_body)
{
    size_t cap = msg1_body > duct_noise_msg2_size ? msg1_body - duct_noise_msg2_size : 0u;
    return (duct_view_u8){ .data = pad, .size = duct_min(s_hs_pad(pad, duct_noise_hs_pad_max, 0u), cap) };
}

/** @brief Build message 1's payload in the instance's work room: the config's
 *  hello, then random zero padding. */
static duct_view_u8 s_msg1_payload(const noise_engine_t *e)
{
    size_t lead = e->cfg->hello_len;
    auto payload = duct_at(e->hs_payload);
    memcpy(payload, e->cfg->hello, lead);
    return (duct_view_u8){ .data = payload, .size = s_hs_pad(payload, lead + duct_noise_hs_pad_max, lead) };
}

/** @brief Write this initiator's IKpsk2 message 1 and hand it to @p ctx.
 *  The payload is the config's hello then random zero padding, and the PDU leads
 *  with the vtbl's length prefix where it has one.
 *  @return false when the message does not write or @p ctx refuses it. */
static bool s_offer_msg1(noise_engine_t *e, duct_unseal_ctx_t *ctx)
{
    size_t hdr = e->vt->pdu_hdr_size;
    size_t framed_cap = s_hs_frame_max(e->cfg->hello_len);
    size_t len = 0u;
    return duct_noise_hs_write_msg1(e->hs, s_msg1_payload(e), duct_at(e->hs_frame) + hdr,
                                    framed_cap - hdr, &len)
        && s_emit(ctx, duct_at(e->hs_frame), hdr, len);
}

/** @brief Write the IKpsk2 message 2 into a PDU behind @p hdr bytes of length
 *  prefix and hand it to @p ctx. */
static bool s_answer_msg1(duct_noise_hs_t *hs, duct_unseal_ctx_t *ctx, size_t hdr,
                          duct_view_u8 payload, uint8_t *framed, size_t framed_cap)
{
    size_t len = 0u;
    return duct_noise_hs_write_msg2(hs, payload, framed + hdr, framed_cap - hdr, &len)
        && s_emit(ctx, framed, hdr, len);
}

/** @brief Write the IKpsk2 initiator's key confirmation, an empty PDU sealed under
 *  @c tp, and hand it to @p ctx.
 *  It leaves at the split: the responder names its peer only on a PDU
 *  authenticating under these keys, and a protocol stays free to hold all
 *  application traffic until then. */
static bool s_confirm(noise_engine_t *e, duct_unseal_ctx_t *ctx)
{
    size_t hdr = e->vt->pdu_hdr_size;
    uint8_t framed[s_len_prefix + s_pdu_overhead];
    size_t len = duct_noise_transport_seal(&e->tp, nullptr, 0u, framed + hdr,
                                           sizeof framed - hdr);
    return s_emit(ctx, framed, hdr, len);
}

/** @brief Hand the message at @p framed, @p len body bytes behind the vtbl's length
 *  prefix, to @p ctx.
 *  The datagram vtbl also keeps it in @c last as the message a repeat is answered
 *  with, whether or not @p ctx took it.
 *  @return false when @p ctx refuses it. */
static bool s_hc_send(noise_engine_t *e, duct_unseal_ctx_t *ctx, uint8_t *framed, size_t len)
{
    size_t hdr = e->vt->pdu_hdr_size;
    bool sent = s_emit(ctx, framed, hdr, len);
    if (s_is_dgram(e)) {
        memcpy(duct_at(e->hc->last), framed, hdr + len);
        e->hc->last_len = (uint16_t)(hdr + len);
    }
    return sent;
}

/** @brief Arm the next resend of the last message, @c hs_rto_ms shifted left by
 *  the resends made.
 *  Nothing is armed by a context without @c arm, on a stream, with @c hs_rto_ms
 *  of 0 or once @c s_hs_tries resends are made. */
static void s_hc_arm(const noise_engine_t *e, duct_unseal_ctx_t *ctx)
{
    if (ctx->arm && s_is_dgram(e) && e->cfg->hs_rto_ms != 0u && e->hc->tries < s_hs_tries)
        duct_discard ctx->arm(ctx, (uint32_t)e->cfg->hs_rto_ms << e->hc->tries);
}

/** @brief Write this initiator's XKpsk3 message 1, hand it to @p ctx and arm its
 *  first resend.
 *  @return false when the message does not write or @p ctx refuses it; the first
 *  resend is armed once it has written, refused or not. */
static bool s_hc_offer(noise_engine_t *e, duct_unseal_ctx_t *ctx)
{
    size_t hdr = e->vt->pdu_hdr_size;
    size_t framed_cap = s_hs_frame_max(e->cfg->hello_len);
    size_t len = 0u;
    bool written = duct_noise_hs_write_msg1_xk(e->hc->hs, s_msg1_payload(e), duct_at(e->hs_frame) + hdr,
                                               framed_cap - hdr, &len);
    bool sent = written && s_hc_send(e, ctx, duct_at(e->hs_frame), len);
    if (written)
        s_hc_arm(e, ctx);
    return sent;
}

/** @brief Hand one opening packet to @p sink, a @c duct_unseal_ctx_t, through its
 *  @c tx_append_bare. */
static bool s_opening_put(void *sink, duct_view_u8 bytes)
{
    auto ctx = (duct_unseal_ctx_t *)sink;
    return ctx->tx_append_bare(ctx, bytes);
}

/** @brief Stage the opening packets the config's @c opening_next supplies, each
 *  as @p ctx takes it.
 *  The callback writes packet @c idx into a buffer of @p ctx's @c opening_ceiling
 *  bytes, clamped to @c s_pdu_ct_max, and those bytes go out as they are;
 *  @ref duct_x_opening_emit ends the opening. Stages none without a ceiling,
 *  @c tx_append_bare or the callback. */
static void s_emit_opening(noise_engine_t *e, duct_unseal_ctx_t *ctx)
{
    auto next = e->cfg->opening_next;
    size_t room = duct_min((size_t)ctx->opening_ceiling, s_pdu_ct_max);
    if (!next || room == 0u || !ctx->tx_append_bare)
        return;
    uint8_t packet[room];
    duct_discard duct_x_opening_emit(next, e->cfg->opening_ctx, packet, room,
                                     s_opening_put, ctx);
}

/** @brief Initiator's opening packets, then message 1; a responder emits
 *  nothing here.
 *  Nothing reports a refused @c tx_append: @c start returns void and runs
 *  before any @c engine_hs_budget reservation, so a full TX ring leaves the
 *  handshake unstarted unless the resend timer an XKpsk3 datagram initiator arms
 *  here sends message 1 again. A refused opening packet ends the opening and
 *  message 1 still follows.
 */
static void s_start(duct_seal_engine_t *eng, duct_unseal_ctx_t *ctx)
{
    auto e = (noise_engine_t *)eng;
    duct_do_if(!e->is_initiator, return);
    s_emit_opening(e, ctx);
    duct_discard (e->hc ? s_hc_offer(e, ctx) : s_offer_msg1(e, ctx));
}

/** @brief Check whether @p peer is among @p cfg's allowed keys.
 *  A config naming none admits every peer.
 */
static bool s_peer_allowed(const duct_noise_cfg_t *cfg, const uint8_t peer[duct_noise_key_size])
{
    if (cfg->n_allowed == 0u)
        return true;
    for (unsigned i = 0u; i < cfg->n_allowed; ++i)
        if (duct_ct_equal(cfg->allowed + (size_t)i * duct_noise_key_size, peer, duct_noise_key_size))
            return true;
    return false;
}

/** @brief Check @p peer against the allowed list, then @c verify_peer where set. */
static bool s_peer_admitted(const duct_noise_cfg_t *cfg, const uint8_t peer[duct_noise_key_size])
{
    return s_peer_allowed(cfg, peer)
        && (!cfg->verify_peer || cfg->verify_peer(cfg->verify_ctx, peer));
}

/** @brief Look up the PSK of the peer @p remote: the config PSK where
 *  @c peer_psk is unset, else what it answers for @p payload.
 *  @return false for a peer @c peer_psk refuses, else true with the PSK in @p out. */
static bool s_psk_lookup(const duct_noise_cfg_t *cfg, const uint8_t remote[duct_noise_key_size],
                         duct_view_u8 payload, uint8_t out[duct_noise_key_size])
{
    if (!cfg->peer_psk) {
        memcpy(out, cfg->psk, duct_noise_key_size);
        return true;
    }
    return cfg->peer_psk(cfg->verify_ctx, remote, payload, out);
}

/** @brief Check the hello a peer's message 1 carried and set the PSK its IKpsk2
 *  message 2 mixes.
 *  @p payload is what message 1 carried whole, the hello then its zero padding,
 *  and it is what @c peer_psk is asked about for @p remote; without @c peer_psk
 *  the config's PSK stands and the payload must carry the config's hello whole.
 *  @return false for an empty payload under @c peer_psk when the config names a
 *          hello, for a payload shorter than the hello without @c peer_psk, and
 *          for a peer @c peer_psk refuses. */
static bool s_psk_for(const duct_noise_cfg_t *cfg, duct_noise_hs_t *hs,
                      const uint8_t remote[duct_noise_key_size], duct_view_u8 payload)
{
    /* A config with no hello admits an empty payload: what carries is padding
     * alone. One with a hello refuses it — no hello came at all. */
    duct_do_if(cfg->peer_psk ? (cfg->hello_len != 0u && payload.size == 0u)
                             : payload.size < cfg->hello_len,
               return false);
    duct_secret_array(uint8_t, psk, duct_noise_key_size);
    if (!s_psk_lookup(cfg, remote, payload, psk))
        return false;
    duct_noise_hs_set_psk(hs, psk);
    return true;
}

/** @brief Keep the peer's hello in its naming: the payload's head, zero-filled to
 *  the config's hello length, so a peer whose hello runs short of it still names
 *  whole and no work-room byte past the payload is read. */
static void s_hello_keep(const noise_engine_t *e, const uint8_t *payload, size_t payload_len)
{
    auto dst = duct_at(e->peer_id) + duct_noise_key_size;
    size_t take = duct_min(payload_len, e->cfg->hello_len);
    memcpy(dst, payload, take);
    memset(dst + take, 0, e->cfg->hello_len - take);
}

/** @brief Run this role's half of the IKpsk2 first exchange on @p body.
 *
 *  An initiator reads message 2, settles and sends its key confirmation; a
 *  responder reads message 1, admits its peer through the allowed list,
 *  @c verify_peer and the PSK lookup in that order, answers message 2 through
 *  @c ctx->tx_append and waits in @c key_confirming.
 */
static duct_result_t s_hs_step(noise_engine_t *e, duct_view_u8 body,
                               duct_unseal_ctx_t *ctx)
{
    if (e->is_initiator) {
        bool ok = duct_noise_hs_read_msg2(e->hs, body);
        duct_do_if(!ok, return rc_invalid_arg);
    } else {
        uint8_t remote[duct_noise_key_size];
        size_t payload_len = 0u;
        auto payload = duct_at(e->hs_payload);
        bool ok = duct_noise_hs_read_msg1(e->hs, body, remote, payload,
                                          e->cfg->hello_len + duct_noise_hs_pad_max, &payload_len);
        duct_do_if(!ok, return rc_invalid_arg);
        /* Ahead of message 2, not after it: a rejected peer that still draws a
         * reply learns its key is one this responder does not carry. */
        bool admitted = s_peer_admitted(e->cfg, remote)
                     && s_psk_for(e->cfg, e->hs, remote,
                                  (duct_view_u8){ .data = payload, .size = payload_len });
        if (!admitted)
            return rc_invalid_arg;
        memcpy(duct_at(e->peer_id), remote, duct_noise_key_size);
        s_hello_keep(e, payload, payload_len);
        /* The payload has gone into the peer's naming, so the answer's padding
         * reuses its room. */
        ok = s_answer_msg1(e->hs, ctx, e->vt->pdu_hdr_size,
                           s_answer_pad(duct_at(e->hs_payload), body.size),
                           duct_at(e->hs_frame), s_hs_frame_max(e->cfg->hello_len));
        duct_do_if(!ok, return rc_invalid_arg);
    }
    bool ok = s_split(e, e->hs, &e->tp)
           && duct_noise_hs_exporter(e->hs, e->exporter);
    duct_do_if(!ok, return rc_invalid_arg);
    duct_noise_hs_destroy(e->hs);
    e->hs = nullptr;
    e->keys = e->is_initiator ? key_settled : key_confirming;
    ok = !e->is_initiator || s_confirm(e, ctx);
    duct_do_if(!ok, return rc_invalid_arg);
    return rc_ok;
}

/** @brief Resolve the PSK of the sender of message 3, @p ctx being the instance.
 *  The core asks while message 3 reads, ahead of its payload opening, so @p remote
 *  is the sender's claim. The allowed list and @c verify_peer admit it, then
 *  @c peer_psk answers for the hello message 1 left in @c peer_id.
 *  @return false for a peer refused, else true with the PSK in @p out. */
static bool s_xk_psk_for(void *ctx, const uint8_t remote[duct_noise_key_size],
                         uint8_t out[duct_noise_key_size])
{
    auto e = (const noise_engine_t *)ctx;
    return s_peer_admitted(e->cfg, remote)
        && s_psk_lookup(e->cfg, remote,
                        (duct_view_u8){ .data = duct_at(e->peer_id) + duct_noise_key_size,
                                        .size = e->cfg->hello_len },
                        out);
}

/** @brief Closing tag of the message in @p body, its last @c duct_noise_tag_size
 *  bytes. */
static const uint8_t *s_tag_of(duct_view_u8 body)
{
    return (const uint8_t *)body.data + body.size - duct_noise_tag_size;
}

/** @brief Keep the length and closing tag of the peer message in @p body, by which
 *  a repeat of it is told.
 *  The datagram vtbl alone keeps them, so a stream recognises no repeat. */
static void s_remember(noise_engine_t *e, duct_view_u8 body)
{
    auto hc = e->hc;
    if (!s_is_dgram(e))
        return;
    hc->seen[hc->seen_n].len = (uint16_t)body.size;
    memcpy(hc->seen[hc->seen_n].tag, s_tag_of(body), duct_noise_tag_size);
    ++hc->seen_n;
}

/** @brief Check whether @p body repeats a peer message taken, by its length and
 *  closing tag.
 *  Whoever holds the message's bytes matches, from any source, so what a repeat
 *  draws is capped by @c s_hs_tries. */
static bool s_repeat(const hs_ctx_t *hc, duct_view_u8 body)
{
    for (unsigned i = 0u; i < hc->seen_n; ++i)
        if (body.size == hc->seen[i].len
            && memcmp(hc->seen[i].tag, s_tag_of(body), duct_noise_tag_size) == 0)
            return true;
    return false;
}

/** @brief Send the last message again, at most @c s_hs_tries times.
 *  Answers a repeat of the peer's message, and is the send of @c s_retry.
 *  @return hc_out_ok: the repeat is taken whether or not anything went out. */
static hc_out_t s_resend(noise_engine_t *e, duct_unseal_ctx_t *ctx)
{
    auto hc = e->hc;
    if (hc->tries < s_hs_tries) {
        ++hc->tries;
        duct_discard ctx->tx_append(ctx, (duct_view_u8){ .data = duct_at(hc->last), .size = hc->last_len });
    }
    return hc_out_ok;
}

/** @brief Send the last message again when the timer @c s_hc_arm armed fires, and
 *  arm the next resend.
 *  A context already freed by the peer's first authentic PDU leaves nothing to
 *  send, and the call does nothing. */
static void s_retry(duct_seal_engine_t *eng, duct_unseal_ctx_t *ctx)
{
    auto e = (noise_engine_t *)eng;
    if (!e->hc)
        return;
    duct_discard s_resend(e, ctx);
    s_hc_arm(e, ctx);
}

/** @brief Split the exchange into the transport keys and the exporter, destroy its
 *  handshake state and settle the keys.
 *  The datagram vtbl moves the context to its confirm state; a stream frees it.
 *  @return false when the split or the exporter fails. */
static bool s_hc_settle(noise_engine_t *e)
{
    auto hc = e->hc;
    bool ok = s_split(e, hc->hs, &e->tp) && duct_noise_hs_exporter(hc->hs, e->exporter);
    duct_do_if(!ok, return false);
    duct_noise_hs_destroy(hc->hs);
    hc->hs = nullptr;
    e->keys = key_settled;
    if (s_is_dgram(e)) {
        hc->state = e->is_initiator ? hc_i_confirm : hc_r_confirm;
        hc->tries = 0u;
    } else {
        s_hc_free(e);
    }
    return true;
}

/** @brief Read message 2, send message 3 and settle.
 *  @return hc_out_refused for a message 2 that does not read, which leaves the
 *          exchange ready for the genuine one, and for a message 3 that does not
 *          write, send or settle; one that @p ctx refuses leaves the end
 *          settled. Else hc_out_ok. */
static hc_out_t s_hc_initiator_m2(noise_engine_t *e, duct_view_u8 body, duct_unseal_ctx_t *ctx)
{
    auto hc = e->hc;
    bool ok = duct_noise_hs_read_msg2_xk(hc->hs, body);
    duct_do_if(!ok, return hc_out_refused);
    s_remember(e, body);
    auto pad = duct_at(e->hs_payload);
    size_t hdr = e->vt->pdu_hdr_size;
    size_t framed_cap = s_hs_frame_max(e->cfg->hello_len);
    size_t len = 0u;
    ok = duct_noise_hs_write_msg3_xk(hc->hs, (duct_view_u8){ .data = pad, .size = s_hs_pad(pad, duct_noise_hs_pad_max, 0u) },
                                     duct_at(e->hs_frame) + hdr, framed_cap - hdr, &len);
    duct_do_if(!ok, return hc_out_refused);
    bool sent = s_hc_send(e, ctx, duct_at(e->hs_frame), len);
    bool settled = s_hc_settle(e);
    return sent && settled ? hc_out_ok : hc_out_refused;
}

/** @brief Read message 1, ask @c hello_ok and answer message 2.
 *  The hello is kept in @c peer_id ahead of the answer, for the resolver of
 *  message 3.
 *  @return hc_out_refused for a message 1 that does not read, a payload the
 *          length gate refuses, and a hello @c hello_ok refuses, none of which
 *          draws message 2, and for an answer that does not write or send. Else
 *          hc_out_ok. */
static hc_out_t s_hc_responder_m1(noise_engine_t *e, duct_view_u8 body, duct_unseal_ctx_t *ctx)
{
    auto hc = e->hc;
    auto cfg = e->cfg;
    auto payload = duct_at(e->hs_payload);
    size_t payload_len = 0u;
    bool ok = duct_noise_hs_read_msg1_xk(hc->hs, body, payload,
                                         cfg->hello_len + duct_noise_hs_pad_max, &payload_len);
    /* Where @c hello_ok stands it names the payload whole — the hello then its
     * zero padding — and an empty one is refused ahead of it unless the config
     * names no hello at all; without the callback the config's hello must be
     * there whole. */
    duct_do_if(!ok || (cfg->hello_ok ? (cfg->hello_len != 0u && payload_len == 0u)
                                     : payload_len < cfg->hello_len),
               return hc_out_refused);
    bool admitted = !cfg->hello_ok
                 || cfg->hello_ok(cfg->verify_ctx, (duct_view_u8){ .data = payload, .size = payload_len });
    if (!admitted)
        return hc_out_refused;
    s_hello_keep(e, payload, payload_len);
    s_remember(e, body);
    auto pad = duct_at(e->hs_payload);
    size_t hdr = e->vt->pdu_hdr_size;
    size_t framed_cap = s_hs_frame_max(cfg->hello_len);
    size_t len = 0u;
    ok = duct_noise_hs_write_msg2_xk(hc->hs, s_answer_pad(pad, body.size), duct_at(e->hs_frame) + hdr,
                                     framed_cap - hdr, &len);
    duct_do_if(!ok, return hc_out_refused);
    hc->state = hc_r_m3;
    return s_hc_send(e, ctx, duct_at(e->hs_frame), len) ? hc_out_ok : hc_out_refused;
}

/** @brief Answer a repeat of message 1 with message 2 again, else read message 3,
 *  name the peer and settle.
 *  @return hc_out_refused for a message 3 that does not read, a peer the allowed
 *          list, @c verify_peer or @c peer_psk refuses included; the exchange stays
 *          ready for a message 3 they admit. Else hc_out_ok. */
static hc_out_t s_hc_responder_m3(noise_engine_t *e, duct_view_u8 body, duct_unseal_ctx_t *ctx)
{
    if (s_repeat(e->hc, body))
        return s_resend(e, ctx);
    uint8_t remote[duct_noise_key_size];
    auto payload = duct_at(e->hs_payload);
    size_t payload_len = 0u;
    bool ok = duct_noise_hs_read_msg3_xk(e->hc->hs, body, s_xk_psk_for, e, remote, payload,
                                         duct_noise_hs_pad_max, &payload_len);
    duct_do_if(!ok, return hc_out_refused);
    memcpy(duct_at(e->peer_id), remote, duct_noise_key_size);
    s_remember(e, body);
    return s_hc_settle(e) ? hc_out_ok : hc_out_refused;
}

/** @brief Run the handshake context's step on @p body, by the state the exchange
 *  stands in.
 *  @return hc_out_pass for a PDU past the split that repeats no peer message;
 *          every PDU before it is the context's. */
static hc_out_t s_hc_step(noise_engine_t *e, duct_view_u8 body, duct_unseal_ctx_t *ctx)
{
    switch (e->hc->state) {
    case hc_i_m2:
        return s_hc_initiator_m2(e, body, ctx);
    case hc_r_m1:
        return s_hc_responder_m1(e, body, ctx);
    case hc_r_m3:
        return s_hc_responder_m3(e, body, ctx);
    case hc_i_confirm:
        return s_repeat(e->hc, body) ? s_resend(e, ctx) : hc_out_pass;
    case hc_r_confirm:
        return s_repeat(e->hc, body) ? hc_out_ok : hc_out_pass;
    }
    duct_unreachable();
}

/** @brief Install @p fresh as the sealing set, keeping what it replaces in
 *  @c prev.
 *  A second offer answered while a set is already pending leaves @c prev
 *  alone: it holds the keys the peer is still sealing under, while the
 *  half-finished set in @c tp is the one nobody reached. */
static void s_adopt(noise_engine_t *e, duct_noise_transport_t *fresh)
{
    if (e->keys != key_pending) {
        duct_noise_transport_destroy(&e->prev);
        e->prev = e->tp;
        e->tp = (duct_noise_transport_t){};
    }
    duct_noise_transport_destroy(&e->tp);
    e->tp = *fresh;
    *fresh = (duct_noise_transport_t){};
    e->keys = key_pending;
}

/** @brief Settle on @c tp, a PDU having authenticated under it, and drop
 *  @c prev, which is empty where @c tp holds the first key set. */
static void s_promote(noise_engine_t *e)
{
    duct_noise_transport_destroy(&e->prev);
    e->keys = key_settled;
}

/** @brief Answer a rekey offer, minting the fresh key set it asks for.
 *
 *  The static key read out of message 1 is compared against the one this conn
 *  already authenticated; an offer under another identity is refused to protect
 *  against identity replacement in flight. The PSK is asked for that peer again with the hello this message
 *  carries, since the hello sits inside the message and shows only after the
 *  Diffie-Hellman that reads it.
 *
 *  A refusal, the PSK lookup's included, is charged to @c rekey_fails, and an
 *  offer arriving past @ref s_rekey_fail_cap is turned away ahead of the
 *  Diffie-Hellman that reads one.
 *
 *  @return @c rc_invalid_arg for anything that is not this peer's message 1,
 *          which an undecryptable PDU gets either way.
 */
static duct_result_t s_rekey_msg1(noise_engine_t *e, duct_view_u8 body,
                                  duct_unseal_ctx_t *ctx)
{
    /* A rekey's message 1 carries the hello, so its payload spans the config's
     * hello and the padding; under @c peer_psk a peer of an older build may
     * carry a shorter hello, so the floor is the fixed fields and one payload
     * byte, and @c s_psk_for refuses the empty payload. */
    size_t lo = duct_noise_hs_msg1_size(e->cfg->peer_psk ? 0u : e->cfg->hello_len),
           hi = duct_noise_hs_msg1_size(e->cfg->hello_len + duct_noise_hs_pad_max);
    duct_do_if(e->is_initiator || body.size < lo || body.size > hi, return rc_invalid_arg);
    duct_do_if(e->rekey_fails >= s_rekey_fail_cap, return rc_invalid_arg);
    auto hs = s_hs_new(e, noise_pattern_ikpsk2);
    duct_do_if(!hs, return rc_invalid_arg);
    uint8_t remote[duct_noise_key_size];
    auto payload = duct_at(e->hs_payload);
    size_t payload_len = 0u;
    duct_secret(duct_noise_transport_t, fresh, {});
    bool ok = duct_noise_hs_read_msg1(hs, body, remote, payload,
                                      e->cfg->hello_len + duct_noise_hs_pad_max, &payload_len)
           && duct_ct_equal(remote, duct_at(e->peer_id), sizeof remote)
           && s_psk_for(e->cfg, hs, remote,
                        (duct_view_u8){ .data = payload, .size = payload_len })
           && s_answer_msg1(hs, ctx, e->vt->pdu_hdr_size,
                            s_answer_pad(payload, body.size),
                            duct_at(e->hs_frame), s_hs_frame_max(e->cfg->hello_len))
           && s_split(e, hs, &fresh);
    duct_noise_hs_destroy(hs);
    if (!ok) {
        duct_noise_transport_destroy(&fresh);
        ++e->rekey_fails;
        return rc_invalid_arg;
    }
    s_adopt(e, &fresh);
    return rc_ok;
}

/** @brief Take the answer to this instance's offer.
 *  A genuine message 2 adopts the fresh keys and answers @c rc_ok; a
 *  non-authenticating body answers @c rc_invalid_arg with the offer left live.
 *  Past @c s_rekey_fail_cap such bodies in one window @c read_msg2 is skipped and
 *  the genuine answer is turned away too, deferring the rekey. */
static duct_result_t s_rekey_msg2(noise_engine_t *e, duct_view_u8 body)
{
    duct_do_if(!e->hs, return rc_invalid_arg);
    duct_do_if(e->rekey_fails >= s_rekey_fail_cap, return rc_invalid_arg);
    bool authed = duct_noise_hs_read_msg2(e->hs, body);
    duct_do_if(!authed, ++e->rekey_fails; return rc_invalid_arg);
    duct_secret(duct_noise_transport_t, fresh, {});
    bool split = s_split(e, e->hs, &fresh);
    duct_noise_hs_destroy(e->hs);
    e->hs = nullptr;
    duct_do_if(!split, duct_noise_transport_destroy(&fresh); return rc_invalid_arg);
    s_adopt(e, &fresh);
    return rc_ok;
}

/** @brief Offer the peer a fresh key set, over the keys still carrying
 *  traffic.
 *
 *  Offering again from @c key_offering recovers a lost message 2: the
 *  stale exchange goes first, and a late answer to it reaches
 *  @ref s_rekey_msg2 and is refused there. A responder declines, IK giving it
 *  no way to open an exchange.
 *
 *  The rekey budget clears ahead of that role check, so this call is also the
 *  period @ref s_rekey_fail_cap is measured over — which is the whole of what
 *  a responder lifetime does.
 *
 *  Answers @c rc_ok where it offered or declined by role, @c rc_no_memory on a
 *  fresh handshake it cannot build, @c rc_again on an offer that fails to go
 *  out, the last two asked again at the conn's next PDU. Never @c rc_fatal, so
 *  this engine outlasts internal operational failures.
 */
static duct_result_t s_rekey(duct_seal_engine_t *eng, duct_unseal_ctx_t *ctx)
{
    auto e = (noise_engine_t *)eng;
    e->rekey_fails = 0u;
    bool offerable = e->is_initiator
                  && (e->keys == key_settled || e->keys == key_offering);
    duct_do_if(!offerable, return rc_ok);
    duct_noise_hs_destroy(e->hs);
    e->hs = nullptr;
    e->hs = s_hs_new(e, noise_pattern_ikpsk2);
    duct_do_if(!e->hs, return rc_no_memory);
    bool ok = s_offer_msg1(e, ctx);
    if (!ok) {
        duct_noise_hs_destroy(e->hs);
        e->hs = nullptr;
        return rc_again;
    }
    e->keys = key_offering;
    return rc_ok;
}

/** @brief Answer the peer's identity, empty until the peer has proven it holds
 *  the split keys.
 *  The identity is the peer's static public key, followed on a responder by the
 *  hello the peer's first message 1 carried. Message 2 is the proof to an
 *  initiator, message 3 to an XKpsk3 responder, and the first PDU authenticating
 *  under @c tp to an IKpsk2 one. A rekey leaves the identity as it was: the offer
 *  it accepts has to carry this same key. */
static duct_view_u8 s_peer_identity(duct_seal_engine_t *eng)
{
    auto e = (noise_engine_t *)eng;
    if (e->keys == key_handshaking || e->keys == key_confirming)
        return (duct_view_u8){};
    return (duct_view_u8){ .data = duct_at(e->peer_id),
                         .size = duct_noise_key_size + (e->is_initiator ? 0u : e->cfg->hello_len) };
}

/** @brief Derive @p len bytes under @p label from the exporter, once the peer
 *  is named. */
static bool s_derive(duct_seal_engine_t *eng, const char *label, void *out, size_t len)
{
    auto e = (noise_engine_t *)eng;
    if (s_peer_identity(eng).size == 0u)
        return false;
    return duct_noise_derive(e->exporter, label, (uint8_t *)out, len);
}

/** @brief Size the cleartext @p pdu unseals to: what is left past the length
 *  prefix where the vtbl has one, the counter and the tag.
 *  0 until the peer is named, so @c on_peer_auth fires on a PDU that reserved
 *  nothing on the frame's destination; 0 also for a PDU no longer than that
 *  overhead. A rekey message is measured as though it were transport data,
 *  which over-reserves on the frame's destination and commits none of it.
 */
static size_t s_unseal_size(duct_seal_engine_t *eng, duct_view_u8 pdu)
{
    if (s_peer_identity(eng).size == 0u)
        return 0u;
    auto e = (const noise_engine_t *)eng;
    size_t framed = e->vt->pdu_hdr_size + e->vt->pdu_overhead;
    duct_do_if(pdu.size <= framed, return 0u);
    return pdu.size - framed;
}

/** @brief Unseal one inbound PDU: the first exchange's message, transport
 *  data, or a rekey message.
 *
 *  A live handshake context takes the PDU first: it reads its exchange's
 *  message, answers a repeat of the peer's or takes it without a word, and past
 *  the split passes on any PDU that repeats nothing. Transport is tried next and
 *  under both key sets, so a rekey message is only ever considered for bytes no
 *  key decrypts: an ordinary packet unseals as transport and never reaches the
 *  rekey path. A PDU authenticating under @c tp while a set is pending or a
 *  responder is confirming settles the keys, and any authenticating PDU frees the
 *  handshake context. A confirming responder refuses every other PDU outright:
 *  the rekey path ends in @c key_pending, where the peer is named, and a replayed
 *  message 1 passes it.
 *
 *  An inbound PDU is also where a counter past @ref s_offer_at_messages turns
 *  into an offer, this being the one per-PDU call that carries a @p ctx to
 *  emit through.
 */
static duct_result_t
s_unseal(duct_seal_engine_t *eng, duct_view_u8 pdu, duct_unseal_ctx_t *ctx)
{
    auto e = (noise_engine_t *)eng;
    size_t hdr = e->vt->pdu_hdr_size;
    duct_do_if(pdu.size <= hdr, return rc_invalid_arg);
    duct_view_u8 body = { .data = (uint8_t *)pdu.data + hdr, .size = pdu.size - hdr };
    if (e->hc) {
        switch (s_hc_step(e, body, ctx)) {
        case hc_out_ok:
            return rc_ok;
        case hc_out_refused:
            return rc_invalid_arg;
        case hc_out_pass:
            break;
        }
    }
    if (e->keys == key_handshaking)
        return s_hs_step(e, body, ctx);
    if (e->keys == key_settled
        && s_tx(e)->send_counter >= s_offer_at_messages)
        duct_discard s_rekey(eng, ctx);
    size_t cap = 0u;
    auto ct = (uint8_t *)ctx->reserve(ctx, &cap);
    size_t out_len = 0u;
    bool pending = e->keys == key_pending;
    bool got = duct_noise_transport_unseal(&e->tp, body, ct, cap, &out_len);
    if (got && (pending || e->keys == key_confirming))
        s_promote(e);
    else if (!got && pending)
        got = duct_noise_transport_unseal(&e->prev, body, ct, cap, &out_len);
    if (got) {
        s_hc_free(e);
        return ctx->commit(ctx, out_len) ? rc_ok : rc_invalid_arg;
    }
    duct_do_if(e->keys == key_confirming, return rc_invalid_arg);
    if (e->keys == key_offering)
        return s_rekey_msg2(e, body);
    return s_rekey_msg1(e, body, ctx);
}

/** @brief Sealed byte count for @p ct_len, 0 until the first exchange ends.
 *
 *  A rekey never parks it: the settled keys go on sealing throughout.
 *  Segmented at @c pdu_ct_max, each PDU charged its length prefix (none on the
 *  datagram vtbl), counter and tag — the arithmetic @ref s_seal then writes.
 *
 *  It answers 0 again once the sealing counter passes
 *  @c duct_noise_seal_counter_max, which parks the response on the
 *  runtime's retry path. A counter that far along means every rekey since
 *  @ref s_offer_at_messages went unanswered, and a nonce repeated under one key
 *  costs both confidentiality and authenticity.
 */
static size_t s_seal_size(duct_seal_engine_t *eng, size_t ct_len)
{
    auto e = (noise_engine_t *)eng;
    duct_do_if(e->keys == key_handshaking, return 0u);
    uint64_t sent = s_tx(e)->send_counter;
    duct_do_if(sent > duct_noise_seal_counter_max, return 0u);
    size_t n = ct_len / s_pdu_ct_max;
    if (ct_len % s_pdu_ct_max != 0u || n == 0u)
        ++n;
    return ct_len + n * (e->vt->pdu_hdr_size + e->vt->pdu_overhead);
}

/** @brief Seal @p spans as one cleartext stream into @p dst.
 *  Segmented at @c pdu_ct_max, each chunk behind a length prefix where the
 *  vtbl writes one. A chunk is sealed from the spans where they lie, one AEAD
 *  update per span it touches.
 */
static void s_seal(duct_seal_engine_t *eng, const duct_view_u8 *spans,
                   size_t n_spans, void *dst)
{
    auto e = (noise_engine_t *)eng;
    size_t hdr = e->vt->pdu_hdr_size;
    auto out = (uint8_t *)dst;
    size_t total = 0u;
    for (size_t i = 0u; i < n_spans; ++i)
        total += spans[i].size;
    duct_fatal(total == 0u);

    duct_view_u8 window[n_spans];
    size_t span_i = 0u,
           span_off = 0u,
           remaining = total;
    while (remaining > 0u) {
        size_t chunk = duct_min(remaining, s_pdu_ct_max),
               left = chunk,
               pieces = 0u;
        while (left > 0u) {
            size_t part = duct_min(spans[span_i].size - span_off, left);
            if (part)
                window[pieces++] = (duct_view_u8){ .data = (uint8_t *)spans[span_i].data + span_off,
                                                 .size = part };
            left -= part;
            span_off += part;
            if (span_off == spans[span_i].size) {
                ++span_i;
                span_off = 0u;
            }
        }
        size_t body = duct_noise_transport_seal_size_of(s_tx(e), chunk);
        if (hdr)
            duct_store_be16(out, (uint16_t)body);
        size_t got = duct_noise_transport_seal(s_tx(e), window, pieces, out + hdr, body);
        duct_fatal(got != body);
        out += hdr + body;
        remaining -= chunk;
    }
}

/* Everything the two framings share; each vtbl adds its create, its name, its PDU
 * framing and the bytes that framing spends on each PDU. */
#define s_vtbl_common                           \
    .destroy = s_destroy,                       \
    .unseal = s_unseal,                         \
    .unseal_size = s_unseal_size,               \
    .peer_identity = s_peer_identity,           \
    .derive = s_derive,                         \
    .pdu_ct_max = s_pdu_ct_max,                 \
    .flags = fl_seal_dgram_ok,                  \
    .engine_hs_budget = s_engine_hs_budget,     \
    .seal_size = s_seal_size,                   \
    .seal = s_seal,                             \
    .start = s_start,                           \
    .rekey = s_rekey

static const duct_seal_engine_vtbl_t s_vtbl = {
    s_vtbl_common,
    .create = s_create,
    .name = "noise",
    .pdu_hdr_size = s_len_prefix,
    .pdu_len = s_pdu_len,
    .pdu_overhead = s_pdu_overhead,
};

/** @brief The datagram-wire crypto engine, @c noise-dgram.
 *  Writes no length prefix: the record header already delimits a datagram's
 *  one PDU. Each PDU sends its sequence number as its low 4 bytes as well,
 *  the receiver rebuilding the rest from the highest it has accepted.
 */
static const duct_seal_engine_vtbl_t s_vtbl_dgram = {
    s_vtbl_common,
    .create = s_create_dgram,
    .name = "noise-dgram",
    .pdu_overhead = s_pdu_overhead_compact,
    .retry = s_retry,
};

const duct_seal_engine_vtbl_t *duct_noise_vtbl(void)
{
    return &s_vtbl;
}

const duct_seal_engine_vtbl_t *duct_noise_vtbl_dgram(void)
{
    return &s_vtbl_dgram;
}

void duct_noise_vtbl_make(duct_seal_engine_vtbl_t *out, size_t hs_budget)
{
    duct_do_if(!out, return);
    *out = s_vtbl;
    out->engine_hs_budget = hs_budget != 0u ? hs_budget : s_engine_hs_budget;
}
