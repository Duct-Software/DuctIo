/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_noise.h
 *  @brief Noise_IKpsk2 and Noise_XKpsk3 as a sealed-wire crypto engine.
 *
 *  Present only in a @c DUCT_WITH_NOISE build. Pass @ref duct_noise_vtbl, or
 *  @ref duct_noise_vtbl_dgram on a datagram wire, to
 *  @ref duct_wire_create_sealed with a @ref duct_noise_cfg_t as its
 *  @c engine_cfg, exactly as the OpenSSL vtbl is passed with an
 *  @c SSL_CTX.
 *
 *  The handshake and transport primitives behind the engine are internal: an
 *  integrator supplies static keys and lets the wire drive the pattern. The
 *  config's @c suite names the pattern of a conn's first exchange, IKpsk2 when
 *  zero; every rekey runs IKpsk2.
 *
 *  @ref duct_hmac_sha256, the HMAC a protocol over the engine derives its tags
 *  and keys with, stands on the same OpenSSL and exists in the same builds.
 *
 *  @see @ref duct_seal_engine_vtbl_t for what the engine owes the wire.
 */

#ifndef DUCT_NOISE_H
#define DUCT_NOISE_H

#include "duct_seal_engine.h"
#include "duct_types.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief X25519 key length, both halves. */
static constexpr size_t duct_noise_key_size = 32u;

/** @brief HMAC-SHA256 output, bytes. */
static constexpr size_t duct_hmac_sha256_size = 32u;

/** @brief X25519 keypair, raw 32-byte encoding both ends. */
typedef struct duct_noise_keypair {
    uint8_t priv[duct_noise_key_size];
    uint8_t pub[duct_noise_key_size];
} duct_noise_keypair_t;

/** @brief Generate a fresh X25519 keypair.
 *  @return false on an RNG or OpenSSL failure.
 */
bool duct_noise_keypair_generate(duct_noise_keypair_t *out);

/** @brief Derive @p out from an already-chosen private key, filling both
 *  @c priv and the matching @c pub.
 *  @return false on an OpenSSL failure, i.e. malformed key material.
 */
duct_nonnull(1, 2) bool
duct_noise_keypair_from_priv(duct_noise_keypair_t *out,
                             const uint8_t priv[duct_noise_key_size]);

/** @brief HMAC-SHA256 of @p data under @p key, written to @p out.
 *  A key up to @c INT_MAX bytes is valid, one longer than the hash's 64-byte
 *  block being hashed first, and a length of 0 is valid for the key and for the
 *  data, their pointers still non-null.
 *  @return false when @p key_len exceeds @c INT_MAX or OpenSSL fails.
 */
[[nodiscard]] duct_nonnull(1, 3, 5) bool
duct_hmac_sha256(const void *key, size_t key_len, const void *data, size_t data_len,
                 uint8_t out[duct_hmac_sha256_size]);

/** @brief Noise handshake pattern.
 *  The transcript starts from the pattern's full protocol name, so two ends
 *  running different patterns do not agree on a key. Enumerators are appended;
 *  none is renumbered or reused. */
typedef enum duct_noise_pattern : uint8_t {
    noise_pattern_ikpsk2 = 0, /**< Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s: two messages, the initiator's
                                *  static key in message 1. */
    noise_pattern_xkpsk3,     /**< Noise_XKpsk3_25519_ChaChaPoly_BLAKE2s: three messages, the initiator's
                                *  static key in message 3 and the PSK mixed at its end. */
    noise_pattern_count,      /**< Count of patterns, not a pattern. */
} duct_noise_pattern_t;

static_assert(sizeof(duct_noise_pattern_t) == sizeof(uint8_t),
    "duct_noise_pattern_t must be 8 bits wide");

/** @brief Handshake suite of a Noise engine instance.
 *  Members are appended and never reordered or removed, so a suite a protocol
 *  has shipped keeps meaning the same exchange. */
typedef struct duct_noise_suite {
    duct_noise_pattern_t pattern; /**< Pattern of a conn's first exchange.
                                    *  Zero is @c noise_pattern_ikpsk2; a rekey runs
                                    *  IKpsk2 under any value. */
} duct_noise_suite_t;

/** @brief Static keys, pre-shared key, admitted peers, opening packets and
 *  first-exchange pattern for a Noise engine instance.
 *
 *  The @c engine_cfg of @ref duct_noise_vtbl and @ref duct_noise_vtbl_dgram.
 *  Caller-owned and borrowed: it must outlive every conn the wire built from it,
 *  and one config backs any number of them.
 *
 *  @c local_static is this side's identity. @c remote_static_pub is the peer's,
 *  which an initiator must know up front under either pattern, and which a
 *  responder leaves unset, learning it from message 1 under IKpsk2 and from
 *  message 3 under XKpsk3. @c psk is mixed
 *  in unconditionally; all-zero is the no-PSK case and still a valid config. A
 *  responder whose @c peer_psk is set mixes the PSK that callback writes for
 *  the peer instead.
 *  Under @c DUCT_HANDSHAKE_MASK, @c wire_key keys the mask over each handshake
 *  message's ephemeral key, and @c psk does where @c wire_key is all-zero. The
 *  mask hides that key only from an observer without the key it is made with;
 *  an all-zero one is known to everyone.
 */
typedef struct duct_noise_cfg {
    duct_noise_keypair_t local_static;
    uint8_t              remote_static_pub[duct_noise_key_size];
    uint8_t              psk[duct_noise_key_size];
    /** @brief Static public keys a responder admits, @c n_allowed of them back to
     *  back.
     *  A peer whose key is none of them is refused before @c verify_peer is asked.
     *  Read by several workers at once, so left unchanged while a wire built from
     *  this config is live.
     */
    const uint8_t       *allowed;
    /** @brief Keys in @c allowed, 0 for no list.
     *  With no list @c verify_peer alone decides.
     */
    unsigned             n_allowed;
    /** @brief Responder-side peer check.
     *  Asked for a peer the allowed list admits; @c nullptr accepts every peer
     *  that list admits.
     *  Under IKpsk2 it is asked once message 1 has read, and false stops the
     *  handshake before message 2, so the initiator gets no reply. Under XKpsk3
     *  it is asked while message 3 reads, after message 2 has gone out, and false
     *  refuses message 3; the key it sees is message 3's claim, which that
     *  message proves only when it opens, after this check and @c peer_psk have
     *  answered.
     *  An initiator never reaches it: it chose @c remote_static_pub itself, and
     *  message 2 proves the responder holds the matching private half. Entered
     *  from a worker inside @c unseal, and one config backs any number of
     *  conns, so several workers reach it at once.
     */
    bool               (*verify_peer)(void *ctx,
                                      const uint8_t peer_pub[duct_noise_key_size]);
    void                *verify_ctx; /**< Context handed to @c verify_peer, @c peer_psk and @c hello_ok unchanged. */
    /** @brief Responder-side PSK lookup, one PSK per peer.
     *  Asked for a peer the allowed list and @c verify_peer admit, with what
     *  message 1 carried: under IKpsk2 once message 1 has authenticated its
     *  static key, and in a rekey, the payload whole — the @c hello_len bytes of
     *  hello then its zero padding, never shorter than the peer's own hello;
     *  under XKpsk3 while message 3 reads, the @c hello_len bytes kept behind
     *  the peer's key, zero-filled where message 1's payload ran short. A
     *  responder that admits hellos of more than one length reads the payload's
     *  lead to tell them. On
     *  true the PSK in @c out_psk, @c duct_noise_key_size bytes the engine lends, is
     *  mixed into message 2 under IKpsk2 and into message 3 under XKpsk3 in place of
     *  @c psk. False refuses the peer as @c verify_peer returning false does, and
     *  @c out_psk is then not read. A rekey message 1 of an admitted peer asks again
     *  with its own hello, and a refusal there is turned away like a forged message.
     *  Unset, @c psk stands.
     *  Entered from a worker inside @c unseal, and one config backs any number of
     *  conns, so several workers reach it at once.
     */
    bool               (*peer_psk)(void *ctx, const uint8_t peer_pub[duct_noise_key_size],
                                   duct_view_u8 hello, uint8_t out_psk[duct_noise_key_size]);
    /** @brief Wire key keying the mask over each handshake message's ephemeral key.
     *  All-zero keys the mask with @c psk. A responder unmasks message 1 before it
     *  knows which peer sent it, so the key is one all its peers share, and both
     *  ends of a conn hold the same key.
     */
    uint8_t              wire_key[duct_noise_key_size];
    /** @brief Leading bytes of message 1's payload that are the hello.
     *  0: none. An initiator sends @c hello in every message 1, rekeys
     *  included, and a responder reads this many bytes of it. Both ends
     *  configure the same length; a responder whose callbacks stand asks them
     *  about the payload whole, so a peer carrying an older, shorter hello is
     *  not refused for its length, and one without them refuses a payload
     *  shorter than this.
     */
    size_t               hello_len;
    /** @brief Hello bytes an initiator sends, @c hello_len of them.
     *  Opaque to the engine, and the caller's storage: it outlives the engine
     *  as the rest of the config does, and a config that never acts as an
     *  initiator leaves it null. A responder hands the payload the bytes lead
     *  to @c hello_ok under XKpsk3 and to @c peer_psk, and keeps @c hello_len
     *  bytes of it behind the peer's key as
     *  its identity, so @c on_peer_auth and the session's join key carry the
     *  key then the hello.
     */
    const uint8_t        *hello;
    /** @name Opening packets
     *  An initiator on a dialed conn whose wire has an @c opening_ceiling puts the
     *  packets @c opening_next supplies on the wire ahead of message 1, bare of the
     *  wire's PDU prefix: one datagram each on a datagram conn, one write each on a
     *  stream conn, where at most eight fit, seven behind a stream lead, and the
     *  peer has to read them off the stream before its handshake begins. A
     *  responder, a wire without a ceiling and a config without the callback
     *  send none.
     *  @{ */
    /** @brief Write opening packet @p idx, counting from 0, into @p out and
     *  return its length.
     *  @p cap is the room in @p out: the wire's @c opening_ceiling, at most the
     *  engine's @c pdu_ct_max. A length of 0 ends the opening, and so does one
     *  past @p cap, whose packet is not sent. The engine asks for packet 0, 1, ...
     *  in turn and sends the bytes as written.
     *  Entered from a worker at each dial, and one config backs any number of
     *  conns, so several workers reach it at once.
     */
    size_t             (*opening_next)(void *ctx, unsigned idx, uint8_t *out, size_t cap);
    void                *opening_ctx; /**< Handed to @c opening_next unchanged. */
    /** @} */
    /** @brief Suite of a conn's first exchange.
     *  A pattern at or past @c noise_pattern_count fails @c create.
     */
    duct_noise_suite_t   suite;
    /** @brief XKpsk3 responder's check of the hello in message 1.
     *  Asked once message 1 has read, with the payload it carried whole — the
     *  @c hello_len bytes of hello, then its zero padding, never shorter than
     *  the peer's own hello; only an empty payload is refused without asking —
     *  ahead of any answer. False refuses the message, so no message 2
     *  goes out. @c nullptr admits every hello; an IKpsk2 responder never asks it.
     *  Handed @c verify_ctx. Entered from a worker inside @c unseal, and one
     *  config backs any number of conns, so several workers reach it at once.
     */
    bool               (*hello_ok)(void *ctx, duct_view_u8 hello);
    /** @brief First resend delay of an XKpsk3 handshake message, milliseconds.
     *  Read by an initiator on the datagram vtbl alone; 0 never resends. The last
     *  message sent leaves again after this delay, then after twice, four times and
     *  eight times it, so the resends come at 1, 3, 7 and 15 times the delay after
     *  the first send, four at most, and the split starts the count again for
     *  message 3. The peer's first authentic PDU ends them. A resend is the message
     *  as first sent; a responder that holds it already takes it as a repeat.
     */
    uint16_t             hs_rto_ms;
} duct_noise_cfg_t;

/** @brief Noise engine vtbl whose PDUs lead with a 2-byte big-endian length.
 *
 *  Each PDU carries a length of its own, so the vtbl needs no TLS record header
 *  and no wire but @ref duct_wire_create_sealed. A wire built from it carries
 *  one @ref duct_seal_role_t, and an initiator emits message 1 without waiting
 *  for inbound bytes. Sets @c fl_seal_dgram_ok: every PDU carries its own
 *  sequence number and a replay window, so a datagram listener admits it.
 */
const duct_seal_engine_vtbl_t *duct_noise_vtbl(void);

/** @brief Noise engine vtbl for a datagram wire.
 *
 *  It is @ref duct_noise_vtbl without the length prefix and with a shorter
 *  sequence number. A datagram is one PDU and the record header already delimits
 *  it, so every PDU leads with the low 4 bytes of the 64-bit counter its nonce
 *  is built from. The receiver rebuilds the counter as the one nearest the
 *  highest it has accepted that has those bytes; a datagram more than 2^31
 *  counters from that one decrypts under a nonce the sender never used and is
 *  dropped.
 *
 *  @c pdu_hdr_size is 0, @c pdu_len unset and @c pdu_overhead 4 bytes less than
 *  @ref duct_noise_vtbl's. A @c seal_framing_datagram wire admits it and a
 *  stream wire refuses it. Both ends of a conn use this variant or neither: a
 *  mixed pair refuses each other's PDUs.
 */
const duct_seal_engine_vtbl_t *duct_noise_vtbl_dgram(void);

/** @brief Copy the stream variant, @c duct_noise_vtbl, into @p out with
 *  @p hs_budget as @c engine_hs_budget.
 *
 *  0 keeps the default. No-op on @c nullptr @p out.
 */
void duct_noise_vtbl_make(duct_seal_engine_vtbl_t *out, size_t hs_budget);

#ifdef __cplusplus
}
#endif

#endif
