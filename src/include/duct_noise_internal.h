/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_noise_internal.h
 *  @brief Noise_IKpsk2 and Noise_XKpsk3 handshakes over 25519, ChaChaPoly and
 *  BLAKE2s, and the transport crypto core — internal, xport/wire-agnostic (no
 *  @c duct_wire_t / @c duct_xport_t dependency).
 *
 *  The static-key half — @ref duct_noise_keypair_t and its two constructors —
 *  is integrator-facing and lives on the public surface, which this header
 *  includes.
 *
 *  Noise Protocol Framework implementation using OpenSSL primitives (X25519,
 *  ChaCha20-Poly1305, BLAKE2s). @ref duct_noise_hs_t is transient handshake
 *  state, consumed by @ref duct_noise_hs_split into a long-lived
 *  @ref duct_noise_transport_t; the two never share a lifetime.
 *
 *  Scope: Noise handshakes and transport AEAD with receive anti-replay.
 *  Callers manage packet framing, demultiplexing, and handshake-replay policy;
 *  this module carries an opaque handshake payload.
 *
 *  Under @c DUCT_HANDSHAKE_MASK the ephemeral key leading message 1 and message 2
 *  of either pattern crosses the wire exclusive-ored with a value keyed by the
 *  handshake's mask key and the message's closing tag
 *  (@ref duct_noise_ephemeral_mask). The transcript hashes the key itself, so the
 *  handshake's state and keys are the ones the unmasked build derives.
 */

#ifndef DUCT_NOISE_INTERNAL_H
#define DUCT_NOISE_INTERNAL_H

#include "duct_noise.h"
#include "duct_core.h"
#include "duct_types.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

static constexpr size_t duct_noise_tag_size = 16u;

/** @brief Opaque, transient Noise handshake state of one pattern, one instance per
 *  handshake attempt.
 *
 *  Discarded via @ref duct_noise_hs_destroy once @ref duct_noise_hs_split
 *  runs or the attempt is abandoned. Never reused across handshakes.
 */
typedef struct duct_noise_hs duct_noise_hs_t;

/** @brief Start a Noise_IKpsk2 handshake.
 *
 *  It is @ref duct_noise_hs_create_for with @c noise_pattern_ikpsk2 and an empty
 *  prologue.
 *
 *  @param local_static       This side's own static keypair; borrowed for the
 *                            call only (copied in).
 *  @param remote_static_pub  The peer's static public key. Required (non-null)
 *                            for the initiator — IK's pre-message (`<- s`)
 *                            assumes the initiator already knows it out of
 *                            band. @c nullptr for the responder: IK does not
 *                            give the responder the initiator's identity in
 *                            advance — @ref duct_noise_hs_read_msg1 learns
 *                            and returns it.
 *  @param psk                32-byte key that keys the mask over each ephemeral
 *                            key and, until @ref duct_noise_hs_set_psk
 *                            replaces it, the `psk2` token; required.
 *  @return New handshake state, or @c nullptr for an initiator without
 *          @p remote_static_pub, on allocation failure or on an OpenSSL failure.
 */
duct_nonnull(1, 3) duct_noise_hs_t *
duct_noise_hs_create(const duct_noise_keypair_t *local_static,
                    const uint8_t remote_static_pub[32],
                    const uint8_t psk[32],
                    bool is_initiator);

/** @brief Start a handshake of @p pattern.
 *
 *  @param local_static       This side's own static keypair; copied in.
 *  @param remote_static_pub  The responder's static public key, the `<- s`
 *                            pre-message of both patterns. Required (non-null)
 *                            for the initiator. @c nullptr for the responder,
 *                            which mixes its own static key in its place.
 *  @param psk                32-byte key that keys the mask over each ephemeral
 *                            key and, until @ref duct_noise_hs_set_psk replaces
 *                            it, the `psk` token; required.
 *  @param prologue           Bytes hashed into the transcript ahead of the
 *                            pre-message. Both ends pass the same bytes, empty
 *                            for none.
 *  @return New handshake state, or @c nullptr for a @p pattern past the last, an
 *          initiator without @p remote_static_pub, on allocation failure or on
 *          an OpenSSL failure.
 */
duct_nonnull(2, 4) duct_noise_hs_t *
duct_noise_hs_create_for(duct_noise_pattern_t pattern,
                         const duct_noise_keypair_t *local_static,
                         const uint8_t remote_static_pub[32],
                         const uint8_t psk[32],
                         bool is_initiator,
                         duct_view_u8 prologue);

/** @brief Release handshake state.
 *  The keys it holds are wiped. Safe on @c nullptr.
 */
void duct_noise_hs_destroy(duct_noise_hs_t *hs);

/** @brief Lend @p hs the caller's store for the Diffie-Hellman between this
 *  side's static key and the peer's.
 *
 *  IKpsk2 writes that one `ss`, the pattern's own name for a DH between two
 *  static keys; its three others each take an ephemeral key and so are new
 *  every handshake. Two statics outlive a handshake, and a caller that does
 *  too spends this DH once and reads @p cache at every rekey after.
 *  All-zero says the store is empty; a real answer never is.
 *
 *  @p peer is the static public key the entry belongs to, and @p hs reads and
 *  fills the entry only where the static it was handed matches it: a responder
 *  learns that static from message 1, before its own caller can refuse an
 *  unknown one, so a message under another identity leaves the entry alone.
 *  Both arrays are borrowed and outlive @p hs. XKpsk3 has no `ss`: the store
 *  goes unread and unwritten there.
 */
duct_nonnull(1, 2, 3) void
duct_noise_hs_ss_cache(duct_noise_hs_t *hs, uint8_t cache[32],
                       const uint8_t peer[32]);

/** @brief Replace the key the `psk` token mixes.
 *  The mask key stays as @ref duct_noise_hs_create set it. The token rides
 *  message 2 of IKpsk2 on either side, so the call comes before
 *  @ref duct_noise_hs_write_msg2 on a responder and before
 *  @ref duct_noise_hs_read_msg2 on an initiator; a responder makes it between
 *  reading message 1 and writing message 2, once it knows the peer. It rides
 *  message 3 of XKpsk3, so the initiator calls before
 *  @ref duct_noise_hs_write_msg3_xk and the responder takes its key from the
 *  resolver of @ref duct_noise_hs_read_msg3_xk.
 */
duct_nonnull(1, 2) void
duct_noise_hs_set_psk(duct_noise_hs_t *hs, const uint8_t psk[duct_noise_key_size]);

/** @brief Fixed-size portion of message 1: ephemeral plus encrypted static
 *  key.
 *
 *  The payload's encrypted length, its own size plus
 *  @ref duct_noise_tag_size, follows it; @ref duct_noise_hs_msg1_size gives
 *  the whole message size.
 */
static constexpr size_t duct_noise_msg1_fixed_size =
    duct_noise_key_size + (duct_noise_key_size + duct_noise_tag_size);

/** @brief Whole message-1 byte count for a given cleartext payload length. */
static inline size_t duct_noise_hs_msg1_size(size_t payload_len)
{
    return duct_noise_msg1_fixed_size + payload_len + duct_noise_tag_size;
}

/** @brief Least message-2 size, bytes: ephemeral and the AEAD tag, what an
 *  empty payload takes. A padded answer adds its payload length on top. */
static constexpr size_t duct_noise_msg2_size =
    duct_noise_key_size + duct_noise_tag_size;

/** @brief Most padding bytes a handshake message carries in its payload.
 *  The length is drawn fresh per message, varying message 1 and message 2 on
 *  the wire; the bytes are zero, since the handshake AEAD makes the ciphertext
 *  pseudorandom whatever they are. Both ends must build with the same value: a
 *  message read rejects a payload padded past it, so a smaller peer fails the
 *  handshake against a larger one with no distinct error. */
static constexpr size_t duct_noise_hs_pad_max = 128u;

/** @brief Domain byte of the mask over message 1's ephemeral key. */
static constexpr uint8_t duct_noise_mask_msg1 = 1u;
/** @brief Domain byte of the mask over message 2's ephemeral key. */
static constexpr uint8_t duct_noise_mask_msg2 = 2u;

/** @brief Compute the mask a @c DUCT_HANDSHAKE_MASK build XORs into the
 *  ephemeral key leading a handshake message.
 *
 *  Two HMAC-BLAKE2s evaluations: a key from @p psk, the handshake's mask key,
 *  and a fixed label, then, under that key, the domain byte @p msg followed by
 *  @p tag. @p tag is the AEAD
 *  tag closing the message, which is unique to its handshake, travels in the
 *  clear and lies outside the masked bytes. A message replayed to a responder
 *  therefore draws a fresh mask for the answer, and no keystream is spent twice.
 *  Computed in every build; the handshake applies it only in a mask build.
 *
 *  @param msg  @ref duct_noise_mask_msg1 or @ref duct_noise_mask_msg2.
 *  @return false on an OpenSSL failure.
 */
duct_nonnull(1, 3, 4) bool
duct_noise_ephemeral_mask(const uint8_t psk[duct_noise_key_size], uint8_t msg,
                          const uint8_t tag[duct_noise_tag_size],
                          uint8_t out[duct_noise_key_size]);

/** @brief Initiator: write message 1 (`e, es, s, ss` + encrypted @p payload)
 *  into @p out.
 *
 *  @param payload   Cleartext handshake payload (e.g. a caller-chosen replay
 *                  timestamp); @c size may be 0.
 *  @param out_cap   Capacity of @p out; must be at least
 *                  @ref duct_noise_hs_msg1_size(payload.size).
 *  @return false on @p out_cap too small or a wrong pattern or role, which leave
 *         @p hs as it was, or on an OpenSSL failure, which ends the attempt: the
 *         caller destroys @p hs.
 */
duct_nonnull(1, 3) bool
duct_noise_hs_write_msg1(duct_noise_hs_t *hs, duct_view_u8 payload,
                         uint8_t *out, size_t out_cap, size_t *out_len);

/** @brief Responder: read message 1, learning and authenticating the
 *  initiator's static public key as part of decryption (IK's own property —
 *  a garbled or wrong-key message fails AEAD auth here, not later).
 *
 *  @param remote_static_out  Filled with the learned initiator static public
 *                           key on success; the caller checks it against its
 *                           own allowlist/policy — this module makes no
 *                           admission decision itself.
 *  @param payload_out        Decrypted handshake payload, always written;
 *                           @p payload_cap must be at least @p msg's payload
 *                           length (@c msg.size @c - @ref
 *                           duct_noise_msg1_fixed_size @c - @ref
 *                           duct_noise_tag_size) — pass a buffer sized off
 *                           @p msg itself, which the caller already has.
 *  @return false on @p payload_cap too small, a malformed message, or an AEAD
 *         authentication failure: a bad key, wrong PSK or tampered bytes. @p hs
 *         is left unchanged on a false return, so a forged or truncated message
 *         leaves it reusable for the genuine one.
 */
duct_nonnull(1, 3, 4, 6) bool
duct_noise_hs_read_msg1(duct_noise_hs_t *hs, duct_view_u8 msg,
                        uint8_t remote_static_out[32],
                        uint8_t *payload_out, size_t payload_cap,
                        size_t *payload_len_out);

/** @brief Responder: write message 2 (`e, ee, se, psk` + encrypted @p payload)
 *  into @p out.
 *
 *  @param payload  Cleartext handshake payload; @c size may be 0.
 *  @param out_cap  Capacity of @p out; at least @ref duct_noise_msg2_size plus
 *                 @p payload's size.
 *  @return false on @p out_cap too small, a wrong role/state call, or an
 *         OpenSSL failure.
 */
duct_nonnull(1, 3) bool
duct_noise_hs_write_msg2(duct_noise_hs_t *hs, duct_view_u8 payload,
                         uint8_t *out, size_t out_cap, size_t *out_len);

/** @brief Initiator: read message 2, completing mutual authentication (the
 *  `se` DH only succeeds if the responder holds the private key matching the
 *  static public key the initiator already knew).
 *
 *  @return false on a malformed message or an AEAD authentication failure.
 *         @p hs is left unchanged on a false return, so a forged or truncated
 *         message leaves it reusable for the genuine one.
 */
duct_nonnull(1) bool
duct_noise_hs_read_msg2(duct_noise_hs_t *hs, duct_view_u8 msg);

/** @brief Least XKpsk3 message-1 size, bytes: ephemeral and the AEAD tag, what an
 *  empty payload takes. */
static constexpr size_t duct_noise_xk_msg1_fixed_size =
    duct_noise_key_size + duct_noise_tag_size;

/** @brief Least XKpsk3 message-3 size, bytes: the encrypted static key with its
 *  tag and the payload's tag, what an empty payload takes. */
static constexpr size_t duct_noise_xk_msg3_fixed_size =
    duct_noise_key_size + duct_noise_tag_size + duct_noise_tag_size;

/** @brief Whole XKpsk3 message-1 byte count for a given cleartext payload length. */
static inline size_t duct_noise_xk_msg1_size(size_t payload_len)
{
    return duct_noise_xk_msg1_fixed_size + payload_len;
}

/** @brief Whole XKpsk3 message-3 byte count for a given cleartext payload length. */
static inline size_t duct_noise_xk_msg3_size(size_t payload_len)
{
    return duct_noise_xk_msg3_fixed_size + payload_len;
}

/** @brief Resolver of the PSK for the initiator that message 3 has just named.
 *
 *  @p remote_static is that initiator's static public key, decrypted and not yet
 *  tied to a password. On true @p out_psk holds the 32 bytes of the PSK, which the
 *  read copies before it goes on. False refuses the peer and leaves @p out_psk
 *  unread.
 */
typedef bool (*duct_noise_psk_for_t)(void *ctx, const uint8_t remote_static[duct_noise_key_size],
                                     uint8_t out_psk[duct_noise_key_size]);

/** @brief Initiator: write XKpsk3 message 1 (`e, es` + encrypted @p payload) into
 *  @p out.
 *
 *  @param payload  Cleartext handshake payload; @c size may be 0.
 *  @param out_cap  Capacity of @p out; at least
 *                 @ref duct_noise_xk_msg1_size(payload.size).
 *  @return false on @p out_cap too small or a call of another pattern, role or
 *         turn, which leave @p hs as it was, or on an OpenSSL failure, which
 *         ends the attempt: the caller destroys @p hs.
 */
duct_nonnull(1, 3, 5) bool
duct_noise_hs_write_msg1_xk(duct_noise_hs_t *hs, duct_view_u8 payload,
                            uint8_t *out, size_t out_cap, size_t *out_len);

/** @brief Responder: read XKpsk3 message 1. It names no peer: the initiator's
 *  static key arrives in message 3.
 *
 *  @param payload_out  Decrypted handshake payload, always written;
 *                     @p payload_cap must be at least @p msg's payload length,
 *                     @c msg.size @c - @ref duct_noise_xk_msg1_fixed_size.
 *  @return false on @p payload_cap too small, a call of another pattern, role or
 *         turn, a malformed message or an AEAD authentication failure: a message
 *         meant for another server, or tampered bytes. @p hs is left unchanged on
 *         a false return, so a forged or truncated message leaves it reusable for
 *         the genuine one.
 */
duct_nonnull(1, 3, 5) bool
duct_noise_hs_read_msg1_xk(duct_noise_hs_t *hs, duct_view_u8 msg,
                           uint8_t *payload_out, size_t payload_cap,
                           size_t *payload_len_out);

/** @brief Responder: write XKpsk3 message 2 (`e, ee` + encrypted @p payload) into
 *  @p out.
 *
 *  @param payload  Cleartext handshake payload; @c size may be 0.
 *  @param out_cap  Capacity of @p out; at least @ref duct_noise_msg2_size plus
 *                 @p payload's size.
 *  @return false on @p out_cap too small or a call of another pattern, role or
 *         turn, which leave @p hs as it was, or on an OpenSSL failure, which
 *         ends the attempt: the caller destroys @p hs.
 */
duct_nonnull(1, 3, 5) bool
duct_noise_hs_write_msg2_xk(duct_noise_hs_t *hs, duct_view_u8 payload,
                            uint8_t *out, size_t out_cap, size_t *out_len);

/** @brief Initiator: read XKpsk3 message 2, authenticating the responder (the
 *  `ee` DH only succeeds for the holder of the ephemeral key message 1 was sent
 *  to).
 *
 *  @return false on a call of another pattern, role or turn, a malformed message
 *         or an AEAD authentication failure. @p hs is left unchanged on a false
 *         return, so a forged or truncated message leaves it reusable for the
 *         genuine one.
 */
duct_nonnull(1) bool
duct_noise_hs_read_msg2_xk(duct_noise_hs_t *hs, duct_view_u8 msg);

/** @brief Initiator: write XKpsk3 message 3 (`s, se, psk` + encrypted @p payload)
 *  into @p out.
 *
 *  The `psk` token mixes the key @ref duct_noise_hs_set_psk last set, else the
 *  one the state was created with.
 *
 *  @param payload  Cleartext handshake payload; @c size may be 0.
 *  @param out_cap  Capacity of @p out; at least
 *                 @ref duct_noise_xk_msg3_size(payload.size).
 *  @return false on @p out_cap too small or a call of another pattern, role or
 *         turn, which leave @p hs as it was, or on an OpenSSL failure, which
 *         ends the attempt: the caller destroys @p hs.
 */
duct_nonnull(1, 3, 5) bool
duct_noise_hs_write_msg3_xk(duct_noise_hs_t *hs, duct_view_u8 payload,
                            uint8_t *out, size_t out_cap, size_t *out_len);

/** @brief Responder: read XKpsk3 message 3, learning and authenticating the
 *  initiator's static public key and its password.
 *
 *  Once the static key has decrypted and `se` is mixed, @p psk_for is asked for
 *  that key's PSK; the `psk` token mixes the key it writes and the payload's tag
 *  then proves the initiator holds it. A message whose static key does not
 *  authenticate never reaches @p psk_for.
 *
 *  @param remote_static_out  Filled with the learned initiator static public key
 *                           on success; this module makes no admission decision.
 *  @param payload_out        Decrypted handshake payload, always written;
 *                           @p payload_cap must be at least @c msg.size @c -
 *                           @ref duct_noise_xk_msg3_fixed_size.
 *  @return false on @p payload_cap too small, a call of another pattern, role or
 *         turn, a malformed message, a refusal by @p psk_for or an AEAD
 *         authentication failure: a wrong password, a message of another
 *         exchange or tampered bytes. @p hs is left unchanged on a false return,
 *         so a forged or truncated message leaves it reusable for the genuine one.
 */
duct_nonnull(1, 3, 5, 6, 8) bool
duct_noise_hs_read_msg3_xk(duct_noise_hs_t *hs, duct_view_u8 msg,
                           duct_noise_psk_for_t psk_for, void *ctx,
                           uint8_t remote_static_out[duct_noise_key_size],
                           uint8_t *payload_out, size_t payload_cap,
                           size_t *payload_len_out);

/** @brief Sliding anti-replay window width, in bits. */
static constexpr unsigned duct_noise_replay_window_bits = 2048u;
/** @brief Sliding anti-replay window width, in 64-bit words. */
static constexpr unsigned duct_noise_replay_window_words =
    duct_noise_replay_window_bits / 64u;

/** @brief Highest send counter one key set may seal under, 2^64 − 2^16 − 1.
 *
 *  The counter is the AEAD nonce: @ref duct_noise_transport_seal refuses to
 *  seal past this threshold without key rotation. Written as
 *  @c UINT64_MAX @c - @c 2^16.
 */
static constexpr uint64_t duct_noise_seal_counter_max =
    UINT64_MAX - (UINT64_C(1) << 16u);

/** @brief Long-lived post-handshake transport state for one peer.
 *
 *  The two directional ChaCha20-Poly1305 keys from @ref duct_noise_hs_split,
 *  this side's own send counter, the receive-side sliding anti-replay window,
 *  and one cipher context per direction.
 *
 *  Worker-owned, single-thread use, same discipline as this codebase's other
 *  per-conn crypto state (@c duct_wire_codec_t's @c engine). It owns heap
 *  state: assign one only before its first seal or unseal, while both
 *  contexts are still null, and release it through
 *  @ref duct_noise_transport_destroy.
 */
typedef struct duct_noise_transport {
    uint8_t  send_key[32];
    uint8_t  recv_key[32];
    uint64_t send_counter;
    uint64_t replay_top;                                  /**< Highest accepted receive counter. */
    uint64_t replay_bitmap[duct_noise_replay_window_words]; /**< Circular, indexed by counter/64 mod word count. */
    bool     replay_started;                              /**< False until the first receive; see s_replay_accept. */
    uint8_t  counter_size; /**< Bytes of the counter on the wire. A split sets
                             *  @c duct_noise_counter_size; the caller sets
                             *  @c duct_noise_counter_compact_size before the first
                             *  seal or unseal, and both ends of a conn use the
                             *  same. */
    void    *send_ctx; /**< @c EVP_CIPHER_CTX over @c send_key, made on first seal. */
    void    *recv_ctx; /**< @c EVP_CIPHER_CTX over @c recv_key, made on first unseal. */
} duct_noise_transport_t;

/** @brief Bytes of the full counter on the wire. */
static constexpr size_t duct_noise_counter_size = 8u;
/** @brief Bytes of the compact counter on the wire: its low 32 bits.
 *  The receiver takes the counter closest to its highest accepted one that has
 *  them, which is the sender's whenever fewer than 2^31 counters separate the
 *  two; a datagram further off decrypts under another nonce and is dropped. */
static constexpr size_t duct_noise_counter_compact_size = 4u;

/** @brief Release @p t's cipher contexts and wipe its key material.
 *  A no-op on @c nullptr, and correct on a transport that never sealed or
 *  unsealed anything.
 */
void duct_noise_transport_destroy(duct_noise_transport_t *t);

/** @brief Derive @p out's two directional transport keys and reset its
 *  counters/window to the initial state. Does not free @p hs — the caller's
 *  own @ref duct_noise_hs_destroy does that, once, after this call.
 *
 *  @return false if @p hs has not processed the last message of its pattern
 *         (caller error) or an OpenSSL failure.
 */
duct_nonnull(1, 2) bool
duct_noise_hs_split(duct_noise_hs_t *hs, duct_noise_transport_t *out);

/** @brief Take the handshake's exporter, HKDF(ck, h): secret, and bound to
 *  the transcript.
 *  @c h alone hashes public keys and ciphertexts, which anyone watching the
 *  exchange recomputes, so the secret comes from @c ck.
 *  @return false before the handshake completes or on an OpenSSL failure. */
duct_nonnull(1, 2) bool
duct_noise_hs_exporter(const duct_noise_hs_t *hs, uint8_t out[duct_noise_key_size]);

/** @brief Write HKDF(@p key, @p label) into @p len bytes, 1 to 64.
 *  @return false outside that range or on an OpenSSL failure. */
duct_nonnull(1, 2, 3) bool
duct_noise_derive(const uint8_t key[duct_noise_key_size], const char *label,
                  uint8_t *out, size_t len);

/** @brief Sealed transport-data body size for @p pt_len plaintext bytes under a
 *  transport with the full counter: 8-byte counter prefix + ciphertext +
 *  16-byte tag.
 */
static inline size_t duct_noise_transport_seal_size(size_t pt_len)
{
    return duct_noise_counter_size + pt_len + duct_noise_tag_size;
}

/** @brief Sealed body size for @p pt_len plaintext bytes under @p t, its counter
 *  as wide as @p t sends it. */
static inline size_t
duct_noise_transport_seal_size_of(const duct_noise_transport_t *t, size_t pt_len)
{
    return t->counter_size + pt_len + duct_noise_tag_size;
}

/** @brief Seal the @p n plaintext spans, one after the other, as one transport-data
 *  message: @c [counter(8 LE)][ciphertext][tag(16)], the counter its low
 *  @c t->counter_size bytes.
 *
 *  A span may be empty, and @p spans may be null for an @p n of 0, which seals an
 *  empty plaintext.
 *  @param out_cap  Capacity of @p out; must be at least
 *                 @ref duct_noise_transport_seal_size_of for the spans' total size.
 *  @return Bytes written, or 0 on @p out_cap too small, @c send_counter past
 *         @ref duct_noise_seal_counter_max, which only a new handshake clears, or an
 *         OpenSSL failure. @c send_counter advances by one on success only.
 */
duct_nonnull(1, 4) size_t
duct_noise_transport_seal(duct_noise_transport_t *t, const duct_view_u8 *spans, size_t n,
                          uint8_t *out, size_t out_cap);

/** @brief Exclusive-or @p counter's first @p wide bytes with a SipHash draw of
 *  the twelve bytes the sealed message keeps at @p sample under @p key — the
 *  first twelve ciphertext bytes, or the tag's own where the plaintext is
 *  empty; both sides read the same bytes. The cover the seal writes and the
 *  read removes, exposed for the tests that drive the transport against
 *  known-answer vectors. */
duct_nonnull(1, 2, 3) void
duct_noise_counter_cover(const uint8_t key[duct_noise_key_size], uint8_t *counter,
                         const uint8_t *sample, size_t wide);

/** @brief Unseal one transport-data message, checking the sliding anti-replay
 *  window before accepting.
 *
 *  Where @c t->counter_size is @c duct_noise_counter_compact_size the counter is
 *  rebuilt from its low 32 bits and the highest counter accepted so far. A wrong
 *  guess cannot become an accepted message: the nonce comes from the rebuilt
 *  counter, so a datagram that rebuilds to another one fails authentication and
 *  is dropped.
 *
 *  @return false on a truncated message, a replayed/too-old counter (window
 *         miss), or AEAD authentication failure — @p t's counters and window are
 *         unchanged on any false return (the window only advances on a
 *         successful decrypt).
 */
duct_nonnull(1, 3) bool
duct_noise_transport_unseal(duct_noise_transport_t *t, duct_view_u8 sealed,
                           uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* DUCT_NOISE_INTERNAL_H */
