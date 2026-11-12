/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file tls_engine_null.h
 * @brief Deterministic fake @c duct_seal_engine_vtbl_t for tls_null_test.c —
 * XOR "cipher" + a 2-byte fake tag, no OS entropy, so both sides of a test
 * can construct/verify records without a real crypto library.
 *
 * Record body shape (what follows the 5-byte TLS record header):
 * @c [ciphertext(ct_len) tag(2)], ciphertext[i] = cleartext[i] ^ 0xA5, and
 * @c tag = { (uint8_t)ct_len ^ 0x5A, xor_checksum(cleartext) ^ 0x3C }. The
 * first record on any conn is treated as a handshake: @c unseal replies
 * with @ref tls_null_server_hello via @c ctx->tx_append and appends no
 * cleartext; every later record is application data, decrypted and tag-
 * checked for real.
 *
 * TX: @c seal_size/@c seal segment at @c pdu_ct_max bytes of
 * cleartext per record, same body shape as RX, at least one record even
 * for an empty cleartext (mirrors @ref duct_wire_t::tx_bound's own rule).
 * @c close_notify emits one record (type 3) with a single fixed marker
 * byte, unencrypted (real TLS close_notify is a sealed alert; this fake
 * skips sealing it since nothing here ever needs to unseal it back).
 *
 * @c dgram_ok is set, so a wire built on this vtbl binds a datagram listener
 * as well as a stream one. The replay window that claim stands for on a real
 * engine has no counterpart here — every test drives this fake in order.
 */

#ifndef TLS_ENGINE_NULL_H
#define TLS_ENGINE_NULL_H

#include "duct_seal_engine.h"
#include "duct_tls.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

/** @brief Frame @p body as one TLS record of @p type into @p out.
 *  @return bytes written: the record header plus @p len. */
size_t tls_null_record(uint8_t *out, uint8_t type, const void *body, size_t len);

/** @brief Fake-seal @p ct into @p out (ciphertext + 2-byte tag), @p out_cap
 *  bytes available. @return bytes written, or 0 if @p out_cap is too small. */
size_t tls_null_seal(const void *ct, size_t ct_len, uint8_t *out, size_t out_cap);

/** @brief Fake-unseal one record body (ciphertext + 2-byte tag, no 5-byte
 *  record header) into @p ct — the client test side's own counterpart to
 *  @ref tls_null_seal, for verifying what the engine's real @c seal
 *  produced. @return cleartext bytes written, or @c SIZE_MAX if @p ct_cap
 *  is too small or the tag does not match. */
size_t tls_null_unseal_body(const uint8_t *body, size_t body_len, uint8_t *ct, size_t ct_cap);

/** @brief The server's fixed, deterministic handshake-reply payload (the 4
 *  bytes after a reply record's own 5-byte header). */
extern const uint8_t tls_null_server_hello[4];

/** @brief The server's fixed, deterministic close_notify payload (the sole
 *  byte after a close_notify record's own 5-byte header, record type 3). */
extern const uint8_t tls_null_close_notify_marker;

/** @brief Total @c unseal calls across every engine instance so far —
 *  tests snapshot before/after a scenario to prove no extra (or missing)
 *  unseal ran, e.g. across a mid-record defer/replay. */
unsigned tls_null_unseal_calls(void);

/** @brief Total @c create calls across every engine instance so far. */
unsigned tls_null_create_calls(void);

/** @brief Total @c destroy calls across every engine instance so far. */
unsigned tls_null_destroy_calls(void);

/** @brief Total @c close_notify calls across every engine instance so far. */
unsigned tls_null_close_notify_calls(void);

/** @brief The peer address the latest @c unseal's context carried. The caller
 *  reads it once the frame that unseal committed has logged — that log is the
 *  ordering point — and no later unseal runs. */
void tls_null_last_peer(duct_peer_t *out);

/** @brief The vtbl itself — one static instance, shared by every wire/conn
 *  a test builds (per-conn state lives in the @c duct_seal_engine_t @c
 *  create returns, not here). */
const duct_seal_engine_vtbl_t *tls_null_vtbl(void);

#endif /* TLS_ENGINE_NULL_H */
