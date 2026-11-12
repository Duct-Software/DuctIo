/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_tls_openssl.h
 *  @brief OpenSSL memory-BIO sealing adapter.
 *
 *  Fills a @ref duct_seal_engine_vtbl_t. Built only when
 *  @c DUCT_WITH_OPENSSL is ON.
 *
 *  TLS 1.3 only, pinned per-instance in @c create regardless of what the
 *  caller's own @c SSL_CTX allows — keeps @ref duct_seal_engine_vtbl_t::pdu_overhead
 *  a single safe constant across every cipher suite TLS 1.3 negotiates:
 *  AES-GCM / ChaCha20-Poly1305, both 16-byte tags. Serves the server role:
 *  the vtbl fills @c create/@c unseal/@c seal_size/@c seal/@c close_notify,
 *  and a client-role first flight needs a @c start hook on top.
 *
 *  @c seals_empty stays false, since @c SSL_write emits a record only for a
 *  non-empty cleartext: with @c inner == nullptr a sealed wire drops an
 *  empty response, and @c s_seal's @c duct_fatal guards that invariant.
 *
 *  @see @ref duct_seal_engine_vtbl_t for the contract this implements.
 */

#ifndef DUCT_TLS_OPENSSL_H
#define DUCT_TLS_OPENSSL_H

#include "duct_seal_engine.h"
#include "duct_tls.h"

#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief The OpenSSL engine vtbl.
 *
 *  Pass to @ref duct_wire_create_sealed. @c engine_cfg for this vtbl must be
 *  a caller-owned @c SSL_CTX* cast to
 *  @c void*, fully configured — certificate, key, verify mode, ALPN,
 *  session cache, anything OpenSSL itself exposes — before the first conn
 *  binds. Borrowed, must outlive every conn this wire ever creates; one
 *  @c SSL_CTX backs any number of conns, each taking a cheap @c SSL_new.
 */
const duct_seal_engine_vtbl_t *duct_tls_openssl_vtbl(void);

/** @brief Copy this vtbl into @p out with @p hs_budget as
 *  @c engine_hs_budget.
 *
 *  0 keeps the default. No-op on @c nullptr @p out.
 */
void duct_tls_openssl_vtbl_make(duct_seal_engine_vtbl_t *out, size_t hs_budget);

/** @brief Configuration of the initiator-side vtbl.
 *  @c sni names a NUL-terminated server name the ClientHello carries, read and
 *  copied at each conn's creation; null leaves the hello without one. The
 *  storage is the caller's and may change between conns.
 */
typedef struct {
    SSL_CTX *ctx;
    const char *sni;
} duct_tls_client_cfg_t;

/** @brief The initiator-side vtbl: @c engine_cfg is a @c duct_tls_client_cfg_t
 *  and @c start drives the first flight, ClientHello ahead, so a dial's first
 *  bytes on the wire are a TLS 1.3 record without a hand outside the engine.
 */
const duct_seal_engine_vtbl_t *duct_tls_openssl_client_vtbl(void);

#ifdef __cplusplus
}
#endif

#endif /* DUCT_TLS_OPENSSL_H */
