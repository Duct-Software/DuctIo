/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_tls.h
 *  @brief TLS wire — sealed RX/TX pipeline over a pluggable crypto engine.
 *
 *  The wire frames records and drives a @ref duct_seal_engine_vtbl_t, the seam
 *  an integrator implements against a TLS library of their choice. RX unseals
 *  io-posted records on the worker; TX packs responses through
 *  @c seal_size/@c seal into wire-reserved TX spans; handshake egress rides
 *  @c unseal's own @c ctx (@ref duct_unseal_ctx_t).
 *
 *  @see @ref duct_wire_t::unseal, @ref duct_wire_t::inner for the sealed-wire
 *  contract this header's constructor plugs into.
 *  @see @ref duct_seal_engine_vtbl_t for the crypto-engine contract.
 */

#ifndef DUCT_TLS_H
#define DUCT_TLS_H

#include "duct_seal_engine.h"
#include "duct_wire.h"
#include "duct_types.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief TLS record header: content-type(1) legacy-version(2) length(2). */
static constexpr size_t duct_tls_record_hdr_size = 5u;

/** @brief Whole-record byte count for the record starting at @p hdr.
 *
 *  The @ref duct_seal_engine_vtbl_t::pdu_len every TLS-framing engine points
 *  at, so the format is decoded in one place. 0 on a zero content-type, which
 *  no TLS record carries. Reads through byte 4, so it pairs only with
 *  @c pdu_hdr_size = @ref duct_tls_record_hdr_size.
 */
static inline size_t duct_tls_record_len(duct_view_u8 hdr)
{
    auto h = (const unsigned char *)hdr.data;
    if (h[0] == 0u)
        return 0u;
    return duct_tls_record_hdr_size + duct_load_be16(h + 3);
}

#ifdef __cplusplus
}
#endif

#endif /* DUCT_TLS_H */
