/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_tls_openssl.c
 *  @brief OpenSSL memory-BIO adapter.
 *
 *  An @c SSL object is irreversibly stateful: once a record's bytes reach
 *  @c BIO_write, @c SSL_do_handshake / @c SSL_read may already have advanced
 *  past them. @c unseal therefore answers every record with one of two
 *  verdicts — @c rc_ok once its bytes are absorbed, even with the handshake
 *  or a cleartext frame still in progress, or @c rc_invalid_arg on a fatal
 *  one. @ref s_unseal carries the full mapping.
 */

#include "duct_tls_openssl.h"
#include "duct_core.h"

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>

#include <string.h>

/** @brief Real TLS record cleartext cap.
 *  Pinned into the @c SSL via @c create's @c SSL_set_max_send_fragment, so
 *  @c seal's per-chunk @c SSL_write calls and @c seal_size's formula derive
 *  one record count.
 */
static constexpr size_t s_record_ct_max = 16384u;
/** @brief Body-only per-record overhead reported as
 *  @c duct_seal_engine_vtbl_t::pdu_overhead.
 *  1-byte TLS 1.3 inner content-type + 16-byte max AEAD tag — AES-GCM and
 *  ChaCha20-Poly1305 both use 16. Exact for every suite @c create's pinned
 *  TLS 1.3 can negotiate.
 */
static constexpr size_t s_record_overhead = 17u;
/** @brief Default @c engine_hs_budget for this vtbl.
 *  Generous for one small EC leaf certificate's whole TLS 1.3 flight —
 *  ServerHello..Finished, no intermediates; a large RSA chain needs more.
 */
static constexpr size_t s_engine_hs_budget = 16384u;

typedef struct {
    struct duct_seal_engine base;
    SSL *ssl;
    /** @brief Per-conn scratch, s_record_ct_max bytes.
     *  Shared by seal()'s per-record cleartext staging and by wbio-draining
     *  in unseal/close_notify; this codec's single worker-thread owner
     *  serializes the two uses.
     */
    duct_ptr_t(uint8_t) scratch;
} openssl_engine_t;

static duct_seal_engine_t *s_create(const duct_seal_engine_vtbl_t *self, void *cfg, duct_seal_role_t role)
{
    /* A role naming neither side is refused here as well as at wire
     * construction: duct_tls_openssl_vtbl and _vtbl_make are public, so this
     * create is reachable without duct_wire_create_sealed ever validating one.
     * The ternary below reads every other value as the initiator side, so an
     * unchecked seal_role_unset puts a responder into a client handshake. */
    bool role_ok = duct_seal_role_valid(role);
    duct_do_if(!role_ok, return nullptr);

    BIO *rbio = nullptr,
        *wbio = nullptr;
    openssl_engine_t *e = nullptr;

    auto ssl = SSL_new((SSL_CTX *)cfg);
    duct_do_if(!ssl, return nullptr);
    if (!SSL_set_min_proto_version(ssl, TLS1_3_VERSION)
        || !SSL_set_max_proto_version(ssl, TLS1_3_VERSION)
        || !SSL_set_max_send_fragment(ssl, (long)s_record_ct_max))
        goto fail;
    SSL_set_options(ssl, SSL_OP_NO_RENEGOTIATION);

    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());
    if (!rbio || !wbio)
        goto fail;
    SSL_set_bio(ssl, rbio, wbio); /* ssl owns both from here on */
    rbio = wbio = nullptr;        /* cleared: the fail path frees them via SSL_free */
    role == seal_role_responder ? SSL_set_accept_state(ssl)
                                : SSL_set_connect_state(ssl);

    e = duct_new(openssl_engine_t);
    if (!e)
        goto fail;
    e->ssl = ssl;
    e->scratch = duct_new(uint8_t, s_record_ct_max);
    if (!e->scratch)
        goto fail;
    e->base.vtbl = self;
    return &e->base;

fail:
    if (rbio) BIO_free(rbio);
    if (wbio) BIO_free(wbio);
    SSL_free(ssl); /* also frees rbio/wbio once SSL_set_bio has run */
    duct_del(e);   /* null-safe: frees the scratch with the engine */
    return nullptr;
}

static void s_destroy(duct_seal_engine_t *eng)
{
    auto e = DUCT_CAST(openssl_engine_t, base, eng);
    SSL_free(e->ssl);
    duct_del(e->scratch);
    duct_del(e);
}

/** @brief Drain every byte OpenSSL has queued for egress into
 *  @p ctx->tx_append.
 *
 *  Queued egress is a handshake flight, an alert, or a session ticket;
 *  drained s_record_ct_max per call.
 *  @return false when tx_append refused the bytes, engine_hs_budget
 *  exhausted; the caller turns that into a fatal result, since draining
 *  already took those bytes out of wbio.
 */
static bool s_drain_wbio(openssl_engine_t *e, duct_unseal_ctx_t *ctx)
{
    auto wbio = SSL_get_wbio(e->ssl);
    for (size_t pending; (pending = (size_t)BIO_pending(wbio)) > 0u; ) {
        size_t chunk = duct_min(pending, s_record_ct_max);
        int n = BIO_read(wbio, duct_at(e->scratch), (int)chunk);
        /* On a memory BIO owned by this one worker thread, BIO_read hands
         * over exactly what BIO_pending just reported. */
        if (n <= 0)
            return false;
        if (!ctx->tx_append(ctx, (duct_view_u8){ .data = duct_at(e->scratch), .size = (size_t)n }))
            return false;
    }
    return true;
}

/** @brief Consume one full TLS record.
 *
 *  Io-side framing already guarantees @p record is exactly one record,
 *  header included. @c BIO_write comes first and consumes the record for
 *  good: from there on @c SSL_do_handshake / @c SSL_read may have advanced
 *  past those bytes, so every outcome below is terminal for this record.
 *  - Mid-handshake, @c SSL_ERROR_WANT_READ: bytes absorbed, the next
 *   handshake step awaits more — @c rc_ok, no cleartext.
 *  - Post-handshake, @c SSL_ERROR_ZERO_RETURN, the peer's own TLS
 *   close_notify, or @c SSL_ERROR_WANT_READ, a control message such as a
 *   session ticket: @c rc_ok, no cleartext; the io thread owns close
 *   detection.
 *  - Any other @c SSL_get_error result, or @c tx_append failing while
 *   draining egress: @c rc_invalid_arg, fatal.
 */
static duct_result_t
s_unseal(duct_seal_engine_t *eng, duct_view_u8 record, duct_unseal_ctx_t *ctx)
{
    auto e = DUCT_CAST(openssl_engine_t, base, eng);
    auto rbio = SSL_get_rbio(e->ssl);
    int wrote = BIO_write(rbio, record.data, (int)record.size);
    duct_do_if(wrote != (int)record.size, return rc_invalid_arg);

    if (!SSL_is_init_finished(e->ssl)) {
        int rc = SSL_do_handshake(e->ssl);
        if (rc != 1) {
            int err = SSL_get_error(e->ssl, rc);
            duct_do_if(err != SSL_ERROR_WANT_READ, return rc_invalid_arg);
        }
    } else {
        size_t cap = 0u;
        auto ct = (uint8_t *)ctx->reserve(ctx, &cap);
        int n = SSL_read(e->ssl, ct, (int)cap);
        if (n <= 0) {
            int err = SSL_get_error(e->ssl, n);
            duct_do_if(err != SSL_ERROR_ZERO_RETURN && err != SSL_ERROR_WANT_READ,
                      return rc_invalid_arg);
        } else {
            bool published = ctx->commit(ctx, (size_t)n);
            duct_do_if(!published, return rc_invalid_arg);
        }
    }
    return s_drain_wbio(e, ctx) ? rc_ok : rc_invalid_arg;
}

/** @brief Sealed byte count for @p ct_len.
 *
 *  0 while the handshake runs, otherwise the ceil-with-a-floor-of-one
 *  per-record formula the TLS wire's own tx_bound uses. A pure
 *  calculation over s_record_ct_max/s_record_overhead, the same constants
 *  s_seal chunks by, so the two agree on the byte count s_tls_on_pack
 *  reserves its TX span from.
 */
static size_t s_seal_size(duct_seal_engine_t *eng, size_t ct_len)
{
    auto e = DUCT_CAST(openssl_engine_t, base, eng);
    if (!SSL_is_init_finished(e->ssl))
        return 0u;
    size_t n = ct_len / s_record_ct_max;
    if (ct_len % s_record_ct_max != 0u || n == 0u)
        ++n;
    return ct_len + n * (duct_tls_record_hdr_size + s_record_overhead);
}

/** @brief Seal @p spans as one logical cleartext stream into @p dst.
 *
 *  One @c SSL_write per s_record_ct_max-sized chunk keeps the record count
 *  equal to seal_size's own `n`, which the reserved @p dst span is sized for.
 *  Each chunk's cleartext is gathered into the reusable @c scratch buffer
 *  first, since @c SSL_write takes one contiguous span, then sealed straight
 *  into @p dst at the running offset.
 *
 *  A 0-byte @p total aborts: @c SSL_write emits no record for it and @c seal
 *  reports no error, so seal_size's reserved span reaches the peer
 *  uninitialized. The TLS wire's own on_pack keeps that case away from
 *  here while this vtbl leaves @c seals_empty false.
 */
static void s_seal(duct_seal_engine_t *eng, const duct_view_u8 *spans, size_t n_spans, void *dst)
{
    auto e = DUCT_CAST(openssl_engine_t, base, eng);
    auto out = (uint8_t *)dst;
    size_t total = 0u;
    for (size_t i = 0u; i < n_spans; ++i)
        total += spans[i].size;
    duct_fatal(total == 0u);

    size_t span_i = 0u, span_off = 0u, remaining = total;
    while (remaining > 0u) {
        size_t chunk = duct_min(remaining, s_record_ct_max);
        size_t written = 0u;
        while (written < chunk) {
            if (span_off == spans[span_i].size) { ++span_i; span_off = 0u; continue; }
            size_t avail = spans[span_i].size - span_off;
            size_t take = duct_min(avail, chunk - written);
            memcpy(duct_at(e->scratch) + written, (const uint8_t *)spans[span_i].data + span_off, take);
            span_off += take;
            written += take;
        }
        int wrote = SSL_write(e->ssl, duct_at(e->scratch), (int)chunk);
        duct_fatal(wrote != (int)chunk);
        auto wbio = SSL_get_wbio(e->ssl);
        int pending = BIO_pending(wbio);
        /* One SSL_write(chunk) queues exactly one app-data record
         * (chunk + hdr + overhead). Checked before BIO_read: a record
         * coalesced alongside it — KeyUpdate, a deferred ticket, since the
         * SSL_CTX is the caller's own — puts more in the BIO than seal_size
         * budgeted for this chunk, and BIO_read overruns the reserved span. */
        duct_fatal((size_t)pending != chunk + duct_tls_record_hdr_size + s_record_overhead);
        int got = BIO_read(wbio, out, pending);
        duct_fatal(got != pending);
        out += got;
        remaining -= chunk;
    }
}

static void s_close_notify(duct_seal_engine_t *eng, duct_unseal_ctx_t *ctx)
{
    auto e = DUCT_CAST(openssl_engine_t, base, eng);
    SSL_shutdown(e->ssl); /* first call sends our close_notify and returns
                             at once, with the peer's reply still outstanding */
    duct_discard s_drain_wbio(e, ctx);
}

static const duct_seal_engine_vtbl_t s_vtbl = {
    .name = "tls",
    .create = s_create,
    .destroy = s_destroy,
    .unseal = s_unseal,
    .pdu_hdr_size = duct_tls_record_hdr_size,
    .pdu_len = duct_tls_record_len,
    .pdu_overhead = s_record_overhead,
    .pdu_ct_max = s_record_ct_max,
    .engine_hs_budget = s_engine_hs_budget,
    .seal_size = s_seal_size,
    .seal = s_seal,
    .close_notify = s_close_notify,
};

const duct_seal_engine_vtbl_t *duct_tls_openssl_vtbl(void)
{
    return &s_vtbl;
}

void duct_tls_openssl_vtbl_make(duct_seal_engine_vtbl_t *out, size_t hs_budget)
{
    duct_do_if(!out, return);
    *out = s_vtbl;
    out->engine_hs_budget = hs_budget != 0u ? hs_budget : s_engine_hs_budget;
}

static duct_seal_engine_t *s_client_create(const struct duct_seal_engine_vtbl *self, void *cfg, duct_seal_role_t role)
{
    auto cc = (duct_tls_client_cfg_t *)cfg;
    duct_do_if(!cc || !cc->ctx, return nullptr);
    auto e = DUCT_CAST(openssl_engine_t, base, s_create(self, cc->ctx, role));
    duct_do_if(!e, return nullptr);
    if (cc->sni && !SSL_set_tlsext_host_name(e->ssl, cc->sni)) {
        s_destroy(&e->base);
        return nullptr;
    }
    return &e->base;
}

static void s_start(duct_seal_engine_t *eng, duct_unseal_ctx_t *ctx)
{
    auto e = DUCT_CAST(openssl_engine_t, base, eng);
    duct_discard SSL_do_handshake(e->ssl);
    duct_discard s_drain_wbio(e, ctx);
}

static const duct_seal_engine_vtbl_t s_client_vtbl = {
    .name = "tls-client",
    .create = s_client_create,
    .destroy = s_destroy,
    .unseal = s_unseal,
    .start = s_start,
    .pdu_hdr_size = duct_tls_record_hdr_size,
    .pdu_len = duct_tls_record_len,
    .pdu_overhead = s_record_overhead,
    .pdu_ct_max = s_record_ct_max,
    .engine_hs_budget = s_engine_hs_budget,
    .seal_size = s_seal_size,
    .seal = s_seal,
    .close_notify = s_close_notify,
};

const duct_seal_engine_vtbl_t *duct_tls_openssl_client_vtbl(void)
{
    return &s_client_vtbl;
}
