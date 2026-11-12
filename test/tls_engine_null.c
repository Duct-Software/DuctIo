/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

#include "tls_engine_null.h"
#include "duct_core.h"

#include <stdlib.h>
#include <string.h>

static constexpr uint8_t s_xor_key = 0xA5u;
static constexpr uint8_t s_tag_key0 = 0x5Au;
static constexpr uint8_t s_tag_key1 = 0x3Cu;
static constexpr size_t s_max_record = 4096u;
static constexpr size_t s_tag_size = 2u;

const uint8_t tls_null_server_hello[4] = { 'S', 'H', 'L', 'O' };
const uint8_t tls_null_close_notify_marker = 0xC1u;

static atomic_uint s_unseal_calls = 0u;
static atomic_uint s_create_calls = 0u;
static atomic_uint s_destroy_calls = 0u;
static atomic_uint s_close_notify_calls = 0u;
static duct_peer_t  s_last_peer = {};

typedef struct {
    bool handshook;
} s_null_engine_t;

static uint8_t s_checksum(const uint8_t *ct, size_t len)
{
    uint8_t c = 0u;
    for (size_t i = 0u; i < len; ++i)
        c ^= ct[i];
    return c;
}

size_t tls_null_record(uint8_t *out, uint8_t type, const void *body, size_t len)
{
    out[0] = type;
    out[1] = 0u;
    out[2] = 0u;
    out[3] = (uint8_t)(len >> 8u);
    out[4] = (uint8_t)len;
    memcpy(out + duct_tls_record_hdr_size, body, len);
    return duct_tls_record_hdr_size + len;
}

size_t tls_null_seal(const void *ct, size_t ct_len, uint8_t *out, size_t out_cap)
{
    if (out_cap < ct_len + s_tag_size)
        return 0u;
    auto ctb = (const uint8_t *)ct;
    for (size_t i = 0u; i < ct_len; ++i)
        out[i] = ctb[i] ^ s_xor_key;
    out[ct_len] = (uint8_t)ct_len ^ s_tag_key0;
    out[ct_len + 1u] = s_checksum(ctb, ct_len) ^ s_tag_key1;
    return ct_len + s_tag_size;
}

size_t tls_null_unseal_body(const uint8_t *body, size_t body_len, uint8_t *ct, size_t ct_cap)
{
    if (body_len < s_tag_size)
        return SIZE_MAX;
    size_t ct_len = body_len - s_tag_size;
    if (ct_cap < ct_len)
        return SIZE_MAX;
    for (size_t i = 0u; i < ct_len; ++i)
        ct[i] = body[i] ^ s_xor_key;
    bool tag_ok = body[ct_len] == ((uint8_t)ct_len ^ s_tag_key0)
                && body[ct_len + 1u] == (s_checksum(ct, ct_len) ^ s_tag_key1);
    return tag_ok ? ct_len : SIZE_MAX;
}

unsigned tls_null_unseal_calls(void) { return atomic_load(&s_unseal_calls); }
unsigned tls_null_create_calls(void) { return atomic_load(&s_create_calls); }
unsigned tls_null_destroy_calls(void) { return atomic_load(&s_destroy_calls); }
unsigned tls_null_close_notify_calls(void) { return atomic_load(&s_close_notify_calls); }

static duct_seal_engine_t *s_create([[maybe_unused]] const struct duct_seal_engine_vtbl *self,
                                    [[maybe_unused]] void *cfg,
                                    [[maybe_unused]] duct_seal_role_t role)
{
    atomic_fetch_add(&s_create_calls, 1u);
    auto e = (s_null_engine_t *)malloc(sizeof(s_null_engine_t));
    if (!e)
        return nullptr;
    *e = (s_null_engine_t){ .handshook = false };
    return (duct_seal_engine_t *)e;
}

static void s_destroy(duct_seal_engine_t *e)
{
    atomic_fetch_add(&s_destroy_calls, 1u);
    free(e);
}

/** @brief Consume one TLS record (header included, per the wire-level
 *  unseal's own contract). First record on this engine instance is the
 *  handshake: replies via ctx->tx_append, commits no cleartext. Every later
 *  record is application data: decrypted straight into ctx->reserve's
 *  span (no engine-owned scratch buffer), then tag-checked in place —
 *  rc_invalid_arg, uncommitted, on mismatch (auth failure). */
static duct_result_t
s_unseal(duct_seal_engine_t *eng, duct_view_u8 pdu, duct_unseal_ctx_t *ctx)
{
    atomic_fetch_add(&s_unseal_calls, 1u);
    auto e = (s_null_engine_t *)eng;
    if (ctx)
        s_last_peer = ctx->peer;
    static constexpr size_t hdr = 5u;
    auto body = (const uint8_t *)pdu.data + hdr;
    size_t body_len = pdu.size - hdr;

    if (!e->handshook) {
        e->handshook = true;
        uint8_t reply[hdr + sizeof tls_null_server_hello];
        reply[0] = 1u; reply[1] = 0u; reply[2] = 0u;
        reply[3] = (uint8_t)(sizeof tls_null_server_hello >> 8u);
        reply[4] = (uint8_t)(sizeof tls_null_server_hello);
        memcpy(reply + hdr, tls_null_server_hello, sizeof tls_null_server_hello);
        if (!ctx->tx_append(ctx, duct_view(duct_view_u8, reply, sizeof reply)))
            return rc_again;
        return rc_ok;
    }

    if (body_len < s_tag_size)
        return rc_invalid_arg;
    size_t ct_len = body_len - s_tag_size,
           cap = 0u;
    auto ct = (uint8_t *)ctx->reserve(ctx, &cap);
    if (ct_len > cap)
        return rc_invalid_arg;
    for (size_t i = 0u; i < ct_len; ++i)
        ct[i] = body[i] ^ s_xor_key;
    bool tag_ok = body[ct_len] == ((uint8_t)ct_len ^ s_tag_key0)
                && body[ct_len + 1u] == (s_checksum(ct, ct_len) ^ s_tag_key1);
    if (!tag_ok)
        return rc_invalid_arg;
    if (!ctx->commit(ctx, ct_len))
        return rc_invalid_arg;
    return rc_ok;
}

/** @brief 0 pre-handshake (mirrors s_unseal's own e->handshook gate);
 *  otherwise ct_len plus one [5-byte header][ciphertext][2-byte tag]
 *  record per s_max_record cleartext bytes, at least one record even for
 *  an empty ct_len -- same rule duct_wire_t::tx_bound itself uses, so a
 *  correctly wired caller's reservation always covers this exactly. */
static size_t s_seal_size(duct_seal_engine_t *eng, size_t ct_len)
{
    auto e = (s_null_engine_t *)eng;
    if (!e->handshook)
        return 0u;
    static constexpr size_t hdr = 5u;
    size_t n = ct_len / s_max_record;
    if (ct_len % s_max_record != 0u || n == 0u)
        ++n;
    return ct_len + n * (hdr + s_tag_size);
}

/** @brief Seal @p spans as one logical cleartext stream, chunked at
 *  s_max_record bytes per record -- record boundaries need not align with
 *  span boundaries. Tag covers the cleartext (matching s_unseal's own
 *  checksum-over-decoded-bytes convention), computed incrementally as
 *  each byte is read so no second pass over the chunk is needed. */
static void s_seal([[maybe_unused]] duct_seal_engine_t *eng,
                   const duct_view_u8 *spans, size_t n_spans, void *dst)
{
    auto out = (uint8_t *)dst;
    size_t total = 0u;
    for (size_t i = 0u; i < n_spans; ++i)
        total += spans[i].size;
    size_t span_i = 0u, span_off = 0u, remaining = total;
    bool first_chunk = true;
    while (remaining > 0u || first_chunk) {
        first_chunk = false;
        size_t chunk = remaining < s_max_record ? remaining : s_max_record;
        out[0] = 2u; out[1] = 0u; out[2] = 0u;
        out[3] = (uint8_t)((chunk + s_tag_size) >> 8u);
        out[4] = (uint8_t)(chunk + s_tag_size);
        out += 5u;
        uint8_t csum = 0u;
        for (size_t written = 0u; written < chunk; ) {
            if (span_off == spans[span_i].size) {
                ++span_i;
                span_off = 0u;
                continue;
            }
            uint8_t ct_byte = ((const uint8_t *)spans[span_i].data)[span_off];
            csum ^= ct_byte;
            *out++ = ct_byte ^ s_xor_key;
            ++span_off;
            ++written;
        }
        out[0] = (uint8_t)chunk ^ s_tag_key0;
        out[1] = csum ^ s_tag_key1;
        out += s_tag_size;
        remaining -= chunk;
    }
}

/** @brief One fixed, unencrypted marker record (type 3) -- the handshake
 *  reply is unencrypted too (no keys established yet); this fake never
 *  needs to unseal its own close_notify back, so sealing it would only
 *  add ceremony no assertion here reads. */
static void s_close_notify([[maybe_unused]] duct_seal_engine_t *eng, duct_unseal_ctx_t *ctx)
{
    atomic_fetch_add(&s_close_notify_calls, 1u);
    uint8_t reply[6] = { 3u, 0u, 0u, 0u, 1u, tls_null_close_notify_marker };
    duct_discard ctx->tx_append(ctx, duct_view(duct_view_u8, reply, sizeof reply));
}

static const duct_seal_engine_vtbl_t s_vtbl = {
    .create = s_create,
    .destroy = s_destroy,
    .unseal = s_unseal,
    .pdu_hdr_size = duct_tls_record_hdr_size,
    .pdu_len = duct_tls_record_len,
    .pdu_overhead = s_tag_size,
    .pdu_ct_max = s_max_record,
    .engine_hs_budget = 256u,
    .flags = (duct_seal_flags_t)(fl_seal_empty | fl_seal_dgram_ok),
    .seal_size = s_seal_size,
    .seal = s_seal,
    .close_notify = s_close_notify,
};

const duct_seal_engine_vtbl_t *tls_null_vtbl(void)
{
    return &s_vtbl;
}

void tls_null_last_peer(duct_peer_t *out)
{
    atomic_thread_fence(memory_order_acquire);
    *out = s_last_peer;
}
