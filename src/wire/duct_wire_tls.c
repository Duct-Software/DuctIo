/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_wire_tls.c
 *  @brief Sealed wire: io-side PDU-boundary parse, worker-side codec
 *  construction, unseal/seal dispatch and TX sizing.
 *
 *  The crypto and PDU length prefix come from the caller-supplied
 *  @ref duct_seal_engine_vtbl_t; this file holds everything around it. One
 *  wire is fixed at construction to a single @ref duct_seal_role_t and a
 *  single @ref duct_seal_framing_t, and the two parse drivers differ by that
 *  framing: under @c seal_framing_datagram every PDU also carries the i/o
 *  thread record header, both where a conn's RX ring feeds the parse
 *  loop and where a shared datagram listener parses a datagram in place.
 *
 *  Datagram framing also fixes two cleartext prefix widths, one per direction,
 *  that ride ahead of the engine's bytes on every PDU. The widths belong to the
 *  wire; the prefix a conn leads PDUs with lives on that conn's codec.
 */

#include "duct_tls.h"
#include "duct_wire_codec.h"
#include "duct_wire_tx.h"
#include "duct_dgram_rec.h"
#include "duct_dgram_lead.h"
#include "duct_join.h"
#include "duct_core.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>


typedef struct duct_wire_tls {
    duct_wire_t                    base;
    const duct_seal_engine_vtbl_t *engine_vtbl;
    void                           *engine_cfg;
    duct_seal_role_t                role;
    duct_seal_framing_t             framing;
    uint8_t                         tx_prefix_len;
    duct_lead_state_t               lead_state; /**< State its codecs start in:
                              *  unkeyed for an initiator that leads its
                              *  datagrams, none for every other. */
    duct_seal_ctl_fn                rx_ctl;
    void                           *rx_ctl_ctx;
    uint16_t                        opening_ceiling; /**< The config's
                              *  @c opening_ceiling. */
    uint8_t                         tx_prefix[duct_seal_prefix_max];
} duct_wire_tls_t;

static void s_tls_wire_destroy(duct_wire_t *self)
{
    duct_del(self);
}

/** @brief Hand out the shared parser sentinel.
 *
 *  duct_frame_rx_post routes bytes through @c on_parse while
 *  @c conn->wire_parser holds an address. Framing works from the input span
 *  alone, so one static byte serves every sealed conn.
 */
static duct_wire_parser_t *s_tls_create_parser([[maybe_unused]] const duct_wire_t *self)
{
    static uint8_t s_stateless;
    return (duct_wire_parser_t *)&s_stateless;
}

static void s_tls_destroy_parser([[maybe_unused]] const duct_wire_t *self,
                                 [[maybe_unused]] duct_wire_parser_t *parser)
{
}

/** @brief Cut one whole sealed PDU out of @p input.
 *
 *  Which length is authoritative is the whole difference between the two
 *  framings. Under @c seal_framing_stream the engine owns it: @c pdu_hdr_size
 *  bytes are buffered, @c pdu_len reads the total off them, and this wire
 *  bounds that total — past one PDU's worst case is a fatal parse, since a
 *  desynced byte stream never resynchronises.
 *
 *  Under @c seal_framing_datagram the record header owns it, written
 *  by the engine i/o thread from the @c recv() length — nothing a peer
 *  sends can alter it. The record is bounded by that length alone and its
 *  contents go to @c unseal unexamined: past the prefix width @ref s_tls_unseal
 *  checks, the AEAD is the judge a datagram gets, and a record that fails it
 *  costs exactly itself.
 *
 *  Both numbers come from the wire configuration. @c header_size is the
 *  record header this framing declared, and on a stream @c max_frame is exactly
 *  one PDU's worst case — the RX prefix it also counts is refused on that
 *  framing.
 */
static duct_result_t
s_tls_on_parse(const duct_wire_t *self, duct_view_u8 input, duct_frame_t *out,
              [[maybe_unused]] duct_wire_parser_t *parser,
              size_t *consumed, size_t *needed)
{
    auto tw = DUCT_CAST(duct_wire_tls_t, base, self);
    auto vt = tw->engine_vtbl;
    size_t hdr = self->header_size;
    size_t total = 0u;
    if (hdr) {
        if (input.size < hdr) {
            *needed = hdr;
            return rc_again;
        }
        if (duct_ckd_add(&total, hdr, duct_dgram_rec_hdr_decode(input.data)))
            return rc_invalid_arg;
    } else {
        if (input.size < vt->pdu_hdr_size) {
            *needed = vt->pdu_hdr_size;
            return rc_again;
        }
        total = vt->pdu_len(duct_view(duct_view_u8, input.data,
                                          vt->pdu_hdr_size));
        if (total < vt->pdu_hdr_size || total > self->max_frame)
            return rc_invalid_arg;
    }
    if (input.size < total) {
        *needed = total;
        return rc_again;
    }
    *consumed = total;
    *out = (duct_frame_t){ .stream_id = 0u, .flags = fl_frame_none,
        .payload = { .data = (uint8_t *)input.data + hdr, .size = total - hdr } };
    return rc_ok;
}

/** @brief Destroy a codec: the parser, the engine, the engine park and the struct go now,
 *  the cleartext buffer with its last pin. */
static void s_tls_codec_destroy(duct_wire_codec_t *self)
{
    if (self->inner)
        duct_wire_parser_destroy(self->inner, self->inner_parser);
    self->engine->vtbl->destroy(self->engine);
    duct_del(self->engine_park);
    duct_del(self->ct_buf);
    duct_del(self);
}

/** @brief @c ct_buf capacity.
 *  One complete worst-case inner frame, header included, plus the record
 *  that completes it and starts the next; with @c inner @c nullptr each
 *  record stands alone as one frame, so one record suffices.
 */
static size_t s_tls_ct_cap(const duct_wire_t *inner, const duct_seal_engine_vtbl_t *vt)
{
    return vt->pdu_ct_max + (inner ? inner->max_frame + inner->header_size : 0u);
}

/** @brief Worst-case sealed bytes for @p ct_len cleartext.
 *
 *  Segmented at @c pdu_ct_max, each PDU adding the engine
 *  @c pdu_hdr_size and @c pdu_overhead. Feeds admission, TX min-room, and the
 *  stage precheck, the reservation s_tls_on_pack's span-open relies on.
 *
 *  @c seal_framing_datagram caps the cleartext at one PDU, answering
 *  @c SIZE_MAX past it: several PDUs in one datagram reach @c unseal as one
 *  PDU's body and fail its tag, so the caller learns its payload is too large
 *  before any byte is staged.
 *
 *  The @c tx_prefix_len rides on top, this being the one place the staging
 *  path, the gather path and the datagram fast buffer all take their sizing
 *  from. It is read off the wire, since a bound is asked for before any conn is
 *  in hand. One frame is one PDU wherever a prefix is admitted, so one prefix is
 *  the whole count.
 */
static size_t s_tls_tx_bound(const duct_wire_t *self, size_t ct_len)
{
    auto tw = DUCT_CAST(duct_wire_tls_t, base, self);
    auto vt = tw->engine_vtbl;
    size_t ct_total = ct_len;
    if (self->inner && duct_ckd_add(&ct_total, ct_total, self->inner->header_size))
        return SIZE_MAX;
    if (tw->framing == seal_framing_datagram && ct_total > vt->pdu_ct_max)
        return SIZE_MAX;
    size_t n = ct_total / vt->pdu_ct_max;
    if (ct_total % vt->pdu_ct_max != 0u || n == 0u)
        ++n; /* ceil, and at least one record even for an empty cleartext */
    size_t per_record = 0u;
    if (duct_ckd_add(&per_record, vt->pdu_hdr_size, vt->pdu_overhead))
        return SIZE_MAX;
    size_t overhead = 0u;
    if (duct_ckd_mul(&overhead, n, per_record))
        return SIZE_MAX;
    size_t total = 0u;
    if (duct_ckd_add(&total, ct_total, overhead))
        return SIZE_MAX;
    if (duct_ckd_add(&total, total, tw->tx_prefix_len))
        return SIZE_MAX;
    return total;
}

/** @brief Pack one frame by sealing @c {inner_hdr, payload} in one pass.
 *
 *  The engine segments into records internally.
 *  @c rc_again sends the frame down the retry-emit path, on a nullptr @p codec
 *  — its lazy creation in the worker's s_tls_codec hit OOM — and on
 *  @c seal_size answering 0, handshake still in flight. An empty cleartext
 *  ends in @c rc_ok with an empty stage unless the engine raises
 *  @c fl_seal_empty; an inner wire's header keeps the cleartext non-empty, so
 *  that exit needs @c inner @c nullptr and a zero-length payload together.
 */
static duct_result_t
s_tls_on_pack(const duct_wire_t *self, [[maybe_unused]] duct_session_t *s,
             const duct_frame_t *frame, duct_wire_tx_t *stage,
             duct_wire_codec_t *codec)
{
    if (!codec)
        return rc_again;
    auto vt = codec->engine->vtbl;
    /* The inner wire on_pack never runs here, only pack_header, so
     * its bound is enforced in its place: a length past it reaches the flag
     * bits a length-prefix inner keeps in its header. max_frame 0 is unset. */
    if (self->inner && self->inner->max_frame
        && frame->payload.size > self->inner->max_frame)
        return rc_invalid_arg;
    uint8_t inner_hdr[16];
    size_t inner_hdr_len = self->inner
        ? self->inner->pack_header(self->inner, frame, inner_hdr) : 0u;
    size_t ct_total = 0u;
    if (duct_ckd_add(&ct_total, inner_hdr_len, frame->payload.size))
        return rc_invalid_arg;
    if (ct_total == 0u && !duct_has(vt->flags, fl_seal_empty))
        return rc_ok;
    size_t sealed_len = vt->seal_size(codec->engine, ct_total);
    if (sealed_len == 0u)
        return rc_again;
    size_t pre = codec->tx_prefix_len;
    auto span = duct_wire_tx_span_open(stage, sealed_len + pre);
    /* Whichever commit path led here reserved tx_bound(payload.size) first, and
     * sealed_len <= tx_bound by construction, so a miss means a sizing site
     * drifted from this one. */
    duct_fatal(!span);
    duct_view_u8 spans[2] = {
        duct_view(duct_view_u8, inner_hdr, inner_hdr_len),
        frame->payload,
    };
    if (pre)
        memcpy(span, codec->prefix, pre);
    vt->seal(codec->engine, spans, 2u, (uint8_t *)span + pre);
    duct_wire_codec_lead(codec, span, pre + sealed_len);
    return rc_ok;
}

/** @brief Build the codec of a sealed conn on @p xport around a fresh engine.
 *  A conn on @c x_udp_shared gets no cleartext buffer, every other one a buffer of
 *  @c s_tls_ct_cap bytes. */
static duct_wire_codec_t *s_tls_create_codec(const duct_wire_t *self, duct_xport_t xport)
{
    auto tw = DUCT_CAST(duct_wire_tls_t, base, self);
    auto vt = tw->engine_vtbl;
    auto engine = vt->create(vt, tw->engine_cfg, tw->role);
    if (!engine)
        return nullptr;
    auto ct_cap = xport == x_udp_shared ? 0u : s_tls_ct_cap(self->inner, vt);
    duct_auto_del auto ct_buf = ct_cap ? duct_new(uint8_t, ct_cap) : nullptr;
    if (ct_cap && !ct_buf) {
        vt->destroy(engine);
        return nullptr;
    }
    auto inner_parser = self->inner ? duct_wire_parser_create(self->inner) : nullptr;
    if (self->inner && !inner_parser) {
        vt->destroy(engine);
        return nullptr;
    }
    duct_auto_del auto codec = duct_new_secret(duct_wire_codec_t);
    if (!codec) {
        duct_wire_parser_destroy(self->inner, inner_parser);
        vt->destroy(engine);
        return nullptr;
    }
    *codec = (duct_wire_codec_t){
        .destroy = s_tls_codec_destroy,
        .inner = self->inner,
        .inner_parser = inner_parser,
        .ct_buf = duct_move(ct_buf),
        .engine = engine,
        .tx_prefix_len = tw->tx_prefix_len,
        .rx_prefix_len = self->rx_prefix_len,
        .lead_state = tw->lead_state,
        .opening_ceiling = tw->opening_ceiling,
    };
    memcpy(codec->prefix, tw->tx_prefix, sizeof codec->prefix);
    if (codec->lead_state != lead_state_none)
        memcpy(codec->lead.cover_key, self->cover_key, sizeof codec->lead.cover_key);
    return duct_move(codec);
}

void duct_wire_codec_lead_write(duct_wire_codec_t *c, uint8_t *dgram, size_t len)
{
    if (c->lead_state == lead_state_unkeyed) {
        if (!duct_join_derive(c->engine->vtbl, c->engine, c->lead.key, c->lead.name))
            return;
        c->lead_state = lead_state_keyed;
    }
    duct_dgram_lead_fill(dgram, c->tx_prefix_len, len, c->lead.key, c->lead.cover_key,
                         c->lead.name);
}

/** @brief Strip @p codec prefix and pass the PDU to the engine.
 *
 *  The strip executes here because a shared datagram listener reaches this
 *  without parsing — @c s_inter_pkt unseals the packet where it lies, and
 *  takes the same strip to size its redirect.
 */
static duct_result_t
s_tls_unseal(const duct_wire_t *self, duct_wire_codec_t *codec,

            duct_view_u8 pdu, duct_unseal_ctx_t *ctx)
{
    /* A control datagram is the protocol's to tell, and only while the engine
     * holds no keys, seal_size answering 0, so one forged past the handshake
     * reaches the AEAD like any PDU. The slice it answers goes out behind the
     * inner wire's header through the same reserve/commit the engine publishes
     * cleartext with, and the protocol sees one ordinary frame. */
    auto tw = DUCT_CAST(duct_wire_tls_t, base, self);
    duct_view_u8 pv = pdu;
    duct_view_u8 ctl = {};
    if (tw->rx_ctl && codec->engine->vtbl->seal_size(codec->engine, 0u) == 0u)
        ctl = tw->rx_ctl(tw->rx_ctl_ctx, pdu);
    if (!ctl.size) {
        bool carries = duct_wire_codec_rx_strip(codec, &pv);
        duct_do_if(!carries, return rc_invalid_arg);
        return codec->engine->vtbl->unseal(codec->engine, pv, ctx);
    }
    assert((const uint8_t *)ctl.data >= (const uint8_t *)pv.data
           && (const uint8_t *)ctl.data + ctl.size <= (const uint8_t *)pv.data + pv.size);
    pv = ctl;
    size_t cap = 0u,
           hdr = codec->inner ? codec->inner->header_size : 0u;
    auto dst = (uint8_t *)ctx->reserve(ctx, &cap);
    duct_do_if(!dst || hdr + pv.size > cap, return rc_invalid_arg);
    if (hdr)
        duct_discard codec->inner->pack_header(codec->inner,
                                               &(duct_frame_t){ .payload = pv }, dst);
    memcpy(dst + hdr, pv.data, pv.size);
    return ctx->commit(ctx, hdr + pv.size) ? rc_ok : rc_invalid_arg;
}

duct_wire_t *duct_wire_create_sealed(const duct_sealed_wire_cfg_t *cfg)
{
    duct_do_if(!cfg, return nullptr);
    bool role_ok = duct_seal_role_valid(cfg->role);
    duct_do_if(!role_ok, return nullptr);
    bool dgram = cfg->framing == seal_framing_datagram;
    duct_do_if(cfg->framing != seal_framing_stream && !dgram, return nullptr);
    duct_do_if(cfg->tx_prefix_len > duct_seal_prefix_max
              || cfg->rx_prefix_len > duct_seal_prefix_max, return nullptr);
    /* A record cut by explicit record length survives leading bytes; a byte stream
     * has only the engine length prefix to cut on, and bytes ahead of it
     * desync the peer past recovery. The refusal is also what makes
     * s_tls_tx_bound's single prefix exact: only a stream segments one frame
     * into several PDUs. */
    duct_do_if(!dgram && (cfg->tx_prefix_len || cfg->rx_prefix_len),
              return nullptr);
    /* A byte stream has no datagram to tell a control one by. */
    duct_do_if(!dgram && cfg->rx_ctl, return nullptr);
    auto inner = cfg->inner;
    auto engine = cfg->engine;
    duct_do_if(!engine || !engine->create || !engine->destroy || !engine->unseal
              || !engine->seal_size || !engine->seal,
              return nullptr);
    /* Both this and duct_wire_t::header_size below read the same dgram, so the
     * framing half is demanded exactly where s_tls_on_parse calls it and a
     * datagram-only engine carries none. pdu_hdr_size stays meaningful there:
     * s_tls_tx_bound budgets those bytes on either framing, the engine parsing
     * them itself inside unseal. */
    duct_do_if(!dgram && (!engine->pdu_len || engine->pdu_hdr_size == 0u),
              return nullptr);
    /* The lead opens the prefix of the side that writes it, the initiator's, or
     * reads it, the responder's, so that prefix has to hold a lead; an engine
     * without derive has no key to build one from. */
    bool initiator = cfg->role == seal_role_initiator;
    duct_do_if(cfg->join_lead
              && (!dgram || !engine->derive
                  || (initiator ? cfg->tx_prefix_len : cfg->rx_prefix_len) < duct_seal_lead_size),
              return nullptr);
    duct_do_if(engine->pdu_ct_max == 0u
              || engine->pdu_ct_max > duct_seal_pdu_ct_max,
              return nullptr);
    duct_do_if(engine->engine_hs_budget == 0u, return nullptr);
    /* A conn's engine park holds two messages of the budget and flushes whole:
     * the smallest TX ring, which duct_conn_tx_olb_cap sets, has to take it.
     * Each message carries the wire's prefix, and on a datagram-framed conn a
     * record header too; a stream wire takes no prefix, see above. */
    static_assert(duct_conn_tx_olb_cap / 2u
                  > duct_dgram_record_hdr_size + duct_seal_prefix_max,
        "a TX ring smaller than two records of one header and one prefix each "
        "underflows the budget cap below");
    size_t budget_cap = duct_conn_tx_olb_cap / 2u
                      - (dgram ? duct_dgram_record_hdr_size : 0u) - cfg->tx_prefix_len;
    duct_do_if(engine->engine_hs_budget > budget_cap, return nullptr);
    /* An inner wire has to frame the cleartext by itself: s_tls_on_pack seals
     * pack_header's bytes and the payload, and nothing else reaches the peer.
     * A wire writing fewer bytes than its header_size is one counting a
     * prefix somebody else lays down — every datagram wire counts the record
     * length the io thread writes, which no PDU carries. Left to build, that pair
     * seals a header the inner parse then reads a missing count out of, with
     * neither side able to tell. The probe takes an empty frame, pack_header
     * being a pure function of the frame it is given. */
    if (inner) {
        duct_do_if(!inner->pack_header, return nullptr);
        uint8_t probe[16];
        size_t writes = inner->pack_header(inner, &(duct_frame_t){}, probe);
        duct_do_if(writes != inner->header_size, return nullptr);
    }
    /* Frame flags and the stream id both travel in the inner wire header,
     * which s_tls_on_pack seals alongside the payload — so a sealed wire
     * carries each exactly when its inner wire does. With no inner wire the
     * cleartext is the whole frame, with nowhere to put either. */
    duct_wire_flags_t wflags = fl_wire_none;
    if (duct_has(engine->flags, fl_seal_dgram_ok))
        wflags = duct_or(wflags, fl_wire_dgram_ok);
    if (inner && duct_has(inner->flags, fl_wire_frame_flags))
        wflags = duct_or(wflags, fl_wire_frame_flags);
    if (inner && duct_has(inner->flags, fl_wire_stream_ids))
        wflags = duct_or(wflags, fl_wire_stream_ids);
    if (cfg->join_lead && !initiator)
        wflags = duct_or(wflags, fl_wire_join_lead);
    auto tw = duct_new_secret(duct_wire_tls_t);
    duct_do_if(!tw, return nullptr);
    *tw = (duct_wire_tls_t){
        .base = {
            .name = engine->name ? engine->name : "sealed",
            .flags = wflags,
            .rx_prefix_len = cfg->rx_prefix_len,
            .header_size = dgram ? duct_dgram_record_hdr_size : 0u,
            /* An ingress bound, so it counts the RX prefix: a datagram past
             * max_frame is dropped as oversize before any wire sees it, and the
             * datagrams it lands on are exactly the largest payloads this
             * framing admits. */
            .max_frame = engine->pdu_hdr_size + engine->pdu_ct_max
                       + engine->pdu_overhead + cfg->rx_prefix_len,
            .inner = inner,
            .tx_bound = s_tls_tx_bound,
            .destroy = s_tls_wire_destroy,
            .on_parse = s_tls_on_parse,
            .on_pack = s_tls_on_pack,
            .create_parser = s_tls_create_parser,
            .destroy_parser = s_tls_destroy_parser,
            .create_codec = s_tls_create_codec,
            .unseal = s_tls_unseal,
        },
        .engine_vtbl = engine, .engine_cfg = cfg->engine_cfg,
        .role = cfg->role,
        .framing = cfg->framing,
        .tx_prefix_len = cfg->tx_prefix_len,
        .lead_state = cfg->join_lead && initiator ? lead_state_unkeyed : lead_state_none,
        .rx_ctl = cfg->rx_ctl,
        .rx_ctl_ctx = cfg->rx_ctl_ctx,
        .opening_ceiling = cfg->opening_ceiling,
    };
    memcpy(tw->tx_prefix, cfg->tx_prefix, sizeof tw->tx_prefix);
    memcpy(tw->base.cover_key, cfg->cover_key, sizeof tw->base.cover_key);
    return &tw->base;
}
