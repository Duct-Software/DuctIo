/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_wire.c
 *  @brief TX staging glue plus the built-in length-prefix wire.
 *
 *  @c duct_wire_tx_stage is the whole @c duct_wire_tx_t contract: every
 *  @c on_pack, built-in or custom, stages header + payload through this one
 *  call and never learns which of the three targets it got, nor touches
 *  internal ring fields.
 *
 *  The five built-ins here are one parse body, @c s_lp_parse_unit, under a
 *  format that resolves to two widths, and two pack bodies split on what
 *  @c max_frame counts. What separates them is where a frame's fields live:
 *  length-prefix takes the header's top three bits for the flags, since it owns
 *  that field; a datagram wire's header is the io thread record length,
 *  which it cannot touch, so it spends leading bytes of the record instead, or
 *  spends nothing and leaves every byte a peer sees as payload. A mux wire adds
 *  a stream id, which the engine stream table is keyed on
 *  and no other built-in puts on the wire.
 *  Each datagram constructor is built on
 *  @c duct_wire_create_length_prefix and keeps its parser management; TX there
 *  stages one datagram per call already, the worker's record-length wrapper
 *  being the only framing a send() ever needs.
 *  Per-connection parser state, @c lp_parser_t, brand-casts to/from the opaque
 *  @c duct_wire_parser_t token — it needs
 *  replay-across-reads fields the wire object itself has no use for.
 */

#include "duct_wire.h"
#include "duct_wire_tx.h"
#include "duct_dgram_rec.h"
#include "duct_olb_rx.h"
#include "duct_olb_tx.h"
#include "duct_core.h"

#include "duct_types.h"
#include <stdint.h>
#include <string.h>

static constexpr size_t lp_max_frame = 1u << 20;
/** @name Length-prefix header bits
 *  The three frame flags ride in the header's top bits and the length in what
 *  is left, so a frame carrying none is byte-identical to a bare length prefix.
 *  @ref duct_wire_create_length_prefix refuses any @c max_frame that reaches
 *  into them.
 *  @{ */
static constexpr uint32_t lp_bit_fin  = 1u << 31;
static constexpr uint32_t lp_bit_rst  = 1u << 30;
static constexpr uint32_t lp_bit_gso  = 1u << 29;
static constexpr uint32_t lp_len_mask = lp_bit_gso - 1u;
/** @} */

/** @brief Frame flags the built-in wires carry, the mask every flags byte
 *  parses through. */
static constexpr uint8_t lp_frame_flags = fl_frame_fin | fl_frame_rst | fl_frame_gso;

/** @brief Bytes a @c framed datagram wire spends on frame flags, per datagram.
 *  Its header is the io thread's record length, so the flags get no bits there
 *  and take a byte of the datagram instead.
 */
static constexpr size_t dgram_flags_size = 1u;

typedef struct { uint8_t octets[duct_wire_length_prefix_hdr_size]; } lp_hdr_t;

/** @name Multiplexed header geometry
 *  A stream mux frame is @c [flags:1][len:3][sid:4]; its datagram counterpart
 *  drops the length, the record prefix already carrying it, and is
 *  @c [flags:1][sid:4]. The flags take a whole byte in both, which is
 *  @c duct_frame_flags_t verbatim: the datagram member has no length field to
 *  borrow bits from, so a byte is the widest the two halves of one family can
 *  share. The 24-bit length caps a mux frame at 16 MiB.
 *  @{ */
static constexpr size_t   mux_hdr_size   = 8u;
static constexpr size_t   mux_dgram_lead = 5u;
static constexpr uint32_t mux_len_max    = 0xFFFFFFu;
/** @} */

/** @brief Which unit layout the shared parse body below is reading. */
typedef enum : uint8_t {
    lp_fmt_dgram = 0,  /**< Whole record is payload. The prefix's
                         *  @c duct_dgram_rec_gso bit becomes @c fl_frame_gso. */
    lp_fmt_count,      /**< Length prefix, flags in the count's top three bits. */
    lp_fmt_dgram_flag, /**< Record led by a flags byte. */
    lp_fmt_mux,        /**< 8-byte header: flags, length, stream id. */
    lp_fmt_mux_dgram,  /**< Record led by flags and a stream id. */
} lp_unit_fmt_t;

/** @brief Per-conn parse state: a header caught mid-flight.
 *  @c partial_len is the whole of it — nonzero says a header arrived split
 *  across reads and @c hdr_buf holds what came so far. A unit whose header
 *  arrived whole leaves nothing behind.
 */
typedef struct {
    uint8_t   hdr_buf[mux_hdr_size];
    uint32_t  partial_len;
} lp_parser_t;

/** @brief Parse one counted unit: a big-endian header, then the bytes it counts.
 *
 *  Every built-in @c on_parse is this function under one @p fmt, resolving to
 *  two widths. @b hdr holds the count — 4 for a length prefix or the io
 *  thread's record header, 8 where a stream id rides along — and is decoded
 *  where it lies, @c lp_parser_t::hdr_buf carrying it only when it arrived
 *  across two reads. @b lead is the part of the counted unit belonging to wire
 *  framing, which a datagram spends on fields lacking a dedicated header.
 *
 *  Answering @c rc_again hands the unit back to be parsed from its first byte
 *  again — the RX driver keeps its offset and drops @p consumed — so a short
 *  payload keeps no state here and @p needed counts the header too.
 *
 *  A unit shorter than @b lead is refused, which keeps
 *  @c duct_wire_t::header_size true of every frame this emits: the worker
 *  subtracts it with no floor. A count of zero with no @b lead stays the empty
 *  frame an empty datagram's record header decodes to. Unknown flag bits are
 *  masked off, so a peer on a later revision loses only bits this one lacks.
 */
static duct_result_t s_lp_parse_unit(const duct_wire_t *self,
                                     duct_view_u8 input, duct_frame_t *out,
                                     duct_wire_parser_t *parser,
                                     size_t *consumed, size_t *needed, lp_unit_fmt_t fmt)
{
    auto lp = (lp_parser_t *)parser;
    *consumed = 0u;
    *needed = 0u;

    size_t hdr = sizeof(lp_hdr_t), lead = 0u;
    switch (fmt) {
    case lp_fmt_mux:        hdr  = mux_hdr_size;     break;
    case lp_fmt_dgram_flag: lead = dgram_flags_size; break;
    case lp_fmt_mux_dgram:  lead = mux_dgram_lead;   break;
    default: break;
    }
    uint8_t *p = (uint8_t *)input.data,
            *end = p + input.size;

    const uint8_t *o;
    if (lp->partial_len > 0u) {
        p += lp->partial_len; /* skip replayed already-buffered bytes */
        uint32_t want = (uint32_t)hdr - lp->partial_len,
                 copy = (uint32_t)(end - p) < want ? (uint32_t)(end - p) : want;
        memcpy(lp->hdr_buf + lp->partial_len, p, copy);
        lp->partial_len += copy;
        p += copy;
        if (lp->partial_len < (uint32_t)hdr) {
            *needed = hdr - lp->partial_len;
            return rc_again;
        }
        o = lp->hdr_buf;
    } else if ((size_t)(end - p) >= hdr) {
        o = p;
        p += hdr;
    } else {
        memcpy(lp->hdr_buf, p, (size_t)(end - p));
        lp->partial_len = (uint32_t)(end - p);
        *needed = hdr - lp->partial_len;
        return rc_again;
    }

    lp->partial_len = 0u;

    duct_frame_flags_t flags = fl_frame_none;
    duct_stream_id_t sid = duct_stream_id_default;
    uint32_t len;
    if (fmt == lp_fmt_mux) {
        flags = (duct_frame_flags_t)(o[0] & lp_frame_flags);
        len = ((uint32_t)o[1] << 16u) | ((uint32_t)o[2] << 8u) | (uint32_t)o[3];
        sid = duct_load_be32(o + 4u);
    } else {
        uint32_t word = duct_load_be32(o);
        len = word;
        if (fmt == lp_fmt_count) {
            if (word & lp_bit_fin)
                flags = duct_or(flags, fl_frame_fin);
            if (word & lp_bit_rst)
                flags = duct_or(flags, fl_frame_rst);
            if (word & lp_bit_gso)
                flags = duct_or(flags, fl_frame_gso);
            len = word & lp_len_mask;
        } else if (fmt == lp_fmt_dgram && (word & duct_dgram_rec_gso)) {
            flags = fl_frame_gso;
            len = word & ~duct_dgram_rec_gso;
        }
    }

    /* A count no replay recovers from: past max_frame, or short of the byte a
     * framed datagram wire keeps its flags in. */
    if (len > self->max_frame || len < lead) {
        *consumed = (size_t)(p - (uint8_t *)input.data);
        return rc_invalid_arg;
    }

    if ((size_t)(end - p) < len) {
        *consumed = (size_t)(p - (uint8_t *)input.data);
        *needed = hdr + len;
        return rc_again;
    }

    *consumed = (size_t)((p + len) - (uint8_t *)input.data);
    if (lead) {
        flags = (duct_frame_flags_t)(p[0] & lp_frame_flags);
        if (fmt == lp_fmt_mux_dgram)
            sid = duct_load_be32(p + 1u);
        p   += lead;
        len -= (uint32_t)lead;
    }
    *out = (duct_frame_t){ .stream_id = sid, .flags = flags,
                           .payload = { .data = p, .size = len } };
    return rc_ok;
}

/** @brief Length-prefix wire @c on_parse: frame flags ride the header top bits. */
static duct_result_t s_lp_parse(const duct_wire_t *self,
                                duct_view_u8 input, duct_frame_t *out,
                                duct_wire_parser_t *parser, size_t *consumed, size_t *needed)
{
    return s_lp_parse_unit(self, input, out, parser, consumed, needed, lp_fmt_count);
}

/** @brief The mux wire's @c on_parse: flags, length and stream id in 8 bytes. */
static duct_result_t s_mux_parse(const duct_wire_t *self,
                                 duct_view_u8 input, duct_frame_t *out,
                                 duct_wire_parser_t *parser, size_t *consumed, size_t *needed)
{
    return s_lp_parse_unit(self, input, out, parser, consumed, needed, lp_fmt_mux);
}

/** @brief The mux datagram wire's @c on_parse: the record is led by flags and
 *  a stream id, its length already known from the record prefix. */
static duct_result_t s_mux_dgram_parse(const duct_wire_t *self,
                                       duct_view_u8 input, duct_frame_t *out,
                                       duct_wire_parser_t *parser, size_t *consumed, size_t *needed)
{
    return s_lp_parse_unit(self, input, out, parser, consumed, needed, lp_fmt_mux_dgram);
}

/** @brief A transparent datagram wire's @c on_parse: the whole record is payload. */
static duct_result_t s_dgram_parse(const duct_wire_t *self,
                                   duct_view_u8 input, duct_frame_t *out,
                                   duct_wire_parser_t *parser, size_t *consumed, size_t *needed)
{
    return s_lp_parse_unit(self, input, out, parser, consumed, needed, lp_fmt_dgram);
}

/** @brief A framed datagram wire's @c on_parse: the record's first byte is flags. */
static duct_result_t s_dgram_parse_framed(const duct_wire_t *self,
                                          duct_view_u8 input, duct_frame_t *out,
                                          duct_wire_parser_t *parser,
                                          size_t *consumed, size_t *needed)
{
    return s_lp_parse_unit(self, input, out, parser, consumed, needed, lp_fmt_dgram_flag);
}

/** @brief Length-prefix 4-byte header: payload length, flag bits on top.
 *
 *  A pure function of @p frame. @ref s_hdr_pack stages exactly what this
 *  writes, and the @ref duct_wire_create_length_prefix @c max_frame bound
 *  keeps the length clear of the flag bits.
 */
static size_t s_lp_pack_header([[maybe_unused]] const duct_wire_t *self,
                               const duct_frame_t *frame, uint8_t buf[16])
{
    uint32_t word = (uint32_t)frame->payload.size;
    if (duct_has(frame->flags, fl_frame_fin)) word |= lp_bit_fin;
    if (duct_has(frame->flags, fl_frame_rst)) word |= lp_bit_rst;
    if (duct_has(frame->flags, fl_frame_gso)) word |= lp_bit_gso;
    duct_store_be32(buf, word);
    return sizeof(lp_hdr_t);
}

/** @brief Stage @p frame behind the header @p self @c pack_header writes.
 *
 *  @p unit_bound says what @c max_frame counts: false bounds the payload
 *  alone, true bounds header and payload together, the datagram wires
 *  spending part of one datagram's budget on a dedicated header.
 *
 *  A gather target already owns @ref wire_tx_hdr_max bytes for its header, so
 *  @c pack_header writes there and the stack buffer stands in for every other
 *  kind. @ref duct_wire_tx_stage answers the same question again before it
 *  copies, which keeps the two choices from having to agree.
 */
static duct_result_t s_hdr_pack(const duct_wire_t *self, const duct_frame_t *frame,
                                duct_wire_tx_t *stage, bool unit_bound)
{
    uint8_t local[wire_tx_hdr_max];
    uint8_t *hdr = stage->kind == wire_tx_gather
                 ? (uint8_t *)stage->gather[0].data : local;
    size_t n = self->pack_header(self, frame, hdr);
    size_t need = 0u;
    bool over = duct_ckd_add(&need, frame->payload.size, unit_bound ? n : 0u);
    /* Past max_frame the peer parse reads a desync, and the length
     * reaches into the flag bits on the way out. */
    duct_do_if(over || need > self->max_frame, return rc_invalid_arg);
    return duct_wire_tx_stage(stage,
        duct_view(duct_view_u8, hdr, n), frame->payload);
}

/** @brief @c on_pack for the wires whose @c max_frame bounds the payload:
 *  length-prefix and mux. */
static duct_result_t s_pack_frame(const duct_wire_t *self,
                                  [[maybe_unused]] duct_session_t *s,
                                  const duct_frame_t *frame, duct_wire_tx_t *stage,
                                  [[maybe_unused]] duct_wire_codec_t *codec)
{
    return s_hdr_pack(self, frame, stage, false);
}

/** @brief @c on_pack for the wires whose @c max_frame bounds the whole
 *  datagram: framed and mux datagram, each spending part of it on its
 *  header. */
static duct_result_t s_pack_record(const duct_wire_t *self,
                                   [[maybe_unused]] duct_session_t *s,
                                   const duct_frame_t *frame, duct_wire_tx_t *stage,
                                   [[maybe_unused]] duct_wire_codec_t *codec)
{
    return s_hdr_pack(self, frame, stage, true);
}

/** @brief A transparent datagram wire's @c on_pack: payload only, no header.
 *
 *  One call here is already exactly one datagram, delimited by the worker
 *  record-length wrapper. Every byte staged is payload,
 *  which carries an @c x_raw_packet leg's packets across unchanged.
 */
static duct_result_t s_dgram_pack(const duct_wire_t *self,
                                  [[maybe_unused]] duct_session_t *s,
                                  const duct_frame_t *frame, duct_wire_tx_t *stage,
                                  [[maybe_unused]] duct_wire_codec_t *codec)
{
    duct_do_if(frame->payload.size > self->max_frame, return rc_invalid_arg);
    return duct_wire_tx_stage(stage, (duct_view_u8){}, frame->payload);
}

/** @brief A transparent datagram wire's @c pack_header: no bytes, any frame.
 *
 *  Answering 0 is also what opens @c s_commit_dgram_shared's zero-copy fork
 *  on the worker, which sends a pooled payload as the datagram itself — a
 *  framed wire answers nonzero and takes the copying path instead.
 */
static size_t s_dgram_pack_header([[maybe_unused]] const duct_wire_t *self,
                                  [[maybe_unused]] const duct_frame_t *frame,
                                  [[maybe_unused]] uint8_t buf[16])
{
    return 0u;
}

/** @brief A framed datagram wire's @c pack_header: its one flags byte. */
static size_t s_dgram_pack_header_framed([[maybe_unused]] const duct_wire_t *self,
                                         const duct_frame_t *frame, uint8_t buf[16])
{
    buf[0] = (uint8_t)frame->flags;
    return dgram_flags_size;
}

/** @brief The mux wire's 8-byte header: flags, 24-bit length, stream id. */
static size_t s_mux_pack_header([[maybe_unused]] const duct_wire_t *self,
                                const duct_frame_t *frame, uint8_t buf[16])
{
    uint32_t len = (uint32_t)frame->payload.size,
             sid = (uint32_t)frame->stream_id;
    buf[0] = (uint8_t)frame->flags;
    buf[1] = (uint8_t)(len >> 16u); buf[2] = (uint8_t)(len >> 8u); buf[3] = (uint8_t)(len);
    duct_store_be32(buf + 4u, sid);
    return mux_hdr_size;
}


/** @brief The mux datagram wire's 5-byte header: flags, then stream id. */
static size_t s_mux_dgram_pack_header([[maybe_unused]] const duct_wire_t *self,
                                      const duct_frame_t *frame, uint8_t buf[16])
{
    uint32_t sid = (uint32_t)frame->stream_id;
    buf[0] = (uint8_t)frame->flags;
    duct_store_be32(buf + 1u, sid);
    return mux_dgram_lead;
}


static duct_wire_parser_t *s_lp_create_parser([[maybe_unused]] const duct_wire_t *self)
{
    return (duct_wire_parser_t *)duct_new(lp_parser_t);
}

static void s_lp_destroy_parser([[maybe_unused]] const duct_wire_t *self, duct_wire_parser_t *parser)
{
    duct_del(parser);
}

static void s_lp_destroy(duct_wire_t *self)
{
    duct_del(self);
}

duct_wire_t *duct_wire_create_length_prefix(size_t max_frame)
{
    duct_do_if(max_frame > lp_len_mask, return nullptr);
    auto w = duct_new(duct_wire_t);
    duct_do_if(!w, return nullptr);
    *w = (duct_wire_t){
        .name             = "length-prefix",
        .flags            = duct_or(fl_wire_frame_flags, fl_wire_gather),
        .header_size      = sizeof(lp_hdr_t),
        .max_frame        = max_frame ? max_frame : lp_max_frame,
        .max_batch_frames = duct_conn_rx_olb_cap / sizeof(lp_hdr_t),
        .destroy          = s_lp_destroy,
        .on_parse         = s_lp_parse,
        .on_pack          = s_pack_frame,
        .pack_header      = s_lp_pack_header,
        .create_parser    = s_lp_create_parser,
        .destroy_parser   = s_lp_destroy_parser,
    };
    return w;
}

duct_wire_t *duct_wire_create_dgram_batch(size_t max_dgram, bool framed)
{
    auto w = duct_wire_create_length_prefix(max_dgram ? max_dgram : duct_udp4_payload_max);
    if (!w)
        return nullptr;
    w->name = framed ? "dgram-framed" : "dgram-batch";
    if (framed) {
        w->flags = duct_or(fl_wire_frame_flags, fl_wire_gather);
        w->header_size = duct_dgram_record_hdr_size + dgram_flags_size;
        w->on_parse = s_dgram_parse_framed;
        w->on_pack = s_pack_record;
        w->pack_header = s_dgram_pack_header_framed;
    } else {
        w->flags = fl_wire_gather;
        w->header_size = duct_dgram_record_hdr_size;
        w->on_parse = s_dgram_parse;
        w->on_pack = s_dgram_pack;
        w->pack_header = s_dgram_pack_header;
    }
    return w;
}

/** @brief Wire behind @c duct_wire_packet, built before main and kept to process exit.
 *  Nothing frees it: the exit-time conn reclaim reads the wire of any leg
 *  still live, and destructors of one priority tier run in no fixed order.
 */
static duct_wire_t *s_packet_wire;

/** @brief Build the packet wire with its @c destroy cleared, since no holder owns it. */
static void s_packet_wire_ctor(void) __attribute__((constructor(DUCT_CTOR_PRI_STATE)));
static void s_packet_wire_ctor(void)
{
    s_packet_wire = duct_wire_create_dgram_batch(duct_ipv4_len_max, false);
    duct_fatal(!s_packet_wire);
    s_packet_wire->destroy = nullptr;
}

const duct_wire_t *duct_wire_packet(void)
{
    return s_packet_wire;
}

duct_wire_t *duct_wire_create_mux(size_t max_frame)
{
    duct_do_if(max_frame > mux_len_max, return nullptr);
    auto w = duct_wire_create_length_prefix(max_frame);
    if (!w)
        return nullptr;
    w->name = "mux";
    w->flags = duct_or(fl_wire_frame_flags, fl_wire_stream_ids, fl_wire_gather);
    w->header_size = mux_hdr_size;
    w->max_batch_frames = duct_conn_rx_olb_cap / mux_hdr_size;
    w->on_parse = s_mux_parse;
    w->on_pack = s_pack_frame;
    w->pack_header = s_mux_pack_header;
    return w;
}

duct_wire_t *duct_wire_create_mux_dgram(size_t max_dgram)
{
    duct_do_if(max_dgram && max_dgram <= mux_dgram_lead, return nullptr);
    auto w = duct_wire_create_dgram_batch(max_dgram, true);
    if (!w)
        return nullptr;
    w->name = "mux-dgram";
    w->flags = duct_or(fl_wire_frame_flags, fl_wire_stream_ids, fl_wire_gather);
    w->header_size = duct_dgram_record_hdr_size + mux_dgram_lead;
    w->on_parse = s_mux_dgram_parse;
    w->on_pack = s_pack_record;
    w->pack_header = s_mux_dgram_pack_header;
    return w;
}

/** @brief @c vmq_view counterpart of @c duct_olb_tx_stage: one-shot span,
 *  no ring, no wrap — overflow past @c capacity is always terminal.
 */
static duct_olb_tx_result_t
s_vmq_view_stage(duct_vmq_tx_view_t *v, const uint8_t *hdr, size_t hdr_size,
                 const void *data, size_t len)
{
    size_t total = (hdr ? hdr_size : 0u) + len;
    if (v->stage + total > v->capacity)
        return olb_tx_too_large;
    auto off = v->data + v->stage;
    if (hdr) { memcpy(off, hdr, hdr_size); off += hdr_size; }
    if (len) memcpy(off, data, len);
    v->stage += total;
    return olb_tx_ok;
}

void *duct_wire_tx_span_open(duct_wire_tx_t *stage, size_t n)
{
    if (stage->kind == wire_tx_gather)
        return nullptr;
    if (stage->kind != wire_tx_vmq_view)
        return duct_olb_tx_span_open(stage->olb, n);
    auto v = &stage->vmq_view;
    size_t end = 0u;
    if (duct_ckd_add(&end, v->stage, n) || end > v->capacity)
        return nullptr;
    auto span = (uint8_t *)v->data + v->stage;
    v->stage = end;
    return span;
}

duct_result_t duct_wire_tx_stage(duct_wire_tx_t *stage, duct_view_u8 hdr, duct_view_u8 payload)
{
    duct_do_if(hdr.size > 0u && !hdr.data, return rc_invalid_arg);
    duct_do_if(payload.size > 0u && !payload.data, return rc_invalid_arg);
    auto hdr_bytes = hdr.size ? (const uint8_t *)hdr.data : nullptr;
    duct_olb_tx_result_t rc = olb_tx_too_large;
    switch (stage->kind) {
    case wire_tx_vmq_view:
        rc = s_vmq_view_stage(&stage->vmq_view, hdr_bytes, hdr.size,
                              payload.data, payload.size);
        break;
    case wire_tx_gather:
        rc = stage->gathered || hdr.size > wire_tx_hdr_max
           ? olb_tx_too_large : olb_tx_ok;
        if (rc == olb_tx_ok) {
            /* Slot 0 is the header's home, so a caller that packed into it
             * hands back that same pointer -- memcpy takes restricted
             * pointers and a self-copy is undefined, not a no-op. */
            if (hdr.size && hdr.data != stage->gather[0].data)
                memcpy(stage->gather[0].data, hdr.data, hdr.size);
            stage->gather[0].size = hdr.size;
            stage->gather[1] = payload;
            stage->gathered = true;
        }
        break;
    case wire_tx_olb:
        rc = duct_olb_tx_stage(stage->olb, hdr_bytes, hdr.size,
                               payload.data, payload.size);
        break;
    }
    return rc == olb_tx_ok ? rc_ok : rc == olb_tx_too_large ? rc_invalid_arg : rc_again;
}
