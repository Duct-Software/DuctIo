/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_seal_engine.h
 *  @brief Sealed-transport crypto engine contract.
 *
 *  Pluggable behind a sealed @ref duct_wire_t, e.g. TLS via @ref
 *  duct_wire_create_sealed. The vtbl is a thin seam an integrator implements
 *  against any record-oriented crypto library.
 *  One sealed PDU in, 0+ cleartext bytes out via @c ctx->reserve /
 *  @c ctx->commit; egress uses @c ctx->tx_append.
 */

#ifndef DUCT_SEAL_ENGINE_H
#define DUCT_SEAL_ENGINE_H

#include "duct_wire.h"
#include "duct_types.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Maximum cleartext PDU capacity, bytes.
 *  Bounds the per-conn cleartext reassembly buffer allocated by sealed wires.
 */
static constexpr size_t duct_seal_pdu_ct_max = 16384u;

/** @brief What a seal engine promises about the PDUs it produces. */
typedef enum duct_seal_flags : uint8_t {
    fl_seal_none     = 0u,
    fl_seal_empty    = 1u << 0, /**< Engine emits a PDU for zero cleartext bytes.
                                  *  Dropped when cleared. */
    fl_seal_dgram_ok = 1u << 1, /**< Engine supports out-of-order and lossy
                                  *  datagram delivery via per-PDU sequence numbers
                                  *  and anti-replay checks. */
} duct_seal_flags_t;

static_assert(sizeof(duct_seal_flags_t) == sizeof(uint8_t),
    "duct_seal_flags_t must be 8 bits wide");

/** @brief Which side of the handshake a sealed wire's engines take.
 *  One wire carries one role; mix roles by constructing two wires.
 *  @c seal_role_unset is rejected at wire construction.
 */
typedef enum duct_seal_role : uint8_t {
    seal_role_unset = 0,
    seal_role_initiator,
    seal_role_responder,
} duct_seal_role_t;

/** @brief Validate that @p role names a handshake side.
 *  Returns true for @c seal_role_initiator or @c seal_role_responder.
 */
static inline bool duct_seal_role_valid(duct_seal_role_t role)
{
    return role == seal_role_initiator || role == seal_role_responder;
}

/** @brief Transport framing mode for sealed PDUs.
 *  @c seal_framing_datagram expects whole PDUs delimited by record headers;
 *  @c seal_framing_stream parses PDUs from byte streams using engine length prefixes.
 */
typedef enum duct_seal_framing : uint8_t {
    seal_framing_unset = 0,
    seal_framing_stream,
    seal_framing_datagram,
} duct_seal_framing_t;

static_assert(sizeof(duct_seal_framing_t) == sizeof(uint8_t),
    "duct_seal_framing_t must be 8 bits wide");

/** @brief Maximum cleartext prefix length for sealed PDUs, bytes.
 *  Bounds identifiers placed ahead of ciphertext in datagram schemes.
 */
static constexpr size_t duct_seal_prefix_max = 20u;

/** @name Cleartext prefix buffer
 *  Prefix storage, at most @ref duct_seal_prefix_max bytes:
 *  @c duct_seal_prefix_t with @c duct_seal_prefix_set and @c duct_seal_prefix_view.
 *  @{
 */
DUCT_OBUF_DECLARE(duct_seal_prefix, duct_seal_prefix_max)
/** @} */

/** @brief Bytes of a datagram join lead: a 2-byte covered session name and an
 *  8-byte MAC.
 *  The lead fills the first bytes of a prefix at least this wide.
 */
static constexpr size_t duct_seal_lead_size = 10u;

/** @brief Opaque per-conn crypto engine instance.
 *  E.g. an @c SSL object.
 */
typedef struct duct_seal_engine duct_seal_engine_t;

/** @brief Sealed-transport crypto engine contract.
 *
 *  Per-conn instance lifecycle, PDU framing, RX unseal, TX seal.
 */
typedef struct duct_seal_engine_vtbl {
    /** @brief Construct one per-conn instance.
     *  @p cfg is the borrowed @c engine_cfg passed to
     *  @ref duct_wire_create_sealed; @p role is that same call's @c role,
     *  never @c seal_role_unset.
     */
    duct_seal_engine_t *(*create)(void *cfg, duct_seal_role_t role);

    /** @brief Release an instance created by @c create. */
    void (*destroy)(duct_seal_engine_t *e);
    /** @brief Consume one full sealed PDU.
     *
     *  Decrypts cleartext directly into @c ctx->reserve's span, then makes
     *  it visible via @c ctx->commit; may append egress PDUs — handshake
     *  replies, alerts — via @c ctx->tx_append.
     *  @retval rc_ok           PDU consumed.
     *  @retval rc_again        Held for an engine-internal reason, e.g. still
     *                          buffering a fragmented handshake message —
     *                          the caller retries this same PDU later; only
     *                          committed reserves ever become visible.
     *  @retval rc_invalid_arg  Fatal: bad PDU, auth/decrypt failure —
     *                          caller closes the conn.
     */
    duct_result_t (*unseal)(duct_seal_engine_t *e, duct_view_u8 pdu,
                            duct_unseal_ctx_t *ctx);
    /** @brief Expected cleartext byte count for @p pdu, or 0 if unauthenticated.
     *  Sizes destination cleartext buffers before @c unseal. Returns 0 for PDUs
     *  without cleartext or before authentication completes. If null, cleartext
     *  is staged through an intermediate buffer.
     */
    size_t (*unseal_size)(duct_seal_engine_t *e, duct_view_u8 pdu);
    /** @brief Authenticated peer identity view, empty until authentication completes.
     *  Returns a borrowed view into engine state valid for the instance lifetime.
     *  Queried after successful unseal to invoke @c on_peer_auth and verify identity.
     */
    duct_view_u8 (*peer_identity)(duct_seal_engine_t *e);
    /** @brief Derive @p len bytes under @p label, secret and bound to this
     *  instance's handshake, the same on both ends of it.
     *
     *  False until @c peer_identity answers, for a length the scheme cannot
     *  produce, and on any failure. The runtime keys a session's join leads
     *  through it from the session's first named leg; left null, the default,
     *  no leg joins a session over this engine by a lead.
     */
    bool (*derive)(duct_seal_engine_t *e, const char *label, void *out, size_t len);
    /** @brief Per-suite worst-case bytes added per sealed PDU.
     *  Header + tag + any framing byte the scheme needs. Used by the
     *  io-side PDU-length guard and the wire's TX worst-case sizing.
     */
    size_t pdu_overhead;
    /** @brief Length prefix header size for stream framing, bytes.
     *  Leading PDU byte count required by @c pdu_len to parse total frame size.
     *  Must be non-zero for @c seal_framing_stream; 0 for datagram framing.
     */
    size_t pdu_hdr_size;
    /** @brief Parse total PDU size from header bytes, including framing overhead.
     *  Called on the I/O thread without engine instance access; must be a pure function.
     *  @param hdr View of @c pdu_hdr_size leading bytes.
     *  @return Total PDU byte count, or 0 on parse error.
     */
    size_t (*pdu_len)(duct_view_u8 hdr);
    /** @brief Max cleartext bytes per sealed PDU this engine ever produces or
     *  accepts. @ref duct_wire_create_sealed rejects a vtbl declaring more
     *  than @ref duct_seal_pdu_ct_max, which the per-conn cleartext buffer is
     *  sized from.
     */
    size_t pdu_ct_max;
    /** @brief Largest egress one @c unseal call appends through
     *  @c ctx->tx_append, bytes.
     *
     *  On a conn with a TX ring, egress the ring has no room for waits in the
     *  conn's engine park, two messages of this budget, and an unseal waits
     *  while the park has no room for one more. Mandatory:
     *  @ref duct_wire_create_sealed rejects 0, and rejects a budget past half
     *  of @c duct_conn_tx_olb_cap, less a record header and @c tx_prefix_len
     *  under @c seal_framing_datagram: a park the smallest ring cannot take
     *  whole. Counts engine bytes alone: on a @c seal_framing_datagram conn
     *  every @c tx_append writes a @c duct_dgram_record_hdr_size record header
     *  and the wire's prefix as well, and one message counts one of each, so an
     *  engine emitting several appends per unseal carries the extra framing in
     *  this budget itself.
     */
    size_t engine_hs_budget;
    duct_seal_flags_t flags; /**< What this engine promises about its PDUs. */
    /** @brief Engine label the wire reports; "sealed" when left unset. */
    const char *name;
    /** @brief Compute sealed byte count needed to encrypt @p ct_len cleartext bytes.
     *  Returns 0 if the handshake is incomplete. Determines the exact TX buffer
     *  size allocated for @c seal.
     */
    size_t (*seal_size)(duct_seal_engine_t *e, size_t ct_len);
    /** @brief Encrypt and seal @p n cleartext @p spans into preallocated buffer @p dst.
     *  @p dst must be pre-sized to the value returned by @c seal_size for this payload.
     */
    void (*seal)(duct_seal_engine_t *e, const duct_view_u8 *spans, size_t n, void *dst);
    /** @brief Emit graceful closure message (e.g. TLS close_notify) via @p ctx->tx_append.
     *  Optional; if null, connections close without a protocol termination alert.
     */
    void (*close_notify)(duct_seal_engine_t *e, duct_unseal_ctx_t *ctx);
    /** @brief Emit initial client handshake flight (e.g. TLS ClientHello) via @p ctx->tx_append.
     *  Called immediately after engine instance creation before any incoming traffic.
     */
    void (*start)(duct_seal_engine_t *e, duct_unseal_ctx_t *ctx);
    /** @brief Replace this instance's key material.
     *
     *  The conn, its session and @c peer_identity stay as they are, so nothing
     *  above this seam learns a key changed. Called with the conn's next PDU
     *  either way once @c duct_engine_cfg_t's @c seal_key_lifetime_ms has
     *  passed, never by the protocol: @p ctx emits ahead of an inbound PDU's
     *  unseal or behind an outbound one already committed. nullptr, the
     *  default, declines: one key set then serves the conn for its whole life.
     *
     *  Same population rule as @c close_notify. Nothing answered here fails the
     *  conn: an engine that cannot start a replacement leaves the current keys
     *  carrying traffic. Codes other than @c rc_again, @c rc_no_memory, and
     *  @c rc_fatal arm the subsequent rotation interval.
     *
     *  @retval rc_again      Asked again at the conn's next PDU.
     *  @retval rc_no_memory  Asked again at the conn's next PDU.
     *  @retval rc_fatal      This engine will not rekey again; nothing re-arms.
     */
    duct_result_t (*rekey)(duct_seal_engine_t *e, duct_unseal_ctx_t *ctx);
    /** @brief Send the engine's last flight again when a timer armed through
     *  @c ctx->arm fires.
     *
     *  Called on the conn's worker, once per arm, in a context built like the one
     *  @c start receives with @c arm set, so the engine arms the next call from
     *  here. nullptr, the default, declines: the engine arms nothing. Same
     *  population rule as @c close_notify. The runtime cancels the timer only with
     *  the conn's session, so a call can arrive after the engine needs none, and
     *  does nothing then. Best-effort: a @c false from @c tx_append loses that
     *  send, unreported.
     */
    void (*retry)(duct_seal_engine_t *e, duct_unseal_ctx_t *ctx);
} duct_seal_engine_vtbl_t;

/** @brief Classifier distinguishing cleartext control datagrams from sealed PDUs.
 *  Returns the payload view to forward to the protocol, or an empty view if the
 *  datagram is a sealed engine PDU.
 */
typedef duct_view_u8 (*duct_seal_ctl_fn)(void *ctx, duct_view_u8 datagram);

/** @brief Configuration for creating a sealed wire. */
typedef struct duct_sealed_wire_cfg {
    const duct_wire_t             *inner;      /**< Inner framing wire (e.g. length-prefix), or null for raw frames. */
    const duct_seal_engine_vtbl_t *engine;     /**< Crypto engine vtbl pointer. */
    void                          *engine_cfg; /**< User context forwarded to engine constructor. */
    duct_seal_role_t               role;       /**< Handshake role: initiator or responder. */
    duct_seal_framing_t            framing;    /**< Transport framing: stream or datagram. */
    /** @name Per-PDU cleartext prefix widths
     *  Lengths of cleartext prefixes prepended/stripped per datagram PDU.
     *  Valid only for @c seal_framing_datagram; capped by @ref duct_seal_prefix_max.
     *  @{ */
    uint8_t                        tx_prefix_len; /**< Outbound cleartext prefix length, bytes. */
    uint8_t                        rx_prefix_len; /**< Inbound cleartext prefix length stripped before unseal, bytes. */
    /** @} */

    /** @name Cleartext control datagram
     *  Handler for pre-handshake control datagrams (e.g. cookie exchanges).
     *  @{ */
    duct_seal_ctl_fn               rx_ctl;        /**< Classifier for pre-handshake datagrams; null if all traffic is sealed. */
    void                          *rx_ctl_ctx;    /**< User context for @c rx_ctl. */
    /** @} */

    /** @brief Opening packet size ceiling, bytes; 0 for default.
     *  Bounds initial handshake packets for @c on_open.
     */
    uint16_t                       opening_ceiling;

    /** @brief Switch for the per-datagram join lead that names the session.
     *
     *  The lead opens the prefix it travels in, which is at least
     *  @ref duct_seal_lead_size bytes wide: an initiator's @c tx_prefix_len, a
     *  responder's @c rx_prefix_len. Datagram framing only, and the engine needs
     *  @c derive, which keys the lead. An initiator leads a datagram with
     *  @c tx_prefix until its engine has derived the join key, and with a lead
     *  after: the session's name, covered by @c cover_key, and a MAC over the
     *  first 16 bytes of the PDU behind the whole prefix, written once the
     *  datagram is sealed, so the bytes differ from one datagram to the next. A
     *  responder's listener checks the lead of a datagram from an address no conn
     *  holds, and a session of its protocols that the MAC names takes the datagram
     *  at that address.
     */
    bool                           join_lead;

    /** @brief Secret both ends of a deployment hold, covering the bytes that name
     *  a session in a join lead.
     *
     *  A datagram lead's name, and the name, counter and conn id of the one-time
     *  lead a stream leg opens with, go out covered by it: they differ from one
     *  lead to the next and read as noise to anyone without the key. An
     *  initiator's key and the responder's are equal, or no lead resolves. Left
     *  zero, the cover comes from a key anyone can write down. A stream protocol's
     *  leads read it from the wire the protocol runs on.
     */
    uint8_t                        cover_key[duct_wire_cover_key_size];

    /** @brief Bytes every conn this wire binds leads its PDUs with on creation,
     *  @c tx_prefix_len of them read.
     *
     *  Copied into a conn's codec as that codec is built, ahead of the engine's
     *  @c start, so a dial opened outside any session carries them on its
     *  first flight. @c duct_io_connect_via names them for such a dial,
     *  @c control.open_leg.tx_prefix for a leg a live session opens, and
     *  @ref duct_conn_set_tx_prefix replaces them on a leg already up.
     */
    uint8_t                        tx_prefix[duct_seal_prefix_max];
} duct_sealed_wire_cfg_t;

/** @brief Build a sealed wire from @p cfg.
 *
 *  The engine is validated here: @c create, @c destroy, @c unseal,
 *  @c seal_size and @c seal set; @c pdu_len set and @c pdu_hdr_size nonzero
 *  under @c seal_framing_stream;
 *  @c pdu_ct_max in (0, @ref duct_seal_pdu_ct_max]; @c engine_hs_budget in
 *  (0, half of @c duct_conn_tx_olb_cap], less one record header and
 *  @c tx_prefix_len under @c seal_framing_datagram. @c start, @c close_notify,
 *  @c rekey and @c retry are optional. @c role and @c framing must each name a case,
 *  so neither is defaulted, and both prefix widths are refused above
 *  @ref duct_seal_prefix_max or on any framing but @c seal_framing_datagram.
 *  @c join_lead is refused on a stream, for an engine without @c derive, and for
 *  an initiator's @c tx_prefix_len or a responder's @c rx_prefix_len under
 *  @ref duct_seal_lead_size. @c rx_ctl is refused on a stream.
 *
 *  A datagram listener accepts the result only from an engine setting
 *  @c fl_seal_dgram_ok: one datagram is one whole PDU, with no order to
 *  sequence on.
 *  @return New wire, or @c nullptr on a rejected argument or alloc failure.
 */
duct_wire_t *duct_wire_create_sealed(const duct_sealed_wire_cfg_t *cfg);

#ifdef __cplusplus
}
#endif

#endif /* DUCT_SEAL_ENGINE_H */
