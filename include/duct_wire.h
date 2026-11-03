/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_wire.h
 *  @brief Wire layer — per-conn byte framing between transport and frames.
 *
 *  Derived types embed @c duct_wire_t as the first field, dispatching operates
 *  via the vtbl. @c on_parse runs on the i/o-thread, @c on_pack on the worker.
 *
 *  Also the fixed sizes a wire is fitted to: its record and length-prefix
 *  headers, and the IP, UDP and TCP headers its bytes travel behind.
 *
 *  Also the reads of an IP packet: its header length, version and length field,
 *  the view of the packet a frame carries, and that view's group, peer, volume and flow key.
 *
 *  Provides wire contracts, built-in kinds, lifecycle and
 *  wire-changing protocol switch.
 */

#ifndef DUCT_WIRE_H
#define DUCT_WIRE_H

#include "duct_core.h"
#include "duct_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Per-conn wire parse state — defined and brand-casted by each wire
 *  implementation; owned by i/o thread, mutated only inside @c on_parse.
 */
typedef struct duct_wire_parser duct_wire_parser_t;

/** @brief Per-conn sealed-wire reassembly state — cleartext buffer,
 *  parse/ack cursors, crypto engine handle.
 *  Constructed by sealed wire's @c create_codec, read and advanced
 *  by RX drain and @c unseal, freed at conn/session teardown.
 */
typedef struct duct_wire_codec duct_wire_codec_t;

/** @brief TX staging handle for @c on_pack.
 *  Opaque: either a conn's internal @ref duct_olb_tx_t ring or a
 *  one-shot VMQ reservation view;
 *  staged by @c duct_wire_tx_stage, which dispatches on the concrete
 *  shape internally. @c on_pack authors never construct one, only pass
 *  it through.
 */
typedef struct duct_wire_tx duct_wire_tx_t;

/** @brief Size of the internal record-length header the i/o thread
 *  prepends to raw datagrams ahead of any wire on both RX and TX;
 *  a custom @c on_parse must fold it into @c duct_wire_t::header_size.
 */
static constexpr size_t duct_dgram_record_hdr_size = 4;

/** @brief Bytes of the header @c duct_wire_create_length_prefix writes ahead of
 *  each frame's payload. */
static constexpr size_t duct_wire_length_prefix_hdr_size = 4u;

/** @brief UDP header, bytes. */
static constexpr size_t duct_udp_hdr_size = 8u;

/** @brief TCP header carrying no options, bytes.
 *  The smallest one: options widen it, and a segment's real header length is its
 *  data offset field in 4-byte words. */
static constexpr size_t duct_tcp_hdr_min = 20u;

/** @brief IPv4 header carrying no options, bytes.
 *  The smallest one: options widen it, and a packet's real header length is its
 *  IHL field in 4-byte words. */
static constexpr size_t duct_ipv4_hdr_min = 20u;

/** @brief IPv6 header, bytes. Extension headers ride past it. */
static constexpr size_t duct_ipv6_hdr_size = 40u;

/** @brief Largest value IPv4's total-length field carries: header and payload
 *  together. */
static constexpr size_t duct_ipv4_len_max = UINT16_MAX;

/** @brief Largest UDP payload one option-less IPv4 datagram carries, bytes.
 *  The default datagram bound of a datagram wire and of a listener's read, and
 *  the most payload one coalesced group of datagrams carries. */
static constexpr size_t duct_udp4_payload_max =
    duct_ipv4_len_max - duct_ipv4_hdr_min - duct_udp_hdr_size;

/** @brief Read the header length of the IP packet at @p p, of which @p n bytes are at hand.
 *  Reads no byte for an @p n of 0.
 *  @return an IPv4 header's IHL in bytes, 40 for an IPv6 header, whose extension headers ride past it;
 *          0 for another version, an IPv4 header under 20 bytes and a header longer than @p n.
 */
static inline size_t duct_ip_hdr_len(const uint8_t *p, size_t n)
{
    unsigned ver = n ? p[0] >> 4u : 0u;
    size_t hdr = ver == 4u ? (size_t)(p[0] & 0xfu) * 4u : ver == 6u ? duct_ipv6_hdr_size : 0u;
    return hdr >= duct_ipv4_hdr_min && hdr <= n ? hdr : 0u;
}

/** @brief Read the length the IP header at @p p states for its whole packet, header included.
 *  An IPv4 total length, or an IPv6 payload length plus 40. @p p holds a header that
 *  @c duct_ip_hdr_len accepted.
 */
duct_nonnull(1) static inline size_t duct_ip_len(const uint8_t *p)
{
    return (p[0] >> 4u) == 4u ? duct_load_be16(p + 2u) : duct_ipv6_hdr_size + duct_load_be16(p + 4u);
}

/** @brief Read the IP version of @p p taken as one whole packet of @p n bytes.
 *  @return 4 or 6 where the header parses and the length it states equals @p n, else 0.
 */
static inline unsigned duct_ip_version(const uint8_t *p, size_t n)
{
    return duct_ip_hdr_len(p, n) && duct_ip_len(p) == n ? p[0] >> 4u : 0u;
}

/** @brief View of the IP packet in one frame payload.
 *  @ref duct_frame_ip builds it, and the readers below take it by pointer. It points into the payload and stays
 *  valid while the payload keeps its address and size. @c size and @c hdr are 0 where @c packet is null.
 */
typedef struct {
    const uint8_t *packet; /**< First byte of the IP header, null where the payload holds no whole IPv4 or IPv6 header. */
    size_t         size,   /**< Bytes of the packet at hand, from @c packet to the end of the payload. */
                   hdr,    /**< Bytes of the IP header: the IPv4 header with its options, 40 for IPv6, extension headers not counted. */
                   total,  /**< Bytes of the whole payload, a GSO record's lead included. */
                   seg;    /**< Segment size in the lead of a GSO record, 0 for any other payload. */
    bool           gso;    /**< GSO record flag: a 2-byte segment-size lead stands ahead of the packet. */
} duct_frame_ip_t;

/** @brief Find the IP packet in @p payload, past the lead of a GSO record.
 *  @p flags carries @c fl_frame_gso for a record, whose first two bytes are the segment size.
 *  @return the view; its @c packet is null where no IPv4 or IPv6 header lies whole in the payload.
 */
duct_frame_ip_t duct_frame_ip(duct_view_u8 payload, duct_frame_flags_t flags);

/** @brief Test whether the packet in @p ip is addressed to a group.
 *  A group is an IPv4 destination from 224.0.0.0 up, the limited broadcast included, or an IPv6 one in
 *  ff00::/8; a view with no packet is no group.
 */
duct_nonnull(1) bool duct_frame_to_group(const duct_frame_ip_t *ip);

/** @brief Test whether the TCP or UDP packet in @p ip is addressed to @p peer.
 *  The destination address and port equal the peer's. An IPv4 packet, whole or a first fragment, is matched
 *  against an IPv4 peer's address or the last four bytes of a mapped IPv6 one; an IPv6 packet, with TCP or
 *  UDP as its next header, against an unmapped IPv6 peer's address. Any other packet, and a view with no
 *  packet, is not addressed to @p peer.
 */
duct_nonnull(1, 2) bool duct_frame_to_peer(const duct_frame_ip_t *ip, const duct_peer_t *peer);

/** @brief Packets and payload bytes of one frame. */
typedef struct {
    size_t   bytes;   /**< Payload bytes, a GSO record's 2-byte lead left out. */
    unsigned packets; /**< Packets the frame holds: a GSO record's segments, else 1. */
} duct_frame_volume_t;

/** @brief Count the packets and payload bytes of the frame behind @p ip.
 *  A GSO record counts the bytes behind its lead and as many packets as it holds segments of the lead's size,
 *  one packet where the lead states no size, its TCP header does not parse or no payload follows that header.
 *  Any other frame is one packet of its whole size.
 */
duct_nonnull(1) duct_frame_volume_t duct_frame_volume(const duct_frame_ip_t *ip);

/** @brief Hash the flow of the packet in @p ip into a key.
 *  The key folds the protocol, both addresses and, for the first fragment of a TCP or UDP packet, both ports.
 *  @return an odd key; 0 for ICMP, an unfragmented TCP ACK that carries no data and no FIN, SYN or RST, and a
 *          view with no packet.
 */
duct_nonnull(1) uint64_t duct_frame_flow_key(const duct_frame_ip_t *ip);

/** @brief Ephemeral wire context.
 *
 *  Passed into @c unseal, @c start, @c rekey, @c retry and @c close_notify, so the
 *  engine can hand back decrypted cleartext and its own outgoing bytes without
 *  reaching directly into @c duct_wire_codec_t's buffer or the TX ring.
 */
typedef struct duct_unseal_ctx {
    duct_handle_t       handle;  /**< Conn handle; @c tx_append
                                  *   resolves it to wake the owning i/o
                                  *   thread once bytes are staged. */
    duct_wire_codec_t  *codec;   /**< Conn codec; passed to @c reserve/
                                  *   @c commit to read and advance its
                                  *   cleartext buffer. */
    duct_wire_tx_t     *tx_buf;  /**< TX staging target;
                                  *   passed to @c tx_append. */

    /** @brief Take the decrypt-in-place span and the room in it.
     *  @p out_cap is at least this engine's own @c pdu_ct_max, and is the
     *  bound one @c unseal call must keep to.
     */
    void *(*reserve) (struct duct_unseal_ctx *self, size_t *out_cap);

    /** @brief Publish @p len of the reserved span as decrypted cleartext.
     *  @return @c false when @p len runs past the room @c reserve reported;
     *  nothing is published then, and the engine's cue is to fail the PDU.
     *  Anything reserved and never committed, e.g. an aborted or
     *  still-buffering decrypt, is overwritten by the next reservation.
     */
    bool (*commit) (struct duct_unseal_ctx *self, size_t len);

    /** @brief Copy one engine egress record into @c tx_buf and publish it, or
     *  park it in the codec's engine park, ahead of every later byte, while the
     *  ring has no room or parked bytes stand ahead.
     *  A datagram conn without a TX ring stages into its listener's outbox
     *  instead.
     *  @return @c false for a conn gone, a park without room and a full outbox;
     *  under @c unseal the pre-call check keeps the park room for one message.
     */
    bool  (*tx_append)  (struct duct_unseal_ctx *self, duct_view_u8 bytes);

    /** @brief Copy and publish one opening packet into @c tx_buf.
     *  The packet goes out bare of the codec's tx prefix, as a datagram of its own
     *  on a connected datagram socket and as one write of its own on a stream
     *  socket. Set in a context built outside an inbound PDU, the one @c start
     *  receives among them, null in the one @c unseal receives.
     *  @return @c false for a conn that is gone or is neither, when TX room is
     *  exhausted, which is ordinary backpressure, when a stream socket's opening
     *  already holds all the packets it can, and when a stream socket has carried
     *  a byte of its own already, a stream lead apart.
     */
    bool  (*tx_append_bare)(struct duct_unseal_ctx *self, duct_view_u8 bytes);

    /** @brief Largest opening packet, bytes: the wire's @c opening_ceiling.
     *  An engine clamps it to the room its own buffers leave. Set in a context
     *  built outside an inbound PDU, zero in the one @c unseal receives; 0 asks
     *  for no opening packets.
     */
    uint16_t opening_ceiling;

    /** @brief Arm one call of the engine's @c retry after @p delay_ms milliseconds.
     *  The timer belongs to the conn's session and retires with it; a fire that
     *  finds the conn or its codec gone does nothing. The call reaches @c retry on
     *  the conn's worker in a context of this kind, so @c retry arms the next one.
     *  Set in a context built outside an inbound PDU, the one @c start receives
     *  among them, null in the one @c unseal receives.
     *  @retval rc_ok         The call is armed.
     *  @retval rc_closed     The conn is gone.
     *  @retval rc_no_memory  No timer is to be had.
     */
    duct_result_t (*arm)(struct duct_unseal_ctx *self, uint32_t delay_ms);
} duct_unseal_ctx_t;

/** @brief What a wire carries beyond payload bytes, fixed at construction. */
typedef enum duct_wire_flags : uint8_t {
    fl_wire_none        = 0u,
    fl_wire_frame_flags = 1u << 0, /**< The wire bytes carry fin and rst.
                                     *  Raised by length-prefix, by a datagram
                                     *  wire built @c framed, and by a sealed
                                     *  wire whose inner wire raises it. Without
                                     *  it a stream close surfaces at
                                     *  @c on_error as @c rc_not_supported, and
                                     *  an engine-initiated RST closes the whole
                                     *  conn. */
    fl_wire_dgram_ok    = 1u << 1, /**< The wire survives datagram delivery.
                                     *  Copied at construction from the sealed
                                     *  engine @ref fl_seal_dgram_ok, and
                                     *  read where @c unseal is set: a datagram
                                     *  listener holds the wire and never the
                                     *  engine behind it. */
    fl_wire_stream_ids  = 1u << 2, /**< The wire bytes carry a stream id.
                                     *  Raised by the two mux builtins and by a
                                     *  sealed wire over one. Without it every
                                     *  frame arrives on stream 0, so inbound
                                     *  multiplexing is inert however the
                                     *  protocol is configured; an id assigned
                                     *  locally for a server push still works,
                                     *  the peer never learns it. */
    fl_wire_gather      = 1u << 3, /**< One @c duct_wire_tx_stage call per pack,
                                     *  handing over a payload buffer that
                                     *  outlives @c on_pack. Header and payload
                                     *  then reach the socket as two spans, the
                                     *  payload read straight from where its
                                     *  author built it; the header is copied,
                                     *  so @c pack_header buffer is free
                                     *  to die with the call. Raised by the
                                     *  length-prefix, datagram and mux
                                     *  builtins. A wire that rewrites bytes
                                     *  into separate storage leaves it clear
                                     *  and is staged whole instead. */
    fl_wire_join_lead   = 1u << 4, /**< A responder's sealed datagram wire whose
                                     *  peer leads its PDUs with a join lead once
                                     *  the handshake has keyed the session.
                                     *  Raised by @c join_lead on such a wire; the
                                     *  lead opens the prefix @c rx_prefix_len
                                     *  gives and the PDU starts behind it. A
                                     *  datagram listener checks the lead of a
                                     *  datagram from an address no conn holds,
                                     *  ahead of every preparse, and a lead naming
                                     *  a session of one of its protocols joins the
                                     *  datagram to that session. */
} duct_wire_flags_t;

static_assert(sizeof(duct_wire_flags_t) == sizeof(uint8_t),
    "duct_wire_flags_t must be 8 bits wide");

/** @brief Bytes of the key that covers the session name in a join lead. */
static constexpr size_t duct_wire_cover_key_size = 16u;

/** @brief Base wire type; derived types embed this as the first field.
 *
 *  @c on_parse must support replay; @c on_pack staging is atomic.
 *  @c create_parser and @c destroy_parser manage the per-conn
 *  @c duct_wire_parser_t.
 */
typedef struct duct_wire {
    const char *name;               /**< Diagnostic label; borrowed string literal. */
    duct_wire_flags_t flags;        /**< What this wire carries beyond payload. */
    uint8_t rx_prefix_len;          /**< Width of the prefix ahead of each PDU in a
                                     *  datagram this wire receives: a sealed
                                     *  wire's own, 0 for every other. Where
                                     *  @c fl_wire_join_lead is raised the prefix
                                     *  opens with the join lead. */
    /** @brief RX payload slice offset, including datagram record prefix.
     *
     *  Must be correct for every frame the wire emits. On a datagram conn
     *  this may exceed what @c on_pack writes — TX measures the actual
     *  record length independently. 0 = no
     *  header.
     */
    size_t header_size,
           max_frame;               /**< Parse-time payload limit per frame.
                                     *   Sizes RX threshold and TX min_room
                                     *   at bind. Constructor param 0 = use
                                     *   default (1 MiB for LP). */
    unsigned max_batch_frames;      /**< Preferred max frames per WFQ batch;
                                     *   clamped to scheduler ceiling. 0 = no
                                     *   wire preference, use scheduler
                                     *   ceiling only. */
    /** @brief Non-null marks a sealed (layered) wire: io-side @c on_parse
     *  emits whole sealed PDUs (e.g. TLS records) and the worker unseals
     *  each into inner frames parsed by @c inner's own @c on_parse.
     *  nullptr for every non-sealed wire (LP, dgram batch). Borrowed, must
     *  outlive self.
     */
    const struct duct_wire *inner;
    /** @brief Worst-case packed byte count for @p ct_len cleartext bytes —
     *  replaces the default @c ct_len + @c header_size estimate wherever
     *  this wire is bound (admission, TX min-room, stage precheck).
     *  nullptr (default) when packed size is always exactly that; a sealed
     *  wire supplies one since its expansion depends on @p ct_len
     *  (segmentation). Returns @c SIZE_MAX on size overflow to reject
     *  admission.
     */
    size_t (*tx_bound)(const struct duct_wire *self, size_t ct_len);
    /** @brief Header bytes @c on_pack writes for @p frame, as a pure
     *  function of @p frame alone — lets a sealed outer wire learn an
     *  inner wire's header without calling its real @c on_pack (which
     *  stages into an OLB the outer wire doesn't use here). @return bytes
     *  written to @p buf, 0..16. nullptr when the header depends on
     *  running state, not just the frame — such a wire cannot sit under a
     *  sealed outer one; every built-in wire implements it trivially.
     */
    size_t (*pack_header)(const struct duct_wire *self,
                          const duct_frame_t *frame, uint8_t buf[16]);
    /** @brief Release the wire object itself. */
    void (*destroy)(struct duct_wire *self);
    /** @brief Parse one frame from @p input into @p out.
     *
     *  Runs on io-thread only, with no session in scope by design — the
     *  frame this call assembles has not been routed to one yet. Must
     *  tolerate byte replay on @c rc_again. @c out->payload must alias
     *  @p input, never a separate buffer.
     *  @retval rc_ok           One frame in @p out, @p consumed set.
     *  @retval rc_again        Not enough bytes; @p needed is a best-effort
     *                          size hint.
     *  @retval rc_invalid_arg  Parser desynced; @p consumed bytes to discard
     *                          before a protocol-error close.
     */
    duct_result_t (*on_parse)(const struct duct_wire *self,
                              duct_view_u8 input, duct_frame_t *out,
                              duct_wire_parser_t *parser,
                              size_t *consumed, size_t *needed);
    /** @brief Pack one frame into TX staging via @p stage.
     *
     *  Runs on worker only. Staging is atomic. @p
     *  codec is non-null only under a sealed wire; every non-sealed wire's
     *  @c on_pack ignores it.
     *  @retval rc_ok     Frame staged.
     *  @retval rc_again  TX ring has no room; nothing staged, caller retries
     *                    the whole pack later.
     */
    duct_result_t (*on_pack)(const struct duct_wire *self, duct_session_t *s,
                             const duct_frame_t *frame,
                             duct_wire_tx_t *stage,
                             duct_wire_codec_t *codec);
    /** @brief Allocate per-conn wire parser state. */
    duct_wire_parser_t *(*create_parser)(const struct duct_wire *self);
    /** @brief Release per-conn wire parser state. */
    void (*destroy_parser)(const struct duct_wire *self,
                           duct_wire_parser_t *parser);
    /** @brief Allocate worker-owned codec state for a conn on @p xport;
     *  nullptr (default) for a non-sealed wire, where @c unseal is nullptr too and
     *  this is never called.
     *  The codec of an @c x_udp_shared conn has no cleartext buffer: its datagrams
     *  are unsealed one at a time into the worker cleartext ring.
     */
    duct_wire_codec_t *(*create_codec)(const struct duct_wire *self, duct_xport_t xport);
    /** @brief Consume one sealed PDU — exactly the bytes of one io-side
     *  frame, header included — appending 0+ cleartext bytes to @p ctx and
     *  optionally emitting egress through it (handshake replies, alerts).
     *  Worker-only, non-null only for a sealed wire.
     *  @retval rc_ok           PDU consumed.
     *  @retval rc_again        Not consumable yet, no side effects (caller
     *                          defers).
     *  @retval rc_invalid_arg  Fatal (bad PDU or auth failure) —
     *                          protocol-error close.
     */
    duct_result_t (*unseal)(const struct duct_wire *self,
                            duct_wire_codec_t *codec,
                            duct_view_u8 pdu, duct_unseal_ctx_t *ctx);
    /** @brief Key covering the bytes that name a session in a join lead, a
     *  datagram's and a stream leg's.
     *  All zero for every wire but a sealed one. Where @c fl_wire_join_lead is
     *  raised, and for the leg leads of a protocol on this wire, io reads the name
     *  through it. */
    uint8_t cover_key[duct_wire_cover_key_size];
} duct_wire_t;

/** @brief Stage header + payload atomically into the TX ring.
 *
 *  Both spans fit, or neither is staged. Pass a zero-size @c hdr for a
 *  header-less frame.
 *
 *  @retval rc_ok           Staged.
 *  @retval rc_again        Staging is full; nothing staged, retry the whole
 *                          pack later.
 *  @retval rc_invalid_arg  A nonzero-size buffer has NULL @c data.
 */
duct_nonnull(1) duct_result_t duct_wire_tx_stage(duct_wire_tx_t *stage,
                                                 duct_view_u8 hdr,
                                                 duct_view_u8 payload);

/** @brief Build a length-prefix wire: 4-byte big-endian header, then payload.
 *
 *  The header's top three bits carry @c fl_frame_fin, @c fl_frame_rst and
 *  @c fl_frame_gso, the low 29 its payload length, so the flags reach the peer
 *  without a byte of their own and a frame carrying none is a bare length
 *  prefix. Caller-owned. Release it with @ref duct_wire_destroy, or hand
 *  ownership to a protocol through @c owned_wire and let @c duct_proto_destroy
 *  do it.
 *
 *  @param max_frame  Maximum payload per frame; 0 = default, 1 MiB. From
 *                    2^29 up there is no room left for the flag bits.
 *  @return Wire handle, or @c nullptr on allocation failure or a refused
 *          @p max_frame.
 */
duct_wire_t *duct_wire_create_length_prefix(size_t max_frame);

/** @brief Build a datagram-batch wire, for datagram conns.
 *
 *  RX splits a batch of received datagrams apart on the same 4-byte length
 *  prefix the io thread writes; that prefix is internal and never reaches the
 *  peer. Ownership is @ref duct_wire_create_length_prefix's.
 *
 *  @param max_dgram  Maximum bytes per datagram; 0 takes
 *                    @ref duct_udp4_payload_max.
 *  @param framed     @c false leaves every byte a peer sees as payload, so a
 *                    raw device leg's packets and a foreign peer's datagrams
 *                    cross unchanged — and there is nowhere to put fin and
 *                    rst, so the wire raises no @c fl_wire_frame_flags.
 *                    @c true prepends one @ref duct_frame_flags_t byte to each
 *                    datagram, raising it; a datagram has no length field of
 *                    its own to carry the flags in, so they cost a byte here.
 *  @return Wire handle, or @c nullptr on allocation failure.
 */
duct_wire_t *duct_wire_create_dgram_batch(size_t max_dgram, bool framed);

/** @brief Return the process-wide wire of packet-fd legs, one frame per packet.
 *
 *  A frame is one whole IP packet of up to @ref duct_ipv4_len_max bytes with no
 *  framing byte: @ref duct_wire_create_dgram_batch at that size with @c framed
 *  false. The library builds it before @c main and keeps it to process exit, so
 *  every leg, protocol and engine binds the same wire and nothing releases it.
 *  Pass it as @c leg_wire to @ref duct_conn_attach_packet_fd.
 *
 *  @return the wire, never @c nullptr.
 */
const duct_wire_t *duct_wire_packet(void);

/** @brief Build a multiplexed wire, for stream conns.
 *
 *  An 8-byte big-endian header — one flags byte, a 24-bit payload length, then
 *  a 32-bit stream id — allowing multiple logical streams over a single
 *  connection where @c fl_frame_fin terminates only the designated stream.
 *  The flags byte is @ref duct_frame_flags_t verbatim; bits this version does
 *  not define are ignored on arrival. Ownership is @ref duct_wire_create_length_prefix's.
 *
 *  The id field is the application's to fill and the engine reads it as opaque,
 *  with one reservation: 0 is the connection-level stream and never claims a
 *  slot. Who may assign which ids is @ref fl_proto_multiplexed's own contract.
 *
 *  @param max_frame  Maximum payload per frame; 0 = default, 1 MiB. Past
 *                    2^24 there is no room in the length field, and the call
 *                    answers @c nullptr.
 *  @return Wire handle, or @c nullptr on allocation failure.
 */
duct_wire_t *duct_wire_create_mux(size_t max_frame);

/** @brief Build a multiplexed wire, for datagram conns.
 *
 *  @ref duct_wire_create_mux's fields minus the length, which the io thread's
 *  own record prefix already carries: each datagram opens with one flags byte
 *  and a 32-bit stream id, and the rest is payload. A datagram too short to
 *  hold those five bytes is dropped whole, costing itself and not the conn.
 *
 *  @param max_dgram  Maximum bytes per datagram, header included; 0 takes
 *                    @ref duct_udp4_payload_max. At or below the 5-byte header
 *                    the call answers @c nullptr, no payload being encodable.
 *  @return Wire handle, or @c nullptr on allocation failure.
 */
duct_wire_t *duct_wire_create_mux_dgram(size_t max_dgram);

/** @brief Destroy a wire and release its resources.
 *
 *  @p w must be non-null (@ref duct_nonnull); a wire that may not have been
 *  built is the caller's own branch. Does not touch per-conn wire state.
 */
duct_nonnull(1) static inline void duct_wire_destroy(duct_wire_t *w)
{
    if (w->destroy)
        w->destroy(w);
}

/** @brief Allocate per-conn wire parser state via the wire's @c create_parser.
 *
 *  Caller stores the result in @c conn->wire_parser.
 */
duct_nonnull(1) static inline duct_wire_parser_t *
duct_wire_parser_create(const duct_wire_t *w)
{
    return w->create_parser ? w->create_parser(w) : nullptr;
}

/** @brief Destroy per-conn wire parser state via the wire's @c destroy_parser
 *  vtbl.
 *
 *  @p w must be non-null (@ref duct_nonnull); @p parser alone may be
 *  @c nullptr — the wire's own @c destroy_parser decides what that means.
 */
duct_nonnull(1) static inline void
duct_wire_parser_destroy(const duct_wire_t *w, duct_wire_parser_t *parser)
{
    if (w->destroy_parser)
        w->destroy_parser(w, parser);
}

#ifdef __cplusplus
}
#endif

#endif /* DUCT_WIRE_H */
