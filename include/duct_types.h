/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_types.h
 *  @brief Fundamental types shared across the public API and internal runtime.
 *
 *  IDs, session token, result/close codes, buffer and frame views, the owning
 *  byte buffer generator, accepted-peer address, inter-conn push-batch view and
 *  coroutine function signatures shared between the protocol surface and the
 *  internal coroutine runtime.
 *  Data and the small accessors that read it; behaviour lives with the API that
 *  uses it.
 */

#ifndef DUCT_TYPES_H
#define DUCT_TYPES_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#if defined(__has_include)
#if __has_include("duct_build_config.h")
#include "duct_build_config.h"
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Byte bound of the array type a @c duct_ptr_t points to.
 *  The smaller of @c PTRDIFF_MAX and 2^61 - 1, the largest array type every compiler of the tree
 *  takes. No real array comes near it.
 */
static constexpr uint64_t duct_ptr_bound_bytes =
    (uint64_t)PTRDIFF_MAX < (UINT64_MAX >> 3) ? (uint64_t)PTRDIFF_MAX : UINT64_MAX >> 3;

/** @brief Pointer to the array of @c T that @c duct_new answers when given a count.
 *  The type is @c T (*)[duct_ptr_bound_bytes / sizeof(T)], a bound only these pointers carry:
 *  the compiler refuses one from another element type, from a plain @c T * and from the address
 *  of a fixed-size array. The address of a variable length array converts without a word, and
 *  @ref duct_is_ptr stops it at the accessors. The pointer is never dereferenced as an array:
 *  @ref duct_at yields the elements, and @c p + off steps in whole arrays.
 *  A read-only view is @c duct_ptr_t(const T), which a writable array converts to;
 *  @c duct_ptr_t(T) a, b; declares two pointers.
 */
#define duct_ptr_t(T) typeof(T (*)[duct_ptr_bound_bytes / sizeof(T)])

/** @brief Runtime engine; owns I/O threads, workers and session table. */
typedef struct duct_engine duct_engine_t;

/** @brief Protocol definition; callbacks for one application protocol. */
typedef struct duct_proto duct_proto_t;

/** @brief Session identity; binds connections and protocol state. */
typedef struct duct_session duct_session_t;

/** @brief Wire parse/pack chain between transport bytes and logical frames. */
typedef struct duct_wire duct_wire_t;

/** @brief Stream identifier within a multiplexed session. */
typedef uint32_t duct_stream_id_t;

/** @brief Timer identifier, unique within a worker heap.
 *
 *  Filled into @c out->control.timer.id_out when a declarative timer is started,
 *  matched by @c out->control.timer.cancel_id.
 */
typedef uint64_t duct_timer_id_t;

/** @brief Connection identifier within a session; a logical transport leg.
 *
 *  Index in session's connection array: 0 is a primary conn created by
 *  listen(), connect() or bind(); higher ids are attached at runtime.
 *  Valid only while the session is live.
 */
typedef uint32_t duct_conn_id_t;

/** @brief Primary connection; a leg created by listen, connect, or bind. */
static constexpr duct_conn_id_t duct_conn_id_primary = 0;

/** @brief Default stream for single-stream and datagram protocols. */
static constexpr duct_stream_id_t duct_stream_id_default = 0;

/** @brief Opaque 64-bit pool-handle word for cross-module storage.
 *
 *  Can only be copied, stored and/or cleared. Internal typed views such as
 *  @c duct_session_handle_t carry resolve and field-access semantics.
 */
typedef uint64_t duct_handle_t;

/** @brief Null handle word; never identifies a live object. */
static constexpr duct_handle_t handle_null = 0u;

/** @brief Result codes for various API calls. */
typedef enum duct_result : int {
    rc_ok,                 /**< Success. */
    rc_defer,             /**< Caller replays the same unit later; no side effect. */
    rc_drop,              /**< Discard current RX unit. */
    rc_again,             /**< Retry the same call now; no side effect. */
    rc_closed,            /**< Object already closed. */
    rc_fatal,             /**< Unrecoverable error. */
    rc_not_implemented,   /**< Runtime entry not wired for this build. */
    rc_not_supported,     /**< Feature or mode unsupported. */
    rc_invalid_arg,       /**< Bad parameter. */
    rc_invalid_order,     /**< Wrong call sequence. */
    rc_no_memory,         /**< Allocation failed. */
    rc_dns_fail,          /**< Outbound connect: hostname resolution failed. */
    rc_conn_refused,      /**< Outbound connect: peer rejected the connection. */
    rc_conn_timeout,      /**< Outbound connect: no completion before @c connect_timeout_ms. */
    rc_timeout,           /**< Caller's bounded wait expired; the posted op still runs. */
    rc_frame_too_large,   /**< Datagram wire refused a frame for its size. Reported through
                               @c on_error; the conn stands. */

    /** @note Additional result codes must be placed here. */
    rc_count
} duct_result_t;

/** @brief Why a session, conn or stream is closing. */
typedef enum duct_close_reason : uint8_t {
    close_normal,           /**< Graceful close by the protocol. */
    close_peer,             /**< Peer initiated the close. */
    close_protocol_error,   /**< Protocol violation detected. */
    close_io_error,         /**< Transport read or write failed. */
    close_timeout,          /**< Deadline run out: idle, keepalive or
                              *   handshake, kept by the protocol or, from its
                              *   config, by the engine. A close requested
                              *   with it takes effect at once, dropping what
                              *   the conn's TX ring still holds. */
    close_internal_error    /**< Runtime internal failure. */
} duct_close_reason_t;

/** @brief Transport kind of a connection's underlying fd;
 *  drives per-conn I/O dispatch behavior across the OS backends.
 */
typedef enum duct_xport : uint8_t {
    x_raw,          /**< Caller-attached fd; read/write. @see duct_conn_attach_fd */
    x_raw_packet,   /**< Caller-attached packet-delimited fd; read/write, one
                      *   whole packet per read, record-framed in the RX ring. */
    x_tcp,          /**< TCP socket; read/write. */
    x_udp,          /**< Shared unconnected datagram socket; sendto/recvfrom. */
    x_udp_peer,     /**< Connected per-peer datagram socket (e.g. SO_REUSEPORT demux); send/recv. */
    x_udp_shared,   /**< No owned @c fd at all: RX/TX both ride the listener's own
                      *  shared socket, demuxed by peer tracking and dispatched through this conn's
                      *  inter lane; @c fd == @c duct_sock_bad. */
    x_bt,           /**< Bluetooth device; reserved, no backend yet. */
    x_can,          /**< CAN bus; reserved, no backend yet. */
    x_inter,        /**< Push-mode leg with no socket; fd is a "kick" premise. */
    x_local         /**< AF_UNIX stream socket accepted on a path-bound listener; read/write. */

    /* x_all = 0xFFu,  All transports. */
} duct_xport_t;

/** @brief True when @p t carries its own message boundaries, so one write is
 *  one message a receiver gets whole or not at all.
 *  An oversized write costs a delimited transport that one message; a stream
 *  has no boundary to resume past, so the same failure ends the conn.
 */
static inline bool duct_xport_delimited(duct_xport_t t)
{
    switch (t) {
    case x_raw_packet:
    case x_udp:
    case x_udp_peer:
    case x_udp_shared:
    case x_can:
        return true;
    case x_raw:
    case x_tcp:
    case x_bt:
    case x_inter:
    case x_local:
        return false;
    }
    return false;
}

/** @brief Bytes a TCP congestion-control name takes, its NUL included.
 *  Linux's @c TCP_CA_NAME_MAX. */
static constexpr size_t duct_tcp_cc_name_max = 16u;

/** @brief Congestion figures the kernel reports for one TCP socket. */
typedef struct duct_tcp_stats {
    uint32_t cwnd;       /**< Congestion window, bytes. */
    uint32_t rtt_us;     /**< Smoothed round-trip time, microseconds. */
    uint32_t min_rtt_us; /**< Least round-trip time measured, microseconds. */
    uint32_t timeouts;   /**< Retransmission-timeout episodes since the socket
                           *  opened. Where the kernel counts none, the count is
                           *  of the episodes the reads caught in progress, so
                           *  one that starts and ends between two reads goes
                           *  uncounted. Where the stack reports acknowledged
                           *  bytes, bytes left unacknowledged for two
                           *  retransmission timeouts count one as well, once
                           *  per such stretch. */
    uint32_t unacked;    /**< Bytes sent and not yet acknowledged, 0 once all
                           *  sent is; segments at the send MSS where the
                           *  stack counts segments. */
} duct_tcp_stats_t;

/** @brief Unsent-bytes figure that was not read, past any queue a socket holds.
 *  What @ref duct_conn_tx_unsent answers where it has none to give. */
static constexpr uint64_t duct_tx_unsent_unread = UINT64_MAX;

/** @name Runtime-counted bounds
 *  The count member names the array's element count, and
 *  @c __builtin_dynamic_object_size reads it back wherever the toolchain
 *  honors the attribute, making every fortify-bounded access through the
 *  member a checked one.
 *
 *  Every branch spells the GNU form: the @c [[gnu::counted_by]] C23 spelling
 *  is unknown to the compilers this tree builds on even where the feature
 *  exists (clang 22 answers "unknown attribute ignored" for it). The two
 *  macros split by what the toolchain accepts: @c counted_by on a trailing
 *  flexible array member follows @c __has_attribute(counted_by), while
 *  pointer-member @c counted_by shares that same attribute name in older
 *  frontends that reject pointers, so CMake probes pointer support directly
 *  with @c check_c_source_compiles into @c DUCT_HAS_PTR_COUNTED_BY.
 *  @{
 */
#if defined(__has_attribute) && __has_attribute(counted_by)
#define duct_counted_by(member) __attribute__((counted_by(member)))
#else
#define duct_counted_by(member)
#endif
#if defined(DUCT_HAS_PTR_COUNTED_BY) && DUCT_HAS_PTR_COUNTED_BY
#define duct_ptr_counted_by(member) __attribute__((counted_by(member)))
#else
#define duct_ptr_counted_by(member)
#endif
/** @} */

/** @brief Named views of the duct_view macros; the constructors live in
 *  duct_core.h. The members lay out as @c struct iovec, the order the kernel
 *  spans ride — the pointer-form counted_by wants the count first, so the
 *  views carry none. */
typedef struct { uint8_t *data; size_t size; } duct_view_u8;
typedef struct { const uint8_t *data; size_t size; } duct_view_cu8;
typedef struct { const char *data; size_t size; } duct_view_cc;
typedef struct { uint32_t *data; size_t size; } duct_view_u32;
typedef struct { const uint32_t *data; size_t size; } duct_view_cu32;

/** @brief The text view @p s as a view of bytes, where text leaves for the wire. */
static inline duct_view_u8 duct_view_bytes(duct_view_cc s)
{
    return (duct_view_u8){ (uint8_t *)(uintptr_t)s.data, s.size };
}

/** @brief The wire view @p s as text.
 *  The reverse of @ref duct_view_bytes, for a protocol whose frames arrive as text. */
static inline duct_view_cc duct_view_text(duct_view_u8 s)
{
    return (duct_view_cc){ (const char *)s.data, s.size };
}

/** @name Owning byte buffer generator
 *  Emits @c name##_t, which holds up to @p cap bytes in storage of its own and
 *  fails the build for a @p cap past a byte's range, with @c name##_set and
 *  @c name##_view.
 *
 *  @c _set copies a @ref duct_view_u8 in. It answers false, leaving the buffer as it
 *  was, for more than @p cap bytes or a size with no data. @c _view answers a
 *  @ref duct_view_u8 over the buffer's bytes, valid while the buffer is.
 *  @{
 */
#define DUCT_OBUF_DECLARE(name, cap)                                        \
static_assert((cap) <= UINT8_MAX, #name " must size itself in one byte");   \
typedef struct {                                                            \
    uint8_t size;                                                           \
    uint8_t data[(cap)];                                                    \
} name##_t;                                                                 \
static inline bool name##_set(name##_t *obuf, duct_view_u8 src)               \
{                                                                           \
    if (src.size > sizeof obuf->data || (src.size && !src.data))            \
        return false;                                                       \
    obuf->size = (uint8_t)src.size;                                         \
    if (src.size)                                                           \
        memcpy(obuf->data, src.data, src.size);                             \
    return true;                                                            \
}                                                                           \
static inline duct_view_u8 name##_view(name##_t *obuf)                        \
{                                                                           \
    return (duct_view_u8){ obuf->data, obuf->size };          \
}
/** @} */

/** @brief Logical frame flags set by the wire layer. */
typedef enum duct_frame_flags : uint8_t {
    fl_frame_none = 0u,
    fl_frame_fin  = 1u << 0,  /**< Final frame of the stream. */
    fl_frame_rst  = 1u << 1,  /**< Stream reset. */
    fl_frame_gso  = 1u << 2,  /**< Payload is a GSO record: a 2-byte big-endian
                                *  segment size, then one TCP packet of two or
                                *  more such segments. A vnet leg reads and
                                *  writes it, a wire with @c fl_wire_frame_flags
                                *  carries it, and every other leg refuses it
                                *  with @c rc_not_supported. */
    fl_frame_env  = 1u << 3,  /**< An 8-byte @c duct_dgram_env_t trailer rides
                                *  the frame's tail; the codec strips it and
                                *  clears the bit before @c on_frame sees the
                                *  frame. */
} duct_frame_flags_t;

static_assert(sizeof(duct_frame_flags_t) == sizeof(uint8_t),
    "duct_frame_flags_t must be 8 bits wide");

/** @brief Logical protocol frame produced by the wire parse. */
typedef struct duct_frame {
    duct_stream_id_t   stream_id; /**< Logical stream; 0 for single-stream protocols. */
    duct_frame_flags_t flags;     /**< Frame flags from wire layer. */
    duct_view_u8        payload;   /**< Non-owning view; valid for callback invocation only. */
} duct_frame_t;

/** @brief Accepted peer address; platform-agnostic. */
typedef struct duct_peer {
    uint16_t family,         /**< @c AF_INET / @c AF_INET6. */
             port;           /**< Port in host byte order. */
    union {
        uint8_t v4[4],       /**< IPv4 address; valid when @c family == @c AF_INET. */
                v6[16];      /**< IPv6 address; valid when @c family == @c AF_INET6. */
    } addr;
} duct_peer_t;

/** @brief IP versions packets travel as, one bit each.
 *  A set holds both bits where both are in use. */
typedef enum duct_ip_flags : uint8_t {
    fl_ip_none = 0u,
    fl_ip_v4   = 1u << 0,  /**< IPv4. */
    fl_ip_v6   = 1u << 1,  /**< IPv6. */
} duct_ip_flags_t;

static_assert(sizeof(duct_ip_flags_t) == sizeof(uint8_t),
    "duct_ip_flags_t must be 8 bits wide");

typedef struct duct_response duct_response_t;

/** @brief Session callback filling an output response.
 *
 *  @param s     Live session.
 *  @param out   Zero-initialized response output.
 *  @param ctx   Host-supplied invocation payload.
 *
 *  @return Result reported back to a synchronous caller; ignored for async posts.
 */
typedef duct_result_t
(*duct_session_fn)(duct_session_t *s, duct_response_t *out, void *ctx);

/** @brief Pre-parse disposition: classify an accepted fd for one protocol.
 *  @c resolve_not_me == 0, so a zero-initialized output continues dispatch safely.
 */
typedef enum duct_resolve_disposition : uint8_t {
    resolve_not_me,       /**< Peek does not match this protocol; try next. */
    resolve_new,          /**< Match; create a new session with this proto. A stream
                            *  listener writes @c preparse_reply's bytes, when the
                            *  protocol offers them, ahead of the session's first
                            *  byte. */
    resolve_join,         /**< Match; join an existing session. */
    resolve_reject,       /**< Match but invalid; close fd, stop dispatch. */
    resolve_retry,        /**< Match, not admissible yet; answer the peer once,
                            *  then drop. A datagram listener answers off its own
                            *  socket, a stream one on the stranger's connection
                            *  before the close. */
    resolve_hold,         /**< Peek may match once more bytes are in; wait for
                            *  them. A stream listener holds the fd under its
                            *  @c probe_wait_ms with the bytes it already holds,
                            *  re-classifying as they grow; anything else reads
                            *  it as @c resolve_not_me. */

    /** @note Additional dispositions must be placed here. */
    resolve_count
} duct_resolve_disposition_t;

static_assert(sizeof(duct_resolve_disposition_t) == sizeof(uint8_t),
    "duct_resolve_disposition_t must be 8 bits wide");

/** @brief Stackless coroutine. */
typedef struct duct_async duct_async_t;

/** @brief Stackful coroutine. */
typedef struct duct_coro duct_coro_t;

/** @brief Stackless coro step outcome. */
typedef enum duct_async_rc : uint8_t {
    async_done = 0u,  /**< Handler finished; the stream closes. */
    async_yield,      /**< Still runnable — step again on the next cycle. */
    async_wait,       /**< Ack the frame and park until the next one arrives. */

    /** @note Additional outcomes must be placed here. */
    async_count
} duct_async_rc_t;

/** @brief Stackless coro step function;
 *  @retval async_done   Handler finished; the stream closes.
 *  @retval async_yield  Still runnable — step again on the next cycle.
 *  @retval async_wait   Ack the frame and park until the next one arrives.
 */
typedef duct_async_rc_t (*duct_async_step_t)(void *state);

/** @brief Stackful coro entry function. */
typedef void (*duct_coro_func_t)(void *arg);

/** @brief Post-step hook for stackless coroutines. */
typedef void (*duct_async_done_fn)(duct_async_t *co, duct_async_rc_t rc, void *ctx);

/** @brief Post-resume hook for stackful coroutines. */
typedef void (*duct_coro_resume_fn)(duct_coro_t *co, void *ctx);

/** @brief Handler dispatch kind for multiplexed protocols. */
typedef enum duct_handler_kind : uint8_t {
    handler_none,   /**< No handler — @c on_frame path. */
    handler_async,  /**< Stackless: @c duct_async_step_t. */
    handler_coro,   /**< Stackful: @c duct_coro_func_t. */

    /** @note Additional handler kinds must be placed here. */
    handler_count
} duct_handler_kind_t;

/** @brief One packet pushed into an inter conn.
 *
 *  @c stream_id and @c flags are host-declared framing metadata for
 *  multiplexing inter conns; set them to @ref duct_stream_id_default and
 *  @c fl_frame_none respectively for opaque / single-stream case.
 */
typedef struct duct_inter_pkt {
    duct_view_u8        payload;   /**< View into caller or held storage. */
    duct_ptr_t(uint8_t) hold;      /**< Optional owning block moved on rc_ok. */
    duct_stream_id_t    stream_id; /**< Target stream; duct_stream_id_default for opaque. */
    duct_frame_flags_t  flags;     /**< @c fl_frame_fin and @c fl_frame_rst close stream
                                     * after this packet. */
} duct_inter_pkt_t;

/** @brief Batch of packets pushed into an inter conn.
 *
 *  Handoff is synchronous: every packet is copied onto the conn's inter lane
 *  before @ref duct_io_inter_batch returns, so caller storage is free as soon as the call returns.
 *  Allocate with @ref duct_inter_batch_bytes and index with @ref duct_inter_batch_pkt.
 */
typedef struct duct_inter_batch {
    unsigned n;                         /**< Number of packets in @c pkts. */
    alignas(8) duct_inter_pkt_t pkts[] duct_counted_by(n); /**< Packets; non-owning views into caller storage. */
} duct_inter_batch_t;

/** @brief Full size of an inter batch holding @p n packets. */
#define duct_inter_batch_bytes(n) \
    (sizeof(duct_inter_batch_t) + (size_t)(n) * sizeof(duct_inter_pkt_t))

/** @brief Pointer to packet @p i in @p b; no bounds check. */
static inline duct_inter_pkt_t *duct_inter_batch_pkt(duct_inter_batch_t *b, unsigned i)
{
    return &b->pkts[i];
}

/** @brief Egress for an inter conn — the runtime hands an outbound packet to the host.
 *
 *  Invoked on the host executor through @c duct_host_cfg_t::run, never on the
 *  worker, when the worker emits TX on a conn attached with @c duct_conn_attach_inter.
 *
 *  @param app_ctx  @c duct_host_cfg_t::ctx.
 *  @param tok      Session that produced the packet.
 *  @param conn_id  Inter conn the packet targets.
 *  @param pkt      Non-owning; valid only for the call. Copy it if the host sink
 *                 consumes it asynchronously.
 *
 *  Must not call @c duct_session_invoke_sync or otherwise block on the worker.
 */
typedef void (*duct_packet_out_fn)(void *app_ctx,
                                    duct_handle_t tok,
                                    duct_conn_id_t conn_id,
                                    duct_view_u8 pkt);

/** @brief Host executor dispatch hook.
 *
 *  Schedules @c fn(ctx) onto the host egress queue for @c on_packet_out
 *  execution. Required when inter connections exist; otherwise @c nullptr.
 *
 *  @param fn         Work item to run on the host queue.
 *  @param ctx        Argument forwarded to @p fn.
 *  @param queue_ctx  @c duct_host_cfg_t::queue_ctx.
 */
typedef void (*duct_host_run_fn)(void (*fn)(void *ctx), void *ctx, void *queue_ctx);

/** @brief Backpressure release for inter-conn ingress.
 *
 *  Called once the conn's RX staging has room again after a pushed batch drains;
 *  the host issues its next read from here. @c nullptr when no inter conn is used.
 *
 *  @param app_ctx  @c duct_host_cfg_t::ctx.
 */
typedef void (*duct_inter_resume_fn)(void *app_ctx);

/** @brief Host-bridge configuration for inter conns.
 *
 *  "Host" is the embedding application: code running on any thread the engine
 *  does not own — not an io thread, not a worker. Leave every field
 *  @c nullptr (zero-initialized) when no inter conn is used.
 */
typedef struct duct_host_cfg {
    duct_host_run_fn     run;             /**< Dispatch onto the host queue; required with inter conns. */
    void                 *queue_ctx;       /**< Forwarded to @c run. */
    duct_packet_out_fn    on_packet_out;   /**< Inter-conn TX sink; required when any inter conn exists. */
    duct_inter_resume_fn  on_inter_resume; /**< Fires after a worker drains an inter conn's lane — a
                                             *  hint to retry a push that returned rc_defer, not a
                                             *  per-push wait requirement. @c nullptr when unused. */
    void                 *ctx;             /**< Forwarded to @c on_packet_out and @c on_inter_resume. */
} duct_host_cfg_t;

/** @brief Listener transport kind. */
typedef enum duct_listener_kind : uint8_t {
    listener_stream, /**< TCP-like: one listen socket, accept() per new session (default). */
    listener_dgram,  /**< UDP-like: one shared classification socket, per-peer conns spun off
                       *  via connect() on first datagram. @see duct_listener_bind */
} duct_listener_kind_t;

/** @brief One bound listener with its protocol array.
 *        Passed to @ref duct_listener_bind.
 *
 *  @c protos is borrowed for the @ref duct_listener_bind call only; the runtime
 *  copies the array. Array order is dispatch priority: on accept/receipt the
 *  runtime tries protocols in order (sync pre-parse, then async, then
 *  @c preparse==NULL fallbacks) and the first non-@c resolve_not_me wins.
 *  @c addr is the bind host only (e.g. @c "127.0.0.1", @c "::1"); the port is
 *  passed separately to @ref duct_listener_bind as an in/out parameter.
 *  A path listener sets @c local_path in place of @c addr, and the three
 *  fields after it are its alone.
 */
typedef struct duct_listener_cfg {
    const char                *addr;     /**< Bind host: bare name/IP, no port, no brackets. */
    unsigned                   n_protos; /**< Entries in @c protos; at least 1. */
    const duct_proto_t *const *protos;   /**< Borrowed for the call; order = dispatch priority. */
    duct_listener_kind_t       kind;     /**< @c listener_stream (default) or @c listener_dgram. */
    size_t                     peek_cap; /**< Stream: max bytes to read for pre-parse
                                              probe — consumed for good, then re-injected
                                              into the conn's own RX once it exists. Datagram: max
                                              accepted payload for classification (whole datagram
                                              either way). Either way, 0 = default. */
    uint32_t                   probe_wait_ms; /**< Stream only: if every sync pre-parse returns
                                              @c resolve_not_me on a literally empty first read, wait
                                              up to this long for the peer's first bytes before falling
                                              back to the has_async/fallback/reject dispatch — at
                                              most one wait per accepted fd. @c peek_min extends the
                                              wait to a first read that is short. 0 = disabled (default). */
    uint16_t                   peek_min; /**< Stream only: bytes a first read has to reach before the
                                              runtime asks anything of it, a pre-parse and the engine's
                                              join lead included. A shorter read is held and the wait
                                              goes on until the bytes are in, the peer closes or
                                              @c probe_wait_ms runs out, and what was read is then
                                              classified as it stands; arrivals leave that deadline
                                              where it was. Needs @c probe_wait_ms and is at most the
                                              stream read span: @c peek_cap, or the runtime's default
                                              clamped to its largest size. 0 = off (default). */
    const char                *local_path; /**< Socket file of an AF_UNIX stream listener, shorter
                                              than @c sockaddr_un's @c sun_path; @c nullptr = an
                                              address listener. Needs @c addr unset and
                                              @c listener_stream. */
    const char                *local_group; /**< Group of the socket file: a name or a decimal gid;
                                              @c nullptr = left as created. Path listener only,
                                              refused on Windows. */
    uint16_t                   local_mode; /**< Permission bits of the socket file, the low nine of
                                              the value, applied before the listener accepts; 0 =
                                              left as created. Path listener only, refused on
                                              Windows. */
    uint16_t                   max_sessions; /**< Most accepted conns alive at once on a path
                                              listener; a client past it is closed before a conn
                                              is taken. 0 = no cap. Path listener only. */
    uint16_t                   max_conns_per_s; /**< Most conns a path listener takes in a second, one every
                                              1/N s: it stops accepting for that long after each accept,
                                              and the clients that come meanwhile wait in the socket's
                                              queue, one place on Linux and five on Windows, a
                                              non-blocking connect that finds it full failing at once.
                                              0 = no pace. Path listener only. */
} duct_listener_cfg_t;

/** @brief Statistics section: a protocol's table of named counters, kept in one shard for each I/O thread and each worker.
 *  Made by @ref duct_stats_create and owned by its engine, which frees it in
 *  @ref duct_engine_destroy.
 */
typedef struct duct_stats duct_stats_t;

/** @brief Row of a section's table: one counter by name and place in the shard. */
typedef struct {
    const char *name;   /**< Counter name, copied into the section. */
    uint16_t    offset; /**< Byte offset of the counter in a shard: a multiple of 8, the start of a @c uint64_t @c _Atomic. */
} duct_stat_field_t;

/** @brief Initializer of one @c duct_stat_field_t row, named as @p member and placed at its offset in the struct @p T. */
#define duct_stat_field(T, member) { #member, offsetof(T, member) }

/** @brief Table of a statistics section. */
typedef struct {
    const char              *name;       /**< Section name, non-empty. */
    const duct_stat_field_t *fields;     /**< Counters of the section, read in this order. */
    uint16_t                 n_fields;   /**< Rows in @c fields, at least 1. */
    uint16_t                 shard_size; /**< Bytes of the struct one shard holds. */
} duct_stats_cfg_t;

/** @brief Receiver of one counter of a reading.
 *  @p section and @p field name the counter and stay valid for the call; @p value is
 *  the counter summed over the shards, stopped at @c UINT64_MAX. It runs on the thread
 *  that calls @ref duct_stats_read.
 */
typedef void (*duct_stats_visit_fn)(void *ctx, const char *section, const char *field,
                                    uint64_t value);

#ifdef __cplusplus
}
#endif

#endif /* DUCT_TYPES_H */
