/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_protocol.h
 *  @brief Protocol definition + session handle operations.
 *
 *  The single author header. Holds the declarative protocol surface — data and
 *  lifecycle callbacks, @ref duct_proto_cfg_t, @ref duct_route_fn, and
 *  @ref duct_proto_create — and the imperative handle operations the author calls
 *  on the opaque @ref duct_session_t during a callback (timers, pause, protocol
 *  switch, stream close, session/conn close, conn attach).
 *
 *  Build a protocol with @ref duct_proto_create, then pass the handle to
 *  @c duct_io_listen, @c duct_io_connect, or @c duct_listener_bind.
 */

#ifndef DUCT_PROTOCOL_H
#define DUCT_PROTOCOL_H

#include "duct_types.h"
#include "duct_core.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Send flags */

/** @brief Send mode and modifiers for a response payload.
 *
 *  Exactly one of fl_send_copy, fl_send_static, fl_send_owned per response.
 *  fl_send_copy is the default when @c flags == 0 — not a combinable bit.
 *  fl_send_done is orthogonal — requests proto_cfg.on_send_done with send_token.
 *  Combining @c fl_send_static and @c fl_send_owned is asserted against in
 *  debug builds (@ref duct_response_commit); in release builds @c fl_send_owned
 *  silently wins.
 */
typedef enum duct_send_flags : uint8_t {
    fl_send_copy     = 0u,        /**< Default: runtime copies buf when flags == 0. */
    fl_send_static   = 1u << 0,   /**< Zero-copy, immutable data. */
    fl_send_owned    = 1u << 1,   /**< Runtime takes ownership and releases the payload once staged or dropped. */
    fl_send_done     = 1u << 2,   /**< on_send_done via proto_cfg; set send_token for correlation. */
    fl_send_pool_keep = 1u << 3,  /**< Payload is a TX-pool region, held one worker pass longer. @see duct_tx_pool_acquire */
} duct_send_flags_t;

static_assert(sizeof(duct_send_flags_t) == sizeof(uint8_t),
    "duct_send_flags_t width");

/* Response — declarative outbound */

/** Sentinel: "use the route fn" for routing, not a real id. */
static constexpr duct_conn_id_t   duct_conn_id_same   = UINT32_MAX;
static constexpr duct_stream_id_t duct_stream_id_same = UINT32_MAX;

/** @brief Close target: nothing, the whole session, or one leg. */
typedef enum duct_close_target : uint8_t {
    close_target_none    = 0,
    close_target_session,
    close_target_conn,
} duct_close_target_t;

/** @brief RX flow-control op for the bound conn.
 *
 *  @c rx_op_pause is sticky session state: the io thread stops reading the bound
 *  conn until a later callback declares @c rx_op_resume. Resume must come from a
 *  trigger that can run while RX is held (timer fire, on_send_done, ctrl msg) —
 *  not from an inbound frame, since none arrive while paused. @c rx_op_none leaves
 *  the current state unchanged.
 */
typedef enum duct_rx_op : uint8_t {
    rx_op_none    = 0,
    rx_op_pause,
    rx_op_resume,
} duct_rx_op_t;

static_assert(sizeof(duct_rx_op_t) == sizeof(uint8_t), "duct_rx_op_t width");

/** @brief Stream-lifecycle op, carried as its own control frame.
 *
 *  A control frame of its own: the FIN carries no payload, the RST carries its
 *  @ref duct_stream_error_t. "Final data + FIN" stays on the TX path instead
 *  (@c payload + @c fl_frame_fin in @c frame_flags) — one wire frame, not
 *  @c stream_op_fin.
 */
typedef enum duct_stream_op : uint8_t {
    stream_op_none  = 0,
    stream_op_fin,
    stream_op_reset,
} duct_stream_op_t;

static_assert(sizeof(duct_stream_op_t) == sizeof(uint8_t), "duct_stream_op_t width");

/** @brief Why a stream was reset, as the four payload bytes of an RST frame.
 *
 *  Rides the frame's payload, so it crosses every wire that carries
 *  @c fl_frame_rst — length-prefix headers have no spare bit to hold it.
 *  A peer issuing an RST sets @c stream_err_none; the engine fills the rest.
 */
typedef enum duct_stream_error : uint32_t {
    stream_err_none     = 0, /**< Unspecified. */
    stream_err_refused,      /**< No stream slot left. The sender had not yet
                               *  reached the protocol, so retrying this stream
                               *  is safe, including on another connection. */
    stream_err_rejected,     /**< @c create_stream_state declined this id. */
    stream_err_internal,     /**< The handler for this stream failed. */
} duct_stream_error_t;

static_assert(sizeof(duct_stream_error_t) == sizeof(uint32_t), "duct_stream_error_t width");

/** @brief Leg-open kind for a declared attach or dial. */
typedef enum duct_leg_kind : uint8_t {
    leg_kind_none = 0,
    leg_kind_accept,  /**< Declarative marker only: resolve_join
                       *   already finds its target
                       *   through the author's own proto_state bookkeeping;
                       *   the framework takes no action for this kind. */
    leg_kind_inter,   /**< Attach a push-mode inter leg at @c conn_id
                       *   (internal @c duct_conn_attach_inter). */
    leg_kind_connect, /**< Dial @c connect_addr and attach the resulting leg
                       *   at @c conn_id once connected (internal
                       *   @c duct_conn_attach_connect). A failure past
                       *   this callback's return (DNS, refused, timeout)
                       *   reaches @c cfg->on_error(s, err, ...) once the
                       *   dial resolves — there is no other channel left. */
    leg_kind_connect_dgram, /**< Dial @c connect_addr over a connected datagram
                             *   socket and attach the resulting leg at
                             *   @c conn_id. A failure past this callback's
                             *   return reaches @c cfg->on_error(s, err, ...)
                             *   once the dial resolves. */
    leg_kind_join,    /**< Dial @c connect_addr over TCP and attach the leg at
                       *   @c conn_id, leading the stream with a one-time lead
                       *   the engine builds from the session's join key, so
                       *   the peer's listener joins it to the peer's side of
                       *   this session. The key comes from the session's first
                       *   named leg under an engine with @c derive; a session
                       *   without one starts no dial. @c tx_prefix is unused.
                       *   The peer resolves the lead once it has named this
                       *   side, through a listener reading first bytes before
                       *   it decides: a preparse or @c probe_wait_ms. A
                       *   listener whose @c peek_min is
                       *   @c duct_seal_prefix_max holds a first read shorter
                       *   than that, so a lead cut across segments is matched
                       *   whole. A
                       *   failure past this callback's return reaches
                       *   @c cfg->on_error as for @c leg_kind_connect. */
} duct_leg_kind_t;

static_assert(sizeof(duct_leg_kind_t) == sizeof(uint8_t), "duct_leg_kind_t width");

/** @brief Callback output: outbound payload + routing + ownership + control effects.
 *
 *  The framework resets @c *out before each callback to all-zero except
 *  @c control.stream_op_conn_id, pre-set to @c duct_conn_id_same; the author
 *  sets only what they need. No runtime pointers cross the boundary, sole
 *  exception @c control.timer.id_out — runtime-written.
 *
 *  Two halves: the top level is the TX frame — @c frame_flags rides into
 *  @c wire.pack, so "final data + FIN" is one response; @c control is the
 *  session/conn side-effects the worker applies after the callback returns —
 *  "timer without a response" = empty @c payload + @c control.timer set.
 *
 *  Payload ownership: staging into the target TX OLB happens synchronously,
 *  same worker turn, right after return.
 *  - @c fl_send_copy (default): buffer must outlive the callback's return, a
 *   callback-local does not qualify; @c release never called.
 *  - @c fl_send_static: buffer valid forever; @c release never called.
 *  - @c fl_send_owned: valid until released, once staged or dropped: @c release(release_arg) where
 *   @c release is set, else @c duct_del of @c release_arg, or of @c payload.data when that is nullptr.
 */
typedef struct duct_response {
    /* TX: the outbound frame. payload.size 0 = no TX. */
    duct_view_u8         payload;       /**< size 0 = no response. */
    duct_send_flags_t   flags;         /**< copy / static / owned (+ done). */
    duct_frame_flags_t  frame_flags;   /**< wire frame flags for this payload: fl_frame_fin etc. */
    duct_conn_id_t      conn_id;       /**< duct_conn_id_same = proto->route. */
    duct_stream_id_t    stream_id;     /**< duct_stream_id_same = proto->route. */
    void (*release)(void *);           /**< Release hook for fl_send_owned; nullptr takes the default @c duct_del. */
    void  *release_arg;                /**< Argument of @c release, or the @c duct_new block @c duct_del frees; nullptr names @c payload.data. */
    uintptr_t           send_token;    /**< for on_send_done. */
    /* Control: session/conn side-effects, applied by the worker after return.
     * Each is a declaration, not a request — the runtime applies what the
     * session can take and absorbs what it cannot, so no failure reaches an
     * author with no move against it; an open_leg it refuses is said on stderr.
     * A dial already in flight is the exception: open_leg's connect kinds
     * report a later failure through on_error, retry or fallback being the
     * author's. */
    struct {
        duct_stream_op_t    stream_op;          /**< Stream op: none, fin, or reset control frame. */
        duct_stream_id_t    stream_op_stream_id; /**< target stream for stream_op. */
        duct_conn_id_t      stream_op_conn_id;   /**< Multi-conn: leg for stream_op's FIN/RST frame.
                                                   *   duct_conn_id_same (the default, see
                                                   *   @ref duct_response_reset) = first live leg
                                                   *   with a wire (single-conn behavior); any other
                                                   *   value pins the frame to that leg, no fallback. */
        duct_stream_error_t stream_op_error;    /**< Reason carried by a
                                                  *   stream_op_reset; ignored by
                                                  *   stream_op_fin, which sends
                                                  *   no payload. */
        struct {                       /**< Leg to attach or dial, applied once the
                                         *   callback returns, in the same worker
                                         *   turn, a response still waiting for TX
                                         *   room included. Its pointers name
                                         *   storage that outlives the callback, a
                                         *   callback-local not qualifying. */
            duct_leg_kind_t  kind;         /**< none / accept (no-op) / inter / connect. */
            duct_conn_id_t   conn_id;      /**< target slot for leg_kind_inter / leg_kind_connect. */
            const char      *connect_addr; /**< "host:port" / "[ipv6]:port" a
                                             *   connect kind dials. */
            duct_view_u8    tx_prefix;    /**< Cleartext bytes the leg leads
                                             *   with on a sealed wire. A
                                             *   datagram leg leads every PDU
                                             *   with them at its wire's
                                             *   tx_prefix_len, until
                                             *   @c duct_conn_set_tx_prefix
                                             *   replaces them; a stream leg
                                             *   writes them once, ahead of its
                                             *   first PDU. Both precede message
                                             *   1, which the engine's start()
                                             *   emits before any callback.
                                             *   Copied during apply, more than
                                             *   @c duct_seal_prefix_max bytes
                                             *   starting no dial, and carried
                                             *   with this dial alone to the
                                             *   codec of the conn it opens; a
                                             *   leg whose codec cannot take
                                             *   them is refused at its join.
                                             *   Empty for none. */
            const char      *tcp_congestion; /**< Congestion control a
                                               *   leg_kind_connect dial's
                                               *   socket asks for by name,
                                               *   under the rules of the
                                               *   protocol's @c tcp_congestion,
                                               *   which @c nullptr or empty
                                               *   takes. Copied during apply, a
                                               *   name of
                                               *   @c duct_tcp_cc_name_max bytes
                                               *   or more starting no dial. */
            uint32_t         egress_if; /**< Index of the interface a
                                          *   connect kind's socket is bound
                                          *   to before it connects. 0 binds
                                          *   none and leaves the choice to
                                          *   routing; an index no interface
                                          *   holds fails the dial through
                                          *   @c on_error with @c rc_fatal.
                                          *   Read during apply. */
        } open_leg;
        struct {                       /**< Timer start and cancel.
                                         *   A nonzero @c delay_ms starts a timer. A
                                         *   nonzero @c key also replaces or cancels
                                         *   the session's timer of that key. */
            uint64_t          delay_ms,     /**< Delay to first fire. */
                              interval_ms;  /**< Repeat period; 0 = one-shot. */
            uintptr_t       arg;           /**< Token passed to cfg->on_timer; no framework free. */
            duct_timer_id_t  *id_out;        /**< Filled with the new timer id, written
                                               *   after the callback returns (same worker
                                               *   turn) — must point into @c proto_state
                                               *   or other storage that outlives the
                                               *   callback; never at a callback-local. */
            duct_timer_id_t   cancel_id;     /**< != 0 cancels a previously started timer. */
            uint32_t          key;           /**< Name of the timer within its session, 0 for none.
                                              *   A start under a key replaces the session's
                                              *   live timer of the same key, which never
                                              *   fires; a zero @c delay_ms cancels it and
                                              *   starts nothing. Eight keys are live in a
                                              *   session at most: a start with every slot
                                              *   taken is refused with a log line. A
                                              *   one-shot frees its key as it fires, a
                                              *   repeating timer when it is cancelled or
                                              *   replaced. */
        } timer;
        duct_rx_op_t        rx;             /**< rx_op_none / pause / resume. */
        duct_close_target_t close_target;   /**< none / session / conn. */
        duct_conn_id_t      close_conn_id;  /**< Leg to close under
                                              *   @c close_target_conn. A
                                              *   concrete slot: the field
                                              *   passes through as given, so
                                              *   @c duct_conn_id_same closes
                                              *   nothing. */
        duct_close_reason_t close_reason;
    } control;
} duct_response_t;

/** @brief Echo: copy the frame's payload back on the same routing, preserving its frame flags. */
static inline void duct_response_echo(duct_response_t *out, const duct_frame_t *frame) {
    *out = (duct_response_t){ .payload = frame->payload, .flags = fl_send_copy,
        .conn_id = duct_conn_id_same, .stream_id = duct_stream_id_same,
        .frame_flags = frame->flags,
        .control.stream_op_conn_id = duct_conn_id_same };
}

/** @brief Copy the frame's payload onto leg @p to, preserving its frame flags.
 *  An echo with @c conn_id set: @c duct_conn_id_same leaves the leg to
 *  @c proto->route.
 */
static inline void duct_response_forward(duct_response_t *out, const duct_frame_t *frame,
                                         duct_conn_id_t to) {
    duct_response_echo(out, frame);
    out->conn_id = to;
}

/** @brief Respond on the same routing (proto->route resolves); author picks frame flags. */
static inline void duct_response_same(duct_response_t *out, duct_view_u8 payload,
                                       duct_send_flags_t flags, duct_frame_flags_t fflags) {
    *out = (duct_response_t){ .payload = payload, .flags = flags,
        .conn_id = duct_conn_id_same, .stream_id = duct_stream_id_same,
        .frame_flags = fflags,
        .control.stream_op_conn_id = duct_conn_id_same };
}

/** @brief Close the session, no payload (idle timeout / abrupt close). */
static inline void duct_response_close_session(duct_response_t *out, duct_close_reason_t reason) {
    *out = (duct_response_t){ .control.close_target = close_target_session,
                              .control.close_reason = reason,
                              .control.stream_op_conn_id = duct_conn_id_same };
}

/** @brief Respond then close the session: send-then-close (HTTP/1 Connection: close, SMTP QUIT). */
static inline void duct_response_respond_then_close(duct_response_t *out, duct_view_u8 payload,
                                                     duct_send_flags_t flags,
                                                     duct_frame_flags_t fflags,
                                                     duct_close_reason_t reason) {
    *out = (duct_response_t){ .payload = payload, .flags = flags, .frame_flags = fflags,
        .conn_id = duct_conn_id_same, .stream_id = duct_stream_id_same,
        .control.close_target = close_target_session, .control.close_reason = reason,
        .control.stream_op_conn_id = duct_conn_id_same };
}

/** @brief Close one leg of the session, no payload (a dialed leg no longer needed). */
static inline void duct_response_close_conn(duct_response_t *out, duct_conn_id_t conn_id,
                                            duct_close_reason_t reason) {
    *out = (duct_response_t){ .control.close_target = close_target_conn,
                              .control.close_conn_id = conn_id,
                              .control.close_reason = reason,
                              .control.stream_op_conn_id = duct_conn_id_same };
}

/** @brief Reset @p out to the framework's pre-callback default. */
static inline void duct_response_reset(duct_response_t *out)
{ *out = (duct_response_t){ .control.stream_op_conn_id = duct_conn_id_same }; }

/* Data callbacks — frame / datagram arrival */

/** @brief Frame callback — stream and datagram protocols alike.
 *
 *  @param s            Live session; opaque handle for direct control calls.
 *  @param conn_id      Connection the frame arrived on.
 *  @param frame        Parsed frame; its @c payload is valid for the call only.
 *                     The built-in dgram-batch wire answers
 *                     @c duct_stream_id_default and @c fl_frame_none; a custom
 *                     dgram wire may carry real ids into the handler path.
 *  @param out          Response output; zero-initialized by the framework.
 *  @param proto_state  Per-session protocol state.
 *  @retval rc_ok     Accepts the frame and processes @p out.
 *  @retval rc_defer  Replays the frame, RX OLB held, once work next reaches its
 *                    worker: a frame, a timer on @p out, @c duct_session_invoke.
 *  @retval rc_drop   Discards it.
 *  @retval other     Rejects the source: @p out is not sent, and a plain
 *                    datagram wire leaves the peer's address as it was.
 *  @note An @c x_inter or @c x_udp_shared leg drains its packets off a lane
 *       before this callback runs, leaving no OLB position to hold: @c rc_defer
 *       loses the packet there and reports @c rc_again through @c on_error.
 */
typedef duct_result_t (*duct_frame_fn)(duct_session_t *s,
                                       duct_conn_id_t conn_id,
                                       const duct_frame_t *frame,
                                       duct_response_t *out,
                                       void *proto_state);

/* Session lifecycle callbacks */

/** @brief Bytes of a stream join lead: name, counter, conn id and MAC. */
static constexpr size_t duct_session_lead_size = 15u;

/** @brief Build the next one-time join lead for @p conn_id of @p s.
 *  The same lead the engine's own stream joins carry, for a protocol that
 *  embeds it inside its own outer handshake instead. Counter and MAC as the
 *  engine's stream leads spend them.
 *  @return false for a session holding no join key, a spent counter space,
 *          or @p conn_id past @c duct_session_max_legs.
 */
duct_nonnull(1, 3) bool
duct_session_lead_build(duct_session_t *s, duct_conn_id_t conn_id,
                        uint8_t out[duct_session_lead_size]);

/** @brief Resolve a join lead over @p protos, as the runtime's own accept does.
 *  For a preparse that digs a lead out of an outer handshake: the first
 *  protocol whose key and index take it wins, its counter spent here.
 *  @return false, nothing written, for any lead these protocols refuse.
 */
duct_nonnull(1, 2, 4, 5) bool
duct_session_lead_resolve(const uint8_t lead[duct_session_lead_size],
                          const duct_proto_t *const *protos, unsigned n_protos,
                          duct_handle_t *tok, duct_conn_id_t *conn_id);

/** @brief Session open — after the first transport binding.
 *
 *  Conn 0 is live; attach more via @ref duct_conn_attach_fd or declaratively
 *  through @c out->control.open_leg (@c leg_kind_inter). May emit a greeting
 *  (SMTP 220, FTP 220); its response routes to conn 0.
 *
 *  @param s            Live session; opaque handle for direct control calls.
 *  @param tok          Copyable session token; stash it for host @c duct_session_invoke or inter ingress.
 *  @param user_ctx     From @c duct_io_connect for outbound, or @c proto_cfg.user_ctx for inbound sessions.
 *  @param out          Response output; zero-initialized by the framework.
 *  @param proto_state  Per-session protocol state.
 *  @retval rc_ok       Accepts the session and commits @p out.
 *  @retval other       Rejects the newly bound primary leg; the runtime
 *                      closes the connection and tears down the session.
 */
typedef duct_result_t (*duct_session_open_fn)(duct_session_t *s,
                                               duct_handle_t tok,
                                               void *user_ctx,
                                               duct_response_t *out,
                                               void *proto_state);

/** @brief Session close — terminal.
 *
 *  @param s            Closing session; valid for the call only.
 *  @param reason       Why the session is closing.
 *  @param proto_state  Per-session protocol state.
 */
typedef void (*duct_session_close_fn)(duct_session_t *s,
                                      duct_close_reason_t reason,
                                      void *proto_state);

/** @brief Transport or runtime error, delivered on the worker thread.
 *
 *  @c out is control-only: the framework applies @c out->control (stream
 *  fin/reset, timer, RX pause/resume, close) on @c rc_ok exactly like a frame
 *  callback's, via the same @c s_ctl_apply path — but @c
 *  out->payload / @c flags / @c release / @c send_token are ignored, no TX
 *  commit runs: error sites may fire from paths already mid-failure, where
 *  re-entering the TX machinery is unsafe. Any return other than @c rc_ok
 *  discards @c out->control entirely. Return @c rc_ok with @c *out left
 *  zero to just observe.
 *
 *  Pre-session: a @ref duct_io_connect failure (DNS, refused, timeout) fires
 *  with @p s == @c nullptr — no session ever existed; @p proto_state carries
 *  that connect's @c user_ctx instead, and @p out is ignored entirely. A
 *  @c leg_kind_connect dial failure is the ordinary form by contrast: @p s is
 *  the live session the leg was meant to join, @p proto_state its real
 *  state, and @p out's control effects apply.
 */
typedef duct_result_t (*duct_error_fn)(duct_session_t *s,
                                       duct_result_t error,
                                       duct_response_t *out,
                                       void *proto_state);

/* Per-stream callbacks — multiplexed protocols */

/** @brief Stream opened — first frame on a non-zero stream, or a server-initiated
 *        stream claimed by a response with a @c stream_id override.
 *
 *  @param s             Live session.
 *  @param stream_id     Newly claimed stream.
 *  @param out           Response output; may emit (server push).
 *  @param stream_state  Per-stream state from @c create_stream_state, or NULL.
 */
typedef duct_result_t (*duct_stream_open_fn)(duct_session_t *s,
                                             duct_stream_id_t stream_id,
                                             duct_response_t *out,
                                             void *stream_state);

/** @brief Stream closed — terminal for one stream.
 *
 *  Fires from @c duct_session_stream_teardown before the slot is recycled. The
 *  slot's @c id is already 0 at this point, so an imperative
 *  @c duct_session_stream_close on the @b same @p stream_id from inside the
 *  callback is a no-op (the lookup misses) — do not rely on it; treat
 *  @c on_stream_close as a notification, not a close trigger. Closing a
 *  @b different stream is fine.
 *
 *  @param s             Live session.
 *  @param stream_id     Closing stream.
 *  @param reason        Why the stream is closing.
 *  @param stream_state  Per-stream state from @c create_stream_state, or NULL.
 */
typedef void (*duct_stream_close_fn)(duct_session_t *s,
                                     duct_stream_id_t stream_id,
                                     duct_close_reason_t reason,
                                     void *stream_state);

/* Listener resolve */

/** @brief Where the pre-parse runs; selects the dispatch phase. */
typedef enum duct_resolve_mode : uint8_t {
    resolve_none = 0,     /**< No pre-parse; always new (fast path / fallback). */
    resolve_sync,         /**< I/O thread; contract: O(1), lock-free, non-blocking. */
    resolve_async,        /**< Worker; arbitrary parse, may lock. */
    resolve_mode_count    /**< Extent; not a valid mode. */
} duct_resolve_mode_t;

static_assert(sizeof(duct_resolve_mode_t) == sizeof(uint8_t),
              "duct_resolve_mode_t width");

/** @brief Classify an accepted fd for one protocol: identify + decide.
 *  The dispatch loop stops at the first answer other than @c resolve_not_me;
 *  @ref duct_resolve_mode_t states the sync/async contracts.
 *
 *  @param ctx           From @ref duct_proto_cfg_t::preparse_ctx.
 *  @param peer          Accepted peer address.
 *  @param peek          Initial bytes, consumed off the socket, never a join lead the
 *                      engine resolved; the conn's first RX content follows @p out_lead
 *                      of them. Empty while the peer has not sent. Valid for the call only.
 *  @param out_tok       @c resolve_join: target session token.
 *  @param out_conn_id   @c resolve_join: slot in the target session's conn array.
 *  @param out_user_ctx  @c resolve_new: passed to @c on_session_open.
 *  @param out_lead      @c resolve_new or @c resolve_join on a stream: leading bytes of
 *                      @p peek consumed here, preset to 0, such as a stream dial's prefix
 *                      (@c open_leg.tx_prefix, @c duct_io_connect_via). One past @p peek
 *                      counts as @c resolve_reject; datagrams ignore it.
 *  @return Disposition. @c resolve_not_me continues dispatch; the runtime closes
 *         the fd on @c resolve_reject, and on @c resolve_retry answers the peer
 *         through @c duct_proto_cfg_t::preparse_reply first.
 */
typedef duct_resolve_disposition_t (*duct_preparse_fn)(
    void *ctx,
    const duct_peer_t *peer,
    duct_view_u8 peek,
    duct_handle_t *out_tok,
    duct_conn_id_t *out_conn_id,
    void **out_user_ctx,
    size_t *out_lead);

/** @brief Bytes to answer @p peer with before the engine acts on a resolve.
 *
 *  Runs on the io thread already holding the datagram, with no conn and no
 *  session behind it, which lets a stateless retry cost nothing. @p out
 *  takes storage the author owns; the engine sends it before this call returns,
 *  so a static or per-listener scratch is enough. A stream listener honors it
 *  on @c resolve_retry — the reply, then the close — on @c resolve_new, where
 *  the reply is written ahead of the session's first byte, and on a
 *  @c resolve_hold, whose reply is written ahead of the wait, from the accept
 *  path or a probe retry alike.
 *
 *  @return false to send nothing, which makes the retry a silent drop.
 */
typedef bool (*duct_preparse_reply_fn)(void *ctx, const duct_peer_t *peer,
                                       duct_view_u8 *out);

/** @brief A new leg joined an existing session.
 *
 *  Runs on the target session's worker. Fills @p out like @c on_session_open /
 *  @c on_frame; the worker processes it via @ref duct_response_commit +
 *  @c s_ctl_apply. Returning non-@c rc_ok closes the new conn but
 *  keeps the session live — a rejected leg is not session-fatal.
 *
 *  @param s            Target session.
 *  @param conn_id      Slot the new leg was attached at.
 *  @param peer         Peer address of a leg a listener accepted, all-zero for
 *                      a leg the session dialed or attached;
 *                      @ref duct_conn_addrs reads a dialed one's.
 *  @param out          Declarative response, zero-init'd by the framework.
 *  @param proto_state  Per-session protocol state.
 */
typedef duct_result_t (*duct_conn_join_fn)(duct_session_t *s,
                                            duct_conn_id_t conn_id,
                                            const duct_peer_t *peer,
                                            duct_response_t *out,
                                            void *proto_state);

/** @brief A leg left the session.
 *
 *  Runs on the session's worker, for every close reason. @p out carries
 *  control effects only, its TX half dropped: @p conn_id is a response's
 *  default route, and that leg is the one that closed.
 *  Control applies after the leg detaches, so @c control.open_leg
 *  with @c leg_kind_connect into this same @p conn_id redials the slot.
 *  A session's last leg fires this and then @c on_session_close; a redial
 *  declared there does not land, since a session does not outlive its legs.
 *
 *  @param s            Session the leg left, live for the call.
 *  @param conn_id      Slot the leg occupied; free once control applies.
 *  @param reason       Close cause: the transport's, or the one the protocol's
 *                      own close request named.
 *  @param out          Declarative response, zero-init'd by the framework.
 *  @param proto_state  Per-session protocol state.
 */
typedef void (*duct_conn_lost_fn)(duct_session_t *s,
                                  duct_conn_id_t conn_id,
                                  duct_close_reason_t reason,
                                  duct_response_t *out,
                                  void *proto_state);

/** @brief A sealed leg's engine named its peer; @p identity is that peer.
 *
 *  Fires once per leg, on the first PDU after which the engine answers an
 *  identity, the peer having proven it holds the leg's keys — after
 *  @c on_session_open, and before the first @c on_frame a sealed PDU of that
 *  leg produces; a cleartext control datagram @c rx_ctl admits comes ahead of it.
 *  Only a wire whose engine answers an identity reaches it at all. A leg
 *  naming a peer other than the one the session's first leg named is closed
 *  instead, unless @c fl_proto_join_any_peer.
 *
 *  @p identity is borrowed for the call: a Noise static public key, another
 *  scheme's own bytes. Copy what outlives the callback.
 *  @p out is filled like @c on_session_open's — payload, routing and control
 *  alike, so a peer this protocol declines is closed through
 *  @c out->control. Admission before the peer draws any reply belongs to the
 *  engine's own check instead.
 */
typedef void (*duct_peer_auth_fn)(duct_session_t *s,
                                  duct_conn_id_t conn_id,
                                  duct_view_u8 identity,
                                  duct_response_t *out,
                                  void *proto_state);

/* Protocol switch */

/** @brief Disposition of the old protocol state across a switch. */
typedef enum duct_leave : uint8_t {
    leave_destroy = 0,   /**< Runtime destroys the old @c proto_state. */
    leave_transfer,      /**< Callback took ownership of the old @c proto_state. */
    leave_reject,        /**< Cancel the switch; stay on the current protocol. */
    leave_count          /**< Extent sentinel; not a valid disposition. */
} duct_leave_t;

/** @brief Leave phase of a protocol switch — runs on the current protocol.
 *
 *  @ref duct_proto_switch records the switch during the callback and executes it
 *  after the response is sent, so the leave phase does not race the in-flight
 *  response.
 *
 *  @param migration_ctx  Shared with the enter phase for state handoff.
 *  @return One of @ref duct_leave_t: @c leave_reject aborts the switch.
 */
typedef duct_leave_t (*duct_proto_leave_fn)(duct_session_t *s,
                                            void *migration_ctx,
                                            void *proto_state);

/** @brief Enter phase of a protocol switch — runs on the next protocol.
 *
 *  @param migration_ctx  Same pointer the leave phase received.
 *  @return @c rc_ok to commit the switch; any error closes the session.
 */
typedef duct_result_t (*duct_proto_enter_fn)(duct_session_t *s,
                                             void *migration_ctx,
                                             void *proto_state);

/* Routing */

/** @brief Resolve the target {conn, stream} for a response.
 *
 *  Default (@c nullptr) = identity: out = in. VPN sets a swap; a proxy reads
 *  @p proto_state to pick a backend. The framework calls it while committing a
 *  response whose @c conn_id is @ref duct_conn_id_same or whose @c stream_id is
 *  @ref duct_stream_id_same; per-field overrides then apply. That commit runs
 *  for every frame result but @c rc_drop and @c rc_defer, so a rejected frame
 *  still reaches here.
 */
typedef void (*duct_route_fn)(duct_conn_id_t in_conn, duct_stream_id_t in_stream,
                              void *proto_state,
                              duct_conn_id_t *out_conn, duct_stream_id_t *out_stream);

/* Direct control on the session handle — imperative, worker thread */

/**
 *  @name Protocol switch and raw fd attach
 *  The two imperative calls on `s`. Stream fin/reset, open leg
 *  (attach_inter) and conn/session close are declarative — declared in
 *  @ref duct_response_t::control from any response-producing callback.
 *
 *  @ref duct_proto_switch records into the session and the runtime runs it
 *  last, after control and after the response. Its @c rc_again, raised when
 *  a switch is already in flight, is the one refusal here an author can act
 *  on; control absorbs every refusal it carries.
 *
 *  @ref duct_conn_attach_fd takes ownership of @c fd on the call whatever it
 *  returns. A declared attach transfers at apply time instead, past the point
 *  anything is left to report a leaked descriptor through.
 */
/**@{*/


/** @brief Switch the session to another protocol through a two-phase barrier.
 *
 *  Recorded during the callback and executed after the response is sent (through
 *  the old protocol's wire). Runs @c on_proto_leave on the current protocol, then
 *  @c on_proto_enter on @p next; @p migration_ctx is handed to both. If either
 *  phase fails, the session is closed.
 *
 *  A switch that changes wires rebinds every leg whose framing the engine owns,
 *  so it is abandoned when any leg carries a wire of its own — one given to
 *  @ref duct_conn_attach_packet_fd — or when @p next carries no wire while a
 *  packet fd leg stands, which needs one. It reaches @c on_error as
 *  @c rc_invalid_order at that point, the call itself having returned a turn
 *  earlier. A switch between protocols sharing one wire touches no leg and is
 *  unaffected.
 */
duct_result_t duct_proto_switch(duct_session_t *s,
                                const duct_proto_t *next,
                                void *migration_ctx);

/** @brief Sugar: request a protocol switch, no payload for this turn.
 *
 *  Fills @p out as empty and forwards to @ref duct_proto_switch — same
 *  two-phase-barrier, defer-survival semantics as a bare call; this only saves
 *  the author a separate `*out = (duct_response_t){};` line. Use directly as
 *  the callback's return: `return duct_response_switch(out, s, next, ctx);`.
 */
static inline duct_result_t
duct_response_switch(duct_response_t *out, duct_session_t *s,
                     const duct_proto_t *next, void *migration_ctx)
{
    *out = (duct_response_t){ .control.stream_op_conn_id = duct_conn_id_same };
    return duct_proto_switch(s, next, migration_ctx);
}

/** @brief Sugar: send a response through the current wire, then switch.
 *
 *  @p payload stages through the OLD protocol's wire before the switch runs
 *  (same ordering as filling `*out` by hand and calling @ref duct_proto_switch
 *  afterwards). Use directly as the callback's return.
 */
static inline duct_result_t
duct_response_respond_then_switch(duct_response_t *out, duct_session_t *s,
                                  duct_view_u8 payload, duct_send_flags_t flags,
                                  duct_frame_flags_t fflags,
                                  const duct_proto_t *next, void *migration_ctx)
{
    *out = (duct_response_t){ .payload = payload, .flags = flags, .frame_flags = fflags,
        .conn_id = duct_conn_id_same, .stream_id = duct_stream_id_same,
        .control.stream_op_conn_id = duct_conn_id_same };
    return duct_proto_switch(s, next, migration_ctx);
}

/** @brief Per-stream state lookup for non-coroutine multiplexed protos (QUIC).
 *
 *  @return The stream's @c stream_state from @c create_stream_state, or NULL for
 *         stream 0 / unclaimed / a non-multiplexed session / a NULL session.
 *         Worker-thread only.
 */
void *duct_stream_state(duct_session_t *s, duct_stream_id_t stream_id);

/** @brief Live leg count. Worker-thread only. */
duct_nonnull(1) uint32_t duct_session_conn_count(const duct_session_t *s);

/** @brief The @p ordinal-th live leg, in ascending @c conn_id order
 *  (0-based) -- lets an author round-robin a response across whichever
 *  legs are live right now without walking the session's own conn table
 *  directly. @return that leg's @c conn_id, or @ref duct_session_max_legs
 *  (an id outside any valid range) if @p ordinal >= @ref
 *  duct_session_conn_count's own return. Worker-thread only.
 */
duct_nonnull(1) duct_conn_id_t
duct_session_nth_live_leg(const duct_session_t *s, uint32_t ordinal);

/** @brief The @c user_ctx a @c resolve_new preparse handed to
 *  @c on_session_open, unchanged for the session's whole life.
 *  See @ref duct_resolve_disposition_t for that disposition.
 *  @c on_session_open/@c on_error
 *  already receive it as a parameter; this exists for callbacks that
 *  don't (@c on_session_close, a stream handler reached via @ref
 *  duct_stream_session). Worker-thread only.
 */
duct_nonnull(1) void *duct_session_user_ctx(const duct_session_t *s);

/** @brief Attach an fd as a poll conn at @p conn_id (multi-conn).
 *
 *  Read/write via @c read()/@c write(), not @c recv()/@c send() — @p fd need
 *  not be a socket: a pipe or any pollable descriptor whose bytes are a
 *  stream. Ownership of @p fd transfers to the engine on this call regardless
 *  of the return value; the caller must not touch or close it afterwards.
 *  Worker-thread only.
 *
 *  @param s        Session handle.
 *  @param conn_id  Slot to attach the conn at; must be unclaimed.
 *  @param fd       File descriptor the reactor will poll.
 */
duct_nonnull(1) duct_result_t duct_conn_attach_fd(duct_session_t *s,
                                                   duct_conn_id_t conn_id,
                                                   duct_sock_t fd);

/** @brief Attach a packet-delimited fd as a conn at @p conn_id.
 *  For a descriptor whose every @c read() yields one whole packet, a tun
 *  device or a @c SOCK_DGRAM socketpair. Each packet keeps its boundary
 *  through the conn's rings, so a datagram-shaped wire sees one frame per
 *  packet. @p fd belongs to the engine from this call on, whatever it
 *  returns. Worker-thread only. On Windows, where a tunnel is a device leg,
 *  the first read is refused and the leg closes with @c close_io_error.
 *
 *  A descriptor whose reads lead with a @c virtio_net_hdr of at most 12
 *  bytes — the @c IFF_VNET_HDR tun shape — hands the header to the engine:
 *  setting the leg up, the engine enables the tun's offloads, cuts the TCP and
 *  UDP superpackets it reads and merges the TCP segments and UDP datagrams it
 *  writes; the wire still sees one plain packet per frame. A header over 12
 *  bytes closes the fd with no join.
 *  @param conn_id  Slot to attach the conn at; must be unclaimed.
 *  @param leg_wire Wire this leg binds, allowing heterogeneous legs per session;
 *                  @ref duct_wire_packet for a tun. @c nullptr binds the
 *                  protocol default wire. @c rc_invalid_arg when the protocol carries
 *                  no wire, a @p leg_wire notwithstanding.
 */
duct_nonnull(1) duct_result_t duct_conn_attach_packet_fd(duct_session_t *s,
                                                          duct_conn_id_t conn_id,
                                                          duct_sock_t fd,
                                                          const duct_wire_t *leg_wire);

/** @brief Capacity of a tun's interface name, terminator included, bytes.
 *  Equals Linux's @c IFNAMSIZ. */
static constexpr size_t duct_ifname_max = 16u;

/** @brief Set the cleartext bytes leading every PDU this leg sends.
 *
 *  @p prefix is copied, and its width must be the @c tx_prefix_len the leg's
 *  sealed wire was built with. It goes out ahead of the engine's own bytes on
 *  every egress path, handshake PDUs included, so a peer reads it while still
 *  holding no key, which lets a shared datagram listener route a datagram
 *  arriving from an address it has no conn for. A leg carries all-zero
 *  bytes until this call.
 *
 *  The bytes are the protocol's to mint and must be unguessable: in the clear
 *  past every observer on the path, anything derived from a counter or a pool
 *  slot publishes how many sessions are live and how fast they turn over.
 *
 *  @retval rc_ok             Stored; the next PDU out carries it.
 *  @retval rc_invalid_arg    @p conn_id past the session's leg count,
 *                            @p prefix a width other than the wire's, or a
 *                            wire that leads its PDUs with nothing.
 *  @retval rc_invalid_order  No leg there, or that leg holds no sealed state.
 */
duct_nonnull(1) duct_result_t duct_conn_set_tx_prefix(duct_session_t *s,
                                                       duct_conn_id_t conn_id,
                                                       duct_view_u8 prefix);

/** @brief Read the path MTU the kernel holds for leg @p conn_id's socket, bytes.
 *
 *  @c IP_MTU or @c IPV6_MTU of the connected socket under an @c x_tcp or
 *  @c x_udp_peer leg: the route's MTU, lowered as ICMP "packet too big" comes
 *  back for host traffic. A figure past 65535 comes back as 65535.
 *  Call from session callbacks; @p out is written on @c rc_ok alone.
 *
 *  @retval rc_ok             @p out holds the figure.
 *  @retval rc_invalid_arg    @p conn_id past the session's leg count.
 *  @retval rc_invalid_order  No leg there, a leg already closing, or a socket
 *                            the kernel names no path for.
 *  @retval rc_not_supported  A leg with no connected socket: a shared datagram
 *                            leg, a packet fd, a device.
 */
duct_nonnull(1, 3) duct_result_t duct_conn_path_mtu(duct_session_t *s,
                                                    duct_conn_id_t conn_id,
                                                    uint16_t *out);

/** @brief Read leg @p conn_id's local and remote addresses.
 *
 *  An @c x_tcp or @c x_udp_peer leg answers its socket address pair. A shared
 *  datagram leg answers its listener's bound address, a wildcard where the
 *  listener bound one, and the peer it last migrated to. Either output may be
 *  @c nullptr, which skips that side. Call from session callbacks; the outputs
 *  are written on @c rc_ok alone.
 *
 *  @retval rc_ok             The outputs hold the pair.
 *  @retval rc_invalid_arg    @p conn_id past the session's leg count.
 *  @retval rc_invalid_order  No leg there, a leg already closing, or a socket
 *                            the kernel names no address for.
 *  @retval rc_not_supported  Any other leg: an attached fd, a packet fd, a
 *                            device.
 */
duct_nonnull(1) duct_result_t duct_conn_addrs(duct_session_t *s, duct_conn_id_t conn_id,
                                              duct_peer_t *local, duct_peer_t *remote);

/** @brief Read the IP version packets to @p peer travel as.
 *  An IPv4 address, and an IPv6 one in the IPv4-mapped range ::ffff:0:0/96, give
 *  @c fl_ip_v4. Any other IPv6 address gives @c fl_ip_v6, and a peer of neither
 *  family @c fl_ip_none. */
duct_nonnull(1) duct_ip_flags_t duct_peer_ip_flags(const duct_peer_t *peer);

/** @brief Hash @p peer's family, port and address into one 64-bit key.
 *  Peers equal in family, port and the 16 address bytes hash alike, an IPv4 peer's unused address tail
 *  being zero.
 */
duct_nonnull(1) uint64_t duct_peer_hash(const duct_peer_t *peer);

/** @brief Read the congestion control in force on leg @p conn_id's TCP socket.
 *
 *  The name the kernel runs, NUL-terminated, whatever the protocol's or the
 *  dial's @c tcp_congestion asked for. Call from session callbacks;
 *  @p out is written on @c rc_ok alone.
 *
 *  @retval rc_ok             @p out holds the name.
 *  @retval rc_invalid_arg    @p conn_id past the session's leg count.
 *  @retval rc_invalid_order  No leg there, or a leg already closing.
 *  @retval rc_not_supported  A leg other than @c x_tcp, or a controller the
 *                            stack cannot name.
 */
duct_nonnull(1, 3) duct_result_t duct_conn_tcp_congestion(duct_session_t *s,
                                                          duct_conn_id_t conn_id,
                                                          char out[duct_tcp_cc_name_max]);

/** @brief Read the congestion figures of leg @p conn_id's TCP socket.
 *
 *  Each call reads the socket afresh. Call from session callbacks;
 *  @p out is written on @c rc_ok alone.
 *
 *  @retval rc_ok             @p out holds the figures.
 *  @retval rc_invalid_arg    @p conn_id past the session's leg count.
 *  @retval rc_invalid_order  No leg there, or a leg already closing.
 *  @retval rc_not_supported  A leg other than @c x_tcp, or a stack that reports
 *                            no figures.
 */
duct_nonnull(1, 3) duct_result_t duct_conn_tcp_stats(duct_session_t *s, duct_conn_id_t conn_id,
                                                     duct_tcp_stats_t *out);

/** @brief Bound how long leg @p conn_id's TCP socket retransmits unanswered
 *  before its stack ends it, milliseconds.
 *
 *  Past the bound the stack ends the socket and the session sees the leg lost;
 *  1 ends it at its first retransmission timeout, and 0 restores the default
 *  stack bound. Call from session callbacks.
 *
 *  @retval rc_ok             Set.
 *  @retval rc_invalid_arg    @p conn_id past the session's leg count, or @p ms
 *                            past @c INT32_MAX.
 *  @retval rc_invalid_order  No leg there, or a leg already closing.
 *  @retval rc_not_supported  A leg other than @c x_tcp, or a stack refusing the
 *                            bound.
 */
duct_nonnull(1) duct_result_t duct_conn_set_ack_timeout(duct_session_t *s, duct_conn_id_t conn_id,
                                                        uint32_t ms);

/** @brief Bound the GSO records vnet leg @p conn_id cuts from what it reads,
 *  bytes.
 *
 *  Each TCP superpacket the leg reads leaves as records of as many whole
 *  segments as @p max holds, lead and headers included, each marked
 *  @c fl_frame_gso; a lone segment leaves as a plain packet. 0, where every leg
 *  starts, cuts every segment apart, and so does a header carrying IPv4 options
 *  or IPv6 extension headers under any bound. The next read takes a new bound.
 *  Call from session callbacks.
 *
 *  @retval rc_ok             Stored.
 *  @retval rc_invalid_arg    @p conn_id past the session's leg count, or @p max
 *                            past the leg wire @c max_frame: the leg parse
 *                            refuses a record past it and ends the conn.
 *  @retval rc_invalid_order  No leg there.
 *  @retval rc_not_supported  A leg whose fd carries no @c virtio_net_hdr.
 */
duct_nonnull(1) duct_result_t duct_conn_set_gso(duct_session_t *s,
                                                duct_conn_id_t conn_id,
                                                uint16_t max);

/** @brief Report the largest GSO record bound vnet leg @p conn_id takes, bytes.
 *
 *  The ceiling @ref duct_conn_set_gso accepts for the leg: its wire's
 *  @c max_frame, capped at 65535. 0 for a leg whose fd carries no
 *  @c virtio_net_hdr, for an empty slot and for a @p conn_id past the
 *  session's leg count. Call from session callbacks.
 */
duct_nonnull(1) uint16_t duct_conn_gso_max(const duct_session_t *s, duct_conn_id_t conn_id);

/** @brief Point in one leg's byte stream.
 *  @ref duct_conn_tx_end reads it and @ref duct_conn_tx_sent compares it; two
 *  points read on one leg differ by the bytes between them. */
typedef struct duct_tx_pos {
    uint64_t at;  /**< Stream offset, bytes: every byte the leg's worker handed
                    *  on ahead of this point, through its TX ring or straight
                    *  to its socket; a packet-fd leg counts its ring alone. */
    uint64_t leg; /**< Handle word of the leg it was read on. */
} duct_tx_pos_t;

/** @brief Read the end of leg @p conn_id's byte stream and the bytes queued
 *  ahead of it.
 *
 *  @p out marks the end of what the leg's worker has handed on, and @p queued
 *  counts the bytes before it io has not yet passed to the kernel. A train this
 *  worker still holds for the leg counts in neither. Call from session
 *  callbacks. Both are written on @c rc_ok alone.
 *
 *  @retval rc_ok             @p out and @p queued hold the figures.
 *  @retval rc_invalid_arg    @p conn_id past the session's leg count.
 *  @retval rc_invalid_order  No leg there.
 *  @retval rc_not_supported  A leg without a TX ring: a shared datagram leg, a
 *                            device.
 */
duct_nonnull(1, 3, 4) duct_result_t duct_conn_tx_end(duct_session_t *s,
                                                     duct_conn_id_t conn_id,
                                                     duct_tx_pos_t *out,
                                                     size_t *queued);

/** @brief Tell whether every byte before @p pos has been handed to the kernel.
 *
 *  True as well for a position read on a leg that no longer holds slot
 *  @p conn_id, its queue gone with it, and for a leg without a TX ring. Call
 *  from session callbacks.
 */
duct_nonnull(1) bool duct_conn_tx_sent(duct_session_t *s, duct_conn_id_t conn_id,
                                       duct_tx_pos_t pos);

/** @brief Tell whether leg @p conn_id's TX ring takes a response of @p size bytes
 *  now and still holds admission's reservation.
 *
 *  The response counts as the leg's wire stages it; the reservation is what
 *  admission asks of a leg ahead of a session open and a join's
 *  @c on_conn_join. A refusal flushes the train this worker holds
 *  for the leg and asks again, arming no wake, as admission does. False where
 *  the wire cannot carry @p size, a datagram leg's past one PDU among them;
 *  true for a slot past the session's legs, an empty slot and a leg without a
 *  TX ring, which admission does not wait on either. Call from session callbacks.
 */
duct_nonnull(1) bool duct_conn_tx_fits(duct_session_t *s, duct_conn_id_t conn_id,
                                       size_t size);

/** @brief Bytes io hands leg @p conn_id's socket per writable edge.
 *
 *  The platform's answer for the bound it keeps on the socket's unsent bytes:
 *  the cap on one write while a following lowat sits under its ceiling, the
 *  share of the bound the socket reports writable under otherwise. 0 for a slot
 *  past the session's legs, an empty slot, a leg without a TX ring, and a socket
 *  under no bound. Call from session callbacks.
 */
duct_nonnull(1) size_t duct_conn_tx_quantum(duct_session_t *s, duct_conn_id_t conn_id);

/** @brief Bytes leg @p conn_id's socket holds unsent, read afresh.
 *
 *  A reading is a system call, and calling this is the opt-in: on Windows the
 *  first call on a connection turns the stack's per-connection statistics on for
 *  it, which an elevated process alone can do, and answers
 *  @ref duct_tx_unsent_unread, as does every call by a process the stack refuses.
 *  A protocol that never calls it leaves the statistics off. Linux reads no
 *  figure, so it always answers unread there, @ref duct_conn_tx_quantum reporting
 *  the lowat bound instead; so do a slot past the session's legs, an empty slot,
 *  a closing leg and any leg other than @c x_tcp. Call from session callbacks.
 */
duct_nonnull(1) uint64_t duct_conn_tx_unsent(duct_session_t *s, duct_conn_id_t conn_id);

/** @brief Capacity of leg @p conn_id's TX ring, bytes.
 *  The @c tx_olb_cap the conn was created with, raised to DUCT_CONN_TX_OLB_CAP,
 *  with the slack of the mapping's rounding to a whole page. 0 for a slot past
 *  the session's legs, an empty slot and a leg without a TX ring. Call from
 *  session callbacks.
 */
duct_nonnull(1) size_t duct_conn_tx_cap(duct_session_t *s, duct_conn_id_t conn_id);

/** @brief Traffic tally of one leg slot, kept by the session's worker.
 *
 *  The tally belongs to the session's @c conn_id slot from session open to
 *  close: a leg replaced in its slot continues it. Payload bytes only, no
 *  wire framing.
 */
typedef struct duct_conn_counters {
    uint64_t rx_frames;  /**< Frames the leg delivered to the session.
                           *  Each counts once: handed to @c on_frame, or claimed
                           *  by a stream handler. A frame deferred for replay counts
                           *  at the replay; an @c x_inter or @c x_udp_shared packet
                           *  that @c on_frame defers is dropped and counts at that
                           *  call. */
    uint64_t rx_bytes;   /**< Payload bytes of @c rx_frames. */
    uint64_t tx_frames;  /**< Responses with a payload handed to the leg's TX path.
                           *  Delivery is not counted: bytes the I/O thread passes
                           *  to the kernel are not seen here. A response parked on a
                           *  full ring counts once, when its replay is taken. */
    uint64_t tx_bytes;   /**< Payload bytes of @c tx_frames. */
    uint64_t tx_refused; /**< Responses addressed to the slot whose commit failed
                           *  for good: a payload over @c max_response, a leg that
                           *  is gone or closing, a payload the leg's wire cannot
                           *  carry, a packet its device lost. A parked response
                           *  counts here only if its replay fails; one addressed
                           *  past the session's legs counts in no slot. */
} duct_conn_counters_t;

/** @brief Read the traffic tally of leg slot @p conn_id.
 *
 *  The tally outlives its leg: @c on_conn_lost reads the leg it reports, and
 *  @c on_session_close reads every slot with the last leg already detached.
 *  A response counts after the callbacks its commit fires, so @c on_send_done
 *  and @c on_error read the tally without it. Zero for a slot never used and
 *  for a @p conn_id past the session's legs. Call from session callbacks.
 */
duct_nonnull(1) duct_conn_counters_t duct_conn_counters(const duct_session_t *s,
                                                        duct_conn_id_t conn_id);

duct_nonnull(1) bool duct_session_closing(const duct_session_t *s);

/** @brief Caller-owned operation table for a non-socket device leg.
 *
 *  @c wait_handle, @c read and @c release must be set, @c write_reserve and
 *  @c write_commit are set together or both left null, and @c release_read and
 *  @c rx_span are optional. A device with no write callback is read-only: a response a
 *  protocol routes to its leg is refused with @c rc_invalid_arg through
 *  @c on_error, and the leg goes on delivering what @c read hands over.
 *  Ownership of @c ctx transfers
 *  to the engine on @ref duct_conn_attach_device, which calls @c release
 *  exactly once, on success and on rejection alike; with @c release itself
 *  null there is nothing to hand @c ctx back through, so that attach is
 *  refused without taking ownership.
 *
 *  Each direction costs one copy at most, and which side owns the memory
 *  decides where the bytes land. Inbound, a device with @c rx_span set fills
 *  engine buffers; any other answers from private memory, which the engine
 *  copies out, or borrows where @c release_read is set. Outbound, the engine
 *  fills the device's send memory.
 */
typedef struct duct_device_ops {
    /** @brief Object the events model waits on for readability.
     *  Auto-resetting: a handle the wait does not consume leaves the I/O
     *  thread spinning. Borrowed — DuctIo never closes it.
     */
    void         *wait_handle;

    /** @brief Size of each engine buffer @c read is offered, bytes; 0 offers none.
     *  A device that fills these buffers reaches the protocol with no copy. A
     *  device that answers from private memory leaves 0 and is offered null
     *  buffers. The engine keeps @c duct_dgram_rx_max_passes slots of one read's
     *  buffers for the leg, so the memory held grows with the span. A span past
     *  @c duct_ipv4_len_max refuses the attach.
     */
    size_t        rx_span;

    /** @brief Fill at most @p max buffers of @p out, answering @p n packets.
     *  A filled buffer reaches the protocol with no copy. Buffers arrive null
     *  when the engine has no slot to offer, always for a device whose
     *  @c rx_span is 0, and a device with private memory overwrites the
     *  pointers instead. @c rc_closed closes the leg. I/O thread.
     */
    duct_result_t (*read)(void *ctx, duct_view_u8 *out,
                          unsigned max, unsigned *n);

    /** @brief Take back one packet @c read answered out of device memory.
     *  Setting this lends read buffers to the engine until returned via this
     *  callback, enabling zero-copy in-place parsing and mutation. When null,
     *  the engine copies packets before the subsequent @c read. Invoked on
     *  I/O thread.
     */
    void          (*release_read)(void *ctx, duct_view_u8 pkt);

    /** @brief Answer @p size writable bytes of device send memory, or @c nullptr when none are free.
     *  A refusal reaches the protocol as @c rc_again through @c on_error and
     *  parks that response for retry, in the ticket order a leg without a TX
     *  OLB keeps. Called on a worker, so a device several can reach must be
     *  thread-safe.
     */
    void         *(*write_reserve)(void *ctx, size_t size);

    /** @brief Send @p len bytes written into @p buf, an earlier
     *  @c write_reserve answer.
     *  @c rc_ok reports the packet taken. @c rc_drop reports it lost: the response fails with
     *  @c rc_drop, reported to @c on_error and to its @c on_send_done, and counts in the leg's
     *  @c tx_refused and not in @c tx_frames, and the leg stays. @c rc_closed closes the leg, and any
     *  other answer fails the response with @c rc_invalid_arg. Same thread as @c write_reserve. Every
     *  reservation reaches this exactly once, @p len 0 among them: that call
     *  sends nothing, its answer is not read, and it hands @p buf back, which is how send memory
     *  reserved for a packet the protocol then dropped returns to the device. Any other @p len is the size
     *  @c write_reserve was asked for.
     */
    duct_result_t (*write_commit)(void *ctx, void *buf, size_t len);

    /** @brief Hand @c ctx back; past this the device is the caller's again. */
    void          (*release)(void *ctx);

    void          *ctx;  /**< Reaches every callback above. */
} duct_device_ops_t;

/** @brief Attach a caller-owned device as an @c x_inter leg on @p conn_id.
 *
 *  @p conn_id must be free: the leg is created here, the same way
 *  @ref duct_conn_attach_fd creates one. @p ops is copied before the request
 *  crosses to the owning I/O thread, so the caller's own struct may expire on
 *  return.
 *
 *  Every events model carries a device leg except @c poll under Windows, where
 *  a waitable handle has no @c WSAPoll form. There the registration fails on
 *  the I/O thread after this call already returned @c rc_ok, and the leg never
 *  opens.
 *
 *  @retval rc_ok            Request posted.
 *  @retval rc_invalid_arg   A null @c wait_handle, @c read or @c release, one
 *                           write callback without the other, an @c rx_span
 *                           past @c duct_ipv4_len_max, or @p conn_id past the
 *                           session's leg count.
 *  @retval rc_invalid_order @p conn_id occupied, or no primary leg to route by.
 *  @retval rc_no_memory     Request allocation failed.
 */
duct_nonnull(1, 3) duct_result_t
duct_conn_attach_device(duct_session_t *s, duct_conn_id_t conn_id,
                        const duct_device_ops_t *ops);

/**@}*/

/* Timer / send-done callbacks */

/** @brief Timer fire callback, executed on the worker thread; a response-producing callback.
 *
 *  The single per-protocol fire callback (@c duct_proto_cfg_t::on_timer). Fill
 *  @p out to send (keepalive ping), set @p out.control to close (idle timeout) or
 *  re-arm (set @p out.control.timer again), or return @c rc_ok with an empty
 *  @p out for nothing. The framework processes @p out exactly like a frame
 *  callback's (TX path + control).
 *
 *  A timer started by @ref duct_timer_start belongs to no session: @p s is
 *  @c nullptr, @p proto_state is the @c user_ctx given at its start, and @p out
 *  is not applied.
 *
 *  @param proto_state  Per-session protocol state — the same value every
 *                      callback receives, regardless of which timer fired.
 *  @param arg  Token supplied at timer start via @c out.control.timer;
 *             identifies the firing timer among several armed on one
 *             session (kind tag, stream id, pointer — the author
 *             interprets it). Stored as-is, no ownership crosses.
 */
typedef duct_result_t (*duct_timer_fn)(duct_session_t *s,
                                        duct_response_t *out,
                                        void *proto_state,
                                        uint64_t arg);

/** @brief Outcome passed to @c on_send_done. */
typedef struct duct_send_done_info {
    duct_conn_id_t   conn_id;     /**< Conn the send targeted. */
    duct_stream_id_t stream_id;   /**< Logical stream the send targeted. */
    uintptr_t        send_token;  /**< Response token, echoed back. */
    duct_result_t    result;      /**< Pack and enqueue outcome. */
} duct_send_done_info_t;

/** @brief Send-done callback; reports the pack/enqueue outcome, not a peer ACK.
 *
 *  @c out is control-only — same contract as @ref duct_error_fn's @c out: the
 *  framework applies @c out->control on @c rc_ok, ignoring @c payload,
 *  @c flags, @c release and @c send_token; any other return discards it.
 *  Declaring @c rx_op_resume once a paused conn's held response is out is the
 *  case it exists for.
 *
 *  Fires once for a response carrying @c fl_send_done, on whichever
 *  disposition resolves it: the send itself, a stage that failed for good, or
 *  a parked retry resolving later. A response still outstanding when its
 *  stream is cancelled or the engine stops fires nothing, teardown running no
 *  protocol callback at all. The stream emit API is closed here — this
 *  callback runs inside the send path it reports on.
 *
 *  @param s            Session that issued the send.
 *  @param info         Conn, stream, send token, and result of the send.
 *  @param out          Control-only output, zero-init'd by the framework.
 *  @param proto_state  Per-session protocol state.
 */
typedef duct_result_t (*duct_send_done_fn)(duct_session_t *s,
                                           const duct_send_done_info_t *info,
                                           duct_response_t *out,
                                           void *proto_state);

/* Protocol config */

/** @brief Protocol capability flags. */
typedef enum duct_proto_flags : uint8_t {
    fl_proto_none         = 0u,
    fl_proto_multiplexed  = 1u << 0,  /**< Allow a non-zero @c stream_id on
                                       *   receive and send. An id is a key the
                                       *   protocol owns and the engine looks
                                       *   up, so ids may be as sparse as it
                                       *   likes, and keeping them unique across
                                       *   both sides is the protocol's too —
                                       *   HTTP/2 odd/even stream ID conventions being
                                       *   the usual answer. What is bounded is
                                       *   how many live at once,
                                       *   @c DUCT_SESSION_MAX_STREAMS: a peer
                                       *   opening one past that draws an RST
                                       *   carrying @ref stream_err_refused and
                                       *   @c rc_again at @c on_error, both
                                       *   meaning it is worth retrying once one
                                       *   closes. @c on_stream_open firing
                                       *   says this side opened a stream;
                                       *   a response naming a live id rides
                                       *   that stream. */
    fl_proto_dgram_shared = 1u << 1,  /**< @c listener_dgram only: never open a
                                       *   per-peer connected socket — every
                                       *   peer's RX/TX rides the listener's own
                                       *   shared socket, demuxed by
                                       *   dgram_peers and dispatched through
                                       *   an @c x_udp_shared conn's own
                                       *   inter_lane. Unset (default): the
                                       *   per-peer-socket behavior.
                                       *   @ref duct_listener_bind
                                       *   rejects this flag on @c
                                       *   listener_stream. */
    fl_proto_join_any_peer = 1u << 2, /**< Keep a joined leg whatever peer it
                                       *   names. Unset (default): a sealed
                                       *   leg naming a peer other than the one
                                       *   the session's first leg named is
                                       *   closed with @c close_protocol_error,
                                       *   the session standing, no frame of it
                                       *   reaching the protocol and no
                                       *   @c on_peer_auth fired for it. */
} duct_proto_flags_t;

static_assert(sizeof(duct_proto_flags_t) == sizeof(uint8_t),
              "duct_proto_flags_t width");

/** @brief Protocol configuration.
 *        Borrowed for the @ref duct_proto_create call only; the returned
 *        handle owns the live protocol.
 *
 *  @c on_frame is required, for stream and datagram protocols alike. @c wire is
 *  @c nullptr for raw byte protocols. Every lifecycle and event callback is
 *  optional unless noted.
 *
 *  @c route is @c nullptr for identity routing (out = in). @c max_response bounds
 *  each @ref duct_response_t payload; 0 means the wire's max frame size, so a
 *  raw protocol (@c wire == nullptr) needs it nonzero, and
 *  @ref duct_proto_create rejects a raw one without it. The framework reserves
 *  @c max_response in the session's TX OLBs ahead of a session open and a
 *  join's @c on_conn_join, holding them while the reservation fails. A frame
 *  callback, an inter packet's included, runs regardless: an answer the ring
 *  has no room for parks, and the conn's next frame or inter message waits for
 *  it.
 */
typedef struct duct_proto_cfg {
    const char *name;                /**< Diagnostic label; borrowed. */
    const duct_wire_t *wire;         /**< Parse/pack chain; @c nullptr means raw bytes. */

    duct_frame_fn on_frame;          /**< Required; stream or datagram callback. */

    /* Per-session protocol state factory. */
    void *create_state_ctx;          /**< Passed as @c ctx to @c create_state and @c destroy_state. */
    void *user_ctx;                  /**< @c on_session_open @c user_ctx for inbound sessions from listen or bind. */
    uint32_t connect_timeout_ms;     /**< @c duct_io_connect: fail with @c rc_conn_timeout if not
                                       *   established in time; 0 = no runtime timer, OS default only. */
    uint32_t join_auth_timeout_ms;   /**< Bound on a sealed leg's handshake: a leg that
                                       *   has not named its peer this long after it
                                       *   joined its session, or after the session
                                       *   opened when it is the session's first,
                                       *   closes with @c close_timeout. A joined leg
                                       *   closes alone and the session stands; a
                                       *   session's only leg takes the session with
                                       *   it. 0 takes 10 s; an engine naming no peer
                                       *   arms none. */
    uint32_t idle_timeout_ms;        /**< Bound on a session's silence, ms. A session
                                       *   whose socket legs have delivered no frame
                                       *   for this long closes with @c close_timeout,
                                       *   up to the timer wheel's coalescing window,
                                       *   1 ms by default, ahead of it. A frame
                                       *   counts once @c on_frame accepted it with
                                       *   @c rc_ok or a stream handler took it, and
                                       *   only on a TCP, UDP or local-socket leg: a raw
                                       *   fd, a packet fd or a device leg says nothing
                                       *   of the peer.
                                       *   The span is read at each expiry, so a
                                       *   protocol switch changes or ends it.
                                       *   0 = none. */
    duct_result_t (*create_state)(duct_session_t *s, void *ctx, void **out); /**< Allocate @c proto_state; return @c rc_ok on success. */
    void (*destroy_state)(duct_session_t *s, void *ctx, void *state);        /**< Release @c proto_state on session teardown. */

    /* Session lifecycle. */
    duct_session_open_fn  on_session_open;  /**< Session established; conn 0 is live. */
    duct_session_close_fn on_session_close; /**< Terminal session close. */
    duct_error_fn         on_error;         /**< Transport or runtime error. */
    duct_send_done_fn     on_send_done;     /**< Pack/enqueue completion for @c fl_send_done responses. */
    duct_timer_fn         on_timer;         /**< Timer fire (keepalive / idle / re-arm); null = no timers. */

    /* Listener resolve — optional; @c preparse == NULL means always-new fast
     * path / fallback. */
    duct_preparse_fn      preparse;         /**< Identify + classify on accept; null = always new. */
    duct_resolve_mode_t   preparse_mode;    /**< sync / async; ignored when @c preparse is null. */
    void                 *preparse_ctx;     /**< Borrowed; passed to @c preparse (e.g. peer→token map). */
    duct_preparse_reply_fn preparse_reply; /**< Answers a @c resolve_retry, a stream's @c resolve_new ahead of the session's first byte, and a @c resolve_hold the engine waits on; null sends nothing. */
    duct_conn_join_fn     on_conn_join;     /**< New leg attached to an existing session; null = silent join. */
    duct_conn_lost_fn     on_conn_lost;     /**< Leg detached, any reason; null = silent loss. */
    duct_peer_auth_fn     on_peer_auth;     /**< Sealed leg's peer named; null = silent. */

    /* Per-stream (multiplexed protocols; NULL → no per-stream overhead). */
    duct_result_t (*create_stream_state)(duct_session_t *s, duct_stream_id_t stream_id,
                                         void *ctx, void **out); /**< Allocate per-stream state on first claim. */
    void (*destroy_stream_state)(duct_session_t *s, duct_stream_id_t stream_id,
                                 void *ctx, void *state);       /**< Release per-stream state on stream close. */
    duct_stream_open_fn  on_stream_open;   /**< Stream claimed; may emit (server push). */
    duct_stream_close_fn on_stream_close;  /**< Stream closed. */

    /* Stream handler (multiplexed protocols; handler_none = on_frame path). */
    duct_handler_kind_t handler_kind;        /**< handler_none / handler_async / handler_coro. */
    union {
        duct_async_step_t   handler_async;  /**< Stackless step fn; used when handler_kind == handler_async. */
        duct_coro_func_t handler_coro;  /**< Stackful entry fn; used when handler_kind == handler_coro. */
    };

    /* Protocol switch. */
    duct_proto_enter_fn on_proto_enter;     /**< Enter phase of a switch. */
    duct_proto_leave_fn on_proto_leave;     /**< Leave phase of a switch. */

    /* Routing + backpressure. */
    duct_route_fn route;                    /**< Resolve response target; @c nullptr = identity. */
    size_t        max_response;             /**< Per-response payload cap; 0 = wire max frame. */
    size_t        tx_olb_cap;               /**< Per-conn TX OLB capacity, bytes. 0, or
                                              *   anything under DUCT_CONN_TX_OLB_CAP,
                                              *   takes that build default; a conn keeps
                                              *   the capacity it was created with. */
    const char   *tcp_congestion;           /**< Congestion control each @c x_tcp conn
                                              *   asks for by name, borrowed; @c nullptr
                                              *   keeps the platform's default, and so
                                              *   does a name the platform refuses or
                                              *   lacks. Names are Linux's, reno, cubic
                                              *   and bbr among them, each platform
                                              *   taking them for controllers of its own,
                                              *   at the point it allows;
                                              *   @ref duct_conn_tcp_congestion reads
                                              *   back the one in force by the platform's
                                              *   name. A leg dial naming its own in
                                              *   @c open_leg takes that instead. */
    uint32_t      tcp_notsent_lowat;        /**< Unsent bytes each @c x_tcp conn's socket
                                              *   holds before it reports writable,
                                              *   @c TCP_NOTSENT_LOWAT; 0 keeps the
                                              *   platform's default. Set when the conn is
                                              *   created, where the platform bounds a
                                              *   socket's unsent bytes;
                                              *   @ref duct_conn_tx_quantum reads back
                                              *   the bound in force. */
    uint32_t      tcp_notsent_lowat_us;     /**< Unsent span each @c x_tcp conn's socket
                                              *   holds, µs at its sending rate; 0 keeps
                                              *   @c tcp_notsent_lowat fixed. Where the
                                              *   platform follows a rate, io re-reads it
                                              *   while it drains a socket that refused
                                              *   and sets the lowat to this much of it,
                                              *   never past @c tcp_notsent_lowat. A
                                              *   socket that never refuses keeps that
                                              *   ceiling, and one that stops keeps the
                                              *   lowat it had. */

    duct_proto_flags_t flags;               /**< Capability flags. */
} duct_proto_cfg_t;

/** @brief Protocol handle — the config, borrowed pointers and all, by value.
 *
 *  Completed here (public) so the runtime and worker can read callbacks and
 *  routing off @c cfg. @c duct_proto_create validates the cfg and owns the heap
 *  handle; callers must not allocate @c duct_proto_t directly.
 */
struct duct_proto {
    duct_proto_cfg_t cfg;
    /** @brief Wire released by @c duct_proto_destroy.
     *  @c duct_proto_create leaves this null; whoever built the wire sets it
     *  to hand ownership over, which @c duct_proto_create_owning does and
     *  @c duct_proto_create_tcp and @c duct_proto_create_udp do through it.
     */
    duct_wire_t     *owned_wire;
    /** @brief duct_worker_admit_need's result for reserve 1 and 2, index
     *  reserve - 1 — the only two values duct_admit_slots ever produces.
     *  Computed once by duct_proto_create from cfg's fields; derived
     *  runtime state the author never sets.
     */
    size_t admit_need[2];
};

/** @brief Borrow the live config off a protocol handle. */
duct_nonnull(1) static inline const duct_proto_cfg_t *
duct_proto_cfg_of(const duct_proto_t *p)
{
    return &p->cfg;
}

/** @brief Create a protocol from a configuration. Caller owns the returned pointer.
 *
 *  The runtime borrows the protocol from @c duct_io_listen, @c duct_io_connect,
 *  or @c duct_listener_bind until @c duct_engine_destroy; keep it alive that long, then
 *  release it with @ref duct_proto_destroy. @c cfg.on_frame is required.
 *
 *  @param cfg  Configuration read during the call only.
 *  @return Protocol handle, or @c nullptr on invalid config or allocation failure.
 *
 *  @code
 *  duct_proto_t *p = duct_proto_create(&(duct_proto_cfg_t){
 *     .name = "echo", .on_frame = on_recv, .on_session_open = on_session_open });
 *  @endcode
 */
duct_proto_t *duct_proto_create(const duct_proto_cfg_t *cfg);

/** @brief Create the protocol described by @p cfg and assume ownership of @p wire.
 *
 *  Sets @c cfg->wire to @p wire, so the two cannot disagree. Either outcome
 *  consumes @p wire: the handle keeps it as @c owned_wire for
 *  @ref duct_proto_destroy to release, and a refusal destroys it, so no caller is
 *  left holding a wire to free. Otherwise as @ref duct_proto_create.
 *
 *  @return Protocol handle, or @c nullptr on a null @p cfg, an invalid config or
 *          an allocation failure, with @p wire destroyed. A null @p wire creates
 *          nothing.
 */
duct_proto_t *duct_proto_create_owning(duct_proto_cfg_t *cfg, duct_wire_t *wire);

/** @brief Release a protocol handle after the runtime has stopped borrowing it.
 *
 *  No-op on @c nullptr. Destroys the wire the handle owns: the one
 *  @c duct_proto_create_tcp and @c duct_proto_create_udp build, or the one
 *  @c duct_proto_create_owning was given. The cfg's other borrowed pointers
 *  (name, @c user_ctx, the callbacks) and a wire handed to
 *  @c duct_proto_create are caller-owned and not released here.
 */
void duct_proto_destroy(duct_proto_t *proto);

/** @brief Build a stream protocol with the built-in length-prefix wire layer.
 *
 *  @param name      Diagnostic label; borrowed.
 *  @param on_frame  Frame callback; required.
 *  @return Protocol handle, or @c nullptr on a missing @p on_frame or
 *         allocation failure.
 */
duct_proto_t *duct_proto_create_tcp(const char *name, duct_frame_fn on_frame);

/** @brief Build a datagram protocol with the built-in dgram-batch record wire.
 *
 *  @param name      Diagnostic label; borrowed.
 *  @param on_dgram  Frame callback; required. @c stream_id / @c flags are
 *                  always the zero sentinel on the frames it receives.
 *  @return Protocol handle, or @c nullptr on a missing @p on_dgram or
 *         allocation failure.
 */
duct_proto_t *duct_proto_create_udp(const char *name, duct_frame_fn on_dgram);

#ifdef __cplusplus
}
#endif

#endif /* DUCT_PROTOCOL_H */
