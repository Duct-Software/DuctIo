/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_conn.h
 *  @brief L4 connection pool — slot lifecycle, generation-checked handles.
 *
 *  Defines connection structure, pool layout, and handle resolution.
 *  Physical reclaim is fence-driven and immediate.
 */

#ifndef DUCT_CONN_H
#define DUCT_CONN_H

#include "duct_types.h"
#include "duct_core.h"
#include "duct_msg.h"
#include "duct_vmq.h"

#include <assert.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct duct_olb_rx duct_olb_rx_t;
typedef struct duct_olb_tx duct_olb_tx_t;
typedef struct duct_wire_parser duct_wire_parser_t;
typedef struct duct_wire_codec duct_wire_codec_t;

/** @brief Sentinel for @c io_id.
 *  Conn is outside every io thread's registry.
 */
static constexpr auto conn_io_none = UINT32_MAX;

/** @brief Sentinel for @c worker_id.
 *  Conn is not yet assigned by the io thread.
 */
static constexpr auto conn_worker_none = UINT32_MAX;

/** @brief Bit width of @c duct_conn_handle_t's @c idx sub-field. */
static constexpr unsigned hconn_idx_bits = 18u;

/** @brief Mask for @c duct_conn_handle_t's @c gen sub-field. */
static constexpr uint64_t hconn_gen_mask =
    (1ull << (64u - hconn_idx_bits)) - 1;

/** @brief Conn pool capacity.
 *  Mirrors @c duct_runtime_max_conns, bounded by @ref hconn_idx_bits.
 */
static constexpr unsigned duct_max_conns = duct_runtime_max_conns;
static_assert(duct_max_conns <= (1u << hconn_idx_bits),
    "duct_runtime_max_conns exceeds conn handle idx width");

/** @brief Packed conn ticket.
 *  @c Bits [17:0] for @c idx, [63:18] for @c slot's generation;
 *  @c gen 0 == unset.
 */
typedef union duct_conn_handle {
    duct_handle_t word;
    struct {
        uint64_t idx : hconn_idx_bits,        /**< Pool slot index. */
                 gen : 64u - hconn_idx_bits;  /**< Slot generation. */
    };
} duct_conn_handle_t;

static_assert(sizeof(duct_conn_handle_t) == sizeof(duct_handle_t),
              "duct_conn_handle_t must be 64 bits");

/** @brief Zero-valued connection handle. */
static constexpr duct_conn_handle_t conn_handle_null = {};

/** @brief Connection state flags.
 *  Atomically manipulated via @ref duct_conn_state_set and
 *  @ref duct_conn_state_clear helpers.
 */
typedef enum duct_conn_flags : uint16_t {

    fl_conn_closed      = 1u << 0, /**< Conn already closed. Set once by the
                                     *  io thread and read at its RX, TX and
                                     *  fence gates; cleared only by the next
                                     *  @ref duct_conn_acquire's state
                                     *  reset. */

    fl_conn_suspended   = 1u << 1,  /**< RX paused by an author's rx_op_pause
                                      *  request. Written by the worker, read
                                      *  at the io thread's RX gate. */

    fl_conn_in_wfq      = 1u << 2, /**< An in-flight ctrl message for this
                                     *  conn is posted on the WFQ. Set on the
                                     *  worker before a ctrl post, cleared
                                     *  there on post failure and in
                                     *  @ref duct_conn_release; read at the io
                                     *  thread's pre-open reclaim gate. */

    fl_conn_rx_full     = 1u << 3, /**< RX OLB out of space; reads paused
                                     *  until the worker acks resume. Set and
                                     *  cleared by the io thread's RX-reserve
                                     *  path and by the worker's resume
                                     *  request; read by both. */

    fl_conn_closing     = 1u << 4, /**< Worker requested close; quiesce once
                                     *  TX drains. Set once by the io thread;
                                     *  read at the close fence and at the io
                                     *  thread's drain and quiesce gates;
                                     *  cleared only by the next @ref
                                     *  duct_conn_acquire's state reset. */

    fl_conn_tx_wait     = 1u << 5, /**< A worker turn was refused TX room on
                                     *  this conn, or a retry node is parked
                                     *  waiting for some to free. Set by the
                                     *  worker; read and cleared by the io
                                     *  thread after each TX head advance and
                                     *  device signal, which wakes the assigned
                                     *  worker only when set. */
    fl_conn_write_armed = 1u << 6, /**< Current write-interest state for
                                     *  reactive backend registration — same
                                     *  contract as @c duct_listener_t::dgram_tx_write_armed:
                                     *  updated exclusively by the assigned
                                     *  I/O thread, gates the worker-side TX
                                     *  fast path (@c x_udp_peer, @c x_tcp,
                                     *  @c x_raw) as a stale-tolerant hint.
                                     *  iocp never touches it — its dgram TX
                                     *  has no reactive readiness concept. */
    fl_conn_roaming     = 1u << 7,  /**< An @c x_udp_peer leg whose listener
                                      *  holds a candidate address for it, put
                                      *  there by a datagram that arrived from
                                      *  somewhere other than where this socket
                                      *  is connected. Written by I/O thread,
                                      *  read by worker thread under the same
                                      *  contract as @c fl_conn_write_armed:
                                      *  the worker posts @c fl_req_peer_roam
                                      *  for an accepted frame whose ack total
                                      *  reaches the RX ring's @c roam_at, and
                                      *  io moves the socket from there. A
                                      *  stale read costs one post io then
                                      *  finds nothing to do. */
    fl_conn_reclaim_held = 1u << 8, /**< A reclaim found this conn's request
                                      *  node posted and not yet run, and
                                      *  waits for it. Set by
                                      *  @ref duct_conn_reclaim; read and
                                      *  cleared by the io thread as it runs
                                      *  that node, which then reclaims. */
    fl_conn_rx_eof      = 1u << 9,  /**< End of the conn's input, read off the
                                      *  peer. Set by the io thread on the
                                      *  zero-length read, and every later read
                                      *  stops at its RX gates; cleared only by
                                      *  the next @ref duct_conn_acquire's state
                                      *  reset. */
    fl_conn_vnet_uso    = 1u << 10, /**< Conn whose tun took the USO flags at its open.
                                      *  Set once by the io thread in
                                      *  @ref duct_conn_setup; read by the worker's
                                      *  vnet write train, which merges UDP
                                      *  datagrams for a conn that carries it.
                                      *  Cleared only by the next
                                      *  @ref duct_conn_acquire's state reset. */
} duct_conn_flags_t;

static_assert(sizeof(duct_conn_flags_t) == sizeof(uint16_t),
              "duct_conn_flags_t width must be 2 bytes");

/** @brief Bits gating a coalesced request message posted onto an io thread's
 *  request stack.
 *  Packed alongside the generation, @see duct_gen_req_pack.
 */
typedef enum duct_conn_req_flags : uint8_t {
    fl_req_tx_drain    = 1u << 0,   /**< Drain/flush this conn TX OLB. */

    fl_req_close       = 1u << 1,   /**< Close this conn;
                                      *  arms @c fl_conn_closing. */

    fl_req_rx_resume   = 1u << 2,   /**< Resume paused RX drives. */

    fl_req_retire      = 1u << 3,   /**< Worker confirmed retire-ready;
                                      *  run the physical retire scan. */

    fl_req_fence_retry = 1u << 4,   /**< Retry a previously failed
                                      *  close-fence publish.*/

    fl_req_wire_rebind = 1u << 5,   /**< Rebind @c conn->wire for a
                                      *  wire-changing proto switch.
                                      *  @see duct_proto_switch */

    fl_req_peer_roam   = 1u << 6,   /**< Point this @c x_udp_peer conn's
                                      *  connected socket at the candidate
                                      *  address its listener holds.
                                      *  @see fl_conn_roaming */
} duct_conn_req_flags_t;

static_assert(sizeof(duct_conn_req_flags_t) == sizeof(uint8_t),
              "duct_conn_req_flags_t width must be 1 byte");

/** @name @c Generation-request word bit layout.
 *  Generation, request-flags and close-request reason share one 64-bit
 *  atomic so a poster's "does my handle's generation still match" check
 *  and "set my request bit" are written at the same CAS, preventing a
 *  race between the two.
 *  Layout (low to high): [6:0] req_flags, [9:7] close reason, [55:10]
 *  generation (46 bits match @ref hconn_gen_mask), [63:56] unused.
 *  @{
 */
static constexpr unsigned gen_req_flags_shift   = 0u;
static constexpr uint64_t gen_req_flags_mask    = 0x7Full;
static constexpr unsigned gen_req_reason_shift  = 7u;
static constexpr uint64_t gen_req_reason_mask   = 0x7ull;
static constexpr unsigned gen_req_gen_shift     = 10u;

/** @brief Pack generation + request flags + close reason into a word. */
static inline uint64_t
duct_gen_req_pack(uint64_t gen, duct_conn_req_flags_t flags,
                  duct_close_reason_t reason)
{
    return (gen << gen_req_gen_shift)
         | ((uint64_t)reason << gen_req_reason_shift)
         | (uint64_t)flags;
}

/** @brief Extract the generation sub-field from a @c gen_req word. */
static inline uint64_t
duct_gen_req_gen(uint64_t word)
{
    return (word >> gen_req_gen_shift) & hconn_gen_mask;
}

/** @brief Extract the request-flags sub-field from a @c gen_req word. */
static inline duct_conn_req_flags_t
duct_gen_req_flags(uint64_t word)
{
    return (duct_conn_req_flags_t)(word & gen_req_flags_mask);
}

/** @brief Extract the close-reason sub-field from a @c gen_req word. */
static inline duct_close_reason_t
duct_gen_req_reason(uint64_t word)
{
    return (duct_close_reason_t)
        ((word >> gen_req_reason_shift) & gen_req_reason_mask);
}
/** @} */

/** @brief Per-conn close-fence state machine.
 *
 *  Monotonic. A fence publication that cannot reserve its lane slot leaves
 *  the conn at @c fence_quiescing and asks for a retry, so @c fence_posted is
 *  reached only once and never walked back.
 *  The worker CAS @c fence_unbound → @c fence_open and the io CAS
 *  @c fence_unbound / @c fence_open → @c fence_quiescing are the critical
 *  synchronization points, preventing:
 *  — a session bind from publishing author callbacks on a quiesced conn,
 *  — io from destroying a conn the worker still references.
 */
typedef enum duct_conn_fence : uint8_t {
    fence_unbound,      /**< No session attached yet. */
    fence_open,         /**< Bound to a session. */
    fence_quiescing,    /**< io stopped the conn; fence unposted yet. */
    fence_posted,       /**< @c conn_lost published to normal WFQ lane. */
    fence_retire_ready, /**< Worker confirmed no further access;
                          *  ready for destroy by io. */
    fence_retired,      /**< io destroyed the conn;
                          * slot is about to be released. */
} duct_conn_fence_t;

static_assert(sizeof(duct_conn_fence_t) == sizeof(uint8_t),
              "duct_conn_fence_t width must be 1 byte");

/** @brief Sealed-wire state for one conn.
 *  Outlives @c codec, which a wire rebind destroys while a task parsed under
 *  the old generation can still replay and ask what was already acked.
 */
typedef struct duct_sealed_conn_ctx {

    /** @brief Worker codec instance.
     *  Nullptr until the first sealed-wire task on this conn
     *  creates it via @c wire->create_codec; destroyed via
     *  @c codec->destroy at conn-lost consume, wire-rebind fence
     *  or final teardown.
     */
    duct_wire_codec_t *codec;

    /** @brief Mid-record replay guard.
     *  True once @c unseal lands a record, false once its drain
     *  empties or stalls short of a full frame. While true,
     *  a replaying task skips @c unseal and resumes draining
     *  in place; also tells a stale task whether its bytes
     *  were already acked or not.
     */
    bool head_unsealed;
} duct_sealed_conn_ctx_t;

/** @brief L4 connection, cacheline-aligned.
 *
 *  L4 ⟷ L5 bind is attach-layer: @c session_token plus a @c conn_fence CAS
 *  is the L4-side half, @ref duct_conn_session_bind.
 *  Attach-side state
 *  (leg and session choice) resides in the session @c conns[] array.
 *  Both halves are bound and unbound by the worker.
 */
typedef struct duct_conn {
    duct_cacheline_struct(
        duct_conn_flags_t _Atomic state;      /**< Lifecycle/gate bits. */

        duct_conn_fence_t _Atomic conn_fence; /**< Close-fence stage. */

        duct_close_reason_t close_reason;     /**< Close reason carried to the
                                                *  worker with the fence.
                                                *  Written once, by
                                                *  @c s_conn_close past the
                                                *  quiesce CAS and only for a
                                                *  conn that was bound — an
                                                *  unbound one reclaims
                                                *  without a reason. */

        uint32_t io_id;     /**< Assigned I/O thread id;
                              *  @c conn_io_none if unset. */
                              
        uint32_t worker_id; /**< Worker thread id the conn's WFQ lane, ctrl
                              *  posts, wakes and inter bit are addressed to,
                              *  assigned by io before the first post. */

        /** @brief Id plus 1 of the worker holding the conn from its bind to
         *  its unbind, 0 otherwise.
         *  Stored by @ref duct_conn_session_bind, cleared by
         *  @ref duct_conn_session_unbind and reset by @ref duct_conn_acquire.
         *  While bound, only that worker writes it; an I/O thread retires the
         *  connection only after worker confirmation.
         */
        uint32_t _Atomic bound_worker;

        /** @brief Bound session handle, @c handle_null if unbound.
         *  Set before worker's release-CAS @c fence_unbound → @c fence_open;
         *  io thread that wins the acquire-CAS to @c fence_quiescing
         *  observes it complete.
         */
        duct_handle_t   session_token;

        uint32_t _Atomic  next_free; /**< Free-list link for Treiber stack. */

        /** @brief Host-thread readers currently pinning this conn.
         *  Unregistered readers, e.g. @ref duct_io_inter_batch,
         *  hold a pin between their generation re-check and their
         *  last touch of @c inter_lane.
         *  @ref duct_conn_reclaim spins on this, reaching 0 before
         *  tearing down @c inter_lane.
         */
        uint32_t _Atomic  host_pins;

        /** @brief Next / prev links in io thread's live-conn list.
         *  Linked by @ref duct_conn_io_list_link, unlinked by
         *  @ref duct_conn_io_list_unlink / @ref duct_conn_fence_retire.
         */
        struct duct_conn *io_next,
                         *io_prev;

        duct_sealed_conn_ctx_t seal; /**< Sealed-wire state, inert under a
                                       *  plain wire. Read through
                                       *  @ref duct_conn_sealed_ctx, which
                                       *  answers whether this xport carries
                                       *  one at all. */

    );  /* CL0 — lifecycle + io thread registry */

    duct_cacheline_struct(
        duct_sock_t fd; /**< Conn socket descriptor. */
        union {
            struct {
                duct_olb_rx_t *rx_buf; /**< Receive buffer. */
                duct_olb_tx_t *tx_buf; /**< Transmit buffer. */
            };

            /** @brief What a leg with no OLB pair carries in their place.
             *  Live exactly when @c rx_buf / @c tx_buf are not, decided by
             *  @c xport.
             */
            struct {
                /** @brief Dedicated MPSC ingress queue.
                 *  A single lane carrying @c x_inter packets — pushed by a
                 *  host thread, or by the io thread draining a device leg —
                 *  and @c x_udp_shared classified datagrams.
                 */
                duct_vmq_mpsc_t *inter_lane;

                /** @brief Commit ordering for a leg with no TX OLB to hold
                 *  it, over @c tx_buf's word.
                 *  @c duct_olb_tx_t keeps the same pair for the legs that do
                 *  have one, so which word a ticket lives in follows the
                 *  xport and nothing reads either as the other. Zeroed by
                 *  @ref duct_conn_acquire @c tx_buf reset, enabling immediate
                 *  ticket issuance on newly acquired slots.
                 */
                struct { uint32_t next,
                                  serve; } tx_seq;
            };
        };

        const duct_wire_t  *wire; /**< Bound wire for RX parse + TX pack.
                                    *  Set by @ref duct_conn_bind_wire at
                                    *  accept/attach, rebound on a
                                    *  wire-changing protocol switch. */

        duct_wire_parser_t *wire_parser; /**< Per-conn parse state. */

        /** @brief Pending wire-rebind target.
         *  Set by the worker before posting @c fl_req_wire_rebind;
         *  cleared by the I/O thread once the completion fence
         *  lands. Also the "fence not yet posted" retry sentinel for
         *  @c fl_req_fence_retry.
         *  Atomic, relaxed both sides: the worker's write and the
         *  io-thread's gen_req-gated reads already get their
         *  ordering from gen_req acquire/release operations; this field's
         *  atomicity exists for opportunistic reads in duct_frame_rx_post,
         *  which has no other synchronization with the worker's write.
         */
        const duct_proto_t * _Atomic wire_rebind_next;
        
        /** @brief Xport-specific context, keyed by @c xport_type.
         *  @ref duct_dgram_shared_ctx_t on @c x_udp_shared and
         *  @ref duct_device_ops_t on a device-backed @c x_inter, each
         *  allocated at attach and freed with the conn; the borrowed
         *  @c duct_listener_t of an accepted @c x_local conn, set by
         *  @ref duct_local_listener_take and cleared by its drop. Nullptr
         *  for every other xport.
         */
        void *ctx;

        /** @brief Transport kind of @c fd.
         *  Drives per-conn I/O dispatch across the OS backends;
         *  @ref duct_xport_t.
         */
        duct_xport_t xport_type;
        
        /** @brief Wire-binding generation.
         *  Bumped by @ref duct_conn_bind_wire on rebind for any xport,
         *  regardless of sealed-ness; a stale sealed dispatch task's
         *  @c sealed_epoch compares against this.
         *  Non-atomic, single-writer discipline.
         */
        uint8_t wire_epoch;

        /** @brief Length of the @c virtio_net_hdr framing every packet on
         *  @c fd, bytes; 0 for none.
         *  Zeroed by @ref duct_conn_acquire and set by @ref duct_conn_setup,
         *  so a slot a vnet leg left carries no length into its next xport. */
        uint8_t vnet_hdr_len;

        /** @brief Largest GSO record the cut writes on this vnet leg, bytes;
         *  0 cuts every segment apart.
         *  Zeroed by @ref duct_conn_acquire, since a peer takes records only
         *  once its session agrees to them. The session's worker stores it
         *  through @ref duct_conn_set_gso and the io thread loads it per read,
         *  both relaxed: a read cut under the previous bound stays valid, that
         *  bound having been valid when set. */
        uint16_t _Atomic vnet_gso;

    ); /* CL1 — I/O path */
} duct_conn_t;

static_assert(sizeof(duct_conn_t) == 2 * duct_cacheline_size,
    "conn must be exactly 2 cachelines");

/** @brief Resolve @p conn's @c gen_req slot. */
duct_nonnull(1) uint64_t _Atomic *
duct_conn_gen_req(const duct_conn_t *conn);

/** @brief Worker→io wake message for @p conn's coalesced @c gen_req requests.
 *  Resident, one per pool slot, indexed 1:1 with @c conns[] the same way
 *  @c gen_req is. Keeping it out of @ref duct_conn_t holds that struct at
 *  the two cachelines verified by static assertion. */
duct_msg_chain_decl(duct_msg_conn_req, duct_conn_handle_t handle);

/** @brief Resolve @p conn's embedded @c req_msg slot. */
duct_nonnull(1) duct_msg_conn_req *
duct_conn_req_msg(const duct_conn_t *conn);

/* Forward-declared for the dgram ctx below. */
typedef struct duct_listener duct_listener_t;

void duct_listener_release_pre_conn_ref(duct_listener_t *listener);

/** @brief Count the registered @p conn against a path listener's session cap.
 *  Adds one to the listener's live sessions and one to its @c pre_conn_refs, and
 *  stores @p listener in @c conn->ctx. io-thread-only.
 */
duct_nonnull(1, 2) void duct_local_listener_take(duct_listener_t *listener, duct_conn_t *conn);

/** @brief Give back the session and the reference @p conn took from its path listener.
 *  Undoes @ref duct_local_listener_take: clears @c conn->ctx, lowers the live
 *  sessions, then releases the @c pre_conn_refs reference, which destroys the
 *  node when it was the last one and a close was requested. io-thread-only.
 */
duct_nonnull(1) void duct_local_listener_drop(duct_conn_t *conn);

/** @brief x_udp_shared conn's @c ctx layout. */
typedef struct duct_dgram_shared_ctx {
    duct_listener_t *listener; /**< Listener back-reference. */
    duct_peer_t      peer;     /**< This leg's current peer address,
                                 *  updated on every migration. */
    struct duct_x_slot_pool *rx_pin; /**< Pool whose @c pins count this conn's
                                 *  lane as held behind a parked answer, null
                                 *  for none. Written by the conn's worker;
                                 *  teardown takes a standing pin back. */
} duct_dgram_shared_ctx_t;

/** @brief True when @p conn's live union arm is @c rx_buf / @c tx_buf.
 *  The set corresponds to transports configured in @ref duct_conn_setup:
 *  missing transports resolve nullptr for allocated rings.
 */
duct_nonnull(1) static inline bool duct_conn_has_olb(const duct_conn_t *conn)
{
    switch (conn->xport_type) {
    case x_raw:
    case x_raw_packet:
    case x_tcp:
    case x_udp_peer:
    case x_local:
        return true;
    case x_udp:
    case x_udp_shared:
    case x_bt:
    case x_can:
    case x_inter:
        return false;
    }
    return false;
}

/** @brief True when @p conn's transport delivers discrete packets into its ring
 *  with per-entry record headers.
 *  Both directions branch on it: @ref duct_io_rx_reserve leaves the header
 *  gap that @c duct_io_rx_commit fills, and a reserve skipping that gap
 *  writes its payload over the preceding record's length; @c duct_io_tx_advance
 *  consumes an entry whole, which lets an @c rc_drop verdict skip one
 *  oversized datagram without parking the ring head.
 */
duct_nonnull(1) static inline bool duct_conn_record_framed(const duct_conn_t *conn)
{
    return duct_xport_delimited(conn->xport_type) && duct_conn_has_olb(conn);
}

/** @brief True when a zero-length read on @p conn is the peer's end of stream.
 *  iocp turns a zero-byte completion into @c rc_closed without consulting the
 *  xport, so this keeps a zero-length datagram from ending the input of a conn
 *  whose transport carries no end-of-stream at all.
 */
duct_nonnull(1) static inline bool duct_conn_reads_eof(const duct_conn_t *conn)
{
    return !duct_xport_delimited(conn->xport_type) && duct_conn_has_olb(conn);
}

/** @brief True when @p conn's xport is a socket to the session's peer.
 *  A caller-attached fd, a device leg and the reserved bluetooth and CAN
 *  xports are not.
 */
duct_nonnull(1) static inline bool duct_conn_peer_socket(const duct_conn_t *conn)
{
    switch (conn->xport_type) {
    case x_tcp:
    case x_udp:
    case x_udp_peer:
    case x_udp_shared:
    case x_local:
        return true;
    case x_raw:
    case x_raw_packet:
    case x_bt:
    case x_can:
    case x_inter:
        return false;
    }
    return false;
}

/** @brief @p conn's RX ring; nullptr on an xport without one. */
duct_nonnull(1) static inline duct_olb_rx_t *duct_conn_rx_olb(const duct_conn_t *conn)
{
    return duct_conn_has_olb(conn) ? conn->rx_buf : nullptr;
}

/** @brief @p conn's TX ring; nullptr on an xport without one. */
duct_nonnull(1) static inline duct_olb_tx_t *duct_conn_tx_olb(const duct_conn_t *conn)
{
    return duct_conn_has_olb(conn) ? conn->tx_buf : nullptr;
}

/** @brief @p conn's inter lane; nullptr on an xport without one. */
duct_nonnull(1) static inline duct_vmq_mpsc_t *duct_conn_lane(const duct_conn_t *conn)
{
    return duct_conn_has_olb(conn) ? nullptr : conn->inter_lane;
}

/** @brief Resolve @p conn's sealed-wire state.
 *  @return @c &conn->seal for an xport a sealed wire runs on — the four
 *  holding an OLB pair, plus @c x_udp_shared, whose RX uses the shared
 *  listener socket and returns false for @ref duct_conn_has_olb; @c nullptr for
 *  the rest.
 */
duct_nonnull(1) static inline duct_sealed_conn_ctx_t *
duct_conn_sealed_ctx(duct_conn_t *conn)
{
    return duct_conn_has_olb(conn) || conn->xport_type == x_udp_shared
         ? &conn->seal : nullptr;
}

/** @brief Detach @p conn's sealed-wire codec and destroy it.
 *  A pin on the codec's cleartext buffer keeps the buffer, not the codec.
 *  No-op if @p conn is not sealed-eligible or has no codec.
 */
duct_nonnull(1) void duct_conn_sealed_codec_detach(duct_conn_t *conn);

/** @brief Wire fd, OLB pair and xport into a pool slot.
 *  The TX OLB holds @p tx_cap bytes; the RX OLB is sized from @p xport and
 *  the fd's vnet header. */
duct_nonnull(1) duct_result_t
duct_conn_setup(duct_conn_t *conn, duct_sock_t fd,
                duct_xport_t xport, size_t tx_cap);

/** @brief Release OLBs, close fd, and reset connection fields. */
duct_nonnull(1) void duct_conn_teardown(duct_conn_t *conn);

/** @brief Return the RX slot an undrained inter batch still references.
 *
 *  The @ref duct_vmq_mpsc_drain callback every discard of an inter lane must
 *  pass: a batch dropped before it reaches a worker takes its slot with it and
 *  nothing hands that slot back — a leak visible only as a pool that stops
 *  handing any out. A message that is not a batch, and a batch carrying its
 *  payload inline, are both no-ops; @p arg is unused.
 */
duct_nonnull(1) void duct_conn_inter_slot_release(duct_vmq_hdr_t *hdr, void *arg);

/** @brief Atomically add @p flags to the conn state. */
duct_nonnull(1) static inline void
duct_conn_state_set(duct_conn_t *conn, duct_conn_flags_t flags)
{
    duct_atomic_fetch(or, &conn->state, flags, release);
}

/** @brief Atomically remove @p flags from the conn state. */
duct_nonnull(1) static inline void
duct_conn_state_clear(duct_conn_t *conn, duct_conn_flags_t flags)
{
    duct_atomic_fetch(and, &conn->state, duct_not(flags), release);
}

/** @brief Load conn state flags. */
duct_nonnull(1) static inline duct_conn_flags_t
duct_conn_state(const duct_conn_t *conn)
{
    return duct_atomic_load(&conn->state, acquire);
}

/** @brief Replace @c gen_req's reason sub-field. */
duct_nonnull(1) static inline void
duct_gen_req_reason_set(duct_conn_t *conn,
                        duct_close_reason_t reason)
{
    auto slot = duct_conn_gen_req(conn);
    auto old = duct_atomic_load(slot, relaxed);
    for (;; duct_cpu_relax()) {
        auto want =
            (old & ~(gen_req_reason_mask << gen_req_reason_shift))
            | ((uint64_t)reason << gen_req_reason_shift);
        if (duct_atomic_cas(weak, slot, &old,
                            want, relaxed, relaxed))
            return;
    }
}

/** @brief Bind conn to a session, gated by the close-fence.
 *
 *  Writes @c session_token and release-CASes @c fence_unbound
 *  → @c fence_open, then stores @c bound_worker. On success the
 *  caller may publish the leg
 *  and invoke the author callback. On failure, e.g. if io
 *  already quiesced this conn, the token is cleared and the
 *  caller must roll back any prepared session state.
 */
duct_nonnull(1) static inline bool
duct_conn_session_bind(duct_conn_t *conn, duct_handle_t tok)
{
    conn->session_token = tok;
    duct_conn_fence_t expected = fence_unbound;
    if (duct_atomic_cas(strong, &conn->conn_fence, &expected,
                        fence_open, release, acquire)) {
        duct_atomic_store(&conn->bound_worker, conn->worker_id + 1u, relaxed);
        return true;
    }
    conn->session_token = handle_null;
    return false;
}

/** @brief Clear the session bind: @c session_token and @c bound_worker.
 *  Called from conn-lost consume on detachment, ahead of the retire confirm,
 *  after which @c s_inter_drain no longer matches the conn.
 */
duct_nonnull(1) static inline void
duct_conn_session_unbind(duct_conn_t *conn)
{
    conn->session_token = handle_null;
    duct_atomic_store(&conn->bound_worker, 0u, relaxed);
}

/** @brief Claim the close-fence for @p conn.
 *
 *  Both io @c s_conn_close, an ordinary close, and worker
 *  @c s_worker_retire_pre_open, rejecting a conn that never
 *  got a session, can reach here for the same conn — whichever
 *  side wins, makes the transition into @c fence_quiescing.
 *
 *  @retval fence_unbound  No session was ever attached, nothing to detach —
 *                         the caller can retire @p conn.
 *  @retval fence_open     A live session must still be told via @c conn_lost
 *                         before retire.
 *
 *  Any other returned value means this call lost the race — @p conn is
 *  already being quiesced elsewhere.
 */
duct_nonnull(1) static inline duct_conn_fence_t
duct_conn_fence_quiesce(duct_conn_t *conn)
{
    duct_conn_fence_t expected = fence_unbound;
    if (duct_atomic_cas(strong, &conn->conn_fence, &expected,
                        fence_quiescing, acq_rel, acquire))
        return fence_unbound;
    expected = fence_open;
    if (duct_atomic_cas(strong, &conn->conn_fence, &expected,
                        fence_quiescing, acq_rel, acquire))
        return fence_open;
    return expected;
}

/** @brief Worker hands @p conn back to io for physical retire.
 *
 *  Called once worker-side cleanup completes on either valid path:
 *  a pre-open reject before any session ever bound — @c fence_quiescing,
 *  or an ordinary conn-lost consume right after detaching a bound
 *  session leg — @c fence_posted.
 *
 *  @retval true   This call won the transition — the caller must then ask
 *                 the assigned io thread to retire the conn, which
 *                 @c duct_io_retire_request does by posting one request bit.
 *  @retval false  Retire was already claimed by a consumer or the dispatch
 *                 was stale/duplicate.
 */
duct_nonnull(1) static inline bool
duct_conn_fence_confirm_retire(duct_conn_t *conn)
{
    duct_conn_fence_t expected = fence_posted;
    if (duct_atomic_cas(strong, &conn->conn_fence, &expected,
                        fence_retire_ready, release, acquire))
        return true;
    expected = fence_quiescing;
    return duct_atomic_cas(strong, &conn->conn_fence, &expected,
                           fence_retire_ready, release, acquire);
}

/** @brief Return conn's slot index within the pool. */
duct_nonnull(1) uint32_t
duct_conn_idx_get(const duct_conn_t *conn);

/** @brief Return conn pointer for pool slot index. */
duct_conn_t *duct_conn_by_idx(unsigned idx);

/** @brief Link @p conn onto thread @p io_id live-conn list.
 *  Called at accept or dial-promotion registration.
 *  Io-thread-only, unsynchronized.
 */
duct_nonnull(1) void
duct_conn_io_list_link(duct_conn_t *conn, unsigned io_id);

/** @brief Unlink @p conn from thread @p io_id live-conn list.
 *  Called from an ordinary close, pre-open retire or process
 *  shutdown. Io-thread-only, unsynchronized, idempotent.
 */
duct_nonnull(1) void
duct_conn_io_list_unlink(duct_conn_t *conn, unsigned io_id);

/** @brief Head of io thread @p io_id's live-conn list,
 *  walked via @c conn->io_next.
 *  @return nullptr if list is empty.
 */
duct_conn_t *duct_conn_io_list_head(unsigned io_id);

/** @brief Store @p conn's current generation into a cross-thread handle.
 *  Resolve it later with @ref duct_conn_by_handle.
 */
duct_nonnull(1) static inline duct_conn_handle_t
duct_conn_handle_get(const duct_conn_t *conn)
{
    return (duct_conn_handle_t){
        .idx = duct_conn_idx_get(conn),
        .gen = duct_gen_req_gen(duct_atomic_load(
            duct_conn_gen_req(conn), relaxed)) };
}

/** @brief Resolve @p handle to its live conn.
 *  @return nullptr if the slot is free or
 *          on generation mismatch.
 */
duct_conn_t *duct_conn_by_handle(duct_conn_handle_t handle);

/** @brief Pop a conn slot off the free stack.
 *  Bumps @c gen_req's generation, invalidating every handle
 *  still pointing at the slot's previous occupant.
 *  @return nullptr when the stack is empty, which adds one to
 *  @c duct_conns_refused, or when the popped slot is at its generation ceiling
 *  and retires for good.
 */
duct_conn_t *duct_conn_acquire(void);

/** @brief Push @p conn back onto the free stack.
 *  Bumps @c gen_req's generation. Caller must tear down conn
 *  resources before — by the time @ref duct_conn_fence_retire
 *  reaches this, the close-fence already proved no worker
 *  or io reference remains, so the slot is now reusable.
 */
duct_nonnull(1) void duct_conn_release(duct_conn_t *conn);

/** @brief Tear down @p conn's resources and release its slot, or retire
 *  it for good at the generation ceiling.
 *  Safe only once nothing in flight can still deref @p conn: the
 *  close-fence's terminal CAS in @ref duct_conn_fence_retire, a quiesce
 *  finding it unbound with no ctrl on the WFQ, a conn never published,
 *  or a shutdown path with no consumer left. A slot whose request node
 *  is posted and not yet run is held instead, @c fl_conn_reclaim_held
 *  set and nothing torn down: the io thread reclaims it as it runs that
 *  node, so no next occupant reposts a node io still walks.
 */
duct_nonnull(1) void duct_conn_reclaim(duct_conn_t *conn);

/** @brief Force every still-live conn slot back to free stack,
 *  bypassing the close-fence entirely.
 *  Recovers slots remaining unclosed during shutdown (such as entries
 *  at @c fence_retire_ready after I/O thread exit).
 *  Called once during engine shutdown before proto/wire teardown.
 *  Idempotent.
 */
void duct_conn_pool_reclaim(void);

/** @brief Bind @p conn to a wire and create its parser.
 *  @p leg_wire binds when provided; @p proto->wire is used otherwise;
 *  safe when neither exists. Also replaces the OLBs' coarse @c buf_size/8 defaults:
 *  RX recv threshold and TX min_room come from the bound wire's frame budget,
 *  while @c cfg->max_response still caps TX — admission sized that from the
 *  protocol's wire before any leg existed.
 *
 *  @retval rc_invalid_order  @p conn already carries a wire or parser — the
 *                            caller must tear those down first,
 *                            @ref duct_conn_wire_rebind is the only place
 *                            that does.
 *  @retval rc_no_memory      The wire needs parser state and allocating it
 *                            failed.
 *  @retval rc_invalid_arg    The bound wire's framing disagrees with @p conn's
 *                            xport over the datagram record header; the dial,
 *                            listener-bind and attach paths reject this
 *                            earlier, where the caller still sees the result.
 *  @retval rc_ok             Bound.
 */
duct_nonnull(1) duct_result_t
duct_conn_bind_wire(duct_conn_t *conn, const duct_proto_t *proto,
                    const duct_wire_t *leg_wire);

#ifdef __cplusplus
}
#endif

#endif /* DUCT_CONN_H */
