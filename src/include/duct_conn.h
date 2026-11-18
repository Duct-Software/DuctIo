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
typedef struct duct_wfq_route duct_wfq_route_t;

/** @brief Sentinel for @c io_id.
 *  Conn is outside every io thread's registry.
 */
static constexpr auto conn_io_none = UINT32_MAX;

/** @brief Sentinel for @c worker_id.
 *  Conn is not yet assigned by the io thread.
 */
static constexpr auto conn_worker_none = UINT32_MAX;

/** @brief Bit width of @c duct_conn_handle_t's @c idx sub-field. */
static constexpr unsigned hconn_idx_bits = alloc_slot_bits;

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

/** @brief Connection state flags — the io thread's gate bits, plus the two
 *  sticky TX hints the shared grouped-send helper records from whichever
 *  thread met the kernel's refusal.
 *  The latch bits this word once carried are single-writer values now:
 *  the RX read stall is the rx header's @c resume_at edge (§6), the TX room
 *  wait the tx header's own @c resume_at, the author's RX pause a bit on the
 *  rx header's ack line, and the write-interest state lives on the tx
 *  header's io line.
 *  Atomically manipulated via @ref duct_conn_state_set and
 *  @ref duct_conn_state_clear helpers.
 */
typedef enum duct_conn_flags : uint16_t {

    fl_conn_closed      = 1u << 0, /**< Conn already closed. Set once by the
                                     *  io thread and read at its RX, TX and
                                     *  fence gates; cleared only by the next
                                     *  @ref duct_conn_acquire's state
                                     *  reset. */

    fl_conn_closing     = 1u << 1, /**< Worker requested close; quiesce once
                                     *  TX drains. Set once by the io thread;
                                     *  read at the close fence and at the io
                                     *  thread's drain and quiesce gates;
                                     *  cleared only by the next @ref
                                     *  duct_conn_acquire's state reset. */

    fl_conn_roaming     = 1u << 2,  /**< An @c x_udp_peer leg whose listener
                                      *  holds a candidate address for it, put
                                      *  there by a datagram that arrived from
                                      *  somewhere other than where this socket
                                      *  is connected. Written by I/O thread,
                                      *  read by worker thread as a
                                      *  stale-tolerant hint: the worker posts
                                      *  @c fl_req_peer_roam for an accepted
                                      *  frame whose ack total reaches the RX
                                      *  ring's @c roam_at, and io moves the
                                      *  socket from there. A stale read costs
                                      *  one post io then finds nothing to do. */
    fl_conn_rx_eof      = 1u << 3,  /**< End of the conn's input, read off the
                                      *  peer. Set by the io thread on the
                                      *  zero-length read, and every later read
                                      *  stops at its RX gates; cleared only by
                                      *  the next @ref duct_conn_acquire's
                                      *  state reset. */
    fl_conn_vnet_uso    = 1u << 4, /**< Conn whose tun took the USO flags at its open.
                                      *  Set once by the io thread in
                                      *  @ref duct_conn_setup; read by the worker's
                                      *  vnet write train, which merges UDP
                                      *  datagrams for a conn that carries it.
                                      *  Cleared only by the next
                                      *  @ref duct_conn_acquire's state reset. */
    fl_conn_dgram_gro   = 1u << 5,
    fl_conn_gso_off     = 1u << 6,
    fl_conn_vnet_uso_tx = 1u << 7,
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

    fl_req_fence_retry = 1u << 3,   /**< Retry a previously failed
                                      *  close-fence publish.*/

    fl_req_wire_rebind = 1u << 4,   /**< Rebind @c conn->wire for a
                                      *  wire-changing proto switch.
                                      *  @see duct_proto_switch */

    fl_req_peer_roam   = 1u << 5,   /**< Point this @c x_udp_peer conn's
                                      *  connected socket at the candidate
                                      *  address its listener holds.
                                      *  @see fl_conn_roaming */
} duct_conn_req_flags_t;

static_assert(sizeof(duct_conn_req_flags_t) == sizeof(uint8_t),
              "duct_conn_req_flags_t width must be 1 byte");

/** @brief Per-conn lifecycle phase, the low three bits of the @c gen_req
 *  lifecycle byte.
 *  Monotonic per generation; a close whose lane slot is refused leaves the
 *  conn at @c conn_quiesced with @c fl_req_fence_retry armed, so
 *  @c conn_lost_posted is reached only once and never walked back.
 *  The worker CAS @c conn_unbound → @c conn_bound and the io CAS
 *  @c phase < conn_quiesced → @c conn_quiesced are the critical
 *  synchronization points, preventing:
 *  — a session bind from publishing author callbacks on a quiesced conn,
 *  — io from destroying a conn the worker still references.
 */
typedef enum duct_conn_phase : uint8_t {
    conn_unbound,      /**< No session attached yet. */
    conn_bound,        /**< Bound to a session. */
    conn_quiesced,     /**< io stopped the conn; lost not yet posted. */
    conn_lost_posted,  /**< @c conn_lost published to normal WFQ lane. */
    conn_retire_done,  /**< Session unbound / teardown done; refs == 0 pending. */
    conn_spent,        /**< refs == 0 with host pins; §5. */
} duct_conn_phase_t;

static_assert(sizeof(duct_conn_phase_t) == sizeof(uint8_t),
              "duct_conn_phase_t width must be 1 byte");

/** @name @c Generation-request word bit layout.
 *  Generation, request-flags, close-request reason and the lifecycle byte
 *  share one 64-bit atomic so a poster's "does my handle's generation still
 *  match" check and "set my request bit" are written at the same CAS,
 *  preventing a race between the two.
 *  Layout (low to high): [6:0] req_flags, [9:7] close reason, [55:10]
 *  generation (46 bits match @ref hconn_gen_mask), [58:56] phase,
 *  [59] rel_pend, [63:60] host pin count (§5).
 *  @{
 */
static constexpr unsigned gen_req_flags_shift   = 0u;
static constexpr uint64_t gen_req_flags_mask    = 0x7Full;
static constexpr unsigned gen_req_reason_shift  = 7u;
static constexpr uint64_t gen_req_reason_mask   = 0x7ull;
static constexpr unsigned gen_req_gen_shift     = 10u;
static constexpr unsigned gen_req_phase_shift   = 56u;
static constexpr uint64_t gen_req_phase_mask    = 7ull << gen_req_phase_shift;
static constexpr uint64_t gen_req_rel_pend      = 1ull << 59u;
static constexpr unsigned gen_req_pins_shift    = 60u;
static constexpr uint64_t gen_req_pins_mask     = 15ull << gen_req_pins_shift;

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

/** @brief Extract the lifecycle phase from a @c gen_req word. */
static inline duct_conn_phase_t
duct_gen_req_phase(uint64_t word)
{
    return (duct_conn_phase_t)
        ((word >> gen_req_phase_shift)
         & (gen_req_phase_mask >> gen_req_phase_shift));
}
/** @} */

/** @brief Sealed-wire state for one conn.
 *  Outlives @c codec, which a wire rebind destroys while a task parsed under
 *  the old generation can still replay and ask what was already acked.
 */
typedef struct duct_sealed_conn_ctx {

    /** @brief Worker codec instance.
     *  Nullptr until the first sealed-wire task on this conn
     *  builds it via @c wire->init_codec in the conn block's codec
     *  slot; released via @c codec->release at conn-lost consume,
     *  wire-rebind fence or final teardown.
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
 *  L4 ⟷ L5 bind is attach-layer: @c session_token plus a lifecycle phase CAS
 *  is the L4-side half, @ref duct_conn_session_bind.
 *  Attach-side state
 *  (leg and session choice) resides in the session @c conns[] array.
 *  Both halves are bound and unbound by the worker.
 */
typedef struct duct_conn {
    duct_cacheline_struct(
        duct_conn_flags_t _Atomic state;      /**< Lifecycle/gate bits. */

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

        /** @brief Release count over the conn's named participants: the io
         *  owner (1 at @ref duct_conn_acquire), a posted ctrl (+1 at
         *  @c s_post_ctrl, converted at bind), and every armed async kernel
         *  I/O submission (+1 before submit, -1 in @c duct_olb_io_done).
         *  The 0-crossing fetch_sub finalizes the slot: @c rel_pend when
         *  request flags are live, @c conn_spent when a host pin rides the
         *  word (§5), else the generation bump and the push back to the
         *  block pool.
         */
        uint32_t _Atomic refs;

        /** @brief Bound session handle, @c handle_null if unbound.
         *  Set before worker's release-CAS @c conn_unbound → @c conn_bound;
         *  io thread that wins the acquire-CAS to @c conn_quiesced
         *  observes it complete.
         */
        duct_handle_t _Atomic session_token;

        /** @brief Next / prev links in io thread's live-conn list.
         *  Linked by @ref duct_conn_io_list_link, unlinked by
         *  @ref duct_conn_io_list_unlink at the close decision.
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
        duct_sock_t fd; /**< Conn socket descriptor. The rx and tx rings, an
                          *  inter lane and the small ctx live at fixed
                          *  page-0 offsets of the conn's block, addressed
                          *  through @ref duct_conn_block.h; the xport alone
                          *  decides which of them is live. */

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

/** @brief Load @p conn's lifecycle phase with one acquire read of the
 *  @c gen_req word. */
duct_nonnull(1) static inline duct_conn_phase_t
duct_conn_phase(const duct_conn_t *conn)
{
    return duct_gen_req_phase(
        duct_atomic_load(duct_conn_gen_req(conn), acquire));
}

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

/** @brief Bind conn to a session, gated by the lifecycle phase.
 *
 *  Writes @c session_token and release-CASes the @c gen_req word's phase
 *  @c conn_unbound → @c conn_bound. On success the
 *  caller may publish the leg
 *  and invoke the author callback. On failure, e.g. if io
 *  already quiesced this conn, the token is cleared and the
 *  caller must roll back any prepared session state.
 */
duct_nonnull(1) static inline bool
duct_conn_session_bind(duct_conn_t *conn, duct_handle_t tok)
{
    duct_atomic_store(&conn->session_token, tok, release);
    auto slot = duct_conn_gen_req(conn);
    uint64_t old = duct_atomic_load(slot, acquire);
    for (;; duct_cpu_relax()) {
        if (duct_gen_req_phase(old) != conn_unbound)
            break;
        uint64_t want = (old & ~gen_req_phase_mask)
                      | ((uint64_t)conn_bound << gen_req_phase_shift);
        if (duct_atomic_cas(weak, slot, &old, want, release, acquire))
            return true;
    }
    duct_atomic_store(&conn->session_token, handle_null, release);
    return false;
}

/** @brief Take one unit of @p conn's release count for a borrower about to
 *  touch the conn past its owner's own unit. */
duct_nonnull(1) static inline void
duct_conn_ref_take(duct_conn_t *conn)
{
    duct_atomic_fetch(add, &conn->refs, 1u, acquire);
}

/** @brief Claim the close for @p conn: CAS the phase below @c conn_quiesced
 *  to @c conn_quiesced, clearing @c fl_req_close in the same word.
 *
 *  Both io @c s_conn_close, an ordinary close, and worker
 *  @c s_worker_retire_pre_open, rejecting a conn that never
 *  got a session, can reach here for the same conn — whichever
 *  side wins, makes the transition into @c conn_quiesced.
 *
 *  The bit clear rides the phase CAS so a word reader never sees
 *  @c fl_req_close gone while the phase still reads @c conn_unbound:
 *  that intermediate would let a dispatch defer a frame to a conn
 *  whose close request already consumed the last release unit.
 *
 *  @retval true   This call won the transition; @c *pre holds the prior
 *                 phase — @c conn_unbound means no session was ever
 *                 attached, nothing to detach, @c conn_bound means a live
 *                 session must still be told via @c conn_lost.
 *  @retval false  This call lost the race — @p conn is already being
 *                 quiesced elsewhere.
 */
duct_nonnull(1, 2) static inline bool
duct_conn_close_claim(duct_conn_t *conn, duct_conn_phase_t *pre)
{
    auto slot = duct_conn_gen_req(conn);
    uint64_t old = duct_atomic_load(slot, acquire);
    for (;; duct_cpu_relax()) {
        auto phase = duct_gen_req_phase(old);
        if (phase >= conn_quiesced)
            return false;
        uint64_t want = (old & ~(gen_req_phase_mask | (uint64_t)fl_req_close))
                      | ((uint64_t)conn_quiesced << gen_req_phase_shift);
        *pre = phase;
        if (duct_atomic_cas(weak, slot, &old, want, acq_rel, acquire))
            return true;
    }
}

/** @brief Advance @p conn's phase from @p from to @p to inside the word,
 *  leaving every other sub-field untouched.
 *  @return true when this call made the transition.
 */
duct_nonnull(1) static inline bool
duct_conn_phase_move(duct_conn_t *conn, duct_conn_phase_t from,
                     duct_conn_phase_t to)
{
    auto slot = duct_conn_gen_req(conn);
    uint64_t old = duct_atomic_load(slot, relaxed);
    for (;; duct_cpu_relax()) {
        if (duct_gen_req_phase(old) != from)
            return false;
        uint64_t want = (old & ~gen_req_phase_mask)
                      | ((uint64_t)to << gen_req_phase_shift);
        if (duct_atomic_cas(weak, slot, &old, want, release, relaxed))
            return true;
    }
}

/** @brief Take one host pin on @p conn's lifecycle word, §5.
 *
 *  A host thread — one the release count never enumerates — resolves the
 *  conn by handle and pins it in the same CAS: the generation check, the
 *  phase gate and the pin increment are one atomic operation on @c gen_req,
 *  so no Dekker store/load pair and no second resolve are needed. The pin
 *  never touches @c conn->refs: a pinned word cannot reach the generation
 *  bump (the count's finish marks it @c conn_spent instead), so the slot
 *  stays put until @ref duct_conn_unpin's 1→0 drop finishes it.
 *
 *  @retval rc_ok     Pinned: @c pins went up by one. The word still matches
 *                    @p gen, and the phase is a live bind.
 *  @retval rc_closed The handle is stale — @p gen no longer matches — or the
 *                    phase reached @c conn_quiesced: the close shut the door
 *                    on new pins, nothing was taken.
 *  @retval rc_defer  The conn is still @c conn_unbound (nothing to deliver
 *                    a batch to), or the pin nibble is saturated at 15.
 */
duct_nonnull(1) static inline duct_result_t
duct_conn_pin(duct_conn_t *conn, uint64_t gen)
{
    auto slot = duct_conn_gen_req(conn);
    uint64_t old = duct_atomic_load(slot, acquire);
    for (;; duct_cpu_relax()) {
        if (duct_gen_req_gen(old) != gen)
            return rc_closed;
        auto phase = duct_gen_req_phase(old);
        if (phase >= conn_quiesced)
            return rc_closed;
        if (phase == conn_unbound || (old & gen_req_pins_mask) == gen_req_pins_mask)
            return rc_defer;
        /* +1 on the nibble: the saturation check above keeps the carry out
         * of bit 63 from ever being attempted. */
        if (duct_atomic_cas(weak, slot, &old,
                            old + (1ull << gen_req_pins_shift), acquire, relaxed))
            return rc_ok;
    }
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

/** @brief Drop one unit of @p conn's release count.
 *  The 0-crossing fetch_sub finalizes the slot: with live request flags it
 *  arms @c rel_pend inside the word and returns — @c s_req_exec finishes the
 *  release as it runs the posted node — with a live host pin it CASes the
 *  word to @c conn_spent and returns, handing the finish to the last
 *  @ref duct_conn_unpin — otherwise it bumps the generation and pushes the
 *  slot back to the block pool (or retires it for good at the generation
 *  ceiling).
 */
duct_nonnull(1) void duct_conn_release(duct_conn_t *conn);

/** @brief Finish a release whose 0-crossing armed @c rel_pend: the posted
 *  request node's run calls this with the generation it resolved the conn
 *  under, clearing the bit, bumping the generation and pushing the slot —
 *  or re-arming @c rel_pend when a racing poster re-posted the node.
 *  A generation mismatch means another cycle owns the slot: no-op.
 */
duct_nonnull(1) void duct_conn_release_finish(duct_conn_t *conn, uint64_t gen);

/** @brief Run @p conn's io-side teardown half: the per-xport ctx work with
 *  no queued worker work behind it — the @c x_local listener drop.
 *  Called at the close decision, ahead of the physical half.
 */
duct_nonnull(1) void duct_conn_teardown_io(duct_conn_t *conn);

/** @brief Run @p conn's per-xport ctx finish: the @c x_udp_shared listener
 *  pre_conn_ref release (any-thread posted form) with the datagram ctx
 *  clear, and the @c x_inter device holds + @c ops->release. Must run past
 *  the lane drain — batches queued ahead of the consume can still carry
 *  device-lent payloads and reserve into the listener outbox — and the
 *  device arm only on the owning io thread (or joined threads).
 */
duct_nonnull(1) void duct_conn_teardown_ctx(duct_conn_t *conn);

/** @brief Drop one host pin taken by @ref duct_conn_pin.
 *  The 1→0 fetch_sub on the word's pin nibble is the pin side's whole
 *  protocol: on a word the count's finish already marked @c conn_spent, this
 *  last unpin is the completing one — it bumps the generation and pushes the
 *  slot (or arms @c rel_pend over live request flags); on any other word the
 *  release count still holds the slot and its own finish observes
 *  @c pins == 0 and completes.
 */
duct_nonnull(1) void duct_conn_unpin(duct_conn_t *conn);

/** @brief Run @p conn's physical teardown half: sealed codec detach, inter
 *  lane drain, fd close and @ref duct_io_accept_resume. Safe against io
 *  completions still in flight: each holds its own @c refs unit and only
 *  touches page-0 words. A host pin still riding the word (§5) is equally
 *  bounded: its in-flight push into the lane is one more MPSC producer the
 *  drain pairs with, and the pinned word keeps the slot from any reuse.
 */
duct_nonnull(1) void duct_conn_teardown_worker(duct_conn_t *conn);

/** @brief Run both teardown halves and drop the io unit of @p conn.
 *  For a conn nothing else references — never published, unbound at its
 *  close, or engine shutdown — this returns the slot once @c refs drains.
 */
duct_nonnull(1) void duct_conn_discard(duct_conn_t *conn);

/** @brief Force every still-live conn slot back to free stack,
 *  bypassing the release count entirely.
 *  Recovers slots remaining unclosed during shutdown (such as conns whose
 *  consuming worker exited before its conn_lost drained).
 *  Called once during engine shutdown before proto/wire teardown.
 *  Idempotent.
 */
void duct_conn_pool_reclaim(void);

/** @brief Rebind @p conn's wire for a wire-changing @c duct_proto_switch.
 *
 *  A peer unaware of the switch may still be mid-frame under the old wire,
 *  so the rebind waits for the unparsed leftover to drain or prove discardable
 *  before swapping. On drain, swaps @c conn->wire / @c wire_parser to
 *  @c wire_rebind_next's and posts the completion fence.
 *  No-op if @c wire_rebind_next is already clear, and for a conn at
 *  @c conn_quiesced or past: it keeps its sentinel and posts no fence, its
 *  @c conn_lost paying the leg's share of the switch.
 */
duct_nonnull(1, 2) void
duct_conn_wire_rebind(const duct_wfq_route_t *route, duct_conn_t *conn);

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
