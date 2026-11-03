/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_codel.h
 *  @brief Queue control over one leg's TX ring: a sojourn tracer, RFC 8289 CoDel
 *  under the caller's law, a byte backstop, and the answer to a signal on an IP
 *  packet.
 *
 *  The tracer stamps the ring's end with the time; the stamp to the moment io
 *  hands that point to the kernel, or the socket sends it where a reader answers,
 *  is one sojourn. CoDel signals once the queue has stood above the law's target
 *  for a whole interval, and the backstop answers @c codel_full for a frame the
 *  ring cannot take. The engine gives the verdict and the protocol acts on it,
 *  through @ref duct_codel_act for a frame holding an IP packet.
 *
 *  @c duct_conn_codel and @c duct_conn_codel_delay read the leg's positions from
 *  the @c duct_conn_tx_* accessors and run in the session's own callbacks, before
 *  the frame is staged. A @ref duct_codel_t serves one leg: all-zero is idle, and
 *  the caller zeroes it when the leg at its conn id is replaced.
 */

#ifndef DUCT_CODEL_H
#define DUCT_CODEL_H

#include "duct_protocol.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief RFC 8289's TARGET, the standing queue delay CoDel accepts, nanoseconds. */
static constexpr uint64_t duct_codel_target_ns   = 5'000'000u;
/** @brief RFC 8289's INTERVAL, the time a queue stays above target before CoDel
 *  signals, nanoseconds. */
static constexpr uint64_t duct_codel_interval_ns = 100'000'000u;

/** @brief CoDel's figures for one leg's queue, nanoseconds. */
typedef struct {
    uint64_t target,   /**< Standing delay the queue keeps under. */
             interval, /**< Time above target before the first signal, and the control
                         *  law's step. Read up to 2^48 - 1, the most the law's 16-bit
                         *  shift carries. */
             at_once;  /**< Sojourn signalled without waiting out the interval;
                         *  @c UINT64_MAX turns the rule off. */
} duct_codel_law_t;

/** @brief One delay sample, as CoDel's state machine takes it. */
typedef enum : uint8_t {
    codel_below, /**< A queue within the floor, or under target and within the ceiling. */
    codel_above, /**< Any other queue, at a delay under the law's @c at_once. */
    codel_far,   /**< Any other queue, at a delay at or past the law's @c at_once. */
} duct_codel_sample_t;

/** @brief Queue control's answer for one frame. */
typedef enum : uint8_t {
    codel_pass,   /**< Frame cleared to go on. */
    codel_signal, /**< Frame chosen for a congestion signal: a run's first, and a later
                    *  one under an interval past @c first_above. */
    codel_loss,   /**< Frame chosen for a later signal of a run, an interval or more
                    *  past @c first_above. */
    codel_full,   /**< Frame the ring cannot take and still hold admission's reservation
                    *  for the next callback. */
} duct_codel_verdict_t;

/** @brief What a CoDel signal did to the frame at hand. */
typedef enum : uint8_t {
    codel_act_mark, /**< Relayed marked CE where it lies: an ECN-capable packet under
                      *  @c codel_signal. */
    codel_act_trim, /**< Relayed less its last segment, cut where it lies: a record of
                      *  three segments or more with no FIN, SYN or RST, when it is
                      *  Not-ECT or the verdict is @c codel_loss. */
    codel_act_keep, /**< Relayed as it came: CE already under @c codel_signal, or no IP
                      *  header. */
    codel_act_drop, /**< Dropped: any other frame, a record the trim refuses among them. */
} duct_codel_action_t;

/** @brief Queue control state for one leg.
 *  All-zero is idle. Times are the caller's monotonic nanoseconds and never 0,
 *  which marks a time field unset. */
typedef struct {
    duct_tx_pos_t tracer;      /**< End of the ring as the open sample was taken. */
    uint64_t      tracer_at,   /**< Time the open sample was taken, 0 with none open. */
                  sojourn,     /**< Last closed sample: @c tracer_at to the moment @c tracer
                                 *  left; 0 once the queue empties. */
                  first_above, /**< Time at which the stretch above target has lasted an
                                 *  interval, RFC 8289's first_above_time; 0 while below. */
                  signal_next; /**< Time of the next signal, RFC 8289's drop_next; kept
                                 *  past a run to date the next one's start. */
    size_t        queued;      /**< Bytes the last offer weighed: the ring's queue plus the
                                 *  socket's unsent bytes at the last reading. */
    uint32_t      count,       /**< Signal counter of the run, RFC 8289's count; 1 or more
                                 *  once a run starts. */
                  last_count;  /**< @c count as the run started, RFC 8289's lastcount. */
    bool          signalling;  /**< In a signalling run, RFC 8289's dropping. */
    uint64_t      unsent,      /**< The leg socket's unsent bytes at the last reading; 0
                                 *  before one. */
                  read_at,     /**< Time of the last reading, 0 before the first. */
                  read_sent;   /**< Stream offset the socket had sent to at the last
                                 *  reading. */
} duct_codel_t;

/** @brief Reader of a leg socket's unsent bytes.
 *  Answers @ref duct_tx_unsent_unread when it reads none. Called from the session's
 *  own callbacks; @c duct_conn_tx_unsent is the reader the engine runs. */
typedef uint64_t (*duct_codel_unsent_fn)(duct_session_t *s, duct_conn_id_t leg);

/** @brief Take one delay sample off a leg's queue.
 *
 *  @p end is @c duct_conn_tx_end's end, read before the frame at hand is staged,
 *  and @p queued the whole queue ahead of it, the ring's and any socket share a
 *  reader answered; @p left_at is when @c q->tracer left, 0 while it has not. An
 *  empty queue drops the open sample and the last sojourn. A queue within @p least
 *  samples below at any delay. A queue past @p most and @p least stands above
 *  target at any delay, which bounds the queue the law's target tolerates to
 *  @p most. @p law's @c target and @c at_once class the rest.
 */
duct_nonnull(1, 2) duct_codel_sample_t
duct_codel_sample(duct_codel_t *q, const duct_codel_law_t *law, duct_tx_pos_t end, size_t queued,
                  size_t least, size_t most, uint64_t left_at, uint64_t now);

/** @brief Step CoDel by one sample and give the frame at hand its verdict.
 *
 *  RFC 8289's state machine under @p law's interval, run as the frame is offered:
 *  the drop the RFC makes at dequeue becomes that frame's signal. A @c codel_far
 *  sample counts the interval as already run; inside a run the control law still
 *  spaces the signals. An interval past 2^48 - 1 reads as 2^48 - 1.
 *
 *  @return @c codel_pass, or the frame's signal: @c codel_signal for a run's first
 *          and for later ones under an interval past @c first_above, @c codel_loss
 *          from there on. Never @c codel_full.
 */
duct_nonnull(1, 2) duct_codel_verdict_t
duct_codel_step(duct_codel_t *q, const duct_codel_law_t *law, duct_codel_sample_t sample,
                uint64_t now);

/** @brief Test whether @p q's queue has stood above its law's target for a whole
 *  interval as of its last sample.
 *  The test @ref duct_codel_step signals on, read without a sample of its own. */
static inline bool duct_codel_due(const duct_codel_t *q, uint64_t now)
{
    return q->first_above && now >= q->first_above;
}

/** @brief Date @p q's open tracer leaving leg @p leg's socket.
 *
 *  The socket has sent S = W - U: W is @p end less @p ring, the bytes the socket
 *  was handed, and U its unsent bytes at a reading through @p read. The tracer, at
 *  stream offset T, has left once S reaches T. A reading falls due once W reaches
 *  T plus the last reading's U, or in a lull once W reaches T: @p law's target past
 *  the later of the take and the last reading, so a U a drained socket left stale
 *  holds for one target at most. With none open, one falls due in a lull once W
 *  passes the last reading's S by more than @p least, the sample's floor: its U
 *  alone shows a queue the socket took whole, the ring left empty. A null @p law
 *  takes no lull. The crossing is interpolated between the reading before and the
 *  one past T, never before the take.
 *
 *  @return when the tracer left; 0 with none open or while it has not; @p now where
 *          a reading fails, no earlier reading exists, or a span passes 2^32.
 */
duct_nonnull(1, 6) uint64_t
duct_codel_left(duct_codel_t *q, const duct_codel_law_t *law, duct_tx_pos_t end, size_t ring,
                size_t least, duct_codel_unsent_fn read, duct_session_t *s, duct_conn_id_t leg,
                uint64_t now);

/** @brief Decide one frame of @p size bytes bound for leg @p conn_id of @p s.
 *
 *  Samples the leg's TX ring, and its socket through @c duct_conn_tx_unsent where
 *  the platform reads one, steps CoDel under @p law, then tests the backstop,
 *  @c duct_conn_tx_fits on @p size: a frame that passes leaves admission its room
 *  for the next one, so no frame waits on the leg where no sample reaches. The
 *  sample's floor is @c duct_conn_tx_quantum and @p size, its ceiling half of
 *  @c duct_conn_tx_cap, and the queue weighed against them is the ring's plus the
 *  last reading's unsent bytes, which land in @c q->queued. Call it from @p s's own
 *  callbacks, before the frame is staged.
 *
 *  @return @c codel_full on a ring short of the backstop, over CoDel's verdict,
 *          CoDel having stepped regardless. @c codel_pass, @p q untouched, wherever
 *          @c duct_conn_tx_end fails: no leg at @p conn_id, or one without a TX
 *          ring, a shared datagram leg. CoDel's verdict otherwise.
 */
duct_nonnull(1, 3, 4) duct_codel_verdict_t
duct_conn_codel(duct_session_t *s, duct_conn_id_t conn_id, duct_codel_t *q,
                const duct_codel_law_t *law, size_t size, uint64_t now);

/** @brief Sample leg @p conn_id of @p s into @p q and answer its queue delay at
 *  @p now, nanoseconds.
 *  The larger of the last closed sojourn and the open tracer's age, @p law taken as
 *  @ref duct_conn_codel takes it; 0 for an empty queue and wherever
 *  @c duct_conn_tx_end fails. Of @p q, the sample's and the reading's own fields
 *  move alone, never CoDel's run. Call it from @p s's own callbacks. */
duct_nonnull(1, 3, 4) uint64_t
duct_conn_codel_delay(duct_session_t *s, duct_conn_id_t conn_id, duct_codel_t *q,
                      const duct_codel_law_t *law, uint64_t now);

/** @brief Answer CoDel's signal @p verdict, @c codel_signal or @c codel_loss,
 *  through @p frame.
 *
 *  For a frame holding one IP packet, or one GSO record, in memory that takes a
 *  write. For @c codel_act_mark and @c codel_act_trim the packet is edited where
 *  @p frame lies, CE set in its header or the record's last segment cut off, and
 *  @p out forwards the edited frame to leg @p leg as a copy-send; @p out and the
 *  frame stay untouched otherwise. A callback that edited answers @c rc_ok or
 *  @c rc_drop, since a frame deferred on a ring replays as edited. A record marked
 *  CE carries the mark to every segment the far kernel cuts from it, and a
 *  trimmed one loses its last segment alone.
 */
duct_nonnull(1, 2) duct_codel_action_t
duct_codel_act(duct_response_t *out, const duct_frame_t *frame, duct_codel_verdict_t verdict,
               duct_conn_id_t leg);

#ifdef __cplusplus
}
#endif

#endif
