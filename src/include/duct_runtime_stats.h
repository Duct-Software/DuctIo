/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_runtime_stats.h
 *  @brief Optional telemetry counter structs.
 */

#ifndef DUCT_RUNTIME_STATS_H
#define DUCT_RUNTIME_STATS_H

#include <stdatomic.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if DUCT_RUNTIME_STATS

#include "duct_core.h"

/** @brief Reactor / RX-path telemetry counters, one block per worker.
 *  Its worker alone writes them, through @c duct_rtstat_obj_inc and
 *  @c duct_rtstat_obj_max; @c duct_engine_stats reads them from any thread. */
typedef struct duct_worker_rt {
    uint64_t _Atomic futex_wait, /**< Times the worker parked on its wake_latch futex — no runnables. */
             loop_pass,      /**< Main-loop iterations. */
             busy_spin,      /**< Idle passes that executed spin iterations before parking. */
             busy_enter,     /**< Idle passes where the spin decision turned on. */
             busy_exit,      /**< Idle passes where it turned off, the worker parking. */
             wfq_drain,      /**< Work units drained off the WFQ: one per plain message,
                                  one per frame of a batch. */
             batch_partial_defer, /**< Frame batches deferred mid-batch: a prefix already
                                    *  dispatched, the remainder parked on defer_q. */
             defer_oom_drop, /**< Frames ack+dropped because a defer-node alloc failed. */
             rx_resume_post, /**< s_rx_ack cleared an RX-full latch and reposted. */
             commit_internal, /**< s_commit_response returned commit_internal. */
             retry_saved,     /**< Successful emit/frame/timer retry save (s_retry_*_save). */
             dgram_shared_tx_drop, /**< x_udp_shared response dropped: its listener's
                                        dgram_tx_outbox lane was full. */
             fastpath_armed_skip, /**< x_udp_peer/x_tcp/x_raw/x_raw_packet worker
                                    *  fast-path send skipped without a syscall:
                                    *  write_armed already known set. An
                                    *  x_udp_shared response answers to
                                    *  dgram_fast_sent and dgram_lane_staged
                                    *  instead, its fast path being the batch. */
             fastpath_eagain, /**< ...vs attempted the syscall and the socket
                                *  took less than it was offered: would-block,
                                *  a short write or a failure. A write cut to
                                *  the cap and taken whole counts in
                                *  tcp_cut_writes alone. */
             dgram_batch_calls, /**< s_worker_dgram_flush calls into
                                   *  duct_io_dgram_shared_send_batch with n >= 1,
                                   *  the x_udp_shared worker fast path's own batch;
                                   *  the io thread's outbox-lane drain counts in
                                   *  duct_io_rt_t::dgram_tx_batch_calls. */
             dgram_batch_msgs,  /**< Sum of n across dgram_batch_calls — submissions,
                                  *  so a retried entry recounts. */
             dgram_batch_max,   /**< Largest single n observed. */
             dgram_fast_sent,   /**< Entries the fast path actually resolved (kernel
                                  *  accepted), each counted once. */
             dgram_lane_staged, /**< Entries the fast path could not send and deferred
                                  *  into the io outbox lane instead. */
             dgram_tx_gso_writes, /**< Segmented writes the fast-path batch made, each
                                    *  one peer's group of equal-sized datagrams. */
             dgram_tx_gso_dgrams, /**< Datagrams those writes carried. */
             tx_pool_acquire_fail, /**< duct_tx_pool_acquire returned NULL: the worker's
                                      *  TX staging pool had no room for the request. */
             vnet_tx_gro_writes, /**< Segmented writes a vnet leg's train made,
                                   *  each of two or more segments. */
             vnet_tx_gro_pkts,   /**< Segments those writes carried. */
             vnet_tx_drop,       /**< Trains a vnet leg's fd refused, each lost
                                   *  whole. */
             vnet_tx_gro_single, /**< Trains of one segment a vnet leg's train
                                   *  wrote, each checked for a merge that
                                   *  never came. */
             tx_train_flush_full, /**< x_udp_peer and x_tcp trains flushed at
                                    *  duct_dgram_tx_batch frames. */
             tx_train_flush_end,  /**< Trains flushed with no frame of the
                                    *  dispatch following. */
             tx_train_flush_wait, /**< Trains flushed once
                                    *  duct_dgram_batch_wait_ns had passed
                                    *  since they opened. */
             inter_held,          /**< Inter-lane messages left on their lane
                                   *  while an answer of their conn waited
                                   *  parked. The message stays at the lane
                                   *  head, so the same one counts again on
                                   *  every later drain that finds the hold
                                   *  standing. */
             tcp_writes,      /**< x_tcp direct sends past the write_armed
                                *  check, one syscall each. */
             tcp_eor_writes,  /**< ...of those, under the socket's write cap,
                                *  each ending its skb. */
             tcp_cut_writes,  /**< ...of those, past the cap and cut to it,
                                *  the rest published for io. */
             pin_fail;        /**< duct_thread_bind_cpu declined or failed at startup;
                                *  this thread is running unpinned. */
} duct_worker_rt_t;

/** @brief I/O telemetry counters, one block per I/O thread.
 *  Its io thread alone writes them, as the worker's block, but for
 *  @c tx_drain_posts and @c tx_drain_deduped, which every thread posting a
 *  drain to it adds to through @c duct_rtstat_atomic_inc. */
typedef struct duct_io_rt {
    uint64_t  _Atomic tx_drain_posts,   /**< drain posts that actually posted (not deduped). */
                      tx_drain_deduped; /**< drain posts skipped by dedup. */
    uint64_t _Atomic wfq_push_full, /**< s_batch_push failures due to VMQ lane full. */
             fence_push_full,  /**< s_conn_post_fence found its norm lane full,
                                 *  fell back to fl_req_fence_retry. */
             rx_full_latch,    /**< s_rx_reserve_space latched an RX-full stall. */
             conns_added,      /**< Conns registered with the events backend on this I/O thread,
                                 *  s_conn_register / _promote: accept, dial-complete, fd-attach,
                                 *  probe promotion. Lane-only conns — x_inter, x_udp_shared —
                                    skip registration, not counted. */
             dgram_shared_rx_drop, /**< A classified datagram for an x_udp_shared conn dropped:
                                     *  its own inter_lane refused the reservation, or the
                                     *  descriptor size for its frame count overflowed. */
             dgram_rx_slot_route, /**< Datagrams the inter lane took by reference
                                    *  to an RX slot, no payload copy. */
             dgram_rx_slot_copy,  /**< Datagrams copied into the lane because no
                                    *  slot was free. */
             dgram_rx_oversize, /**< Datagrams dropped on the io thread for
                                  *  exceeding the conn wire's max_frame, ahead
                                  *  of any lane reservation or slot. */
             pin_fail,         /**< duct_thread_bind_cpu declined or failed at startup;
                                 *  this thread is running unpinned. */
             loop_pass,        /**< Main-loop iterations (duct_events_run_loop), every backend. */
             busy_spin,        /**< Passes whose wait went out with timeout 0 on the
                                 *  last duct_spin_next answer: after work, or inside a
                                 *  spin. */
             busy_enter,       /**< Passes where that answer turned true after a pass
                                 *  free to block. */
             busy_exit,        /**< Passes where it turned false, this one free to
                                 *  block. */
             dgram_tx_real_kick,      /**< s_msg_exec_dgram_tx_kick executions: the actual
                                        *  queued worker->io kick message running. */
             dgram_tx_real_kick_idle, /**< ...of those, found nothing queued — the kick
                                        *  round-tripped through trunk.stack for nothing,
                                        *  because a real EPOLLOUT reconcile already emptied
                                        *  the lane first. */
             dgram_tx_batch_calls,    /**< s_dgram_tx_lane_drain_batch calls that offered
                                        *  the socket at least one entry. */
             dgram_tx_batch_msgs,     /**< Entries those calls offered: submissions, so an
                                        *  entry EAGAIN-retried across passes recounts. */
             dgram_tx_batch_max,      /**< Most entries one call offered. */
             dgram_tx_lane_sent,      /**< Entries actually resolved (accepted by the kernel)
                                        *  across those calls — the io slow path's real
                                        *  datagram output, each counted once. */
             dgram_tx_gso_writes,     /**< Segmented writes this io thread made: a
                                        *  conn's record batch, the outbox lane, or a
                                        *  completed iocp group. */
             dgram_tx_gso_dgrams,     /**< Datagrams those writes carried. */
             dgram_rx_gro_reads,      /**< Reads that returned a coalesced group, on a
                                        *  conn's socket or a listener's. */
             dgram_rx_gro_dgrams,     /**< Datagrams those groups held, counted by
                                        *  segment size. */
             vnet_rx_tso_reads,       /**< Vnet leg reads that cut into two or
                                        *  more packets. */
             vnet_rx_tso_pkts,        /**< Packets those reads cut into. */
             vnet_rx_drop,            /**< Vnet leg reads the cut refused, each
                                        *  lost whole. */
             tcp_writes,              /**< x_tcp drain writes, one per
                                        *  duct_io_tx_send. */
             tcp_eor_writes,          /**< ...of those, under the socket's write
                                        *  cap, each ending its skb. */
             tcp_lowat_reads,         /**< Pacing-rate reads of sockets following
                                        *  their lowat. */
             tcp_lowat_sets,          /**< Lowat changes those reads applied. */
             tcp_rcvbuf_reads,        /**< Steps of sockets whose receive buffer
                                        *  follows what their conn consumes. */
             tcp_rcvbuf_sets;         /**< Window or buffer changes those steps
                                        *  applied. */
} duct_io_rt_t;

#endif /* DUCT_RUNTIME_STATS */

#ifdef __cplusplus
}
#endif

#endif /* DUCT_RUNTIME_STATS_H */
