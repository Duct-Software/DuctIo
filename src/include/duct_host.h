/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_host.h
 *  @brief io/worker → host egress relay.
 *
 *  "Host" is the embedding application: code running on any thread
 *  the engine does not own — neither an io thread, nor a worker.
 */

#ifndef DUCT_HOST_H
#define DUCT_HOST_H

#include "duct_types.h"
#include "duct_vmq.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef union duct_session_handle duct_session_handle_t;

/** @brief Copy @p cfg into the host-bridge singleton.
 *
 *  Called once from @ref duct_engine_launch.
 */
duct_nonnull(1) void duct_host_init(const duct_host_cfg_t *cfg);

/** @brief Stop egress drains from being scheduled, and wait out any already
 *  in flight.
 *
 *  A scheduled drain reads lane memory, so it must complete before lanes are
 *  freed. Runs after worker join (no producers remain) and before lanes are
 *  freed. A callback already queued still runs and delivers what it holds.
 *
 *  Bounded by @p timeout_ms, because a host that tore its queue down first
 *  leaves a drain that never runs: on expiry the lane is abandoned through
 *  @ref duct_worker_egress_abandon, its memory left allocated while a
 *  pending callback still points at it.
 */
void duct_host_egress_quiesce(unsigned n_workers, uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* DUCT_HOST_H */
