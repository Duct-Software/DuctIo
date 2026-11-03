/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_tx_pool.h
 *  @brief Per-worker TX staging pool -- a stable-address buffer for an
 *  outbound payload that outlives one callback turn.
 *
 *  Every response's payload normally either points at author-owned memory
 *  the runtime copies (@c fl_send_copy) or is already immutable/owned
 *  (@c fl_send_static / @c fl_send_owned). A pool region is a third option
 *  for the case those two don't cover well: bytes an author builds once and
 *  emits from without re-copying into place — the same payload fanned out to
 *  several conns on one session, or built in one worker pass and emitted
 *  again in a later one under @c fl_send_pool_keep. @c x_udp_shared recognizes
 *  pool pointers and sends them by reference; other transports copy into their
 *  staging rings.
 */

#ifndef DUCT_TX_POOL_H
#define DUCT_TX_POOL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Reserve @p size bytes of stable-address TX staging on the
 *  calling worker's own pool. Worker-thread-only, like @ref
 *  duct_stream_emit_response.
 *
 *  The bytes are the author's own to write for the worker pass that acquired
 *  them; the runtime releases the region at that pass's end unless a response
 *  carrying it declared @c fl_send_pool_keep, which holds it one pass longer.
 *  A send still in flight keeps the bytes alive either way. Referencing it from a
 *  @c duct_response_t::payload on a conn other than the acquiring worker's
 *  own @c x_udp_shared conns still works -- that path copies it like any
 *  other author buffer -- but the pointer itself must never cross to
 *  another worker thread.
 *
 *  @param size  Payload bytes needed.
 *  @return A pointer good for @p size bytes; @c nullptr on pool pressure
 *         -- yield and retry on a later worker turn, not a hard failure.
 *         A call off a worker thread answers @c nullptr too, and always will.
 */
void *duct_tx_pool_acquire(size_t size);

#ifdef __cplusplus
}
#endif

#endif /* DUCT_TX_POOL_H */
