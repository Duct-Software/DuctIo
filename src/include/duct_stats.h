/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_stats.h
 *  @brief Engine side of the statistics sections: the list a section joins and the shard index a thread binds.
 *
 *  A section is one allocation holding its table and a shard of counters for each I/O
 *  thread and each worker. The engine keeps its sections in a list that grows by a
 *  compare-and-swap on the head and is freed whole; a reading walks it without a lock.
 *  A thread's shard is the one at the index it binds as its entry begins: an I/O thread
 *  takes its io id, a worker the number of I/O threads plus its worker id.
 */

#ifndef DUCT_STATS_H
#define DUCT_STATS_H

#include "duct.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Add a section made from @p cfg to @p list.
 *  The section copies the table and its names and keeps a zeroed shard, a cache line
 *  apart from the next, for each of @p n_shards threads.
 *  @return the section; nullptr for a table that does not hold, as @ref duct_stats_create
 *          lists them, and for want of memory.
 */
duct_nonnull(1, 3) duct_stats_t *duct_stats_list_add(duct_stats_t *_Atomic *list, unsigned n_shards,
                                                     const duct_stats_cfg_t *cfg);

/** @brief Visit the counters of the sections of @p list, newest section first.
 *  Each value is the sum over the section's shards, stopped at @c UINT64_MAX.
 */
duct_nonnull(1, 2) void duct_stats_list_read(duct_stats_t *_Atomic *list, duct_stats_visit_fn visit,
                                             void *ctx);

/** @brief Free every section of @p list and empty it.
 *  Runs once no thread reads the list or writes a shard of it.
 */
duct_nonnull(1) void duct_stats_list_free(duct_stats_t *_Atomic *list);

/** @brief Bind the calling thread to the shard at @p index of every section. */
void duct_stats_bind(unsigned index);

/** @brief Unbind the calling thread, which then gets no shard. */
void duct_stats_unbind(void);

#ifdef __cplusplus
}
#endif

#endif /* DUCT_STATS_H */
