/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_stats.c
 *  @brief Statistics sections: a protocol's table of counters, one shard of them for each engine thread, and the reading that sums the shards.
 *
 *  A section is one allocation holding this struct, a copy of the table and its names;
 *  its shards sit in a second one. A thread writes only the shard at its bound index, so
 *  a shard needs no synchronisation, and a reading adds the shards with relaxed loads
 *  and takes no lock.
 *  - A section joins the list by a release compare-and-swap of the head and stays until
 *    the list is freed whole.
 *  - A shard starts on a cache line and is a whole number of lines long, so two threads
 *    never write one line.
 */

#include "duct_stats.h"

#include <limits.h>
#include <string.h>

/** Shard index of a thread that bound none. */
static constexpr unsigned stats_unbound = UINT_MAX;

/** Shard index of the calling thread. */
static thread_local unsigned s_shard = stats_unbound;

/** @brief One statistics section. */
struct duct_stats {
    duct_stats_t *_Atomic    next;     /**< Section that joined the list before this one. */
    const char              *name;     /**< Section name, stored behind the fields. */
    const duct_stat_field_t *fields;   /**< Copy of the table, stored behind this struct. */
    uint8_t                 *shards;   /**< The shards, @c n_shards of @c stride bytes, in an allocation of their own. */
    size_t                   stride;   /**< Bytes from one shard to the next: the shard size rounded up to a cache line. */
    unsigned                 n_shards, /**< Shards, one for each I/O thread and each worker. */
                             n_fields; /**< Rows in @c fields. */
};

void duct_stats_bind(unsigned index)
{
    s_shard = index;
}

void duct_stats_unbind(void)
{
    s_shard = stats_unbound;
}

void *duct_stats_shard(duct_stats_t *st)
{
    return s_shard < st->n_shards ? st->shards + (size_t)s_shard * st->stride : nullptr;
}

/** @brief Copy @p text, its NUL included, to @p *at and move @p *at past the copy.
 *  @return the copy.
 */
static const char *s_text_copy(char **at, const char *text)
{
    size_t n = strlen(text) + 1u;
    const char *copy = memcpy(*at, text, n);
    *at += n;
    return copy;
}

/** @brief Bytes of name text a section made from @p cfg stores, its own name and every field's, NULs included.
 *  @return that size; 0 for a table with no name or an empty one, no fields, a shard of no bytes, a
 *          field with no name or an empty one, and one off an 8-byte boundary or too near the
 *          shard's end for a counter.
 */
static size_t s_names_size(const duct_stats_cfg_t *cfg)
{
    duct_do_if(!cfg->name || !cfg->name[0] || !cfg->fields || cfg->n_fields == 0u || cfg->shard_size == 0u,
               return 0u);
    size_t size = strlen(cfg->name) + 1u;
    for (unsigned i = 0u; i < cfg->n_fields; ++i) {
        auto field = &cfg->fields[i];
        duct_do_if(!field->name || !field->name[0] || field->offset % sizeof(uint64_t) != 0u
                       || field->offset + sizeof(uint64_t) > cfg->shard_size,
                   return 0u);
        size += strlen(field->name) + 1u;
    }
    return size;
}

duct_stats_t *duct_stats_list_add(duct_stats_t *_Atomic *list, unsigned n_shards,
                                  const duct_stats_cfg_t *cfg)
{
    size_t text = s_names_size(cfg);
    if (!text)
        return nullptr;
    size_t fields_size = (size_t)cfg->n_fields * sizeof(duct_stat_field_t),
           stride = duct_align_up(cfg->shard_size, duct_cacheline_size);
    duct_auto_del auto st = (duct_stats_t *)duct_at(duct_new(uint8_t, sizeof(duct_stats_t) + fields_size + text,
                                                             alignof(duct_stats_t)));
    duct_do_if(!st, return nullptr);
    duct_auto_del auto shards = duct_at(duct_new(uint8_t, (size_t)n_shards * stride, duct_cacheline_size));
    duct_do_if(!shards, return nullptr);
    auto fields = (duct_stat_field_t *)(st + 1);
    char *at = (char *)fields + fields_size;
    st->name = s_text_copy(&at, cfg->name);
    for (unsigned i = 0u; i < cfg->n_fields; ++i)
        fields[i] = (duct_stat_field_t){ .name = s_text_copy(&at, cfg->fields[i].name),
                                         .offset = cfg->fields[i].offset };
    st->fields = fields;
    st->shards = duct_move(shards);
    st->stride = stride;
    st->n_shards = n_shards;
    st->n_fields = cfg->n_fields;
    /* The release on the head lets a reading that loads it with acquire see the section whole. */
    auto head = duct_atomic_load(list, relaxed);
    do
        duct_atomic_store(&st->next, head, relaxed);
    while (!duct_atomic_cas(weak, list, &head, st, release, relaxed));
    return duct_move(st);
}

void duct_stats_list_read(duct_stats_t *_Atomic *list, duct_stats_visit_fn visit, void *ctx)
{
    for (auto st = duct_atomic_load(list, acquire); st; st = duct_atomic_load(&st->next, acquire))
        for (unsigned i = 0u; i < st->n_fields; ++i) {
            uint64_t sum = 0u;
            for (unsigned t = 0u; t < st->n_shards; ++t) {
                auto cell = (const uint64_t _Atomic *)(st->shards + (size_t)t * st->stride
                                                       + st->fields[i].offset);
                uint64_t value = duct_atomic_load(cell, relaxed);
                sum = value > UINT64_MAX - sum ? UINT64_MAX : sum + value;
            }
            visit(ctx, st->name, st->fields[i].name, sum);
        }
}

void duct_stats_list_free(duct_stats_t *_Atomic *list)
{
    auto st = duct_atomic_exchange(list, nullptr, acquire);
    while (st) {
        auto next = duct_atomic_load(&st->next, relaxed);
        duct_del(st->shards);
        duct_del(st);
        st = next;
    }
}
