/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_proto.c
 *  @brief Protocol handle construction.
 *
 *  @c duct_proto_create copies the author-supplied @ref duct_proto_cfg_t by
 *  value into a heap handle; the cfg's borrowed pointers (name, wire,
 *  user_ctx, the callbacks) stay valid for the protocol's lifetime as
 *  documented on the public protocol surface. The runtime borrows the resulting
 *  proto until @c duct_engine_destroy; the caller releases it afterward via
 *  @c duct_proto_destroy. @c duct_proto_create_owning stores a wire its caller
 *  built as @c owned_wire, which @c duct_proto_destroy releases;
 *  @c duct_proto_create_tcp / @c _udp build a wire of their own and hand it to it.
 */

#include "duct_protocol.h"

#include "duct_core.h"
#include "duct_wire.h"
#include "duct_worker.h"

/** @brief Bytes to reserve for the next callback transaction on one leg,
 *  scaled by @p reserve response slots.
 *
 *  One slot normally, two when the callback can also trigger a server push,
 *  @ref duct_admit_slots. Returns 0 when @p cfg has no explicit
 *  @c max_response, meaning admission falls back to a coarse TX-backpressure
 *  check.
 *
 *  Every slot also adds @c duct_dgram_record_hdr_size, the length-prefix
 *  header the worker stages ahead of the payload on a datagram leg; on a
 *  stream leg that header is never actually staged, so the extra bytes
 *  reserved for it there just go unused. Returns @c SIZE_MAX on size
 *  overflow, a config error.
 *
 *  Computed once at construction: @c duct_proto_create copies @p cfg, and
 *  neither @c wire nor @c max_response changes after that.
 */
static size_t s_compute_admit_need(const duct_proto_cfg_t *cfg, unsigned reserve)
{
    size_t eff_max = cfg->max_response;
    if (eff_max == 0u)
        return 0u;
    size_t per_slot = eff_max;
    if (cfg->wire && cfg->wire->tx_bound) {
        per_slot = cfg->wire->tx_bound(cfg->wire, eff_max);
    } else if (cfg->wire && cfg->wire->header_size != 0u
              && duct_ckd_add(&per_slot, eff_max, cfg->wire->header_size)) {
        return SIZE_MAX;
    }
    /* per_slot may already be SIZE_MAX (tx_bound's own overflow sentinel);
     * this add always runs, so it still catches that case below. */
    if (duct_ckd_add(&per_slot, per_slot, duct_dgram_record_hdr_size))
        return SIZE_MAX;
    size_t need = 0u;
    if (duct_ckd_mul(&need, per_slot, reserve))
        return SIZE_MAX;
    return need;
}

duct_proto_t *duct_proto_create(const duct_proto_cfg_t *cfg)
{
    duct_do_if(!cfg, return nullptr);
    duct_do_if(!cfg->on_frame, return nullptr);
    /* preparse without a mode is a config error; mode without preparse is ignored. */
    duct_do_if(cfg->preparse && cfg->preparse_mode == resolve_none, return nullptr);
    duct_do_if(cfg->preparse && cfg->preparse_mode >= resolve_mode_count, return nullptr);
    /* Handler requires multiplexed flag. */
    if (cfg->handler_kind != handler_none) {
        duct_do_if(cfg->handler_kind >= handler_count, return nullptr);
        duct_do_if(!duct_has(cfg->flags, fl_proto_multiplexed), return nullptr);
        duct_do_if(cfg->handler_kind == handler_async && !cfg->handler_async, return nullptr);
        duct_do_if(cfg->handler_kind == handler_coro && !cfg->handler_coro, return nullptr);
    }
    /* Raw response-producing protocols must declare a finite per-response cap. */
    duct_do_if(!cfg->wire && cfg->max_response == 0u, return nullptr);
    auto p = duct_new(duct_proto_t);
    duct_do_if(!p, return nullptr);
    p->cfg = *cfg;
    p->owned_wire = nullptr;
    p->admit_need[0] = s_compute_admit_need(&p->cfg, admit_reserve_response);
    p->admit_need[1] = s_compute_admit_need(&p->cfg, admit_reserve_with_push);
    return p;
}

duct_proto_t *duct_proto_create_owning(duct_proto_cfg_t *cfg, duct_wire_t *wire)
{
    duct_do_if(!wire, return nullptr);
    duct_do_if(!cfg,
        duct_wire_destroy(wire);
        return nullptr);
    cfg->wire = wire;
    auto p = duct_proto_create(cfg);
    if (p)
        p->owned_wire = wire;
    else
        duct_wire_destroy(wire);
    return p;
}

void duct_proto_destroy(duct_proto_t *proto)
{
    if (!proto)
        return;
    if (proto->owned_wire)
        duct_wire_destroy(proto->owned_wire);
    duct_del(proto);
}

duct_proto_t *duct_proto_create_tcp(const char *name, duct_frame_fn on_frame)
{
    duct_do_if(!on_frame, return nullptr);
    auto wire = duct_wire_create_length_prefix(0u);
    duct_do_if(!wire, return nullptr);
    return duct_proto_create_owning(&(duct_proto_cfg_t){
        .name = name,
        .on_frame = on_frame,
    }, wire);
}

duct_proto_t *duct_proto_create_udp(const char *name, duct_frame_fn on_dgram)
{
    duct_do_if(!on_dgram, return nullptr);
    auto wire = duct_wire_create_dgram_batch(0u, false);
    duct_do_if(!wire, return nullptr);
    return duct_proto_create_owning(&(duct_proto_cfg_t){
        .name = name,
        .on_frame = on_dgram,
        .max_response = 65535u,
    }, wire);
}
