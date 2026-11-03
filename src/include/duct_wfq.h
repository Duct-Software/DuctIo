/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_wfq.h
 *  @brief Weighted Fair Queue - a sharded MPSC queue with priority lanes over per-worker lanes.
 *
 *  Lane layout: [Pri1 × n_workers × n_io][Pri2 × n_workers × n_io][...][PriN × n_workers × n_io].
 */

#ifndef DUCT_WFQ_H
#define DUCT_WFQ_H

#include "duct_core.h"
#include "duct_vmq.h"
#include "duct_wfq_msg.h"
#include "duct_timer.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DUCT_WFQ_CAP_HI
    #define DUCT_WFQ_CAP_HI kbytes(64)
#endif

#ifndef DUCT_WFQ_CAP_NORM
    #define DUCT_WFQ_CAP_NORM kbytes(256)
#endif

#ifndef DUCT_WFQ_CAP_LO
    #define DUCT_WFQ_CAP_LO kbytes(64)
#endif

/** @brief Create a WFQ with per-priority capacities.
 *
 *  @param n_workers Number of worker threads.
 *  @param n_io Number of I/O threads.
 *  @param ... Per-priority capacities in descending order, each fans-out
 *              to @c n_workers × @c n_io lanes, so every I/O thread gets
 *              its own group of per-priority lanes.
 */
#define duct_wfq_new(n_workers, n_io, ...)                              \
    ({                                                                  \
        unsigned _w = (n_workers), _n = (n_io);                         \
        duct_vmq_mpsc_t *_wfq = nullptr;                                \
        if (_w && _n) {                                                 \
            size_t _per_pri[] = { __VA_ARGS__ };                        \
            unsigned _n_pri = sizeof(_per_pri) / sizeof(_per_pri[0]),   \
                     _pp = _w * _n,                                     \
                     _lanes = _n_pri * _pp;                             \
            size_t _caps[_lanes];                                       \
            for (unsigned _p = 0u; _p < _n_pri; ++_p)                   \
                for (unsigned _i = 0u; _i < _pp; ++_i)                  \
                    _caps[_p * _pp + _i] = _per_pri[_p];                \
            _wfq = duct_vmq_mpsc_new(_lanes, _caps);                    \
        }                                                               \
        _wfq;                                                           \
    })

/** @brief Generic post, dispatched by task type.
 *
 *  @param wfq  WFQ handle.
 *  @param lane Lane index.
 *  @param pri  Priority.
 *  @param task Task to post.
 *  @param ...  Optional trailing FAM-tailed task size, bytes.
 *
 *  @return @c vmq_push_ok on success.
 */
#define duct_wfq_post(wfq, lane, pri, task, ...)                        \
    ({                                                                  \
        auto _wfq = (wfq);                                              \
        auto _task = (task);                                            \
        unsigned _lane = (lane);                                        \
        size_t _size = sizeof(*_task);                                  \
        __VA_OPT__(_size = (size_t)(__VA_ARGS__);)                      \
        duct_vmq_push_rc_t _rc = vmq_push_full;                         \
        if (_lane < _wfq->n_lanes) {                                    \
            auto _ln = duct_mpsc_lane(_wfq, _lane);                     \
            _rc = duct_vmq_push(                                        \
                &_ln,                                                   \
                _Generic((_task),                                       \
                          duct_msg_frame_batch_t *: msg_frame_batch,    \
                    const duct_msg_frame_batch_t *: msg_frame_batch,    \
                               duct_msg_callback *: msg_callback,       \
                         const duct_msg_callback *: msg_callback        \
                ),                                                      \
                (pri), _task, _size                                     \
            );                                                          \
            if (_rc == vmq_push_ok)                                     \
                duct_vmq_notify(_ln.ctrl);                              \
        }                                                               \
        _rc;                                                            \
    })

/** @brief Post async timer cancellation on owner processor WFQ lane. */
duct_nonnull(1, 3) static inline duct_vmq_push_rc_t
duct_wfq_post_timer_cancel(duct_vmq_mpsc_t *wfq,
                           unsigned lane,
                           duct_timers_t *timers,
                           duct_timer_handle_t handle)
{
    duct_do_if(handle == timer_handle_null, return vmq_push_err);
    auto ctx = duct_new(duct_timer_cancel_ctx_t); /* freed by duct_timer_cancel_fn */
    duct_do_if(!ctx, return vmq_push_err);
    ctx->tl = timers;
    ctx->h = handle;
    duct_msg_callback task = { .msg = { .exec_fn = duct_timer_cancel_fn, .arg = ctx } };
    auto rc = duct_wfq_post(wfq, lane, wfq_pri_hi, &task);
    if (rc != vmq_push_ok)
        duct_del(ctx);
    return rc;
}

#ifdef __cplusplus
}
#endif

#endif /* DUCT_WFQ_H */
