/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_msg.h
 *  @brief Universal message root, constructors, Treiber MPSC stack helpers.
 *
 *  Owns @c duct_msg_t root for all message kinds (stack ctrl, WFQ payload,
 *  deferred copy), a callback type @c duct_exec_fn, shared with the timer
 *  subsystem, two decl macros: @ref duct_msg_decl (WFQ
 *  payloads, no chain) and @ref duct_msg_chain_decl for stack/defer nodes
 *  with intrusive @c next.
 */

#ifndef DUCT_MSG_H
#define DUCT_MSG_H

#include "duct_core.h"
#include "duct_exec.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Universal message root — the executor @c exec_fn and its @c arg. */
typedef struct duct_msg {
    duct_exec_fn exec_fn;
    void        *arg;
} duct_msg_t;

/** @brief Declare a non-chainable message. */
#define duct_msg_decl(name, ...) \
    typedef struct name { duct_msg_t msg; __VA_ARGS__; } name

/** @brief Declare a chainable message.
 *
 *  Injects @c duct_msg_t *next as the first member after the base and emits
 *  @c static_assert so @ref duct_msg_next's fixed offset holds by construction.
 */
#define duct_msg_chain_decl(name, ...)                          \
    typedef struct name {                                       \
        duct_msg_t msg, *next;                                  \
        __VA_ARGS__;                                            \
    } name;                                                     \
    static_assert(offsetof(name, next) == sizeof(duct_msg_t),   \
        #name ": next must sit at sizeof(duct_msg_t)")

/** @brief Allocate + fill.
 *
 *  Answers a @p T with @c exec_fn and @c arg set, or @c nullptr when @p _exec_fn is null or the
 *  allocation fails. @c msg must be @p T's first member; the build stops otherwise.
 *  @p ... holds optional trailing FAM byte count.
 */
#define duct_msg_new(T, _exec_fn, _arg, ...)                                    \
    ((T *)({                                                                    \
        static_assert(sizeof(T) >= sizeof(duct_msg_t),                          \
            "duct_msg_new: type too small");                                    \
        static_assert(offsetof(T, msg) == 0,                                    \
            "duct_msg_new: msg must be the first member");                      \
        static_assert(duct_is_types_compatible(_exec_fn, (duct_exec_fn)0)       \
                   || duct_is_types_compatible((_exec_fn)+0, (duct_exec_fn)0),  \
            "duct_msg_new: function must be duct_exec_fn");                     \
        T *_out = nullptr;                                                      \
        duct_exec_fn _fn = (_exec_fn);                                          \
        if (_fn) {                                                              \
            size_t _size = sizeof(T);                                           \
            __VA_OPT__(if (duct_ckd_add(&_size, _size, (size_t)(__VA_ARGS__)))  \
                       _size = 0u;)                                             \
            auto _base = (duct_msg_t *)duct_at(duct_new(char, _size, alignof(T))); \
            if (_base) {                                                        \
                _base->exec_fn = _fn;                                           \
                _base->arg = (void *)(_arg);                                    \
                _out = (T *)_base;                                              \
            }                                                                   \
        }                                                                       \
        _out;                                                                   \
    }))

/** @brief Release message and return @c exec_done. */
static inline duct_exec_rc_t duct_msg_done(void *self)
{
    duct_del(self);
    return exec_done;
}

/** @brief Reach @c next on a chainable message at fixed offset.
 *
 *  Only valid on nodes declared with @ref duct_msg_chain_decl which places
 *  @c next at @c sizeof(duct_msg_t) offset.
 */
#define duct_msg_next(m) (*(duct_msg_t **)((char *)(m) + sizeof(duct_msg_t)))

/** @brief O(1) message queue. */
typedef struct duct_msg_queue {
    duct_msg_t *head,
               *tail;
} duct_msg_queue_t;

/** @brief Append one chainable message at the queue tail. */
duct_nonnull(1, 2) static inline void
duct_msg_queue_push(duct_msg_queue_t *q, duct_msg_t *m)
{
    duct_msg_next(m) = nullptr;
    if (q->tail)
        duct_msg_next(q->tail) = m;
    else
        q->head = m;
    q->tail = m;
}

/** @brief Treiber MPSC stack. */
typedef struct {
    duct_msg_t * _Atomic top;
} duct_msg_stack_t;

/** @brief Push one chainable message in a CAS loop. */
duct_nonnull(1, 2) static inline void
duct_msg_stack_push(duct_msg_stack_t *stack, duct_msg_t *msg)
{
    auto old = duct_atomic_load(&stack->top, relaxed);
    do {
        duct_msg_next(msg) = old;
    } while (!duct_atomic_cas(weak, &stack->top, &old, msg, release, acquire));
}

/** @brief Detach stack atomically.
 *
 *  @return Full detached chain in LIFO order.
 */
duct_nonnull(1) static inline duct_msg_t *
duct_msg_stack_detach(duct_msg_stack_t *stack)
{
    return duct_atomic_exchange(&stack->top, nullptr, acquire);
}

/** @brief Reverse detached chain from LIFO to FIFO order. */
static inline duct_msg_t *duct_msg_reverse(duct_msg_t *head)
{
    duct_msg_t *prev = nullptr;
    while (head) {
        auto next = duct_msg_next(head);
        duct_msg_next(head) = prev;
        prev = head;
        head = next;
    }
    return prev;
}

#ifdef __cplusplus
}
#endif

#endif /* DUCT_MSG_H */
