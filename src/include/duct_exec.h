/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_exec.h
 *  @brief Universal exec callback + result code.
 *
 *  Leaf primitive shared by the message system and the timer subsystem.
 *  The callback takes @c void * so it can carry
 *  either a @c duct_msg_t *self (msg dispatch) or an opaque ctx (timer fire);
 *  each exec casts to the type it expects.
 */

#ifndef DUCT_EXEC_H
#define DUCT_EXEC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Exec return code. */
typedef enum duct_exec_rc : uint8_t {
    exec_done,   /**< Consumed. */
    exec_defer,  /**< Retry later. */
    exec_drop,   /**< Discard. */
} duct_exec_rc_t;

static_assert(sizeof(duct_exec_rc_t) == sizeof(uint8_t),
    "duct_exec_rc_t width must be 1 byte");

/** @brief Universal exec callback.
 *
 *  @p self is @c void *: a @c duct_msg_t * for msg dispatch
 *  or an opaque ctx, e.g. for timer fire.
 */
typedef duct_exec_rc_t (*duct_exec_fn)(void *self);

#ifdef __cplusplus
}
#endif

#endif /* DUCT_EXEC_H */
