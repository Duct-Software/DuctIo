/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file kqueue_listener_register_test.c
 *  @brief A rejected listener EV_ADD must return false to the bind caller.
 */

#include "duct_events.h"

#include <limits.h>
#include <stdio.h>

int main(void)
{
    auto env = duct_events_init();
    if (!env)
        return 1;

    int tag = 0;
    bool registered = duct_events_watch(env, INT_MAX, io_tag_listener, &tag, x_tcp);
    duct_events_fini(env);
    if (registered) {
        fprintf(stderr, "kqueue listener: rejected EV_ADD returned success\n");
        return 1;
    }
    return 0;
}
