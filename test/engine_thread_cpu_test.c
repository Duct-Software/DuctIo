/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file engine_thread_cpu_test.c
 *  @brief One io thread and one worker report where they were placed: each an
 *  online cpu or -1, two placed threads never on one cpu, an index past either
 *  role's count -1, and both -1 in a build with pinning off.
 */

#include "duct.h"

#include <stdio.h>

int main(void)
{
    auto e = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1u, .workers = 1u });
    if (!e) {
        fprintf(stderr, "engine_thread_cpu: launch failed\n");
        return 1;
    }
    int io = duct_engine_thread_cpu(e, thread_io, 0u),
        worker = duct_engine_thread_cpu(e, thread_worker, 0u),
        past_io = duct_engine_thread_cpu(e, thread_io, 1u),
        past_worker = duct_engine_thread_cpu(e, thread_worker, 1u);
    duct_engine_destroy(e);
    unsigned online = duct_cpu_online_count();
    bool ok = past_io == -1 && past_worker == -1
           && (io < 0 || (unsigned)io < online)
           && (worker < 0 || (unsigned)worker < online)
           && (io < 0 || worker < 0 || io != worker)
           && (duct_thread_pinning || (io == -1 && worker == -1));
    if (!ok) {
        fprintf(stderr, "engine_thread_cpu: io %d worker %d, past %d %d, %u cpus\n",
                io, worker, past_io, past_worker, online);
        return 1;
    }
    printf("engine_thread_cpu: io on cpu %d, worker on cpu %d\n", io, worker);
    return 0;
}
