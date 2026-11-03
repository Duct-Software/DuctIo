/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file engine_report_test.c
 *  @brief duct_engine_stats_print and duct_process_cpu.
 *
 *  @c sc_print launches an engine, stops it and prints its counters to a file. A
 *  call with a null engine, file or tag writes nothing. Every line leads with the
 *  log stamp, then the tag, and the first is the pool's refusals. A build with counters compiled out
 *  has one line more, saying so; any other has the six the header names, seven in
 *  all. @c sc_cpu spins for 200 ms and expects the process's processor time to
 *  have grown, by under two seconds.
 */

#include "duct.h"
#include "duct_ticks.h"

#include <stdio.h>
#include <string.h>

static constexpr char report_path[] = "engine_report_test.out";
/** @brief Bytes of the stamp duct_log puts ahead of a line, its blank included. */
static constexpr size_t stamp_len = 24u;

/** @brief Print a stopped engine's counters to a file and read the lines back.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_print(void)
{
    auto e = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1u, .workers = 1u });
    if (!e)
        return "engine launch failed";
    duct_rt_stats_t counters = {};
    bool counted = duct_engine_stats(e, &counters);
    auto out = fopen(report_path, "w+");
    if (!out) {
        duct_engine_destroy(e);
        return "report file create failed";
    }
    duct_engine_stats_print(nullptr, out, "tag");
    duct_engine_stats_print(e, nullptr, "tag");
    duct_engine_stats_print(e, out, nullptr);
    long nothing = ftell(out);
    duct_engine_stop(e);
    duct_engine_stats_print(e, out, "tag");
    duct_engine_destroy(e);
    fflush(out);
    rewind(out);
    char text[8192] = {};
    size_t got = fread(text, 1u, sizeof text - 1u, out);
    text[got] = '\0';
    fclose(out);
    duct_discard remove(report_path);
    if (nothing != 0L)
        return "a call with a null argument wrote something";
    if (got == 0u)
        return "the report is empty";

    unsigned lines = 0u;
    for (char *line = text; *line;) {
        if (strlen(line) < stamp_len + 5u || line[stamp_len - 1u] != ' ' || strncmp(line + stamp_len, "tag: ", 5u) != 0)
            return "a line does not lead with the stamp and the tag";
        ++lines;
        char *end = strchr(line, '\n');
        line = end ? end + 1 : line + strlen(line);
    }
    if (!strstr(text, "tag: conn pool refused="))
        return "the pool line is missing";
    if (!counted)
        return lines == 2u && strstr(text, "tag: engine stats compiled out\n")
             ? nullptr : "a build without counters did not say so in one line";
    static const char *const leaders[] = {
        "tag: fastpath ", "tag: offload ", "tag: train flush ",
        "tag: tcp ", "tag: drops ", "tag: backpressure ",
    };
    for (unsigned i = 0u; i < sizeof leaders / sizeof leaders[0]; ++i)
        if (!strstr(text, leaders[i]))
            return "a line of the counters is missing";
    return lines == 7u ? nullptr : "the report is not seven lines";
}

/** @brief Spin for 200 ms and read the process's processor time either side.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_cpu(void)
{
    duct_cpu_time_t before = duct_process_cpu();
    uint64_t start = duct_ticks_mono_ns();
    volatile uint64_t spin = 0u;
    do
        for (unsigned i = 0u; i < 100000u; ++i)
            spin += i;
    while (duct_ticks_mono_ns() - start < 200'000'000u);
    duct_cpu_time_t after = duct_process_cpu();
    if (after.user_ns < before.user_ns || after.kernel_ns < before.kernel_ns)
        return "a reading went back";
    uint64_t spent = (after.user_ns - before.user_ns) + (after.kernel_ns - before.kernel_ns);
    if (spent == 0u)
        return "200 ms of spinning cost no cpu";
    return spent < 2'000'000'000u ? nullptr : "200 ms of spinning cost over two seconds of cpu";
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    const char *err = sc_print();
    if (!err)
        err = sc_cpu();
    if (err) {
        fprintf(stderr, "engine_report: %s\n", err);
        return 1;
    }
    printf("engine_report: OK (the counters' report, the process's cpu)\n");
    return 0;
}
