/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_log.c
 *  @brief Timestamped log line of the engine and of the programs built on it.
 *
 *  A line opens with the local time to the millisecond. Each thread keeps the date, hour
 *  and minute of the minute it last wrote as text and writes the seconds and milliseconds
 *  as digits from its wall clock, so a line inside that minute costs no calendar conversion.
 *
 *  A finished line goes to the process's logger when one is installed, to the stream otherwise.
 *  The logger is one atomic pointer read once per line, so a line meets the old logger or the new.
 */

#include "duct_core.h"
#include "duct_ticks.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/** Stamp head of a second the platform cannot convert, and the template the head's fields are written over. */
static constexpr char log_blank_head[] = "0000-00-00 00:00:";

/** @brief Sizes of the line buffer and of the stamp, bytes. */
enum : size_t {
    log_line_max  = 1024u,                      /**< Buffer a line is built in. */
    log_head_len  = sizeof log_blank_head - 1u, /**< Stamp head: date, hour and minute, ending in a colon. */
    log_stamp_len = log_head_len + 7u,          /**< Whole stamp: the head, two digits of seconds, a point, three of milliseconds and a blank. */
};

/** @brief Time constants of the stamp. */
enum : uint64_t {
    log_second_ns = 1'000'000'000u, /**< Nanoseconds in a second. */
    log_milli_ns  = 1'000'000u,     /**< Nanoseconds in a millisecond. */
    log_resync_ns = log_second_ns,  /**< Longest time a step of the system clock stays out of the stamps. */
    log_minute_s  = 60u,            /**< Seconds one stamp head serves. */
};

/** @brief The installed logger, nullptr for none. */
static _Atomic(const duct_logger_t *) s_logger;

/** @brief Stamp state of one thread. */
typedef struct {
    duct_tickwall_t wall;  /**< Wall clock the seconds and milliseconds are read from. */
    int64_t         start; /**< Epoch second the head's minute began at, 0 before the first line. */
    char            head[sizeof log_blank_head]; /**< Local date, hour and minute of that minute as YYYY-MM-DD HH:MM:. */
} log_stamp_t;

/** @brief Write @p value at @p at as @p width decimal digits, zero padded.
 *  A value wider than @p width keeps its low digits.
 */
static void s_digits(char *at, unsigned value, unsigned width)
{
    while (width--) {
        at[width] = (char)('0' + value % 10u);
        value /= 10u;
    }
}

/** @brief Rebuild @p stamp's head and start for the local minute that holds @p sec.
 *  A second the platform cannot convert leaves the blank head and a minute that begins at @p sec.
 */
static void s_minute(log_stamp_t *stamp, int64_t sec)
{
    struct tm local = {};
    bool known = duct_localtime(sec, &local);
    stamp->start = known ? sec - local.tm_sec : sec;
    memcpy(stamp->head, log_blank_head, sizeof stamp->head);
    if (!known)
        return;
    s_digits(stamp->head, (unsigned)(local.tm_year + 1900), 4u);
    s_digits(stamp->head + 5, (unsigned)(local.tm_mon + 1), 2u);
    s_digits(stamp->head + 8, (unsigned)local.tm_mday, 2u);
    s_digits(stamp->head + 11, (unsigned)local.tm_hour, 2u);
    s_digits(stamp->head + 14, (unsigned)local.tm_min, 2u);
}

/* The head is rebuilt when the clock leaves its minute. The unsigned difference sends a clock
 * stepped back to the rebuild as well. */
void duct_log(FILE *out, const char *fmt, ...)
{
    static thread_local log_stamp_t stamp;
    char line[log_line_max];
    uint64_t wall = duct_tickwall_read_ns(&stamp.wall, log_resync_ns);
    int64_t sec = (int64_t)(wall / log_second_ns);
    if ((uint64_t)(sec - stamp.start) >= log_minute_s)
        s_minute(&stamp, sec);
    memcpy(line, stamp.head, log_head_len);
    s_digits(line + log_head_len, (unsigned)(sec - stamp.start), 2u);
    line[log_head_len + 2u] = '.';
    s_digits(line + log_head_len + 3u, (unsigned)(wall % log_second_ns / log_milli_ns), 3u);
    line[log_stamp_len - 1u] = ' ';
    size_t room = sizeof line - log_stamp_len - 1u;
    va_list args;
    va_start(args, fmt);
    int wanted = vsnprintf(line + log_stamp_len, room, fmt, args);
    va_end(args);
    size_t len = wanted < 0 ? 0u : (size_t)wanted < room ? (size_t)wanted : room - 1u;
    if (wanted >= 0 && (size_t)wanted >= room)
        memcpy(line + log_stamp_len + len - 3u, "...", 3u);
    line[log_stamp_len + len] = '\n';
    auto logger = duct_atomic_load(&s_logger, acquire);
    if (logger)
        logger->write(logger->ctx, out, line, log_stamp_len + len + 1u);
    else
        duct_discard fwrite(line, 1u, log_stamp_len + len + 1u, out);
}

void duct_logger_init(const duct_logger_t *logger)
{
    if (logger->write)
        duct_atomic_store(&s_logger, logger, release);
}

void duct_logger_fini(const duct_logger_t *logger)
{
    const duct_logger_t *none = nullptr;
    duct_discard duct_atomic_cas(strong, &s_logger, &logger, none, acq_rel, relaxed);
}
