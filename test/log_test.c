/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file log_test.c
 *  @brief The timestamped log line of duct_core.h and the local time it reads.
 *
 *  @c sc_line expects a line to open with the local date and time to the
 *  millisecond, as of the moment of the call, then a blank, the formatted message
 *  and one newline. @c sc_burst expects lines written back to back by one thread to come
 *  out whole, in order, none lost, with stamps that go back by no more than two milliseconds
 *  and never leave the span of the writing. @c sc_truncate expects a message past the line cap to be cut
 *  to a line of that cap ending in an ellipsis and a newline, and the next line
 *  to be whole. @c sc_threads expects lines written by several threads to one
 *  stream to come out whole, none lost, repeated or joined to another.
 *  @c sc_localtime expects a plain time to convert and a time past the platform's
 *  range to be refused. @c sc_error expects duct_log_err to write the message, a colon
 *  and the text duct_strerr gives for the code. @c sc_logger expects an initialised
 *  logger to take every line, whole, in place of the stream while it stands, a later one
 *  to take over, a finished one that is no longer installed to leave the installed one
 *  alone, a logger with no write function to be ignored, and the stream to take the lines
 *  again once the last logger is finished. A host that gives no temporary
 *  file skips the stream checks with a note and passes.
 */

#include "duct_core.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define expect(cond, msg) do { if (!(cond)) return msg; } while (0)

/** @brief Threads that write at once. */
static constexpr unsigned log_threads = 4u;
/** @brief Lines each thread writes. */
static constexpr unsigned log_lines   = 200u;
/** @brief Bytes of the longest line the log writes, newline included. */
static constexpr size_t   log_cap     = 1024u;
/** @brief Lines one thread writes back to back. */
static constexpr unsigned log_burst   = 2000u;
/** @brief Milliseconds a stamp may fall behind the one before it: the two clock reads of a resync are not one instant. */
static constexpr long long log_jitter_ms = 2;

/** @brief Whether the host gave a temporary file; a note when it did not. */
static bool g_skipped;

/** @brief Parse the stamp at the head of @p line.
 *  @return the offset of the message, 0 when the line does not open with a stamp or names a time that does not exist.
 */
static size_t stamp_of(const char *line, time_t *when)
{
    int year, month, day, hour, minute, second, milli, used = 0;
    if (sscanf(line, "%4d-%2d-%2d %2d:%2d:%2d.%3d%n", &year, &month, &day, &hour, &minute, &second, &milli,
               &used) != 7 || used != 23 || line[used] != ' ')
        return 0u;
    if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 61)
        return 0u;
    struct tm tm = { .tm_year = year - 1900, .tm_mon = month - 1, .tm_mday = day, .tm_hour = hour,
                     .tm_min = minute, .tm_sec = second, .tm_isdst = -1 };
    *when = mktime(&tm);
    return (size_t)used + 1u;
}

static const char *sc_line(void)
{
    FILE *out = tmpfile();
    if (!out) {
        g_skipped = true;
        return nullptr;
    }
    time_t before = time(nullptr);
    duct_log(out, "port %u of %s", 4433u, "the server");
    duct_log(out, "%s", "");
    time_t after = time(nullptr);
    rewind(out);
    char first[log_cap],
         second[log_cap],
         third[log_cap];
    bool read = fgets(first, sizeof first, out) && fgets(second, sizeof second, out);
    bool more = read && fgets(third, sizeof third, out);
    fclose(out);
    expect(read && !more, "two lines written do not read back as two lines");
    time_t when = 0;
    size_t at = stamp_of(first, &when);
    expect(at, "a line does not open with the stamp");
    expect(when >= before - 1 && when <= after + 1, "the stamp is not the time of the call");
    expect(strcmp(first + at, "port 4433 of the server\n") == 0, "the message is not the one formatted");
    at = stamp_of(second, &when);
    expect(at && strcmp(second + at, "\n") == 0, "an empty message is not a stamp and a newline");
    expect(when >= before - 1 && when <= after + 1, "the stamp of a second line is not the time of the call");
    return nullptr;
}

static const char *sc_burst(void)
{
    FILE *out = tmpfile();
    if (!out) {
        g_skipped = true;
        return nullptr;
    }
    time_t before = time(nullptr);
    for (unsigned n = 0u; n < log_burst; ++n)
        duct_log(out, "n%u", n);
    time_t after = time(nullptr);
    rewind(out);
    char line[log_cap];
    long long last_ms = 0;
    unsigned total = 0u;
    const char *err = nullptr;
    while (!err && fgets(line, sizeof line, out)) {
        time_t when = 0;
        size_t at = stamp_of(line, &when);
        unsigned n = 0u;
        long long ms = (long long)when * 1000 + (line[20] - '0') * 100 + (line[21] - '0') * 10 + (line[22] - '0');
        if (!at || sscanf(line + at, "n%u", &n) != 1 || n != total)
            err = "a line of a burst is not whole or out of order";
        else if (when < before - 1 || when > after + 1)
            err = "the stamp of a line of a burst is not the time of the call";
        else if (ms + log_jitter_ms < last_ms)
            err = "a stamp of a burst goes back";
        else {
            last_ms = ms;
            ++total;
        }
    }
    fclose(out);
    return err ? err : total != log_burst ? "a line of a burst is lost" : nullptr;
}

static const char *sc_truncate(void)
{
    FILE *out = tmpfile();
    if (!out) {
        g_skipped = true;
        return nullptr;
    }
    char big[3000];
    memset(big, 'x', sizeof big - 1u);
    big[sizeof big - 1u] = '\0';
    duct_log(out, "%s", big);
    duct_log(out, "after %d", 7);
    rewind(out);
    char cut[4 * log_cap],
         next[log_cap];
    bool read = fgets(cut, sizeof cut, out) && fgets(next, sizeof next, out);
    fclose(out);
    expect(read, "a long line and a short one do not read back");
    size_t len = strlen(cut);
    expect(len <= log_cap && len > log_cap - 8u, "a long message is not cut to the line cap");
    expect(len >= 4u && memcmp(cut + len - 4u, "...\n", 4u) == 0, "a cut line does not end in an ellipsis");
    expect(strchr(cut, '\n') == cut + len - 1u, "a cut line holds more than one newline");
    time_t when = 0;
    size_t at = stamp_of(next, &when);
    expect(at && strcmp(next + at, "after 7\n") == 0, "the line after a cut one is not whole");
    return nullptr;
}

static void *writer(void *arg)
{
    FILE *out = ((void **)arg)[0];
    unsigned id = (unsigned)(uintptr_t)((void **)arg)[1];
    for (unsigned n = 0u; n < log_lines; ++n)
        duct_log(out, "t%u n%u", id, n);
    return nullptr;
}

static const char *sc_threads(void)
{
    FILE *out = tmpfile();
    if (!out) {
        g_skipped = true;
        return nullptr;
    }
    pthread_t threads[log_threads];
    void *args[log_threads][2];
    unsigned started = 0u;
    for (; started < log_threads; ++started) {
        args[started][0] = out;
        args[started][1] = (void *)(uintptr_t)started;
        if (pthread_create(&threads[started], nullptr, writer, args[started]) != 0)
            break;
    }
    for (unsigned i = 0u; i < started; ++i)
        pthread_join(threads[i], nullptr);
    expect(started == log_threads, "a writer thread does not start");
    rewind(out);
    static bool seen[log_threads][log_lines];
    memset(seen, 0, sizeof seen);
    unsigned total = 0u;
    char line[log_cap];
    const char *err = nullptr;
    time_t lo = time(nullptr) - 60;
    while (!err && fgets(line, sizeof line, out)) {
        time_t when = 0;
        size_t at = stamp_of(line, &when);
        unsigned id, n;
        char end = '\0';
        if (!at || sscanf(line + at, "t%u n%u%c", &id, &n, &end) != 3 || end != '\n' || id >= log_threads
            || n >= log_lines || when < lo || when > lo + 120)
            err = "a line written by a thread is not whole";
        else if (seen[id][n])
            err = "a line written by a thread comes out twice";
        else {
            seen[id][n] = true;
            ++total;
        }
    }
    fclose(out);
    return err ? err : total != log_threads * log_lines ? "a line written by a thread is lost" : nullptr;
}

static const char *sc_localtime(void)
{
    struct tm tm = {};
    expect(duct_localtime(1'700'000'000, &tm), "a plain time does not convert");
    expect(tm.tm_year == 123, "a time of November 2023 is not in the year 2023");
    expect(!duct_localtime(INT64_MAX, &tm), "a time past the platform's range converts");
    return nullptr;
}

static const char *sc_error(void)
{
    FILE *out = tmpfile();
    if (!out) {
        g_skipped = true;
        return nullptr;
    }
    constexpr int code = 2;
    char text[duct_err_text_max];
    duct_strerr(code, text, sizeof text);
    duct_log_err(out, code, "port %u of %s", 4433u, "the server");
    duct_log_err(out, code, "plain");
    rewind(out);
    char line[2][log_cap];
    bool read = fgets(line[0], sizeof line[0], out) && fgets(line[1], sizeof line[1], out);
    fclose(out);
    expect(read, "two lines written with an error do not read back");
    static const char *const head[] = { "port 4433 of the server", "plain" };
    for (size_t i = 0u; i < sizeof head / sizeof head[0]; ++i) {
        time_t when = 0;
        size_t at = stamp_of(line[i], &when);
        char want[log_cap];
        snprintf(want, sizeof want, "%s: %s\n", head[i], text);
        expect(at && strcmp(line[i] + at, want) == 0, "a line with an error is not the message, a colon and the text of the code");
    }
    return nullptr;
}

/** @brief What a test logger took: the lines, their bytes and the last one. */
typedef struct {
    atomic_uint  lines;
    atomic_ullong bytes;
    char         last[log_cap];
} taken_t;

static void taken_write(void *ctx, FILE *, const char *line, size_t len)
{
    auto taken = (taken_t *)ctx;
    duct_atomic_fetch(add, &taken->lines, 1u, relaxed);
    duct_atomic_fetch(add, &taken->bytes, (unsigned long long)len, relaxed);
    memcpy(taken->last, line, len);
    taken->last[len] = '\0';
}

static const char *sc_logger(void)
{
    FILE *out = tmpfile();
    if (!out) {
        g_skipped = true;
        return nullptr;
    }
    static taken_t got, later_got;
    duct_logger_t logger = { .write = taken_write, .ctx = &got },
                  later = { .write = taken_write, .ctx = &later_got },
                  mute = {};
    duct_logger_init(&mute);
    duct_log(out, "no write function");
    duct_logger_init(&logger);
    duct_log(out, "to the logger %d", 1);
    duct_log_err(out, 2, "and again");
    duct_logger_init(&later);
    duct_log(out, "to the later logger");
    duct_logger_fini(&logger);
    duct_log(out, "still the later one");
    duct_logger_fini(&later);
    duct_log(out, "to the stream");
    rewind(out);
    char first[log_cap],
         second[log_cap],
         third[log_cap];
    bool two = fgets(first, sizeof first, out) && fgets(second, sizeof second, out)
            && !fgets(third, sizeof third, out);
    fclose(out);
    expect(duct_atomic_load(&got.lines, relaxed) == 2u, "a logger does not take the lines written while it stands");
    expect(duct_atomic_load(&later_got.lines, relaxed) == 2u, "a logger installed later does not take over, or keeps no line after an earlier logger left");
    char text[duct_err_text_max],
         want[log_cap];
    duct_strerr(2, text, sizeof text);
    snprintf(want, sizeof want, "and again: %s\n", text);
    time_t when = 0;
    size_t at = stamp_of(got.last, &when);
    expect(at && strcmp(got.last + at, want) == 0, "a line in the logger is not the line the stream would have had");
    expect(duct_atomic_load(&got.bytes, relaxed) > strlen(got.last), "a logger is not handed both lines whole");
    expect(two && strstr(first, "no write function") && strstr(second, "to the stream"),
           "a logger with no write function takes the lines, or a line written after the last logger left is not the stream's alone");
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    const char *err = sc_line();
    if (!err)
        err = sc_burst();
    if (!err)
        err = sc_truncate();
    if (!err)
        err = sc_threads();
    if (!err)
        err = sc_localtime();
    if (!err)
        err = sc_error();
    if (!err)
        err = sc_logger();
    if (err) {
        fprintf(stderr, "log: %s\n", err);
        return 1;
    }
    printf("log: OK (stamp, cut, threads, local time, error text, logger)%s\n", g_skipped ? "; stream checks skipped, no temporary file" : "");
    return 0;
}
