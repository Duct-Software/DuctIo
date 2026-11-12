/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */
/* AI-generated test code. */

/** @file logfile_test.c
 *  @brief The file sink and the platform resolver of the default directory, engine side.
 *
 *  @c sc_append_reopen expects a reopen to append, the two lines reading back whole and
 *  stamped. @c sc_threads expects the lines of several writers whole, each once.
 *  @c sc_echo expects the one line in the file and on the stream named at the call byte for
 *  byte the same. @c sc_crop expects a long message cut to a 1023-byte line ending in an
 *  ellipsis. @c sc_selfremove expects the fatal line on the call's stream, one diag and the
 *  file left open; @c sc_selfremove_threads expects one removal, a diag per thread in flight
 *  and the lines after it raw on the call's stream. @c sc_fini_order expects the lines after
 *  the fini on the raw stream and a second fini to pass. The open refusals expect the false
 *  return to leave @c file null. @c sc_append_two_procs expects the lines of two processes
 *  whole. The resolver scenarios hold each platform's env ladder, the mkdir refusal, the
 *  host's cap and the end-to-end run out of a resolved directory.
 */

#include "duct_file.h"
#include "duct_logfile.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <sys/stat.h>
#include <windows.h>
#define s_getcwd(buf, cap)   _getcwd(buf, (int)(cap))
#define s_mkdir(path)        _mkdir(path)
#define s_chmod_ro(path)     _chmod(path, _S_IREAD)
#define s_chmod_rw(path)     _chmod(path, _S_IWRITE)
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#define s_getcwd(buf, cap)   getcwd(buf, cap)
#define s_mkdir(path)        mkdir(path, 0755)
#define s_chmod_ro(path)     chmod(path, 0444)
#define s_chmod_rw(path)     chmod(path, 0644)
#endif

#define expect(cond, msg) do { if (!(cond)) return msg; } while (0)

static constexpr char     log_path[]  = "ductio_logfile_test.log";
static constexpr char     product[]   = "ductio_logfile_test";
static constexpr unsigned thr_count  = 4u;
static constexpr unsigned thr_lines  = 200u;
static constexpr unsigned proc_lines = 100u;
static constexpr size_t   log_stamp  = 24u;

static bool g_skipped_root;

static bool s_stamp_ok(const char *line)
{
    unsigned year, month, day, hour, minute, second, milli;
    char blank = '\0';
    return sscanf(line, "%4u-%2u-%2u %2u:%2u:%2u.%3u%c", &year, &month, &day, &hour, &minute, &second,
                  &milli, &blank) == 8
           && blank == ' ' && month >= 1u && month <= 12u && day >= 1u && day <= 31u && hour <= 23u
           && minute <= 59u && second <= 61u;
}

static void s_env(const char *name, const char *value)
{
#ifdef _WIN32
    char slot[512];
    snprintf(slot, sizeof slot, "%s=%s", name, value ? value : "");
    duct_discard _putenv(slot);
#else
    if (value)
        setenv(name, value, 1);
    else
        unsetenv(name);
#endif
}

static bool s_dir_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static unsigned s_count_lines(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0u;
    unsigned total = 0u;
    char line[1100];
    while (fgets(line, sizeof line, f))
        ++total;
    fclose(f);
    return total;
}

static const char *sc_append_reopen(void)
{
    unlink(log_path);
    duct_logfile_t sink = {};
    expect(duct_logfile_init(&sink, log_path), "the append open was refused");
    duct_logger_init(&sink.logger);
    duct_log(stderr, "first %u", 1u);
    duct_logfile_fini(&sink);
    expect(duct_logfile_init(&sink, log_path), "the reopen was refused");
    duct_logger_init(&sink.logger);
    duct_log(stderr, "second %u", 2u);
    duct_logfile_fini(&sink);
    FILE *f = fopen(log_path, "rb");
    expect(f, "the log file does not read back");
    char line[1100],
         first[1100],
         second[1100];
    bool read = fgets(line, sizeof line, f) != nullptr;
    snprintf(first, sizeof first, "%s", line);
    bool more = read && fgets(line, sizeof line, f) != nullptr;
    snprintf(second, sizeof second, "%s", line);
    bool past = more && fgets(line, sizeof line, f) != nullptr;
    fclose(f);
    unlink(log_path);
    expect(read && more && !past, "two logged lines do not read back as two lines");
    expect(s_stamp_ok(first) && strstr(first, "first 1\n"), "the first line is not the stamped message");
    expect(s_stamp_ok(second) && strstr(second, "second 2\n"), "the reopened log did not append the second line");
    return nullptr;
}

static void *s_writer(void *arg)
{
    unsigned id = *(const unsigned *)arg;
    for (unsigned n = 0u; n < thr_lines; ++n)
        duct_log(stderr, "t%u n%u", id, n);
    return nullptr;
}

static const char *sc_threads(void)
{
    unlink(log_path);
    duct_logfile_t sink = {};
    expect(duct_logfile_init(&sink, log_path), "the log file does not open");
    duct_logger_init(&sink.logger);
    pthread_t threads[thr_count];
    unsigned ids[thr_count],
             started = 0u;
    for (; started < thr_count; ++started) {
        ids[started] = started;
        if (pthread_create(&threads[started], nullptr, s_writer, &ids[started]) != 0)
            break;
    }
    for (unsigned i = 0u; i < started; ++i)
        pthread_join(threads[i], nullptr);
    duct_logfile_fini(&sink);
    expect(started == thr_count, "a writer thread does not start");
    bool seen[thr_count][thr_lines] = {};
    unsigned total = 0u;
    char line[1100];
    const char *err = nullptr;
    FILE *f = fopen(log_path, "rb");
    expect(f, "the log file does not read back");
    while (!err && fgets(line, sizeof line, f)) {
        unsigned id, n;
        char end = '\0';
        if (!s_stamp_ok(line) || sscanf(line + log_stamp, "t%u n%u%c", &id, &n, &end) != 3 || end != '\n'
            || id >= thr_count || n >= thr_lines)
            err = "a line in the log file is not whole";
        else if (seen[id][n])
            err = "a line in the log file comes out twice";
        else {
            seen[id][n] = true;
            ++total;
        }
    }
    fclose(f);
    unlink(log_path);
    return err ? err : total != thr_count * thr_lines ? "a line in the log file is lost" : nullptr;
}

static const char *sc_echo(void)
{
    unlink(log_path);
    FILE *out = tmpfile();
    expect(out, "no stream temporary file");
    duct_logfile_t sink = {};
    expect(duct_logfile_init(&sink, log_path), "the log file does not open");
    duct_logger_init(&sink.logger);
    duct_log(out, "fanout %u", 3u);
    duct_logfile_fini(&sink);
    char file_line[1100],
         out_line[1100],
         past[1100];
    FILE *f = fopen(log_path, "rb");
    expect(f, "the log file does not read back");
    bool file_read = fgets(file_line, sizeof file_line, f) != nullptr;
    bool file_past = file_read && fgets(past, sizeof past, f) != nullptr;
    fclose(f);
    rewind(out);
    bool out_read = fgets(out_line, sizeof out_line, out) != nullptr;
    bool out_past = out_read && fgets(past, sizeof past, out) != nullptr;
    fclose(out);
    unlink(log_path);
    expect(file_read && !file_past, "the log file does not hold the one logged line");
    expect(out_read && !out_past, "the call's stream does not hold the one logged line");
    expect(strcmp(file_line, out_line) == 0, "the file and the stream lines differ");
    expect(s_stamp_ok(file_line) && strstr(file_line, "fanout 3\n"), "the fanned-out line is not the stamped message");
    return nullptr;
}

static const char *sc_crop(void)
{
    unlink(log_path);
    duct_logfile_t sink = {};
    expect(duct_logfile_init(&sink, log_path), "the log file does not open");
    duct_logger_init(&sink.logger);
    char big[2000];
    memset(big, 'x', sizeof big - 1u);
    big[sizeof big - 1u] = '\0';
    duct_log(stderr, "%s", big);
    duct_logfile_fini(&sink);
    char line[1100],
         past[1100];
    FILE *f = fopen(log_path, "rb");
    expect(f, "the log file does not read back");
    bool read = fgets(line, sizeof line, f) != nullptr;
    bool past_took = read && fgets(past, sizeof past, f) != nullptr;
    fclose(f);
    unlink(log_path);
    expect(read && !past_took, "the cut line and the end do not read back as one line");
    expect(strlen(line) == 1023u, "a long message is not cut to a 1023-byte line");
    expect(memcmp(line + 1019u, "...\n", 4u) == 0, "a cut line does not end in an ellipsis and a newline");
    expect(s_stamp_ok(line), "a cut line does not open with the stamp");
    return nullptr;
}

#ifndef _WIN32
static FILE *s_stderr_capture(int *saved)
{
    fflush(nullptr);
    *saved = dup(STDERR_FILENO);
    FILE *cap = tmpfile();
    if (*saved < 0 || !cap) {
        if (*saved >= 0)
            close(*saved);
        return nullptr;
    }
    dup2(fileno(cap), STDERR_FILENO);
    return cap;
}

static void s_stderr_release(FILE *cap, int saved)
{
    fflush(nullptr);
    dup2(saved, STDERR_FILENO);
    close(saved);
    rewind(cap);
}

static unsigned s_capture_diag(FILE *cap)
{
    unsigned total = 0u;
    char line[1100];
    rewind(cap);
    while (fgets(line, sizeof line, cap))
        if (strstr(line, "duct: log file"))
            ++total;
    return total;
}

static unsigned s_capture_rest(FILE *cap)
{
    unsigned total = 0u;
    char line[1100];
    rewind(cap);
    while (fgets(line, sizeof line, cap))
        if (!strstr(line, "duct: log file"))
            ++total;
    return total;
}

static const char *sc_selfremove(void)
{
    int saved = -1;
    FILE *cap = s_stderr_capture(&saved);
    expect(cap, "the stderr capture does not start");
    duct_logfile_t sink = {};
    expect(duct_logfile_init(&sink, "/dev/full"), "the full device does not open for append");
    duct_logger_init(&sink.logger);
    duct_log(stderr, "lost %u", 6u);
    duct_logfile_fini(&sink);
    unsigned diags = s_capture_diag(cap);
    unsigned rest = s_capture_rest(cap);
    char raw_line[1100] = "";
    rewind(cap);
    while (fgets(raw_line, sizeof raw_line, cap))
        if (!strstr(raw_line, "duct: log file"))
            break;
    s_stderr_release(cap, saved);
    fclose(cap);
    expect(rest == 1u, "the fatal line is not alone on the call's stream");
    expect(s_stamp_ok(raw_line) && strstr(raw_line, "lost 6\n"), "the fatal line is not the stamped message");
    expect(diags == 1u, "the self-removal does not diag once");
    return nullptr;
}

static void *s_full_writer(void *arg)
{
    unsigned id = *(const unsigned *)arg;
    for (unsigned n = 0u; n < 20u; ++n)
        duct_log(stderr, "t%u n%u", id, n);
    return nullptr;
}

static const char *sc_selfremove_threads(void)
{
    int saved = -1;
    FILE *cap = s_stderr_capture(&saved);
    expect(cap, "the stderr capture does not start");
    duct_logfile_t sink = {};
    expect(duct_logfile_init(&sink, "/dev/full"), "the full device does not open for append");
    duct_logger_init(&sink.logger);
    pthread_t threads[thr_count];
    unsigned ids[thr_count],
             started = 0u;
    for (; started < thr_count; ++started) {
        ids[started] = started;
        if (pthread_create(&threads[started], nullptr, s_full_writer, &ids[started]) != 0)
            break;
    }
    for (unsigned i = 0u; i < started; ++i)
        pthread_join(threads[i], nullptr);
    duct_logfile_fini(&sink);
    unsigned diags = s_capture_diag(cap);
    s_stderr_release(cap, saved);
    expect(started == thr_count, "a writer thread does not start");
    expect(diags >= 1u && diags <= thr_count, "the fatal writes a diag per thread in flight or none");
    bool whole = true;
    unsigned raw = 0u;
    char line[1100];
    rewind(cap);
    while (fgets(line, sizeof line, cap)) {
        if (strstr(line, "duct: log file"))
            continue;
        unsigned id, n;
        char end = '\0';
        whole = whole && s_stamp_ok(line) && sscanf(line + log_stamp, "t%u n%u%c", &id, &n, &end) == 3
             && end == '\n' && id < thr_count;
        ++raw;
    }
    fclose(cap);
    expect(whole, "a raw line of the fatal is not whole");
    expect(raw >= thr_count, "the raw stream does not hold a line per writer thread");
    return nullptr;
}
#endif

static const char *sc_fini_order(void)
{
    unlink(log_path);
    duct_logfile_t sink = {};
    expect(duct_logfile_init(&sink, log_path), "the log file does not open");
    duct_logger_init(&sink.logger);
    duct_log(stderr, "before %u", 8u);
    duct_logfile_fini(&sink);
    expect(sink.file == nullptr, "the fini leaves the file handle behind");
    FILE *out = tmpfile();
    expect(out, "no stream temporary file");
    duct_log(out, "after %u", 8u);
    rewind(out);
    char line[1100];
    bool stream_took = fgets(line, sizeof line, out) != nullptr;
    fclose(out);
    unsigned lines = s_count_lines(log_path);
    unlink(log_path);
    expect(stream_took && strstr(line, "after 8\n"), "a line after the fini does not reach the raw stream");
    expect(lines == 1u, "a line after the fini reaches the log file");
    duct_logfile_fini(&sink);
    return nullptr;
}

static const char *sc_open_dir(void)
{
    duct_logfile_t sink = {};
    expect(!duct_logfile_init(&sink, "no_such_dir/ductio_logfile_test.log"),
           "an open into a missing directory was taken");
    expect(sink.file == nullptr, "a refused open leaves a file handle behind");
    return nullptr;
}

static const char *sc_open_perm(void)
{
    FILE *f = fopen(log_path, "wb");
    expect(f, "the permission file does not create");
    fclose(f);
    expect(s_chmod_ro(log_path) == 0, "the permission file does not turn read-only");
    duct_logfile_t sink = {};
    bool opened = duct_logfile_init(&sink, log_path);
    expect(s_chmod_rw(log_path) == 0, "the permission file does not turn writable again");
    unlink(log_path);
    expect(!opened, "an append open of a read-only file was taken");
    expect(sink.file == nullptr, "a refused open leaves a file handle behind");
    return nullptr;
}

static const char *sc_open_long(void)
{
    char path[5000];
    memset(path, 'a', sizeof path - 1u);
    path[sizeof path - 1u] = '\0';
    duct_logfile_t sink = {};
    expect(!duct_logfile_init(&sink, path), "an open of a 4999-byte path was taken");
    expect(sink.file == nullptr, "a refused open leaves a file handle behind");
    return nullptr;
}

#ifndef _WIN32
static const char *sc_append_two_procs(void)
{
    unlink(log_path);
    pid_t kids[2];
    for (unsigned k = 0u; k < 2u; ++k) {
        kids[k] = fork();
        expect(kids[k] >= 0, "a writer process does not start");
        if (kids[k] == 0) {
            duct_logfile_t sink = {};
            if (!duct_logfile_init(&sink, log_path))
                _exit(2);
            duct_logger_init(&sink.logger);
            for (unsigned n = 0u; n < proc_lines; ++n)
                duct_log(stderr, "p%u n%u", k, n);
            duct_logfile_fini(&sink);
            _exit(0);
        }
    }
    for (unsigned k = 0u; k < 2u; ++k) {
        int status = 0;
        expect(waitpid(kids[k], &status, 0) == kids[k] && WIFEXITED(status) && WEXITSTATUS(status) == 0,
               "a writer process does not end cleanly");
    }
    bool seen[2u][proc_lines] = {};
    unsigned total = 0u;
    char line[1100];
    const char *err = nullptr;
    FILE *f = fopen(log_path, "rb");
    expect(f, "the log file does not read back");
    while (!err && fgets(line, sizeof line, f)) {
        unsigned p, n;
        char end = '\0';
        if (!s_stamp_ok(line) || sscanf(line + log_stamp, "p%u n%u%c", &p, &n, &end) != 3 || end != '\n'
            || p >= 2u || n >= proc_lines)
            err = "a line of two processes is not whole";
        else if (seen[p][n])
            err = "a line of two processes comes out twice";
        else {
            seen[p][n] = true;
            ++total;
        }
    }
    fclose(f);
    unlink(log_path);
    return err ? err : total != 2u * proc_lines ? "a line of two processes is lost" : nullptr;
}

static const char *sc_resolver_xdg(void)
{
    char base[512],
         want[512],
         dir[512];
    expect(s_getcwd(base, sizeof base), "the working directory does not read");
    expect(snprintf(want, sizeof want, "%s/ductio_logfile_test_xdg", base) > 0, "the base path does not build");
    expect(s_mkdir(want) == 0, "the resolver base does not create");
    const char *saved = getenv("XDG_STATE_HOME");
    s_env("XDG_STATE_HOME", want);
    bool got = duct_logfile_default_dir(dir, sizeof dir, product);
    s_env("XDG_STATE_HOME", saved);
    char made_path[512];
    expect(snprintf(made_path, sizeof made_path, "%s/%s", want, product) > 0, "the product path does not build");
    bool made = s_dir_exists(made_path);
    rmdir(made_path);
    rmdir(want);
    expect(got, "an absolute XDG_STATE_HOME does not resolve");
    expect(strcmp(dir, made_path) == 0, "the resolved directory is not the product directory under XDG_STATE_HOME");
    expect(made, "the resolver does not make the product directory");
    return nullptr;
}

static const char *sc_resolver_home(void)
{
    char base[512],
         local[512],
         state[512],
         made_path[512],
         dir[512];
    expect(s_getcwd(base, sizeof base), "the working directory does not read");
    expect(snprintf(local, sizeof local, "%s/.local", base) > 0, "the local path does not build");
    expect(snprintf(state, sizeof state, "%s/.local/state", base) > 0, "the state path does not build");
    expect(snprintf(made_path, sizeof made_path, "%s/.local/state/%s", base, product) > 0,
           "the product path does not build");
    expect(s_mkdir(local) == 0 && s_mkdir(state) == 0, "the HOME state parent does not create");
    const char *saved = getenv("XDG_STATE_HOME"),
               *saved_home = getenv("HOME");
    s_env("XDG_STATE_HOME", nullptr);
    s_env("HOME", base);
    bool got = duct_logfile_default_dir(dir, sizeof dir, product);
    s_env("XDG_STATE_HOME", saved);
    s_env("HOME", saved_home);
    bool made = s_dir_exists(made_path);
    rmdir(made_path);
    rmdir(state);
    rmdir(local);
    expect(got, "an unset XDG_STATE_HOME with a HOME does not fall back to the state home");
    expect(strcmp(dir, made_path) == 0, "the resolved directory is not the product directory under the HOME state");
    expect(made, "the resolver does not make the product directory");
    return nullptr;
}

static const char *sc_resolver_syslog(void)
{
    if (geteuid() == 0) {
        g_skipped_root = true;
        return nullptr;
    }
    const char *saved = getenv("XDG_STATE_HOME"),
               *saved_home = getenv("HOME");
    s_env("XDG_STATE_HOME", nullptr);
    s_env("HOME", nullptr);
    char dir[512];
    bool got = duct_logfile_default_dir(dir, sizeof dir, product);
    s_env("XDG_STATE_HOME", saved);
    s_env("HOME", saved_home);
    if (got) {
        char made_path[512];
        expect(snprintf(made_path, sizeof made_path, "/var/log/%s", product) > 0, "the product path does not build");
        rmdir(made_path);
    }
    expect(!got, "a mkdir refusal under /var/log is not a no-default answer");
    return nullptr;
}

static const char *sc_resolver_rel(void)
{
    char base[512],
         local[512],
         state[512],
         made_path[512],
         dir[512];
    expect(s_getcwd(base, sizeof base), "the working directory does not read");
    expect(snprintf(local, sizeof local, "%s/.local", base) > 0, "the local path does not build");
    expect(snprintf(state, sizeof state, "%s/.local/state", base) > 0, "the state path does not build");
    expect(snprintf(made_path, sizeof made_path, "%s/.local/state/%s", base, product) > 0,
           "the product path does not build");
    expect(s_mkdir(local) == 0 && s_mkdir(state) == 0, "the HOME state parent does not create");
    const char *saved = getenv("XDG_STATE_HOME"),
               *saved_home = getenv("HOME");
    s_env("XDG_STATE_HOME", "relative/state");
    s_env("HOME", base);
    bool got = duct_logfile_default_dir(dir, sizeof dir, product);
    s_env("XDG_STATE_HOME", saved);
    s_env("HOME", saved_home);
    bool made = s_dir_exists(made_path);
    rmdir(made_path);
    rmdir(state);
    rmdir(local);
    expect(got, "a relative XDG_STATE_HOME does not fall through to the HOME state");
    expect(strcmp(dir, made_path) == 0, "the resolved directory is not the HOME state after a relative XDG_STATE_HOME");
    expect(made, "the resolver does not make the product directory");
    return nullptr;
}

static const char *sc_resolver_mkdir(void)
{
    char ro[512],
         made_path[512],
         dir[512];
    snprintf(ro, sizeof ro, "/tmp/ductio_logfile_test_ro_XXXXXX");
    expect(mkdtemp(ro), "the read-only base does not create");
    expect(chmod(ro, 0555) == 0, "the base does not turn read-only");
    expect(snprintf(made_path, sizeof made_path, "%s/%s", ro, product) > 0, "the product path does not build");
    const char *saved = getenv("XDG_STATE_HOME");
    s_env("XDG_STATE_HOME", ro);
    bool got = duct_logfile_default_dir(dir, sizeof dir, product);
    s_env("XDG_STATE_HOME", saved);
    expect(chmod(ro, 0755) == 0, "the base does not turn writable again");
    rmdir(made_path);
    rmdir(ro);
    expect(!got, "a mkdir refusal is not a no-default answer");
    expect(!s_dir_exists(made_path), "a refused mkdir leaves the product directory behind");
    return nullptr;
}
#endif

static const char *sc_resolver_cap(void)
{
    char tiny[4];
    expect(!duct_logfile_default_dir(tiny, sizeof tiny, product), "a cap past the path is not a no-default answer");
    return nullptr;
}

#ifdef _WIN32
static const char *sc_resolver_lad(void)
{
    char cwd[512],
         base[512],
         made_path[512],
         dir[512];
    expect(s_getcwd(cwd, sizeof cwd), "the working directory does not read");
    expect(snprintf(made_path, sizeof made_path, "%s\\ductio_logfile_test_lad\\%s", cwd, product) > 0,
           "the product path does not build");
    expect(snprintf(base, sizeof base, "%s\\ductio_logfile_test_lad", cwd) > 0, "the base path does not build");
    expect(s_mkdir(base) == 0, "the resolver base does not create");
    const char *saved = getenv("LOCALAPPDATA");
    s_env("LOCALAPPDATA", base);
    bool got = duct_logfile_default_dir(dir, sizeof dir, product);
    s_env("LOCALAPPDATA", saved);
    bool made = s_dir_exists(made_path);
    RemoveDirectoryA(made_path);
    RemoveDirectoryA(base);
    expect(got, "a set LOCALAPPDATA does not resolve");
    expect(strcmp(dir, made_path) == 0, "the resolved directory is not the product directory under LOCALAPPDATA");
    expect(made, "the resolver does not make the product directory");
    return nullptr;
}

static const char *sc_resolver_pd(void)
{
    char cwd[512],
         base[512],
         made_path[512],
         dir[512];
    expect(s_getcwd(cwd, sizeof cwd), "the working directory does not read");
    expect(snprintf(made_path, sizeof made_path, "%s\\ductio_logfile_test_pd\\%s", cwd, product) > 0,
           "the product path does not build");
    expect(snprintf(base, sizeof base, "%s\\ductio_logfile_test_pd", cwd) > 0, "the base path does not build");
    expect(s_mkdir(base) == 0, "the resolver base does not create");
    const char *saved = getenv("ProgramData");
    s_env("LOCALAPPDATA", "");
    s_env("ProgramData", base);
    bool got = duct_logfile_default_dir(dir, sizeof dir, product);
    s_env("ProgramData", saved);
    bool made = s_dir_exists(made_path);
    RemoveDirectoryA(made_path);
    RemoveDirectoryA(base);
    expect(got, "an empty LOCALAPPDATA with ProgramData does not resolve");
    expect(strcmp(dir, made_path) == 0, "the resolved directory is not the product directory under ProgramData");
    expect(made, "the resolver does not make the product directory");
    return nullptr;
}

static const char *sc_resolver_none(void)
{
    const char *saved = getenv("LOCALAPPDATA"),
               *saved_pd = getenv("ProgramData");
    s_env("LOCALAPPDATA", "");
    s_env("ProgramData", "");
    char dir[512];
    bool got = duct_logfile_default_dir(dir, sizeof dir, product);
    s_env("LOCALAPPDATA", saved);
    s_env("ProgramData", saved_pd);
    expect(!got, "no environment variable is not a no-default answer");
    return nullptr;
}
#endif

static const char *sc_resolver_e2e(void)
{
    char base[512],
         made_path[512],
         dir[512];
    expect(s_getcwd(base, sizeof base), "the working directory does not read");
    expect(snprintf(made_path, sizeof made_path, "%s/ductio_logfile_test_e2e/%s", base, product) > 0,
           "the product path does not build");
    char env_base[512];
    expect(snprintf(env_base, sizeof env_base, "%s/ductio_logfile_test_e2e", base) > 0, "the base path does not build");
    expect(s_mkdir(env_base) == 0, "the resolver base does not create");
#ifdef _WIN32
    const char *saved = getenv("LOCALAPPDATA");
    s_env("LOCALAPPDATA", env_base);
#else
    const char *saved = getenv("XDG_STATE_HOME");
    s_env("XDG_STATE_HOME", env_base);
#endif
    bool got = duct_logfile_default_dir(dir, sizeof dir, product);
    size_t used = got ? strlen(dir) : 0u;
    bool path_ok = got && snprintf(dir + used, sizeof dir - used, ".log") > 0;
    duct_logfile_t sink = {};
    bool opened = path_ok && duct_logfile_init(&sink, dir);
    if (opened) {
        duct_logger_init(&sink.logger);
        duct_log(stderr, "e2e %u", 25u);
        duct_logfile_fini(&sink);
    }
    unsigned lines = opened ? s_count_lines(dir) : 0u;
    char text[1100] = "";
    if (lines == 1u) {
        FILE *f = fopen(dir, "rb");
        if (f) {
            duct_discard fgets(text, sizeof text, f);
            fclose(f);
        }
    }
    unlink(dir);
    rmdir(made_path);
    rmdir(env_base);
#ifdef _WIN32
    s_env("LOCALAPPDATA", saved);
#else
    s_env("XDG_STATE_HOME", saved);
#endif
    expect(got && path_ok, "the resolver does not hand a product directory to append .log to");
    expect(opened, "the end-to-end open of the resolved path was refused");
    expect(lines == 1u && s_stamp_ok(text) && strstr(text, "e2e 25\n"),
           "the first line does not land in the resolved file");
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    static const struct { const char *name; const char *(*fn)(void); } cases[] = {
        { "append_reopen",      sc_append_reopen },
        { "threads",            sc_threads },
        { "echo",               sc_echo },
        { "crop",               sc_crop },
#ifndef _WIN32
        { "selfremove",         sc_selfremove },
        { "selfremove_threads", sc_selfremove_threads },
#endif
        { "fini_order",         sc_fini_order },
        { "open_dir",           sc_open_dir },
        { "open_perm",          sc_open_perm },
        { "open_long",          sc_open_long },
#ifndef _WIN32
        { "append_two_procs",   sc_append_two_procs },
        { "resolver_xdg",       sc_resolver_xdg },
        { "resolver_home",      sc_resolver_home },
        { "resolver_syslog",    sc_resolver_syslog },
        { "resolver_rel",       sc_resolver_rel },
        { "resolver_mkdir",     sc_resolver_mkdir },
#endif
        { "resolver_cap",       sc_resolver_cap },
#ifdef _WIN32
        { "resolver_lad",       sc_resolver_lad },
        { "resolver_pd",        sc_resolver_pd },
        { "resolver_none",      sc_resolver_none },
#endif
        { "resolver_e2e",       sc_resolver_e2e },
    };
    int failed = 0;
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        const char *err = cases[i].fn();
        printf("logfile: %-20s %s%s\n", cases[i].name, err ? "FAILED: " : "ok", err ? err : "");
        failed += err != nullptr;
    }
    if (g_skipped_root)
        printf("logfile: the /var/log refusal was skipped, the caller is root\n");
    return failed ? 1 : 0;
}
