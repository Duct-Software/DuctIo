/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file local_listener_test.c
 * @brief The x_local listener: what a bind refuses and takes over, the access it applies, a close
 *  that leaves a newer socket alone, and the cap on the sessions that live through it.
 *
 * A raw echo protocol serves a listener bound on a path in the temp directory, and plain AF_UNIX
 * clients of the test talk to it. Each scenario binds its own listener on its own path and closes
 * it before the next one runs; the last one stops the engine with a listener bound and a session
 * live. A Windows build below 10 1803 has no AF_UNIX: there the one thing asked is that the bind
 * says so.
 */

#include "duct.h"
#include "duct_ticks.h"
#include "test_helpers.h"

#include <stdatomic.h>
#include <string.h>

#ifdef _WIN32
    #include <afunix.h>
#else
    #include <fcntl.h>
    #include <grp.h>
    #include <sys/stat.h>
    #include <sys/un.h>
#endif

#if defined(_WIN32) && NTDDI_VERSION < NTDDI_WIN10_RS4
static constexpr bool local_floor = false;
#else
static constexpr bool local_floor = true;
#endif

static constexpr unsigned wait_ms = 3000u;
static constexpr size_t   chunk   = 3000u;

static atomic_int g_opened = 0;
static atomic_int g_closed = 0;

static duct_result_t
on_session_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_opened, 1, release);
    return rc_ok;
}

static void
on_session_close([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_close_reason_t reason,
                 [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_closed, 1, release);
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
         const duct_frame_t *frame, duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

typedef struct {
    duct_engine_t      *e;
    duct_proto_t       *proto;
    const duct_proto_t *protos[1];
    pthread_t           thread;
} rig_t;

static bool rig_up(rig_t *r)
{
    r->e = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!r->e)
        return false;
    r->proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "local-echo", .on_frame = on_frame, .max_response = 4096u,
        .on_session_open = on_session_open, .on_session_close = on_session_close,
    });
    if (!r->proto || pthread_create(&r->thread, nullptr, th_run, r->e) != 0) {
        duct_engine_destroy(r->e);
        duct_proto_destroy(r->proto);
        return false;
    }
    r->protos[0] = r->proto;
    return true;
}

static void rig_down(rig_t *r)
{
    duct_engine_stop(r->e);
    pthread_join(r->thread, nullptr);
    duct_engine_destroy(r->e);
    duct_proto_destroy(r->proto);
}

/* ── the file system, as each platform names it ───────────────────────────────────────────── */

static bool s_exists(const char *path)
{
#ifdef _WIN32
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
#else
    struct stat st;
    return lstat(path, &st) == 0;
#endif
}

static bool s_is_socket(const char *path)
{
#ifdef _WIN32
    WIN32_FIND_DATAA found;
    HANDLE h = FindFirstFileA(path, &found);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    FindClose(h);
    return (found.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        && found.dwReserved0 == IO_REPARSE_TAG_AF_UNIX;
#else
    struct stat st;
    return lstat(path, &st) == 0 && S_ISSOCK(st.st_mode);
#endif
}

static bool s_rename(const char *from, const char *to)
{
#ifdef _WIN32
    return MoveFileA(from, to) != 0;
#else
    return rename(from, to) == 0;
#endif
}

/* ── the listener under test ───────────────────────────────────────────────────────────────── */

static duct_listener_cfg_t local_cfg(rig_t *r, const char *path)
{
    return (duct_listener_cfg_t){
        .n_protos = 1u, .protos = r->protos, .kind = listener_stream, .local_path = path,
    };
}

static duct_result_t bind_cfg(rig_t *r, const duct_listener_cfg_t *cfg, duct_sock_t *fd)
{
    uint16_t port = 0u;
    unsigned n = 0u;
    *fd = duct_sock_bad;
    return duct_listener_bind(r->e, cfg, &port, fd, 1u, &n);
}

/** @brief Send @p size bytes of @p text repeated, read them back, compare.
 *  @return the text of the failed step, nullptr when the bytes came back whole. */
static const char *s_echo(duct_sock_t fd, const char *text, size_t size)
{
    char out[chunk], got[chunk];
    size_t len = strlen(text);
    for (size_t i = 0u; i < size; ++i)
        out[i] = text[i % len];
    if (send(fd, out, (int)size, 0) != (int)size)
        return "a send failed";
    if (th_read_exact(fd, got, size) != 0)
        return "the echo did not come";
    return memcmp(got, out, size) == 0 ? nullptr : "the echo differs";
}

/** @brief Wait until the engine's open and close tallies differ by @p open. */
static bool s_sessions(int open)
{
    for (unsigned waited = 0u; waited < wait_ms; waited += 10u) {
        if (duct_atomic_load(&g_opened, acquire) - duct_atomic_load(&g_closed, acquire) == open)
            return true;
        th_sleep_ms(10u);
    }
    return false;
}

/** @brief A socket file nobody serves: bound, then its socket closed. */
static void s_make_stale(const char *path)
{
    struct sockaddr_un sa;
    th_local_fill(&sa, path);
    duct_discard remove(path);
    duct_sock_t s = socket(AF_UNIX, SOCK_STREAM, 0);
    duct_discard bind(s, (struct sockaddr *)&sa, (int)sizeof sa);
    duct_sock_close(s);
}

/* ── scenarios ─────────────────────────────────────────────────────────────────────────────── */

/** @brief A listener's own file: the socket, the mode asked for where there is one, an echo of a
 *  small and a chunk-sized piece, the session gone with its client, the path gone with the close. */
static const char *sc_serves(rig_t *r)
{
    char path[th_local_path_max];
    th_local_path(path, sizeof path,"serves");
    auto cfg = local_cfg(r, path);
#ifndef _WIN32
    cfg.local_mode = 0660u;
#endif
    duct_sock_t lfd;
    if (bind_cfg(r, &cfg, &lfd) != rc_ok)
        return "the bind failed";
    const char *error = nullptr;
    if (!s_is_socket(path))
        error = "no socket file at the path";
#ifndef _WIN32
    struct stat st;
    if (!error && (lstat(path, &st) != 0 || (st.st_mode & 0777) != 0660))
        error = "the mode is not the one asked for";
#endif
    duct_sock_t c = error ? duct_sock_bad : th_local_connect(path);
    if (!error && c == duct_sock_bad)
        error = "connect failed";
    if (!error)
        error = s_echo(c, "hello", 5u);
    for (unsigned round = 0u; !error && round < 40u; ++round)
        error = s_echo(c, "0123456789abcdef", chunk);
    if (c != duct_sock_bad)
        duct_sock_close(c);
    if (!s_sessions(0) && !error)
        error = "the session did not close with its client";
    if (duct_listener_close(r->e, lfd) != rc_ok && !error)
        error = "the close failed";
    if (!error && s_exists(path))
        error = "the path stands after the close";
    return error;
}

/** @brief A socket file nobody serves is bound over. */
static const char *sc_stale(rig_t *r)
{
    char path[th_local_path_max];
    th_local_path(path, sizeof path,"stale");
    s_make_stale(path);
    if (!s_is_socket(path))
        return "the stale socket was not made";
    auto cfg = local_cfg(r, path);
    duct_sock_t lfd;
    if (bind_cfg(r, &cfg, &lfd) != rc_ok)
        return "a stale socket was not bound over";
    duct_sock_t c = th_local_connect(path);
    const char *error = c == duct_sock_bad ? "connect failed" : s_echo(c, "x", 1u);
    if (c != duct_sock_bad)
        duct_sock_close(c);
    duct_discard s_sessions(0);
    duct_discard duct_listener_close(r->e, lfd);
    return error;
}

/** @brief A live listener is refused, and it keeps serving on the same file. */
static const char *sc_live(rig_t *r)
{
    char path[th_local_path_max];
    th_local_path(path, sizeof path,"live");
    auto cfg = local_cfg(r, path);
    duct_sock_t first, second;
    if (bind_cfg(r, &cfg, &first) != rc_ok)
        return "the first bind failed";
#ifndef _WIN32
    struct stat before, after;
    duct_discard lstat(path, &before);
#endif
    const char *error = nullptr;
    if (bind_cfg(r, &cfg, &second) == rc_ok)
        error = "a second bind on a live path succeeded";
#ifndef _WIN32
    if (!error && (lstat(path, &after) != 0 || after.st_ino != before.st_ino))
        error = "the live socket file changed";
#endif
    duct_sock_t c = error ? duct_sock_bad : th_local_connect(path);
    if (!error)
        error = c == duct_sock_bad ? "the live listener stopped serving" : s_echo(c, "y", 1u);
    if (c != duct_sock_bad)
        duct_sock_close(c);
    duct_discard s_sessions(0);
    duct_discard duct_listener_close(r->e, first);
    return error;
}

/** @brief A regular file at the path is refused and left as it was; so is a symlink, where a
 *  symlink can be made. */
static const char *sc_other(rig_t *r)
{
    char path[th_local_path_max];
    th_local_path(path, sizeof path,"other");
    remove(path);
    FILE *made = fopen(path, "w");
    if (!made)
        return "the file was not made";
    fclose(made);
    auto cfg = local_cfg(r, path);
    duct_sock_t lfd;
    if (bind_cfg(r, &cfg, &lfd) == rc_ok) {
        duct_discard duct_listener_close(r->e, lfd);
        remove(path);
        return "a regular file was taken for a listener";
    }
    if (!s_exists(path) || s_is_socket(path)) {
        remove(path);
        return "the file was disturbed by the refusal";
    }
    remove(path);
#ifndef _WIN32
    if (symlink("/nonexistent/duct_local_target", path) != 0)
        return "the symlink was not made";
    if (bind_cfg(r, &cfg, &lfd) == rc_ok) {
        duct_discard duct_listener_close(r->e, lfd);
        remove(path);
        return "a symlink was taken for a listener";
    }
    struct stat st;
    const char *error = lstat(path, &st) == 0 && S_ISLNK(st.st_mode) ? nullptr
                      : "the symlink was disturbed by the refusal";
    remove(path);
    return error;
#else
    return nullptr;
#endif
}

/** @brief A close removes the path only while it is still the listener's own file.
 *  The listener's file is renamed aside, not unlinked, so the newer socket cannot be handed
 *  the freed file identity. */
static const char *sc_inode(rig_t *r)
{
    char path[th_local_path_max], aside[th_local_path_max + 8];
    th_local_path(path, sizeof path,"inode");
    snprintf(aside, sizeof aside, "%s.old", path);
    auto cfg = local_cfg(r, path);
    duct_sock_t first;
    if (bind_cfg(r, &cfg, &first) != rc_ok)
        return "the bind failed";
    const char *error = nullptr;
    struct sockaddr_un sa;
    th_local_fill(&sa, path);
    duct_sock_t mine = socket(AF_UNIX, SOCK_STREAM, 0);
    if (!s_rename(path, aside))
        error = "the listener's file was not moved aside";
    else if (bind(mine, (struct sockaddr *)&sa, (int)sizeof sa) != 0)
        error = "the newer socket was not bound";
    else if (duct_listener_close(r->e, first) != rc_ok)
        error = "the close failed";
    else if (!s_is_socket(path))
        error = "a close removed a socket that was not its own";
    else if (!s_exists(aside))
        error = "a close removed the old file, which is no longer at the path";
    duct_sock_close(mine);
    remove(path);
    remove(aside);
    return error;
}

/** @brief A close while a session lives takes the path at once and leaves the session its socket. */
static const char *sc_close_live(rig_t *r)
{
    char path[th_local_path_max];
    th_local_path(path, sizeof path,"closelive");
    auto cfg = local_cfg(r, path);
    duct_sock_t lfd;
    if (bind_cfg(r, &cfg, &lfd) != rc_ok)
        return "the bind failed";
    duct_sock_t c = th_local_connect(path);
    const char *error = c == duct_sock_bad ? "connect failed" : s_echo(c, "one", 3u);
    if (!error && duct_listener_close(r->e, lfd) != rc_ok)
        error = "the close failed";
    if (!error && s_exists(path))
        error = "the path stands while a session lives";
    if (!error)
        error = s_echo(c, "two", 3u);
    if (c != duct_sock_bad)
        duct_sock_close(c);
    if (!error && !s_sessions(0))
        error = "the session did not end with its client";
    return error;
}

/** @brief Past max_sessions a connection is closed at accept and takes no conn; a place a closed
 *  session gave back is taken again, and many cycles through the cap do not wear it down. */
static const char *sc_cap(rig_t *r)
{
    char path[th_local_path_max];
    th_local_path(path, sizeof path,"cap");
    auto cfg = local_cfg(r, path);
    cfg.max_sessions = 2u;
    duct_sock_t lfd;
    if (bind_cfg(r, &cfg, &lfd) != rc_ok)
        return "the bind failed";
    duct_sock_t c1 = th_local_connect(path),
                c2 = th_local_connect(path),
                c3 = duct_sock_bad,
                c4 = duct_sock_bad;
    const char *error = nullptr;
    if (c1 == duct_sock_bad || c2 == duct_sock_bad)
        error = "connect failed";
    if (!error)
        error = s_echo(c1, "a", 1u);
    if (!error)
        error = s_echo(c2, "b", 1u);
    if (!error && !s_sessions(2))
        error = "two sessions were not counted";
    unsigned free_before = duct_conns_free();
    if (!error) {
        c3 = th_local_connect(path);
        if (c3 == duct_sock_bad)
            error = "the third connect failed outright";
        else if (!th_peer_closed(c3, 1500))
            error = "a third session was not closed at accept";
    }
    if (!error && duct_conns_free() != free_before)
        error = "a refused connection took a conn";
    if (!error)
        error = s_echo(c1, "c", 1u);
    if (!error) {
        duct_sock_close(c1);
        c1 = duct_sock_bad;
        if (!s_sessions(1))
            error = "a closed session was not given back";
    }
    if (!error) {
        c4 = th_local_connect(path);
        error = c4 == duct_sock_bad ? "the fourth connect failed" : s_echo(c4, "d", 1u);
    }
    duct_sock_t all[] = { c1, c2, c3, c4 };
    for (size_t i = 0u; i < sizeof all / sizeof all[0]; ++i)
        if (all[i] != duct_sock_bad)
            duct_sock_close(all[i]);
    if (!s_sessions(0) && !error)
        error = "sessions stayed open after their clients left";
    for (unsigned cycle = 0u; !error && cycle < 40u; ++cycle) {
        duct_sock_t c = th_local_connect(path);
        error = c == duct_sock_bad ? "a cycle's connect failed" : s_echo(c, "e", 1u);
        if (c != duct_sock_bad)
            duct_sock_close(c);
        if (!error && !s_sessions(0))
            error = "a cycle's session did not close";
    }
    duct_discard duct_listener_close(r->e, lfd);
    return error;
}

/** @brief One non-blocking connect to @p path with no retry.
 *  @return the socket when the kernel queued it, @c duct_sock_bad when it did not. */
static duct_sock_t s_queue_one(const char *path)
{
    struct sockaddr_un sa;
    th_local_fill(&sa, path);
    duct_sock_t fd = (duct_sock_t)socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == duct_sock_bad)
        return duct_sock_bad;
#ifdef _WIN32
    u_long nonblock = 1u;
    ioctlsocket(fd, FIONBIO, &nonblock);
    bool queued = connect(fd, (struct sockaddr *)&sa, (int)sizeof sa) == 0
               || WSAGetLastError() == WSAEWOULDBLOCK;
#else
    fcntl(fd, F_SETFL, O_NONBLOCK);
    bool queued = connect(fd, (struct sockaddr *)&sa, sizeof sa) == 0;
#endif
    if (queued)
        return fd;
    duct_sock_close(fd);
    return duct_sock_bad;
}

/** @brief With max_conns_per_s a path listener takes one connection every 1/N s: the second of two
 *  that arrive together is answered a window after the first, and the kernel's queue behind it is
 *  short, so a third is refused at its connect and takes nothing of the engine. */
static const char *sc_pace(rig_t *r)
{
    char path[th_local_path_max];
    th_local_path(path, sizeof path, "pace");
    auto cfg = local_cfg(r, path);
    cfg.max_conns_per_s = 4u;
    duct_sock_t lfd;
    if (bind_cfg(r, &cfg, &lfd) != rc_ok)
        return "the bind failed";
    uint64_t t0 = duct_ticks_mono_ns();
    duct_sock_t c1 = th_local_connect(path),
                c2 = duct_sock_bad,
                more[8];
    unsigned queued = 0u;
    const char *error = c1 == duct_sock_bad ? "connect failed" : s_echo(c1, "a", 1u);
    if (!error) {
        c2 = th_local_connect(path);
        error = c2 == duct_sock_bad ? "the second connect failed" : nullptr;
    }
    if (!error && (duct_ticks_mono_ns() - t0) / 1'000'000u < 150u) {
        while (queued < sizeof more / sizeof more[0] && (more[queued] = s_queue_one(path)) != duct_sock_bad)
            ++queued;
        if (queued == sizeof more / sizeof more[0])
            error = "the queue behind a held listener does not end";
    }
    if (!error)
        error = s_echo(c2, "b", 1u);
    uint64_t took = (duct_ticks_mono_ns() - t0) / 1'000'000u;
    if (!error && took < 240u)
        error = "the second connection was answered inside the window of the first";
    for (unsigned i = 0u; i < queued; ++i)
        duct_sock_close(more[i]);
    if (c1 != duct_sock_bad)
        duct_sock_close(c1);
    if (c2 != duct_sock_bad)
        duct_sock_close(c2);
    if (!error && !s_sessions(0))
        error = "sessions stayed open after their clients left";
    duct_discard duct_listener_close(r->e, lfd);
    return error;
}

/** @brief A close of a listener that holds its accepts takes the path at once, leaves the live
 *  session its socket and lets the held window run out with nothing left to open. */
static const char *sc_pace_close(rig_t *r)
{
    char path[th_local_path_max];
    th_local_path(path, sizeof path, "paceclose");
    auto cfg = local_cfg(r, path);
    cfg.max_conns_per_s = 1u;
    duct_sock_t lfd;
    if (bind_cfg(r, &cfg, &lfd) != rc_ok)
        return "the bind failed";
    duct_sock_t c = th_local_connect(path);
    const char *error = c == duct_sock_bad ? "connect failed" : s_echo(c, "one", 3u);
    if (!error && duct_listener_close(r->e, lfd) != rc_ok)
        error = "the close failed";
    if (!error && s_exists(path))
        error = "the path stands after the close";
    if (!error)
        error = s_echo(c, "two", 3u);
    th_sleep_ms(1200u);
    if (!error)
        error = s_echo(c, "three", 5u);
    if (c != duct_sock_bad)
        duct_sock_close(c);
    if (!error && !s_sessions(0))
        error = "the session did not end with its client";
    return error;
}

#ifdef _WIN32
/** @brief A mode and a group do not apply here, and a bind that asks for either is refused. */
static const char *sc_access(rig_t *r)
{
    char path[th_local_path_max];
    th_local_path(path, sizeof path,"access");
    auto cfg = local_cfg(r, path);
    duct_sock_t lfd;
    cfg.local_mode = 0600u;
    if (bind_cfg(r, &cfg, &lfd) == rc_ok) {
        duct_discard duct_listener_close(r->e, lfd);
        return "a mode was taken where none applies";
    }
    cfg.local_mode = 0u;
    cfg.local_group = "users";
    if (bind_cfg(r, &cfg, &lfd) == rc_ok) {
        duct_discard duct_listener_close(r->e, lfd);
        return "a group was taken where none applies";
    }
    return s_exists(path) ? "a refused bind left a file behind" : nullptr;
}
#else
/** @brief The group and the mode land on the file; an unknown group refuses the bind, leaves no
 *  file and takes no stale socket away; a group given as a number is read as one, and as text it
 *  is looked up. */
static const char *sc_access(rig_t *r)
{
    char path[th_local_path_max], group[24];
    th_local_path(path, sizeof path,"access");
    snprintf(group, sizeof group, "%u", (unsigned)getgid());
    auto cfg = local_cfg(r, path);
    cfg.local_mode = 0600u;
    cfg.local_group = group;
    duct_sock_t lfd;
    if (bind_cfg(r, &cfg, &lfd) != rc_ok)
        return "the bind with the process's own group failed";
    struct stat st;
    const char *error = nullptr;
    if (lstat(path, &st) != 0)
        error = "no file after the bind";
    else if ((st.st_mode & 0777) != 0600)
        error = "the mode is not the one asked for";
    else if (st.st_gid != getgid())
        error = "the group is not the one asked for";
    duct_discard duct_listener_close(r->e, lfd);
    if (error)
        return error;
    /* The same group by its name, which the group database has to answer. */
    struct group *own = getgrgid(getgid());
    if (own) {
        cfg.local_group = own->gr_name;
        if (bind_cfg(r, &cfg, &lfd) != rc_ok)
            return "the bind with the process's own group by name failed";
        if (lstat(path, &st) != 0 || st.st_gid != getgid())
            error = "the group given by name is not the one on the file";
        duct_discard duct_listener_close(r->e, lfd);
        if (error)
            return error;
    }
    static const char *const refused[] = { "duct-no-such-group-0", "0123", "+5", "12x" };
    for (size_t i = 0u; i < sizeof refused / sizeof refused[0]; ++i) {
        cfg.local_group = refused[i];
        if (bind_cfg(r, &cfg, &lfd) == rc_ok) {
            duct_discard duct_listener_close(r->e, lfd);
            return "a group that is neither a name nor a plain number was accepted";
        }
        if (s_exists(path))
            return "a refused bind left a file behind";
        s_make_stale(path);
        if (bind_cfg(r, &cfg, &lfd) == rc_ok) {
            duct_discard duct_listener_close(r->e, lfd);
            return "a group that is neither a name nor a plain number was accepted over a stale socket";
        }
        bool stale_stands = s_is_socket(path);
        remove(path);
        if (!stale_stands)
            return "a refused group took the stale socket away";
    }
    return nullptr;
}
#endif

/** @brief Arguments the bind refuses before it touches a path. */
static const char *sc_args(rig_t *r)
{
    char path[th_local_path_max], too_long[200];
    th_local_path(path, sizeof path,"args");
    memset(too_long, 'x', sizeof too_long - 1u);
    too_long[sizeof too_long - 1u] = '\0';
    duct_sock_t fd;
    uint16_t port = 0u;
    unsigned n = 0u;

    auto both = local_cfg(r, path);
    both.addr = "127.0.0.1";
    if (duct_listener_bind(r->e, &both, &port, &fd, 1u, &n) != rc_invalid_arg)
        return "a path together with a host was not refused";

    auto stray = (duct_listener_cfg_t){
        .addr = "127.0.0.1", .n_protos = 1u, .protos = r->protos, .local_mode = 0600u,
    };
    if (duct_listener_bind(r->e, &stray, &port, &fd, 1u, &n) != rc_invalid_arg)
        return "a mode on an IP listener was not refused";

    auto paced = (duct_listener_cfg_t){
        .addr = "127.0.0.1", .n_protos = 1u, .protos = r->protos, .max_conns_per_s = 1u,
    };
    if (duct_listener_bind(r->e, &paced, &port, &fd, 1u, &n) != rc_invalid_arg)
        return "a rate on an IP listener was not refused";

    auto dgram = local_cfg(r, path);
    dgram.kind = listener_dgram;
    if (duct_listener_bind(r->e, &dgram, &port, &fd, 1u, &n) != rc_invalid_arg)
        return "a path on a datagram listener was not refused";

    auto longer = local_cfg(r, too_long);
    if (duct_listener_bind(r->e, &longer, &port, &fd, 1u, &n) != rc_invalid_arg)
        return "a path past sun_path was not refused";

    auto empty = local_cfg(r, "");
    if (duct_listener_bind(r->e, &empty, &port, &fd, 1u, &n) != rc_invalid_arg)
        return "an empty path was not refused";
    return nullptr;
}

/** @brief The engine stops with a listener bound and a session live: the path goes with it. */
static const char *sc_teardown(void)
{
    rig_t r = {};
    if (!rig_up(&r))
        return "engine or protocol create failed";
    char path[th_local_path_max];
    th_local_path(path, sizeof path,"teardown");
    auto cfg = local_cfg(&r, path);
    cfg.max_conns_per_s = 1u;
    duct_sock_t lfd;
    const char *error = bind_cfg(&r, &cfg, &lfd) != rc_ok ? "the bind failed" : nullptr;
    duct_sock_t c = duct_sock_bad;
    if (!error) {
        c = th_local_connect(path);
        error = c == duct_sock_bad ? "connect failed" : s_echo(c, "up", 2u);
    }
    rig_down(&r);
    if (c != duct_sock_bad)
        duct_sock_close(c);
    if (!error && s_exists(path)) {
        error = "the path stands after the engine is gone";
        remove(path);
    }
    return error;
}

/** @brief Below the floor of the build the bind says so, and leaves no file. */
static const char *sc_floor(rig_t *r)
{
    char path[th_local_path_max];
    th_local_path(path, sizeof path,"floor");
    auto cfg = local_cfg(r, path);
    duct_sock_t lfd;
    duct_result_t rc = bind_cfg(r, &cfg, &lfd);
    if (rc == rc_ok)
        duct_discard duct_listener_close(r->e, lfd);
    if (rc != rc_not_supported)
        return "a bind below the floor did not answer rc_not_supported";
    return s_exists(path) ? "a refused bind left a file behind" : nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    rig_t rig = {};
    if (!rig_up(&rig)) {
        fprintf(stderr, "local_listener: engine or protocol create failed\n");
        return 1;
    }
    static const struct {
        const char *name;
        const char *(*run)(rig_t *);
    } scenarios[] = {
        { "serves", sc_serves }, { "stale", sc_stale }, { "live", sc_live },
        { "other", sc_other }, { "inode", sc_inode }, { "close_live", sc_close_live },
        { "cap", sc_cap }, { "pace", sc_pace }, { "pace_close", sc_pace_close },
        { "access", sc_access }, { "args", sc_args },
    };
    int failed = 0;
    if (!local_floor) {
        const char *error = sc_floor(&rig);
        printf("local_listener: %-10s %s%s\n", "floor", error ? "FAILED: " : "ok", error ? error : "");
        failed += error != nullptr;
    } else {
        for (size_t i = 0u; i < sizeof scenarios / sizeof scenarios[0]; ++i) {
            const char *error = scenarios[i].run(&rig);
            printf("local_listener: %-10s %s%s\n", scenarios[i].name, error ? "FAILED: " : "ok",
                   error ? error : "");
            failed += error != nullptr;
        }
    }
    rig_down(&rig);
    if (local_floor) {
        const char *error = sc_teardown();
        printf("local_listener: %-10s %s%s\n", "teardown", error ? "FAILED: " : "ok", error ? error : "");
        failed += error != nullptr;
    }
    if (failed) {
        fprintf(stderr, "local_listener: %d scenario(s) failed\n", failed);
        return 1;
    }
    printf("local_listener: OK\n");
    return 0;
}
