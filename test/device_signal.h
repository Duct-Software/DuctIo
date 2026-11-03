/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file device_signal.h
 * @brief The waitable handle a test's fake device hands the engine: an
 * auto-reset event on Windows, an eventfd on Linux, a pipe on other POSIX
 * systems, Darwin among them.
 *
 * th_signal_open answers 0 on failure. A pipe's read end is the handle, and
 * its write end rides in a table indexed by it. Include after "duct.h".
 */

#ifndef DUCT_TEST_DEVICE_SIGNAL_H
#define DUCT_TEST_DEVICE_SIGNAL_H

#include <stdbool.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>

typedef HANDLE th_signal_t;

static inline th_signal_t th_signal_open(void)
{
    return CreateEventW(nullptr, FALSE, FALSE, nullptr);
}

static inline bool th_signal_raise(th_signal_t d) { return SetEvent(d) != 0; }

static inline void th_signal_drain([[maybe_unused]] th_signal_t d) {}

/** @brief Raise @p d and take the signal back: true while the handle lives. */
static inline bool th_signal_alive(th_signal_t d)
{
    return SetEvent(d) != 0 && WaitForSingleObject(d, 0u) == WAIT_OBJECT_0;
}

static inline void th_signal_close(th_signal_t d) { CloseHandle(d); }

#elif defined(__linux__)
#include <sys/eventfd.h>
#include <unistd.h>

typedef int th_signal_t;

static inline th_signal_t th_signal_open(void)
{
    int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    return fd < 0 ? 0 : fd;
}

static inline bool th_signal_raise(th_signal_t d)
{
    uint64_t one = 1u;
    return write(d, &one, sizeof one) == (ssize_t)sizeof one;
}

static inline void th_signal_drain(th_signal_t d)
{
    uint64_t v = 0u;
    while (read(d, &v, sizeof v) > 0)
        ;
}

/** @brief Raise @p d and take the signal back: true while the handle lives. */
static inline bool th_signal_alive(th_signal_t d)
{
    uint64_t v = 0u;
    return th_signal_raise(d) && read(d, &v, sizeof v) == (ssize_t)sizeof v;
}

static inline void th_signal_close(th_signal_t d) { close(d); }

#else
#include <fcntl.h>
#include <unistd.h>

typedef int th_signal_t;

/** @brief Bound on a pipe's read end, the size of the write-end table. */
static constexpr int th_signal_fds = 1024;

/** @brief Write end of the pipe whose read end indexes it. */
static int th_signal_wr[th_signal_fds];

static inline th_signal_t th_signal_open(void)
{
    int fds[2];
    if (pipe(fds) != 0)
        return 0;
    if (fds[0] >= th_signal_fds) {
        close(fds[0]);
        close(fds[1]);
        return 0;
    }
    for (unsigned i = 0u; i < 2u; ++i) {
        fcntl(fds[i], F_SETFL, fcntl(fds[i], F_GETFL, 0) | O_NONBLOCK);
        fcntl(fds[i], F_SETFD, FD_CLOEXEC);
    }
    th_signal_wr[fds[0]] = fds[1];
    return fds[0];
}

static inline bool th_signal_raise(th_signal_t d)
{
    uint8_t one = 1u;
    return write(th_signal_wr[d], &one, sizeof one) == (ssize_t)sizeof one;
}

static inline void th_signal_drain(th_signal_t d)
{
    uint8_t buf[64];
    while (read(d, buf, sizeof buf) > 0)
        ;
}

/** @brief Raise @p d and take the signal back: true while the handle lives. */
static inline bool th_signal_alive(th_signal_t d)
{
    uint8_t v = 0u;
    return th_signal_raise(d) && read(d, &v, sizeof v) == (ssize_t)sizeof v;
}

static inline void th_signal_close(th_signal_t d)
{
    close(th_signal_wr[d]);
    close(d);
}

#endif

#endif /* DUCT_TEST_DEVICE_SIGNAL_H */
