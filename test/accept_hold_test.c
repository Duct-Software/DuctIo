/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file accept_hold_test.c
 *  @brief A stream listener out of descriptors parks with its queue, spends no CPU, and
 *  takes one queued client each time the engine closes a socket.
 *
 *  The process lowers its descriptor limit to s_limit, serves s_served clients, takes
 *  every number left and connects s_waiting more, whose accepts meet EMFILE. Pass: the
 *  process spends at most s_idle_cap_ns of CPU over s_idle_ms with clients queued; no
 *  queued client is served while every number is taken; and each served client that
 *  hangs up, its own descriptor kept, lets exactly one queued client through to its echo.
 *  Two io threads each hold a node of the listener, so a close on one thread resumes a
 *  node parked on the other.
 */

#include "duct.h"
#include "duct_core.h"
#include "test_helpers.h"

#include <fcntl.h>
#include <limits.h>
#include <sys/resource.h>
#include <unistd.h>

static constexpr rlim_t s_limit = 256u;
static constexpr unsigned s_served = 4u;
static constexpr unsigned s_waiting = 4u;
static constexpr unsigned s_clients = s_served + s_waiting;
static constexpr unsigned s_idle_ms = 500u;
static constexpr uint64_t s_idle_cap_ns = 50'000'000u;
static constexpr int s_echo_ms = 3000;
static const char s_msg[] = "held-then-served";

static uint16_t s_port;
static struct sockaddr_in s_addr;
static duct_sock_t s_client[s_clients];
static unsigned s_made;
static bool s_echoed[s_clients];
static int s_fill[s_limit];
static unsigned s_filled;

static duct_result_t on_frame([[maybe_unused]] duct_session_t *s,
                              [[maybe_unused]] duct_conn_id_t conn_id,
                              const duct_frame_t *frame, duct_response_t *out,
                              [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

/** @brief Process CPU time, user and kernel together, nanoseconds. */
static uint64_t s_cpu_ns(void)
{
    duct_cpu_time_t cpu = duct_process_cpu();
    return cpu.user_ns + cpu.kernel_ns;
}

/** @brief Make every client socket ahead of the fill. */
static bool s_make_clients(void)
{
    for (; s_made < s_clients; ++s_made) {
        s_client[s_made] = socket(AF_INET, SOCK_STREAM, 0);
        if (s_client[s_made] == duct_sock_bad) {
            perror("accept_hold: client socket");
            return false;
        }
    }
    return true;
}

/** @brief Connect client @p i and send it its frame. */
static bool s_connect_send(unsigned i)
{
    if (connect(s_client[i], (struct sockaddr *)&s_addr, sizeof s_addr) == 0
        && th_send(s_client[i], s_msg, sizeof s_msg - 1u) == 0)
        return true;
    fprintf(stderr, "accept_hold: client %u connect or send failed, errno %d\n", i, errno);
    return false;
}

/** @brief Serve the first s_served clients, each to its echo. */
static bool s_serve_first(void)
{
    for (unsigned i = 0u; i < s_served; ++i) {
        if (!s_connect_send(i))
            return false;
        if (th_recv_eq(s_client[i], s_msg, sizeof s_msg - 1u) != 0) {
            fprintf(stderr, "accept_hold: client %u not served before the fill\n", i);
            return false;
        }
    }
    return true;
}

/** @brief Take every number left under the limit. */
static bool s_fill_up(void)
{
    for (int fd; (fd = open("/dev/null", O_RDONLY | O_CLOEXEC)) >= 0; )
        s_fill[s_filled++] = fd;
    if (errno == EMFILE)
        return true;
    perror("accept_hold: fill");
    return false;
}

/** @brief Connect the queued clients, each sending its frame at once. */
static bool s_queue_rest(void)
{
    for (unsigned i = s_served; i < s_clients; ++i)
        if (!s_connect_send(i))
            return false;
    return true;
}

/** @brief Wait up to @p timeout_ms for one queued client's echo.
 *  @return its index, or UINT_MAX when none arrives or the echo is wrong. */
static unsigned s_next_echo(int timeout_ms)
{
    struct pollfd pfd[s_waiting];
    unsigned idx[s_waiting],
             n = 0u;
    for (unsigned i = s_served; i < s_clients; ++i)
        if (!s_echoed[i]) {
            pfd[n] = (struct pollfd){ .fd = s_client[i], .events = POLLIN };
            idx[n++] = i;
        }
    if (n == 0u || poll(pfd, n, timeout_ms) <= 0)
        return UINT_MAX;
    for (unsigned k = 0u; k < n; ++k)
        if (pfd[k].revents & POLLIN) {
            unsigned i = idx[k];
            if (th_recv_eq(s_client[i], s_msg, sizeof s_msg - 1u) != 0)
                return UINT_MAX;
            s_echoed[i] = true;
            return i;
        }
    return UINT_MAX;
}

/** @brief Measure the CPU over a stretch with clients queued, and see none served. */
static bool s_idle(void)
{
    uint64_t start = s_cpu_ns();
    th_sleep_ms(s_idle_ms);
    uint64_t spent = s_cpu_ns() - start;
    printf("accept_hold: %.2f ms cpu over %u ms with %u clients queued\n",
           (double)spent / 1e6, s_idle_ms, s_waiting);
    if (spent > s_idle_cap_ns) {
        fprintf(stderr, "accept_hold: idle cpu %.2f ms, cap %.2f ms\n",
                (double)spent / 1e6, (double)s_idle_cap_ns / 1e6);
        return false;
    }
    if (s_next_echo(0) != UINT_MAX) {
        fprintf(stderr, "accept_hold: a queued client was served with every number taken\n");
        return false;
    }
    return true;
}

/** @brief Hang up the served clients one at a time, each letting one queued client through.
 *  shutdown keeps the client's own descriptor, so the engine's close frees the only number. */
static bool s_release_each(void)
{
    for (unsigned i = 0u; i < s_served; ++i) {
        shutdown(s_client[i], SHUT_RDWR);
        if (s_next_echo(s_echo_ms) == UINT_MAX) {
            fprintf(stderr, "accept_hold: no queued client served after client %u hung up\n", i);
            return false;
        }
        if (s_next_echo(200) != UINT_MAX) {
            fprintf(stderr, "accept_hold: two queued clients served after client %u hung up\n", i);
            return false;
        }
    }
    printf("accept_hold: %u queued clients served, one per close\n", s_served);
    return true;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    if (setrlimit(RLIMIT_NOFILE, &(struct rlimit){ s_limit, s_limit }) != 0) {
        perror("accept_hold: lower the limit");
        return 1;
    }
    auto e = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 2u, .workers = 2u });
    auto wire = duct_wire_create_length_prefix(1024u);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "accept_hold", .wire = wire, .on_frame = on_frame,
    }) : nullptr;
    auto rc = e && proto ? duct_io_listen(e, "127.0.0.1", &s_port, proto) : rc_fatal;
    bool ok = rc == rc_ok;
    if (!ok)
        fprintf(stderr, "accept_hold: setup failed: engine %s, proto %s, listen %d\n",
                e ? "up" : "down", proto ? "made" : "missing", (int)rc);
    s_addr = (struct sockaddr_in){ .sin_family = AF_INET, .sin_port = htons(s_port) };
    inet_pton(AF_INET, "127.0.0.1", &s_addr.sin_addr);

    ok = ok && s_make_clients() && s_serve_first() && s_fill_up() && s_queue_rest()
            && s_idle() && s_release_each();

    for (unsigned i = 0u; i < s_made; ++i)
        duct_sock_close(s_client[i]);
    for (unsigned i = 0u; i < s_filled; ++i)
        close(s_fill[i]);
    if (e)
        duct_engine_destroy(e);
    if (proto)
        duct_proto_destroy(proto);
    if (wire)
        duct_wire_destroy(wire);
    if (ok)
        printf("accept_hold: OK\n");
    return ok ? 0 : 1;
}
