/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file egress_if_test.c
 * @brief The interface index a dial names is the one its socket is bound to.
 *
 * Each scenario runs once for a stream dial and once for a datagram dial, and
 * reads the binding off the process's own descriptors:
 * - loopback: a dial naming the loopback interface opens its session with one
 *   socket bound to it, and the same dial naming none binds nothing;
 * - absent: a dial naming an index no interface holds fails through on_error;
 * - leg: a leg a session dials through open_leg binds the same way, and fails
 *   the same way on an absent index.
 *
 * The primitive under test is SO_BINDTODEVICE on Linux, which reads the binding
 * back by name off /proc/self/fd, and IP_BOUND_IF on Darwin, which reads it back
 * by index off every descriptor up to the open-file limit.
 */

#include "duct.h"
#include "test_helpers.h"

#ifdef __APPLE__
#include <netinet/in.h>
#else
#include <dirent.h>
#endif
#include <net/if.h>
#include <stdatomic.h>

duct_wire_t *duct_wire_create_dgram_batch(size_t max_dgram, bool framed);

static constexpr unsigned wait_ms = 3000u;
static constexpr uint32_t absent_if = 0x7ffffff0u;

static atomic_int  g_cli_open;
static atomic_int  g_cli_err_count;
static atomic_int  g_leg_joined;
static atomic_uint g_leg_if;
static atomic_bool g_leg_dgram;
static char        g_addr[64];

static void s_reset(void)
{
    duct_atomic_store(&g_cli_open, 0, relaxed);
    duct_atomic_store(&g_cli_err_count, 0, relaxed);
    duct_atomic_store(&g_leg_joined, 0, relaxed);
}

static duct_result_t
srv_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             const duct_frame_t *frame, duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

static duct_result_t
cli_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             [[maybe_unused]] const duct_frame_t *frame, [[maybe_unused]] duct_response_t *out,
             [[maybe_unused]] void *proto_state)
{
    return rc_ok;
}

static duct_result_t
cli_on_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_cli_open, 1, release);
    return rc_ok;
}

/** @brief Open, then dial a second leg naming the interface in @c g_leg_if. */
static duct_result_t
cli_on_open_dial([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
                 [[maybe_unused]] void *user_ctx, duct_response_t *out,
                 [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_cli_open, 1, release);
    out->control.open_leg.kind = duct_atomic_load(&g_leg_dgram, acquire) ? leg_kind_connect_dgram
                                                                         : leg_kind_connect;
    out->control.open_leg.conn_id = 1u;
    out->control.open_leg.connect_addr = g_addr;
    out->control.open_leg.egress_if = duct_atomic_load(&g_leg_if, acquire);
    return rc_ok;
}

static duct_result_t
cli_on_error([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_result_t error,
             [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_cli_err_count, 1, release);
    return rc_ok;
}

static duct_result_t
cli_on_join([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
            [[maybe_unused]] const duct_peer_t *peer, [[maybe_unused]] duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    if (conn_id != duct_conn_id_primary)
        duct_atomic_fetch(add, &g_leg_joined, 1, release);
    return rc_ok;
}

#ifdef __APPLE__
/** @brief The loopback interface's name. */
static const char s_lo[] = "lo0";

/** @brief Count this process's sockets bound to the interface @p name. */
static unsigned s_bound_to(const char *name)
{
    unsigned want = if_nametoindex(name),
             n = 0u;
    long top = sysconf(_SC_OPEN_MAX);
    if (!want || top <= 0)
        return 0u;
    for (int fd = 0; fd < (int)(top < 65536 ? top : 65536); ++fd) {
        unsigned bound = 0u;
        socklen_t len = sizeof bound;
        if (getsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &bound, &len) == 0 && bound == want)
            ++n;
    }
    return n;
}
#else
/** @brief The loopback interface's name. */
static const char s_lo[] = "lo";

/** @brief Count this process's sockets bound to the device @p name. */
static unsigned s_bound_to(const char *name)
{
    DIR *dir = opendir("/proc/self/fd");
    unsigned n = 0u;
    for (struct dirent *e; dir && (e = readdir(dir));) {
        int fd = atoi(e->d_name);
        char bound[IF_NAMESIZE] = {};
        socklen_t len = sizeof bound;
        if (e->d_name[0] != '.' && getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, bound, &len) == 0
            && strcmp(bound, name) == 0)
            ++n;
    }
    if (dir)
        closedir(dir);
    return n;
}
#endif

typedef struct {
    duct_engine_t *io;
    duct_proto_t  *srv, *cli;
    pthread_t      th;
    uint16_t       port;
    bool           running;
} rig_t;

/** @brief An engine with a stream or datagram listener on loopback and a client protocol. */
static bool s_rig_up(rig_t *r, bool dgram, duct_session_open_fn client_open)
{
    *r = (rig_t){};
    r->io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!r->io)
        return false;
    auto srv_wire = dgram ? duct_wire_create_dgram_batch(0u, false) : duct_wire_create_length_prefix(0u);
    auto cli_wire = dgram ? duct_wire_create_dgram_batch(0u, false) : duct_wire_create_length_prefix(0u);
    r->srv = duct_proto_create(&(duct_proto_cfg_t){
        .name = "egress-srv", .wire = srv_wire, .on_frame = srv_on_frame,
    });
    r->cli = duct_proto_create(&(duct_proto_cfg_t){
        .name = "egress-cli", .wire = cli_wire, .on_frame = cli_on_frame,
        .on_session_open = client_open, .on_error = cli_on_error, .on_conn_join = cli_on_join,
        .connect_timeout_ms = 1000u,
    });
    if (r->srv)
        r->srv->owned_wire = srv_wire;
    else
        duct_wire_destroy(srv_wire);
    if (r->cli)
        r->cli->owned_wire = cli_wire;
    else
        duct_wire_destroy(cli_wire);
    bool ok = r->srv && r->cli;
    if (ok)
        ok = dgram ? duct_listener_bind(r->io, &(duct_listener_cfg_t){ .kind = listener_dgram,
                         .addr = "127.0.0.1", .n_protos = 1, .protos = (const duct_proto_t *[]){ r->srv },
                     }, &r->port, nullptr, 0u, nullptr) == rc_ok
                   : duct_io_listen(r->io, "127.0.0.1", &r->port, r->srv) == rc_ok;
    r->running = ok && pthread_create(&r->th, nullptr, th_run, r->io) == 0;
    return r->running;
}

static void s_rig_down(rig_t *r)
{
    if (r->running) {
        duct_engine_stop(r->io);
        pthread_join(r->th, nullptr);
    }
    if (r->io)
        duct_engine_destroy(r->io);
    duct_proto_destroy(r->srv);
    duct_proto_destroy(r->cli);
}

/** @brief Dial the rig's listener naming @p egress, retrying past the engine's start. */
static duct_result_t s_dial(rig_t *r, bool dgram, uint32_t egress)
{
    snprintf(g_addr, sizeof g_addr, "127.0.0.1:%u", (unsigned)r->port);
    duct_result_t rc = rc_invalid_order;
    for (unsigned waited = 0u; waited < wait_ms && rc == rc_invalid_order; waited += 5u) {
        rc = duct_io_connect_via(r->io, g_addr, r->cli, nullptr, dgram ? x_udp_peer : x_tcp, egress,
                                 (duct_view_u8){});
        if (rc == rc_invalid_order)
            th_sleep_ms(5u);
    }
    return rc;
}

static const char *sc_loopback(bool dgram)
{
    s_reset();
    rig_t r;
    const char *err = nullptr;
    uint32_t lo = if_nametoindex(s_lo);
    if (!s_rig_up(&r, dgram, cli_on_open) || !lo)
        err = "rig failed";
    else if (s_dial(&r, dgram, lo) != rc_ok)
        err = "the dial was refused at the call";
    else if (!th_wait_int(&g_cli_open, 1, wait_ms))
        err = "a dial naming the loopback never opened its session";
    else if (s_bound_to(s_lo) != 1u)
        err = "a dial naming the loopback left no socket bound to it";
    else if (s_dial(&r, dgram, 0u) != rc_ok || !th_wait_int(&g_cli_open, 2, wait_ms))
        err = "a dial naming none never opened its session";
    else if (s_bound_to(s_lo) != 1u)
        err = "a dial naming none bound a socket";
    s_rig_down(&r);
    return err;
}

static const char *sc_absent(bool dgram)
{
    s_reset();
    rig_t r;
    const char *err = nullptr;
    if (!s_rig_up(&r, dgram, cli_on_open))
        err = "rig failed";
    else if (s_dial(&r, dgram, absent_if) != rc_ok)
        err = "the dial was refused at the call, not through on_error";
    else if (!th_wait_int(&g_cli_err_count, 1, wait_ms))
        err = "a dial naming an absent interface never failed";
    else if (duct_atomic_load(&g_cli_open, acquire) != 0)
        err = "a dial naming an absent interface opened a session";
    s_rig_down(&r);
    return err;
}

/** @brief A session opened without an interface dials its second leg naming @p egress. */
static const char *s_leg(bool dgram, uint32_t egress, bool want_joined)
{
    s_reset();
    duct_atomic_store(&g_leg_if, egress, release);
    duct_atomic_store(&g_leg_dgram, dgram, release);
    rig_t r;
    const char *err = nullptr;
    if (!s_rig_up(&r, dgram, cli_on_open_dial))
        err = "rig failed";
    else if (s_dial(&r, dgram, 0u) != rc_ok)
        err = "the session dial was refused at the call";
    else if (!th_wait_int(&g_cli_open, 1, wait_ms))
        err = "the session never opened";
    else if (want_joined && !th_wait_int(&g_leg_joined, 1, wait_ms))
        err = "a leg naming the loopback never joined";
    else if (want_joined && s_bound_to(s_lo) != 1u)
        err = "a leg naming the loopback left no socket bound to it";
    else if (!want_joined && !th_wait_int(&g_cli_err_count, 1, wait_ms))
        err = "a leg naming an absent interface never failed";
    s_rig_down(&r);
    return err;
}

static const char *sc_leg(bool dgram)
{
    const char *err = s_leg(dgram, if_nametoindex(s_lo), true);
    return err ? err : s_leg(dgram, absent_if, false);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    static const struct {
        const char *name;
        const char *(*run)(bool dgram);
    } scenarios[] = {
        { "loopback", sc_loopback },
        { "absent",   sc_absent },
        { "leg",      sc_leg },
    };
    int failed = 0;
    for (unsigned i = 0u; i < sizeof scenarios / sizeof scenarios[0]; ++i)
        for (unsigned d = 0u; d < 2u; ++d) {
            const char *err = scenarios[i].run(d != 0u);
            if (err) {
                fprintf(stderr, "egress_if: %s %s: %s\n", scenarios[i].name, d ? "datagram" : "stream", err);
                ++failed;
            } else
                printf("egress_if: %s %s OK\n", scenarios[i].name, d ? "datagram" : "stream");
        }
    return failed ? 1 : 0;
}
