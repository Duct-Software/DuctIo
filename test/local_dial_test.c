/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file local_dial_test.c
 * @brief The x_local dial: a session that opens on a path, trades bytes both ways and closes; what
 *  a dial that fails reports; a request that arrives split across reads, on a dialled conn and on a
 *  listened one; the idle bound on a silent peer; the engine stopping with a dialled session live.
 *
 * One engine plays every part. Its raw echo and line protocols serve path listeners, a raw gathering
 * protocol dials, and plain AF_UNIX sockets of the test stand in for a peer that has to be slow,
 * silent or full. A Windows build below 10 1803 has no AF_UNIX: there the one thing asked is that the
 * dial says so.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) && NTDDI_VERSION < NTDDI_WIN10_RS4
static constexpr bool local_floor = false;
#else
static constexpr bool local_floor = true;
#endif

static constexpr unsigned wait_ms   = 3000u;
static constexpr size_t   bulk      = 60000u;
static constexpr unsigned idle_ms   = 200u;

/** @brief What one dial expects and finds. The worker thread writes the reply and the tallies, the
 *  test thread reads them once @c done or the tally it waits for has moved. */
typedef struct {
    atomic_int  opened, closed, errors, done, err_code, close_reason;
    const char *request;
    size_t      request_n, want;
    bool        until_newline, close_when_done;
    char        reply[bulk + 64u];
    size_t      reply_n;
} dial_t;

typedef struct {
    dial_t *dial;
} cli_state_t;

typedef struct {
    char   line[256];
    size_t n;
    char   answer[300];
} lines_state_t;

static atomic_int g_echo_closed = 0;

/** @brief A fresh dial record. Each dial takes a slot no earlier dial used, so a callback that
 *  arrives late for an earlier scenario finds its own record and not this one. */
static dial_t *dial_make(const char *request, size_t request_n, size_t want, bool until_newline,
                         bool close_when_done)
{
    static dial_t slots[16];
    static unsigned used;
    dial_t *d = &slots[used++ % (sizeof slots / sizeof slots[0])];
    memset(d, 0, sizeof *d);
    d->request = request;
    d->request_n = request_n;
    d->want = want;
    d->until_newline = until_newline;
    d->close_when_done = close_when_done;
    return d;
}

/* ── the server side: an echo and a line protocol ──────────────────────────────────────────── */

static void
echo_on_close([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_close_reason_t reason,
              [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_echo_closed, 1, release);
}

static duct_result_t
echo_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
              const duct_frame_t *frame, duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_response_echo(out, frame);
    return rc_ok;
}

static duct_result_t lines_new([[maybe_unused]] duct_session_t *s, [[maybe_unused]] void *ctx,
                               void **out)
{
    *out = calloc(1u, sizeof(lines_state_t));
    return *out ? rc_ok : rc_no_memory;
}

static void lines_free([[maybe_unused]] duct_session_t *s, [[maybe_unused]] void *ctx, void *state)
{
    free(state);
}

/** @brief Gathers a request until its newline, whatever the reads split it into, then answers
 *  "OK:" and the line and closes. */
static duct_result_t
lines_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
               const duct_frame_t *frame, duct_response_t *out, void *proto_state)
{
    auto st = (lines_state_t *)proto_state;
    for (size_t i = 0u; i < frame->payload.size; ++i) {
        char c = ((const char *)frame->payload.data)[i];
        if (st->n + 1u < sizeof st->line)
            st->line[st->n++] = c;
        if (c != '\n')
            continue;
        int len = snprintf(st->answer, sizeof st->answer, "OK:%.*s", (int)st->n, st->line);
        duct_response_respond_then_close(out, duct_view(duct_view_u8, (void *)st->answer, (size_t)len),
                                         fl_send_copy, 0, close_normal);
        return rc_ok;
    }
    return rc_ok;
}

/* ── the client side: a protocol that dials and gathers what comes back ─────────────────────── */

static duct_result_t cli_new([[maybe_unused]] duct_session_t *s, [[maybe_unused]] void *ctx,
                             void **out)
{
    *out = calloc(1u, sizeof(cli_state_t));
    return *out ? rc_ok : rc_no_memory;
}

static void cli_free([[maybe_unused]] duct_session_t *s, [[maybe_unused]] void *ctx, void *state)
{
    free(state);
}

static duct_result_t
cli_on_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok, void *user_ctx,
            duct_response_t *out, void *proto_state)
{
    auto d = (dial_t *)user_ctx;
    ((cli_state_t *)proto_state)->dial = d;
    duct_atomic_fetch(add, &d->opened, 1, release);
    if (d->request_n)
        duct_response_same(out, duct_view(duct_view_u8, (void *)d->request, d->request_n),
                           fl_send_static, 0);
    return rc_ok;
}

static duct_result_t
cli_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             const duct_frame_t *frame, duct_response_t *out, void *proto_state)
{
    auto d = ((cli_state_t *)proto_state)->dial;
    if (duct_atomic_load(&d->done, acquire))
        return rc_ok;
    size_t room = sizeof d->reply - d->reply_n,
           take = frame->payload.size < room ? frame->payload.size : room;
    memcpy(d->reply + d->reply_n, frame->payload.data, take);
    d->reply_n += take;
    bool complete = d->until_newline ? memchr(d->reply, '\n', d->reply_n) != nullptr
                                     : d->reply_n >= d->want;
    if (!complete)
        return rc_ok;
    duct_atomic_store(&d->done, 1, release);
    if (d->close_when_done)
        duct_response_close_session(out, close_normal);
    return rc_ok;
}

static void
cli_on_close([[maybe_unused]] duct_session_t *s, duct_close_reason_t reason, void *proto_state)
{
    auto d = ((cli_state_t *)proto_state)->dial;
    duct_atomic_store(&d->close_reason, (int)reason, relaxed);
    duct_atomic_fetch(add, &d->closed, 1, release);
}

/** @brief A dial that failed before a session existed: @p proto_state is the dial's @c user_ctx. */
static duct_result_t
cli_on_error(duct_session_t *s, duct_result_t error, [[maybe_unused]] duct_response_t *out,
             void *proto_state)
{
    auto d = s ? ((cli_state_t *)proto_state)->dial : (dial_t *)proto_state;
    duct_atomic_store(&d->err_code, (int)error, relaxed);
    duct_atomic_fetch(add, &d->errors, 1, release);
    return rc_ok;
}

/* ── the rig ───────────────────────────────────────────────────────────────────────────────── */

typedef struct {
    duct_engine_t      *e;
    duct_proto_t       *echo, *lines, *cli, *cli_idle;
    const duct_proto_t *echo_set[1], *lines_set[1];
    pthread_t           thread;
} rig_t;

static duct_proto_t *make_cli(const char *name, uint32_t idle_timeout_ms)
{
    return duct_proto_create(&(duct_proto_cfg_t){
        .name = name, .on_frame = cli_on_frame, .max_response = 65536u,
        .create_state = cli_new, .destroy_state = cli_free,
        .on_session_open = cli_on_open, .on_session_close = cli_on_close, .on_error = cli_on_error,
        .idle_timeout_ms = idle_timeout_ms,
    });
}

static bool rig_up(rig_t *r)
{
    r->e = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!r->e)
        return false;
    r->echo = duct_proto_create(&(duct_proto_cfg_t){
        .name = "local-echo", .on_frame = echo_on_frame, .max_response = 65536u,
        .on_session_close = echo_on_close,
    });
    r->lines = duct_proto_create(&(duct_proto_cfg_t){
        .name = "local-lines", .on_frame = lines_on_frame, .max_response = 4096u,
        .create_state = lines_new, .destroy_state = lines_free,
    });
    r->cli = make_cli("local-cli", 0u);
    r->cli_idle = make_cli("local-cli-idle", idle_ms);
    bool built = r->echo && r->lines && r->cli && r->cli_idle;
    if (!built || pthread_create(&r->thread, nullptr, th_run, r->e) != 0) {
        duct_engine_destroy(r->e);
        duct_proto_destroy(r->echo);
        duct_proto_destroy(r->lines);
        duct_proto_destroy(r->cli);
        duct_proto_destroy(r->cli_idle);
        return false;
    }
    r->echo_set[0] = r->echo;
    r->lines_set[0] = r->lines;
    return true;
}

static void rig_down(rig_t *r)
{
    duct_engine_stop(r->e);
    pthread_join(r->thread, nullptr);
    duct_engine_destroy(r->e);
    duct_proto_destroy(r->echo);
    duct_proto_destroy(r->lines);
    duct_proto_destroy(r->cli);
    duct_proto_destroy(r->cli_idle);
}

static duct_result_t bind_on(rig_t *r, const duct_proto_t *const *set, const char *path,
                             duct_sock_t *fd)
{
    duct_listener_cfg_t cfg = {
        .n_protos = 1u, .protos = set, .kind = listener_stream, .local_path = path,
    };
    uint16_t port = 0u;
    unsigned n = 0u;
    *fd = duct_sock_bad;
    return duct_listener_bind(r->e, &cfg, &port, fd, 1u, &n);
}

/** @brief Dial @p path as @c x_local, waiting out the moment before the engine runs. */
static duct_result_t dial_via(rig_t *r, duct_proto_t *proto, const char *path, dial_t *d,
                              uint32_t egress_if)
{
    duct_result_t rc = rc_invalid_order;
    for (unsigned waited = 0u; waited < TH_CONNECT_RETRY_MS && rc == rc_invalid_order; waited += 5u) {
        rc = duct_io_connect_via(r->e, path, proto, d, x_local, egress_if, (duct_view_u8){});
        if (rc == rc_invalid_order)
            th_sleep_ms(5u);
    }
    return rc;
}

static duct_result_t dial(rig_t *r, const char *path, dial_t *d)
{
    return dial_via(r, r->cli, path, d, 0u);
}

/** @brief Wait until @p value reaches @p target. */
static bool reached(atomic_int *value, int target)
{
    return th_wait_int(value, target, wait_ms);
}

/** @brief A plain stream socket listening on @p path, standing in for a peer the engine dials. */
static duct_sock_t plain_listen(const char *path, int backlog)
{
    struct sockaddr_un sa;
    th_local_fill(&sa, path);
    remove(path);
    duct_sock_t fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == duct_sock_bad)
        return duct_sock_bad;
    if (bind(fd, (struct sockaddr *)&sa, (int)sizeof sa) != 0 || listen(fd, backlog) != 0) {
        duct_sock_close(fd);
        return duct_sock_bad;
    }
    return fd;
}

static void plain_close(duct_sock_t lfd, const char *path)
{
    if (lfd != duct_sock_bad)
        duct_sock_close(lfd);
    remove(path);
}

/* ── scenarios ─────────────────────────────────────────────────────────────────────────────── */

/** @brief A session opens on a path, a small request and one many reads long come back whole, and the
 *  client's close ends the server's session too. */
static const char *sc_trade(rig_t *r)
{
    char path[th_local_path_max];
    th_local_path(path, sizeof path,"trade");
    duct_sock_t lfd;
    if (bind_on(r, r->echo_set, path, &lfd) != rc_ok)
        return "the bind failed";
    static char big[bulk];
    for (size_t i = 0u; i < sizeof big; ++i)
        big[i] = (char)('a' + i % 26u);
    const struct {
        const char *text;
        size_t      size;
    } rounds[] = { { "hello", 5u }, { big, bulk } };
    const char *error = nullptr;
    int served = duct_atomic_load(&g_echo_closed, acquire);
    for (size_t i = 0u; !error && i < sizeof rounds / sizeof rounds[0]; ++i) {
        dial_t *d = dial_make(rounds[i].text, rounds[i].size, rounds[i].size, false, true);
        if (dial(r, path, d) != rc_ok)
            error = "the dial was refused";
        else if (!reached(&d->done, 1))
            error = "the reply did not come whole";
        else if (d->reply_n != rounds[i].size || memcmp(d->reply, rounds[i].text, d->reply_n) != 0)
            error = "the reply differs from the request";
        else if (!reached(&d->closed, 1))
            error = "the client's session did not close";
        else if (!reached(&g_echo_closed, ++served))
            error = "the server's session did not close with the client's";
        else if (duct_atomic_load(&d->errors, acquire) != 0)
            error = "a good dial reported an error";
    }
    duct_discard duct_listener_close(r->e, lfd);
    return error;
}

/** @brief A path nobody listens on answers rc_conn_refused through on_error, with the dial's user_ctx. */
static const char *sc_refused(rig_t *r)
{
    char path[th_local_path_max];
    th_local_path(path, sizeof path,"refused");
    remove(path);
    dial_t *d = dial_make(nullptr, 0u, 0u, false, false);
    if (dial(r, path, d) != rc_ok)
        return "the dial was refused at the call";
    if (!reached(&d->errors, 1))
        return "no error came";
    if (duct_atomic_load(&d->err_code, acquire) != rc_conn_refused)
        return "a missing path did not answer rc_conn_refused";
    return duct_atomic_load(&d->opened, acquire) == 0 ? nullptr : "a session opened on a missing path";
}

/** @brief A regular file at the path fails the dial, and no session opens. */
static const char *sc_other(rig_t *r)
{
    char path[th_local_path_max];
    th_local_path(path, sizeof path,"other");
    remove(path);
    FILE *made = fopen(path, "w");
    if (!made)
        return "the file was not made";
    fclose(made);
    dial_t *d = dial_make(nullptr, 0u, 0u, false, false);
    const char *error = nullptr;
    if (dial(r, path, d) != rc_ok)
        error = "the dial was refused at the call";
    else if (!reached(&d->errors, 1))
        error = "no error came";
    else if (duct_atomic_load(&d->err_code, acquire) != rc_conn_refused
             && duct_atomic_load(&d->err_code, acquire) != rc_fatal)
        error = "a file at the path did not fail as a refusal or a fault";
    else if (duct_atomic_load(&d->opened, acquire) != 0)
        error = "a session opened on a regular file";
    remove(path);
    return error;
}

/** @brief What the call itself refuses: an egress interface, a path past sun_path, an empty one. */
static const char *sc_args(rig_t *r)
{
    char path[th_local_path_max], too_long[200];
    th_local_path(path, sizeof path,"args");
    memset(too_long, 'x', sizeof too_long - 1u);
    too_long[sizeof too_long - 1u] = '\0';
    dial_t *d = dial_make(nullptr, 0u, 0u, false, false);
    if (dial_via(r, r->cli, path, d, 1u) != rc_invalid_arg)
        return "an egress interface on a local dial was not refused";
    if (dial(r, too_long, d) != rc_invalid_arg)
        return "a path past sun_path was not refused";
    if (dial(r, "", d) != rc_invalid_arg)
        return "an empty path was not refused";
    if (duct_io_connect(r->e, path, r->cli, d, x_bt) != rc_invalid_arg)
        return "a transport the dial does not know was not refused";
    th_sleep_ms(50u);
    return duct_atomic_load(&d->errors, acquire) == 0 ? nullptr
                                                      : "a refused call reported through on_error";
}

#ifdef __linux__
/** @brief A listener whose backlog is full answers rc_again, and takes the dial once a place is free. */
static const char *sc_backlog(rig_t *r)
{
    char path[th_local_path_max];
    th_local_path(path, sizeof path,"backlog");
    duct_sock_t lfd = plain_listen(path, 0);
    if (lfd == duct_sock_bad)
        return "the plain listener was not made";
    duct_sock_t filler = th_local_connect(path);
    dial_t *full = dial_make(nullptr, 0u, 0u, false, false);
    const char *error = nullptr;
    if (filler == duct_sock_bad)
        error = "the backlog was not filled";
    else if (dial(r, path, full) != rc_ok)
        error = "the dial was refused at the call";
    else if (!reached(&full->errors, 1))
        error = "a full backlog reported nothing";
    else if (duct_atomic_load(&full->err_code, acquire) != rc_again)
        error = "a full backlog did not answer rc_again";
    duct_sock_t waiting = error ? duct_sock_bad : th_accept(lfd, (int)wait_ms);
    if (!error && waiting == duct_sock_bad)
        error = "the filler was not accepted";
    dial_t *again = dial_make(nullptr, 0u, 0u, false, false);
    if (!error && dial(r, path, again) != rc_ok)
        error = "the second dial was refused at the call";
    duct_sock_t second = error ? duct_sock_bad : th_accept(lfd, (int)wait_ms);
    if (!error && (second == duct_sock_bad || !reached(&again->opened, 1)))
        error = "a place given back was not taken";
    duct_sock_t held[] = { filler, waiting, second };
    for (size_t i = 0u; i < sizeof held / sizeof held[0]; ++i)
        if (held[i] != duct_sock_bad)
            duct_sock_close(held[i]);
    plain_close(lfd, path);
    return error;
}
#endif

/** @brief A request that reaches a listened conn one byte at a time is gathered and answered. */
static const char *sc_split_listened(rig_t *r)
{
    char path[th_local_path_max];
    th_local_path(path, sizeof path,"splitl");
    duct_sock_t lfd;
    if (bind_on(r, r->lines_set, path, &lfd) != rc_ok)
        return "the bind failed";
    duct_sock_t c = th_local_connect(path);
    const char *error = c == duct_sock_bad ? "connect failed" : nullptr;
    static const char request[] = "GET /stats\n";
    for (size_t i = 0u; !error && i < sizeof request - 1u; ++i) {
        if (send(c, &request[i], 1, 0) != 1)
            error = "a byte did not go";
        th_sleep_ms(3u);
    }
    static const char answer[] = "OK:GET /stats\n";
    char got[sizeof answer];
    if (!error && th_read_exact(c, got, sizeof answer - 1u) != 0)
        error = "the answer did not come";
    if (!error && memcmp(got, answer, sizeof answer - 1u) != 0)
        error = "the answer differs";
    if (!error && !th_peer_closed(c, 1500))
        error = "the session did not close after its answer";
    if (c != duct_sock_bad)
        duct_sock_close(c);
    duct_discard duct_listener_close(r->e, lfd);
    return error;
}

/** @brief A reply that reaches a dialled conn one byte at a time is gathered; the peer's close ends the
 *  session. */
static const char *sc_split_dialled(rig_t *r)
{
    char path[th_local_path_max];
    th_local_path(path, sizeof path,"splitd");
    duct_sock_t lfd = plain_listen(path, 4);
    if (lfd == duct_sock_bad)
        return "the plain listener was not made";
    dial_t *d = dial_make("who\n", 4u, 0u, true, false);
    const char *error = nullptr;
    duct_sock_t peer = duct_sock_bad;
    if (dial(r, path, d) != rc_ok)
        error = "the dial was refused at the call";
    else if ((peer = th_accept(lfd, (int)wait_ms)) == duct_sock_bad)
        error = "the dial did not arrive";
    char got[4];
    if (!error && th_read_exact(peer, got, sizeof got) != 0)
        error = "the request did not arrive";
    if (!error && memcmp(got, "who\n", sizeof got) != 0)
        error = "the request differs";
    static const char reply[] = "unit-resolver-42\n";
    for (size_t i = 0u; !error && i < sizeof reply - 1u; ++i) {
        if (send(peer, &reply[i], 1, 0) != 1)
            error = "a reply byte did not go";
        th_sleep_ms(3u);
    }
    if (!error && !reached(&d->done, 1))
        error = "the reply was not gathered";
    if (!error && (d->reply_n != sizeof reply - 1u || memcmp(d->reply, reply, d->reply_n) != 0))
        error = "the gathered reply differs";
    if (peer != duct_sock_bad)
        duct_sock_close(peer);
    if (!error && !reached(&d->closed, 1))
        error = "the peer's close did not end the session";
    plain_close(lfd, path);
    return error;
}

/** @brief A peer that stays silent is cut by idle_timeout_ms, and the session says why. */
static const char *sc_idle(rig_t *r)
{
    char path[th_local_path_max];
    th_local_path(path, sizeof path,"idle");
    duct_sock_t lfd = plain_listen(path, 4);
    if (lfd == duct_sock_bad)
        return "the plain listener was not made";
    dial_t *d = dial_make(nullptr, 0u, 0u, false, false);
    const char *error = nullptr;
    duct_sock_t peer = duct_sock_bad;
    if (dial_via(r, r->cli_idle, path, d, 0u) != rc_ok)
        error = "the dial was refused at the call";
    else if ((peer = th_accept(lfd, (int)wait_ms)) == duct_sock_bad)
        error = "the dial did not arrive";
    else if (!reached(&d->opened, 1))
        error = "the session did not open";
    else if (!reached(&d->closed, 1))
        error = "a silent peer was not cut";
    else if (duct_atomic_load(&d->close_reason, acquire) != close_timeout)
        error = "the session did not close for the idle bound";
    if (peer != duct_sock_bad)
        duct_sock_close(peer);
    plain_close(lfd, path);
    return error;
}

/** @brief The engine stops with a dialled session live: the peer sees the end of the stream. */
static const char *sc_teardown(void)
{
    rig_t r = {};
    if (!rig_up(&r))
        return "engine or protocol create failed";
    char path[th_local_path_max];
    th_local_path(path, sizeof path,"teardown");
    duct_sock_t lfd = plain_listen(path, 4);
    if (lfd == duct_sock_bad) {
        rig_down(&r);
        return "the plain listener was not made";
    }
    dial_t *d = dial_make(nullptr, 0u, 0u, false, false);
    const char *error = nullptr;
    duct_sock_t peer = duct_sock_bad;
    if (dial(&r, path, d) != rc_ok)
        error = "the dial was refused at the call";
    else if ((peer = th_accept(lfd, (int)wait_ms)) == duct_sock_bad)
        error = "the dial did not arrive";
    else if (!reached(&d->opened, 1))
        error = "the session did not open";
    rig_down(&r);
    if (!error && !th_peer_closed(peer, 1500))
        error = "the peer did not see the stream end with the engine";
    if (peer != duct_sock_bad)
        duct_sock_close(peer);
    plain_close(lfd, path);
    return error;
}

/** @brief Below the floor of the build the dial says so, and no session or error follows. */
static const char *sc_floor(rig_t *r)
{
    char path[th_local_path_max];
    th_local_path(path, sizeof path,"floor");
    dial_t *d = dial_make(nullptr, 0u, 0u, false, false);
    if (dial(r, path, d) != rc_not_supported)
        return "a dial below the floor did not answer rc_not_supported";
    th_sleep_ms(50u);
    return duct_atomic_load(&d->errors, acquire) == 0 && duct_atomic_load(&d->opened, acquire) == 0
         ? nullptr : "a refused dial reported afterwards";
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    rig_t rig = {};
    if (!rig_up(&rig)) {
        fprintf(stderr, "local_dial: engine or protocol create failed\n");
        return 1;
    }
    static const struct {
        const char *name;
        const char *(*run)(rig_t *);
    } scenarios[] = {
        { "trade", sc_trade }, { "refused", sc_refused }, { "other", sc_other },
        { "args", sc_args },
#ifdef __linux__
        { "backlog", sc_backlog },
#endif
        { "split_in", sc_split_listened }, { "split_out", sc_split_dialled }, { "idle", sc_idle },
    };
    int failed = 0;
    if (!local_floor) {
        const char *error = sc_floor(&rig);
        printf("local_dial: %-10s %s%s\n", "floor", error ? "FAILED: " : "ok", error ? error : "");
        failed += error != nullptr;
    } else {
        for (size_t i = 0u; i < sizeof scenarios / sizeof scenarios[0]; ++i) {
            const char *error = scenarios[i].run(&rig);
            printf("local_dial: %-10s %s%s\n", scenarios[i].name, error ? "FAILED: " : "ok",
                   error ? error : "");
            failed += error != nullptr;
        }
    }
    rig_down(&rig);
    if (local_floor) {
        const char *error = sc_teardown();
        printf("local_dial: %-10s %s%s\n", "teardown", error ? "FAILED: " : "ok", error ? error : "");
        failed += error != nullptr;
    }
    if (failed) {
        fprintf(stderr, "local_dial: %d scenario(s) failed\n", failed);
        return 1;
    }
    printf("local_dial: OK\n");
    return 0;
}
