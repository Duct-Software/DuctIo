/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file e2e_reconnect_test.c
 * @brief Two genuinely separate OS processes, each its own duct_engine_t —
 * a real client app dialing a real server app, not two threads sharing one
 * engine like every other test here. Covers two things nothing else in this
 * suite exercises: outbound (client-mode) operation as a standalone process,
 * and reconnect-with-continuity — the client force-drops its own session
 * mid-stream (artificial disconnect), redials, and the conversation resumes
 * from where it left off instead of restarting.
 *
 * Three roles behind one binary, selected by argv[1]:
 *   (no args) driver — spawns "server" then "client" as child processes of
 *             itself, hands the server's ephemeral port to the client via a
 *             small temp file, waits on both, checks exit codes.
 *   server  — listens, echoes, tracks each client-id's last-seen sequence
 *             number across however many sessions that id shows up in.
 *   client  — sends seq 1..3, force-closes its own session on the 3rd echo,
 *             reconnects with the same client-id, sends seq 4..6.
 *
 * Continuity is proven server-side: a reconnect that actually resumed shows
 * up as seq 4 immediately following seq 3 for the same client-id, even
 * though it arrived on a brand new duct_session_t. A client-id whose second
 * session restarts at seq 1 (no real continuity) fails the check.
 */

#include "duct.h"
#include "test_helpers.h"

#include <stdlib.h>

#ifdef _WIN32
    #include <process.h>
#else
    #include <signal.h>
    #include <sys/wait.h>
#endif

/* ── Wire payload — deliberately minimal: both ends are the same compiled
 * binary on the same machine, no serialization concerns. ────────────────── */

typedef struct {
    uint32_t client_id;
    uint32_t seq;
} msg_t;

static constexpr uint32_t total_msgs      = 6u;
static constexpr uint32_t disconnect_after_seq = 3u; /* drop right after this seq's echo arrives */
static constexpr uint32_t test_client_id  = 0xC11E7701u;
static constexpr unsigned wait_step_ms    = 10u;
static constexpr unsigned soft_deadline_ms = 15000u;

/* ── Process spawn/wait — the one piece with no existing helper in this
 * suite: every other test runs client and server as threads in one
 * process. ──────────────────────────────────────────────────────────── */

#ifdef _WIN32
typedef HANDLE proc_handle_t;
#else
typedef pid_t proc_handle_t;
#endif

#ifndef _WIN32
/** @brief CTest invokes this binary by its own resolved build path — argv[0]
 *  is reliably a directly-executable path in that context, not a bare
 *  PATH-searched name. Stashed in main() before dispatching by role. */
static const char *g_self_argv0;
#endif

static bool s_self_path(char *out, size_t cap)
{
#ifdef _WIN32
    DWORD n = GetModuleFileNameA(nullptr, out, (DWORD)cap);
    return n > 0u && n < cap;
#else
    return g_self_argv0 && strlen(g_self_argv0) < cap
        ? (strcpy(out, g_self_argv0), true) : false;
#endif
}

static bool s_spawn(const char *role, const char *arg2, proc_handle_t *out)
{
    char self[1024];
    duct_do_if(!s_self_path(self, sizeof self), return false);
#ifdef _WIN32
    char cmdline[1200];
    snprintf(cmdline, sizeof cmdline, "\"%s\" %s \"%s\"", self, role, arg2 ? arg2 : "");
    STARTUPINFOA si = { .cb = sizeof si };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(nullptr, cmdline, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi))
        return false;
    CloseHandle(pi.hThread);
    *out = pi.hProcess;
    return true;
#else
    pid_t pid = fork();
    duct_do_if(pid < 0, return false);
    if (pid == 0) {
        char *args[] = { (char *)self, (char *)role, (char *)arg2, nullptr };
        execv(self, args);
        _exit(127); /* exec failed */
    }
    *out = pid;
    return true;
#endif
}

/** @brief Wait up to @p timeout_ms for @p h to exit. @return true and fills
 *  @p out_code on a clean exit within budget; force-kills and returns false
 *  on timeout — never leaves an orphaned child behind. */
static bool s_wait_process(proc_handle_t h, unsigned timeout_ms, int *out_code)
{
#ifdef _WIN32
    bool done = WaitForSingleObject(h, timeout_ms) == WAIT_OBJECT_0;
    if (!done) {
        TerminateProcess(h, 1);
        WaitForSingleObject(h, 2000);
    }
    DWORD code = 1;
    GetExitCodeProcess(h, &code);
    CloseHandle(h);
    *out_code = (int)code;
    return done;
#else
    for (unsigned waited = 0u; waited < timeout_ms; waited += wait_step_ms) {
        int status = 0;
        pid_t r = waitpid(h, &status, WNOHANG);
        if (r == h) {
            *out_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
            return true;
        }
        th_sleep_ms(wait_step_ms);
    }
    kill(h, SIGKILL);
    int status = 0;
    waitpid(h, &status, 0);
    *out_code = 1;
    return false;
#endif
}

/* ── Port handoff: server writes its ephemeral port to a temp file, driver
 * reads it before spawning the client — avoids a fixed port (collision risk
 * across concurrent runs) without needing pipe-across-CreateProcess. ───── */

static void s_tmp_path(char *out, size_t cap)
{
#ifdef _WIN32
    char dir[MAX_PATH];
    GetTempPathA(sizeof dir, dir);
    snprintf(out, cap, "%sductio_e2e_port_%u.tmp", dir, (unsigned)_getpid());
#else
    const char *dir = getenv("TMPDIR");
    snprintf(out, cap, "%s/ductio_e2e_port_%u.tmp", dir ? dir : "/tmp", (unsigned)getpid());
#endif
}

static bool s_write_port(const char *path, uint16_t port)
{
    FILE *f = fopen(path, "w");
    duct_do_if(!f, return false);
    bool ok = fprintf(f, "%u\n", (unsigned)port) > 0;
    fclose(f);
    return ok;
}

/** @brief Poll @p path for a parseable port, up to @p timeout_ms. */
static bool s_read_port(const char *path, unsigned timeout_ms, uint16_t *out_port)
{
    for (unsigned waited = 0u; waited < timeout_ms; waited += wait_step_ms) {
        FILE *f = fopen(path, "r");
        if (f) {
            unsigned v = 0u;
            bool got = fscanf(f, "%u", &v) == 1 && v > 0u && v <= 65535u;
            fclose(f);
            if (got) {
                *out_port = (uint16_t)v;
                remove(path);
                return true;
            }
        }
        th_sleep_ms(wait_step_ms);
    }
    return false;
}

/* ── Server role ──────────────────────────────────────────────────────── */

/** @brief Per-client-id continuity state; tiny fixed table — this test only
 *  ever drives one logical client, room to spare is not a design point. */
typedef struct {
    uint32_t client_id;
    uint32_t last_seq;
    bool     seen;
} srv_client_t;

static srv_client_t     g_srv_clients[8];
static _Atomic(uint32_t) g_srv_frames  = 0u;
static _Atomic(uint32_t) g_srv_opens   = 0u;
static _Atomic(bool)     g_srv_continuity_ok = true;

static srv_client_t *s_srv_find_or_add(uint32_t client_id)
{
    for (unsigned i = 0u; i < sizeof g_srv_clients / sizeof g_srv_clients[0]; ++i) {
        if (g_srv_clients[i].seen && g_srv_clients[i].client_id == client_id)
            return &g_srv_clients[i];
        if (!g_srv_clients[i].seen) {
            g_srv_clients[i] = (srv_client_t){ .client_id = client_id };
            return &g_srv_clients[i];
        }
    }
    return nullptr; /* table full — not reachable with one test client */
}

static duct_result_t
srv_on_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, [[maybe_unused]] duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_srv_opens, 1u, release);
    return rc_ok;
}

static duct_result_t
srv_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             const duct_frame_t *frame, duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    if (frame->payload.size != sizeof(msg_t)) {
        duct_atomic_store(&g_srv_continuity_ok, false, relaxed);
        return rc_ok;
    }
    msg_t m;
    memcpy(&m, frame->payload.data, sizeof m);
    auto c = s_srv_find_or_add(m.client_id);
    if (!c) {
        duct_atomic_store(&g_srv_continuity_ok, false, relaxed);
        return rc_ok;
    }
    /* The actual continuity proof: a reconnect's first frame must pick up
     * at last_seq + 1 — same as any two consecutive frames on one
     * never-dropped session — regardless of which duct_session_t it
     * physically arrived on. */
    bool expected = !c->seen ? m.seq == 1u : m.seq == c->last_seq + 1u;
    if (!expected)
        duct_atomic_store(&g_srv_continuity_ok, false, relaxed);
    c->seen = true;
    c->last_seq = m.seq;
    duct_atomic_fetch(add, &g_srv_frames, 1u, release);
    duct_response_echo(out, frame);
    return rc_ok;
}

static int s_run_server(const char *port_file)
{
    auto io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    duct_do_if(!io, fprintf(stderr, "e2e server: launch failed\n"); return 1);

    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "e2e-srv", .wire = wire,
        .on_frame = srv_on_frame, .on_session_open = srv_on_open,
    });
    if (proto) proto->owned_wire = wire; else duct_wire_destroy(wire);
    duct_do_if(!proto, duct_engine_destroy(io); return 1);

    uint16_t port = 0u;
    bool ok = duct_io_listen(io, "127.0.0.1", &port, proto) == rc_ok;
    ok = ok && s_write_port(port_file, port);
    duct_do_if(!ok, fprintf(stderr, "e2e server: listen/port-file failed\n");
        duct_proto_destroy(proto); duct_engine_destroy(io); return 1);

    pthread_t th;
    ok = pthread_create(&th, nullptr, th_run, io) == 0;
    duct_do_if(!ok, fprintf(stderr, "e2e server: wait-thread spawn failed\n");
        duct_proto_destroy(proto); duct_engine_destroy(io); return 1);

    for (unsigned waited = 0u; waited < soft_deadline_ms; waited += wait_step_ms) {
        if (duct_atomic_load(&g_srv_frames, acquire) >= total_msgs)
            break;
        th_sleep_ms(wait_step_ms);
    }
    th_sleep_ms(300u); /* let the last echo's TX actually flush before teardown */

    duct_engine_stop(io);
    pthread_join(th, nullptr);
    duct_engine_destroy(io);
    duct_proto_destroy(proto);

    unsigned frames = duct_atomic_load(&g_srv_frames, acquire);
    unsigned opens  = duct_atomic_load(&g_srv_opens, acquire);
    bool cont_ok    = duct_atomic_load(&g_srv_continuity_ok, relaxed);
    if (frames != total_msgs || opens != 2u || !cont_ok) {
        fprintf(stderr, "e2e server: frames=%u/%u opens=%u/2 continuity=%d\n",
                frames, total_msgs, opens, (int)cont_ok);
        return 1;
    }
    return 0;
}

/* ── Client role ──────────────────────────────────────────────────────── */

static duct_engine_t *g_cli_engine;
static duct_proto_t  *g_cli_proto;
static char            g_cli_addr[64];
static _Atomic(uint32_t) g_cli_next_seq   = 1u;
static _Atomic(uint32_t) g_cli_recv_count = 0u;
static _Atomic(uint32_t) g_cli_open_count = 0u;
static _Atomic(bool)     g_cli_reconnected = false;
static _Atomic(bool)     g_cli_done        = false;
static _Atomic(bool)     g_cli_mismatch    = false;

/** @brief duct_io_connect needs engine_state_running; the io thread flips
 *  that shortly after launch — retry past the short window instead of
 *  racing it, same discipline as connect_test.c's own s_connect_retry. */
static duct_result_t s_client_dial(void)
{
    duct_result_t rc = rc_invalid_order;
    for (unsigned waited = 0u; waited < 3000u; waited += wait_step_ms) {
        rc = duct_io_connect(g_cli_engine, g_cli_addr, g_cli_proto, nullptr, x_tcp);
        if (rc != rc_invalid_order)
            return rc;
        th_sleep_ms(wait_step_ms);
    }
    return rc;
}

/** @brief Only one worker turn is ever mid-send for this session, so static
 *  reuse is safe — and needed: fl_send_copy's actual copy runs later than
 *  "right after the callback returns" suggests. A stack-local here, even
 *  the callback's own (not a nested helper's), was observed clobbered
 *  before the framework read it back; a static buffer sidesteps the
 *  question entirely. */
static msg_t g_cli_send_buf;

static void s_fill_send(duct_response_t *out, uint32_t seq)
{
    g_cli_send_buf = (msg_t){ .client_id = test_client_id, .seq = seq };
    duct_response_same(out, duct_view(duct_view_u8, (void *)&g_cli_send_buf, sizeof g_cli_send_buf),
                        fl_send_copy, 0);
}

static duct_result_t
cli_on_open([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_handle_t tok,
            [[maybe_unused]] void *user_ctx, duct_response_t *out,
            [[maybe_unused]] void *proto_state)
{
    duct_atomic_fetch(add, &g_cli_open_count, 1u, release);
    s_fill_send(out, duct_atomic_load(&g_cli_next_seq, relaxed));
    return rc_ok;
}

static duct_result_t
cli_on_frame([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
             const duct_frame_t *frame, duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    uint32_t expect_seq = duct_atomic_load(&g_cli_next_seq, relaxed);
    if (frame->payload.size != sizeof(msg_t)) {
        duct_atomic_store(&g_cli_mismatch, true, relaxed);
        return rc_ok;
    }
    msg_t m;
    memcpy(&m, frame->payload.data, sizeof m);
    if (m.client_id != test_client_id || m.seq != expect_seq) {
        duct_atomic_store(&g_cli_mismatch, true, relaxed);
        return rc_ok;
    }
    duct_atomic_fetch(add, &g_cli_recv_count, 1u, release);

    uint32_t next = expect_seq + 1u;
    duct_atomic_store(&g_cli_next_seq, next, relaxed);
    if (expect_seq == disconnect_after_seq) {
        /* Artificial disconnect: drop our own session mid-stream. Nothing
         * queued this turn — on_session_close below does the redial. */
        duct_response_close_session(out, close_normal);
        return rc_ok;
    }
    if (next <= total_msgs) {
        s_fill_send(out, next);
        return rc_ok;
    }
    duct_atomic_store(&g_cli_done, true, relaxed);
    duct_response_close_session(out, close_normal);
    return rc_ok;
}

static void
cli_on_close([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_close_reason_t reason,
             [[maybe_unused]] void *proto_state)
{
    if (duct_atomic_load(&g_cli_done, relaxed))
        return; /* final close — nothing left to resume */
    duct_atomic_store(&g_cli_reconnected, true, relaxed);
    if (s_client_dial() != rc_ok)
        duct_atomic_store(&g_cli_mismatch, true, relaxed);
}

static duct_result_t
cli_on_error([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_result_t error,
             [[maybe_unused]] duct_response_t *out, [[maybe_unused]] void *proto_state)
{
    duct_atomic_store(&g_cli_mismatch, true, relaxed);
    return rc_ok;
}

static int s_run_client(uint16_t port)
{
    snprintf(g_cli_addr, sizeof g_cli_addr, "127.0.0.1:%u", (unsigned)port);
    g_cli_engine = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    duct_do_if(!g_cli_engine, fprintf(stderr, "e2e client: launch failed\n"); return 1);

    auto wire = duct_wire_create_length_prefix(0u);
    g_cli_proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "e2e-cli", .wire = wire,
        .on_frame = cli_on_frame, .on_session_open = cli_on_open,
        .on_session_close = cli_on_close, .on_error = cli_on_error,
    });
    if (g_cli_proto) g_cli_proto->owned_wire = wire; else duct_wire_destroy(wire);
    duct_do_if(!g_cli_proto, duct_engine_destroy(g_cli_engine); return 1);

    pthread_t th;
    bool ok = pthread_create(&th, nullptr, th_run, g_cli_engine) == 0;
    ok = ok && s_client_dial() == rc_ok;
    duct_do_if(!ok, fprintf(stderr, "e2e client: dial failed\n");
        duct_proto_destroy(g_cli_proto); duct_engine_destroy(g_cli_engine); return 1);

    for (unsigned waited = 0u; waited < soft_deadline_ms; waited += wait_step_ms) {
        if (duct_atomic_load(&g_cli_done, acquire) || duct_atomic_load(&g_cli_mismatch, acquire))
            break;
        th_sleep_ms(wait_step_ms);
    }
    th_sleep_ms(200u); /* let the final close's own teardown settle */

    duct_engine_stop(g_cli_engine);
    pthread_join(th, nullptr);
    duct_engine_destroy(g_cli_engine);
    duct_proto_destroy(g_cli_proto);

    bool done  = duct_atomic_load(&g_cli_done, acquire);
    bool mism  = duct_atomic_load(&g_cli_mismatch, acquire);
    bool recon = duct_atomic_load(&g_cli_reconnected, acquire);
    unsigned recv = duct_atomic_load(&g_cli_recv_count, acquire);
    unsigned opens = duct_atomic_load(&g_cli_open_count, acquire);
    if (!done || mism || !recon || recv != total_msgs || opens != 2u) {
        fprintf(stderr, "e2e client: done=%d mismatch=%d reconnected=%d recv=%u/%u opens=%u/2\n",
                (int)done, (int)mism, (int)recon, recv, total_msgs, opens);
        return 1;
    }
    return 0;
}

/* ── Driver role ──────────────────────────────────────────────────────── */

static int s_run_driver(void)
{
    char port_file[1024];
    s_tmp_path(port_file, sizeof port_file);
    remove(port_file); /* stale leftover from a killed prior run */

    proc_handle_t srv_h;
    bool ok = s_spawn("server", port_file, &srv_h);
    duct_do_if(!ok, fprintf(stderr, "e2e driver: server spawn failed\n"); return 1);

    uint16_t port = 0u;
    ok = s_read_port(port_file, 5000u, &port);
    duct_do_if(!ok, fprintf(stderr, "e2e driver: server never published a port\n");
        int discard; s_wait_process(srv_h, 5000u, &discard); return 1);

    char port_arg[16];
    snprintf(port_arg, sizeof port_arg, "%u", (unsigned)port);
    proc_handle_t cli_h;
    ok = s_spawn("client", port_arg, &cli_h);
    duct_do_if(!ok, fprintf(stderr, "e2e driver: client spawn failed\n");
        int discard; s_wait_process(srv_h, 5000u, &discard); return 1);

    int cli_code = 1, srv_code = 1;
    bool cli_done = s_wait_process(cli_h, 30000u, &cli_code);
    bool srv_done = s_wait_process(srv_h, 30000u, &srv_code);

    if (!cli_done || !srv_done || cli_code != 0 || srv_code != 0) {
        fprintf(stderr, "e2e driver: client(done=%d code=%d) server(done=%d code=%d)\n",
                (int)cli_done, cli_code, (int)srv_done, srv_code);
        return 1;
    }
    printf("e2e_reconnect: OK (client-mode process, artificial disconnect, "
           "reconnect with sequence continuity 1..%u across the drop)\n", total_msgs);
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
#ifndef _WIN32
    g_self_argv0 = argv[0];
#endif
    if (argc < 2)
        return s_run_driver();
    if (strcmp(argv[1], "server") == 0 && argc >= 3)
        return s_run_server(argv[2]);
    if (strcmp(argv[1], "client") == 0 && argc >= 3)
        return s_run_client((uint16_t)atoi(argv[2]));
    fprintf(stderr, "e2e_reconnect_test: bad args\n");
    return 1;
}
