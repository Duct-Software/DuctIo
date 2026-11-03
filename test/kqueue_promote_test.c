/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file kqueue_promote_test.c
 *  @brief Promotion replaces pending and installed pre_conn tags; rejected
 *  batched registrations are fatal under the current reactor contract.
 */
#include "../os/kqueue/duct_events.c"

#include <TargetConditionals.h>
#include <limits.h>
#include <stdio.h>
#if !TARGET_OS_IPHONE
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#endif

static int check_promotion(bool installed)
{
    auto env = duct_events_init();
    int sv[2];
    if (!env || socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        if (env) duct_events_fini(env);
        return 0;
    }
    duct_pre_conn_t old_tag = { .kind = pre_conn_dial };
    int new_tag = 0;
    int pass = 0;
    if (!duct_events_watch(env, sv[0], io_tag_pre_conn, &old_tag, x_tcp))
        goto done;
    if (installed)
        s_changes_flush(env);
    if (!duct_events_promote(env, sv[0], &new_tag))
        goto done;
    /* Neither the pending list nor the kernel may retain the retired tag. */
    for (unsigned i = 0; i < env->n_changes; ++i)
        if ((uintptr_t)env->changes[i].udata != s_tag_pack(io_tag_conn, &new_tag))
            goto done;
    s_changes_flush(env);
    if (write(sv[1], "x", 1) != 1)
        goto done;
    struct kevent events[4];
    int n = kevent(env->kq, nullptr, 0, events, 4, &(struct timespec){ .tv_sec = 1 });
    bool read_seen = false, write_seen = false;
    for (int i = 0; i < n; ++i) {
        if (events[i].ident != (uintptr_t)sv[0])
            continue;
        if ((events[i].flags & EV_ERROR)
            || (uintptr_t)events[i].udata != s_tag_pack(io_tag_conn, &new_tag))
            goto done;
        read_seen |= events[i].filter == EVFILT_READ;
        write_seen |= events[i].filter == EVFILT_WRITE;
    }
    pass = read_seen && write_seen;
done:
    close(sv[0]);
    close(sv[1]);
    duct_events_fini(env);
    return pass;
}

#if !TARGET_OS_IPHONE
/* iOS does not permit fork; exercise the fatal path only on macOS. */
static int check_rejected_change(void)
{
    pid_t child = fork();
    if (child == 0) {
        setrlimit(RLIMIT_CORE, &(struct rlimit){ 0, 0 });
        auto env = duct_events_init();
        duct_pre_conn_t tag = { .kind = pre_conn_dial };
        if (!env || !duct_events_watch(env, INT_MAX, io_tag_pre_conn, &tag, x_tcp))
            _exit(2);
        s_changes_flush(env);
        _exit(3);
    }
    int status = 0;
    return child > 0 && waitpid(child, &status, 0) == child
        && WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT;
}
#endif

int main(void)
{
    bool pass = check_promotion(false) && check_promotion(true);
#if !TARGET_OS_IPHONE
    pass = pass && check_rejected_change();
#endif
    if (!pass) {
        fprintf(stderr, "kqueue_promote: promotion/tag or fatal-rejection contract failed\n");
        return 1;
    }
    puts("kqueue_promote: OK (pending/installed tags replaced)");
    return 0;
}
