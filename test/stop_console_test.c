/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file stop_console_test.c
 *  @brief A console break as a stop request, on Windows.
 *
 *  The test starts itself as a child in a process group of its own. The child arms
 *  @c duct_engine_stop_on_signals, signals an event it was handed and waits for the
 *  request. The parent waits for that event, sends the child's group a
 *  Ctrl-Break and expects the child to leave with exit code 0.
 */

#include "duct.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/** @brief Longest the parent waits for the child to arm or to leave, milliseconds. */
static constexpr DWORD patience_ms = 10'000u;

/** @brief The child: arm the stop hook, signal @p ready_text's event, wait for the request.
 *  @p ready_text is the event handle in decimal.
 *  @return the exit code: 0 after the request, otherwise the step that failed. */
static int child_run(const char *ready_text)
{
    auto ready = (HANDLE)(uintptr_t)strtoull(ready_text, nullptr, 10);
    auto e = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1u, .workers = 1u });
    if (!e)
        return 2;
    if (duct_engine_stop_on_signals(e) != rc_ok) {
        duct_engine_destroy(e);
        return 3;
    }
    SetEvent(ready);
    duct_result_t rc = duct_engine_wait_request(e);
    duct_engine_stop(e);
    duct_engine_destroy(e);
    return rc == rc_ok ? 0 : 4;
}

/** @brief Start @p self as the child, send it a Ctrl-Break and read its exit code.
 *  @return the text of the first failed check, nullptr when all hold. */
static const char *sc_break(const char *self)
{
    SECURITY_ATTRIBUTES inherit = { .nLength = sizeof inherit, .bInheritHandle = TRUE };
    HANDLE ready = CreateEventW(&inherit, TRUE, FALSE, nullptr);
    if (!ready)
        return "the ready event did not create";
    char cmd[MAX_PATH + 64];
    snprintf(cmd, sizeof cmd, "\"%s\" child %llu", self, (unsigned long long)(uintptr_t)ready);
    STARTUPINFOA startup = { .cb = sizeof startup };
    PROCESS_INFORMATION child = {};
    if (!CreateProcessA(nullptr, cmd, nullptr, nullptr, TRUE, CREATE_NEW_PROCESS_GROUP,
                        nullptr, nullptr, &startup, &child)) {
        CloseHandle(ready);
        return "the child process did not start";
    }
    const char *err = nullptr;
    if (WaitForSingleObject(ready, patience_ms) != WAIT_OBJECT_0)
        err = "the child did not arm its stop hook";
    else if (!GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child.dwProcessId))
        err = "no console event could be sent to the child";
    DWORD code = 1u;
    if (WaitForSingleObject(child.hProcess, patience_ms) != WAIT_OBJECT_0) {
        TerminateProcess(child.hProcess, 1u);
        WaitForSingleObject(child.hProcess, patience_ms);
        if (!err)
            err = "a console break did not end the child's wait for the request";
    }
    GetExitCodeProcess(child.hProcess, &code);
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    CloseHandle(ready);
    if (err)
        return err;
    return code == 0u ? nullptr : "the child did not end cleanly after the console break";
}

int main(int argc, char **argv)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    if (argc > 2 && strcmp(argv[1], "child") == 0)
        return child_run(argv[2]);
    const char *err = sc_break(argv[0]);
    if (err) {
        fprintf(stderr, "stop_console: %s\n", err);
        return 1;
    }
    printf("stop_console: OK\n");
    return 0;
}
