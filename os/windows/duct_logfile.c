/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

#include "duct_logfile.h"

#include <stdlib.h>
#include <windows.h>

static constexpr size_t dir_wide_max = 1024u;

/* The Windows base: %LOCALAPPDATA%, %ProgramData% behind it for a service or a system
 * account; both standing empty leave the answer false. The product directory is made
 * through CreateDirectoryW on a wide copy of the path, the buffer keeping UTF-8. A
 * directory standing is the answer. */
bool duct_logfile_default_dir(char *buf, size_t cap, const char *product)
{
    const char *env = getenv("LOCALAPPDATA");
    if (!(env && *env))
        env = getenv("ProgramData");
    if (!(env && *env))
        return false;
    int n = snprintf(buf, cap, "%s\\%s", env, product);
    if (n <= 0 || (size_t)n >= cap)
        return false;
    wchar_t wide[dir_wide_max];
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, buf, -1, wide, (int)(sizeof wide / sizeof wide[0])))
        return false;
    return CreateDirectoryW(wide, nullptr) || GetLastError() == ERROR_ALREADY_EXISTS;
}
