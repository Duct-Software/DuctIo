/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

#include "duct_logfile.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>

/* The darwin base: $HOME/Library/Logs, the place the Console app reads logs from; on iOS
 * $HOME is the application's sandbox container, the same code path. The product directory
 * is made one level deep, mode 0700, a standing directory the answer. */
bool duct_logfile_default_dir(char *buf, size_t cap, const char *product)
{
    const char *home = getenv("HOME");
    if (!(home && *home == '/'))
        return false;
    int n = snprintf(buf, cap, "%s/Library/Logs/%s", home, product);
    if (n <= 0 || (size_t)n >= cap)
        return false;
    return mkdir(buf, 0700) == 0 || errno == EEXIST;
}
