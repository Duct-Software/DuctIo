/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

#include "duct_logfile.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>

/* The Linux base: $XDG_STATE_HOME, absolute as the XDG Base Directory Specification asks
 * — a relative value reads as invalid and falls through — then $HOME/.local/state under
 * the same absolute rule on $HOME, then /var/log for the system context. The product
 * directory is made one level deep, mode 0700, a standing directory the answer. The
 * Android branch answers false: the application's directory is the host's to name. */
bool duct_logfile_default_dir(char *buf, size_t cap, const char *product)
{
#ifdef __ANDROID__
    return false;
#else
    const char *env = getenv("XDG_STATE_HOME"),
               *suffix = "";
    if (!(env && *env == '/')) {
        suffix = "/.local/state";
        env = getenv("HOME");
        if (!(env && *env == '/')) {
            suffix = "";
            env = "/var/log";
        }
    }
    int n = snprintf(buf, cap, "%s%s/%s", env, suffix, product);
    if (n <= 0 || (size_t)n >= cap)
        return false;
    return mkdir(buf, 0700) == 0 || errno == EEXIST;
#endif
}
