/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

#include "duct_core.h"
#include "duct_timer.h"

#include <time.h>

uint64_t _Atomic duct_timer_global_id = 0;

/* Windows converts through _localtime64_s, which takes the seconds from 1970 to the end of the
 * year 3000 and refuses the rest; localtime_r refuses a second whose year overflows tm_year. */
bool duct_localtime(int64_t sec, struct tm *out)
{
#ifdef _WIN32
    __time64_t t = sec;
    return _localtime64_s(out, &t) == 0;
#else
    time_t t = (time_t)sec;
    return localtime_r(&t, out) != nullptr;
#endif
}
