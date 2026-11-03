/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

#include "duct_time.h"
#include "duct_core.h"

#include <stdatomic.h>
#include <windows.h>
#include <mmsystem.h>

uint32_t _Atomic duct_timer_hires_refcount = 0;

void duct_timer_hires_on(void)
{
    duct_discard timeBeginPeriod(1u);
}

void duct_timer_hires_off(void)
{
    duct_discard timeEndPeriod(1u);
}
