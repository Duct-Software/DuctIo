# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Duct Software, author: Constantin Papizh

# Platform data for Windows via MSYS2/MinGW-w64 (no MSVC support).
set(DUCT_PLATFORM_OS_DIR "os/windows")

# poll: WSAPoll; iocp: completion ports; wsaevent: WSAEventSelect, 63 handles per thread.
set(DUCT_EVENTS_MODEL "poll" CACHE STRING
    "Event-notification model: poll | iocp | wsaevent")

set_property(CACHE DUCT_EVENTS_MODEL PROPERTY
    STRINGS poll iocp wsaevent)
    
if(NOT DUCT_EVENTS_MODEL STREQUAL "poll"
    AND NOT DUCT_EVENTS_MODEL STREQUAL "iocp"
    AND NOT DUCT_EVENTS_MODEL STREQUAL "wsaevent")
        message(FATAL_ERROR
                "DuctIo: DUCT_EVENTS_MODEL expected 'poll' | 'iocp'"
                " | 'wsaevent', got '${DUCT_EVENTS_MODEL}'")
endif()

# 8.1 keeps the engine's floor; 10-1803 is where AF_UNIX sockets begin, and with them x_local.
set(DUCT_WINDOWS_FLOOR "8.1" CACHE STRING "Lowest Windows the build runs on: 8.1 | 10-1803")
set_property(CACHE DUCT_WINDOWS_FLOOR PROPERTY STRINGS 8.1 10-1803)

if(DUCT_WINDOWS_FLOOR STREQUAL "8.1")
    set(_DUCT_WINDOWS_FLOOR_DEFINITIONS
        _WIN32_WINNT=_WIN32_WINNT_WINBLUE)  # Windows 8.1 Update, for DiscardVirtualMemory
elseif(DUCT_WINDOWS_FLOOR STREQUAL "10-1803")
    set(_DUCT_WINDOWS_FLOOR_DEFINITIONS
        _WIN32_WINNT=_WIN32_WINNT_WIN10
        NTDDI_VERSION=NTDDI_WIN10_RS4)
else()
    message(FATAL_ERROR
            "DuctIo: DUCT_WINDOWS_FLOOR expected '8.1' | '10-1803', got '${DUCT_WINDOWS_FLOOR}'")
endif()

set(DUCT_PLATFORM_COMPILE_DEFINITIONS
    WIN32_LEAN_AND_MEAN
    ${_DUCT_WINDOWS_FLOOR_DEFINITIONS}
)

if(NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
    set(DUCT_PLATFORM_COMPILE_OPTIONS -fstack-clash-protection)
endif()

if(DUCT_EVENTS_MODEL STREQUAL "iocp")
    set(_DUCT_EVENTS_IOCP_DEFINE "#define DUCT_EVENTS_MODEL_IOCP 1")
else()
    set(_DUCT_EVENTS_IOCP_DEFINE "#define DUCT_EVENTS_MODEL_IOCP 0")
endif()

# timeBeginPeriod settings, read by duct_timer.h.
option(DUCT_TIMER_NO_HIRES [[Never request high-resolution timer ticks (timeBeginPeriod) for
fine-grained timers -- lower power draw, coarser sub-15ms precision]] OFF)
set(DUCT_TIMER_COARSE_GRANULARITY_US 15600 CACHE STRING [[Wait-primitive granularity assumed when high-res timing is disabled,
microseconds (measured default Windows system tick)]])
if(DUCT_TIMER_NO_HIRES)
    set(_DUCT_TIMER_NO_HIRES_DEFINE "#define DUCT_TIMER_NO_HIRES 1")
else()
    set(_DUCT_TIMER_NO_HIRES_DEFINE "#define DUCT_TIMER_NO_HIRES 0")
endif()

set(DUCT_PLATFORM_CONFIG_LINES
"${_DUCT_EVENTS_IOCP_DEFINE}
${_DUCT_TIMER_NO_HIRES_DEFINE}
[[maybe_unused]] constexpr uint64_t duct_timer_coarse_granularity_us = ${DUCT_TIMER_COARSE_GRANULARITY_US}u;")

set(DUCT_PLATFORM_LINK_LIBRARIES
    ws2_32
    mswsock
    iphlpapi
    bcrypt
    synchronization
    winpthread
    winmm
)
