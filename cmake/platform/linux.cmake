# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Duct Software, author: Constantin Papizh

# Platform data for Linux.
set(DUCT_PLATFORM_OS_DIR "os/linux")

# epoll: the Linux default; poll: the portable fallback.
set(DUCT_EVENTS_MODEL "epoll" CACHE STRING
    "Event-notification model: epoll | poll")

set_property(CACHE DUCT_EVENTS_MODEL PROPERTY STRINGS epoll poll)

if(NOT DUCT_EVENTS_MODEL STREQUAL "epoll" 
    AND NOT DUCT_EVENTS_MODEL STREQUAL "poll")
        message(FATAL_ERROR
                "DuctIo: DUCT_EVENTS_MODEL expected 'poll'"
                " | 'epoll' , got '${DUCT_EVENTS_MODEL}'")
endif()

set(DUCT_PLATFORM_COMPILE_DEFINITIONS
    _GNU_SOURCE
    _POSIX_C_SOURCE=200809L
    _FILE_OFFSET_BITS=64
)
set(DUCT_PLATFORM_COMPILE_OPTIONS -fstack-clash-protection)
if(ANDROID)
    # Bionic provides pthread APIs in libc, not a separate libpthread.
    set(DUCT_PLATFORM_LINK_LIBRARIES "")
else()
    set(DUCT_PLATFORM_LINK_LIBRARIES pthread)
endif()
