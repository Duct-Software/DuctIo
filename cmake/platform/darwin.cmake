# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Duct Software, author: Constantin Papizh

set(DUCT_PLATFORM_OS_DIR "os/darwin")

# The engine waits on os_sync_wait_on_address, available from macOS 14.4 and iOS 17.4.
if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
    set(_duct_apple_os "iOS")
    set(_duct_apple_floor "17.4")
else()
    set(_duct_apple_os "macOS")
    set(_duct_apple_floor "14.4")
endif()
if(NOT CMAKE_OSX_DEPLOYMENT_TARGET)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "${_duct_apple_floor}")
elseif(CMAKE_OSX_DEPLOYMENT_TARGET VERSION_LESS _duct_apple_floor)
    message(FATAL_ERROR
        "DuctIo: ${_duct_apple_os} ${_duct_apple_floor} is the oldest target it supports; "
        "CMAKE_OSX_DEPLOYMENT_TARGET asks for ${CMAKE_OSX_DEPLOYMENT_TARGET}")
endif()
set(DUCT_EVENTS_MODEL "kqueue" CACHE STRING "Event-notification model: kqueue or poll")
set_property(CACHE DUCT_EVENTS_MODEL PROPERTY STRINGS kqueue poll)
if(NOT DUCT_EVENTS_MODEL STREQUAL "poll" AND NOT DUCT_EVENTS_MODEL STREQUAL "kqueue")
    message(FATAL_ERROR "DuctIo: Darwin supports DUCT_EVENTS_MODEL=kqueue or poll")
endif()

# RFC 3542 API for IPv6 socket options, including IPV6_DONTFRAG.
set(DUCT_PLATFORM_COMPILE_DEFINITIONS _DARWIN_C_SOURCE __APPLE_USE_RFC_3542)
set(DUCT_PLATFORM_LINK_LIBRARIES "")
