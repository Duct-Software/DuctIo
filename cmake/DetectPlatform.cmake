# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Duct Software, author: Constantin Papizh

if(CMAKE_SYSTEM_NAME MATCHES "^(Linux|Android)$")
    set(DUCT_PLATFORM linux)
elseif(CMAKE_SYSTEM_NAME MATCHES "^(Darwin|iOS)$")
    set(DUCT_PLATFORM darwin)
elseif(CMAKE_SYSTEM_NAME MATCHES "^(FreeBSD|OpenBSD|NetBSD|DragonFly)$")
    set(DUCT_PLATFORM bsd)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(DUCT_PLATFORM mingw)
else()
    message(FATAL_ERROR
        "DuctIo: unsupported OS ${CMAKE_SYSTEM_NAME}. \r\n"
        "Use Linux, macOS, a BSD (FreeBSD / OpenBSD / NetBSD / DragonFly)"
        " or Windows + MinGW.")
endif()
