# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Duct Software, author: Constantin Papizh

# OS/CPU source collection.
#
# Layout:
#   os/*.c                      — cross-OS platform primitives, #ifdef _WIN32
#                                 internally for the few spots that differ between OSes
#   os/include/duct_events.h    — the DUCT_EVENTS_MODEL downcall/upcall contract,
#                                 one shared header for every platform and model;
#   os/<platform>/*.c           — OS-specific platform glue;
#   os/<platform>/include/*.h   — OS-specific primitives shared by every
#                                 DUCT_EVENTS_MODEL on that platform (duct_xport.h),
#                                 and a socket's send state the TX ring holds
#                                 (duct_xsock.h), each under the same names on
#                                 every platform;
#   os/poll/*.c                 — portable poll()-based DUCT_EVENTS_MODEL;
#   os/<platform>/<model>/*.c   — platform-specific DUCT_EVENTS_MODEL, see ./platform/*.cmake;
#   arch/<cpu>/*.c              — CPU-specific glue, shared across OS backends;

set(DUCT_CPU "" CACHE STRING
    "CPU name under arch/ autodetected from CMAKE_SYSTEM_PROCESSOR")

function(duct_detect_cpu out_var)
    if(APPLE)
        list(LENGTH CMAKE_OSX_ARCHITECTURES _duct_apple_arch_count)
        if(_duct_apple_arch_count GREATER 1)
            message(FATAL_ERROR
                "DuctIo: build each Apple architecture separately; "
                "CMAKE_OSX_ARCHITECTURES='${CMAKE_OSX_ARCHITECTURES}' selects "
                "multiple architectures but arch/ contains one context switch per build.")
        endif()
    endif()
    if(DUCT_CPU)
        set(${out_var} "${DUCT_CPU}" PARENT_SCOPE)
        return()
    endif()
    if(APPLE AND CMAKE_OSX_ARCHITECTURES STREQUAL "arm64")
        set(${out_var} aarch64 PARENT_SCOPE)
    elseif(APPLE AND CMAKE_OSX_ARCHITECTURES STREQUAL "x86_64")
        set(${out_var} x86_64 PARENT_SCOPE)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
        set(${out_var} aarch64 PARENT_SCOPE)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
        set(${out_var} x86_64 PARENT_SCOPE)
    else()
        message(FATAL_ERROR
            "DuctIo: unsupported CMAKE_SYSTEM_PROCESSOR '${CMAKE_SYSTEM_PROCESSOR}'. "
            "Set -DDUCT_CPU=<arch> for cross-compiles.")
    endif()
endfunction()

function(duct_collect_os_sources os_dir out_var)
    if(NOT IS_DIRECTORY "${os_dir}")
        message(FATAL_ERROR "DuctIo: OS source directory not found: ${os_dir}")
    endif()
    file(GLOB _os_common CONFIGURE_DEPENDS "${os_dir}/*.c")
    if(NOT _os_common)
        message(FATAL_ERROR "DuctIo: no OS sources under ${os_dir}")
    endif()
    set(${out_var} ${_os_common} PARENT_SCOPE)
endfunction()

# Cross-OS files kept directly under os/
function(duct_collect_shared_os_sources os_root out_var)
    if(NOT IS_DIRECTORY "${os_root}")
        message(FATAL_ERROR "DuctIo: shared OS source directory not found: ${os_root}")
    endif()
    file(GLOB _shared CONFIGURE_DEPENDS "${os_root}/*.c")
    if(NOT _shared)
        message(FATAL_ERROR "DuctIo: no shared OS sources under ${os_root}")
    endif()
    set(${out_var} ${_shared} PARENT_SCOPE)
endfunction()

# CPU-specific glue under arch/<cpu>/, shared by every OS backend.
function(duct_collect_arch_sources arch_root out_var)
    if(NOT IS_DIRECTORY "${arch_root}")
        message(FATAL_ERROR "DuctIo: arch source directory not found: ${arch_root}")
    endif()
    duct_detect_cpu(_cpu)
    set(_arch_dir "${arch_root}/${_cpu}")
    if(NOT IS_DIRECTORY "${_arch_dir}")
        message(FATAL_ERROR
            "DuctIo: missing arch directory ${_arch_dir} (DUCT_CPU='${DUCT_CPU}')")
    endif()
    file(GLOB _arch_src CONFIGURE_DEPENDS "${_arch_dir}/*.c")
    if(NOT _arch_src)
        message(FATAL_ERROR "DuctIo: no sources under ${_arch_dir}")
    endif()
    set(${out_var} ${_arch_src} PARENT_SCOPE)
endfunction()

# src/ sources, excluding src/include/.
function(duct_collect_src_sources src_dir out_var)
    file(GLOB_RECURSE _src CONFIGURE_DEPENDS "${src_dir}/*.c")
    list(FILTER _src EXCLUDE REGEX ".*/src/include/.*")
    set(${out_var} ${_src} PARENT_SCOPE)
endfunction()

# Sources of the selected DUCT_EVENTS_MODEL, from the directory the caller resolved.
function(duct_collect_events_model_sources model_dir out_var)
    if(NOT IS_DIRECTORY "${model_dir}")
        message(FATAL_ERROR "DuctIo: DUCT_EVENTS_MODEL has no directory at ${model_dir}")
    endif()
    file(GLOB _model_src CONFIGURE_DEPENDS "${model_dir}/*.c")
    if(NOT _model_src)
        message(FATAL_ERROR "DuctIo: no sources found under ${model_dir}")
    endif()
    set(${out_var} ${_model_src} PARENT_SCOPE)
endfunction()
