# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Duct Software, author: Constantin Papizh

# Link-time optimization (IPO/LTO).

include(CheckIPOSupported)

check_ipo_supported(RESULT DUCT_IPO_SUPPORTED OUTPUT DUCT_IPO_ERROR LANGUAGES C)

option(DUCT_ENABLE_LTO
    "Build with link-time optimization. Requires Release or RelWithDebInfo mode."
    OFF)

if(DUCT_ENABLE_LTO)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        message(FATAL_ERROR
                "DuctIo: DUCT_ENABLE_LTO is incompatible with Debug build")
    endif()
    if(NOT DUCT_IPO_SUPPORTED)
        message(FATAL_ERROR "DuctIo: LTO not supported: ${DUCT_IPO_ERROR}")
    endif()
endif()

function(duct_apply_lto target)
    if(NOT DUCT_ENABLE_LTO)
        return()
    endif()
    set_target_properties(${target} PROPERTIES
        INTERPROCEDURAL_OPTIMIZATION TRUE)
    # GCC's IPA proves an "address zero" object on paths its own callers guard
    # (every flagged access runs past a null check of the base pointer, and the
    # regions are conn-page carves whose bounds live in runtime offsets), then
    # sizes the destination at zero and flags every atomic and fortified
    # access inlined there as -Wstringop-overflow and -Warray-bounds. The
    # diagnostic runs twice: at each TU's compile pass and again in the lto1
    # pass at each consuming link, so the option rides both, and PUBLIC: the
    # tests linking this target emit it too. Clang does not merge those paths;
    # the diagnostics stay armed on non-LTO toolchains.
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${target} PUBLIC
            -Wno-stringop-overflow -Wno-array-bounds)
        target_link_options(${target} PUBLIC -Wno-stringop-overflow -Wno-array-bounds)
    endif()
endfunction()
