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
endfunction()
