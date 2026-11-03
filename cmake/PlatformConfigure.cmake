# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Duct Software, author: Constantin Papizh

# Apply platform variables from cmake/platform/<os>.cmake to a CMake target.
function(duct_platform_configure target)
    if(NOT DUCT_PLATFORM_OS_DIR)
        message(FATAL_ERROR
            "DUCT_PLATFORM_OS_DIR is unset, include cmake/platform/${DUCT_PLATFORM}.cmake first.")
    endif()
    if(DUCT_PLATFORM_COMPILE_DEFINITIONS)
        target_compile_definitions(${target} PRIVATE ${DUCT_PLATFORM_COMPILE_DEFINITIONS})
    endif()
    if(DUCT_PLATFORM_COMPILE_OPTIONS)
        target_compile_options(${target} PRIVATE ${DUCT_PLATFORM_COMPILE_OPTIONS})
    endif()
    if(DUCT_PLATFORM_LINK_LIBRARIES)
        target_link_libraries(${target} PUBLIC ${DUCT_PLATFORM_LINK_LIBRARIES})
    endif()
endfunction()
