# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Duct Software

# Compile-fail harness of the `alloc_misuse` test. Run as
#   cmake -DCC=<compiler> -DSRC=<alloc_misuse.c> -DINCLUDES=<dir>|<dir> -DGNU=<1|0> -P CheckAllocMisuse.cmake
# CC is the build's C compiler, INCLUDES the include directories of the library joined with `|`, and
# GNU is 1 for GCC, which takes one more flag than the others. The cases are the `CASE == N` lines of SRC:
# case 0 has to compile and every other case has to stop the compiler.

foreach(var CC SRC INCLUDES GNU)
    if(NOT DEFINED ${var})
        message(FATAL_ERROR "alloc_misuse: ${var} is not set")
    endif()
endforeach()

string(REPLACE "|" ";" include_dirs "${INCLUDES}")
set(flags -std=gnu2x -fsyntax-only -Werror=incompatible-pointer-types)
if(GNU)
    list(APPEND flags -Werror=discarded-array-qualifiers)
endif()
foreach(dir IN LISTS include_dirs)
    list(APPEND flags "-I${dir}")
endforeach()

file(STRINGS "${SRC}" case_lines REGEX "^#(el)?if CASE == [0-9]+")
set(failures "")
set(refused 0)
foreach(line IN LISTS case_lines)
    string(REGEX REPLACE "^#(el)?if CASE == ([0-9]+).*$" "\\2" case "${line}")
    execute_process(
        COMMAND "${CC}" ${flags} "-DCASE=${case}" "${SRC}"
        RESULT_VARIABLE rc
        OUTPUT_VARIABLE out
        ERROR_VARIABLE err)
    if(case EQUAL 0)
        if(NOT rc EQUAL 0)
            list(APPEND failures "case 0, the control, does not compile:\n${err}")
        endif()
    elseif(rc EQUAL 0)
        list(APPEND failures "case ${case} compiles, and has to stop the build")
    else()
        math(EXPR refused "${refused} + 1")
    endif()
endforeach()

if(refused EQUAL 0)
    list(APPEND failures "no case was read from ${SRC}")
endif()
if(failures)
    string(REPLACE ";" "\n" report "${failures}")
    message(FATAL_ERROR "alloc_misuse:\n${report}")
endif()
message(STATUS "alloc_misuse: ${refused} misuses stopped the build")
