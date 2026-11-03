# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Duct Software, author: Constantin Papizh

cmake_minimum_required(VERSION 3.21)

set(DUCTIO_VERSION 0.1.1)

project(DuctIo VERSION "${DUCTIO_VERSION}" LANGUAGES C)

if(ANDROID AND CMAKE_C_COMPILER_VERSION VERSION_LESS 21)
    message(FATAL_ERROR "DuctIo Android requires NDK r29 / Clang 21+ for C23 constexpr linkage and anonymous-struct alignment")
endif()

set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# duct_ptr_t is a pointer to an array whose bound marks it as ours: a pointer of another type has to stop
# the build, where GCC 13 only warns by default.
add_compile_options(
    "$<$<COMPILE_LANGUAGE:C>:-Werror=incompatible-pointer-types>"
    "$<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU>>:-Werror=discarded-array-qualifiers>")

include(cmake/DetectPlatform.cmake)
include("cmake/platform/${DUCT_PLATFORM}.cmake")
include(cmake/PlatformConfigure.cmake)
include(cmake/CollectSources.cmake)
duct_detect_cpu(DUCT_ARCH)
include(cmake/RuntimeOptions.cmake)
include(cmake/LTO.cmake)

# Build axes for consumers; Config.cmake.in re-exports them on install.
set(DuctIo_WITH_OPENSSL "${DUCT_WITH_OPENSSL}" CACHE INTERNAL "")
set(DuctIo_WITH_NOISE "${DUCT_WITH_NOISE}" CACHE INTERNAL "")
set(DuctIo_EVENTS_MODEL "${DUCT_EVENTS_MODEL}" CACHE INTERNAL "")

duct_collect_os_sources(
    "${CMAKE_CURRENT_SOURCE_DIR}/${DUCT_PLATFORM_OS_DIR}"
    DUCTIO_SRC_OS
)

duct_collect_shared_os_sources(
    "${CMAKE_CURRENT_SOURCE_DIR}/os"
    DUCTIO_SRC_OS_SHARED
)
list(APPEND DUCTIO_SRC_OS ${DUCTIO_SRC_OS_SHARED})

duct_collect_arch_sources(
    "${CMAKE_CURRENT_SOURCE_DIR}/arch"
    DUCTIO_SRC_ARCH
)
list(APPEND DUCTIO_SRC_OS ${DUCTIO_SRC_ARCH})

duct_collect_src_sources(
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    DUCTIO_SRC
)

if(NOT DUCT_WITH_OPENSSL)
    list(REMOVE_ITEM DUCTIO_SRC
        "${CMAKE_CURRENT_SOURCE_DIR}/src/wire/duct_tls_openssl.c")
endif()

if(NOT DUCT_WITH_NOISE)
    list(REMOVE_ITEM DUCTIO_SRC
        "${CMAKE_CURRENT_SOURCE_DIR}/src/wire/duct_noise.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/wire/duct_noise_engine.c")
endif()

if(NOT DUCTIO_SRC_OS)
    message(FATAL_ERROR
        "DuctIo: no OS sources found under ${DUCT_PLATFORM_OS_DIR}/")
endif()
if(NOT DUCTIO_SRC)
    message(FATAL_ERROR "DuctIo: no sources found under src/")
endif()

if(DUCT_EVENTS_MODEL STREQUAL "poll" OR DUCT_EVENTS_MODEL STREQUAL "kqueue")
    set(DUCT_EVENTS_MODEL_DIR
        "${CMAKE_CURRENT_SOURCE_DIR}/os/${DUCT_EVENTS_MODEL}")
else()
    set(DUCT_EVENTS_MODEL_DIR
        "${CMAKE_CURRENT_SOURCE_DIR}/${DUCT_PLATFORM_OS_DIR}/${DUCT_EVENTS_MODEL}")
endif()

duct_collect_events_model_sources("${DUCT_EVENTS_MODEL_DIR}"
    DUCTIO_SRC_EVENTS_MODEL)

list(APPEND DUCTIO_SRC_OS ${DUCTIO_SRC_EVENTS_MODEL})

set(DUCT_INTERNAL_INCLUDE_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/os/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/${DUCT_PLATFORM_OS_DIR}/include"
)

add_library(ductio STATIC)
add_library(DuctIo::ductio ALIAS ductio)

set_target_properties(ductio PROPERTIES
    VERSION "${PROJECT_VERSION}"
    SOVERSION "${PROJECT_VERSION_MAJOR}"
)

target_sources(ductio
    PRIVATE
        ${DUCTIO_SRC_OS}
        ${DUCTIO_SRC}
)

duct_platform_configure(ductio)
duct_apply_lto(ductio)

if(DUCT_ENABLE_RUNTIME_STATS)
    target_compile_definitions(ductio PRIVATE DUCT_RUNTIME_STATS=1)
else()
    target_compile_definitions(ductio PRIVATE DUCT_RUNTIME_STATS=0)
endif()

if(DUCT_RIO_FORCE_DISABLE)
    target_compile_definitions(ductio PRIVATE DUCT_RIO_FORCE_DISABLE=1)
else()
    target_compile_definitions(ductio PRIVATE DUCT_RIO_FORCE_DISABLE=0)
endif()

if(DUCT_WITH_OPENSSL OR DUCT_WITH_NOISE)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(ductio PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()    

target_include_directories(ductio
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${DUCT_GENERATED_INCLUDE_DIR}>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${DUCT_INTERNAL_INCLUDE_DIRS}
)

target_compile_features(ductio PUBLIC c_std_23)

target_compile_options(ductio
    PRIVATE
        -Wall -Wextra -Wenum-conversion -Wformat=2
)

set(DUCT_TARGET_ARCH "" CACHE STRING
    "Optional -march value applied to ductio (e.g. x86-64-v3); empty keeps the portable GCC default")
if(DUCT_TARGET_ARCH)
    target_compile_options(ductio PRIVATE "-march=${DUCT_TARGET_ARCH}")
endif()

include(cmake/Install.cmake)

option(DUCT_BUILD_EXAMPLES "Build DuctIO examples" ${PROJECT_IS_TOP_LEVEL})
if(DUCT_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

option(DUCT_BUILD_TESTS "Build DuctIO tests" ${PROJECT_IS_TOP_LEVEL})
if(DUCT_BUILD_TESTS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test/CMakeLists.txt")
    enable_testing()
    add_subdirectory(test)
endif()

message(STATUS "DuctIo ${PROJECT_VERSION}\n"
    " platform: ${DUCT_PLATFORM}\n"
    " arch: ${DUCT_ARCH}\n"
    " build_type: ${CMAKE_BUILD_TYPE}\n"
    " runtime_stats: ${DUCT_ENABLE_RUNTIME_STATS}\n"
    " rio_force_disable: ${DUCT_RIO_FORCE_DISABLE}\n"
    " lto: ${DUCT_ENABLE_LTO}")
