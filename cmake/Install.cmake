# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Duct Software, author: Constantin Papizh

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS ductio
    EXPORT DuctIoTargets
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

file(GLOB _ductio_public_headers CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/duct.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/duct_*.h")
if(NOT DUCT_WITH_NOISE)
    list(REMOVE_ITEM _ductio_public_headers
        "${CMAKE_CURRENT_SOURCE_DIR}/include/duct_noise.h")
endif()
if(NOT DUCT_WITH_OPENSSL)
    list(REMOVE_ITEM _ductio_public_headers
        "${CMAKE_CURRENT_SOURCE_DIR}/include/duct_tls_openssl.h")
endif()
if(NOT _ductio_public_headers)
    message(FATAL_ERROR
        "DuctIo install: no public headers matched include/duct_*.h")
endif()
install(FILES ${_ductio_public_headers}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

if(DUCT_BUILD_CONFIG_HEADER)
    install(FILES "${DUCT_BUILD_CONFIG_HEADER}"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    )
endif()

install(EXPORT DuctIoTargets
    NAMESPACE DuctIo::
    FILE DuctIoTargets.cmake
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/DuctIo"
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/DuctIoConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/DuctIo"
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/DuctIoConfigVersion.cmake"
    VERSION "${PROJECT_VERSION}"
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/DuctIoConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/DuctIoConfigVersion.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/DuctIo"
)

# Rust workspace, installed beside the C package.
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bindings/rust/"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/ductio/rust"
    PATTERN "target" EXCLUDE
    PATTERN "target-*" EXCLUDE
    PATTERN ".gitignore" EXCLUDE
)
