# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Duct Software, author: Constantin Papizh

# Public API.
add_executable(ductio_example_dual_transport_echo dual_transport_echo.c)
target_link_libraries(ductio_example_dual_transport_echo PRIVATE DuctIo::ductio)
target_compile_features(ductio_example_dual_transport_echo PRIVATE c_std_23)

# Uses the internal Noise handshake primitives, so it includes src/include.
if(DUCT_WITH_NOISE)
    add_executable(ductio_example_noise_register noise_register_service.c)
    target_link_libraries(ductio_example_noise_register PRIVATE
        DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_include_directories(ductio_example_noise_register PRIVATE
        ${DUCT_INTERNAL_INCLUDE_DIRS})
    target_compile_features(ductio_example_noise_register PRIVATE c_std_23)
endif()

# Public API.
if(DUCT_WITH_OPENSSL)
    add_executable(ductio_example_https_server https_server.c)
    target_link_libraries(ductio_example_https_server PRIVATE
        DuctIo::ductio OpenSSL::SSL OpenSSL::Crypto)
    target_compile_features(ductio_example_https_server PRIVATE c_std_23)
endif()

