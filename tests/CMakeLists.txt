# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

# Vendored Unity test framework (MIT-licensed; see vendor/unity/LICENSE.txt).
add_library(unity STATIC vendor/unity/unity.c)
target_include_directories(unity PUBLIC vendor/unity)

if(NOT MSVC)
    target_compile_options(unity PRIVATE -w)
endif()

# Test-only crypto binding. The library ships no crypto (see CLAUDE.md);
# this supplies a real SHA-256 and a scriptable ECDSA stub so tests can
# assert what the state machine hands to verification.
add_library(asymcred_test_crypto STATIC support/test_crypto.c)
target_link_libraries(asymcred_test_crypto PUBLIC asymcred_core)
target_include_directories(asymcred_test_crypto
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Helper: declare an AsymCred unit test executable from a single .c file.
function(asymcred_add_test test_name)
    add_executable(${test_name} ${test_name}.c)
    target_link_libraries(${test_name} PRIVATE
        asymcred_core asymcred_pkoc asymcred_test_crypto unity)
    target_include_directories(${test_name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME ${test_name} COMMAND ${test_name})
endfunction()

asymcred_add_test(test_tlv)
asymcred_add_test(test_apdu)
asymcred_add_test(test_pkoc)
asymcred_add_test(test_pkoc_credential)
