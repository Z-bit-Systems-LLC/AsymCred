# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

cmake_minimum_required(VERSION 3.16)

project(asymcred
    VERSION 0.1.0
    DESCRIPTION "Portable C11 asymmetric credential library (PKOC) for OSDP readers"
    LANGUAGES C
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(ASYMCRED_BUILD_TESTS "Build unit tests" ON)
option(ASYMCRED_SANITIZE    "Build with AddressSanitizer (and UBSan on GCC/Clang)" OFF)
option(ASYMCRED_WERROR      "Treat compiler warnings as errors (CI gate)" OFF)

# Strict warnings + per-function/data sections so consumers can use
# --gc-sections to drop anything they do not reference.
if(MSVC)
    add_compile_options(/W4 /permissive-)
    add_compile_options(/MP)
else()
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wconversion
        -Wsign-conversion
        -Wstrict-prototypes
        -Wmissing-prototypes
        -Wpointer-arith
        -Wcast-align
        -Wcast-qual
        -ffunction-sections
        -fdata-sections
    )
endif()

# Warnings-as-errors is a CI gate, not a build default. CI turns it on
# (ci/build-c.yml, ci/cross-arm64.yml) so a new warning cannot land;
# consumers building AsymCred inside their own tree keep warnings as
# warnings, so a compiler version this project has never seen cannot
# break their build over a diagnostic. The vendored Unity is insulated
# separately in tests/CMakeLists.txt.
if(ASYMCRED_WERROR)
    if(MSVC)
        add_compile_options(/WX)
    else()
        add_compile_options(-Werror)
    endif()
endif()

if(ASYMCRED_SANITIZE)
    if(MSVC)
        add_compile_options(/fsanitize=address /Od)
        string(REPLACE "/ZI" "/Zi" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
        string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
    else()
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
        add_link_options   (-fsanitize=address,undefined)
    endif()
    message(STATUS "AsymCred: AddressSanitizer build enabled")
endif()

add_subdirectory(core)
add_subdirectory(pkoc)

if(ASYMCRED_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
