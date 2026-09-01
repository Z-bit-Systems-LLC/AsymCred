# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

# asymcred::pkoc - reader-side PKOC 1.1 transaction state machine and
# credential derivation. One translation unit per concern so a reader
# that only derives credentials from an already-read key does not link
# the state machine, and vice versa.
add_library(asymcred_pkoc STATIC
    src/pkoc.c
    src/pkoc_credential.c
)

target_include_directories(asymcred_pkoc
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

target_link_libraries(asymcred_pkoc PUBLIC asymcred_core)

target_compile_features(asymcred_pkoc PUBLIC c_std_11)

add_library(asymcred::pkoc ALIAS asymcred_pkoc)
