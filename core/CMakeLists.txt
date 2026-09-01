# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

# asymcred::core - transport-agnostic primitives shared by every
# credential standard: the PKOC-dialect TLV codec and ISO 7816-4 short
# APDU helpers. Carries no standard-specific logic.
add_library(asymcred_core STATIC
    src/shared/tlv.c
    src/shared/apdu.c
)

target_include_directories(asymcred_core
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

target_compile_features(asymcred_core PUBLIC c_std_11)

add_library(asymcred::core ALIAS asymcred_core)
