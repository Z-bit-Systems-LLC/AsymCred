# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

# CMake toolchain file: cross-compile for 64-bit ARM Linux
# (aarch64-linux-gnu). Adapted from OSDP-Embedded's file of the same
# name; the two repos target the same reader hardware.
#
# Usage:
#   cmake -S . -B build-arm64 \
#     -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/aarch64-linux-gnu.cmake \
#     -DCMAKE_BUILD_TYPE=Release
#   cmake --build build-arm64
#
# Requires the GNU cross toolchain on PATH. On Debian/Ubuntu:
#   sudo apt-get install gcc-aarch64-linux-gnu
#
# This is a build-only cross target: the binaries it produces run on the
# ARM device, not on the build host. CI uses it as a compile/link gate
# (see ci/cross-arm64.yml); executing the test suite on-device needs a
# native/self-hosted ARM agent.

set(CMAKE_SYSTEM_NAME      Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

# The Debian/Ubuntu `gcc-aarch64-linux-gnu` package installs these
# triple-prefixed tools. Only C is needed (the project declares
# LANGUAGES C), so the C++ compiler is intentionally not set — that
# avoids requiring the separate g++ cross package.
set(cross_prefix aarch64-linux-gnu-)
set(CMAKE_C_COMPILER ${cross_prefix}gcc)
set(CMAKE_AR         ${cross_prefix}ar)
set(CMAKE_RANLIB     ${cross_prefix}ranlib)
set(CMAKE_STRIP      ${cross_prefix}strip)

# Cross-compile hygiene: find host programs on the host, but resolve
# headers and libraries only inside the target sysroot, so a host .so or
# header can never leak into an aarch64 link. AsymCred has no external
# dependencies at all (freestanding C; the crypto is supplied by the
# consumer through asymcred_crypto_t), so this is belt-and-suspenders —
# but it keeps the toolchain file correct if that ever changes.
set(CMAKE_FIND_ROOT_PATH /usr/aarch64-linux-gnu)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
