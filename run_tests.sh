#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# run_tests.sh — single entrypoint that builds Morok and runs the ENTIRE test
# suite at once:
#
#   * core   logic / property unit tests   (PRNGs, ciphers, MBA & substitution
#            identities — no LLVM)
#   * config unit tests                     (preset/merge/resolve/TOML)
#   * ir     LLVM-linked pass unit tests    (each pass emits well-formed IR and
#            actually fires)
#   * e2e    differential tests             (c -> clang --morok--> binary, run
#            clean vs obfuscated, require identical output) across low/mid/high
#            and the `max` config
#   * e2e    programs sweep                 (compile EVERY program in programs/
#            clean and through the plugin at `high` and at `max` settings, then
#            run every target-supported program clean vs obfuscated at `max`)
#
# Any failure in any category fails the whole run.  This is the gate the project
# treats as authoritative: all passes must keep every sample program compiling
# at maximum settings.
#
# Usage:
#   ./run_tests.sh            # build (incremental) + run everything
#   ./run_tests.sh --clean    # wipe build/ and reconfigure from scratch first
#   ./run_tests.sh -R <regex> # only the tests whose name matches <regex>
#   ./run_tests.sh -L <label> # only the tests carrying <label> (core/config/
#                             #   ir/e2e/programs/max/unit/aggregate)
#
# Extra arguments after a bare `--` are forwarded verbatim to ctest.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD="$ROOT/build"
JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

# Toolchain: prefer whatever the build cache already pins; otherwise fall back to
# the custom LLVM install the project is developed against.
CLANG_DEFAULT="/Users/int/local/bin/clang"
CLANGXX_DEFAULT="/Users/int/local/bin/clang++"
LLVM_DIR_DEFAULT="/Users/int/local/lib/cmake/llvm"

CLEAN=0
CTEST_ARGS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --clean) CLEAN=1; shift ;;
    --) shift; CTEST_ARGS+=("$@"); break ;;
    *) CTEST_ARGS+=("$1"); shift ;;
  esac
done

if [ "$CLEAN" -eq 1 ]; then
  echo ">> wiping $BUILD"
  rm -rf "$BUILD"
fi

if [ ! -f "$BUILD/CMakeCache.txt" ]; then
  echo ">> configuring (fresh)"
  CC="${CC:-$CLANG_DEFAULT}"
  CXX="${CXX:-$CLANGXX_DEFAULT}"
  LLVM_DIR="${LLVM_DIR:-$LLVM_DIR_DEFAULT}"
  cmake -S "$ROOT" -B "$BUILD" -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DLLVM_DIR="$LLVM_DIR"
fi

echo ">> building"
cmake --build "$BUILD" -j "$JOBS"

echo ">> running full test suite (ctest -j $JOBS)"
set -x
ctest --test-dir "$BUILD" -j "$JOBS" --no-tests=error --output-on-failure "${CTEST_ARGS[@]}"
