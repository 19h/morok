#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Usage: caller_keyed_stack_base.sh <clang> <plugin> <sdk> <source>
set -euo pipefail

CLANG="$1"; PLUGIN="$2"; SDK="$3"; SRC="$4"
OPT="$(dirname "$CLANG")/opt"
if [ -z "$SDK" ] && command -v xcrun >/dev/null 2>&1; then
  SDK="$(xcrun --show-sdk-path 2>/dev/null || true)"
fi
CC=("$CLANG")
if [ -n "$SDK" ]; then CC+=(-isysroot "$SDK"); fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"${CC[@]}" -O2 -std=c11 -S -emit-llvm "$SRC" -o "$TMP/clean.ll"
"$OPT" -load-pass-plugin="$PLUGIN" -passes='morok-ckd,verify' \
  "$TMP/clean.ll" -S -o "$TMP/obf.ll"
grep -q '@morok.ckd.dispatch' "$TMP/obf.ll"

# The optimized source IR is already the workload. Lower the transformed IR
# directly, preserving the explicit dispatcher boundary for the ABI oracle.
"${CC[@]}" -O0 "$TMP/clean.ll" -o "$TMP/clean"
"${CC[@]}" -O0 "$TMP/obf.ll" -o "$TMP/obf"
"$TMP/clean"
"$TMP/obf"
echo "OK caller-keyed dispatch preserves stack locals and call arguments"
