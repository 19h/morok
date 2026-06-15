#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# End-to-end differential correctness check: compile a workload twice — once
# clean, once through the Morok plugin — run both, and require identical output.
# Proves the obfuscation is semantics-preserving for the given preset.
#
# Usage: differential.sh <clang> <plugin> <sdk> <source> <preset> [seed]
set -euo pipefail

CLANG="$1"; PLUGIN="$2"; SDK="$3"; SRC="$4"; PRESET="$5"; SEED="${6:-1234}"

# Fall back to the active SDK when the build did not pass an explicit sysroot.
if [ -z "$SDK" ] && command -v xcrun >/dev/null 2>&1; then
  SDK="$(xcrun --show-sdk-path 2>/dev/null || true)"
fi

SYSROOT=()
[ -n "$SDK" ] && SYSROOT=(-isysroot "$SDK")

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"$CLANG" "${SYSROOT[@]}" -O2 "$SRC" -o "$TMP/ref"
"$CLANG" "${SYSROOT[@]}" -O2 \
    -fpass-plugin="$PLUGIN" \
    -mllvm -morok -mllvm -morok-preset="$PRESET" -mllvm -morok-seed="$SEED" \
    "$SRC" -o "$TMP/obf"

REF="$("$TMP/ref")"
OBF="$("$TMP/obf")"

if [ "$REF" = "$OBF" ]; then
  echo "OK   preset=$PRESET seed=$SEED  output=$REF"
  exit 0
fi
echo "FAIL preset=$PRESET seed=$SEED  ref='$REF'  obf='$OBF'" >&2
exit 1
