#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Regression for #172: TracerPid seal enforcement is valid only when Linux
# self-trace is disabled.  Both configs must run cleanly, and the emitted IR
# must show enforcement only in the no-self-trace build.

set -euo pipefail

CLANG="$1"
PLUGIN="$2"
SDK="$3"
SRC="$4"
SELFTRACE_CFG="$5"
NO_SELFTRACE_CFG="$6"
SEED="${7:-1720}"

if [ "$(uname -s)" != "Linux" ]; then
  echo "SKIP TracerPid clean-run check requires Linux"
  exit 77
fi

SYSROOT=()
[ -n "$SDK" ] && SYSROOT=(-isysroot "$SDK")

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

CFLAGS=(-O2 -std=c11 -D_GNU_SOURCE -fno-builtin)

"$CLANG" "${SYSROOT[@]}" "${CFLAGS[@]}" "$SRC" -o "$TMP/clean"

build_obfuscated() {
  local cfg="$1"
  local stem="$2"
  env MOROK_ENABLE=1 MOROK_CONFIG="$cfg" MOROK_SEED="$SEED" \
    "$CLANG" "${SYSROOT[@]}" "${CFLAGS[@]}" -fpass-plugin="$PLUGIN" \
    "$SRC" -o "$TMP/$stem"
  env MOROK_ENABLE=1 MOROK_CONFIG="$cfg" MOROK_SEED="$SEED" \
    "$CLANG" "${SYSROOT[@]}" "${CFLAGS[@]}" -fpass-plugin="$PLUGIN" \
    -S -emit-llvm "$SRC" -o "$TMP/$stem.ll"
}

build_obfuscated "$SELFTRACE_CFG" selftrace
build_obfuscated "$NO_SELFTRACE_CFG" no_selftrace

require_ir_contains() {
  local file="$1"
  local needle="$2"
  if ! grep -q "$needle" "$file"; then
    echo "FAIL missing IR marker '$needle' in $file" >&2
    exit 1
  fi
}

require_ir_absent() {
  local file="$1"
  local needle="$2"
  if grep -q "$needle" "$file"; then
    echo "FAIL unexpected IR marker '$needle' in $file" >&2
    exit 1
  fi
}

for needle in \
  'morok\.antidbg\.status\.traced' \
  'morok\.antidbg\.watch\.status\.traced' \
  'morok\.antidbg\.probe\.status\.traced'; do
  require_ir_contains "$TMP/selftrace.ll" "$needle"
  require_ir_contains "$TMP/no_selftrace.ll" "$needle"
done

for needle in \
  'morok\.antidbg\.status\.enforced' \
  'morok\.antidbg\.watch\.status\.enforced' \
  'morok\.antidbg\.probe\.status\.enforced'; do
  require_ir_absent "$TMP/selftrace.ll" "$needle"
  require_ir_contains "$TMP/no_selftrace.ll" "$needle"
done

clean_out="$("$TMP/clean" 2>&1)"
selftrace_out="$("$TMP/selftrace" 2>&1)"
no_selftrace_out="$("$TMP/no_selftrace" 2>&1)"

if [ "$clean_out" != "$selftrace_out" ]; then
  echo "FAIL self-trace clean output mismatch" >&2
  printf 'clean: %s\nselftrace: %s\n' "$clean_out" "$selftrace_out" >&2
  exit 1
fi

if [ "$clean_out" != "$no_selftrace_out" ]; then
  echo "FAIL no-self-trace clean output mismatch" >&2
  printf 'clean: %s\nno-selftrace: %s\n' "$clean_out" "$no_selftrace_out" >&2
  exit 1
fi

echo "OK TracerPid clean run preserved: $selftrace_out"
