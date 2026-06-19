#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Regression for #48: callback/ops-table dispatches must still run, while a
# vptr slot that was initialized from a harvested _ZTV address point must reject
# a later swap to an unknown table.
#
# Usage: vtable_integrity_dispatch.sh <clang++> <plugin> <sdk> <source> <config.toml> [seed]
set -euo pipefail

CXX="$1"
PLUGIN="$2"
SDK="$3"
SRC="$4"
CONFIG="$5"
SEED="${6:-4801}"

if [ -z "$SDK" ] && command -v xcrun >/dev/null 2>&1; then
  SDK="$(xcrun --show-sdk-path 2>/dev/null || true)"
fi

SYSROOT=()
[ -n "$SDK" ] && SYSROOT=(-isysroot "$SDK")

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

CXXFLAGS=(-O1 -std=c++17 -fno-exceptions)

"$CXX" "${SYSROOT[@]}" "${CXXFLAGS[@]}" "$SRC" -o "$TMP/ref"

env MOROK_ENABLE=1 MOROK_CONFIG="$CONFIG" MOROK_SEED="$SEED" \
  "$CXX" "${SYSROOT[@]}" "${CXXFLAGS[@]}" -fpass-plugin="$PLUGIN" \
  "$SRC" -o "$TMP/obf"

ref_ops="$("$TMP/ref" ops)"
obf_ops="$("$TMP/obf" ops)"
if [ "$ref_ops" != "$obf_ops" ] || [ "$obf_ops" != "ops=22" ]; then
  echo "FAIL ops-table path ref='$ref_ops' obf='$obf_ops'" >&2
  exit 1
fi

ref_virtual="$("$TMP/ref" virtual)"
obf_virtual="$("$TMP/obf" virtual)"
if [ "$ref_virtual" != "$obf_virtual" ] || [ "$obf_virtual" != "virtual=15" ]; then
  echo "FAIL virtual path ref='$ref_virtual' obf='$obf_virtual'" >&2
  exit 1
fi

ref_tamper="$("$TMP/ref" tamper)"
if [ "$ref_tamper" != "tamper=99" ]; then
  echo "FAIL clean tamper fixture expected fake-table dispatch, got '$ref_tamper'" >&2
  exit 1
fi

set +e
obf_tamper="$("$TMP/obf" tamper 2>&1)"
obf_tamper_rc=$?
set -e
if [ "$obf_tamper_rc" -eq 0 ]; then
  echo "FAIL protected tamper path returned successfully: '$obf_tamper'" >&2
  exit 1
fi

echo "OK vtable integrity ops='$obf_ops' virtual='$obf_virtual' tamper_rc=$obf_tamper_rc"
