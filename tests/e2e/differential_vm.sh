#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Virtualization differential gate.  Like differential.sh, but in addition to
# requiring identical clean-vs-obfuscated output it asserts exact coverage of
# every explicitly targeted workload function, absence of the old reversible
# opcode-shadow table, a non-complete handler ISA, and cross-seed topology
# diversity.  A regression that silently leaves only one target protected can
# no longer pass merely because one `morok.vm.bytecode.*` global exists.
#
# Usage: differential_vm.sh <clang> <plugin> <sdk> <source> <config.toml> [seed]
set -euo pipefail

CLANG="$1"; PLUGIN="$2"; SDK="$3"; SRC="$4"; CONFIG="$5"; SEED="${6:-4242}"

if [ -z "$SDK" ] && command -v xcrun >/dev/null 2>&1; then
  SDK="$(xcrun --show-sdk-path 2>/dev/null || true)"
fi
SYSROOT=()
[ -n "$SDK" ] && SYSROOT=(-isysroot "$SDK")

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

MOROK_ENV=(MOROK_ENABLE=1 MOROK_CONFIG="$CONFIG" MOROK_SEED="$SEED")
VM_CFLAGS=(-O2 -fno-vectorize -fno-slp-vectorize)

"$CLANG" "${SYSROOT[@]}" "${VM_CFLAGS[@]}" "$SRC" -o "$TMP/ref"
env "${MOROK_ENV[@]}" "$CLANG" "${SYSROOT[@]}" "${VM_CFLAGS[@]}" \
    -fpass-plugin="$PLUGIN" \
    "$SRC" -o "$TMP/obf"
env "${MOROK_ENV[@]}" "$CLANG" "${SYSROOT[@]}" "${VM_CFLAGS[@]}" \
    -fpass-plugin="$PLUGIN" \
    -S -emit-llvm "$SRC" -o "$TMP/obf.ll"

# A neighboring seed must change native VM topology, not only ciphertext and
# numeric handler IDs.  This is a resistance property, separate from semantic
# equivalence of the primary build.
ALT_SEED=$((SEED + 1))
env MOROK_ENABLE=1 MOROK_CONFIG="$CONFIG" MOROK_SEED="$ALT_SEED" \
    "$CLANG" "${SYSROOT[@]}" "${VM_CFLAGS[@]}" \
    -fpass-plugin="$PLUGIN" -S -emit-llvm "$SRC" -o "$TMP/obf-alt.ll"

LIFTED="$(grep -c '^@morok\.vm\.bytecode\.' "$TMP/obf.ll" || true)"
EXPECTED=(sum_weighted fnv1a route range_count)
if [ "$LIFTED" -ne "${#EXPECTED[@]}" ]; then
  echo "FAIL config=$CONFIG seed=$SEED  expected ${#EXPECTED[@]} VM payloads, found $LIFTED" >&2
  exit 1
fi
for FN in "${EXPECTED[@]}"; do
  if ! grep -q "@morok\.vm\.bytecode\.$FN" "$TMP/obf.ll"; then
    echo "FAIL config=$CONFIG seed=$SEED  explicitly targeted function '$FN' remained native" >&2
    exit 1
  fi
done
if grep -q '^@morok\.vm\.opguard\.' "$TMP/obf.ll"; then
  echo "FAIL config=$CONFIG seed=$SEED  reversible opcode-shadow table was emitted" >&2
  exit 1
fi
PAGE_CACHES="$(grep -c '^@morok\.fpp\.page\.cache\..*= private .*global \[64 x i8\]' \
    "$TMP/obf.ll" || true)"
if [ "$PAGE_CACHES" -ne "${#EXPECTED[@]}" ]; then
  echo "FAIL config=$CONFIG seed=$SEED  expected ${#EXPECTED[@]} 64-byte page caches, found $PAGE_CACHES" >&2
  exit 1
fi
if grep -q '^define private void @morok\.sdb\.ensure\.' "$TMP/obf.ll"; then
  echo "FAIL config=$CONFIG seed=$SEED  eager full-payload decryptor was emitted" >&2
  exit 1
fi

TOPOLOGY=""
ALT_TOPOLOGY=""
for FN in "${EXPECTED[@]}"; do
  COUNT="$(grep "^@morok.vm.targets.$FN " "$TMP/obf.ll" | \
      grep -oE 'exec, %[0-9]+' | sort -u | wc -l | tr -d ' ')"
  ALT_COUNT="$(grep "^@morok.vm.targets.$FN " "$TMP/obf-alt.ll" | \
      grep -oE 'exec, %[0-9]+' | sort -u | wc -l | tr -d ' ')"
  if [ "$COUNT" -ge 55 ] || [ "$ALT_COUNT" -ge 55 ]; then
    echo "FAIL function=$FN  complete fixed VM ISA exposed ($COUNT/$ALT_COUNT targets)" >&2
    exit 1
  fi
  TOPOLOGY="$TOPOLOGY:$COUNT"
  ALT_TOPOLOGY="$ALT_TOPOLOGY:$ALT_COUNT"
done
if [ "$TOPOLOGY" = "$ALT_TOPOLOGY" ]; then
  echo "FAIL seeds=$SEED/$ALT_SEED  VM handler topology did not change ($TOPOLOGY)" >&2
  exit 1
fi

REF="$("$TMP/ref")"
OBF="$("$TMP/obf")"
if [ "$REF" != "$OBF" ]; then
  echo "FAIL config=$CONFIG seed=$SEED  ref='$REF'  obf='$OBF'" >&2
  exit 1
fi
echo "OK   config=$CONFIG seed=$SEED  lifted=$LIFTED topology=$TOPOLOGY/$ALT_TOPOLOGY  output=$REF"
exit 0
