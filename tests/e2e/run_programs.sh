#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Runtime differential over a curated set of self-contained sample programs:
# compile each one clean and through the Morok plugin, run BOTH (no stdin), and
# require identical output.  This is the gate the plain compile sweep cannot
# provide — it catches *miscompilations* that still produce valid, compilable IR
# but wrong runtime behaviour (e.g. a string that decrypts to garbage).
#
# Only deterministic, self-contained programs are listed: nothing that prints
# timings, raw pointers, random data, depends on stdin/args/network/files, or is
# a long-running benchmark.  Output is normalized to drop the few inherently
# non-deterministic lines (elapsed time, hex addresses) before diffing.
#
# Usage:
#   run_programs.sh <clang> <clang++> <plugin> <sdk> <program-dir> <preset|config> [seed]
set -uo pipefail

CLANG="$1"; CLANGXX="$2"; PLUGIN="$3"; SDK="$4"; DIR="$5"; CFG="$6"; SEED="${7:-1234}"

# Fall back to the active SDK when the build did not pass an explicit sysroot.
if [ -z "$SDK" ] && command -v xcrun >/dev/null 2>&1; then
  SDK="$(xcrun --show-sdk-path 2>/dev/null || true)"
fi

SYSROOT=()
[ -n "$SDK" ] && SYSROOT=(-isysroot "$SDK")

MOROK=()
if [ -f "$CFG" ]; then MOROK=(-mllvm -morok-config="$CFG"); else MOROK=(-mllvm -morok-preset="$CFG"); fi

# Curated deterministic programs (pure-result output, quick, no external input).
PROGRAMS=(
  01_hello_world.c 09_bytecode_vm.c
  int_sha256.c int_crc32.c int_popcount.c int_galois.c int_bitfields.c
  int_int128_ops.c int_carryless_crc_mesh.c int_divrem_wide_lattice.c
  simd_dot_product.c simd_matrix_mul.c simd_portable_bitplane.c
  call_many_int_args.c call_many_float_args.c call_variadic.c call_nested.c
  call_tail_recursive.c call_struct_return.c
  cf_switch_dense.c cf_switch_sparse.c cf_computed_goto.c cf_duff_device_parser.c
  mem_strided.c mem_sequential.c mem_unaligned_packed.c
  min_add_chain.c min_mul_chain.c min_shift_chain.c min_bitwise.c
  07_regex.c 08_json_parser.cpp 04_bst.cpp
  cpp_rtti.cpp cpp_virtual.cpp cpp_constexpr_variant_graph.cpp
)

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
# Strip inherently non-deterministic lines so they do not cause false failures.
NOISE='Time|elapsed|seconds|nanosecond|µs| ns | ms |cycles|faster|throughput|MB/s|0x[0-9a-fA-F]{6,}'

fails=0; total=0
for base in "${PROGRAMS[@]}"; do
  src="$DIR/$base"
  [ -f "$src" ] || { echo "skip (absent) $base"; continue; }
  total=$((total + 1))
  cc=("$CLANG"); std=(-std=c11)
  case "$src" in *.cpp) cc=("$CLANGXX"); std=(-std=c++23);; esac

  if ! "${cc[@]}" "${SYSROOT[@]}" -O2 "${std[@]}" "$src" -o "$TMP/clean" >/dev/null 2>&1; then
    echo "FAIL clean-compile $base" >&2; fails=$((fails + 1)); continue; fi
  if ! "${cc[@]}" "${SYSROOT[@]}" -O2 "${std[@]}" -fpass-plugin="$PLUGIN" \
        -mllvm -morok "${MOROK[@]}" -mllvm -morok-seed="$SEED" \
        "$src" -o "$TMP/obf" >/dev/null 2>&1; then
    echo "FAIL obf-compile $base" >&2; fails=$((fails + 1)); continue; fi

  a="$(timeout 30 "$TMP/clean" </dev/null 2>&1)"; ca=$?
  b="$(timeout 60 "$TMP/obf"   </dev/null 2>&1)"; cb=$?
  if [ "$ca" -ne "$cb" ]; then
    echo "FAIL exit-code $base (clean=$ca obf=$cb)" >&2; fails=$((fails + 1)); continue; fi
  if [ "$(printf '%s' "$a" | grep -vE "$NOISE")" != \
       "$(printf '%s' "$b" | grep -vE "$NOISE")" ]; then
    echo "FAIL output-mismatch $base" >&2
    diff <(printf '%s' "$a" | grep -vE "$NOISE") \
         <(printf '%s' "$b" | grep -vE "$NOISE") | head -8 >&2
    fails=$((fails + 1)); continue; fi
  echo "OK $base"
done

if [ "$fails" -ne 0 ]; then
  echo "FAIL runtime-differential programs=$total failures=$fails config=$CFG" >&2
  exit 1
fi
echo "OK runtime-differential programs=$total config=$CFG seed=$SEED"
