#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Compile a clean binary and a Morok-protected binary, post-link seal protected
# integrity manifests, then deliberately patch selected native bytes. The
# patched binary must not retain the same exit code and output as the sealed
# baseline.
#
# Usage:
#   adversarial_patch.sh <python3> <clang> <plugin> <sdk> <source> <config.toml> <patch-mode> [seed]
set -uo pipefail

PYTHON="$1"
CLANG="$2"
PLUGIN="$3"
SDK="$4"
SRC="$5"
CONFIG="$6"
PATCH_MODE="$7"
SEED="${8:-4242}"

ROOT="$(cd "$(dirname "$0")" && pwd)"
TOOL="$ROOT/adversarial_binary.py"

if [ -z "$SDK" ] && command -v xcrun >/dev/null 2>&1; then
  SDK="$(xcrun --show-sdk-path 2>/dev/null || true)"
fi

SYSROOT=()
[ -n "$SDK" ] && SYSROOT=(-isysroot "$SDK")

if command -v timeout >/dev/null 2>&1; then LIMIT=(timeout)
elif command -v gtimeout >/dev/null 2>&1; then LIMIT=(gtimeout)
else LIMIT=(); fi

run_limited() {
  local secs="$1"; shift
  if [ "${#LIMIT[@]}" -gt 0 ]; then
    "${LIMIT[@]}" "$secs" "$@"
  elif command -v perl >/dev/null 2>&1; then
    perl -e '
      use strict;
      use warnings;
      my $secs = shift @ARGV;
      my $pid = fork();
      die "fork failed\n" unless defined $pid;
      if ($pid == 0) {
        exec @ARGV;
        exit 127;
      }
      my $timed_out = 0;
      local $SIG{ALRM} = sub {
        $timed_out = 1;
        kill "TERM", $pid;
        select undef, undef, undef, 0.2;
        kill "KILL", $pid;
      };
      alarm $secs;
      waitpid($pid, 0);
      my $status = $?;
      alarm 0;
      exit 124 if $timed_out;
      exit 127 if $status == -1;
      exit(128 + ($status & 127)) if ($status & 127);
      exit(($status >> 8) & 255);
    ' "$secs" "$@"
  else
    "$@"
  fi
}

resign_if_needed() {
  local exe="$1"
  if [ "$(uname -s)" = "Darwin" ]; then
    /usr/bin/codesign --force --sign - "$exe" >/dev/null 2>&1 || {
      echo "FAIL codesign $exe" >&2
      return 1
    }
  fi
}

run_capture() {
  local exe="$1"
  local out="$2"
  local rcfile="$3"
  run_limited 30 "$exe" >"$out" 2>&1
  printf '%s\n' "$?" >"$rcfile"
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

CLEAN="$TMP/clean"
OBF="$TMP/obf"
PATCHED="$TMP/patched"
CLEAN_LOG="$TMP/clean.compile.log"
OBF_LOG="$TMP/obf.compile.log"
MOROK_ENV=(MOROK_ENABLE=1 MOROK_CONFIG="$CONFIG" MOROK_SEED="$SEED")

if ! "$CLANG" "${SYSROOT[@]}" -O2 -std=c11 -D_GNU_SOURCE "$SRC" \
    -o "$CLEAN" >"$CLEAN_LOG" 2>&1; then
  echo "FAIL clean compile" >&2
  tail -80 "$CLEAN_LOG" >&2
  exit 1
fi

if ! env "${MOROK_ENV[@]}" "$CLANG" "${SYSROOT[@]}" -O2 -std=c11 -D_GNU_SOURCE \
    -fpass-plugin="$PLUGIN" \
    "$SRC" -o "$OBF" >"$OBF_LOG" 2>&1; then
  echo "FAIL morok compile config=$CONFIG" >&2
  tail -120 "$OBF_LOG" >&2
  exit 1
fi

SEAL_ARGS=(seal "$OBF" --window 262144)
if [ "$PATCH_MODE" = "timing" ]; then
  SEAL_ARGS+=(--cover-timing-stubs)
fi

if ! "$PYTHON" "$TOOL" "${SEAL_ARGS[@]}"; then
  echo "FAIL post-link seal produced no integrity manifests" >&2
  exit 1
fi
if ! "$PYTHON" "$TOOL" assert-no-postlink-oracles "$OBF"; then
  echo "FAIL sealed binary retains post-link oracle data" >&2
  exit 1
fi
resign_if_needed "$OBF" || exit 1

run_capture "$CLEAN" "$TMP/clean.out" "$TMP/clean.rc"
run_capture "$OBF" "$TMP/obf.out" "$TMP/obf.rc"

if [ "$(cat "$TMP/clean.rc")" != "$(cat "$TMP/obf.rc")" ] ||
   ! cmp -s "$TMP/clean.out" "$TMP/obf.out"; then
  echo "FAIL sealed baseline changed behaviour" >&2
  echo "clean rc=$(cat "$TMP/clean.rc") output=$(cat "$TMP/clean.out")" >&2
  echo "obf   rc=$(cat "$TMP/obf.rc") output=$(cat "$TMP/obf.out")" >&2
  exit 1
fi

cp "$OBF" "$PATCHED"
case "$PATCH_MODE" in
  selfcheck-code)
    "$PYTHON" "$TOOL" patch-selfcheck-code "$PATCHED"
    patch_rc="$?"
    ;;
  mutualguard-code)
    "$PYTHON" "$TOOL" patch-mutualguard-code "$PATCHED"
    patch_rc="$?"
    ;;
  ckd-code)
    "$PYTHON" "$TOOL" patch-ckd-code "$PATCHED"
    patch_rc="$?"
    ;;
  ckd-downgrade)
    "$PYTHON" "$TOOL" patch-ckd-downgrade "$PATCHED"
    patch_rc="$?"
    ;;
  ckd-code-reset-size)
    "$PYTHON" "$TOOL" patch-ckd-code-reset-size "$PATCHED"
    patch_rc="$?"
    ;;
  timing)
    "$PYTHON" "$TOOL" patch-timing "$PATCHED"
    patch_rc="$?"
    ;;
  *)
    echo "FAIL unknown patch mode: $PATCH_MODE" >&2
    exit 1
    ;;
esac

if [ "$patch_rc" -eq 77 ]; then
  echo "SKIP patch mode $PATCH_MODE unsupported on this host binary"
  exit 77
fi
if [ "$patch_rc" -ne 0 ]; then
  echo "FAIL patch mode $PATCH_MODE failed" >&2
  exit "$patch_rc"
fi
resign_if_needed "$PATCHED" || exit 1

run_capture "$PATCHED" "$TMP/patched.out" "$TMP/patched.rc"

if [ "$(cat "$TMP/patched.rc")" = "$(cat "$TMP/obf.rc")" ] &&
   cmp -s "$TMP/patched.out" "$TMP/obf.out"; then
  echo "FAIL patched binary preserved sealed behaviour mode=$PATCH_MODE" >&2
  echo "rc=$(cat "$TMP/patched.rc") output=$(cat "$TMP/patched.out")" >&2
  exit 1
fi

echo "OK adversarial mode=$PATCH_MODE baseline='$(cat "$TMP/obf.out")' patched_rc=$(cat "$TMP/patched.rc")"
