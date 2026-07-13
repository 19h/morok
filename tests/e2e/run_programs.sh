#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Runtime differential over the full sample-program corpus: compile each
# program clean and through the Morok plugin, run BOTH (no stdin), and require
# identical exit status and normalized output.  This is the gate the plain
# compile sweep cannot provide — it catches *miscompilations* that still produce
# valid, compilable IR but wrong runtime behaviour (e.g. a string that decrypts
# to garbage).
#
# Usage:
#   run_programs.sh <clang> <clang++> <plugin> <sdk> <program-dir> <preset|config> [seed]
#
# MOROK_SKIP excludes target-unsupported programs from both compile and runtime
# corpus tests. MOROK_RUN_SKIP excludes runtime-only stress cases while leaving
# the compile sweeps strict.
set -uo pipefail

CLANG="$1"; CLANGXX="$2"; PLUGIN="$3"; SDK="$4"; DIR="$5"; CFG="$6"; SEED="${7:-1234}"

# Fall back to the active SDK when the build did not pass an explicit sysroot.
if [ -z "$SDK" ] && command -v xcrun >/dev/null 2>&1; then
  SDK="$(xcrun --show-sdk-path 2>/dev/null || true)"
fi

# Resolve a portable run-time limiter. GNU coreutils ships `timeout` (Linux);
# Homebrew installs it as `gtimeout` (macOS); stock macOS has neither, so fall
# back to running without a hard limit (ctest's per-test TIMEOUT still bounds
# the whole test).  Without this, a missing `timeout` makes *both* clean and obf
# runs emit an identical-looking shell error that, because the two call sites are
# on different lines, diffs as a spurious mismatch on every program.
LIMIT_BIN=""
if command -v timeout >/dev/null 2>&1; then LIMIT_BIN=timeout
elif command -v gtimeout >/dev/null 2>&1; then LIMIT_BIN=gtimeout; fi
CLEAN_TIMEOUT="${MOROK_RUN_CLEAN_TIMEOUT:-30}"
OBF_TIMEOUT="${MOROK_RUN_OBF_TIMEOUT:-300}"
run_limited() { # <seconds> <cmd...>
  local secs="$1"; shift
  if [ -n "$LIMIT_BIN" ]; then "$LIMIT_BIN" "$secs" "$@"; else "$@"; fi
}

MOROK_ENV=(MOROK_ENABLE=1 MOROK_SEED="$SEED")
if [ -f "$CFG" ]; then MOROK_ENV+=(MOROK_CONFIG="$CFG"); else MOROK_ENV+=(MOROK_PRESET="$CFG"); fi

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
# Strip inherently non-deterministic lines so they do not cause false failures.
NOISE='Time|elapsed|seconds|nanosecond|µs| ns | ms | ms\)|cycles|faster|speedup|throughput|tasks pending|MB/s|0x[0-9a-fA-F]{6,}'

compile_one() { # <src> <out> <log> [clean|obf]
  local src="$1"; local out="$2"; local log="$3"; local mode="$4"
  local cc=("$CLANG"); local std=(-std=c11 -D_GNU_SOURCE)
  local ldlibs=()
  case "$src" in *.cpp) cc=("$CLANGXX"); std=(-std=c++23 -D_GNU_SOURCE);; esac
  [ "${RUNNER_OS:-}" = "Windows" ] || ldlibs=(-lm)

  if [ "$mode" = "obf" ]; then
    if [ -n "$SDK" ]; then
      env "${MOROK_ENV[@]}" "${cc[@]}" -isysroot "$SDK" -O2 "${std[@]}" \
        -fpass-plugin="$PLUGIN" \
        "$src" -o "$out" "${ldlibs[@]}" >"$log" 2>&1
    else
      env "${MOROK_ENV[@]}" "${cc[@]}" -O2 "${std[@]}" \
        -fpass-plugin="$PLUGIN" \
        "$src" -o "$out" "${ldlibs[@]}" >"$log" 2>&1
    fi
  else
    if [ -n "$SDK" ]; then
      "${cc[@]}" -isysroot "$SDK" -O2 "${std[@]}" \
        "$src" -o "$out" "${ldlibs[@]}" >"$log" 2>&1
    else
      "${cc[@]}" -O2 "${std[@]}" \
        "$src" -o "$out" "${ldlibs[@]}" >"$log" 2>&1
    fi
  fi
}

run_capture() { # <seconds> <exe> <cwd> <out>
  local seconds="$1"; local exe="$2"; local cwd="$3"; local out="$4"
  shift 4
  mkdir -p "$cwd"
  (cd "$cwd" && run_limited "$seconds" "$exe" "$@" </dev/null >"$out" 2>&1)
}

normalize_output() { # <in> <out>
  grep -viE "$NOISE" "$1" >"$2" || true
}

is_listed() { # <basename> <space-separated-list>
  case " $2 " in *" $1 "*) return 0;; *) return 1;; esac
}

fails=0; total=0; skipped=0; discovered=0
while IFS= read -r src; do
  base="$(basename "$src")"
  discovered=$((discovered + 1))
  # See compile_programs.sh: exclude programs not yet supported on this target.
  # MOROK_RUN_SKIP is runtime-only and must not weaken the compile sweeps.
  if is_listed "$base" "${MOROK_SKIP:-}" || is_listed "$base" "${MOROK_RUN_SKIP:-}"; then
    echo "skip (excluded on this target) $base"
    skipped=$((skipped + 1))
    continue
  fi

  src="$DIR/$base"
  total=$((total + 1))

  clean="$TMP/${base%.*}.clean"
  obf="$TMP/${base%.*}.obf"
  clean_log="$TMP/${base%.*}.clean.compile.log"
  obf_log="$TMP/${base%.*}.obf.compile.log"

  if ! compile_one "$src" "$clean" "$clean_log" clean; then
    echo "FAIL clean-compile $base" >&2
    tail -80 "$clean_log" >&2
    fails=$((fails + 1))
    continue
  fi
  if ! compile_one "$src" "$obf" "$obf_log" obf; then
    echo "FAIL obf-compile $base" >&2
    tail -120 "$obf_log" >&2
    fails=$((fails + 1))
    continue
  fi

  clean_out="$TMP/${base%.*}.clean.out"
  obf_out="$TMP/${base%.*}.obf.out"
  clean_norm="$TMP/${base%.*}.clean.norm"
  obf_norm="$TMP/${base%.*}.obf.norm"
  extra_arg=""
  case "$base" in
    02_fibonacci.c) extra_arg="30" ;;
  esac

  if [ -n "$extra_arg" ]; then
    run_capture "$CLEAN_TIMEOUT" "$clean" "$TMP/${base%.*}.clean.cwd" "$clean_out" "$extra_arg"; ca=$?
    run_capture "$OBF_TIMEOUT" "$obf" "$TMP/${base%.*}.obf.cwd" "$obf_out" "$extra_arg"; cb=$?
  else
    run_capture "$CLEAN_TIMEOUT" "$clean" "$TMP/${base%.*}.clean.cwd" "$clean_out"; ca=$?
    run_capture "$OBF_TIMEOUT" "$obf" "$TMP/${base%.*}.obf.cwd" "$obf_out"; cb=$?
  fi
  if [ -n "$LIMIT_BIN" ] && [ "$ca" -eq 124 ]; then
    echo "FAIL timeout-clean $base" >&2
    fails=$((fails + 1))
    continue
  fi
  if [ -n "$LIMIT_BIN" ] && [ "$cb" -eq 124 ]; then
    echo "FAIL timeout-obf $base" >&2
    fails=$((fails + 1))
    continue
  fi
  if [ "$ca" -ne "$cb" ]; then
    echo "FAIL exit-code $base (clean=$ca obf=$cb)" >&2; fails=$((fails + 1)); continue; fi

  normalize_output "$clean_out" "$clean_norm"
  normalize_output "$obf_out" "$obf_norm"
  if ! cmp -s "$clean_norm" "$obf_norm"; then
    echo "FAIL output-mismatch $base" >&2
    diff "$clean_norm" "$obf_norm" | head -8 >&2
    fails=$((fails + 1)); continue; fi
  echo "OK $base exit=$ca"
done < <(find "$DIR" -maxdepth 1 -type f \( -name '*.c' -o -name '*.cpp' \) | sort)

if [ "$discovered" -eq 0 ]; then
  echo "FAIL no programs found in $DIR" >&2
  exit 1
fi

if [ "$total" -eq 0 ]; then
  echo "FAIL no runnable programs selected in $DIR" >&2
  exit 1
fi

if [ "$fails" -ne 0 ]; then
  echo "FAIL runtime-differential programs=$total skipped=$skipped failures=$fails config=$CFG" >&2
  exit 1
fi
echo "OK runtime-differential programs=$total skipped=$skipped config=$CFG seed=$SEED"
