#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Cross-build one source through Morok for Linux and macOS.
#
# Defaults match the crackme command commonly used during development:
#   ./cross_build.sh
#
# Outputs are written under build/cross/ so generated binaries stay out of git.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
HOST_OS="$(uname -s)"
HOST_ARCH="$(uname -m)"
case "$HOST_OS" in
  Darwin)
    DEFAULT_BUILD_MACOS=1
    DEFAULT_PLUGIN_EXT="dylib"
    DEFAULT_LINUX_TARGET="x86_64-linux-musl"
    ;;
  Linux)
    DEFAULT_BUILD_MACOS=0
    DEFAULT_PLUGIN_EXT="so"
    case "$HOST_ARCH" in
      x86_64|amd64) DEFAULT_LINUX_TARGET="x86_64-linux-gnu" ;;
      aarch64|arm64) DEFAULT_LINUX_TARGET="aarch64-linux-gnu" ;;
      *) DEFAULT_LINUX_TARGET="$HOST_ARCH-linux-gnu" ;;
    esac
    ;;
  *)
    DEFAULT_BUILD_MACOS=0
    DEFAULT_PLUGIN_EXT="so"
    DEFAULT_LINUX_TARGET="x86_64-linux-musl"
    ;;
esac

SRC="programs/cf_license_crackme.c"
OUT_DIR="${OUT_DIR:-$BUILD_DIR/cross}"
CLANG="${CLANG:-clang-23}"
CLANGXX="${CLANGXX:-clang++}"
PLUGIN="${PLUGIN:-$BUILD_DIR/src/pipeline/libMorok.$DEFAULT_PLUGIN_EXT}"
PRESET="${PRESET:-max}"
CONFIG=""
# Default to Morok's entropy-seeded mode (seed 0): each build draws a fresh PRNG
# stream, so layout decisions, salts, and generated runtime material differ per
# build (per-build polymorphism).  A fixed nonzero default would make every
# rebuild byte-comparable and fingerprintable.  Pass --seed N (or SEED=N) for an
# intentionally reproducible build.
SEED="${SEED:-0}"
OPT_LEVEL="${OPT_LEVEL:--O3}"

# Extra flexibility for multi-file projects (e.g. crackmes/zorya).
# EXTRA_SOURCES: additional source files compiled alongside SRC.
# EXTRA_CFLAGS:  extra compiler flags (e.g. -no-pie -ffast-math).
# LIBS:          extra link libraries (e.g. -lpthread).
# C_STD:         override the C/C++ standard (default: c11 / c++23).
EXTRA_SOURCES="${EXTRA_SOURCES:-}"
EXTRA_CFLAGS="${EXTRA_CFLAGS:-}"
LIBS="${LIBS:-}"
C_STD=""

# Post-link self-check sealing.  The self_checksum/DFI passes emit a runtime
# native-code hash gated on a patchable window length that is only filled in
# after the final layout is known.  Without this step the window length stays at
# its unsealed sentinel, the code-byte hash is skipped, and a patched branch is
# never detected.  Sealing is mandatory for a shippable binary.
SEAL_BINARIES="${SEAL_BINARIES:-1}"
SEAL_WINDOW="${SEAL_WINDOW:-262144}"
SEAL_TOOL="${SEAL_TOOL:-$ROOT/tests/e2e/adversarial_binary.py}"
AUDIT_BINARIES="${AUDIT_BINARIES:-$SEAL_BINARIES}"
AUDIT_TOOL="${AUDIT_TOOL:-$ROOT/tools/morok-audit.py}"
AUDIT_PROVENANCE="${AUDIT_PROVENANCE:-}"
AUDIT_ALLOWLIST="${AUDIT_ALLOWLIST:-}"
PYTHON="${PYTHON:-python3}"

# Optional Linux/x86-64 runtime-metadata shadowing.  This is a post-link ELF
# transform, so it is meaningful only for dynamically linked Linux outputs.
# The conventional DT_JMPREL records name per-site decoy symbols and target a
# derangement of GOT slots, while a later page-overlapping PT_LOAD supplies the
# complete original records to the runtime loader.
ELF_SHADOW="${ELF_SHADOW:-0}"
ELF_SHADOW_TOOL="${ELF_SHADOW_TOOL:-$ROOT/tools/morok_elf_shadow.py}"
ELF_SHADOW_MAX_BYTES="${ELF_SHADOW_MAX_BYTES:-1048576}"

# Optional Linux ELF64 native-code packing.  This is explicitly outside the
# ordinary presets: enabling it changes the link/finalization contract and
# therefore requires this build-pipeline switch in addition to the IR pass.
NATIVE_PACK="${NATIVE_PACK:-0}"
NATIVE_PACK_TOOL="${NATIVE_PACK_TOOL:-$BUILD_DIR/src/packer/morok-native-pack}"
NATIVE_PACK_LOADER="${NATIVE_PACK_LOADER:-$ROOT/runtime/native_pack_loader.c}"
NATIVE_PACK_META="${NATIVE_PACK_META:-$ROOT/runtime/native_pack_meta.S}"
NATIVE_PACK_SCRIPT="${NATIVE_PACK_SCRIPT:-$ROOT/runtime/native_pack.ld}"
NATIVE_PACK_TEMP=""

cleanup_native_pack_temp() {
  if [ -n "$NATIVE_PACK_TEMP" ] && [ -d "$NATIVE_PACK_TEMP" ]; then
    rm -rf "$NATIVE_PACK_TEMP"
  fi
}
trap cleanup_native_pack_temp EXIT

BUILD_LINUX=1
BUILD_MACOS="$DEFAULT_BUILD_MACOS"
STRIP_BINARIES=1
CLEAN_OUT=0
CHECK_CLEAN_DIR=0
EMIT_PLATFORM_DEFAULTS=0

LINUX_TARGET="${LINUX_TARGET:-$DEFAULT_LINUX_TARGET}"
LINUX_CC="${LINUX_CC:-}"
LINUX_STATIC="${LINUX_STATIC:-1}"

MACOS_ARCHES="${MACOS_ARCHES:-$(uname -m)}"
MACOS_MIN="${MACOS_MIN:-13.0}"
MACOS_SDK="${MACOS_SDK:-}"

usage() {
  cat <<'USAGE'
Usage:
  ./cross_build.sh [options] [source]

Options:
  --source PATH          Source file to build (default: programs/cf_license_crackme.c)
  --out-dir DIR          Output directory (default: build/cross)
  --preset NAME          Morok preset when --config is not used (default: max)
  --config PATH          Morok TOML config instead of a preset
  --seed N               Morok seed; 0 = per-build entropy (default: 0)
  --clang PATH           C compiler with the Morok pass ABI (default: clang-23)
  --clangxx PATH         C++ compiler with the Morok pass ABI (default: clang++)
  --plugin PATH          Morok pass plugin (default: host suffix, .dylib on macOS,
                         .so elsewhere)
  --linux-target TRIPLE  Linux target triple (default: host-aware)
  --linux-cc PATH        GCC-compatible cross toolchain driver for crt/libgcc lookup
  --macos-arches LIST    Space-separated macOS arches: native, arm64, x86_64
                         (default: current host arch)
  --macos-min VERSION    macOS deployment target (default: 13.0)
  --linux-only           Build only the Linux artifact
  --macos-only           Build only the macOS artifact(s); requires a Darwin host
  --no-linux             Skip Linux
  --no-macos             Skip macOS
  --no-strip             Do not strip produced binaries
  --no-audit             Skip the final morok-audit release gate
  --clean                Wipe a safely constrained output dir before building
  --dynamic              Linux dynamic link (default: static)
  --elf-shadow           Apply Linux/x86-64 DT_JMPREL symbol/offset shadowing;
                         requires
                         --dynamic (default: off)
  --no-elf-shadow        Disable DT_JMPREL page shadowing
  --native-pack          Lazily encrypt selected native functions in the Linux
                         ELF64 output; implies --linux-only and is incompatible
                         with --elf-shadow
  --no-native-pack       Disable native-code packing (default)
  --extra-cflags FLAGS   Extra compiler flags (e.g. "-no-pie -ffast-math")
  --extra-sources PATHS  Extra source files compiled alongside the main source
                         (space-separated, e.g. "tweetnacl.c")
  --libs FLAGS           Extra link libraries (e.g. "-lpthread")
  --c-std STD            Override C/C++ standard (e.g. c23, c17, c++20)
  -h, --help             Show this help

Environment overrides mirror the option names in uppercase, for example:
  SRC=programs/01_hello_world.c MACOS_ARCHES="arm64 x86_64" ./cross_build.sh
  LINUX_TARGET=i686-linux-musl LINUX_CC=i686-linux-musl-gcc ./cross_build.sh
  AUDIT_TOOL=tools/morok-audit.py AUDIT_PROVENANCE=build/cross/audit.json ./cross_build.sh
  AUDIT_ALLOWLIST=release-audit-allow.json ./cross_build.sh

Multi-file Linux-only project (e.g. crackmes/zorya):
  ./cross_build.sh --linux-only --no-macos \
    --source crackmes/zorya/zorya.c \
    --extra-sources "crackmes/zorya/tweetnacl.c" \
    --libs "-lpthread" \
    --extra-cflags "-no-pie -ffast-math -Wno-implicit-function-declaration" \
    --c-std c23 \
    --config crackmes/zorya/morok-linux-static.toml \
    --seed 1234
USAGE
}

die() {
  echo "error: $*" >&2
  exit 1
}

need_tool() {
  command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"
}

root_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "$ROOT" "$1" ;;
  esac
}

canonical_path() {
  need_tool "$PYTHON"
  "$PYTHON" - "$1" <<'PY'
import os
import sys

print(os.path.realpath(sys.argv[1]))
PY
}

validate_clean_out_dir() {
  local base out
  base="$(canonical_path "$BUILD_DIR")" ||
    die "could not canonicalize BUILD_DIR: '$BUILD_DIR'"
  out="$(canonical_path "$OUT_DIR")" ||
    die "could not canonicalize OUT_DIR: '$OUT_DIR'"

  [ -n "$base" ] || die "refusing to --clean empty BUILD_DIR"
  [ "$base" != "/" ] || die "refusing to --clean with root BUILD_DIR"
  [ -n "$out" ] || die "refusing to --clean empty OUT_DIR"
  [ "$out" != "/" ] || die "refusing to --clean root OUT_DIR"
  [ "$out" != "$base" ] ||
    die "refusing to --clean build directory itself: '$OUT_DIR'"

  case "$out" in
    "$base"/*) ;;
    *)
      die "refusing to --clean unsafe OUT_DIR: '$OUT_DIR' resolves to '$out' outside '$base'"
      ;;
  esac

  OUT_DIR="$out"
}

# Build the derived static-link config: the chosen preset/config with
# function_call_obfuscate forced off (dlsym-based FCO cannot work in a static
# binary).  A pre-existing [passes.function_call_obfuscate] table in the source
# config is stripped first — TOML forbids declaring a table twice, and a
# duplicate makes the whole derived file fail to parse, causing the plugin to
# silently drop EVERY protection (issue #42).  The build also passes the preset
# as a fallback so even a parse failure cannot leave the binary unprotected.
#   $1: source config path (empty -> use the preset)
#   $2: preset name
#   $3: output path
derive_static_config() {
  local src="$1" preset="$2" out="$3"
  {
    if [ -n "$src" ]; then
      awk '
        function inject_platform_runtime() {
          if (in_platform_runtime && !injected_static_flag) {
            print "static_link_expected = true"
            injected_static_flag = 1
          }
        }
        /^[[:space:]]*\[passes\.function_call_obfuscate\][[:space:]]*$/ {
          inject_platform_runtime()
          skip=1
          in_platform_runtime=0
          next
        }
        /^[[:space:]]*\[/ {
          inject_platform_runtime()
          skip=0
          in_platform_runtime=0
        }
        /^[[:space:]]*\[passes\.platform_runtime\][[:space:]]*$/ {
          skip=0
          in_platform_runtime=1
          saw_platform_runtime=1
          injected_static_flag=0
          print
          next
        }
        in_platform_runtime && /^[[:space:]]*static_link_expected[[:space:]]*=/ { next }
        !skip { print }
        END {
          inject_platform_runtime()
          if (!saw_platform_runtime) {
            print ""
            print "[passes.platform_runtime]"
            print "static_link_expected = true"
          }
        }
      ' "$src"
    else
      printf '[global]\npreset = "%s"\n' "$preset"
      printf '\n[passes.platform_runtime]\nstatic_link_expected = true\n'
    fi
    printf '\n[passes.function_call_obfuscate]\nenabled = false\n'
  } >"$out"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --source) SRC="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --preset) PRESET="$2"; CONFIG=""; shift 2 ;;
    --config) CONFIG="$2"; shift 2 ;;
    --seed) SEED="$2"; shift 2 ;;
    --clang) CLANG="$2"; shift 2 ;;
    --clangxx) CLANGXX="$2"; shift 2 ;;
    --plugin) PLUGIN="$2"; shift 2 ;;
    --linux-target) LINUX_TARGET="$2"; shift 2 ;;
    --linux-cc) LINUX_CC="$2"; shift 2 ;;
    --macos-arches) MACOS_ARCHES="$2"; shift 2 ;;
    --macos-min) MACOS_MIN="$2"; shift 2 ;;
    --linux-only) BUILD_LINUX=1; BUILD_MACOS=0; shift ;;
    --macos-only) BUILD_LINUX=0; BUILD_MACOS=1; shift ;;
    --no-linux) BUILD_LINUX=0; shift ;;
    --no-macos) BUILD_MACOS=0; shift ;;
    --no-strip) STRIP_BINARIES=0; shift ;;
    --no-audit) AUDIT_BINARIES=0; shift ;;
    --clean) CLEAN_OUT=1; shift ;;
    --dynamic) LINUX_STATIC=0; shift ;;
    --elf-shadow) ELF_SHADOW=1; shift ;;
    --no-elf-shadow) ELF_SHADOW=0; shift ;;
    --native-pack) NATIVE_PACK=1; BUILD_LINUX=1; BUILD_MACOS=0; shift ;;
    --no-native-pack) NATIVE_PACK=0; shift ;;
    --extra-cflags) EXTRA_CFLAGS="$2"; shift 2 ;;
    --extra-sources) EXTRA_SOURCES="$2"; shift 2 ;;
    --libs) LIBS="$2"; shift 2 ;;
    --c-std) C_STD="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    # Test hook: emit the derived static config and exit (see
    # tests/e2e/static_config_layering.sh).  Args: <src|""> <preset> <out>.
    --emit-static-config) derive_static_config "$2" "$3" "$4"; exit 0 ;;
    # Test hook: print the resolved Morok seed and exit (see
    # tests/e2e/cross_build_seed.sh).
    --emit-seed) printf '%s\n' "$SEED"; exit 0 ;;
    # Test hook: print host-aware platform defaults and exit (see
    # tests/e2e/cross_build_platform_defaults.sh).
    --emit-platform-defaults) EMIT_PLATFORM_DEFAULTS=1; shift ;;
    # Test hook: validate and print the canonical --clean target without
    # deleting it (see tests/e2e/cross_build_clean.sh).
    --check-clean-dir) CHECK_CLEAN_DIR=1; shift ;;
    --) shift; break ;;
    -*)
      die "unknown option: $1"
      ;;
    *)
      SRC="$1"
      shift
      ;;
  esac
done

if [ "$EMIT_PLATFORM_DEFAULTS" -eq 1 ]; then
  printf 'host=%s\n' "$HOST_OS"
  printf 'linux=%s\n' "$BUILD_LINUX"
  printf 'macos=%s\n' "$BUILD_MACOS"
  printf 'plugin=%s\n' "$PLUGIN"
  printf 'linux_target=%s\n' "$LINUX_TARGET"
  exit 0
fi

[ "$BUILD_LINUX" -eq 1 ] || [ "$BUILD_MACOS" -eq 1 ] || die "nothing to build"

case "$ELF_SHADOW" in
  0|1) ;;
  *) die "ELF_SHADOW must be 0 or 1" ;;
esac
if [ "$ELF_SHADOW" -eq 1 ]; then
  [ "$BUILD_LINUX" -eq 1 ] || die "--elf-shadow requires a Linux output"
  [ "$LINUX_STATIC" -eq 0 ] || die "--elf-shadow requires --dynamic"
  case "${LINUX_TARGET%%-*}" in
    x86_64|amd64) ;;
    *) die "--elf-shadow supports only Linux x86-64 targets" ;;
  esac
fi

case "$NATIVE_PACK" in
  0|1) ;;
  *) die "NATIVE_PACK must be 0 or 1" ;;
esac
if [ "$NATIVE_PACK" -eq 1 ]; then
  need_tool "$CLANG"
  [ "$BUILD_LINUX" -eq 1 ] || die "--native-pack requires a Linux output"
  [ "$BUILD_MACOS" -eq 0 ] || die "--native-pack does not support macOS"
  [ "$ELF_SHADOW" -eq 0 ] ||
    die "--native-pack and --elf-shadow require unimplemented PHDR coordination"
  case "${LINUX_TARGET%%-*}" in
    x86_64|amd64|aarch64|arm64) ;;
    *) die "--native-pack supports Linux ELF64 x86-64/AArch64 only" ;;
  esac
fi

if [ "$BUILD_MACOS" -eq 1 ] && [ "$HOST_OS" != "Darwin" ]; then
  die "macOS builds require a Darwin host; run with --linux-only or --no-macos on $HOST_OS"
fi

BUILD_DIR="$(root_path "$BUILD_DIR")"
SRC="$(root_path "$SRC")"
OUT_DIR="$(root_path "$OUT_DIR")"
PLUGIN="$(root_path "$PLUGIN")"
NATIVE_PACK_TOOL="$(root_path "$NATIVE_PACK_TOOL")"
NATIVE_PACK_LOADER="$(root_path "$NATIVE_PACK_LOADER")"
NATIVE_PACK_META="$(root_path "$NATIVE_PACK_META")"
NATIVE_PACK_SCRIPT="$(root_path "$NATIVE_PACK_SCRIPT")"

if [ "$CHECK_CLEAN_DIR" -eq 1 ]; then
  [ "$CLEAN_OUT" -eq 1 ] || die "--check-clean-dir requires --clean"
  validate_clean_out_dir
  printf '%s\n' "$OUT_DIR"
  exit 0
fi

[ -f "$SRC" ] || die "source not found: $SRC"

if [ ! -f "$PLUGIN" ] && [ -f "$BUILD_DIR/CMakeCache.txt" ]; then
  echo ">> building missing Morok plugin"
  cmake --build "$BUILD_DIR" --target morok_plugin
fi
[ -f "$PLUGIN" ] || die "Morok plugin not found: $PLUGIN"
if [ "$NATIVE_PACK" -eq 1 ]; then
  if [ ! -x "$NATIVE_PACK_TOOL" ] && [ -f "$BUILD_DIR/CMakeCache.txt" ]; then
    echo ">> building missing native-pack finalizer"
    cmake --build "$BUILD_DIR" --target morok-native-pack
  fi
  [ -x "$NATIVE_PACK_TOOL" ] ||
    die "native-pack finalizer not found: $NATIVE_PACK_TOOL"
  [ -f "$NATIVE_PACK_LOADER" ] || die "native-pack loader not found"
  [ -f "$NATIVE_PACK_META" ] || die "native-pack metadata source not found"
  [ -f "$NATIVE_PACK_SCRIPT" ] || die "native-pack linker script not found"
fi

case "$SRC" in
  *.cc|*.cpp|*.cxx|*.C)
    COMPILER="$CLANGXX"
    STD=(-std=c++23)
    ;;
  *)
    COMPILER="$CLANG"
    STD=(-std=c11)
    ;;
esac
if [ -n "$C_STD" ]; then
  STD=(-std="$C_STD")
fi
need_tool "$COMPILER"

# --clean removes stale outputs when requested, but only after resolving OUT_DIR
# to a strict descendant of BUILD_DIR so '.', '..', symlink escapes, $HOME, and
# arbitrary absolute paths never reach rm -rf.  The release audit below scopes
# itself to OUTPUTS, so OUT_DIR may also be a larger existing directory.
if [ "$CLEAN_OUT" -eq 1 ]; then
  validate_clean_out_dir
  echo ">> cleaning $OUT_DIR"
  rm -rf "$OUT_DIR"
fi

mkdir -p "$OUT_DIR"
BASE="$(basename "$SRC")"
STEM="${BASE%.*}"

# Resolve extra source files relative to ROOT
EXTRA_SRC_ARRAY=()
for f in $EXTRA_SOURCES; do
  EXTRA_SRC_ARRAY+=("$(root_path "$f")")
done

MOROK_CONFIG=()
if [ -n "$CONFIG" ]; then
  CONFIG="$(root_path "$CONFIG")"
  [ -f "$CONFIG" ] || die "config not found: $CONFIG"
  MOROK_CONFIG=(-mllvm "-morok-config=$CONFIG")
else
  MOROK_CONFIG=(-mllvm "-morok-preset=$PRESET")
fi

# Extra compiler flags (e.g. -no-pie -ffast-math) parsed into an array
EXTRA_CFLAG_ARRAY=()
for f in $EXTRA_CFLAGS; do
  EXTRA_CFLAG_ARRAY+=("$f")
done

# Extra link libraries parsed into an array
LIB_ARRAY=()
for l in $LIBS; do
  LIB_ARRAY+=("$l")
done

# Obfuscation flags shared by every target, MINUS the preset/config selection
# (which a target may need to override — see build_linux for static links).
# Source files and link libs are kept separate so build_linux/build_macos can
# place them correctly relative to --static and other target-specific flags.
COMMON=("$OPT_LEVEL")
if [ "${#STD[@]}" -gt 0 ]; then
  COMMON+=("${STD[@]}")
fi
if [ "${#EXTRA_CFLAG_ARRAY[@]}" -gt 0 ]; then
  COMMON+=("${EXTRA_CFLAG_ARRAY[@]}")
fi
COMMON+=(
  -fpass-plugin="$PLUGIN"
  -mllvm -morok
  -mllvm "-morok-seed=$SEED"
  "$SRC"
)
# Append extra sources after the main source
if [ "${#EXTRA_SRC_ARRAY[@]}" -gt 0 ]; then
  COMMON+=("${EXTRA_SRC_ARRAY[@]}")
fi
# Append extra link libs at the very end
if [ "${#LIB_ARRAY[@]}" -gt 0 ]; then
  COMMON+=("${LIB_ARRAY[@]}")
fi

OUTPUTS=()

strip_linux() {
  local out="$1"
  [ "$STRIP_BINARIES" -eq 1 ] || return 0
  local strip_tool="${LINUX_STRIP:-${LINUX_TARGET}-strip}"
  if command -v "$strip_tool" >/dev/null 2>&1; then
    "$strip_tool" -s "$out"
  elif command -v llvm-strip >/dev/null 2>&1; then
    llvm-strip -s "$out"
  fi
}

strip_macos() {
  local out="$1"
  [ "$STRIP_BINARIES" -eq 1 ] || return 0
  xcrun strip -ur "$out"
  # The misleading-metadata pass emits decoy DWARF.  On ELF, `llvm-strip -s`
  # removes it (strip_linux); on Mach-O, `strip` leaves a __TEXT,__debug_* section
  # in place, so the decoy build-path strings and the debug section itself survive
  # into the artifact and trip the release audit (embedded-dev-path /
  # debug-symbols).  Remove every __debug* section explicitly — `strip`/
  # `--strip-debug` miss it because the section lives in __TEXT, not __DWARF.
  local objcopy="${MACOS_OBJCOPY:-llvm-objcopy}"
  if command -v "$objcopy" >/dev/null 2>&1; then
    local secs
    secs="$(xcrun otool -l "$out" 2>/dev/null | awk '
      /segname/ { seg = $2 }
      /sectname/ { if ($2 ~ /debug/) print "--remove-section " seg "," $2 }' \
      | sort -u)"
    if [ -n "$secs" ]; then
      # shellcheck disable=SC2086
      "$objcopy" $secs "$out" 2>/dev/null || true
    fi
  fi
}

# Post-link seal MUST run after strip, so the sealed code-window hash is taken
# over the exact native code bytes that exist at runtime.  Linux ELF relocation
# shadowing runs after this step but changes only loader metadata, not a sealed
# code window.  On macOS the in-place byte rewrite invalidates the signature, so
# re-sign afterwards.  Fail closed: a binary with zero sealed manifests has no
# native-code patch protection and must not be shipped.
seal_binary() {
  local out="$1"
  [ "$SEAL_BINARIES" -eq 1 ] || return 0
  [ -f "$SEAL_TOOL" ] || die "sealer not found: $SEAL_TOOL"
  need_tool "$PYTHON"
  echo ">> sealing self-check manifests in $out"
  local log
  if ! log="$("$PYTHON" "$SEAL_TOOL" seal "$out" --window "$SEAL_WINDOW" 2>&1)"; then
    printf '%s\n' "$log" >&2
    die "post-link seal failed for $out"
  fi
  printf '   %s\n' "$log"
  case "$log" in
    *manifests=0*)
      die "refusing to ship UNSEALED binary (0 self-check manifests): $out"
      ;;
  esac
  if [ "$(uname -s)" = "Darwin" ] && file "$out" 2>/dev/null | grep -q "Mach-O"; then
    /usr/bin/codesign --force --sign - "$out" >/dev/null 2>&1 ||
      die "codesign failed after seal: $out"
  fi
}

shadow_linux_imports() {
  local out="$1"
  [ "$ELF_SHADOW" -eq 1 ] || return 0
  [ "$LINUX_STATIC" -eq 0 ] ||
    die "--elf-shadow requires --dynamic; static ELF has no DT_JMPREL loader path"
  [ -f "$ELF_SHADOW_TOOL" ] ||
    die "ELF shadow tool not found: $ELF_SHADOW_TOOL"
  need_tool "$PYTHON"

  echo ">> shadowing Linux import relocations in $out"
  local cmd=("$PYTHON" "$ELF_SHADOW_TOOL" apply "$out"
             --max-shadow-bytes "$ELF_SHADOW_MAX_BYTES")
  # A fixed Morok seed makes the post-link decoy selection reproducible too.
  # Seed zero retains per-artifact derivation from the final binary bytes.
  if [ "$SEED" != "0" ]; then
    cmd+=(--seed "$SEED")
  fi
  "${cmd[@]}" || die "ELF relocation shadowing failed for $out"
  "$PYTHON" "$ELF_SHADOW_TOOL" verify "$out" >/dev/null ||
    die "ELF relocation shadow verification failed for $out"
}

audit_bundle() {
  [ "$AUDIT_BINARIES" -eq 1 ] || return 0
  [ -f "$AUDIT_TOOL" ] || die "audit tool not found: $AUDIT_TOOL"
  need_tool "$PYTHON"
  local provenance="$OUT_DIR/morok-audit.json"
  if [ -n "$AUDIT_PROVENANCE" ]; then
    provenance="$AUDIT_PROVENANCE"
  fi
  local allowlist=()
  if [ -n "$AUDIT_ALLOWLIST" ]; then
    allowlist=(--allowlist "$AUDIT_ALLOWLIST")
  fi
  echo ">> auditing release bundle $OUT_DIR"
  local audit_cmd=("$PYTHON" "$AUDIT_TOOL" "$OUT_DIR" --release
                   --require-sealed-manifest --provenance "$provenance")
  local out
  for out in "${OUTPUTS[@]}"; do
    audit_cmd+=(--include "$out")
  done
  if [ "$NATIVE_PACK" -eq 1 ]; then
    audit_cmd+=(--require-native-pack --native-pack-tool "$NATIVE_PACK_TOOL")
  fi
  if [ "${#allowlist[@]}" -gt 0 ]; then
    audit_cmd+=("${allowlist[@]}")
  fi
  "${audit_cmd[@]}" ||
    die "release audit failed for $OUT_DIR"
}

build_linux() {
  local cc="${LINUX_CC:-${LINUX_TARGET}-gcc}"
  need_tool "$cc"

  local sysroot="${LINUX_SYSROOT:-$("$cc" -print-sysroot)}"
  local crt1="$("$cc" -print-file-name=crt1.o)"
  local libgcc="$("$cc" -print-libgcc-file-name)"
  [ "$crt1" != "crt1.o" ] || die "$cc did not report crt1.o; install the $LINUX_TARGET runtime"
  [ -f "$libgcc" ] || die "$cc did not report libgcc.a"
  local sysroot_arg=()
  if [ -n "$sysroot" ]; then
    sysroot_arg=("--sysroot=$sysroot")
  fi

  local tool_bin
  local crt_dir
  local gcc_lib_dir
  tool_bin="$(cd "$(dirname "$(command -v "$cc")")" && pwd)"
  crt_dir="$(cd "$(dirname "$crt1")" && pwd)"
  gcc_lib_dir="$(cd "$(dirname "$libgcc")" && pwd)"

  local arch="${LINUX_TARGET%%-*}"
  local static_flag=()
  local elf_shadow_link=()
  local static_suffix=""
  local morok_cfg=("${MOROK_CONFIG[@]}")
  local native_pack_dir=""
  local native_pack_objects=()
  local native_pack_link=()
  if [ "$LINUX_STATIC" -eq 1 ]; then
    static_flag=(-static)
    static_suffix="-static"
    # A static binary has no dynamic linker, so dlsym(RTLD_DEFAULT, …) returns
    # null at runtime — the dlsym-based call obfuscation would then jump to a
    # null pointer and crash at startup.  It also hides nothing for a static
    # link (there is no dynamic import table).  Disable it via a derived config
    # layered on the chosen preset/config.
    local static_cfg="$OUT_DIR/.morok-static-$STEM.toml"
    derive_static_config "$CONFIG" "$PRESET" "$static_cfg"
    # Keep the preset as an explicit fallback: if the derived config ever fails
    # to parse, the plugin must still apply the intended protections rather than
    # silently produce a bare, unprotected binary.
    morok_cfg=(-mllvm "-morok-config=$static_cfg" -mllvm "-morok-preset=$PRESET")
  elif [ "$ELF_SHADOW" -eq 1 ]; then
    # Reserve a conventional, late PT_NOTE header for the post-link shadow
    # PT_LOAD.  Compact lld/musl links otherwise have no disposable program
    # header, and growing/relocating the table is not loader-portable.
    elf_shadow_link=("-Wl,--build-id=sha1")
  fi

  if [ "$NATIVE_PACK" -eq 1 ]; then
    morok_cfg+=(-mllvm -morok-native-pack)
    native_pack_dir="$(mktemp -d "$OUT_DIR/.morok-native-pack.XXXXXX")" ||
      die "could not create native-pack temporary directory"
    NATIVE_PACK_TEMP="$native_pack_dir"
    "$NATIVE_PACK_TOOL" prepare "$native_pack_dir" --seed "$SEED" || {
      rm -rf "$native_pack_dir"
      die "native-pack key preparation failed"
    }
    local loader_obj="$native_pack_dir/loader.o"
    local meta_obj="$native_pack_dir/meta.o"
    local loader_common=("--target=$LINUX_TARGET")
    if [ "${#sysroot_arg[@]}" -gt 0 ]; then
      loader_common+=("${sysroot_arg[@]}")
    fi
    loader_common+=("-B$tool_bin" "-B$gcc_lib_dir" "-B$crt_dir"
      "-I$native_pack_dir" -ffreestanding -fno-builtin
      -fPIC
      -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables
      -fvisibility=hidden -O2)
    # A freestanding AArch64 loader cannot depend on compiler-rt's optional
    # __aarch64_* outline-atomic helpers: those helpers may not be linked into
    # the protected artifact and would also create a pre-open import edge.
    case "$LINUX_TARGET" in
      aarch64-*|arm64-*) loader_common+=(-mno-outline-atomics) ;;
    esac
    "$CLANG" "${loader_common[@]}" -std=c11 -c "$NATIVE_PACK_LOADER" \
      -o "$loader_obj" || {
        rm -rf "$native_pack_dir"
        die "native-pack loader compilation failed"
      }
    "$CLANG" "${loader_common[@]}" -c "$NATIVE_PACK_META" -o "$meta_obj" || {
      rm -rf "$native_pack_dir"
      die "native-pack metadata compilation failed"
    }
    native_pack_objects=("$loader_obj" "$meta_obj")
    native_pack_link=("-Wl,-T,$NATIVE_PACK_SCRIPT" -Wl,--build-id=sha1)
  fi

  local out="$OUT_DIR/$STEM-linux-$arch$static_suffix"
  echo ">> linux $LINUX_TARGET -> $out"
  local linux_cmd=("$COMPILER" "--target=$LINUX_TARGET")
  if [ "${#sysroot_arg[@]}" -gt 0 ]; then
    linux_cmd+=("${sysroot_arg[@]}")
  fi
  linux_cmd+=("-B$tool_bin" "-B$gcc_lib_dir" "-B$crt_dir" "-L$gcc_lib_dir"
              -D_GNU_SOURCE)
  if [ "${#static_flag[@]}" -gt 0 ]; then
    linux_cmd+=("${static_flag[@]}")
  fi
  linux_cmd+=("${morok_cfg[@]}")
  # Bash 3.2 (the system shell on macOS runners) treats an empty-array
  # expansion as an unbound variable under `set -u`.  Keep the optional ELF
  # linker flags behind the same explicit cardinality guard used above.
  if [ "${#elf_shadow_link[@]}" -gt 0 ]; then
    linux_cmd+=("${elf_shadow_link[@]}")
  fi
  if [ "${#native_pack_link[@]}" -gt 0 ]; then
    linux_cmd+=("${native_pack_link[@]}")
  fi
  linux_cmd+=("${COMMON[@]}" -o "$out")
  if [ "${#native_pack_objects[@]}" -gt 0 ]; then
    linux_cmd+=("${native_pack_objects[@]}")
  fi
  "${linux_cmd[@]}"
  strip_linux "$out"
  seal_binary "$out"
  if [ "$NATIVE_PACK" -eq 1 ]; then
    "$NATIVE_PACK_TOOL" finalize "$out" \
      --key "$native_pack_dir/morok_native_pack.key" --consume-key || {
        rm -rf "$native_pack_dir"
        die "native-pack finalization failed for $out"
      }
    "$NATIVE_PACK_TOOL" verify "$out" || {
      rm -rf "$native_pack_dir"
      die "native-pack verification failed for $out"
    }
    rm -rf "$native_pack_dir"
    NATIVE_PACK_TEMP=""
  fi
  shadow_linux_imports "$out"
  OUTPUTS+=("$out")
}

macos_target_for_arch() {
  case "$1" in
    native) printf '%s\n' "" ;;
    arm64|aarch64) printf '%s\n' "arm64-apple-macos" ;;
    x86_64|amd64) printf '%s\n' "x86_64-apple-macos" ;;
    *) printf '%s\n' "$1" ;;
  esac
}

macos_suffix_for_arch() {
  case "$1" in
    native) uname -m ;;
    aarch64) printf '%s\n' "arm64" ;;
    amd64) printf '%s\n' "x86_64" ;;
    *-apple-*) printf '%s\n' "${1%%-*}" ;;
    *) printf '%s\n' "$1" ;;
  esac
}

build_macos() {
  need_tool xcrun
  local sdk="$MACOS_SDK"
  if [ -z "$sdk" ]; then
    sdk="$(xcrun --show-sdk-path)"
  fi
  [ -d "$sdk" ] || die "macOS SDK not found: $sdk"

  # macOS artifacts are post-link sealed on this Darwin host (seal_binary), so
  # bind the seal-dependent passes to the sealer:
  #   * -morok-ckd-seal-required (#21): drop caller-keyed dispatch's startup
  #     self-seal fallback and poison unsealed targets, so a static patcher
  #     cannot reset the code_size sentinel to re-seal tampered code.
  #   * -morok-fail-closed-on-unsealed (#106): fold the unsealed sentinel into
  #     self-checksum / mutual-guard / dispatch key material, so a binary that
  #     was never sealed (a forgotten seal step) reconstructs garbage and dies
  #     at startup instead of silently running unprotected.
  # Only set these where sealing actually runs — an unsealed strict build would
  # corrupt itself.  Linux artifacts are not sealed (build_linux), so they keep
  # the fail-SAFE self-recovering behaviour.
  local seal_strict=()
  if [ "$SEAL_BINARIES" -eq 1 ]; then
    seal_strict=(-mllvm -morok-ckd-seal-required
                 -mllvm -morok-fail-closed-on-unsealed)
  fi

  local arch
  for arch in $MACOS_ARCHES; do
    local target
    local suffix
    local target_args=()
    target="$(macos_target_for_arch "$arch")"
    suffix="$(macos_suffix_for_arch "$arch")"
    if [ -n "$target" ]; then
      target_args=(-target "$target")
    fi

    local out="$OUT_DIR/$STEM-macos-$suffix"
    echo ">> macos $suffix -> $out"
    local macos_cmd=("$COMPILER")
    if [ "${#target_args[@]}" -gt 0 ]; then
      macos_cmd+=("${target_args[@]}")
    fi
    macos_cmd+=(-isysroot "$sdk" -mmacosx-version-min="$MACOS_MIN"
                "${MOROK_CONFIG[@]}")
    if [ "${#seal_strict[@]}" -gt 0 ]; then
      macos_cmd+=("${seal_strict[@]}")
    fi
    macos_cmd+=("${COMMON[@]}" -o "$out")
    "${macos_cmd[@]}"
    strip_macos "$out"
    seal_binary "$out"
    OUTPUTS+=("$out")
  done
}

if [ "$BUILD_LINUX" -eq 1 ]; then
  build_linux
fi

if [ "$BUILD_MACOS" -eq 1 ]; then
  build_macos
fi

audit_bundle

echo ">> built"
printf '   %s\n' "${OUTPUTS[@]}"
