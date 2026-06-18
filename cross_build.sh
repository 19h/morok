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

SRC="programs/cf_license_crackme.c"
OUT_DIR="${OUT_DIR:-$BUILD_DIR/cross}"
CLANG="${CLANG:-clang-23}"
CLANGXX="${CLANGXX:-clang++}"
PLUGIN="${PLUGIN:-$BUILD_DIR/src/pipeline/libMorok.dylib}"
PRESET="${PRESET:-max}"
CONFIG=""
SEED="${SEED:-832040}"
OPT_LEVEL="${OPT_LEVEL:--O3}"

BUILD_LINUX=1
BUILD_MACOS=1
STRIP_BINARIES=1

LINUX_TARGET="${LINUX_TARGET:-x86_64-linux-musl}"
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
  --seed N               Morok seed (default: 832040)
  --clang PATH           C compiler with the Morok pass ABI (default: clang-23)
  --clangxx PATH         C++ compiler with the Morok pass ABI (default: clang++)
  --plugin PATH          Morok pass plugin (default: build/src/pipeline/libMorok.dylib)
  --linux-target TRIPLE  Linux target triple (default: x86_64-linux-musl)
  --linux-cc PATH        GCC-compatible cross toolchain driver for crt/libgcc lookup
  --macos-arches LIST    Space-separated macOS arches: native, arm64, x86_64
                         (default: current host arch)
  --macos-min VERSION    macOS deployment target (default: 13.0)
  --linux-only           Build only the Linux artifact
  --macos-only           Build only the macOS artifact(s)
  --no-linux             Skip Linux
  --no-macos             Skip macOS
  --no-strip             Do not strip produced binaries
  -h, --help             Show this help

Environment overrides mirror the option names in uppercase, for example:
  SRC=programs/01_hello_world.c MACOS_ARCHES="arm64 x86_64" ./cross_build.sh
  LINUX_TARGET=i686-linux-musl LINUX_CC=i686-linux-musl-gcc ./cross_build.sh
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
    -h|--help) usage; exit 0 ;;
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

[ "$BUILD_LINUX" -eq 1 ] || [ "$BUILD_MACOS" -eq 1 ] || die "nothing to build"

SRC="$(root_path "$SRC")"
OUT_DIR="$(root_path "$OUT_DIR")"
PLUGIN="$(root_path "$PLUGIN")"
[ -f "$SRC" ] || die "source not found: $SRC"

if [ ! -f "$PLUGIN" ] && [ -f "$BUILD_DIR/CMakeCache.txt" ]; then
  echo ">> building missing Morok plugin"
  cmake --build "$BUILD_DIR" --target morok_plugin
fi
[ -f "$PLUGIN" ] || die "Morok plugin not found: $PLUGIN"

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
need_tool "$COMPILER"

mkdir -p "$OUT_DIR"
BASE="$(basename "$SRC")"
STEM="${BASE%.*}"

MOROK_CONFIG=()
if [ -n "$CONFIG" ]; then
  CONFIG="$(root_path "$CONFIG")"
  [ -f "$CONFIG" ] || die "config not found: $CONFIG"
  MOROK_CONFIG=(-mllvm "-morok-config=$CONFIG")
else
  MOROK_CONFIG=(-mllvm "-morok-preset=$PRESET")
fi

# Obfuscation flags shared by every target, MINUS the preset/config selection
# (which a target may need to override — see build_linux for static links).
COMMON=(
  "$OPT_LEVEL" "${STD[@]}"
  -fpass-plugin="$PLUGIN"
  -mllvm -morok
  -mllvm "-morok-seed=$SEED"
  "$SRC"
)

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
}

build_linux() {
  local cc="${LINUX_CC:-${LINUX_TARGET}-gcc}"
  need_tool "$cc"

  local sysroot="${LINUX_SYSROOT:-$("$cc" -print-sysroot)}"
  local crt1="$("$cc" -print-file-name=crt1.o)"
  local libgcc="$("$cc" -print-libgcc-file-name)"
  [ -n "$sysroot" ] || die "$cc did not report a sysroot"
  [ "$crt1" != "crt1.o" ] || die "$cc did not report crt1.o; install the $LINUX_TARGET runtime"
  [ -f "$libgcc" ] || die "$cc did not report libgcc.a"

  local tool_bin
  local crt_dir
  local gcc_lib_dir
  tool_bin="$(cd "$(dirname "$(command -v "$cc")")" && pwd)"
  crt_dir="$(cd "$(dirname "$crt1")" && pwd)"
  gcc_lib_dir="$(cd "$(dirname "$libgcc")" && pwd)"

  local arch="${LINUX_TARGET%%-*}"
  local static_flag=()
  local static_suffix=""
  local morok_cfg=("${MOROK_CONFIG[@]}")
  if [ "$LINUX_STATIC" -eq 1 ]; then
    static_flag=(-static)
    static_suffix="-static"
    # A static binary has no dynamic linker, so dlsym(RTLD_DEFAULT, …) returns
    # null at runtime — the dlsym-based call obfuscation would then jump to a
    # null pointer and crash at startup.  It also hides nothing for a static
    # link (there is no dynamic import table).  Disable it via a derived config
    # layered on the chosen preset/config.
    local static_cfg="$OUT_DIR/.morok-static-$STEM.toml"
    {
      if [ -n "$CONFIG" ]; then
        cat "$CONFIG"
      else
        printf '[global]\npreset = "%s"\n' "$PRESET"
      fi
      printf '\n[passes.function_call_obfuscate]\nenabled = false\n'
    } >"$static_cfg"
    morok_cfg=(-mllvm "-morok-config=$static_cfg")
  fi

  local out="$OUT_DIR/$STEM-linux-$arch$static_suffix"
  echo ">> linux $LINUX_TARGET -> $out"
  "$COMPILER" "--target=$LINUX_TARGET" "--sysroot=$sysroot" \
    "-B$tool_bin" "-B$gcc_lib_dir" "-B$crt_dir" "-L$gcc_lib_dir" \
    -D_GNU_SOURCE "${static_flag[@]}" "${morok_cfg[@]}" "${COMMON[@]}" -o "$out"
  strip_linux "$out"
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
    "$COMPILER" "${target_args[@]}" -isysroot "$sdk" \
      -mmacosx-version-min="$MACOS_MIN" "${MOROK_CONFIG[@]}" "${COMMON[@]}" \
      -o "$out"
    strip_macos "$out"
    OUTPUTS+=("$out")
  done
}

if [ "$BUILD_LINUX" -eq 1 ]; then
  build_linux
fi

if [ "$BUILD_MACOS" -eq 1 ]; then
  build_macos
fi

echo ">> built"
printf '   %s\n' "${OUTPUTS[@]}"
