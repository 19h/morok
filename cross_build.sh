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
  --seed N               Morok seed; 0 = per-build entropy (default: 0)
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
  --no-audit             Skip the final morok-audit release gate
  --dynamic              Linux dynamic link (default: static)
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
        /^[[:space:]]*\[passes\.function_call_obfuscate\][[:space:]]*$/ { skip=1; next }
        /^[[:space:]]*\[/ { skip=0 }
        !skip { print }
      ' "$src"
    else
      printf '[global]\npreset = "%s"\n' "$preset"
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
    --dynamic) LINUX_STATIC=0; shift ;;
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
if [ -n "$C_STD" ]; then
  STD=(-std="$C_STD")
fi
need_tool "$COMPILER"

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
COMMON=(
  "$OPT_LEVEL" "${STD[@]}"
  "${EXTRA_CFLAG_ARRAY[@]}"
  -fpass-plugin="$PLUGIN"
  -mllvm -morok
  -mllvm "-morok-seed=$SEED"
  "$SRC"
)
# Append extra sources after the main source
COMMON+=("${EXTRA_SRC_ARRAY[@]}")
# Append extra link libs at the very end
COMMON+=("${LIB_ARRAY[@]}")

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

# Post-link seal MUST run last (after strip), so the sealed code-window hash is
# taken over the exact bytes that exist at runtime.  On macOS the in-place byte
# rewrite invalidates the signature, so re-sign afterwards.  Fail closed: a
# binary with zero sealed manifests has no native-code patch protection and must
# not be shipped.
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
  "$PYTHON" "$AUDIT_TOOL" "$OUT_DIR" --release --require-sealed-manifest \
    --provenance "$provenance" "${allowlist[@]}" ||
    die "release audit failed for $OUT_DIR"
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
    derive_static_config "$CONFIG" "$PRESET" "$static_cfg"
    # Keep the preset as an explicit fallback: if the derived config ever fails
    # to parse, the plugin must still apply the intended protections rather than
    # silently produce a bare, unprotected binary.
    morok_cfg=(-mllvm "-morok-config=$static_cfg" -mllvm "-morok-preset=$PRESET")
  fi

  local out="$OUT_DIR/$STEM-linux-$arch$static_suffix"
  echo ">> linux $LINUX_TARGET -> $out"
  "$COMPILER" "--target=$LINUX_TARGET" "--sysroot=$sysroot" \
    "-B$tool_bin" "-B$gcc_lib_dir" "-B$crt_dir" "-L$gcc_lib_dir" \
    -D_GNU_SOURCE "${static_flag[@]}" "${morok_cfg[@]}" "${COMMON[@]}" -o "$out"
  strip_linux "$out"
  seal_binary "$out"
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
    "$COMPILER" "${target_args[@]}" -isysroot "$sdk" \
      -mmacosx-version-min="$MACOS_MIN" "${MOROK_CONFIG[@]}" "${seal_strict[@]}" \
      "${COMMON[@]}" \
      -o "$out"
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
