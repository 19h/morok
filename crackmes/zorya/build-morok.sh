#!/usr/bin/env bash
# Build ZORYA obfuscated with Morok.
#
# ZORYA is x86_64-Linux-only (userfaultfd, perf_event_open, self-ptrace, named
# ELF sections), so this wrapper delegates to Morok's maintained cross_build.sh
# with zorya's Linux-only source list and required fixed-address flags.
#
# Outputs default to $MOROK_ROOT/build/cross/zorya so the release audit never
# sees issuer-only sidecars such as zorya.sk. Use OUT_DIR=... to override.
#
#   LINK=static   (default) -> fully static Linux artifact
#   LINK=dynamic            -> musl dynamic artifact
#
# The verifier still needs the ZORYA payload seal for a playable challenge:
#   ./zorya-mint seal ./<built-verifier> "Winner Name" flag.txt
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOROK_ROOT="${MOROK_ROOT:-$(cd "$HERE/../.." && pwd)}"
CROSS_BUILD="${CROSS_BUILD:-$MOROK_ROOT/cross_build.sh}"

die() {
  echo "error: $*" >&2
  exit 1
}

need_tool() {
  command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"
}

usage() {
  cat <<USAGE
Usage:
  ./build-morok.sh [cross_build options]

Environment:
  LINK=static|dynamic       Linux link mode (default: static)
  OUT_DIR=DIR               Output directory (default: $MOROK_ROOT/build/cross/zorya)
  MOROK_CONFIG=PATH         Base Morok config (default: $MOROK_ROOT/foo.toml)
  MOROK_SEED=N              Morok seed; 0 = per-build entropy (default: 0)
  BUILD_DIR=DIR             Morok build directory (default: $MOROK_ROOT/build)
  LINUX_TARGET=TRIPLE       Linux target (default: x86_64-linux-musl)
  LINUX_CC=PATH             GCC-compatible cross driver for crt/libgcc lookup
  CLANG=PATH                C compiler with the Morok pass ABI
  PLUGIN=PATH               Morok pass plugin

This is a zorya-specific wrapper around:
  $CROSS_BUILD

Examples:
  ./build-morok.sh --clean
  LINK=dynamic ./build-morok.sh --clean
  MOROK_SEED=1234 ./build-morok.sh --no-audit
USAGE
}

case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
esac

[ -x "$CROSS_BUILD" ] || die "cross_build.sh not found or not executable: $CROSS_BUILD"
[ -f "$HERE/zorya.c" ] || die "source not found: $HERE/zorya.c"
[ -f "$HERE/tweetnacl.c" ] || die "source not found: $HERE/tweetnacl.c"

LINK="${LINK:-static}"
USER_ARGS=("$@")
ARGC=$#
ARGI=0
while [ "$ARGI" -lt "$ARGC" ]; do
  ARG="${USER_ARGS[$ARGI]}"
  case "$ARG" in
    --dynamic)
      LINK=dynamic
      ARGI=$((ARGI + 1))
      ;;
    --linux-target)
      [ $((ARGI + 1)) -lt "$ARGC" ] || die "--linux-target needs a value"
      LINUX_TARGET="${USER_ARGS[$((ARGI + 1))]}"
      ARGI=$((ARGI + 2))
      ;;
    --linux-cc)
      [ $((ARGI + 1)) -lt "$ARGC" ] || die "--linux-cc needs a value"
      LINUX_CC="${USER_ARGS[$((ARGI + 1))]}"
      ARGI=$((ARGI + 2))
      ;;
    --clang)
      [ $((ARGI + 1)) -lt "$ARGC" ] || die "--clang needs a value"
      CLANG="${USER_ARGS[$((ARGI + 1))]}"
      ARGI=$((ARGI + 2))
      ;;
    --plugin)
      [ $((ARGI + 1)) -lt "$ARGC" ] || die "--plugin needs a value"
      PLUGIN="${USER_ARGS[$((ARGI + 1))]}"
      ARGI=$((ARGI + 2))
      ;;
    --c-std)
      [ $((ARGI + 1)) -lt "$ARGC" ] || die "--c-std needs a value"
      C_STD="${USER_ARGS[$((ARGI + 1))]}"
      ARGI=$((ARGI + 2))
      ;;
    --config)
      [ $((ARGI + 1)) -lt "$ARGC" ] || die "--config needs a value"
      MOROK_CONFIG="${USER_ARGS[$((ARGI + 1))]}"
      ARGI=$((ARGI + 2))
      ;;
    --out-dir)
      [ $((ARGI + 1)) -lt "$ARGC" ] || die "--out-dir needs a value"
      OUT_DIR="${USER_ARGS[$((ARGI + 1))]}"
      ARGI=$((ARGI + 2))
      ;;
    --seed)
      [ $((ARGI + 1)) -lt "$ARGC" ] || die "--seed needs a value"
      SEED="${USER_ARGS[$((ARGI + 1))]}"
      ARGI=$((ARGI + 2))
      ;;
    --)
      break
      ;;
    *)
      ARGI=$((ARGI + 1))
      ;;
  esac
done

case "$LINK" in
  static) LINK_ARGS=() ;;
  dynamic) LINK_ARGS=(--dynamic) ;;
  *) die "LINK must be 'static' or 'dynamic'" ;;
esac

OUT_DIR="${OUT_DIR:-$MOROK_ROOT/build/cross/zorya}"
BUILD_DIR="${BUILD_DIR:-$MOROK_ROOT/build}"
CONFIG="${MOROK_CONFIG:-$MOROK_ROOT/foo.toml}"
SEED="${SEED:-${MOROK_SEED:-0}}"
LINUX_TARGET="${LINUX_TARGET:-x86_64-linux-musl}"
C_STD="${C_STD:-c23}"
CLANG_BIN="${CLANG:-clang-23}"
LINUX_CC_BIN="${LINUX_CC:-${LINUX_TARGET}-gcc}"
case "$BUILD_DIR" in
  /*) ;;
  *) BUILD_DIR="$MOROK_ROOT/$BUILD_DIR" ;;
esac
case "$CONFIG" in
  /*) ;;
  *)
    if [ -f "$HERE/$CONFIG" ]; then
      CONFIG="$HERE/$CONFIG"
    else
      CONFIG="$MOROK_ROOT/$CONFIG"
    fi
    ;;
esac
case "$(uname -s)" in
  Darwin) DEFAULT_PLUGIN_EXT="dylib" ;;
  *) DEFAULT_PLUGIN_EXT="so" ;;
esac
PLUGIN_PATH="${PLUGIN:-${MOROK_PLUGIN:-$BUILD_DIR/src/pipeline/libMorok.$DEFAULT_PLUGIN_EXT}}"

[ -f "$CONFIG" ] || die "Morok config not found: $CONFIG"
if [ ! -f "$PLUGIN_PATH" ] && [ -f "$BUILD_DIR/CMakeCache.txt" ]; then
  echo "[*] building missing Morok plugin"
  cmake --build "$BUILD_DIR" --target morok_plugin
fi
[ -f "$PLUGIN_PATH" ] || die "Morok plugin not found: $PLUGIN_PATH"

derive_support_config() {
  local src="$1"
  local out="$2"
  local static_link="$3"
  local strip_fco=0
  if [ "$static_link" -eq 1 ]; then
    strip_fco=1
  fi

  awk -v static_link="$static_link" -v strip_fco="$strip_fco" '
    function inject_static_flag() {
      if (static_link && in_platform_runtime && !injected_static_flag) {
        print "static_link_expected = true"
        injected_static_flag = 1
      }
    }
    /^[[:space:]]*\[passes\.(external_secret_binding|env_binding_kdf|environment_binding_kdf)\][[:space:]]*$/ {
      inject_static_flag()
      skip = 1
      in_platform_runtime = 0
      next
    }
    strip_fco && /^[[:space:]]*\[passes\.function_call_obfuscate\][[:space:]]*$/ {
      inject_static_flag()
      skip = 1
      in_platform_runtime = 0
      next
    }
    /^[[:space:]]*\[/ {
      inject_static_flag()
      skip = 0
      in_platform_runtime = 0
    }
    /^[[:space:]]*\[passes\.platform_runtime\][[:space:]]*$/ {
      skip = 0
      in_platform_runtime = 1
      saw_platform_runtime = 1
      injected_static_flag = 0
      print
      next
    }
    static_link && in_platform_runtime && /^[[:space:]]*static_link_expected[[:space:]]*=/ {
      next
    }
    !skip {
      print
    }
    END {
      inject_static_flag()
      if (static_link && !saw_platform_runtime) {
        print ""
        print "[passes.platform_runtime]"
        print "static_link_expected = true"
      }
    }
  ' "$src" >"$out"

  cat >>"$out" <<'EOF'

# zorya support-object compatibility: feed-API helpers have fixed external
# names, so only the verifier TU keeps these bindings enabled.
[passes.external_secret_binding]
enabled = false

[passes.env_binding_kdf]
enabled = false
EOF

  if [ "$static_link" -eq 1 ]; then
    cat >>"$out" <<'EOF'

[passes.function_call_obfuscate]
enabled = false
EOF
  fi
}

# Build TweetNaCl as a Morok-protected support object. The support config is
# derived from foo.toml but disables the fixed-name feed helpers so it can link
# beside the verifier TU, which keeps the full base config.
need_tool "$CLANG_BIN"
need_tool "$LINUX_CC_BIN"
SUPPORT_DIR="$BUILD_DIR/cross/.zorya-obj"
TWEET_OBJ="$SUPPORT_DIR/tweetnacl-$LINUX_TARGET.o"
mkdir -p "$SUPPORT_DIR"
SUPPORT_CONFIG="$SUPPORT_DIR/tweetnacl-morok.toml"
if [ "$LINK" = "static" ]; then
  derive_support_config "$CONFIG" "$SUPPORT_CONFIG" 1
else
  derive_support_config "$CONFIG" "$SUPPORT_CONFIG" 0
fi
SYSROOT="$("$LINUX_CC_BIN" -print-sysroot)"
CRT1="$("$LINUX_CC_BIN" -print-file-name=crt1.o)"
LIBGCC="$("$LINUX_CC_BIN" -print-libgcc-file-name)"
[ "$CRT1" != "crt1.o" ] || die "$LINUX_CC_BIN did not report crt1.o; install the $LINUX_TARGET runtime"
[ -f "$LIBGCC" ] || die "$LINUX_CC_BIN did not report libgcc.a"
TOOLBIN="$(cd "$(dirname "$(command -v "$LINUX_CC_BIN")")" && pwd)"
CRTDIR="$(cd "$(dirname "$CRT1")" && pwd)"
GCCLIBDIR="$(cd "$(dirname "$LIBGCC")" && pwd)"
SYSROOT_ARG=()
if [ -n "$SYSROOT" ]; then
  SYSROOT_ARG=(--sysroot="$SYSROOT")
fi

echo "[*] compiling support object $TWEET_OBJ"
"$CLANG_BIN" --target="$LINUX_TARGET" "${SYSROOT_ARG[@]}" \
  -B"$TOOLBIN" -B"$GCCLIBDIR" -B"$CRTDIR" \
  -O3 -std="$C_STD" -D_GNU_SOURCE -fno-pie \
  -ffast-math -Wno-implicit-function-declaration \
  -fno-zero-initialized-in-bss -ffunction-sections -fdata-sections \
  -fpass-plugin="$PLUGIN_PATH" -mllvm -morok \
  -mllvm "-morok-config=$SUPPORT_CONFIG" -mllvm "-morok-seed=$SEED" \
  -c "$HERE/tweetnacl.c" -o "$TWEET_OBJ"

ARGS=(
  --linux-only
  --no-macos
  --source "$HERE/zorya.c"
  --libs "$TWEET_OBJ -lpthread"
  --extra-cflags "-fno-pie -no-pie -ffast-math -Wno-implicit-function-declaration -fno-zero-initialized-in-bss -ffunction-sections -fdata-sections"
  --c-std "$C_STD"
  --config "$CONFIG"
  --seed "$SEED"
  --out-dir "$OUT_DIR"
  --linux-target "$LINUX_TARGET"
)

if [ -n "${LINUX_CC:-}" ]; then
  ARGS+=(--linux-cc "$LINUX_CC")
fi
if [ -n "${CLANG:-}" ]; then
  ARGS+=(--clang "$CLANG")
fi
if [ -n "${CLANGXX:-}" ]; then
  ARGS+=(--clangxx "$CLANGXX")
fi
ARGS+=(--plugin "$PLUGIN_PATH")

echo "[*] building zorya with Morok (link=$LINK config=$CONFIG seed=$SEED)"
"$CROSS_BUILD" "${LINK_ARGS[@]}" "${ARGS[@]}" "$@"

cat <<EOF
[*] zorya Morok build complete.
[*] This artifact has Morok post-link manifests sealed/audited unless disabled.
[*] It is still a ZORYA-unsealed verifier until zorya-mint patches zoryabc/zoryaseal.
EOF
