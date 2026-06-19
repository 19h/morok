#!/bin/sh
# Build ZORYA obfuscated with Morok.
#
# ZORYA is x86_64-Linux-only (userfaultfd, perf_event_open, self-ptrace, named
# ELF sections), so the macOS/arm64 clang command used for the other crackmes
# does NOT apply. We cross-compile with the host LLVM clang driving the musl
# toolchain's sysroot/headers, exactly like crackmes/siloterminal's morok-linux
# target. Always -no-pie (type EXEC, fixed addresses) so the zoryatext file
# bytes == runtime bytes, which the self-checksum/sealer rely on.
#
#   LINK=dynamic  (default)  -> needs /lib/ld-musl-x86_64.so.1 on the target
#   LINK=static              -> runs on any x86_64 Linux, no runtime deps
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

CLANG=${CLANG:-/Users/int/local/bin/clang}
CROSS=${CROSS:-x86_64-linux-musl}
SEED=${MOROK_SEED:-1234}
LINK=${LINK:-dynamic}
MOROK_ROOT=${MOROK_ROOT:-../..}
PLUGIN=${MOROK_PLUGIN:-$MOROK_ROOT/build/src/pipeline/libMorok.dylib}
CONFIG=${MOROK_CONFIG:-morok-linux-static.toml}

case "$LINK" in
    static)  LINKFLAG="-static"; OUT=${OUT:-zorya-linux-x86_64-static} ;;
    dynamic) LINKFLAG="";        OUT=${OUT:-zorya-linux-x86_64}; ;;
    *) echo "LINK must be 'static' or 'dynamic'" >&2; exit 2 ;;
esac

SYSROOT="$(${CROSS}-gcc -print-sysroot)"
CRT1="$(${CROSS}-gcc -print-file-name=crt1.o)"
LIBGCC="$(${CROSS}-gcc -print-libgcc-file-name)"
TOOLBIN="$(dirname "$(command -v ${CROSS}-gcc)")"
CRTDIR="$(dirname "$CRT1")"
GCCLIBDIR="$(dirname "$LIBGCC")"

echo "[*] building $OUT with morok (link=$LINK config=$CONFIG seed=$SEED)"
"$CLANG" --target="$CROSS" --sysroot="$SYSROOT" \
    -B"$TOOLBIN" -B"$GCCLIBDIR" -B"$CRTDIR" -L"$GCCLIBDIR" \
    -O3 -std=c23 -D_GNU_SOURCE -no-pie $LINKFLAG \
    -Wno-implicit-function-declaration \
    -ffast-math \
    -fpass-plugin="$PLUGIN" -mllvm -morok \
    -mllvm -morok-config="$CONFIG" -mllvm -morok-seed="$SEED" \
    -o "$OUT" zorya.c tweetnacl.c -lpthread

echo "[*] done -> $OUT"
file "$OUT"
# Note: this is the *unsealed* verifier. Seal it for a winner with the issuer's
# zorya-mint + zorya.sk (see AUTHORS_NOTE.md) before it can print a flag:
#   ./zorya-mint seal ./$OUT "Winner Name" flag.txt
