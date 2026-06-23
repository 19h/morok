#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Regression: GCC-compatible Linux drivers may report an empty -print-sysroot
# while still providing usable crt/libgcc paths. cross_build.sh must omit
# --sysroot in that case instead of failing before the compile step.
set -euo pipefail

script="${1:?usage: cross_build_empty_sysroot.sh <path-to-cross_build.sh>}"

fail() { echo "FAIL: $*"; exit 1; }

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

build="$workdir/build"
fakebin="$workdir/bin"
crt_dir="$workdir/crt"
gcc_dir="$workdir/gcc"
mkdir -p "$build/src/pipeline" "$fakebin" "$crt_dir" "$gcc_dir"

plugin="$build/src/pipeline/libMorok.so"
source="$workdir/hello.c"
cc="$fakebin/fake-linux-gcc"
clang="$fakebin/fake-clang"
arglog="$workdir/clang.args"
crt1="$crt_dir/crt1.o"
libgcc="$gcc_dir/libgcc.a"

touch "$plugin" "$crt1" "$libgcc"
printf 'int main(void) { return 0; }\n' >"$source"

cat >"$cc" <<FAKECC
#!/usr/bin/env bash
case "\$1" in
  -print-sysroot) exit 0 ;;
  -print-file-name=crt1.o) printf '%s\n' "$crt1"; exit 0 ;;
  -print-libgcc-file-name) printf '%s\n' "$libgcc"; exit 0 ;;
esac
exit 1
FAKECC
chmod +x "$cc"

cat >"$clang" <<FAKECLANG
#!/usr/bin/env bash
printf '%s\n' "\$@" >"$arglog"
out=""
while [ "\$#" -gt 0 ]; do
  case "\$1" in
    -o) out="\$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "\$out" ] || exit 1
mkdir -p "\$(dirname "\$out")"
: >"\$out"
FAKECLANG
chmod +x "$clang"

BUILD_DIR="$build" LINUX_CC="$cc" SEAL_BINARIES=0 "$script" \
  --source "$source" \
  --out-dir "$build/cross" \
  --clang "$clang" \
  --linux-target x86_64-linux-musl \
  --linux-only \
  --plugin "$plugin" \
  --dynamic \
  --no-strip \
  --no-audit \
  --clean >/dev/null

grep -q -- '--target=x86_64-linux-musl' "$arglog" ||
  fail "compiler was not invoked for the Linux target"
if grep -q -- '--sysroot=' "$arglog"; then
  cat "$arglog"
  fail "empty toolchain sysroot was forwarded to clang"
fi

echo "PASS: cross_build omits --sysroot for empty Linux driver sysroots"
