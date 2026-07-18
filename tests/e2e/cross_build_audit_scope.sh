#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Regression: an existing --out-dir can contain unrelated files.  The release
# audit must receive only artifacts produced by the current cross-build instead
# of recursively treating the entire output root as the current release bundle.
set -euo pipefail

script="${1:?usage: cross_build_audit_scope.sh <path-to-cross_build.sh>}"

fail() { echo "FAIL: $*"; exit 1; }

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

build="$workdir/build"
bundle="$workdir/existing-bundle"
fakebin="$workdir/bin"
crt_dir="$workdir/crt"
gcc_dir="$workdir/gcc"
mkdir -p "$build/src/pipeline" "$bundle" "$fakebin" "$crt_dir" "$gcc_dir"

plugin="$build/src/pipeline/libMorok.so"
source="$workdir/hello.c"
cc="$fakebin/fake-linux-gcc"
clang="$fakebin/fake-clang"
audit="$workdir/fake-audit.py"
audit_log="$workdir/audit.args"
crt1="$crt_dir/crt1.o"
libgcc="$gcc_dir/libgcc.a"
output="$bundle/hello-linux-x86_64"

touch "$plugin" "$crt1" "$libgcc" "$bundle/unrelated-stale-binary"
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

cat >"$clang" <<'FAKECLANG'
#!/usr/bin/env bash
out=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$out" ] || exit 1
mkdir -p "$(dirname "$out")"
: >"$out"
FAKECLANG
chmod +x "$clang"

cat >"$audit" <<'FAKEAUDIT'
#!/usr/bin/env python3
import os
import pathlib
import sys

pathlib.Path(os.environ["MOROK_AUDIT_TEST_LOG"]).write_text(
    "\n".join(sys.argv[1:]) + "\n"
)
FAKEAUDIT

BUILD_DIR="$build" LINUX_CC="$cc" SEAL_BINARIES=0 AUDIT_BINARIES=1 \
  AUDIT_TOOL="$audit" MOROK_AUDIT_TEST_LOG="$audit_log" "$script" \
  --source "$source" \
  --out-dir "$bundle" \
  --clang "$clang" \
  --linux-target x86_64-linux-musl \
  --linux-only \
  --plugin "$plugin" \
  --dynamic \
  --no-strip >/dev/null

[ -f "$output" ] || fail "cross-build output was not produced"
grep -Fxq -- "$bundle" "$audit_log" ||
  fail "audit root was not the requested output directory"
include_count="$(grep -Fxc -- '--include' "$audit_log" || true)"
[ "$include_count" -eq 1 ] ||
  fail "audit received $include_count include selectors instead of one"
grep -Fxq -- "$output" "$audit_log" ||
  fail "current cross-build output was not included in the audit"
if grep -Fq -- "$bundle/unrelated-stale-binary" "$audit_log"; then
  fail "unrelated output-directory content leaked into the scoped audit"
fi

echo "PASS: cross_build scopes release audit to current outputs"
