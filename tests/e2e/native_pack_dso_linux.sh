#!/usr/bin/env bash
set -euo pipefail
ulimit -c 0

CC="$1"
PLUGIN="$2"
PACKER="$3"
ROOT="$4"
STRIP="$5"
NM="$6"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

CONFIG="$ROOT/tests/e2e/native_pack.toml"
SOURCE="$ROOT/tests/e2e/fixtures/native_pack_dso.c"
DRIVER_SOURCE="$ROOT/tests/e2e/fixtures/native_pack_dso_driver.c"
IFUNC_SOURCE="$ROOT/tests/e2e/fixtures/native_pack_ifunc.S"
LOADER="$ROOT/runtime/native_pack_loader.c"
META="$ROOT/runtime/native_pack_meta.S"
SCRIPT="$ROOT/runtime/native_pack.ld"

"$CC" -O2 "$DRIVER_SOURCE" -ldl -pthread -o "$TMP/driver"

build_pair() {
  local suffix="$1"
  local define="$2"
  local keydir="$TMP/key-$suffix"
  "$PACKER" prepare "$keydir" --seed "$((31337 + suffix))" >/dev/null
  local common=(-I"$keydir" -ffreestanding -fno-builtin -fPIC -fno-stack-protector
    -fno-unwind-tables -fno-asynchronous-unwind-tables -fvisibility=hidden -O2)
  "$CC" "${common[@]}" -std=c11 -c "$LOADER" -o "$TMP/loader-$suffix.o"
  "$CC" "${common[@]}" -c "$META" -o "$TMP/meta-$suffix.o"
  local loader_undefined
  loader_undefined="$("$NM" -u "$TMP/loader-$suffix.o" | awk '{print $NF}')"
  [ "$loader_undefined" = "__morok_npack_meta" ]
  "$CC" -O2 -shared -fPIC $define "$SOURCE" -Wl,--build-id=sha1 \
    -o "$TMP/clean-$suffix.so"
  "$CC" -O2 -shared -fPIC $define "$SOURCE" \
    "$TMP/loader-$suffix.o" "$TMP/meta-$suffix.o" \
    -fpass-plugin="$PLUGIN" -mllvm -morok \
    -mllvm "-morok-config=$CONFIG" -mllvm -morok-native-pack \
    -mllvm "-morok-seed=$((31337 + suffix))" \
    -Wl,-T,"$SCRIPT" -Wl,--build-id=sha1 -o "$TMP/packed-$suffix.so"
  "$STRIP" -s "$TMP/packed-$suffix.so"
  "$PACKER" finalize "$TMP/packed-$suffix.so" \
    --key "$keydir/morok_native_pack.key" --consume-key >/dev/null
  "$PACKER" verify "$TMP/packed-$suffix.so" >/dev/null
  local clean packed
  clean="$($TMP/driver "$TMP/clean-$suffix.so")"
  packed="$($TMP/driver "$TMP/packed-$suffix.so")"
  [ "$clean" = "$packed" ]
}

# No constructor: eight threads race the first protected entry.
build_pair 1 ""
# Constructor mode: DT_INIT_ARRAY calls a plaintext constructor which enters a
# protected export before dlopen returns.
build_pair 2 "-DNATIVE_PACK_CTOR=1"

# Relocation-time resolvers execute before lazy entry is possible.  The
# finalizer must reject the artifact without modifying it.
"$PACKER" prepare "$TMP/key-ifunc" --seed 31340 >/dev/null
IFUNC_COMMON=(-I"$TMP/key-ifunc" -ffreestanding -fno-builtin -fPIC
  -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables
  -fvisibility=hidden -O2)
"$CC" "${IFUNC_COMMON[@]}" -std=c11 -c "$LOADER" -o "$TMP/loader-ifunc.o"
"$CC" "${IFUNC_COMMON[@]}" -c "$META" -o "$TMP/meta-ifunc.o"
"$CC" -fPIC -c "$IFUNC_SOURCE" -o "$TMP/ifunc-symbol.o"
"$CC" -O2 -shared -fPIC "$SOURCE" "$TMP/ifunc-symbol.o" \
  "$TMP/loader-ifunc.o" "$TMP/meta-ifunc.o" \
  -fpass-plugin="$PLUGIN" -mllvm -morok \
  -mllvm "-morok-config=$CONFIG" -mllvm -morok-native-pack \
  -mllvm -morok-seed=31340 -Wl,-T,"$SCRIPT" -Wl,--build-id=sha1 \
  -o "$TMP/ifunc.so"
"$STRIP" -s "$TMP/ifunc.so"
if "$PACKER" finalize "$TMP/ifunc.so" \
    --key "$TMP/key-ifunc/morok_native_pack.key" \
    >"$TMP/ifunc.out" 2>"$TMP/ifunc.err"; then
  echo "native-pack finalizer accepted a GNU IFUNC artifact" >&2
  exit 1
fi
grep -q 'GNU IFUNC' "$TMP/ifunc.err"
