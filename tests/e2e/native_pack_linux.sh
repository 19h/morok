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
WORKLOAD="$ROOT/tests/e2e/fixtures/native_pack_workload.c"
LOADER="$ROOT/runtime/native_pack_loader.c"
META="$ROOT/runtime/native_pack_meta.S"
SCRIPT="$ROOT/runtime/native_pack.ld"

"$PACKER" prepare "$TMP/key" --seed 31337 >/dev/null
COMMON=(-I"$TMP/key" -ffreestanding -fno-builtin -fPIC -fno-stack-protector
  -fno-unwind-tables -fno-asynchronous-unwind-tables -fvisibility=hidden -O2)
"$CC" "${COMMON[@]}" -std=c11 -c "$LOADER" -o "$TMP/loader.o"
"$CC" "${COMMON[@]}" -c "$META" -o "$TMP/meta.o"
loader_undefined="$("$NM" -u "$TMP/loader.o" | awk '{print $NF}')"
[ "$loader_undefined" = "__morok_npack_meta" ]

"$CC" -O2 "$WORKLOAD" "$TMP/loader.o" "$TMP/meta.o" \
  -fpass-plugin="$PLUGIN" -mllvm -morok \
  -mllvm "-morok-config=$CONFIG" -mllvm -morok-native-pack \
  -mllvm -morok-seed=31337 -Wl,-T,"$SCRIPT" -Wl,--build-id=sha1 \
  -o "$TMP/packed"
"$CC" -O2 "$WORKLOAD" -Wl,--build-id=sha1 -o "$TMP/clean"

"$STRIP" -s "$TMP/packed"
"$PACKER" finalize "$TMP/packed" \
  --key "$TMP/key/morok_native_pack.key" --consume-key >/dev/null
"$PACKER" verify "$TMP/packed" >/dev/null
[ ! -e "$TMP/key/morok_native_pack.key" ]

packed_out="$($TMP/packed)"
clean_out="$($TMP/clean)"
[ "$packed_out" = "$clean_out" ]

if strings -a "$TMP/packed" | grep -Eq \
    'morok[_\.]npack|native_pack|native-pack-result'; then
  echo "native-pack labels or protected user strings survived in the ELF" >&2
  exit 1
fi

cp "$TMP/packed" "$TMP/corrupt"
python3 - "$TMP/corrupt" <<'PY'
import struct
import sys

path = sys.argv[1]
data = bytearray(open(path, "rb").read())
phoff = struct.unpack_from("<Q", data, 32)[0]
phentsz, phnum = struct.unpack_from("<HH", data, 54)
loads = []
for i in range(phnum):
    off = phoff + i * phentsz
    typ, flags = struct.unpack_from("<II", data, off)
    if typ == 1 and flags & 1:
        fileoff = struct.unpack_from("<Q", data, off + 8)[0]
        vaddr = struct.unpack_from("<Q", data, off + 16)[0]
        filesz = struct.unpack_from("<Q", data, off + 32)[0]
        loads.append((fileoff, vaddr, filesz))
if not loads:
    raise SystemExit("missing executable PT_LOAD")
fileoff, _, filesz = loads[-1]
if filesz < 65536:
    raise SystemExit("protected PT_LOAD is too small")
data[fileoff + 257] ^= 0x40
open(path, "wb").write(data)
PY
if "$PACKER" verify "$TMP/corrupt" >/dev/null 2>&1; then
  echo "corrupted packed artifact passed verification" >&2
  exit 1
fi
if "$TMP/corrupt" >/dev/null 2>&1; then
  echo "corrupted packed artifact executed successfully" >&2
  exit 1
fi
