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
TARGET="$($CC -dumpmachine)"
ARCH_FLAGS=()
case "$TARGET" in
  aarch64-*|arm64-*) ARCH_FLAGS=(-mno-outline-atomics) ;;
esac
COMMON=(-I"$TMP/key" -ffreestanding -fno-builtin -fPIC -fno-stack-protector
  -fno-unwind-tables -fno-asynchronous-unwind-tables -fvisibility=hidden -O2
  "${ARCH_FLAGS[@]}")
"$CC" "${COMMON[@]}" -std=c11 -c "$LOADER" -o "$TMP/loader.o"
"$CC" "${COMMON[@]}" -c "$META" -o "$TMP/meta.o"
loader_undefined="$("$NM" -u "$TMP/loader.o" | awk '{print $NF}')"
if [ "$loader_undefined" != "__morok_npack_meta" ]; then
  echo "native-pack loader has unexpected undefined symbols:" >&2
  "$NM" -u "$TMP/loader.o" >&2
  exit 1
fi

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
    if typ == 1:
        fileoff = struct.unpack_from("<Q", data, off + 8)[0]
        vaddr = struct.unpack_from("<Q", data, off + 16)[0]
        filesz = struct.unpack_from("<Q", data, off + 32)[0]
        loads.append((fileoff, vaddr, filesz, flags))

def file_to_vaddr(offset, size):
    for fileoff, vaddr, filesz, _ in loads:
        if offset >= fileoff and offset - fileoff <= filesz \
                and size <= filesz - (offset - fileoff):
            return vaddr + offset - fileoff
    return None

domain = 0x9f4a7c15d3e26b81
found = None
for meta in range(0, len(data) - 128 + 1, 8):
    version, flags = struct.unpack_from("<II", data, meta + 16)
    if version != 1 or flags != 1:
        continue
    delta = struct.unpack_from("<q", data, meta + 24)[0]
    length = struct.unpack_from("<Q", data, meta + 32)[0]
    tag0 = struct.unpack_from("<Q", data, meta + 56)[0]
    cookie = struct.unpack_from("<Q", data, meta + 72)[0]
    salt0 = struct.unpack_from("<Q", data, meta + 112)[0]
    meta_vaddr = file_to_vaddr(meta, 128)
    if meta_vaddr is None or length == 0 or length % 65536 != 0:
        continue
    begin = meta_vaddr + delta
    if meta_vaddr - begin != length or cookie != tag0 ^ length ^ salt0 ^ domain:
        continue
    matches = []
    for fileoff, vaddr, filesz, segment_flags in loads:
        if segment_flags & 1 and begin >= vaddr and begin - vaddr <= filesz \
                and length <= filesz - (begin - vaddr):
            matches.append(fileoff + begin - vaddr)
    if len(matches) != 1 or found is not None:
        raise SystemExit("ambiguous finalized protected range")
    found = matches[0]
if found is None:
    raise SystemExit("finalized protected range was not found")
data[found + 257] ^= 0x40
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
