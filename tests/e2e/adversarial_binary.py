#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# Test-only binary mutator for adversarial e2e gates.
#
# `seal` finalizes post-link integrity manifests by filling expected hashes and
# code-window lengths after native layout is known. `patch-*` deliberately
# mutates protected bytes so the sealed binary must stop behaving like the
# unpatched one.

from __future__ import annotations

import argparse
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


SC_MAGIC = 0xA7D13C5E9000C3B2
SC_MANIFEST_SIZE = 72
MG_MAGIC = 0x8E21B7C4005AF10D
MG_HEADER_SIZE = 24
MG_RECORD_V2_SIZE = 32
MG_RECORD_V3_SIZE = 56
MG_UNSEALED_CODE_SIZE = 0xFFFFFFFF
CKD_MAGIC = 0xC30D5B11A6E48F27
CKD_HEADER_SIZE = 16
CKD_RECORD_V1_SIZE = 72
CKD_RECORD_V2_SIZE = 88
CKD_MAX_REGION_BYTES = 32
CKD_UNSEALED_CODE_SIZE = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
S_SYMBOL_STUBS = 0x8
INDIRECT_SYMBOL_MASK = 0x0FFFFFFF

ELF_MACHINE_X86_64 = 62
ELF_MACHINE_AARCH64 = 183
PT_LOAD = 1


@dataclass
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    flags: int = 0


@dataclass
class Section:
    sectname: str
    segname: str
    addr: int
    size: int
    offset: int
    flags: int
    reserved1: int
    reserved2: int


@dataclass
class Manifest:
    offset: int
    region: int
    expected: int
    region_size: int
    seed: int
    expected_hash: int
    target: int
    code_size: int


@dataclass
class MgNodeManifest:
    offset: int
    index: int
    region: int
    expected: int
    target: int
    code_size: int
    native_expected: int
    seed: int
    expected_hash: int


@dataclass
class MgManifest:
    offset: int
    version: int
    region_size: int
    coverage_depth: int
    nodes: list[MgNodeManifest]


@dataclass
class CkdNodeManifest:
    offset: int
    index: int
    encoded: int
    code_size: int
    seal_state: int
    dispatcher: int
    site: int
    target: int
    salt: int
    mul: int
    add: int
    seal_salt: int
    rot: int
    region_bytes: int


@dataclass
class CkdManifest:
    offset: int
    version: int
    nodes: list[CkdNodeManifest]


class Binary:
    def __init__(self, path: Path):
        self.path = path
        self.data = bytearray(path.read_bytes())
        self.kind = ""
        self.arch = ""
        self.segments: list[Segment] = []
        self.sections: list[Section] = []
        self.symbols: list[str] = []
        self.indirect_symbols: list[int] = []
        self.macho_base = 0
        self._parse()

    def _parse(self) -> None:
        if self.data.startswith(b"\x7fELF"):
            self._parse_elf64()
            return
        magic = self.u32(0)
        if magic == 0xFEEDFACF:
            self._parse_macho64()
            return
        raise SystemExit(f"unsupported binary format: {self.path}")

    def u16(self, off: int) -> int:
        return struct.unpack_from("<H", self.data, off)[0]

    def u32(self, off: int) -> int:
        return struct.unpack_from("<I", self.data, off)[0]

    def u64(self, off: int) -> int:
        return struct.unpack_from("<Q", self.data, off)[0]

    def put_u32(self, off: int, value: int) -> None:
        struct.pack_into("<I", self.data, off, value & 0xFFFFFFFF)

    def put_u64(self, off: int, value: int) -> None:
        struct.pack_into("<Q", self.data, off, value & 0xFFFFFFFFFFFFFFFF)

    def _parse_elf64(self) -> None:
        if self.data[4] != 2 or self.data[5] != 1:
            raise SystemExit("only little-endian ELF64 is supported")
        self.kind = "elf"
        machine = self.u16(18)
        if machine == ELF_MACHINE_X86_64:
            self.arch = "x86_64"
        elif machine == ELF_MACHINE_AARCH64:
            self.arch = "arm64"
        else:
            self.arch = f"elf-machine-{machine}"

        e_phoff = self.u64(32)
        e_phentsize = self.u16(54)
        e_phnum = self.u16(56)
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _align = (
                struct.unpack_from("<IIQQQQQQ", self.data, off)
            )
            if p_type == PT_LOAD and p_filesz:
                self.segments.append(
                    Segment(
                        name=f"PT_LOAD_{i}",
                        vmaddr=p_vaddr,
                        vmsize=p_memsz,
                        fileoff=p_offset,
                        filesize=p_filesz,
                        flags=p_flags,
                    )
                )

    def _parse_macho64(self) -> None:
        self.kind = "macho"
        (
            _magic,
            cputype,
            _cpusubtype,
            _filetype,
            ncmds,
            _sizeofcmds,
            _flags,
            _reserved,
        ) = struct.unpack_from("<IiiIIIII", self.data, 0)
        if cputype == CPU_TYPE_ARM64:
            self.arch = "arm64"
        elif cputype == CPU_TYPE_X86_64:
            self.arch = "x86_64"
        else:
            self.arch = f"macho-cpu-{cputype}"

        symoff = nsyms = stroff = strsize = None
        indirectsymoff = nindirectsyms = None

        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", self.data, off)
            if cmd == LC_SEGMENT_64:
                (
                    _cmd,
                    _cmdsize,
                    segname_raw,
                    vmaddr,
                    vmsize,
                    fileoff,
                    filesize,
                    maxprot,
                    _initprot,
                    nsects,
                    _segflags,
                ) = struct.unpack_from("<II16sQQQQiiII", self.data, off)
                segname = cstr(segname_raw)
                self.segments.append(
                    Segment(segname, vmaddr, vmsize, fileoff, filesize, maxprot)
                )
                sec_off = off + 72
                for _sec in range(nsects):
                    (
                        sect_raw,
                        sec_seg_raw,
                        addr,
                        size,
                        offset,
                        _align,
                        _reloff,
                        _nreloc,
                        flags,
                        reserved1,
                        reserved2,
                        _reserved3,
                    ) = struct.unpack_from("<16s16sQQIIIIIIII", self.data, sec_off)
                    self.sections.append(
                        Section(
                            cstr(sect_raw),
                            cstr(sec_seg_raw),
                            addr,
                            size,
                            offset,
                            flags,
                            reserved1,
                            reserved2,
                        )
                    )
                    sec_off += 80
            elif cmd == LC_SYMTAB:
                symoff, nsyms, stroff, strsize = struct.unpack_from(
                    "<IIII", self.data, off + 8
                )
            elif cmd == LC_DYSYMTAB:
                fields = struct.unpack_from("<18I", self.data, off + 8)
                indirectsymoff, nindirectsyms = fields[12], fields[13]
            off += cmdsize

        file_backed = [seg.vmaddr for seg in self.segments if seg.filesize > 0]
        if file_backed:
            self.macho_base = min(file_backed)

        if symoff is not None and stroff is not None:
            strtab = self.data[stroff : stroff + strsize]
            for i in range(nsyms):
                n_strx = self.u32(symoff + i * 16)
                self.symbols.append(read_str(strtab, n_strx))
        if indirectsymoff is not None:
            for i in range(nindirectsyms):
                self.indirect_symbols.append(self.u32(indirectsymoff + i * 4))

    def write(self) -> None:
        self.path.write_bytes(self.data)

    def segment_for_addr(self, addr: int) -> Segment | None:
        for seg in self.segments:
            end = seg.vmaddr + min(seg.vmsize, seg.filesize)
            if seg.vmaddr <= addr < end:
                return seg
        return None

    def fileoff_for_addr(self, addr: int) -> int | None:
        seg = self.segment_for_addr(addr)
        if not seg:
            return None
        delta = addr - seg.vmaddr
        if delta >= seg.filesize:
            return None
        return seg.fileoff + delta

    def read_addr(self, addr: int, size: int) -> bytes | None:
        off = self.fileoff_for_addr(addr)
        if off is None or off + size > len(self.data):
            return None
        return bytes(self.data[off : off + size])

    def decode_pointer(self, raw: int) -> int:
        if self.fileoff_for_addr(raw) is not None:
            return raw
        if self.kind == "macho" and self.macho_base:
            # Modern arm64 Mach-O files commonly store local data pointers as
            # dyld chained rebase records. For DYLD_CHAINED_PTR_64_REBASE the
            # low 36 bits are the unslid target offset from the image base; the
            # high bits carry chain metadata. Decode that form for post-link
            # manifests without needing symbol names.
            target = raw & ((1 << 36) - 1)
            candidate = self.macho_base + target
            if self.fileoff_for_addr(candidate) is not None:
                return candidate
        return raw

    def find_sc_manifests(self) -> list[Manifest]:
        needle = struct.pack("<Q", SC_MAGIC)
        found: list[Manifest] = []
        start = 0
        while True:
            off = self.data.find(needle, start)
            if off < 0:
                break
            start = off + 1
            if off + SC_MANIFEST_SIZE > len(self.data):
                continue
            version = self.u32(off + 8)
            region_size = self.u32(off + 32)
            if version != 2 or region_size == 0 or region_size > 1 << 20:
                continue
            region = self.decode_pointer(self.u64(off + 16))
            expected = self.decode_pointer(self.u64(off + 24))
            target = self.decode_pointer(self.u64(off + 56))
            code_size = self.decode_pointer(self.u64(off + 64))
            m = Manifest(
                offset=off,
                region=region,
                expected=expected,
                region_size=region_size,
                seed=self.u64(off + 40),
                expected_hash=self.u64(off + 48),
                target=target,
                code_size=code_size,
            )
            if (
                self.fileoff_for_addr(m.region) is not None
                and self.fileoff_for_addr(m.expected) is not None
                and self.fileoff_for_addr(m.target) is not None
                and self.fileoff_for_addr(m.code_size) is not None
            ):
                found.append(m)
        return found

    def find_mg_manifests(self) -> list[MgManifest]:
        needle = struct.pack("<Q", MG_MAGIC)
        found: list[MgManifest] = []
        start = 0
        while True:
            off = self.data.find(needle, start)
            if off < 0:
                break
            start = off + 1
            if off + MG_HEADER_SIZE > len(self.data):
                continue
            version = self.u32(off + 8)
            count = self.u32(off + 12)
            region_size = self.u32(off + 16)
            coverage = self.u32(off + 20)
            if version == 2:
                record_size = MG_RECORD_V2_SIZE
            elif version == 3:
                record_size = MG_RECORD_V3_SIZE
            else:
                continue
            if count == 0 or count > 1024 or region_size == 0 or region_size > 1 << 20:
                continue
            total_size = MG_HEADER_SIZE + count * record_size
            if off + total_size > len(self.data):
                continue

            nodes: list[MgNodeManifest] = []
            for i in range(count):
                rec = off + MG_HEADER_SIZE + i * record_size
                region = self.decode_pointer(self.u64(rec))
                expected = self.decode_pointer(self.u64(rec + 8))
                if (
                    self.fileoff_for_addr(region) is None
                    or self.fileoff_for_addr(expected) is None
                ):
                    continue
                if version == 2:
                    nodes.append(
                        MgNodeManifest(
                            offset=rec,
                            index=i,
                            region=region,
                            expected=expected,
                            target=0,
                            code_size=0,
                            native_expected=0,
                            seed=self.u64(rec + 16),
                            expected_hash=self.u64(rec + 24),
                        )
                    )
                    continue

                target = self.decode_pointer(self.u64(rec + 16))
                code_size = self.decode_pointer(self.u64(rec + 24))
                native_expected = self.decode_pointer(self.u64(rec + 32))
                if (
                    self.fileoff_for_addr(target) is None
                    or self.fileoff_for_addr(code_size) is None
                    or self.fileoff_for_addr(native_expected) is None
                ):
                    continue
                nodes.append(
                    MgNodeManifest(
                        offset=rec,
                        index=i,
                        region=region,
                        expected=expected,
                        target=target,
                        code_size=code_size,
                        native_expected=native_expected,
                        seed=self.u64(rec + 40),
                        expected_hash=self.u64(rec + 48),
                    )
                )
            if nodes:
                found.append(
                    MgManifest(
                        offset=off,
                        version=version,
                        region_size=region_size,
                        coverage_depth=coverage,
                        nodes=nodes,
                    )
                )
        return found

    def find_ckd_manifests(self, require_patchable: bool = True) -> list[CkdManifest]:
        needle = struct.pack("<Q", CKD_MAGIC)
        found: list[CkdManifest] = []
        start = 0
        while True:
            off = self.data.find(needle, start)
            if off < 0:
                break
            start = off + 1
            if off + CKD_HEADER_SIZE > len(self.data):
                continue
            version = self.u32(off + 8)
            count = self.u32(off + 12)
            if version not in (1, 2) or count == 0 or count > 4096:
                continue
            record_size = CKD_RECORD_V2_SIZE if version == 2 else CKD_RECORD_V1_SIZE
            total_size = CKD_HEADER_SIZE + count * record_size
            if off + total_size > len(self.data):
                continue

            nodes: list[CkdNodeManifest] = []
            for i in range(count):
                rec = off + CKD_HEADER_SIZE + i * record_size
                def manifest_ptr(rel: int) -> int:
                    raw = self.u64(rec + rel)
                    return 0 if raw == 0 else self.decode_pointer(raw)

                encoded = manifest_ptr(0)
                code_size = manifest_ptr(8)
                if version == 2:
                    seal_state = manifest_ptr(16)
                    dispatcher = manifest_ptr(24)
                    site = manifest_ptr(32)
                    target = manifest_ptr(40)
                    salt = self.u64(rec + 48)
                    mul = self.u64(rec + 56)
                    add = self.u64(rec + 64)
                    seal_salt = self.u64(rec + 72)
                    rot = self.u32(rec + 80)
                    region_bytes = self.u32(rec + 84)
                else:
                    seal_state = 0
                    dispatcher = manifest_ptr(16)
                    site = manifest_ptr(24)
                    target = manifest_ptr(32)
                    salt = self.u64(rec + 40)
                    mul = self.u64(rec + 48)
                    add = self.u64(rec + 56)
                    seal_salt = 0
                    rot = self.u32(rec + 64)
                    region_bytes = self.u32(rec + 68)
                if self.fileoff_for_addr(site) is None:
                    continue
                if require_patchable and (
                    self.fileoff_for_addr(encoded) is None
                    or self.fileoff_for_addr(code_size) is None
                    or (version == 2 and self.fileoff_for_addr(seal_state) is None)
                    or self.fileoff_for_addr(dispatcher) is None
                    or self.fileoff_for_addr(target) is None
                    or region_bytes == 0
                    or region_bytes > CKD_MAX_REGION_BYTES
                    or rot > 63
                ):
                    continue
                nodes.append(
                    CkdNodeManifest(
                        offset=rec,
                        index=i,
                        encoded=encoded,
                        code_size=code_size,
                        seal_state=seal_state,
                        dispatcher=dispatcher,
                        site=site,
                        target=target,
                        salt=salt,
                        mul=mul,
                        add=add,
                        seal_salt=seal_salt,
                        rot=rot,
                        region_bytes=region_bytes,
                    )
                )
            if nodes:
                found.append(CkdManifest(offset=off, version=version, nodes=nodes))
        return found

    def macho_stub_offsets(self, wanted: set[str]) -> list[tuple[str, int, int]]:
        if self.kind != "macho" or not self.symbols or not self.indirect_symbols:
            return []
        out: list[tuple[str, int, int]] = []
        for sec in self.sections:
            if (sec.flags & 0xFF) != S_SYMBOL_STUBS or sec.reserved2 == 0:
                continue
            count = sec.size // sec.reserved2
            for i in range(count):
                indirect_index = sec.reserved1 + i
                if indirect_index >= len(self.indirect_symbols):
                    continue
                sym_index = self.indirect_symbols[indirect_index]
                sym_index &= INDIRECT_SYMBOL_MASK
                if sym_index >= len(self.symbols):
                    continue
                name = self.symbols[sym_index]
                if name in wanted:
                    out.append((name, sec.offset + i * sec.reserved2, sec.reserved2))
        return out


def cstr(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


def read_str(raw: bytes, off: int) -> str:
    if off <= 0 or off >= len(raw):
        return ""
    end = raw.find(b"\0", off)
    if end < 0:
        end = len(raw)
    return raw[off:end].decode("utf-8", "replace")


def hash_step(h: int, b: int) -> int:
    h ^= b
    h = (h * 0xFF51AFD7ED558CCD) & 0xFFFFFFFFFFFFFFFF
    h ^= h >> 32
    h = (h * 0xC4CEB9FE1A85EC53) & 0xFFFFFFFFFFFFFFFF
    h ^= h >> 29
    return h & 0xFFFFFFFFFFFFFFFF


def hash_bytes(blob: bytes, seed: int) -> int:
    h = seed & 0xFFFFFFFFFFFFFFFF
    for b in blob:
        h = hash_step(h, b)
    return h


def rotl64_value(value: int, amount: int) -> int:
    sh = (amount % 63) + 1
    return ((value << sh) | (value >> (64 - sh))) & MASK64


def rotl64_ckd(value: int, amount: int) -> int:
    sh = amount & 63
    if sh == 0:
        return value & MASK64
    return ((value << sh) | (value >> (64 - sh))) & MASK64


def ckd_site_hash(blob: bytes, site_delta: int, node: CkdNodeManifest) -> int:
    h = (node.salt ^ site_delta) & MASK64
    for i, b in enumerate(blob):
        salted = (
            b + node.add + ((0x9E3779B97F4A7C15 * i) & MASK64)
        ) & MASK64
        h ^= salted
        h = (h * (node.mul | 1)) & MASK64
        h = rotl64_ckd(h, (node.rot + i) & 63)
        h = (h + site_delta) & MASK64
        h ^= h >> 29
        h &= MASK64
    return h


def ckd_seal_mix(value: int) -> int:
    value ^= value >> 33
    value = (value * 0xFF51AFD7ED558CCD) & MASK64
    value ^= value >> 29
    value = (value * 0xC4CEB9FE1A85EC53) & MASK64
    value ^= value >> 32
    return value & MASK64


def ckd_seal_state(
    encoded: int, code_size: int, site_delta: int, target_delta: int, node: CkdNodeManifest
) -> int:
    h = (encoded ^ node.seal_salt) & MASK64
    h = ckd_seal_mix(h ^ code_size)
    h = ckd_seal_mix((h + site_delta) & MASK64)
    h = ckd_seal_mix(h ^ target_delta)
    h = ckd_seal_mix((h + node.salt) & MASK64)
    h = ckd_seal_mix(h ^ (node.mul | 1))
    h = ckd_seal_mix((h + node.add) & MASK64)
    shape = ((node.rot & 0xFFFFFFFF) << 32) | (node.region_bytes & 0xFFFFFFFF)
    h = ckd_seal_mix(h ^ shape)
    return h or 0xA5A5D13C5EEDC0DE


def mg_native_seed(region_hash: int, index: int) -> int:
    salt = (0xD6E8FEB86659FD93 + index * 0x100000001B3) & MASK64
    mul = (0x94D049BB133111EB + index * 0x9E37) & MASK64
    mixed = ((region_hash ^ salt) * mul) & MASK64
    return (rotl64_value(region_hash, 17 + index * 11) ^ mixed) & MASK64


def resign_macho(binary: "Binary", path: Path) -> None:
    """Re-sign a modified Mach-O so the kernel will run it.

    Sealing rewrites bytes in __DATA, which invalidates any existing code
    signature.  On arm64 macOS the kernel SIGKILLs a binary whose signature no
    longer matches its pages BEFORE a single instruction executes — so without
    this step a freshly sealed binary just dies with "killed" and the runtime
    self-check never even runs.  Ad-hoc re-sign to make it launchable again.
    """
    if binary.kind != "macho":
        return
    codesign = shutil.which("codesign")
    if not codesign:
        return
    result = subprocess.run(
        [codesign, "--force", "--sign", "-", str(path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(
            f"warning: codesign failed after seal ({result.stderr.strip()}); "
            f"re-sign {path} manually or it will be killed at launch",
            file=sys.stderr,
        )


def sealed_code_len(
    target_seg: Segment,
    target: int,
    configured_region_size: int,
    window: int,
    cover_timing_stubs: bool,
) -> int:
    seg_end_addr = target_seg.vmaddr + target_seg.filesize
    available = max(0, min(window, seg_end_addr - target))
    if cover_timing_stubs:
        return available
    # Keep the normal sealed runtime hash bounded by the pass' configured
    # native region size. Hot functions may call the diff helper thousands of
    # times; sealing the whole remaining text segment makes intact binaries
    # spend most of their time rehashing unrelated code.
    return max(0, min(configured_region_size, available))


def seal(path: Path, window: int, cover_timing_stubs: bool = False) -> int:
    binary = Binary(path)
    manifests = binary.find_sc_manifests()
    sealed_sc = 0
    for m in manifests:
        if m.seed == 0 and m.expected_hash == 0:
            continue
        region = binary.read_addr(m.region, m.region_size)
        target_seg = binary.segment_for_addr(m.target)
        target_off = binary.fileoff_for_addr(m.target)
        expected_off = binary.fileoff_for_addr(m.expected)
        code_size_off = binary.fileoff_for_addr(m.code_size)
        if (
            region is None
            or target_seg is None
            or target_off is None
            or expected_off is None
            or code_size_off is None
        ):
            continue
        code_len = sealed_code_len(
            target_seg, m.target, m.region_size, window, cover_timing_stubs
        )
        if code_len <= 0:
            continue
        code = bytes(binary.data[target_off : target_off + code_len])
        expected = hash_bytes(code, hash_bytes(region, m.seed))
        binary.put_u64(expected_off, expected)
        binary.put_u32(code_size_off, code_len)
        binary.put_u64(m.offset + 40, 0)
        binary.put_u64(m.offset + 48, 0)
        sealed_sc += 1

    sealed_mg = 0
    for manifest in binary.find_mg_manifests():
        if manifest.version != 3:
            continue
        for node in manifest.nodes:
            expected_off = binary.fileoff_for_addr(node.expected)
            target_seg = binary.segment_for_addr(node.target)
            target_off = binary.fileoff_for_addr(node.target)
            code_size_off = binary.fileoff_for_addr(node.code_size)
            native_expected_off = binary.fileoff_for_addr(node.native_expected)
            if (
                expected_off is None
                or target_seg is None
                or target_off is None
                or code_size_off is None
                or native_expected_off is None
            ):
                continue
            code_len = sealed_code_len(
                target_seg,
                node.target,
                manifest.region_size,
                window,
                cover_timing_stubs,
            )
            if code_len <= 0 or code_len == MG_UNSEALED_CODE_SIZE:
                continue
            code = bytes(binary.data[target_off : target_off + code_len])
            region_hash = binary.u64(expected_off)
            native_expected = hash_bytes(code, mg_native_seed(region_hash, node.index))
            binary.put_u64(native_expected_off, native_expected)
            binary.put_u32(code_size_off, code_len)
            binary.put_u64(node.offset + 40, 0)
            binary.put_u64(node.offset + 48, 0)
            sealed_mg += 1

    sealed_ckd = 0
    for manifest in binary.find_ckd_manifests():
        for node in manifest.nodes:
            encoded_off = binary.fileoff_for_addr(node.encoded)
            code_size_off = binary.fileoff_for_addr(node.code_size)
            seal_state_off = (
                binary.fileoff_for_addr(node.seal_state)
                if manifest.version == 2
                else None
            )
            if encoded_off is None or code_size_off is None:
                continue
            if manifest.version == 2 and seal_state_off is None:
                continue
            if node.region_bytes == 0 or node.region_bytes > window:
                continue
            code = binary.read_addr(node.site, node.region_bytes)
            if code is None:
                continue
            site_delta = (node.site - node.dispatcher) & MASK64
            target_delta = (node.target - node.dispatcher) & MASK64
            encoded = (target_delta + ckd_site_hash(code, site_delta, node)) & MASK64
            binary.put_u64(encoded_off, encoded)
            binary.put_u32(code_size_off, node.region_bytes)
            if manifest.version == 2:
                seal_value = ckd_seal_state(
                    encoded, node.region_bytes, site_delta, target_delta, node
                )
                binary.put_u64(seal_state_off, seal_value)
            # Do not rewrite pointer fields in Mach-O manifests: they
            # participate in dyld chained-fixup metadata on arm64 and zeroing
            # them can break later GOT binds on the same page.  Scrub only the
            # scalar hash material needed to recompute the encoded target.
            if manifest.version == 2:
                for rel in (48, 56, 64, 72):
                    binary.put_u64(node.offset + rel, 0)
                binary.put_u32(node.offset + 80, 0)
                binary.put_u32(node.offset + 84, 0)
            else:
                for rel in (40, 48, 56):
                    binary.put_u64(node.offset + rel, 0)
                binary.put_u32(node.offset + 64, 0)
                binary.put_u32(node.offset + 68, 0)
            sealed_ckd += 1

    if sealed_sc or sealed_mg or sealed_ckd:
        binary.write()
        resign_macho(binary, path)
    print(
        f"sealed self-check manifests={sealed_sc} "
        f"mutual-guard nodes={sealed_mg} "
        f"caller-keyed-dispatch sites={sealed_ckd} binary={path}"
    )
    return 0 if sealed_sc or sealed_mg or sealed_ckd else 1


def postlink_oracle_findings(binary: Binary) -> list[str]:
    findings: list[str] = []
    for m in binary.find_sc_manifests():
        if m.seed != 0 or m.expected_hash != 0:
            findings.append(
                f"self-check manifest at file+0x{m.offset:x} retains "
                "seed/expected_hash"
            )

    for manifest in binary.find_mg_manifests():
        for node in manifest.nodes:
            if node.seed != 0 or node.expected_hash != 0:
                findings.append(
                    f"mutual-guard manifest at file+0x{manifest.offset:x} "
                    f"node={node.index} "
                    "retains seed/expected_hash"
                )
    for manifest in binary.find_ckd_manifests(require_patchable=False):
        for node in manifest.nodes:
            if (
                node.salt != 0
                or node.mul != 0
                or node.add != 0
                or node.seal_salt != 0
                or node.rot != 0
                or node.region_bytes != 0
            ):
                findings.append(
                    f"caller-keyed-dispatch manifest at file+0x{manifest.offset:x} "
                    f"node={node.index} retains dispatch/hash oracle data"
                )
    return findings


def assert_no_postlink_oracles(path: Path) -> int:
    binary = Binary(path)
    findings = postlink_oracle_findings(binary)
    for finding in findings:
        print(f"FAIL {finding}", file=sys.stderr)
    if findings:
        return 1
    print(f"OK no retained post-link oracle data binary={path}")
    return 0


def patch_code_at(binary: Binary, target: int, label: str) -> int:
    target_off = binary.fileoff_for_addr(target)
    if target_off is None:
        print(f"{label} target is not file-backed", file=sys.stderr)
        return 1
    if binary.arch == "arm64":
        # ARM64 NOP: 1f 20 03 d5
        patch_off = target_off - (target_off % 4)
        binary.data[patch_off : patch_off + 4] = b"\x1f\x20\x03\xd5"
    elif binary.arch == "x86_64":
        binary.data[target_off] = 0x90
    else:
        print(f"unsupported architecture for code patch: {binary.arch}", file=sys.stderr)
        return 77
    print(f"patched {label} code byte at target=0x{target:x}")
    return 0


def patch_selfcheck_code(path: Path) -> int:
    binary = Binary(path)
    manifests = binary.find_sc_manifests()
    if not manifests:
        print("no self-check manifests to patch", file=sys.stderr)
        return 1
    rc = patch_code_at(binary, manifests[0].target, "self-check")
    if rc != 0:
        return rc
    binary.write()
    return 0


def patch_mutualguard_code(path: Path) -> int:
    binary = Binary(path)
    manifests = [m for m in binary.find_mg_manifests() if m.version == 3]
    if not manifests or not manifests[0].nodes:
        print("no mutual-guard manifests to patch", file=sys.stderr)
        return 1
    rc = patch_code_at(binary, manifests[0].nodes[0].target, "mutual-guard")
    if rc != 0:
        return rc
    binary.write()
    return 0


def patch_ckd_code(path: Path) -> int:
    binary = Binary(path)
    manifests = binary.find_ckd_manifests(require_patchable=False)
    if not manifests or not manifests[0].nodes:
        print("no caller-keyed-dispatch manifests to patch", file=sys.stderr)
        return 1
    rc = patch_code_at(
        binary, manifests[0].nodes[0].site, "caller-keyed-dispatch"
    )
    if rc != 0:
        return rc
    binary.write()
    return 0


def patch_ckd_downgrade(path: Path) -> int:
    # Regression for #21: simulate a static attacker who resets the mutable
    # code_size seal slot back to the unsealed sentinel to downgrade a sealed
    # binary.  Pre-fix, the startup constructor treats the unsealed slot as
    # "compute from scratch", re-hashes the live bytes, and re-seals the encoded
    # target — so a downgraded (and, in the full attack, also code-patched)
    # binary silently self-adapts and runs identically to the sealed baseline.
    # With the sealed-release fix the constructor never recomputes; an unsealed
    # slot poisons the encoded target, so the downgraded binary MUST diverge
    # from the sealed baseline.
    #
    # We reset the seal slot WITHOUT corrupting an executing instruction on
    # purpose: a code-byte patch would crash the process by itself (instruction
    # corruption) regardless of the seal logic, which would mask the very
    # behaviour under test.  Resetting the flag alone isolates the fix — pre-fix
    # the binary self-seals and behaves normally; post-fix it poisons and
    # diverges.  The full code-patch+downgrade attack is covered transitively:
    # if the bare flag reset already poisons, adding a code patch cannot rescue
    # it.
    binary = Binary(path)
    manifests = binary.find_ckd_manifests(require_patchable=False)
    if not manifests or not manifests[0].nodes:
        print("no caller-keyed-dispatch manifests to patch", file=sys.stderr)
        return 1
    reset = 0
    for manifest in manifests:
        for node in manifest.nodes:
            code_size_off = binary.fileoff_for_addr(node.code_size)
            if code_size_off is None:
                continue
            binary.put_u32(code_size_off, CKD_UNSEALED_CODE_SIZE)
            reset += 1
    if reset == 0:
        print(
            "caller-keyed-dispatch code_size slot not addressable",
            file=sys.stderr,
        )
        return 1
    binary.write()
    print(
        f"reset caller-keyed-dispatch code_size slots={reset} to unsealed "
        "sentinel"
    )
    return 0


def patch_ckd_code_reset_size(path: Path) -> int:
    binary = Binary(path)
    manifests = binary.find_ckd_manifests(require_patchable=False)
    if not manifests or not manifests[0].nodes:
        print("no caller-keyed-dispatch manifests to patch", file=sys.stderr)
        return 1
    node = manifests[0].nodes[0]
    rc = patch_code_at(binary, node.site, "caller-keyed-dispatch")
    if rc != 0:
        return rc
    code_size_off = binary.fileoff_for_addr(node.code_size)
    if code_size_off is None:
        print(
            "caller-keyed-dispatch code_size is not file-backed",
            file=sys.stderr,
        )
        return 1
    binary.put_u32(code_size_off, CKD_UNSEALED_CODE_SIZE)
    print("reset caller-keyed-dispatch code_size to unsealed sentinel")
    binary.write()
    return 0


def patch_rdtscp_sequences(binary: Binary) -> int:
    # lfence; rdtscp; lfence
    sequence = b"\x0f\xae\xe8\x0f\x01\xf9\x0f\xae\xe8"
    count = 0
    start = 0
    while True:
        off = binary.data.find(sequence, start)
        if off < 0:
            break
        binary.data[off : off + len(sequence)] = b"\x90" * len(sequence)
        count += 1
        start = off + len(sequence)
    # Some assemblers may separate the fences. Patch bare RDTSCP too, after the
    # full sequence pass so it cannot hide a sequence match.
    bare = b"\x0f\x01\xf9"
    start = 0
    while True:
        off = binary.data.find(bare, start)
        if off < 0:
            break
        binary.data[off : off + len(bare)] = b"\x90" * len(bare)
        count += 1
        start = off + len(bare)
    return count


def patch_arm64_import_stub(binary: Binary, name: str, off: int, size: int) -> int:
    if size < 8:
        return 0
    # mov x0, #0; ret; nop...
    patch = bytearray(b"\x00\x00\x80\xd2\xc0\x03\x5f\xd6")
    while len(patch) < size:
        patch += b"\x1f\x20\x03\xd5"
    binary.data[off : off + size] = patch[:size]
    print(f"patched {name} stub at file+0x{off:x} size={size}")
    return 1


def patch_timing(path: Path) -> int:
    binary = Binary(path)
    patched = 0
    if binary.arch == "x86_64":
        patched += patch_rdtscp_sequences(binary)
    if binary.kind == "macho" and binary.arch == "arm64":
        wanted = {"_mach_absolute_time", "_clock_gettime"}
        for name, off, size in binary.macho_stub_offsets(wanted):
            patched += patch_arm64_import_stub(binary, name, off, size)
    if not patched:
        print(
            f"no supported timing primitive found in {path} "
            f"(format={binary.kind} arch={binary.arch})",
            file=sys.stderr,
        )
        return 77
    binary.write()
    print(f"patched timing primitives={patched} binary={path}")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_seal = sub.add_parser("seal")
    p_seal.add_argument("binary", type=Path)
    p_seal.add_argument("--window", type=int, default=262144)
    p_seal.add_argument("--cover-timing-stubs", action="store_true")

    p_code = sub.add_parser("patch-selfcheck-code")
    p_code.add_argument("binary", type=Path)

    p_mg_code = sub.add_parser("patch-mutualguard-code")
    p_mg_code.add_argument("binary", type=Path)

    p_ckd_code = sub.add_parser("patch-ckd-code")
    p_ckd_code.add_argument("binary", type=Path)
    p_ckd_reset = sub.add_parser("patch-ckd-code-reset-size")
    p_ckd_reset.add_argument("binary", type=Path)

    p_ckd_downgrade = sub.add_parser("patch-ckd-downgrade")
    p_ckd_downgrade.add_argument("binary", type=Path)

    p_timing = sub.add_parser("patch-timing")
    p_timing.add_argument("binary", type=Path)

    p_oracles = sub.add_parser("assert-no-postlink-oracles")
    p_oracles.add_argument("binary", type=Path)

    args = parser.parse_args(argv)
    if args.cmd == "seal":
        return seal(args.binary, args.window, args.cover_timing_stubs)
    if args.cmd == "patch-selfcheck-code":
        return patch_selfcheck_code(args.binary)
    if args.cmd == "patch-mutualguard-code":
        return patch_mutualguard_code(args.binary)
    if args.cmd == "patch-ckd-code":
        return patch_ckd_code(args.binary)
    if args.cmd == "patch-ckd-downgrade":
        return patch_ckd_downgrade(args.binary)
    if args.cmd == "patch-ckd-code-reset-size":
        return patch_ckd_code_reset_size(args.binary)
    if args.cmd == "patch-timing":
        return patch_timing(args.binary)
    if args.cmd == "assert-no-postlink-oracles":
        return assert_no_postlink_oracles(args.binary)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
