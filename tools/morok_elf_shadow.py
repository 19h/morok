#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Post-link ELF relocation shadowing for Linux ELF64 executables.

The conventional DT_JMPREL records are rewritten to name decoy dynamic
symbols.  A later, page-overlapping PT_LOAD maps an unmodified copy of the
relocation page(s) at process start, so the Linux dynamic linker consumes the
original symbol indices.  Code, PLT stubs, GOT slots, and runtime behaviour are
unchanged.

This is intentionally a narrow producer, not a general ELF editor.  It rejects
inputs whose loader image cannot be established unambiguously instead of
guessing about their runtime layout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import struct
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path


ELF64_EHDR_SIZE = 64
ELF64_PHDR_SIZE = 56
ELF64_DYN_SIZE = 16
ELF64_RELA_SIZE = 24
ELF64_SYM_SIZE = 24

ET_EXEC = 2
ET_DYN = 3
EM_X86_64 = 62

PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4

DT_NULL = 0
DT_PLTRELSZ = 2
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_STRSZ = 10
DT_SYMENT = 11
DT_PLTREL = 20
DT_JMPREL = 23
DT_GNU_HASH = 0x6FFFFEF5
DT_RELA = 7

SHT_DYNSYM = 11
STB_GLOBAL = 1
STB_WEAK = 2
STT_NOTYPE = 0
STT_FUNC = 2
STT_GNU_IFUNC = 10

R_X86_64_JUMP_SLOT = 7
DEFAULT_PAGE_SIZE = 4096
DEFAULT_MAX_SHADOW_BYTES = 1 << 20
MAX_DYNAMIC_SYMBOLS = 1 << 20


class ShadowError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProgramHeader:
    index: int
    file_offset: int
    p_type: int
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_align: int


@dataclass(frozen=True)
class DynamicSymbol:
    index: int
    name: str
    st_info: int
    st_other: int
    st_shndx: int

    @property
    def binding(self) -> int:
        return self.st_info >> 4

    @property
    def symbol_type(self) -> int:
        return self.st_info & 0xF


@dataclass(frozen=True)
class Relocation:
    index: int
    vaddr: int
    file_offset: int
    r_offset: int
    r_info: int
    r_addend: int

    @property
    def symbol_index(self) -> int:
        return self.r_info >> 32

    @property
    def relocation_type(self) -> int:
        return self.r_info & 0xFFFFFFFF


@dataclass(frozen=True)
class RelocationView:
    relocation_index: int
    static_symbol_index: int
    static_symbol: str
    runtime_symbol_index: int
    runtime_symbol: str


@dataclass(frozen=True)
class ShadowReport:
    input_size: int
    output_size: int
    page_size: int
    shadow_vaddr: int
    shadow_bytes: int
    shadow_file_offset: int
    declared_displacement: int
    program_header_index: int
    replaced_program_header_type: int
    relocations: list[RelocationView]


def align_down(value: int, alignment: int) -> int:
    return value & ~(alignment - 1)


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


class Elf64:
    def __init__(self, data: bytes | bytearray, page_size: int = DEFAULT_PAGE_SIZE):
        self.data = bytearray(data)
        self.page_size = page_size
        if page_size != DEFAULT_PAGE_SIZE:
            raise ShadowError("Linux x86-64 ELF shadowing requires 4096-byte pages")
        self._parse_header()
        self.program_headers = self._parse_program_headers()

    def _need(self, offset: int, size: int, what: str) -> None:
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ShadowError(
                f"{what} lies outside the file: file+0x{offset:x} size=0x{size:x}"
            )

    def _parse_header(self) -> None:
        self._need(0, ELF64_EHDR_SIZE, "ELF header")
        if self.data[:4] != b"\x7fELF":
            raise ShadowError("input is not an ELF file")
        if self.data[4] != 2 or self.data[5] != 1:
            raise ShadowError("only little-endian ELF64 is supported")
        self.e_type = struct.unpack_from("<H", self.data, 16)[0]
        self.e_machine = struct.unpack_from("<H", self.data, 18)[0]
        self.e_phoff = struct.unpack_from("<Q", self.data, 32)[0]
        self.e_shoff = struct.unpack_from("<Q", self.data, 40)[0]
        self.e_phentsize = struct.unpack_from("<H", self.data, 54)[0]
        self.e_phnum = struct.unpack_from("<H", self.data, 56)[0]
        self.e_shentsize = struct.unpack_from("<H", self.data, 58)[0]
        self.e_shnum = struct.unpack_from("<H", self.data, 60)[0]
        if self.e_type not in (ET_EXEC, ET_DYN):
            raise ShadowError("input must be an ET_EXEC or ET_DYN executable")
        if self.e_machine != EM_X86_64:
            raise ShadowError("only Linux x86-64 ELF relocation shadowing is supported")
        if self.e_phentsize != ELF64_PHDR_SIZE or self.e_phnum == 0:
            raise ShadowError("unsupported or empty ELF64 program-header table")
        self._need(
            self.e_phoff,
            self.e_phentsize * self.e_phnum,
            "program-header table",
        )

    def _parse_program_headers(self) -> list[ProgramHeader]:
        out: list[ProgramHeader] = []
        for index in range(self.e_phnum):
            off = self.e_phoff + index * self.e_phentsize
            fields = struct.unpack_from("<IIQQQQQQ", self.data, off)
            out.append(ProgramHeader(index, off, *fields))
        return out

    @property
    def loads(self) -> list[ProgramHeader]:
        return [p for p in self.program_headers if p.p_type == PT_LOAD]

    def declared_file_offset(
        self, vaddr: int, size: int = 1, *, loads: list[ProgramHeader] | None = None
    ) -> int:
        for phdr in loads if loads is not None else self.loads:
            if phdr.p_vaddr <= vaddr and vaddr + size <= phdr.p_vaddr + phdr.p_filesz:
                off = phdr.p_offset + vaddr - phdr.p_vaddr
                self._need(off, size, f"virtual range 0x{vaddr:x}")
                return off
        raise ShadowError(
            f"virtual range 0x{vaddr:x}..0x{vaddr + size:x} is not declared file-backed"
        )

    def runtime_file_offset(self, vaddr: int, size: int = 1) -> int:
        winner: ProgramHeader | None = None
        winner_off = 0
        for phdr in self.loads:
            displacement = phdr.p_vaddr & (self.page_size - 1)
            if phdr.p_offset < displacement:
                continue
            map_addr = align_down(phdr.p_vaddr, self.page_size)
            map_size = align_up(phdr.p_filesz + displacement, self.page_size)
            if map_addr <= vaddr and vaddr + size <= map_addr + map_size:
                map_off = phdr.p_offset - displacement
                candidate = map_off + vaddr - map_addr
                if candidate + size <= len(self.data):
                    winner = phdr
                    winner_off = candidate
        if winner is None:
            raise ShadowError(
                f"runtime range 0x{vaddr:x}..0x{vaddr + size:x} has no file mapping"
            )
        return winner_off

    def load_for_declared_range(self, vaddr: int, size: int) -> ProgramHeader:
        matches = [
            p
            for p in self.loads
            if p.p_vaddr <= vaddr and vaddr + size <= p.p_vaddr + p.p_filesz
        ]
        if len(matches) != 1:
            raise ShadowError(
                "DT_JMPREL must have exactly one unambiguous declared PT_LOAD owner"
            )
        return matches[0]

    def reject_existing_load_overlap(self) -> None:
        spans: list[tuple[int, int, int]] = []
        for phdr in self.loads:
            if phdr.p_filesz == 0:
                continue
            start = align_down(phdr.p_vaddr, self.page_size)
            end = start + align_up(
                phdr.p_filesz + (phdr.p_vaddr & (self.page_size - 1)),
                self.page_size,
            )
            for old_start, old_end, old_index in spans:
                if max(start, old_start) < min(end, old_end):
                    raise ShadowError(
                        "input already has page-overlapping PT_LOAD entries "
                        f"{old_index} and {phdr.index}; refusing an ambiguous/repeated transform"
                    )
            spans.append((start, end, phdr.index))

    def dynamic_tags(self) -> dict[int, int]:
        dynamic = [p for p in self.program_headers if p.p_type == PT_DYNAMIC]
        if len(dynamic) != 1:
            raise ShadowError("input must contain exactly one PT_DYNAMIC segment")
        phdr = dynamic[0]
        self._need(phdr.p_offset, phdr.p_filesz, "PT_DYNAMIC")
        tags: dict[int, int] = {}
        for rel in range(0, phdr.p_filesz, ELF64_DYN_SIZE):
            if rel + ELF64_DYN_SIZE > phdr.p_filesz:
                break
            tag, value = struct.unpack_from("<qQ", self.data, phdr.p_offset + rel)
            if tag == DT_NULL:
                break
            tags[tag] = value
        return tags

    def jmprel_relocations(self, tags: dict[int, int]) -> list[Relocation]:
        for required in (DT_JMPREL, DT_PLTRELSZ, DT_PLTREL):
            if required not in tags:
                raise ShadowError("input has no complete DT_JMPREL relocation table")
        if tags[DT_PLTREL] != DT_RELA:
            raise ShadowError("only DT_RELA PLT relocations are supported")
        size = tags[DT_PLTRELSZ]
        if size == 0 or size % ELF64_RELA_SIZE != 0:
            raise ShadowError("DT_PLTRELSZ is empty or not an Elf64_Rela multiple")
        base_addr = tags[DT_JMPREL]
        base_off = self.declared_file_offset(base_addr, size)
        out: list[Relocation] = []
        for index in range(size // ELF64_RELA_SIZE):
            off = base_off + index * ELF64_RELA_SIZE
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", self.data, off)
            out.append(
                Relocation(
                    index,
                    base_addr + index * ELF64_RELA_SIZE,
                    off,
                    r_offset,
                    r_info,
                    r_addend,
                )
            )
        return out

    def _dynsym_count_from_sections(self, symtab_addr: int) -> int | None:
        if self.e_shoff == 0 or self.e_shnum == 0 or self.e_shentsize != 64:
            return None
        if self.e_shnum > MAX_DYNAMIC_SYMBOLS:
            return None
        self._need(self.e_shoff, self.e_shnum * self.e_shentsize, "section table")
        for index in range(self.e_shnum):
            off = self.e_shoff + index * self.e_shentsize
            fields = struct.unpack_from("<IIQQQQIIQQ", self.data, off)
            sh_type, sh_addr, sh_size, sh_entsize = fields[1], fields[3], fields[5], fields[9]
            if sh_type == SHT_DYNSYM and sh_addr == symtab_addr:
                if sh_entsize != ELF64_SYM_SIZE or sh_size % sh_entsize != 0:
                    raise ShadowError("malformed SHT_DYNSYM section")
                return sh_size // sh_entsize
        return None

    def _dynsym_count_from_hash(self, tags: dict[int, int]) -> int | None:
        if DT_HASH not in tags:
            return None
        off = self.declared_file_offset(tags[DT_HASH], 8)
        _nbucket, nchain = struct.unpack_from("<II", self.data, off)
        if nchain == 0 or nchain > MAX_DYNAMIC_SYMBOLS:
            raise ShadowError("invalid DT_HASH symbol count")
        return nchain

    def _dynsym_count_from_gnu_hash(self, tags: dict[int, int]) -> int | None:
        if DT_GNU_HASH not in tags:
            return None
        header_off = self.declared_file_offset(tags[DT_GNU_HASH], 16)
        nbuckets, symoffset, bloom_size, _bloom_shift = struct.unpack_from(
            "<IIII", self.data, header_off
        )
        if nbuckets == 0 or bloom_size > MAX_DYNAMIC_SYMBOLS:
            raise ShadowError("invalid DT_GNU_HASH header")
        buckets_off = header_off + 16 + bloom_size * 8
        self._need(buckets_off, nbuckets * 4, "DT_GNU_HASH buckets")
        buckets = struct.unpack_from(f"<{nbuckets}I", self.data, buckets_off)
        highest = max(buckets, default=0)
        if highest == 0:
            # An empty GNU hash has no chain endpoint from which the total
            # .dynsym size can be inferred; undefined imports before symoffset
            # may still exist.  Let SHT_DYNSYM or DT_HASH establish the count.
            return None
        if highest < symoffset or highest > MAX_DYNAMIC_SYMBOLS:
            raise ShadowError("invalid DT_GNU_HASH bucket symbol index")
        chains_off = buckets_off + nbuckets * 4
        index = highest
        while index < MAX_DYNAMIC_SYMBOLS:
            chain_off = chains_off + (index - symoffset) * 4
            self._need(chain_off, 4, "DT_GNU_HASH chain")
            value = struct.unpack_from("<I", self.data, chain_off)[0]
            index += 1
            if value & 1:
                return index
        raise ShadowError("unterminated DT_GNU_HASH chain")

    def dynamic_symbols(self, tags: dict[int, int]) -> list[DynamicSymbol]:
        for required in (DT_SYMTAB, DT_STRTAB, DT_STRSZ, DT_SYMENT):
            if required not in tags:
                raise ShadowError("input has no complete dynamic symbol/string tables")
        if tags[DT_SYMENT] != ELF64_SYM_SIZE:
            raise ShadowError("unsupported DT_SYMENT")
        counts = [
            self._dynsym_count_from_sections(tags[DT_SYMTAB]),
            self._dynsym_count_from_hash(tags),
            self._dynsym_count_from_gnu_hash(tags),
        ]
        counts = [count for count in counts if count is not None]
        if not counts:
            raise ShadowError("cannot establish the dynamic-symbol count")
        if any(count != counts[0] for count in counts[1:]):
            raise ShadowError(f"dynamic-symbol count sources disagree: {counts}")
        count = counts[0]
        if count <= 1 or count > MAX_DYNAMIC_SYMBOLS:
            raise ShadowError("dynamic-symbol table has no usable imports")
        symtab_off = self.declared_file_offset(tags[DT_SYMTAB], count * ELF64_SYM_SIZE)
        strtab_off = self.declared_file_offset(tags[DT_STRTAB], tags[DT_STRSZ])
        strtab = bytes(self.data[strtab_off : strtab_off + tags[DT_STRSZ]])
        out: list[DynamicSymbol] = []
        for index in range(count):
            off = symtab_off + index * ELF64_SYM_SIZE
            st_name, st_info, st_other, st_shndx = struct.unpack_from(
                "<IBBH", self.data, off
            )
            name = ""
            if st_name:
                if st_name >= len(strtab):
                    raise ShadowError(f"dynamic symbol {index} has invalid st_name")
                end = strtab.find(b"\0", st_name)
                if end < 0:
                    raise ShadowError(f"dynamic symbol {index} has unterminated name")
                name = strtab[st_name:end].decode("utf-8", "replace")
            out.append(DynamicSymbol(index, name, st_info, st_other, st_shndx))
        return out

    def choose_spare_program_header(
        self, after_index: int, explicit_index: int | None
    ) -> ProgramHeader | None:
        if explicit_index is not None:
            if explicit_index < 0 or explicit_index >= len(self.program_headers):
                raise ShadowError("--phdr-index is outside the program-header table")
            candidate = self.program_headers[explicit_index]
            if candidate.index <= after_index or candidate.p_type not in (
                PT_NULL,
                PT_NOTE,
            ):
                raise ShadowError(
                    "explicit program header must be a later PT_NULL or PT_NOTE"
                )
            return candidate
        for wanted in (PT_NULL, PT_NOTE):
            for candidate in reversed(self.program_headers):
                if candidate.index > after_index and candidate.p_type == wanted:
                    return candidate
        return None

    def put_program_header(
        self,
        slot: ProgramHeader,
        *,
        p_flags: int,
        p_offset: int,
        p_vaddr: int,
        p_filesz: int,
        p_align: int,
    ) -> None:
        struct.pack_into(
            "<IIQQQQQQ",
            self.data,
            slot.file_offset,
            PT_LOAD,
            p_flags,
            p_offset,
            p_vaddr,
            p_vaddr,
            p_filesz,
            p_filesz,
            p_align,
        )
        self.program_headers = self._parse_program_headers()


def eligible_decoy_symbols(symbols: list[DynamicSymbol]) -> list[DynamicSymbol]:
    return [
        symbol
        for symbol in symbols
        if symbol.index != 0
        and symbol.name
        and symbol.binding in (STB_GLOBAL, STB_WEAK)
        and symbol.symbol_type in (STT_NOTYPE, STT_FUNC, STT_GNU_IFUNC)
        and (symbol.st_other & 0x3) == 0
    ]


def decoy_for_relocation(
    relocation: Relocation,
    candidates: list[DynamicSymbol],
    seed_material: bytes,
    actual_name: str,
    excluded: set[int] | None = None,
) -> DynamicSymbol:
    if excluded is None:
        excluded = set()
    usable = [
        candidate
        for candidate in candidates
        if candidate.index != relocation.symbol_index
        and candidate.name != actual_name
        and candidate.index not in excluded
    ]
    if not usable:
        raise ShadowError(
            f"relocation {relocation.index} has no alternate function-like symbol"
        )
    domain = (
        seed_material
        + relocation.index.to_bytes(8, "little")
        + relocation.r_offset.to_bytes(8, "little")
    )
    return min(
        usable,
        key=lambda candidate: hashlib.sha256(
            domain + candidate.index.to_bytes(4, "little")
        ).digest(),
    )


def _read_runtime_relocation(elf: Elf64, relocation: Relocation) -> tuple[int, int]:
    off = elf.runtime_file_offset(relocation.vaddr, ELF64_RELA_SIZE)
    _r_offset, r_info, _r_addend = struct.unpack_from("<QQq", elf.data, off)
    return r_info >> 32, r_info & 0xFFFFFFFF


def verify_bytes(data: bytes | bytearray, page_size: int = DEFAULT_PAGE_SIZE) -> ShadowReport:
    elf = Elf64(data, page_size)
    tags = elf.dynamic_tags()
    symbols = elf.dynamic_symbols(tags)
    relocations = elf.jmprel_relocations(tags)
    loads = elf.loads
    overlap_pairs: list[tuple[ProgramHeader, ProgramHeader]] = []
    for pos, left in enumerate(loads):
        left_start = align_down(left.p_vaddr, page_size)
        left_end = left_start + align_up(
            left.p_filesz + (left.p_vaddr & (page_size - 1)), page_size
        )
        for right in loads[pos + 1 :]:
            right_start = align_down(right.p_vaddr, page_size)
            right_end = right_start + align_up(
                right.p_filesz + (right.p_vaddr & (page_size - 1)), page_size
            )
            if max(left_start, right_start) < min(left_end, right_end):
                overlap_pairs.append((left, right))
    if len(overlap_pairs) != 1:
        raise ShadowError(
            f"expected exactly one page-overlapping PT_LOAD pair, found {len(overlap_pairs)}"
        )
    original, shadow = overlap_pairs[0]
    if shadow.index <= original.index:
        raise ShadowError("overlapping shadow PT_LOAD is not ordered after its source")

    views: list[RelocationView] = []
    for relocation in relocations:
        if relocation.relocation_type != R_X86_64_JUMP_SLOT:
            continue
        static_index = relocation.symbol_index
        runtime_index, runtime_type = _read_runtime_relocation(elf, relocation)
        if runtime_type != R_X86_64_JUMP_SLOT:
            raise ShadowError(
                f"runtime relocation {relocation.index} changed relocation type"
            )
        if static_index == runtime_index:
            raise ShadowError(
                f"relocation {relocation.index} has no static/runtime symbol divergence"
            )
        if static_index >= len(symbols) or runtime_index >= len(symbols):
            raise ShadowError("relocation symbol index is outside DT_SYMTAB")
        if symbols[static_index].name == symbols[runtime_index].name:
            raise ShadowError(
                f"relocation {relocation.index} has no static/runtime name divergence"
            )
        views.append(
            RelocationView(
                relocation.index,
                static_index,
                symbols[static_index].name,
                runtime_index,
                symbols[runtime_index].name,
            )
        )
    if not views:
        raise ShadowError("no divergent R_X86_64_JUMP_SLOT relocations found")

    shadow_start = align_down(shadow.p_vaddr, page_size)
    shadow_bytes = align_up(
        shadow.p_filesz + (shadow.p_vaddr & (page_size - 1)), page_size
    )
    shadow_file_offset = shadow.p_offset - (shadow.p_vaddr & (page_size - 1))
    return ShadowReport(
        input_size=len(data),
        output_size=len(data),
        page_size=page_size,
        shadow_vaddr=shadow_start,
        shadow_bytes=shadow_bytes,
        shadow_file_offset=shadow_file_offset,
        declared_displacement=shadow.p_vaddr - shadow_start,
        program_header_index=shadow.index,
        replaced_program_header_type=-1,
        relocations=views,
    )


def apply_bytes(
    data: bytes,
    *,
    seed: int | None = None,
    page_size: int = DEFAULT_PAGE_SIZE,
    max_shadow_bytes: int = DEFAULT_MAX_SHADOW_BYTES,
    phdr_index: int | None = None,
) -> tuple[bytes, ShadowReport]:
    original_size = len(data)
    elf = Elf64(data, page_size)
    if not any(phdr.p_type == PT_INTERP for phdr in elf.program_headers):
        raise ShadowError("input must be a dynamically interpreted Linux executable")
    elf.reject_existing_load_overlap()
    tags = elf.dynamic_tags()
    symbols = elf.dynamic_symbols(tags)
    relocations = elf.jmprel_relocations(tags)
    jump_slots = [
        relocation
        for relocation in relocations
        if relocation.relocation_type == R_X86_64_JUMP_SLOT
    ]
    if not jump_slots:
        raise ShadowError("DT_JMPREL contains no R_X86_64_JUMP_SLOT relocations")
    for relocation in jump_slots:
        if relocation.symbol_index == 0 or relocation.symbol_index >= len(symbols):
            raise ShadowError(
                f"relocation {relocation.index} has invalid dynamic-symbol index"
            )

    candidates = eligible_decoy_symbols(symbols)
    if len(candidates) < 2:
        raise ShadowError("at least two function-like dynamic symbols are required")

    table_addr = tags[DT_JMPREL]
    table_size = tags[DT_PLTRELSZ]
    source = elf.load_for_declared_range(table_addr, table_size)
    shadow_start = align_down(table_addr, page_size)
    shadow_end = align_up(table_addr + table_size, page_size)
    source_map_start = align_down(source.p_vaddr, page_size)
    source_map_end = source_map_start + align_up(
        source.p_filesz + (source.p_vaddr & (page_size - 1)), page_size
    )
    if shadow_start < source_map_start or shadow_end > source_map_end:
        raise ShadowError("DT_JMPREL page span is not wholly file-mapped by its PT_LOAD")
    source_map_file = source.p_offset - (source.p_vaddr & (page_size - 1))
    if source_map_file < 0:
        raise ShadowError("DT_JMPREL source PT_LOAD has invalid page/file congruence")
    source_file = source_map_file + shadow_start - source_map_start

    slot = elf.choose_spare_program_header(source.index, phdr_index)
    if slot is None:
        raise ShadowError(
            "no later PT_NULL/PT_NOTE program-header slot is available; relink "
            "with --build-id to reserve a conventional PT_NOTE"
        )
    replaced_type = slot.p_type

    shadow_size = shadow_end - shadow_start
    if shadow_size == 0 or shadow_size > max_shadow_bytes:
        raise ShadowError(
            f"shadow span 0x{shadow_size:x} exceeds --max-shadow-bytes "
            f"0x{max_shadow_bytes:x}"
        )

    append_base = align_up(len(elf.data), page_size)
    seed_material = (
        hashlib.sha256(data).digest()
        if seed is None
        else hashlib.sha256(str(seed).encode("ascii")).digest()
    )
    # Keep the segment-precise declaration beyond every dynamic-tag address in
    # the first replaced page.  The kernel still rounds the mapping down to the
    # page boundary, while tools resolving DT_SYMTAB/DT_STRTAB/DT_JMPREL by
    # virtual address continue to select the conventional segment/file view.
    pointer_floor = max(
        (
            value - shadow_start
            for value in tags.values()
            if shadow_start <= value < shadow_start + page_size
        ),
        default=0,
    )
    displacement_floor = pointer_floor + 1
    displacement_ceiling = page_size - 1
    source_declared_end = source.p_vaddr + source.p_filesz
    if source_declared_end <= shadow_start + page_size:
        displacement_floor = max(
            displacement_floor,
            min(
                source_declared_end - shadow_start,
                displacement_ceiling,
            ),
        )
    else:
        displacement_floor = max(displacement_floor, page_size * 3 // 4)
    displacement_choices = tuple(
        range(displacement_floor, displacement_ceiling + 1)
    )
    if not displacement_choices:
        raise ShadowError(
            "first relocation page leaves no metadata-free declared displacement"
        )
    displacement_hash = hashlib.sha256(seed_material + b"phdr-displacement").digest()
    displacement = displacement_choices[
        int.from_bytes(displacement_hash[:8], "little") % len(displacement_choices)
    ]
    if displacement >= shadow_size:
        raise ShadowError("chosen declared displacement exceeds the shadow span")

    elf.put_program_header(
        slot,
        p_flags=source.p_flags,
        p_offset=append_base + displacement,
        p_vaddr=shadow_start + displacement,
        p_filesz=shadow_size - displacement,
        p_align=page_size,
    )

    shadow = bytearray(shadow_size)
    available = max(0, min(shadow_size, len(elf.data) - source_file))
    if available:
        shadow[:available] = elf.data[source_file : source_file + available]
    # Linux zeroes the trailing p_filesz..p_memsz portion of the last file page.
    # Reproduce that state if the source segment has BSS sharing this page.
    if source.p_memsz > source.p_filesz:
        zero_addr = source.p_vaddr + source.p_filesz
        if shadow_start <= zero_addr < shadow_end:
            shadow[zero_addr - shadow_start :] = b"\0" * (shadow_end - zero_addr)

    decoy_views: list[RelocationView] = []
    used_decoys: set[int] = set()
    for relocation in jump_slots:
        actual = symbols[relocation.symbol_index]
        try:
            decoy = decoy_for_relocation(
                relocation, candidates, seed_material, actual.name, used_decoys
            )
        except ShadowError:
            used_decoys.clear()
            decoy = decoy_for_relocation(
                relocation, candidates, seed_material, actual.name, used_decoys
            )
        used_decoys.add(decoy.index)
        decoy_info = (decoy.index << 32) | relocation.relocation_type
        struct.pack_into("<Q", elf.data, relocation.file_offset + 8, decoy_info)
        decoy_views.append(
            RelocationView(
                relocation.index,
                decoy.index,
                decoy.name,
                actual.index,
                actual.name,
            )
        )

    elf.data.extend(b"\0" * (append_base - len(elf.data)))
    elf.data.extend(shadow)
    output = bytes(elf.data)
    verified = verify_bytes(output, page_size)
    expected = [
        (v.relocation_index, v.static_symbol_index, v.runtime_symbol_index)
        for v in decoy_views
    ]
    observed = [
        (v.relocation_index, v.static_symbol_index, v.runtime_symbol_index)
        for v in verified.relocations
    ]
    if expected != observed:
        raise ShadowError(
            f"internal post-transform verification mismatch: expected {expected}, observed {observed}"
        )
    report = ShadowReport(
        input_size=original_size,
        output_size=len(output),
        page_size=page_size,
        shadow_vaddr=shadow_start,
        shadow_bytes=shadow_size,
        shadow_file_offset=append_base,
        declared_displacement=displacement,
        program_header_index=slot.index,
        replaced_program_header_type=replaced_type,
        relocations=decoy_views,
    )
    return output, report


def atomic_write(path: Path, data: bytes, source_mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, stat.S_IMODE(source_mode))
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def report_dict(report: ShadowReport) -> dict[str, object]:
    return asdict(report)


def print_report(report: ShadowReport, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report_dict(report), sort_keys=True))
        return
    print(
        "elf-shadow: "
        f"relocations={len(report.relocations)} "
        f"phdr={report.program_header_index} "
        f"runtime=0x{report.shadow_vaddr:x}+0x{report.shadow_bytes:x} "
        f"file=0x{report.shadow_file_offset:x} "
        f"growth={report.output_size - report.input_size}"
    )


def parse_int(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return parsed


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Apply or verify Linux/x86-64 ELF relocation shadowing"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    apply_parser = sub.add_parser("apply", help="apply relocation shadowing")
    apply_parser.add_argument("binary", type=Path)
    apply_parser.add_argument("-o", "--output", type=Path)
    apply_parser.add_argument("--seed", type=parse_int)
    apply_parser.add_argument(
        "--page-size",
        type=parse_int,
        default=DEFAULT_PAGE_SIZE,
        help="target loader page size; Linux x86-64 requires 4096",
    )
    apply_parser.add_argument(
        "--max-shadow-bytes", type=parse_int, default=DEFAULT_MAX_SHADOW_BYTES
    )
    apply_parser.add_argument("--phdr-index", type=parse_int)
    apply_parser.add_argument("--dry-run", action="store_true")
    apply_parser.add_argument("--json", action="store_true")

    verify_parser = sub.add_parser("verify", help="verify static/runtime divergence")
    verify_parser.add_argument("binary", type=Path)
    verify_parser.add_argument(
        "--page-size",
        type=parse_int,
        default=DEFAULT_PAGE_SIZE,
        help="target loader page size; Linux x86-64 requires 4096",
    )
    verify_parser.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    try:
        if args.command == "apply":
            source = args.binary
            raw = source.read_bytes()
            output, report = apply_bytes(
                raw,
                seed=args.seed,
                page_size=args.page_size,
                max_shadow_bytes=args.max_shadow_bytes,
                phdr_index=args.phdr_index,
            )
            if not args.dry_run:
                destination = args.output or source
                atomic_write(destination, output, source.stat().st_mode)
            print_report(report, args.json)
            return 0
        report = verify_bytes(args.binary.read_bytes(), args.page_size)
        print_report(report, args.json)
        return 0
    except (OSError, ShadowError) as exc:
        print(f"elf-shadow: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
