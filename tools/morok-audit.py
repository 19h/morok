#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# Fail-closed release audit for post-link Morok artifacts.

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests" / "e2e"))

import adversarial_binary as adv  # noqa: E402


UNSEALED_CODE_SIZE = 0xFFFFFFFF
PROVENANCE_VERSION = 1

PRIVATE_KEY_NAMES = {
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "zorya.sk",
}
PRIVATE_KEY_SUFFIXES = {
    ".pem",
    ".key",
    ".p8",
    ".p12",
    ".pfx",
    ".sk",
}
PRIVATE_KEY_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
)
DEV_PATH_MARKERS = (
    b"/Users/",
    b"/home/",
    b"C:\\Users\\",
    b"\\Users\\",
)
HIGH_VALUE_MARKERS = (
    b"zorya.sk",
    b"MorokAbsentExportCanary",
    b"placeholder_ciphertext",
    b"PLACEHOLDER_CIPHERTEXT",
    b"UNSEALED_MANIFEST",
)
OUTPUT_LABEL_MARKERS = (
    b"Password:",
    b"Act Key:",
    b"Hash:",
)
PLAINTEXT_SENTINEL_MARKERS = (
    b"MOROK_MAGIC",
    b"MOROK_SENTINEL",
    b"MOROK_SEALED_MAGIC",
    b"MOROK_SEALED_SENTINEL",
    b"SEALED_BLOB_MAGIC",
    b"SEALED_BLOB_SENTINEL",
    b"placeholder_magic",
    b"PLACEHOLDER_MAGIC",
)
FAT_MACHO_MAGICS = {
    b"\xca\xfe\xba\xbe",  # FAT_MAGIC
    b"\xbe\xba\xfe\xca",  # FAT_CIGAM
    b"\xca\xfe\xba\xbf",  # FAT_MAGIC_64
    b"\xbf\xba\xfe\xca",  # FAT_CIGAM_64
}
THIN_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",  # MH_MAGIC
    b"\xce\xfa\xed\xfe",  # MH_CIGAM
    b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64 (big-endian byte order)
    b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64 / parser-supported little-endian form
}


@dataclass
class Finding:
    check: str
    path: str
    detail: str


@dataclass
class BinaryReport:
    path: str
    kind: str
    arch: str
    manifests: int
    sealed_manifests: int


class Allowlist:
    def __init__(self, path: Path | None):
        self.entries: list[dict[str, object]] = []
        if path is None:
            return
        raw = json.loads(path.read_text())
        if raw.get("version") != 1:
            raise SystemExit(f"unsupported audit allowlist version: {path}")
        entries = raw.get("allow", [])
        if not isinstance(entries, list):
            raise SystemExit(f"allowlist 'allow' must be a list: {path}")
        self.entries = entries

    def permits(self, rel: str, check: str) -> bool:
        for entry in self.entries:
            pattern = entry.get("path")
            checks = entry.get("checks", [])
            if not isinstance(pattern, str):
                continue
            if not fnmatch.fnmatch(rel, pattern):
                continue
            if checks == "*" or check == "*":
                return True
            if isinstance(checks, list) and (check in checks or "*" in checks):
                return True
        return False


class Auditor:
    def __init__(
        self,
        root: Path,
        *,
        release: bool,
        require_sealed_manifest: bool,
        require_native_pack: bool,
        native_pack_tool: Path | None,
        allowlist: Allowlist,
        provenance_path: Path | None,
        include_paths: list[Path],
    ):
        self.root = root.resolve()
        self.release = release
        self.require_sealed_manifest = require_sealed_manifest
        self.require_native_pack = require_native_pack
        self.native_pack_tool = native_pack_tool.resolve() if native_pack_tool else None
        self.allowlist = allowlist
        self.provenance_path = provenance_path.resolve() if provenance_path else None
        self.include_paths = [path.resolve() for path in include_paths]
        self.findings: list[Finding] = []
        self.allowed_findings: list[Finding] = []
        self.files: list[dict[str, object]] = []
        self.binaries: list[BinaryReport] = []

    def rel(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.root).as_posix()
        except ValueError:
            return path.name

    def emit_finding(self, check: str, path: Path | str, detail: str) -> None:
        rel = path if isinstance(path, str) else self.rel(path)
        finding = Finding(check, rel, detail)
        if self.allowlist.permits(rel, check):
            self.allowed_findings.append(finding)
            return
        self.findings.append(finding)

    def paths(self) -> list[Path]:
        if self.include_paths:
            out: list[Path] = []
            seen: set[Path] = set()
            for path in self.include_paths:
                try:
                    path.relative_to(self.root)
                except ValueError:
                    self.emit_finding(
                        "invalid-audit-include",
                        path,
                        f"included path resolves outside audit root {self.root}",
                    )
                    continue
                if not path.is_file():
                    self.emit_finding(
                        "invalid-audit-include",
                        path,
                        "included path does not exist or is not a file",
                    )
                    continue
                if self.provenance_path and path == self.provenance_path:
                    self.emit_finding(
                        "invalid-audit-include",
                        path,
                        "provenance output cannot be an audited input",
                    )
                    continue
                if path not in seen:
                    seen.add(path)
                    out.append(path)
            return sorted(out)
        if self.root.is_file():
            return [self.root]
        out: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            if self.provenance_path and path.resolve() == self.provenance_path:
                continue
            out.append(path)
        return out

    def read_bytes(self, path: Path) -> bytes:
        try:
            return path.read_bytes()
        except OSError as exc:
            self.emit_finding("read-error", path, str(exc))
            return b""

    def hash_file(self, path: Path, data: bytes) -> None:
        self.files.append(
            {
                "path": self.rel(path),
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )

    def audit_sidecar_name(self, path: Path) -> None:
        name = path.name
        lower = name.lower()
        if name.endswith(".pub"):
            return
        if lower in PRIVATE_KEY_NAMES or path.suffix.lower() in PRIVATE_KEY_SUFFIXES:
            self.emit_finding(
                "private-key-sidecar",
                path,
                "release bundle contains private-key-like sidecar filename",
            )

    def audit_content_markers(self, path: Path, data: bytes) -> None:
        for marker in PRIVATE_KEY_MARKERS:
            if marker in data:
                self.emit_finding(
                    "private-key-content",
                    path,
                    "release bundle contains PEM/OpenSSH private key material",
                )
                break
        for marker in DEV_PATH_MARKERS:
            if marker in data:
                self.emit_finding(
                    "embedded-dev-path",
                    path,
                    f"release artifact contains development path marker {marker!r}",
                )
                break
        for marker in HIGH_VALUE_MARKERS:
            if marker in data:
                self.emit_finding(
                    "plaintext-high-value-marker",
                    path,
                    f"release artifact contains plaintext marker {marker!r}",
                )
                break
        for marker in OUTPUT_LABEL_MARKERS:
            if marker in data:
                self.emit_finding(
                    "plaintext-output-label",
                    path,
                    f"release artifact contains plaintext output label {marker!r}",
                )
                break
        for marker in PLAINTEXT_SENTINEL_MARKERS:
            if marker in data:
                self.emit_finding(
                    "plaintext-sentinel-marker",
                    path,
                    f"release artifact contains plaintext sentinel {marker!r}",
                )
                break

    def elf_section_names(self, data: bytes) -> list[str]:
        if not data.startswith(b"\x7fELF") or len(data) < 64:
            return []
        if data[4] != 2 or data[5] != 1:
            return []
        try:
            e_shoff = struct.unpack_from("<Q", data, 40)[0]
            e_shentsize = struct.unpack_from("<H", data, 58)[0]
            e_shnum = struct.unpack_from("<H", data, 60)[0]
            e_shstrndx = struct.unpack_from("<H", data, 62)[0]
        except struct.error:
            return []
        if e_shoff == 0 or e_shentsize == 0 or e_shnum == 0 or e_shstrndx >= e_shnum:
            return []
        shstr = e_shoff + e_shstrndx * e_shentsize
        try:
            shstr_off = struct.unpack_from("<Q", data, shstr + 24)[0]
            shstr_size = struct.unpack_from("<Q", data, shstr + 32)[0]
        except struct.error:
            return []
        if shstr_off + shstr_size > len(data):
            return []
        names = bytes(data[shstr_off : shstr_off + shstr_size])
        out: list[str] = []
        for i in range(e_shnum):
            sec = e_shoff + i * e_shentsize
            try:
                name_off = struct.unpack_from("<I", data, sec)[0]
            except struct.error:
                continue
            if name_off >= len(names):
                continue
            end = names.find(b"\0", name_off)
            if end < 0:
                end = len(names)
            out.append(names[name_off:end].decode("utf-8", "replace"))
        return out

    def audit_debug_symbols(self, path: Path, data: bytes, binary: adv.Binary) -> None:
        names = self.elf_section_names(data) if binary.kind == "elf" else []
        if binary.kind == "macho":
            names = [section.sectname for section in binary.sections]
        debug_names = [
            name
            for name in names
            if name == ".symtab"
            or name.startswith(".debug")
            or name.startswith("__debug")
            or name in {"__DWARF"}
        ]
        if debug_names:
            self.emit_finding(
                "debug-symbols",
                path,
                "release binary retains debug/private symbol sections: "
                + ", ".join(debug_names[:8]),
            )

    def read_u32_at_addr(self, binary: adv.Binary, addr: int) -> int | None:
        off = binary.fileoff_for_addr(addr)
        if off is None or off + 4 > len(binary.data):
            return None
        return binary.u32(off)

    def read_u64_at_addr(self, binary: adv.Binary, addr: int) -> int | None:
        off = binary.fileoff_for_addr(addr)
        if off is None or off + 8 > len(binary.data):
            return None
        return binary.u64(off)

    def is_macho_signature_valid(self, path: Path, binary: adv.Binary) -> bool:
        if binary.kind != "macho" or platform.system() != "Darwin":
            return True
        codesign = shutil.which("codesign")
        if not codesign:
            self.emit_finding(
                "signature-check-unavailable",
                path,
                "codesign is unavailable for Mach-O release audit",
            )
            return False
        result = subprocess.run(
            [codesign, "--verify", "--strict", str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode == 0:
            return True
        self.emit_finding(
            "invalid-macho-signature",
            path,
            result.stderr.strip() or "codesign --verify failed",
        )
        return False

    def audit_sc_manifest(self, path: Path, binary: adv.Binary, manifest: adv.Manifest) -> bool:
        sealed = True
        if manifest.seed != 0 or manifest.expected_hash != 0:
            self.emit_finding(
                "unsealed-manifest",
                path,
                f"self-check manifest file+0x{manifest.offset:x} retains seal seed/hash",
            )
            sealed = False
        code_size = self.read_u32_at_addr(binary, manifest.code_size)
        expected = self.read_u64_at_addr(binary, manifest.expected)
        if code_size in (None, 0, UNSEALED_CODE_SIZE):
            self.emit_finding(
                "placeholder-manifest",
                path,
                f"self-check manifest file+0x{manifest.offset:x} has unsealed code size",
            )
            sealed = False
        if expected in (None, 0):
            self.emit_finding(
                "placeholder-manifest",
                path,
                f"self-check manifest file+0x{manifest.offset:x} has zero expected hash",
            )
            sealed = False
        return sealed

    def audit_mg_node(
        self, path: Path, binary: adv.Binary, manifest: adv.MgManifest, node: adv.MgNodeManifest
    ) -> bool:
        sealed = True
        if manifest.version != 3:
            self.emit_finding(
                "legacy-mutual-guard-manifest",
                path,
                f"mutual-guard manifest file+0x{manifest.offset:x} is not native-sealed v3",
            )
            return False
        if node.seed != 0 or node.expected_hash != 0:
            self.emit_finding(
                "unsealed-manifest",
                path,
                f"mutual-guard manifest file+0x{manifest.offset:x} node {node.index} "
                "retains seal seed/hash",
            )
            sealed = False
        code_size = self.read_u32_at_addr(binary, node.code_size)
        native_expected = self.read_u64_at_addr(binary, node.native_expected)
        if code_size in (None, 0, UNSEALED_CODE_SIZE):
            self.emit_finding(
                "placeholder-manifest",
                path,
                f"mutual-guard manifest file+0x{manifest.offset:x} node {node.index} "
                "has unsealed code size",
            )
            sealed = False
        if native_expected in (None, 0):
            self.emit_finding(
                "placeholder-manifest",
                path,
                f"mutual-guard manifest file+0x{manifest.offset:x} node {node.index} "
                "has zero native expected hash",
            )
            sealed = False
        return sealed

    def audit_ckd_node(
        self,
        path: Path,
        binary: adv.Binary,
        manifest: adv.CkdManifest,
        node: adv.CkdNodeManifest,
    ) -> bool:
        sealed = True
        if manifest.version != 2:
            self.emit_finding(
                "legacy-ckd-manifest",
                path,
                f"caller-keyed-dispatch manifest file+0x{manifest.offset:x} "
                "is not seal-state v2",
            )
            sealed = False
        if (
            node.salt != 0
            or node.mul != 0
            or node.add != 0
            or node.seal_salt != 0
            or node.rot != 0
            or node.region_bytes != 0
        ):
            self.emit_finding(
                "unsealed-manifest",
                path,
                f"caller-keyed-dispatch manifest file+0x{manifest.offset:x} node {node.index} "
                "retains dispatch/hash oracle data",
            )
            sealed = False
        code_size = self.read_u32_at_addr(binary, node.code_size)
        encoded = self.read_u64_at_addr(binary, node.encoded)
        seal_state = self.read_u64_at_addr(binary, node.seal_state)
        if code_size in (None, 0, UNSEALED_CODE_SIZE):
            self.emit_finding(
                "placeholder-manifest",
                path,
                f"caller-keyed-dispatch manifest file+0x{manifest.offset:x} node {node.index} "
                "has unsealed code size",
            )
            sealed = False
        if encoded in (None, 0):
            self.emit_finding(
                "placeholder-manifest",
                path,
                f"caller-keyed-dispatch manifest file+0x{manifest.offset:x} node {node.index} "
                "has unsealed encoded target",
            )
            sealed = False
        if seal_state in (None, 0):
            self.emit_finding(
                "placeholder-manifest",
                path,
                f"caller-keyed-dispatch manifest file+0x{manifest.offset:x} node {node.index} "
                "has unsealed seal state",
            )
            sealed = False
        return sealed

    def unsupported_binary_finding(self, data: bytes) -> tuple[str, str] | None:
        if data.startswith(b"MZ"):
            return (
                "unsupported-pe-audit",
                "PE release audit is not implemented yet for sealed-manifest verification",
            )
        if data[:4] in FAT_MACHO_MAGICS:
            return (
                "unsupported-fat-macho-audit",
                "fat Mach-O release audit must verify every architecture slice",
            )
        if data.startswith(b"\x7fELF"):
            return (
                "unsupported-elf-audit",
                "ELF release audit parser does not support this ELF class or byte order",
            )
        if data[:4] in THIN_MACHO_MAGICS:
            return (
                "unsupported-macho-audit",
                "Mach-O release audit parser does not support this Mach-O variant",
            )
        return None

    def audit_binary(self, path: Path) -> None:
        data = self.read_bytes(path)
        try:
            binary = adv.Binary(path)
        except SystemExit:
            if self.require_sealed_manifest:
                finding = self.unsupported_binary_finding(data)
                if finding:
                    check, detail = finding
                    self.emit_finding(check, path, detail)
            return
        except Exception as exc:
            self.emit_finding("binary-parse-error", path, str(exc))
            return

        if self.release:
            self.audit_debug_symbols(path, data, binary)
        sealed = 0
        total = 0
        for manifest in binary.find_sc_manifests():
            total += 1
            if self.audit_sc_manifest(path, binary, manifest):
                sealed += 1
        for manifest in binary.find_mg_manifests():
            for node in manifest.nodes:
                total += 1
                if self.audit_mg_node(path, binary, manifest, node):
                    sealed += 1
        for manifest in binary.find_ckd_manifests(require_patchable=False):
            for node in manifest.nodes:
                total += 1
                if self.audit_ckd_node(path, binary, manifest, node):
                    sealed += 1

        self.is_macho_signature_valid(path, binary)
        if self.require_native_pack:
            if binary.kind != "elf":
                self.emit_finding(
                    "missing-native-pack",
                    path,
                    "native-code packing is supported only for Linux ELF64 artifacts",
                )
            elif (
                self.native_pack_tool is None
                or not self.native_pack_tool.is_file()
                or not os.access(self.native_pack_tool, os.X_OK)
            ):
                self.emit_finding(
                    "native-pack-verifier-unavailable",
                    path,
                    "native-pack finalizer/verifier executable is unavailable",
                )
            else:
                try:
                    result = subprocess.run(
                        [str(self.native_pack_tool), "verify", str(path)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=30,
                    )
                except (OSError, subprocess.TimeoutExpired) as exc:
                    self.emit_finding(
                        "native-pack-verifier-unavailable", path, str(exc)
                    )
                    result = None
                if result is not None and result.returncode != 0:
                    self.emit_finding(
                        "missing-native-pack",
                        path,
                        result.stderr.strip() or "native-pack verification failed",
                    )
        self.binaries.append(
            BinaryReport(self.rel(path), binary.kind, binary.arch, total, sealed)
        )
        if self.require_sealed_manifest and total == 0:
            self.emit_finding(
                "missing-sealed-manifest",
                path,
                "release binary contains no recognized post-link seal manifests",
            )
        elif self.require_sealed_manifest and sealed == 0:
            self.emit_finding(
                "missing-sealed-manifest",
                path,
                "release binary contains manifests but none are sealed",
            )

    def run(self) -> int:
        for path in self.paths():
            data = self.read_bytes(path)
            self.hash_file(path, data)
            if self.release:
                self.audit_sidecar_name(path)
                self.audit_content_markers(path, data)
            self.audit_binary(path)

        if (self.require_sealed_manifest or self.require_native_pack) and not self.binaries:
            self.emit_finding(
                "missing-release-binary",
                ".",
                "release audit found no ELF/Mach-O/PE artifacts",
            )
        self.write_provenance()
        for finding in self.findings:
            print(f"FAIL {finding.check} {finding.path}: {finding.detail}", file=sys.stderr)
        if self.findings:
            return 1
        print(
            "OK morok-audit "
            f"files={len(self.files)} binaries={len(self.binaries)} "
            f"sealed_manifests={sum(b.sealed_manifests for b in self.binaries)}"
        )
        return 0

    def write_provenance(self) -> None:
        if self.provenance_path is None:
            return
        payload = {
            "version": PROVENANCE_VERSION,
            "root": str(self.root),
            "release": self.release,
            "require_sealed_manifest": self.require_sealed_manifest,
            "require_native_pack": self.require_native_pack,
            "includes": [self.rel(path) for path in self.include_paths],
            "files": self.files,
            "binaries": [asdict(b) for b in self.binaries],
            "findings": [asdict(f) for f in self.findings],
            "allowed_findings": [asdict(f) for f in self.allowed_findings],
        }
        self.provenance_path.parent.mkdir(parents=True, exist_ok=True)
        self.provenance_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Audit final Morok release artifacts")
    parser.add_argument("path", type=Path, help="release binary or bundle directory")
    parser.add_argument("--release", action="store_true", help="enable fail-closed release hygiene checks")
    parser.add_argument(
        "--require-sealed-manifest",
        action="store_true",
        help="require every recognized release binary to contain at least one sealed manifest",
    )
    parser.add_argument(
        "--require-native-pack",
        action="store_true",
        help="require every recognized release binary to pass native-pack verification",
    )
    parser.add_argument(
        "--native-pack-tool",
        type=Path,
        help="path to the morok-native-pack finalizer/verifier",
    )
    parser.add_argument("--allowlist", type=Path, help="versioned JSON allowlist")
    parser.add_argument("--provenance", type=Path, help="write JSON provenance manifest")
    parser.add_argument(
        "--include",
        action="append",
        type=Path,
        default=[],
        help="audit only this file beneath PATH; repeatable",
    )
    args = parser.parse_args(argv)

    allowlist = Allowlist(args.allowlist)
    auditor = Auditor(
        args.path,
        release=args.release,
        require_sealed_manifest=args.require_sealed_manifest,
        require_native_pack=args.require_native_pack,
        native_pack_tool=args.native_pack_tool,
        allowlist=allowlist,
        provenance_path=args.provenance,
        include_paths=args.include,
    )
    return auditor.run()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
