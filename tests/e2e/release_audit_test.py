#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


BASE = 0x400000
SC_MAGIC = 0xA7D13C5E9000C3B2


def write_synthetic_elf(path: Path, *, sealed: bool, manifest: bool = True) -> None:
    size = 0x800
    data = bytearray(size)
    ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\0" * 9
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        data,
        0,
        ident,
        2,
        62,
        1,
        BASE,
        64,
        0,
        0,
        64,
        56,
        1,
        0,
        0,
        0,
    )
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, BASE, BASE, size, size, 0x1000)
    if manifest:
        manifest_off = 0x200
        region_off = 0x300
        expected_off = 0x340
        code_size_off = 0x348
        target_off = 0x400
        data[region_off : region_off + 16] = b"region-hash-seed"
        data[target_off : target_off + 16] = b"\x55\x48\x89\xe5\x90\x90\x90\xc3" * 2
        struct.pack_into("<Q", data, manifest_off, SC_MAGIC)
        struct.pack_into("<I", data, manifest_off + 8, 2)
        struct.pack_into("<Q", data, manifest_off + 16, BASE + region_off)
        struct.pack_into("<Q", data, manifest_off + 24, BASE + expected_off)
        struct.pack_into("<I", data, manifest_off + 32, 16)
        struct.pack_into("<Q", data, manifest_off + 56, BASE + target_off)
        struct.pack_into("<Q", data, manifest_off + 64, BASE + code_size_off)
        if sealed:
            struct.pack_into("<Q", data, manifest_off + 40, 0)
            struct.pack_into("<Q", data, manifest_off + 48, 0)
            struct.pack_into("<Q", data, expected_off, 0xD134A7F00D551231)
            struct.pack_into("<I", data, code_size_off, 16)
        else:
            struct.pack_into("<Q", data, manifest_off + 40, 0x1111222233334444)
            struct.pack_into("<Q", data, manifest_off + 48, 0x5555666677778888)
            struct.pack_into("<Q", data, expected_off, 0)
            struct.pack_into("<I", data, code_size_off, 0xFFFFFFFF)
    path.write_bytes(data)


def run(tool: Path, bundle: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(tool), str(bundle), "--release", *extra],
        capture_output=True,
        text=True,
    )


def require_ok(result: subprocess.CompletedProcess[str]) -> None:
    if result.returncode != 0:
        raise AssertionError(f"expected success\nstdout={result.stdout}\nstderr={result.stderr}")


def require_fail(result: subprocess.CompletedProcess[str], needle: str) -> None:
    if result.returncode == 0 or needle not in result.stderr:
        raise AssertionError(
            f"expected failure containing {needle!r}\n"
            f"rc={result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}"
        )


def main(argv: list[str]) -> int:
    repo = Path(argv[0]).resolve()
    tool = repo / "tools" / "morok-audit.py"
    with tempfile.TemporaryDirectory(prefix="morok-audit-") as tmp_raw:
        tmp = Path(tmp_raw)

        good = tmp / "good"
        good.mkdir()
        write_synthetic_elf(good / "app", sealed=True)
        provenance = good / "morok-audit.json"
        result = run(
            tool,
            good,
            "--require-sealed-manifest",
            "--provenance",
            str(provenance),
        )
        require_ok(result)
        payload = json.loads(provenance.read_text())
        assert payload["binaries"][0]["sealed_manifests"] == 1
        assert payload["findings"] == []

        unsealed = tmp / "unsealed"
        unsealed.mkdir()
        write_synthetic_elf(unsealed / "app", sealed=False)
        require_fail(
            run(tool, unsealed, "--require-sealed-manifest"),
            "unsealed-manifest",
        )

        missing = tmp / "missing"
        missing.mkdir()
        write_synthetic_elf(missing / "app", sealed=True, manifest=False)
        require_fail(
            run(tool, missing, "--require-sealed-manifest"),
            "missing-sealed-manifest",
        )

        sidecar = tmp / "sidecar"
        sidecar.mkdir()
        write_synthetic_elf(sidecar / "app", sealed=True)
        (sidecar / "zorya.sk").write_text("fixture key material\n")
        require_fail(
            run(tool, sidecar, "--require-sealed-manifest"),
            "private-key-sidecar",
        )
        allowlist = tmp / "audit-allow.json"
        allowlist.write_text(
            json.dumps(
                {
                    "version": 1,
                    "allow": [
                        {
                            "path": "zorya.sk",
                            "checks": ["private-key-sidecar"],
                        }
                    ],
                }
            )
        )
        require_ok(
            run(
                tool,
                sidecar,
                "--require-sealed-manifest",
                "--allowlist",
                str(allowlist),
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
