#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Structural and native-runtime regression for ELF relocation shadowing."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


FIXTURE = r"""
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    const char message[] = "elf-shadow-ok\n";
    size_t length = strlen(message);
    if (getpid() <= 0)
        return 3;
    ssize_t written = write(1, message, length);
    return written == (ssize_t)length ? 0 : 4;
}
"""


def load_tool(root: Path):
    path = root / "tools" / "morok_elf_shadow.py"
    spec = importlib.util.spec_from_file_location("morok_elf_shadow", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def find_compiler() -> str | None:
    override = os.environ.get("MOROK_ELF_SHADOW_CC")
    if override:
        return override
    if platform.system() == "Linux" and platform.machine() in ("x86_64", "amd64"):
        return shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    return shutil.which("x86_64-linux-musl-gcc") or shutil.which(
        "x86_64-linux-gnu-gcc"
    )


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: elf_relocation_shadow_test.py SOURCE_ROOT", file=sys.stderr)
        return 2
    root = Path(argv[0]).resolve()
    tool = load_tool(root)
    compiler = find_compiler()
    if compiler is None:
        print("SKIP: no Linux x86-64 C compiler available")
        return 77

    with tempfile.TemporaryDirectory(prefix="morok-elf-shadow-") as tmp:
        work = Path(tmp)
        source = work / "fixture.c"
        binary = work / "fixture"
        source.write_text(FIXTURE)
        run(
            [
                compiler,
                "-O2",
                "-fno-builtin",
                "-Wl,-z,now",
                "-Wl,-z,relro",
                "-Wl,--build-id=sha1",
                str(source),
                "-o",
                str(binary),
            ]
        )
        original = binary.read_bytes()
        original_mode = binary.stat().st_mode

        first, first_report = tool.apply_bytes(original, seed=0xA11CE)
        second, second_report = tool.apply_bytes(original, seed=0xA11CE)
        assert first == second, "fixed-seed transformation is not reproducible"
        assert first_report == second_report
        assert len(first_report.relocations) >= 2
        assert all(
            view.static_symbol_index != view.runtime_symbol_index
            for view in first_report.relocations
        )
        assert all(
            view.static_symbol != view.runtime_symbol
            for view in first_report.relocations
        )
        assert first_report.shadow_bytes <= tool.DEFAULT_MAX_SHADOW_BYTES
        assert first_report.output_size - first_report.input_size < (
            first_report.shadow_bytes + first_report.page_size
        )

        verified = tool.verify_bytes(first)
        assert verified.relocations == first_report.relocations
        assert verified.shadow_vaddr == first_report.shadow_vaddr
        assert verified.shadow_file_offset == first_report.shadow_file_offset

        transformed = work / "fixture-shadowed"
        tool.atomic_write(transformed, first, original_mode)
        assert transformed.stat().st_mode & 0o111, "atomic output lost executable mode"

        before_repeat = hashlib.sha256(first).digest()
        try:
            tool.apply_bytes(first, seed=0xA11CE)
        except tool.ShadowError as exc:
            assert "overlapping" in str(exc)
        else:
            raise AssertionError("repeated transformation was not rejected")
        assert hashlib.sha256(first).digest() == before_repeat

        try:
            tool.apply_bytes(original, max_shadow_bytes=1)
        except tool.ShadowError as exc:
            assert "max-shadow-bytes" in str(exc)
        else:
            raise AssertionError("shadow-size bound was not enforced")

        try:
            tool.apply_bytes(original, page_size=8192)
        except tool.ShadowError as exc:
            assert "4096-byte pages" in str(exc)
        else:
            raise AssertionError("unsupported loader page size was not rejected")

        native_runtime = platform.system() == "Linux" and platform.machine() in (
            "x86_64",
            "amd64",
        )
        if native_runtime:
            clean = run([str(binary)])
            shadowed = run([str(transformed)])
            assert clean.stdout == b"elf-shadow-ok\n"
            assert shadowed.stdout == clean.stdout
            assert shadowed.stderr == clean.stderr
            assert shadowed.returncode == clean.returncode

    print(
        "elf relocation shadow: PASS "
        f"relocations={len(first_report.relocations)} "
        f"native_runtime={int(native_runtime)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
