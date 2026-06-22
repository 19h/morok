#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# Binary adversarial audit for the trace techniques that recover plaintext
# strings, printf-family formats, and clean libc formatting/parsing imports.

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional


NEEDLES = [
    b"TRACE_RUNTIME_PLAINTEXT_761",
    b"%s@%s$%s&%s",
    b"%s:%ld:%u:%x",
    b"pid=%d ",
    b"audit=%u:%d:%d:%u\n",
    b"alpha",
    b"gamma",
    b"delta",
]

FORBIDDEN_IMPORTS = [
    "printf",
    "fprintf",
    "sprintf",
    "snprintf",
    "sscanf",
]


def run(cmd: List[str], *, env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def fail(message: str) -> None:
    print(f"FAIL boundary trace audit: {message}", file=sys.stderr)
    sys.exit(1)


def compile_binary(
    clang: str,
    plugin: str,
    sdk: str,
    source: str,
    output: Path,
    *,
    config: Optional[str] = None,
    seed: str = "9091",
) -> None:
    sysroot: List[str] = []
    if sdk:
        sysroot = ["-isysroot", sdk]
    elif shutil.which("xcrun"):
        detected = run(["xcrun", "--show-sdk-path"])
        if detected.returncode == 0 and detected.stdout.strip():
            sysroot = ["-isysroot", detected.stdout.strip()]

    cmd = [clang, *sysroot, "-O2", source, "-o", str(output)]
    env = os.environ.copy()
    if config is not None:
        env.update(
            {
                "MOROK_ENABLE": "1",
                "MOROK_SEED": seed,
                "MOROK_CONFIG": config,
            }
        )
        cmd.insert(-2, f"-fpass-plugin={plugin}")

    result = run(cmd, env=env)
    if result.returncode != 0:
        fail(
            "compile failed for "
            + ("obfuscated" if config is not None else "reference")
            + f"\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


def run_binary(path: Path) -> str:
    result = run([str(path)])
    if result.returncode != 0:
        fail(
            f"{path.name} exited {result.returncode}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result.stdout


def assert_no_plaintext(path: Path) -> None:
    blob = path.read_bytes()
    hits = [needle.decode("utf-8", "replace") for needle in NEEDLES if needle in blob]
    if hits:
        fail("obfuscated binary still contains plaintext needles: " + ", ".join(hits))


def assert_no_forbidden_imports(path: Path) -> None:
    nm = shutil.which("nm")
    if nm is None:
        fail("nm is required for import audit")
    result = run([nm, "-u", str(path)])
    if result.returncode != 0:
        fail(f"nm -u failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")

    for sym in FORBIDDEN_IMPORTS:
        pattern = re.compile(rf"(^|[^A-Za-z0-9])_?{re.escape(sym)}(@|$|[^A-Za-z0-9])")
        if pattern.search(result.stdout):
            fail(f"forbidden clean libc boundary remains imported: {sym}\n{result.stdout}")


def main(argv: List[str]) -> int:
    if len(argv) < 7:
        print(
            "usage: boundary_trace_audit.py <clang> <plugin> <sdk> "
            "<source> <config.toml> <seed>",
            file=sys.stderr,
        )
        return 2

    clang, plugin, sdk, source, config, seed = argv[1:7]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        ref = root / "ref"
        obf = root / "obf"

        compile_binary(clang, plugin, sdk, source, ref)
        compile_binary(clang, plugin, sdk, source, obf, config=config, seed=seed)

        ref_out = run_binary(ref)
        obf_out = run_binary(obf)
        if ref_out != obf_out:
            fail(f"output mismatch\nref={ref_out!r}\nobf={obf_out!r}")

        assert_no_plaintext(obf)
        assert_no_forbidden_imports(obf)
        print(f"OK boundary trace audit output={obf_out.strip()}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
