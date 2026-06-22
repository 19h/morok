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
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple


NEEDLES = [
    b"TRACE_RUNTIME_PLAINTEXT_761",
    b"%s@%s$%s&%s",
    b"%s$%s&%s",
    b"%s::%s:%s",
    b"%s::%s",
    b"%s:%ld:%u:%x",
    b"pid=%d ",
    b"Act Key: %s\n",
    b"audit=%u:%d:%d:%d:%d:%d:%u\n",
    b"MID-77",
    b"EXP-2030",
    b"NUM-6A",
    b"ACT-XYZ",
    b"BODY-TRACE",
]

FORBIDDEN_IMPORTS = [
    "printf",
    "fprintf",
    "sprintf",
    "snprintf",
    "sscanf",
]

NO_BUILTIN_FLAGS = [
    "-fno-builtin-printf",
    "-fno-builtin-fprintf",
    "-fno-builtin-sprintf",
    "-fno-builtin-snprintf",
    "-fno-builtin-sscanf",
]

HOOK_SOURCE = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#endif

#ifdef printf
#undef printf
#endif
#ifdef fprintf
#undef fprintf
#endif
#ifdef sprintf
#undef sprintf
#endif
#ifdef snprintf
#undef snprintf
#endif
#ifdef sscanf
#undef sscanf
#endif

static unsigned long long c_printf;
static unsigned long long c_fprintf;
static unsigned long long c_sprintf;
static unsigned long long c_snprintf;
static unsigned long long c_sscanf;

#if defined(__APPLE__)
#define HOOKED(name) hook_##name
#define DYLD_INTERPOSE(replacement, replacee)                                \
    __attribute__((used)) static struct {                                    \
        const void *replacement;                                             \
        const void *replacee;                                                \
    } _interpose_##replacee __attribute__((section("__DATA,__interpose"))) = \
        { (const void *)(unsigned long)&replacement,                         \
          (const void *)(unsigned long)&replacee }
#else
#define HOOKED(name) name
#endif

static int from_target_addr(void *ra) {
    const char *target = getenv("BOUNDARY_TARGET_PATH");
    if (!target || !*target)
        return 1;
    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (!dladdr(ra, &info) || !info.dli_fname)
        return 0;
    return strcmp(info.dli_fname, target) == 0;
}

#define COUNT_IF_TARGET(counter)                         \
    do {                                                 \
        if (from_target_addr(__builtin_return_address(0))) \
            ++(counter);                                 \
    } while (0)

static char *append_str(char *p, const char *s) {
    while (*s)
        *p++ = *s++;
    return p;
}

static char *append_uint(char *p, unsigned long long v) {
    char tmp[32];
    unsigned n = 0;
    do {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    } while (v);
    while (n)
        *p++ = tmp[--n];
    return p;
}

static char *append_line(char *p, const char *name, unsigned long long value) {
    p = append_str(p, name);
    *p++ = '=';
    p = append_uint(p, value);
    *p++ = '\n';
    return p;
}

__attribute__((destructor)) static void boundary_hook_flush(void) {
    const char *path = getenv("BOUNDARY_HOOK_LOG");
    if (!path || !*path)
        return;
    FILE *f = fopen(path, "wb");
    if (!f)
        return;
    char buf[512];
    char *p = buf;
    p = append_line(p, "printf", c_printf);
    p = append_line(p, "fprintf", c_fprintf);
    p = append_line(p, "sprintf", c_sprintf);
    p = append_line(p, "snprintf", c_snprintf);
    p = append_line(p, "sscanf", c_sscanf);
    fwrite(buf, 1, (size_t)(p - buf), f);
    fclose(f);
}

int HOOKED(printf)(const char *fmt, ...) {
    COUNT_IF_TARGET(c_printf);
    va_list ap;
    va_start(ap, fmt);
    int r = vprintf(fmt, ap);
    va_end(ap);
    return r;
}

int HOOKED(fprintf)(FILE *stream, const char *fmt, ...) {
    COUNT_IF_TARGET(c_fprintf);
    va_list ap;
    va_start(ap, fmt);
    int r = vfprintf(stream, fmt, ap);
    va_end(ap);
    return r;
}

int HOOKED(sprintf)(char *dst, const char *fmt, ...) {
    COUNT_IF_TARGET(c_sprintf);
    va_list ap;
    va_start(ap, fmt);
    int r = vsprintf(dst, fmt, ap);
    va_end(ap);
    return r;
}

int HOOKED(snprintf)(char *dst, size_t size, const char *fmt, ...) {
    COUNT_IF_TARGET(c_snprintf);
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(dst, size, fmt, ap);
    va_end(ap);
    return r;
}

int HOOKED(__sprintf_chk)(char *dst, int flag, size_t dst_size, const char *fmt, ...) {
    (void)flag;
    (void)dst_size;
    COUNT_IF_TARGET(c_sprintf);
    va_list ap;
    va_start(ap, fmt);
    int r = vsprintf(dst, fmt, ap);
    va_end(ap);
    return r;
}

int HOOKED(__snprintf_chk)(char *dst, size_t size, int flag, size_t dst_size, const char *fmt, ...) {
    (void)flag;
    (void)dst_size;
    COUNT_IF_TARGET(c_snprintf);
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(dst, size, fmt, ap);
    va_end(ap);
    return r;
}

int HOOKED(sscanf)(const char *input, const char *fmt, ...) {
    COUNT_IF_TARGET(c_sscanf);
    va_list ap;
    va_start(ap, fmt);
    int r = vsscanf(input, fmt, ap);
    va_end(ap);
    return r;
}

#if !defined(__APPLE__)
int __isoc99_sscanf(const char *input, const char *fmt, ...) {
    COUNT_IF_TARGET(c_sscanf);
    va_list ap;
    va_start(ap, fmt);
    int r = vsscanf(input, fmt, ap);
    va_end(ap);
    return r;
}
#endif

#if defined(__APPLE__)
DYLD_INTERPOSE(hook_printf, printf);
DYLD_INTERPOSE(hook_fprintf, fprintf);
DYLD_INTERPOSE(hook_sprintf, sprintf);
DYLD_INTERPOSE(hook_snprintf, snprintf);
DYLD_INTERPOSE(hook___sprintf_chk, __sprintf_chk);
DYLD_INTERPOSE(hook___snprintf_chk, __snprintf_chk);
DYLD_INTERPOSE(hook_sscanf, sscanf);
#endif
"""


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

    cmd = [clang, *sysroot, "-O2", *NO_BUILTIN_FLAGS, source, "-o", str(output)]
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


def compile_hook(clang: str, sdk: str, root: Path) -> Optional[Path]:
    if os.name == "nt":
        return None

    hook_c = root / "boundary_hook.c"
    hook_c.write_text(HOOK_SOURCE)
    out = root / ("boundary_hook.dylib" if sys.platform == "darwin" else "boundary_hook.so")

    sysroot: List[str] = []
    if sdk:
        sysroot = ["-isysroot", sdk]
    elif shutil.which("xcrun"):
        detected = run(["xcrun", "--show-sdk-path"])
        if detected.returncode == 0 and detected.stdout.strip():
            sysroot = ["-isysroot", detected.stdout.strip()]

    mode = "-dynamiclib" if sys.platform == "darwin" else "-shared"
    cmd = [clang, *sysroot, "-O2", "-fPIC", mode, str(hook_c), "-o", str(out)]
    if sys.platform.startswith("linux"):
        cmd.append("-ldl")
    result = run(cmd)
    if result.returncode != 0:
        fail(f"hook compile failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")
    return out


def run_binary(path: Path, *, env: Optional[Dict[str, str]] = None) -> str:
    result = run([str(path)], env=env)
    if result.returncode != 0:
        fail(
            f"{path.name} exited {result.returncode}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result.stdout


def parse_hook_log(path: Path) -> Dict[str, int]:
    if not path.exists():
        fail(f"hook log was not written: {path}")
    counts: Dict[str, int] = {}
    for line in path.read_text().splitlines():
        if "=" not in line:
            continue
        name, value = line.split("=", 1)
        counts[name] = int(value)
    missing = [name for name in FORBIDDEN_IMPORTS if name not in counts]
    if missing:
        fail("hook log missing counters: " + ", ".join(missing))
    return counts


def run_with_boundary_hook(path: Path, hook: Path, root: Path, label: str) -> Tuple[str, Dict[str, int]]:
    log = root / f"{label}.hook"
    env = os.environ.copy()
    env["BOUNDARY_HOOK_LOG"] = str(log)
    env["BOUNDARY_TARGET_PATH"] = str(path.resolve())
    if sys.platform == "darwin":
        env["DYLD_INSERT_LIBRARIES"] = str(hook)
        env["DYLD_FORCE_FLAT_NAMESPACE"] = "1"
    else:
        env["LD_PRELOAD"] = str(hook)
    out = run_binary(path, env=env)
    return out, parse_hook_log(log)


def readable_ranges(pid: int) -> List[Tuple[int, int]]:
    ranges: List[Tuple[int, int]] = []
    with open(f"/proc/{pid}/maps", "r", encoding="utf-8") as maps:
        for line in maps:
            parts = line.split()
            if len(parts) < 2 or "r" not in parts[1]:
                continue
            start_s, end_s = parts[0].split("-", 1)
            start = int(start_s, 16)
            end = int(end_s, 16)
            if end > start:
                ranges.append((start, end))
    return ranges


def process_memory_contains(pid: int, needle: bytes) -> Tuple[bool, int]:
    scanned = 0
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
        for start, end in readable_ranges(pid):
            try:
                mem.seek(start)
                remaining = end - start
                tail = b""
                while remaining:
                    chunk = mem.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    scanned += len(chunk)
                    window = tail + chunk
                    if needle in window:
                        return True, scanned
                    tail = window[-(len(needle) - 1):]
                    remaining -= len(chunk)
            except OSError:
                continue
    return False, scanned


def run_paused_and_scan(path: Path, root: Path, label: str, needle: bytes) -> Tuple[str, bool]:
    if not sys.platform.startswith("linux"):
        return run_binary(path), False

    pause = root / f"{label}.pause"
    env = os.environ.copy()
    env["BOUNDARY_TRACE_PAUSE"] = str(pause)
    proc = subprocess.Popen(
        [str(path)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
    )

    deadline = time.time() + 15.0
    while time.time() < deadline:
        if pause.exists():
            break
        if proc.poll() is not None:
            out, err = proc.communicate()
            fail(
                f"{path.name} exited before pause\n"
                f"stdout:\n{out.decode(errors='replace')}\n"
                f"stderr:\n{err.decode(errors='replace')}"
            )
        time.sleep(0.02)
    else:
        proc.kill()
        out, err = proc.communicate()
        fail(
            f"{path.name} did not reach pause point\n"
            f"stdout:\n{out.decode(errors='replace')}\n"
            f"stderr:\n{err.decode(errors='replace')}"
        )

    try:
        found, scanned = process_memory_contains(proc.pid, needle)
        if scanned == 0:
            fail(f"/proc/{proc.pid}/mem scan read zero bytes")
    finally:
        try:
            pause.unlink()
        except FileNotFoundError:
            pass

    try:
        out, err = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        fail(
            f"{path.name} did not exit after pause release\n"
            f"stdout:\n{out.decode(errors='replace')}\n"
            f"stderr:\n{err.decode(errors='replace')}"
        )
    if proc.returncode != 0:
        fail(
            f"{path.name} exited {proc.returncode} after pause\n"
            f"stdout:\n{out.decode(errors='replace')}\n"
            f"stderr:\n{err.decode(errors='replace')}"
        )
    return out.decode(), found


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
        hook = compile_hook(clang, sdk, root)
        if hook is not None:
            ref_hook_out, ref_counts = run_with_boundary_hook(ref, hook, root, "ref")
            obf_hook_out, obf_counts = run_with_boundary_hook(obf, hook, root, "obf")
            if ref_hook_out != ref_out or obf_hook_out != obf_out:
                fail(
                    "hooked output mismatch\n"
                    f"ref={ref_out!r} ref_hook={ref_hook_out!r}\n"
                    f"obf={obf_out!r} obf_hook={obf_hook_out!r}"
                )
            missing_clean = [
                name for name in FORBIDDEN_IMPORTS if ref_counts.get(name, 0) == 0
            ]
            if missing_clean:
                fail(
                    "reference hook did not observe expected clean boundaries: "
                    + ", ".join(missing_clean)
                    + f"\ncounts={ref_counts}"
                )
            remaining_obf = {
                name: obf_counts.get(name, 0)
                for name in FORBIDDEN_IMPORTS
                if obf_counts.get(name, 0) != 0
            }
            if remaining_obf:
                fail(f"obfuscated binary still crosses hooked boundaries: {remaining_obf}")

        ref_pause_out, ref_found = run_paused_and_scan(
            ref, root, "ref", b"TRACE_RUNTIME_PLAINTEXT_761"
        )
        obf_pause_out, obf_found = run_paused_and_scan(
            obf, root, "obf", b"TRACE_RUNTIME_PLAINTEXT_761"
        )
        if ref_pause_out != ref_out or obf_pause_out != obf_out:
            fail(
                "paused output mismatch\n"
                f"ref={ref_out!r} ref_pause={ref_pause_out!r}\n"
                f"obf={obf_out!r} obf_pause={obf_pause_out!r}"
            )
        if sys.platform.startswith("linux") and not ref_found:
            fail("reference /proc memory scan did not find the plaintext sentinel")
        if obf_found:
            fail("obfuscated /proc memory scan found the plaintext sentinel after scoped use")
        print(f"OK boundary trace audit output={obf_out.strip()}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
