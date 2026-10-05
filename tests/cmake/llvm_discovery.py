#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise LLVM discovery with isolated packages, without building LLVM."""

import pathlib
import subprocess
import sys
import tempfile


def main():
    cmake, root, cc, cxx = sys.argv[1:]
    root = pathlib.Path(root).resolve()
    with tempfile.TemporaryDirectory(prefix="morok-llvm-discovery-") as temporary:
        work = pathlib.Path(temporary)
        harness = work / "harness"
        harness.mkdir()
        (harness / "CMakeLists.txt").write_text(
            'cmake_minimum_required(VERSION 3.28)\n'
            'project(LLVMDiscovery NONE)\n'
            f'include("{root.as_posix()}/cmake/MorokLLVM.cmake")\n'
            'if(NOT "${Morok_LLVM_FOUND}" STREQUAL "${EXPECT_FOUND}")\n'
            '  message(FATAL_ERROR "Unexpected LLVM discovery result")\n'
            'endif()\n'
            'if(Morok_LLVM_FOUND AND NOT TARGET morok::llvm)\n'
            '  message(FATAL_ERROR "Missing LLVM interface target")\n'
            'endif()\n'
            'if(Morok_LLVM_FOUND AND NOT MOROK_PLUGIN_API_VERSION STREQUAL EXPECT_API)\n'
            '  message(FATAL_ERROR "Wrong LLVM plugin API selected")\n'
            'endif()\n'
        )

        def package(name, api, major=24):
            prefix = work / name
            headers = prefix / "include/llvm/Plugins"
            headers.mkdir(parents=True)
            if api is not None:
                (headers / "PassPlugin.h").write_text(
                    f"#define LLVM_PLUGIN_API_VERSION {api}\n"
                )
            config = prefix / "lib/cmake/llvm"
            config.mkdir(parents=True)
            (config / "LLVMConfig.cmake").write_text(
                f'set(LLVM_VERSION_MAJOR {major})\n'
                f'set(LLVM_PACKAGE_VERSION "{major}.0.0-test")\n'
                f'set(LLVM_INCLUDE_DIRS "{prefix.as_posix()}/include")\n'
                'set(LLVM_DEFINITIONS "")\n'
            )
            return config

        packages = {
            "v2": package("v2", 2),
            "v3": package("v3", 3),
            "legacy": package("legacy", 1),
            "future": package("future", 99),
            "missing": package("missing", None),
            "old": package("old", 2, major=17),
        }

        def configure(source, build, extra, success=True, diagnostic=None):
            result = subprocess.run(
                [cmake, "-S", str(source), "-B", str(build), *extra],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                check=False,
            )
            if (result.returncode == 0) != success:
                raise AssertionError(result.stdout)
            if diagnostic and diagnostic not in result.stdout:
                raise AssertionError(result.stdout)

        # Reconfigure one cache across API versions, including a legacy cached
        # find_file result. The new LLVM_DIR must determine header selection.
        for name in ("v2", "v3", "legacy", "future", "missing", "old"):
            configure(harness, work / "discovery", [
                f"-DLLVM_DIR={packages[name]}",
                f"-DEXPECT_FOUND={'TRUE' if name in ('v2', 'v3') else 'FALSE'}",
                f"-DEXPECT_API={2 if name == 'v2' else 3}",
                f"-DMOROK_PASSPLUGIN_HEADER:FILEPATH={work}/v2/include/llvm/Plugins/PassPlugin.h",
            ])

        # A requested plugin must fail at configure time, rather than allowing
        # a pure-layer build whose IR test selection is empty.
        for name in ("legacy", "future", "missing"):
            configure(root, work / f"plugin-{name}", [
                f"-DLLVM_DIR={packages[name]}",
                f"-DCMAKE_C_COMPILER={cc}", f"-DCMAKE_CXX_COMPILER={cxx}",
                "-DMOROK_BUILD_PLUGIN=ON", "-DMOROK_BUILD_TESTS=OFF",
            ], success=False,
                diagnostic="MOROK_BUILD_PLUGIN=ON requires a usable LLVM")

        # Explicit pure-layer builds remain available without a usable LLVM.
        configure(root, work / "pure", [
            f"-DLLVM_DIR={packages['legacy']}",
            f"-DCMAKE_C_COMPILER={cc}", f"-DCMAKE_CXX_COMPILER={cxx}",
            "-DMOROK_BUILD_PLUGIN=OFF", "-DMOROK_BUILD_TESTS=ON",
        ], diagnostic="LLVM not usable for plugin/IR layers")
    print("PASS: LLVM API selection, cache changes, and required-plugin failures")


if __name__ == "__main__":
    main()
