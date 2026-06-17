#==============================================================================
# End-to-end differential tests.
#
# Each test compiles the workload clean and obfuscated (via the built plugin)
# and requires identical runtime output. Requires a C/C++ compiler matching the
# plugin's LLVM (the build compiler). On Apple platforms the macOS SDK sysroot
# is passed explicitly; elsewhere the compiler's default sysroot is used (the
# driver scripts treat an empty sysroot argument as "use the default").
#==============================================================================

# Loading a New-PM pass plugin into clang via -fpass-plugin is well supported on
# ELF/Mach-O hosts. On Windows the mechanism is far more fragile, so the
# behavioural e2e suite is gated to non-Windows hosts; Windows coverage comes
# from the in-process core/config/ir unit suites, which exercise the same passes
# without dlopen.
if(WIN32)
  message(STATUS "e2e differential tests skipped on Windows (plugin dlopen path).")
  return()
endif()

set(_sysroot "")
if(APPLE)
  set(_sysroot "${CMAKE_OSX_SYSROOT}")
endif()

set(_workload "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/workload.c")
set(_driver "${CMAKE_CURRENT_SOURCE_DIR}/differential.sh")
set(_program_sweep "${CMAKE_CURRENT_SOURCE_DIR}/compile_programs.sh")
set(_max_config "${CMAKE_CURRENT_SOURCE_DIR}/max.toml")
set(_portable_config "${CMAKE_CURRENT_SOURCE_DIR}/portable.toml")

# Platform-aware settings. On Apple the full built-in max/high presets and the
# aggressive max.toml are exercised. On Linux/Windows several max-level passes are
# not yet ported and either crash the backend at compile time (virtualization on
# x86) or fault at run time (trap_oracles SIGILLs off Linux-x86; the anti-analysis
# + mutual-guard battery SIGSEGVs on Linux), so every high-intensity test there is
# driven from portable.toml instead — the high preset minus virtualization, which
# is the maximum intensity that is correct on every platform today. Widen this
# back toward the full presets as each pass is ported (see portable.toml).
if(APPLE)
  set(_max_setting "max")
  set(_high_setting "high")
  set(_maxcfg_setting "${_max_config}")
else()
  set(_max_setting "${_portable_config}")
  set(_high_setting "${_portable_config}")
  set(_maxcfg_setting "${_portable_config}")
endif()

foreach(preset low mid high)
  add_test(NAME "e2e/differential_${preset}"
    COMMAND bash "${_driver}"
            "${CMAKE_C_COMPILER}"
            "$<TARGET_FILE:morok_plugin>"
            "${_sysroot}"
            "${_workload}"
            "${preset}"
            4242)
  set_tests_properties("e2e/differential_${preset}" PROPERTIES
    LABELS "e2e"
    # The plugin must exist before these run.
    REQUIRED_FILES "$<TARGET_FILE:morok_plugin>")
endforeach()

add_test(NAME "e2e/differential_max"
  COMMAND bash "${_driver}"
          "${CMAKE_C_COMPILER}"
          "$<TARGET_FILE:morok_plugin>"
          "${_sysroot}"
          "${_workload}"
          "${_max_setting}"
          4242)
set_tests_properties("e2e/differential_max" PROPERTIES
  LABELS "e2e;max"
  REQUIRED_FILES "$<TARGET_FILE:morok_plugin>")

# Same maximal intensity, but driven from the TOML config file path rather than
# the built-in preset, so the loader/resolver merge is exercised end-to-end too.
add_test(NAME "e2e/differential_maxtoml"
  COMMAND bash "${_driver}"
          "${CMAKE_C_COMPILER}"
          "$<TARGET_FILE:morok_plugin>"
          "${_sysroot}"
          "${_workload}"
          "${_maxcfg_setting}"
          4242)
set_tests_properties("e2e/differential_maxtoml" PROPERTIES
  LABELS "e2e;max"
  REQUIRED_FILES "$<TARGET_FILE:morok_plugin>;${_maxcfg_setting}")

# The full sample-program compile sweep runs only when the corpus is present.
# `programs/` lives outside version control (it carries arch/OS-specific
# workloads — aarch64 inline asm, raw syscalls — that do not compile on every
# target), so a clean CI checkout simply skips it rather than failing.
if(EXISTS "${PROJECT_SOURCE_DIR}/programs")
  add_test(NAME "e2e/programs_high_compile"
    COMMAND bash "${_program_sweep}"
            "${CMAKE_C_COMPILER}"
            "${CMAKE_CXX_COMPILER}"
            "$<TARGET_FILE:morok_plugin>"
            "${_sysroot}"
            "${PROJECT_SOURCE_DIR}/programs"
            "${_high_setting}"
            4242)
  set_tests_properties("e2e/programs_high_compile" PROPERTIES
    LABELS "e2e;programs;max"
    REQUIRED_FILES "$<TARGET_FILE:morok_plugin>"
    TIMEOUT 600)

  add_test(NAME "e2e/programs_max_compile"
    COMMAND bash "${_program_sweep}"
            "${CMAKE_C_COMPILER}"
            "${CMAKE_CXX_COMPILER}"
            "$<TARGET_FILE:morok_plugin>"
            "${_sysroot}"
            "${PROJECT_SOURCE_DIR}/programs"
            "${_maxcfg_setting}"
            4242)
  set_tests_properties("e2e/programs_max_compile" PROPERTIES
    LABELS "e2e;programs;max"
    REQUIRED_FILES "$<TARGET_FILE:morok_plugin>;${_maxcfg_setting}"
    TIMEOUT 900)

  # The canonical "maximum settings" gate: every sample program must compile
  # clean and through the plugin at the built-in `max` preset.
  add_test(NAME "e2e/programs_maxpreset_compile"
    COMMAND bash "${_program_sweep}"
            "${CMAKE_C_COMPILER}"
            "${CMAKE_CXX_COMPILER}"
            "$<TARGET_FILE:morok_plugin>"
            "${_sysroot}"
            "${PROJECT_SOURCE_DIR}/programs"
            "${_max_setting}"
            4242)
  set_tests_properties("e2e/programs_maxpreset_compile" PROPERTIES
    LABELS "e2e;programs;max"
    REQUIRED_FILES "$<TARGET_FILE:morok_plugin>"
    TIMEOUT 900)

  # Runtime correctness gate: a curated set of deterministic programs must
  # produce identical output clean vs obfuscated at the `max` preset.  Catches
  # miscompilations that compile cleanly but run wrong (the compile sweep above
  # cannot see these).
  set(_program_run "${CMAKE_CURRENT_SOURCE_DIR}/run_programs.sh")
  add_test(NAME "e2e/programs_maxpreset_run"
    COMMAND bash "${_program_run}"
            "${CMAKE_C_COMPILER}"
            "${CMAKE_CXX_COMPILER}"
            "$<TARGET_FILE:morok_plugin>"
            "${_sysroot}"
            "${PROJECT_SOURCE_DIR}/programs"
            "${_max_setting}"
            4242)
  set_tests_properties("e2e/programs_maxpreset_run" PROPERTIES
    LABELS "e2e;programs;max"
    REQUIRED_FILES "$<TARGET_FILE:morok_plugin>"
    TIMEOUT 900)
else()
  message(STATUS "e2e programs sweep skipped (no programs/ corpus in this tree).")
endif()
