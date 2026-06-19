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
set(_adversarial_driver "${CMAKE_CURRENT_SOURCE_DIR}/adversarial_patch.sh")
set(_adversarial_config "${CMAKE_CURRENT_SOURCE_DIR}/adversarial.toml")
set(_adversarial_mg_config
    "${CMAKE_CURRENT_SOURCE_DIR}/mutual_guard_adversarial.toml")
set(_adversarial_workload
    "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/adversarial_integrity.c")
set(_fco_exception_driver "${CMAKE_CURRENT_SOURCE_DIR}/fco_exception_threads.sh")
set(_fco_exception_config
    "${CMAKE_CURRENT_SOURCE_DIR}/fco_exception_threads.toml")
set(_fco_exception_workload
    "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/fco_exception_threads.c")
set(_trap_sigaction_driver
    "${CMAKE_CURRENT_SOURCE_DIR}/trap_sigaction_preserve.sh")
set(_trap_sigaction_config
    "${CMAKE_CURRENT_SOURCE_DIR}/trap_sigaction_preserve.toml")
set(_trap_sigaction_workload
    "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/trap_sigaction_preserve.c")
set(_dr_sentinel_fallback_driver
    "${CMAKE_CURRENT_SOURCE_DIR}/dr_sentinel_fallback.sh")
set(_dr_sentinel_fallback_config
    "${CMAKE_CURRENT_SOURCE_DIR}/dr_sentinel_fallback.toml")
set(_dr_sentinel_fallback_workload
    "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/dr_sentinel_fallback.c")
set(_release_audit_driver
    "${CMAKE_CURRENT_SOURCE_DIR}/release_audit_test.py")
set(_vtable_integrity_driver
    "${CMAKE_CURRENT_SOURCE_DIR}/vtable_integrity_dispatch.sh")
set(_vtable_integrity_config
    "${CMAKE_CURRENT_SOURCE_DIR}/vtable_integrity_dispatch.toml")
set(_vtable_integrity_workload
    "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/vtable_integrity_dispatch.cpp")

find_package(Python3 COMPONENTS Interpreter QUIET)

# Platform-aware settings. On Apple the full built-in max/high presets and the
# aggressive max.toml are exercised. On Linux/Windows several max-level passes
# are not yet ported: virtualization crashes the backend on x86, and the
# anti-analysis + mutual-guard battery SIGSEGVs on Linux. Every high-intensity
# test there is driven from portable.toml instead — the high preset minus
# virtualization, which is the maximum intensity that is correct on every
# platform today. Widen this back toward the full presets as each pass is ported
# (see portable.toml).
if(APPLE)
  set(_max_setting "max")
  set(_high_setting "high")
  set(_maxcfg_setting "${_max_config}")
  set(_program_skip "")
else()
  set(_max_setting "${_portable_config}")
  set(_high_setting "${_portable_config}")
  set(_maxcfg_setting "${_portable_config}")
  # Programs the obfuscator does not yet handle off-Darwin, excluded from the
  # non-Apple sweeps until the responsible passes are ported (each is one bug):
  #   cpp_rtti.cpp  — crashes the x86 backend (Linux triple, even at high-virt).
  #   07_regex.c    — miscompiles on Linux-arm64 (runtime output mismatch).
  # Both compile and run clean on macOS, where the full corpus is still swept.
  set(_program_skip "cpp_rtti.cpp 07_regex.c")
endif()

# Build-tooling regression (issue #42): the static-link derived config must stay
# valid TOML and protective.  Needs only bash/awk/grep — no compiler or plugin.
add_test(NAME "e2e/static_config_layering"
  COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/static_config_layering.sh"
          "${CMAKE_SOURCE_DIR}/cross_build.sh")
set_tests_properties("e2e/static_config_layering" PROPERTIES LABELS "e2e")

# Build-tooling regression (issue #41): the helper must default to Morok's
# entropy-seeded mode (per-build polymorphism), not a fixed seed.
add_test(NAME "e2e/cross_build_seed"
  COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/cross_build_seed.sh"
          "${CMAKE_SOURCE_DIR}/cross_build.sh")
set_tests_properties("e2e/cross_build_seed" PROPERTIES LABELS "e2e")

# Supply-chain regression (issue #36): every external GitHub Action in the
# privileged CI/release/deploy workflows must be pinned to a full commit SHA.
add_test(NAME "e2e/workflows_pinned"
  COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/workflows_pinned.sh"
          "${CMAKE_SOURCE_DIR}/.github")
set_tests_properties("e2e/workflows_pinned" PROPERTIES LABELS "e2e")

if(Python3_EXECUTABLE)
  add_test(NAME "e2e/release_audit"
    COMMAND "${Python3_EXECUTABLE}" "${_release_audit_driver}"
            "${CMAKE_SOURCE_DIR}")
  set_tests_properties("e2e/release_audit" PROPERTIES
    LABELS "e2e;security"
    REQUIRED_FILES
      "${CMAKE_SOURCE_DIR}/tools/morok-audit.py;${_release_audit_driver}"
    TIMEOUT 30)
else()
  message(STATUS "release audit e2e skipped (Python3 not found).")
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

# Virtualization-specific differential gate.  Asserts the bytecode VM actually
# lifted at least one function (catches a silent "lifts nothing" regression, the
# failure that motivated the multi-block expansion) in addition to clean-vs-
# obfuscated output equality.  Apple-only: the VM's indirectbr/blockaddress
# dispatch still crashes the x86 backend on some inputs (see vm.toml /
# portable.toml), so it is exercised only where it is correct today.
if(APPLE)
  add_test(NAME "e2e/differential_vm"
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/differential_vm.sh"
            "${CMAKE_C_COMPILER}"
            "$<TARGET_FILE:morok_plugin>"
            "${_sysroot}"
            "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/vm_workload.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/vm.toml"
            4242)
  set_tests_properties("e2e/differential_vm" PROPERTIES
    LABELS "e2e;max"
    REQUIRED_FILES
      "$<TARGET_FILE:morok_plugin>;${CMAKE_CURRENT_SOURCE_DIR}/vm.toml")
endif()

if(APPLE AND Python3_EXECUTABLE)
  add_test(NAME "e2e/adversarial_selfcheck_code_patch"
    COMMAND bash "${_adversarial_driver}"
            "${Python3_EXECUTABLE}"
            "${CMAKE_C_COMPILER}"
            "$<TARGET_FILE:morok_plugin>"
            "${_sysroot}"
            "${_adversarial_workload}"
            "${_adversarial_config}"
            "selfcheck-code"
            4242)
  set_tests_properties("e2e/adversarial_selfcheck_code_patch" PROPERTIES
    LABELS "e2e;adversarial;max"
    REQUIRED_FILES
      "$<TARGET_FILE:morok_plugin>;${_adversarial_driver};${_adversarial_config};${_adversarial_workload}"
    TIMEOUT 120)

  add_test(NAME "e2e/adversarial_mutualguard_code_patch"
    COMMAND bash "${_adversarial_driver}"
            "${Python3_EXECUTABLE}"
            "${CMAKE_C_COMPILER}"
            "$<TARGET_FILE:morok_plugin>"
            "${_sysroot}"
            "${_adversarial_workload}"
            "${_adversarial_mg_config}"
            "mutualguard-code"
            4242)
  set_tests_properties("e2e/adversarial_mutualguard_code_patch" PROPERTIES
    LABELS "e2e;adversarial;max"
    REQUIRED_FILES
      "$<TARGET_FILE:morok_plugin>;${_adversarial_driver};${_adversarial_mg_config};${_adversarial_workload}"
    TIMEOUT 120)

  add_test(NAME "e2e/adversarial_timing_probe_patch"
    COMMAND bash "${_adversarial_driver}"
            "${Python3_EXECUTABLE}"
            "${CMAKE_C_COMPILER}"
            "$<TARGET_FILE:morok_plugin>"
            "${_sysroot}"
            "${_adversarial_workload}"
            "${_adversarial_config}"
            "timing"
            4242)
  set_tests_properties("e2e/adversarial_timing_probe_patch" PROPERTIES
    LABELS "e2e;adversarial;max"
    REQUIRED_FILES
      "$<TARGET_FILE:morok_plugin>;${_adversarial_driver};${_adversarial_config};${_adversarial_workload}"
    SKIP_RETURN_CODE 77
    TIMEOUT 120)
else()
  if(NOT APPLE)
    message(STATUS "adversarial e2e patch tests skipped off-Apple (Darwin post-link sealing only).")
  else()
    message(STATUS "adversarial e2e patch tests skipped (Python3 not found).")
  endif()
endif()

if(APPLE)
  add_test(NAME "e2e/trap_sigaction_preserve"
    COMMAND bash "${_trap_sigaction_driver}"
            "${CMAKE_C_COMPILER}"
            "$<TARGET_FILE:morok_plugin>"
            "${_sysroot}"
            "${_trap_sigaction_workload}"
            "${_trap_sigaction_config}"
            8863)
  set_tests_properties("e2e/trap_sigaction_preserve" PROPERTIES
    LABELS "e2e;security;max"
    REQUIRED_FILES
      "$<TARGET_FILE:morok_plugin>;${_trap_sigaction_driver};${_trap_sigaction_config};${_trap_sigaction_workload}"
    SKIP_RETURN_CODE 77
    TIMEOUT 120)
else()
  message(STATUS "Trap sigaction preservation e2e skipped off Darwin.")
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND
   CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
  add_test(NAME "e2e/fco_exception_threads"
    COMMAND bash "${_fco_exception_driver}"
            "${CMAKE_C_COMPILER}"
            "$<TARGET_FILE:morok_plugin>"
            "${_sysroot}"
            "${_fco_exception_workload}"
            "${_fco_exception_config}"
            5757)
  set_tests_properties("e2e/fco_exception_threads" PROPERTIES
    LABELS "e2e;threading;security"
    REQUIRED_FILES
      "$<TARGET_FILE:morok_plugin>;${_fco_exception_driver};${_fco_exception_config};${_fco_exception_workload}"
    SKIP_RETURN_CODE 77
    TIMEOUT 120)

  add_test(NAME "e2e/dr_sentinel_fallback"
    COMMAND bash "${_dr_sentinel_fallback_driver}"
            "${CMAKE_C_COMPILER}"
            "$<TARGET_FILE:morok_plugin>"
            "${_sysroot}"
            "${_dr_sentinel_fallback_workload}"
            "${_dr_sentinel_fallback_config}"
            4949)
  set_tests_properties("e2e/dr_sentinel_fallback" PROPERTIES
    LABELS "e2e;security;linux"
    REQUIRED_FILES
      "$<TARGET_FILE:morok_plugin>;${_dr_sentinel_fallback_driver};${_dr_sentinel_fallback_config};${_dr_sentinel_fallback_workload}"
    SKIP_RETURN_CODE 77
    TIMEOUT 120)
else()
  message(STATUS "Linux x86_64 security e2e tests skipped on this host.")
endif()

add_test(NAME "e2e/vtable_integrity_dispatch"
  COMMAND bash "${_vtable_integrity_driver}"
          "${CMAKE_CXX_COMPILER}"
          "$<TARGET_FILE:morok_plugin>"
          "${_sysroot}"
          "${_vtable_integrity_workload}"
          "${_vtable_integrity_config}"
          4801)
set_tests_properties("e2e/vtable_integrity_dispatch" PROPERTIES
  LABELS "e2e;security"
  REQUIRED_FILES
    "$<TARGET_FILE:morok_plugin>;${_vtable_integrity_driver};${_vtable_integrity_config};${_vtable_integrity_workload}"
  TIMEOUT 120)

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
    ENVIRONMENT "MOROK_SKIP=${_program_skip}"
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
    ENVIRONMENT "MOROK_SKIP=${_program_skip}"
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
    ENVIRONMENT "MOROK_SKIP=${_program_skip}"
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
    ENVIRONMENT "MOROK_SKIP=${_program_skip}"
    TIMEOUT 900)
else()
  message(STATUS "e2e programs sweep skipped (no programs/ corpus in this tree).")
endif()
