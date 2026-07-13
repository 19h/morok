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
set(_adversarial_ckd_config
    "${CMAKE_CURRENT_SOURCE_DIR}/caller_keyed_dispatch_adversarial.toml")
set(_adversarial_workload
    "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/adversarial_integrity.c")
set(_adversarial_ckd_workload
    "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/caller_keyed_dispatch.c")
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
set(_timing_false_positive_driver
    "${CMAKE_CURRENT_SOURCE_DIR}/timing_false_positive_clean_run.sh")
set(_timing_false_positive_config
    "${CMAKE_CURRENT_SOURCE_DIR}/timing_false_positive.toml")
set(_timing_false_positive_workload
    "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/timing_false_positive.c")
set(_tracerpid_clean_driver
    "${CMAKE_CURRENT_SOURCE_DIR}/tracerpid_zero_clean.sh")
set(_tracerpid_clean_selftrace_config
    "${CMAKE_CURRENT_SOURCE_DIR}/tracerpid_zero_clean_selftrace.toml")
set(_tracerpid_clean_no_selftrace_config
    "${CMAKE_CURRENT_SOURCE_DIR}/tracerpid_zero_clean_no_selftrace.toml")
set(_tracerpid_clean_workload
    "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/tracerpid_zero_clean.c")
set(_release_audit_driver
    "${CMAKE_CURRENT_SOURCE_DIR}/release_audit_test.py")
set(_boundary_trace_driver
    "${CMAKE_CURRENT_SOURCE_DIR}/boundary_trace_audit.py")
set(_boundary_trace_config
    "${CMAKE_CURRENT_SOURCE_DIR}/boundary_trace.toml")
set(_boundary_trace_workload
    "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/boundary_trace.c")
set(_string_dynamic_escape_config
    "${CMAKE_CURRENT_SOURCE_DIR}/string_dynamic_escape.toml")
set(_string_dynamic_escape_workload
    "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/string_dynamic_escape.c")
set(_vtable_integrity_driver
    "${CMAKE_CURRENT_SOURCE_DIR}/vtable_integrity_dispatch.sh")
set(_vtable_integrity_config
    "${CMAKE_CURRENT_SOURCE_DIR}/vtable_integrity_dispatch.toml")
set(_vtable_integrity_workload
    "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/vtable_integrity_dispatch.cpp")
set(_mirage_config "${CMAKE_CURRENT_SOURCE_DIR}/mirage.toml")
set(_mirage_fake_config "${CMAKE_CURRENT_SOURCE_DIR}/mirage_forced_fake.toml")
set(_mirage_fake_driver "${CMAKE_CURRENT_SOURCE_DIR}/mirage_forced_fake.sh")
set(_mirage_workload "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/mirage_verdict.c")
set(_elf_shadow_driver
    "${CMAKE_CURRENT_SOURCE_DIR}/elf_relocation_shadow_test.py")

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

# Runtime-only exclusions. These programs are still compiled clean and through
# the plugin by the full corpus compile sweeps, but are not safe as generic
# no-stdin runtime oracles at max obfuscation today:
#   asm_context_switch.c — deliberate user-space stack switching; max-obfuscated
#     Darwin arm64 binary currently SIGSEGVs before producing an oracle.
#   syscall_signals.c — deliberate process signal choreography; max-obfuscated
#     Darwin arm64 binary currently hangs in the runtime probe.
set(_program_run_skip "asm_context_switch.c syscall_signals.c")

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

# Build-tooling regression: Linux hosts must default to Linux-only builds and the
# ELF plugin suffix; Darwin hosts keep the existing Linux+macOS default.
add_test(NAME "e2e/cross_build_platform_defaults"
  COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/cross_build_platform_defaults.sh"
          "${CMAKE_SOURCE_DIR}/cross_build.sh")
set_tests_properties("e2e/cross_build_platform_defaults" PROPERTIES
  LABELS "e2e")

# Build-tooling regression: an empty Linux -print-sysroot is valid for some
# GCC-compatible drivers and must not block the compile step.
add_test(NAME "e2e/cross_build_empty_sysroot"
  COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/cross_build_empty_sysroot.sh"
          "${CMAKE_SOURCE_DIR}/cross_build.sh")
set_tests_properties("e2e/cross_build_empty_sysroot" PROPERTIES
  LABELS "e2e")

# Build-tooling regression (issue #116): --clean must be constrained to a
# canonical build-dir descendant and refuse destructive OUT_DIR values.
add_test(NAME "e2e/cross_build_clean"
  COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/cross_build_clean.sh"
          "${CMAKE_SOURCE_DIR}/cross_build.sh")
set_tests_properties("e2e/cross_build_clean" PROPERTIES LABELS "e2e;security")

# Supply-chain regression (issue #36): every external GitHub Action in the
# privileged CI/release/deploy workflows must be pinned to a full commit SHA.
add_test(NAME "e2e/workflows_pinned"
  COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/workflows_pinned.sh"
          "${CMAKE_SOURCE_DIR}/.github")
set_tests_properties("e2e/workflows_pinned" PROPERTIES LABELS "e2e")

if(Python3_EXECUTABLE)
  add_test(NAME "e2e/elf_relocation_shadow"
    COMMAND "${Python3_EXECUTABLE}" "${_elf_shadow_driver}"
            "${CMAKE_SOURCE_DIR}")
  set_tests_properties("e2e/elf_relocation_shadow" PROPERTIES
    LABELS "e2e;security;linux"
    REQUIRED_FILES
      "${CMAKE_SOURCE_DIR}/tools/morok_elf_shadow.py;${_elf_shadow_driver}"
    SKIP_RETURN_CODE 77
    TIMEOUT 30)

  add_test(NAME "e2e/release_audit"
    COMMAND "${Python3_EXECUTABLE}" "${_release_audit_driver}"
            "${CMAKE_SOURCE_DIR}")
  set_tests_properties("e2e/release_audit" PROPERTIES
    LABELS "e2e;security"
    REQUIRED_FILES
      "${CMAKE_SOURCE_DIR}/tools/morok-audit.py;${_release_audit_driver}"
    TIMEOUT 30)

  add_test(NAME "e2e/boundary_trace_audit"
    COMMAND "${Python3_EXECUTABLE}" "${_boundary_trace_driver}"
            "${CMAKE_C_COMPILER}"
            "$<TARGET_FILE:morok_plugin>"
            "${_sysroot}"
            "${_boundary_trace_workload}"
            "${_boundary_trace_config}"
            9091)
  set_tests_properties("e2e/boundary_trace_audit" PROPERTIES
    LABELS "e2e;security;adversarial"
    REQUIRED_FILES
      "$<TARGET_FILE:morok_plugin>;${_boundary_trace_driver};${_boundary_trace_config};${_boundary_trace_workload}"
    TIMEOUT 120)
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

add_test(NAME "e2e/string_dynamic_escape"
  COMMAND bash "${_driver}"
          "${CMAKE_C_COMPILER}"
          "$<TARGET_FILE:morok_plugin>"
          "${_sysroot}"
          "${_string_dynamic_escape_workload}"
          "${_string_dynamic_escape_config}"
          6114)
set_tests_properties("e2e/string_dynamic_escape" PROPERTIES
  LABELS "e2e;security"
  REQUIRED_FILES
    "$<TARGET_FILE:morok_plugin>;${_string_dynamic_escape_config};${_string_dynamic_escape_workload}"
  TIMEOUT 120)

add_test(NAME "e2e/tracerpid_zero_clean"
  COMMAND bash "${_tracerpid_clean_driver}"
          "${CMAKE_C_COMPILER}"
          "$<TARGET_FILE:morok_plugin>"
          "${_sysroot}"
          "${_tracerpid_clean_workload}"
          "${_tracerpid_clean_selftrace_config}"
          "${_tracerpid_clean_no_selftrace_config}"
          1720)
set_tests_properties("e2e/tracerpid_zero_clean" PROPERTIES
  LABELS "e2e;security"
  REQUIRED_FILES
    "$<TARGET_FILE:morok_plugin>;${_tracerpid_clean_driver};${_tracerpid_clean_selftrace_config};${_tracerpid_clean_no_selftrace_config};${_tracerpid_clean_workload}"
  SKIP_RETURN_CODE 77
  TIMEOUT 120)

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

  # Regression for #107: default release sealing must cover the requested
  # code window, not just the small self-check random-data region. The patch
  # mutates neutral padding beyond region_size so only the sealed code hash
  # should make the patched binary diverge.
  add_test(NAME "e2e/adversarial_selfcheck_far_code_patch"
    COMMAND bash "${_adversarial_driver}"
            "${Python3_EXECUTABLE}"
            "${CMAKE_C_COMPILER}"
            "$<TARGET_FILE:morok_plugin>"
            "${_sysroot}"
            "${_adversarial_workload}"
            "${_adversarial_config}"
            "selfcheck-code-far"
            4242)
  set_tests_properties("e2e/adversarial_selfcheck_far_code_patch" PROPERTIES
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

  add_test(NAME "e2e/adversarial_ckd_code_patch"
    COMMAND bash "${_adversarial_driver}"
            "${Python3_EXECUTABLE}"
            "${CMAKE_C_COMPILER}"
            "$<TARGET_FILE:morok_plugin>"
            "${_sysroot}"
            "${_adversarial_ckd_workload}"
            "${_adversarial_ckd_config}"
            "ckd-code"
            4242)
  set_tests_properties("e2e/adversarial_ckd_code_patch" PROPERTIES
    LABELS "e2e;adversarial;max"
    REQUIRED_FILES
      "$<TARGET_FILE:morok_plugin>;${_adversarial_driver};${_adversarial_ckd_config};${_adversarial_ckd_workload}"
    TIMEOUT 120)

  # Regression for #21: downgrade attack — reset the mutable code_size seal slot
  # to the unsealed sentinel.  In sealed-release mode (seal_required) the startup
  # constructor must poison the encoded target instead of re-sealing from live
  # bytes, so the downgraded binary diverges from the sealed baseline.
  add_test(NAME "e2e/adversarial_ckd_downgrade"
    COMMAND bash "${_adversarial_driver}"
            "${Python3_EXECUTABLE}"
            "${CMAKE_C_COMPILER}"
            "$<TARGET_FILE:morok_plugin>"
            "${_sysroot}"
            "${_adversarial_ckd_workload}"
            "${_adversarial_ckd_config}"
            "ckd-downgrade"
            4242)
  set_tests_properties("e2e/adversarial_ckd_downgrade" PROPERTIES
    LABELS "e2e;adversarial;max"
    REQUIRED_FILES
      "$<TARGET_FILE:morok_plugin>;${_adversarial_driver};${_adversarial_ckd_config};${_adversarial_ckd_workload}"
    TIMEOUT 120)

  add_test(NAME "e2e/adversarial_ckd_code_reset_size"
    COMMAND bash "${_adversarial_driver}"
            "${Python3_EXECUTABLE}"
            "${CMAKE_C_COMPILER}"
            "$<TARGET_FILE:morok_plugin>"
            "${_sysroot}"
            "${_adversarial_ckd_workload}"
            "${_adversarial_ckd_config}"
            "ckd-code-reset-size"
            4242)
  set_tests_properties("e2e/adversarial_ckd_code_reset_size" PROPERTIES
    LABELS "e2e;adversarial;max"
    REQUIRED_FILES
      "$<TARGET_FILE:morok_plugin>;${_adversarial_driver};${_adversarial_ckd_config};${_adversarial_ckd_workload}"
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

  # Regression for #106: a fail_closed_on_unsealed build must be non-functional
  # when the post-link seal step is skipped, yet run normally once sealed.
  add_test(NAME "e2e/fail_closed_unsealed"
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/fail_closed_unsealed.sh"
            "${Python3_EXECUTABLE}"
            "${CMAKE_C_COMPILER}"
            "$<TARGET_FILE:morok_plugin>"
            "${_sysroot}"
            "${_adversarial_ckd_workload}"
            4242)
  set_tests_properties("e2e/fail_closed_unsealed" PROPERTIES
    LABELS "e2e;adversarial;max"
    REQUIRED_FILES
      "$<TARGET_FILE:morok_plugin>;${CMAKE_CURRENT_SOURCE_DIR}/fail_closed_unsealed.sh;${_adversarial_ckd_workload}"
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

# Mirage clean differential: on a clean run the seal-gated hub always routes to a
# real clone, so obfuscated output must match the reference exactly even as the
# per-invocation epoch alternates between the equivalent clones.  The mirage.toml
# intensity is portable (high minus virtualization), so this runs on every host.
add_test(NAME "e2e/mirage_clean_differential"
  COMMAND bash "${_driver}"
          "${CMAKE_C_COMPILER}"
          "$<TARGET_FILE:morok_plugin>"
          "${_sysroot}"
          "${_mirage_workload}"
          "${_mirage_config}"
          4242)
set_tests_properties("e2e/mirage_clean_differential" PROPERTIES
  LABELS "e2e;security"
  REQUIRED_FILES
    "$<TARGET_FILE:morok_plugin>;${_driver};${_mirage_config};${_mirage_workload}"
  TIMEOUT 120)

# Mirage counterfeit route: a force_route="fake" build must run without trapping
# yet diverge from the real reference, proving the counterfeit algorithms are
# wired and produce a wrong-but-plausible verdict on a dirty seal state.
add_test(NAME "e2e/mirage_forced_fake"
  COMMAND bash "${_mirage_fake_driver}"
          "${CMAKE_C_COMPILER}"
          "$<TARGET_FILE:morok_plugin>"
          "${_sysroot}"
          "${_mirage_workload}"
          "${_mirage_fake_config}"
          4242)
set_tests_properties("e2e/mirage_forced_fake" PROPERTIES
  LABELS "e2e;security;adversarial"
  REQUIRED_FILES
    "$<TARGET_FILE:morok_plugin>;${_mirage_fake_driver};${_mirage_fake_config};${_mirage_workload}"
  TIMEOUT 120)

add_test(NAME "e2e/timing_false_positive_clean_run"
  COMMAND bash "${_timing_false_positive_driver}"
          "${CMAKE_C_COMPILER}"
          "$<TARGET_FILE:morok_plugin>"
          "${_sysroot}"
          "${_timing_false_positive_workload}"
          "${_timing_false_positive_config}"
          1818)
set_tests_properties("e2e/timing_false_positive_clean_run" PROPERTIES
  LABELS "e2e;security"
  REQUIRED_FILES
    "$<TARGET_FILE:morok_plugin>;${_timing_false_positive_driver};${_timing_false_positive_config};${_timing_false_positive_workload}"
  TIMEOUT 120)

# The full sample-program compile/runtime sweep runs only when the corpus is
# present.  The corpus carries arch/OS-specific workloads — aarch64 inline asm,
# raw syscalls — so target-specific skips are explicit and kept out of the
# Darwin job, which sweeps every tracked program.
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
    RESOURCE_LOCK morok_program_corpus
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
    RESOURCE_LOCK morok_program_corpus
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
    RESOURCE_LOCK morok_program_corpus
    TIMEOUT 900)

  # Runtime correctness gate: every runnable sample program on this target must
  # produce identical exit status and normalized output clean vs obfuscated at
  # the `max` preset.  Catches miscompilations that compile cleanly but run
  # wrong (the compile sweep above cannot see these).
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
    ENVIRONMENT "MOROK_SKIP=${_program_skip};MOROK_RUN_SKIP=${_program_run_skip}"
    RESOURCE_LOCK morok_program_corpus
    TIMEOUT 1800)
else()
  message(STATUS "e2e programs sweep skipped (no programs/ corpus in this tree).")
endif()
