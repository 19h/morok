#==============================================================================
# End-to-end differential tests.
#
# Each test compiles the workload clean and obfuscated (via the built plugin)
# and requires identical runtime output.  Requires a C compiler matching the
# plugin's LLVM (the build compiler) and, on Apple platforms, the macOS SDK.
#==============================================================================

if(NOT APPLE)
  message(STATUS "e2e differential tests currently target Apple toolchains; skipping.")
  return()
endif()

set(_workload "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/workload.c")
set(_driver "${CMAKE_CURRENT_SOURCE_DIR}/differential.sh")

foreach(preset low mid high)
  add_test(NAME "e2e/differential_${preset}"
    COMMAND bash "${_driver}"
            "${CMAKE_C_COMPILER}"
            "$<TARGET_FILE:morok_plugin>"
            "${CMAKE_OSX_SYSROOT}"
            "${_workload}"
            "${preset}"
            4242)
  set_tests_properties("e2e/differential_${preset}" PROPERTIES
    LABELS "e2e"
    # The plugin must exist before these run.
    REQUIRED_FILES "$<TARGET_FILE:morok_plugin>")
endforeach()
