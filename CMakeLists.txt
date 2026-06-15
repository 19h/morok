#==============================================================================
# Morok — a modular LLVM IR obfuscator (clean-room rewrite)
#
# Top-level build orchestration.  The project is split into independently
# testable layers, each its own CMake target:
#
#     morok_core      pure C++23 algorithms — zero LLVM, zero I/O
#     morok_config    preset/policy/TOML configuration — zero LLVM
#     morok_ir        LLVM-IR helper utilities (links LLVM)
#     morok_passes    the obfuscation passes (links LLVM + the above)
#     morok_plugin    the loadable New-PM pass plugin (libMorok)
#
# Tests live under tests/ and mirror this layering: the pure layers are
# exercised by fast doctest unit suites with no LLVM dependency; the IR layers
# are exercised by JIT-backed differential tests and lit/FileCheck; the whole
# stack is exercised end-to-end by differential behavioural tests.
#==============================================================================
cmake_minimum_required(VERSION 3.28)

project(Morok
  VERSION 0.1.0
  DESCRIPTION "Modular LLVM IR obfuscator"
  LANGUAGES C CXX)

#------------------------------------------------------------------------------
# Guard-rails
#------------------------------------------------------------------------------
if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
  message(FATAL_ERROR
    "In-source builds are forbidden. Configure into a separate directory, e.g.\n"
    "    cmake -S . -B build")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)

# Always emit a compile database for clang-tidy / editors.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Position-independent code everywhere: the plugin is a shared object and the
# static layers are linked into it.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
  message(STATUS "No build type set — defaulting to RelWithDebInfo")
endif()

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

#------------------------------------------------------------------------------
# Options
#------------------------------------------------------------------------------
option(MOROK_BUILD_TESTS    "Build the test suite"                       ON)
option(MOROK_BUILD_PLUGIN   "Build the loadable LLVM pass plugin"        ON)
option(MOROK_WERROR         "Treat warnings as errors"                   OFF)
option(MOROK_SANITIZE       "Build the pure layers + tests with ASan/UBSan" OFF)

include(MorokWarnings)

#------------------------------------------------------------------------------
# Third-party (vendored, header-only): doctest, toml++
#------------------------------------------------------------------------------
add_subdirectory(third_party)

#------------------------------------------------------------------------------
# Layer composition.
#
# Each layer is added only once its CMakeLists exists, so the project can be
# grown and built incrementally without breaking configuration.
#------------------------------------------------------------------------------
function(morok_add_layer subdir)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${subdir}/CMakeLists.txt")
    add_subdirectory(${subdir})
  endif()
endfunction()

# LLVM-independent layers (always built).
morok_add_layer(src/core)
morok_add_layer(src/config)

# LLVM-dependent layers (require a usable LLVM with the New-PM plugin API).
if(MOROK_BUILD_PLUGIN OR MOROK_BUILD_TESTS)
  include(MorokLLVM)            # discovers LLVM, validates the plugin API
  if(Morok_LLVM_FOUND)
    morok_add_layer(src/ir)
    morok_add_layer(src/passes)
    morok_add_layer(src/pipeline)
  else()
    message(WARNING
      "LLVM not usable for plugin/IR layers — building pure layers only.")
  endif()
endif()

#------------------------------------------------------------------------------
# Tests
#------------------------------------------------------------------------------
if(MOROK_BUILD_TESTS)
  enable_testing()
  include(MorokTest)
  add_subdirectory(tests)
endif()

#------------------------------------------------------------------------------
# Configuration summary
#------------------------------------------------------------------------------
message(STATUS "")
message(STATUS "Morok ${PROJECT_VERSION} configuration:")
message(STATUS "  build type        : ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ standard      : ${CMAKE_CXX_STANDARD}")
message(STATUS "  tests             : ${MOROK_BUILD_TESTS}")
message(STATUS "  plugin            : ${MOROK_BUILD_PLUGIN}")
message(STATUS "  warnings-as-errors: ${MOROK_WERROR}")
message(STATUS "  sanitizers        : ${MOROK_SANITIZE}")
if(Morok_LLVM_FOUND)
  message(STATUS "  LLVM              : ${LLVM_PACKAGE_VERSION} (${LLVM_DIR})")
endif()
message(STATUS "")
