#==============================================================================
# MorokLLVM.cmake
#
# Locates LLVM and validates that it exposes the New-PM plugin API this project
# targets.  This environment ships a *customised* LLVM where the plugin header
# was moved to <llvm/Plugins/PassPlugin.h> and the API version is 2 (upstream
# uses <llvm/Passes/PassPlugin.h>, version 1).  We fail loudly if the header /
# version we depend on is not present, rather than producing a plugin that the
# host `opt`/`clang` will reject at load time with a cryptic version error.
#
# Produces:
#   Morok_LLVM_FOUND          BOOL — set when everything validated
#   morok::llvm               INTERFACE target: include dirs + defs + no-EH/RTTI
#   morok_llvm_map_components(<out> comp...)   helper for test exes that link LLVM
#==============================================================================

set(Morok_LLVM_FOUND FALSE)

# Allow an explicit override; otherwise probe the known install, then PATH.
if(NOT DEFINED LLVM_DIR OR LLVM_DIR STREQUAL "")
  if(EXISTS "$ENV{HOME}/local/lib/cmake/llvm/LLVMConfig.cmake")
    set(LLVM_DIR "$ENV{HOME}/local/lib/cmake/llvm")
  endif()
endif()

find_package(LLVM CONFIG QUIET)
if(NOT LLVM_FOUND)
  message(WARNING "MorokLLVM: find_package(LLVM CONFIG) failed (LLVM_DIR='${LLVM_DIR}').")
  return()
endif()

if(LLVM_VERSION_MAJOR VERSION_LESS 18)
  message(WARNING "MorokLLVM: need LLVM >= 18, found ${LLVM_PACKAGE_VERSION}.")
  return()
endif()

# --- Validate the New-PM plugin API we compile against ----------------------
find_file(MOROK_PASSPLUGIN_HEADER
  NAMES llvm/Plugins/PassPlugin.h
  PATHS ${LLVM_INCLUDE_DIRS}
  NO_DEFAULT_PATH)

if(NOT MOROK_PASSPLUGIN_HEADER)
  message(WARNING
    "MorokLLVM: <llvm/Plugins/PassPlugin.h> not found under ${LLVM_INCLUDE_DIRS}.\n"
    "This build targets a forked LLVM that moved the plugin header there.")
  return()
endif()

file(STRINGS "${MOROK_PASSPLUGIN_HEADER}" _api_line
  REGEX "define[ \t]+LLVM_PLUGIN_API_VERSION")
string(REGEX MATCH "[0-9]+" MOROK_PLUGIN_API_VERSION "${_api_line}")
if(NOT MOROK_PLUGIN_API_VERSION STREQUAL "2")
  message(WARNING
    "MorokLLVM: expected LLVM_PLUGIN_API_VERSION 2, got '${MOROK_PLUGIN_API_VERSION}'.")
  return()
endif()

message(STATUS "MorokLLVM: LLVM ${LLVM_PACKAGE_VERSION}, plugin API v${MOROK_PLUGIN_API_VERSION}")

# --- Interface target carrying the LLVM compile environment -----------------
add_library(morok_llvm INTERFACE)
add_library(morok::llvm ALIAS morok_llvm)

target_include_directories(morok_llvm SYSTEM INTERFACE ${LLVM_INCLUDE_DIRS})
separate_arguments(_llvm_defs NATIVE_COMMAND "${LLVM_DEFINITIONS}")
target_compile_definitions(morok_llvm INTERFACE ${_llvm_defs})
# LLVM's API churns; do not let its own deprecation notices break our build.
target_compile_options(morok_llvm INTERFACE
  $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang,AppleClang>:-Wno-deprecated-declarations>)
# Note: the no-exceptions / no-RTTI policy LLVM-facing code must follow is applied
# PRIVATELY by each LLVM-facing library (morok_ir / morok_passes / morok_plugin)
# so it governs their own translation units without leaking onto consumers such as
# the doctest executables, which require exceptions.

# Helper: resolve LLVM component names to concrete link libraries for the small
# number of test executables that link LLVM directly (the plugin itself does
# not link LLVM — it resolves symbols from the host process at load time).
function(morok_llvm_map_components out_var)
  llvm_map_components_to_libnames(_libs ${ARGN})
  set(${out_var} ${_libs} PARENT_SCOPE)
endfunction()

set(Morok_LLVM_FOUND TRUE)
