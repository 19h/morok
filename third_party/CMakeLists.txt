#==============================================================================
# Vendored, header-only third-party dependencies.
#
# Pinned and committed in-tree for fully reproducible, offline builds:
#   doctest 2.4.11   — unit-test framework
#   toml++  3.4.0    — TOML parser (used in exception-free configurations)
#==============================================================================

# --- doctest ----------------------------------------------------------------
add_library(doctest INTERFACE)
add_library(doctest::doctest ALIAS doctest)
target_include_directories(doctest SYSTEM INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/doctest")
# Expose the discovery script directory for MorokTest.cmake.
set(DOCTEST_CMAKE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/doctest" CACHE INTERNAL "")

# --- toml++ -----------------------------------------------------------------
add_library(tomlplusplus INTERFACE)
add_library(tomlplusplus::tomlplusplus ALIAS tomlplusplus)
target_include_directories(tomlplusplus SYSTEM INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/tomlplusplus")
