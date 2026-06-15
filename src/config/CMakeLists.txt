#==============================================================================
# morok_config — preset / policy / TOML configuration.
#
# Pure (no LLVM): the configuration model, preset tables, merge/resolve logic,
# and the TOML loader.  Exceptions are enabled here (this is not an LLVM-facing
# TU); toml++ errors are caught locally and never escape into linked plugins.
# Name demangling is injected by the caller, so this layer is fully unit-testable
# without LLVM.
#==============================================================================

add_library(morok_config STATIC
  Preset.cpp
  Resolver.cpp
  TomlLoader.cpp)
add_library(morok::config ALIAS morok_config)

target_compile_features(morok_config PUBLIC cxx_std_23)
target_include_directories(morok_config PUBLIC
  "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(morok_config
  PRIVATE tomlplusplus::tomlplusplus morok::warnings morok::sanitizers)
