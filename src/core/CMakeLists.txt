#==============================================================================
# morok_core — pure algorithmic core.
#
# Almost entirely header-only (constexpr engines and identity catalogs); the
# only compiled unit is host entropy collection.  Depends on nothing but the
# standard library, so it builds and tests without LLVM and links cleanly into
# both the exception-using config layer and the exception-free plugin.
#==============================================================================

add_library(morok_core STATIC
  Entropy.cpp)
add_library(morok::core ALIAS morok_core)

target_compile_features(morok_core PUBLIC cxx_std_23)
target_include_directories(morok_core PUBLIC
  "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(morok_core PRIVATE morok::warnings morok::sanitizers)
