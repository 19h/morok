#==============================================================================
# morok_ir — LLVM-IR helper utilities.
#
# The first LLVM-facing layer.  Compiled against LLVM's headers with the same
# no-exceptions / no-RTTI policy LLVM itself uses (via morok::llvm).  Provides
# annotation handling and the PRNG↔IR adaptor that the passes build on.
#==============================================================================

add_library(morok_ir STATIC
  Annotations.cpp
  IRRandom.cpp
  Reg2Mem.cpp
  ControlFlowFlattener.cpp)
add_library(morok::ir ALIAS morok_ir)

target_compile_features(morok_ir PUBLIC cxx_std_23)
target_include_directories(morok_ir PUBLIC
  "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(morok_ir
  PUBLIC morok::core morok::llvm
  PRIVATE morok::warnings morok::no_eh_rtti)
