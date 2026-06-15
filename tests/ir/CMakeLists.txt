#==============================================================================
# IR-linked unit tests.  Unlike the pure-layer suites these link LLVM directly
# (the executable parses and verifies IR), so they map the needed LLVM
# components to concrete libraries.
#==============================================================================

morok_llvm_map_components(_llvm_libs core support irreader asmparser transformutils)

morok_add_unit_test(morok_ir_tests
  SOURCES test_passes.cpp
  LINK morok::passes ${_llvm_libs}
  LABELS ir)
