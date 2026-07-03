#==============================================================================
# IR-linked unit tests.  Unlike the pure-layer suites these link LLVM directly
# (the executable parses and verifies IR), so they map the needed LLVM
# components to concrete libraries.
#==============================================================================

morok_llvm_map_components(_llvm_libs core support irreader asmparser transformutils analysis)

morok_add_unit_test(morok_ir_tests
  SOURCES
    test_passes.cpp
    test_returnless_dispatch.cpp
    test_code_region_kdf.cpp
    test_misleading_metadata.cpp
    test_flattening.cpp
    test_bogus_control_flow.cpp
    test_fault_paged_payload.cpp
    test_external_secret_binding.cpp
    test_alias_opaque_predicates.cpp
    test_annotations.cpp
    test_ir_random.cpp
    test_inst_util.cpp
    test_reg2mem.cpp
    test_symbol_cloak.cpp
    test_control_flow_flattener.cpp
  LINK morok::passes morok::config morok::ir morok::runtime morok::core ${_llvm_libs}
  LABELS ir)

target_sources(morok_ir_tests
  PRIVATE "${CMAKE_SOURCE_DIR}/src/pipeline/Scheduler.cpp")
