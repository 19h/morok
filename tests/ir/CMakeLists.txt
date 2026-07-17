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
    # --- deep per-pass suites (one file per pass) ---
    test_adversarial_function_merging.cpp
    test_adversarial_self_tuning.cpp
    test_anti_analysis.cpp
    test_arithmetic_tables.cpp
    test_caller_keyed_dispatch.cpp
    test_chaos_state_machine.cpp
    test_coherent_decoys.cpp
    test_constant_encryption.cpp
    test_data_entangled_flattening.cpp
    test_data_flow_integrity.cpp
    test_decoy_strings.cpp
    test_dispatcherless_routing.cpp
    test_env_binding_kdf.cpp
    test_external_opaque_predicates.cpp
    test_function_call_obfuscate.cpp
    test_function_fission.cpp
    test_function_wrapper.cpp
    test_hash_gated_self_decrypt.cpp
    test_indirect_branch.cpp
    test_interprocedural_fsm.cpp
    test_mba.cpp
    test_microcode_stress.cpp
    test_mirage.cpp
    test_mq_gate.cpp
    test_mutual_guard_graph.cpp
    test_native_code_pack.cpp
    test_nanomites.cpp
    test_non_invertible_state.cpp
    test_optimizer_amplification.cpp
    test_path_explosion.cpp
    test_per_build_polymorphism.cpp
    test_phi_tangling.cpp
    test_pointer_laundering.cpp
    test_runtime_seal.cpp
    test_sealed_blob.cpp
    test_self_checksum_constants.cpp
    test_shamir_share.cpp
    test_split_basic_blocks.cpp
    test_stack_coalescing.cpp
    test_stack_delta_games.cpp
    test_stack_rebase.cpp
    test_state_opaque_predicates.cpp
    test_string_encryption.cpp
    test_sub_threshold_persistence.cpp
    test_substitution.cpp
    test_trace_keying.cpp
    test_tracer_attestation.cpp
    test_type_punning.cpp
    test_uniform_primitive_lowering.cpp
    test_vector_obfuscation.cpp
    test_virtualization.cpp
    test_vtable_integrity.cpp
  LINK morok::passes morok::config morok::ir morok::runtime morok::core ${_llvm_libs}
  LABELS ir)

target_sources(morok_ir_tests
  PRIVATE "${CMAKE_SOURCE_DIR}/src/pipeline/Scheduler.cpp")
