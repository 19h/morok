// SPDX-License-Identifier: MIT
//
// Unit tests for morok::config::merge precedence.

#include "doctest.h"

#include "morok/config/Resolver.hpp"

using namespace morok::config;

TEST_CASE("merge copies set fields and leaves unset ones untouched") {
    PassConfig dst;
    dst.bcf.probability = 10u;
    dst.bcf.iterations = 1u;

    PassConfig src;
    src.bcf.probability = 90u; // set → overrides
    // src.bcf.iterations unset → dst keeps its value

    merge(dst, src);
    CHECK(dst.bcf.probability == 90u);
    CHECK(dst.bcf.iterations == 1u);
}

TEST_CASE("merge fills previously-unset fields from src") {
    PassConfig dst;
    PassConfig src;
    src.mba.enabled = true;
    src.mba.layers = 3u;

    merge(dst, src);
    CHECK(dst.mba.enabled == true);
    CHECK(dst.mba.layers == 3u);
}

TEST_CASE("merge replaces non-empty string vectors but not empty ones") {
    PassConfig dst;
    dst.str_enc.skip_content = {"keep"};

    PassConfig src; // empty skip_content → must not clobber
    merge(dst, src);
    REQUIRE(dst.str_enc.skip_content.size() == 1);
    CHECK(dst.str_enc.skip_content[0] == "keep");

    src.str_enc.skip_content = {"a", "b"};
    merge(dst, src);
    REQUIRE(dst.str_enc.skip_content.size() == 2);
    CHECK(dst.str_enc.skip_content[0] == "a");
}

TEST_CASE("merge is layerable: preset base then targeted overrides") {
    PassConfig eff = presetConfig(Preset::Mid);
    CHECK(eff.const_enc.share_count == 3u);

    PassConfig override_;
    override_.const_enc.share_count = 6u;
    override_.bcf.probability = 90u;
    merge(eff, override_);

    CHECK(eff.const_enc.share_count == 6u); // overridden
    CHECK(eff.bcf.probability == 90u);      // overridden
    CHECK(eff.mba.layers == 2u);            // preserved from preset
    CHECK(eff.flatten.enabled == true);     // preserved from preset
}

TEST_CASE("merge handles every pass family") {
    PassConfig dst;
    PassConfig src;
    src.split.splits = 8u;
    src.stack_coalesce.enabled = true;
    src.stack_coalesce.probability = 70u;
    src.stack_coalesce.opaque_offsets = true;
    src.pointer_launder.enabled = true;
    src.pointer_launder.pointer_probability = 85u;
    src.pointer_launder.integer_probability = 30u;
    src.type_pun.enabled = true;
    src.type_pun.probability = 45u;
    src.type_pun.include_floating = true;
    src.type_pun.max_targets = 12u;
    src.phi_tangle.enabled = true;
    src.phi_tangle.probability = 65u;
    src.phi_tangle.layers = 2u;
    src.phi_tangle.max_phis = 14u;
    src.alias_op.enabled = true;
    src.alias_op.probability = 72u;
    src.alias_op.iterations = 2u;
    src.alias_op.max_blocks = 9u;
    src.external_op.enabled = true;
    src.external_op.probability = 59u;
    src.external_op.max_blocks = 6u;
    src.external_op.decoy_stores = 2u;
    src.coherent_decoy.enabled = true;
    src.coherent_decoy.probability = 62u;
    src.coherent_decoy.max_blocks = 5u;
    src.coherent_decoy.depth = 4u;
    src.data_entangled_flatten.enabled = true;
    src.data_entangled_flatten.max_terms = 6u;
    src.non_invertible_state.enabled = true;
    src.non_invertible_state.max_terms = 7u;
    src.non_invertible_state.rounds = 5u;
    src.state_opaque.enabled = true;
    src.state_opaque.probability = 77u;
    src.state_opaque.max_blocks = 10u;
    src.state_opaque.max_terms = 6u;
    src.interprocedural_fsm.enabled = true;
    src.interprocedural_fsm.probability = 81u;
    src.interprocedural_fsm.max_sites = 13u;
    src.interprocedural_fsm.max_terms = 6u;
    src.opt_amplify.enabled = true;
    src.opt_amplify.probability = 34u;
    src.opt_amplify.max_forms = 3u;
    src.table_arith.enabled = true;
    src.table_arith.probability = 44u;
    src.table_arith.max_tables = 5u;
    src.sub_threshold.enabled = true;
    src.sub_threshold.probability = 57u;
    src.sub_threshold.max_terms = 3u;
    src.uniform_lower.enabled = true;
    src.uniform_lower.op_probability = 48u;
    src.uniform_lower.branch_probability = 64u;
    src.uniform_lower.max_tables = 6u;
    src.uniform_lower.max_branches = 8u;
    src.virtualization.enabled = true;
    src.virtualization.probability = 29u;
    src.virtualization.max_functions = 2u;
    src.virtualization.max_instructions = 40u;
    src.virtualization.max_registers = 48u;
    src.hash_self_decrypt.enabled = true;
    src.hash_self_decrypt.probability = 91u;
    src.hash_self_decrypt.max_payloads = 3u;
    src.self_checksum.enabled = true;
    src.self_checksum.probability = 82u;
    src.self_checksum.max_constants = 7u;
    src.self_checksum.region_bytes = 40u;
    src.data_flow_integrity.enabled = true;
    src.data_flow_integrity.probability = 69u;
    src.data_flow_integrity.max_tables = 4u;
    src.data_flow_integrity.region_bytes = 56u;
    src.mutual_guard.enabled = true;
    src.mutual_guard.probability = 67u;
    src.mutual_guard.nodes = 5u;
    src.mutual_guard.region_bytes = 64u;
    src.mutual_guard.max_returns = 3u;
    src.adversarial_merge.enabled = true;
    src.adversarial_merge.probability = 53u;
    src.adversarial_merge.max_groups = 2u;
    src.adversarial_merge.max_functions = 6u;
    src.adversarial_merge.outline_probability = 74u;
    src.adversarial_merge.max_outlines = 11u;
    src.per_build_polymorphism.enabled = true;
    src.per_build_polymorphism.function_order = true;
    src.per_build_polymorphism.block_order = false;
    src.per_build_polymorphism.anchor_probability = 64u;
    src.per_build_polymorphism.max_anchors = 13u;
    src.path_explosion.enabled = true;
    src.path_explosion.probability = 52u;
    src.path_explosion.max_blocks = 3u;
    src.path_explosion.max_iterations = 12u;
    src.trace_keying.enabled = true;
    src.trace_keying.probability = 41u;
    src.trace_keying.max_blocks = 5u;
    src.dispatcherless.enabled = true;
    src.dispatcherless.probability = 66u;
    src.dispatcherless.max_routes = 7u;
    src.dispatcherless.max_terms = 4u;
    src.vec.probability = 77u;
    src.vec.width = 512u;
    src.vec.shuffle = true;
    src.vec.lift_comparisons = false;
    src.csm.warmup = 256u;
    src.indir_branch.enabled = true;
    src.func_wrap.times = 3u;
    src.fco.enabled = true;
    src.anti_dbg.enabled = true;
    merge(dst, src);
    CHECK(dst.split.splits == 8u);
    CHECK(dst.stack_coalesce.enabled == true);
    CHECK(dst.stack_coalesce.probability == 70u);
    CHECK(dst.stack_coalesce.opaque_offsets == true);
    CHECK(dst.pointer_launder.enabled == true);
    CHECK(dst.pointer_launder.pointer_probability == 85u);
    CHECK(dst.pointer_launder.integer_probability == 30u);
    CHECK(dst.type_pun.enabled == true);
    CHECK(dst.type_pun.probability == 45u);
    CHECK(dst.type_pun.include_floating == true);
    CHECK(dst.type_pun.max_targets == 12u);
    CHECK(dst.phi_tangle.enabled == true);
    CHECK(dst.phi_tangle.probability == 65u);
    CHECK(dst.phi_tangle.layers == 2u);
    CHECK(dst.phi_tangle.max_phis == 14u);
    CHECK(dst.alias_op.enabled == true);
    CHECK(dst.alias_op.probability == 72u);
    CHECK(dst.alias_op.iterations == 2u);
    CHECK(dst.alias_op.max_blocks == 9u);
    CHECK(dst.external_op.enabled == true);
    CHECK(dst.external_op.probability == 59u);
    CHECK(dst.external_op.max_blocks == 6u);
    CHECK(dst.external_op.decoy_stores == 2u);
    CHECK(dst.coherent_decoy.enabled == true);
    CHECK(dst.coherent_decoy.probability == 62u);
    CHECK(dst.coherent_decoy.max_blocks == 5u);
    CHECK(dst.coherent_decoy.depth == 4u);
    CHECK(dst.data_entangled_flatten.enabled == true);
    CHECK(dst.data_entangled_flatten.max_terms == 6u);
    CHECK(dst.non_invertible_state.enabled == true);
    CHECK(dst.non_invertible_state.max_terms == 7u);
    CHECK(dst.non_invertible_state.rounds == 5u);
    CHECK(dst.state_opaque.enabled == true);
    CHECK(dst.state_opaque.probability == 77u);
    CHECK(dst.state_opaque.max_blocks == 10u);
    CHECK(dst.state_opaque.max_terms == 6u);
    CHECK(dst.interprocedural_fsm.enabled == true);
    CHECK(dst.interprocedural_fsm.probability == 81u);
    CHECK(dst.interprocedural_fsm.max_sites == 13u);
    CHECK(dst.interprocedural_fsm.max_terms == 6u);
    CHECK(dst.opt_amplify.enabled == true);
    CHECK(dst.opt_amplify.probability == 34u);
    CHECK(dst.opt_amplify.max_forms == 3u);
    CHECK(dst.table_arith.enabled == true);
    CHECK(dst.table_arith.probability == 44u);
    CHECK(dst.table_arith.max_tables == 5u);
    CHECK(dst.sub_threshold.enabled == true);
    CHECK(dst.sub_threshold.probability == 57u);
    CHECK(dst.sub_threshold.max_terms == 3u);
    CHECK(dst.uniform_lower.enabled == true);
    CHECK(dst.uniform_lower.op_probability == 48u);
    CHECK(dst.uniform_lower.branch_probability == 64u);
    CHECK(dst.uniform_lower.max_tables == 6u);
    CHECK(dst.uniform_lower.max_branches == 8u);
    CHECK(dst.virtualization.enabled == true);
    CHECK(dst.virtualization.probability == 29u);
    CHECK(dst.virtualization.max_functions == 2u);
    CHECK(dst.virtualization.max_instructions == 40u);
    CHECK(dst.virtualization.max_registers == 48u);
    CHECK(dst.hash_self_decrypt.enabled == true);
    CHECK(dst.hash_self_decrypt.probability == 91u);
    CHECK(dst.hash_self_decrypt.max_payloads == 3u);
    CHECK(dst.self_checksum.enabled == true);
    CHECK(dst.self_checksum.probability == 82u);
    CHECK(dst.self_checksum.max_constants == 7u);
    CHECK(dst.self_checksum.region_bytes == 40u);
    CHECK(dst.data_flow_integrity.enabled == true);
    CHECK(dst.data_flow_integrity.probability == 69u);
    CHECK(dst.data_flow_integrity.max_tables == 4u);
    CHECK(dst.data_flow_integrity.region_bytes == 56u);
    CHECK(dst.mutual_guard.enabled == true);
    CHECK(dst.mutual_guard.probability == 67u);
    CHECK(dst.mutual_guard.nodes == 5u);
    CHECK(dst.mutual_guard.region_bytes == 64u);
    CHECK(dst.mutual_guard.max_returns == 3u);
    CHECK(dst.adversarial_merge.enabled == true);
    CHECK(dst.adversarial_merge.probability == 53u);
    CHECK(dst.adversarial_merge.max_groups == 2u);
    CHECK(dst.adversarial_merge.max_functions == 6u);
    CHECK(dst.adversarial_merge.outline_probability == 74u);
    CHECK(dst.adversarial_merge.max_outlines == 11u);
    CHECK(dst.per_build_polymorphism.enabled == true);
    CHECK(dst.per_build_polymorphism.function_order == true);
    CHECK(dst.per_build_polymorphism.block_order == false);
    CHECK(dst.per_build_polymorphism.anchor_probability == 64u);
    CHECK(dst.per_build_polymorphism.max_anchors == 13u);
    CHECK(dst.path_explosion.enabled == true);
    CHECK(dst.path_explosion.probability == 52u);
    CHECK(dst.path_explosion.max_blocks == 3u);
    CHECK(dst.path_explosion.max_iterations == 12u);
    CHECK(dst.trace_keying.enabled == true);
    CHECK(dst.trace_keying.probability == 41u);
    CHECK(dst.trace_keying.max_blocks == 5u);
    CHECK(dst.dispatcherless.enabled == true);
    CHECK(dst.dispatcherless.probability == 66u);
    CHECK(dst.dispatcherless.max_routes == 7u);
    CHECK(dst.dispatcherless.max_terms == 4u);
    CHECK(dst.vec.probability == 77u);
    CHECK(dst.vec.width == 512u);
    CHECK(dst.vec.shuffle == true);
    CHECK(dst.vec.lift_comparisons == false);
    CHECK(dst.csm.warmup == 256u);
    CHECK(dst.indir_branch.enabled == true);
    CHECK(dst.func_wrap.times == 3u);
    CHECK(dst.fco.enabled == true);
    CHECK(dst.anti_dbg.enabled == true);
}
