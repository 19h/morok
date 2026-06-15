// SPDX-License-Identifier: MIT
//
// Unit tests for morok::config presets.

#include "doctest.h"

#include "morok/config/Preset.hpp"

using namespace morok::config;

TEST_CASE("preset names round-trip") {
    CHECK(parsePreset("low") == Preset::Low);
    CHECK(parsePreset("mid") == Preset::Mid);
    CHECK(parsePreset("high") == Preset::High);
    CHECK(parsePreset("none") == Preset::None);
    CHECK(parsePreset("") == Preset::None);
    CHECK(parsePreset("bogus") == Preset::None);
    CHECK(presetName(Preset::Low) == "low");
    CHECK(presetName(Preset::Mid) == "mid");
    CHECK(presetName(Preset::High) == "high");
    CHECK(presetName(Preset::None) == "none");
}

TEST_CASE("preset 'none' leaves every field unset") {
    const PassConfig c = presetConfig(Preset::None);
    CHECK_FALSE(c.bcf.enabled.has_value());
    CHECK_FALSE(c.sub.probability.has_value());
    CHECK_FALSE(c.const_enc.share_count.has_value());
    CHECK_FALSE(c.csm.enabled.has_value());
}

TEST_CASE("low preset matches the documented table") {
    const PassConfig c = presetConfig(Preset::Low);
    CHECK(c.bcf.probability == 30u);
    CHECK(c.bcf.complexity == 2u);
    CHECK(c.sub.probability == 40u);
    CHECK(c.mba.layers == 1u);
    CHECK(c.mba.heuristic == false);
    CHECK(c.const_enc.share_count == 2u);
    CHECK(c.const_enc.feistel == false);
    CHECK(c.stack_coalesce.enabled == false);
    CHECK(c.pointer_launder.enabled == false);
    CHECK(c.type_pun.enabled == false);
    CHECK(c.phi_tangle.enabled == false);
    CHECK(c.alias_op.enabled == false);
    CHECK(c.coherent_decoy.enabled == false);
    CHECK(c.data_entangled_flatten.enabled == false);
    CHECK(c.non_invertible_state.enabled == false);
    CHECK(c.state_opaque.enabled == false);
    CHECK(c.interprocedural_fsm.enabled == false);
    CHECK(c.opt_amplify.enabled == false);
    CHECK(c.table_arith.enabled == false);
    CHECK(c.sub_threshold.enabled == false);
    CHECK(c.uniform_lower.enabled == false);
    CHECK(c.virtualization.enabled == false);
    CHECK(c.path_explosion.enabled == false);
    CHECK(c.trace_keying.enabled == false);
    CHECK(c.dispatcherless.enabled == false);
    CHECK(c.vec.enabled == false);
    CHECK(c.csm.enabled == false);
    CHECK(c.flatten.enabled == false);
}

TEST_CASE("mid preset matches the documented table") {
    const PassConfig c = presetConfig(Preset::Mid);
    CHECK(c.bcf.probability == 60u);
    CHECK(c.bcf.complexity == 4u);
    CHECK(c.sub.probability == 60u);
    CHECK(c.mba.layers == 2u);
    CHECK(c.mba.heuristic == true);
    CHECK(c.const_enc.share_count == 3u);
    CHECK(c.const_enc.feistel == false);
    CHECK(c.stack_coalesce.enabled == true);
    CHECK(c.stack_coalesce.probability == 60u);
    CHECK(c.pointer_launder.enabled == true);
    CHECK(c.pointer_launder.pointer_probability == 50u);
    CHECK(c.type_pun.enabled == true);
    CHECK(c.type_pun.probability == 30u);
    CHECK(c.type_pun.max_targets == 16u);
    CHECK(c.phi_tangle.enabled == true);
    CHECK(c.phi_tangle.layers == 1u);
    CHECK(c.alias_op.enabled == true);
    CHECK(c.alias_op.probability == 35u);
    CHECK(c.alias_op.iterations == 1u);
    CHECK(c.alias_op.max_blocks == 6u);
    CHECK(c.coherent_decoy.enabled == true);
    CHECK(c.coherent_decoy.probability == 35u);
    CHECK(c.coherent_decoy.max_blocks == 4u);
    CHECK(c.coherent_decoy.depth == 3u);
    CHECK(c.data_entangled_flatten.enabled == true);
    CHECK(c.data_entangled_flatten.max_terms == 3u);
    CHECK(c.non_invertible_state.enabled == true);
    CHECK(c.non_invertible_state.max_terms == 3u);
    CHECK(c.non_invertible_state.rounds == 2u);
    CHECK(c.state_opaque.enabled == true);
    CHECK(c.state_opaque.probability == 45u);
    CHECK(c.state_opaque.max_blocks == 12u);
    CHECK(c.state_opaque.max_terms == 3u);
    CHECK(c.interprocedural_fsm.enabled == true);
    CHECK(c.interprocedural_fsm.probability == 50u);
    CHECK(c.interprocedural_fsm.max_sites == 16u);
    CHECK(c.interprocedural_fsm.max_terms == 3u);
    CHECK(c.opt_amplify.enabled == true);
    CHECK(c.opt_amplify.probability == 10u);
    CHECK(c.opt_amplify.max_forms == 1u);
    CHECK(c.table_arith.enabled == true);
    CHECK(c.table_arith.probability == 20u);
    CHECK(c.table_arith.max_tables == 2u);
    CHECK(c.sub_threshold.enabled == true);
    CHECK(c.sub_threshold.probability == 15u);
    CHECK(c.sub_threshold.max_terms == 1u);
    CHECK(c.uniform_lower.enabled == true);
    CHECK(c.uniform_lower.op_probability == 15u);
    CHECK(c.uniform_lower.branch_probability == 20u);
    CHECK(c.uniform_lower.max_tables == 2u);
    CHECK(c.uniform_lower.max_branches == 2u);
    CHECK(c.virtualization.enabled == false);
    CHECK(c.path_explosion.enabled == true);
    CHECK(c.path_explosion.probability == 15u);
    CHECK(c.path_explosion.max_blocks == 2u);
    CHECK(c.path_explosion.max_iterations == 8u);
    CHECK(c.trace_keying.enabled == true);
    CHECK(c.trace_keying.probability == 10u);
    CHECK(c.trace_keying.max_blocks == 2u);
    CHECK(c.dispatcherless.enabled == true);
    CHECK(c.dispatcherless.probability == 35u);
    CHECK(c.dispatcherless.max_routes == 8u);
    CHECK(c.dispatcherless.max_terms == 3u);
    CHECK(c.vec.width == 128u);
    CHECK(c.vec.shuffle == false);
    CHECK(c.vec.lift_comparisons == true);
    CHECK(c.flatten.enabled == true);
    CHECK(c.csm.enabled == false);
    CHECK(c.indir_branch.enabled == true);
}

TEST_CASE("high preset matches the documented table") {
    const PassConfig c = presetConfig(Preset::High);
    CHECK(c.bcf.probability == 75u);
    CHECK(c.bcf.iterations == 2u);
    CHECK(c.bcf.complexity == 6u);
    CHECK(c.bcf.entropy_chain == true);
    CHECK(c.sub.iterations == 2u);
    CHECK(c.mba.layers == 3u);
    CHECK(c.const_enc.share_count == 4u);
    CHECK(c.const_enc.feistel == true);
    CHECK(c.stack_coalesce.enabled == true);
    CHECK(c.stack_coalesce.probability == 100u);
    CHECK(c.stack_coalesce.opaque_offsets == true);
    CHECK(c.pointer_launder.enabled == true);
    CHECK(c.pointer_launder.pointer_probability == 90u);
    CHECK(c.pointer_launder.integer_probability == 45u);
    CHECK(c.type_pun.enabled == true);
    CHECK(c.type_pun.probability == 60u);
    CHECK(c.type_pun.include_floating == true);
    CHECK(c.type_pun.max_targets == 32u);
    CHECK(c.phi_tangle.enabled == true);
    CHECK(c.phi_tangle.probability == 80u);
    CHECK(c.phi_tangle.layers == 2u);
    CHECK(c.phi_tangle.max_phis == 24u);
    CHECK(c.alias_op.enabled == true);
    CHECK(c.alias_op.probability == 65u);
    CHECK(c.alias_op.iterations == 2u);
    CHECK(c.alias_op.max_blocks == 10u);
    CHECK(c.coherent_decoy.enabled == true);
    CHECK(c.coherent_decoy.probability == 70u);
    CHECK(c.coherent_decoy.max_blocks == 8u);
    CHECK(c.coherent_decoy.depth == 5u);
    CHECK(c.data_entangled_flatten.enabled == true);
    CHECK(c.data_entangled_flatten.max_terms == 5u);
    CHECK(c.non_invertible_state.enabled == true);
    CHECK(c.non_invertible_state.max_terms == 5u);
    CHECK(c.non_invertible_state.rounds == 4u);
    CHECK(c.state_opaque.enabled == true);
    CHECK(c.state_opaque.probability == 80u);
    CHECK(c.state_opaque.max_blocks == 32u);
    CHECK(c.state_opaque.max_terms == 5u);
    CHECK(c.interprocedural_fsm.enabled == true);
    CHECK(c.interprocedural_fsm.probability == 100u);
    CHECK(c.interprocedural_fsm.max_sites == 64u);
    CHECK(c.interprocedural_fsm.max_terms == 5u);
    CHECK(c.opt_amplify.enabled == true);
    CHECK(c.opt_amplify.probability == 20u);
    CHECK(c.opt_amplify.max_forms == 2u);
    CHECK(c.table_arith.enabled == true);
    CHECK(c.table_arith.probability == 35u);
    CHECK(c.table_arith.max_tables == 4u);
    CHECK(c.sub_threshold.enabled == true);
    CHECK(c.sub_threshold.probability == 15u);
    CHECK(c.sub_threshold.max_terms == 1u);
    CHECK(c.uniform_lower.enabled == true);
    CHECK(c.uniform_lower.op_probability == 15u);
    CHECK(c.uniform_lower.branch_probability == 10u);
    CHECK(c.uniform_lower.max_tables == 2u);
    CHECK(c.uniform_lower.max_branches == 1u);
    CHECK(c.virtualization.enabled == true);
    CHECK(c.virtualization.probability == 25u);
    CHECK(c.virtualization.max_functions == 1u);
    CHECK(c.virtualization.max_instructions == 48u);
    CHECK(c.virtualization.max_registers == 64u);
    CHECK(c.path_explosion.enabled == true);
    CHECK(c.path_explosion.probability == 35u);
    CHECK(c.path_explosion.max_blocks == 4u);
    CHECK(c.path_explosion.max_iterations == 16u);
    CHECK(c.trace_keying.enabled == true);
    CHECK(c.trace_keying.probability == 25u);
    CHECK(c.trace_keying.max_blocks == 4u);
    CHECK(c.dispatcherless.enabled == true);
    CHECK(c.dispatcherless.probability == 75u);
    CHECK(c.dispatcherless.max_routes == 24u);
    CHECK(c.dispatcherless.max_terms == 5u);
    CHECK(c.vec.width == 256u);
    CHECK(c.vec.shuffle == true);
    CHECK(c.vec.lift_comparisons == true);
    CHECK(c.csm.enabled == true);
    CHECK(c.flatten.enabled == false);
    CHECK(c.func_wrap.enabled == true);
    CHECK(c.fco.enabled == true);
}
