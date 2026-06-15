// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/config/Preset.cpp — preset intensity tables.
//
//  Preset  BCF prob/loop/compl  Sub prob/loop  MBA prob/layers  ConstEnc
//  k/feistel  Vec  CSM low     30 / 1 / 2           40 / 1         30 / 1 2 /
//  no              off  off mid     60 / 1 / 4           60 / 1         50 / 2
//  3 / no              128  off high    75 / 2 / 6           80 / 2         70
//  / 3           4 / yes             256  on

#include "morok/config/Preset.hpp"

namespace morok::config {

Preset parsePreset(std::string_view name) noexcept {
    if (name == "low")
        return Preset::Low;
    if (name == "mid")
        return Preset::Mid;
    if (name == "high")
        return Preset::High;
    return Preset::None;
}

std::string_view presetName(Preset p) noexcept {
    switch (p) {
    case Preset::Low:
        return "low";
    case Preset::Mid:
        return "mid";
    case Preset::High:
        return "high";
    case Preset::None:
        break;
    }
    return "none";
}

namespace {

PassConfig makeLow() {
    PassConfig c;
    c.bcf.enabled = true;
    c.bcf.probability = 30;
    c.bcf.iterations = 1;
    c.bcf.complexity = 2;
    c.bcf.entropy_chain = false;
    c.bcf.junk_asm = false;
    c.bcf.junk_asm_min = 0;
    c.bcf.junk_asm_max = 0;

    c.sub.enabled = true;
    c.sub.probability = 40;
    c.sub.iterations = 1;

    c.mba.enabled = true;
    c.mba.probability = 30;
    c.mba.layers = 1;
    c.mba.heuristic = false;

    c.str_enc.enabled = true;
    c.str_enc.probability = 70;

    c.const_enc.enabled = true;
    c.const_enc.iterations = 1;
    c.const_enc.share_count = 2;
    c.const_enc.feistel = false;
    c.const_enc.substitute_xor = false;
    c.const_enc.substitute_xor_prob = 0;
    c.const_enc.globalize = false;
    c.const_enc.globalize_prob = 0;

    c.split.enabled = true;
    c.split.splits = 2;
    c.split.stack_confusion = false;

    c.stack_coalesce.enabled = false;
    c.stack_coalesce.probability = 0;
    c.stack_coalesce.opaque_offsets = false;

    c.pointer_launder.enabled = false;
    c.pointer_launder.pointer_probability = 0;
    c.pointer_launder.integer_probability = 0;

    c.type_pun.enabled = false;
    c.type_pun.probability = 0;
    c.type_pun.include_floating = false;
    c.type_pun.max_targets = 0;

    c.phi_tangle.enabled = false;
    c.phi_tangle.probability = 0;
    c.phi_tangle.layers = 0;
    c.phi_tangle.max_phis = 0;

    c.alias_op.enabled = false;
    c.alias_op.probability = 0;
    c.alias_op.iterations = 0;
    c.alias_op.max_blocks = 0;

    c.coherent_decoy.enabled = false;
    c.coherent_decoy.probability = 0;
    c.coherent_decoy.max_blocks = 0;
    c.coherent_decoy.depth = 0;

    c.data_entangled_flatten.enabled = false;
    c.data_entangled_flatten.max_terms = 0;

    c.non_invertible_state.enabled = false;
    c.non_invertible_state.max_terms = 0;
    c.non_invertible_state.rounds = 0;

    c.state_opaque.enabled = false;
    c.state_opaque.probability = 0;
    c.state_opaque.max_blocks = 0;
    c.state_opaque.max_terms = 0;

    c.interprocedural_fsm.enabled = false;
    c.interprocedural_fsm.probability = 0;
    c.interprocedural_fsm.max_sites = 0;
    c.interprocedural_fsm.max_terms = 0;

    c.opt_amplify.enabled = false;
    c.opt_amplify.probability = 0;
    c.opt_amplify.max_forms = 0;

    c.table_arith.enabled = false;
    c.table_arith.probability = 0;
    c.table_arith.max_tables = 0;

    c.sub_threshold.enabled = false;
    c.sub_threshold.probability = 0;
    c.sub_threshold.max_terms = 0;

    c.uniform_lower.enabled = false;
    c.uniform_lower.op_probability = 0;
    c.uniform_lower.branch_probability = 0;
    c.uniform_lower.max_tables = 0;
    c.uniform_lower.max_branches = 0;

    c.path_explosion.enabled = false;
    c.path_explosion.probability = 0;
    c.path_explosion.max_blocks = 0;
    c.path_explosion.max_iterations = 0;

    c.dispatcherless.enabled = false;
    c.dispatcherless.probability = 0;
    c.dispatcherless.max_routes = 0;
    c.dispatcherless.max_terms = 0;

    c.vec.enabled = false;
    c.csm.enabled = false;
    c.flatten.enabled = false;
    c.indir_branch.enabled = false;
    c.func_wrap.enabled = false;
    c.fco.enabled = false;
    c.anti_hook.enabled = false;
    c.anti_dbg.enabled = false;
    c.anti_class_dump.enabled = false;
    return c;
}

PassConfig makeMid() {
    PassConfig c;
    c.bcf.enabled = true;
    c.bcf.probability = 60;
    c.bcf.iterations = 1;
    c.bcf.complexity = 4;
    c.bcf.entropy_chain = false;
    c.bcf.junk_asm = false;
    c.bcf.junk_asm_min = 2;
    c.bcf.junk_asm_max = 4;

    c.sub.enabled = true;
    c.sub.probability = 60;
    c.sub.iterations = 1;

    c.mba.enabled = true;
    c.mba.probability = 50;
    c.mba.layers = 2;
    c.mba.heuristic = true;

    c.str_enc.enabled = true;
    c.str_enc.probability = 100;

    c.const_enc.enabled = true;
    c.const_enc.iterations = 1;
    c.const_enc.share_count = 3;
    c.const_enc.feistel = false;
    c.const_enc.substitute_xor = true;
    c.const_enc.substitute_xor_prob = 40;
    c.const_enc.globalize = false;
    c.const_enc.globalize_prob = 50;

    c.split.enabled = true;
    c.split.splits = 3;
    c.split.stack_confusion = true;

    c.stack_coalesce.enabled = true;
    c.stack_coalesce.probability = 60;
    c.stack_coalesce.opaque_offsets = true;

    c.pointer_launder.enabled = true;
    c.pointer_launder.pointer_probability = 50;
    c.pointer_launder.integer_probability = 25;

    c.type_pun.enabled = true;
    c.type_pun.probability = 30;
    c.type_pun.include_floating = true;
    c.type_pun.max_targets = 16;

    c.phi_tangle.enabled = true;
    c.phi_tangle.probability = 45;
    c.phi_tangle.layers = 1;
    c.phi_tangle.max_phis = 12;

    c.alias_op.enabled = true;
    c.alias_op.probability = 35;
    c.alias_op.iterations = 1;
    c.alias_op.max_blocks = 6;

    c.coherent_decoy.enabled = true;
    c.coherent_decoy.probability = 35;
    c.coherent_decoy.max_blocks = 4;
    c.coherent_decoy.depth = 3;

    c.data_entangled_flatten.enabled = true;
    c.data_entangled_flatten.max_terms = 3;

    c.non_invertible_state.enabled = true;
    c.non_invertible_state.max_terms = 3;
    c.non_invertible_state.rounds = 2;

    c.state_opaque.enabled = true;
    c.state_opaque.probability = 45;
    c.state_opaque.max_blocks = 12;
    c.state_opaque.max_terms = 3;

    c.interprocedural_fsm.enabled = true;
    c.interprocedural_fsm.probability = 50;
    c.interprocedural_fsm.max_sites = 16;
    c.interprocedural_fsm.max_terms = 3;

    c.opt_amplify.enabled = true;
    c.opt_amplify.probability = 10;
    c.opt_amplify.max_forms = 1;

    c.table_arith.enabled = true;
    c.table_arith.probability = 20;
    c.table_arith.max_tables = 2;

    c.sub_threshold.enabled = true;
    c.sub_threshold.probability = 15;
    c.sub_threshold.max_terms = 1;

    c.uniform_lower.enabled = true;
    c.uniform_lower.op_probability = 15;
    c.uniform_lower.branch_probability = 20;
    c.uniform_lower.max_tables = 2;
    c.uniform_lower.max_branches = 2;

    c.path_explosion.enabled = true;
    c.path_explosion.probability = 15;
    c.path_explosion.max_blocks = 2;
    c.path_explosion.max_iterations = 8;

    c.dispatcherless.enabled = true;
    c.dispatcherless.probability = 35;
    c.dispatcherless.max_routes = 8;
    c.dispatcherless.max_terms = 3;

    c.vec.enabled = true;
    c.vec.probability = 40;
    c.vec.width = 128;
    c.vec.shuffle = false;
    c.vec.lift_comparisons = true;

    c.csm.enabled = false;
    c.flatten.enabled = true;
    c.indir_branch.enabled = true;

    c.func_wrap.enabled = false;
    c.fco.enabled = false;
    c.anti_hook.enabled = false;
    c.anti_dbg.enabled = false;
    c.anti_class_dump.enabled = false;
    return c;
}

PassConfig makeHigh() {
    PassConfig c;
    c.bcf.enabled = true;
    c.bcf.probability = 75;
    c.bcf.iterations = 2;
    c.bcf.complexity = 6;
    c.bcf.entropy_chain = true;
    c.bcf.junk_asm = true;
    c.bcf.junk_asm_min = 2;
    c.bcf.junk_asm_max = 4;

    c.sub.enabled = true;
    c.sub.probability = 80;
    c.sub.iterations = 2;

    c.mba.enabled = true;
    c.mba.probability = 70;
    c.mba.layers = 3;
    c.mba.heuristic = true;

    c.str_enc.enabled = true;
    c.str_enc.probability = 100;

    c.const_enc.enabled = true;
    c.const_enc.iterations = 2;
    c.const_enc.share_count = 4;
    c.const_enc.feistel = true;
    c.const_enc.substitute_xor = true;
    c.const_enc.substitute_xor_prob = 60;
    c.const_enc.globalize = false;
    c.const_enc.globalize_prob = 50;

    c.split.enabled = true;
    c.split.splits = 5;
    c.split.stack_confusion = true;

    c.stack_coalesce.enabled = true;
    c.stack_coalesce.probability = 100;
    c.stack_coalesce.opaque_offsets = true;

    c.pointer_launder.enabled = true;
    c.pointer_launder.pointer_probability = 90;
    c.pointer_launder.integer_probability = 45;

    c.type_pun.enabled = true;
    c.type_pun.probability = 60;
    c.type_pun.include_floating = true;
    c.type_pun.max_targets = 32;

    c.phi_tangle.enabled = true;
    c.phi_tangle.probability = 80;
    c.phi_tangle.layers = 2;
    c.phi_tangle.max_phis = 24;

    c.alias_op.enabled = true;
    c.alias_op.probability = 65;
    c.alias_op.iterations = 2;
    c.alias_op.max_blocks = 10;

    c.coherent_decoy.enabled = true;
    c.coherent_decoy.probability = 70;
    c.coherent_decoy.max_blocks = 8;
    c.coherent_decoy.depth = 5;

    c.data_entangled_flatten.enabled = true;
    c.data_entangled_flatten.max_terms = 5;

    c.non_invertible_state.enabled = true;
    c.non_invertible_state.max_terms = 5;
    c.non_invertible_state.rounds = 4;

    c.state_opaque.enabled = true;
    c.state_opaque.probability = 80;
    c.state_opaque.max_blocks = 32;
    c.state_opaque.max_terms = 5;

    c.interprocedural_fsm.enabled = true;
    c.interprocedural_fsm.probability = 100;
    c.interprocedural_fsm.max_sites = 64;
    c.interprocedural_fsm.max_terms = 5;

    c.opt_amplify.enabled = true;
    c.opt_amplify.probability = 20;
    c.opt_amplify.max_forms = 2;

    c.table_arith.enabled = true;
    c.table_arith.probability = 35;
    c.table_arith.max_tables = 4;

    c.sub_threshold.enabled = true;
    c.sub_threshold.probability = 15;
    c.sub_threshold.max_terms = 1;

    c.uniform_lower.enabled = true;
    c.uniform_lower.op_probability = 15;
    c.uniform_lower.branch_probability = 10;
    c.uniform_lower.max_tables = 2;
    c.uniform_lower.max_branches = 1;

    c.path_explosion.enabled = true;
    c.path_explosion.probability = 35;
    c.path_explosion.max_blocks = 4;
    c.path_explosion.max_iterations = 16;

    c.dispatcherless.enabled = true;
    c.dispatcherless.probability = 75;
    c.dispatcherless.max_routes = 24;
    c.dispatcherless.max_terms = 5;

    c.vec.enabled = true;
    c.vec.probability = 65;
    c.vec.width = 256;
    c.vec.shuffle = true;
    c.vec.lift_comparisons = true;

    c.csm.enabled = true;
    c.csm.nested_dispatch = false;
    c.csm.warmup = 128;
    c.flatten.enabled = false;

    c.indir_branch.enabled = true;

    c.func_wrap.enabled = true;
    c.func_wrap.probability = 50;
    c.func_wrap.times = 1;

    c.fco.enabled = true;

    c.anti_hook.enabled = false;
    c.anti_dbg.enabled = false;
    c.anti_class_dump.enabled = false;
    return c;
}

} // namespace

PassConfig presetConfig(Preset p) {
    switch (p) {
    case Preset::Low:
        return makeLow();
    case Preset::Mid:
        return makeMid();
    case Preset::High:
        return makeHigh();
    case Preset::None:
        break;
    }
    return {};
}

} // namespace morok::config
