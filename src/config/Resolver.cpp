// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/config/Resolver.cpp — merge and policy resolution.

#include "morok/config/Resolver.hpp"

#include <regex>
#include <string>

namespace morok::config {

namespace {

// Copy a set optional from src to dst.
template <class T> void mergeOpt(Opt<T> &dst, const Opt<T> &src) {
    if (src.has_value())
        dst = src;
}
// Replace dst with src when src is non-empty.
void mergeVec(std::vector<std::string> &dst,
              const std::vector<std::string> &src) {
    if (!src.empty())
        dst = src;
}

// Match `text` against an ECMAScript regex; invalid patterns never throw out.
bool regexSearch(const std::string &pattern, const std::string &text) {
    try {
        std::regex re(pattern, std::regex::ECMAScript | std::regex::optimize);
        return std::regex_search(text, re);
    } catch (const std::regex_error &) {
        return false;
    }
}

} // namespace

void merge(PassConfig &dst, const PassConfig &src) {
    // BCF
    mergeOpt(dst.bcf.enabled, src.bcf.enabled);
    mergeOpt(dst.bcf.probability, src.bcf.probability);
    mergeOpt(dst.bcf.iterations, src.bcf.iterations);
    mergeOpt(dst.bcf.complexity, src.bcf.complexity);
    mergeOpt(dst.bcf.entropy_chain, src.bcf.entropy_chain);
    mergeOpt(dst.bcf.junk_asm, src.bcf.junk_asm);
    mergeOpt(dst.bcf.junk_asm_min, src.bcf.junk_asm_min);
    mergeOpt(dst.bcf.junk_asm_max, src.bcf.junk_asm_max);
    // Sub
    mergeOpt(dst.sub.enabled, src.sub.enabled);
    mergeOpt(dst.sub.probability, src.sub.probability);
    mergeOpt(dst.sub.iterations, src.sub.iterations);
    // MBA
    mergeOpt(dst.mba.enabled, src.mba.enabled);
    mergeOpt(dst.mba.probability, src.mba.probability);
    mergeOpt(dst.mba.layers, src.mba.layers);
    mergeOpt(dst.mba.heuristic, src.mba.heuristic);
    // Split
    mergeOpt(dst.split.enabled, src.split.enabled);
    mergeOpt(dst.split.splits, src.split.splits);
    mergeOpt(dst.split.stack_confusion, src.split.stack_confusion);
    // Stack coalescing
    mergeOpt(dst.stack_coalesce.enabled, src.stack_coalesce.enabled);
    mergeOpt(dst.stack_coalesce.probability, src.stack_coalesce.probability);
    mergeOpt(dst.stack_coalesce.opaque_offsets,
             src.stack_coalesce.opaque_offsets);
    // Pointer laundering
    mergeOpt(dst.pointer_launder.enabled, src.pointer_launder.enabled);
    mergeOpt(dst.pointer_launder.pointer_probability,
             src.pointer_launder.pointer_probability);
    mergeOpt(dst.pointer_launder.integer_probability,
             src.pointer_launder.integer_probability);
    // Type punning
    mergeOpt(dst.type_pun.enabled, src.type_pun.enabled);
    mergeOpt(dst.type_pun.probability, src.type_pun.probability);
    mergeOpt(dst.type_pun.include_floating, src.type_pun.include_floating);
    mergeOpt(dst.type_pun.max_targets, src.type_pun.max_targets);
    // Phi tangling
    mergeOpt(dst.phi_tangle.enabled, src.phi_tangle.enabled);
    mergeOpt(dst.phi_tangle.probability, src.phi_tangle.probability);
    mergeOpt(dst.phi_tangle.layers, src.phi_tangle.layers);
    mergeOpt(dst.phi_tangle.max_phis, src.phi_tangle.max_phis);
    // Alias opaque predicates
    mergeOpt(dst.alias_op.enabled, src.alias_op.enabled);
    mergeOpt(dst.alias_op.probability, src.alias_op.probability);
    mergeOpt(dst.alias_op.iterations, src.alias_op.iterations);
    mergeOpt(dst.alias_op.max_blocks, src.alias_op.max_blocks);
    // Coherent decoy dead paths
    mergeOpt(dst.coherent_decoy.enabled, src.coherent_decoy.enabled);
    mergeOpt(dst.coherent_decoy.probability, src.coherent_decoy.probability);
    mergeOpt(dst.coherent_decoy.max_blocks, src.coherent_decoy.max_blocks);
    mergeOpt(dst.coherent_decoy.depth, src.coherent_decoy.depth);
    // Data-entangled flattening
    mergeOpt(dst.data_entangled_flatten.enabled,
             src.data_entangled_flatten.enabled);
    mergeOpt(dst.data_entangled_flatten.max_terms,
             src.data_entangled_flatten.max_terms);
    // Non-invertible state flattening
    mergeOpt(dst.non_invertible_state.enabled,
             src.non_invertible_state.enabled);
    mergeOpt(dst.non_invertible_state.max_terms,
             src.non_invertible_state.max_terms);
    mergeOpt(dst.non_invertible_state.rounds, src.non_invertible_state.rounds);
    // Stateful MBA opaque predicates
    mergeOpt(dst.state_opaque.enabled, src.state_opaque.enabled);
    mergeOpt(dst.state_opaque.probability, src.state_opaque.probability);
    mergeOpt(dst.state_opaque.max_blocks, src.state_opaque.max_blocks);
    mergeOpt(dst.state_opaque.max_terms, src.state_opaque.max_terms);
    // Interprocedural FSM splitting
    mergeOpt(dst.interprocedural_fsm.enabled,
             src.interprocedural_fsm.enabled);
    mergeOpt(dst.interprocedural_fsm.probability,
             src.interprocedural_fsm.probability);
    mergeOpt(dst.interprocedural_fsm.max_sites,
             src.interprocedural_fsm.max_sites);
    mergeOpt(dst.interprocedural_fsm.max_terms,
             src.interprocedural_fsm.max_terms);
    // Optimizer amplification
    mergeOpt(dst.opt_amplify.enabled, src.opt_amplify.enabled);
    mergeOpt(dst.opt_amplify.probability, src.opt_amplify.probability);
    mergeOpt(dst.opt_amplify.max_forms, src.opt_amplify.max_forms);
    // Table arithmetic
    mergeOpt(dst.table_arith.enabled, src.table_arith.enabled);
    mergeOpt(dst.table_arith.probability, src.table_arith.probability);
    mergeOpt(dst.table_arith.max_tables, src.table_arith.max_tables);
    // Sub-threshold persistence
    mergeOpt(dst.sub_threshold.enabled, src.sub_threshold.enabled);
    mergeOpt(dst.sub_threshold.probability, src.sub_threshold.probability);
    mergeOpt(dst.sub_threshold.max_terms, src.sub_threshold.max_terms);
    // Uniform primitive lowering
    mergeOpt(dst.uniform_lower.enabled, src.uniform_lower.enabled);
    mergeOpt(dst.uniform_lower.op_probability,
             src.uniform_lower.op_probability);
    mergeOpt(dst.uniform_lower.branch_probability,
             src.uniform_lower.branch_probability);
    mergeOpt(dst.uniform_lower.max_tables, src.uniform_lower.max_tables);
    mergeOpt(dst.uniform_lower.max_branches, src.uniform_lower.max_branches);
    // Virtualization
    mergeOpt(dst.virtualization.enabled, src.virtualization.enabled);
    mergeOpt(dst.virtualization.probability, src.virtualization.probability);
    mergeOpt(dst.virtualization.max_functions,
             src.virtualization.max_functions);
    mergeOpt(dst.virtualization.max_instructions,
             src.virtualization.max_instructions);
    mergeOpt(dst.virtualization.max_registers,
             src.virtualization.max_registers);
    // Hash-gated VM bytecode self-decrypt
    mergeOpt(dst.hash_self_decrypt.enabled, src.hash_self_decrypt.enabled);
    mergeOpt(dst.hash_self_decrypt.probability,
             src.hash_self_decrypt.probability);
    mergeOpt(dst.hash_self_decrypt.max_payloads,
             src.hash_self_decrypt.max_payloads);
    // Path explosion
    mergeOpt(dst.path_explosion.enabled, src.path_explosion.enabled);
    mergeOpt(dst.path_explosion.probability, src.path_explosion.probability);
    mergeOpt(dst.path_explosion.max_blocks, src.path_explosion.max_blocks);
    mergeOpt(dst.path_explosion.max_iterations,
             src.path_explosion.max_iterations);
    // Execution-trace keying
    mergeOpt(dst.trace_keying.enabled, src.trace_keying.enabled);
    mergeOpt(dst.trace_keying.probability, src.trace_keying.probability);
    mergeOpt(dst.trace_keying.max_blocks, src.trace_keying.max_blocks);
    // Dispatcherless routing
    mergeOpt(dst.dispatcherless.enabled, src.dispatcherless.enabled);
    mergeOpt(dst.dispatcherless.probability, src.dispatcherless.probability);
    mergeOpt(dst.dispatcherless.max_routes, src.dispatcherless.max_routes);
    mergeOpt(dst.dispatcherless.max_terms, src.dispatcherless.max_terms);
    // StrEnc
    mergeOpt(dst.str_enc.enabled, src.str_enc.enabled);
    mergeOpt(dst.str_enc.probability, src.str_enc.probability);
    mergeVec(dst.str_enc.skip_content, src.str_enc.skip_content);
    mergeVec(dst.str_enc.force_content, src.str_enc.force_content);
    // ConstEnc
    mergeOpt(dst.const_enc.enabled, src.const_enc.enabled);
    mergeOpt(dst.const_enc.iterations, src.const_enc.iterations);
    mergeOpt(dst.const_enc.share_count, src.const_enc.share_count);
    mergeOpt(dst.const_enc.feistel, src.const_enc.feistel);
    mergeOpt(dst.const_enc.substitute_xor, src.const_enc.substitute_xor);
    mergeOpt(dst.const_enc.substitute_xor_prob,
             src.const_enc.substitute_xor_prob);
    mergeOpt(dst.const_enc.globalize, src.const_enc.globalize);
    mergeOpt(dst.const_enc.globalize_prob, src.const_enc.globalize_prob);
    mergeVec(dst.const_enc.skip_value, src.const_enc.skip_value);
    mergeVec(dst.const_enc.force_value, src.const_enc.force_value);
    // Vec
    mergeOpt(dst.vec.enabled, src.vec.enabled);
    mergeOpt(dst.vec.probability, src.vec.probability);
    mergeOpt(dst.vec.width, src.vec.width);
    mergeOpt(dst.vec.shuffle, src.vec.shuffle);
    mergeOpt(dst.vec.lift_comparisons, src.vec.lift_comparisons);
    // CSM
    mergeOpt(dst.csm.enabled, src.csm.enabled);
    mergeOpt(dst.csm.nested_dispatch, src.csm.nested_dispatch);
    mergeOpt(dst.csm.warmup, src.csm.warmup);
    // Toggles
    mergeOpt(dst.flatten.enabled, src.flatten.enabled);
    mergeOpt(dst.indir_branch.enabled, src.indir_branch.enabled);
    mergeOpt(dst.fco.enabled, src.fco.enabled);
    mergeOpt(dst.anti_hook.enabled, src.anti_hook.enabled);
    mergeOpt(dst.anti_dbg.enabled, src.anti_dbg.enabled);
    mergeOpt(dst.anti_class_dump.enabled, src.anti_class_dump.enabled);
    // FuncWrap
    mergeOpt(dst.func_wrap.enabled, src.func_wrap.enabled);
    mergeOpt(dst.func_wrap.probability, src.func_wrap.probability);
    mergeOpt(dst.func_wrap.times, src.func_wrap.times);
}

PassConfig resolve(const Config &cfg, std::string_view module_name,
                   std::string_view func_name, const Demangler &demangle) {
    PassConfig eff = cfg.passes;

    const std::string module_str(module_name);
    const std::string func_str(func_name);
    std::string demangled;
    if (cfg.demangle_names && demangle && !func_str.empty()) {
        std::string d = demangle(func_name);
        if (d != func_str)
            demangled = std::move(d);
    }

    for (const auto &pol : cfg.policies) {
        if (!regexSearch(pol.module_regex, module_str))
            continue;

        if (!pol.func_regex.empty()) {
            bool matched = regexSearch(pol.func_regex, func_str);
            if (!matched && !demangled.empty())
                matched = regexSearch(pol.func_regex, demangled);
            if (!matched)
                continue;
        }

        if (pol.preset != Preset::None)
            merge(eff, presetConfig(pol.preset));
        merge(eff, pol.overrides);
    }

    return eff;
}

} // namespace morok::config
