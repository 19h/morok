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
    // Stack pointer delta games
    mergeOpt(dst.stack_delta.enabled, src.stack_delta.enabled);
    mergeOpt(dst.stack_delta.probability, src.stack_delta.probability);
    mergeOpt(dst.stack_delta.max_blocks, src.stack_delta.max_blocks);
    mergeOpt(dst.stack_delta.min_bytes, src.stack_delta.min_bytes);
    mergeOpt(dst.stack_delta.max_extra_bytes, src.stack_delta.max_extra_bytes);
    mergeOpt(dst.stack_delta.touches, src.stack_delta.touches);
    // Persistent stack-frame rebasing pressure
    mergeOpt(dst.stack_rebase.enabled, src.stack_rebase.enabled);
    mergeOpt(dst.stack_rebase.realign_align, src.stack_rebase.realign_align);
    mergeOpt(dst.stack_rebase.dynamic_size, src.stack_rebase.dynamic_size);
    mergeOpt(dst.stack_rebase.relocate_probability,
             src.stack_rebase.relocate_probability);
    mergeOpt(dst.stack_rebase.alias_amplify, src.stack_rebase.alias_amplify);
    mergeOpt(dst.stack_rebase.nonentry_shuffle,
             src.stack_rebase.nonentry_shuffle);
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
    // External/volatile-derived opaque predicates
    mergeOpt(dst.external_op.enabled, src.external_op.enabled);
    mergeOpt(dst.external_op.probability, src.external_op.probability);
    mergeOpt(dst.external_op.max_blocks, src.external_op.max_blocks);
    mergeOpt(dst.external_op.decoy_stores, src.external_op.decoy_stores);
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
    mergeOpt(dst.interprocedural_fsm.enabled, src.interprocedural_fsm.enabled);
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
    mergeOpt(dst.hash_self_decrypt.max_payload_bytes,
             src.hash_self_decrypt.max_payload_bytes);
    mergeOpt(dst.hash_self_decrypt.context_keying,
             src.hash_self_decrypt.context_keying);
    // Fault-paged VM bytecode delivery
    mergeOpt(dst.fault_paged_payload.enabled,
             src.fault_paged_payload.enabled);
    mergeOpt(dst.fault_paged_payload.probability,
             src.fault_paged_payload.probability);
    mergeOpt(dst.fault_paged_payload.max_payloads,
             src.fault_paged_payload.max_payloads);
    mergeOpt(dst.fault_paged_payload.max_payload_bytes,
             src.fault_paged_payload.max_payload_bytes);
    mergeOpt(dst.fault_paged_payload.page_size,
             src.fault_paged_payload.page_size);
    mergeOpt(dst.fault_paged_payload.delivery,
             src.fault_paged_payload.delivery);
    mergeOpt(dst.fault_paged_payload.backend,
             src.fault_paged_payload.backend);
    mergeOpt(dst.fault_paged_payload.per_page_keys,
             src.fault_paged_payload.per_page_keys);
    mergeOpt(dst.fault_paged_payload.reseal_after_use,
             src.fault_paged_payload.reseal_after_use);
    mergeOpt(dst.fault_paged_payload.decoy_pages,
             src.fault_paged_payload.decoy_pages);
    mergeOpt(dst.fault_paged_payload.fallback,
             src.fault_paged_payload.fallback);
    mergeOpt(dst.fault_paged_payload.bind_to_runtime_seal,
             src.fault_paged_payload.bind_to_runtime_seal);
    mergeOpt(dst.fault_paged_payload.virtualize_helpers,
             src.fault_paged_payload.virtualize_helpers);
    // External proof/license binding
    mergeOpt(dst.external_secret_binding.enabled,
             src.external_secret_binding.enabled);
    mergeOpt(dst.external_secret_binding.mode,
             src.external_secret_binding.mode);
    mergeOpt(dst.external_secret_binding.public_key,
             src.external_secret_binding.public_key);
    mergeOpt(dst.external_secret_binding.expected_digest,
             src.external_secret_binding.expected_digest);
    mergeOpt(dst.external_secret_binding.identity_policy,
             src.external_secret_binding.identity_policy);
    mergeOpt(dst.external_secret_binding.entitlement_gate,
             src.external_secret_binding.entitlement_gate);
    mergeOpt(dst.external_secret_binding.entitlement_required_mask,
             src.external_secret_binding.entitlement_required_mask);
    mergeOpt(dst.external_secret_binding.entitlement_not_before_epoch,
             src.external_secret_binding.entitlement_not_before_epoch);
    mergeOpt(dst.external_secret_binding.entitlement_not_after_epoch,
             src.external_secret_binding.entitlement_not_after_epoch);
    mergeOpt(dst.external_secret_binding.bind_to_runtime_seal,
             src.external_secret_binding.bind_to_runtime_seal);
    mergeOpt(dst.external_secret_binding.virtualize_helpers,
             src.external_secret_binding.virtualize_helpers);
    // Environment-bound host identity KDF
    mergeOpt(dst.env_binding_kdf.enabled, src.env_binding_kdf.enabled);
    mergeOpt(dst.env_binding_kdf.mode, src.env_binding_kdf.mode);
    mergeOpt(dst.env_binding_kdf.expected_digest,
             src.env_binding_kdf.expected_digest);
    mergeOpt(dst.env_binding_kdf.identity_policy,
             src.env_binding_kdf.identity_policy);
    mergeOpt(dst.env_binding_kdf.min_factors,
             src.env_binding_kdf.min_factors);
    mergeOpt(dst.env_binding_kdf.bind_to_runtime_seal,
             src.env_binding_kdf.bind_to_runtime_seal);
    mergeOpt(dst.env_binding_kdf.virtualize_helpers,
             src.env_binding_kdf.virtualize_helpers);
    // Tracer attestation
    mergeOpt(dst.tracer_attestation.enabled, src.tracer_attestation.enabled);
    mergeOpt(dst.tracer_attestation.mode, src.tracer_attestation.mode);
    mergeOpt(dst.tracer_attestation.shares, src.tracer_attestation.shares);
    mergeOpt(dst.tracer_attestation.renewal, src.tracer_attestation.renewal);
    mergeOpt(dst.tracer_attestation.bind_to_runtime_seal,
             src.tracer_attestation.bind_to_runtime_seal);
    mergeOpt(dst.tracer_attestation.virtualize_helpers,
             src.tracer_attestation.virtualize_helpers);
    // General sealed byte blobs
    mergeOpt(dst.sealed_blob.enabled, src.sealed_blob.enabled);
    mergeOpt(dst.sealed_blob.max_blobs, src.sealed_blob.max_blobs);
    mergeOpt(dst.sealed_blob.max_blob_bytes, src.sealed_blob.max_blob_bytes);
    mergeVec(dst.sealed_blob.key_sources, src.sealed_blob.key_sources);
    mergeOpt(dst.sealed_blob.delivery, src.sealed_blob.delivery);
    mergeOpt(dst.sealed_blob.zeroize_after_use,
             src.sealed_blob.zeroize_after_use);
    mergeOpt(dst.sealed_blob.runtime_keyed_magic,
             src.sealed_blob.runtime_keyed_magic);
    mergeOpt(dst.sealed_blob.magic_bytes, src.sealed_blob.magic_bytes);
    // Self-checksum-fused constants
    mergeOpt(dst.self_checksum.enabled, src.self_checksum.enabled);
    mergeOpt(dst.self_checksum.probability, src.self_checksum.probability);
    mergeOpt(dst.self_checksum.max_constants, src.self_checksum.max_constants);
    mergeOpt(dst.self_checksum.region_bytes, src.self_checksum.region_bytes);
    mergeOpt(dst.self_checksum.diff_cache, src.self_checksum.diff_cache);
    // Data-flow-entangled integrity
    mergeOpt(dst.data_flow_integrity.enabled, src.data_flow_integrity.enabled);
    mergeOpt(dst.data_flow_integrity.probability,
             src.data_flow_integrity.probability);
    mergeOpt(dst.data_flow_integrity.max_tables,
             src.data_flow_integrity.max_tables);
    mergeOpt(dst.data_flow_integrity.region_bytes,
             src.data_flow_integrity.region_bytes);
    // Mutual guard graph
    mergeOpt(dst.mutual_guard.enabled, src.mutual_guard.enabled);
    mergeOpt(dst.mutual_guard.probability, src.mutual_guard.probability);
    mergeOpt(dst.mutual_guard.nodes, src.mutual_guard.nodes);
    mergeOpt(dst.mutual_guard.region_bytes, src.mutual_guard.region_bytes);
    mergeOpt(dst.mutual_guard.max_returns, src.mutual_guard.max_returns);
    // Shamir threshold sharing
    mergeOpt(dst.shamir_share.enabled, src.shamir_share.enabled);
    mergeOpt(dst.shamir_share.probability, src.shamir_share.probability);
    mergeOpt(dst.shamir_share.threshold, src.shamir_share.threshold);
    mergeOpt(dst.shamir_share.shares, src.shamir_share.shares);
    mergeOpt(dst.shamir_share.max_secrets, src.shamir_share.max_secrets);
    // Multivariate-quadratic gate
    mergeOpt(dst.mq_gate.enabled, src.mq_gate.enabled);
    mergeOpt(dst.mq_gate.probability, src.mq_gate.probability);
    mergeOpt(dst.mq_gate.vars, src.mq_gate.vars);
    mergeOpt(dst.mq_gate.eqs, src.mq_gate.eqs);
    mergeOpt(dst.mq_gate.density, src.mq_gate.density);
    mergeOpt(dst.mq_gate.max_gates, src.mq_gate.max_gates);
    mergeOpt(dst.mq_gate.fold_diff, src.mq_gate.fold_diff);
    // Adversarial function merging + outlining
    mergeOpt(dst.adversarial_merge.enabled, src.adversarial_merge.enabled);
    mergeOpt(dst.adversarial_merge.probability,
             src.adversarial_merge.probability);
    mergeOpt(dst.adversarial_merge.max_groups,
             src.adversarial_merge.max_groups);
    mergeOpt(dst.adversarial_merge.max_functions,
             src.adversarial_merge.max_functions);
    mergeOpt(dst.adversarial_merge.outline_probability,
             src.adversarial_merge.outline_probability);
    mergeOpt(dst.adversarial_merge.max_outlines,
             src.adversarial_merge.max_outlines);
    // Adversarial self-tuning
    mergeOpt(dst.adversarial_tuning.enabled, src.adversarial_tuning.enabled);
    mergeOpt(dst.adversarial_tuning.max_candidates,
             src.adversarial_tuning.max_candidates);
    mergeOpt(dst.adversarial_tuning.max_candidate_passes,
             src.adversarial_tuning.max_candidate_passes);
    mergeOpt(dst.adversarial_tuning.score_floor,
             src.adversarial_tuning.score_floor);
    mergeOpt(dst.adversarial_tuning.emit_marker,
             src.adversarial_tuning.emit_marker);
    // Per-build polymorphism
    mergeOpt(dst.per_build_polymorphism.enabled,
             src.per_build_polymorphism.enabled);
    mergeOpt(dst.per_build_polymorphism.function_order,
             src.per_build_polymorphism.function_order);
    mergeOpt(dst.per_build_polymorphism.block_order,
             src.per_build_polymorphism.block_order);
    mergeOpt(dst.per_build_polymorphism.anchor_probability,
             src.per_build_polymorphism.anchor_probability);
    mergeOpt(dst.per_build_polymorphism.max_anchors,
             src.per_build_polymorphism.max_anchors);
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
    // Microcode optimizer stress
    mergeOpt(dst.microcode_stress.enabled, src.microcode_stress.enabled);
    mergeOpt(dst.microcode_stress.probability,
             src.microcode_stress.probability);
    mergeOpt(dst.microcode_stress.max_sites, src.microcode_stress.max_sites);
    mergeOpt(dst.microcode_stress.table_entries,
             src.microcode_stress.table_entries);
    mergeOpt(dst.microcode_stress.decoy_blocks,
             src.microcode_stress.decoy_blocks);
    mergeOpt(dst.microcode_stress.alias_stores,
             src.microcode_stress.alias_stores);
    // Caller-keyed indirect call dispatch
    mergeOpt(dst.caller_keyed_dispatch.enabled,
             src.caller_keyed_dispatch.enabled);
    mergeOpt(dst.caller_keyed_dispatch.probability,
             src.caller_keyed_dispatch.probability);
    mergeOpt(dst.caller_keyed_dispatch.max_calls,
             src.caller_keyed_dispatch.max_calls);
    mergeOpt(dst.caller_keyed_dispatch.region_bytes,
             src.caller_keyed_dispatch.region_bytes);
    mergeOpt(dst.caller_keyed_dispatch.seal_required,
             src.caller_keyed_dispatch.seal_required);
    mergeOpt(dst.caller_keyed_dispatch.carriers,
             src.caller_keyed_dispatch.carriers);
    mergeOpt(dst.returnless_dispatch.enabled,
             src.returnless_dispatch.enabled);
    mergeOpt(dst.returnless_dispatch.probability,
             src.returnless_dispatch.probability);
    mergeOpt(dst.returnless_dispatch.max_sites,
             src.returnless_dispatch.max_sites);
    mergeOpt(dst.function_fission.enabled, src.function_fission.enabled);
    mergeOpt(dst.function_fission.probability,
             src.function_fission.probability);
    mergeOpt(dst.function_fission.max_splits, src.function_fission.max_splits);
    mergeOpt(dst.function_fission.min_region_blocks,
             src.function_fission.min_region_blocks);
    mergeOpt(dst.function_fission.max_region_blocks,
             src.function_fission.max_region_blocks);
    // Trap-mediated branch nanomites
    mergeOpt(dst.nanomites.enabled, src.nanomites.enabled);
    mergeOpt(dst.nanomites.probability, src.nanomites.probability);
    mergeOpt(dst.nanomites.max_sites, src.nanomites.max_sites);
    // Mirage counterfeit-computation substrate
    mergeOpt(dst.mirage.enabled, src.mirage.enabled);
    mergeOpt(dst.mirage.sensitive_only, src.mirage.sensitive_only);
    mergeOpt(dst.mirage.clone_count, src.mirage.clone_count);
    mergeOpt(dst.mirage.counterfeit_count, src.mirage.counterfeit_count);
    mergeOpt(dst.mirage.max_functions, src.mirage.max_functions);
    mergeOpt(dst.mirage.max_instructions, src.mirage.max_instructions);
    mergeVec(dst.mirage.counterfeit_domains, src.mirage.counterfeit_domains);
    mergeOpt(dst.mirage.seal_gated_reality, src.mirage.seal_gated_reality);
    mergeOpt(dst.mirage.per_invocation_epoch, src.mirage.per_invocation_epoch);
    mergeOpt(dst.mirage.cross_guard, src.mirage.cross_guard);
    mergeOpt(dst.mirage.force_route, src.mirage.force_route);
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
    mergeOpt(dst.csm.generator, src.csm.generator);
    mergeOpt(dst.csm.tf_const, src.csm.tf_const);
    mergeOpt(dst.csm.nested_dispatch, src.csm.nested_dispatch);
    mergeOpt(dst.csm.warmup, src.csm.warmup);
    // Toggles
    mergeOpt(dst.flatten.enabled, src.flatten.enabled);
    mergeOpt(dst.indir_branch.enabled, src.indir_branch.enabled);
    mergeOpt(dst.fco.enabled, src.fco.enabled);
    mergeOpt(dst.anti_hook.enabled, src.anti_hook.enabled);
    mergeOpt(dst.anti_dbg.enabled, src.anti_dbg.enabled);
    mergeOpt(dst.anti_dbg.allow_self_trace, src.anti_dbg.allow_self_trace);
    mergeOpt(dst.anti_dbg.distribution_signed,
             src.anti_dbg.distribution_signed);
    mergeOpt(dst.anti_class_dump.enabled, src.anti_class_dump.enabled);
    mergeOpt(dst.windows_pe_foundation.enabled,
             src.windows_pe_foundation.enabled);
    mergeOpt(dst.windows_peb_heap_debug.enabled,
             src.windows_peb_heap_debug.enabled);
    mergeOpt(dst.windows_debug_object.enabled,
             src.windows_debug_object.enabled);
    mergeOpt(dst.windows_thread_hide.enabled, src.windows_thread_hide.enabled);
    mergeOpt(dst.windows_anti_attach.enabled, src.windows_anti_attach.enabled);
    mergeOpt(dst.windows_kernel_debugger.enabled,
             src.windows_kernel_debugger.enabled);
    mergeOpt(dst.windows_syscalls.enabled, src.windows_syscalls.enabled);
    mergeOpt(dst.windows_process_modules.enabled,
             src.windows_process_modules.enabled);
    mergeOpt(dst.platform_runtime.enabled, src.platform_runtime.enabled);
    mergeOpt(dst.platform_runtime.direct_syscalls,
             src.platform_runtime.direct_syscalls);
    mergeOpt(dst.platform_runtime.windows_mode,
             src.platform_runtime.windows_mode);
    mergeOpt(dst.platform_runtime.per_build_stubs,
             src.platform_runtime.per_build_stubs);
    mergeOpt(dst.platform_runtime.minimize_imports,
             src.platform_runtime.minimize_imports);
    mergeOpt(dst.platform_runtime.import_table_audit,
             src.platform_runtime.import_table_audit);
    mergeOpt(dst.platform_runtime.static_link_expected,
             src.platform_runtime.static_link_expected);
    mergeOpt(dst.windows_unhook.enabled, src.windows_unhook.enabled);
    mergeOpt(dst.windows_veh_audit.enabled, src.windows_veh_audit.enabled);
    mergeOpt(dst.windows_process_mitigations.enabled,
             src.windows_process_mitigations.enabled);
    mergeOpt(dst.timing_oracles.enabled, src.timing_oracles.enabled);
    mergeOpt(dst.scheduler_step_oracles.enabled,
             src.scheduler_step_oracles.enabled);
    mergeOpt(dst.trap_oracles.enabled, src.trap_oracles.enabled);
    mergeOpt(dst.page_fault_oracles.enabled, src.page_fault_oracles.enabled);
    mergeOpt(dst.cache_timing_oracles.enabled,
             src.cache_timing_oracles.enabled);
    mergeOpt(dst.microarchitectural_canaries.enabled,
             src.microarchitectural_canaries.enabled);
    mergeOpt(dst.decoy_strings.enabled, src.decoy_strings.enabled);
    mergeOpt(dst.vtable_integrity.enabled, src.vtable_integrity.enabled);
    // FuncWrap
    mergeOpt(dst.func_wrap.enabled, src.func_wrap.enabled);
    mergeOpt(dst.func_wrap.probability, src.func_wrap.probability);
    mergeOpt(dst.func_wrap.times, src.func_wrap.times);
    mergeOpt(dst.fail_closed_on_unsealed, src.fail_closed_on_unsealed);
}

PassConfig resolve(const Config &cfg, std::string_view module_name,
                   std::string_view func_name, const Demangler &demangle) {
    // Fast path: with no policy rules the effective config is exactly the base
    // config, and the demangle is only consumed by policy matching.  Skip the
    // per-function demangle and policy scan entirely.
    if (cfg.policies.empty())
        return cfg.passes;

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
