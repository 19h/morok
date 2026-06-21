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
    if (name == "max")
        return Preset::Max;
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
    case Preset::Max:
        return "max";
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

    c.split.enabled = true;
    c.split.splits = 2;
    c.split.stack_confusion = false;

    c.stack_coalesce.enabled = false;
    c.stack_coalesce.probability = 0;
    c.stack_coalesce.opaque_offsets = false;

    c.stack_delta.enabled = false;
    c.stack_delta.probability = 0;
    c.stack_delta.max_blocks = 0;
    c.stack_delta.min_bytes = 0;
    c.stack_delta.max_extra_bytes = 0;
    c.stack_delta.touches = 0;

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

    c.external_op.enabled = false;
    c.external_op.probability = 0;
    c.external_op.max_blocks = 0;
    c.external_op.decoy_stores = 0;

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

    c.virtualization.enabled = false;
    c.virtualization.probability = 0;
    c.virtualization.max_functions = 0;
    c.virtualization.max_instructions = 0;
    c.virtualization.max_registers = 0;

    c.hash_self_decrypt.enabled = false;
    c.hash_self_decrypt.probability = 0;
    c.hash_self_decrypt.max_payloads = 0;
    c.hash_self_decrypt.max_payload_bytes = 0;
    c.hash_self_decrypt.context_keying = false;

    c.fault_paged_payload.enabled = false;
    c.fault_paged_payload.probability = 0;
    c.fault_paged_payload.max_payloads = 0;
    c.fault_paged_payload.max_payload_bytes = 0;
    c.fault_paged_payload.page_size = 4096;
    c.fault_paged_payload.delivery = "lazy_accessor";
    c.fault_paged_payload.backend = "lazy_accessor";
    c.fault_paged_payload.per_page_keys = true;
    c.fault_paged_payload.reseal_after_use = true;
    c.fault_paged_payload.decoy_pages = 0;
    c.fault_paged_payload.fallback = true;
    c.fault_paged_payload.bind_to_runtime_seal = true;
    c.fault_paged_payload.virtualize_helpers = true;

    c.tracer_attestation.enabled = false;
    c.tracer_attestation.mode = "linux_ptrace";
    c.tracer_attestation.shares = 0;
    c.tracer_attestation.renewal = "startup";
    c.tracer_attestation.bind_to_runtime_seal = true;
    c.tracer_attestation.virtualize_helpers = true;
    c.sealed_blob.enabled = false;
    c.sealed_blob.max_blobs = 0;
    c.sealed_blob.max_blob_bytes = 0;
    c.sealed_blob.delivery = "eager";
    c.sealed_blob.zeroize_after_use = true;
    c.sealed_blob.runtime_keyed_magic = false;
    c.sealed_blob.magic_bytes = 0;

    c.self_checksum.enabled = false;
    c.self_checksum.probability = 0;
    c.self_checksum.max_constants = 0;
    c.self_checksum.region_bytes = 0;

    c.data_flow_integrity.enabled = false;
    c.data_flow_integrity.probability = 0;
    c.data_flow_integrity.max_tables = 0;
    c.data_flow_integrity.region_bytes = 0;

    c.mutual_guard.enabled = false;
    c.mutual_guard.probability = 0;
    c.mutual_guard.nodes = 0;
    c.mutual_guard.region_bytes = 0;
    c.mutual_guard.max_returns = 0;

    c.shamir_share.enabled = false;
    c.shamir_share.probability = 0;
    c.shamir_share.threshold = 0;
    c.shamir_share.shares = 0;
    c.shamir_share.max_secrets = 0;

    c.mq_gate.enabled = false;
    c.mq_gate.probability = 0;
    c.mq_gate.vars = 0;
    c.mq_gate.eqs = 0;
    c.mq_gate.density = 0;
    c.mq_gate.max_gates = 0;
    c.mq_gate.fold_diff = false;

    c.adversarial_merge.enabled = false;
    c.adversarial_merge.probability = 0;
    c.adversarial_merge.max_groups = 0;
    c.adversarial_merge.max_functions = 0;
    c.adversarial_merge.outline_probability = 0;
    c.adversarial_merge.max_outlines = 0;

    c.adversarial_tuning.enabled = false;
    c.adversarial_tuning.max_candidates = 0;
    c.adversarial_tuning.max_candidate_passes = 0;
    c.adversarial_tuning.score_floor = 0;
    c.adversarial_tuning.emit_marker = false;

    c.per_build_polymorphism.enabled = false;
    c.per_build_polymorphism.function_order = false;
    c.per_build_polymorphism.block_order = false;
    c.per_build_polymorphism.anchor_probability = 0;
    c.per_build_polymorphism.max_anchors = 0;

    c.path_explosion.enabled = false;
    c.path_explosion.probability = 0;
    c.path_explosion.max_blocks = 0;
    c.path_explosion.max_iterations = 0;

    c.trace_keying.enabled = false;
    c.trace_keying.probability = 0;
    c.trace_keying.max_blocks = 0;

    c.dispatcherless.enabled = false;
    c.dispatcherless.probability = 0;
    c.dispatcherless.max_routes = 0;
    c.dispatcherless.max_terms = 0;

    c.microcode_stress.enabled = false;
    c.microcode_stress.probability = 0;
    c.microcode_stress.max_sites = 0;
    c.microcode_stress.table_entries = 0;
    c.microcode_stress.decoy_blocks = 0;
    c.microcode_stress.alias_stores = 0;

    c.caller_keyed_dispatch.enabled = false;
    c.caller_keyed_dispatch.probability = 100;
    c.caller_keyed_dispatch.max_calls = 4096;
    c.caller_keyed_dispatch.region_bytes = 16;

    // Off in every preset for now: opt-in via [passes.returnless_dispatch] while
    // the tail-branch return rewrite is validated per platform (increment 1).
    c.returnless_dispatch.enabled = false;
    c.returnless_dispatch.probability = 100;
    c.returnless_dispatch.max_sites = 64;

    // Off in every preset for now: opt-in via [passes.function_fission] while the
    // CodeExtractor-based function splitting is validated per platform.
    c.function_fission.enabled = false;
    c.function_fission.probability = 100;
    c.function_fission.max_splits = 8;
    c.function_fission.min_region_blocks = 2;
    c.function_fission.max_region_blocks = 64;

    c.vec.enabled = false;
    c.csm.enabled = false;
    c.csm.generator = CsmGenerator::Logistic;
    c.csm.tf_const = 0;
    c.flatten.enabled = false;
    c.indir_branch.enabled = false;
    c.func_wrap.enabled = false;
    c.fco.enabled = false;
    c.anti_hook.enabled = false;
    c.anti_dbg.enabled = false;
    c.anti_class_dump.enabled = false;
    c.platform_runtime.enabled = false;
    c.platform_runtime.direct_syscalls = "auto";
    c.platform_runtime.windows_mode = "documented_api";
    c.platform_runtime.per_build_stubs = false;
    c.platform_runtime.minimize_imports = false;
    c.platform_runtime.import_table_audit = false;
    c.timing_oracles.enabled = false;
    c.scheduler_step_oracles.enabled = false;
    c.trap_oracles.enabled = false;
    c.decoy_strings.enabled = true;
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

    c.split.enabled = true;
    c.split.splits = 3;
    c.split.stack_confusion = true;

    c.stack_coalesce.enabled = true;
    c.stack_coalesce.probability = 60;
    c.stack_coalesce.opaque_offsets = true;

    c.stack_delta.enabled = true;
    c.stack_delta.probability = 15;
    c.stack_delta.max_blocks = 2;
    c.stack_delta.min_bytes = 17;
    c.stack_delta.max_extra_bytes = 32;
    c.stack_delta.touches = 2;

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

    c.external_op.enabled = true;
    c.external_op.probability = 20;
    c.external_op.max_blocks = 4;
    c.external_op.decoy_stores = 1;

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

    c.virtualization.enabled = false;
    c.virtualization.probability = 0;
    c.virtualization.max_functions = 0;
    c.virtualization.max_instructions = 0;
    c.virtualization.max_registers = 0;

    c.hash_self_decrypt.enabled = false;
    c.hash_self_decrypt.probability = 0;
    c.hash_self_decrypt.max_payloads = 0;
    c.hash_self_decrypt.max_payload_bytes = 0;
    c.hash_self_decrypt.context_keying = false;

    c.fault_paged_payload.enabled = false;
    c.fault_paged_payload.probability = 0;
    c.fault_paged_payload.max_payloads = 0;
    c.fault_paged_payload.max_payload_bytes = 0;
    c.fault_paged_payload.page_size = 4096;
    c.fault_paged_payload.delivery = "lazy_accessor";
    c.fault_paged_payload.backend = "lazy_accessor";
    c.fault_paged_payload.per_page_keys = true;
    c.fault_paged_payload.reseal_after_use = true;
    c.fault_paged_payload.decoy_pages = 0;
    c.fault_paged_payload.fallback = true;
    c.fault_paged_payload.bind_to_runtime_seal = true;
    c.fault_paged_payload.virtualize_helpers = true;

    c.tracer_attestation.enabled = false;
    c.tracer_attestation.mode = "linux_ptrace";
    c.tracer_attestation.shares = 0;
    c.tracer_attestation.renewal = "startup";
    c.tracer_attestation.bind_to_runtime_seal = true;
    c.tracer_attestation.virtualize_helpers = true;
    c.sealed_blob.enabled = false;
    c.sealed_blob.max_blobs = 0;
    c.sealed_blob.max_blob_bytes = 0;
    c.sealed_blob.delivery = "eager";
    c.sealed_blob.zeroize_after_use = true;
    c.sealed_blob.runtime_keyed_magic = false;
    c.sealed_blob.magic_bytes = 0;

    c.self_checksum.enabled = false;
    c.self_checksum.probability = 0;
    c.self_checksum.max_constants = 0;
    c.self_checksum.region_bytes = 0;

    c.data_flow_integrity.enabled = false;
    c.data_flow_integrity.probability = 0;
    c.data_flow_integrity.max_tables = 0;
    c.data_flow_integrity.region_bytes = 0;

    c.mutual_guard.enabled = false;
    c.mutual_guard.probability = 0;
    c.mutual_guard.nodes = 0;
    c.mutual_guard.region_bytes = 0;
    c.mutual_guard.max_returns = 0;

    c.shamir_share.enabled = true;
    c.shamir_share.probability = 15;
    c.shamir_share.threshold = 3;
    c.shamir_share.shares = 5;
    c.shamir_share.max_secrets = 4;

    c.mq_gate.enabled = false;
    c.mq_gate.probability = 0;
    c.mq_gate.vars = 0;
    c.mq_gate.eqs = 0;
    c.mq_gate.density = 0;
    c.mq_gate.max_gates = 0;
    c.mq_gate.fold_diff = false;

    c.adversarial_merge.enabled = false;
    c.adversarial_merge.probability = 0;
    c.adversarial_merge.max_groups = 0;
    c.adversarial_merge.max_functions = 0;
    c.adversarial_merge.outline_probability = 0;
    c.adversarial_merge.max_outlines = 0;

    c.adversarial_tuning.enabled = false;
    c.adversarial_tuning.max_candidates = 0;
    c.adversarial_tuning.max_candidate_passes = 0;
    c.adversarial_tuning.score_floor = 0;
    c.adversarial_tuning.emit_marker = false;

    c.per_build_polymorphism.enabled = false;
    c.per_build_polymorphism.function_order = false;
    c.per_build_polymorphism.block_order = false;
    c.per_build_polymorphism.anchor_probability = 0;
    c.per_build_polymorphism.max_anchors = 0;

    c.path_explosion.enabled = true;
    c.path_explosion.probability = 15;
    c.path_explosion.max_blocks = 2;
    c.path_explosion.max_iterations = 8;

    c.trace_keying.enabled = true;
    c.trace_keying.probability = 10;
    c.trace_keying.max_blocks = 2;

    c.dispatcherless.enabled = true;
    c.dispatcherless.probability = 35;
    c.dispatcherless.max_routes = 8;
    c.dispatcherless.max_terms = 3;

    c.microcode_stress.enabled = false;
    c.microcode_stress.probability = 0;
    c.microcode_stress.max_sites = 0;
    c.microcode_stress.table_entries = 0;
    c.microcode_stress.decoy_blocks = 0;
    c.microcode_stress.alias_stores = 0;

    c.caller_keyed_dispatch.enabled = false;
    c.caller_keyed_dispatch.probability = 100;
    c.caller_keyed_dispatch.max_calls = 4096;
    c.caller_keyed_dispatch.region_bytes = 16;

    c.vec.enabled = true;
    c.vec.probability = 40;
    c.vec.width = 128;
    c.vec.shuffle = false;
    c.vec.lift_comparisons = true;

    c.csm.enabled = false;
    c.csm.generator = CsmGenerator::TFunction;
    c.csm.tf_const = 0;
    c.flatten.enabled = true;
    c.indir_branch.enabled = true;

    c.func_wrap.enabled = false;
    c.fco.enabled = false;
    c.anti_hook.enabled = false;
    c.anti_dbg.enabled = false;
    c.anti_class_dump.enabled = false;
    c.platform_runtime.enabled = false;
    c.platform_runtime.direct_syscalls = "auto";
    c.platform_runtime.windows_mode = "documented_api";
    c.platform_runtime.per_build_stubs = false;
    c.platform_runtime.minimize_imports = false;
    c.platform_runtime.import_table_audit = false;
    c.timing_oracles.enabled = false;
    c.scheduler_step_oracles.enabled = false;
    c.trap_oracles.enabled = false;
    c.decoy_strings.enabled = true;
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

    c.split.enabled = true;
    c.split.splits = 5;
    c.split.stack_confusion = true;

    c.stack_coalesce.enabled = true;
    c.stack_coalesce.probability = 100;
    c.stack_coalesce.opaque_offsets = true;

    c.stack_delta.enabled = true;
    c.stack_delta.probability = 35;
    c.stack_delta.max_blocks = 6;
    c.stack_delta.min_bytes = 17;
    c.stack_delta.max_extra_bytes = 64;
    c.stack_delta.touches = 3;

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

    c.external_op.enabled = true;
    c.external_op.probability = 50;
    c.external_op.max_blocks = 12;
    c.external_op.decoy_stores = 2;

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
    c.opt_amplify.probability = 30;
    c.opt_amplify.max_forms = 2;

    c.table_arith.enabled = true;
    c.table_arith.probability = 50;
    c.table_arith.max_tables = 6;

    c.sub_threshold.enabled = true;
    c.sub_threshold.probability = 25;
    c.sub_threshold.max_terms = 2;

    c.uniform_lower.enabled = true;
    c.uniform_lower.op_probability = 25;
    c.uniform_lower.branch_probability = 25;
    c.uniform_lower.max_tables = 3;
    c.uniform_lower.max_branches = 3;

    c.virtualization.enabled = true;
    c.virtualization.probability = 25;
    c.virtualization.max_functions = 1;
    c.virtualization.max_instructions = 48;
    c.virtualization.max_registers = 48;

    c.hash_self_decrypt.enabled = true;
    c.hash_self_decrypt.probability = 100;
    c.hash_self_decrypt.max_payloads = 1;
    c.hash_self_decrypt.max_payload_bytes = 64 * 1024;
    c.hash_self_decrypt.context_keying = true;

    c.fault_paged_payload.enabled = false;
    c.fault_paged_payload.probability = 100;
    c.fault_paged_payload.max_payloads = 1;
    c.fault_paged_payload.max_payload_bytes = 64 * 1024;
    c.fault_paged_payload.page_size = 4096;
    c.fault_paged_payload.delivery = "lazy_accessor";
    c.fault_paged_payload.backend = "lazy_accessor";
    c.fault_paged_payload.per_page_keys = true;
    c.fault_paged_payload.reseal_after_use = true;
    c.fault_paged_payload.decoy_pages = 1;
    c.fault_paged_payload.fallback = true;
    c.fault_paged_payload.bind_to_runtime_seal = true;
    c.fault_paged_payload.virtualize_helpers = true;

    c.tracer_attestation.enabled = true;
    c.tracer_attestation.mode = "linux_ptrace";
    c.tracer_attestation.shares = 1;
    c.tracer_attestation.renewal = "startup";
    c.tracer_attestation.bind_to_runtime_seal = true;
    c.tracer_attestation.virtualize_helpers = true;
    c.sealed_blob.enabled = true;
    c.sealed_blob.max_blobs = 4;
    c.sealed_blob.max_blob_bytes = 64 * 1024;
    c.sealed_blob.key_sources = {"runtime_seal", "external_proof",
                                 "code_region"};
    c.sealed_blob.delivery = "eager";
    c.sealed_blob.zeroize_after_use = true;
    c.sealed_blob.runtime_keyed_magic = true;
    c.sealed_blob.magic_bytes = 8;

    c.self_checksum.enabled = true;
    c.self_checksum.probability = 20;
    c.self_checksum.max_constants = 4;
    c.self_checksum.region_bytes = 16;

    c.data_flow_integrity.enabled = true;
    c.data_flow_integrity.probability = 25;
    c.data_flow_integrity.max_tables = 1;
    c.data_flow_integrity.region_bytes = 16;

    c.mutual_guard.enabled = false;
    c.mutual_guard.probability = 0;
    c.mutual_guard.nodes = 0;
    c.mutual_guard.region_bytes = 0;
    c.mutual_guard.max_returns = 0;

    c.shamir_share.enabled = true;
    c.shamir_share.probability = 40;
    c.shamir_share.threshold = 3;
    c.shamir_share.shares = 5;
    c.shamir_share.max_secrets = 12;

    c.mq_gate.enabled = true;
    c.mq_gate.probability = 15;
    c.mq_gate.vars = 16;
    c.mq_gate.eqs = 16;
    c.mq_gate.density = 35;
    c.mq_gate.max_gates = 1;
    c.mq_gate.fold_diff = true;

    c.adversarial_merge.enabled = false;
    c.adversarial_merge.probability = 0;
    c.adversarial_merge.max_groups = 0;
    c.adversarial_merge.max_functions = 0;
    c.adversarial_merge.outline_probability = 0;
    c.adversarial_merge.max_outlines = 0;

    c.adversarial_tuning.enabled = false;
    c.adversarial_tuning.max_candidates = 0;
    c.adversarial_tuning.max_candidate_passes = 0;
    c.adversarial_tuning.score_floor = 0;
    c.adversarial_tuning.emit_marker = false;

    c.per_build_polymorphism.enabled = true;
    c.per_build_polymorphism.function_order = true;
    c.per_build_polymorphism.block_order = true;
    c.per_build_polymorphism.anchor_probability = 35;
    c.per_build_polymorphism.max_anchors = 24;

    c.path_explosion.enabled = true;
    c.path_explosion.probability = 25;
    c.path_explosion.max_blocks = 3;
    c.path_explosion.max_iterations = 12;

    c.trace_keying.enabled = true;
    c.trace_keying.probability = 20;
    c.trace_keying.max_blocks = 4;

    c.dispatcherless.enabled = true;
    c.dispatcherless.probability = 50;
    c.dispatcherless.max_routes = 12;
    c.dispatcherless.max_terms = 4;

    c.microcode_stress.enabled = true;
    c.microcode_stress.probability = 15;
    c.microcode_stress.max_sites = 1;
    c.microcode_stress.table_entries = 16;
    c.microcode_stress.decoy_blocks = 4;
    c.microcode_stress.alias_stores = 1;

    // CKD now emits post-link manifests so sealed high/max binaries cannot
    // self-adapt to pre-start static patches; unsealed dev builds still use the
    // constructor fallback for normal differential testing.
    c.caller_keyed_dispatch.enabled = true;
    c.caller_keyed_dispatch.probability = 100;
    c.caller_keyed_dispatch.max_calls = 4096;
    c.caller_keyed_dispatch.region_bytes = 16;

    c.vec.enabled = true;
    c.vec.probability = 75;
    c.vec.width = 256;
    c.vec.shuffle = true;
    c.vec.lift_comparisons = true;

    c.csm.enabled = true;
    c.csm.generator = CsmGenerator::TFunction;
    c.csm.tf_const = 0;
    // warmup / nested_dispatch are reserved no-ops (the telescoping dispatch
    // pins the state to block IDs, leaving no free-running chaos state to warm
    // up and no second dispatch level); presets must not imply variation the
    // pass cannot deliver — see ChaosStateMachine.hpp.
    c.flatten.enabled = false;

    c.indir_branch.enabled = true;

    c.func_wrap.enabled = true;
    c.func_wrap.probability = 20;
    c.func_wrap.times = 1;

    c.fco.enabled = true;

    c.anti_hook.enabled = false;
    c.anti_dbg.enabled = false;
    c.anti_class_dump.enabled = false;
    c.platform_runtime.enabled = true;
    c.platform_runtime.direct_syscalls = "auto";
    c.platform_runtime.windows_mode = "hashed_import";
    c.platform_runtime.per_build_stubs = true;
    c.platform_runtime.minimize_imports = true;
    c.platform_runtime.import_table_audit = false;
    c.timing_oracles.enabled = false;
    c.scheduler_step_oracles.enabled = false;
    c.trap_oracles.enabled = false;
    c.decoy_strings.enabled = true;
    return c;
}

// The maximum-intensity preset: every pass enabled, every probability at 100,
// and every budget at its proven ceiling.  The values mirror the validated
// `tests/e2e/max.toml` (the full corpus compiles at exactly these settings),
// with the handful of fields that file leaves to the `high` base cranked up
// further here.  This is the strongest configuration the project ships.
PassConfig makeMax() {
    PassConfig c;
    c.bcf.enabled = true;
    c.bcf.probability = 100;
    c.bcf.iterations = 3;
    c.bcf.complexity = 8;
    c.bcf.entropy_chain = true;
    c.bcf.junk_asm = true;
    c.bcf.junk_asm_min = 3;
    c.bcf.junk_asm_max = 6;

    c.sub.enabled = true;
    c.sub.probability = 100;
    c.sub.iterations = 3;

    c.mba.enabled = true;
    c.mba.probability = 100;
    c.mba.layers = 3;
    c.mba.heuristic = true;

    c.str_enc.enabled = true;
    c.str_enc.probability = 100;

    c.const_enc.enabled = true;
    c.const_enc.iterations = 3;
    c.const_enc.share_count = 8;
    c.const_enc.feistel = true;
    c.const_enc.substitute_xor = true;
    c.const_enc.substitute_xor_prob = 100;

    c.split.enabled = true;
    c.split.splits = 8;
    c.split.stack_confusion = true;

    c.stack_coalesce.enabled = true;
    c.stack_coalesce.probability = 100;
    c.stack_coalesce.opaque_offsets = true;

    c.stack_delta.enabled = true;
    c.stack_delta.probability = 100;
    c.stack_delta.max_blocks = 10;
    c.stack_delta.min_bytes = 17;
    c.stack_delta.max_extra_bytes = 96;
    c.stack_delta.touches = 4;

    c.pointer_launder.enabled = true;
    c.pointer_launder.pointer_probability = 100;
    c.pointer_launder.integer_probability = 100;

    c.type_pun.enabled = true;
    c.type_pun.probability = 100;
    c.type_pun.include_floating = true;
    c.type_pun.max_targets = 64;

    c.phi_tangle.enabled = true;
    c.phi_tangle.probability = 100;
    c.phi_tangle.layers = 3;
    c.phi_tangle.max_phis = 48;

    c.alias_op.enabled = true;
    c.alias_op.probability = 100;
    c.alias_op.iterations = 3;
    c.alias_op.max_blocks = 16;

    c.external_op.enabled = true;
    c.external_op.probability = 100;
    c.external_op.max_blocks = 16;
    c.external_op.decoy_stores = 3;

    c.coherent_decoy.enabled = true;
    c.coherent_decoy.probability = 100;
    c.coherent_decoy.max_blocks = 12;
    c.coherent_decoy.depth = 6;

    c.data_entangled_flatten.enabled = true;
    c.data_entangled_flatten.max_terms = 8;

    c.non_invertible_state.enabled = true;
    c.non_invertible_state.max_terms = 8;
    c.non_invertible_state.rounds = 5;

    c.state_opaque.enabled = true;
    c.state_opaque.probability = 100;
    c.state_opaque.max_blocks = 48;
    c.state_opaque.max_terms = 8;

    c.interprocedural_fsm.enabled = true;
    c.interprocedural_fsm.probability = 100;
    c.interprocedural_fsm.max_sites = 96;
    c.interprocedural_fsm.max_terms = 8;

    c.opt_amplify.enabled = true;
    c.opt_amplify.probability = 100;
    c.opt_amplify.max_forms = 4;

    c.table_arith.enabled = true;
    c.table_arith.probability = 100;
    c.table_arith.max_tables = 12;

    c.sub_threshold.enabled = true;
    c.sub_threshold.probability = 100;
    c.sub_threshold.max_terms = 4;

    c.uniform_lower.enabled = true;
    c.uniform_lower.op_probability = 100;
    c.uniform_lower.branch_probability = 100;
    c.uniform_lower.max_tables = 8;
    c.uniform_lower.max_branches = 12;

    c.virtualization.enabled = true;
    c.virtualization.probability = 100;
    c.virtualization.max_functions = 16;
    // Headroom for whole multi-block loop kernels: after CFG/memory/call/
    // intrinsic lifting a real round function is several hundred VM ops with a
    // large cross-block live set, so push the register file to the 1-byte
    // operand-index ceiling (255 selectable registers).
    c.virtualization.max_instructions = 1024;
    c.virtualization.max_registers = 255;

    c.hash_self_decrypt.enabled = true;
    c.hash_self_decrypt.probability = 100;
    c.hash_self_decrypt.max_payloads = 16;
    c.hash_self_decrypt.max_payload_bytes = 64 * 1024;
    c.hash_self_decrypt.context_keying = true;

    c.fault_paged_payload.enabled = false;
    c.fault_paged_payload.probability = 100;
    c.fault_paged_payload.max_payloads = 16;
    c.fault_paged_payload.max_payload_bytes = 64 * 1024;
    c.fault_paged_payload.page_size = 4096;
    c.fault_paged_payload.delivery = "lazy_accessor";
    c.fault_paged_payload.backend = "lazy_accessor";
    c.fault_paged_payload.per_page_keys = true;
    c.fault_paged_payload.reseal_after_use = true;
    c.fault_paged_payload.decoy_pages = 2;
    c.fault_paged_payload.fallback = true;
    c.fault_paged_payload.bind_to_runtime_seal = true;
    c.fault_paged_payload.virtualize_helpers = true;

    c.tracer_attestation.enabled = true;
    c.tracer_attestation.mode = "linux_ptrace";
    c.tracer_attestation.shares = 4;
    c.tracer_attestation.renewal = "startup";
    c.tracer_attestation.bind_to_runtime_seal = true;
    c.tracer_attestation.virtualize_helpers = true;
    c.sealed_blob.enabled = true;
    c.sealed_blob.max_blobs = 16;
    c.sealed_blob.max_blob_bytes = 64 * 1024;
    c.sealed_blob.key_sources = {"runtime_seal", "external_proof",
                                 "code_region"};
    c.sealed_blob.delivery = "eager";
    c.sealed_blob.zeroize_after_use = true;
    c.sealed_blob.runtime_keyed_magic = true;
    c.sealed_blob.magic_bytes = 16;

    c.self_checksum.enabled = true;
    c.self_checksum.probability = 100;
    c.self_checksum.max_constants = 12;
    c.self_checksum.region_bytes = 48;

    c.data_flow_integrity.enabled = true;
    c.data_flow_integrity.probability = 100;
    c.data_flow_integrity.max_tables = 4;
    c.data_flow_integrity.region_bytes = 48;

    c.mutual_guard.enabled = true;
    c.mutual_guard.probability = 100;
    c.mutual_guard.nodes = 3;
    c.mutual_guard.region_bytes = 48;
    c.mutual_guard.max_returns = 2;

    c.shamir_share.enabled = true;
    c.shamir_share.probability = 100;
    c.shamir_share.threshold = 3;
    c.shamir_share.shares = 5;
    c.shamir_share.max_secrets = 24;

    c.mq_gate.enabled = true;
    c.mq_gate.probability = 100;
    c.mq_gate.vars = 24;
    c.mq_gate.eqs = 24;
    c.mq_gate.density = 50;
    c.mq_gate.max_gates = 2;
    c.mq_gate.fold_diff = true;

    c.adversarial_merge.enabled = true;
    c.adversarial_merge.probability = 100;
    c.adversarial_merge.max_groups = 1;
    c.adversarial_merge.max_functions = 3;
    c.adversarial_merge.outline_probability = 100;
    c.adversarial_merge.max_outlines = 4;

    c.adversarial_tuning.enabled = true;
    c.adversarial_tuning.max_candidates = 2;
    c.adversarial_tuning.max_candidate_passes = 2;
    c.adversarial_tuning.score_floor = 0;
    c.adversarial_tuning.emit_marker = true;

    c.per_build_polymorphism.enabled = true;
    c.per_build_polymorphism.function_order = true;
    c.per_build_polymorphism.block_order = true;
    c.per_build_polymorphism.anchor_probability = 100;
    c.per_build_polymorphism.max_anchors = 48;

    c.path_explosion.enabled = true;
    c.path_explosion.probability = 100;
    c.path_explosion.max_blocks = 4;
    c.path_explosion.max_iterations = 16;

    c.trace_keying.enabled = true;
    c.trace_keying.probability = 100;
    c.trace_keying.max_blocks = 8;

    c.dispatcherless.enabled = true;
    c.dispatcherless.probability = 100;
    c.dispatcherless.max_routes = 24;
    c.dispatcherless.max_terms = 6;

    c.microcode_stress.enabled = true;
    c.microcode_stress.probability = 100;
    c.microcode_stress.max_sites = 3;
    c.microcode_stress.table_entries = 32;
    c.microcode_stress.decoy_blocks = 8;
    c.microcode_stress.alias_stores = 2;

    // See makeHigh(): CKD uses post-link manifests for sealed release builds
    // while preserving constructor fallback behavior for unsealed tests.
    c.caller_keyed_dispatch.enabled = true;
    c.caller_keyed_dispatch.probability = 100;
    c.caller_keyed_dispatch.max_calls = 4096;
    c.caller_keyed_dispatch.region_bytes = 16;

    c.vec.enabled = true;
    c.vec.probability = 100;
    c.vec.width = 512;
    c.vec.shuffle = true;
    c.vec.lift_comparisons = true;

    c.csm.enabled = true;
    c.csm.generator = CsmGenerator::TFunction;
    c.csm.tf_const = 0;
    // warmup / nested_dispatch are reserved no-ops; do not vary them per preset
    // (see ChaosStateMachine.hpp and makeHigh()).

    c.flatten.enabled = true;
    c.indir_branch.enabled = true;

    c.func_wrap.enabled = true;
    c.func_wrap.probability = 100;
    c.func_wrap.times = 2;

    c.fco.enabled = true;
    c.vtable_integrity.enabled = true;

    c.anti_hook.enabled = true;
    c.anti_dbg.enabled = true;
    c.anti_class_dump.enabled = true;
    c.windows_pe_foundation.enabled = true;
    c.windows_peb_heap_debug.enabled = true;
    c.windows_debug_object.enabled = true;
    c.windows_thread_hide.enabled = true;
    c.windows_anti_attach.enabled = true;
    c.windows_kernel_debugger.enabled = true;
    c.windows_syscalls.enabled = true;
    c.platform_runtime.enabled = true;
    c.platform_runtime.direct_syscalls = "auto";
    c.platform_runtime.windows_mode = "direct_syscall";
    c.platform_runtime.per_build_stubs = true;
    c.platform_runtime.minimize_imports = true;
    c.platform_runtime.import_table_audit = true;
    c.windows_unhook.enabled = true;
    c.windows_veh_audit.enabled = true;
    c.windows_process_mitigations.enabled = true;
    c.timing_oracles.enabled = true;
    c.scheduler_step_oracles.enabled = true;
    c.trap_oracles.enabled = true;
    c.page_fault_oracles.enabled = true;
    c.cache_timing_oracles.enabled = true;
    c.microarchitectural_canaries.enabled = true;
    c.nanomites.enabled = true;
    c.nanomites.probability = 100;
    c.nanomites.max_sites = 16;
    c.decoy_strings.enabled = true;
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
    case Preset::Max:
        return makeMax();
    case Preset::None:
        break;
    }
    return {};
}

} // namespace morok::config
