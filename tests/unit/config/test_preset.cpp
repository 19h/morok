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
    CHECK(parsePreset("max") == Preset::Max);
    CHECK(parsePreset("none") == Preset::None);
    CHECK(parsePreset("") == Preset::None);
    CHECK(parsePreset("bogus") == Preset::None);
    CHECK(presetName(Preset::Low) == "low");
    CHECK(presetName(Preset::Mid) == "mid");
    CHECK(presetName(Preset::High) == "high");
    CHECK(presetName(Preset::Max) == "max");
    CHECK(presetName(Preset::None) == "none");
}

TEST_CASE("preset 'none' leaves every field unset") {
    const PassConfig c = presetConfig(Preset::None);
    CHECK_FALSE(c.bcf.enabled.has_value());
    CHECK_FALSE(c.sub.probability.has_value());
    CHECK_FALSE(c.const_enc.share_count.has_value());
    CHECK_FALSE(c.csm.enabled.has_value());
}

// Regression for #23: chaos_state_machine.warmup / nested_dispatch are reserved
// no-ops — the telescoping dispatch pins the state to block IDs, so there is no
// chaos state to warm up and no second dispatch level.  The pass ignores them,
// so no preset may advertise per-level variation the pass cannot deliver (the
// presets previously set warmup=128/256 and nested_dispatch=false/true).
TEST_CASE("presets do not vary reserved chaos_state_machine knobs") {
    for (Preset p : {Preset::Low, Preset::Mid, Preset::High, Preset::Max}) {
        const PassConfig c = presetConfig(p);
        CHECK_FALSE(c.csm.warmup.has_value());
        CHECK_FALSE(c.csm.nested_dispatch.has_value());
    }
}

// Regression for #20: globalize/globalize_prob are user-visible knobs, but no
// preset should silently opt users into the extra global store/load layer.
TEST_CASE("presets leave constant_encryption globalize opt-in") {
    for (Preset p : {Preset::Low, Preset::Mid, Preset::High, Preset::Max}) {
        const PassConfig c = presetConfig(p);
        CHECK_FALSE(c.const_enc.globalize.has_value());
        CHECK_FALSE(c.const_enc.globalize_prob.has_value());
    }
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
    CHECK(c.stack_delta.enabled == false);
    CHECK(c.stack_rebase.enabled == false);
    CHECK(c.pointer_launder.enabled == false);
    CHECK(c.type_pun.enabled == false);
    CHECK(c.phi_tangle.enabled == false);
    CHECK(c.alias_op.enabled == false);
    CHECK(c.external_op.enabled == false);
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
    CHECK(c.hash_self_decrypt.enabled == false);
    CHECK(c.hash_self_decrypt.max_payload_bytes == 0u);
    CHECK(c.self_checksum.enabled == false);
    CHECK(c.data_flow_integrity.enabled == false);
    CHECK(c.mutual_guard.enabled == false);
    CHECK(c.shamir_share.enabled == false);
    CHECK(c.mq_gate.enabled == false);
    CHECK(c.adversarial_merge.enabled == false);
    CHECK(c.adversarial_tuning.enabled == false);
    CHECK(c.per_build_polymorphism.enabled == false);
    CHECK(c.path_explosion.enabled == false);
    CHECK(c.trace_keying.enabled == false);
    CHECK(c.dispatcherless.enabled == false);
    CHECK(c.microcode_stress.enabled == false);
    CHECK(c.caller_keyed_dispatch.enabled == false);
    CHECK(c.caller_keyed_dispatch.probability == 100u);
    CHECK(c.caller_keyed_dispatch.max_calls == 4096u);
    CHECK(c.caller_keyed_dispatch.region_bytes == 16u);
    CHECK(c.vec.enabled == false);
    CHECK(c.csm.enabled == false);
    CHECK(c.flatten.enabled == false);
    CHECK(c.timing_oracles.enabled == false);
    CHECK(c.scheduler_step_oracles.enabled == false);
    CHECK(c.trap_oracles.enabled == false);
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
    CHECK(c.stack_delta.enabled == true);
    CHECK(c.stack_delta.probability == 15u);
    CHECK(c.stack_delta.max_blocks == 2u);
    CHECK(c.stack_delta.min_bytes == 17u);
    CHECK(c.stack_delta.max_extra_bytes == 32u);
    CHECK(c.stack_delta.touches == 2u);
    CHECK(c.stack_rebase.enabled == false);
    CHECK(c.stack_rebase.realign_align == 0u);
    CHECK(c.stack_rebase.dynamic_size == 0u);
    CHECK(c.stack_rebase.relocate_probability == 0u);
    CHECK(c.stack_rebase.alias_amplify == 0u);
    CHECK(c.stack_rebase.nonentry_shuffle == false);
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
    CHECK(c.external_op.enabled == true);
    CHECK(c.external_op.probability == 20u);
    CHECK(c.external_op.max_blocks == 4u);
    CHECK(c.external_op.decoy_stores == 1u);
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
    CHECK(c.hash_self_decrypt.enabled == false);
    CHECK(c.hash_self_decrypt.max_payload_bytes == 0u);
    CHECK(c.self_checksum.enabled == false);
    CHECK(c.data_flow_integrity.enabled == false);
    CHECK(c.mutual_guard.enabled == false);
    CHECK(c.shamir_share.enabled == true);
    CHECK(c.shamir_share.probability == 15u);
    CHECK(c.shamir_share.threshold == 3u);
    CHECK(c.shamir_share.shares == 5u);
    CHECK(c.shamir_share.max_secrets == 4u);
    CHECK(c.mq_gate.enabled == false);
    CHECK(c.adversarial_merge.enabled == false);
    CHECK(c.adversarial_tuning.enabled == false);
    CHECK(c.per_build_polymorphism.enabled == false);
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
    CHECK(c.microcode_stress.enabled == false);
    CHECK(c.caller_keyed_dispatch.enabled == false);
    CHECK(c.caller_keyed_dispatch.probability == 100u);
    CHECK(c.caller_keyed_dispatch.max_calls == 4096u);
    CHECK(c.caller_keyed_dispatch.region_bytes == 16u);
    CHECK(c.vec.width == 128u);
    CHECK(c.vec.shuffle == false);
    CHECK(c.vec.lift_comparisons == true);
    CHECK(c.flatten.enabled == true);
    CHECK(c.csm.enabled == false);
    CHECK(c.csm.generator == CsmGenerator::TFunction);
    CHECK(c.csm.tf_const == 0u);
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
    CHECK(c.stack_delta.enabled == true);
    CHECK(c.stack_delta.probability == 35u);
    CHECK(c.stack_delta.max_blocks == 6u);
    CHECK(c.stack_delta.min_bytes == 17u);
    CHECK(c.stack_delta.max_extra_bytes == 64u);
    CHECK(c.stack_delta.touches == 3u);
    CHECK(c.stack_rebase.enabled == true);
    CHECK(c.stack_rebase.realign_align == 64u);
    CHECK(c.stack_rebase.dynamic_size == 128u);
    CHECK(c.stack_rebase.relocate_probability == 60u);
    CHECK(c.stack_rebase.alias_amplify == 40u);
    CHECK(c.stack_rebase.nonentry_shuffle == false);
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
    CHECK(c.external_op.enabled == true);
    CHECK(c.external_op.probability == 50u);
    CHECK(c.external_op.max_blocks == 12u);
    CHECK(c.external_op.decoy_stores == 2u);
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
    CHECK(c.opt_amplify.probability == 30u);
    CHECK(c.opt_amplify.max_forms == 2u);
    CHECK(c.table_arith.enabled == true);
    CHECK(c.table_arith.probability == 50u);
    CHECK(c.table_arith.max_tables == 6u);
    CHECK(c.sub_threshold.enabled == true);
    CHECK(c.sub_threshold.probability == 25u);
    CHECK(c.sub_threshold.max_terms == 2u);
    CHECK(c.uniform_lower.enabled == true);
    CHECK(c.uniform_lower.op_probability == 25u);
    CHECK(c.uniform_lower.branch_probability == 25u);
    CHECK(c.uniform_lower.max_tables == 3u);
    CHECK(c.uniform_lower.max_branches == 3u);
    CHECK(c.virtualization.enabled == true);
    CHECK(c.virtualization.probability == 25u);
    CHECK(c.virtualization.max_functions == 1u);
    CHECK(c.virtualization.max_instructions == 48u);
    CHECK(c.virtualization.max_registers == 48u);
    CHECK(c.hash_self_decrypt.enabled == true);
    CHECK(c.hash_self_decrypt.probability == 100u);
    CHECK(c.hash_self_decrypt.max_payloads == 1u);
    CHECK(c.hash_self_decrypt.max_payload_bytes == 65536u);
    CHECK(c.hash_self_decrypt.context_keying == true);
    CHECK(c.fault_paged_payload.enabled == false);
    CHECK(c.fault_paged_payload.probability == 100u);
    CHECK(c.fault_paged_payload.max_payloads == 1u);
    CHECK(c.fault_paged_payload.max_payload_bytes == 65536u);
    CHECK(c.fault_paged_payload.page_size == 4096u);
    CHECK(c.fault_paged_payload.backend == "lazy_accessor");
    CHECK(c.fault_paged_payload.per_page_keys == true);
    CHECK(c.fault_paged_payload.reseal_after_use == true);
    CHECK(c.fault_paged_payload.decoy_pages == 1u);
    CHECK(c.fault_paged_payload.bind_to_runtime_seal == true);
    CHECK(c.fault_paged_payload.virtualize_helpers == true);
    CHECK(c.tracer_attestation.enabled == true);
    CHECK(c.tracer_attestation.mode == "linux_ptrace");
    CHECK(c.tracer_attestation.shares == 1u);
    CHECK(c.tracer_attestation.renewal == "startup");
    CHECK(c.tracer_attestation.bind_to_runtime_seal == true);
    CHECK(c.tracer_attestation.virtualize_helpers == true);
    CHECK(c.sealed_blob.enabled == true);
    CHECK(c.sealed_blob.max_blobs == 4u);
    CHECK(c.sealed_blob.max_blob_bytes == 65536u);
    REQUIRE(c.sealed_blob.key_sources.size() == 3);
    CHECK(c.sealed_blob.key_sources[0] == "runtime_seal");
    CHECK(c.sealed_blob.delivery == "eager");
    CHECK(c.sealed_blob.zeroize_after_use == true);
    CHECK(c.sealed_blob.runtime_keyed_magic == true);
    CHECK(c.sealed_blob.magic_bytes == 8u);
    CHECK(c.self_checksum.enabled == true);
    CHECK(c.self_checksum.probability == 20u);
    CHECK(c.self_checksum.max_constants == 4u);
    CHECK(c.self_checksum.region_bytes == 16u);
    CHECK(c.data_flow_integrity.enabled == true);
    CHECK(c.data_flow_integrity.probability == 25u);
    CHECK(c.data_flow_integrity.max_tables == 1u);
    CHECK(c.data_flow_integrity.region_bytes == 16u);
    CHECK(c.mutual_guard.enabled == false);
    CHECK(c.mutual_guard.probability == 0u);
    CHECK(c.mutual_guard.nodes == 0u);
    CHECK(c.mutual_guard.region_bytes == 0u);
    CHECK(c.mutual_guard.max_returns == 0u);
    CHECK(c.shamir_share.enabled == true);
    CHECK(c.shamir_share.probability == 40u);
    CHECK(c.shamir_share.threshold == 3u);
    CHECK(c.shamir_share.shares == 5u);
    CHECK(c.shamir_share.max_secrets == 12u);
    CHECK(c.mq_gate.enabled == true);
    CHECK(c.mq_gate.probability == 15u);
    CHECK(c.mq_gate.vars == 16u);
    CHECK(c.mq_gate.eqs == 16u);
    CHECK(c.mq_gate.density == 35u);
    CHECK(c.mq_gate.max_gates == 1u);
    CHECK(c.mq_gate.fold_diff == true);
    CHECK(c.adversarial_merge.enabled == false);
    CHECK(c.adversarial_merge.probability == 0u);
    CHECK(c.adversarial_merge.max_groups == 0u);
    CHECK(c.adversarial_merge.max_functions == 0u);
    CHECK(c.adversarial_merge.outline_probability == 0u);
    CHECK(c.adversarial_merge.max_outlines == 0u);
    CHECK(c.adversarial_tuning.enabled == false);
    CHECK(c.adversarial_tuning.max_candidates == 0u);
    CHECK(c.adversarial_tuning.max_candidate_passes == 0u);
    CHECK(c.adversarial_tuning.score_floor == 0u);
    CHECK(c.adversarial_tuning.emit_marker == false);
    CHECK(c.per_build_polymorphism.enabled == true);
    CHECK(c.per_build_polymorphism.function_order == true);
    CHECK(c.per_build_polymorphism.block_order == true);
    CHECK(c.per_build_polymorphism.anchor_probability == 35u);
    CHECK(c.per_build_polymorphism.max_anchors == 24u);
    CHECK(c.path_explosion.enabled == true);
    CHECK(c.path_explosion.probability == 25u);
    CHECK(c.path_explosion.max_blocks == 3u);
    CHECK(c.path_explosion.max_iterations == 12u);
    CHECK(c.trace_keying.enabled == true);
    CHECK(c.trace_keying.probability == 20u);
    CHECK(c.trace_keying.max_blocks == 4u);
    CHECK(c.dispatcherless.enabled == true);
    CHECK(c.dispatcherless.probability == 50u);
    CHECK(c.dispatcherless.max_routes == 12u);
    CHECK(c.dispatcherless.max_terms == 4u);
    CHECK(c.microcode_stress.enabled == true);
    CHECK(c.microcode_stress.probability == 15u);
    CHECK(c.microcode_stress.max_sites == 1u);
    CHECK(c.microcode_stress.table_entries == 16u);
    CHECK(c.microcode_stress.decoy_blocks == 4u);
    CHECK(c.microcode_stress.alias_stores == 1u);
    CHECK(c.caller_keyed_dispatch.enabled == true);
    CHECK(c.caller_keyed_dispatch.probability == 100u);
    CHECK(c.caller_keyed_dispatch.max_calls == 4096u);
    CHECK(c.caller_keyed_dispatch.region_bytes == 16u);
    CHECK(c.vec.width == 256u);
    CHECK(c.vec.shuffle == true);
    CHECK(c.vec.lift_comparisons == true);
    CHECK(c.csm.enabled == true);
    CHECK(c.csm.generator == CsmGenerator::TFunction);
    CHECK(c.csm.tf_const == 0u);
    CHECK(c.flatten.enabled == false);
    CHECK(c.func_wrap.enabled == true);
    CHECK(c.func_wrap.probability == 20u);
    CHECK(c.func_wrap.times == 1u);
    CHECK(c.fco.enabled == true);
    CHECK(c.platform_runtime.enabled == true);
    CHECK(c.platform_runtime.direct_syscalls == "auto");
    CHECK(c.platform_runtime.windows_mode == "hashed_import");
    CHECK(c.platform_runtime.per_build_stubs == true);
    CHECK(c.platform_runtime.minimize_imports == true);
    CHECK(c.platform_runtime.import_table_audit == false);
    CHECK(c.platform_runtime.static_link_expected == false);
}

TEST_CASE("max preset enables every pass at full intensity") {
    const PassConfig c = presetConfig(Preset::Max);

    // Every preset-safe toggleable pass is enabled — including the four the
    // `high` preset leaves off (mutual_guard, adversarial_merge,
    // adversarial_tuning, flatten) and the runtime anti-analysis trio.  CKD
    // stays opt-in until its final-binary post-link expected hash exists.
    CHECK(c.bcf.enabled == true);
    CHECK(c.sub.enabled == true);
    CHECK(c.mba.enabled == true);
    CHECK(c.str_enc.enabled == true);
    CHECK(c.const_enc.enabled == true);
    CHECK(c.split.enabled == true);
    CHECK(c.stack_coalesce.enabled == true);
    CHECK(c.stack_delta.enabled == true);
    CHECK(c.stack_rebase.enabled == true);
    CHECK(c.stack_rebase.realign_align == 128u);
    CHECK(c.stack_rebase.dynamic_size == 256u);
    CHECK(c.stack_rebase.relocate_probability == 100u);
    CHECK(c.stack_rebase.alias_amplify == 75u);
    CHECK(c.stack_rebase.nonentry_shuffle == true);
    CHECK(c.pointer_launder.enabled == true);
    CHECK(c.type_pun.enabled == true);
    CHECK(c.phi_tangle.enabled == true);
    CHECK(c.alias_op.enabled == true);
    CHECK(c.external_op.enabled == true);
    CHECK(c.coherent_decoy.enabled == true);
    CHECK(c.data_entangled_flatten.enabled == true);
    CHECK(c.non_invertible_state.enabled == true);
    CHECK(c.state_opaque.enabled == true);
    CHECK(c.interprocedural_fsm.enabled == true);
    CHECK(c.opt_amplify.enabled == true);
    CHECK(c.table_arith.enabled == true);
    CHECK(c.sub_threshold.enabled == true);
    CHECK(c.uniform_lower.enabled == true);
    CHECK(c.virtualization.enabled == true);
    CHECK(c.hash_self_decrypt.enabled == true);
    CHECK(c.hash_self_decrypt.max_payload_bytes == 65536u);
    CHECK(c.fault_paged_payload.enabled == false);
    CHECK(c.fault_paged_payload.max_payloads == 16u);
    CHECK(c.fault_paged_payload.decoy_pages == 2u);
    CHECK(c.tracer_attestation.enabled == true);
    CHECK(c.sealed_blob.enabled == true);
    CHECK(c.sealed_blob.max_blobs == 16u);
    CHECK(c.sealed_blob.runtime_keyed_magic == true);
    CHECK(c.sealed_blob.magic_bytes == 16u);
    CHECK(c.self_checksum.enabled == true);
    CHECK(c.data_flow_integrity.enabled == true);
    CHECK(c.mutual_guard.enabled == true);
    CHECK(c.shamir_share.enabled == true);
    CHECK(c.mq_gate.enabled == true);
    CHECK(c.adversarial_merge.enabled == true);
    CHECK(c.adversarial_tuning.enabled == true);
    CHECK(c.per_build_polymorphism.enabled == true);
    CHECK(c.path_explosion.enabled == true);
    CHECK(c.trace_keying.enabled == true);
    CHECK(c.dispatcherless.enabled == true);
    CHECK(c.microcode_stress.enabled == true);
    CHECK(c.caller_keyed_dispatch.enabled == true);
    CHECK(c.vec.enabled == true);
    CHECK(c.csm.enabled == true);
    CHECK(c.flatten.enabled == true);
    CHECK(c.indir_branch.enabled == true);
    CHECK(c.func_wrap.enabled == true);
    CHECK(c.fco.enabled == true);
    CHECK(c.vtable_integrity.enabled == true);
    CHECK(c.anti_hook.enabled == true);
    CHECK(c.anti_dbg.enabled == true);
    CHECK(c.anti_class_dump.enabled == true);
    CHECK(c.windows_pe_foundation.enabled == true);
    CHECK(c.windows_peb_heap_debug.enabled == true);
    CHECK(c.windows_debug_object.enabled == true);
    CHECK(c.windows_thread_hide.enabled == true);
    CHECK(c.windows_anti_attach.enabled == true);
    CHECK(c.windows_kernel_debugger.enabled == true);
    CHECK(c.windows_syscalls.enabled == true);
    CHECK(c.windows_process_modules.enabled == true);
    CHECK(c.platform_runtime.enabled == true);
    CHECK(c.platform_runtime.direct_syscalls == "auto");
    CHECK(c.platform_runtime.windows_mode == "direct_syscall");
    CHECK(c.platform_runtime.per_build_stubs == true);
    CHECK(c.platform_runtime.minimize_imports == true);
    CHECK(c.platform_runtime.import_table_audit == true);
    CHECK(c.platform_runtime.static_link_expected == false);
    CHECK(c.windows_unhook.enabled == true);
    CHECK(c.windows_veh_audit.enabled == true);
    CHECK(c.windows_process_mitigations.enabled == true);
    CHECK(c.timing_oracles.enabled == true);
    CHECK(c.scheduler_step_oracles.enabled == true);
    CHECK(c.trap_oracles.enabled == true);
    CHECK(c.page_fault_oracles.enabled == true);
    CHECK(c.cache_timing_oracles.enabled == true);
    CHECK(c.microarchitectural_canaries.enabled == true);
    CHECK(c.nanomites.enabled == true);
    CHECK(c.decoy_strings.enabled == true);

    // Probabilities are pinned at 100 and budgets exceed the high preset.
    CHECK(c.bcf.probability == 100u);
    CHECK(c.sub.probability == 100u);
    CHECK(c.mba.probability == 100u);
    CHECK(c.virtualization.probability == 100u);
    CHECK(c.virtualization.max_functions == 16u);
    CHECK(c.virtualization.max_instructions == 1024u);
    CHECK(c.virtualization.max_registers == 255u);
    CHECK(c.tracer_attestation.mode == "linux_ptrace");
    CHECK(c.tracer_attestation.shares == 4u);
    CHECK(c.tracer_attestation.renewal == "startup");
    CHECK(c.tracer_attestation.bind_to_runtime_seal == true);
    CHECK(c.tracer_attestation.virtualize_helpers == true);
    CHECK(c.vec.width == 512u);
    CHECK(c.const_enc.share_count == 8u);
    CHECK(c.func_wrap.times == 2u);
    CHECK(c.nanomites.probability == 100u);
    CHECK(c.nanomites.max_sites == 16u);
    CHECK(c.caller_keyed_dispatch.probability == 100u);
    CHECK(c.caller_keyed_dispatch.max_calls == 4096u);
    CHECK(c.caller_keyed_dispatch.region_bytes == 16u);

    // Max is strictly at least as strong as high on shared scalar knobs.
    const PassConfig h = presetConfig(Preset::High);
    CHECK(c.bcf.probability >= h.bcf.probability);
    CHECK(c.mba.probability >= h.mba.probability);
    CHECK(c.virtualization.max_instructions >=
          h.virtualization.max_instructions);
    CHECK(c.vec.width >= h.vec.width);
}
