// SPDX-License-Identifier: MIT
//
// Unit tests for morok::config TOML loading.

#include "doctest.h"

#include "morok/config/Resolver.hpp"
#include "morok/config/TomlLoader.hpp"

using namespace morok::config;

TEST_CASE("empty document parses to all-default config") {
    const auto r = loadFromString("");
    REQUIRE(r.ok);
    CHECK(r.config.preset == Preset::None);
    CHECK(r.config.seed == 0u);
    CHECK(r.config.demangle_names == true);
    CHECK(r.config.policies.empty());
}

TEST_CASE("global section is parsed") {
    const auto r = loadFromString(R"(
    [global]
    preset = "high"
    seed = 0xDEADBEEF1337
    verbose = true
    demangle_names = false
  )");
    REQUIRE(r.ok);
    CHECK(r.config.preset == Preset::High);
    CHECK(r.config.seed == 0xDEADBEEF1337ULL);
    CHECK(r.config.verbose == true);
    CHECK(r.config.demangle_names == false);
}

TEST_CASE("unsigned TOML integers reject negative and overflowing values") {
    const auto r = loadFromString(R"(
    [global]
    seed = -1
    [passes.split_blocks]
    splits = -3
    [passes.bcf]
    junk_asm_min = -4
    junk_asm_max = 4294967296
    [passes.external_opaque_predicates]
    enabled = true
    probability = -25
    max_blocks = -5
    decoy_stores = 4294967296
  )");
    REQUIRE(r.ok);
    CHECK(r.config.seed == 0u);
    CHECK_FALSE(r.config.passes.split.splits.has_value());
    CHECK_FALSE(r.config.passes.bcf.junk_asm_min.has_value());
    CHECK_FALSE(r.config.passes.bcf.junk_asm_max.has_value());
    CHECK(r.config.passes.external_op.enabled == true);
    CHECK_FALSE(r.config.passes.external_op.probability.has_value());
    CHECK_FALSE(r.config.passes.external_op.max_blocks.has_value());
    CHECK_FALSE(r.config.passes.external_op.decoy_stores.has_value());
}

TEST_CASE("decoy_strings toggle is parsed") {
    const auto r = loadFromString(R"(
    [passes.decoy_strings]
    enabled = true
  )");
    REQUIRE(r.ok);
    CHECK(r.config.passes.decoy_strings.enabled == true);
}

TEST_CASE("vtable_integrity toggle is parsed") {
    const auto r = loadFromString(R"(
    [passes.vtable_integrity]
    enabled = true
  )");
    REQUIRE(r.ok);
    CHECK(r.config.passes.vtable_integrity.enabled == true);
}

TEST_CASE("nanomites section is parsed") {
    const auto r = loadFromString(R"(
    [passes.nanomites]
    enabled = true
    probability = 81
    max_sites = 7
  )");
    REQUIRE(r.ok);
    CHECK(r.config.passes.nanomites.enabled == true);
    CHECK(r.config.passes.nanomites.probability == 81u);
    CHECK(r.config.passes.nanomites.max_sites == 7u);
}

TEST_CASE("a tuning section does not disable a preset-enabled pass") {
    // Regression: a [passes.X] section that only tunes a parameter must NOT
    // reset the pass's other preset-provided fields (notably `enabled`).  The
    // "high" preset enables BCF and substitution; a probability-only override
    // must keep them enabled while changing the probability.
    const auto r = loadFromString(R"(
    [global]
    preset = "high"
    [passes.bcf]
    probability = 50
    [passes.substitution]
    probability = 33
    [passes.tracer_attestation]
    shares = 2
  )");
    REQUIRE(r.ok);
    const auto base = presetConfig(Preset::High);
    REQUIRE(base.bcf.enabled.has_value());
    CHECK(r.config.passes.bcf.enabled == base.bcf.enabled);
    CHECK(r.config.passes.bcf.probability == 50u);
    CHECK(r.config.passes.sub.enabled == base.sub.enabled);
    CHECK(r.config.passes.sub.probability == 33u);
    CHECK(r.config.passes.tracer_attestation.enabled ==
          base.tracer_attestation.enabled);
    CHECK(r.config.passes.tracer_attestation.shares == 2u);
    CHECK(r.config.passes.tracer_attestation.bind_to_runtime_seal ==
          base.tracer_attestation.bind_to_runtime_seal);
    // Fields the section never mentioned keep their preset values.
    CHECK(r.config.passes.bcf.iterations == base.bcf.iterations);
}

TEST_CASE("caller keyed dispatch opt-in inherits usable preset knobs") {
    const auto high = loadFromString(R"(
    [global]
    preset = "high"
    [passes.caller_keyed_dispatch]
    enabled = true
  )");
    REQUIRE(high.ok);
    CHECK(high.config.passes.caller_keyed_dispatch.enabled == true);
    CHECK(high.config.passes.caller_keyed_dispatch.probability == 100u);
    CHECK(high.config.passes.caller_keyed_dispatch.max_calls == 4096u);
    CHECK(high.config.passes.caller_keyed_dispatch.region_bytes == 16u);

    const auto max = loadFromString(R"(
    [global]
    preset = "max"
    [passes.caller_keyed_dispatch]
    enabled = true
  )");
    REQUIRE(max.ok);
    CHECK(max.config.passes.caller_keyed_dispatch.enabled == true);
    CHECK(max.config.passes.caller_keyed_dispatch.probability == 100u);
    CHECK(max.config.passes.caller_keyed_dispatch.max_calls == 4096u);
    CHECK(max.config.passes.caller_keyed_dispatch.region_bytes == 16u);

    // The sealed-release knob (#21) parses from an explicit table and is unset
    // (nullopt) when absent so presets keep the self-recovering dev fallback.
    const auto sealed = loadFromString(R"(
    [passes.caller_keyed_dispatch]
    enabled = true
    seal_required = true
  )");
    REQUIRE(sealed.ok);
    CHECK(sealed.config.passes.caller_keyed_dispatch.seal_required == true);
    CHECK_FALSE(high.config.passes.caller_keyed_dispatch.seal_required.has_value());

    // The cross-pass fail-closed-on-unsealed knob (#106) is a top-level
    // [passes] key, unset (nullopt) when absent so default builds stay fail-safe.
    const auto strict = loadFromString(R"(
    [passes]
    fail_closed_on_unsealed = true
  )");
    REQUIRE(strict.ok);
    CHECK(strict.config.passes.fail_closed_on_unsealed == true);
    CHECK_FALSE(high.config.passes.fail_closed_on_unsealed.has_value());
}

TEST_CASE("preset is the base and [passes.*] overrides it") {
    const auto r = loadFromString(R"(
    [global]
    preset = "mid"
    [passes.bcf]
    probability = 88
    [passes.constant_encryption]
    share_count = 6
    feistel = true
    [passes.stack_coalescing]
    enabled = true
    probability = 75
    opaque_offsets = true
    [passes.stack_delta_games]
    enabled = true
    probability = 44
    max_blocks = 5
    min_bytes = 21
    max_extra_bytes = 48
    touches = 4
    [passes.pointer_laundering]
    enabled = true
    pointer_probability = 80
    integer_probability = 20
    [passes.type_punning]
    enabled = true
    probability = 55
    include_floating = false
    max_targets = 9
    [passes.phi_tangling]
    enabled = true
    probability = 70
    layers = 3
    max_phis = 11
    [passes.alias_opaque_predicates]
    enabled = true
    probability = 73
    iterations = 2
    max_blocks = 7
    [passes.external_opaque_predicates]
    enabled = true
    probability = 47
    max_blocks = 6
    decoy_stores = 3
    [passes.coherent_decoys]
    enabled = true
    probability = 62
    max_blocks = 5
    depth = 4
    [passes.data_entangled_flattening]
    enabled = true
    max_terms = 6
    [passes.non_invertible_state]
    enabled = true
    max_terms = 7
    rounds = 5
    [passes.state_opaque_predicates]
    enabled = true
    probability = 77
    max_blocks = 10
    max_terms = 6
    [passes.interprocedural_fsm]
    enabled = true
    probability = 81
    max_sites = 13
    max_terms = 6
    [passes.optimizer_amplification]
    enabled = true
    probability = 37
    max_forms = 4
    [passes.table_arithmetic]
    enabled = true
    probability = 42
    max_tables = 3
    [passes.sub_threshold_persistence]
    enabled = true
    probability = 58
    max_terms = 4
    [passes.uniform_primitive_lowering]
    enabled = true
    op_probability = 49
    branch_probability = 67
    max_tables = 5
    max_branches = 7
    [passes.virtualization]
    enabled = true
    probability = 31
    max_functions = 2
    max_instructions = 44
    max_registers = 52
    [passes.hash_gated_self_decrypt]
    enabled = true
    probability = 92
    max_payloads = 3
    max_payload_bytes = 4096
    context_keying = true
    [passes.fault_paged_payload]
    enabled = true
    probability = 93
    max_payloads = 4
    max_payload_bytes = 8192
    page_size = 2048
    delivery = "fault_paged"
    backend = "lazy_accessor"
    per_page_keys = true
    reseal_after_use = false
    decoy_pages = 2
    fallback = true
    bind_to_runtime_seal = true
    virtualize_helpers = false
    [passes.external_secret_binding]
    enabled = true
    mode = "feed_api"
    public_key = "pub-rot-a"
    expected_digest = "0x1122334455667788"
    identity_policy = "raw"
    bind_to_runtime_seal = true
    virtualize_helpers = false
    [passes.env_binding_kdf]
    enabled = true
    mode = "auto"
    expected_digest = "0x8877665544332211"
    identity_policy = "ascii_lower_strip_ws"
    min_factors = 3
    bind_to_runtime_seal = true
    virtualize_helpers = false
    [passes.tracer_attestation]
    enabled = true
    mode = "linux_ptrace"
    shares = 3
    renewal = "startup"
    bind_to_runtime_seal = true
    virtualize_helpers = false
    [passes.sealed_blob]
    enabled = true
    max_blobs = 5
    max_blob_bytes = 2048
    key_sources = ["runtime_seal", "external_proof", "code_region"]
    delivery = "eager"
    zeroize_after_use = false
    runtime_keyed_magic = true
    magic_bytes = 11
    [passes.self_checksum_constants]
    enabled = true
    probability = 83
    max_constants = 6
    region_bytes = 48
    [passes.data_flow_integrity]
    enabled = true
    probability = 64
    max_tables = 5
    region_bytes = 72
    [passes.mutual_guard_graph]
    enabled = true
    probability = 61
    nodes = 4
    region_bytes = 80
    max_returns = 3
    [passes.shamir_share]
    enabled = true
    probability = 46
    threshold = 4
    shares = 7
    max_secrets = 6
    [passes.mq_gate]
    enabled = true
    probability = 21
    vars = 40
    eqs = 39
    density = 47
    max_gates = 3
    fold_diff = false
    [passes.adversarial_function_merging]
    enabled = true
    probability = 57
    max_groups = 2
    max_functions = 5
    outline_probability = 71
    max_outlines = 9
    [passes.adversarial_self_tuning]
    enabled = true
    max_candidates = 7
    max_candidate_passes = 4
    score_floor = 96
    emit_marker = false
    [passes.per_build_polymorphism]
    enabled = true
    function_order = false
    block_order = true
    anchor_probability = 68
    max_anchors = 12
    [passes.path_explosion]
    enabled = true
    probability = 51
    max_blocks = 4
    max_iterations = 10
    [passes.execution_trace_keying]
    enabled = true
    probability = 43
    max_blocks = 6
    [passes.dispatcherless_routing]
    enabled = true
    probability = 63
    max_routes = 9
    max_terms = 5
    [passes.microcode_stress]
    enabled = true
    probability = 54
    max_sites = 4
    table_entries = 48
    decoy_blocks = 9
    alias_stores = 3
    [passes.caller_keyed_dispatch]
    enabled = true
    probability = 100
    max_calls = 2048
    region_bytes = 24
    [passes.nanomites]
    enabled = true
    probability = 82
    max_sites = 6
    [passes.vector_obfuscation]
    enabled = true
    probability = 88
    width = 512
    shuffle = true
    lift_comparisons = false
    [passes.chaos_state_machine]
    enabled = true
    generator = "tfunction"
    tf_const = 13
    nested_dispatch = true
    warmup = 128
    [passes.windows_pe_foundation]
    enabled = true
    [passes.windows_peb_heap_debug]
    enabled = true
    [passes.windows_debug_object]
    enabled = true
    [passes.windows_thread_hide]
    enabled = true
    [passes.windows_anti_attach]
    enabled = true
    [passes.windows_kernel_debugger]
    enabled = true
    [passes.windows_syscalls]
    enabled = true
    [passes.platform_runtime]
    enabled = true
    direct_syscalls = "auto"
    windows_mode = "hashed_import"
    per_build_stubs = true
    minimize_imports = true
    import_table_audit = true
    [passes.windows_unhook]
    enabled = true
    [passes.windows_veh_audit]
    enabled = true
    [passes.windows_process_mitigations]
    enabled = true
    [passes.timing_oracles]
    enabled = true
    [passes.scheduler_step_oracles]
    enabled = true
    [passes.trap_oracles]
    enabled = true
    [passes.page_fault_oracles]
    enabled = true
    [passes.cache_timing_oracles]
    enabled = true
    [passes.microarchitectural_canaries]
    enabled = true
  )");
    REQUIRE(r.ok);
    // From the mid preset base:
    CHECK(r.config.passes.mba.layers == 2u);
    CHECK(r.config.passes.flatten.enabled == true);
    // Overridden by [passes.*]:
    CHECK(r.config.passes.bcf.probability == 88u);
    CHECK(r.config.passes.const_enc.share_count == 6u);
    CHECK(r.config.passes.const_enc.feistel == true);
    CHECK(r.config.passes.stack_coalesce.enabled == true);
    CHECK(r.config.passes.stack_coalesce.probability == 75u);
    CHECK(r.config.passes.stack_coalesce.opaque_offsets == true);
    CHECK(r.config.passes.stack_delta.enabled == true);
    CHECK(r.config.passes.stack_delta.probability == 44u);
    CHECK(r.config.passes.stack_delta.max_blocks == 5u);
    CHECK(r.config.passes.stack_delta.min_bytes == 21u);
    CHECK(r.config.passes.stack_delta.max_extra_bytes == 48u);
    CHECK(r.config.passes.stack_delta.touches == 4u);
    CHECK(r.config.passes.pointer_launder.enabled == true);
    CHECK(r.config.passes.pointer_launder.pointer_probability == 80u);
    CHECK(r.config.passes.pointer_launder.integer_probability == 20u);
    CHECK(r.config.passes.type_pun.enabled == true);
    CHECK(r.config.passes.type_pun.probability == 55u);
    CHECK(r.config.passes.type_pun.include_floating == false);
    CHECK(r.config.passes.type_pun.max_targets == 9u);
    CHECK(r.config.passes.phi_tangle.enabled == true);
    CHECK(r.config.passes.phi_tangle.probability == 70u);
    CHECK(r.config.passes.phi_tangle.layers == 3u);
    CHECK(r.config.passes.phi_tangle.max_phis == 11u);
    CHECK(r.config.passes.alias_op.enabled == true);
    CHECK(r.config.passes.alias_op.probability == 73u);
    CHECK(r.config.passes.alias_op.iterations == 2u);
    CHECK(r.config.passes.alias_op.max_blocks == 7u);
    CHECK(r.config.passes.external_op.enabled == true);
    CHECK(r.config.passes.external_op.probability == 47u);
    CHECK(r.config.passes.external_op.max_blocks == 6u);
    CHECK(r.config.passes.external_op.decoy_stores == 3u);
    CHECK(r.config.passes.coherent_decoy.enabled == true);
    CHECK(r.config.passes.coherent_decoy.probability == 62u);
    CHECK(r.config.passes.coherent_decoy.max_blocks == 5u);
    CHECK(r.config.passes.coherent_decoy.depth == 4u);
    CHECK(r.config.passes.data_entangled_flatten.enabled == true);
    CHECK(r.config.passes.data_entangled_flatten.max_terms == 6u);
    CHECK(r.config.passes.non_invertible_state.enabled == true);
    CHECK(r.config.passes.non_invertible_state.max_terms == 7u);
    CHECK(r.config.passes.non_invertible_state.rounds == 5u);
    CHECK(r.config.passes.state_opaque.enabled == true);
    CHECK(r.config.passes.state_opaque.probability == 77u);
    CHECK(r.config.passes.state_opaque.max_blocks == 10u);
    CHECK(r.config.passes.state_opaque.max_terms == 6u);
    CHECK(r.config.passes.interprocedural_fsm.enabled == true);
    CHECK(r.config.passes.interprocedural_fsm.probability == 81u);
    CHECK(r.config.passes.interprocedural_fsm.max_sites == 13u);
    CHECK(r.config.passes.interprocedural_fsm.max_terms == 6u);
    CHECK(r.config.passes.opt_amplify.enabled == true);
    CHECK(r.config.passes.opt_amplify.probability == 37u);
    CHECK(r.config.passes.opt_amplify.max_forms == 4u);
    CHECK(r.config.passes.table_arith.enabled == true);
    CHECK(r.config.passes.table_arith.probability == 42u);
    CHECK(r.config.passes.table_arith.max_tables == 3u);
    CHECK(r.config.passes.sub_threshold.enabled == true);
    CHECK(r.config.passes.sub_threshold.probability == 58u);
    CHECK(r.config.passes.sub_threshold.max_terms == 4u);
    CHECK(r.config.passes.uniform_lower.enabled == true);
    CHECK(r.config.passes.uniform_lower.op_probability == 49u);
    CHECK(r.config.passes.uniform_lower.branch_probability == 67u);
    CHECK(r.config.passes.uniform_lower.max_tables == 5u);
    CHECK(r.config.passes.uniform_lower.max_branches == 7u);
    CHECK(r.config.passes.virtualization.enabled == true);
    CHECK(r.config.passes.virtualization.probability == 31u);
    CHECK(r.config.passes.virtualization.max_functions == 2u);
    CHECK(r.config.passes.virtualization.max_instructions == 44u);
    CHECK(r.config.passes.virtualization.max_registers == 52u);
    CHECK(r.config.passes.hash_self_decrypt.enabled == true);
    CHECK(r.config.passes.hash_self_decrypt.probability == 92u);
    CHECK(r.config.passes.hash_self_decrypt.max_payloads == 3u);
    CHECK(r.config.passes.hash_self_decrypt.max_payload_bytes == 4096u);
    CHECK(r.config.passes.hash_self_decrypt.context_keying == true);
    CHECK(r.config.passes.fault_paged_payload.enabled == true);
    CHECK(r.config.passes.fault_paged_payload.probability == 93u);
    CHECK(r.config.passes.fault_paged_payload.max_payloads == 4u);
    CHECK(r.config.passes.fault_paged_payload.max_payload_bytes == 8192u);
    CHECK(r.config.passes.fault_paged_payload.page_size == 2048u);
    CHECK(r.config.passes.fault_paged_payload.delivery == "fault_paged");
    CHECK(r.config.passes.fault_paged_payload.backend == "lazy_accessor");
    CHECK(r.config.passes.fault_paged_payload.per_page_keys == true);
    CHECK(r.config.passes.fault_paged_payload.reseal_after_use == false);
    CHECK(r.config.passes.fault_paged_payload.decoy_pages == 2u);
    CHECK(r.config.passes.fault_paged_payload.fallback == true);
    CHECK(r.config.passes.fault_paged_payload.bind_to_runtime_seal == true);
    CHECK(r.config.passes.fault_paged_payload.virtualize_helpers == false);
    CHECK(r.config.passes.external_secret_binding.enabled == true);
    CHECK(r.config.passes.external_secret_binding.mode == "feed_api");
    CHECK(r.config.passes.external_secret_binding.public_key == "pub-rot-a");
    CHECK(r.config.passes.external_secret_binding.expected_digest ==
          "0x1122334455667788");
    CHECK(r.config.passes.external_secret_binding.identity_policy == "raw");
    CHECK(r.config.passes.external_secret_binding.bind_to_runtime_seal == true);
    CHECK(r.config.passes.external_secret_binding.virtualize_helpers == false);
    CHECK(r.config.passes.env_binding_kdf.enabled == true);
    CHECK(r.config.passes.env_binding_kdf.mode == "auto");
    CHECK(r.config.passes.env_binding_kdf.expected_digest ==
          "0x8877665544332211");
    CHECK(r.config.passes.env_binding_kdf.identity_policy ==
          "ascii_lower_strip_ws");
    CHECK(r.config.passes.env_binding_kdf.min_factors == 3u);
    CHECK(r.config.passes.env_binding_kdf.bind_to_runtime_seal == true);
    CHECK(r.config.passes.env_binding_kdf.virtualize_helpers == false);
    CHECK(r.config.passes.tracer_attestation.enabled == true);
    CHECK(r.config.passes.tracer_attestation.mode == "linux_ptrace");
    CHECK(r.config.passes.tracer_attestation.shares == 3u);
    CHECK(r.config.passes.tracer_attestation.renewal == "startup");
    CHECK(r.config.passes.tracer_attestation.bind_to_runtime_seal == true);
    CHECK(r.config.passes.tracer_attestation.virtualize_helpers == false);
    CHECK(r.config.passes.sealed_blob.enabled == true);
    CHECK(r.config.passes.sealed_blob.max_blobs == 5u);
    CHECK(r.config.passes.sealed_blob.max_blob_bytes == 2048u);
    REQUIRE(r.config.passes.sealed_blob.key_sources.size() == 3);
    CHECK(r.config.passes.sealed_blob.key_sources[2] == "code_region");
    CHECK(r.config.passes.sealed_blob.delivery == "eager");
    CHECK(r.config.passes.sealed_blob.zeroize_after_use == false);
    CHECK(r.config.passes.sealed_blob.runtime_keyed_magic == true);
    CHECK(r.config.passes.sealed_blob.magic_bytes == 11u);
    CHECK(r.config.passes.self_checksum.enabled == true);
    CHECK(r.config.passes.self_checksum.probability == 83u);
    CHECK(r.config.passes.self_checksum.max_constants == 6u);
    CHECK(r.config.passes.self_checksum.region_bytes == 48u);
    CHECK(r.config.passes.data_flow_integrity.enabled == true);
    CHECK(r.config.passes.data_flow_integrity.probability == 64u);
    CHECK(r.config.passes.data_flow_integrity.max_tables == 5u);
    CHECK(r.config.passes.data_flow_integrity.region_bytes == 72u);
    CHECK(r.config.passes.mutual_guard.enabled == true);
    CHECK(r.config.passes.mutual_guard.probability == 61u);
    CHECK(r.config.passes.mutual_guard.nodes == 4u);
    CHECK(r.config.passes.mutual_guard.region_bytes == 80u);
    CHECK(r.config.passes.mutual_guard.max_returns == 3u);
    CHECK(r.config.passes.shamir_share.enabled == true);
    CHECK(r.config.passes.shamir_share.probability == 46u);
    CHECK(r.config.passes.shamir_share.threshold == 4u);
    CHECK(r.config.passes.shamir_share.shares == 7u);
    CHECK(r.config.passes.shamir_share.max_secrets == 6u);
    CHECK(r.config.passes.mq_gate.enabled == true);
    CHECK(r.config.passes.mq_gate.probability == 21u);
    CHECK(r.config.passes.mq_gate.vars == 40u);
    CHECK(r.config.passes.mq_gate.eqs == 39u);
    CHECK(r.config.passes.mq_gate.density == 47u);
    CHECK(r.config.passes.mq_gate.max_gates == 3u);
    CHECK(r.config.passes.mq_gate.fold_diff == false);
    CHECK(r.config.passes.adversarial_merge.enabled == true);
    CHECK(r.config.passes.adversarial_merge.probability == 57u);
    CHECK(r.config.passes.adversarial_merge.max_groups == 2u);
    CHECK(r.config.passes.adversarial_merge.max_functions == 5u);
    CHECK(r.config.passes.adversarial_merge.outline_probability == 71u);
    CHECK(r.config.passes.adversarial_merge.max_outlines == 9u);
    CHECK(r.config.passes.adversarial_tuning.enabled == true);
    CHECK(r.config.passes.adversarial_tuning.max_candidates == 7u);
    CHECK(r.config.passes.adversarial_tuning.max_candidate_passes == 4u);
    CHECK(r.config.passes.adversarial_tuning.score_floor == 96u);
    CHECK(r.config.passes.adversarial_tuning.emit_marker == false);
    CHECK(r.config.passes.per_build_polymorphism.enabled == true);
    CHECK(r.config.passes.per_build_polymorphism.function_order == false);
    CHECK(r.config.passes.per_build_polymorphism.block_order == true);
    CHECK(r.config.passes.per_build_polymorphism.anchor_probability == 68u);
    CHECK(r.config.passes.per_build_polymorphism.max_anchors == 12u);
    CHECK(r.config.passes.path_explosion.enabled == true);
    CHECK(r.config.passes.path_explosion.probability == 51u);
    CHECK(r.config.passes.path_explosion.max_blocks == 4u);
    CHECK(r.config.passes.path_explosion.max_iterations == 10u);
    CHECK(r.config.passes.trace_keying.enabled == true);
    CHECK(r.config.passes.trace_keying.probability == 43u);
    CHECK(r.config.passes.trace_keying.max_blocks == 6u);
    CHECK(r.config.passes.dispatcherless.enabled == true);
    CHECK(r.config.passes.dispatcherless.probability == 63u);
    CHECK(r.config.passes.dispatcherless.max_routes == 9u);
    CHECK(r.config.passes.dispatcherless.max_terms == 5u);
    CHECK(r.config.passes.microcode_stress.enabled == true);
    CHECK(r.config.passes.microcode_stress.probability == 54u);
    CHECK(r.config.passes.microcode_stress.max_sites == 4u);
    CHECK(r.config.passes.microcode_stress.table_entries == 48u);
    CHECK(r.config.passes.microcode_stress.decoy_blocks == 9u);
    CHECK(r.config.passes.microcode_stress.alias_stores == 3u);
    CHECK(r.config.passes.caller_keyed_dispatch.enabled == true);
    CHECK(r.config.passes.caller_keyed_dispatch.probability == 100u);
    CHECK(r.config.passes.caller_keyed_dispatch.max_calls == 2048u);
    CHECK(r.config.passes.caller_keyed_dispatch.region_bytes == 24u);
    CHECK(r.config.passes.nanomites.enabled == true);
    CHECK(r.config.passes.nanomites.probability == 82u);
    CHECK(r.config.passes.nanomites.max_sites == 6u);
    CHECK(r.config.passes.vec.enabled == true);
    CHECK(r.config.passes.vec.probability == 88u);
    CHECK(r.config.passes.vec.width == 512u);
    CHECK(r.config.passes.vec.shuffle == true);
    CHECK(r.config.passes.vec.lift_comparisons == false);
    CHECK(r.config.passes.csm.enabled == true);
    CHECK(r.config.passes.csm.generator == CsmGenerator::TFunction);
    CHECK(r.config.passes.csm.tf_const == 13u);
    CHECK(r.config.passes.csm.nested_dispatch == true);
    CHECK(r.config.passes.csm.warmup == 128u);
    CHECK(r.config.passes.windows_pe_foundation.enabled == true);
    CHECK(r.config.passes.windows_peb_heap_debug.enabled == true);
    CHECK(r.config.passes.windows_debug_object.enabled == true);
    CHECK(r.config.passes.windows_thread_hide.enabled == true);
    CHECK(r.config.passes.windows_anti_attach.enabled == true);
    CHECK(r.config.passes.windows_kernel_debugger.enabled == true);
    CHECK(r.config.passes.windows_syscalls.enabled == true);
    CHECK(r.config.passes.platform_runtime.enabled == true);
    CHECK(r.config.passes.platform_runtime.direct_syscalls == "auto");
    CHECK(r.config.passes.platform_runtime.windows_mode == "hashed_import");
    CHECK(r.config.passes.platform_runtime.per_build_stubs == true);
    CHECK(r.config.passes.platform_runtime.minimize_imports == true);
    CHECK(r.config.passes.platform_runtime.import_table_audit == true);
    CHECK(r.config.passes.windows_unhook.enabled == true);
    CHECK(r.config.passes.windows_veh_audit.enabled == true);
    CHECK(r.config.passes.windows_process_mitigations.enabled == true);
    CHECK(r.config.passes.timing_oracles.enabled == true);
    CHECK(r.config.passes.scheduler_step_oracles.enabled == true);
    CHECK(r.config.passes.trap_oracles.enabled == true);
    CHECK(r.config.passes.page_fault_oracles.enabled == true);
    CHECK(r.config.passes.cache_timing_oracles.enabled == true);
    CHECK(r.config.passes.microarchitectural_canaries.enabled == true);
}

TEST_CASE("string-array filters are parsed") {
    const auto r = loadFromString(R"(
    [passes.string_encryption]
    enabled = true
    probability = 100
    skip_content = ["Usage:", "debug"]
    force_content = ["secret", "key"]
    [passes.constant_encryption]
    force_value = ["0xDEADBEEF", "0xCAFEBABE"]
  )");
    REQUIRE(r.ok);
    REQUIRE(r.config.passes.str_enc.skip_content.size() == 2);
    CHECK(r.config.passes.str_enc.skip_content[0] == "Usage:");
    REQUIRE(r.config.passes.str_enc.force_content.size() == 2);
    CHECK(r.config.passes.str_enc.force_content[1] == "key");
    REQUIRE(r.config.passes.const_enc.force_value.size() == 2);
    CHECK(r.config.passes.const_enc.force_value[0] == "0xDEADBEEF");
}

TEST_CASE("policy array is parsed in order with inline overrides") {
    const auto r = loadFromString(R"(
    [[policy]]
    module = ".*crypto.*"
    function = ".*encrypt.*"
    preset = "high"
    passes.bcf.probability = 90

    [[policy]]
    module = ".*"
    function = "^main$"
    passes.bcf.enabled = false
    passes.substitution.enabled = false
  )");
    REQUIRE(r.ok);
    REQUIRE(r.config.policies.size() == 2);
    CHECK(r.config.policies[0].module_regex == ".*crypto.*");
    CHECK(r.config.policies[0].func_regex == ".*encrypt.*");
    CHECK(r.config.policies[0].preset == Preset::High);
    CHECK(r.config.policies[0].overrides.bcf.probability == 90u);
    CHECK(r.config.policies[1].func_regex == "^main$");
    CHECK(r.config.policies[1].overrides.bcf.enabled == false);
    CHECK(r.config.policies[1].overrides.sub.enabled == false);
}

TEST_CASE("loaded policies resolve end-to-end") {
    const auto r = loadFromString(R"(
    [global]
    preset = "low"
    [[policy]]
    module = ".*app.*"
    function = "^core$"
    preset = "high"
  )");
    REQUIRE(r.ok);
    // core in app.c → upgraded to high
    CHECK(resolve(r.config, "src/app.c", "core").csm.enabled == true);
    // other functions stay at the low global base
    CHECK(resolve(r.config, "src/app.c", "helper").csm.enabled == false);
}

TEST_CASE("malformed TOML reports an error instead of throwing") {
    const auto r = loadFromString("this is = = not valid toml [[[");
    CHECK_FALSE(r.ok);
    CHECK_FALSE(r.error.empty());
    // Defaults are returned so callers can proceed safely.
    CHECK(r.config.preset == Preset::None);
}

TEST_CASE("missing file reports an error") {
    const auto r = loadFromFile("/nonexistent/path/morok-does-not-exist.toml");
    CHECK_FALSE(r.ok);
    CHECK_FALSE(r.error.empty());
}
