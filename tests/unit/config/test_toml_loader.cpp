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
    [passes.vector_obfuscation]
    enabled = true
    probability = 88
    width = 512
    shuffle = true
    lift_comparisons = false
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
    CHECK(r.config.passes.vec.enabled == true);
    CHECK(r.config.passes.vec.probability == 88u);
    CHECK(r.config.passes.vec.width == 512u);
    CHECK(r.config.passes.vec.shuffle == true);
    CHECK(r.config.passes.vec.lift_comparisons == false);
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
