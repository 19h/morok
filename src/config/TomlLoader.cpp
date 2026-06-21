// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/config/TomlLoader.cpp — TOML → Config parsing (toml++).
//
// Parsing is exception-isolated: toml++ may throw on malformed input, but every
// error is caught and converted into a LoadResult, so no exception escapes this
// translation unit into the (exception-free) LLVM layers that link it.

#include "morok/config/TomlLoader.hpp"

#include "morok/config/Resolver.hpp"

#define TOML_IMPLEMENTATION
#include "toml.hpp"

#include <cstdint>
#include <limits>
#include <optional>
#include <string>

namespace morok::config {

namespace {

using Node = toml::node_view<const toml::node>;

Opt<std::uint32_t> readU32(const Node &v) {
    if (auto i = v.value<std::int64_t>()) {
        if (*i < 0 || *i > static_cast<std::int64_t>(
                               std::numeric_limits<std::uint32_t>::max()))
            return std::nullopt;
        return static_cast<std::uint32_t>(*i);
    }
    return std::nullopt;
}

Opt<std::uint64_t> readU64(const Node &v) {
    if (auto i = v.value<std::int64_t>()) {
        if (*i < 0)
            return std::nullopt;
        return static_cast<std::uint64_t>(*i);
    }
    return std::nullopt;
}

Opt<bool> readBool(const Node &v) {
    if (auto b = v.value<bool>())
        return *b;
    return std::nullopt;
}

Opt<std::string> readString(const Node &v) {
    if (auto s = v.value<std::string>())
        return *s;
    return std::nullopt;
}

void readStrArr(const Node &v, std::vector<std::string> &out) {
    if (const auto *arr = v.as_array())
        for (const auto &el : *arr)
            if (auto s = el.value<std::string>())
                out.push_back(*s);
}

void parseBcf(const toml::table &t, BcfConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.iterations = readU32(t["iterations"]);
    c.complexity = readU32(t["complexity"]);
    c.entropy_chain = readBool(t["entropy_chain"]);
    c.junk_asm = readBool(t["junk_asm"]);
    c.junk_asm_min = readU32(t["junk_asm_min"]);
    c.junk_asm_max = readU32(t["junk_asm_max"]);
}

void parseSub(const toml::table &t, SubConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.iterations = readU32(t["iterations"]);
}

void parseMba(const toml::table &t, MbaConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.layers = readU32(t["layers"]);
    c.heuristic = readBool(t["heuristic"]);
}

void parseSplit(const toml::table &t, SplitConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.splits = readU32(t["splits"]);
    c.stack_confusion = readBool(t["stack_confusion"]);
}

void parseStackCoalesce(const toml::table &t, StackCoalesceConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.opaque_offsets = readBool(t["opaque_offsets"]);
}

void parseStackDelta(const toml::table &t, StackDeltaConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.max_blocks = readU32(t["max_blocks"]);
    c.min_bytes = readU32(t["min_bytes"]);
    c.max_extra_bytes = readU32(t["max_extra_bytes"]);
    c.touches = readU32(t["touches"]);
}

void parsePointerLaunder(const toml::table &t, PointerLaunderConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.pointer_probability = readU32(t["pointer_probability"]);
    c.integer_probability = readU32(t["integer_probability"]);
}

void parseTypePun(const toml::table &t, TypePunConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.include_floating = readBool(t["include_floating"]);
    c.max_targets = readU32(t["max_targets"]);
}

void parsePhiTangle(const toml::table &t, PhiTangleConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.layers = readU32(t["layers"]);
    c.max_phis = readU32(t["max_phis"]);
}

void parseAliasOp(const toml::table &t, AliasOpConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.iterations = readU32(t["iterations"]);
    c.max_blocks = readU32(t["max_blocks"]);
}

void parseExternalOp(const toml::table &t, ExternalOpConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.max_blocks = readU32(t["max_blocks"]);
    c.decoy_stores = readU32(t["decoy_stores"]);
}

void parseCoherentDecoy(const toml::table &t, CoherentDecoyConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.max_blocks = readU32(t["max_blocks"]);
    c.depth = readU32(t["depth"]);
}

void parseDataEntangledFlatten(const toml::table &t,
                               DataEntangledFlattenConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.max_terms = readU32(t["max_terms"]);
}

void parseNonInvertibleState(const toml::table &t,
                             NonInvertibleStateConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.max_terms = readU32(t["max_terms"]);
    c.rounds = readU32(t["rounds"]);
}

void parseStateOpaque(const toml::table &t, StateOpaqueConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.max_blocks = readU32(t["max_blocks"]);
    c.max_terms = readU32(t["max_terms"]);
}

void parseInterproceduralFsm(const toml::table &t,
                             InterproceduralFsmConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.max_sites = readU32(t["max_sites"]);
    c.max_terms = readU32(t["max_terms"]);
}

void parseOptAmplify(const toml::table &t, OptAmplifyConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.max_forms = readU32(t["max_forms"]);
}

void parseTableArith(const toml::table &t, TableArithConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.max_tables = readU32(t["max_tables"]);
}

void parseSubThreshold(const toml::table &t, SubThresholdConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.max_terms = readU32(t["max_terms"]);
}

void parseUniformLower(const toml::table &t, UniformLowerConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.op_probability = readU32(t["op_probability"]);
    c.branch_probability = readU32(t["branch_probability"]);
    c.max_tables = readU32(t["max_tables"]);
    c.max_branches = readU32(t["max_branches"]);
}

void parseVirtualization(const toml::table &t, VirtualizationConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.max_functions = readU32(t["max_functions"]);
    c.max_instructions = readU32(t["max_instructions"]);
    c.max_registers = readU32(t["max_registers"]);
}

void parseHashSelfDecrypt(const toml::table &t, HashSelfDecryptConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.max_payloads = readU32(t["max_payloads"]);
    c.max_payload_bytes = readU32(t["max_payload_bytes"]);
    c.context_keying = readBool(t["context_keying"]);
}

void parseFaultPagedPayload(const toml::table &t,
                            FaultPagedPayloadConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.max_payloads = readU32(t["max_payloads"]);
    c.max_payload_bytes = readU32(t["max_payload_bytes"]);
    c.page_size = readU32(t["page_size"]);
    c.delivery = readString(t["delivery"]);
    c.backend = readString(t["backend"]);
    c.per_page_keys = readBool(t["per_page_keys"]);
    c.reseal_after_use = readBool(t["reseal_after_use"]);
    c.decoy_pages = readU32(t["decoy_pages"]);
    c.fallback = readBool(t["fallback"]);
    c.bind_to_runtime_seal = readBool(t["bind_to_runtime_seal"]);
    c.virtualize_helpers = readBool(t["virtualize_helpers"]);
}

void parseExternalSecretBinding(const toml::table &t,
                                ExternalSecretBindingConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.mode = readString(t["mode"]);
    c.public_key = readString(t["public_key"]);
    c.expected_digest = readString(t["expected_digest"]);
    c.identity_policy = readString(t["identity_policy"]);
    c.bind_to_runtime_seal = readBool(t["bind_to_runtime_seal"]);
    c.virtualize_helpers = readBool(t["virtualize_helpers"]);
}

void parseTracerAttestation(const toml::table &t,
                            TracerAttestationConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.mode = readString(t["mode"]);
    c.shares = readU32(t["shares"]);
    c.renewal = readString(t["renewal"]);
    c.bind_to_runtime_seal = readBool(t["bind_to_runtime_seal"]);
    c.virtualize_helpers = readBool(t["virtualize_helpers"]);
}

void parseSealedBlob(const toml::table &t, SealedBlobConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.max_blobs = readU32(t["max_blobs"]);
    c.max_blob_bytes = readU32(t["max_blob_bytes"]);
    readStrArr(t["key_sources"], c.key_sources);
    c.delivery = readString(t["delivery"]);
    c.zeroize_after_use = readBool(t["zeroize_after_use"]);
    c.runtime_keyed_magic = readBool(t["runtime_keyed_magic"]);
    c.magic_bytes = readU32(t["magic_bytes"]);
}

void parseSelfChecksum(const toml::table &t, SelfChecksumConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.max_constants = readU32(t["max_constants"]);
    c.region_bytes = readU32(t["region_bytes"]);
}

void parseDataFlowIntegrity(const toml::table &t, DataFlowIntegrityConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.max_tables = readU32(t["max_tables"]);
    c.region_bytes = readU32(t["region_bytes"]);
}

void parseMutualGuard(const toml::table &t, MutualGuardConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.nodes = readU32(t["nodes"]);
    c.region_bytes = readU32(t["region_bytes"]);
    c.max_returns = readU32(t["max_returns"]);
}

void parseShamirShare(const toml::table &t, ShamirShareConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.threshold = readU32(t["threshold"]);
    c.shares = readU32(t["shares"]);
    c.max_secrets = readU32(t["max_secrets"]);
}

void parseMqGate(const toml::table &t, MqGateConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.vars = readU32(t["vars"]);
    c.eqs = readU32(t["eqs"]);
    c.density = readU32(t["density"]);
    c.max_gates = readU32(t["max_gates"]);
    c.fold_diff = readBool(t["fold_diff"]);
}

void parseAdversarialMerge(const toml::table &t, AdversarialMergeConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.max_groups = readU32(t["max_groups"]);
    c.max_functions = readU32(t["max_functions"]);
    c.outline_probability = readU32(t["outline_probability"]);
    c.max_outlines = readU32(t["max_outlines"]);
}

void parseAdversarialTuning(const toml::table &t, AdversarialTuningConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.max_candidates = readU32(t["max_candidates"]);
    c.max_candidate_passes = readU32(t["max_candidate_passes"]);
    c.score_floor = readU32(t["score_floor"]);
    c.emit_marker = readBool(t["emit_marker"]);
}

void parsePerBuildPolymorphism(const toml::table &t,
                               PerBuildPolymorphismConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.function_order = readBool(t["function_order"]);
    c.block_order = readBool(t["block_order"]);
    c.anchor_probability = readU32(t["anchor_probability"]);
    c.max_anchors = readU32(t["max_anchors"]);
}

void parsePathExplosion(const toml::table &t, PathExplosionConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.max_blocks = readU32(t["max_blocks"]);
    c.max_iterations = readU32(t["max_iterations"]);
}

void parseTraceKeying(const toml::table &t, TraceKeyConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.max_blocks = readU32(t["max_blocks"]);
}

void parseDispatcherless(const toml::table &t, DispatcherlessConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.max_routes = readU32(t["max_routes"]);
    c.max_terms = readU32(t["max_terms"]);
}

void parseMicrocodeStress(const toml::table &t, MicrocodeStressConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.max_sites = readU32(t["max_sites"]);
    c.table_entries = readU32(t["table_entries"]);
    c.decoy_blocks = readU32(t["decoy_blocks"]);
    c.alias_stores = readU32(t["alias_stores"]);
}

void parseCallerKeyedDispatch(const toml::table &t,
                              CallerKeyedDispatchConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.max_calls = readU32(t["max_calls"]);
    c.region_bytes = readU32(t["region_bytes"]);
    c.seal_required = readBool(t["seal_required"]);
    c.carriers = readU32(t["carriers"]);
}

void parseReturnlessDispatch(const toml::table &t,
                            ReturnlessDispatchConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.max_sites = readU32(t["max_sites"]);
}

void parseFunctionFission(const toml::table &t, FunctionFissionConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.max_splits = readU32(t["max_splits"]);
    c.min_region_blocks = readU32(t["min_region_blocks"]);
    c.max_region_blocks = readU32(t["max_region_blocks"]);
}

void parseNanomites(const toml::table &t, NanomiteConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.max_sites = readU32(t["max_sites"]);
}

void parseStrEnc(const toml::table &t, StrEncConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    readStrArr(t["skip_content"], c.skip_content);
    readStrArr(t["force_content"], c.force_content);
}

void parseConstEnc(const toml::table &t, ConstEncConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.iterations = readU32(t["iterations"]);
    c.share_count = readU32(t["share_count"]);
    c.feistel = readBool(t["feistel"]);
    c.substitute_xor = readBool(t["substitute_xor"]);
    c.substitute_xor_prob = readU32(t["substitute_xor_prob"]);
    c.globalize = readBool(t["globalize"]);
    c.globalize_prob = readU32(t["globalize_prob"]);
    readStrArr(t["skip_value"], c.skip_value);
    readStrArr(t["force_value"], c.force_value);
}

void parseVec(const toml::table &t, VecConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.width = readU32(t["width"]);
    c.shuffle = readBool(t["shuffle"]);
    c.lift_comparisons = readBool(t["lift_comparisons"]);
}

void parseCsm(const toml::table &t, CsmConfig &c) {
    c.enabled = readBool(t["enabled"]);
    if (auto s = t["generator"].value<std::string>()) {
        if (*s == "tfunction")
            c.generator = CsmGenerator::TFunction;
        else if (*s == "logistic")
            c.generator = CsmGenerator::Logistic;
    }
    c.tf_const = readU64(t["tf_const"]);
    c.nested_dispatch = readBool(t["nested_dispatch"]);
    c.warmup = readU32(t["warmup"]);
}

void parsePlatformRuntime(const toml::table &t, PlatformRuntimeConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.direct_syscalls = readString(t["direct_syscalls"]);
    c.windows_mode = readString(t["windows_mode"]);
    c.per_build_stubs = readBool(t["per_build_stubs"]);
    c.minimize_imports = readBool(t["minimize_imports"]);
    c.import_table_audit = readBool(t["import_table_audit"]);
}

void parseFuncWrap(const toml::table &t, PassConfig::FuncWrapConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.times = readU32(t["times"]);
}

void parseToggle(const toml::table &t, ToggleConfig &c) {
    c.enabled = readBool(t["enabled"]);
}

void parsePasses(const toml::table &p, PassConfig &pc) {
    if (auto *t = p["bcf"].as_table())
        parseBcf(*t, pc.bcf);
    if (auto *t = p["substitution"].as_table())
        parseSub(*t, pc.sub);
    if (auto *t = p["mba"].as_table())
        parseMba(*t, pc.mba);
    if (auto *t = p["split_blocks"].as_table())
        parseSplit(*t, pc.split);
    if (auto *t = p["stack_coalescing"].as_table())
        parseStackCoalesce(*t, pc.stack_coalesce);
    if (auto *t = p["stack_delta_games"].as_table())
        parseStackDelta(*t, pc.stack_delta);
    if (auto *t = p["pointer_laundering"].as_table())
        parsePointerLaunder(*t, pc.pointer_launder);
    if (auto *t = p["type_punning"].as_table())
        parseTypePun(*t, pc.type_pun);
    if (auto *t = p["phi_tangling"].as_table())
        parsePhiTangle(*t, pc.phi_tangle);
    if (auto *t = p["alias_opaque_predicates"].as_table())
        parseAliasOp(*t, pc.alias_op);
    if (auto *t = p["external_opaque_predicates"].as_table())
        parseExternalOp(*t, pc.external_op);
    if (auto *t = p["coherent_decoys"].as_table())
        parseCoherentDecoy(*t, pc.coherent_decoy);
    if (auto *t = p["data_entangled_flattening"].as_table())
        parseDataEntangledFlatten(*t, pc.data_entangled_flatten);
    if (auto *t = p["non_invertible_state"].as_table())
        parseNonInvertibleState(*t, pc.non_invertible_state);
    if (auto *t = p["state_opaque_predicates"].as_table())
        parseStateOpaque(*t, pc.state_opaque);
    if (auto *t = p["interprocedural_fsm"].as_table())
        parseInterproceduralFsm(*t, pc.interprocedural_fsm);
    if (auto *t = p["optimizer_amplification"].as_table())
        parseOptAmplify(*t, pc.opt_amplify);
    if (auto *t = p["table_arithmetic"].as_table())
        parseTableArith(*t, pc.table_arith);
    if (auto *t = p["sub_threshold_persistence"].as_table())
        parseSubThreshold(*t, pc.sub_threshold);
    if (auto *t = p["uniform_primitive_lowering"].as_table())
        parseUniformLower(*t, pc.uniform_lower);
    if (auto *t = p["virtualization"].as_table())
        parseVirtualization(*t, pc.virtualization);
    if (auto *t = p["hash_gated_self_decrypt"].as_table())
        parseHashSelfDecrypt(*t, pc.hash_self_decrypt);
    if (auto *t = p["fault_paged_payload"].as_table())
        parseFaultPagedPayload(*t, pc.fault_paged_payload);
    if (auto *t = p["external_secret_binding"].as_table())
        parseExternalSecretBinding(*t, pc.external_secret_binding);
    if (auto *t = p["tracer_attestation"].as_table())
        parseTracerAttestation(*t, pc.tracer_attestation);
    if (auto *t = p["sealed_blob"].as_table())
        parseSealedBlob(*t, pc.sealed_blob);
    if (auto *t = p["self_checksum_constants"].as_table())
        parseSelfChecksum(*t, pc.self_checksum);
    if (auto *t = p["data_flow_integrity"].as_table())
        parseDataFlowIntegrity(*t, pc.data_flow_integrity);
    if (auto *t = p["mutual_guard_graph"].as_table())
        parseMutualGuard(*t, pc.mutual_guard);
    if (auto *t = p["shamir_share"].as_table())
        parseShamirShare(*t, pc.shamir_share);
    if (auto *t = p["mq_gate"].as_table())
        parseMqGate(*t, pc.mq_gate);
    if (auto *t = p["adversarial_function_merging"].as_table())
        parseAdversarialMerge(*t, pc.adversarial_merge);
    if (auto *t = p["adversarial_self_tuning"].as_table())
        parseAdversarialTuning(*t, pc.adversarial_tuning);
    if (auto *t = p["per_build_polymorphism"].as_table())
        parsePerBuildPolymorphism(*t, pc.per_build_polymorphism);
    if (auto *t = p["path_explosion"].as_table())
        parsePathExplosion(*t, pc.path_explosion);
    if (auto *t = p["execution_trace_keying"].as_table())
        parseTraceKeying(*t, pc.trace_keying);
    if (auto *t = p["dispatcherless_routing"].as_table())
        parseDispatcherless(*t, pc.dispatcherless);
    if (auto *t = p["microcode_stress"].as_table())
        parseMicrocodeStress(*t, pc.microcode_stress);
    if (auto *t = p["caller_keyed_dispatch"].as_table())
        parseCallerKeyedDispatch(*t, pc.caller_keyed_dispatch);
    if (auto *t = p["returnless_dispatch"].as_table())
        parseReturnlessDispatch(*t, pc.returnless_dispatch);
    if (auto *t = p["function_fission"].as_table())
        parseFunctionFission(*t, pc.function_fission);
    if (auto *t = p["nanomites"].as_table())
        parseNanomites(*t, pc.nanomites);
    if (auto *t = p["string_encryption"].as_table())
        parseStrEnc(*t, pc.str_enc);
    if (auto *t = p["constant_encryption"].as_table())
        parseConstEnc(*t, pc.const_enc);
    if (auto *t = p["vector_obfuscation"].as_table())
        parseVec(*t, pc.vec);
    if (auto *t = p["chaos_state_machine"].as_table())
        parseCsm(*t, pc.csm);
    if (auto *t = p["flattening"].as_table())
        parseToggle(*t, pc.flatten);
    if (auto *t = p["indirect_branch"].as_table())
        parseToggle(*t, pc.indir_branch);
    if (auto *t = p["function_wrapper"].as_table())
        parseFuncWrap(*t, pc.func_wrap);
    if (auto *t = p["function_call_obfuscate"].as_table())
        parseToggle(*t, pc.fco);
    if (auto *t = p["anti_hooking"].as_table())
        parseToggle(*t, pc.anti_hook);
    if (auto *t = p["anti_debugging"].as_table())
        parseToggle(*t, pc.anti_dbg);
    if (auto *t = p["anti_class_dump"].as_table())
        parseToggle(*t, pc.anti_class_dump);
    if (auto *t = p["windows_pe_foundation"].as_table())
        parseToggle(*t, pc.windows_pe_foundation);
    if (auto *t = p["windows_peb_heap_debug"].as_table())
        parseToggle(*t, pc.windows_peb_heap_debug);
    if (auto *t = p["windows_debug_object"].as_table())
        parseToggle(*t, pc.windows_debug_object);
    if (auto *t = p["windows_thread_hide"].as_table())
        parseToggle(*t, pc.windows_thread_hide);
    if (auto *t = p["windows_anti_attach"].as_table())
        parseToggle(*t, pc.windows_anti_attach);
    if (auto *t = p["windows_kernel_debugger"].as_table())
        parseToggle(*t, pc.windows_kernel_debugger);
    if (auto *t = p["windows_syscalls"].as_table())
        parseToggle(*t, pc.windows_syscalls);
    if (auto *t = p["platform_runtime"].as_table())
        parsePlatformRuntime(*t, pc.platform_runtime);
    if (auto *t = p["windows_unhook"].as_table())
        parseToggle(*t, pc.windows_unhook);
    if (auto *t = p["windows_veh_audit"].as_table())
        parseToggle(*t, pc.windows_veh_audit);
    if (auto *t = p["windows_process_mitigations"].as_table())
        parseToggle(*t, pc.windows_process_mitigations);
    if (auto *t = p["timing_oracles"].as_table())
        parseToggle(*t, pc.timing_oracles);
    if (auto *t = p["scheduler_step_oracles"].as_table())
        parseToggle(*t, pc.scheduler_step_oracles);
    if (auto *t = p["trap_oracles"].as_table())
        parseToggle(*t, pc.trap_oracles);
    if (auto *t = p["page_fault_oracles"].as_table())
        parseToggle(*t, pc.page_fault_oracles);
    if (auto *t = p["cache_timing_oracles"].as_table())
        parseToggle(*t, pc.cache_timing_oracles);
    if (auto *t = p["microarchitectural_canaries"].as_table())
        parseToggle(*t, pc.microarchitectural_canaries);
    if (auto *t = p["decoy_strings"].as_table())
        parseToggle(*t, pc.decoy_strings);
    if (auto *t = p["vtable_integrity"].as_table())
        parseToggle(*t, pc.vtable_integrity);
    // Cross-pass top-level switch (#106), e.g. [passes] fail_closed_on_unsealed.
    pc.fail_closed_on_unsealed = readBool(p["fail_closed_on_unsealed"]);
}

Policy parsePolicy(const toml::table &pt) {
    Policy pol;
    if (auto v = pt["module"].value<std::string>())
        pol.module_regex = *v;
    if (auto v = pt["function"].value<std::string>())
        pol.func_regex = *v;
    if (auto v = pt["preset"].value<std::string>())
        pol.preset = parsePreset(*v);
    if (auto *passes = pt["passes"].as_table())
        parsePasses(*passes, pol.overrides);
    return pol;
}

Config buildConfig(const toml::table &tbl) {
    Config cfg;
    if (const auto *global = tbl["global"].as_table()) {
        if (auto v = (*global)["preset"].value<std::string>())
            cfg.preset = parsePreset(*v);
        if (auto v = readU64((*global)["seed"]))
            cfg.seed = *v;
        if (auto v = (*global)["verbose"].value<bool>())
            cfg.verbose = *v;
        if (auto v = (*global)["trace"].value<bool>())
            cfg.trace = *v;
        if (auto v = (*global)["demangle_names"].value<bool>())
            cfg.demangle_names = *v;
    }

    // Preset is the lowest-priority base for pass parameters.
    if (cfg.preset != Preset::None)
        cfg.passes = presetConfig(cfg.preset);

    // [passes.*] overrides on top of the preset.  Parse the file's sections
    // into a fresh overlay (every field the file does not mention stays unset)
    // and merge it onto the preset base.  Parsing directly into `cfg.passes`
    // would clobber preset-provided fields the section omits back to unset —
    // most damagingly `enabled`, silently disabling a pass whose section only
    // tunes a parameter (e.g. probability).
    if (const auto *passes = tbl["passes"].as_table()) {
        PassConfig overlay;
        parsePasses(*passes, overlay);
        merge(cfg.passes, overlay);
    }

    // Ordered [[policy]] rules.
    if (const auto *arr = tbl["policy"].as_array())
        for (const auto &el : *arr)
            if (const auto *t = el.as_table())
                cfg.policies.push_back(parsePolicy(*t));

    return cfg;
}

} // namespace

LoadResult loadFromString(std::string_view toml_text) {
    LoadResult r;
    try {
        auto tbl = toml::parse(toml_text);
        r.config = buildConfig(tbl);
        r.ok = true;
    } catch (const toml::parse_error &e) {
        r.error = std::string("TOML parse error: ") + e.what();
    } catch (const std::exception &e) {
        r.error = std::string("config error: ") + e.what();
    }
    return r;
}

LoadResult loadFromFile(std::string_view path) {
    LoadResult r;
    try {
        auto tbl = toml::parse_file(path);
        r.config = buildConfig(tbl);
        r.ok = true;
    } catch (const toml::parse_error &e) {
        r.error = std::string("TOML parse error: ") + e.what();
    } catch (const std::exception &e) {
        r.error = std::string("config error: ") + e.what();
    }
    return r;
}

} // namespace morok::config
