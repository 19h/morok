// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/config/PassConfig.hpp — the structured configuration model.
//
// Every per-pass option is an std::optional: "unset" means "fall through to the
// pass's own default".  This lets presets, file settings, and per-function
// policies be layered by merging only the fields each level actually specifies.
// The model is deliberately free of LLVM and I/O so it can be unit-tested in
// isolation; loading (TOML) and resolution (policy/preset merge) are separate
// translation units.

#ifndef MOROK_CONFIG_PASS_CONFIG_HPP
#define MOROK_CONFIG_PASS_CONFIG_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace morok::config {

template <class T> using Opt = std::optional<T>;

struct BcfConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability; // 0–100
    Opt<std::uint32_t> iterations;
    Opt<std::uint32_t> complexity; // predicate depth
    Opt<bool> entropy_chain;
    Opt<bool> junk_asm;
    Opt<std::uint32_t> junk_asm_min;
    Opt<std::uint32_t> junk_asm_max;
};

struct SubConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> iterations;
};

struct MbaConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> layers; // 1–3
    Opt<bool> heuristic;
};

struct SplitConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> splits;
    Opt<bool> stack_confusion;
};

struct StackCoalesceConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<bool> opaque_offsets;
};

struct StackDeltaConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> max_blocks;
    Opt<std::uint32_t> min_bytes;
    Opt<std::uint32_t> max_extra_bytes;
    Opt<std::uint32_t> touches;
};

struct PointerLaunderConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> pointer_probability;
    Opt<std::uint32_t> integer_probability;
};

struct TypePunConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<bool> include_floating;
    Opt<std::uint32_t> max_targets;
};

struct PhiTangleConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> layers;
    Opt<std::uint32_t> max_phis;
};

struct AliasOpConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> iterations;
    Opt<std::uint32_t> max_blocks;
};

struct ExternalOpConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> max_blocks;
    Opt<std::uint32_t> decoy_stores;
};

struct CoherentDecoyConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> max_blocks;
    Opt<std::uint32_t> depth;
};

struct DataEntangledFlattenConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> max_terms;
};

struct NonInvertibleStateConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> max_terms;
    Opt<std::uint32_t> rounds;
};

struct StateOpaqueConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> max_blocks;
    Opt<std::uint32_t> max_terms;
};

struct InterproceduralFsmConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> max_sites;
    Opt<std::uint32_t> max_terms;
};

struct OptAmplifyConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> max_forms;
};

struct TableArithConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> max_tables;
};

struct SubThresholdConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> max_terms;
};

struct UniformLowerConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> op_probability;
    Opt<std::uint32_t> branch_probability;
    Opt<std::uint32_t> max_tables;
    Opt<std::uint32_t> max_branches;
};

struct VirtualizationConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> max_functions;
    Opt<std::uint32_t> max_instructions;
    Opt<std::uint32_t> max_registers;
};

struct HashSelfDecryptConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> max_payloads;
    Opt<std::uint32_t> max_payload_bytes;
    Opt<bool> context_keying;
};

struct ExternalSecretBindingConfig {
    Opt<bool> enabled;
    Opt<std::string> mode;
    Opt<std::string> public_key;
    Opt<std::string> identity_policy;
    Opt<bool> bind_to_runtime_seal;
    Opt<bool> virtualize_helpers;
};

struct SelfChecksumConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> max_constants;
    Opt<std::uint32_t> region_bytes;
};

struct DataFlowIntegrityConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> max_tables;
    Opt<std::uint32_t> region_bytes;
};

struct MutualGuardConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> nodes;
    Opt<std::uint32_t> region_bytes;
    Opt<std::uint32_t> max_returns;
};

struct ShamirShareConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> threshold;
    Opt<std::uint32_t> shares;
    Opt<std::uint32_t> max_secrets;
};

struct MqGateConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> vars;
    Opt<std::uint32_t> eqs;
    Opt<std::uint32_t> density;
    Opt<std::uint32_t> max_gates;
    Opt<bool> fold_diff;
};

struct AdversarialMergeConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> max_groups;
    Opt<std::uint32_t> max_functions;
    Opt<std::uint32_t> outline_probability;
    Opt<std::uint32_t> max_outlines;
};

struct AdversarialTuningConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> max_candidates;
    Opt<std::uint32_t> max_candidate_passes;
    Opt<std::uint32_t> score_floor;
    Opt<bool> emit_marker;
};

struct PerBuildPolymorphismConfig {
    Opt<bool> enabled;
    Opt<bool> function_order;
    Opt<bool> block_order;
    Opt<std::uint32_t> anchor_probability;
    Opt<std::uint32_t> max_anchors;
};

struct PathExplosionConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> max_blocks;
    Opt<std::uint32_t> max_iterations;
};

struct TraceKeyConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> max_blocks;
};

struct DispatcherlessConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> max_routes;
    Opt<std::uint32_t> max_terms;
};

struct MicrocodeStressConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> max_sites;
    Opt<std::uint32_t> table_entries;
    Opt<std::uint32_t> decoy_blocks;
    Opt<std::uint32_t> alias_stores;
};

struct CallerKeyedDispatchConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> max_calls;
    Opt<std::uint32_t> region_bytes;
};

struct NanomiteConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> max_sites;
};

struct StrEncConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    std::vector<std::string> skip_content;
    std::vector<std::string> force_content;
};

struct ConstEncConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> iterations;
    Opt<std::uint32_t> share_count; // 2–8
    Opt<bool> feistel;
    Opt<bool> substitute_xor;
    Opt<std::uint32_t> substitute_xor_prob;
    // Reserved: the XOR shares are ALWAYS emitted as private globals read with
    // volatile loads (see ConstantEncryption.cpp), so globalization is applied
    // unconditionally; these knobs are parsed for forward-compatibility but do
    // not change the output, so presets must not vary them.
    Opt<bool> globalize;
    Opt<std::uint32_t> globalize_prob;
    std::vector<std::string> skip_value;
    std::vector<std::string> force_value;
};

struct VecConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> width; // 128 | 256 | 512
    Opt<bool> shuffle;
    Opt<bool> lift_comparisons;
};

enum class CsmGenerator {
    Logistic,
    TFunction,
};

struct CsmConfig {
    Opt<bool> enabled;
    Opt<CsmGenerator> generator;
    Opt<std::uint64_t> tf_const;
    Opt<bool> nested_dispatch;
    Opt<std::uint32_t> warmup;
};

struct ToggleConfig {
    Opt<bool> enabled;
};

/// The full set of per-pass options.
struct PassConfig {
    BcfConfig bcf;
    SubConfig sub;
    MbaConfig mba;
    SplitConfig split;
    StackCoalesceConfig stack_coalesce;
    StackDeltaConfig stack_delta;
    PointerLaunderConfig pointer_launder;
    TypePunConfig type_pun;
    PhiTangleConfig phi_tangle;
    AliasOpConfig alias_op;
    ExternalOpConfig external_op;
    CoherentDecoyConfig coherent_decoy;
    DataEntangledFlattenConfig data_entangled_flatten;
    NonInvertibleStateConfig non_invertible_state;
    StateOpaqueConfig state_opaque;
    InterproceduralFsmConfig interprocedural_fsm;
    OptAmplifyConfig opt_amplify;
    TableArithConfig table_arith;
    SubThresholdConfig sub_threshold;
    UniformLowerConfig uniform_lower;
    VirtualizationConfig virtualization;
    HashSelfDecryptConfig hash_self_decrypt;
    ExternalSecretBindingConfig external_secret_binding;
    SelfChecksumConfig self_checksum;
    DataFlowIntegrityConfig data_flow_integrity;
    MutualGuardConfig mutual_guard;
    ShamirShareConfig shamir_share;
    MqGateConfig mq_gate;
    AdversarialMergeConfig adversarial_merge;
    AdversarialTuningConfig adversarial_tuning;
    PerBuildPolymorphismConfig per_build_polymorphism;
    PathExplosionConfig path_explosion;
    TraceKeyConfig trace_keying;
    DispatcherlessConfig dispatcherless;
    MicrocodeStressConfig microcode_stress;
    CallerKeyedDispatchConfig caller_keyed_dispatch;
    NanomiteConfig nanomites;
    StrEncConfig str_enc;
    ConstEncConfig const_enc;
    VecConfig vec;
    CsmConfig csm;
    ToggleConfig flatten;
    ToggleConfig indir_branch;
    ToggleConfig fco;
    ToggleConfig anti_hook;
    ToggleConfig anti_dbg;
    ToggleConfig anti_class_dump;
    ToggleConfig windows_pe_foundation;
    ToggleConfig windows_peb_heap_debug;
    ToggleConfig windows_debug_object;
    ToggleConfig windows_thread_hide;
    ToggleConfig windows_anti_attach;
    ToggleConfig windows_kernel_debugger;
    ToggleConfig windows_syscalls;
    ToggleConfig windows_unhook;
    ToggleConfig windows_veh_audit;
    ToggleConfig windows_process_mitigations;
    ToggleConfig timing_oracles;
    ToggleConfig trap_oracles;
    ToggleConfig page_fault_oracles;
    ToggleConfig cache_timing_oracles;
    ToggleConfig microarchitectural_canaries;
    ToggleConfig decoy_strings;
    ToggleConfig vtable_integrity;

    struct FuncWrapConfig {
        Opt<bool> enabled;
        Opt<std::uint32_t> probability;
        Opt<std::uint32_t> times;
    } func_wrap;
};

} // namespace morok::config

#endif // MOROK_CONFIG_PASS_CONFIG_HPP
