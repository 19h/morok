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

struct StackRebaseConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> realign_align;
    Opt<std::uint32_t> dynamic_size;
    Opt<std::uint32_t> relocate_probability;
    Opt<std::uint32_t> alias_amplify;
    Opt<bool> nonentry_shuffle;
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

struct FaultPagedPayloadConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> max_payloads;
    Opt<std::uint32_t> max_payload_bytes;
    Opt<std::uint32_t> page_size;
    Opt<std::string> delivery;
    Opt<std::string> backend;
    Opt<bool> per_page_keys;
    Opt<bool> reseal_after_use;
    Opt<std::uint32_t> decoy_pages;
    Opt<bool> fallback;
    Opt<bool> bind_to_runtime_seal;
    Opt<bool> virtualize_helpers;
};

struct ExternalSecretBindingConfig {
    Opt<bool> enabled;
    Opt<std::string> mode;
    Opt<std::string> public_key;
    Opt<std::string> expected_digest;
    Opt<std::string> identity_policy;
    Opt<bool> entitlement_gate;
    Opt<std::uint64_t> entitlement_required_mask;
    Opt<std::uint64_t> entitlement_not_before_epoch;
    Opt<std::uint64_t> entitlement_not_after_epoch;
    Opt<bool> bind_to_runtime_seal;
    Opt<bool> virtualize_helpers;
};

struct EnvBindingKdfConfig {
    Opt<bool> enabled;
    Opt<std::string> mode;
    Opt<std::string> expected_digest;
    Opt<std::string> identity_policy;
    Opt<std::uint32_t> min_factors;
    Opt<bool> bind_to_runtime_seal;
    Opt<bool> virtualize_helpers;
};

struct TracerAttestationConfig {
    Opt<bool> enabled;
    Opt<std::string> mode;
    Opt<std::uint32_t> shares;
    Opt<std::string> renewal;
    Opt<bool> bind_to_runtime_seal;
    Opt<bool> virtualize_helpers;
};

struct SealedBlobConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> max_blobs;
    Opt<std::uint32_t> max_blob_bytes;
    std::vector<std::string> key_sources;
    Opt<std::string> delivery;
    Opt<bool> zeroize_after_use;
    Opt<bool> runtime_keyed_magic;
    Opt<std::uint32_t> magic_bytes;
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
    Opt<bool> seal_required;
    Opt<std::uint32_t> carriers; ///< distinct carrier registers to rotate
};

struct ReturnlessDispatchConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> max_sites;
};

struct FunctionFissionConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> max_splits;
    Opt<std::uint32_t> min_region_blocks;
    Opt<std::uint32_t> max_region_blocks;
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

struct AntiDebuggingConfig {
    Opt<bool> enabled;
    // Defaults to true unless trap oracles require SIGTRAP ownership.  Set false
    // for configurations that prefer seal-enforced TracerPid checks over
    // PTRACE_TRACEME self-tracing.
    Opt<bool> allow_self_trace;
    // Only release/distribution pipelines should set this.  Developer and
    // ad-hoc macOS builds commonly carry get-task-allow=true, so entitlement
    // probes must remain telemetry-only unless this is explicit.
    Opt<bool> distribution_signed;
};

struct PlatformRuntimeConfig {
    Opt<bool> enabled;
    Opt<std::string> direct_syscalls; // auto | always | never
    Opt<std::string> windows_mode; // documented_api | hashed_import | direct_syscall
    Opt<bool> per_build_stubs;
    Opt<bool> minimize_imports;
    Opt<bool> import_table_audit;
    // Static-link release builds can opt into Linux AT_BASE enforcement.  The
    // verdict is not zero-on-clean for ordinary dynamic binaries, so presets
    // must keep this false unless the build system knows it is linking -static.
    Opt<bool> static_link_expected;
};

/// The full set of per-pass options.
struct PassConfig {
    BcfConfig bcf;
    SubConfig sub;
    MbaConfig mba;
    SplitConfig split;
    StackCoalesceConfig stack_coalesce;
    StackDeltaConfig stack_delta;
    StackRebaseConfig stack_rebase;
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
    FaultPagedPayloadConfig fault_paged_payload;
    ExternalSecretBindingConfig external_secret_binding;
    EnvBindingKdfConfig env_binding_kdf;
    TracerAttestationConfig tracer_attestation;
    SealedBlobConfig sealed_blob;
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
    ReturnlessDispatchConfig returnless_dispatch;
    FunctionFissionConfig function_fission;
    NanomiteConfig nanomites;
    StrEncConfig str_enc;
    ConstEncConfig const_enc;
    VecConfig vec;
    CsmConfig csm;
    ToggleConfig flatten;
    ToggleConfig indir_branch;
    ToggleConfig fco;
    ToggleConfig anti_hook;
    AntiDebuggingConfig anti_dbg;
    ToggleConfig anti_class_dump;
    ToggleConfig windows_pe_foundation;
    ToggleConfig windows_peb_heap_debug;
    ToggleConfig windows_debug_object;
    ToggleConfig windows_thread_hide;
    ToggleConfig windows_anti_attach;
    ToggleConfig windows_kernel_debugger;
    ToggleConfig windows_syscalls;
    ToggleConfig windows_process_modules;
    PlatformRuntimeConfig platform_runtime;
    ToggleConfig windows_unhook;
    ToggleConfig windows_veh_audit;
    ToggleConfig windows_process_mitigations;
    ToggleConfig timing_oracles;
    ToggleConfig scheduler_step_oracles;
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

    // Cross-pass fail-closed-on-unsealed mode (#106).  When set, the seal-
    // dependent passes (self-checksum, mutual-guard, caller-keyed dispatch) bind
    // the post-link code_size sentinel into their live key material so a binary
    // that was never post-link sealed (or whose seal slot was reset by a
    // downgrade patch) reconstructs garbage and cannot perform any seal-
    // dependent operation, instead of silently running unprotected.  Off by
    // default; only enable it for builds that are guaranteed to be sealed.
    Opt<bool> fail_closed_on_unsealed;
};

} // namespace morok::config

#endif // MOROK_CONFIG_PASS_CONFIG_HPP
