// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/pipeline/Scheduler.cpp

#include "morok/pipeline/Scheduler.hpp"

#include "morok/core/Entropy.hpp"
#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/Annotations.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/AdversarialFunctionMerging.hpp"
#include "morok/passes/AdversarialSelfTuning.hpp"
#include "morok/passes/AliasOpaquePredicates.hpp"
#include "morok/passes/AntiAnalysis.hpp"
#include "morok/passes/ArithmeticTables.hpp"
#include "morok/passes/BogusControlFlow.hpp"
#include "morok/passes/CallerKeyedDispatch.hpp"
#include "morok/passes/ChaosStateMachine.hpp"
#include "morok/passes/CoherentDecoys.hpp"
#include "morok/passes/ConstantEncryption.hpp"
#include "morok/passes/DataEntangledFlattening.hpp"
#include "morok/passes/DataFlowIntegrity.hpp"
#include "morok/passes/DecoyStrings.hpp"
#include "morok/passes/DispatcherlessRouting.hpp"
#include "morok/passes/EnvBindingKdf.hpp"
#include "morok/passes/ExternalOpaquePredicates.hpp"
#include "morok/passes/ExternalSecretBinding.hpp"
#include "morok/passes/Flattening.hpp"
#include "morok/passes/FaultPagedPayload.hpp"
#include "morok/passes/FunctionCallObfuscate.hpp"
#include "morok/passes/FunctionFission.hpp"
#include "morok/passes/FunctionWrapper.hpp"
#include "morok/passes/HashGatedSelfDecrypt.hpp"
#include "morok/passes/IndirectBranch.hpp"
#include "morok/passes/InterproceduralFsm.hpp"
#include "morok/passes/Mba.hpp"
#include "morok/passes/MicrocodeStress.hpp"
#include "morok/passes/Mirage.hpp"
#include "morok/passes/MisleadingMetadata.hpp"
#include "morok/passes/MqGate.hpp"
#include "morok/passes/MutualGuardGraph.hpp"
#include "morok/passes/Nanomites.hpp"
#include "morok/passes/NonInvertibleState.hpp"
#include "morok/passes/OptimizerAmplification.hpp"
#include "morok/passes/PathExplosion.hpp"
#include "morok/passes/PerBuildPolymorphism.hpp"
#include "morok/passes/PhiTangling.hpp"
#include "morok/passes/PointerLaundering.hpp"
#include "morok/passes/ReturnlessDispatch.hpp"
#include "morok/passes/SealedBlob.hpp"
#include "morok/passes/SelfChecksumConstants.hpp"
#include "morok/passes/ShamirShare.hpp"
#include "morok/passes/SplitBasicBlocks.hpp"
#include "morok/passes/StackCoalescing.hpp"
#include "morok/passes/StackDeltaGames.hpp"
#include "morok/passes/StackRebase.hpp"
#include "morok/passes/StateOpaquePredicates.hpp"
#include "morok/passes/StringEncryption.hpp"
#include "morok/passes/SubThresholdPersistence.hpp"
#include "morok/passes/Substitution.hpp"
#include "morok/passes/TracerAttestation.hpp"
#include "morok/passes/TraceKeying.hpp"
#include "morok/passes/TypePunning.hpp"
#include "morok/passes/UniformPrimitiveLowering.hpp"
#include "morok/passes/VTableIntegrity.hpp"
#include "morok/passes/VectorObfuscation.hpp"
#include "morok/passes/Virtualization.hpp"

#include "morok/runtime/PlatformRuntime.hpp"

#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

using namespace llvm;

namespace morok::pipeline {

namespace {

constexpr std::uint64_t kGrowthFunctionInstLimit = 2500;
constexpr std::uint64_t kGrowthFunctionBlockLimit = 300;
constexpr std::uint64_t kHeavyFunctionInstLimit = 1200;
constexpr std::uint64_t kHeavyFunctionBlockLimit = 160;
constexpr std::uint64_t kExplosiveFunctionInstLimit = 700;
constexpr std::uint64_t kExplosiveFunctionBlockLimit = 96;
constexpr std::uint64_t kSensitiveFunctionInstLimit = 1600;
constexpr std::uint64_t kSensitiveFunctionBlockLimit = 220;

// Integrity passes (DFI, self-checksum, mutual-guard) are placed at the tail of
// the per-function loop, so by the time they run the function has already been
// grown by every structural/value-level pass ahead of them.  Gating them on the
// generic growth/heavy budgets therefore made them silently skip on any
// non-trivial function (the same body that was 400 instructions at loop entry
// is past 2500 by the integrity stage).  They are checksum/guard transforms
// whose cost scales with a fixed region size, not with the whole function, so
// they can safely tolerate a much larger host than the growth-producing passes.
// Give them a dedicated, deliberately higher budget instead of loosening the
// shared limits (which would also amplify split/bcf/flatten on huge functions).
constexpr std::uint64_t kIntegrityFunctionInstLimit = 6000;
constexpr std::uint64_t kIntegrityFunctionBlockLimit = 800;

constexpr std::uint64_t kModuleGrowthInstLimit = 60000;
constexpr std::uint64_t kModuleGrowthBlockLimit = 8000;
constexpr std::uint64_t kModuleGrowthFunctionLimit = 1500;
constexpr std::uint64_t kModuleCloneInstLimit = 20000;
constexpr std::uint64_t kModuleCloneBlockLimit = 3000;
constexpr std::uint64_t kModuleCloneFunctionLimit = 500;
// Caller-keyed and returnless dispatch are bounded-cost passes: their work
// scales with the number of call/return SITES (already capped by max_calls /
// max_sites) and each site adds only a small fixed decode/branch sequence — they
// do not grow the module in proportion to its size.  Gating them on the growth
// budget (meant to bound passes that EXPLODE the module) wrongly skips them on a
// heavily-grown module — e.g. a tiny program whose verdict function flattens to
// tens of thousands of instructions — leaving the binary with no sealed dispatch
// at all.  Give them a much larger dedicated host, mirroring the integrity
// passes' dedicated per-function budget.
constexpr std::uint64_t kDispatchModuleInstLimit = 600000;
constexpr std::uint64_t kDispatchModuleBlockLimit = 80000;
constexpr std::uint64_t kDispatchModuleFunctionLimit = 12000;
constexpr std::uint64_t kModuleEligibleFunctionVisitLimit = 256;
constexpr std::uint64_t kSensitiveHelperVisitLimit = 64;

struct ModuleSize {
    std::uint64_t instructions = 0;
    std::uint64_t blocks = 0;
    std::uint64_t functions = 0;
};

std::uint64_t instructionCount(const Function &F) {
    std::uint64_t Count = 0;
    for (const BasicBlock &BB : F)
        Count += BB.size();
    return Count;
}

// Like instructionCount but stops as soon as `Max` is exceeded.  The
// per-function budget checks only need the boolean, so an over-budget function
// bails without walking its remaining blocks.
bool instructionCountAtMost(const Function &F, std::uint64_t Max) {
    std::uint64_t Count = 0;
    for (const BasicBlock &BB : F) {
        Count += BB.size();
        if (Count > Max)
            return false;
    }
    return true;
}

bool withinFunctionBudget(const Function &F, std::uint64_t MaxInstructions,
                          std::uint64_t MaxBlocks) {
    // Cheap O(1) block-count check first, then the early-exiting instruction
    // count, so over-budget functions bail without a full instruction walk.
    return F.size() <= MaxBlocks && instructionCountAtMost(F, MaxInstructions);
}

bool growthFunctionOk(const Function &F) {
    return withinFunctionBudget(F, kGrowthFunctionInstLimit,
                                kGrowthFunctionBlockLimit);
}

bool heavyFunctionOk(const Function &F) {
    return withinFunctionBudget(F, kHeavyFunctionInstLimit,
                                kHeavyFunctionBlockLimit);
}

bool explosiveFunctionOk(const Function &F) {
    return withinFunctionBudget(F, kExplosiveFunctionInstLimit,
                                kExplosiveFunctionBlockLimit);
}

bool sensitiveFunctionOk(const Function &F) {
    return withinFunctionBudget(F, kSensitiveFunctionInstLimit,
                                kSensitiveFunctionBlockLimit);
}

bool integrityFunctionOk(const Function &F) {
    return withinFunctionBudget(F, kIntegrityFunctionInstLimit,
                                kIntegrityFunctionBlockLimit);
}

ModuleSize measureModule(const Module &M) {
    ModuleSize Size;
    for (const Function &F : M) {
        if (F.isDeclaration())
            continue;
        ++Size.functions;
        Size.blocks += F.size();
        Size.instructions += instructionCount(F);
    }
    return Size;
}

// User-code-only size: excludes morok.* generated helpers (VM interpreters,
// anti-debug, decoys, …).  The per-function obfuscation budget is meant to
// bound how much we GROW the user's code, not the fixed-cost helpers other
// passes emit.  Counting the (large) VM interpreters here would let
// virtualization alone trip the budget and skip the still-pending integrity
// passes — leaving a binary with zero self-check coverage.
ModuleSize measureUserModule(const Module &M) {
    ModuleSize Size;
    for (const Function &F : M) {
        if (F.isDeclaration() || F.getName().starts_with("morok."))
            continue;
        ++Size.functions;
        Size.blocks += F.size();
        Size.instructions += instructionCount(F);
    }
    return Size;
}

bool withinModuleBudget(const ModuleSize &Size, std::uint64_t MaxInstructions,
                        std::uint64_t MaxBlocks, std::uint64_t MaxFunctions) {
    return Size.instructions <= MaxInstructions && Size.blocks <= MaxBlocks &&
           Size.functions <= MaxFunctions;
}

bool moduleGrowthOk(const ModuleSize &Size) {
    return withinModuleBudget(Size, kModuleGrowthInstLimit,
                              kModuleGrowthBlockLimit,
                              kModuleGrowthFunctionLimit);
}

bool dispatchModuleOk(const ModuleSize &Size) {
    return withinModuleBudget(Size, kDispatchModuleInstLimit,
                              kDispatchModuleBlockLimit,
                              kDispatchModuleFunctionLimit);
}

bool moduleCloneOk(const ModuleSize &Size) {
    return withinModuleBudget(Size, kModuleCloneInstLimit,
                              kModuleCloneBlockLimit,
                              kModuleCloneFunctionLimit);
}

bool hasSensitiveGeneratedPrefix(StringRef Name) {
    return Name.starts_with("morok.strdec") ||
           Name.starts_with("morok.sdb.ensure") ||
           Name.starts_with("morok.tablearith.ensure") ||
           Name.starts_with("morok.dfi.hash.") ||
           Name.starts_with("morok.sc.diff.") ||
           Name.starts_with("morok.sealed.") ||
           Name.starts_with("morok.mg.node.") ||
           Name.starts_with("morok.mg.diff.") ||
           Name.starts_with("morok.envbind.") ||
           Name.starts_with("morok.fpp.") ||
           Name.starts_with("morok.fission") ||
           Name.starts_with("morok.antidbg") ||
           Name.starts_with("morok.watchdog") ||
           Name.starts_with("morok.antihook") ||
           Name.starts_with("morok.vti.") || Name.starts_with("morok.timing") ||
           Name.starts_with("morok.trap");
}

bool isSensitiveGeneratedFunction(const Function &F) {
    if (F.isDeclaration())
        return false;
    StringRef Name = F.getName();
    // Keep fault/page-protection choreography native; generic shell hardening
    // can disturb the exact signal and mprotect edge these probes rely on.
    if (Name == "morok.antihook" ||
        Name.starts_with("morok.antihook.schro") ||
        Name.starts_with("morok.antihook.antidump") ||
        Name.starts_with("morok.fpp.signal.") ||
        Name.starts_with("morok.fpp.mprotect.") ||
        Name.starts_with("morok.fpp.veh."))
        return false;
    return hasSensitiveGeneratedPrefix(Name);
}

bool isUserSensitiveFunction(const Function &F) {
    return ir::hasAnnotation(F, "sensitive");
}

bool virtualizationConfigDiffers(const config::VirtualizationConfig &A,
                                 const config::VirtualizationConfig &B) {
    return A.enabled != B.enabled || A.probability != B.probability ||
           A.max_functions != B.max_functions ||
           A.max_instructions != B.max_instructions ||
           A.max_registers != B.max_registers;
}

bool vmEnabledForFunction(const Function &F,
                          const config::VirtualizationConfig &C) {
    if (ir::hasAnnotation(F, "novm") ||
        ir::hasAnnotation(F, "novirtualization"))
        return false;
    if (ir::hasAnnotation(F, "vm") || ir::hasAnnotation(F, "virtualization"))
        return true;
    return C.enabled.value_or(false);
}

struct UserVmPriorityPlan {
    bool has_target = false;
    std::uint32_t target_count = 0;
    std::uint32_t probability = 0;
    std::uint32_t max_functions = 0;
    std::uint32_t max_instructions = 0;
    std::uint32_t max_registers = 0;
};

UserVmPriorityPlan
markUserVmPriorityFunctions(Module &M, const config::Config &Config,
                            StringRef ModuleName,
                            const config::Demangler &Demangle) {
    UserVmPriorityPlan Plan;

    for (Function &F : M) {
        if (F.isDeclaration() || F.getName().starts_with("morok."))
            continue;

        const config::PassConfig Eff =
            config::resolve(Config, ModuleName, F.getName(), Demangle);
        if (!vmEnabledForFunction(F, Eff.virtualization))
            continue;

        const bool PolicyTargetsVm = virtualizationConfigDiffers(
            Eff.virtualization, Config.passes.virtualization);
        const bool SourceTargetsVm = isUserSensitiveFunction(F) ||
                                     ir::hasAnnotation(F, "vm") ||
                                     ir::hasAnnotation(F, "virtualization");
        if (!PolicyTargetsVm && !SourceTargetsVm)
            continue;

        const std::uint32_t TargetProbability =
            Eff.virtualization.probability.value_or(20);
        const std::uint32_t TargetMaxFunctions =
            Eff.virtualization.max_functions.value_or(1);
        if (TargetProbability == 0 || TargetMaxFunctions == 0)
            continue;

        ir::addAnnotation(F, "morok.vm.priority");
        Plan.has_target = true;
        ++Plan.target_count;
        Plan.probability = std::max(Plan.probability, TargetProbability);
        Plan.max_functions = std::max(Plan.max_functions, TargetMaxFunctions);
        Plan.max_instructions =
            std::max(Plan.max_instructions,
                     Eff.virtualization.max_instructions.value_or(
                         passes::VirtualizationParams{}.max_instructions));
        Plan.max_registers =
            std::max(Plan.max_registers,
                     Eff.virtualization.max_registers.value_or(
                         passes::VirtualizationParams{}.max_registers));
    }

    if (Plan.has_target) {
        Plan.probability = std::max<std::uint32_t>(Plan.probability, 100);
        Plan.max_functions =
            std::max<std::uint32_t>(Plan.max_functions, Plan.target_count);
        Plan.max_instructions =
            std::max<std::uint32_t>(Plan.max_instructions, 1024);
        Plan.max_registers = std::max<std::uint32_t>(Plan.max_registers, 255);
    }
    return Plan;
}

std::uint32_t raised(std::uint32_t Value, std::uint32_t Floor, bool Sensitive) {
    return Sensitive ? std::max(Value, Floor) : Value;
}

passes::BcfParams bcfParams(const config::BcfConfig &C, bool Sensitive) {
    passes::BcfParams P;
    P.probability = raised(C.probability.value_or(60), 100, Sensitive);
    P.iterations = C.iterations.value_or(1);
    P.complexity = C.complexity.value_or(1);
    P.entropy_chain = C.entropy_chain.value_or(false);
    P.junk_asm = C.junk_asm.value_or(false);
    P.junk_asm_min =
        std::min(C.junk_asm_min.value_or(0), passes::kBcfMaxJunkAsm);
    P.junk_asm_max =
        std::min(C.junk_asm_max.value_or(0), passes::kBcfMaxJunkAsm);
    if (P.junk_asm_max < P.junk_asm_min)
        P.junk_asm_max = P.junk_asm_min;
    return P;
}

passes::MbaParams mbaParams(const config::MbaConfig &C, bool Sensitive) {
    passes::MbaParams P;
    P.probability = raised(C.probability.value_or(60), 100, Sensitive);
    P.layers = raised(C.layers.value_or(2), 2, Sensitive);
    P.heuristic = Sensitive ? true : C.heuristic.value_or(true);
    return P;
}

passes::ExternalOpaqueParams
externalOpaqueParams(const config::ExternalOpConfig &C, bool Sensitive,
                     bool IncludeGenerated = false) {
    passes::ExternalOpaqueParams P;
    P.probability = raised(C.probability.value_or(35), 100, Sensitive);
    P.max_blocks = std::min(raised(C.max_blocks.value_or(8), 12, Sensitive),
                            passes::kExternalOpaqueMaxBlocks);
    P.decoy_stores = std::min(raised(C.decoy_stores.value_or(2), 3, Sensitive),
                              passes::kExternalOpaqueMaxDecoyStores);
    P.include_generated = IncludeGenerated;
    return P;
}

passes::HashGatedSelfDecryptParams
hashSelfDecryptParams(const config::HashSelfDecryptConfig &C) {
    passes::HashGatedSelfDecryptParams P;
    P.probability = C.probability.value_or(100);
    P.max_payloads = C.max_payloads.value_or(2);
    P.max_payload_bytes = C.max_payload_bytes.value_or(P.max_payload_bytes);
    P.context_keying = C.context_keying.value_or(true);
    return P;
}

passes::SealedBlobParams sealedBlobParams(const config::SealedBlobConfig &C) {
    passes::SealedBlobParams P;
    P.max_blobs = C.max_blobs.value_or(P.max_blobs);
    P.max_blob_bytes = C.max_blob_bytes.value_or(P.max_blob_bytes);
    if (!C.key_sources.empty())
        P.key_sources = C.key_sources;
    P.delivery = C.delivery.value_or(P.delivery);
    P.zeroize_after_use = C.zeroize_after_use.value_or(P.zeroize_after_use);
    P.runtime_keyed_magic =
        C.runtime_keyed_magic.value_or(P.runtime_keyed_magic);
    P.magic_bytes = C.magic_bytes.value_or(P.magic_bytes);
    return P;
}

passes::FaultPagedPayloadParams
faultPagedPayloadParams(const config::FaultPagedPayloadConfig &C) {
    passes::FaultPagedPayloadParams P;
    P.enabled = C.enabled.value_or(true);
    P.probability = C.probability.value_or(100);
    P.max_payloads = C.max_payloads.value_or(4);
    P.max_payload_bytes = C.max_payload_bytes.value_or(P.max_payload_bytes);
    P.page_size = C.page_size.value_or(P.page_size);
    P.backend = C.backend.value_or(C.delivery.value_or(P.backend));
    P.per_page_keys = C.per_page_keys.value_or(true);
    P.reseal_after_use = C.reseal_after_use.value_or(true);
    P.decoy_pages = C.decoy_pages.value_or(0);
    P.fallback = C.fallback.value_or(true);
    P.bind_to_runtime_seal = C.bind_to_runtime_seal.value_or(true);
    P.virtualize_helpers = C.virtualize_helpers.value_or(true);
    return P;
}

passes::MirageParams mirageParams(const config::MirageConfig &C,
                                  bool VmAvailable) {
    passes::MirageParams P;
    P.sensitive_only = C.sensitive_only.value_or(true);
    P.clone_count = C.clone_count.value_or(2);
    P.counterfeit_count = C.counterfeit_count.value_or(2);
    P.max_functions = C.max_functions.value_or(8);
    P.max_instructions = C.max_instructions.value_or(256);
    P.seal_gated_reality = C.seal_gated_reality.value_or(true);
    P.per_invocation_epoch = C.per_invocation_epoch.value_or(true);
    P.cross_guard = C.cross_guard.value_or(false);
    P.vm_profile_available = VmAvailable;
    if (!C.counterfeit_domains.empty())
        P.counterfeit_domains = C.counterfeit_domains;
    const std::string Route = C.force_route.value_or("auto");
    if (Route == "real")
        P.force_route = passes::MirageForceRoute::Real;
    else if (Route == "fake")
        P.force_route = passes::MirageForceRoute::Fake;
    return P;
}

passes::SelfChecksumDiffCacheMode
selfChecksumDiffCacheMode(const config::SelfChecksumConfig &C) {
    const std::string Mode = C.diff_cache.value_or("activation");
    if (Mode == "static")
        return passes::SelfChecksumDiffCacheMode::Static;
    return passes::SelfChecksumDiffCacheMode::Activation;
}

bool passEnabledOrImplicitSensitive(config::Opt<bool> Enabled, bool Sensitive) {
    if (Enabled.has_value())
        return *Enabled;
    return Sensitive;
}

bool hardenSensitiveGeneratedFunctions(Module &M,
                                       const config::PassConfig &Config,
                                       ir::IRRandom &Rng) {
    if (!Config.bcf.enabled.value_or(false) &&
        !Config.mba.enabled.value_or(false) &&
        !Config.external_op.enabled.value_or(false))
        return false;

    std::vector<Function *> Targets;
    Targets.reserve(16);
    for (Function &F : M) {
        if (Targets.size() >= kSensitiveHelperVisitLimit)
            break;
        if (isSensitiveGeneratedFunction(F) && sensitiveFunctionOk(F))
            Targets.push_back(&F);
    }

    bool Changed = false;
    for (Function *F : Targets) {
        if (!moduleGrowthOk(measureModule(M)))
            break;

        if (Config.bcf.enabled.value_or(false) && sensitiveFunctionOk(*F))
            Changed |= passes::bogusControlFlowFunction(
                *F, bcfParams(Config.bcf, /*Sensitive=*/true), Rng);
        if (Config.external_op.enabled.value_or(false) &&
            sensitiveFunctionOk(*F))
            Changed |= passes::externalOpaquePredicatesFunction(
                *F,
                externalOpaqueParams(Config.external_op, /*Sensitive=*/true,
                                     /*IncludeGenerated=*/true),
                Rng);
        if (Config.mba.enabled.value_or(false) && growthFunctionOk(*F))
            Changed |= passes::mbaFunction(
                *F, mbaParams(Config.mba, /*Sensitive=*/true), Rng);
    }
    return Changed;
}

bool virtualizeSensitiveGeneratedFunctions(Module &M,
                                           const config::PassConfig &Config,
                                           ir::IRRandom &Rng) {
    if (!Config.virtualization.enabled.value_or(false))
        return false;

    passes::VirtualizationParams P;
    P.probability = raised(Config.virtualization.probability.value_or(100), 100,
                           /*Sensitive=*/true);
    P.max_functions = raised(Config.virtualization.max_functions.value_or(1), 8,
                             /*Sensitive=*/true);
    P.max_instructions =
        raised(Config.virtualization.max_instructions.value_or(64), 256,
               /*Sensitive=*/true);
    P.max_registers = raised(Config.virtualization.max_registers.value_or(96),
                             160, /*Sensitive=*/true);
    P.include_protection_helpers = true;
    P.protection_helpers_only = true;
    return passes::virtualizeModule(M, P, Rng);
}

} // namespace

PreservedAnalyses MorokPass::run(Module &M, ModuleAnalysisManager &) {
    // Seed the shared engine: explicit seed for reproducible builds, otherwise
    // collected entropy.
    core::Xoshiro256pp engine = config_.seed != 0
                                    ? core::Xoshiro256pp::fromSeed(config_.seed)
                                    : core::makeSeededEngine();
    ir::IRRandom rng(engine);

    ir::materializeAnnotations(M);

    // Apply the operator's syscall-surface policy (#102) before any pass emits a
    // platform primitive, so platform_runtime.direct_syscalls = "never" actually
    // routes every syscall through imports instead of inline direct syscalls.
    runtime::setDirectSyscallPolicy(
        M, config_.passes.platform_runtime.direct_syscalls.value_or("auto"));

    const config::Demangler demangle = [](std::string_view s) -> std::string {
        return llvm::demangle(std::string(s));
    };

    const std::string moduleName = M.getSourceFileName();
    const ModuleSize InitialSize = measureModule(M);
    const bool InitialModuleGrowthOk = moduleGrowthOk(InitialSize);
    bool changed = false;

    // Mirage runs first, before VM priority marking and the first VM wave: it
    // clones each selected verdict-like function into equivalent reals + wrong-
    // but-plausible counterfeits behind a seal-gated branchless hub.  Real clone
    // 1 is stamped `vm`, so the VM priority planner below sees it and the first
    // wave can lift it; every candidate carries a non-`morok.*` name so it still
    // flows through the normal per-function transforms.  Gated on the module
    // growth budget so a huge module does not balloon further.
    if (InitialModuleGrowthOk &&
        config_.passes.mirage.enabled.value_or(false)) {
        const bool VmAvailable =
            config_.passes.virtualization.enabled.value_or(false);
        passes::MirageParams p =
            mirageParams(config_.passes.mirage, VmAvailable);
        changed |= passes::mirageModule(M, p, rng);
    }

    const UserVmPriorityPlan InitialVmPriority =
        InitialModuleGrowthOk
            ? markUserVmPriorityFunctions(M, config_, moduleName, demangle)
            : UserVmPriorityPlan{};

    if (InitialModuleGrowthOk &&
        config_.passes.external_secret_binding.enabled.value_or(false)) {
        passes::ExternalSecretBindingParams p;
        p.mode =
            config_.passes.external_secret_binding.mode.value_or("feed_api");
        p.expected_digest =
            config_.passes.external_secret_binding.expected_digest.value_or("");
        p.identity_policy =
            config_.passes.external_secret_binding.identity_policy.value_or(
                "ascii_lower_strip_ws");
        p.entitlement_gate = config_.passes.external_secret_binding
                                 .entitlement_gate.value_or(false);
        p.entitlement_required_mask =
            config_.passes.external_secret_binding.entitlement_required_mask
                .value_or(0);
        p.entitlement_not_before_epoch =
            config_.passes.external_secret_binding.entitlement_not_before_epoch
                .value_or(0);
        p.entitlement_not_after_epoch =
            config_.passes.external_secret_binding.entitlement_not_after_epoch
                .value_or(0);
        p.bind_to_runtime_seal = config_.passes.external_secret_binding
                                     .bind_to_runtime_seal.value_or(true);
        p.virtualize_helpers =
            config_.passes.external_secret_binding.virtualize_helpers.value_or(
                true);
        changed |= passes::externalSecretBindingModule(M, p, rng);
    }

    if (InitialModuleGrowthOk &&
        config_.passes.env_binding_kdf.enabled.value_or(false)) {
        passes::EnvBindingKdfParams p;
        p.mode = config_.passes.env_binding_kdf.mode.value_or("auto");
        p.expected_digest =
            config_.passes.env_binding_kdf.expected_digest.value_or("");
        p.identity_policy =
            config_.passes.env_binding_kdf.identity_policy.value_or(
                "ascii_lower_strip_ws");
        p.min_factors =
            config_.passes.env_binding_kdf.min_factors.value_or(2);
        p.bind_to_runtime_seal =
            config_.passes.env_binding_kdf.bind_to_runtime_seal.value_or(true);
        p.virtualize_helpers =
            config_.passes.env_binding_kdf.virtualize_helpers.value_or(true);
        changed |= passes::envBindingKdfModule(M, p, rng);
    }

    // Tracer attestation emits only generated helpers/constructors here. Seed
    // its seal channel before the first user VM wave so VM bytecode keys can
    // consume the channel; the later protection-helper VM wave can still lift
    // the generated share helper.
    if (InitialModuleGrowthOk &&
        config_.passes.tracer_attestation.enabled.value_or(false)) {
        passes::TracerAttestationParams p;
        p.mode =
            config_.passes.tracer_attestation.mode.value_or("linux_ptrace");
        p.shares = config_.passes.tracer_attestation.shares.value_or(2);
        p.renewal =
            config_.passes.tracer_attestation.renewal.value_or("startup");
        p.bind_to_runtime_seal =
            config_.passes.tracer_attestation.bind_to_runtime_seal.value_or(
                true);
        p.virtualize_helpers =
            config_.passes.tracer_attestation.virtualize_helpers.value_or(true);
        changed |= passes::tracerAttestationModule(M, p, rng);
    }

    if (InitialModuleGrowthOk &&
        config_.passes.sealed_blob.enabled.value_or(false)) {
        passes::SealedBlobParams p =
            sealedBlobParams(config_.passes.sealed_blob);
        changed |= passes::sealedBlobModule(M, p, rng);
    }

    // VM lifting runs before any later obfuscation touches user code.
    // The virtualizer only lifts pristine integer/pointer computation kernels;
    // later passes rewrite those bodies in ways the bytecode cannot encode and
    // would make them ineligible — decoy-string injection plants references to
    // global string pointers (un-encodable as bytecode immediates), and the
    // per-function loop's splitting/flattening reshapes the CFG.  Running the VM
    // up front lets it claim the clean kernels; every later pass then layers on
    // top of the resulting wrappers/helpers.  Fault-paged payload delivery and
    // hash-gated self-decrypt wrap this first wave of emitted bytecode, so they
    // run immediately after.  A later protection-helper-only VM pass covers
    // generated checker helpers once the anti-analysis/integrity passes have
    // emitted them.
    if (InitialModuleGrowthOk &&
        (config_.passes.virtualization.enabled.value_or(false) ||
         InitialVmPriority.has_target)) {
        passes::VirtualizationParams p;
        p.probability = config_.passes.virtualization.probability.value_or(20);
        p.max_functions =
            config_.passes.virtualization.max_functions.value_or(1);
        p.max_instructions =
            config_.passes.virtualization.max_instructions.value_or(64);
        p.max_registers =
            config_.passes.virtualization.max_registers.value_or(96);
        if (InitialVmPriority.has_target) {
            p.probability =
                std::max(p.probability, InitialVmPriority.probability);
            p.max_functions =
                std::max(p.max_functions, InitialVmPriority.max_functions);
            p.max_instructions = std::max(p.max_instructions,
                                          InitialVmPriority.max_instructions);
            p.max_registers =
                std::max(p.max_registers, InitialVmPriority.max_registers);
            p.prioritize_marked_user_functions = true;
        }
        // Lift trust-boundary functions that contain only DIRECT calls to
        // defined internal helpers (e.g. a license verdict computer), not just
        // pure leaf math.  virtualizeModule guards this with a call-graph SCC
        // check so a recursive / mutually-recursive function is never lifted —
        // routing recursion through the bytecode interpreter would amplify
        // stack frames and trap.  Indirect/import/vararg calls remain excluded.
        p.allow_internal_user_calls = true;
        changed |= passes::virtualizeModule(M, p, rng);
    }

    if (InitialModuleGrowthOk &&
        config_.passes.fault_paged_payload.enabled.value_or(false)) {
        passes::FaultPagedPayloadParams p =
            faultPagedPayloadParams(config_.passes.fault_paged_payload);
        changed |= passes::faultPagedPayloadModule(M, p, rng);
    }

    if (InitialModuleGrowthOk &&
        config_.passes.hash_self_decrypt.enabled.value_or(false)) {
        passes::HashGatedSelfDecryptParams p =
            hashSelfDecryptParams(config_.passes.hash_self_decrypt);
        changed |= passes::hashGatedSelfDecryptModule(M, p, rng);
    }

    // Anti-analysis module passes run earliest.
    if (config_.passes.anti_hook.enabled.value_or(false))
        changed |= passes::antiHookingModule(
            M, rng,
            config_.passes.platform_runtime.static_link_expected.value_or(false));
    if (config_.passes.anti_class_dump.enabled.value_or(false))
        changed |= passes::antiClassDumpModule(M);
    if (config_.passes.windows_pe_foundation.enabled.value_or(false))
        changed |= passes::windowsPeFoundationModule(M, rng);
    if (config_.passes.windows_peb_heap_debug.enabled.value_or(false))
        changed |= passes::windowsPebHeapDebugModule(M, rng);
    if (config_.passes.windows_debug_object.enabled.value_or(false))
        changed |= passes::windowsDebugObjectModule(M, rng);
    if (config_.passes.windows_thread_hide.enabled.value_or(false))
        changed |= passes::windowsThreadHideModule(M, rng);
    if (config_.passes.windows_anti_attach.enabled.value_or(false))
        changed |= passes::windowsAntiAttachModule(M, rng);
    if (config_.passes.windows_kernel_debugger.enabled.value_or(false))
        changed |= passes::windowsKernelDebuggerModule(M, rng);
    if (config_.passes.windows_syscalls.enabled.value_or(false))
        changed |= passes::windowsSyscallsModule(M, rng);
    if (config_.passes.windows_process_modules.enabled.value_or(false))
        changed |= passes::windowsProcessModulesModule(M, rng);
    if (config_.passes.windows_unhook.enabled.value_or(false))
        changed |= passes::windowsUnhookModule(M, rng);
    if (config_.passes.windows_veh_audit.enabled.value_or(false))
        changed |= passes::windowsVehAuditModule(M, rng);
    if (config_.passes.windows_process_mitigations.enabled.value_or(false))
        changed |= passes::windowsProcessMitigationsModule(M, rng);
    if (config_.passes.anti_dbg.enabled.value_or(false)) {
        bool allowSelfTrace =
            config_.passes.anti_dbg.allow_self_trace.value_or(true);
        if (config_.passes.trap_oracles.enabled.value_or(false))
            allowSelfTrace = false;
        changed |= passes::antiDebuggingModule(
            M, rng, allowSelfTrace,
            config_.passes.anti_dbg.distribution_signed.value_or(false));
    }
    if (config_.passes.timing_oracles.enabled.value_or(false))
        changed |= passes::timingOracleModule(M, rng);
    if (config_.passes.scheduler_step_oracles.enabled.value_or(false))
        changed |= passes::schedulerStepOracleModule(M, rng);
    if (config_.passes.trap_oracles.enabled.value_or(false))
        changed |= passes::trapOracleModule(M, rng);
    if (config_.passes.page_fault_oracles.enabled.value_or(false))
        changed |= passes::pageFaultTlbOracleModule(M, rng);
    if (config_.passes.cache_timing_oracles.enabled.value_or(false))
        changed |= passes::cacheTimingOracleModule(M, rng);
    if (config_.passes.microarchitectural_canaries.enabled.value_or(false))
        changed |= passes::microarchitecturalCanaryModule(M, rng);

    // Honeypot: distribute plausible plaintext diagnostics across user code.
    if (config_.passes.decoy_strings.enabled.value_or(false))
        changed |= passes::decoyStringsModule(M, rng);

    // Module-level string encryption runs before import rewriting, while the
    // original direct call sites still expose argument attributes/use shapes.
    if (InitialModuleGrowthOk &&
        config_.passes.str_enc.enabled.value_or(false)) {
        // Inline supported constant printf-family and simple sscanf formats
        // first, so recoverable format constants and hookable libc boundaries
        // are gone before the dead format globals are swept (and the remaining
        // strings encrypted).
        changed |= passes::inlineConstantFormatCalls(M);
        passes::StrEncParams sp;
        sp.probability = config_.passes.str_enc.probability.value_or(100);
        sp.skip_content = config_.passes.str_enc.skip_content;
        sp.force_content = config_.passes.str_enc.force_content;
        changed |= passes::stringEncryptModule(M, sp, rng);
    }

    // C++ virtual dispatch still has recognizable vptr/slot load shapes here.
    // Guard those call sites before VM/per-function transforms obscure them.
    if (InitialModuleGrowthOk &&
        config_.passes.vtable_integrity.enabled.value_or(false))
        changed |= passes::vtableIntegrityModule(M);

    // Function fission: split user functions into smaller `morok.fission.*`
    // callees BEFORE the per-function obfuscation wave.  The shrunken originals
    // fall back under the per-function budgets (so the integrity/seal passes can
    // reach logic an un-split monster function would have grown past every
    // budget), and the source function boundaries no longer match the binary.
    // Runs after the VM wave so virtualization claims whole kernels first.
    if (InitialModuleGrowthOk &&
        config_.passes.function_fission.enabled.value_or(false) &&
        dispatchModuleOk(measureUserModule(M))) {
        passes::FunctionFissionParams p;
        p.probability = config_.passes.function_fission.probability.value_or(100);
        p.max_splits = config_.passes.function_fission.max_splits.value_or(8);
        p.min_region_blocks =
            config_.passes.function_fission.min_region_blocks.value_or(2);
        p.max_region_blocks =
            config_.passes.function_fission.max_region_blocks.value_or(64);
        changed |= passes::functionFissionModule(M, p, rng);
    }

    if (InitialModuleGrowthOk) {
        std::uint64_t VisitedEligibleFunctions = 0;
        for (Function &F : M) {
            if (F.isDeclaration() || F.getName().starts_with("morok."))
                continue;
            if (VisitedEligibleFunctions >= kModuleEligibleFunctionVisitLimit)
                break;
            ++VisitedEligibleFunctions;
            // Gate on USER-code growth only: virtualization may have emitted
            // large morok.* interpreters that must not starve the integrity
            // passes still pending in this loop body.
            if (!moduleGrowthOk(measureUserModule(M)))
                break;

            const config::PassConfig eff =
                config::resolve(config_, moduleName, F.getName(), demangle);
            const bool Sensitive = isUserSensitiveFunction(F);

            // De-switch wide-magic gates FIRST, before any CFG pass consumes a
            // switch into a dispatch/jump-table form.  A license tier table
            // (`switch (hash) { case 0xMAGIC: ... }`) otherwise leaks every
            // case value as a cleartext compare the backend materializes;
            // lowering it here to encrypted comparison chains leaves
            // volatile-load constants that survive
            // split/flatten/dispatcherless/indirectbranch.  Only wide-magic
            // switches are touched, so dense dispatch stays intact and the
            // integrity passes are not inflated out of budget.
            if (integrityFunctionOk(F) &&
                ir::shouldObfuscate(F, "constenc",
                                    eff.const_enc.enabled.value_or(false))) {
                passes::ConstEncParams p;
                p.share_count = eff.const_enc.share_count.value_or(2);
                changed |= passes::deSwitchGateConstantsFunction(F, p, rng);
            }

            // Structural passes first: split creates more dispatch targets,
            // then bogus control flow widens the CFG, before the value-level
            // passes.
            if (heavyFunctionOk(F) &&
                ir::shouldObfuscate(F, "split",
                                    eff.split.enabled.value_or(false))) {
                passes::SplitParams p;
                p.splits = eff.split.splits.value_or(3);
                p.stack_confusion = eff.split.stack_confusion.value_or(false);
                changed |= passes::splitBlocksFunction(F, p, rng);
            }

            if (heavyFunctionOk(F) &&
                ir::shouldObfuscate(F, "bcf",
                                    passEnabledOrImplicitSensitive(
                                        eff.bcf.enabled, Sensitive))) {
                changed |= passes::bogusControlFlowFunction(
                    F, bcfParams(eff.bcf, Sensitive), rng);
            }

            // PM-sensitive: for `-mllvm -morok` this runs from the plugin's
            // vectorizer-start callback. This scheduler fallback supports
            // manual
            // `-passes=morok` placement without requiring a separate pass name.
            if (growthFunctionOk(F) &&
                ir::shouldObfuscate(F, "optamp",
                                    eff.opt_amplify.enabled.value_or(false))) {
                passes::OptAmpParams p;
                p.probability = eff.opt_amplify.probability.value_or(20);
                p.max_forms = eff.opt_amplify.max_forms.value_or(2);
                changed |= passes::optimizerAmplifyFunction(F, p, rng);
            }

            // Substitution before MBA, mirroring the documented ordering.
            if (growthFunctionOk(F) &&
                ir::shouldObfuscate(F, "sub",
                                    eff.sub.enabled.value_or(false))) {
                passes::SubstitutionParams p;
                p.probability = eff.sub.probability.value_or(50);
                p.iterations = eff.sub.iterations.value_or(1);
                changed |= passes::substituteFunction(F, p, rng);
            }

            if (growthFunctionOk(F) &&
                ir::shouldObfuscate(F, "mba",
                                    passEnabledOrImplicitSensitive(
                                        eff.mba.enabled, Sensitive))) {
                changed |=
                    passes::mbaFunction(F, mbaParams(eff.mba, Sensitive), rng);
            }

            // Add small volatile-neutral webs after Sub/MBA have expanded
            // scalar expressions but before CFG-heavy passes make the local
            // value graph harder to place near the original operation.
            if (growthFunctionOk(F) &&
                ir::shouldObfuscate(
                    F, "threshold",
                    eff.sub_threshold.enabled.value_or(false))) {
                passes::SubThresholdParams p;
                p.probability = eff.sub_threshold.probability.value_or(25);
                p.max_terms = eff.sub_threshold.max_terms.value_or(1);
                changed |= passes::subThresholdPersistFunction(F, p, rng);
            }

            // Alias-invariant guards widen the CFG after value-level expansion,
            // so their own pointer/int scaffolding does not get amplified by
            // Sub/MBA.
            if (heavyFunctionOk(F) &&
                ir::shouldObfuscate(F, "aliasop",
                                    eff.alias_op.enabled.value_or(false))) {
                passes::AliasOpParams p;
                p.probability = eff.alias_op.probability.value_or(45);
                p.iterations = eff.alias_op.iterations.value_or(1);
                p.max_blocks = eff.alias_op.max_blocks.value_or(16);
                changed |= passes::aliasOpaquePredicatesFunction(F, p, rng);
            }

            // Context-derived opaque predicates add side-effecting guard calls
            // before decoys and flattening absorb the widened CFG.
            if ((Sensitive ? sensitiveFunctionOk(F) : heavyFunctionOk(F)) &&
                ir::shouldObfuscate(F, "extop",
                                    passEnabledOrImplicitSensitive(
                                        eff.external_op.enabled, Sensitive))) {
                changed |= passes::externalOpaquePredicatesFunction(
                    F, externalOpaqueParams(eff.external_op, Sensitive), rng);
            }

            // Coherent dead paths use opaque-true guards but return plausible
            // alternate results, so flattening later absorbs them as
            // real-looking CFG structure rather than obvious junk.
            if (heavyFunctionOk(F) &&
                ir::shouldObfuscate(
                    F, "decoy", eff.coherent_decoy.enabled.value_or(false))) {
                passes::CoherentDecoyParams p;
                p.probability = eff.coherent_decoy.probability.value_or(35);
                p.max_blocks = eff.coherent_decoy.max_blocks.value_or(4);
                p.depth = eff.coherent_decoy.depth.value_or(3);
                changed |= passes::coherentDecoysFunction(F, p, rng);
            }

            // Exactly one control-flow-flattening layer per function, after the
            // value-level passes: prefer non-invertible encoded states, then
            // data-entangled state updates, then the chaos state machine, then
            // plain flattening.
            bool flattened = false;
            if (explosiveFunctionOk(F) &&
                ir::shouldObfuscate(
                    F, "nistate",
                    eff.non_invertible_state.enabled.value_or(false))) {
                passes::NonInvertibleStateParams p;
                p.max_terms = eff.non_invertible_state.max_terms.value_or(4);
                p.rounds = eff.non_invertible_state.rounds.value_or(3);
                flattened = passes::nonInvertibleStateFunction(F, p, rng);
                changed |= flattened;
            }
            if (!flattened && explosiveFunctionOk(F) &&
                ir::shouldObfuscate(
                    F, "entfla",
                    eff.data_entangled_flatten.enabled.value_or(false))) {
                passes::DataEntangledFlattenParams p;
                p.max_terms = eff.data_entangled_flatten.max_terms.value_or(4);
                flattened = passes::dataEntangledFlattenFunction(F, p, rng);
                changed |= flattened;
            }
            if (!flattened && explosiveFunctionOk(F) &&
                ir::shouldObfuscate(F, "csm",
                                    eff.csm.enabled.value_or(false))) {
                passes::CsmParams p;
                p.generator = eff.csm.generator.value_or(
                                  config::CsmGenerator::Logistic) ==
                                      config::CsmGenerator::TFunction
                                  ? passes::CsmGenerator::TFunction
                                  : passes::CsmGenerator::Logistic;
                p.tf_const = eff.csm.tf_const.value_or(0);
                p.warmup = eff.csm.warmup.value_or(64);
                p.nested_dispatch = eff.csm.nested_dispatch.value_or(false);
                flattened = passes::chaosStateMachineFunction(F, p, rng);
                changed |= flattened;
            }
            if (!flattened && explosiveFunctionOk(F) &&
                ir::shouldObfuscate(F, "fla",
                                    eff.flatten.enabled.value_or(false))) {
                changed |= passes::flattenFunction(F, rng);
            }

            if (heavyFunctionOk(F) &&
                ir::shouldObfuscate(F, "stateop",
                                    eff.state_opaque.enabled.value_or(false))) {
                passes::StateOpParams p;
                p.probability = eff.state_opaque.probability.value_or(45);
                p.max_blocks = eff.state_opaque.max_blocks.value_or(16);
                p.max_terms = eff.state_opaque.max_terms.value_or(4);
                changed |= passes::stateOpaquePredicatesFunction(F, p, rng);
            }

            if (heavyFunctionOk(F) &&
                ir::shouldObfuscate(
                    F, "ifsm",
                    eff.interprocedural_fsm.enabled.value_or(false))) {
                passes::InterproceduralFsmParams p;
                p.probability =
                    eff.interprocedural_fsm.probability.value_or(100);
                p.max_sites = eff.interprocedural_fsm.max_sites.value_or(64);
                p.max_terms = eff.interprocedural_fsm.max_terms.value_or(4);
                changed |= passes::interproceduralFsmSplitFunction(F, p, rng);
            }

            if (heavyFunctionOk(F) &&
                ir::shouldObfuscate(F, "phitangle",
                                    eff.phi_tangle.enabled.value_or(false))) {
                passes::PhiTangleParams p;
                p.probability = eff.phi_tangle.probability.value_or(45);
                p.layers = eff.phi_tangle.layers.value_or(2);
                p.max_phis = eff.phi_tangle.max_phis.value_or(32);
                changed |= passes::phiTangleFunction(F, p, rng);
            }

            if (growthFunctionOk(F) &&
                ir::shouldObfuscate(F, "typepun",
                                    eff.type_pun.enabled.value_or(false))) {
                passes::TypePunParams p;
                p.probability = eff.type_pun.probability.value_or(35);
                p.include_floating =
                    eff.type_pun.include_floating.value_or(true);
                p.max_targets = eff.type_pun.max_targets.value_or(64);
                changed |= passes::typePunFunction(F, p, rng);
            }

            // Collapse user and Reg2Mem-created locals after flattening has
            // introduced its frame slots, directly attacking lvar recovery.
            if (growthFunctionOk(F) &&
                ir::shouldObfuscate(
                    F, "stackcoalesce",
                    eff.stack_coalesce.enabled.value_or(false))) {
                passes::StackCoalesceParams p;
                p.probability = eff.stack_coalesce.probability.value_or(100);
                p.opaque_offsets =
                    eff.stack_coalesce.opaque_offsets.value_or(true);
                changed |= passes::stackCoalesceFunction(F, p, rng);
            }

            // Force dynamic stack-pointer deltas after static locals have been
            // coalesced, while leaving the generated stack slots available for
            // the pointer-laundering pass below.
            if (heavyFunctionOk(F) &&
                ir::shouldObfuscate(F, "stackdelta",
                                    eff.stack_delta.enabled.value_or(false))) {
                passes::StackDeltaParams p;
                p.probability = eff.stack_delta.probability.value_or(35);
                p.max_blocks = eff.stack_delta.max_blocks.value_or(6);
                p.min_bytes = eff.stack_delta.min_bytes.value_or(17);
                p.max_extra_bytes =
                    eff.stack_delta.max_extra_bytes.value_or(64);
                p.touches = eff.stack_delta.touches.value_or(3);
                changed |= passes::stackDeltaGamesFunction(F, p, rng);
            }

            // Persistently pressure the backend into realigned/dynamic stack
            // frames and escape selected frame addresses before pointer
            // laundering obscures the emitted GEP/int traffic.
            if (heavyFunctionOk(F) &&
                ir::shouldObfuscate(F, "stackrebase",
                                    eff.stack_rebase.enabled.value_or(false))) {
                passes::StackRebaseParams p;
                p.realign_align =
                    eff.stack_rebase.realign_align.value_or(64);
                p.dynamic_size =
                    eff.stack_rebase.dynamic_size.value_or(128);
                p.relocate_probability =
                    eff.stack_rebase.relocate_probability.value_or(60);
                p.alias_amplify =
                    eff.stack_rebase.alias_amplify.value_or(40);
                p.nonentry_shuffle =
                    eff.stack_rebase.nonentry_shuffle.value_or(false);
                changed |= passes::stackRebaseFunction(F, p, rng);
            }

            // Launder the frame/GEP pointers introduced above and selected
            // integer SSA values through pointer-int and vector-scalar
            // boundaries.
            if (growthFunctionOk(F) &&
                ir::shouldObfuscate(
                    F, "ptrlaunder",
                    eff.pointer_launder.enabled.value_or(false))) {
                passes::PointerLaunderParams p;
                p.pointer_probability =
                    eff.pointer_launder.pointer_probability.value_or(80);
                p.integer_probability =
                    eff.pointer_launder.integer_probability.value_or(35);
                changed |= passes::pointerLaunderFunction(F, p, rng);
            }

            // Integrity-bound byte tables consume selected byte ops before the
            // generic arithmetic table pass handles the remaining ones.
            if (integrityFunctionOk(F) &&
                ir::shouldObfuscate(
                    F, "dfi",
                    eff.data_flow_integrity.enabled.value_or(false))) {
                passes::DataFlowIntegrityParams p;
                p.probability =
                    eff.data_flow_integrity.probability.value_or(35);
                p.max_tables = eff.data_flow_integrity.max_tables.value_or(2);
                p.region_bytes =
                    eff.data_flow_integrity.region_bytes.value_or(32);
                // Entangle with the coherent-decoy hidden state whenever decoys
                // are enabled, so the state load is emitted on every protected
                // function regardless of module/RNG visit order (#53).
                p.decoy_state = eff.coherent_decoy.enabled.value_or(false);
                changed |= passes::dataFlowIntegrityFunction(F, p, rng);
            }

            // Replace surviving byte arithmetic with encrypted lazy lookup
            // tables.
            if (growthFunctionOk(F) &&
                ir::shouldObfuscate(F, "tablearith",
                                    eff.table_arith.enabled.value_or(false))) {
                passes::TableArithParams p;
                p.probability = eff.table_arith.probability.value_or(30);
                p.max_tables = eff.table_arith.max_tables.value_or(8);
                changed |= passes::tableArithmeticFunction(F, p, rng);
            }

            // Uniform primitive lowering moves byte ops to tables and selected
            // direct branch structure to memory-loaded indirect dispatch.
            if (growthFunctionOk(F) &&
                ir::shouldObfuscate(
                    F, "uniform", eff.uniform_lower.enabled.value_or(false))) {
                passes::UniformLowerParams p;
                p.op_probability =
                    eff.uniform_lower.op_probability.value_or(25);
                p.branch_probability =
                    eff.uniform_lower.branch_probability.value_or(35);
                p.max_tables = eff.uniform_lower.max_tables.value_or(4);
                p.max_branches = eff.uniform_lower.max_branches.value_or(8);
                changed |= passes::uniformPrimitiveLowerFunction(F, p, rng);
            }

            // SIMD lifting after the control-flow passes, so even dispatcher
            // arithmetic gets vectorised.
            if (growthFunctionOk(F) &&
                ir::shouldObfuscate(F, "vobf",
                                    eff.vec.enabled.value_or(false))) {
                passes::VecParams p;
                p.probability = eff.vec.probability.value_or(40);
                p.width = eff.vec.width.value_or(128);
                p.shuffle = eff.vec.shuffle.value_or(false);
                p.lift_comparisons = eff.vec.lift_comparisons.value_or(true);
                changed |= passes::vectorObfuscateFunction(F, p, rng);
            }

            // Anti-DSE decoy loops run after flattening/vectorization so their
            // indirectbr regions do not block the CFG-structuring passes.
            if (explosiveFunctionOk(F) &&
                ir::shouldObfuscate(
                    F, "pathexplode",
                    eff.path_explosion.enabled.value_or(false))) {
                passes::PathExplosionParams p;
                p.probability = eff.path_explosion.probability.value_or(25);
                p.max_blocks = eff.path_explosion.max_blocks.value_or(4);
                p.max_iterations =
                    eff.path_explosion.max_iterations.value_or(16);
                changed |= passes::pathExplosionFunction(F, p, rng);
            }

            // Plant a quadratic GF(2) gate over argument-derived bits before
            // trace keying and dispatcherless routing hide the resulting guard
            // edge.
            if (explosiveFunctionOk(F) &&
                ir::shouldObfuscate(F, "mq",
                                    eff.mq_gate.enabled.value_or(false))) {
                passes::MqGateParams p;
                p.probability = eff.mq_gate.probability.value_or(20);
                p.vars = eff.mq_gate.vars.value_or(24);
                p.eqs = eff.mq_gate.eqs.value_or(24);
                p.density = eff.mq_gate.density.value_or(50);
                p.max_gates = eff.mq_gate.max_gates.value_or(2);
                p.fold_diff = eff.mq_gate.fold_diff.value_or(true);
                changed |= passes::mqGateFunction(F, p, rng);
            }

            // Fold the observed CFG order into a rolling accumulator, then
            // guard selected blocks and poison data/control only if the trace
            // diverges.
            if (explosiveFunctionOk(F) &&
                ir::shouldObfuscate(F, "tracekey",
                                    eff.trace_keying.enabled.value_or(false))) {
                passes::TraceKeyParams p;
                p.probability = eff.trace_keying.probability.value_or(20);
                p.max_blocks = eff.trace_keying.max_blocks.value_or(8);
                changed |= passes::traceKeyFunction(F, p, rng);
            }

            // Dispatcherless routing converts remaining direct
            // branches/switches to local indirectbr table lookups after every
            // CFG-structuring pass.
            if (explosiveFunctionOk(F) &&
                ir::shouldObfuscate(
                    F, "dispatchless",
                    eff.dispatcherless.enabled.value_or(false))) {
                passes::DispatcherlessRoutingParams p;
                p.probability = eff.dispatcherless.probability.value_or(50);
                p.max_routes = eff.dispatcherless.max_routes.value_or(32);
                p.max_terms = eff.dispatcherless.max_terms.value_or(4);
                changed |= passes::dispatcherlessRoutingFunction(F, p, rng);
            }

            // Add semantics-neutral oversized computed jump tables and aliased
            // decoy destinations after real routing has been lowered, so this
            // pass stresses decompiler microcode without blocking earlier CFG
            // transforms.
            if (explosiveFunctionOk(F) &&
                ir::shouldObfuscate(
                    F, "microstress",
                    eff.microcode_stress.enabled.value_or(false))) {
                passes::MicrocodeStressParams p;
                p.probability = eff.microcode_stress.probability.value_or(25);
                p.max_sites = eff.microcode_stress.max_sites.value_or(3);
                p.table_entries =
                    eff.microcode_stress.table_entries.value_or(32);
                p.decoy_blocks = eff.microcode_stress.decoy_blocks.value_or(8);
                p.alias_stores = eff.microcode_stress.alias_stores.value_or(2);
                changed |= passes::microcodeStressFunction(F, p, rng);
            }

            // Feed a runtime checksum diff into constants as data, not a
            // branch.
            if (integrityFunctionOk(F) &&
                ir::shouldObfuscate(
                    F, "selfcheck",
                    eff.self_checksum.enabled.value_or(false))) {
                passes::SelfChecksumParams p;
                p.probability = eff.self_checksum.probability.value_or(35);
                p.max_constants = eff.self_checksum.max_constants.value_or(8);
                p.region_bytes = eff.self_checksum.region_bytes.value_or(32);
                p.fail_closed_on_unsealed =
                    eff.fail_closed_on_unsealed.value_or(false);
                p.diff_cache = selfChecksumDiffCacheMode(eff.self_checksum);
                changed |= passes::selfChecksumConstantsFunction(F, p, rng);
            }

            // Overlap several checksum nodes and poison selected return values
            // with the aggregate graph diff.  Constant encryption can still
            // hide the literals introduced in the user function.
            if (integrityFunctionOk(F) &&
                ir::shouldObfuscate(F, "mutualguard",
                                    eff.mutual_guard.enabled.value_or(false))) {
                passes::MutualGuardGraphParams p;
                p.probability = eff.mutual_guard.probability.value_or(35);
                p.nodes = eff.mutual_guard.nodes.value_or(3);
                p.region_bytes = eff.mutual_guard.region_bytes.value_or(32);
                p.max_returns = eff.mutual_guard.max_returns.value_or(2);
                p.fail_closed_on_unsealed =
                    eff.fail_closed_on_unsealed.value_or(false);
                changed |= passes::mutualGuardGraphFunction(F, p, rng);
            }

            // Threshold-share selected literals after the late integrity passes
            // have seen the original constants and before generic constant
            // encryption claims any remaining eligible operands.
            if (growthFunctionOk(F) &&
                ir::shouldObfuscate(F, "shamir",
                                    eff.shamir_share.enabled.value_or(false))) {
                passes::ShamirShareParams p;
                p.probability = eff.shamir_share.probability.value_or(30);
                p.threshold = eff.shamir_share.threshold.value_or(3);
                p.shares = eff.shamir_share.shares.value_or(5);
                p.max_secrets = eff.shamir_share.max_secrets.value_or(8);
                changed |= passes::shamirShareFunction(F, p, rng);
            }

            // Constant encryption hides the literals the other passes
            // introduce.
            if (growthFunctionOk(F) &&
                ir::shouldObfuscate(F, "constenc",
                                    eff.const_enc.enabled.value_or(false))) {
                passes::ConstEncParams p;
                p.probability =
                    100; // encrypt every eligible literal when enabled
                p.share_count = eff.const_enc.share_count.value_or(2);
                p.iterations = eff.const_enc.iterations.value_or(1);
                p.feistel = eff.const_enc.feistel.value_or(false);
                p.substitute_xor = eff.const_enc.substitute_xor.value_or(false);
                p.substitute_xor_prob =
                    eff.const_enc.substitute_xor_prob.value_or(100);
                p.globalize = eff.const_enc.globalize.value_or(false);
                p.globalize_prob = eff.const_enc.globalize_prob.value_or(100);
                p.skip_value = eff.const_enc.skip_value;
                p.force_value = eff.const_enc.force_value;
                changed |= passes::constantEncryptFunction(F, p, rng);
            }

            // Decision-gate rescue: the generic constenc above runs on the
            // tight growth budget and skips heavily-inlined gate functions (a
            // license check folds h0/h1/k2 into one large body well past 2500
            // insts), leaving the gate `cmp reg, #0xMAGIC` in the clear for an
            // attacker to read and NOP.  Re-run constenc here on the higher
            // integrity budget, scoped to wide comparison magics only, so the
            // gate immediate is encrypted even in those large functions. Placed
            // after the integrity passes so it never inflates them out of their
            // own budget.
            if (integrityFunctionOk(F) &&
                ir::shouldObfuscate(F, "constenc",
                                    eff.const_enc.enabled.value_or(false))) {
                passes::ConstEncParams p;
                p.probability = 100;
                p.share_count = eff.const_enc.share_count.value_or(2);
                p.iterations = 1;
                p.conditions_only = true;
                p.feistel = eff.const_enc.feistel.value_or(false);
                p.substitute_xor = eff.const_enc.substitute_xor.value_or(false);
                p.substitute_xor_prob =
                    eff.const_enc.substitute_xor_prob.value_or(100);
                p.globalize = eff.const_enc.globalize.value_or(false);
                p.globalize_prob = eff.const_enc.globalize_prob.value_or(100);
                p.skip_value = eff.const_enc.skip_value;
                p.force_value = eff.const_enc.force_value;
                changed |= passes::constantEncryptFunction(F, p, rng);
            }

            // Indirect branching last per function (it consumes the conditional
            // branches the other passes leave behind).
            if (heavyFunctionOk(F) &&
                ir::shouldObfuscate(F, "indibran",
                                    eff.indir_branch.enabled.value_or(false))) {
                passes::IndirParams p;
                changed |= passes::indirectBranchFunction(F, p, rng);
            }

            // Record that the per-function wave reached this function, so the
            // guaranteed integrity wave below only revisits the functions the
            // loop never got to (it breaks once the growing module exceeds the
            // growth budget).
            F.addFnAttr("morok.reached");
        }
    }

    // Guaranteed integrity coverage.  The per-function loop above breaks once the
    // growing module exceeds the growth budget, so a single ballooning function
    // (e.g. a date routine that flattens to 100k+ instructions) can starve every
    // function after it in module order of self-check / mutual-guard coverage —
    // and which functions those are shifts per target, so the same source can
    // ship sealed on one arch and unsealed (0 self-check manifests) on another.
    // Re-run only the bounded integrity passes on the not-yet-reached eligible
    // functions, gated on their own per-function budget and a dispatch-style
    // module budget rather than the growth break, so every build carries at
    // least the configured seal coverage.
    if (InitialModuleGrowthOk && dispatchModuleOk(measureUserModule(M))) {
        for (Function &F : M) {
            if (F.isDeclaration() || F.getName().starts_with("morok.") ||
                F.hasFnAttribute("morok.reached") || !integrityFunctionOk(F))
                continue;
            const config::PassConfig eff =
                config::resolve(config_, moduleName, F.getName(), demangle);
            if (ir::shouldObfuscate(F, "selfcheck",
                                    eff.self_checksum.enabled.value_or(false))) {
                passes::SelfChecksumParams p;
                p.probability = eff.self_checksum.probability.value_or(35);
                p.max_constants = eff.self_checksum.max_constants.value_or(8);
                p.region_bytes = eff.self_checksum.region_bytes.value_or(32);
                p.fail_closed_on_unsealed =
                    eff.fail_closed_on_unsealed.value_or(false);
                p.diff_cache = selfChecksumDiffCacheMode(eff.self_checksum);
                changed |= passes::selfChecksumConstantsFunction(F, p, rng);
            }
            if (ir::shouldObfuscate(F, "mutualguard",
                                    eff.mutual_guard.enabled.value_or(false))) {
                passes::MutualGuardGraphParams p;
                p.probability = eff.mutual_guard.probability.value_or(35);
                p.nodes = eff.mutual_guard.nodes.value_or(3);
                p.region_bytes = eff.mutual_guard.region_bytes.value_or(32);
                p.max_returns = eff.mutual_guard.max_returns.value_or(2);
                p.fail_closed_on_unsealed =
                    eff.fail_closed_on_unsealed.value_or(false);
                changed |= passes::mutualGuardGraphFunction(F, p, rng);
            }
            F.addFnAttr("morok.reached");
        }
    }

    // M4: bind reused leaf helpers (l1/g*/… in the validation cluster) to the
    // anti-debug seal, so a keygen calling them directly from an injected
    // context gets garbage.  Runs after the self-checksum loop so the seal
    // exists and the already-poisoned helpers (m0/m1/l0 — poisonReturns already
    // folds the seal-bearing diff into their returns) are skipped to avoid an
    // XOR double-fold.
    if (InitialModuleGrowthOk)
        changed |= passes::bindLeafHelpersToSeal(M, rng);

    // Bind the string-seed provider to the same anti-debug seal: zero-on-clean,
    // so the encrypted string pool decodes only when no analysis verdict has
    // fired — directly countering the dynamic recovery the field report used.
    if (InitialModuleGrowthOk)
        changed |= passes::bindStringSeedToSeal(M, rng);

    // Sensitive generated helpers are deliberately skipped by the normal
    // per-function loop because they are `morok.*`.  Once anti-debug,
    // anti-hook, and integrity passes have emitted their helpers, lift the
    // allowlisted checker bodies into bytecode VMs so their logic is not left
    // as native plaintext.  The existing shell-hardening pass can then add MBA
    // and opaque predicates around whatever wrapper/helper code remains.
    if (InitialModuleGrowthOk)
        changed |=
            virtualizeSensitiveGeneratedFunctions(M, config_.passes, rng);

    if (InitialModuleGrowthOk)
        changed |= hardenSensitiveGeneratedFunctions(M, config_.passes, rng);

    // Re-scan after the late generated-helper stage.  Already wrapped user VM
    // bytecode is mutable and skipped, while any new helper bytecode emitted
    // late is still a constant morok.vm.bytecode.* payload and receives the
    // same configured delivery boundary.
    if (InitialModuleGrowthOk &&
        config_.passes.fault_paged_payload.enabled.value_or(false)) {
        passes::FaultPagedPayloadParams p =
            faultPagedPayloadParams(config_.passes.fault_paged_payload);
        changed |= passes::faultPagedPayloadModule(M, p, rng);
    }

    if (InitialModuleGrowthOk &&
        config_.passes.hash_self_decrypt.enabled.value_or(false)) {
        passes::HashGatedSelfDecryptParams p =
            hashSelfDecryptParams(config_.passes.hash_self_decrypt);
        changed |= passes::hashGatedSelfDecryptModule(M, p, rng);
    }

    // Nanomites consume the branch shape that survives all per-function CFG
    // passes.  Keep them late so their trap sites are not restructured away.
    //
    // These late module-pass gates measure USER code only (measureUserModule):
    // string encryption runs earlier and can emit thousands of generated
    // `morok.strdec` decryptor functions, and counting those against the
    // module-function budget would push a string-heavy-but-otherwise-small
    // module past the limit and silently drop these configured protections on
    // the actual user code (#40).  The clone budgets below stay on
    // measureModule because a whole-module clone really does copy the helpers
    // too.
    if (InitialModuleGrowthOk &&
        config_.passes.nanomites.enabled.value_or(false) &&
        moduleGrowthOk(measureUserModule(M))) {
        passes::NanomiteParams p;
        p.probability = config_.passes.nanomites.probability.value_or(35);
        p.max_sites = config_.passes.nanomites.max_sites.value_or(16);
        changed |= passes::nanomitesModule(M, p, rng);
    }

    const ModuleSize PostFunctionSize =
        InitialModuleGrowthOk ? measureModule(M) : InitialSize;

    // Score-guided harness: search bounded candidate bundles on cloned modules,
    // then replay the strongest verified bundle before final call-graph/layout
    // perturbation makes module-level structure less comparable.
    if (InitialModuleGrowthOk &&
        config_.passes.adversarial_tuning.enabled.value_or(false) &&
        moduleCloneOk(PostFunctionSize)) {
        passes::AdversarialTuningParams p;
        p.max_candidates =
            config_.passes.adversarial_tuning.max_candidates.value_or(4);
        p.max_candidate_passes =
            config_.passes.adversarial_tuning.max_candidate_passes.value_or(3);
        p.score_floor =
            config_.passes.adversarial_tuning.score_floor.value_or(32);
        p.emit_marker =
            config_.passes.adversarial_tuning.emit_marker.value_or(true);
        changed |= passes::adversarialSelfTuneModule(M, p, rng);
    }

    // Late whole-module call-graph confusion: keep original symbols but route
    // same-signature bodies through shared selector dispatchers, with selected
    // scalar fragments outlined into shared noinline helpers.
    if (InitialModuleGrowthOk &&
        config_.passes.adversarial_merge.enabled.value_or(false) &&
        moduleGrowthOk(measureUserModule(M))) {
        passes::AdversarialMergeParams p;
        p.probability =
            config_.passes.adversarial_merge.probability.value_or(25);
        p.max_groups = config_.passes.adversarial_merge.max_groups.value_or(1);
        p.max_functions =
            config_.passes.adversarial_merge.max_functions.value_or(4);
        p.outline_probability =
            config_.passes.adversarial_merge.outline_probability.value_or(35);
        p.max_outlines =
            config_.passes.adversarial_merge.max_outlines.value_or(8);
        changed |= passes::adversarialFunctionMergingModule(M, p, rng);
    }

    // Hide surviving library imports after the CFG/body mutation wave, but
    // before caller-keyed dispatch records live code-byte hashes.  CKD skips the
    // generated `morok.fco.*` resolver edges and then seals the final user-code
    // shape, including FCO's per-callsite resolver/cache material.
    if (InitialModuleGrowthOk && config_.passes.fco.enabled.value_or(false)) {
        passes::FcoParams fp;
        changed |= passes::functionCallObfuscateModule(M, fp, rng);
    }

    // Collapse surviving direct user calls through one shared native dispatch
    // hub.  Run before returnless dispatch so direct tail-position calls are
    // sealed while they are still direct; returnless will skip the generated
    // `morok.ckd.*` dispatcher edges.  Keep this after merge/tuning/FCO and
    // before FunctionWrapper; otherwise wrappers would consume user edges first
    // and leave only generated `morok.wrap` callees for this pass to skip.
    if (InitialModuleGrowthOk &&
        config_.passes.caller_keyed_dispatch.enabled.value_or(false) &&
        dispatchModuleOk(measureUserModule(M))) {
        passes::CallerKeyedDispatchParams p;
        p.probability =
            config_.passes.caller_keyed_dispatch.probability.value_or(100);
        p.max_calls =
            config_.passes.caller_keyed_dispatch.max_calls.value_or(4096);
        p.region_bytes =
            config_.passes.caller_keyed_dispatch.region_bytes.value_or(16);
        p.carriers = config_.passes.caller_keyed_dispatch.carriers.value_or(1);
        // Fail-closed-on-unsealed (#106) subsumes CKD's seal_required: when an
        // unsealed binary must die, the dispatch target poison is exactly the
        // behaviour wanted, so enable the same poison path here too.
        p.seal_required =
            config_.passes.caller_keyed_dispatch.seal_required.value_or(false) ||
            config_.passes.fail_closed_on_unsealed.value_or(false);
        changed |= passes::callerKeyedDispatchModule(M, p, rng);
    }

    // Returnless dispatch: rewrite surviving tail-position returns (`%r = call
    // g(args) ; ret %r`) into indirect tail branches so eligible functions
    // leave through a computed `br x16` / `jmp *rax` read from a volatile slot
    // instead of a `ret`.  This runs after caller-keyed dispatch so CKD gets the
    // first chance to seal direct user call edges; returnless then handles only
    // the direct tail edges CKD deliberately left alone.
    if (InitialModuleGrowthOk &&
        config_.passes.returnless_dispatch.enabled.value_or(false) &&
        dispatchModuleOk(measureUserModule(M))) {
        passes::ReturnlessParams p;
        p.probability =
            config_.passes.returnless_dispatch.probability.value_or(100);
        p.max_sites = config_.passes.returnless_dispatch.max_sites.value_or(64);
        changed |= passes::returnlessDispatchModule(M, p, rng);
    }

    // Module-level call-site wrapping runs after the per-function transforms so
    // it proxies calls into already-obfuscated functions.
    if (InitialModuleGrowthOk &&
        config_.passes.func_wrap.enabled.value_or(false) &&
        moduleCloneOk(measureModule(M))) {
        passes::FuncWrapParams wp;
        wp.probability = config_.passes.func_wrap.probability.value_or(50);
        wp.times = config_.passes.func_wrap.times.value_or(1);
        changed |= passes::functionWrapModule(M, wp, rng);
    }

    // Final seed-driven diversity layer: reorder the emitted IR layout and add
    // neutral volatile return anchors after every other configured transform.
    if (InitialModuleGrowthOk &&
        config_.passes.per_build_polymorphism.enabled.value_or(false) &&
        moduleGrowthOk(measureUserModule(M))) {
        passes::PerBuildPolymorphismParams p;
        p.function_order =
            config_.passes.per_build_polymorphism.function_order.value_or(true);
        p.block_order =
            config_.passes.per_build_polymorphism.block_order.value_or(true);
        p.anchor_probability =
            config_.passes.per_build_polymorphism.anchor_probability.value_or(
                25);
        p.max_anchors =
            config_.passes.per_build_polymorphism.max_anchors.value_or(16);
        changed |= passes::perBuildPolymorphismModule(M, p, rng);
    }

    if (InitialModuleGrowthOk)
        changed |= passes::misleadingMetadataModule(M, rng);

    // Final symbol hygiene: every generated `morok.*` helper still carries its
    // descriptive internal-linkage name (`morok.gf8mul`, `morok.strdec`, …),
    // which leaks into the binary's symbol table and hands an analyst a
    // labelled roadmap of the protection.  Demote them to private linkage — the
    // IR name survives for any by-name coordination, but private symbols are
    // dropped from the object symbol table (the encrypted string globals
    // already rely on this), so the names never reach the artifact.
    for (Function &F : M)
        if (F.hasLocalLinkage() && F.getName().starts_with("morok."))
            F.setLinkage(GlobalValue::PrivateLinkage);
    for (GlobalVariable &GV : M.globals())
        if (GV.hasLocalLinkage() && GV.getName().starts_with("morok."))
            GV.setLinkage(GlobalValue::PrivateLinkage);

    return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace morok::pipeline
