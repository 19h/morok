// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/pipeline/Plugin.cpp — New-PM pass-plugin entry point.
//
// Targets this environment's plugin API v2 (<llvm/Plugins/PassPlugin.h>).
// Registers:
//   • the module pipeline name "morok"            (full scheduler)
//   • standalone module/function pipeline names for individual passes
//   • vectorizer-start / optimizer-last EP callbacks gated by -morok, so
//     `clang -fpass-plugin` auto-runs PM-sensitive and late passes without an
//     explicit -passes string.

#include "morok/config/Preset.hpp"
#include "morok/config/Resolver.hpp"
#include "morok/config/TomlLoader.hpp"
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
#include "morok/passes/ExternalOpaquePredicates.hpp"
#include "morok/passes/ExternalSecretBinding.hpp"
#include "morok/passes/Flattening.hpp"
#include "morok/passes/FaultPagedPayload.hpp"
#include "morok/passes/FunctionCallObfuscate.hpp"
#include "morok/passes/FunctionWrapper.hpp"
#include "morok/passes/HashGatedSelfDecrypt.hpp"
#include "morok/passes/IndirectBranch.hpp"
#include "morok/passes/InterproceduralFsm.hpp"
#include "morok/passes/Mba.hpp"
#include "morok/passes/MicrocodeStress.hpp"
#include "morok/passes/MqGate.hpp"
#include "morok/passes/MutualGuardGraph.hpp"
#include "morok/passes/Nanomites.hpp"
#include "morok/passes/NonInvertibleState.hpp"
#include "morok/passes/OptimizerAmplification.hpp"
#include "morok/passes/PathExplosion.hpp"
#include "morok/passes/PerBuildPolymorphism.hpp"
#include "morok/passes/PhiTangling.hpp"
#include "morok/passes/PointerLaundering.hpp"
#include "morok/passes/SealedBlob.hpp"
#include "morok/passes/SelfChecksumConstants.hpp"
#include "morok/passes/ShamirShare.hpp"
#include "morok/passes/SplitBasicBlocks.hpp"
#include "morok/passes/StackCoalescing.hpp"
#include "morok/passes/StackDeltaGames.hpp"
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
#include "morok/pipeline/Scheduler.hpp"

#include "morok/ir/Annotations.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Plugins/PassPlugin.h"
#include "llvm/Support/CommandLine.h"

#include <cstdint>
#include <cstdlib>
#include <string>
#include <utility>

using namespace llvm;

namespace {

cl::opt<bool> EnableMorok("morok", cl::init(false), cl::NotHidden,
                          cl::desc("Enable Morok IR obfuscation."));
cl::opt<std::string>
    MorokConfigPath("morok-config", cl::init(""), cl::NotHidden,
                    cl::desc("Path to a Morok TOML configuration file."));
cl::opt<std::string>
    MorokPreset("morok-preset", cl::init(""), cl::NotHidden,
                cl::desc("Obfuscation preset: low | mid | high | max."));
cl::opt<std::uint64_t>
    MorokSeed("morok-seed", cl::init(0),
              cl::desc("Deterministic PRNG seed (0 = entropy)."));

// Whether the auto-injection (clang -fpass-plugin) entry points should fire.
// On Unix this is driven by the `-morok` cl::opt (`-mllvm -morok`).  On Windows
// the plugin's cl::opts register into its own static-LLVM registry, which the
// host clang's option parser never sees ("Unknown command line argument
// '-morok'"), so the MOROK_ENABLE env var is the portable switch there.  The
// env var is also a convenient opt-in on Unix; it never overrides an explicit
// disable since EnableMorok defaults off.
bool morokAutoInjectEnabled() {
    return EnableMorok || std::getenv("MOROK_ENABLE") != nullptr;
}

// Resolve the effective configuration from flags / environment / file.
morok::config::Config loadConfig() {
    using namespace morok::config;
    Config cfg;

    std::string path = MorokConfigPath;
    if (path.empty())
        if (const char *env = std::getenv("MOROK_CONFIG"))
            path = env;

    bool fromFile = false;
    if (!path.empty()) {
        LoadResult r = loadFromFile(path);
        if (r.ok) {
            cfg = r.config;
            fromFile = true;
        } else {
            errs() << "[morok] " << r.error << " — ignoring config file.\n";
        }
    }

    if (!fromFile) {
        // The preset flag falls back to MOROK_PRESET.  On Windows the plugin's
        // cl::opts register into its own (host-unparsed) registry, so env is
        // the only way to drive the preset there; on Unix the cl::opt still
        // wins because it is non-empty when set.
        std::string preset = MorokPreset;
        if (preset.empty())
            if (const char *env = std::getenv("MOROK_PRESET"))
                preset = env;
        if (!preset.empty()) {
            cfg.preset = parsePreset(preset);
            cfg.passes = presetConfig(cfg.preset);
        }
    }

    std::uint64_t seed = MorokSeed;
    if (seed == 0)
        if (const char *env = std::getenv("MOROK_SEED"))
            seed = std::strtoull(env, nullptr, 0);
    if (seed != 0)
        cfg.seed = seed;

    return cfg;
}

class EarlyOptimizerAmplificationPass
    : public PassInfoMixin<EarlyOptimizerAmplificationPass> {
public:
    explicit EarlyOptimizerAmplificationPass(morok::config::Config config)
        : config_(std::move(config)),
          engine_(morok::core::Xoshiro256pp::fromSeed(
              config_.seed == 0 ? 0x1337 : config_.seed)) {}

    PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
        if (F.isDeclaration() || F.getName().starts_with("morok."))
            return PreservedAnalyses::all();

        Module *M = F.getParent();
        if (!M)
            return PreservedAnalyses::all();
        morok::ir::materializeAnnotations(*M);

        const morok::config::Demangler demangle =
            [](std::string_view s) -> std::string {
            return llvm::demangle(std::string(s));
        };
        const morok::config::PassConfig eff = morok::config::resolve(
            config_, M->getSourceFileName(), F.getName(), demangle);

        // Yield VM-bound functions to the virtualizer untouched: amplification
        // would bloat them past the lifter's instruction budget (it runs later,
        // at OptimizerLast).  Virtualization is the stronger transform, so it
        // takes priority on any function it can lift.
        if (eff.virtualization.enabled.value_or(false)) {
            morok::passes::VirtualizationParams vp;
            vp.probability = eff.virtualization.probability.value_or(20);
            vp.max_functions = eff.virtualization.max_functions.value_or(1);
            vp.max_instructions =
                eff.virtualization.max_instructions.value_or(64);
            vp.max_registers = eff.virtualization.max_registers.value_or(96);
            if (morok::passes::virtualizationWillLift(F, vp))
                return PreservedAnalyses::all();
        }

        if (!morok::ir::shouldObfuscate(
                F, "optamp", eff.opt_amplify.enabled.value_or(false)))
            return PreservedAnalyses::all();

        morok::passes::OptAmpParams params;
        params.probability = eff.opt_amplify.probability.value_or(20);
        params.max_forms = eff.opt_amplify.max_forms.value_or(2);

        morok::ir::IRRandom rng(engine_);
        return morok::passes::optimizerAmplifyFunction(F, params, rng)
                   ? PreservedAnalyses::none()
                   : PreservedAnalyses::all();
    }

    static bool isRequired() { return true; }

private:
    morok::config::Config config_;
    morok::core::Xoshiro256pp engine_;
};

// Pre-inline candidate preservation for the bytecode VM.
//
// The full Morok pass (and therefore the virtualizer) runs at OptimizerLast,
// i.e. *after* the inliner.  By then a program's small leaf helpers — exactly
// the integer/pointer computation kernels the VM can lift (key mixers, hashes,
// round functions) — have been inlined into their callers and no longer exist
// as standalone, VM-eligible functions.  The net effect on real -O2/-O3 input
// is that the VM lifts nothing.
//
// This pass runs at PipelineEarlySimplification, *before* the inliner, and pins
// the plausible VM candidates with `noinline` so they survive intact to
// OptimizerLast where the virtualizer can lift them.  Adding `noinline` is
// always semantics-preserving (it only constrains code layout, never results),
// and it is gated on virtualization being enabled, so non-VM builds (and the
// VM-disabled x86/portable configurations) are completely unaffected.
class VmCandidatePreserverPass
    : public PassInfoMixin<VmCandidatePreserverPass> {
public:
    explicit VmCandidatePreserverPass(morok::config::Config config)
        : config_(std::move(config)) {}

    PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
        if (!config_.passes.virtualization.enabled.value_or(false))
            return PreservedAnalyses::all();

        bool changed = false;
        for (Function &F : M)
            if (isCandidate(F)) {
                F.addFnAttr(Attribute::NoInline);
                changed = true;
            }
        return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }

    static bool isRequired() { return true; }

private:
    static bool vmScalarType(Type *T) {
        if (auto *I = dyn_cast<IntegerType>(T))
            return I->getBitWidth() >= 1 && I->getBitWidth() <= 64;
        if (auto *P = dyn_cast<PointerType>(T))
            return P->getAddressSpace() == 0;
        return false;
    }

    static bool reachesBlock(const BasicBlock *From, const BasicBlock *Target,
                             SmallPtrSetImpl<const BasicBlock *> &Seen) {
        if (!Seen.insert(From).second)
            return false;
        if (Seen.size() > 512)
            return false;
        for (const BasicBlock *Succ : successors(From)) {
            if (Succ == Target)
                return true;
            if (reachesBlock(Succ, Target, Seen))
                return true;
        }
        return false;
    }

    static bool blockIsCyclic(const BasicBlock &BB) {
        for (const BasicBlock *Succ : successors(&BB)) {
            if (Succ == &BB)
                return true;
            SmallPtrSet<const BasicBlock *, 32> Seen;
            if (reachesBlock(Succ, &BB, Seen))
                return true;
        }
        return false;
    }

    static bool hasLoopCallsite(const Function &F) {
        for (const User *U : F.users()) {
            const auto *CB = dyn_cast<CallBase>(U);
            if (!CB || CB->getCalledFunction() != &F)
                continue;
            if (const BasicBlock *BB = CB->getParent())
                if (blockIsCyclic(*BB))
                    return true;
        }
        return false;
    }

    // A plausible VM lift target: a small, leaf, local-linkage function whose
    // signature is scalar (integer/pointer/void).  The virtualizer applies the
    // precise eligibility check later; this only has to avoid pinning functions
    // that obviously can never lift (so the inliner stays free to flatten
    // them).
    static bool isCandidate(const Function &F) {
        if (F.isDeclaration() || F.isVarArg() || !F.hasLocalLinkage())
            return false;
        if (F.getName() == "main" || F.getName().starts_with("morok."))
            return false;
        if (F.hasFnAttribute(Attribute::NoInline) ||
            F.hasFnAttribute(Attribute::AlwaysInline) ||
            F.hasFnAttribute(Attribute::InlineHint) ||
            F.hasFnAttribute(Attribute::Naked) ||
            F.hasFnAttribute(Attribute::OptimizeNone) || F.hasPersonalityFn())
            return false;

        Type *Ret = F.getReturnType();
        if (!Ret->isVoidTy() && !vmScalarType(Ret))
            return false;
        for (const Argument &A : F.args())
            if (!vmScalarType(A.getType()))
                return false;

        // Do not pin tiny helpers called from loops.  Those are exactly the
        // round/multiply/hash primitives the inliner must flatten; virtualizing
        // them turns a single ALU expression in a hot loop into an interpreter
        // dispatch for every dynamic call.
        if (hasLoopCallsite(F))
            return false;

        // Size bound (pre-optimization instruction count) + call check.  The VM
        // can lift a body whose only calls are DIRECT calls to defined internal
        // functions (the allow_internal_user_calls path) — e.g. a license
        // verdict/tier decision that calls internal hash helpers — so pin those
        // too, not just pure leaves.  A call through an import declaration, an
        // indirect call, or a vararg call is still un-liftable, so leave those
        // bodies free for the inliner.
        std::uint64_t insts = 0;
        for (const BasicBlock &BB : F)
            for (const Instruction &I : BB) {
                ++insts;
                if (const auto *CB = dyn_cast<CallBase>(&I)) {
                    const Function *Callee = CB->getCalledFunction();
                    if (Callee && Callee->isIntrinsic())
                        continue;
                    if (!Callee || Callee->isDeclaration() ||
                        Callee->isVarArg())
                        return false;
                }
            }
        return insts >= 4 && insts <= 256;
    }

    morok::config::Config config_;
};

} // namespace

namespace morok::pipeline {

PassPluginLibraryInfo getPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION, "Morok", LLVM_VERSION_STRING,
        [](PassBuilder &PB) {
            // Module pipeline: -passes=morok
            PB.registerPipelineParsingCallback(
                [](StringRef name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (name == "morok") {
                        MPM.addPass(MorokPass(loadConfig()));
                        return true;

                    }
                    if (name == "morok-strenc") {
                        MPM.addPass(passes::StringEncryptionPass());
                        return true;
                    }
                    if (name == "morok-funcwrap") {
                        MPM.addPass(passes::FunctionWrapperPass());
                        return true;
                    }
                    if (name == "morok-fco") {
                        MPM.addPass(passes::FunctionCallObfuscatePass());
                        return true;
                    }
                    if (name == "morok-ckd") {
                        MPM.addPass(passes::CallerKeyedDispatchPass());
                        return true;
                    }
                    if (name == "morok-afm") {
                        MPM.addPass(passes::AdversarialFunctionMergingPass());
                        return true;
                    }
                    if (name == "morok-selftune") {
                        MPM.addPass(passes::AdversarialSelfTuningPass());
                        return true;
                    }
                    if (name == "morok-polymorph") {
                        MPM.addPass(passes::PerBuildPolymorphismPass());
                        return true;
                    }
                    if (name == "morok-ifsm") {
                        MPM.addPass(passes::InterproceduralFsmPass());
                        return true;
                    }
                    if (name == "morok-vm") {
                        MPM.addPass(passes::VirtualizationPass());
                        return true;
                    }
                    if (name == "morok-selfdecrypt") {
                        MPM.addPass(passes::HashGatedSelfDecryptPass());
                        return true;
                    }
                    if (name == "morok-fpp") {
                        MPM.addPass(passes::FaultPagedPayloadPass());
                        return true;
                    }
                    if (name == "morok-proofbind") {
                        MPM.addPass(passes::ExternalSecretBindingPass());
                        return true;
                    }
                    if (name == "morok-tracer") {
                        MPM.addPass(passes::TracerAttestationPass());
                        return true;
                    }
                    if (name == "morok-sealedblob") {
                        MPM.addPass(passes::SealedBlobPass());
                        return true;
                    }
                    if (name == "morok-antidbg") {
                        MPM.addPass(passes::AntiDebuggingPass());
                        return true;
                    }
                    if (name == "morok-antihook") {
                        MPM.addPass(passes::AntiHookingPass());
                        return true;
                    }
                    if (name == "morok-antiacd") {
                        MPM.addPass(passes::AntiClassDumpPass());
                        return true;
                    }
                    if (name == "morok-winpe") {
                        MPM.addPass(passes::WindowsPEFoundationPass());
                        return true;
                    }
                    if (name == "morok-winpeb") {
                        MPM.addPass(passes::WindowsPebHeapDebugPass());
                        return true;
                    }
                    if (name == "morok-windbgobj") {
                        MPM.addPass(passes::WindowsDebugObjectPass());
                        return true;
                    }
                    if (name == "morok-winthide") {
                        MPM.addPass(passes::WindowsThreadHidePass());
                        return true;
                    }
                    if (name == "morok-winattach") {
                        MPM.addPass(passes::WindowsAntiAttachPass());
                        return true;
                    }
                    if (name == "morok-winkdbg") {
                        MPM.addPass(passes::WindowsKernelDebuggerPass());
                        return true;
                    }
                    if (name == "morok-winsys") {
                        MPM.addPass(passes::WindowsSyscallsPass());
                        return true;
                    }
                    if (name == "morok-winunhook") {
                        MPM.addPass(passes::WindowsUnhookPass());
                        return true;
                    }
                    if (name == "morok-winveh") {
                        MPM.addPass(passes::WindowsVehAuditPass());
                        return true;
                    }
                    if (name == "morok-winmitigate") {
                        MPM.addPass(passes::WindowsProcessMitigationsPass());
                        return true;
                    }
                    if (name == "morok-timing") {
                        MPM.addPass(passes::TimingOraclePass());
                        return true;
                    }
                    if (name == "morok-step") {
                        MPM.addPass(passes::SchedulerStepOraclePass());
                        return true;
                    }
                    if (name == "morok-trap") {
                        MPM.addPass(passes::TrapOraclePass());
                        return true;
                    }
                    if (name == "morok-pftlb") {
                        MPM.addPass(passes::PageFaultTlbOraclePass());
                        return true;
                    }
                    if (name == "morok-cachetime") {
                        MPM.addPass(passes::CacheTimingOraclePass());
                        return true;
                    }
                    if (name == "morok-microcanary") {
                        MPM.addPass(passes::MicroarchitecturalCanaryPass());
                        return true;
                    }
                    if (name == "morok-nanomites") {
                        MPM.addPass(passes::NanomitesPass());
                        return true;
                    }
                    if (name == "morok-decoystr") {
                        MPM.addPass(passes::DecoyStringsPass());
                        return true;
                    }
                    if (name == "morok-vtable") {
                        MPM.addPass(passes::VTableIntegrityPass());
                        return true;
                    }
                    return false;
                });

            // Function pipelines: -passes=morok-substitution / morok-mba
            PB.registerPipelineParsingCallback(
                [](StringRef name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (name == "morok-substitution") {
                        FPM.addPass(passes::SubstitutionPass());
                        return true;
                    }
                    if (name == "morok-mba") {
                        FPM.addPass(passes::MbaPass());
                        return true;
                    }
                    if (name == "morok-optamp") {
                        FPM.addPass(passes::OptimizerAmplificationPass());
                        return true;
                    }
                    if (name == "morok-threshold") {
                        FPM.addPass(passes::SubThresholdPersistencePass());
                        return true;
                    }
                    if (name == "morok-constenc") {
                        FPM.addPass(passes::ConstantEncryptionPass());
                        return true;
                    }
                    if (name == "morok-selfcheck") {
                        FPM.addPass(passes::SelfChecksumConstantsPass());
                        return true;
                    }
                    if (name == "morok-mutualguard") {
                        FPM.addPass(passes::MutualGuardGraphPass());
                        return true;
                    }
                    if (name == "morok-shamir") {
                        FPM.addPass(passes::ShamirSharePass());
                        return true;
                    }
                    if (name == "morok-split") {
                        FPM.addPass(passes::SplitBasicBlocksPass());
                        return true;
                    }
                    if (name == "morok-stackcoalesce") {
                        FPM.addPass(passes::StackCoalescingPass());
                        return true;
                    }
                    if (name == "morok-stackdelta") {
                        FPM.addPass(passes::StackDeltaGamesPass());
                        return true;
                    }
                    if (name == "morok-ptrlaunder") {
                        FPM.addPass(passes::PointerLaunderingPass());
                        return true;
                    }
                    if (name == "morok-typepun") {
                        FPM.addPass(passes::TypePunningPass());
                        return true;
                    }
                    if (name == "morok-phitangle") {
                        FPM.addPass(passes::PhiTanglingPass());
                        return true;
                    }
                    if (name == "morok-aliasop") {
                        FPM.addPass(passes::AliasOpaquePredicatesPass());
                        return true;
                    }
                    if (name == "morok-extop") {
                        FPM.addPass(passes::ExternalOpaquePredicatesPass());
                        return true;
                    }
                    if (name == "morok-decoy") {
                        FPM.addPass(passes::CoherentDecoysPass());
                        return true;
                    }
                    if (name == "morok-bcf") {
                        FPM.addPass(passes::BogusControlFlowPass());
                        return true;
                    }
                    if (name == "morok-flatten") {
                        FPM.addPass(passes::FlatteningPass());
                        return true;
                    }
                    if (name == "morok-entfla") {
                        FPM.addPass(passes::DataEntangledFlatteningPass());
                        return true;
                    }
                    if (name == "morok-nistate") {
                        FPM.addPass(passes::NonInvertibleStatePass());
                        return true;
                    }
                    if (name == "morok-stateop") {
                        FPM.addPass(passes::StateOpaquePredicatesPass());
                        return true;
                    }
                    if (name == "morok-csm") {
                        FPM.addPass(passes::ChaosStateMachinePass());
                        return true;
                    }
                    if (name == "morok-tfa") {
                        passes::CsmParams p;
                        p.generator = passes::CsmGenerator::TFunction;
                        FPM.addPass(passes::ChaosStateMachinePass(p));
                        return true;
                    }
                    if (name == "morok-vec") {
                        FPM.addPass(passes::VectorObfuscationPass());
                        return true;
                    }
                    if (name == "morok-tablearith") {
                        FPM.addPass(passes::ArithmeticTablesPass());
                        return true;
                    }
                    if (name == "morok-dfi") {
                        FPM.addPass(passes::DataFlowIntegrityPass());
                        return true;
                    }
                    if (name == "morok-uniform") {
                        FPM.addPass(passes::UniformPrimitiveLoweringPass());
                        return true;
                    }
                    if (name == "morok-pathexplode") {
                        FPM.addPass(passes::PathExplosionPass());
                        return true;
                    }
                    if (name == "morok-mq") {
                        FPM.addPass(passes::MqGatePass());
                        return true;
                    }
                    if (name == "morok-tracekey") {
                        FPM.addPass(passes::TraceKeyingPass());
                        return true;
                    }
                    if (name == "morok-microstress") {
                        FPM.addPass(passes::MicrocodeStressPass());
                        return true;
                    }
                    if (name == "morok-dispatchless") {
                        FPM.addPass(passes::DispatcherlessRoutingPass());
                        return true;
                    }
                    if (name == "morok-indbr") {
                        FPM.addPass(passes::IndirectBranchPass());
                        return true;
                    }
                    return false;
                });

            // Auto-injection for `clang -fpass-plugin=... -mllvm -morok`.
            PB.registerOptimizerLastEPCallback([](ModulePassManager &MPM,
                                                  OptimizationLevel,
                                                  ThinOrFullLTOPhase) {
                if (morokAutoInjectEnabled()) {
                    auto cfg = loadConfig();
                    cfg.passes.opt_amplify.enabled = false;
                    MPM.addPass(MorokPass(cfg));
                }
            });

            PB.registerVectorizerStartEPCallback([](FunctionPassManager &FPM,
                                                    OptimizationLevel) {
                if (morokAutoInjectEnabled())
                    FPM.addPass(EarlyOptimizerAmplificationPass(loadConfig()));
            });

            // Pre-inline: pin VM-liftable leaf helpers with noinline so they
            // survive the inliner and are still standalone functions when the
            // virtualizer runs at OptimizerLast.  Gated on -morok + an
            // enabled virtualization config, so it is a no-op otherwise.
            PB.registerPipelineEarlySimplificationEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel,
                   ThinOrFullLTOPhase) {
                    if (EnableMorok)
                        MPM.addPass(VmCandidatePreserverPass(loadConfig()));
                });
        }};
}

} // namespace morok::pipeline

#ifdef _WIN32
extern "C" __declspec(dllexport)
#else
extern "C" LLVM_ATTRIBUTE_WEAK
#endif
::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return morok::pipeline::getPluginInfo();
}
