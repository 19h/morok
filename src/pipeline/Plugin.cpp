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
#include "morok/passes/ChaosStateMachine.hpp"
#include "morok/passes/CoherentDecoys.hpp"
#include "morok/passes/ConstantEncryption.hpp"
#include "morok/passes/DataEntangledFlattening.hpp"
#include "morok/passes/DataFlowIntegrity.hpp"
#include "morok/passes/DispatcherlessRouting.hpp"
#include "morok/passes/ExternalOpaquePredicates.hpp"
#include "morok/passes/Flattening.hpp"
#include "morok/passes/FunctionCallObfuscate.hpp"
#include "morok/passes/FunctionWrapper.hpp"
#include "morok/passes/HashGatedSelfDecrypt.hpp"
#include "morok/passes/IndirectBranch.hpp"
#include "morok/passes/InterproceduralFsm.hpp"
#include "morok/passes/Mba.hpp"
#include "morok/passes/MicrocodeStress.hpp"
#include "morok/passes/MqGate.hpp"
#include "morok/passes/MutualGuardGraph.hpp"
#include "morok/passes/NonInvertibleState.hpp"
#include "morok/passes/OptimizerAmplification.hpp"
#include "morok/passes/PathExplosion.hpp"
#include "morok/passes/PerBuildPolymorphism.hpp"
#include "morok/passes/PhiTangling.hpp"
#include "morok/passes/PointerLaundering.hpp"
#include "morok/passes/SelfChecksumConstants.hpp"
#include "morok/passes/ShamirShare.hpp"
#include "morok/passes/SplitBasicBlocks.hpp"
#include "morok/passes/StackCoalescing.hpp"
#include "morok/passes/StackDeltaGames.hpp"
#include "morok/passes/StateOpaquePredicates.hpp"
#include "morok/passes/StringEncryption.hpp"
#include "morok/passes/SubThresholdPersistence.hpp"
#include "morok/passes/Substitution.hpp"
#include "morok/passes/TraceKeying.hpp"
#include "morok/passes/TypePunning.hpp"
#include "morok/passes/UniformPrimitiveLowering.hpp"
#include "morok/passes/Virtualization.hpp"
#include "morok/passes/VectorObfuscation.hpp"
#include "morok/pipeline/Scheduler.hpp"

#include "morok/ir/Annotations.hpp"

#include "llvm/Demangle/Demangle.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Plugins/PassPlugin.h"
#include "llvm/Support/CommandLine.h"

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

    if (!fromFile && !MorokPreset.empty()) {
        cfg.preset = parsePreset(MorokPreset);
        cfg.passes = presetConfig(cfg.preset);
    }

    if (MorokSeed != 0)
        cfg.seed = MorokSeed;

    return cfg;
}

class EarlyOptimizerAmplificationPass
    : public PassInfoMixin<EarlyOptimizerAmplificationPass> {
public:
    explicit EarlyOptimizerAmplificationPass(morok::config::Config config)
        : config_(std::move(config)),
          engine_(morok::core::Xoshiro256pp::fromSeed(config_.seed == 0
                                                          ? 0x1337
                                                          : config_.seed)) {}

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
        const morok::config::PassConfig eff =
            morok::config::resolve(config_, M->getSourceFileName(),
                                   F.getName(), demangle);
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

} // namespace

namespace morok::pipeline {

PassPluginLibraryInfo getPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "Morok", LLVM_VERSION_STRING,
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
                        if (name == "morok-afm") {
                            MPM.addPass(
                                passes::AdversarialFunctionMergingPass());
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
                        if (name == "morok-timing") {
                            MPM.addPass(passes::TimingOraclePass());
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
                            FPM.addPass(
                                passes::ExternalOpaquePredicatesPass());
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
                    if (EnableMorok) {
                        auto cfg = loadConfig();
                        cfg.passes.opt_amplify.enabled = false;
                        MPM.addPass(MorokPass(cfg));
                    }
                });

                PB.registerVectorizerStartEPCallback(
                    [](FunctionPassManager &FPM, OptimizationLevel) {
                        if (EnableMorok)
                            FPM.addPass(
                                EarlyOptimizerAmplificationPass(loadConfig()));
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
