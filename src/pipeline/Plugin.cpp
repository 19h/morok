// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/pipeline/Plugin.cpp — New-PM pass-plugin entry point.
//
// Targets this environment's plugin API v2 (<llvm/Plugins/PassPlugin.h>).
// Registers:
//   • the module pipeline name "morok"            (full scheduler)
//   • function pipeline names "morok-substitution", "morok-mba"
//   • an optimizer-last EP callback gated by -morok, so `clang -fpass-plugin`
//     auto-runs the obfuscator without an explicit -passes string.

#include "morok/config/Preset.hpp"
#include "morok/config/Resolver.hpp"
#include "morok/config/TomlLoader.hpp"
#include "morok/passes/AntiAnalysis.hpp"
#include "morok/passes/BogusControlFlow.hpp"
#include "morok/passes/ChaosStateMachine.hpp"
#include "morok/passes/ConstantEncryption.hpp"
#include "morok/passes/Flattening.hpp"
#include "morok/passes/FunctionCallObfuscate.hpp"
#include "morok/passes/FunctionWrapper.hpp"
#include "morok/passes/IndirectBranch.hpp"
#include "morok/passes/Mba.hpp"
#include "morok/passes/SplitBasicBlocks.hpp"
#include "morok/passes/StringEncryption.hpp"
#include "morok/passes/Substitution.hpp"
#include "morok/passes/VectorObfuscation.hpp"
#include "morok/pipeline/Scheduler.hpp"

#include "llvm/Passes/PassBuilder.h"
#include "llvm/Plugins/PassPlugin.h"
#include "llvm/Support/CommandLine.h"

#include <cstdlib>
#include <string>

using namespace llvm;

namespace {

cl::opt<bool> EnableMorok("morok", cl::init(false), cl::NotHidden,
                          cl::desc("Enable Morok IR obfuscation."));
cl::opt<std::string>
    MorokConfigPath("morok-config", cl::init(""), cl::NotHidden,
                    cl::desc("Path to a Morok TOML configuration file."));
cl::opt<std::string>
    MorokPreset("morok-preset", cl::init(""), cl::NotHidden,
                cl::desc("Obfuscation preset: low | mid | high."));
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
                        if (name == "morok-constenc") {
                            FPM.addPass(passes::ConstantEncryptionPass());
                            return true;
                        }
                        if (name == "morok-split") {
                            FPM.addPass(passes::SplitBasicBlocksPass());
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
                        if (name == "morok-csm") {
                            FPM.addPass(passes::ChaosStateMachinePass());
                            return true;
                        }
                        if (name == "morok-vec") {
                            FPM.addPass(passes::VectorObfuscationPass());
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
                    if (EnableMorok)
                        MPM.addPass(MorokPass(loadConfig()));
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
