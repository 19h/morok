// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/pipeline/Scheduler.cpp

#include "morok/pipeline/Scheduler.hpp"

#include "morok/core/Entropy.hpp"
#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/Annotations.hpp"
#include "morok/ir/IRRandom.hpp"
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

#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"

#include <string>

using namespace llvm;

namespace morok::pipeline {

PreservedAnalyses MorokPass::run(Module &M, ModuleAnalysisManager &) {
    // Seed the shared engine: explicit seed for reproducible builds, otherwise
    // collected entropy.
    core::Xoshiro256pp engine = config_.seed != 0
                                    ? core::Xoshiro256pp::fromSeed(config_.seed)
                                    : core::makeSeededEngine();
    ir::IRRandom rng(engine);

    ir::materializeAnnotations(M);

    const config::Demangler demangle = [](std::string_view s) -> std::string {
        return llvm::demangle(std::string(s));
    };

    const std::string moduleName = M.getSourceFileName();
    bool changed = false;

    // Anti-analysis module passes run earliest.
    if (config_.passes.anti_hook.enabled.value_or(false))
        changed |= passes::antiHookingModule(M);
    if (config_.passes.anti_class_dump.enabled.value_or(false))
        changed |= passes::antiClassDumpModule(M);
    if (config_.passes.anti_dbg.enabled.value_or(false))
        changed |= passes::antiDebuggingModule(M);

    // Hide library imports behind dlsym.
    if (config_.passes.fco.enabled.value_or(false)) {
        passes::FcoParams fp;
        changed |= passes::functionCallObfuscateModule(M, fp, rng);
    }

    // Module-level string encryption (its decryptor constructor and key globals
    // are independent of the per-function transforms).
    if (config_.passes.str_enc.enabled.value_or(false)) {
        passes::StrEncParams sp;
        sp.probability = config_.passes.str_enc.probability.value_or(100);
        changed |= passes::stringEncryptModule(M, sp, rng);
    }

    for (Function &F : M) {
        if (F.isDeclaration())
            continue;

        const config::PassConfig eff =
            config::resolve(config_, moduleName, F.getName(), demangle);

        // Structural passes first: split creates more dispatch targets, then
        // bogus control flow widens the CFG, before the value-level passes.
        if (ir::shouldObfuscate(F, "split",
                                eff.split.enabled.value_or(false))) {
            passes::SplitParams p;
            p.splits = eff.split.splits.value_or(3);
            changed |= passes::splitBlocksFunction(F, p, rng);
        }

        if (ir::shouldObfuscate(F, "bcf", eff.bcf.enabled.value_or(false))) {
            passes::BcfParams p;
            p.probability = eff.bcf.probability.value_or(60);
            p.iterations = eff.bcf.iterations.value_or(1);
            changed |= passes::bogusControlFlowFunction(F, p, rng);
        }

        // Substitution before MBA, mirroring the documented ordering.
        if (ir::shouldObfuscate(F, "sub", eff.sub.enabled.value_or(false))) {
            passes::SubstitutionParams p;
            p.probability = eff.sub.probability.value_or(50);
            p.iterations = eff.sub.iterations.value_or(1);
            changed |= passes::substituteFunction(F, p, rng);
        }

        if (ir::shouldObfuscate(F, "mba", eff.mba.enabled.value_or(false))) {
            passes::MbaParams p;
            p.probability = eff.mba.probability.value_or(60);
            p.layers = eff.mba.layers.value_or(2);
            p.heuristic = eff.mba.heuristic.value_or(true);
            changed |= passes::mbaFunction(F, p, rng);
        }

        // Exactly one control-flow-flattening layer per function, after the
        // value-level passes: prefer the chaos state machine, fall back to
        // plain flattening (so each function gets a single, strongest CFF
        // layer).
        bool flattened = false;
        if (ir::shouldObfuscate(F, "csm", eff.csm.enabled.value_or(false))) {
            flattened = passes::chaosStateMachineFunction(F, rng);
            changed |= flattened;
        }
        if (!flattened && ir::shouldObfuscate(
                              F, "fla", eff.flatten.enabled.value_or(false))) {
            changed |= passes::flattenFunction(F, rng);
        }

        // SIMD lifting after the control-flow passes, so even dispatcher
        // arithmetic gets vectorised.
        if (ir::shouldObfuscate(F, "vobf", eff.vec.enabled.value_or(false))) {
            passes::VecParams p;
            p.probability = eff.vec.probability.value_or(40);
            changed |= passes::vectorObfuscateFunction(F, p, rng);
        }

        // Constant encryption hides the literals the other passes introduce.
        if (ir::shouldObfuscate(F, "constenc",
                                eff.const_enc.enabled.value_or(false))) {
            passes::ConstEncParams p;
            p.probability = 100; // encrypt every eligible literal when enabled
            p.share_count = eff.const_enc.share_count.value_or(2);
            p.iterations = eff.const_enc.iterations.value_or(1);
            changed |= passes::constantEncryptFunction(F, p, rng);
        }

        // Indirect branching last per function (it consumes the conditional
        // branches the other passes leave behind).
        if (ir::shouldObfuscate(F, "indibran",
                                eff.indir_branch.enabled.value_or(false))) {
            passes::IndirParams p;
            changed |= passes::indirectBranchFunction(F, p, rng);
        }
    }

    // Module-level call-site wrapping runs after the per-function transforms so
    // it proxies calls into already-obfuscated functions.
    if (config_.passes.func_wrap.enabled.value_or(false)) {
        passes::FuncWrapParams wp;
        wp.probability = config_.passes.func_wrap.probability.value_or(50);
        wp.times = config_.passes.func_wrap.times.value_or(1);
        changed |= passes::functionWrapModule(M, wp, rng);
    }

    return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace morok::pipeline
