// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/passes/Flattening.cpp
//
// Plain control-flow flattening: the next state is simply the successor's id
// (selected by the branch condition for two-way edges).  All the CFG surgery
// lives in the reusable engine; this pass only supplies the transition rule.

#include "morok/passes/Flattening.hpp"

#include "morok/ir/ControlFlowFlattener.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"

using namespace llvm;

namespace morok::passes {

bool flattenFunction(Function &F, ir::IRRandom &rng) {
    return ir::flattenControlFlow(
        F, rng,
        [](IRBuilder<> &B, AllocaInst *, std::uint32_t,
           const ir::SuccessorIds &s) -> Value * {
            auto *i32 = B.getInt32Ty();
            // Next state = the successor's id, chosen by the branch/switch
            // arms.
            Value *acc = ConstantInt::get(i32, s.defaultId);
            for (auto it = s.arms.rbegin(); it != s.arms.rend(); ++it)
                acc = B.CreateSelect(it->condition,
                                     ConstantInt::get(i32, it->targetId), acc);
            return acc;
        });
}

PreservedAnalyses FlatteningPass::run(Function &F, FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return flattenFunction(F, rng) ? PreservedAnalyses::none()
                                   : PreservedAnalyses::all();
}

} // namespace morok::passes
