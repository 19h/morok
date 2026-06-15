// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/passes/VectorObfuscation.cpp
//
// a OP b  becomes  extractelement( <a,j1> OP <b,j2>, 0 ), where j1/j2 are junk
// lanes.  Per-lane vector semantics make lane 0 exactly a OP b, so the value is
// preserved; the surface form becomes vector arithmetic.

#include "morok/passes/VectorObfuscation.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

bool liftable(BinaryOperator *bo) {
    auto *ty = dyn_cast<IntegerType>(bo->getType());
    if (!ty)
        return false;
    switch (bo->getOpcode()) {
    case Instruction::Add:
    case Instruction::Sub:
    case Instruction::Mul:
    case Instruction::And:
    case Instruction::Or:
    case Instruction::Xor:
    case Instruction::Shl:
    case Instruction::LShr:
    case Instruction::AShr:
        return true;
    default:
        return false;
    }
}

} // namespace

bool vectorObfuscateFunction(Function &F, const VecParams &params,
                             ir::IRRandom &rng) {
    std::vector<BinaryOperator *> targets;
    for (BasicBlock &bb : F)
        for (Instruction &inst : bb)
            if (auto *bo = dyn_cast<BinaryOperator>(&inst))
                if (liftable(bo))
                    targets.push_back(bo);

    bool changed = false;
    for (BinaryOperator *bo : targets) {
        if (!rng.chance(params.probability))
            continue;

        auto *ty = cast<IntegerType>(bo->getType());
        auto *vecTy = FixedVectorType::get(ty, 2);
        IRBuilder<> B(bo);

        auto lane = [&](Value *real, std::uint64_t junk) {
            Value *v = B.CreateInsertElement(PoisonValue::get(vecTy), real,
                                             B.getInt32(0));
            return B.CreateInsertElement(v, ConstantInt::get(ty, junk),
                                         B.getInt32(1));
        };
        Value *va = lane(bo->getOperand(0), rng.next());
        Value *vb = lane(bo->getOperand(1), rng.next());
        Value *vr = B.CreateBinOp(bo->getOpcode(), va, vb);
        Value *r = B.CreateExtractElement(vr, B.getInt32(0));

        bo->replaceAllUsesWith(r);
        bo->eraseFromParent();
        changed = true;
    }
    return changed;
}

PreservedAnalyses VectorObfuscationPass::run(Function &F,
                                             FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return vectorObfuscateFunction(F, params_, rng) ? PreservedAnalyses::none()
                                                    : PreservedAnalyses::all();
}

} // namespace morok::passes
