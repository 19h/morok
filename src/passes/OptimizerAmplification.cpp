// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/OptimizerAmplification.cpp
//
// This pass deliberately avoids volatile state and helper calls.  It emits
// ordinary branchless arithmetic: several equivalent forms of the same operation
// are selected by input-derived guards.  Placing the pass before the vectorizers
// gives LLVM a larger arithmetic graph to reassociate and lower into normal
// optimized code without carrying a distinctive runtime obfuscation scaffold.

#include "morok/passes/OptimizerAmplification.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/NoFolder.h"

#include <algorithm>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

using Builder = IRBuilder<NoFolder>;

bool eligible(BinaryOperator *BO) {
    auto *Ty = dyn_cast<IntegerType>(BO->getType());
    if (!Ty || Ty->getBitWidth() == 0)
        return false;
    if (BO->getName().starts_with("morok.optamp"))
        return false;
    if (BO->hasPoisonGeneratingFlags())
        return false;

    switch (BO->getOpcode()) {
    case Instruction::Add:
    case Instruction::Sub:
    case Instruction::Mul:
    case Instruction::And:
    case Instruction::Or:
    case Instruction::Xor:
        return true;
    default:
        return false;
    }
}

Value *one(IntegerType *Ty) { return ConstantInt::get(Ty, 1); }

Value *two(Builder &B, Value *V, IntegerType *Ty) {
    return B.CreateShl(V, one(Ty), "morok.optamp.twice");
}

Value *equivalentForm(Builder &B, BinaryOperator *BO, std::uint32_t Variant) {
    Value *A = BO->getOperand(0);
    Value *C = BO->getOperand(1);
    auto *Ty = cast<IntegerType>(BO->getType());

    switch (BO->getOpcode()) {
    case Instruction::Add:
        if ((Variant & 1u) == 0 && Ty->getBitWidth() > 1)
            return B.CreateAdd(B.CreateXor(A, C, "morok.optamp.add.xor"),
                               two(B, B.CreateAnd(A, C,
                                                  "morok.optamp.add.carry"),
                                   Ty),
                               "morok.optamp.form");
        return B.CreateAdd(B.CreateOr(A, C, "morok.optamp.add.or"),
                           B.CreateAnd(A, C, "morok.optamp.add.and"),
                           "morok.optamp.form");
    case Instruction::Sub:
        if ((Variant & 1u) == 0 && Ty->getBitWidth() > 1)
            return B.CreateSub(
                B.CreateXor(A, C, "morok.optamp.sub.xor"),
                two(B, B.CreateAnd(B.CreateNot(A, "morok.optamp.sub.nota"), C,
                                   "morok.optamp.sub.borrow"),
                    Ty),
                "morok.optamp.form");
        return B.CreateAdd(
            B.CreateAdd(A, B.CreateNot(C, "morok.optamp.sub.notb"),
                        "morok.optamp.sub.ones"),
            one(Ty), "morok.optamp.form");
    case Instruction::Mul:
        if ((Variant & 1u) == 0)
            return B.CreateSub(
                B.CreateMul(A, B.CreateAdd(C, one(Ty),
                                           "morok.optamp.mul.inc"),
                            "morok.optamp.mul.wide"),
                A, "morok.optamp.form");
        return B.CreateNeg(
            B.CreateMul(A, B.CreateNeg(C, "morok.optamp.mul.negb"),
                        "morok.optamp.mul.negprod"),
            "morok.optamp.form");
    case Instruction::And:
        if ((Variant & 1u) == 0)
            return B.CreateNot(
                B.CreateOr(B.CreateNot(A, "morok.optamp.and.nota"),
                           B.CreateNot(C, "morok.optamp.and.notb"),
                           "morok.optamp.and.demorgan"),
                "morok.optamp.form");
        return B.CreateAnd(B.CreateXor(A, B.CreateNot(C,
                                                      "morok.optamp.and.notb"),
                                       "morok.optamp.and.mask"),
                           A, "morok.optamp.form");
    case Instruction::Or:
        if ((Variant & 1u) == 0)
            return B.CreateNot(
                B.CreateAnd(B.CreateNot(A, "morok.optamp.or.nota"),
                            B.CreateNot(C, "morok.optamp.or.notb"),
                            "morok.optamp.or.demorgan"),
                "morok.optamp.form");
        return B.CreateOr(B.CreateAnd(A, C, "morok.optamp.or.and"),
                          B.CreateXor(A, C, "morok.optamp.or.xor"),
                          "morok.optamp.form");
    case Instruction::Xor:
        if ((Variant & 1u) == 0)
            return B.CreateSub(B.CreateOr(A, C, "morok.optamp.xor.or"),
                               B.CreateAnd(A, C, "morok.optamp.xor.and"),
                               "morok.optamp.form");
        return B.CreateOr(
            B.CreateAnd(B.CreateNot(A, "morok.optamp.xor.nota"), C,
                        "morok.optamp.xor.rhs"),
            B.CreateAnd(A, B.CreateNot(C, "morok.optamp.xor.notb"),
                        "morok.optamp.xor.lhs"),
            "morok.optamp.form");
    default:
        return nullptr;
    }
}

Value *inputGuard(Builder &B, BinaryOperator *BO, std::uint32_t Index,
                  ir::IRRandom &rng) {
    auto *Ty = cast<IntegerType>(BO->getType());
    const unsigned Width = Ty->getBitWidth();
    const unsigned ShiftA = static_cast<unsigned>((Index * 5u) % Width);
    const unsigned ShiftB = static_cast<unsigned>((Index * 7u + 3u) % Width);

    Value *A = BO->getOperand(0);
    Value *C = BO->getOperand(1);
    Value *SA = ShiftA == 0 ? A : B.CreateLShr(A, ConstantInt::get(Ty, ShiftA),
                                               "morok.optamp.guard.sa");
    Value *SB = ShiftB == 0 ? C : B.CreateLShr(C, ConstantInt::get(Ty, ShiftB),
                                               "morok.optamp.guard.sb");
    Value *Salt = ConstantInt::get(Ty, rng.next());
    Value *Mix = B.CreateXor(B.CreateXor(SA, SB, "morok.optamp.guard.mix"),
                             Salt, "morok.optamp.guard.salt");
    Value *Bit = B.CreateAnd(Mix, one(Ty), "morok.optamp.guard.bit");
    return B.CreateICmpNE(Bit, ConstantInt::get(Ty, 0), "morok.optamp.guard");
}

Value *amplify(BinaryOperator *BO, const OptAmpParams &Params,
               ir::IRRandom &rng) {
    Builder B(BO);
    Value *Result = B.CreateBinOp(BO->getOpcode(), BO->getOperand(0),
                                  BO->getOperand(1), "morok.optamp.base");
    const std::uint32_t Forms =
        std::clamp<std::uint32_t>(Params.max_forms, 1, 4);
    const std::uint32_t FirstVariant = rng.range(2);

    for (std::uint32_t I = 0; I < Forms; ++I) {
        Value *Alt = equivalentForm(B, BO, FirstVariant + I);
        if (!Alt)
            return nullptr;
        Value *Guard = inputGuard(B, BO, I + 1, rng);
        Result = B.CreateSelect(Guard, Alt, Result, "morok.optamp.select");
    }
    return Result;
}

} // namespace

bool optimizerAmplifyFunction(Function &F, const OptAmpParams &Params,
                              ir::IRRandom &rng) {
    if (F.isDeclaration() || Params.probability == 0 || Params.max_forms == 0)
        return false;

    std::vector<BinaryOperator *> Targets;
    for (BasicBlock &BB : F)
        for (Instruction &I : BB)
            if (auto *BO = dyn_cast<BinaryOperator>(&I))
                if (eligible(BO))
                    Targets.push_back(BO);

    bool Changed = false;
    for (BinaryOperator *BO : Targets) {
        if (!rng.chance(Params.probability))
            continue;
        if (Value *Replacement = amplify(BO, Params, rng)) {
            BO->replaceAllUsesWith(Replacement);
            BO->eraseFromParent();
            Changed = true;
        }
    }
    return Changed;
}

PreservedAnalyses
OptimizerAmplificationPass::run(Function &F, FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return optimizerAmplifyFunction(F, params_, rng) ? PreservedAnalyses::none()
                                                     : PreservedAnalyses::all();
}

} // namespace morok::passes
