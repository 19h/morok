// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/passes/Substitution.cpp
//
// Each emitted expression mirrors a verified identity from
// morok/core/SubstitutionIdentities.hpp.  IRBuilder is used with NoFolder so
// the constant-bearing sub-expressions survive into the output instead of being
// folded back to the original operation.

#include "morok/passes/Substitution.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/NoFolder.h"

#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

using Builder = IRBuilder<NoFolder>;

// Emit an equivalent expression for `bo`, or nullptr if this opcode/operand
// shape is not handled (e.g. a variable shift amount).
Value *emitSubstitution(BinaryOperator *bo, ir::IRRandom &rng) {
    Builder B(bo);
    Value *a = bo->getOperand(0);
    Value *b = bo->getOperand(1);
    auto *ty = cast<IntegerType>(bo->getType());
    const unsigned width = ty->getBitWidth();

    auto two = [&](Value *v) {
        return B.CreateShl(v, ConstantInt::get(ty, 1));
    };

    switch (bo->getOpcode()) {
    case Instruction::Add:
        switch (rng.range(3)) {
        case 0: // (a & b) + (a | b)
            return B.CreateAdd(B.CreateAnd(a, b), B.CreateOr(a, b));
        case 1: // (a ^ b) + 2*(a & b)
            return B.CreateAdd(B.CreateXor(a, b), two(B.CreateAnd(a, b)));
        default: // a - (-b)
            return B.CreateSub(a, B.CreateNeg(b));
        }
    case Instruction::Sub:
        switch (rng.range(2)) {
        case 0: // (a & ~b) - (~a & b)
            return B.CreateSub(B.CreateAnd(a, B.CreateNot(b)),
                               B.CreateAnd(B.CreateNot(a), b));
        default: // a + (-b)
            return B.CreateAdd(a, B.CreateNeg(b));
        }
    case Instruction::And:
        switch (rng.range(2)) {
        case 0: // (a ^ ~b) & a
            return B.CreateAnd(B.CreateXor(a, B.CreateNot(b)), a);
        default: // (a ^ b) ^ (a | b)
            return B.CreateXor(B.CreateXor(a, b), B.CreateOr(a, b));
        }
    case Instruction::Or:
        switch (rng.range(2)) {
        case 0: // (a & b) | (a ^ b)
            return B.CreateOr(B.CreateAnd(a, b), B.CreateXor(a, b));
        default: // ~((~a) & (~b))
            return B.CreateNot(B.CreateAnd(B.CreateNot(a), B.CreateNot(b)));
        }
    case Instruction::Xor:
        switch (rng.range(2)) {
        case 0: // (~a & b) | (a & ~b)
            return B.CreateOr(B.CreateAnd(B.CreateNot(a), b),
                              B.CreateAnd(a, B.CreateNot(b)));
        default: // (a + b) - 2*(a & b)
            return B.CreateSub(B.CreateAdd(a, b), two(B.CreateAnd(a, b)));
        }
    case Instruction::Mul:
        switch (rng.range(2)) {
        case 0: // a*(b + 1) - a
            return B.CreateSub(
                B.CreateMul(a, B.CreateAdd(b, ConstantInt::get(ty, 1))), a);
        default: // -(a * (-b))
            return B.CreateNeg(B.CreateMul(a, B.CreateNeg(b)));
        }
    case Instruction::Shl: {
        auto *k = dyn_cast<ConstantInt>(b);
        if (!k || k->uge(width))
            return nullptr;
        APInt factor(width, 0);
        factor.setBit(static_cast<unsigned>(k->getZExtValue()));
        return B.CreateMul(a, ConstantInt::get(ty, factor)); // a * 2^k
    }
    case Instruction::LShr: {
        auto *k = dyn_cast<ConstantInt>(b);
        if (!k || k->isZero() || k->uge(width))
            return nullptr;
        const unsigned kk = static_cast<unsigned>(k->getZExtValue());
        // (a & high-bits) >>u k — the low k bits are discarded by the shift
        // anyway.
        APInt mask = APInt::getHighBitsSet(width, width - kk);
        return B.CreateLShr(B.CreateAnd(a, ConstantInt::get(ty, mask)), kk);
    }
    case Instruction::AShr: {
        auto *k = dyn_cast<ConstantInt>(b);
        if (!k || k->isZero() || k->uge(width))
            return nullptr;
        Value *r = rng.constInt(ty);
        // ((a ^ r) >>s k) ^ (r >>s k) — XOR distributes over arithmetic shift.
        Value *lhs = B.CreateAShr(B.CreateXor(a, r), b);
        Value *rhs = B.CreateAShr(r, b);
        return B.CreateXor(lhs, rhs);
    }
    default:
        return nullptr;
    }
}

} // namespace

bool substituteFunction(Function &F, const SubstitutionParams &params,
                        ir::IRRandom &rng) {
    const std::uint32_t iterations = params.iterations ? params.iterations : 1;
    bool changed = false;

    for (std::uint32_t it = 0; it < iterations; ++it) {
        std::vector<BinaryOperator *> targets;
        for (BasicBlock &bb : F)
            for (Instruction &inst : bb)
                if (auto *bo = dyn_cast<BinaryOperator>(&inst))
                    if (bo->getType()->isIntegerTy())
                        targets.push_back(bo);

        for (BinaryOperator *bo : targets) {
            if (!rng.chance(params.probability))
                continue;
            if (Value *repl = emitSubstitution(bo, rng)) {
                bo->replaceAllUsesWith(repl);
                bo->eraseFromParent();
                changed = true;
            }
        }
    }
    return changed;
}

PreservedAnalyses SubstitutionPass::run(Function &F,
                                        FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return substituteFunction(F, params_, rng) ? PreservedAnalyses::none()
                                               : PreservedAnalyses::all();
}

} // namespace morok::passes
