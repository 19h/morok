// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/Mba.cpp
//
// Emits the default identity from each MBA family (proven in core), then —
// when heuristics are on — folds in a provably-zero noise term.  IRBuilder uses
// NoFolder so the structure is not collapsed back to the original op.

#include "morok/passes/Mba.hpp"

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

constexpr std::size_t kMaxMbaTargetsPerLayer = 256;

using Builder = IRBuilder<NoFolder>;

// A value provably equal to zero, derived from a and b (mirrors core zeroTerm).
Value *zeroTerm(Builder &B, Value *a, Value *b, ir::IRRandom &rng) {
    switch (rng.range(4)) {
    case 0:
        return B.CreateXor(a, a); // a ^ a
    case 1:
        return B.CreateXor(b, b); // b ^ b
    case 2:
        return B.CreateAnd(a, B.CreateNot(a)); // a & ~a
    default:
        return B.CreateAnd(b, B.CreateNot(b)); // b & ~b
    }
}

Value *emitMba(BinaryOperator *bo, const MbaParams &params, ir::IRRandom &rng) {
    Builder B(bo);
    Value *a = bo->getOperand(0);
    Value *b = bo->getOperand(1);
    auto *ty = cast<IntegerType>(bo->getType());
    const unsigned width = ty->getBitWidth();

    auto two = [&](Value *v) {
        // 2*v is zero modulo 2; shifting i1 by one would produce poison.
        if (width == 1)
            return static_cast<Value *>(ConstantInt::get(ty, 0));
        return B.CreateShl(v, ConstantInt::get(ty, 1));
    };

    Value *result = nullptr;
    switch (bo->getOpcode()) {
    case Instruction::Add: // (a ^ b) + 2*(a & b)
        result = B.CreateAdd(B.CreateXor(a, b), two(B.CreateAnd(a, b)));
        break;
    case Instruction::Sub: // (a ^ b) - 2*((~a) & b)
        result =
            B.CreateSub(B.CreateXor(a, b), two(B.CreateAnd(B.CreateNot(a), b)));
        break;
    case Instruction::Xor: // (a | b) - (a & b)
        result = B.CreateSub(B.CreateOr(a, b), B.CreateAnd(a, b));
        break;
    case Instruction::And: // ~((~a) | (~b))
        result = B.CreateNot(B.CreateOr(B.CreateNot(a), B.CreateNot(b)));
        break;
    case Instruction::Or: // (a + b) - (a & b)
        result = B.CreateSub(B.CreateAdd(a, b), B.CreateAnd(a, b));
        break;
    case Instruction::Mul: // a*(b + 1) - a
        result = B.CreateSub(
            B.CreateMul(a, B.CreateAdd(b, ConstantInt::get(ty, 1))), a);
        break;
    case Instruction::Shl: { // a << k  ==  a * 2^k  (constant k < width)
        auto *k = dyn_cast<ConstantInt>(b);
        if (!k || k->uge(width))
            return nullptr;
        APInt factor(width, 0);
        factor.setBit(static_cast<unsigned>(k->getZExtValue()));
        result = B.CreateMul(a, ConstantInt::get(ty, factor));
        break;
    }
    case Instruction::LShr: { // a >>u k  ==  (a & high-bits) >>u k
        auto *k = dyn_cast<ConstantInt>(b);
        if (!k || k->isZero() || k->uge(width))
            return nullptr;
        const unsigned kk = static_cast<unsigned>(k->getZExtValue());
        APInt mask = APInt::getHighBitsSet(width, width - kk);
        result = B.CreateLShr(B.CreateAnd(a, ConstantInt::get(ty, mask)), kk);
        break;
    }
    case Instruction::AShr: { // ((a^r) >>s k) ^ (r >>s k) — XOR distributes
        auto *k = dyn_cast<ConstantInt>(b);
        if (!k || k->isZero() || k->uge(width))
            return nullptr;
        Value *r = rng.constInt(ty);
        result = B.CreateXor(B.CreateAShr(B.CreateXor(a, r), b),
                             B.CreateAShr(r, b));
        break;
    }
    default:
        return nullptr;
    }

    if (params.heuristic)
        result = B.CreateAdd(result, zeroTerm(B, a, b, rng));
    return result;
}

} // namespace

bool mbaFunction(Function &F, const MbaParams &params, ir::IRRandom &rng) {
    const std::uint32_t layers = std::clamp<std::uint32_t>(params.layers, 1, 3);
    bool changed = false;

    for (std::uint32_t layer = 0; layer < layers; ++layer) {
        std::vector<BinaryOperator *> targets;
        for (BasicBlock &bb : F) {
            for (Instruction &inst : bb) {
                if (targets.size() >= kMaxMbaTargetsPerLayer)
                    break;
                if (auto *bo = dyn_cast<BinaryOperator>(&inst))
                    if (bo->getType()->isIntegerTy())
                        targets.push_back(bo);
            }
            if (targets.size() >= kMaxMbaTargetsPerLayer)
                break;
        }

        for (BinaryOperator *bo : targets) {
            if (!rng.chance(params.probability))
                continue;
            if (Value *repl = emitMba(bo, params, rng)) {
                bo->replaceAllUsesWith(repl);
                bo->eraseFromParent();
                changed = true;
            }
        }
    }
    return changed;
}

PreservedAnalyses MbaPass::run(Function &F, FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return mbaFunction(F, params_, rng) ? PreservedAnalyses::none()
                                        : PreservedAnalyses::all();
}

} // namespace morok::passes
