// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/VectorObfuscation.cpp
//
// a OP b  becomes  extractelement(shuffle(<a,j...> OP <b,j...>), 0).  Per-lane
// vector semantics keep the chosen real lane exactly equal to the scalar op;
// the surrounding vector lanes and optional shuffle create a SIMD surface for
// decompilers.

#include "morok/passes/VectorObfuscation.hpp"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

#include <algorithm>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr std::size_t kMaxVectorLiftTargets = 128;
constexpr std::size_t kMaxVectorCompareTargets = 128;

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

bool liftableCompare(ICmpInst *cmp) {
    return cmp->getOperand(0)->getType()->isIntegerTy() &&
           cmp->getOperand(1)->getType()->isIntegerTy();
}

std::uint32_t laneCount(IntegerType *ty, const VecParams &params) {
    const std::uint32_t bits = std::max<std::uint32_t>(
        static_cast<std::uint32_t>(ty->getBitWidth()), 1u);
    const std::uint32_t width =
        params.width == 256 || params.width == 512 ? params.width : 128u;
    const std::uint32_t lanes = width / bits;
    return lanes >= 2u ? lanes : 0u;
}

ConstantInt *junkInt(IntegerType *ty, ir::IRRandom &rng) {
    return ConstantInt::get(ty, static_cast<std::uint64_t>(rng.next()));
}

Value *buildVector(IRBuilder<> &B, Value *real, FixedVectorType *vecTy,
                   std::uint32_t realLane, ir::IRRandom &rng,
                   const Twine &name) {
    auto *ty = cast<IntegerType>(real->getType());
    Value *v = PoisonValue::get(vecTy);
    const std::uint32_t lanes =
        static_cast<std::uint32_t>(vecTy->getNumElements());
    for (std::uint32_t lane = 0; lane < lanes; ++lane) {
        Value *element = lane == realLane ? real : junkInt(ty, rng);
        v = B.CreateInsertElement(v, element, B.getInt32(lane), name);
    }
    return v;
}

Value *extractRealLane(IRBuilder<> &B, Value *vector, std::uint32_t lanes,
                       std::uint32_t realLane, bool shuffle, ir::IRRandom &rng,
                       const Twine &name) {
    if (!shuffle)
        return B.CreateExtractElement(vector, B.getInt32(realLane), name);

    SmallVector<int, 16> mask;
    mask.reserve(lanes);
    mask.push_back(static_cast<int>(realLane));
    for (std::uint32_t lane = 1; lane < lanes; ++lane)
        mask.push_back(static_cast<int>(rng.range(lanes)));
    Value *shuffled = B.CreateShuffleVector(
        vector, PoisonValue::get(vector->getType()), mask, name + ".shuffle");
    return B.CreateExtractElement(shuffled, B.getInt32(0), name);
}

bool liftBinary(BinaryOperator *bo, const VecParams &params,
                ir::IRRandom &rng) {
    auto *ty = cast<IntegerType>(bo->getType());
    const std::uint32_t lanes = laneCount(ty, params);
    if (lanes < 2u)
        return false;

    auto *vecTy = FixedVectorType::get(ty, lanes);
    IRBuilder<> B(bo);
    const std::uint32_t realLane =
        params.shuffle ? rng.range(lanes) : static_cast<std::uint32_t>(0);
    Value *va =
        buildVector(B, bo->getOperand(0), vecTy, realLane, rng, "morok.vec.a");
    Value *vb =
        buildVector(B, bo->getOperand(1), vecTy, realLane, rng, "morok.vec.b");
    Value *vr = B.CreateBinOp(bo->getOpcode(), va, vb, "morok.vec.op");
    Value *r = extractRealLane(B, vr, lanes, realLane, params.shuffle, rng,
                               "morok.vec.value");

    bo->replaceAllUsesWith(r);
    bo->eraseFromParent();
    return true;
}

bool liftCompare(ICmpInst *cmp, const VecParams &params, ir::IRRandom &rng) {
    auto *ty = cast<IntegerType>(cmp->getOperand(0)->getType());
    const std::uint32_t lanes = laneCount(ty, params);
    if (lanes < 2u)
        return false;

    auto *vecTy = FixedVectorType::get(ty, lanes);
    IRBuilder<> B(cmp);
    const std::uint32_t realLane =
        params.shuffle ? rng.range(lanes) : static_cast<std::uint32_t>(0);
    Value *va = buildVector(B, cmp->getOperand(0), vecTy, realLane, rng,
                            "morok.vec.cmp.a");
    Value *vb = buildVector(B, cmp->getOperand(1), vecTy, realLane, rng,
                            "morok.vec.cmp.b");
    Value *vcmp = B.CreateICmp(cmp->getPredicate(), va, vb, "morok.vec.cmp");
    Value *r = extractRealLane(B, vcmp, lanes, realLane, params.shuffle, rng,
                               "morok.vec.cmp.value");

    cmp->replaceAllUsesWith(r);
    cmp->eraseFromParent();
    return true;
}

} // namespace

bool vectorObfuscateFunction(Function &F, const VecParams &params,
                             ir::IRRandom &rng) {
    std::vector<BinaryOperator *> targets;
    std::vector<ICmpInst *> compares;
    for (BasicBlock &bb : F) {
        for (Instruction &inst : bb) {
            if (auto *bo = dyn_cast<BinaryOperator>(&inst))
                if (liftable(bo))
                    if (targets.size() < kMaxVectorLiftTargets)
                        targets.push_back(bo);
            if (params.lift_comparisons)
                if (auto *cmp = dyn_cast<ICmpInst>(&inst))
                    if (liftableCompare(cmp))
                        if (compares.size() < kMaxVectorCompareTargets)
                            compares.push_back(cmp);
            if (targets.size() >= kMaxVectorLiftTargets &&
                (!params.lift_comparisons ||
                 compares.size() >= kMaxVectorCompareTargets))
                break;
        }
        if (targets.size() >= kMaxVectorLiftTargets &&
            (!params.lift_comparisons ||
             compares.size() >= kMaxVectorCompareTargets))
            break;
    }

    bool changed = false;
    for (BinaryOperator *bo : targets) {
        if (!rng.chance(params.probability))
            continue;
        changed |= liftBinary(bo, params, rng);
    }
    for (ICmpInst *cmp : compares) {
        if (!rng.chance(params.probability))
            continue;
        changed |= liftCompare(cmp, params, rng);
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
