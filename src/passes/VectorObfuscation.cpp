// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/VectorObfuscation.cpp
//
// a OP b  becomes  extractelement(shuffle(<a,j...> OP <b,j...>), 0), scalar
// casts become vector casts over junk-filled lanes, and scalar selects get the
// same true/false vector treatment.  Per-lane vector semantics keep the chosen
// real lane exactly equal to the scalar op; the surrounding vector lanes and
// optional shuffle create a SIMD surface for decompilers.

#include "morok/passes/VectorObfuscation.hpp"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Operator.h"

#include <algorithm>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr std::size_t kMaxVectorLiftTargets = 128;
constexpr std::size_t kMaxVectorCompareTargets = 128;
constexpr std::size_t kMaxVectorSelectTargets = 128;
constexpr std::size_t kMaxVectorCastTargets = 128;

bool passGenerated(const Instruction *I) {
    return I && I->getName().starts_with("morok.vec");
}

bool supportedScalar(Type *Ty) {
    // Sub-byte integers (notably i1) vectorize into <N x i1> mask vectors that
    // several backends mis-lower or crash on — e.g. the X86 Assembly Printer
    // aborts on a junk-filled <32 x i1> vector trunc produced from `trunc i8 to
    // i1`. Such lanes also carry no obfuscation value, so only vectorize integer
    // lanes that are at least one byte wide.
    if (auto *IT = dyn_cast<IntegerType>(Ty))
        return IT->getBitWidth() >= 8;
    return Ty->isHalfTy() || Ty->isBFloatTy() || Ty->isFloatTy() ||
           Ty->isDoubleTy();
}

bool liftable(BinaryOperator *bo) {
    Type *Ty = bo->getType();
    if (auto *IT = dyn_cast<IntegerType>(Ty)) {
        // Skip sub-byte (i1) lanes: <N x i1> vectors are backend-fragile and
        // pointless to obfuscate. See supportedScalar().
        if (IT->getBitWidth() < 8)
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

    if (!(Ty->isHalfTy() || Ty->isBFloatTy() || Ty->isFloatTy() ||
          Ty->isDoubleTy()))
        return false;
    // Fast-math flags are copied onto the lifted vector op, so the real lane
    // computes the identical flagged result; any junk lane that violates a
    // flag merely poisons that (unused) lane.
    //
    // FDiv/FRem are deliberately excluded: unlike poison in an unused integer
    // lane, the hardware still *executes* the divide on the junk lanes, whose
    // denominator can be exactly 0.0 (junkScalar emits 0..255).  That raises
    // FE_DIVBYZERO/FE_INVALID in the shared fenv and SIGFPE if the protected
    // program enabled FP traps — a side effect the scalar op never had.  Bounded
    // finite junk through FAdd/FSub/FMul cannot trap, so those stay eligible.
    switch (bo->getOpcode()) {
    case Instruction::FAdd:
    case Instruction::FSub:
    case Instruction::FMul:
        return true;
    default:
        return false;
    }
}

bool liftableCompare(CmpInst *cmp) {
    Type *Ty = cmp->getOperand(0)->getType();
    if (auto *ICmp = dyn_cast<ICmpInst>(cmp)) {
        auto *IT = dyn_cast<IntegerType>(Ty);
        return IT && IT->getBitWidth() >= 8 &&
               ICmp->getOperand(1)->getType() == Ty;
    }
    if (auto *FCmp = dyn_cast<FCmpInst>(cmp)) {
        if (!(Ty->isHalfTy() || Ty->isBFloatTy() || Ty->isFloatTy() ||
              Ty->isDoubleTy()))
            return false;
        if (FCmp->getOperand(1)->getType() != Ty)
            return false;
        return true;
    }
    return false;
}

bool liftableSelect(SelectInst *sel) {
    Type *Ty = sel->getType();
    return (Ty->isIntegerTy() || Ty->isHalfTy() || Ty->isBFloatTy() ||
            Ty->isFloatTy() || Ty->isDoubleTy()) &&
           sel->getCondition()->getType()->isIntegerTy(1);
}

bool supportedCastOpcode(unsigned Opcode) {
    switch (Opcode) {
    case Instruction::Trunc:
    case Instruction::ZExt:
    case Instruction::SExt:
    case Instruction::FPTrunc:
    case Instruction::FPExt:
    case Instruction::FPToUI:
    case Instruction::FPToSI:
    case Instruction::UIToFP:
    case Instruction::SIToFP:
    case Instruction::BitCast:
        return true;
    default:
        return false;
    }
}

bool liftableCast(CastInst *Cast) {
    if (!supportedCastOpcode(Cast->getOpcode()))
        return false;
    Type *SrcTy = Cast->getSrcTy();
    Type *DstTy = Cast->getDestTy();
    if (!supportedScalar(SrcTy) || !supportedScalar(DstTy))
        return false;
    if (Cast->getOpcode() == Instruction::BitCast)
        return SrcTy->getPrimitiveSizeInBits() ==
               DstTy->getPrimitiveSizeInBits();
    return true;
}

unsigned scalarBits(Type *Ty) {
    if (auto *IT = dyn_cast<IntegerType>(Ty))
        return IT->getBitWidth();
    return static_cast<unsigned>(Ty->getPrimitiveSizeInBits());
}

std::uint32_t laneCountForBits(unsigned bits, const VecParams &params) {
    const std::uint32_t width =
        params.width == 256 || params.width == 512 ? params.width : 128u;
    const std::uint32_t lanes = width / std::max<unsigned>(bits, 1u);
    return lanes >= 2u ? lanes : 0u;
}

std::uint32_t laneCount(Type *Ty, const VecParams &params) {
    return laneCountForBits(scalarBits(Ty), params);
}

std::uint32_t laneCount(Type *SrcTy, Type *DstTy, const VecParams &params) {
    return laneCountForBits(std::max(scalarBits(SrcTy), scalarBits(DstTy)),
                            params);
}

Constant *junkScalar(Type *Ty, ir::IRRandom &rng) {
    if (auto *IT = dyn_cast<IntegerType>(Ty))
        return ConstantInt::get(IT, static_cast<std::uint64_t>(rng.next()));
    const double V =
        static_cast<double>(static_cast<std::int32_t>(rng.next() & 0xffffu)) /
        257.0;
    return ConstantFP::get(Ty, V);
}

Value *buildVector(IRBuilder<> &B, Value *real, FixedVectorType *vecTy,
                   std::uint32_t realLane, ir::IRRandom &rng,
                   const Twine &name) {
    Type *Ty = real->getType();
    Value *v = PoisonValue::get(vecTy);
    const std::uint32_t lanes =
        static_cast<std::uint32_t>(vecTy->getNumElements());
    for (std::uint32_t lane = 0; lane < lanes; ++lane) {
        Value *element = lane == realLane ? real : junkScalar(Ty, rng);
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
    Type *Ty = bo->getType();
    const std::uint32_t lanes = laneCount(Ty, params);
    if (lanes < 2u)
        return false;

    auto *vecTy = FixedVectorType::get(Ty, lanes);
    IRBuilder<> B(bo);
    const std::uint32_t realLane =
        params.shuffle ? rng.range(lanes) : static_cast<std::uint32_t>(0);
    Value *va =
        buildVector(B, bo->getOperand(0), vecTy, realLane, rng, "morok.vec.a");
    Value *vb =
        buildVector(B, bo->getOperand(1), vecTy, realLane, rng, "morok.vec.b");
    Value *vr = B.CreateBinOp(bo->getOpcode(), va, vb, "morok.vec.op");
    if (auto *VecBO = dyn_cast<BinaryOperator>(vr)) {
        if (auto *OldOverflow = dyn_cast<OverflowingBinaryOperator>(bo)) {
            VecBO->setHasNoUnsignedWrap(OldOverflow->hasNoUnsignedWrap());
            VecBO->setHasNoSignedWrap(OldOverflow->hasNoSignedWrap());
        }
        if (auto *OldExact = dyn_cast<PossiblyExactOperator>(bo))
            VecBO->setIsExact(OldExact->isExact());
        if (isa<FPMathOperator>(bo))
            VecBO->copyFastMathFlags(bo);
    }
    Value *r = extractRealLane(B, vr, lanes, realLane, params.shuffle, rng,
                               "morok.vec.value");

    bo->replaceAllUsesWith(r);
    bo->eraseFromParent();
    return true;
}

bool liftCast(CastInst *Cast, const VecParams &params, ir::IRRandom &rng) {
    Type *SrcTy = Cast->getSrcTy();
    Type *DstTy = Cast->getDestTy();
    const std::uint32_t lanes = laneCount(SrcTy, DstTy, params);
    if (lanes < 2u)
        return false;

    auto *SrcVecTy = FixedVectorType::get(SrcTy, lanes);
    auto *DstVecTy = FixedVectorType::get(DstTy, lanes);
    IRBuilder<> B(Cast);
    const std::uint32_t realLane =
        params.shuffle ? rng.range(lanes) : static_cast<std::uint32_t>(0);
    Value *Input = buildVector(B, Cast->getOperand(0), SrcVecTy, realLane, rng,
                               "morok.vec.cast.input");
    Value *VecCast =
        B.CreateCast(Cast->getOpcode(), Input, DstVecTy, "morok.vec.cast");
    Value *R = extractRealLane(B, VecCast, lanes, realLane, params.shuffle, rng,
                               "morok.vec.cast.value");

    Cast->replaceAllUsesWith(R);
    Cast->eraseFromParent();
    return true;
}

bool liftCompare(CmpInst *cmp, const VecParams &params, ir::IRRandom &rng) {
    Type *Ty = cmp->getOperand(0)->getType();
    const std::uint32_t lanes = laneCount(Ty, params);
    if (lanes < 2u)
        return false;

    auto *vecTy = FixedVectorType::get(Ty, lanes);
    IRBuilder<> B(cmp);
    const std::uint32_t realLane =
        params.shuffle ? rng.range(lanes) : static_cast<std::uint32_t>(0);
    Value *va = buildVector(B, cmp->getOperand(0), vecTy, realLane, rng,
                            "morok.vec.cmp.a");
    Value *vb = buildVector(B, cmp->getOperand(1), vecTy, realLane, rng,
                            "morok.vec.cmp.b");
    Value *vcmp =
        isa<ICmpInst>(cmp)
            ? B.CreateICmp(cmp->getPredicate(), va, vb, "morok.vec.cmp")
            : B.CreateFCmp(cmp->getPredicate(), va, vb, "morok.vec.cmp");
    if (isa<FCmpInst>(cmp))
        if (auto *VecCmp = dyn_cast<Instruction>(vcmp))
            VecCmp->copyFastMathFlags(cmp);
    Value *r = extractRealLane(B, vcmp, lanes, realLane, params.shuffle, rng,
                               "morok.vec.cmp.value");

    cmp->replaceAllUsesWith(r);
    cmp->eraseFromParent();
    return true;
}

bool liftSelect(SelectInst *sel, const VecParams &params, ir::IRRandom &rng) {
    Type *Ty = sel->getType();
    const std::uint32_t lanes = laneCount(Ty, params);
    if (lanes < 2u)
        return false;

    auto *vecTy = FixedVectorType::get(Ty, lanes);
    IRBuilder<> B(sel);
    const std::uint32_t realLane =
        params.shuffle ? rng.range(lanes) : static_cast<std::uint32_t>(0);
    Value *vt = buildVector(B, sel->getTrueValue(), vecTy, realLane, rng,
                            "morok.vec.sel.t");
    Value *vf = buildVector(B, sel->getFalseValue(), vecTy, realLane, rng,
                            "morok.vec.sel.f");
    Value *vsel = B.CreateSelect(sel->getCondition(), vt, vf, "morok.vec.sel");
    Value *r = extractRealLane(B, vsel, lanes, realLane, params.shuffle, rng,
                               "morok.vec.sel.value");

    sel->replaceAllUsesWith(r);
    sel->eraseFromParent();
    return true;
}

} // namespace

bool vectorObfuscateFunction(Function &F, const VecParams &params,
                             ir::IRRandom &rng) {
    std::vector<BinaryOperator *> targets;
    std::vector<CmpInst *> compares;
    std::vector<SelectInst *> selects;
    std::vector<CastInst *> casts;
    for (BasicBlock &bb : F) {
        for (Instruction &inst : bb) {
            if (passGenerated(&inst))
                continue;
            if (auto *bo = dyn_cast<BinaryOperator>(&inst))
                if (liftable(bo))
                    if (targets.size() < kMaxVectorLiftTargets)
                        targets.push_back(bo);
            if (params.lift_comparisons)
                if (auto *cmp = dyn_cast<CmpInst>(&inst))
                    if (liftableCompare(cmp))
                        if (compares.size() < kMaxVectorCompareTargets)
                            compares.push_back(cmp);
            if (auto *sel = dyn_cast<SelectInst>(&inst))
                if (liftableSelect(sel))
                    if (selects.size() < kMaxVectorSelectTargets)
                        selects.push_back(sel);
            if (auto *cast = dyn_cast<CastInst>(&inst))
                if (liftableCast(cast))
                    if (casts.size() < kMaxVectorCastTargets)
                        casts.push_back(cast);
            if (targets.size() >= kMaxVectorLiftTargets &&
                (!params.lift_comparisons ||
                 compares.size() >= kMaxVectorCompareTargets) &&
                selects.size() >= kMaxVectorSelectTargets &&
                casts.size() >= kMaxVectorCastTargets)
                break;
        }
        if (targets.size() >= kMaxVectorLiftTargets &&
            (!params.lift_comparisons ||
             compares.size() >= kMaxVectorCompareTargets) &&
            selects.size() >= kMaxVectorSelectTargets &&
            casts.size() >= kMaxVectorCastTargets)
            break;
    }

    bool changed = false;
    for (CastInst *cast : casts) {
        if (!rng.chance(params.probability))
            continue;
        changed |= liftCast(cast, params, rng);
    }
    for (BinaryOperator *bo : targets) {
        if (!rng.chance(params.probability))
            continue;
        changed |= liftBinary(bo, params, rng);
    }
    for (CmpInst *cmp : compares) {
        if (!rng.chance(params.probability))
            continue;
        changed |= liftCompare(cmp, params, rng);
    }
    for (SelectInst *sel : selects) {
        if (!rng.chance(params.probability))
            continue;
        changed |= liftSelect(sel, params, rng);
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
