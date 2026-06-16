// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/TypePunning.cpp
//
// Type-punning chains: value V is stored into a local byte-array "union" and
// loaded through a conflicting type view before being restored to V's type.
// Volatile memory operations keep the punning surface visible to the optimizer
// and to decompiler type recovery.

#include "morok/passes/TypePunning.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

struct Target {
    Instruction *inst = nullptr;
    std::uint64_t bytes = 0;
    Align align{1};
};

struct PunResult {
    Value *replacement = nullptr;
    std::vector<Instruction *> generated;
};

bool isPassGenerated(const Value *V) {
    if (const auto *I = dyn_cast<Instruction>(V))
        return I->getName().starts_with("morok.pun");
    return false;
}

bool eligibleType(Type *Ty, const TypePunParams &params) {
    if (auto *IT = dyn_cast<IntegerType>(Ty)) {
        const unsigned bits = IT->getBitWidth();
        return bits >= 1 && bits <= 1024;
    }
    if (!params.include_floating)
        return false;
    return Ty->isHalfTy() || Ty->isBFloatTy() || Ty->isFloatTy() ||
           Ty->isDoubleTy();
}

bool eligibleInstruction(const Instruction &I, const TypePunParams &params) {
    if (I.isTerminator() || isa<AllocaInst>(I) || isa<LandingPadInst>(I) ||
        isa<IntrinsicInst>(I))
        return false;
    if (isa<PHINode>(I) && I.getParent()->isEHPad())
        return false;
    if (isPassGenerated(&I))
        return false;
    return I.getNextNode() && eligibleType(I.getType(), params);
}

std::optional<Target> makeTarget(Instruction &I, const DataLayout &DL,
                                 const TypePunParams &params) {
    if (!eligibleInstruction(I, params))
        return std::nullopt;

    Type *Ty = I.getType();
    TypeSize size = DL.getTypeStoreSize(Ty);
    if (size.isScalable())
        return std::nullopt;
    const std::uint64_t bytes = size.getFixedValue();
    if (bytes == 0 || bytes > 128)
        return std::nullopt;

    return Target{&I, bytes, DL.getABITypeAlign(Ty)};
}

Type *integerViewType(LLVMContext &Ctx, std::uint64_t bytes) {
    return IntegerType::get(Ctx, static_cast<unsigned>(bytes * 8u));
}

Type *alternateLoadType(Type *OriginalTy, std::uint64_t bytes) {
    LLVMContext &Ctx = OriginalTy->getContext();
    if (auto *IT = dyn_cast<IntegerType>(OriginalTy)) {
        if (IT->getBitWidth() % 8u != 0)
            return integerViewType(Ctx, bytes);
        return FixedVectorType::get(Type::getInt8Ty(Ctx),
                                    static_cast<unsigned>(bytes));
    }
    return integerViewType(Ctx, bytes);
}

bool needsCoveringInteger(Type *Ty) {
    auto *IT = dyn_cast<IntegerType>(Ty);
    return IT && IT->getBitWidth() % 8u != 0;
}

AllocaInst *createPunBuffer(Function &F, const Target &target) {
    BasicBlock &entry = F.getEntryBlock();
    IRBuilder<NoFolder> EntryB(&*entry.getFirstInsertionPt());
    Type *i8 = Type::getInt8Ty(F.getContext());
    auto *bufferTy = ArrayType::get(i8, target.bytes);
    AllocaInst *buffer = EntryB.CreateAlloca(bufferTy, nullptr, "morok.pun");
    buffer->setAlignment(target.align);
    return buffer;
}

PunResult createPunChain(Function &F, const Target &target) {
    Instruction &I = *target.inst;
    Type *Ty = I.getType();
    AllocaInst *buffer = createPunBuffer(F, target);
    Type *altTy = alternateLoadType(Ty, target.bytes);

    Instruction *InsertBefore = isa<PHINode>(I)
                                    ? &*I.getParent()->getFirstNonPHIIt()
                                    : I.getNextNode();
    IRBuilder<NoFolder> B(InsertBefore);
    Value *Stored = &I;
    if (needsCoveringInteger(Ty))
        Stored = B.CreateZExt(&I, altTy, "morok.pun.widen");

    auto *store = B.CreateStore(Stored, buffer, /*isVolatile=*/true);
    store->setAlignment(target.align);

    auto *loaded =
        B.CreateLoad(altTy, buffer, /*isVolatile=*/true, "morok.pun.view");
    loaded->setAlignment(target.align);

    Value *replacement = needsCoveringInteger(Ty)
                             ? B.CreateTrunc(loaded, Ty, "morok.pun.value")
                             : B.CreateBitCast(loaded, Ty, "morok.pun.value");

    PunResult result;
    result.replacement = replacement;
    result.generated.push_back(buffer);
    if (Stored != &I)
        if (auto *Widen = dyn_cast<Instruction>(Stored))
            result.generated.push_back(Widen);
    result.generated.push_back(store);
    result.generated.push_back(loaded);
    result.generated.push_back(cast<Instruction>(replacement));
    return result;
}

void replaceExternalUses(Instruction &I, const PunResult &result) {
    SmallPtrSet<const User *, 8> generated;
    for (Instruction *inst : result.generated)
        generated.insert(inst);

    I.replaceUsesWithIf(result.replacement, [&](Use &U) {
        if (isa<PHINode>(I) && isa<PHINode>(U.getUser()))
            return false;
        return !generated.contains(U.getUser());
    });
}

void shuffleTargets(std::vector<Target> &targets, ir::IRRandom &rng) {
    for (std::size_t i = targets.size(); i > 1; --i) {
        const std::size_t j = rng.range(static_cast<std::uint32_t>(i));
        std::swap(targets[i - 1], targets[j]);
    }
}

} // namespace

bool typePunFunction(Function &F, const TypePunParams &params,
                     ir::IRRandom &rng) {
    if (F.isDeclaration() || params.probability == 0 || params.max_targets == 0)
        return false;
    Module *M = F.getParent();
    if (!M)
        return false;

    const DataLayout &DL = M->getDataLayout();
    std::vector<Target> targets;
    for (BasicBlock &BB : F)
        for (Instruction &I : BB)
            if (auto target = makeTarget(I, DL, params))
                targets.push_back(*target);

    shuffleTargets(targets, rng);

    bool changed = false;
    std::uint32_t emitted = 0;
    for (const Target &target : targets) {
        if (emitted >= params.max_targets)
            break;
        if (!rng.chance(params.probability))
            continue;
        PunResult result = createPunChain(F, target);
        replaceExternalUses(*target.inst, result);
        changed = true;
        ++emitted;
    }
    return changed;
}

PreservedAnalyses TypePunningPass::run(Function &F, FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return typePunFunction(F, params_, rng) ? PreservedAnalyses::none()
                                            : PreservedAnalyses::all();
}

} // namespace morok::passes
