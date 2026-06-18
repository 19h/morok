// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/AliasOpaquePredicates.cpp
//
// Pointer/aliasing-invariant opaque predicates.  Each selected block maintains
// a tiny runtime cell:
//   slot1 == slot0 ^ slot2
// The guard reloads the slots through pointer/int/pointer aliases and branches
// on that invariant.  The predicate is true by construction, but a recovery
// pipeline has to reason about volatile memory, pointer laundering, and
// aliasing rather than normalize a pure arithmetic identity.

#include "morok/passes/AliasOpaquePredicates.hpp"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <algorithm>
#include <cstdint>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr char kCellPrefix[] = "morok.aliasop.cell";
constexpr char kJunkPrefix[] = "morok.aliasop.junk";

bool isGeneratedBlock(const BasicBlock &BB) {
    return BB.getName().starts_with("morok.aliasop");
}

Instruction *guardSplitPoint(BasicBlock &BB) {
    for (Instruction &I : BB) {
        if (isa<PHINode>(&I) || isa<AllocaInst>(&I))
            continue;
        if (I.isTerminator())
            return nullptr;
        return &I;
    }
    return nullptr;
}

AllocaInst *findCell(Function &F) {
    for (Instruction &I : F.getEntryBlock())
        if (auto *AI = dyn_cast<AllocaInst>(&I))
            if (AI->getName().starts_with(kCellPrefix))
                return AI;
    return nullptr;
}

AllocaInst *ensureCell(Function &F) {
    if (AllocaInst *Existing = findCell(F))
        return Existing;

    LLVMContext &Ctx = F.getContext();
    IRBuilder<> B(&*F.getEntryBlock().getFirstInsertionPt());
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *CellTy = ArrayType::get(I64, 3);
    auto *Cell = B.CreateAlloca(CellTy, nullptr, kCellPrefix);
    Cell->setAlignment(Align(8));
    return Cell;
}

Value *slotPtr(IRBuilder<NoFolder> &B, AllocaInst *Cell, unsigned Slot,
               const Twine &Name) {
    auto *I32 = Type::getInt32Ty(B.getContext());
    Value *Zero = ConstantInt::get(I32, 0);
    Value *Idx = ConstantInt::get(I32, Slot);
    return B.CreateInBoundsGEP(Cell->getAllocatedType(), Cell, {Zero, Idx},
                               Name);
}

Value *aliasPtr(IRBuilder<NoFolder> &B, Value *Ptr, ir::IRRandom &rng,
                const Twine &Name) {
    auto *I64 = Type::getInt64Ty(B.getContext());
    Value *Raw = B.CreatePtrToInt(Ptr, I64, Name + ".raw");
    Value *Key = ConstantInt::get(I64, rng.next() | 1ull);
    Value *Masked = B.CreateXor(Raw, Key, Name + ".mask");
    Value *Unmasked = B.CreateXor(Masked, Key, Name + ".unmask");
    return B.CreateIntToPtr(Unmasked, Ptr->getType(), Name + ".alias");
}

StoreInst *volatileStore(IRBuilder<NoFolder> &B, Value *V, Value *Ptr) {
    auto *SI = B.CreateStore(V, Ptr);
    SI->setVolatile(true);
    SI->setAlignment(Align(8));
    return SI;
}

LoadInst *volatileLoad(IRBuilder<NoFolder> &B, Type *Ty, Value *Ptr,
                       const Twine &Name) {
    auto *LI = B.CreateLoad(Ty, Ptr, Name);
    LI->setVolatile(true);
    LI->setAlignment(Align(8));
    return LI;
}

Value *buildPredicate(IRBuilder<NoFolder> &B, AllocaInst *Cell,
                      ir::IRRandom &rng) {
    auto *I64 = Type::getInt64Ty(B.getContext());
    Value *S0 = slotPtr(B, Cell, 0, "morok.aliasop.slot0");
    Value *S1 = slotPtr(B, Cell, 1, "morok.aliasop.slot1");
    Value *S2 = slotPtr(B, Cell, 2, "morok.aliasop.slot2");

    Value *CellBits = B.CreatePtrToInt(Cell, I64, "morok.aliasop.cellbits");
    Value *Salt = ConstantInt::get(I64, rng.next());
    Value *Base = B.CreateXor(CellBits, Salt, "morok.aliasop.base");
    Value *Key = ConstantInt::get(I64, rng.next() | 1ull);
    Value *Encoded = B.CreateXor(Base, Key, "morok.aliasop.encoded");

    volatileStore(B, Base, aliasPtr(B, S0, rng, "morok.aliasop.store0"));
    volatileStore(B, Encoded, aliasPtr(B, S1, rng, "morok.aliasop.store1"));
    volatileStore(B, Key, aliasPtr(B, S2, rng, "morok.aliasop.store2"));

    Value *A = volatileLoad(B, I64, aliasPtr(B, S0, rng, "morok.aliasop.load0"),
                            "morok.aliasop.a");
    Value *Bv = volatileLoad(
        B, I64, aliasPtr(B, S1, rng, "morok.aliasop.load1"), "morok.aliasop.b");
    Value *K = volatileLoad(B, I64, aliasPtr(B, S2, rng, "morok.aliasop.load2"),
                            "morok.aliasop.k");
    Value *Decoded = B.CreateXor(A, K, "morok.aliasop.decoded");
    return B.CreateICmpEQ(Decoded, Bv, "morok.aliasop.pred");
}

void buildJunkBlock(BasicBlock *Junk, BasicBlock *Body, AllocaInst *Cell,
                    ir::IRRandom &rng) {
    LLVMContext &Ctx = Junk->getContext();
    IRBuilder<NoFolder> B(Junk);
    auto *I64 = Type::getInt64Ty(Ctx);
    Value *S1 = slotPtr(B, Cell, 1, "morok.aliasop.junk.slot1");
    Value *S2 = slotPtr(B, Cell, 2, "morok.aliasop.junk.slot2");
    Value *A =
        volatileLoad(B, I64, aliasPtr(B, S1, rng, "morok.aliasop.junk.load1"),
                     "morok.aliasop.junk.a");
    Value *K =
        volatileLoad(B, I64, aliasPtr(B, S2, rng, "morok.aliasop.junk.load2"),
                     "morok.aliasop.junk.k");
    Value *Noise = B.CreateAdd(A, K, "morok.aliasop.junk.noise");
    Noise = B.CreateXor(Noise, ConstantInt::get(I64, rng.next()),
                        "morok.aliasop.junk.mix");
    volatileStore(B, Noise, aliasPtr(B, S1, rng, "morok.aliasop.junk.store"));
    B.CreateBr(Body);
}

} // namespace

bool aliasOpaquePredicatesFunction(Function &F, const AliasOpParams &params,
                                   ir::IRRandom &rng) {
    if (F.isDeclaration() || params.probability == 0 || params.max_blocks == 0)
        return false;

    // max_blocks already caps how many blocks are transformed across all
    // iterations, but the outer loop still spins once per iteration; clamp to a
    // generous ceiling so a malformed config — or a stale/partial build handing
    // this pass an uninitialized AliasOpParams — cannot spin it billions of
    // times.  The "max" preset asks for 2.
    constexpr std::uint32_t kMaxAliasOpIterations = 8;
    const std::uint32_t iterations = std::clamp<std::uint32_t>(
        std::max<std::uint32_t>(params.iterations, 1), 1, kMaxAliasOpIterations);
    AllocaInst *Cell = nullptr;
    bool changed = false;
    std::uint32_t transformed = 0;

    for (std::uint32_t it = 0; it < iterations; ++it) {
        std::vector<BasicBlock *> blocks;
        for (BasicBlock &BB : F)
            blocks.push_back(&BB);

        for (BasicBlock *Head : blocks) {
            if (transformed >= params.max_blocks)
                return changed;
            if (Head->isEHPad() || Head->isLandingPad() ||
                isGeneratedBlock(*Head))
                continue;
            if (!rng.chance(params.probability))
                continue;

            Instruction *SplitPt = guardSplitPoint(*Head);
            if (!SplitPt)
                continue;

            if (!Cell)
                Cell = ensureCell(F);

            BasicBlock *Body = SplitBlock(Head, SplitPt);
            Instruction *HeadTerm = Head->getTerminator();
            IRBuilder<NoFolder> B(HeadTerm);
            Value *Pred = buildPredicate(B, Cell, rng);

            BasicBlock *Junk =
                BasicBlock::Create(F.getContext(), kJunkPrefix, &F, Body);
            buildJunkBlock(Junk, Body, Cell, rng);

            B.CreateCondBr(Pred, Body, Junk);
            HeadTerm->eraseFromParent();
            changed = true;
            ++transformed;
        }
    }

    return changed;
}

PreservedAnalyses AliasOpaquePredicatesPass::run(Function &F,
                                                 FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return aliasOpaquePredicatesFunction(F, params_, rng)
               ? PreservedAnalyses::none()
               : PreservedAnalyses::all();
}

} // namespace morok::passes
