// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/StackDeltaGames.cpp
//
// Stack-pointer-delta games from IR.  The pass injects stack save/restore
// pairs around variable-sized `alloca i8, N` frames, then writes overlapping
// volatile slots at odd offsets.  This forces real dynamic SP adjustment and
// irregular stack memory without changing program-visible data flow.

#include "morok/passes/StackDeltaGames.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <algorithm>
#include <cstdint>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

using Builder = IRBuilder<NoFolder>;

constexpr char kSeedName[] = "morok.stackdelta.seed";
constexpr char kFrameName[] = "morok.stackdelta.frame";

bool isGeneratedFunction(const Function &F) {
    return F.getName().starts_with("morok.");
}

bool isGeneratedBlock(const BasicBlock &BB) {
    return BB.getName().starts_with("morok.stackdelta");
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

GlobalVariable *ensureSeed(Module &M, ir::IRRandom &rng) {
    if (auto *GV = M.getGlobalVariable(kSeedName, /*AllowInternal=*/true))
        return GV;
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *GV = new GlobalVariable(
        M, I64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, rng.next()), kSeedName);
    GV->setAlignment(Align(8));
    GV->setDSOLocal(true);
    return GV;
}

void addTerm(Value *V, SmallPtrSetImpl<Value *> &Seen,
             std::vector<Value *> &Terms) {
    if (!V || !V->getType()->isIntegerTy())
        return;
    if (Seen.insert(V).second)
        Terms.push_back(V);
}

std::vector<Value *> collectTerms(Function &F, Instruction &SplitPt) {
    std::vector<Value *> Terms;
    SmallPtrSet<Value *, 32> Seen;
    for (Argument &Arg : F.args())
        addTerm(&Arg, Seen, Terms);

    for (Instruction &I : *SplitPt.getParent()) {
        if (&I == &SplitPt)
            break;
        if (isa<AllocaInst>(&I) || isa<PHINode>(&I))
            continue;
        addTerm(&I, Seen, Terms);
    }
    return Terms;
}

Value *asI64(Builder &B, Value *V) {
    auto *I64 = B.getInt64Ty();
    if (V->getType() == I64)
        return V;
    auto *IT = dyn_cast<IntegerType>(V->getType());
    if (!IT)
        return nullptr;
    if (IT->getBitWidth() < 64)
        return B.CreateZExt(V, I64, "morok.stackdelta.term.zext");
    return B.CreateTrunc(V, I64, "morok.stackdelta.term.trunc");
}

Value *buildMix(Builder &B, GlobalVariable *Seed, Function &F,
                Instruction &SplitPt, ir::IRRandom &rng) {
    auto *I64 = B.getInt64Ty();
    auto *Loaded = B.CreateLoad(I64, Seed, "morok.stackdelta.seed.load");
    Loaded->setVolatile(true);
    Loaded->setAlignment(Align(8));

    Value *Mix = Loaded;
    Mix = B.CreateXor(Mix, ConstantInt::get(I64, rng.next()),
                      "morok.stackdelta.mix.salt");
    std::vector<Value *> Terms = collectTerms(F, SplitPt);
    for (Value *Term : Terms) {
        Value *T = asI64(B, Term);
        if (!T)
            continue;
        Mix = B.CreateXor(Mix, T, "morok.stackdelta.mix.term");
        Mix = B.CreateMul(Mix, ConstantInt::get(I64, rng.next() | 1ull),
                          "morok.stackdelta.mix.mul");
    }
    return Mix;
}

std::uint32_t normalizedMinBytes(const StackDeltaParams &Params) {
    std::uint32_t Min = std::max<std::uint32_t>(Params.min_bytes, 17);
    if ((Min & 1u) == 0)
        ++Min;
    return Min;
}

Value *buildDynamicSize(Builder &B, Value *Mix,
                        const StackDeltaParams &Params) {
    auto *I64 = B.getInt64Ty();
    Value *Extra = B.CreateAnd(
        Mix, ConstantInt::get(I64, Params.max_extra_bytes),
        "morok.stackdelta.extra");
    return B.CreateAdd(Extra, ConstantInt::get(I64, normalizedMinBytes(Params)),
                       "morok.stackdelta.size");
}

void volatileStore(Builder &B, Value *V, Value *Ptr, Align A = Align(1)) {
    auto *SI = B.CreateStore(V, Ptr);
    SI->setVolatile(true);
    SI->setAlignment(A);
}

void emitStackDelta(BasicBlock *Head, Instruction &SplitPt,
                    GlobalVariable *Seed, const StackDeltaParams &Params,
                    ir::IRRandom &rng) {
    Function &F = *Head->getParent();
    Module &M = *F.getParent();
    LLVMContext &Ctx = M.getContext();
    auto *PtrTy = PointerType::get(Ctx, 0);
    Function *StackSave =
        Intrinsic::getOrInsertDeclaration(&M, Intrinsic::stacksave, {PtrTy});
    Function *StackRestore =
        Intrinsic::getOrInsertDeclaration(&M, Intrinsic::stackrestore,
                                          {PtrTy});

    Builder B(Head->getTerminator());
    auto *I8 = B.getInt8Ty();
    auto *I64 = B.getInt64Ty();
    Value *Save = B.CreateCall(StackSave->getFunctionType(), StackSave, {},
                               "morok.stackdelta.save");
    Value *Mix = buildMix(B, Seed, F, SplitPt, rng);
    Value *Size = buildDynamicSize(B, Mix, Params);
    AllocaInst *Frame = B.CreateAlloca(I8, Size, kFrameName);
    Frame->setAlignment(Align(1));

    Value *OverlapPtr =
        B.CreateInBoundsGEP(I8, Frame, ConstantInt::get(I64, 1),
                            "morok.stackdelta.overlap.i64");
    volatileStore(B, Mix, OverlapPtr);

    const std::uint32_t Touches = std::max<std::uint32_t>(Params.touches, 1);
    for (std::uint32_t I = 0; I != Touches; ++I) {
        Value *Byte = B.CreateTrunc(
            B.CreateXor(Mix, ConstantInt::get(I64, rng.next()),
                        "morok.stackdelta.byte.mix"),
            I8, "morok.stackdelta.byte");
        Value *Offset = ConstantInt::get(I64, 2 + (I % 7));
        Value *Ptr = B.CreateInBoundsGEP(I8, Frame, Offset,
                                         "morok.stackdelta.overlap.i8");
        volatileStore(B, Byte, Ptr);
    }

    B.CreateCall(StackRestore->getFunctionType(), StackRestore, {Save});
}

void shuffleBlocks(std::vector<BasicBlock *> &Blocks, ir::IRRandom &rng) {
    for (std::size_t I = Blocks.size(); I > 1; --I) {
        const std::size_t J = rng.range(static_cast<std::uint32_t>(I));
        std::swap(Blocks[I - 1], Blocks[J]);
    }
}

} // namespace

bool stackDeltaGamesFunction(Function &F, const StackDeltaParams &params,
                             ir::IRRandom &rng) {
    if (F.isDeclaration() || isGeneratedFunction(F) || params.probability == 0 ||
        params.max_blocks == 0 || F.hasFnAttribute(Attribute::Naked))
        return false;

    std::vector<BasicBlock *> Blocks;
    for (BasicBlock &BB : F)
        Blocks.push_back(&BB);
    shuffleBlocks(Blocks, rng);

    GlobalVariable *Seed = nullptr;
    bool Changed = false;
    std::uint32_t Count = 0;
    for (BasicBlock *Head : Blocks) {
        if (Count >= params.max_blocks)
            break;
        if (Head->isEHPad() || Head->isLandingPad() || isGeneratedBlock(*Head))
            continue;
        if (!rng.chance(params.probability))
            continue;
        Instruction *SplitPt = guardSplitPoint(*Head);
        if (!SplitPt)
            continue;

        if (!Seed)
            Seed = ensureSeed(*F.getParent(), rng);

        BasicBlock *Body = SplitBlock(Head, SplitPt);
        Instruction *HeadTerm = Head->getTerminator();
        emitStackDelta(Head, *SplitPt, Seed, params, rng);
        HeadTerm->eraseFromParent();
        BranchInst::Create(Body, Head);
        Changed = true;
        ++Count;
    }

    return Changed;
}

PreservedAnalyses StackDeltaGamesPass::run(Function &F,
                                           FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return stackDeltaGamesFunction(F, params_, rng) ? PreservedAnalyses::none()
                                                    : PreservedAnalyses::all();
}

} // namespace morok::passes
