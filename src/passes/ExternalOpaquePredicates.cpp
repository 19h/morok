// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/ExternalOpaquePredicates.cpp
//
// External/volatile-derived opaque predicates.  Each selected block is guarded
// by two calls to a noinline/optnone helper that volatile-loads a private
// per-module seed and mixes a call-site tag.  Calling the helper twice with the
// same arguments yields equal values at runtime, while the side-effecting
// helper prevents local algebraic simplification and IPO constant folding.

#include "morok/passes/ExternalOpaquePredicates.hpp"

#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/ModRef.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <algorithm>
#include <cstdint>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

using Builder = IRBuilder<NoFolder>;

constexpr char kContextName[] = "morok.extop.context";
constexpr char kSeedName[] = "morok.extop.seed";
constexpr char kScratchName[] = "morok.extop.scratch";
constexpr char kDecoyPrefix[] = "morok.extop.decoy";

bool isGeneratedFunction(const Function &F) {
    return F.getName().starts_with("morok.");
}

bool isGeneratedBlock(const BasicBlock &BB) {
    return BB.getName().starts_with("morok.extop");
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

GlobalVariable *ensureI64Global(Module &M, StringRef Name,
                                std::uint64_t Init) {
    if (auto *GV = M.getGlobalVariable(Name, /*AllowInternal=*/true))
        return GV;
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *GV = new GlobalVariable(
        M, I64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, Init), Name);
    GV->setAlignment(Align(8));
    GV->setDSOLocal(true);
    return GV;
}

LoadInst *volatileLoad(Builder &B, Type *Ty, Value *Ptr, const Twine &Name) {
    auto *LI = B.CreateLoad(Ty, Ptr, Name);
    LI->setVolatile(true);
    LI->setAlignment(Align(8));
    return LI;
}

StoreInst *volatileStore(Builder &B, Value *V, Value *Ptr) {
    auto *SI = B.CreateStore(V, Ptr);
    SI->setVolatile(true);
    SI->setAlignment(Align(8));
    return SI;
}

Function *ensureContextHelper(Module &M, ir::IRRandom &rng) {
    if (Function *F = M.getFunction(kContextName))
        return F;

    LLVMContext &Ctx = M.getContext();
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *Ptr = PointerType::get(Ctx, 0);
    auto *FTy = FunctionType::get(I64, {Ptr, I64}, false);
    auto *F = Function::Create(FTy, GlobalValue::InternalLinkage, kContextName,
                               M);
    F->setDSOLocal(true);
    F->addFnAttr(Attribute::NoInline);
    F->addFnAttr(Attribute::OptimizeNone);
    F->setMemoryEffects(MemoryEffects::unknown());

    GlobalVariable *Seed = ensureI64Global(M, kSeedName, rng.next());

    auto *Entry = BasicBlock::Create(Ctx, "entry", F);
    Builder B(Entry);
    auto ArgIt = F->arg_begin();
    Value *Site = &*ArgIt++;
    Site->setName("site");
    Value *Tag = &*ArgIt;
    Tag->setName("tag");

    Value *SeedV = volatileLoad(B, I64, Seed, "morok.extop.seed.load");
    Value *SiteBits = B.CreatePtrToInt(Site, I64, "morok.extop.site");
    Value *Mix = B.CreateXor(SeedV, SiteBits, "morok.extop.mix.site");
    Mix = B.CreateXor(Mix, Tag, "morok.extop.mix.tag");
    Mix = B.CreateMul(Mix, ConstantInt::get(I64, rng.next() | 1ull),
                      "morok.extop.mix.mul");
    Mix = B.CreateXor(Mix, B.CreateLShr(Mix, 33), "morok.extop.mix.fold");
    B.CreateRet(Mix);
    return F;
}

Function *sitePointer(Function &F) { return &F; }

Value *buildPredicate(Builder &B, Function &F, Function *Context,
                      ir::IRRandom &rng) {
    auto *I64 = B.getInt64Ty();
    Value *Site = sitePointer(F);
    Value *Tag = ConstantInt::get(I64, rng.next());
    auto *A = B.CreateCall(Context->getFunctionType(), Context, {Site, Tag},
                           "morok.extop.a");
    auto *Bv = B.CreateCall(Context->getFunctionType(), Context, {Site, Tag},
                            "morok.extop.b");
    Value *Diff = B.CreateXor(A, Bv, "morok.extop.diff");
    return B.CreateICmpEQ(Diff, ConstantInt::get(I64, 0), "morok.extop.pred");
}

void buildDecoyBlock(BasicBlock *Decoy, BasicBlock *Body,
                     GlobalVariable *Scratch,
                     const ExternalOpaqueParams &Params, ir::IRRandom &rng) {
    Builder B(Decoy);
    auto *I64 = B.getInt64Ty();
    Value *Acc = ConstantInt::get(I64, rng.next());
    const std::uint32_t Stores =
        std::max<std::uint32_t>(Params.decoy_stores, 1);
    for (std::uint32_t I = 0; I != Stores; ++I) {
        Value *Prev =
            volatileLoad(B, I64, Scratch, "morok.extop.decoy.prev");
        Acc = B.CreateAdd(Acc, Prev, "morok.extop.decoy.add");
        Acc = B.CreateXor(
            Acc, ConstantInt::get(I64, rng.next()),
            "morok.extop.decoy.mix");
        volatileStore(B, Acc, Scratch);
    }
    B.CreateBr(Body);
}

void shuffleBlocks(std::vector<BasicBlock *> &Blocks, ir::IRRandom &rng) {
    for (std::size_t I = Blocks.size(); I > 1; --I) {
        const std::size_t J = rng.range(static_cast<std::uint32_t>(I));
        std::swap(Blocks[I - 1], Blocks[J]);
    }
}

} // namespace

bool externalOpaquePredicatesFunction(Function &F,
                                      const ExternalOpaqueParams &params,
                                      ir::IRRandom &rng) {
    if (F.isDeclaration() || isGeneratedFunction(F) || params.probability == 0 ||
        params.max_blocks == 0)
        return false;

    std::vector<BasicBlock *> Blocks;
    for (BasicBlock &BB : F)
        Blocks.push_back(&BB);
    shuffleBlocks(Blocks, rng);

    Function *Context = nullptr;
    GlobalVariable *Scratch = nullptr;
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

        Module &M = *F.getParent();
        if (!Context)
            Context = ensureContextHelper(M, rng);
        if (!Scratch)
            Scratch = ensureI64Global(M, kScratchName, rng.next());

        BasicBlock *Body = SplitBlock(Head, SplitPt);
        Instruction *HeadTerm = Head->getTerminator();
        Builder B(HeadTerm);
        Value *Pred = buildPredicate(B, F, Context, rng);

        BasicBlock *Decoy =
            BasicBlock::Create(F.getContext(), kDecoyPrefix, &F, Body);
        buildDecoyBlock(Decoy, Body, Scratch, params, rng);

        B.CreateCondBr(Pred, Body, Decoy);
        HeadTerm->eraseFromParent();
        Changed = true;
        ++Count;
    }

    return Changed;
}

PreservedAnalyses ExternalOpaquePredicatesPass::run(
    Function &F, FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return externalOpaquePredicatesFunction(F, params_, rng)
               ? PreservedAnalyses::none()
               : PreservedAnalyses::all();
}

} // namespace morok::passes
