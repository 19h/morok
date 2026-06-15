// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/PerBuildPolymorphism.cpp
//
// Final per-build polymorphism layer.  Most Morok passes already draw from the
// shared seeded PRNG; this pass adds an explicit final diversification surface:
// seed-dependent function order, non-entry basic-block order, and neutral
// volatile return anchors whose global initializers differ across seeds.

#include "morok/passes/PerBuildPolymorphism.hpp"

#include "morok/ir/InstUtil.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/ModRef.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

using Builder = IRBuilder<NoFolder>;

bool generatedFunction(const Function &F) {
    return F.getName().starts_with("morok.poly.");
}

bool hasExistingPoly(const Module &M) {
    for (const GlobalVariable &GV : M.globals())
        if (GV.getName().starts_with("morok.poly."))
            return true;
    return false;
}

void relaxFunctionEffects(Function &F) {
    F.setMemoryEffects(MemoryEffects::unknown());
    F.removeFnAttr(Attribute::NoSync);
    F.removeFnAttr(Attribute::ReadNone);
    F.removeFnAttr(Attribute::ReadOnly);
    F.removeFnAttr(Attribute::WillReturn);
}

void invalidateCallerEffects(Function &F) {
    SmallVector<Function *, 8> Worklist;
    SmallPtrSet<Function *, 16> Seen;
    Worklist.push_back(&F);
    Seen.insert(&F);

    while (!Worklist.empty()) {
        Function *Current = Worklist.pop_back_val();
        for (User *U : Current->users()) {
            auto *CB = dyn_cast<CallBase>(U);
            if (!CB)
                continue;
            CB->setMemoryEffects(MemoryEffects::unknown());
            CB->removeFnAttr(Attribute::NoSync);

            Function *Caller = CB->getFunction();
            if (!Caller || !Seen.insert(Caller).second)
                continue;
            relaxFunctionEffects(*Caller);
            Worklist.push_back(Caller);
        }
    }
}

template <class T> bool sameOrder(ArrayRef<T *> A, ArrayRef<T *> B) {
    if (A.size() != B.size())
        return false;
    for (std::size_t I = 0; I != A.size(); ++I)
        if (A[I] != B[I])
            return false;
    return true;
}

template <class T> void shuffleAndForceChange(std::vector<T *> &Items,
                                              ir::IRRandom &Rng) {
    if (Items.size() < 2)
        return;
    const std::vector<T *> Original = Items;
    for (std::size_t I = Items.size(); I > 1; --I) {
        const std::size_t J = Rng.range(static_cast<std::uint32_t>(I));
        std::swap(Items[I - 1], Items[J]);
    }
    if (sameOrder<T>(ArrayRef<T *>(Items), ArrayRef<T *>(Original)))
        std::rotate(Items.begin(), Items.begin() + 1, Items.end());
}

bool shuffleFunctionOrder(Module &M, ir::IRRandom &Rng) {
    std::vector<Function *> Functions;
    for (Function &F : M)
        if (!F.isDeclaration())
            Functions.push_back(&F);
    if (Functions.size() < 2)
        return false;
    const std::vector<Function *> Original = Functions;
    shuffleAndForceChange(Functions, Rng);
    if (sameOrder<Function>(ArrayRef<Function *>(Functions),
                            ArrayRef<Function *>(Original)))
        return false;

    auto &List = M.getFunctionList();
    for (Function *F : Functions)
        List.splice(List.end(), List, F->getIterator());
    return true;
}

bool shuffleBlockOrder(Function &F, ir::IRRandom &Rng) {
    if (F.empty())
        return false;
    std::vector<BasicBlock *> Blocks;
    for (BasicBlock &BB : F)
        if (&BB != &F.getEntryBlock())
            Blocks.push_back(&BB);
    if (Blocks.size() < 2)
        return false;
    const std::vector<BasicBlock *> Original = Blocks;
    shuffleAndForceChange(Blocks, Rng);
    if (sameOrder<BasicBlock>(ArrayRef<BasicBlock *>(Blocks),
                              ArrayRef<BasicBlock *>(Original)))
        return false;

    BasicBlock *Prev = &F.getEntryBlock();
    for (BasicBlock *BB : Blocks) {
        BB->moveAfter(Prev);
        Prev = BB;
    }
    return true;
}

bool eligibleReturn(ReturnInst *RI) {
    if (!RI || RI->getNumOperands() == 0)
        return false;
    if (ir::isMustTailReturn(*RI))
        return false;
    auto *Ty = dyn_cast<IntegerType>(RI->getOperand(0)->getType());
    return Ty && Ty->getBitWidth() <= 64;
}

GlobalVariable *createSalt(Module &M, Function &F, std::uint64_t Salt) {
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *GV = new GlobalVariable(
        M, I64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, Salt),
        (Twine("morok.poly.salt.") + F.getName()).str());
    GV->setAlignment(Align(8));
    GV->setDSOLocal(true);
    return GV;
}

Value *castZero(Builder &B, Value *Zero64, IntegerType *Ty) {
    auto *I64 = B.getInt64Ty();
    if (Ty == I64)
        return Zero64;
    return B.CreateTrunc(Zero64, Ty, "morok.poly.zero");
}

void anchorReturn(Module &M, ReturnInst &RI, ir::IRRandom &Rng) {
    Function &F = *RI.getFunction();
    auto *Ty = cast<IntegerType>(RI.getOperand(0)->getType());
    GlobalVariable *Salt = createSalt(M, F, Rng.next());

    Builder B(&RI);
    auto *I64 = B.getInt64Ty();
    auto *A = B.CreateLoad(I64, Salt, "morok.poly.salt.a");
    A->setVolatile(true);
    A->setAlignment(Align(8));
    auto *Bv = B.CreateLoad(I64, Salt, "morok.poly.salt.b");
    Bv->setVolatile(true);
    Bv->setAlignment(Align(8));
    Value *Zero64 = B.CreateXor(A, Bv, "morok.poly.zero64");
    Value *Zero = castZero(B, Zero64, Ty);
    RI.setOperand(0, B.CreateXor(RI.getOperand(0), Zero, "morok.poly.value"));
    relaxFunctionEffects(F);
    invalidateCallerEffects(F);
}

bool addAnchors(Module &M, const PerBuildPolymorphismParams &Params,
                ir::IRRandom &Rng) {
    if (Params.anchor_probability == 0 || Params.max_anchors == 0)
        return false;

    std::vector<ReturnInst *> Returns;
    for (Function &F : M) {
        if (F.isDeclaration() || generatedFunction(F))
            continue;
        for (BasicBlock &BB : F)
            if (eligibleReturn(dyn_cast<ReturnInst>(BB.getTerminator())))
                Returns.push_back(cast<ReturnInst>(BB.getTerminator()));
    }
    if (Returns.empty())
        return false;
    shuffleAndForceChange(Returns, Rng);

    bool Changed = false;
    std::uint32_t Count = 0;
    for (ReturnInst *RI : Returns) {
        if (Count >= Params.max_anchors)
            break;
        if (!Rng.chance(Params.anchor_probability))
            continue;
        anchorReturn(M, *RI, Rng);
        ++Count;
        Changed = true;
    }
    return Changed;
}

} // namespace

bool perBuildPolymorphismModule(Module &M,
                                const PerBuildPolymorphismParams &Params,
                                ir::IRRandom &Rng) {
    if (hasExistingPoly(M))
        return false;

    bool Changed = false;
    if (Params.function_order)
        Changed |= shuffleFunctionOrder(M, Rng);
    if (Params.block_order) {
        // shuffleBlockOrder only permutes blocks within a function and never
        // adds or removes functions, so iterate the module directly instead of
        // materializing a function-pointer worklist.
        for (Function &F : M)
            if (!F.isDeclaration())
                Changed |= shuffleBlockOrder(F, Rng);
    }
    Changed |= addAnchors(M, Params, Rng);
    return Changed;
}

PreservedAnalyses
PerBuildPolymorphismPass::run(Module &M, ModuleAnalysisManager &) {
    ir::IRRandom Rng(engine_);
    return perBuildPolymorphismModule(M, params_, Rng)
               ? PreservedAnalyses::none()
               : PreservedAnalyses::all();
}

} // namespace morok::passes
