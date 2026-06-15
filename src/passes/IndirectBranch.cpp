// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/passes/IndirectBranch.cpp

#include "morok/passes/IndirectBranch.hpp"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

bool eligible(BranchInst *br) {
    if (!br->isConditional())
        return false;
    for (BasicBlock *succ : br->successors())
        if (succ->isEHPad() || succ->isLandingPad())
            return false;
    return true;
}

} // namespace

bool indirectBranchFunction(Function &F, const IndirParams &params,
                            ir::IRRandom &rng) {
    Module &M = *F.getParent();
    LLVMContext &ctx = F.getContext();
    auto *ptrTy = PointerType::getUnqual(ctx);
    auto *i64 = Type::getInt64Ty(ctx);

    std::vector<BranchInst *> targets;
    for (BasicBlock &bb : F)
        if (auto *br = dyn_cast<BranchInst>(bb.getTerminator()))
            if (eligible(br))
                targets.push_back(br);

    bool changed = false;
    for (BranchInst *br : targets) {
        if (!rng.chance(params.probability))
            continue;

        BasicBlock *t = br->getSuccessor(0);
        BasicBlock *f = br->getSuccessor(1);
        const bool keyBit = (rng.next() & 1) != 0;

        // Table order is permuted by the key; the index is un-permuted with the
        // same key so table[idx] always resolves to the correct block.
        Constant *addrT = BlockAddress::get(&F, t);
        Constant *addrF = BlockAddress::get(&F, f);
        Constant *entries[2] = {keyBit ? addrF : addrT, keyBit ? addrT : addrF};
        auto *arrTy = ArrayType::get(ptrTy, 2);
        auto *table = new GlobalVariable(
            M, arrTy, /*isConstant=*/true, GlobalValue::PrivateLinkage,
            ConstantArray::get(arrTy, entries), "morok.ibtable");

        IRBuilder<> B(br);
        // idx = (cond ? 0 : 1) XOR keyBit
        Value *idx =
            B.CreateSelect(br->getCondition(), ConstantInt::get(i64, 0),
                           ConstantInt::get(i64, 1));
        idx = B.CreateXor(idx, ConstantInt::get(i64, keyBit ? 1 : 0));
        Value *slot =
            B.CreateInBoundsGEP(arrTy, table, {ConstantInt::get(i64, 0), idx});
        Value *dest = B.CreateLoad(ptrTy, slot);

        auto *ib = B.CreateIndirectBr(dest, 2);
        ib->addDestination(t);
        ib->addDestination(f);
        br->eraseFromParent();
        changed = true;
    }
    return changed;
}

PreservedAnalyses IndirectBranchPass::run(Function &F,
                                          FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return indirectBranchFunction(F, params_, rng) ? PreservedAnalyses::none()
                                                   : PreservedAnalyses::all();
}

} // namespace morok::passes
