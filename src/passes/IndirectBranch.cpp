// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/IndirectBranch.cpp

#include "morok/passes/IndirectBranch.hpp"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <algorithm>
#include <cstdint>
#include <utility>

using namespace llvm;

namespace morok::passes {

namespace {

struct Target {
    Instruction *term = nullptr;
    SmallVector<BasicBlock *, 4> successors;
};

bool addUniqueSuccessor(SmallVectorImpl<BasicBlock *> &successors,
                        BasicBlock *succ) {
    if (succ->isEHPad() || succ->isLandingPad())
        return false;
    if (std::find(successors.begin(), successors.end(), succ) ==
        successors.end())
        successors.push_back(succ);
    return true;
}

bool collectEligibleSuccessors(Instruction *term,
                               SmallVectorImpl<BasicBlock *> &successors) {
    if (auto *br = dyn_cast<BranchInst>(term)) {
        if (!br->isConditional())
            return false;
        for (BasicBlock *succ : br->successors())
            if (!addUniqueSuccessor(successors, succ))
                return false;
        return successors.size() >= 2;
    }

    if (auto *sw = dyn_cast<SwitchInst>(term)) {
        if (!addUniqueSuccessor(successors, sw->getDefaultDest()))
            return false;
        for (auto &c : sw->cases())
            if (!addUniqueSuccessor(successors, c.getCaseSuccessor()))
                return false;
        return successors.size() >= 2;
    }

    return false;
}

void shuffle(SmallVectorImpl<BasicBlock *> &blocks, ir::IRRandom &rng) {
    for (std::size_t i = blocks.size(); i > 1; --i) {
        const std::size_t j = rng.range(static_cast<std::uint32_t>(i));
        std::swap(blocks[i - 1], blocks[j]);
    }
}

DenseMap<BasicBlock *, std::uint64_t>
slotIds(ArrayRef<BasicBlock *> tableOrder) {
    DenseMap<BasicBlock *, std::uint64_t> ids;
    for (std::uint64_t i = 0; i < tableOrder.size(); ++i)
        ids[tableOrder[i]] = i;
    return ids;
}

Value *branchIndex(IRBuilder<> &B, BranchInst *br,
                   const DenseMap<BasicBlock *, std::uint64_t> &ids) {
    auto *i64 = Type::getInt64Ty(B.getContext());
    return B.CreateSelect(
        br->getCondition(),
        ConstantInt::get(i64, ids.lookup(br->getSuccessor(0))),
        ConstantInt::get(i64, ids.lookup(br->getSuccessor(1))),
        "morok.indbr.index");
}

Value *switchIndex(IRBuilder<> &B, SwitchInst *sw,
                   const DenseMap<BasicBlock *, std::uint64_t> &ids) {
    auto *i64 = Type::getInt64Ty(B.getContext());
    Value *idx = ConstantInt::get(i64, ids.lookup(sw->getDefaultDest()));
    for (auto &c : sw->cases()) {
        Value *match = B.CreateICmpEQ(sw->getCondition(), c.getCaseValue(),
                                      "morok.indbr.case");
        idx = B.CreateSelect(
            match, ConstantInt::get(i64, ids.lookup(c.getCaseSuccessor())), idx,
            "morok.indbr.index");
    }
    return idx;
}

} // namespace

bool indirectBranchFunction(Function &F, const IndirParams &params,
                            ir::IRRandom &rng) {
    Module &M = *F.getParent();
    LLVMContext &ctx = F.getContext();
    auto *ptrTy = PointerType::getUnqual(ctx);
    auto *i64 = Type::getInt64Ty(ctx);

    SmallVector<Target, 16> targets;
    for (BasicBlock &bb : F) {
        Target target;
        target.term = bb.getTerminator();
        if (collectEligibleSuccessors(target.term, target.successors))
            targets.push_back(std::move(target));
    }

    bool changed = false;
    for (Target &target : targets) {
        if (!rng.chance(params.probability))
            continue;

        SmallVector<BasicBlock *, 4> tableOrder = target.successors;
        shuffle(tableOrder, rng);
        DenseMap<BasicBlock *, std::uint64_t> ids = slotIds(tableOrder);

        SmallVector<Constant *, 4> entries;
        entries.reserve(tableOrder.size());
        for (BasicBlock *succ : tableOrder)
            entries.push_back(BlockAddress::get(&F, succ));

        auto *arrTy = ArrayType::get(ptrTy, tableOrder.size());
        auto *table = new GlobalVariable(
            M, arrTy, /*isConstant=*/true, GlobalValue::PrivateLinkage,
            ConstantArray::get(arrTy, entries), "morok.ibtable");

        IRBuilder<> B(target.term);
        Value *idx = nullptr;
        if (auto *br = dyn_cast<BranchInst>(target.term))
            idx = branchIndex(B, br, ids);
        else
            idx = switchIndex(B, cast<SwitchInst>(target.term), ids);

        Value *slot = B.CreateInBoundsGEP(
            arrTy, table, {ConstantInt::get(i64, 0), idx}, "morok.indbr.slot");
        Value *dest = B.CreateLoad(ptrTy, slot, "morok.indbr.target");

        auto *ib =
            B.CreateIndirectBr(dest, static_cast<unsigned>(tableOrder.size()));
        for (BasicBlock *succ : tableOrder)
            ib->addDestination(succ);
        target.term->eraseFromParent();
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
