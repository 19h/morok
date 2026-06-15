// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/UniformPrimitiveLowering.cpp
//
// IR-level uniform primitive lowering: arithmetic intent is moved into encrypted
// byte lookup tables, while direct CFG intent is moved into memory-loaded
// block-address dispatch.  The resulting function body favors loads, selects,
// GEPs, and indirectbr over recognizable arithmetic opcodes and branch opcodes.

#include "morok/passes/UniformPrimitiveLowering.hpp"

#include "morok/passes/ArithmeticTables.hpp"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"

#include <algorithm>
#include <cstdint>
#include <unordered_map>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

using Builder = IRBuilder<NoFolder>;

struct BranchSite {
    Instruction *term = nullptr;
    std::vector<BasicBlock *> successors;
};

bool generatedBlock(const BasicBlock &BB) {
    return BB.getName().starts_with("morok.");
}

void addUnique(std::vector<BasicBlock *> &Blocks, BasicBlock *BB) {
    if (BB && std::find(Blocks.begin(), Blocks.end(), BB) == Blocks.end())
        Blocks.push_back(BB);
}

std::vector<BasicBlock *> successorsOf(Instruction &Term) {
    std::vector<BasicBlock *> Succs;
    if (auto *Br = dyn_cast<BranchInst>(&Term)) {
        for (BasicBlock *Succ : Br->successors())
            addUnique(Succs, Succ);
    } else if (auto *Sw = dyn_cast<SwitchInst>(&Term)) {
        addUnique(Succs, Sw->getDefaultDest());
        for (const auto &Case : Sw->cases())
            addUnique(Succs, Case.getCaseSuccessor());
    }
    return Succs;
}

bool eligibleTerminator(Instruction &Term, BasicBlock *Entry) {
    if (!isa<BranchInst>(&Term) && !isa<SwitchInst>(&Term))
        return false;
    BasicBlock *Parent = Term.getParent();
    if (!Parent || Parent->isEHPad() || Parent->isLandingPad() ||
        generatedBlock(*Parent))
        return false;
    std::vector<BasicBlock *> Succs = successorsOf(Term);
    if (Succs.empty())
        return false;
    for (BasicBlock *Succ : Succs)
        if (!Succ || Succ == Entry || Succ->isEHPad() || Succ->isLandingPad())
            return false;
    return true;
}

void shuffleSites(std::vector<BranchSite> &Sites, ir::IRRandom &rng) {
    for (std::size_t I = Sites.size(); I > 1; --I) {
        const std::size_t J = rng.range(static_cast<std::uint32_t>(I));
        std::swap(Sites[I - 1], Sites[J]);
    }
}

GlobalVariable *createTargetTable(Function &F, ArrayRef<BasicBlock *> Targets) {
    Module &M = *F.getParent();
    LLVMContext &Ctx = F.getContext();
    auto *PtrTy = PointerType::getUnqual(Ctx);
    auto *ArrTy = ArrayType::get(PtrTy, Targets.size());

    SmallVector<Constant *, 16> Entries;
    Entries.reserve(Targets.size());
    for (BasicBlock *Target : Targets)
        Entries.push_back(BlockAddress::get(&F, Target));

    return new GlobalVariable(
        M, ArrTy, /*isConstant=*/true, GlobalValue::PrivateLinkage,
        ConstantArray::get(ArrTy, Entries), "morok.uniform.table");
}

Value *selectedIndex(Builder &B, Instruction &Term,
                     const std::unordered_map<BasicBlock *, std::uint32_t> &ID) {
    auto *I32 = B.getInt32Ty();

    if (auto *Br = dyn_cast<BranchInst>(&Term)) {
        if (Br->isUnconditional())
            return ConstantInt::get(I32, ID.at(Br->getSuccessor(0)));
        return B.CreateSelect(Br->getCondition(),
                              ConstantInt::get(I32, ID.at(Br->getSuccessor(0))),
                              ConstantInt::get(I32, ID.at(Br->getSuccessor(1))),
                              "morok.uniform.index");
    }

    auto *Sw = cast<SwitchInst>(&Term);
    Value *Index = ConstantInt::get(I32, ID.at(Sw->getDefaultDest()));
    Value *Cond = Sw->getCondition();
    for (auto It = Sw->case_begin(), End = Sw->case_end(); It != End; ++It) {
        Value *Match =
            B.CreateICmpEQ(Cond, It->getCaseValue(), "morok.uniform.case");
        Index = B.CreateSelect(
            Match, ConstantInt::get(I32, ID.at(It->getCaseSuccessor())), Index,
            "morok.uniform.index");
    }
    return Index;
}

void lowerBranchSite(BranchSite &Site, GlobalVariable *Table,
                     const std::unordered_map<BasicBlock *, std::uint32_t> &ID) {
    Instruction *Term = Site.term;
    Builder B(Term);
    auto *I32 = B.getInt32Ty();
    auto *PtrTy = PointerType::getUnqual(Term->getContext());
    auto *TableTy = cast<ArrayType>(Table->getValueType());
    Value *Index = selectedIndex(B, *Term, ID);
    Value *Slot =
        B.CreateInBoundsGEP(TableTy, Table, {ConstantInt::get(I32, 0), Index},
                            "morok.uniform.slot");
    Value *Target = B.CreateLoad(PtrTy, Slot, "morok.uniform.target");
    auto *IB = B.CreateIndirectBr(
        Target, static_cast<unsigned>(Site.successors.size()));
    for (BasicBlock *Succ : Site.successors)
        IB->addDestination(Succ);
    Term->eraseFromParent();
}

bool lowerBranches(Function &F, const UniformLowerParams &Params,
                   ir::IRRandom &rng) {
    if (Params.branch_probability == 0 || Params.max_branches == 0)
        return false;

    std::vector<BranchSite> Sites;
    BasicBlock *Entry = &F.getEntryBlock();
    for (BasicBlock &BB : F) {
        Instruction *Term = BB.getTerminator();
        if (Term && eligibleTerminator(*Term, Entry))
            Sites.push_back(BranchSite{Term, successorsOf(*Term)});
    }
    shuffleSites(Sites, rng);

    std::vector<BranchSite> Selected;
    for (BranchSite &Site : Sites) {
        if (Selected.size() >= Params.max_branches)
            break;
        if (rng.chance(Params.branch_probability))
            Selected.push_back(Site);
    }
    if (Selected.empty())
        return false;

    std::vector<BasicBlock *> Targets;
    for (const BranchSite &Site : Selected)
        for (BasicBlock *Succ : Site.successors)
            addUnique(Targets, Succ);

    std::unordered_map<BasicBlock *, std::uint32_t> ID;
    for (std::uint32_t I = 0; I < Targets.size(); ++I)
        ID[Targets[I]] = I;

    GlobalVariable *Table = createTargetTable(F, Targets);
    for (BranchSite &Site : Selected)
        lowerBranchSite(Site, Table, ID);
    return true;
}

} // namespace

bool uniformPrimitiveLowerFunction(Function &F, const UniformLowerParams &Params,
                                   ir::IRRandom &rng) {
    if (F.isDeclaration() || F.getName().starts_with("morok."))
        return false;

    bool Changed = false;
    if (Params.op_probability > 0 && Params.max_tables > 0) {
        TableArithParams TableParams;
        TableParams.probability = Params.op_probability;
        TableParams.max_tables = Params.max_tables;
        Changed |= tableArithmeticFunction(F, TableParams, rng);
    }
    Changed |= lowerBranches(F, Params, rng);
    return Changed;
}

PreservedAnalyses
UniformPrimitiveLoweringPass::run(Function &F, FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return uniformPrimitiveLowerFunction(F, params_, rng)
               ? PreservedAnalyses::none()
               : PreservedAnalyses::all();
}

} // namespace morok::passes
