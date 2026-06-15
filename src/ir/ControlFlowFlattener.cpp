// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/ir/ControlFlowFlattener.cpp

#include "morok/ir/ControlFlowFlattener.hpp"

#include "morok/ir/Reg2Mem.hpp"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace llvm;

namespace morok::ir {

namespace {

bool isFlattenable(Function &F) {
    if (F.size() < 2)
        return false;
    for (BasicBlock &bb : F) {
        Instruction *term = bb.getTerminator();
        if (isa<InvokeInst>(term) || isa<IndirectBrInst>(term) ||
            isa<CallBrInst>(term) || isa<CatchSwitchInst>(term) ||
            isa<CatchReturnInst>(term) || isa<CleanupReturnInst>(term) ||
            isa<ResumeInst>(term))
            return false;
        if (bb.isEHPad() || bb.isLandingPad())
            return false;
    }
    return true;
}

std::uint32_t freshId(IRRandom &rng, std::unordered_set<std::uint32_t> &used) {
    std::uint32_t id = 0;
    do {
        id = static_cast<std::uint32_t>(rng.next());
    } while (id == 0 || used.count(id));
    used.insert(id);
    return id;
}

} // namespace

bool flattenControlFlow(Function &F, IRRandom &rng,
                        const NextStateFn &nextState) {
    if (!isFlattenable(F))
        return false;

    LLVMContext &ctx = F.getContext();
    auto *i32 = Type::getInt32Ty(ctx);

    std::vector<BasicBlock *> blocks;
    for (BasicBlock &bb : F)
        blocks.push_back(&bb);
    BasicBlock *entry = blocks.front();
    blocks.erase(blocks.begin());

    // The first dispatched block is the entry's actual successor (after a split
    // for multi-way entries), NOT merely the textually-next block.
    BasicBlock *firstReal = nullptr;
    if (entry->getTerminator()->getNumSuccessors() > 1) {
        firstReal = entry->splitBasicBlock(
            entry->getTerminator()->getIterator(), "fla.entry");
        blocks.insert(blocks.begin(), firstReal);
    } else {
        firstReal = entry->getTerminator()->getSuccessor(0);
    }
    if (blocks.empty())
        return false;

    std::unordered_map<BasicBlock *, std::uint32_t> idOf;
    std::unordered_set<std::uint32_t> used;
    for (BasicBlock *bb : blocks)
        idOf[bb] = freshId(rng, used);

    IRBuilder<> entryB(entry, entry->getFirstInsertionPt());
    auto *stateVar = entryB.CreateAlloca(i32, nullptr, "fla.state");

    BasicBlock *dispatch = BasicBlock::Create(ctx, "fla.dispatch", &F);
    BasicBlock *backEdge = BasicBlock::Create(ctx, "fla.backedge", &F);
    BasicBlock *defaultBB = BasicBlock::Create(ctx, "fla.default", &F);

    Instruction *entryTerm = entry->getTerminator();
    IRBuilder<> initB(entryTerm);
    initB.CreateStore(ConstantInt::get(i32, idOf[firstReal]), stateVar);
    initB.CreateBr(dispatch);
    entryTerm->eraseFromParent();

    IRBuilder<> dispB(dispatch);
    LoadInst *stateLoad = dispB.CreateLoad(i32, stateVar, "fla.cur");
    SwitchInst *sw = dispB.CreateSwitch(stateLoad, defaultBB,
                                        static_cast<unsigned>(blocks.size()));

    BranchInst::Create(dispatch, backEdge);
    BranchInst::Create(backEdge, defaultBB);

    for (BasicBlock *bb : blocks) {
        bb->moveBefore(backEdge);
        sw->addCase(ConstantInt::get(i32, idOf[bb]), bb);
    }

    for (BasicBlock *bb : blocks) {
        Instruction *term = bb->getTerminator();
        IRBuilder<> b(term);
        SuccessorIds succ;

        if (auto *br = dyn_cast<BranchInst>(term)) {
            if (br->isUnconditional()) {
                succ.defaultId = idOf[br->getSuccessor(0)];
            } else {
                succ.arms.push_back(
                    {br->getCondition(), idOf[br->getSuccessor(0)]});
                succ.defaultId = idOf[br->getSuccessor(1)];
            }
        } else if (auto *swTerm = dyn_cast<SwitchInst>(term)) {
            // Route every case through the dispatcher (no direct edges), so the
            // state stays consistent — essential for state-dependent
            // transitions.
            Value *switchCond = swTerm->getCondition();
            for (const auto &c : swTerm->cases())
                succ.arms.push_back(
                    {b.CreateICmpEQ(switchCond, c.getCaseValue()),
                     idOf[c.getCaseSuccessor()]});
            succ.defaultId = idOf[swTerm->getDefaultDest()];
        } else {
            continue; // returns / unreachable exit the dispatch loop directly
        }

        Value *next = nextState(b, stateVar, idOf[bb], succ);
        b.CreateStore(next, stateVar);
        b.CreateBr(backEdge);
        term->eraseFromParent();
    }

    demoteToStack(F);
    return true;
}

} // namespace morok::ir
