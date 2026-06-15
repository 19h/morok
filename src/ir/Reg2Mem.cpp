// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/ir/Reg2Mem.cpp

#include "morok/ir/Reg2Mem.hpp"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Transforms/Utils/Local.h"

#include <vector>

using namespace llvm;

namespace morok::ir {

namespace {

// A value "escapes" its block if it is used in another block or by a PHI.
bool valueEscapes(const Instruction &inst) {
    const BasicBlock *bb = inst.getParent();
    for (const User *u : inst.users()) {
        const auto *user = cast<Instruction>(u);
        if (user->getParent() != bb || isa<PHINode>(user))
            return true;
    }
    return false;
}

} // namespace

void demoteToStack(Function &F) {
    if (F.isDeclaration() || F.empty())
        return;

    BasicBlock &entry = F.getEntryBlock();
    BasicBlock::iterator allocaPt = entry.begin();
    while (allocaPt != entry.end() && isa<AllocaInst>(*allocaPt))
        ++allocaPt;
    if (allocaPt == entry.end())
        return; // pathological; nothing to anchor allocas before

    // Repeat until a fixed point: demoting can expose new escaping values.
    for (;;) {
        std::vector<PHINode *> phis;
        std::vector<Instruction *> regs;
        for (BasicBlock &bb : F)
            for (Instruction &inst : bb) {
                if (auto *phi = dyn_cast<PHINode>(&inst)) {
                    phis.push_back(phi);
                    continue;
                }
                const bool isEntryAlloca =
                    isa<AllocaInst>(&inst) && inst.getParent() == &entry;
                if (!isEntryAlloca &&
                    (valueEscapes(inst) || inst.isUsedOutsideOfBlock(&bb)))
                    regs.push_back(&inst);
            }

        if (regs.empty() && phis.empty())
            break;

        for (Instruction *inst : regs)
            DemoteRegToStack(*inst, false, allocaPt);
        for (PHINode *phi : phis)
            DemotePHIToStack(phi, allocaPt);
    }
}

} // namespace morok::ir
