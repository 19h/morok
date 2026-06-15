// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/passes/SplitBasicBlocks.cpp
//
// Walks down each original block, repeatedly cleaving its tail into a fresh
// block at a random instruction boundary.  Only unconditional fall-through
// edges are introduced, so behaviour is unchanged by construction; blocks
// containing PHIs are split only after the PHIs, and EH pads are skipped.

#include "morok/passes/SplitBasicBlocks.hpp"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <iterator>
#include <vector>

using namespace llvm;

namespace morok::passes {

bool splitBlocksFunction(Function &F, const SplitParams &params,
                         ir::IRRandom &rng) {
    if (params.splits == 0)
        return false;

    // Snapshot the original blocks; we only split each once into `splits`
    // pieces.
    std::vector<BasicBlock *> originals;
    for (BasicBlock &bb : F)
        originals.push_back(&bb);

    bool changed = false;
    for (BasicBlock *bb : originals) {
        if (bb->isEHPad() || bb->isLandingPad())
            continue;

        // `cur` is the block whose tail we keep cleaving off.
        BasicBlock *cur = bb;
        for (std::uint32_t i = 0; i < params.splits; ++i) {
            // Candidate cut points: non-PHI instructions strictly between the
            // first non-PHI instruction and the terminator (so both halves are
            // non-empty and the head keeps at least one real instruction).
            BasicBlock::iterator firstNonPhi = cur->getFirstNonPHIIt();
            if (firstNonPhi == cur->end())
                break;
            std::vector<BasicBlock::iterator> points;
            for (BasicBlock::iterator it = std::next(firstNonPhi);
                 it != cur->end() && !it->isTerminator(); ++it)
                points.push_back(it);
            if (points.empty())
                break;

            BasicBlock::iterator cut =
                points[rng.range(static_cast<std::uint32_t>(points.size()))];
            BasicBlock *tail = SplitBlock(cur, cut);
            changed = true;
            cur = tail; // keep splitting the remaining tail
        }
    }
    return changed;
}

PreservedAnalyses SplitBasicBlocksPass::run(Function &F,
                                            FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return splitBlocksFunction(F, params_, rng) ? PreservedAnalyses::none()
                                                : PreservedAnalyses::all();
}

} // namespace morok::passes
