// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
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
            // Count candidate cut points without materializing them, then walk
            // back to the selected one.  The rng draw and the chosen iterator
            // are identical to collecting into a vector first.
            std::uint32_t count = 0;
            for (BasicBlock::iterator it = std::next(firstNonPhi);
                 it != cur->end() && !it->isTerminator(); ++it)
                ++count;
            if (count == 0)
                break;

            std::uint32_t pick = rng.range(count);
            BasicBlock::iterator cut = std::next(firstNonPhi);
            for (std::uint32_t k = 0; k < pick; ++k)
                ++cut;
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
