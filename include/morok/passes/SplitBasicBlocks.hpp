// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/passes/SplitBasicBlocks.hpp — basic-block splitting.
//
// Splits each basic block into several smaller ones at random points.  This is
// trivially semantics-preserving (it only inserts unconditional edges) but
// multiplies the number of control-flow nodes, giving later control-flow passes
// (flattening, the chaos machine) far more dispatch targets to work with.

#ifndef MOROK_PASSES_SPLIT_BASIC_BLOCKS_HPP
#define MOROK_PASSES_SPLIT_BASIC_BLOCKS_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct SplitParams {
    std::uint32_t splits = 3; ///< desired extra cuts per eligible block
};

/// Split eligible blocks of `F`.  Returns true if any block was split.
bool splitBlocksFunction(llvm::Function &F, const SplitParams &params,
                         morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-split`).
class SplitBasicBlocksPass : public llvm::PassInfoMixin<SplitBasicBlocksPass> {
public:
    explicit SplitBasicBlocksPass(SplitParams params = {},
                                  std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    SplitParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_SPLIT_BASIC_BLOCKS_HPP
