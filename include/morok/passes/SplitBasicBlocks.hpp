// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
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
    /// Clobber a small pool of decoy stack slots with volatile traffic at each
    /// split boundary, so stack-frame/spill analysis sees spurious slots and
    /// data movement.  Semantics-preserving (the slots are never meaningfully
    /// read); off by default.
    bool stack_confusion = false;
};

/// Split eligible blocks of `F`.  Returns true if any block was split.
bool splitBlocksFunction(llvm::Function &F, const SplitParams &params,
                         morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-split`).
class SplitBasicBlocksPass : public llvm::RequiredPassInfoMixin<SplitBasicBlocksPass> {
public:
    explicit SplitBasicBlocksPass(SplitParams params = {},
                                  std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);

private:
    SplitParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_SPLIT_BASIC_BLOCKS_HPP
