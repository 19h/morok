// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/Flattening.hpp — control-flow flattening.
//
// Collapses a function's CFG into a single dispatch loop: a switch on a state
// variable selects the next original block, and each block, instead of
// branching to its successor, writes the successor's state id and returns to
// the dispatcher.  SSA values that crossed blocks are first demoted to stack
// (morok/ir/Reg2Mem.hpp), so the rewiring is sound.  State ids are randomised.

#ifndef MOROK_PASSES_FLATTENING_HPP
#define MOROK_PASSES_FLATTENING_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

/// Flatten `F`'s control flow.  Returns true if the function was flattened
/// (functions with fewer than two blocks or containing EH/indirect terminators
/// are skipped and return false).
bool flattenFunction(llvm::Function &F, morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-flatten`).
class FlatteningPass : public llvm::RequiredPassInfoMixin<FlatteningPass> {
public:
    explicit FlatteningPass(std::uint64_t seed = 0x1337)
        : engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);

private:
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_FLATTENING_HPP
