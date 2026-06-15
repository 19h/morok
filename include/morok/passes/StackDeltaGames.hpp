// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/StackDeltaGames.hpp — dynamic stack-pointer perturbation.
//
// Forces backend-visible stack-pointer deltas from IR by injecting bounded
// variable-sized allocas with odd, overlapping volatile stack touches.

#ifndef MOROK_PASSES_STACK_DELTA_GAMES_HPP
#define MOROK_PASSES_STACK_DELTA_GAMES_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct StackDeltaParams {
    std::uint32_t probability = 35;       ///< per-block chance, 0..100
    std::uint32_t max_blocks = 6;         ///< per-function transformed blocks
    std::uint32_t min_bytes = 17;         ///< minimum dynamic frame size
    std::uint32_t max_extra_bytes = 64;   ///< data-derived bounded extra bytes
    std::uint32_t touches = 3;            ///< volatile overlapping stack stores
};

/// Apply dynamic stack-pointer delta games to `F`.
bool stackDeltaGamesFunction(llvm::Function &F,
                             const StackDeltaParams &params,
                             morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-stackdelta`).
class StackDeltaGamesPass : public llvm::PassInfoMixin<StackDeltaGamesPass> {
public:
    explicit StackDeltaGamesPass(StackDeltaParams params = {},
                                 std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    StackDeltaParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_STACK_DELTA_GAMES_HPP
