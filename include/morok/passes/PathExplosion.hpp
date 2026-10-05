// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/PathExplosion.hpp — anti-DSE decoy path injection.
//
// Inserts opaque-guarded decoy paths containing integer/pointer/FP
// input-derived bounded loops, per-iteration volatile stores, and computed
// indirect jumps. Runtime execution takes the original edge, while static and
// symbolic engines must account for a plausible, input-dependent alternate
// execution region.

#ifndef MOROK_PASSES_PATH_EXPLOSION_HPP
#define MOROK_PASSES_PATH_EXPLOSION_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct PathExplosionParams {
    std::uint32_t probability = 25;    ///< per-block chance, 0..100
    std::uint32_t max_blocks = 4;      ///< per-function transformed block cap
    std::uint32_t max_iterations = 16; ///< maximum decoy loop trip count
};

/// Inject anti-DSE decoy paths into `F`. Returns true if anything changed.
bool pathExplosionFunction(llvm::Function &F, const PathExplosionParams &params,
                           morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-pathexplode`).
class PathExplosionPass : public llvm::RequiredPassInfoMixin<PathExplosionPass> {
public:
    explicit PathExplosionPass(PathExplosionParams params = {},
                               std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);

private:
    PathExplosionParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_PATH_EXPLOSION_HPP
