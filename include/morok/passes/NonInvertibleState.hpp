// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/NonInvertibleState.hpp — non-invertible next-state flattening.
//
// Builds a flattened dispatcher where logical successor ids are never stored
// directly.  Each transition computes a keyed lossy hash of the selected logical
// successor after fusing in volatile-neutralized live program data.  The switch
// cases contain only encoded states, so a de-flattener cannot recover edges by
// matching plaintext state constants.

#ifndef MOROK_PASSES_NON_INVERTIBLE_STATE_HPP
#define MOROK_PASSES_NON_INVERTIBLE_STATE_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct NonInvertibleStateParams {
    std::uint32_t max_terms = 4; ///< live scalar integer/FP values mixed/block
    std::uint32_t rounds = 3;    ///< lossy hash rounds, clamped to at least 1
};

/// Apply non-invertible next-state flattening to `F`.
bool nonInvertibleStateFunction(llvm::Function &F,
                                const NonInvertibleStateParams &params,
                                morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-nistate`).
class NonInvertibleStatePass
    : public llvm::RequiredPassInfoMixin<NonInvertibleStatePass> {
public:
    explicit NonInvertibleStatePass(NonInvertibleStateParams params = {},
                                    std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);

private:
    NonInvertibleStateParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_NON_INVERTIBLE_STATE_HPP
