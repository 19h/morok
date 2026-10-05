// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/OptimizerAmplification.hpp — optimizer-amplified arithmetic.
//
// Builds branchless, input-selected lattices of equivalent arithmetic and
// comparison expressions.  The pass is intended to run early, before
// vectorization and late scalar cleanups, so the backend sees ordinary optimized
// IR rather than a runtime stub or volatile obfuscation signature.

#ifndef MOROK_PASSES_OPTIMIZER_AMPLIFICATION_HPP
#define MOROK_PASSES_OPTIMIZER_AMPLIFICATION_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct OptAmpParams {
    std::uint32_t probability = 20; ///< per-instruction chance, 0..100
    std::uint32_t max_forms = 2;    ///< selected equivalent forms per op
};

/// Add optimizer-amplified branchless equivalent forms to eligible arithmetic
/// and comparison ops.  Returns true if anything changed.
bool optimizerAmplifyFunction(llvm::Function &F, const OptAmpParams &params,
                              morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-optamp`).
class OptimizerAmplificationPass
    : public llvm::RequiredPassInfoMixin<OptimizerAmplificationPass> {
public:
    explicit OptimizerAmplificationPass(OptAmpParams params = {},
                                        std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);

private:
    OptAmpParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_OPTIMIZER_AMPLIFICATION_HPP
