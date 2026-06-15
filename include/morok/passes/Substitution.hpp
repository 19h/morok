// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/passes/Substitution.hpp — instruction substitution.
//
// Replaces integer binary operators with equivalent expression trees drawn from
// the verified catalog in morok/core/SubstitutionIdentities.hpp.  The math is
// proven there; this pass only emits matching IR.  The transformation is
// exposed both as a free function (for direct testing and for the scheduler to
// drive with per-function parameters) and as a New-PM pass wrapper.

#ifndef MOROK_PASSES_SUBSTITUTION_HPP
#define MOROK_PASSES_SUBSTITUTION_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct SubstitutionParams {
    std::uint32_t probability = 50; ///< per-instruction chance, 0..100
    std::uint32_t iterations = 1;   ///< sweeps over the function (>=1)
};

/// Apply substitution to `F`.  Returns true if any instruction was replaced.
bool substituteFunction(llvm::Function &F, const SubstitutionParams &params,
                        morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-substitution`).
/// Owns a private engine seeded from the given seed for reproducibility.
class SubstitutionPass : public llvm::PassInfoMixin<SubstitutionPass> {
public:
    explicit SubstitutionPass(SubstitutionParams params = {},
                              std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    SubstitutionParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_SUBSTITUTION_HPP
