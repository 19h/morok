// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/passes/Mba.hpp — Mixed Boolean-Arithmetic substitution.
//
// Rewrites integer binary operators into MBA expressions from the verified
// catalog in morok/core/MbaIdentities.hpp, optionally layered (each sweep feeds
// the next) and salted with provably-zero noise terms.  Math proven in core;
// this pass only emits matching IR.

#ifndef MOROK_PASSES_MBA_HPP
#define MOROK_PASSES_MBA_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct MbaParams {
    std::uint32_t probability = 60; ///< per-instruction chance, 0..100
    std::uint32_t layers = 2;       ///< compounding sweeps (clamped 1..3)
    bool heuristic = true;          ///< inject zero-valued noise terms
};

/// Apply MBA substitution to `F`.  Returns true if any instruction changed.
bool mbaFunction(llvm::Function &F, const MbaParams &params,
                 morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-mba`).
class MbaPass : public llvm::PassInfoMixin<MbaPass> {
public:
    explicit MbaPass(MbaParams params = {}, std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    MbaParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_MBA_HPP
