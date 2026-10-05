// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/CoherentDecoys.hpp — plausible dead alternate implementations.
//
// Adds opaque-guarded dead return arms whose bodies compute return-typed values
// from real program inputs.  Unlike junk BCF, the false path looks like a
// coherent alternate implementation, so live/dead classification cannot rely on
// obviously meaningless instructions.

#ifndef MOROK_PASSES_COHERENT_DECOYS_HPP
#define MOROK_PASSES_COHERENT_DECOYS_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct CoherentDecoyParams {
    std::uint32_t probability = 35; ///< per-return chance, 0..100
    std::uint32_t max_blocks = 4;   ///< maximum decoy return arms per function
    std::uint32_t depth = 3;        ///< live/input terms folded into decoy value
};

/// Add coherent opaque-dead return alternatives to `F`.
bool coherentDecoysFunction(llvm::Function &F,
                            const CoherentDecoyParams &params,
                            morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-decoy`).
class CoherentDecoysPass : public llvm::RequiredPassInfoMixin<CoherentDecoysPass> {
public:
    explicit CoherentDecoysPass(CoherentDecoyParams params = {},
                                std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);

private:
    CoherentDecoyParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_COHERENT_DECOYS_HPP
