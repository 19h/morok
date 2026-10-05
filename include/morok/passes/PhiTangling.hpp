// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/PhiTangling.hpp — SSA/PHI web tangling.
//
// Builds redundant, cross-block PHI webs around existing scalar integer/FP
// PHIs.  Each web is value-neutral but forces expression propagation and lvar
// recovery to follow duplicated edge copies, PHIs, and zero-valued cross terms.

#ifndef MOROK_PASSES_PHI_TANGLING_HPP
#define MOROK_PASSES_PHI_TANGLING_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct PhiTangleParams {
    std::uint32_t probability = 45; ///< per PHI chance, 0..100
    std::uint32_t layers = 2;       ///< redundant web layers per PHI
    std::uint32_t max_phis = 32;    ///< per-function selected PHI cap
};

/// Tangle eligible scalar integer/FP PHIs in `F`.  Returns true if any web was
/// inserted.
bool phiTangleFunction(llvm::Function &F, const PhiTangleParams &params,
                       morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-phitangle`).
class PhiTanglingPass : public llvm::RequiredPassInfoMixin<PhiTanglingPass> {
public:
    explicit PhiTanglingPass(PhiTangleParams params = {},
                             std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);

private:
    PhiTangleParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_PHI_TANGLING_HPP
