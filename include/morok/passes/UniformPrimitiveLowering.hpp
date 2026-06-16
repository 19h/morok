// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/UniformPrimitiveLowering.hpp — uniform primitive lowering.
//
// Lowers selected i1..i8 operations/comparisons to encrypted table loads and
// selected branch/switch terminators to block-address table loads feeding
// indirectbr.  This IR-level layer approximates the roadmap's MOV-only-style
// uniformity without relying on target-specific MIR.

#ifndef MOROK_PASSES_UNIFORM_PRIMITIVE_LOWERING_HPP
#define MOROK_PASSES_UNIFORM_PRIMITIVE_LOWERING_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct UniformLowerParams {
    std::uint32_t op_probability = 25;     ///< i1..i8 op/cmp table chance
    std::uint32_t branch_probability = 35; ///< branch/switch lowering chance
    std::uint32_t max_tables = 4;          ///< per-function arithmetic tables
    std::uint32_t max_branches = 8;        ///< per-function branch sites
};

/// Lower selected primitive operations in `F`. Returns true if changed.
bool uniformPrimitiveLowerFunction(llvm::Function &F,
                                   const UniformLowerParams &params,
                                   morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-uniform`).
class UniformPrimitiveLoweringPass
    : public llvm::PassInfoMixin<UniformPrimitiveLoweringPass> {
public:
    explicit UniformPrimitiveLoweringPass(UniformLowerParams params = {},
                                          std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    UniformLowerParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_UNIFORM_PRIMITIVE_LOWERING_HPP
