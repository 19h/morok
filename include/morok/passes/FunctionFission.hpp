// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/FunctionFission.hpp — split functions into smaller functions.
//
// Single-entry/single-exit regions of a function are outlined into fresh
// internal functions (via LLVM's CodeExtractor), replacing each region with a
// call.  The original function shrinks and its logic is scattered across several
// smaller callees, so the source function boundaries no longer match the binary
// and the call graph fans out.  Smaller callees also fall back under the
// per-function obfuscation/integrity budgets, so the seal-binding passes can
// reach logic that an un-split monster function would have grown past every
// budget.

#ifndef MOROK_PASSES_FUNCTION_FISSION_HPP
#define MOROK_PASSES_FUNCTION_FISSION_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
class Module;
} // namespace llvm

namespace morok::passes {

struct FunctionFissionParams {
    std::uint32_t probability = 100;      ///< per-eligible-region chance, 0..100
    std::uint32_t max_splits = 8;         ///< extracted regions per function
    std::uint32_t min_region_blocks = 2;  ///< smallest region to outline
    std::uint32_t max_region_blocks = 64; ///< largest region to outline
};

/// Outline eligible regions of `F` into fresh internal functions.  Returns true
/// if `F` changed.
bool functionFissionFunction(llvm::Function &F,
                             const FunctionFissionParams &params,
                             morok::ir::IRRandom &rng);

/// Module driver: snapshot the eligible user functions, then fission each.  The
/// outlined parts are created during the walk and are not themselves re-split.
bool functionFissionModule(llvm::Module &M,
                           const FunctionFissionParams &params,
                           morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-fission`).
class FunctionFissionPass : public llvm::PassInfoMixin<FunctionFissionPass> {
public:
    explicit FunctionFissionPass(FunctionFissionParams params = {},
                                 std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    FunctionFissionParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_FUNCTION_FISSION_HPP
