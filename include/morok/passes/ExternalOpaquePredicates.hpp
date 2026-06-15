// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/ExternalOpaquePredicates.hpp — context-derived predicates.
//
// Guards selected blocks with predicates derived from an IPO-blocked helper
// that performs volatile runtime-context reads.  The branch is true by
// construction, but it is not a pure algebraic identity and cannot be reduced
// without reasoning through side-effecting calls and memory.

#ifndef MOROK_PASSES_EXTERNAL_OPAQUE_PREDICATES_HPP
#define MOROK_PASSES_EXTERNAL_OPAQUE_PREDICATES_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct ExternalOpaqueParams {
    std::uint32_t probability = 35;    ///< per-block chance, 0..100
    std::uint32_t max_blocks = 8;      ///< per-function transformed block cap
    std::uint32_t decoy_stores = 2;    ///< volatile scratch writes in false arm
};

/// Apply external/volatile-derived opaque predicates to `F`.
bool externalOpaquePredicatesFunction(llvm::Function &F,
                                      const ExternalOpaqueParams &params,
                                      morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-extop`).
class ExternalOpaquePredicatesPass
    : public llvm::PassInfoMixin<ExternalOpaquePredicatesPass> {
public:
    explicit ExternalOpaquePredicatesPass(ExternalOpaqueParams params = {},
                                          std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    ExternalOpaqueParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_EXTERNAL_OPAQUE_PREDICATES_HPP
