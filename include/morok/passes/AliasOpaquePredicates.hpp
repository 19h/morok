// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/AliasOpaquePredicates.hpp — pointer/alias invariant predicates.
//
// Guards selected blocks with predicates derived from a maintained aliasing
// invariant over a runtime cell.  Unlike algebraic opaque predicates, the
// truth of the branch depends on memory state reached through pointer/int alias
// views, which is deliberately hostile to simple AA and decompiler recovery.

#ifndef MOROK_PASSES_ALIAS_OPAQUE_PREDICATES_HPP
#define MOROK_PASSES_ALIAS_OPAQUE_PREDICATES_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct AliasOpParams {
    std::uint32_t probability = 45; ///< per-block chance, 0..100
    std::uint32_t iterations = 1;   ///< sweeps over the function (>=1)
    std::uint32_t max_blocks = 16;  ///< per-function transformed block cap
};

/// Apply alias-invariant opaque predicates to `F`. Returns true if changed.
bool aliasOpaquePredicatesFunction(llvm::Function &F,
                                   const AliasOpParams &params,
                                   morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-aliasop`).
class AliasOpaquePredicatesPass
    : public llvm::RequiredPassInfoMixin<AliasOpaquePredicatesPass> {
public:
    explicit AliasOpaquePredicatesPass(AliasOpParams params = {},
                                       std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);

private:
    AliasOpParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_ALIAS_OPAQUE_PREDICATES_HPP
