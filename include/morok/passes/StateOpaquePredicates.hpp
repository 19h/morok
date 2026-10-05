// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/StateOpaquePredicates.hpp — stateful MBA opaque predicates.
//
// Guards flattened blocks with opaque-true predicates whose expression is built
// from the live dispatcher state plus MBA-style cancellation through volatile
// shadow memory.  Unlike pure algebraic predicates, the guard is stateful and
// tied to the flattened FSM, so symbolic simplifiers cannot normalize it in
// isolation.

#ifndef MOROK_PASSES_STATE_OPAQUE_PREDICATES_HPP
#define MOROK_PASSES_STATE_OPAQUE_PREDICATES_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct StateOpParams {
    std::uint32_t probability = 45; ///< per-block chance, 0..100
    std::uint32_t max_blocks = 16;  ///< per-function transformed block cap
    std::uint32_t max_terms = 4;    ///< live scalar integer/FP terms mixed into
                                    ///< token
};

/// Add stateful MBA opaque predicates to an already-flattened function.
bool stateOpaquePredicatesFunction(llvm::Function &F,
                                   const StateOpParams &params,
                                   morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-stateop`).
class StateOpaquePredicatesPass
    : public llvm::RequiredPassInfoMixin<StateOpaquePredicatesPass> {
public:
    explicit StateOpaquePredicatesPass(StateOpParams params = {},
                                       std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);

private:
    StateOpParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_STATE_OPAQUE_PREDICATES_HPP
