// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/InterproceduralFsm.hpp — split flattened FSM transitions across
// helper functions.
//
// Rewrites stores to flattened dispatcher state variables so the next-state
// value is returned by mutually-recursive module helpers.  The original function
// keeps the dispatcher skeleton, but transition recovery now requires
// interprocedural reasoning through args, returns, and a shared volatile state
// slot.

#ifndef MOROK_PASSES_INTERPROCEDURAL_FSM_HPP
#define MOROK_PASSES_INTERPROCEDURAL_FSM_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
class Module;
} // namespace llvm

namespace morok::passes {

struct InterproceduralFsmParams {
    std::uint32_t probability = 100; ///< per state-store chance, 0..100
    std::uint32_t max_sites = 64;    ///< maximum wrapped transition stores
    std::uint32_t max_terms = 4;     ///< live scalar integer/FP token terms
};

/// Wrap flattened dispatcher state updates in shared interprocedural helpers.
bool interproceduralFsmSplitFunction(llvm::Function &F,
                                     const InterproceduralFsmParams &params,
                                     morok::ir::IRRandom &rng);

/// Wrap flattened dispatcher state updates across `M`.
bool interproceduralFsmSplitModule(llvm::Module &M,
                                   const InterproceduralFsmParams &params,
                                   morok::ir::IRRandom &rng);

/// New-PM module-pass wrapper for standalone use (`-passes=morok-ifsm`).
class InterproceduralFsmPass
    : public llvm::RequiredPassInfoMixin<InterproceduralFsmPass> {
public:
    explicit InterproceduralFsmPass(InterproceduralFsmParams params = {},
                                    std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M,
                                llvm::ModuleAnalysisManager &AM);

private:
    InterproceduralFsmParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_INTERPROCEDURAL_FSM_HPP
