// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/ChaosStateMachine.hpp — nonlinear-state control-flow flattening.
//
// Like flattening, but the dispatcher state is advanced through a nonlinear
// generator: either the legacy logistic map or a single-cycle T-function.  Each
// block computes next = step(current) XOR correction(i,j), where correction is
// chosen so the expression telescopes to the successor's state id.

#ifndef MOROK_PASSES_CHAOS_STATE_MACHINE_HPP
#define MOROK_PASSES_CHAOS_STATE_MACHINE_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

enum class CsmGenerator {
    Logistic,
    TFunction,
};

struct CsmParams {
    CsmGenerator generator = CsmGenerator::Logistic;
    std::uint64_t tf_const = 0;      ///< 0/invalid => draw valid C per function
    std::uint32_t warmup = 64;       ///< retained for logistic parity
    bool nested_dispatch = false;    ///< reserved scheduler/config knob
};

/// Apply the chaos state machine to `F`.  Returns true if it was flattened.
bool chaosStateMachineFunction(llvm::Function &F, const CsmParams &params,
                               morok::ir::IRRandom &rng);

/// Compatibility overload: logistic-map CSM.
bool chaosStateMachineFunction(llvm::Function &F, morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-csm`).
class ChaosStateMachinePass
    : public llvm::PassInfoMixin<ChaosStateMachinePass> {
public:
    explicit ChaosStateMachinePass(CsmParams params = {},
                                   std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    CsmParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_CHAOS_STATE_MACHINE_HPP
