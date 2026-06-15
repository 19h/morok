// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/passes/ChaosStateMachine.hpp — chaos-driven control-flow flattening.
//
// Like flattening, but the dispatcher state is advanced through the logistic
// map: each block computes next = step(current) XOR correction(i, j), where the
// correction is a compile-time constant chosen so the XOR telescopes to the
// successor's state id (see morok/core/LogisticMap.hpp).  An analyst must model
// the chaotic recurrence to follow the control flow.

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

/// Apply the chaos state machine to `F`.  Returns true if it was flattened.
bool chaosStateMachineFunction(llvm::Function &F, morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-csm`).
class ChaosStateMachinePass
    : public llvm::PassInfoMixin<ChaosStateMachinePass> {
public:
    explicit ChaosStateMachinePass(std::uint64_t seed = 0x1337)
        : engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_CHAOS_STATE_MACHINE_HPP
