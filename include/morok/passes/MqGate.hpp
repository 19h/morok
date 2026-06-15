// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/MqGate.hpp — planted MQ opaque gates for anti-symbolic pressure.

#ifndef MOROK_PASSES_MQ_GATE_HPP
#define MOROK_PASSES_MQ_GATE_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct MqGateParams {
    std::uint32_t probability = 20; ///< per eligible branch, 0..100
    std::uint32_t vars = 24;        ///< MQ variable count
    std::uint32_t eqs = 24;         ///< quadratic equation count
    std::uint32_t density = 50;     ///< coefficient 1-probability
    std::uint32_t max_gates = 2;    ///< per-function cap
    bool fold_diff = true;          ///< emit decoy side-effect path
};

/// Insert planted MQ gates on selected input-derived conditional branches.
bool mqGateFunction(llvm::Function &F, const MqGateParams &params,
                    morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-mq`).
class MqGatePass : public llvm::PassInfoMixin<MqGatePass> {
public:
    explicit MqGatePass(MqGateParams params = {}, std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    MqGateParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_MQ_GATE_HPP
