// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/passes/BogusControlFlow.hpp — opaque-predicate bogus control flow.
//
// Guards each eligible block with an opaque-always-true predicate whose false
// edge leads to a never-executed junk block.  The predicate is derived from a
// volatile load so the optimizer cannot fold it away, and the construction adds
// no PHI obligations, so behaviour is preserved by construction.

#ifndef MOROK_PASSES_BOGUS_CONTROL_FLOW_HPP
#define MOROK_PASSES_BOGUS_CONTROL_FLOW_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct BcfParams {
    std::uint32_t probability = 60; ///< per-block chance, 0..100
    std::uint32_t iterations = 1;   ///< sweeps over the function (>=1)
};

/// Apply bogus control flow to `F`.  Returns true if anything changed.
bool bogusControlFlowFunction(llvm::Function &F, const BcfParams &params,
                              morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-bcf`).
class BogusControlFlowPass : public llvm::PassInfoMixin<BogusControlFlowPass> {
public:
    explicit BogusControlFlowPass(BcfParams params = {},
                                  std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    BcfParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_BOGUS_CONTROL_FLOW_HPP
