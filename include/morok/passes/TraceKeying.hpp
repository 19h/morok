// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/TraceKeying.hpp — execution-trace keyed guards.

#ifndef MOROK_PASSES_TRACE_KEYING_HPP
#define MOROK_PASSES_TRACE_KEYING_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct TraceKeyParams {
    std::uint32_t probability = 20; ///< per-block chance, 0..100
    std::uint32_t max_blocks = 8;   ///< per-function guarded block cap
};

/// Fold selected CFG edges into a rolling trace accumulator and guard blocks.
bool traceKeyFunction(llvm::Function &F, const TraceKeyParams &params,
                      morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-tracekey`).
class TraceKeyingPass : public llvm::PassInfoMixin<TraceKeyingPass> {
public:
    explicit TraceKeyingPass(TraceKeyParams params = {},
                             std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    TraceKeyParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_TRACE_KEYING_HPP
