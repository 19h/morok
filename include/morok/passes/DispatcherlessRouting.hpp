// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/DispatcherlessRouting.hpp — dispatcherless computed CFG routing.
//
// Replaces direct branch/switch terminators with per-block indirectbr dispatch.
// Target indices are computed through a shared block-address table and fused
// with previous route state plus live data, so there is no central switch or
// separable plaintext dispatcher state for de-flatteners to anchor on.

#ifndef MOROK_PASSES_DISPATCHERLESS_ROUTING_HPP
#define MOROK_PASSES_DISPATCHERLESS_ROUTING_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct DispatcherlessRoutingParams {
    std::uint32_t probability = 50; ///< per terminator chance, 0..100
    std::uint32_t max_routes = 32;  ///< per-function transformed edge sites
    std::uint32_t max_terms = 4;    ///< live scalar integer/FP token terms
};

/// Replace eligible branch/switch terminators in `F` with computed indirectbrs.
bool dispatcherlessRoutingFunction(llvm::Function &F,
                                   const DispatcherlessRoutingParams &params,
                                   morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-dispatchless`).
class DispatcherlessRoutingPass
    : public llvm::RequiredPassInfoMixin<DispatcherlessRoutingPass> {
public:
    explicit DispatcherlessRoutingPass(DispatcherlessRoutingParams params = {},
                                       std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);

private:
    DispatcherlessRoutingParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_DISPATCHERLESS_ROUTING_HPP
