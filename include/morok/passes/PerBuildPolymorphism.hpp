// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/PerBuildPolymorphism.hpp — final seed-driven layout diversity.

#ifndef MOROK_PASSES_PER_BUILD_POLYMORPHISM_HPP
#define MOROK_PASSES_PER_BUILD_POLYMORPHISM_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Module;
} // namespace llvm

namespace morok::passes {

struct PerBuildPolymorphismParams {
    bool function_order = true;              ///< shuffle defined function order
    bool block_order = true;                 ///< shuffle non-entry block order
    std::uint32_t anchor_probability = 25;   ///< per scalar return, 0..100
    std::uint32_t max_anchors = 16;          ///< semantic-zero return anchors
};

/// Apply a final seed-driven diversification layer: reorder functions and
/// non-entry blocks, and inject seed-dependent neutral volatile return anchors.
bool perBuildPolymorphismModule(llvm::Module &M,
                                const PerBuildPolymorphismParams &params,
                                morok::ir::IRRandom &rng);

/// New-PM module-pass wrapper for standalone use (`-passes=morok-polymorph`).
class PerBuildPolymorphismPass
    : public llvm::RequiredPassInfoMixin<PerBuildPolymorphismPass> {
public:
    explicit PerBuildPolymorphismPass(PerBuildPolymorphismParams params = {},
                                      std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M,
                                llvm::ModuleAnalysisManager &AM);

private:
    PerBuildPolymorphismParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_PER_BUILD_POLYMORPHISM_HPP
