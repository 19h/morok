// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/AdversarialFunctionMerging.hpp — call-graph confusion by
// unrelated function fusion and shared scalar operation/comparison outlining.

#ifndef MOROK_PASSES_ADVERSARIAL_FUNCTION_MERGING_HPP
#define MOROK_PASSES_ADVERSARIAL_FUNCTION_MERGING_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Module;
} // namespace llvm

namespace morok::passes {

struct AdversarialMergeParams {
    std::uint32_t probability = 100;          ///< per candidate function, 0..100
    std::uint32_t max_groups = 1;             ///< signature groups to merge
    std::uint32_t max_functions = 4;          ///< functions per dispatcher
    std::uint32_t outline_probability = 50;   ///< per eligible scalar op, 0..100
    std::uint32_t max_outlines = 8;           ///< scalar fragments to outline
};

/// Fuse unrelated same-signature functions behind hidden selector dispatchers
/// and outline selected scalar integer/floating operation/comparison fragments
/// into shared noinline helpers.
bool adversarialFunctionMergingModule(llvm::Module &M,
                                      const AdversarialMergeParams &params,
                                      morok::ir::IRRandom &rng);

/// New-PM module-pass wrapper for standalone use (`-passes=morok-afm`).
class AdversarialFunctionMergingPass
    : public llvm::RequiredPassInfoMixin<AdversarialFunctionMergingPass> {
public:
    explicit AdversarialFunctionMergingPass(AdversarialMergeParams params = {},
                                            std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M,
                                llvm::ModuleAnalysisManager &AM);

private:
    AdversarialMergeParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_ADVERSARIAL_FUNCTION_MERGING_HPP
