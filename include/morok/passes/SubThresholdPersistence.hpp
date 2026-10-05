// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/SubThresholdPersistence.hpp — optimizer-threshold persistence.
//
// Wraps selected scalar binary operations in small volatile-seeded neutral
// expression webs.  The constructs are intentionally bounded by max_terms so
// they sit below common simplifier thresholds while still resisting trivial
// InstCombine/GVN folding.

#ifndef MOROK_PASSES_SUB_THRESHOLD_PERSISTENCE_HPP
#define MOROK_PASSES_SUB_THRESHOLD_PERSISTENCE_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct SubThresholdParams {
    std::uint32_t probability = 25; ///< per-instruction chance, 0..100
    std::uint32_t max_terms = 1;    ///< opaque zero terms per selected op
};

/// Add bounded opaque-neutral terms to eligible scalar ops in `F`.
/// Returns true if anything changed.
bool subThresholdPersistFunction(llvm::Function &F,
                                 const SubThresholdParams &params,
                                 morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-threshold`).
class SubThresholdPersistencePass
    : public llvm::RequiredPassInfoMixin<SubThresholdPersistencePass> {
public:
    explicit SubThresholdPersistencePass(SubThresholdParams params = {},
                                         std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);

private:
    SubThresholdParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_SUB_THRESHOLD_PERSISTENCE_HPP
