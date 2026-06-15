// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/AdversarialSelfTuning.hpp — score-guided obfuscation search.

#ifndef MOROK_PASSES_ADVERSARIAL_SELF_TUNING_HPP
#define MOROK_PASSES_ADVERSARIAL_SELF_TUNING_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Module;
} // namespace llvm

namespace morok::passes {

struct AdversarialScore {
    std::uint64_t total = 0;
    std::uint64_t cfg_recovery = 0;
    std::uint64_t lvar_recovery = 0;
    std::uint64_t type_recovery = 0;
    std::uint64_t symbolic_pressure = 0;
    std::uint64_t diff_resistance = 0;
};

struct AdversarialTuningParams {
    std::uint32_t max_candidates = 4;       ///< candidate bundles to evaluate
    std::uint32_t max_candidate_passes = 3; ///< pass actions per candidate
    std::uint32_t score_floor = 32;         ///< minimum total-score improvement
    bool emit_marker = true;                ///< emit chosen-candidate evidence
};

/// Score the current IR with a decompiler-recovery pressure heuristic.
AdversarialScore adversarialScoreModule(const llvm::Module &M);

/// Search candidate obfuscation bundles on cloned modules, then replay only the
/// highest-scoring verified candidate on `M`.
bool adversarialSelfTuneModule(llvm::Module &M,
                               const AdversarialTuningParams &params,
                               morok::ir::IRRandom &rng);

/// New-PM module-pass wrapper for standalone use (`-passes=morok-selftune`).
class AdversarialSelfTuningPass
    : public llvm::PassInfoMixin<AdversarialSelfTuningPass> {
public:
    explicit AdversarialSelfTuningPass(AdversarialTuningParams params = {},
                                       std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M,
                                llvm::ModuleAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    AdversarialTuningParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_ADVERSARIAL_SELF_TUNING_HPP
