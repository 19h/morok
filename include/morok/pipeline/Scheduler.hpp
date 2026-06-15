// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/pipeline/Scheduler.hpp — the master obfuscation pass.
//
// Drives the configured transformations over a module: it seeds the shared
// PRNG, materializes source annotations, then for each function resolves the
// effective configuration (preset ← file ← policy) and runs each enabled pass,
// honouring per-function annotation overrides.

#ifndef MOROK_PIPELINE_SCHEDULER_HPP
#define MOROK_PIPELINE_SCHEDULER_HPP

#include "morok/config/Resolver.hpp"

#include "llvm/IR/PassManager.h"

namespace morok::pipeline {

/// Module pass that applies the whole Morok obfuscation pipeline.
class MorokPass : public llvm::PassInfoMixin<MorokPass> {
public:
    explicit MorokPass(config::Config config) : config_(std::move(config)) {}

    llvm::PreservedAnalyses run(llvm::Module &M,
                                llvm::ModuleAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    config::Config config_;
};

} // namespace morok::pipeline

#endif // MOROK_PIPELINE_SCHEDULER_HPP
