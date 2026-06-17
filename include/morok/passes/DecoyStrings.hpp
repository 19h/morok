// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/DecoyStrings.hpp — honeypot logging calls distributed across the module.
//
// Sprinkle decoy logging calls throughout the program.  Each call looks like a
// legitimate diagnostics/instrumentation function writing a log line — firmware
// init output, hardware calibration data, build metadata, distribution notices.
// The calls are spread across random functions (one per line of the chosen decoy
// string) and reference bogus logging infrastructure with its own volatile state
// globals, so the optimizer cannot eliminate them.

#ifndef MOROK_PASSES_DECOY_STRINGS_HPP
#define MOROK_PASSES_DECOY_STRINGS_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Module;
} // namespace llvm

namespace morok::passes {

/// Insert decoy logging calls throughout the module.
/// Returns true if any calls were inserted.
bool decoyStringsModule(llvm::Module &M, morok::ir::IRRandom &rng);

/// New-PM module-pass wrapper for standalone use (`-passes=morok-decoystr`).
class DecoyStringsPass : public llvm::PassInfoMixin<DecoyStringsPass> {
public:
    explicit DecoyStringsPass(std::uint64_t seed = 0xDE001337u)
        : engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M,
                                llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }

private:
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_DECOY_STRINGS_HPP
