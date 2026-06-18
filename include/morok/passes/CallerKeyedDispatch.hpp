// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/CallerKeyedDispatch.hpp — caller-byte-keyed call dispatch.

#ifndef MOROK_PASSES_CALLER_KEYED_DISPATCH_HPP
#define MOROK_PASSES_CALLER_KEYED_DISPATCH_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Module;
} // namespace llvm

namespace morok::passes {

struct CallerKeyedDispatchParams {
    std::uint32_t probability = 100;  ///< per direct call-site chance, 0..100
    std::uint32_t max_calls = 4096;   ///< transformed direct call-site cap
    std::uint32_t region_bytes = 16;  ///< live code bytes hashed per site
};

/// Collapse eligible direct internal calls through one native dispatcher.  The
/// carried target is sealed at startup as a dispatcher-relative delta keyed by
/// a volatile hash over the call site's own native bytes.  The first execution
/// at a site decodes and caches the target locally, keeping hot loops practical
/// while preserving the caller-keyed dispatch shape.
bool callerKeyedDispatchModule(llvm::Module &M,
                               const CallerKeyedDispatchParams &params,
                               morok::ir::IRRandom &rng);

/// New-PM module-pass wrapper for standalone use (`-passes=morok-ckd`).
class CallerKeyedDispatchPass
    : public llvm::PassInfoMixin<CallerKeyedDispatchPass> {
public:
    explicit CallerKeyedDispatchPass(CallerKeyedDispatchParams params = {},
                                     std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M,
                                llvm::ModuleAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    CallerKeyedDispatchParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_CALLER_KEYED_DISPATCH_HPP
