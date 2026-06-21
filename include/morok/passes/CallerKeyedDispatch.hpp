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
    std::uint32_t probability = 100; ///< per direct call-site chance, 0..100
    std::uint32_t max_calls = 4096;  ///< transformed direct call-site cap
    std::uint32_t region_bytes = 16; ///< live code bytes hashed per site
    /// Number of distinct callee-saved carrier registers to rotate the indirect
    /// dispatch through (1 = the single legacy `morok.ckd.dispatch` / `br x19`).
    /// Higher values spread sites across per-register dispatchers
    /// (`morok.ckd.dispatch.x21`, ...) so the final indirect branch differs per
    /// site and the call ABI looks bespoke.  Clamped to the per-arch pool.
    std::uint32_t carriers = 1;
    /// Sealed-release mode.  When true, the startup constructor never
    /// recomputes the encoded target from live code bytes: the post-link sealer
    /// is the sole source of truth, and an unsealed (or downgrade-reset) seal
    /// slot poisons the target instead of self-sealing the live bytes. Defaults
    /// false so unsealed dev/differential builds keep the self-recovering
    /// fallback.  Only enable it for builds guaranteed to be post-link sealed
    /// (#21).
    bool seal_required = false;
};

/// Collapse eligible direct internal calls through one native dispatcher.  The
/// carried target is sealed at startup as a dispatcher-relative delta keyed by
/// a volatile hash over the call site's own native bytes.  Each execution still
/// recomputes that live hash; the cache stores only the encoded target value so
/// warmed sites do not bypass caller-byte tamper response.
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
