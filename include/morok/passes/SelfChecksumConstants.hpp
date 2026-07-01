// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/SelfChecksumConstants.hpp — checksum-fused constants.

#ifndef MOROK_PASSES_SELF_CHECKSUM_CONSTANTS_HPP
#define MOROK_PASSES_SELF_CHECKSUM_CONSTANTS_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

enum class SelfChecksumDiffCacheMode {
    Activation,
    Static,
};

struct SelfChecksumParams {
    std::uint32_t probability = 100;    ///< per eligible constant, 0..100
    std::uint32_t max_constants = 16;   ///< per-function replacement cap
    std::uint32_t region_bytes = 32;    ///< bytes hashed by the runtime stub
    /// Fail-closed-on-unsealed (#106): when set, an unsealed code_size slot folds
    /// a nonzero corruption into the diff so reconstructed constants/returns are
    /// garbage and the never-sealed binary cannot run.  Sealed builds unaffected.
    bool fail_closed_on_unsealed = false;
    SelfChecksumDiffCacheMode diff_cache =
        SelfChecksumDiffCacheMode::Activation; ///< helper diff reuse policy
};

/// Fuse selected scalar constant operands, including PHI incoming values,
/// branch/switch conditions, and store values, with a runtime checksum diff.
/// The valid checksum reconstructs the original constant; tampering silently
/// corrupts data flow.
bool selfChecksumConstantsFunction(llvm::Function &F,
                                   const SelfChecksumParams &params,
                                   morok::ir::IRRandom &rng);

/// M4: bind reused leaf helpers to the anti-debug seal.  Folds (seal ^ S0) into
/// the integer return value of internal, non-main helper functions in the
/// validation cluster that are NOT already self-checksum-poisoned (to avoid an
/// XOR double-fold).  On a clean run seal==S0 so the fold is identity; under a
/// tripped detector (a keygen running under DYLD injection, etc.) the helper
/// returns garbage, defeating direct helper reuse.  Must run AFTER the
/// self-checksum pass so the seal exists and poisoned helpers can be detected.
bool bindLeafHelpersToSeal(llvm::Module &M, morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-selfcheck`).
class SelfChecksumConstantsPass
    : public llvm::PassInfoMixin<SelfChecksumConstantsPass> {
public:
    explicit SelfChecksumConstantsPass(SelfChecksumParams params = {},
                                       std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    SelfChecksumParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_SELF_CHECKSUM_CONSTANTS_HPP
