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

struct SelfChecksumParams {
    std::uint32_t probability = 100;    ///< per eligible constant, 0..100
    std::uint32_t max_constants = 16;   ///< per-function replacement cap
    std::uint32_t region_bytes = 32;    ///< bytes hashed by the runtime stub
};

/// Fuse selected constant operands, including store values, with a runtime
/// checksum diff.  The valid checksum reconstructs the original constant;
/// tampering silently corrupts data flow.
bool selfChecksumConstantsFunction(llvm::Function &F,
                                   const SelfChecksumParams &params,
                                   morok::ir::IRRandom &rng);

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
