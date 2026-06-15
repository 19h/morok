// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/ShamirShare.hpp — threshold sharing for integer literals.

#ifndef MOROK_PASSES_SHAMIR_SHARE_HPP
#define MOROK_PASSES_SHAMIR_SHARE_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct ShamirShareParams {
    std::uint32_t probability = 30; ///< per eligible literal, 0..100
    std::uint32_t threshold = 3;    ///< k, clamped to [2, shares]
    std::uint32_t shares = 5;       ///< n, clamped to [threshold, 255]
    std::uint32_t max_secrets = 8;  ///< per-function transformed literals
};

/// Replace selected integer literals with GF(2^8) Shamir reconstruction.
bool shamirShareFunction(llvm::Function &F, const ShamirShareParams &params,
                         morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-shamir`).
class ShamirSharePass : public llvm::PassInfoMixin<ShamirSharePass> {
public:
    explicit ShamirSharePass(ShamirShareParams params = {},
                             std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    ShamirShareParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_SHAMIR_SHARE_HPP
