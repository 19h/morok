// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/passes/VectorObfuscation.hpp — scalar-to-SIMD lifting.
//
// Rewrites scalar integer binary operations into 2-lane vector operations whose
// lane 0 carries the real computation (lane 1 is junk), then extracts lane 0.
// A decompiler renders the result as opaque vector intrinsics; the value is
// unchanged because per-lane semantics make lane 0 equal to the original op.

#ifndef MOROK_PASSES_VECTOR_OBFUSCATION_HPP
#define MOROK_PASSES_VECTOR_OBFUSCATION_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct VecParams {
    std::uint32_t probability = 40; ///< per-instruction chance, 0..100
};

/// Lift eligible scalar integer ops in `F` to SIMD.  Returns true if changed.
bool vectorObfuscateFunction(llvm::Function &F, const VecParams &params,
                             morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-vec`).
class VectorObfuscationPass
    : public llvm::PassInfoMixin<VectorObfuscationPass> {
public:
    explicit VectorObfuscationPass(VecParams params = {},
                                   std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    VecParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_VECTOR_OBFUSCATION_HPP
