// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/VectorObfuscation.hpp — scalar-to-SIMD lifting.
//
// Rewrites scalar integer/floating binary operations, comparisons, and selects
// into configurable-width vector operations whose real lane carries the
// original computation and the remaining lanes are junk, then extracts the real
// lane.  A decompiler renders the result as opaque vector intrinsics while
// per-lane semantics preserve the scalar value.

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
    std::uint32_t width = 128;      ///< target vector width in bits
    bool shuffle = false;           ///< route real lane through shufflevector
    bool lift_comparisons = true;   ///< also lift scalar integer/floating cmps
};

/// Lift eligible scalar integer/floating ops in `F` to SIMD.  Returns true if
/// changed.
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
