// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/PointerLaundering.hpp — pointer/scalar laundering.
//
// Launders memory/call/return pointer operands through ptrtoint/inttoptr and
// computed byte GEPs, and launders integer or scalar FP SSA values through
// vector/scalar bitcast chains.  The transformed value is bit-identical, but
// alias analysis and decompiler type propagation see opaque integer/pointer and
// scalar/vector boundaries.

#ifndef MOROK_PASSES_POINTER_LAUNDERING_HPP
#define MOROK_PASSES_POINTER_LAUNDERING_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct PointerLaunderParams {
    std::uint32_t pointer_probability = 80; ///< per pointer operand, 0..100
    std::uint32_t integer_probability = 35; ///< per scalar SSA value, 0..100
};

/// Launder eligible pointer operands and scalar SSA values in `F`.  Returns
/// true if anything changed.
bool pointerLaunderFunction(llvm::Function &F,
                            const PointerLaunderParams &params,
                            morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-ptrlaunder`).
class PointerLaunderingPass
    : public llvm::PassInfoMixin<PointerLaunderingPass> {
public:
    explicit PointerLaunderingPass(PointerLaunderParams params = {},
                                   std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    PointerLaunderParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_POINTER_LAUNDERING_HPP
