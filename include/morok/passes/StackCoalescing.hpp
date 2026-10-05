// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/StackCoalescing.hpp — single-buffer stack coalescing.
//
// Coalesces many static stack slots into one byte buffer and rewrites the
// original alloca uses to typed offsets inside that buffer.  Decompilers see a
// single opaque frame object plus pointer arithmetic instead of independent
// typed locals, which directly attacks lvar and stack-frame recovery.

#ifndef MOROK_PASSES_STACK_COALESCING_HPP
#define MOROK_PASSES_STACK_COALESCING_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct StackCoalesceParams {
    std::uint32_t probability = 100; ///< per-alloca chance, 0..100
    bool opaque_offsets = true;      ///< keep offsets data-dependent in IR
};

/// Coalesce eligible static allocas in `F`.  Returns true if a byte buffer was
/// introduced and at least one alloca was replaced.
bool stackCoalesceFunction(llvm::Function &F, const StackCoalesceParams &params,
                           morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-stackcoalesce`).
class StackCoalescingPass : public llvm::RequiredPassInfoMixin<StackCoalescingPass> {
public:
    explicit StackCoalescingPass(StackCoalesceParams params = {},
                                 std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);

private:
    StackCoalesceParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_STACK_COALESCING_HPP
