// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/StackRebase.hpp — persistent stack-frame rebasing pressure.
//
// Emits legal IR that pressures the backend into dynamic, over-aligned stack
// frames and keeps selected frame addresses observable through volatile sinks.

#ifndef MOROK_PASSES_STACK_REBASE_HPP
#define MOROK_PASSES_STACK_REBASE_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct StackRebaseParams {
    std::uint32_t realign_align = 64;          ///< over-aligned entry alloca
    std::uint32_t dynamic_size = 128;          ///< bounded dynamic extra bytes
    std::uint32_t relocate_probability = 60;   ///< per-static-alloca escape
    std::uint32_t alias_amplify = 40;          ///< address-taken amplifier chance
    bool nonentry_shuffle = false;             ///< extra LIFO mid-function VLA
};

/// Apply persistent stack-frame rebasing pressure to `F`.
bool stackRebaseFunction(llvm::Function &F, const StackRebaseParams &params,
                         morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-stackrebase`).
class StackRebasePass : public llvm::PassInfoMixin<StackRebasePass> {
public:
    explicit StackRebasePass(StackRebaseParams params = {},
                             std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    StackRebaseParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_STACK_REBASE_HPP
