// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/IndirectBranch.hpp — replace direct edges with indirect jumps.
//
// Conditional branches and switches are rewritten to an `indirectbr` through a
// private table of block addresses.  The table order is randomized per site and
// the original condition/case chain selects the matching slot, so static
// CFG-edge recovery must now resolve a data-dependent table load.
//
// Note: a multiplicative (Knuth-hash) encryption of the loaded pointer is not
// expressible here because modern LLVM forbids the multiply/XOR ConstantExprs
// it would require, so the indirection keys the index instead; the verified
// Knuth primitive remains available in morok/core/KnuthHash.hpp.

#ifndef MOROK_PASSES_INDIRECT_BRANCH_HPP
#define MOROK_PASSES_INDIRECT_BRANCH_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct IndirParams {
    std::uint32_t probability = 100; ///< per-terminator chance, 0..100
};

/// Indirect-ify eligible conditional branches and switches in `F`.
/// Returns true if changed.
bool indirectBranchFunction(llvm::Function &F, const IndirParams &params,
                            morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-indbr`).
class IndirectBranchPass : public llvm::PassInfoMixin<IndirectBranchPass> {
public:
    explicit IndirectBranchPass(IndirParams params = {},
                                std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    IndirParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_INDIRECT_BRANCH_HPP
