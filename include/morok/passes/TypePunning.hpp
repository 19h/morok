// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/TypePunning.hpp — union/vector scalar punning.
//
// Round-trips scalar SSA values, including ordinary PHI results, through a
// local byte buffer and reloads them through a conflicting type view before
// bitcasting back.  The result is bit-identical, but decompiler type recovery
// sees union-like memory and vector/integer/scalar aliases for the same value.

#ifndef MOROK_PASSES_TYPE_PUNNING_HPP
#define MOROK_PASSES_TYPE_PUNNING_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct TypePunParams {
    std::uint32_t probability = 35; ///< per scalar value chance, 0..100
    bool include_floating = true;   ///< also pun floating-point scalars
    std::uint32_t max_targets = 64; ///< per-function cap, 0 = disabled
};

/// Apply type-punning chains to eligible scalar values in `F`.  Returns true if
/// any value was rewritten.
bool typePunFunction(llvm::Function &F, const TypePunParams &params,
                     morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-typepun`).
class TypePunningPass : public llvm::PassInfoMixin<TypePunningPass> {
public:
    explicit TypePunningPass(TypePunParams params = {},
                             std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    TypePunParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_TYPE_PUNNING_HPP
