// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/ArithmeticTables.hpp — arithmetic-as-table lowering.
//
// Replaces selected i1..i8 integer arithmetic and comparisons with
// lookup-table loads.  The table is stored encrypted and lazily materialized by
// a tiny runtime decoder, so the opcode intent disappears from the function
// body and plaintext tables are not present in the static initializer.

#ifndef MOROK_PASSES_ARITHMETIC_TABLES_HPP
#define MOROK_PASSES_ARITHMETIC_TABLES_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct TableArithParams {
    std::uint32_t probability = 30; ///< per eligible op chance, 0..100
    std::uint32_t max_tables = 8;   ///< per-function table cap
};

/// Replace eligible i1..i8 binary operations/comparisons in `F` with encrypted
/// table lookups.
bool tableArithmeticFunction(llvm::Function &F, const TableArithParams &params,
                             morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-tablearith`).
class ArithmeticTablesPass : public llvm::PassInfoMixin<ArithmeticTablesPass> {
public:
    explicit ArithmeticTablesPass(TableArithParams params = {},
                                  std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    TableArithParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_ARITHMETIC_TABLES_HPP
