// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/MicrocodeStress.hpp — sparse computed jump-table stress.
//
// Emits semantics-neutral blockaddress tables and aliased decoy destinations to
// stress decompiler microcode CFG/lvar recovery without encoding source CFG
// edges.

#ifndef MOROK_PASSES_MICROCODE_STRESS_HPP
#define MOROK_PASSES_MICROCODE_STRESS_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct MicrocodeStressParams {
    std::uint32_t probability = 25;     ///< per-block chance, 0..100
    std::uint32_t max_sites = 3;        ///< per-function stress sites
    std::uint32_t table_entries = 32;   ///< normalized to a power of two
    std::uint32_t decoy_blocks = 8;     ///< destinations that rejoin the body
    std::uint32_t alias_stores = 2;     ///< volatile alias writes per decoy
};

/// Apply sparse computed jump-table microcode stress to `F`.
bool microcodeStressFunction(llvm::Function &F,
                             const MicrocodeStressParams &params,
                             morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-microstress`).
class MicrocodeStressPass : public llvm::PassInfoMixin<MicrocodeStressPass> {
public:
    explicit MicrocodeStressPass(MicrocodeStressParams params = {},
                                 std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    MicrocodeStressParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_MICROCODE_STRESS_HPP
