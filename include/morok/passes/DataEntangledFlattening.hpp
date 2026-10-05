// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/DataEntangledFlattening.hpp — data-entangled CFF.
//
// Builds a flattened dispatcher whose state update is fused with live program
// values and the previous dispatcher state.  The neutralizing terms are routed
// through volatile shadow memory so the stored successor id is correct at run
// time but not a pure, trivially sliceable constant expression in the IR.

#ifndef MOROK_PASSES_DATA_ENTANGLED_FLATTENING_HPP
#define MOROK_PASSES_DATA_ENTANGLED_FLATTENING_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct DataEntangledFlattenParams {
    std::uint32_t max_terms = 4; ///< live scalar integer/FP values mixed/block
};

/// Apply data-entangled control-flow flattening to `F`.
bool dataEntangledFlattenFunction(llvm::Function &F,
                                  const DataEntangledFlattenParams &params,
                                  morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-entfla`).
class DataEntangledFlatteningPass
    : public llvm::RequiredPassInfoMixin<DataEntangledFlatteningPass> {
public:
    explicit DataEntangledFlatteningPass(DataEntangledFlattenParams params = {},
                                         std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);

private:
    DataEntangledFlattenParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_DATA_ENTANGLED_FLATTENING_HPP
