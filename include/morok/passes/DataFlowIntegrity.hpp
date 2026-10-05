// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/DataFlowIntegrity.hpp — integrity-derived data tables.

#ifndef MOROK_PASSES_DATA_FLOW_INTEGRITY_HPP
#define MOROK_PASSES_DATA_FLOW_INTEGRITY_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct DataFlowIntegrityParams {
    std::uint32_t probability = 100; ///< per eligible op/cmp, 0..100
    std::uint32_t max_tables = 4;    ///< per-function table cap
    std::uint32_t region_bytes = 32; ///< bytes hashed by the runtime stub
    /// Entangle table lookups with the coherent-decoy hidden state.  When set,
    /// DFI get-or-creates the shared `morok.decoy.state` global so the state
    /// load is emitted on EVERY protected function, independent of whether a
    /// decoy was selected earlier in module order (it was previously only
    /// emitted if the global already happened to exist).
    bool decoy_state = false;
};

/// Replace selected i1..i8 operations/comparisons and const-indexed i9..i16
/// operations/comparisons with lookup tables decoded from a runtime integrity
/// hash.  Tampering with the hashed region poisons table data.
bool dataFlowIntegrityFunction(llvm::Function &F,
                               const DataFlowIntegrityParams &params,
                               morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-dfi`).
class DataFlowIntegrityPass
    : public llvm::RequiredPassInfoMixin<DataFlowIntegrityPass> {
public:
    explicit DataFlowIntegrityPass(DataFlowIntegrityParams params = {},
                                   std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);

private:
    DataFlowIntegrityParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_DATA_FLOW_INTEGRITY_HPP
