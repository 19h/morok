// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/MutualGuardGraph.hpp — overlapping integrity guard graph.

#ifndef MOROK_PASSES_MUTUAL_GUARD_GRAPH_HPP
#define MOROK_PASSES_MUTUAL_GUARD_GRAPH_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct MutualGuardGraphParams {
    std::uint32_t probability = 100;  ///< per eligible return, 0..100
    std::uint32_t nodes = 3;          ///< per-function checker nodes
    std::uint32_t region_bytes = 32;  ///< bytes hashed by each checker
    std::uint32_t max_returns = 2;    ///< return values poisoned by graph diff
    /// Fail-closed-on-unsealed (#106): keep the native code-hash term live (not
    /// zeroed) when the code_size slot is unsealed, so a never-sealed binary's
    /// cover diff no longer resolves and it cannot run.  Sealed builds unchanged.
    bool fail_closed_on_unsealed = false;
};

/// Emit an overlapping integrity graph and feed its combined diff into selected
/// return values.  Valid graphs contribute zero; tampering corrupts data flow.
bool mutualGuardGraphFunction(llvm::Function &F,
                              const MutualGuardGraphParams &params,
                              morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-mutualguard`).
class MutualGuardGraphPass : public llvm::RequiredPassInfoMixin<MutualGuardGraphPass> {
public:
    explicit MutualGuardGraphPass(MutualGuardGraphParams params = {},
                                  std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);

private:
    MutualGuardGraphParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_MUTUAL_GUARD_GRAPH_HPP
