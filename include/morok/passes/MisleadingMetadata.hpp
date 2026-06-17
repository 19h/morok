// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/MisleadingMetadata.hpp — false analysis anchors.

#ifndef MOROK_PASSES_MISLEADING_METADATA_HPP
#define MOROK_PASSES_MISLEADING_METADATA_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Module;
} // namespace llvm

namespace morok::passes {

/// Add retained local decoy functions, alias boundaries, and contradictory
/// debug metadata so static analyzers see plausible but false function ranges.
bool misleadingMetadataModule(llvm::Module &M, morok::ir::IRRandom &rng);

class MisleadingMetadataPass
    : public llvm::PassInfoMixin<MisleadingMetadataPass> {
public:
    explicit MisleadingMetadataPass(std::uint64_t seed = 0x51A7E5u)
        : engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }

private:
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_MISLEADING_METADATA_HPP
