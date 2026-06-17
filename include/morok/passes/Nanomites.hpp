// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/Nanomites.hpp — trap-mediated conditional branches.

#ifndef MOROK_PASSES_NANOMITES_HPP
#define MOROK_PASSES_NANOMITES_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Module;
} // namespace llvm

namespace morok::passes {

struct NanomiteParams {
    std::uint32_t probability = 35;
    std::uint32_t max_sites = 16;
};

/// Replace selected conditional branches with a synchronous trap and an
/// encrypted address table interpreted from a POSIX SIGTRAP handler.
bool nanomitesModule(llvm::Module &M, const NanomiteParams &Params,
                     morok::ir::IRRandom &Rng);

class NanomitesPass : public llvm::PassInfoMixin<NanomitesPass> {
public:
    explicit NanomitesPass(std::uint64_t seed = 0x4E414E4Fu)
        : engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }

private:
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_NANOMITES_HPP
