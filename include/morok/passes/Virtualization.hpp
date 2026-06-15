// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/Virtualization.hpp — per-function bytecode VM lifting.

#ifndef MOROK_PASSES_VIRTUALIZATION_HPP
#define MOROK_PASSES_VIRTUALIZATION_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
class Module;
} // namespace llvm

namespace morok::passes {

struct VirtualizationParams {
    std::uint32_t probability = 100;       ///< per eligible function, 0..100
    std::uint32_t max_functions = 4;       ///< maximum lifted functions/module
    std::uint32_t max_instructions = 128;  ///< maximum VM instructions/function
    std::uint32_t max_registers = 96;      ///< bytecode virtual-register cap
};

/// Lift a single eligible function into a private threaded bytecode VM helper.
bool virtualizeFunction(llvm::Function &F, const VirtualizationParams &params,
                        morok::ir::IRRandom &rng);

/// Lift selected eligible functions in `M` into per-function bytecode VMs.
bool virtualizeModule(llvm::Module &M, const VirtualizationParams &params,
                      morok::ir::IRRandom &rng);

/// New-PM module-pass wrapper for standalone use (`-passes=morok-vm`).
class VirtualizationPass : public llvm::PassInfoMixin<VirtualizationPass> {
public:
    explicit VirtualizationPass(VirtualizationParams params = {},
                                std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M,
                                llvm::ModuleAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    VirtualizationParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_VIRTUALIZATION_HPP
