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
    bool include_protection_helpers = false; ///< lift allowlisted checkers too
    bool protection_helpers_only = false;    ///< restrict selection to checkers
    /// Permit lifting user functions that contain DIRECT calls to defined
    /// internal functions (simple scalar signatures only — never imports,
    /// indirect calls, varargs, or by-value aggregates).  This lets the VM claim
    /// trust-boundary functions (e.g. a license verdict computer) that were
    /// previously rejected outright for containing any call, while staying clear
    /// of the ABI/indirect-dispatch surface that is risky to virtualize.
    bool allow_internal_user_calls = false;
    /// Prefer user functions explicitly marked for VM priority before ordinary
    /// candidates consume the per-module lifting budget.
    bool prioritize_marked_user_functions = false;
};

/// Lift a single eligible function into a private threaded bytecode VM helper.
bool virtualizeFunction(llvm::Function &F, const VirtualizationParams &params,
                        morok::ir::IRRandom &rng);

/// Lift selected eligible functions in `M` into per-function bytecode VMs.
bool virtualizeModule(llvm::Module &M, const VirtualizationParams &params,
                      morok::ir::IRRandom &rng);

/// Read-only predicate: would `F` (in its current shape) be lifted by the
/// virtualizer under `params`?  Used by earlier pipeline stages (e.g. optimizer
/// amplification) to yield VM-bound functions to the virtualizer untouched —
/// growth transforms would otherwise bloat them past the lifter's budget.
bool virtualizationWillLift(llvm::Function &F,
                            const VirtualizationParams &params);

/// New-PM module-pass wrapper for standalone use (`-passes=morok-vm`).
class VirtualizationPass : public llvm::RequiredPassInfoMixin<VirtualizationPass> {
public:
    explicit VirtualizationPass(VirtualizationParams params = {},
                                std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M,
                                llvm::ModuleAnalysisManager &AM);

private:
    VirtualizationParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_VIRTUALIZATION_HPP
