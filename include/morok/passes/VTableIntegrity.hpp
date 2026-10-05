// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/VTableIntegrity.hpp — C++ vptr/vtable-slot verification.

#ifndef MOROK_PASSES_VTABLE_INTEGRITY_HPP
#define MOROK_PASSES_VTABLE_INTEGRITY_HPP

#include "llvm/IR/PassManager.h"

namespace llvm {
class Module;
} // namespace llvm

namespace morok::passes {

/// Verify recognized C++ virtual dispatches against expected vptr address
/// points and vtable slot targets. Returns true if any dispatch was guarded.
bool vtableIntegrityModule(llvm::Module &M);

/// New-PM module-pass wrapper for standalone use (`-passes=morok-vtable`).
class VTableIntegrityPass : public llvm::RequiredPassInfoMixin<VTableIntegrityPass> {
public:
    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
};

} // namespace morok::passes

#endif // MOROK_PASSES_VTABLE_INTEGRITY_HPP
