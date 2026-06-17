// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/StringEncryption.hpp — encrypt string literals at rest.
//
// Each eligible private byte-array global is encrypted at rest.  Constant
// C-string uses that can be safely rewritten materialize into a fresh stack
// buffer at the use site; globals with unsupported address-identity or mutation
// uses fall back to a private per-string constructor decryptor.

#ifndef MOROK_PASSES_STRING_ENCRYPTION_HPP
#define MOROK_PASSES_STRING_ENCRYPTION_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Module;
} // namespace llvm

namespace morok::passes {

struct StrEncParams {
    std::uint32_t probability = 100; ///< per-string chance, 0..100
};

/// Encrypt eligible string literals in `M`.  Returns true if any changed.
bool stringEncryptModule(llvm::Module &M, const StrEncParams &params,
                         morok::ir::IRRandom &rng);

/// New-PM module-pass wrapper for standalone use (`-passes=morok-strenc`).
class StringEncryptionPass : public llvm::PassInfoMixin<StringEncryptionPass> {
public:
    explicit StringEncryptionPass(StrEncParams params = {},
                                  std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M,
                                llvm::ModuleAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    StrEncParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_STRING_ENCRYPTION_HPP
