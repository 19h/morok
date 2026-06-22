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
#include <string>
#include <vector>

namespace llvm {
class Module;
} // namespace llvm

namespace morok::passes {

struct StrEncParams {
    std::uint32_t probability = 100; ///< per-string chance, 0..100
    std::vector<std::string> skip_content;
    std::vector<std::string> force_content;
};

/// Encrypt eligible string literals in `M`.  Returns true if any changed.
bool stringEncryptModule(llvm::Module &M, const StrEncParams &params,
                         morok::ir::IRRandom &rng);

/// Bind the runtime string-seed provider (morok.str.seed) to the anti-debug
/// runtime seal: the per-string keystream seed is XORed with a KDF of the seal
/// delta, which is zero on a clean run (strings decrypt normally) and nonzero
/// once any analysis verdict trips (debugger/ptrace/anti-hook), so the whole
/// string pool decodes to garbage under dynamic analysis.  Must run after the
/// seal channel exists (integrity tail).  No-op if the seed or seal is absent.
bool bindStringSeedToSeal(llvm::Module &M, morok::ir::IRRandom &rng);

/// Replace supported constant-format `snprintf`/`sprintf`, `printf`/`fprintf`,
/// simple `sscanf`/glibc alias integer parses, and
/// `sscanf("%31s %255[^\n]")` calls with generated per-site helpers.  The
/// printer grammar is intentionally narrow (`%s`, `%c`, simple integer
/// decimal/hex, `%%`, and literals).  This removes recoverable format constants
/// (e.g. "%s@%s$%s&%s") and clean libc formatting/parsing boundaries that
/// in-process hooks use to read canonicalized secrets.  Unsupported
/// printf/scanf features are intentionally left untouched.
bool inlineConstantFormatCalls(llvm::Module &M);

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
