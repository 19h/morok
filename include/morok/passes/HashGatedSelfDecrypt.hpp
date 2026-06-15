// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/HashGatedSelfDecrypt.hpp — VM-bytecode self-decrypt pass.

#ifndef MOROK_PASSES_HASH_GATED_SELF_DECRYPT_HPP
#define MOROK_PASSES_HASH_GATED_SELF_DECRYPT_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Module;
} // namespace llvm

namespace morok::passes {

struct HashGatedSelfDecryptParams {
    std::uint32_t probability = 100; ///< per VM bytecode payload, 0..100
    std::uint32_t max_payloads = 4;  ///< per-module wrapped payload cap
    bool context_keying = true;      ///< fold helper args into decrypt key
};

/// Add hash-gated lazy decryptors to VM bytecode payloads.
bool hashGatedSelfDecryptModule(llvm::Module &M,
                                const HashGatedSelfDecryptParams &params,
                                morok::ir::IRRandom &rng);

/// New-PM module-pass wrapper for standalone use (`-passes=morok-selfdecrypt`).
class HashGatedSelfDecryptPass
    : public llvm::PassInfoMixin<HashGatedSelfDecryptPass> {
public:
    explicit HashGatedSelfDecryptPass(HashGatedSelfDecryptParams params = {},
                                      std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M,
                                llvm::ModuleAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    HashGatedSelfDecryptParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_HASH_GATED_SELF_DECRYPT_HPP
