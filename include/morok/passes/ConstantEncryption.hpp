// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/passes/ConstantEncryption.hpp — constant hiding via XOR secret sharing.
//
// Each eligible integer literal is replaced by the XOR of k private global
// "shares" (see morok/core/XorShare.hpp): the value never appears verbatim in
// the binary and is reconstructed at run time.  The shares are loaded
// volatilely so later optimisation passes cannot fold the reconstruction back
// to the original constant.

#ifndef MOROK_PASSES_CONSTANT_ENCRYPTION_HPP
#define MOROK_PASSES_CONSTANT_ENCRYPTION_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct ConstEncParams {
    std::uint32_t probability = 100; ///< per-constant chance, 0..100
    std::uint32_t share_count = 2;   ///< XOR shares, clamped to [2,8]
    std::uint32_t iterations = 1;    ///< sweeps over the function (>=1)
};

/// Encrypt eligible integer constants in `F`.  Returns true if any changed.
bool constantEncryptFunction(llvm::Function &F, const ConstEncParams &params,
                             morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-constenc`).
class ConstantEncryptionPass
    : public llvm::PassInfoMixin<ConstantEncryptionPass> {
public:
    explicit ConstantEncryptionPass(ConstEncParams params = {},
                                    std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    ConstEncParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_CONSTANT_ENCRYPTION_HPP
