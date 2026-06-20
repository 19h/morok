// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/ConstantEncryption.hpp — constant hiding via XOR secret sharing.
//
// Each eligible scalar integer or floating literal operand, including PHI
// incoming values, branch/switch conditions, and store values, is replaced by
// the XOR of k private global "shares" (see morok/core/XorShare.hpp): the value
// never appears verbatim in the binary and is reconstructed at run time.
// Floating literals are shared by raw bit pattern and bitcast back exactly.  The
// shares are loaded volatilely so later optimisation passes cannot fold the
// reconstruction back to the original constant.

#ifndef MOROK_PASSES_CONSTANT_ENCRYPTION_HPP
#define MOROK_PASSES_CONSTANT_ENCRYPTION_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>
#include <string>
#include <vector>

namespace llvm {
class Function;
} // namespace llvm

namespace morok::passes {

struct ConstEncParams {
    std::uint32_t probability = 100; ///< per-constant chance, 0..100
    std::uint32_t share_count = 2;   ///< XOR shares, clamped to [2,8]
    std::uint32_t iterations = 1;    ///< sweeps over the function (>=1)
    bool feistel = false;            ///< 4-round Feistel layer before XOR shares
    bool substitute_xor = false;     ///< extra runtime-keyed XOR substitution layer
    std::uint32_t substitute_xor_prob = 100; ///< per-constant chance, sub layer
    bool globalize = false;          ///< route reconstructed carrier via a global
    std::uint32_t globalize_prob = 100; ///< per-constant chance, global layer
    /// Restrict to decision-gate constants only: the operands of comparisons and
    /// of constant branch/switch conditions.  Used for an early sweep that hides
    /// a license gate's `cmp reg, #imm` BEFORE the structural passes inflate the
    /// host function past the value-pass budget, so the immediate never survives
    /// as a patchable cleartext compare.
    bool conditions_only = false;
    /// Value-based filtering: ECMAScript regexes matched against the lowercase
    /// minimal hex of each integer constant.  A value matching any `force_value`
    /// pattern is always encrypted (ignoring `probability`); a value matching
    /// any `skip_value` pattern is never encrypted.  force_value wins ties.
    /// Empty (the default) leaves selection entirely to `probability`.
    std::vector<std::string> skip_value;
    std::vector<std::string> force_value;
};

/// Encrypt eligible scalar constants in `F`.  Returns true if any changed.
bool constantEncryptFunction(llvm::Function &F, const ConstEncParams &params,
                             morok::ir::IRRandom &rng);

/// Lower any `switch` carrying a wide-magic case value into a chain of encrypted
/// equality comparisons, so gate constants buried in switch cases (immutable
/// literals that `constantEncryptFunction` cannot touch) are hidden too.  Must
/// run EARLY — before the CFG passes that consume switches into dispatch forms —
/// so the encrypted comparisons it leaves behind survive every later transform.
bool deSwitchGateConstantsFunction(llvm::Function &F,
                                   const ConstEncParams &params,
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
