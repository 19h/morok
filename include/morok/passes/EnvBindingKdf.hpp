// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/EnvBindingKdf.hpp — host identity as seal key material.

#ifndef MOROK_PASSES_ENV_BINDING_KDF_HPP
#define MOROK_PASSES_ENV_BINDING_KDF_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>
#include <string>
#include <utility>

namespace llvm {
class Module;
} // namespace llvm

namespace morok::passes {

struct EnvBindingKdfParams {
    bool enabled = true;
    std::string mode = "auto";
    std::string expected_digest;
    std::string identity_policy = "ascii_lower_strip_ws";
    std::uint32_t min_factors = 2;
    bool bind_to_runtime_seal = true;
    bool virtualize_helpers = true;
};

/// Materialize host-identity feed/finish helpers and, where supported, a
/// startup collector that folds an enrolled host digest into the RuntimeSeal
/// env_binding channel.  The bound host contributes exactly zero to the seal;
/// missing or mismatched identity material dirties the channel consumed by
/// string, sealed-blob, and VM key schedules.
bool envBindingKdfModule(llvm::Module &M, const EnvBindingKdfParams &params,
                         morok::ir::IRRandom &rng);

/// New-PM module-pass wrapper for standalone use (`-passes=morok-envbind`).
class EnvBindingKdfPass : public llvm::PassInfoMixin<EnvBindingKdfPass> {
public:
    explicit EnvBindingKdfPass(EnvBindingKdfParams params = {},
                               std::uint64_t seed = 0xE1B17D1EULL)
        : params_(std::move(params)),
          engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M,
                                llvm::ModuleAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    EnvBindingKdfParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_ENV_BINDING_KDF_HPP
