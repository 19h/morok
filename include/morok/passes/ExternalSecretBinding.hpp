// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/ExternalSecretBinding.hpp — proof bytes as seal key material.

#ifndef MOROK_PASSES_EXTERNAL_SECRET_BINDING_HPP
#define MOROK_PASSES_EXTERNAL_SECRET_BINDING_HPP

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

struct ExternalSecretBindingParams {
    bool enabled = true;
    std::string mode = "feed_api";
    std::string expected_digest;
    std::string identity_policy = "ascii_lower_strip_ws";
    bool entitlement_gate = false;
    std::uint64_t entitlement_required_mask = 0;
    std::uint64_t entitlement_not_before_epoch = 0;
    std::uint64_t entitlement_not_after_epoch = 0;
    bool bind_to_runtime_seal = true;
    bool virtualize_helpers = true;
};

/// Materialize the generic proof feed API and bind the finished proof digest
/// into the RuntimeSeal external_proof channel.  A seen proof keeps the channel
/// clean only when its accumulated digest matches the build-time expected
/// digest; verifier backends can call the same API without returning a
/// branchable boolean verdict.
bool externalSecretBindingModule(llvm::Module &M,
                                 const ExternalSecretBindingParams &params,
                                 morok::ir::IRRandom &rng);

/// New-PM module-pass wrapper for standalone use (`-passes=morok-proofbind`).
class ExternalSecretBindingPass
    : public llvm::RequiredPassInfoMixin<ExternalSecretBindingPass> {
public:
    explicit ExternalSecretBindingPass(ExternalSecretBindingParams params = {},
                                       std::uint64_t seed = 0x1337)
        : params_(std::move(params)),
          engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M,
                                llvm::ModuleAnalysisManager &AM);

private:
    ExternalSecretBindingParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_EXTERNAL_SECRET_BINDING_HPP
