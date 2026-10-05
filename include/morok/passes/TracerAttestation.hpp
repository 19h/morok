// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/TracerAttestation.hpp — buddy-process tracer seal producer.

#ifndef MOROK_PASSES_TRACER_ATTESTATION_HPP
#define MOROK_PASSES_TRACER_ATTESTATION_HPP

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

struct TracerAttestationParams {
    bool enabled = true;
    std::string mode = "linux_ptrace";
    std::uint32_t shares = 2;
    std::string renewal = "startup";
    bool bind_to_runtime_seal = true;
    bool virtualize_helpers = true;
};

/// Materialize a Linux/x86_64 buddy-process tracer that injects runtime-only
/// words into the parent and folds only delivery mismatch deltas into the
/// RuntimeSeal tracer and consumed anti-debug seal channels.
bool tracerAttestationModule(llvm::Module &M,
                             const TracerAttestationParams &params,
                             morok::ir::IRRandom &rng);

/// New-PM module-pass wrapper for standalone use (`-passes=morok-tracer`).
class TracerAttestationPass
    : public llvm::RequiredPassInfoMixin<TracerAttestationPass> {
public:
    explicit TracerAttestationPass(TracerAttestationParams params = {},
                                   std::uint64_t seed = 0x7AACEu)
        : params_(std::move(params)),
          engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M,
                                llvm::ModuleAnalysisManager &AM);

private:
    TracerAttestationParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_TRACER_ATTESTATION_HPP
