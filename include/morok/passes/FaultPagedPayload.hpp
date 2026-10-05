// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/FaultPagedPayload.hpp — page-local VM bytecode delivery.

#ifndef MOROK_PASSES_FAULT_PAGED_PAYLOAD_HPP
#define MOROK_PASSES_FAULT_PAGED_PAYLOAD_HPP

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

struct FaultPagedPayloadParams {
    bool enabled = true;
    std::uint32_t probability = 100;
    std::uint32_t max_payloads = 4;
    std::uint32_t max_payload_bytes = 64u * 1024u;
    std::uint32_t page_size = 4096;
    std::string backend = "lazy_accessor";
    bool per_page_keys = true;
    bool reseal_after_use = true;
    std::uint32_t decoy_pages = 0;
    bool fallback = true;
    bool bind_to_runtime_seal = true;
    bool virtualize_helpers = true;
};

/// Replace direct VM bytecode loads with a page-local encrypted accessor.  The
/// accessor decrypts only the touched page into a fixed-size cache and clears it
/// before another page is materialized.
bool faultPagedPayloadModule(llvm::Module &M,
                             const FaultPagedPayloadParams &params,
                             morok::ir::IRRandom &rng);

/// New-PM module-pass wrapper for standalone use (`-passes=morok-fpp`).
class FaultPagedPayloadPass
    : public llvm::RequiredPassInfoMixin<FaultPagedPayloadPass> {
public:
    explicit FaultPagedPayloadPass(FaultPagedPayloadParams params = {},
                                   std::uint64_t seed = 0xF00D5EEDu)
        : params_(std::move(params)),
          engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M,
                                llvm::ModuleAnalysisManager &AM);

private:
    FaultPagedPayloadParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_FAULT_PAGED_PAYLOAD_HPP
