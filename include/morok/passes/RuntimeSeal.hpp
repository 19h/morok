// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// Shared runtime seal / KDF support for dataflow-bound detector consumers.
//
#pragma once

#include "morok/ir/IRRandom.hpp"

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/GlobalVariable.h"

#include <cstdint>

namespace morok::passes::runtime_seal {

inline constexpr llvm::StringLiteral kAntiDebugChannel = "anti_debug";
inline constexpr llvm::StringLiteral kExternalProofChannel = "external_proof";
inline constexpr llvm::StringLiteral kEnvBindingChannel = "env_binding";
inline constexpr llvm::StringLiteral kTracerChannel = "tracer";
inline constexpr llvm::StringLiteral kFaultPagedPayloadChannel =
    "fault_paged_payload";

llvm::GlobalVariable *getChannel(llvm::Module &M, llvm::StringRef Channel,
                                 ir::IRRandom &Rng);
llvm::GlobalVariable *findChannel(llvm::Module &M, llvm::StringRef Channel);
std::uint64_t initialValue(const llvm::GlobalVariable *Seal);

llvm::Value *emitDelta(llvm::IRBuilderBase &B, llvm::GlobalVariable *Seal,
                       std::uint64_t Initial, const llvm::Twine &Name);
llvm::Value *emitChannelDelta(llvm::IRBuilderBase &B, llvm::StringRef Channel,
                              const llvm::Twine &Name);
llvm::Value *emitKdf64(llvm::IRBuilderBase &B, llvm::Value *Delta,
                       std::uint64_t Domain, const llvm::Twine &Name);

void foldFlag(llvm::IRBuilderBase &B, llvm::StringRef Channel,
              llvm::Value *Flag, std::uint64_t Salt,
              const llvm::Twine &Name);
void foldWord(llvm::IRBuilderBase &B, llvm::StringRef Channel,
              llvm::Value *Word, std::uint64_t Salt,
              const llvm::Twine &Name);

void foldWeightedFlag(llvm::IRBuilderBase &B, llvm::StringRef Channel,
                      llvm::Value *Flag, std::uint32_t Weight,
                      std::uint64_t EvidenceMask, std::uint32_t Threshold,
                      std::uint64_t Salt, const llvm::Twine &Name);

} // namespace morok::passes::runtime_seal
