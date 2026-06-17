// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/AntiAnalysis.hpp — runtime anti-analysis module passes.
//
// These inject self-defence code that is inert under normal execution but
// resists interactive analysis:
//   • AntiDebugging  — denies debugger attachment at startup.
//   • AntiHooking    — checks a function prologue for inline-hook trampolines.
//   • AntiClassDump  — scrambles Objective-C metadata (no-op on non-ObjC code).
//   • TimingOracle   — samples independent clocks around short spans.
//   • TrapOracle     — checks whether SIGTRAP/int3-style traps reach the app.
// AntiHooking also folds decoy-grade VM/sandbox heuristics into delayed state.
// All five are module passes that add code/metadata without altering the
// program's observable behaviour in an un-instrumented run.

#ifndef MOROK_PASSES_ANTI_ANALYSIS_HPP
#define MOROK_PASSES_ANTI_ANALYSIS_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Module;
} // namespace llvm

namespace morok::passes {

/// Inject startup debugger-denial and source-state checks.  Runtime strings are
/// cloaked with per-site material from `rng`.  Returns true if code was added.
bool antiDebuggingModule(llvm::Module &M, morok::ir::IRRandom &rng,
                         bool allowSelfTrace = true);

/// Compatibility overload for standalone tests / direct use.
bool antiDebuggingModule(llvm::Module &M);

/// Inject a startup inline-hook prologue check.  The probed symbol name is
/// cloaked inline (never a readable string), keyed off `rng`.  Returns true if
/// code was added.
bool antiHookingModule(llvm::Module &M, morok::ir::IRRandom &rng);

/// Scramble Objective-C metadata; a no-op (returns false) on modules without
/// it.
bool antiClassDumpModule(llvm::Module &M);

/// Inject a runtime timing oracle.  The emitted helper samples independent
/// clocks around short deterministic spans and folds distribution-level
/// anomalies into hidden state.  Returns true if code was added.
bool timingOracleModule(llvm::Module &M, morok::ir::IRRandom &rng);

/// Inject a trap-delivery oracle.  The emitted constructor temporarily installs
/// a SIGTRAP handler, triggers a few architecture-appropriate traps, and folds
/// missing delivery into hidden state.  Returns true if code was added.
bool trapOracleModule(llvm::Module &M, morok::ir::IRRandom &rng);

class AntiDebuggingPass : public llvm::PassInfoMixin<AntiDebuggingPass> {
public:
    explicit AntiDebuggingPass(std::uint64_t seed = 0xA17D3B9u)
        : engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }

private:
    core::Xoshiro256pp engine_;
};

class AntiHookingPass : public llvm::PassInfoMixin<AntiHookingPass> {
public:
    explicit AntiHookingPass(std::uint64_t seed = 0x1337)
        : engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }

private:
    core::Xoshiro256pp engine_;
};

class AntiClassDumpPass : public llvm::PassInfoMixin<AntiClassDumpPass> {
public:
    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }
};

class TimingOraclePass : public llvm::PassInfoMixin<TimingOraclePass> {
public:
    explicit TimingOraclePass(std::uint64_t seed = 0x710C10C5u)
        : engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }

private:
    core::Xoshiro256pp engine_;
};

class TrapOraclePass : public llvm::PassInfoMixin<TrapOraclePass> {
public:
    explicit TrapOraclePass(std::uint64_t seed = 0x7A9A7A9Au)
        : engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }

private:
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_ANTI_ANALYSIS_HPP
