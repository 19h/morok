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
//   • WindowsPEFoundation — emits reusable Windows PEB/TEB, PE, syscall, VEH helpers.
//   • TimingOracle   — samples independent clocks around short spans.
//   • TrapOracle     — checks whether SIGTRAP/int3-style traps reach the app.
//   • PageFaultTlbOracle — samples protected-page fault delivery and latency.
//   • CacheTimingOracle — pointer-chases over own code under clock bounds.
//   • MicroarchitecturalCanary — probes branch-predictor/speculation side effects.
// AntiHooking also folds decoy-grade VM/sandbox heuristics into delayed state.
// All are module passes that add code/metadata without altering the
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

/// Inject a Windows/PE foundation helper layer.  The emitted constructor and
/// helpers expose GS-relative TEB/PEB readers, PE export-by-hash scanning,
/// syscall-stub scanning/dispatch scaffolding, and VEH registration.  Returns
/// true if code was added for the target.
bool windowsPeFoundationModule(llvm::Module &M, morok::ir::IRRandom &rng);

/// Inject a runtime timing oracle.  The emitted helper samples independent
/// clocks around short deterministic spans and folds distribution-level
/// anomalies into hidden state.  Returns true if code was added.
bool timingOracleModule(llvm::Module &M, morok::ir::IRRandom &rng);

/// Inject a trap-delivery oracle.  The emitted constructor temporarily installs
/// a SIGTRAP handler, triggers a few architecture-appropriate traps, and folds
/// missing delivery into hidden state.  Returns true if code was added.
bool trapOracleModule(llvm::Module &M, morok::ir::IRRandom &rng);

/// Inject a page-fault/TLB timing oracle.  The emitted constructor temporarily
/// protects several anonymous pages, validates one expected fault per page, and
/// folds abnormal latency/fault patterns into hidden state.  Returns true if
/// code was added for the target.
bool pageFaultTlbOracleModule(llvm::Module &M, morok::ir::IRRandom &rng);

/// Inject a cache-timing self-attestation oracle.  The emitted constructor
/// performs a pseudo-random pointer chase over code bytes from selected user
/// functions and folds cumulative timing anomalies into hidden state.  Returns
/// true if code was added.
bool cacheTimingOracleModule(llvm::Module &M, morok::ir::IRRandom &rng);

/// Inject speculative side-effect canaries.  The emitted constructor trains a
/// branch, perturbs a cache line, and folds unexpected timing around the
/// predicted-path side effect into hidden state.  Returns true if code was
/// added.
bool microarchitecturalCanaryModule(llvm::Module &M,
                                    morok::ir::IRRandom &rng);

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

class WindowsPEFoundationPass
    : public llvm::PassInfoMixin<WindowsPEFoundationPass> {
public:
    explicit WindowsPEFoundationPass(std::uint64_t seed = 0x51D0BEEF)
        : engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }

private:
    core::Xoshiro256pp engine_;
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

class PageFaultTlbOraclePass
    : public llvm::PassInfoMixin<PageFaultTlbOraclePass> {
public:
    explicit PageFaultTlbOraclePass(std::uint64_t seed = 0x9A6EF17Du)
        : engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }

private:
    core::Xoshiro256pp engine_;
};

class CacheTimingOraclePass
    : public llvm::PassInfoMixin<CacheTimingOraclePass> {
public:
    explicit CacheTimingOraclePass(std::uint64_t seed = 0xCACE710Cu)
        : engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }

private:
    core::Xoshiro256pp engine_;
};

class MicroarchitecturalCanaryPass
    : public llvm::PassInfoMixin<MicroarchitecturalCanaryPass> {
public:
    explicit MicroarchitecturalCanaryPass(std::uint64_t seed = 0xC411A9E5u)
        : engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }

private:
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_ANTI_ANALYSIS_HPP
