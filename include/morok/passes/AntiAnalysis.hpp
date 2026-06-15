// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/passes/AntiAnalysis.hpp — runtime anti-analysis module passes.
//
// These inject self-defence code that is inert under normal execution but
// resists interactive analysis:
//   • AntiDebugging  — denies debugger attachment at startup.
//   • AntiHooking    — checks a function prologue for inline-hook trampolines.
//   • AntiClassDump  — scrambles Objective-C metadata (no-op on non-ObjC code).
// All three are module passes that add code/metadata without altering the
// program's observable behaviour in an un-instrumented run.

#ifndef MOROK_PASSES_ANTI_ANALYSIS_HPP
#define MOROK_PASSES_ANTI_ANALYSIS_HPP

#include "llvm/IR/PassManager.h"

namespace llvm {
class Module;
} // namespace llvm

namespace morok::passes {

/// Inject a startup debugger-denial check.  Returns true if code was added.
bool antiDebuggingModule(llvm::Module &M);

/// Inject a startup inline-hook prologue check.  Returns true if code was
/// added.
bool antiHookingModule(llvm::Module &M);

/// Scramble Objective-C metadata; a no-op (returns false) on modules without
/// it.
bool antiClassDumpModule(llvm::Module &M);

class AntiDebuggingPass : public llvm::PassInfoMixin<AntiDebuggingPass> {
public:
    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }
};

class AntiHookingPass : public llvm::PassInfoMixin<AntiHookingPass> {
public:
    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }
};

class AntiClassDumpPass : public llvm::PassInfoMixin<AntiClassDumpPass> {
public:
    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }
};

} // namespace morok::passes

#endif // MOROK_PASSES_ANTI_ANALYSIS_HPP
