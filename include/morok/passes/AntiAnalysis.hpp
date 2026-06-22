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
//   • WindowsPebHeapDebug — samples Windows PEB/heap debug fields directly.
//   • WindowsDebugObject — queries Windows debug port/object/flags by NT API.
//   • WindowsThreadHide — applies ThreadHideFromDebugger to current threads.
//   • WindowsAntiAttach — patches remote-breakin/debug-break stubs.
//   • WindowsKernelDebugger — samples kernel-debugger and decoy census signals.
//   • WindowsSyscalls — uses Hell's/Halo's/Tartarus-style syscall dispatch.
//   • WindowsProcessModules — scores debugger process and module census hits.
//   • WindowsUnhook — remaps KnownDlls and restores hooked `.text` sections.
//   • WindowsVehAudit — decodes and strips foreign vectored exception handlers.
//   • WindowsProcessMitigations — opts into ACG/CIG process policies.
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
                         bool allowSelfTrace = true,
                         bool distributionSigned = false);

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

/// Inject Windows x86_64 PEB/heap debug-structure checks.  The emitted startup
/// probe reads PEB.BeingDebugged, PEB.NtGlobalFlag, ProcessHeap, and heap
/// Flags/ForceFlags through GS-derived PEB state without calling hooked APIs.
/// Returns true if code was added for the target.
bool windowsPebHeapDebugModule(llvm::Module &M, morok::ir::IRRandom &rng);

/// Inject Windows x86_64 debug-object checks.  The emitted startup probe
/// resolves ntdll from PEB.Ldr, resolves NtQueryInformationProcess,
/// NtQueryObject, and NtQuerySystemInformation by export hash, scans NtQIP for
/// a direct-syscall DebugPort path, and folds ProcessDebugPort,
/// DebugObjectHandle, DebugFlags, ObjectTypesInformation DebugObject evidence,
/// plus bounded handle-census telemetry into hidden Windows state.  Returns
/// true if code was added.
bool windowsDebugObjectModule(llvm::Module &M, morok::ir::IRRandom &rng);

/// Inject Windows x86_64 thread-hide checks.  The emitted startup probe resolves
/// NtGetNextThread, NtSetInformationThread, NtQueryInformationThread, and
/// NtClose by export hash, applies ThreadHideFromDebugger to each current
/// thread, then queries the class back and folds failures into hidden state.
/// Returns true if code was added.
bool windowsThreadHideModule(llvm::Module &M, morok::ir::IRRandom &rng);

/// Inject Windows x86_64 anti-attach patching.  The emitted startup probe
/// resolves ntdll/kernel32 by PEB.Ldr and export hash, patches
/// DbgUiRemoteBreakin to tail-jump ExitProcess, patches DbgBreakPoint to ret,
/// launches a same-image self-debugger child that calls DebugActiveProcess,
/// gates on NtQueryInformationProcess(ProcessDebugObjectHandle), samples
/// invalid-handle CloseHandle/NtClose behavior and debugger-only invalid-handle
/// exception delivery, and checks UnhandledExceptionFilter routing.  Returns
/// true if code was added.
bool windowsAntiAttachModule(llvm::Module &M, morok::ir::IRRandom &rng);

/// Inject Windows x86_64 kernel-debugger probes.  The emitted startup probe
/// reads SharedUserData.KdDebugger* directly, calls
/// NtQuerySystemInformation(SystemKernelDebuggerInformation), and folds driver,
/// parent-PID, plus debugger-window class/caption telemetry into hidden state.
/// Returns true if code was added.
bool windowsKernelDebuggerModule(llvm::Module &M, morok::ir::IRRandom &rng);

/// Inject Windows x86_64 direct and indirect syscall probes.  The emitted
/// startup probe resolves ntdll by PEB.Ldr, resolves NT exports by hash,
/// recovers SSNs from clean or neighbor syscall stubs, calls direct and
/// ntdll-gadget syscall paths, and folds divergences into hidden Windows state.
/// Returns true if code was added.
bool windowsSyscallsModule(llvm::Module &M, morok::ir::IRRandom &rng);

/// Inject Windows x86_64 process/module census probes.  The emitted startup
/// probe resolves NtQuerySystemInformation by hash, recovers its direct syscall
/// number, walks bounded SystemProcessInformation and SystemModuleInformation
/// buffers, and folds debugger-tool basename hits as telemetry/soft score only.
/// Returns true if code was added.
bool windowsProcessModulesModule(llvm::Module &M, morok::ir::IRRandom &rng);

/// Inject Windows x86_64 KnownDlls unhooking.  The emitted startup probe resolves
/// `NtOpenSection`, `NtMapViewOfSection`, `NtProtectVirtualMemory`,
/// `NtUnmapViewOfSection`, and `NtClose` by hashed ntdll export lookup, maps
/// pristine KnownDlls ntdll/kernel32 views, locates their `.text` sections, and
/// overwrites the live text bytes after a transient page-protection flip.
/// Returns true if code was added.
bool windowsUnhookModule(llvm::Module &M, morok::ir::IRRandom &rng);

/// Inject Windows x86_64 VEH-list auditing.  The emitted startup probe resolves
/// ntdll's vectored-handler exports by hash, locates the internal
/// LdrpVectorHandlerList through RIP-relative references in those routines,
/// decodes encoded handler pointers with RtlDecodePointer, and folds suspicious
/// handler findings without removing entries from the process-wide VEH list.
/// Returns true if code was added.
bool windowsVehAuditModule(llvm::Module &M, morok::ir::IRRandom &rng);

/// Inject Windows x86_64 process-mitigation opt-ins.  The emitted startup probe
/// resolves SetProcessMitigationPolicy by hashed kernelbase/kernel32 export
/// lookup and enables ProcessDynamicCodePolicy (ACG: prohibit dynamic code) and
/// ProcessSignaturePolicy (CIG: Microsoft-signed images only).  Returns true if
/// code was added.
bool windowsProcessMitigationsModule(llvm::Module &M,
                                     morok::ir::IRRandom &rng);

/// Inject a runtime timing oracle.  The emitted helper samples independent
/// clocks around short deterministic spans and folds distribution-level
/// anomalies into hidden state.  Returns true if code was added.
bool timingOracleModule(llvm::Module &M, morok::ir::IRRandom &rng);

/// Inject a scheduler/context-switch oracle.  The emitted helper samples Linux
/// context-switch counters or platform thread-time skew over short spans and
/// folds high-confidence anomalies into hidden state.  Returns true if code was
/// added for the target.
bool schedulerStepOracleModule(llvm::Module &M, morok::ir::IRRandom &rng);

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

class WindowsPebHeapDebugPass
    : public llvm::PassInfoMixin<WindowsPebHeapDebugPass> {
public:
    explicit WindowsPebHeapDebugPass(std::uint64_t seed = 0x5EA1B0A7u)
        : engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }

private:
    core::Xoshiro256pp engine_;
};

class WindowsDebugObjectPass
    : public llvm::PassInfoMixin<WindowsDebugObjectPass> {
public:
    explicit WindowsDebugObjectPass(std::uint64_t seed = 0xD3B60B1Eu)
        : engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }

private:
    core::Xoshiro256pp engine_;
};

class WindowsThreadHidePass
    : public llvm::PassInfoMixin<WindowsThreadHidePass> {
public:
    explicit WindowsThreadHidePass(std::uint64_t seed = 0x71D1E11Du)
        : engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }

private:
    core::Xoshiro256pp engine_;
};

class WindowsAntiAttachPass
    : public llvm::PassInfoMixin<WindowsAntiAttachPass> {
public:
    explicit WindowsAntiAttachPass(std::uint64_t seed = 0xA77A11CEu)
        : engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }

private:
    core::Xoshiro256pp engine_;
};

class WindowsKernelDebuggerPass
    : public llvm::PassInfoMixin<WindowsKernelDebuggerPass> {
public:
    explicit WindowsKernelDebuggerPass(std::uint64_t seed = 0x1EADBEEFu)
        : engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }

private:
    core::Xoshiro256pp engine_;
};

class WindowsSyscallsPass : public llvm::PassInfoMixin<WindowsSyscallsPass> {
public:
    explicit WindowsSyscallsPass(std::uint64_t seed = 0x5C411C5u)
        : engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }

private:
    core::Xoshiro256pp engine_;
};

class WindowsProcessModulesPass
    : public llvm::PassInfoMixin<WindowsProcessModulesPass> {
public:
    explicit WindowsProcessModulesPass(std::uint64_t seed = 0xC011EC75u)
        : engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }

private:
    core::Xoshiro256pp engine_;
};

class WindowsUnhookPass : public llvm::PassInfoMixin<WindowsUnhookPass> {
public:
    explicit WindowsUnhookPass(std::uint64_t seed = 0xC1EAD11Du)
        : engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }

private:
    core::Xoshiro256pp engine_;
};

class WindowsVehAuditPass
    : public llvm::PassInfoMixin<WindowsVehAuditPass> {
public:
    explicit WindowsVehAuditPass(std::uint64_t seed = 0x5EA11D17u)
        : engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
    static bool isRequired() { return true; }

private:
    core::Xoshiro256pp engine_;
};

class WindowsProcessMitigationsPass
    : public llvm::PassInfoMixin<WindowsProcessMitigationsPass> {
public:
    explicit WindowsProcessMitigationsPass(std::uint64_t seed = 0xAC6C161Du)
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

class SchedulerStepOraclePass
    : public llvm::PassInfoMixin<SchedulerStepOraclePass> {
public:
    explicit SchedulerStepOraclePass(std::uint64_t seed = 0x57E0A11Cu)
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
