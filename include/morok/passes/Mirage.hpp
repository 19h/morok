// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/Mirage.hpp — counterfeit-computation substrate.
//
// For a selected verdict-like function `F`, Mirage replaces the body of `F`
// with a thin, branchless dispatch hub and emits a private candidate table:
//
//     F                     original symbol, body replaced by hub
//     F.__mirage.real0      real clone 0, equivalent to the original F
//     F.__mirage.real1      real clone 1, equivalent to the original F
//     F.__mirage.fake0      counterfeit algorithm 0 (plausible, wrong)
//     F.__mirage.fake1      counterfeit algorithm 1 (plausible, wrong)
//
// On a clean runtime seal state the hub selects a real clone (index chosen from
// a per-invocation epoch, so a single dynamic trace never observes the whole
// population).  On a dirty seal state — anti-debug / env-binding / tracer
// evidence folded into a runtime seal channel — the hub routes to a counterfeit,
// so tampering yields a plausible denial/bad-token result instead of a trap.
//
// This attacks two steps of the reversing workflow Morok does not otherwise
// target directly: deciding *which* candidate is the real algorithm, and
// generalizing from *one* trace of the protected computation.
//
// Scope (v1): verdict-like functions with an `iN` (N<=64) return and scalar
// integer/pointer arguments; no vararg, EH, sret/byval, recursion, or observable
// side effects (unless explicitly annotated `mirage`).  Real clones are
// equivalence-by-construction (LLVM CloneFunction + semantics-preserving Morok
// transforms); counterfeits are deliberately wrong-but-plausible.  Cross-
// candidate mutual guarding is a documented phase-2 extension.

#ifndef MOROK_PASSES_MIRAGE_HPP
#define MOROK_PASSES_MIRAGE_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>
#include <string>
#include <vector>

namespace llvm {
class Function;
class Module;
} // namespace llvm

namespace morok::passes {

/// Diagnostic/test-only routing override applied at emission time.  It changes
/// the generated IR, never the runtime binary, so it cannot weaken a normal
/// build (see MirageConfig::force_route).
enum class MirageForceRoute {
    Auto, ///< normal seal-gated routing
    Real, ///< pin the real-clone path (constant clean route)
    Fake, ///< pin the counterfeit path (constant dirty route)
};

struct MirageParams {
    bool sensitive_only = true;           ///< only transform sensitive/mirage
    std::uint32_t clone_count = 2;        ///< equivalent real clones (clamped>=1)
    std::uint32_t counterfeit_count = 2;  ///< counterfeit algorithms (0 = none)
    std::uint32_t max_functions = 8;      ///< cap of hubs emitted per module
    std::uint32_t max_instructions = 256; ///< per-function clone-size cap
    bool seal_gated_reality = true;       ///< route to counterfeits on dirty seal
    bool per_invocation_epoch = true;     ///< vary real clone per call via epoch
    bool cross_guard = false;             ///< phase-2 cross-candidate guarding (nyi)
    /// True when the build has virtualization available; only then is real clone
    /// 1 given the VM-priority profile (so a VM-disabled build is never forced
    /// into a VM wave by Mirage).  Set by the scheduler; false for standalone.
    bool vm_profile_available = false;
    MirageForceRoute force_route = MirageForceRoute::Auto;
    /// Counterfeit template names to draw from (empty = built-in default set).
    std::vector<std::string> counterfeit_domains;
};

/// Apply Mirage to every eligible function in `M`.  Returns true if the module
/// changed.  Intended to run early in the pipeline — after annotations are
/// materialized and before VM priority marking / the first VM wave — so a real
/// clone marked `vm` can be lifted and every candidate flows through the normal
/// per-function transforms.
bool mirageModule(llvm::Module &M, const MirageParams &params,
                  morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-mirage`).
class MiragePass : public llvm::PassInfoMixin<MiragePass> {
public:
    explicit MiragePass(MirageParams params = {}, std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    MirageParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_MIRAGE_HPP
