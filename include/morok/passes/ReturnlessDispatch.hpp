// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/ReturnlessDispatch.hpp — turn tail-position returns into
// indirect dispatch sites with the callee target hidden behind a volatile-loaded
// slot.  Sites that are safe for tail-call lowering can leave through a computed
// `br x16` / `jmp *rax` instead of a `ret`.
//
// Scope (honest): this only covers returns that are already in tail position
// (`ret %call` where `%call` is the immediately preceding call, or `ret void`
// after a void tail call).  Those are the only returns the stock backend can
// legitimately lower to an indirect tail branch with the frame torn down
// correctly — a function that ended in a bare branch with no epilogue would
// skip the callee-saved restore and corrupt the caller.  Returns of computed
// values keep a real ABI return; eliminating those needs a uniform-signature
// continuation transform or a post-link rewriter, neither of which lives here.
//
// For the perfect-forwarding subset (the call forwards F's own arguments with a
// matching prototype) the call is marked `musttail`, which the verifier and
// backend guarantee lowers to a tail branch with no `ret`.  Other eligible sites
// are marked `tail` only when the pass can rule out pointer arguments derived
// from F's local frame; unsafe sites remain ordinary indirect calls.

#ifndef MOROK_PASSES_RETURNLESS_DISPATCH_HPP
#define MOROK_PASSES_RETURNLESS_DISPATCH_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Function;
class Module;
} // namespace llvm

namespace morok::passes {

struct ReturnlessParams {
    std::uint32_t probability = 100; ///< per-eligible-site chance, 0..100
    std::uint32_t max_sites = 64;    ///< cap of rewritten sites per function
};

/// Rewrite eligible tail-position-return call sites in `F` into indirect tail
/// branches.  Returns true if `F` changed.
bool returnlessDispatchFunction(llvm::Function &F,
                                const ReturnlessParams &params,
                                morok::ir::IRRandom &rng);

/// Module driver used by the scheduler: apply `returnlessDispatchFunction` to
/// every eligible user function.  Returns true if anything changed.
bool returnlessDispatchModule(llvm::Module &M, const ReturnlessParams &params,
                              morok::ir::IRRandom &rng);

/// New-PM wrapper for standalone use (`-passes=morok-returnless`).
class ReturnlessDispatchPass
    : public llvm::RequiredPassInfoMixin<ReturnlessDispatchPass> {
public:
    explicit ReturnlessDispatchPass(ReturnlessParams params = {},
                                    std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Function &F,
                                llvm::FunctionAnalysisManager &AM);

private:
    ReturnlessParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_RETURNLESS_DISPATCH_HPP
