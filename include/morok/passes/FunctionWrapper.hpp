// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/FunctionWrapper.hpp — call-site proxying.
//
// Replaces direct calls with calls to freshly-generated forwarder functions
// that simply tail through to the original callee.  This adds a layer of
// indirection at every wrapped call site (and, with multiple passes, distinct
// proxies for identical calls), frustrating call-graph reconstruction.  It is
// value-neutral by construction: the forwarder passes its arguments through
// unchanged.

#ifndef MOROK_PASSES_FUNCTION_WRAPPER_HPP
#define MOROK_PASSES_FUNCTION_WRAPPER_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Module;
} // namespace llvm

namespace morok::passes {

struct FuncWrapParams {
    std::uint32_t probability = 50;   ///< per-call-site chance, 0..100
    std::uint32_t times = 1;          ///< wrapping rounds (nested proxies)
    std::uint32_t max_wrappers = 256; ///< total generated forwarder cap
};

/// Wrap eligible call sites in `M`.  Returns true if any call was redirected.
bool functionWrapModule(llvm::Module &M, const FuncWrapParams &params,
                        morok::ir::IRRandom &rng);

/// New-PM module-pass wrapper for standalone use (`-passes=morok-funcwrap`).
class FunctionWrapperPass : public llvm::PassInfoMixin<FunctionWrapperPass> {
public:
    explicit FunctionWrapperPass(FuncWrapParams params = {},
                                 std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M,
                                llvm::ModuleAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    FuncWrapParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_FUNCTION_WRAPPER_HPP
