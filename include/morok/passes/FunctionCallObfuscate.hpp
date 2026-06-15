// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/FunctionCallObfuscate.hpp — resolve external calls via dlsym.
//
// Direct calls to external (library) functions are rewritten to look the symbol
// up at run time with dlsym and call the resolved pointer.  The import no
// longer appears as a static call edge, hiding which library functions are
// used.

#ifndef MOROK_PASSES_FUNCTION_CALL_OBFUSCATE_HPP
#define MOROK_PASSES_FUNCTION_CALL_OBFUSCATE_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>

namespace llvm {
class Module;
} // namespace llvm

namespace morok::passes {

struct FcoParams {
    std::uint32_t probability = 100; ///< per-call-site chance, 0..100
    std::uint32_t max_calls = 256;   ///< total redirected call-site cap
};

/// Redirect eligible external calls in `M` through dlsym.  Returns true if any
/// call was rewritten.
bool functionCallObfuscateModule(llvm::Module &M, const FcoParams &params,
                                 morok::ir::IRRandom &rng);

/// New-PM module-pass wrapper for standalone use (`-passes=morok-fco`).
class FunctionCallObfuscatePass
    : public llvm::PassInfoMixin<FunctionCallObfuscatePass> {
public:
    explicit FunctionCallObfuscatePass(FcoParams params = {},
                                       std::uint64_t seed = 0x1337)
        : params_(params), engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M,
                                llvm::ModuleAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    FcoParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_FUNCTION_CALL_OBFUSCATE_HPP
