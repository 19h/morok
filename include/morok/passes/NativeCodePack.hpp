// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// Late Linux ELF native-code pack boundary construction.  This pass does not
// encrypt machine code: it moves selected implementations into a dedicated
// section and leaves ABI-compatible lazy-entry stubs in plaintext.  Final
// layout, authenticated encryption, and runtime page materialization belong to
// the post-link packer.

#ifndef MOROK_PASSES_NATIVE_CODE_PACK_HPP
#define MOROK_PASSES_NATIVE_CODE_PACK_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>
#include <utility>

namespace llvm {
class Module;
} // namespace llvm

namespace morok::passes {

struct NativeCodePackParams {
    bool enabled = true;
    std::uint32_t probability = 100;
    std::uint32_t max_functions = 32;
    std::uint32_t min_instructions = 1;
    bool protect_generated = false;
};

bool nativeCodePackModule(llvm::Module &M,
                          const NativeCodePackParams &params,
                          morok::ir::IRRandom &rng);

class NativeCodePackPass : public llvm::PassInfoMixin<NativeCodePackPass> {
public:
    explicit NativeCodePackPass(NativeCodePackParams params = {},
                                std::uint64_t seed = 0x4E5041434BULL)
        : params_(std::move(params)),
          engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M,
                                llvm::ModuleAnalysisManager &AM);
    static bool isRequired() { return true; }

private:
    NativeCodePackParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_NATIVE_CODE_PACK_HPP
