// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/SealedBlob.hpp — encrypt explicit byte blobs at rest.

#ifndef MOROK_PASSES_SEALED_BLOB_HPP
#define MOROK_PASSES_SEALED_BLOB_HPP

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/PassManager.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace llvm {
class Module;
} // namespace llvm

namespace morok::passes {

struct SealedBlobParams {
    bool enabled = true;
    std::uint32_t max_blobs = 8;
    std::uint32_t max_blob_bytes = 64 * 1024;
    std::vector<std::string> key_sources = {"runtime_seal", "external_proof"};
    std::string delivery = "eager";
    bool zeroize_after_use = true;
    bool runtime_keyed_magic = false;
    std::uint32_t magic_bytes = 8;
};

/// Encrypt explicitly selected byte-array globals and rewrite supported uses to
/// lazily materialize through per-blob accessors.  Selection is explicit:
/// section ".morok.sealed" or a "morok.sealed." global prefix.
bool sealedBlobModule(llvm::Module &M, const SealedBlobParams &params,
                      morok::ir::IRRandom &rng);

/// New-PM module-pass wrapper for standalone use (`-passes=morok-sealedblob`).
class SealedBlobPass : public llvm::RequiredPassInfoMixin<SealedBlobPass> {
public:
    explicit SealedBlobPass(SealedBlobParams params = {},
                            std::uint64_t seed = 0x1337)
        : params_(std::move(params)),
          engine_(core::Xoshiro256pp::fromSeed(seed)) {}

    llvm::PreservedAnalyses run(llvm::Module &M,
                                llvm::ModuleAnalysisManager &AM);

private:
    SealedBlobParams params_;
    core::Xoshiro256pp engine_;
};

} // namespace morok::passes

#endif // MOROK_PASSES_SEALED_BLOB_HPP
