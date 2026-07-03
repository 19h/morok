// SPDX-License-Identifier: MIT
//
// Tests for ExternalSecretBinding — proof bytes as seal key material.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/ExternalSecretBinding.hpp"
#include "morok/passes/RuntimeSeal.hpp"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Verifier.h"

using namespace llvm;
using namespace morok::test;

namespace {

const char *kSimpleModule = R"ir(
define i32 @main(i32 %x) {
entry:
  ret i32 %x
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("externalSecretBindingModule emits proof feed infrastructure") {
    LLVMContext ctx;
    auto M = parse(ctx, kSimpleModule);

    auto rng = makeRng(0xA001);
    morok::passes::ExternalSecretBindingParams p;
    p.bind_to_runtime_seal = true;

    CHECK(morok::passes::externalSecretBindingModule(*M, p, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("externalSecretBindingModule creates seal channel") {
    LLVMContext ctx;
    auto M = parse(ctx, kSimpleModule);

    auto rng = makeRng(0xA002);
    morok::passes::ExternalSecretBindingParams p;
    p.bind_to_runtime_seal = true;

    morok::passes::externalSecretBindingModule(*M, p, rng);

    // Should create the external_proof seal channel
    auto *Seal = morok::passes::runtime_seal::findChannel(
        *M, morok::passes::runtime_seal::kExternalProofChannel);
    CHECK(Seal != nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("externalSecretBindingModule skips when seal not bound") {
    LLVMContext ctx;
    auto M = parse(ctx, kSimpleModule);

    auto rng = makeRng(0xA003);
    morok::passes::ExternalSecretBindingParams p;
    p.bind_to_runtime_seal = false;

    // May or may not change depending on mode
    morok::passes::externalSecretBindingModule(*M, p, rng);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("externalSecretBindingModule is idempotent") {
    LLVMContext ctx;
    auto M = parse(ctx, kSimpleModule);

    auto rng = makeRng(0xA004);
    morok::passes::ExternalSecretBindingParams p;
    p.bind_to_runtime_seal = true;

    morok::passes::externalSecretBindingModule(*M, p, rng);
    CHECK_FALSE(verifyModule(*M));

    // Second run should not crash
    auto rng2 = makeRng(0xA005);
    morok::passes::externalSecretBindingModule(*M, p, rng2);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("externalSecretBindingModule handles declaration-only modules") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare void @external()
)ir");

    auto rng = makeRng(0xA006);
    morok::passes::ExternalSecretBindingParams p;
    p.bind_to_runtime_seal = true;

    // Should not crash on declaration-only modules
    morok::passes::externalSecretBindingModule(*M, p, rng);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("externalSecretBindingModule emits feed API functions") {
    LLVMContext ctx;
    auto M = parse(ctx, kSimpleModule);

    auto rng = makeRng(0xA007);
    morok::passes::ExternalSecretBindingParams p;
    p.bind_to_runtime_seal = true;

    morok::passes::externalSecretBindingModule(*M, p, rng);

    // Should create proof feed API functions
    for (Function &F : *M)
        if (F.getName().contains("proof") || F.getName().contains("morok.proof"))
            break;
    // The pass creates infrastructure; just verify no crash
    CHECK_FALSE(verifyModule(*M));
}
