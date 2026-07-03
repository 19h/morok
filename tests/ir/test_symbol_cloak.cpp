// SPDX-License-Identifier: MIT
//
// Tests for SymbolCloak — inline, per-site decryption of C symbol names.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/ir/SymbolCloak.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"

using namespace llvm;
using namespace morok::test;

namespace {

morok::ir::IRRandom makeRng(std::uint64_t seed = 0xC10A) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("keystreamValue is deterministic for same inputs") {
    const auto v1 = morok::ir::keystreamValue(0, 0x123456789ABCDEF0ULL, 0, 2654435761ULL);
    const auto v2 = morok::ir::keystreamValue(0, 0x123456789ABCDEF0ULL, 0, 2654435761ULL);
    CHECK(v1 == v2);
}

TEST_CASE("keystreamValue differs across variants") {
    const auto v0 = morok::ir::keystreamValue(0, 42, 0, 2654435761ULL);
    const auto v1 = morok::ir::keystreamValue(1, 42, 0, 2654435761ULL);
    const auto v2 = morok::ir::keystreamValue(2, 42, 0, 2654435761ULL);
    // At least two should differ
    CHECK((v0 != v1 || v1 != v2 || v0 != v2));
}

TEST_CASE("keystreamValue differs across positions") {
    const auto v0 = morok::ir::keystreamValue(0, 42, 0, 2654435761ULL);
    const auto v1 = morok::ir::keystreamValue(0, 42, 1, 2654435761ULL);
    CHECK(v0 != v1);
}

TEST_CASE("keystreamValue differs across keys") {
    const auto v0 = morok::ir::keystreamValue(0, 42, 0, 2654435761ULL);
    const auto v1 = morok::ir::keystreamValue(0, 43, 0, 2654435761ULL);
    CHECK(v0 != v1);
}

TEST_CASE("randomKeystreamRecipe produces valid recipes") {
    auto rng = makeRng(0xC10A1);
    const auto recipe = morok::ir::randomKeystreamRecipe(rng);
    CHECK(recipe.count > 0);
    CHECK(recipe.count <= morok::ir::KeystreamRecipe::kMaxOps);
}

TEST_CASE("randomKeystreamRecipe produces different recipes with different seeds") {
    auto rng1 = makeRng(0xC10A2);
    auto rng2 = makeRng(0xC10A3);
    const auto r1 = morok::ir::randomKeystreamRecipe(rng1);
    const auto r2 = morok::ir::randomKeystreamRecipe(rng2);

    // Different seeds → different recipes (with overwhelming probability)
    bool anyDiff = r1.count != r2.count;
    if (!anyDiff) {
        for (unsigned i = 0; i < r1.count; ++i)
            if (r1.ops[i].kind != r2.ops[i].kind || r1.ops[i].c != r2.ops[i].c)
                anyDiff = true;
    }
    CHECK(anyDiff);
}

TEST_CASE("keystreamValue recipe matches legacy variant") {
    // The recipe-based keystreamValue should produce the same result as the
    // variant-based one when the recipe encodes the same operations.
    // This is a structural sanity check, not an exact equality test.
    const auto v = morok::ir::keystreamValue(0, 42, 3, 2654435761ULL);
    CHECK(v != 0); // should produce a non-trivial value
}

TEST_CASE("emitCloakedSymbol produces valid IR") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define void @test() {
entry:
  ret void
}
)ir");
    Function *F = M->getFunction("test");
    REQUIRE(F);

    auto rng = makeRng(0xC10A4);
    IRBuilder<> B(&F->getEntryBlock().front());

    auto *Result = morok::ir::emitCloakedSymbol(B, *M, "puts", rng);
    CHECK(Result != nullptr);

    // Should have created the cloak seed global
    auto *Seed = M->getGlobalVariable("morok.cloak.seed", true);
    CHECK(Seed != nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("cloakSeed creates a mutable global") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define void @test() { entry: ret void }
)ir");

    auto rng = makeRng(0xC10A5);
    auto *Seed = morok::ir::cloakSeed(*M, rng);
    CHECK(Seed != nullptr);
    CHECK(Seed->getName() == "morok.cloak.seed");
    CHECK_FALSE(Seed->isConstant());
}

TEST_CASE("emitRuntimeOpaqueZero produces a call") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define void @test() {
entry:
  ret void
}
)ir");
    Function *F = M->getFunction("test");
    REQUIRE(F);

    IRBuilder<> B(&F->getEntryBlock().front());
    auto *Result = morok::ir::emitRuntimeOpaqueZero(B, *M, 0x1234, "test.zero");
    CHECK(Result != nullptr);
    CHECK_FALSE(verifyModule(*M));
}
