// SPDX-License-Identifier: MIT
//
// Tests for AliasOpaquePredicates — pointer/alias invariant predicates.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/AliasOpaquePredicates.hpp"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Verifier.h"

using namespace llvm;
using namespace morok::test;

namespace {

const char *kArith = R"ir(
define i32 @arith(i32 %a, i32 %b) {
entry:
  %0 = add i32 %a, %b
  %1 = mul i32 %a, %b
  %2 = xor i32 %0, %1
  %3 = and i32 %0, %2
  %4 = or  i32 %1, %3
  %5 = sub i32 %4, %a
  ret i32 %5
}
)ir";

const char *kBranchy = R"ir(
define i32 @branchy(i32 %a, i32 %b) {
entry:
  %c = icmp slt i32 %a, %b
  br i1 %c, label %then, label %else
then:
  %t = add i32 %a, 1
  br label %join
else:
  %e = sub i32 %b, 1
  br label %join
join:
  %p = phi i32 [ %t, %then ], [ %e, %else ]
  ret i32 %p
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 61) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("aliasOpaquePredicatesFunction builds alias-invariant guards") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t beforeBlocks = F->size();

    auto rng = makeRng(61);
    CHECK(morok::passes::aliasOpaquePredicatesFunction(
        *F, {/*probability=*/100, /*iterations=*/1}, rng));

    CHECK(F->size() > beforeBlocks);
    CHECK(countNamedAllocas(*F, "morok.aliasop.cell") == 1u);

    bool hasJunk = false;
    bool hasInvariantCompare = false;
    for (BasicBlock &BB : *F) {
        if (BB.getName().starts_with("morok.aliasop.junk"))
            hasJunk = true;
        for (Instruction &I : BB)
            if (I.getName().starts_with("morok.aliasop.pred"))
                hasInvariantCompare = true;
    }
    CHECK(hasJunk);
    CHECK(hasInvariantCompare);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("aliasOpaquePredicatesFunction respects probability=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t beforeBlocks = F->size();

    auto rng = makeRng(62);
    CHECK_FALSE(morok::passes::aliasOpaquePredicatesFunction(
        *F, {/*probability=*/0, /*iterations=*/1}, rng));
    CHECK(F->size() == beforeBlocks);
    CHECK(countNamedAllocas(*F, "morok.aliasop.cell") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("aliasOpaquePredicatesFunction skips single-block functions") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @trivial(i32 %x) {
entry:
  ret i32 %x
}
)ir");
    Function *F = M->getFunction("trivial");
    REQUIRE(F);

    auto rng = makeRng(63);
    // Single-block functions have no block to guard
    morok::passes::aliasOpaquePredicatesFunction(
        *F, {/*probability=*/100, /*iterations=*/1}, rng);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("aliasOpaquePredicatesFunction skips declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @external(i32)
)ir");
    Function *F = M->getFunction("external");
    REQUIRE(F);

    auto rng = makeRng(64);
    morok::passes::aliasOpaquePredicatesFunction(
        *F, {/*probability=*/100, /*iterations=*/1}, rng);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("aliasOpaquePredicatesFunction handles branchy functions") {
    LLVMContext ctx;
    auto M = parse(ctx, kBranchy);
    Function *F = M->getFunction("branchy");
    REQUIRE(F);
    const std::size_t beforeBlocks = F->size();

    auto rng = makeRng(65);
    CHECK(morok::passes::aliasOpaquePredicatesFunction(
        *F, {/*probability=*/100, /*iterations=*/1}, rng));
    CHECK(F->size() > beforeBlocks);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("aliasOpaquePredicatesFunction is idempotent") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);

    auto rng = makeRng(66);
    CHECK(morok::passes::aliasOpaquePredicatesFunction(
        *F, {/*probability=*/100, /*iterations=*/1}, rng));
    CHECK_FALSE(verifyModule(*M));

    // Second run should not crash
    auto rng2 = makeRng(67);
    morok::passes::aliasOpaquePredicatesFunction(
        *F, {/*probability=*/100, /*iterations=*/1}, rng2);
    CHECK_FALSE(verifyModule(*M));
}
