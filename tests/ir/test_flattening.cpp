// SPDX-License-Identifier: MIT
//
// Tests for Flattening — control-flow flattening.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/Flattening.hpp"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Verifier.h"

using namespace llvm;
using namespace morok::test;

namespace {

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

const char *kSingleBlock = R"ir(
define i32 @trivial(i32 %x) {
entry:
  %r = add i32 %x, 1
  ret i32 %r
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 17) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("flattenFunction collapses a branchy function into a dispatcher") {
    LLVMContext ctx;
    auto M = parse(ctx, kBranchy);
    Function *F = M->getFunction("branchy");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(17);
    CHECK(morok::passes::flattenFunction(*F, rng));
    CHECK(F->size() > before);

    // A switch-based dispatcher must now exist.
    bool hasSwitch = false;
    for (Instruction &I : instructions(*F))
        if (isa<SwitchInst>(&I))
            hasSwitch = true;
    CHECK(hasSwitch);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("flattenFunction skips single-block functions") {
    LLVMContext ctx;
    auto M = parse(ctx, kSingleBlock);
    Function *F = M->getFunction("trivial");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(18);
    CHECK_FALSE(morok::passes::flattenFunction(*F, rng));
    CHECK(F->size() == before);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("flattenFunction skips declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @external(i32)
)ir");
    Function *F = M->getFunction("external");
    REQUIRE(F);

    auto rng = makeRng(19);
    CHECK_FALSE(morok::passes::flattenFunction(*F, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("flattenFunction produces a state variable alloca") {
    LLVMContext ctx;
    auto M = parse(ctx, kBranchy);
    Function *F = M->getFunction("branchy");
    REQUIRE(F);

    auto rng = makeRng(20);
    CHECK(morok::passes::flattenFunction(*F, rng));

    // The flattener creates a state variable alloca (name may vary)
    bool hasAlloca = false;
    for (Instruction &I : instructions(*F))
        if (isa<AllocaInst>(&I))
            hasAlloca = true;
    CHECK(hasAlloca);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("flattenFunction is deterministic with same seed") {
    LLVMContext ctx;
    auto M1 = parse(ctx, kBranchy);
    auto M2 = parse(ctx, kBranchy);

    auto rng1 = makeRng(21);
    auto rng2 = makeRng(21);
    morok::passes::flattenFunction(*M1->getFunction("branchy"), rng1);
    morok::passes::flattenFunction(*M2->getFunction("branchy"), rng2);

    // Same seed → same block count
    CHECK(M1->getFunction("branchy")->size() ==
          M2->getFunction("branchy")->size());
}

TEST_CASE("flattenFunction is idempotent on re-run") {
    LLVMContext ctx;
    auto M = parse(ctx, kBranchy);
    Function *F = M->getFunction("branchy");
    REQUIRE(F);

    auto rng = makeRng(22);
    CHECK(morok::passes::flattenFunction(*F, rng));
    CHECK_FALSE(verifyModule(*M));

    // Second run should not crash
    auto rng2 = makeRng(23);
    morok::passes::flattenFunction(*F, rng2);
    CHECK_FALSE(verifyModule(*M));
}
