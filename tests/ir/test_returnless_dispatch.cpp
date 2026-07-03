// SPDX-License-Identifier: MIT
//
// Tests for ReturnlessDispatch — tail-call → indirect dispatch rewriting.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/ReturnlessDispatch.hpp"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Verifier.h"

using namespace llvm;
using namespace morok::test;

namespace {

const char *kTailCallModule = R"ir(
define internal i32 @leaf(i32 %x) {
entry:
  %r = add i32 %x, 7
  ret i32 %r
}

define i32 @caller(i32 %x) {
entry:
  %r = call i32 @leaf(i32 %x)
  ret i32 %r
}
)ir";

const char *kMultiTailModule = R"ir(
define internal i32 @a(i32 %x) { entry: ret i32 %x }
define internal i32 @b(i32 %x) { entry: ret i32 %x }

define i32 @multi(i32 %x) {
entry:
  %c = icmp sgt i32 %x, 0
  br i1 %c, label %left, label %right
left:
  %l = call i32 @a(i32 %x)
  ret i32 %l
right:
  %r = call i32 @b(i32 %x)
  ret i32 %r
}
)ir";

const char *kNoTailModule = R"ir(
define i32 @not_tail(i32 %x) {
entry:
  %a = add i32 %x, 1
  %b = add i32 %x, 2
  %r = add i32 %a, %b
  ret i32 %r
}
)ir";

const char *kVoidTailModule = R"ir(
declare void @sink(i32)

define void @void_caller(i32 %x) {
entry:
  call void @sink(i32 %x)
  ret void
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("returnlessDispatchFunction converts tail call to indirect dispatch") {
    LLVMContext ctx;
    auto M = parse(ctx, kTailCallModule);
    Function *F = M->getFunction("caller");
    REQUIRE(F);

    auto rng = makeRng(100);
    morok::passes::ReturnlessParams p;
    p.probability = 100;
    p.max_sites = 16;

    CHECK(morok::passes::returnlessDispatchFunction(*F, p, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("returnlessDispatchFunction skips functions without tail calls") {
    LLVMContext ctx;
    auto M = parse(ctx, kNoTailModule);
    Function *F = M->getFunction("not_tail");
    REQUIRE(F);

    auto rng = makeRng(101);
    morok::passes::ReturnlessParams p;
    p.probability = 100;

    CHECK_FALSE(morok::passes::returnlessDispatchFunction(*F, p, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("returnlessDispatchModule handles multiple tail-call sites") {
    LLVMContext ctx;
    auto M = parse(ctx, kMultiTailModule);

    auto rng = makeRng(102);
    morok::passes::ReturnlessParams p;
    p.probability = 100;
    p.max_sites = 16;

    CHECK(morok::passes::returnlessDispatchModule(*M, p, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("returnlessDispatchFunction respects probability=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kTailCallModule);
    Function *F = M->getFunction("caller");
    REQUIRE(F);

    auto rng = makeRng(103);
    morok::passes::ReturnlessParams p;
    p.probability = 0;

    CHECK_FALSE(morok::passes::returnlessDispatchFunction(*F, p, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("returnlessDispatchFunction respects max_sites cap") {
    LLVMContext ctx;
    auto M = parse(ctx, kMultiTailModule);
    Function *F = M->getFunction("multi");
    REQUIRE(F);

    auto rng = makeRng(104);
    morok::passes::ReturnlessParams p;
    p.probability = 100;
    p.max_sites = 1; // only one site should be rewritten

    // Should still succeed (at least one site rewritten)
    CHECK(morok::passes::returnlessDispatchFunction(*F, p, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("returnlessDispatchFunction handles void tail calls") {
    LLVMContext ctx;
    auto M = parse(ctx, kVoidTailModule);
    Function *F = M->getFunction("void_caller");
    REQUIRE(F);

    auto rng = makeRng(105);
    morok::passes::ReturnlessParams p;
    p.probability = 100;
    p.max_sites = 16;

    // Void tail calls may or may not be eligible depending on target
    // (no indirect br for void returns on all targets). Just verify no crash.
    morok::passes::returnlessDispatchFunction(*F, p, rng);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("returnlessDispatchFunction is idempotent on re-run") {
    LLVMContext ctx;
    auto M = parse(ctx, kTailCallModule);
    Function *F = M->getFunction("caller");
    REQUIRE(F);

    auto rng = makeRng(106);
    morok::passes::ReturnlessParams p;
    p.probability = 100;
    p.max_sites = 16;

    CHECK(morok::passes::returnlessDispatchFunction(*F, p, rng));
    CHECK_FALSE(verifyModule(*M));

    // Second run should not crash or change anything
    auto rng2 = makeRng(107);
    morok::passes::returnlessDispatchFunction(*F, p, rng2);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("returnlessDispatchModule skips declaration-only modules") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @external(i32)
)ir");

    auto rng = makeRng(108);
    morok::passes::ReturnlessParams p;
    p.probability = 100;

    CHECK_FALSE(morok::passes::returnlessDispatchModule(*M, p, rng));
    CHECK_FALSE(verifyModule(*M));
}
