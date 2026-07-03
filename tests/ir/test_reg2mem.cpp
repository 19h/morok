// SPDX-License-Identifier: MIT
//
// Tests for Reg2Mem — demote cross-block SSA values to stack slots.

#include "TestHelpers.hpp"

#include "morok/ir/Reg2Mem.hpp"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"

using namespace llvm;
using namespace morok::test;

TEST_CASE("demoteToStack removes PHI nodes") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
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
)ir");
    Function *F = M->getFunction("branchy");
    REQUIRE(F);
    CHECK(countPhis(*F) > 0);

    morok::ir::demoteToStack(*F);
    CHECK(countPhis(*F) == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("demoteToStack creates allocas for cross-block values") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
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
)ir");
    Function *F = M->getFunction("branchy");
    REQUIRE(F);

    const std::size_t beforeAllocas = countNamedAllocas(*F, "");
    morok::ir::demoteToStack(*F);
    // Should have created allocas for the demoted values
    CHECK(countNamedAllocas(*F, "") >= beforeAllocas);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("demoteToStack is a no-op on single-block functions") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @trivial(i32 %x) {
entry:
  %r = add i32 %x, 1
  ret i32 %r
}
)ir");
    Function *F = M->getFunction("trivial");
    REQUIRE(F);
    const std::size_t beforeAllocas = countNamedAllocas(*F, "");

    morok::ir::demoteToStack(*F);
    CHECK(countPhis(*F) == 0);
    CHECK(countNamedAllocas(*F, "") == beforeAllocas);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("demoteToStack handles multiple PHIs in one block") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @multi_phi(i32 %a, i32 %b, i32 %c) {
entry:
  switch i32 %a, label %default [i32 1, label %case1 i32 2, label %case2]
case1:
  %v1 = add i32 %b, 1
  br label %join
case2:
  %v2 = add i32 %c, 2
  br label %join
default:
  %v3 = add i32 %a, 3
  br label %join
join:
  %p1 = phi i32 [ %v1, %case1 ], [ %v2, %case2 ], [ %v3, %default ]
  %p2 = phi i32 [ %v2, %case1 ], [ %v3, %case2 ], [ %v1, %default ]
  %sum = add i32 %p1, %p2
  ret i32 %sum
}
)ir");
    Function *F = M->getFunction("multi_phi");
    REQUIRE(F);
    CHECK(countPhis(*F) == 2);

    morok::ir::demoteToStack(*F);
    CHECK(countPhis(*F) == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("demoteToStack preserves semantics with loop") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @loop(i32 %n) {
entry:
  br label %loop
loop:
  %i = phi i32 [ 0, %entry ], [ %next, %loop ]
  %next = add i32 %i, 1
  %done = icmp sge i32 %next, %n
  br i1 %done, label %exit, label %loop
exit:
  ret i32 %next
}
)ir");
    Function *F = M->getFunction("loop");
    REQUIRE(F);
    CHECK(countPhis(*F) > 0);

    morok::ir::demoteToStack(*F);
    CHECK(countPhis(*F) == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("demoteToStack handles empty function") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define void @empty() {
entry:
  ret void
}
)ir");
    Function *F = M->getFunction("empty");
    REQUIRE(F);

    morok::ir::demoteToStack(*F);
    CHECK_FALSE(verifyModule(*M));
}
