// SPDX-License-Identifier: MIT
//
// Tests for InstUtil — shared instruction-level resilience helpers.

#include "TestHelpers.hpp"

#include "morok/ir/InstUtil.hpp"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"

using namespace llvm;
using namespace morok::test;

TEST_CASE("isMustTailReturn true for musttail+ret") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @callee(i32)

define i32 @caller(i32 %x) {
entry:
  %r = musttail call i32 @callee(i32 %x)
  ret i32 %r
}
)ir");
    Function *F = M->getFunction("caller");
    REQUIRE(F);

    // Find the ret instruction
    for (Instruction &I : instructions(*F))
        if (auto *RI = dyn_cast<ReturnInst>(&I))
            CHECK(morok::ir::isMustTailReturn(*RI));
}

TEST_CASE("isMustTailReturn false for regular ret") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @normal(i32 %x) {
entry:
  %r = add i32 %x, 1
  ret i32 %r
}
)ir");
    Function *F = M->getFunction("normal");
    REQUIRE(F);

    for (Instruction &I : instructions(*F))
        if (auto *RI = dyn_cast<ReturnInst>(&I))
            CHECK_FALSE(morok::ir::isMustTailReturn(*RI));
}

TEST_CASE("isMustTailReturn false for call without musttail") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @callee(i32)

define i32 @caller(i32 %x) {
entry:
  %r = tail call i32 @callee(i32 %x)
  ret i32 %r
}
)ir");
    Function *F = M->getFunction("caller");
    REQUIRE(F);

    for (Instruction &I : instructions(*F))
        if (auto *RI = dyn_cast<ReturnInst>(&I))
            CHECK_FALSE(morok::ir::isMustTailReturn(*RI));
}

TEST_CASE("usesFuncletEH false for no personality") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @no_eh(i32 %x) {
entry:
  ret i32 %x
}
)ir");
    Function *F = M->getFunction("no_eh");
    REQUIRE(F);
    CHECK_FALSE(morok::ir::usesFuncletEH(*F));
}

TEST_CASE("usesFuncletEH false for Itanium personality") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @itanium(i32 %x) personality ptr @__gxx_personality_v0 {
entry:
  ret i32 %x
}

declare i32 @__gxx_personality_v0(...)
)ir");
    Function *F = M->getFunction("itanium");
    REQUIRE(F);
    CHECK_FALSE(morok::ir::usesFuncletEH(*F));
}

TEST_CASE("usesFuncletEH true for MSVC personality") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @msvc(i32 %x) personality ptr @__CxxFrameHandler3 {
entry:
  ret i32 %x
}

declare i32 @__CxxFrameHandler3(...)
)ir");
    Function *F = M->getFunction("msvc");
    REQUIRE(F);
    CHECK(morok::ir::usesFuncletEH(*F));
}
