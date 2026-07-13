// SPDX-License-Identifier: MIT
//
// Tests for StackRebase ("AnchorScramble") — persistent stack-frame rebasing
// pressure (over-aligned anchor + dynamic frame, observable through volatile
// sinks, plus an optional non-entry LIFO shuffle).

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/StackRebase.hpp"

#include "llvm/IR/Attributes.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// Two eligible static i32 slots with loads/stores on a supported (ELF) target.
// This is the canonical input: StackRebase needs allocas plus a fixed target.
const char *kSlots = R"ir(
target triple = "x86_64-unknown-linux-gnu"
target datalayout = "e-m:e-p:64:64-i64:64-f80:128-n8:16:32:64-S128"

define i32 @slots(i32 %a, i32 %b) {
entry:
  %p = alloca i32, align 4
  %q = alloca i32, align 4
  store i32 %a, ptr %p, align 4
  store i32 %b, ptr %q, align 4
  %x = load i32, ptr %p, align 4
  %y = load i32, ptr %q, align 4
  %s = add i32 %x, %y
  ret i32 %s
}
)ir";

// A multi-block function (three non-entry blocks) so the non-entry shuffle has
// candidate blocks and the kNonEntryMaxBlocks cap becomes observable.
const char *kBranchy = R"ir(
target triple = "x86_64-unknown-linux-gnu"
target datalayout = "e-m:e-p:64:64-i64:64-f80:128-n8:16:32:64-S128"

define i32 @branchy(i32 %a, i32 %b) {
entry:
  %p = alloca i32, align 4
  store i32 %a, ptr %p, align 4
  %c = icmp slt i32 %a, %b
  br i1 %c, label %then, label %else
then:
  br label %join
else:
  br label %join
join:
  %m = load i32, ptr %p, align 4
  ret i32 %m
}
)ir";

// A trivial single-block function with no allocas at all.
const char *kTrivial = R"ir(
target triple = "x86_64-unknown-linux-gnu"
target datalayout = "e-m:e-p:64:64-i64:64-f80:128-n8:16:32:64-S128"

define i32 @trivial(i32 %x) {
entry:
  ret i32 %x
}
)ir";

// A declaration — no body to rebase.
const char *kDecl = R"ir(
declare i32 @external(i32)
)ir";

// The same slot shape but on a Windows target, which the pass refuses.
const char *kWindowsSlots = R"ir(
target triple = "x86_64-pc-windows-msvc"

define i32 @winslots(i32 %a, i32 %b) {
entry:
  %p = alloca i32, align 4
  store i32 %a, ptr %p, align 4
  %x = load i32, ptr %p, align 4
  ret i32 %x
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::string printModule(Module &M) {
    std::string text;
    raw_string_ostream os(text);
    M.print(os, nullptr);
    return os.str();
}

std::size_t countVolatileStores(Function &F) {
    std::size_t n = 0;
    for (Instruction &I : instructions(F))
        if (auto *SI = dyn_cast<StoreInst>(&I))
            if (SI->isVolatile())
                ++n;
    return n;
}

std::size_t countVolatileLoads(Function &F) {
    std::size_t n = 0;
    for (Instruction &I : instructions(F))
        if (auto *LI = dyn_cast<LoadInst>(&I))
            if (LI->isVolatile())
                ++n;
    return n;
}

// The over-aligned anchor is a static `[16 x i8]` alloca with the requested
// alignment; the persistent frame is a non-static (dynamically sized) alloca.
bool hasOveralignedArrayAlloca(Function &F, std::uint64_t alignBytes) {
    for (Instruction &I : instructions(F)) {
        auto *AI = dyn_cast<AllocaInst>(&I);
        if (!AI)
            continue;
        if (AI->isStaticAlloca() && isa<ArrayType>(AI->getAllocatedType()) &&
            AI->getAlign().value() >= alignBytes)
            return true;
    }
    return false;
}

bool hasDynamicAlloca(Function &F) {
    for (Instruction &I : instructions(F)) {
        auto *AI = dyn_cast<AllocaInst>(&I);
        if (AI && !AI->isStaticAlloca())
            return true;
    }
    return false;
}

} // namespace

TEST_CASE("stackRebaseFunction rebases stack slots and grows the module") {
    LLVMContext ctx;
    auto M = parse(ctx, kSlots);
    Function *F = M->getFunction("slots");
    REQUIRE(F);

    const std::size_t allocasBefore = countOpcode(*M, Instruction::Alloca);
    const std::size_t globalsBefore = countGlobals(*M, "__");
    REQUIRE(globalsBefore == 0u);

    auto rng = makeRng();
    CHECK(morok::passes::stackRebaseFunction(*F, {}, rng));

    // The module strictly grows: new anchor + dynamic frame allocas, and a
    // batch of private observation sinks named "__<hex>".
    CHECK(countOpcode(*M, Instruction::Alloca) > allocasBefore);
    CHECK(countGlobals(*M, "__") >= 4u);
    // Frame addresses are materialised as integers before being sunk.
    CHECK(countOpcode(*M, Instruction::PtrToInt) >= 2u);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stackRebaseFunction plants an over-aligned anchor and a dynamic "
          "frame") {
    LLVMContext ctx;
    auto M = parse(ctx, kSlots);
    Function *F = M->getFunction("slots");
    REQUIRE(F);

    auto rng = makeRng();
    // Default params: realign_align=64, dynamic_size=128.
    CHECK(morok::passes::stackRebaseFunction(*F, {}, rng));

    // The realign anchor is a static [16 x i8] alloca at >= 64-byte alignment,
    // and the persistent frame is a non-static (dynamically sized) alloca.
    CHECK(hasOveralignedArrayAlloca(*F, 64u));
    CHECK(hasDynamicAlloca(*F));

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stackRebaseFunction keeps frame addresses observable through "
          "volatile sinks") {
    LLVMContext ctx;
    auto M = parse(ctx, kSlots);
    Function *F = M->getFunction("slots");
    REQUIRE(F);

    auto rng = makeRng();
    CHECK(morok::passes::stackRebaseFunction(*F, {}, rng));

    // Guaranteed volatile traffic: pointer-int escape + dynamic-frame escape
    // and byte touch give >= 3 volatile stores; the two mix seeds are read via
    // volatile loads.
    CHECK(countVolatileStores(*F) >= 3u);
    CHECK(countVolatileLoads(*F) >= 2u);
    // Every observation sink is a fresh "__"-prefixed private global.
    CHECK(countGlobals(*M, "__") >= 4u);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stackRebaseFunction tags the function no-inline with a forced frame "
          "pointer") {
    LLVMContext ctx;
    auto M = parse(ctx, kSlots);
    Function *F = M->getFunction("slots");
    REQUIRE(F);
    REQUIRE_FALSE(F->hasFnAttribute(Attribute::NoInline));

    auto rng = makeRng();
    CHECK(morok::passes::stackRebaseFunction(*F, {}, rng));

    CHECK(F->hasFnAttribute(Attribute::NoInline));
    CHECK(F->getFnAttribute("frame-pointer").getValueAsString() == "all");

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stackRebaseFunction is inert when every parameter is disabled") {
    LLVMContext ctx;
    auto M = parse(ctx, kSlots);
    Function *F = M->getFunction("slots");
    REQUIRE(F);

    const std::size_t allocasBefore = countOpcode(*M, Instruction::Alloca);
    const std::size_t globalsBefore = countGlobals(*M, "__");

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::stackRebaseFunction(
        *F,
        {/*realign_align=*/0, /*dynamic_size=*/0, /*relocate_probability=*/0,
         /*alias_amplify=*/0, /*nonentry_shuffle=*/false},
        rng));

    // Fully disabled: nothing added, no marker attribute.
    CHECK(countOpcode(*M, Instruction::Alloca) == allocasBefore);
    CHECK(countGlobals(*M, "__") == globalsBefore);
    CHECK_FALSE(F->hasFnAttribute(Attribute::NoInline));

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stackRebaseFunction leaves declarations untouched") {
    LLVMContext ctx;
    auto M = parse(ctx, kDecl);
    Function *F = M->getFunction("external");
    REQUIRE(F);

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::stackRebaseFunction(*F, {}, rng));
    CHECK_FALSE(F->hasFnAttribute(Attribute::NoInline));

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stackRebaseFunction hardens a trivial single-block function without "
          "crashing") {
    LLVMContext ctx;
    auto M = parse(ctx, kTrivial);
    Function *F = M->getFunction("trivial");
    REQUIRE(F);

    auto rng = makeRng();
    // No original allocas, but the anchor + dynamic frame still apply.
    CHECK(morok::passes::stackRebaseFunction(*F, {}, rng));
    CHECK(hasOveralignedArrayAlloca(*F, 64u));

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stackRebaseFunction refuses unsupported Windows targets") {
    LLVMContext ctx;
    auto M = parse(ctx, kWindowsSlots);
    Function *F = M->getFunction("winslots");
    REQUIRE(F);

    const std::size_t allocasBefore = countOpcode(*M, Instruction::Alloca);

    auto rng = makeRng();
    // supportedTarget() rejects Windows regardless of the host we run on.
    CHECK_FALSE(morok::passes::stackRebaseFunction(*F, {}, rng));
    CHECK(countOpcode(*M, Instruction::Alloca) == allocasBefore);
    CHECK(countGlobals(*M, "__") == 0u);
    CHECK_FALSE(F->hasFnAttribute(Attribute::NoInline));

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stackRebaseFunction is deterministic for a fixed seed") {
    LLVMContext ctx1;
    LLVMContext ctx2;
    auto M1 = parse(ctx1, kSlots);
    auto M2 = parse(ctx2, kSlots);
    Function *F1 = M1->getFunction("slots");
    Function *F2 = M2->getFunction("slots");
    REQUIRE(F1);
    REQUIRE(F2);

    // Independent engines from the same seed must yield byte-identical IR.
    auto engine1 = morok::core::Xoshiro256pp::fromSeed(0xBEEF);
    auto engine2 = morok::core::Xoshiro256pp::fromSeed(0xBEEF);
    morok::ir::IRRandom rng1(engine1);
    morok::ir::IRRandom rng2(engine2);

    CHECK(morok::passes::stackRebaseFunction(*F1, {}, rng1));
    CHECK(morok::passes::stackRebaseFunction(*F2, {}, rng2));

    CHECK(printModule(*M1) == printModule(*M2));
    CHECK_FALSE(verifyModule(*M1));
    CHECK_FALSE(verifyModule(*M2));
}

TEST_CASE("stackRebaseFunction caps optional non-entry LIFO frames via "
          "stacksave") {
    LLVMContext ctx;
    auto M = parse(ctx, kBranchy);
    Function *F = M->getFunction("branchy");
    REQUIRE(F);

    auto rng = makeRng();
    // Persistent knobs off, shuffle on: isolates the non-entry LIFO path.
    CHECK(morok::passes::stackRebaseFunction(
        *F,
        {/*realign_align=*/0, /*dynamic_size=*/0, /*relocate_probability=*/0,
         /*alias_amplify=*/0, /*nonentry_shuffle=*/true},
        rng));

    // Each shuffled block is bracketed by a stacksave/stackrestore pair, and
    // the count is clamped by kNonEntryMaxBlocks (2) even though three
    // non-entry blocks are eligible.
    const std::size_t saves = countCallsToPrefix(*F, "llvm.stacksave");
    const std::size_t restores = countCallsToPrefix(*F, "llvm.stackrestore");
    CHECK(saves >= 1u);
    CHECK(saves <= 2u);
    CHECK(restores == saves);

    CHECK_FALSE(verifyModule(*M));
}
