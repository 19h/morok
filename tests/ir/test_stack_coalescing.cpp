// SPDX-License-Identifier: MIT
//
// Tests for StackCoalescing — merge many static allocas into one [N x i8] frame
// buffer and rewrite each original alloca to a typed offset inside that buffer.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/StackCoalescing.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// Four eligible static allocas whose addresses never escape (only load/store/GEP
// uses). An explicit datalayout + triple keeps sizes/alignments and therefore
// the emitted frame layout identical on every CI host.
const char *kFrame = R"ir(
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

define i32 @frame(i32 %a, i32 %b) {
entry:
  %x = alloca i32, align 4
  %y = alloca i32, align 4
  %z = alloca i64, align 8
  %w = alloca [4 x i32], align 16
  store i32 %a, ptr %x, align 4
  store i32 %b, ptr %y, align 4
  store i64 0, ptr %z, align 8
  %gx = load i32, ptr %x, align 4
  %gy = load i32, ptr %y, align 4
  %sum = add i32 %gx, %gy
  %e0 = getelementptr inbounds [4 x i32], ptr %w, i64 0, i64 0
  store i32 %sum, ptr %e0, align 4
  %r = load i32, ptr %e0, align 4
  ret i32 %r
}
)ir";

// The single alloca's address is handed to an external callee: coalescing must
// treat it as escaping and leave it alone.
const char *kEscape = R"ir(
declare void @sink(ptr)

define void @escape() {
entry:
  %p = alloca i32, align 4
  store i32 7, ptr %p, align 4
  call void @sink(ptr %p)
  ret void
}
)ir";

// One eligible alloca — the smallest input that still coalesces.
const char *kSingle = R"ir(
define i32 @single(i32 %a) {
entry:
  %x = alloca i32, align 4
  store i32 %a, ptr %x, align 4
  %r = load i32, ptr %x, align 4
  ret i32 %r
}
)ir";

// No allocas at all — nothing to coalesce.
const char *kNoAlloca = R"ir(
define i32 @noalloca(i32 %x) {
entry:
  %r = add i32 %x, 1
  ret i32 %r
}
)ir";

const char *kDecl = R"ir(
declare i32 @external(i32)
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("stackCoalesceFunction coalesces allocas into one frame and grows") {
    LLVMContext ctx;
    auto M = parse(ctx, kFrame);
    Function *F = M->getFunction("frame");
    REQUIRE(F);

    const std::size_t beforeAllocas = countNamedAllocas(*F, "");
    CHECK(beforeAllocas == 4u);
    const auto beforeInsts = F->getInstructionCount();

    auto rng = makeRng();
    CHECK(morok::passes::stackCoalesceFunction(*F, {}, rng));

    // Exactly one frame buffer remains; every original local alloca is gone.
    CHECK(countNamedAllocas(*F, "morok.stack") == 1u);
    CHECK(countNamedAllocas(*F, "") == 1u);
    // The rewrite adds a frame alloca, per-slot GEPs and decode arithmetic.
    CHECK(F->getInstructionCount() > beforeInsts);
    CHECK(countGlobals(*M, "morok.stack.off") > 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stackCoalesceFunction respects probability=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kFrame);
    Function *F = M->getFunction("frame");
    REQUIRE(F);
    const auto beforeInsts = F->getInstructionCount();

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::stackCoalesceFunction(
        *F, {/*probability=*/0, /*opaque_offsets=*/true}, rng));

    CHECK(F->getInstructionCount() == beforeInsts);
    CHECK(countNamedAllocas(*F, "") == 4u);
    CHECK(countGlobals(*M, "morok.stack.off") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stackCoalesceFunction skips declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, kDecl);
    Function *F = M->getFunction("external");
    REQUIRE(F);

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::stackCoalesceFunction(*F, {}, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stackCoalesceFunction leaves escaping allocas untouched") {
    LLVMContext ctx;
    auto M = parse(ctx, kEscape);
    Function *F = M->getFunction("escape");
    REQUIRE(F);

    auto rng = makeRng();
    // The alloca's address is observed by @sink, so it is ineligible and the
    // pass finds no coalescible slot.
    CHECK_FALSE(morok::passes::stackCoalesceFunction(*F, {}, rng));
    CHECK(countNamedAllocas(*F, "") == 1u);
    CHECK(countNamedAllocas(*F, "morok.stack") == 0u);
    CHECK(countGlobals(*M, "morok.stack.off") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stackCoalesceFunction emits opaque offset globals and volatile loads") {
    LLVMContext ctx;
    auto M = parse(ctx, kFrame);
    Function *F = M->getFunction("frame");
    REQUIRE(F);

    auto rng = makeRng();
    CHECK(morok::passes::stackCoalesceFunction(
        *F, {/*probability=*/100, /*opaque_offsets=*/true}, rng));

    const std::size_t kSlots = 4;
    // One private encoded-offset global and one volatile decode load per slot.
    CHECK(countGlobals(*M, "morok.stack.off") == kSlots);
    CHECK(countNamedInstructions(*F, "morok.stack.off.enc") == kSlots);
    // Each encoded offset is XORed back to a plaintext byte offset.
    CHECK(countOpcode(*M, Instruction::Xor) >= kSlots);

    auto *decode =
        dyn_cast_or_null<LoadInst>(findNamedInstruction(*F, "morok.stack.off.enc"));
    REQUIRE(decode);
    CHECK(decode->isVolatile());

    GlobalVariable *gv = M->getGlobalVariable("morok.stack.off", true);
    REQUIRE(gv);
    CHECK(gv->hasPrivateLinkage());
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stackCoalesceFunction with opaque_offsets=false emits no globals") {
    LLVMContext ctx;
    auto M = parse(ctx, kFrame);
    Function *F = M->getFunction("frame");
    REQUIRE(F);

    auto rng = makeRng();
    CHECK(morok::passes::stackCoalesceFunction(
        *F, {/*probability=*/100, /*opaque_offsets=*/false}, rng));

    // Plain-constant offsets: no side channel globals, loads, or XOR decode.
    CHECK(countGlobals(*M, "morok.stack.off") == 0u);
    CHECK(countNamedInstructions(*F, "morok.stack.off.enc") == 0u);
    CHECK(countOpcode(*M, Instruction::Xor) == 0u);
    CHECK(countNamedAllocas(*F, "morok.stack") == 1u);

    // The slot pointer is still a constant-offset GEP into the frame.
    auto *slotGep =
        dyn_cast_or_null<GetElementPtrInst>(findNamedInstruction(*F, "x.slot"));
    REQUIRE(slotGep);
    CHECK(slotGep->isInBounds());
    CHECK(isa<ConstantInt>(slotGep->getOperand(1)));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stackCoalesceFunction is deterministic for a fixed seed") {
    LLVMContext ctx;
    auto M1 = parse(ctx, kFrame);
    auto M2 = parse(ctx, kFrame);

    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xABCDEF);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xABCDEF);
    morok::ir::IRRandom rngA(engineA);
    morok::ir::IRRandom rngB(engineB);

    CHECK(morok::passes::stackCoalesceFunction(*M1->getFunction("frame"), {}, rngA));
    CHECK(morok::passes::stackCoalesceFunction(*M2->getFunction("frame"), {}, rngB));

    std::string textA;
    std::string textB;
    {
        raw_string_ostream osA(textA);
        M1->print(osA, nullptr);
    }
    {
        raw_string_ostream osB(textB);
        M2->print(osB, nullptr);
    }
    CHECK(textA == textB);
    CHECK_FALSE(verifyModule(*M1));
    CHECK_FALSE(verifyModule(*M2));
}

TEST_CASE("stackCoalesceFunction is a no-op with no allocas") {
    LLVMContext ctx;
    auto M = parse(ctx, kNoAlloca);
    Function *F = M->getFunction("noalloca");
    REQUIRE(F);
    const auto beforeInsts = F->getInstructionCount();

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::stackCoalesceFunction(*F, {}, rng));
    CHECK(F->getInstructionCount() == beforeInsts);
    CHECK(countGlobals(*M, "morok.stack.off") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stackCoalesceFunction coalesces a single eligible alloca") {
    LLVMContext ctx;
    auto M = parse(ctx, kSingle);
    Function *F = M->getFunction("single");
    REQUIRE(F);
    CHECK(countNamedAllocas(*F, "") == 1u);

    auto rng = makeRng();
    CHECK(morok::passes::stackCoalesceFunction(*F, {}, rng));
    // The one local was replaced by the frame buffer.
    CHECK(countNamedAllocas(*F, "morok.stack") == 1u);
    CHECK(countNamedAllocas(*F, "") == 1u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stackCoalesceFunction emits inbounds i8 slot GEPs into the frame") {
    LLVMContext ctx;
    auto M = parse(ctx, kFrame);
    Function *F = M->getFunction("frame");
    REQUIRE(F);

    auto rng = makeRng();
    CHECK(morok::passes::stackCoalesceFunction(*F, {}, rng));

    auto *frame =
        dyn_cast_or_null<AllocaInst>(findNamedInstruction(*F, "morok.stack"));
    REQUIRE(frame);
    auto *frameTy = dyn_cast<ArrayType>(frame->getAllocatedType());
    REQUIRE(frameTy);
    CHECK(frameTy->getElementType()->isIntegerTy(8));

    for (const char *slotName : {"x.slot", "y.slot", "z.slot", "w.slot"}) {
        auto *gep =
            dyn_cast_or_null<GetElementPtrInst>(findNamedInstruction(*F, slotName));
        REQUIRE(gep);
        CHECK(gep->isInBounds());
        CHECK(gep->getPointerOperand() == frame);
    }
    CHECK_FALSE(verifyModule(*M));
}
