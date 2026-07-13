// SPDX-License-Identifier: MIT
//
// Tests for PointerLaundering — routes pointer operands through
// ptrtoint/inttoptr + computed byte-GEPs and scalar SSA values through a
// byte-vector shuffle round-trip, preserving the value while poisoning
// alias/type propagation.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/PointerLaundering.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;
using namespace morok::test;

namespace {

// Function with pointer operands (alloca/load/store) and integer SSA values so
// both the pointer- and scalar-laundering paths have work to do.  Explicit
// datalayout/triple keep the intptr width deterministic across CI hosts.
const char *kMixed = R"ir(
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

define i32 @laundry(ptr %p, i32 %x) {
entry:
  %slot = alloca i32, align 4
  store i32 %x, ptr %slot, align 4
  %v = load i32, ptr %p, align 4
  %w = add i32 %v, %x
  store i32 %w, ptr %slot, align 4
  %r = load i32, ptr %slot, align 4
  ret i32 %r
}
)ir";

// Scalar floating-point SSA values exercise the FP carrier path.
const char *kFp = R"ir(
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

define double @fp(double %a, double %b) {
entry:
  %s = fadd double %a, %b
  %m = fmul double %s, %a
  ret double %m
}
)ir";

const char *kTrivialVoid = R"ir(
define void @trivial_void() {
entry:
  ret void
}
)ir";

const char *kDecl = R"ir(
declare ptr @external(ptr)
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::size_t instructionCount(Function &F) {
    std::size_t n = 0;
    for (Instruction &I : instructions(F)) {
        (void)I;
        ++n;
    }
    return n;
}

} // namespace

TEST_CASE("pointerLaunderFunction launders pointers and scalars and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kMixed);
    Function *F = M->getFunction("laundry");
    REQUIRE(F);
    const std::size_t beforeInsts = instructionCount(*F);
    REQUIRE(countGlobals(*M, "morok.ptr.key") == std::size_t{0});

    auto rng = makeRng(1);
    CHECK(morok::passes::pointerLaunderFunction(
        *F, {/*.pointer_probability=*/100u, /*.integer_probability=*/100u},
        rng));

    // Laundering inserts instructions in-place and adds key globals; it does
    // not create new basic blocks, so growth shows in the instruction/global
    // counts rather than the block count.
    CHECK(instructionCount(*F) > beforeInsts);
    CHECK(countGlobals(*M, "morok.ptr.key") >= std::size_t{2});
    CHECK(countNamedInstructions(*F, "morok.ptr") > std::size_t{0});
    CHECK(countNamedInstructions(*F, "morok.int") > std::size_t{0});
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("pointerLaunderFunction respects zero probabilities as a no-op") {
    LLVMContext ctx;
    auto M = parse(ctx, kMixed);
    Function *F = M->getFunction("laundry");
    REQUIRE(F);
    const std::size_t beforeInsts = instructionCount(*F);

    auto rng = makeRng(2);
    CHECK_FALSE(morok::passes::pointerLaunderFunction(
        *F, {/*.pointer_probability=*/0u, /*.integer_probability=*/0u}, rng));

    CHECK(instructionCount(*F) == beforeInsts);
    CHECK(countGlobals(*M, "morok.ptr.key") == std::size_t{0});
    CHECK(countNamedInstructions(*F, "morok") == std::size_t{0});
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("pointerLaunderFunction skips declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, kDecl);
    Function *F = M->getFunction("external");
    REQUIRE(F);

    auto rng = makeRng(3);
    CHECK_FALSE(morok::passes::pointerLaunderFunction(
        *F, {/*.pointer_probability=*/100u, /*.integer_probability=*/100u},
        rng));
    CHECK(countGlobals(*M, "morok.ptr.key") == std::size_t{0});
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("pointerLaunderFunction is safe on a trivial void function") {
    LLVMContext ctx;
    auto M = parse(ctx, kTrivialVoid);
    Function *F = M->getFunction("trivial_void");
    REQUIRE(F);
    const std::size_t beforeInsts = instructionCount(*F);

    auto rng = makeRng(4);
    // No pointer operands and no launderable scalar values: nothing to do.
    CHECK_FALSE(morok::passes::pointerLaunderFunction(
        *F, {/*.pointer_probability=*/100u, /*.integer_probability=*/100u},
        rng));
    CHECK(instructionCount(*F) == beforeInsts);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("pointerLaunderFunction is deterministic for a fixed seed") {
    LLVMContext ctxA;
    LLVMContext ctxB;
    auto Ma = parse(ctxA, kMixed);
    auto Mb = parse(ctxB, kMixed);

    // Two independent engines from one seed must draw the same sequence, so the
    // laundered modules print byte-identically.
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0x0BADC0DE);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0x0BADC0DE);
    morok::ir::IRRandom rngA(engineA);
    morok::ir::IRRandom rngB(engineB);

    const morok::passes::PointerLaunderParams params{
        /*.pointer_probability=*/100u, /*.integer_probability=*/100u};
    CHECK(morok::passes::pointerLaunderFunction(*Ma->getFunction("laundry"),
                                                params, rngA));
    CHECK(morok::passes::pointerLaunderFunction(*Mb->getFunction("laundry"),
                                                params, rngB));

    std::string textA;
    std::string textB;
    {
        raw_string_ostream osA(textA);
        Ma->print(osA, nullptr);
    }
    {
        raw_string_ostream osB(textB);
        Mb->print(osB, nullptr);
    }
    CHECK(textA == textB);
    CHECK_FALSE(verifyModule(*Ma));
    CHECK_FALSE(verifyModule(*Mb));
}

TEST_CASE("pointerLaunderFunction emits key globals and ptr<->int casts for pointers") {
    LLVMContext ctx;
    auto M = parse(ctx, kMixed);
    Function *F = M->getFunction("laundry");
    REQUIRE(F);

    // Pointer path only: no scalar laundering.
    auto rng = makeRng(5);
    CHECK(morok::passes::pointerLaunderFunction(
        *F, {/*.pointer_probability=*/100u, /*.integer_probability=*/0u}, rng));

    const std::size_t ptrToInt = countOpcode(*M, Instruction::PtrToInt);
    const std::size_t intToPtr = countOpcode(*M, Instruction::IntToPtr);
    // Each laundered pointer emits exactly one ptrtoint, one inttoptr, and two
    // private "morok.ptr.key" carrier globals.
    CHECK(ptrToInt > std::size_t{0});
    CHECK(ptrToInt == intToPtr);
    CHECK(countGlobals(*M, "morok.ptr.key") == 2u * ptrToInt);

    // The round-trip lands on a computed i8 byte-GEP.
    auto *GEP = dyn_cast_or_null<GetElementPtrInst>(
        findNamedInstruction(*F, "morok.ptr.gep"));
    REQUIRE(GEP != nullptr);
    CHECK(GEP->getSourceElementType()->isIntegerTy(8));

    // Scalar path stayed dormant.
    CHECK(countNamedInstructions(*F, "morok.int") == std::size_t{0});
    CHECK(countOpcode(*M, Instruction::ShuffleVector) == std::size_t{0});
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("pointerLaunderFunction round-trips scalar values through a byte-vector shuffle") {
    LLVMContext ctx;
    auto M = parse(ctx, kMixed);
    Function *F = M->getFunction("laundry");
    REQUIRE(F);

    // Scalar path only: no pointer laundering.
    auto rng = makeRng(6);
    CHECK(morok::passes::pointerLaunderFunction(
        *F, {/*.pointer_probability=*/0u, /*.integer_probability=*/100u}, rng));

    // Each laundered integer bitcasts to <N x i8>, shuffles, and bitcasts back.
    CHECK(countOpcode(*M, Instruction::ShuffleVector) > std::size_t{0});
    CHECK(findNamedInstruction(*F, "morok.int.bytes") != nullptr);
    CHECK(findNamedInstruction(*F, "morok.int.shuffle") != nullptr);
    CHECK(findNamedInstruction(*F, "morok.int.wide.value") != nullptr);

    // Pointer path stayed dormant: no casts, no carrier globals.
    CHECK(countGlobals(*M, "morok.ptr.key") == std::size_t{0});
    CHECK(countNamedInstructions(*F, "morok.ptr") == std::size_t{0});
    CHECK(countOpcode(*M, Instruction::PtrToInt) == std::size_t{0});
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("pointerLaunderFunction launders scalar FP values through an integer carrier") {
    LLVMContext ctx;
    auto M = parse(ctx, kFp);
    Function *F = M->getFunction("fp");
    REQUIRE(F);
    const std::size_t beforeInsts = instructionCount(*F);

    auto rng = makeRng(7);
    CHECK(morok::passes::pointerLaunderFunction(
        *F, {/*.pointer_probability=*/0u, /*.integer_probability=*/100u}, rng));

    // FP values cross an integer carrier (bitcast to iN) before the byte
    // shuffle and bitcast back to the FP type.
    CHECK(instructionCount(*F) > beforeInsts);
    CHECK(findNamedInstruction(*F, "morok.int.fpbits") != nullptr);
    CHECK(findNamedInstruction(*F, "morok.int.fpvalue") != nullptr);
    CHECK(countOpcode(*M, Instruction::ShuffleVector) > std::size_t{0});
    CHECK_FALSE(verifyModule(*M));
}
