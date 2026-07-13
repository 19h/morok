// SPDX-License-Identifier: MIT
//
// Tests for VectorObfuscation — lifts eligible scalar integer/floating ops,
// casts, compares, and selects into fixed-width vector ops whose lane 0 (or a
// shuffle-selected lane) carries the real value and the rest are junk.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/VectorObfuscation.hpp"

#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// Six i32 binary operators, all eligible for lifting (Add/Sub/Mul/And/Or/Xor),
// no compares/selects/casts.  At width 128 each i32 lifts to a <4 x i32> op.
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

// A function whose only obfuscation-eligible instruction is an integer compare.
const char *kCmpOnly = R"ir(
define i1 @cmponly(i32 %a, i32 %b) {
entry:
  %c = icmp slt i32 %a, %b
  ret i1 %c
}
)ir";

// A single i128 add: liftable() accepts it (>= 8 bits, Add opcode) but at width
// 128 the lane count is 128/128 = 1 (< 2), so liftBinary bails and nothing
// changes.
const char *kWideI128 = R"ir(
define i128 @wide(i128 %a, i128 %b) {
entry:
  %s = add i128 %a, %b
  ret i128 %s
}
)ir";

// A declaration and a trivial single-block function with no eligible ops.
const char *kInert = R"ir(
declare i32 @external(i32)

define i32 @trivial(i32 %x) {
entry:
  ret i32 %x
}

define void @empty() {
entry:
  ret void
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::size_t instructionTotal(Function &F) {
    std::size_t n = 0;
    for (Instruction &I : instructions(F)) {
        (void)I;
        ++n;
    }
    return n;
}

} // namespace

TEST_CASE("vectorObfuscateFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = instructionTotal(*F);

    auto rng = makeRng();
    CHECK(morok::passes::vectorObfuscateFunction(
        *F,
        {/*probability=*/100, /*width=*/128, /*shuffle=*/false,
         /*lift_comparisons=*/true},
        rng));
    // Each lifted binop expands into insertelement chains plus the vector op
    // and an extract, so the instruction count strictly grows.
    CHECK(instructionTotal(*F) > before);
    CHECK(countNamedInstructions(*F, "morok.vec") > 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("vectorObfuscateFunction is a no-op at probability zero") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = instructionTotal(*F);

    auto rng = makeRng();
    // chance(0) is always false, so no target is ever transformed.
    CHECK_FALSE(morok::passes::vectorObfuscateFunction(
        *F,
        {/*probability=*/0, /*width=*/128, /*shuffle=*/false,
         /*lift_comparisons=*/true},
        rng));
    CHECK(instructionTotal(*F) == before);
    CHECK(countNamedInstructions(*F, "morok.vec") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("vectorObfuscateFunction leaves declarations and trivial functions "
          "untouched") {
    LLVMContext ctx;
    auto M = parse(ctx, kInert);
    Function *Decl = M->getFunction("external");
    Function *Trivial = M->getFunction("trivial");
    Function *Empty = M->getFunction("empty");
    REQUIRE(Decl);
    REQUIRE(Trivial);
    REQUIRE(Empty);

    auto rng = makeRng();
    const morok::passes::VecParams params{
        /*probability=*/100, /*width=*/128, /*shuffle=*/true,
        /*lift_comparisons=*/true};
    // A declaration has no body, and neither trivial function has an eligible
    // op; all three must report "unchanged" and must not crash.
    CHECK_FALSE(morok::passes::vectorObfuscateFunction(*Decl, params, rng));
    CHECK_FALSE(morok::passes::vectorObfuscateFunction(*Trivial, params, rng));
    CHECK_FALSE(morok::passes::vectorObfuscateFunction(*Empty, params, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("vectorObfuscateFunction is deterministic for a fixed seed") {
    LLVMContext ctx;
    auto MA = parse(ctx, kArith);
    auto MB = parse(ctx, kArith);

    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xBEEF);
    morok::ir::IRRandom rngA(engineA);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xBEEF);
    morok::ir::IRRandom rngB(engineB);

    const morok::passes::VecParams params{
        /*probability=*/100, /*width=*/256, /*shuffle=*/true,
        /*lift_comparisons=*/true};
    CHECK(morok::passes::vectorObfuscateFunction(*MA->getFunction("arith"),
                                                 params, rngA));
    CHECK(morok::passes::vectorObfuscateFunction(*MB->getFunction("arith"),
                                                 params, rngB));

    std::string textA;
    std::string textB;
    {
        raw_string_ostream osA(textA);
        MA->print(osA, nullptr);
    }
    {
        raw_string_ostream osB(textB);
        MB->print(osB, nullptr);
    }
    // Same seed + same input IR => byte-identical output (including junk lanes
    // and shuffle masks).
    CHECK(textA == textB);
    CHECK_FALSE(verifyModule(*MA));
    CHECK_FALSE(verifyModule(*MB));
}

TEST_CASE("vectorObfuscateFunction emits insert and extract element ops") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);

    auto rng = makeRng();
    CHECK(morok::passes::vectorObfuscateFunction(
        *F,
        {/*probability=*/100, /*width=*/128, /*shuffle=*/false,
         /*lift_comparisons=*/true},
        rng));

    // buildVector inserts every lane and extractRealLane pulls lane 0 back out.
    CHECK(countOpcode(*M, static_cast<unsigned>(Instruction::InsertElement)) >
          0u);
    CHECK(countOpcode(*M, static_cast<unsigned>(Instruction::ExtractElement)) >
          0u);
    // shuffle=false must not route through shufflevector.
    CHECK(countOpcode(*M, static_cast<unsigned>(Instruction::ShuffleVector)) ==
          0u);

    // The first lifted binop's vector op keeps the exact name "morok.vec.op"
    // and is a 4-lane vector BinaryOperator.
    Instruction *VecOp = findNamedInstruction(*F, "morok.vec.op");
    REQUIRE(VecOp);
    CHECK(isa<BinaryOperator>(VecOp));
    auto *VecTy = dyn_cast<FixedVectorType>(VecOp->getType());
    REQUIRE(VecTy);
    CHECK(VecTy->getNumElements() == 4u);
}

TEST_CASE("vectorObfuscateFunction routes the real lane through a shuffle when "
          "enabled") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);

    auto rng = makeRng();
    CHECK(morok::passes::vectorObfuscateFunction(
        *F,
        {/*probability=*/100, /*width=*/128, /*shuffle=*/true,
         /*lift_comparisons=*/true},
        rng));

    // shuffle=true swaps the plain extract for a shufflevector + extract lane 0.
    CHECK(countOpcode(*M, static_cast<unsigned>(Instruction::ShuffleVector)) >
          0u);
    CHECK(hasNamedInstructionContaining(*F, "shuffle"));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("vectorObfuscateFunction honors the lift_comparisons gate") {
    LLVMContext ctx;
    auto Moff = parse(ctx, kCmpOnly);
    auto Mon = parse(ctx, kCmpOnly);
    Function *Foff = Moff->getFunction("cmponly");
    Function *Fon = Mon->getFunction("cmponly");
    REQUIRE(Foff);
    REQUIRE(Fon);

    auto rngOff = makeRng();
    // The only eligible op is the icmp; with lift_comparisons=false it is never
    // collected, so nothing changes.
    CHECK_FALSE(morok::passes::vectorObfuscateFunction(
        *Foff,
        {/*probability=*/100, /*width=*/128, /*shuffle=*/false,
         /*lift_comparisons=*/false},
        rngOff));
    CHECK(countNamedInstructions(*Foff, "morok.vec") == 0u);

    auto rngOn = makeRng();
    CHECK(morok::passes::vectorObfuscateFunction(
        *Fon,
        {/*probability=*/100, /*width=*/128, /*shuffle=*/false,
         /*lift_comparisons=*/true},
        rngOn));
    bool hasVectorICmp = false;
    for (Instruction &I : instructions(*Fon))
        if (auto *Cmp = dyn_cast<ICmpInst>(&I))
            hasVectorICmp |= Cmp->getType()->isVectorTy();
    CHECK(hasVectorICmp);
    CHECK_FALSE(verifyModule(*Moff));
    CHECK_FALSE(verifyModule(*Mon));
}

TEST_CASE("vectorObfuscateFunction widens lane count with a larger vector "
          "width") {
    LLVMContext ctx;
    auto M128 = parse(ctx, kArith);
    auto M256 = parse(ctx, kArith);

    auto engine128 = morok::core::Xoshiro256pp::fromSeed(0x51D);
    morok::ir::IRRandom rng128(engine128);
    auto engine256 = morok::core::Xoshiro256pp::fromSeed(0x51D);
    morok::ir::IRRandom rng256(engine256);

    CHECK(morok::passes::vectorObfuscateFunction(
        *M128->getFunction("arith"),
        {/*probability=*/100, /*width=*/128, /*shuffle=*/false,
         /*lift_comparisons=*/true},
        rng128));
    CHECK(morok::passes::vectorObfuscateFunction(
        *M256->getFunction("arith"),
        {/*probability=*/100, /*width=*/256, /*shuffle=*/false,
         /*lift_comparisons=*/true},
        rng256));

    // i32 at width 128 => 4 lanes; at width 256 => 8 lanes.  More lanes means
    // strictly more insertelement instructions for the same input.
    const std::size_t inserts128 =
        countOpcode(*M128, static_cast<unsigned>(Instruction::InsertElement));
    const std::size_t inserts256 =
        countOpcode(*M256, static_cast<unsigned>(Instruction::InsertElement));
    CHECK(inserts128 > 0u);
    CHECK(inserts256 > inserts128);
    CHECK_FALSE(verifyModule(*M128));
    CHECK_FALSE(verifyModule(*M256));
}

TEST_CASE("vectorObfuscateFunction leaves ops too wide for the vector "
          "untouched") {
    LLVMContext ctx;
    auto M = parse(ctx, kWideI128);
    Function *F = M->getFunction("wide");
    REQUIRE(F);
    const std::size_t before = instructionTotal(*F);

    auto rng = makeRng();
    // i128 at width 128 yields a single lane (< 2), so liftBinary declines and
    // the function is reported unchanged even at probability 100.
    CHECK_FALSE(morok::passes::vectorObfuscateFunction(
        *F,
        {/*probability=*/100, /*width=*/128, /*shuffle=*/false,
         /*lift_comparisons=*/true},
        rng));
    CHECK(instructionTotal(*F) == before);
    CHECK(countNamedInstructions(*F, "morok.vec") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("vectorObfuscateFunction caps the number of lifted operators") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("vec-cap", ctx);
    Type *i32 = Type::getInt32Ty(ctx);
    FunctionType *FT = FunctionType::get(i32, {i32, i32}, false);
    Function *F =
        Function::Create(FT, GlobalValue::ExternalLinkage, "bigadds", M.get());
    BasicBlock *BB = BasicBlock::Create(ctx, "entry", F);
    IRBuilder<> B(BB);
    Value *acc = F->getArg(0);
    Value *addend = F->getArg(1);
    // 130 eligible i32 adds, all sharing the "step" name prefix.
    const std::uint32_t kOps = 130u;
    for (std::uint32_t i = 0; i < kOps; ++i)
        acc = B.CreateAdd(acc, addend, "step");
    B.CreateRet(acc);
    REQUIRE(countNamedInstructions(*F, "step") == kOps);

    auto rng = makeRng();
    CHECK(morok::passes::vectorObfuscateFunction(
        *F,
        {/*probability=*/100, /*width=*/128, /*shuffle=*/false,
         /*lift_comparisons=*/false},
        rng));

    // Only the first 128 collected targets are lifted (kMaxVectorLiftTargets);
    // the erased originals leave 130 - 128 = 2 "step" instructions behind.
    CHECK(countNamedInstructions(*F, "step") == 2u);
    CHECK_FALSE(verifyModule(*M));
}
