// SPDX-License-Identifier: MIT
//
// Tests for OptimizerAmplification — branchless, input-selected lattices of
// equivalent arithmetic/comparison forms (morok::passes::optimizerAmplifyFunction).

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/OptimizerAmplification.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// Six eligible integer binops (add/mul/xor/and/or/sub) in a single block.
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

// Exactly one eligible op, so per-op emission counts are unambiguous.
const char *kSingleAdd = R"ir(
define i32 @single_add(i32 %a, i32 %b) {
entry:
  %r = add i32 %a, %b
  ret i32 %r
}
)ir";

const char *kIntCompare = R"ir(
define i1 @icmp_lt(i32 %a, i32 %b) {
entry:
  %c = icmp slt i32 %a, %b
  ret i1 %c
}
)ir";

const char *kFloatCompare = R"ir(
define i1 @fcmp_lt(float %a, float %b) {
entry:
  %c = fcmp olt float %a, %b
  ret i1 %c
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::size_t instructionCount(Function &F) {
    std::size_t n = 0;
    for (Instruction &I : instructions(F))
        (void)I, ++n;
    return n;
}

} // namespace

TEST_CASE("optimizerAmplifyFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t beforeInsts = instructionCount(*F);
    const std::size_t beforeBinops = countBinops(*F);

    auto rng = makeRng();
    CHECK(morok::passes::optimizerAmplifyFunction(
        *F, {/*probability=*/100, /*max_forms=*/2}, rng));

    // Branchless amplification stays in one block but adds many instructions.
    CHECK(instructionCount(*F) > beforeInsts);
    CHECK(countBinops(*F) > beforeBinops);
    CHECK(countNamedInstructions(*F, "morok.optamp") > 0);
    CHECK(countOpcode(*M, Instruction::Select) > 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("optimizerAmplifyFunction respects probability=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = instructionCount(*F);

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::optimizerAmplifyFunction(
        *F, {/*probability=*/0, /*max_forms=*/2}, rng));
    CHECK(instructionCount(*F) == before);
    CHECK(countNamedInstructions(*F, "morok.optamp") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("optimizerAmplifyFunction respects max_forms=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = instructionCount(*F);

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::optimizerAmplifyFunction(
        *F, {/*probability=*/100, /*max_forms=*/0}, rng));
    CHECK(instructionCount(*F) == before);
    CHECK(countNamedInstructions(*F, "morok.optamp") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("optimizerAmplifyFunction is safe on declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @external(i32)
)ir");
    Function *F = M->getFunction("external");
    REQUIRE(F);

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::optimizerAmplifyFunction(
        *F, {/*probability=*/100, /*max_forms=*/2}, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("optimizerAmplifyFunction is deterministic for a fixed seed") {
    LLVMContext ctx;
    auto M1 = parse(ctx, kArith);
    auto M2 = parse(ctx, kArith);

    // Two independently-seeded engines with identical state must drive
    // identical salt/variant/guard choices, so the printed IR must match.
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0x51EDu);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0x51EDu);
    morok::ir::IRRandom rngA(engineA);
    morok::ir::IRRandom rngB(engineB);

    CHECK(morok::passes::optimizerAmplifyFunction(
        *M1->getFunction("arith"), {/*probability=*/100, /*max_forms=*/3}, rngA));
    CHECK(morok::passes::optimizerAmplifyFunction(
        *M2->getFunction("arith"), {/*probability=*/100, /*max_forms=*/3}, rngB));

    std::string t1;
    std::string t2;
    raw_string_ostream os1(t1);
    raw_string_ostream os2(t2);
    M1->getFunction("arith")->print(os1);
    M2->getFunction("arith")->print(os2);
    CHECK(os1.str() == os2.str());
    CHECK_FALSE(verifyModule(*M1));
    CHECK_FALSE(verifyModule(*M2));
}

TEST_CASE("optimizerAmplifyFunction emits base, guard and select constructs") {
    LLVMContext ctx;
    auto M = parse(ctx, kSingleAdd);
    Function *F = M->getFunction("single_add");
    REQUIRE(F);

    auto rng = makeRng();
    CHECK(morok::passes::optimizerAmplifyFunction(
        *F, {/*probability=*/100, /*max_forms=*/2}, rng));

    // The flag-free base op reproduces the original opcode.
    Instruction *baseAdd = findNamedInstruction(*F, "morok.optamp.base");
    REQUIRE(baseAdd != nullptr);
    auto *baseBinop = dyn_cast<BinaryOperator>(baseAdd);
    REQUIRE(baseBinop != nullptr);
    CHECK(baseBinop->getOpcode() == Instruction::Add);

    // The final input guard is an `icmp ne <bit>, 0`.
    Instruction *guard = findNamedInstruction(*F, "morok.optamp.guard");
    REQUIRE(guard != nullptr);
    auto *guardCmp = dyn_cast<ICmpInst>(guard);
    REQUIRE(guardCmp != nullptr);
    CHECK(guardCmp->getPredicate() == CmpInst::ICMP_NE);

    // One select per selected form: max_forms=2 -> exactly two selects.
    CHECK(countOpcode(*M, Instruction::Select) == 2);
    CHECK(countNamedInstructions(*F, "morok.optamp.select") == 2);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("optimizerAmplifyFunction clamps max_forms to at most four") {
    LLVMContext ctx;
    auto M = parse(ctx, kSingleAdd);
    Function *F = M->getFunction("single_add");
    REQUIRE(F);

    auto rng = makeRng();
    // max_forms is clamped to [1, 4]; a request of 32 yields exactly 4 forms.
    CHECK(morok::passes::optimizerAmplifyFunction(
        *F, {/*probability=*/100, /*max_forms=*/32}, rng));
    CHECK(countOpcode(*M, Instruction::Select) == 4);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("optimizerAmplifyFunction amplifies integer comparisons") {
    LLVMContext ctx;
    auto M = parse(ctx, kIntCompare);
    Function *F = M->getFunction("icmp_lt");
    REQUIRE(F);

    auto rng = makeRng();
    CHECK(morok::passes::optimizerAmplifyFunction(
        *F, {/*probability=*/100, /*max_forms=*/2}, rng));

    Instruction *baseCmp = findNamedInstruction(*F, "morok.optamp.base");
    REQUIRE(baseCmp != nullptr);
    auto *baseICmp = dyn_cast<ICmpInst>(baseCmp);
    REQUIRE(baseICmp != nullptr);
    CHECK(baseICmp->getPredicate() == CmpInst::ICMP_SLT);

    CHECK(countOpcode(*M, Instruction::Select) == 2);
    CHECK(countNamedInstructions(*F, "morok.optamp.cmp") > 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("optimizerAmplifyFunction amplifies floating-point comparisons") {
    LLVMContext ctx;
    auto M = parse(ctx, kFloatCompare);
    Function *F = M->getFunction("fcmp_lt");
    REQUIRE(F);

    auto rng = makeRng();
    CHECK(morok::passes::optimizerAmplifyFunction(
        *F, {/*probability=*/100, /*max_forms=*/2}, rng));

    Instruction *baseFcmp = findNamedInstruction(*F, "morok.optamp.base");
    REQUIRE(baseFcmp != nullptr);
    auto *baseFCmp = dyn_cast<FCmpInst>(baseFcmp);
    REQUIRE(baseFCmp != nullptr);
    CHECK(baseFCmp->getPredicate() == CmpInst::FCMP_OLT);

    // The float guard bitcasts operands to an integer carrier.
    Instruction *bits = findNamedInstruction(*F, "morok.optamp.guard.bits");
    REQUIRE(bits != nullptr);
    CHECK(isa<BitCastInst>(bits));

    CHECK(countOpcode(*M, Instruction::Select) == 2);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("optimizerAmplifyFunction leaves nothing eligible after a full pass") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);

    auto firstRng = makeRng();
    CHECK(morok::passes::optimizerAmplifyFunction(
        *F, {/*probability=*/100, /*max_forms=*/2}, firstRng));

    // Every emitted op is named "morok.optamp.*" and thus excluded by eligible();
    // a second full-probability pass therefore finds no target and returns false.
    auto secondRng = makeRng();
    CHECK_FALSE(morok::passes::optimizerAmplifyFunction(
        *F, {/*probability=*/100, /*max_forms=*/2}, secondRng));
    CHECK_FALSE(verifyModule(*M));
}
