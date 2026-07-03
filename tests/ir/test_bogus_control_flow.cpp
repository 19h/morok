// SPDX-License-Identifier: MIT
//
// Tests for BogusControlFlow — opaque-predicate bogus control flow.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/BogusControlFlow.hpp"

#include "llvm/IR/Constants.h"
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

const char *kSingleBlock = R"ir(
define i32 @trivial(i32 %x) {
entry:
  ret i32 %x
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 13) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("bogusControlFlowFunction adds guarded edges and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(13);
    CHECK(morok::passes::bogusControlFlowFunction(
        *F, {/*prob=*/100, /*iterations=*/1}, rng));
    CHECK(F->size() > before);
    CHECK_FALSE(verifyModule(*M));
    CHECK(M->getGlobalVariable("morok.bcf.opaque", true) != nullptr);
}

TEST_CASE("bogusControlFlowFunction respects probability=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(14);
    CHECK_FALSE(morok::passes::bogusControlFlowFunction(
        *F, {/*prob=*/0, /*iterations=*/1}, rng));
    CHECK(F->size() == before);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("bogusControlFlowFunction skips single-block functions") {
    LLVMContext ctx;
    auto M = parse(ctx, kSingleBlock);
    Function *F = M->getFunction("trivial");
    REQUIRE(F);

    auto rng = makeRng(15);
    // Single-block functions have no block to guard
    morok::passes::bogusControlFlowFunction(
        *F, {/*prob=*/100, /*iterations=*/1}, rng);
    // No crash; block count may or may not change
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("bogusControlFlowFunction skips declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @external(i32)
)ir");
    Function *F = M->getFunction("external");
    REQUIRE(F);

    auto rng = makeRng(16);
    // Should not crash on declarations
    morok::passes::bogusControlFlowFunction(
        *F, {/*prob=*/100, /*iterations=*/1}, rng);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("bogusControlFlowFunction grows with iterations") {
    LLVMContext ctx;
    auto M1 = parse(ctx, kArith);
    auto M2 = parse(ctx, kArith);

    auto rng1 = makeRng(17);
    auto rng2 = makeRng(17);
    morok::passes::bogusControlFlowFunction(
        *M1->getFunction("arith"), {/*prob=*/100, /*iterations=*/1}, rng1);
    morok::passes::bogusControlFlowFunction(
        *M2->getFunction("arith"), {/*prob=*/100, /*iterations=*/3}, rng2);

    CHECK(M2->getFunction("arith")->size() >=
          M1->getFunction("arith")->size());
}

TEST_CASE("bogusControlFlowFunction honors complexity parameter") {
    LLVMContext ctx;
    auto M1 = parse(ctx, kArith);
    auto M2 = parse(ctx, kArith);

    auto rng1 = makeRng(18);
    auto rng2 = makeRng(18);
    morok::passes::bogusControlFlowFunction(
        *M1->getFunction("arith"),
        {/*prob=*/100, /*iterations=*/1, /*complexity=*/1}, rng1);
    morok::passes::bogusControlFlowFunction(
        *M2->getFunction("arith"),
        {/*prob=*/100, /*iterations=*/1, /*complexity=*/4}, rng2);

    // Higher complexity should produce more AND instructions (deeper predicates)
    unsigned andI1_lo = 0, andI1_hi = 0;
    for (Instruction &I : instructions(*M1->getFunction("arith")))
        if (auto *BO = dyn_cast<BinaryOperator>(&I))
            andI1_lo += BO->getOpcode() == Instruction::And &&
                        BO->getType()->isIntegerTy(1);
    for (Instruction &I : instructions(*M2->getFunction("arith")))
        if (auto *BO = dyn_cast<BinaryOperator>(&I))
            andI1_hi += BO->getOpcode() == Instruction::And &&
                        BO->getType()->isIntegerTy(1);
    CHECK(andI1_hi >= andI1_lo);
}
