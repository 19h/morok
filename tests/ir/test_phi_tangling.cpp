// SPDX-License-Identifier: MIT
//
// Tests for PhiTangling — redundant cross-block PHI/edge-copy webs around
// eligible scalar integer/FP PHIs (value-neutral, semantics-preserving).

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/PhiTangling.hpp"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// Diamond with a single eligible i32 PHI at the join.
const char *kIntDiamond = R"ir(
define i32 @diamond(i32 %a, i32 %b) {
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
  %r = add i32 %p, 7
  ret i32 %r
}
)ir";

// Diamond with a single eligible double PHI at the join.
const char *kFloatDiamond = R"ir(
define double @fdiamond(double %a, double %b, i1 %c) {
entry:
  br i1 %c, label %then, label %else
then:
  %t = fadd double %a, 1.000000e+00
  br label %join
else:
  %e = fsub double %b, 1.000000e+00
  br label %join
join:
  %p = phi double [ %t, %then ], [ %e, %else ]
  %r = fadd double %p, 2.000000e+00
  ret double %r
}
)ir";

// Switch join with two eligible i32 PHIs (used for the max_phis cap).
const char *kTwoPhis = R"ir(
define i32 @two_phis(i32 %a, i32 %b, i32 %c) {
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
  %p2 = phi i32 [ %a, %case1 ], [ %b, %case2 ], [ %c, %default ]
  %sum = add i32 %p1, %p2
  ret i32 %sum
}
)ir";

// Multi-block function with no PHIs at all.
const char *kNoPhi = R"ir(
define i32 @nophi(i32 %a, i32 %b) {
entry:
  %c = icmp slt i32 %a, %b
  br i1 %c, label %then, label %else
then:
  ret i32 %a
else:
  ret i32 %b
}
)ir";

const char *kDecl = R"ir(
declare i32 @external(i32)
)ir";

// Mandated RNG idiom: the static engine outlives every IRRandom that wraps it.
morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("phiTangleFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kIntDiamond);
    Function *F = M->getFunction("diamond");
    REQUIRE(F);
    const std::size_t phisBefore = countPhis(*F);
    const std::size_t binopsBefore = countBinops(*F);
    REQUIRE(phisBefore == 1u);

    auto rng = makeRng();
    CHECK(morok::passes::phiTangleFunction(
        *F, {/*probability=*/100u, /*layers=*/2u, /*max_phis=*/32u}, rng));
    // Two redundant PHIs (edge + direct) per layer are woven in.
    CHECK(countPhis(*F) > phisBefore);
    // XOR-based carrier arithmetic adds binary operators.
    CHECK(countBinops(*F) > binopsBefore);
    CHECK(countOpcode(*M, Instruction::Xor) > 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("phiTangleFunction respects probability=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kIntDiamond);
    Function *F = M->getFunction("diamond");
    REQUIRE(F);
    const std::size_t phisBefore = countPhis(*F);

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::phiTangleFunction(
        *F, {/*probability=*/0u, /*layers=*/2u, /*max_phis=*/32u}, rng));
    CHECK(countPhis(*F) == phisBefore);
    CHECK(countNamedInstructions(*F, "morok.phi") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("phiTangleFunction respects max_phis=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kIntDiamond);
    Function *F = M->getFunction("diamond");
    REQUIRE(F);
    const std::size_t phisBefore = countPhis(*F);

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::phiTangleFunction(
        *F, {/*probability=*/100u, /*layers=*/2u, /*max_phis=*/0u}, rng));
    CHECK(countPhis(*F) == phisBefore);
    CHECK(countNamedInstructions(*F, "morok.phi") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("phiTangleFunction is safe on declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, kDecl);
    Function *F = M->getFunction("external");
    REQUIRE(F);

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::phiTangleFunction(
        *F, {/*probability=*/100u, /*layers=*/2u, /*max_phis=*/32u}, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("phiTangleFunction is a no-op on functions without eligible PHIs") {
    LLVMContext ctx;
    auto M = parse(ctx, kNoPhi);
    Function *F = M->getFunction("nophi");
    REQUIRE(F);
    REQUIRE(countPhis(*F) == 0u);

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::phiTangleFunction(
        *F, {/*probability=*/100u, /*layers=*/2u, /*max_phis=*/32u}, rng));
    CHECK(countPhis(*F) == 0u);
    CHECK(countNamedInstructions(*F, "morok.phi") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("phiTangleFunction emits named PHI-web instructions and no globals") {
    LLVMContext ctx;
    auto M = parse(ctx, kIntDiamond);
    Function *F = M->getFunction("diamond");
    REQUIRE(F);

    auto rng = makeRng();
    CHECK(morok::passes::phiTangleFunction(
        *F, {/*probability=*/100u, /*layers=*/2u, /*max_phis=*/32u}, rng));

    // Every generated value carries the "morok.phi" prefix; the distinct
    // carrier steps are all present.
    CHECK(countNamedInstructions(*F, "morok.phi.direct") > 0u);
    CHECK(countNamedInstructions(*F, "morok.phi.edge") > 0u);
    CHECK(countNamedInstructions(*F, "morok.phi.zero") > 0u);
    CHECK(countNamedInstructions(*F, "morok.phi.value") > 0u);

    // The "direct" clone is a PHINode.
    Instruction *direct = findNamedInstruction(*F, "morok.phi.direct");
    REQUIRE(direct != nullptr);
    CHECK(dyn_cast<PHINode>(direct) != nullptr);

    // This is a purely intra-function transform: it materialises no globals and
    // no helper functions.
    CHECK(countGlobals(*M, "morok") == 0u);
    CHECK(countFunctions(*M, "morok") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("phiTangleFunction adds two PHIs per layer") {
    LLVMContext ctx;
    auto M1 = parse(ctx, kIntDiamond);
    auto M2 = parse(ctx, kIntDiamond);
    Function *F1 = M1->getFunction("diamond");
    Function *F2 = M2->getFunction("diamond");
    REQUIRE(F1);
    REQUIRE(F2);

    auto rng1 = makeRng();
    auto rng2 = makeRng();
    CHECK(morok::passes::phiTangleFunction(
        *F1, {/*probability=*/100u, /*layers=*/1u, /*max_phis=*/32u}, rng1));
    CHECK(morok::passes::phiTangleFunction(
        *F2, {/*probability=*/100u, /*layers=*/3u, /*max_phis=*/32u}, rng2));

    // One eligible PHI + 2 PHIs (edge + direct) per layer.
    CHECK(countPhis(*F1) == 1u + 2u * 1u);
    CHECK(countPhis(*F2) == 1u + 2u * 3u);
    CHECK(countPhis(*F2) > countPhis(*F1));
    CHECK_FALSE(verifyModule(*M1));
    CHECK_FALSE(verifyModule(*M2));
}

TEST_CASE("phiTangleFunction caps tangled PHIs at max_phis") {
    LLVMContext ctx;
    auto Mcap = parse(ctx, kTwoPhis);
    auto Mall = parse(ctx, kTwoPhis);
    Function *Fcap = Mcap->getFunction("two_phis");
    Function *Fall = Mall->getFunction("two_phis");
    REQUIRE(Fcap);
    REQUIRE(Fall);
    REQUIRE(countPhis(*Fcap) == 2u);

    auto rngCap = makeRng();
    auto rngAll = makeRng();
    // probability=100 tangles every selected PHI, so counts are deterministic
    // regardless of the shuffle order.
    CHECK(morok::passes::phiTangleFunction(
        *Fcap, {/*probability=*/100u, /*layers=*/1u, /*max_phis=*/1u}, rngCap));
    CHECK(morok::passes::phiTangleFunction(
        *Fall, {/*probability=*/100u, /*layers=*/1u, /*max_phis=*/32u}, rngAll));

    // Cap of 1 tangles exactly one of the two PHIs: 2 + 2 = 4.
    CHECK(countPhis(*Fcap) == 4u);
    // Uncapped tangles both PHIs: 2 + 2 + 2 = 6.
    CHECK(countPhis(*Fall) == 6u);
    CHECK(countPhis(*Fcap) < countPhis(*Fall));
    CHECK_FALSE(verifyModule(*Mcap));
    CHECK_FALSE(verifyModule(*Mall));
}

TEST_CASE("phiTangleFunction is deterministic for a fixed seed") {
    LLVMContext ctx;
    auto MA = parse(ctx, kIntDiamond);
    auto MB = parse(ctx, kIntDiamond);
    Function *FA = MA->getFunction("diamond");
    Function *FB = MB->getFunction("diamond");
    REQUIRE(FA);
    REQUIRE(FB);

    const morok::passes::PhiTangleParams params{/*probability=*/100u,
                                                /*layers=*/2u,
                                                /*max_phis=*/32u};

    // Two independent engines seeded identically must drive identical output.
    std::string textA;
    std::string textB;
    {
        auto engineA = morok::core::Xoshiro256pp::fromSeed(0x9E37u);
        morok::ir::IRRandom rngA(engineA);
        CHECK(morok::passes::phiTangleFunction(*FA, params, rngA));
        raw_string_ostream osA(textA);
        MA->print(osA, nullptr);
    }
    {
        auto engineB = morok::core::Xoshiro256pp::fromSeed(0x9E37u);
        morok::ir::IRRandom rngB(engineB);
        CHECK(morok::passes::phiTangleFunction(*FB, params, rngB));
        raw_string_ostream osB(textB);
        MB->print(osB, nullptr);
    }

    CHECK(textA == textB);
    CHECK_FALSE(verifyModule(*MA));
    CHECK_FALSE(verifyModule(*MB));
}

TEST_CASE("phiTangleFunction tangles floating-point PHIs via integer carriers") {
    LLVMContext ctx;
    auto M = parse(ctx, kFloatDiamond);
    Function *F = M->getFunction("fdiamond");
    REQUIRE(F);
    REQUIRE(countPhis(*F) == 1u);
    REQUIRE(countOpcode(*M, Instruction::BitCast) == 0u);

    auto rng = makeRng();
    CHECK(morok::passes::phiTangleFunction(
        *F, {/*probability=*/100u, /*layers=*/2u, /*max_phis=*/32u}, rng));

    // FP PHIs are routed through an integer carrier, so bitcasts appear.
    CHECK(countOpcode(*M, Instruction::BitCast) > 0u);
    CHECK(countNamedInstructions(*F, "morok.phi.bits") > 0u);
    CHECK(countPhis(*F) > 1u);
    CHECK_FALSE(verifyModule(*M));
}
