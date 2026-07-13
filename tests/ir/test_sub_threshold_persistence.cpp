// SPDX-License-Identifier: MIT
//
// Tests for SubThresholdPersistence — wraps eligible scalar binops in bounded
// opaque-zero webs seeded from a private volatile stack slot.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/SubThresholdPersistence.hpp"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// Four eligible integer binops (add/sub/mul/xor), all i64 so the seed loads
// need no width cast.
const char *kMultiInt = R"ir(
define i64 @multi(i64 %a, i64 %b) {
entry:
  %x0 = add i64 %a, %b
  %x1 = sub i64 %x0, %a
  %x2 = mul i64 %x1, %b
  %x3 = xor i64 %x2, %a
  ret i64 %x3
}
)ir";

// Exactly one eligible i64 op — keeps per-op counts unambiguous.
const char *kSingleInt = R"ir(
define i64 @single(i64 %a, i64 %b) {
entry:
  %r = add i64 %a, %b
  ret i64 %r
}
)ir";

// No BinaryOperator at all — targets vector stays empty.
const char *kNoEligible = R"ir(
define i32 @noeligible(i32 %x) {
entry:
  ret i32 %x
}
)ir";

const char *kDecl = R"ir(
declare i32 @ext(i32)
)ir";

// fast-math flags make a float op ineligible.
const char *kOnlyFast = R"ir(
define double @onlyfast(double %a, double %b) {
entry:
  %f = fadd fast double %a, %b
  ret double %f
}
)ir";

// A plain (no fast-math) float op is eligible and takes the bitcast carrier.
const char *kPlainFloat = R"ir(
define double @plainfloat(double %a, double %b) {
entry:
  %f = fadd double %a, %b
  ret double %f
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("subThresholdPersistFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kMultiInt);
    Function *F = M->getFunction("multi");
    REQUIRE(F);
    const std::size_t beforeBinops = countBinops(*F);

    auto rng = makeRng();
    CHECK(morok::passes::subThresholdPersistFunction(
        *F, {/*probability=*/100u, /*max_terms=*/1u}, rng));
    // Each wrapped op adds a base clone plus opaque-zero binops.
    CHECK(countBinops(*F) > beforeBinops);
    CHECK(countNamedInstructions(*F, "morok.threshold") > 0);
    // The private seed slot is materialised exactly once.
    CHECK(countNamedAllocas(*F, "morok.threshold.seed") == 1);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("subThresholdPersistFunction respects probability=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kMultiInt);
    Function *F = M->getFunction("multi");
    REQUIRE(F);
    const std::size_t before = countBinops(*F);

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::subThresholdPersistFunction(
        *F, {/*probability=*/0u, /*max_terms=*/1u}, rng));
    CHECK(countBinops(*F) == before);
    CHECK(countNamedAllocas(*F, "morok.threshold.seed") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("subThresholdPersistFunction respects max_terms=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kMultiInt);
    Function *F = M->getFunction("multi");
    REQUIRE(F);
    const std::size_t before = countBinops(*F);

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::subThresholdPersistFunction(
        *F, {/*probability=*/100u, /*max_terms=*/0u}, rng));
    CHECK(countBinops(*F) == before);
    CHECK(countNamedAllocas(*F, "morok.threshold.seed") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("subThresholdPersistFunction skips declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, kDecl);
    Function *F = M->getFunction("ext");
    REQUIRE(F);

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::subThresholdPersistFunction(
        *F, {/*probability=*/100u, /*max_terms=*/1u}, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("subThresholdPersistFunction is a no-op without eligible ops") {
    LLVMContext ctx;
    auto M = parse(ctx, kNoEligible);
    Function *F = M->getFunction("noeligible");
    REQUIRE(F);

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::subThresholdPersistFunction(
        *F, {/*probability=*/100u, /*max_terms=*/1u}, rng));
    CHECK(countNamedAllocas(*F, "morok.threshold.seed") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("subThresholdPersistFunction is deterministic for a fixed seed") {
    LLVMContext ctxA;
    auto MA = parse(ctxA, kMultiInt);
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xC0FFEEULL);
    morok::ir::IRRandom rngA(engineA);
    CHECK(morok::passes::subThresholdPersistFunction(
        *MA->getFunction("multi"), {/*probability=*/100u, /*max_terms=*/3u},
        rngA));

    LLVMContext ctxB;
    auto MB = parse(ctxB, kMultiInt);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xC0FFEEULL);
    morok::ir::IRRandom rngB(engineB);
    CHECK(morok::passes::subThresholdPersistFunction(
        *MB->getFunction("multi"), {/*probability=*/100u, /*max_terms=*/3u},
        rngB));

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
    CHECK(textA == textB);
    CHECK_FALSE(verifyModule(*MA));
}

TEST_CASE("subThresholdPersistFunction clamps max_terms to six") {
    // One eligible op -> the number of opaque-zero terms equals the clamped
    // per-op term count, so both 6 and 100 must yield exactly six.
    LLVMContext ctx6;
    auto M6 = parse(ctx6, kSingleInt);
    auto rng6 = makeRng();
    CHECK(morok::passes::subThresholdPersistFunction(
        *M6->getFunction("single"), {/*probability=*/100u, /*max_terms=*/6u},
        rng6));

    LLVMContext ctxBig;
    auto MBig = parse(ctxBig, kSingleInt);
    auto rngBig = makeRng();
    CHECK(morok::passes::subThresholdPersistFunction(
        *MBig->getFunction("single"),
        {/*probability=*/100u, /*max_terms=*/100u}, rngBig));

    const std::size_t terms6 =
        countNamedInstructions(*M6->getFunction("single"),
                               "morok.threshold.zero");
    const std::size_t termsBig =
        countNamedInstructions(*MBig->getFunction("single"),
                               "morok.threshold.zero");
    CHECK(terms6 == 6);
    CHECK(termsBig == 6);
    CHECK(termsBig == terms6);
    CHECK_FALSE(verifyModule(*M6));
    CHECK_FALSE(verifyModule(*MBig));
}

TEST_CASE("subThresholdPersistFunction emits volatile seed loads and named "
          "web instructions") {
    LLVMContext ctx;
    auto M = parse(ctx, kSingleInt);
    Function *F = M->getFunction("single");
    REQUIRE(F);

    auto rng = makeRng();
    CHECK(morok::passes::subThresholdPersistFunction(
        *F, {/*probability=*/100u, /*max_terms=*/1u}, rng));

    // One op, one term: exactly one base clone, one opaque zero, two loads.
    CHECK(countNamedAllocas(*F, "morok.threshold.seed") == 1);
    CHECK(countNamedInstructions(*F, "morok.threshold.base") == 1);
    CHECK(countNamedInstructions(*F, "morok.threshold.zero") == 1);
    CHECK(countNamedInstructions(*F, "morok.threshold.load") == 2);

    // The seed reads must be volatile — that is what keeps the two loads
    // distinct side-effecting SSA values.
    auto *loadA = dyn_cast_or_null<LoadInst>(
        findNamedInstruction(*F, "morok.threshold.load.a"));
    REQUIRE(loadA);
    CHECK(loadA->isVolatile());
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("subThresholdPersistFunction shares one seed across wrapped ops") {
    LLVMContext ctx;
    auto M = parse(ctx, kMultiInt);
    Function *F = M->getFunction("multi");
    REQUIRE(F);

    auto rng = makeRng();
    CHECK(morok::passes::subThresholdPersistFunction(
        *F, {/*probability=*/100u, /*max_terms=*/1u}, rng));

    // All four eligible ops get wrapped (probability=100 always fires), each
    // contributing one base clone, but only a single shared seed slot.
    CHECK(countNamedAllocas(*F, "morok.threshold.seed") == 1);
    CHECK(countNamedInstructions(*F, "morok.threshold.base") == 4);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("subThresholdPersistFunction wraps plain floats but skips fast-math") {
    // fast-math op: ineligible, nothing emitted.
    LLVMContext ctxFast;
    auto MFast = parse(ctxFast, kOnlyFast);
    auto rngFast = makeRng();
    CHECK_FALSE(morok::passes::subThresholdPersistFunction(
        *MFast->getFunction("onlyfast"),
        {/*probability=*/100u, /*max_terms=*/1u}, rngFast));
    CHECK(countNamedAllocas(*MFast->getFunction("onlyfast"),
                            "morok.threshold.seed") == 0);
    CHECK_FALSE(verifyModule(*MFast));

    // plain float op: eligible, wrapped through the integer bitcast carrier.
    LLVMContext ctxPlain;
    auto MPlain = parse(ctxPlain, kPlainFloat);
    Function *FPlain = MPlain->getFunction("plainfloat");
    REQUIRE(FPlain);
    auto rngPlain = makeRng();
    CHECK(morok::passes::subThresholdPersistFunction(
        *FPlain, {/*probability=*/100u, /*max_terms=*/1u}, rngPlain));
    CHECK(countNamedAllocas(*FPlain, "morok.threshold.seed") == 1);
    CHECK(countNamedInstructions(*FPlain, "morok.threshold.base") == 1);
    CHECK(countNamedInstructions(*FPlain, "morok.threshold.zero") == 1);
    // The float path bitcasts the running value into the integer carrier.
    CHECK(countOpcode(*MPlain, Instruction::BitCast) >= 1);
    CHECK_FALSE(verifyModule(*MPlain));
}
