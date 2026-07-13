// SPDX-License-Identifier: MIT
//
// Tests for MutualGuardGraph — an overlapping integrity guard graph whose
// combined checksum diff is fused into selected return values as data.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/MutualGuardGraph.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// Single eligible (i32) return with a few arithmetic ops to guard.
const char *kArith = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @arith(i32 %a, i32 %b) {
entry:
  %0 = add i32 %a, %b
  %1 = mul i32 %a, %b
  %2 = xor i32 %0, %1
  %3 = sub i32 %2, %a
  ret i32 %3
}
)ir";

// Two eligible returns in distinct blocks, for the max_returns cap.
const char *kTwoExits = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @twoexits(i32 %a) {
entry:
  %c = icmp sgt i32 %a, 0
  br i1 %c, label %pos, label %neg
pos:
  ret i32 %a
neg:
  %n = sub i32 0, %a
  ret i32 %n
}
)ir";

// No eligible return: `ret void` has no operand to poison.
const char *kVoidProc = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define void @proc(i32 %a) {
entry:
  ret void
}
)ir";

// A bare declaration — nothing to transform.
const char *kDecl = R"ir(
target triple = "x86_64-unknown-linux-gnu"

declare i32 @external(i32)
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

// Build params without brace-narrowing; fail_closed stays at its default.
morok::passes::MutualGuardGraphParams
makeParams(std::uint32_t prob = 100, std::uint32_t nodeCount = 3,
           std::uint32_t region = 32, std::uint32_t maxRet = 2) {
    morok::passes::MutualGuardGraphParams p;
    p.probability = prob;
    p.nodes = nodeCount;
    p.region_bytes = region;
    p.max_returns = maxRet;
    return p;
}

} // namespace

TEST_CASE("mutualGuardGraphFunction grows the module and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);

    const std::size_t funcsBefore = countFunctions(*M, "");
    const std::size_t globalsBefore = countGlobals(*M, "");

    auto rng = makeRng(1);
    CHECK(morok::passes::mutualGuardGraphFunction(*F, makeParams(), rng));

    // The graph adds per-node checkers plus a combining diff function, and the
    // node's checksum region/expected/code-size/native-expected globals.
    CHECK(countFunctions(*M, "") > funcsBefore);
    CHECK(countGlobals(*M, "") > globalsBefore);

    // Exactly `nodes` (=3) checker functions and one diff function for @arith.
    CHECK(countFunctions(*M, "morok.mg.node.arith.") == 3);
    CHECK(countFunctions(*M, "morok.mg.diff.") == 1);

    // Four private globals per node, plus a single post-link manifest.
    CHECK(countGlobals(*M, "morok.mg.region.arith.") == 3);
    CHECK(countGlobals(*M, "morok.mg.expected.arith.") == 3);
    CHECK(countGlobals(*M, "morok.mg.code.size.arith.") == 3);
    CHECK(countGlobals(*M, "morok.mg.native.expected.arith.") == 3);
    CHECK(countGlobals(*M, "morok.postlink.mg.") == 1);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mutualGuardGraphFunction poisons the return with a graph diff call") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);

    auto rng = makeRng(2);
    CHECK(morok::passes::mutualGuardGraphFunction(*F, makeParams(), rng));

    // A single call into the combining diff function is fused into the return.
    auto *call = dyn_cast_or_null<CallInst>(
        findNamedInstruction(*F, "morok.mg.diff.call"));
    REQUIRE(call);
    REQUIRE(call->getCalledFunction() != nullptr);
    CHECK(call->getCalledFunction()->getName().starts_with("morok.mg.diff."));

    // The poisoned integer return value is an XOR of the original bits with the
    // (truncated) graph diff.
    auto *poisoned = dyn_cast_or_null<BinaryOperator>(
        findNamedInstruction(*F, "morok.mg.value"));
    REQUIRE(poisoned);
    CHECK(poisoned->getOpcode() == Instruction::Xor);

    CHECK(countCallsToPrefix(*F, "morok.mg.diff") == 1);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mutualGuardGraphFunction respects probability=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);

    const std::size_t blocksBefore = F->size();
    auto rng = makeRng(3);
    CHECK_FALSE(morok::passes::mutualGuardGraphFunction(
        *F, makeParams(/*prob=*/0), rng));

    // Nothing emitted, nothing mutated.
    CHECK(F->size() == blocksBefore);
    CHECK(countFunctions(*M, "morok.mg.") == 0);
    CHECK(countGlobals(*M, "morok.mg.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mutualGuardGraphFunction rejects out-of-range parameters") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);

    auto rng = makeRng(4);
    // nodes < 2 is degenerate (a mutual graph needs at least two peers).
    CHECK_FALSE(morok::passes::mutualGuardGraphFunction(
        *F, makeParams(/*prob=*/100, /*nodeCount=*/1), rng));
    // region_bytes == 0 leaves nothing to hash.
    CHECK_FALSE(morok::passes::mutualGuardGraphFunction(
        *F, makeParams(/*prob=*/100, /*nodeCount=*/3, /*region=*/0), rng));
    // max_returns == 0 means no carrier for the diff.
    CHECK_FALSE(morok::passes::mutualGuardGraphFunction(
        *F, makeParams(/*prob=*/100, /*nodeCount=*/3, /*region=*/32,
                       /*maxRet=*/0),
        rng));

    CHECK(countFunctions(*M, "morok.mg.") == 0);
    CHECK(countGlobals(*M, "morok.mg.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mutualGuardGraphFunction is safe on declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, kDecl);
    Function *F = M->getFunction("external");
    REQUIRE(F);

    auto rng = makeRng(5);
    CHECK_FALSE(
        morok::passes::mutualGuardGraphFunction(*F, makeParams(), rng));
    CHECK(countFunctions(*M, "morok.mg.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mutualGuardGraphFunction skips functions with no eligible return") {
    LLVMContext ctx;
    auto M = parse(ctx, kVoidProc);
    Function *F = M->getFunction("proc");
    REQUIRE(F);

    auto rng = makeRng(6);
    // `ret void` carries no value to poison, so the pass declines.
    CHECK_FALSE(
        morok::passes::mutualGuardGraphFunction(*F, makeParams(), rng));
    CHECK(countFunctions(*M, "morok.mg.") == 0);
    CHECK(countGlobals(*M, "morok.mg.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mutualGuardGraphFunction is deterministic for a fixed seed") {
    LLVMContext ctxA;
    LLVMContext ctxB;
    auto MA = parse(ctxA, kArith);
    auto MB = parse(ctxB, kArith);

    // Two independent engines from the same seed must produce identical IR.
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xC0FFEE);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xC0FFEE);
    morok::ir::IRRandom rngA(engineA);
    morok::ir::IRRandom rngB(engineB);

    CHECK(morok::passes::mutualGuardGraphFunction(*MA->getFunction("arith"),
                                                  makeParams(), rngA));
    CHECK(morok::passes::mutualGuardGraphFunction(*MB->getFunction("arith"),
                                                  makeParams(), rngB));

    auto toText = [](Module &Mod) {
        std::string s;
        raw_string_ostream os(s);
        Mod.print(os, nullptr);
        os.flush();
        return s;
    };
    CHECK(toText(*MA) == toText(*MB));

    CHECK_FALSE(verifyModule(*MA));
    CHECK_FALSE(verifyModule(*MB));
}

TEST_CASE("mutualGuardGraphFunction does not reprocess a guarded function") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);

    auto rngFirst = makeRng(7);
    CHECK(morok::passes::mutualGuardGraphFunction(*F, makeParams(), rngFirst));
    const std::size_t nodesAfterFirst =
        countFunctions(*M, "morok.mg.node.arith.");
    CHECK(nodesAfterFirst == 3);

    // A second run sees the existing morok.mg.diff.arith and declines, so the
    // graph is not duplicated.
    auto rngSecond = makeRng(8);
    CHECK_FALSE(
        morok::passes::mutualGuardGraphFunction(*F, makeParams(), rngSecond));
    CHECK(countFunctions(*M, "morok.mg.node.arith.") == nodesAfterFirst);
    CHECK(countFunctions(*M, "morok.mg.diff.") == 1);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mutualGuardGraphFunction clamps the node count to 16") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);

    auto rng = makeRng(9);
    // Request far more nodes than the upper clamp allows.
    CHECK(morok::passes::mutualGuardGraphFunction(
        *F, makeParams(/*prob=*/100, /*nodeCount=*/100), rng));

    // clamp(nodes, 2, 16) => 16 checker functions and 16 checksum regions.
    CHECK(countFunctions(*M, "morok.mg.node.arith.") == 16);
    CHECK(countGlobals(*M, "morok.mg.region.arith.") == 16);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mutualGuardGraphFunction caps poisoned returns at max_returns") {
    LLVMContext ctx;
    auto M = parse(ctx, kTwoExits);
    Function *F = M->getFunction("twoexits");
    REQUIRE(F);

    auto rng = makeRng(10);
    // Two eligible returns, but max_returns=1 selects only one to poison.
    CHECK(morok::passes::mutualGuardGraphFunction(
        *F, makeParams(/*prob=*/100, /*nodeCount=*/3, /*region=*/32,
                       /*maxRet=*/1),
        rng));

    CHECK(countCallsToPrefix(*F, "morok.mg.diff") == 1);
    CHECK_FALSE(verifyModule(*M));
}
