// SPDX-License-Identifier: MIT
//
// Tests for SplitBasicBlocks — cleaves each block into several smaller ones at
// random instruction boundaries (unconditional fall-through edges only).

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/SplitBasicBlocks.hpp"

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

// Straight-line block with six non-terminator instructions: five candidate cut
// points, so at least one split is guaranteed to fire.
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

// One real instruction plus a terminator: the impl requires both halves to keep
// a real instruction, so there is no valid cut point here.
const char *kMinimal = R"ir(
define i32 @minimal(i32 %x) {
entry:
  %r = add i32 %x, 1
  ret i32 %r
}
)ir";

// A PHI-carrying loop: the loop body has one candidate cut point after the PHI.
const char *kLoop = R"ir(
define i32 @loop(i32 %n) {
entry:
  br label %loop
loop:
  %i = phi i32 [ 0, %entry ], [ %next, %loop ]
  %next = add i32 %i, 1
  %done = icmp sge i32 %next, %n
  br i1 %done, label %exit, label %loop
exit:
  ret i32 %next
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("splitBlocksFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(0x1337);
    morok::passes::SplitParams params{/*splits=*/3u, /*stack_confusion=*/false};
    CHECK(morok::passes::splitBlocksFunction(*F, params, rng));
    // Every SplitBlock introduces exactly one new fall-through block.
    CHECK(F->size() > before);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("splitBlocksFunction respects splits=0 as a no-op") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(0x2001);
    morok::passes::SplitParams params{/*splits=*/0u, /*stack_confusion=*/false};
    // splits == 0 bails out before touching the function.
    CHECK_FALSE(morok::passes::splitBlocksFunction(*F, params, rng));
    CHECK(F->size() == before);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("splitBlocksFunction is safe on declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @external(i32)
)ir");
    Function *F = M->getFunction("external");
    REQUIRE(F);

    auto rng = makeRng(0x3003);
    morok::passes::SplitParams params{/*splits=*/3u, /*stack_confusion=*/true};
    // A declaration has no blocks, so nothing is split and no decoys are made.
    CHECK_FALSE(morok::passes::splitBlocksFunction(*F, params, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("splitBlocksFunction leaves a minimal block unsplit") {
    LLVMContext ctx;
    auto M = parse(ctx, kMinimal);
    Function *F = M->getFunction("minimal");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(0x4004);
    morok::passes::SplitParams params{/*splits=*/5u, /*stack_confusion=*/false};
    // Only one non-terminator instruction means zero valid cut points: splitting
    // would leave an empty head, so the pass declines.
    CHECK_FALSE(morok::passes::splitBlocksFunction(*F, params, rng));
    CHECK(F->size() == before);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("splitBlocksFunction caps new blocks at the splits budget") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(0x5005);
    const std::uint32_t budget = 3u;
    morok::passes::SplitParams params{budget, /*stack_confusion=*/false};
    CHECK(morok::passes::splitBlocksFunction(*F, params, rng));
    // The single original block is cleaved at most `splits` times, so growth is
    // bounded by the budget and is at least one.
    CHECK(F->size() > before);
    CHECK(F->size() <= before + budget);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("splitBlocksFunction is deterministic for a fixed seed") {
    LLVMContext ctx;
    auto M1 = parse(ctx, kArith);
    auto M2 = parse(ctx, kArith);

    // Fresh, independent engines from the same seed must reproduce identical IR.
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0x600d);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0x600d);
    morok::ir::IRRandom rngA(engineA);
    morok::ir::IRRandom rngB(engineB);

    morok::passes::SplitParams params{/*splits=*/3u, /*stack_confusion=*/true};
    CHECK(morok::passes::splitBlocksFunction(*M1->getFunction("arith"), params,
                                             rngA));
    CHECK(morok::passes::splitBlocksFunction(*M2->getFunction("arith"), params,
                                             rngB));

    auto printModule = [](Module &mod) {
        std::string text;
        raw_string_ostream os(text);
        mod.print(os, nullptr);
        os.flush();
        return text;
    };
    CHECK(printModule(*M1) == printModule(*M2));
    CHECK_FALSE(verifyModule(*M1));
    CHECK_FALSE(verifyModule(*M2));
}

TEST_CASE("splitBlocksFunction preserves PHI nodes") {
    LLVMContext ctx;
    auto M = parse(ctx, kLoop);
    Function *F = M->getFunction("loop");
    REQUIRE(F);
    const std::size_t before = F->size();
    const std::size_t phisBefore = countPhis(*F);
    REQUIRE(phisBefore == 1u);

    auto rng = makeRng(0x7007);
    morok::passes::SplitParams params{/*splits=*/3u, /*stack_confusion=*/false};
    CHECK(morok::passes::splitBlocksFunction(*F, params, rng));
    // Cuts only happen after the PHIs, so PHI count is untouched and the CFG
    // stays valid despite the rerouted loop back-edge.
    CHECK(F->size() > before);
    CHECK(countPhis(*F) == phisBefore);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("splitBlocksFunction with stack_confusion emits volatile decoy slots") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);

    auto rng = makeRng(0x8008);
    morok::passes::SplitParams params{/*splits=*/3u, /*stack_confusion=*/true};
    CHECK(morok::passes::splitBlocksFunction(*F, params, rng));

    // Exactly kDecoySlotCount (3) decoy stack slots are materialized once.
    CHECK(countNamedAllocas(*F, "morok.split.decoy") == 3u);
    // At least one volatile load/store pair is pushed at a split boundary.
    CHECK(countNamedInstructions(*F, "morok.split.decoy.load") >= 1u);

    auto *load = dyn_cast_or_null<LoadInst>(
        findNamedInstruction(*F, "morok.split.decoy.load"));
    REQUIRE(load != nullptr);
    CHECK(load->isVolatile());

    bool sawVolatileStore = false;
    for (Instruction &I : instructions(*F))
        if (auto *st = dyn_cast<StoreInst>(&I))
            if (st->isVolatile()) {
                sawVolatileStore = true;
                break;
            }
    CHECK(sawVolatileStore);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("splitBlocksFunction without stack_confusion adds no decoy slots") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(0x9009);
    morok::passes::SplitParams params{/*splits=*/3u, /*stack_confusion=*/false};
    CHECK(morok::passes::splitBlocksFunction(*F, params, rng));
    // Splitting still happens, but no decoy allocas or volatile traffic appear.
    CHECK(F->size() > before);
    CHECK(countNamedAllocas(*F, "morok.split.decoy") == 0u);
    CHECK(countNamedInstructions(*F, "morok.split.decoy.load") == 0u);
    CHECK_FALSE(verifyModule(*M));
}
