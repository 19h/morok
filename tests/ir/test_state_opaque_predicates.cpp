// SPDX-License-Identifier: MIT
//
// Tests for StateOpaquePredicates — stateful MBA opaque predicates guarding
// flattened blocks with an evolving `fla.state`-driven, volatile-shadow token.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/StateOpaquePredicates.hpp"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;
using namespace morok::test;

namespace {

// A small flattened-style function: an entry `fla.state` slot plus a dispatch
// loop over three work blocks and an exit.  Every non-entry block has a real
// (non-PHI/alloca/terminator) first instruction, so all five are split
// candidates for the pass.
const char *kFlattened = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @flat(i32 %a, i32 %b) {
entry:
  %fla.state = alloca i32, align 4
  store i32 0, ptr %fla.state, align 4
  br label %dispatch

dispatch:
  %s = load i32, ptr %fla.state, align 4
  switch i32 %s, label %exit [
    i32 0, label %bb0
    i32 1, label %bb1
    i32 2, label %bb2
  ]

bb0:
  %x0 = add i32 %a, %b
  store i32 1, ptr %fla.state, align 4
  br label %dispatch

bb1:
  %x1 = mul i32 %a, %b
  store i32 2, ptr %fla.state, align 4
  br label %dispatch

bb2:
  %x2 = xor i32 %a, %b
  store i32 3, ptr %fla.state, align 4
  br label %dispatch

exit:
  %r = load i32, ptr %fla.state, align 4
  ret i32 %r
}
)ir";

// Same shape but with no `fla.state` alloca — the pass cannot find its anchor.
const char *kNoState = R"ir(
define i32 @nostate(i32 %a, i32 %b) {
entry:
  %c = icmp slt i32 %a, %b
  br i1 %c, label %t, label %f
t:
  %u = add i32 %a, %b
  ret i32 %u
f:
  %v = sub i32 %a, %b
  ret i32 %v
}
)ir";

// A single-block function that owns a `fla.state` slot but has no candidate
// block other than entry.
const char *kSingleBlockState = R"ir(
define i32 @lonely(i32 %x) {
entry:
  %fla.state = alloca i32, align 4
  store i32 0, ptr %fla.state, align 4
  %r = add i32 %x, 1
  ret i32 %r
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("stateOpaquePredicatesFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kFlattened);
    Function *F = M->getFunction("flat");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng();
    CHECK(morok::passes::stateOpaquePredicatesFunction(
        *F, {/*probability=*/100u, /*max_blocks=*/8u, /*max_terms=*/4u}, rng));
    // Each fired candidate contributes a split body block plus a false block.
    CHECK(F->size() > before);
    // The volatile shadow slot is materialised exactly once and reused.
    CHECK(countNamedAllocas(*F, "morok.stateop.shadow") == 1u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stateOpaquePredicatesFunction emits false edges, MBA and volatile "
          "shadow traffic") {
    LLVMContext ctx;
    auto M = parse(ctx, kFlattened);
    Function *F = M->getFunction("flat");
    REQUIRE(F);

    auto rng = makeRng();
    REQUIRE(morok::passes::stateOpaquePredicatesFunction(
        *F, {/*probability=*/100u, /*max_blocks=*/8u, /*max_terms=*/4u}, rng));

    bool hasFalseBlock = false;
    bool hasPredicate = false;
    bool hasStateLoad = false;
    bool hasMba = false;
    bool hasCancel = false;
    std::size_t volatileAccesses = 0;
    for (BasicBlock &BB : *F) {
        if (BB.getName().starts_with("morok.stateop.false"))
            hasFalseBlock = true;
        for (Instruction &I : BB) {
            if (I.getName().starts_with("morok.stateop.pred"))
                hasPredicate = true;
            if (I.getName().starts_with("morok.stateop.state"))
                hasStateLoad = true;
            if (I.getName().starts_with("morok.stateop.mba"))
                hasMba = true;
            if (I.getName().starts_with("morok.stateop.cancel"))
                hasCancel = true;
            if (auto *LI = dyn_cast<LoadInst>(&I))
                volatileAccesses += LI->isVolatile() ? 1u : 0u;
            if (auto *SI = dyn_cast<StoreInst>(&I))
                volatileAccesses += SI->isVolatile() ? 1u : 0u;
        }
    }
    CHECK(hasFalseBlock);
    CHECK(hasPredicate);
    CHECK(hasStateLoad);
    CHECK(hasMba);
    CHECK(hasCancel);
    // Per guard: two volatile stores + two volatile loads through the shadow,
    // plus one volatile store in the false block.
    CHECK(volatileAccesses >= 4u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stateOpaquePredicatesFunction returns false for zero probability") {
    LLVMContext ctx;
    auto M = parse(ctx, kFlattened);
    Function *F = M->getFunction("flat");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::stateOpaquePredicatesFunction(
        *F, {/*probability=*/0u, /*max_blocks=*/8u, /*max_terms=*/4u}, rng));
    CHECK(F->size() == before);
    CHECK(countNamedAllocas(*F, "morok.stateop.shadow") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stateOpaquePredicatesFunction returns false for zero max_blocks") {
    LLVMContext ctx;
    auto M = parse(ctx, kFlattened);
    Function *F = M->getFunction("flat");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::stateOpaquePredicatesFunction(
        *F, {/*probability=*/100u, /*max_blocks=*/0u, /*max_terms=*/4u}, rng));
    CHECK(F->size() == before);
    CHECK(countNamedAllocas(*F, "morok.stateop.shadow") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stateOpaquePredicatesFunction is a no-op without an fla.state slot") {
    LLVMContext ctx;
    auto M = parse(ctx, kNoState);
    Function *F = M->getFunction("nostate");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::stateOpaquePredicatesFunction(
        *F, {/*probability=*/100u, /*max_blocks=*/8u, /*max_terms=*/4u}, rng));
    CHECK(F->size() == before);
    CHECK(countNamedAllocas(*F, "morok.stateop.shadow") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stateOpaquePredicatesFunction is safe on declarations and "
          "single-block functions") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @external(i32)
)ir");
    Function *Ext = M->getFunction("external");
    REQUIRE(Ext);
    auto rng = makeRng();
    // Declarations have no body to transform.
    CHECK_FALSE(morok::passes::stateOpaquePredicatesFunction(
        *Ext, {/*probability=*/100u, /*max_blocks=*/8u, /*max_terms=*/4u}, rng));
    CHECK_FALSE(verifyModule(*M));

    LLVMContext ctx2;
    auto M2 = parse(ctx2, kSingleBlockState);
    Function *Lonely = M2->getFunction("lonely");
    REQUIRE(Lonely);
    const std::size_t before = Lonely->size();
    // Only the (excluded) entry block exists — nothing to guard.
    CHECK_FALSE(morok::passes::stateOpaquePredicatesFunction(
        *Lonely, {/*probability=*/100u, /*max_blocks=*/8u, /*max_terms=*/4u},
        rng));
    CHECK(Lonely->size() == before);
    CHECK(countNamedAllocas(*Lonely, "morok.stateop.shadow") == 0u);
    CHECK_FALSE(verifyModule(*M2));
}

TEST_CASE("stateOpaquePredicatesFunction respects the max_blocks cap") {
    LLVMContext ctx;
    auto M = parse(ctx, kFlattened);
    Function *F = M->getFunction("flat");
    REQUIRE(F);

    // Five split candidates exist; with certain firing and a cap of two, only
    // two guards (hence two false blocks) may be produced.
    auto rng = makeRng();
    CHECK(morok::passes::stateOpaquePredicatesFunction(
        *F, {/*probability=*/100u, /*max_blocks=*/2u, /*max_terms=*/4u}, rng));

    std::size_t falseBlocks = 0;
    for (BasicBlock &BB : *F)
        if (BB.getName().starts_with("morok.stateop.false"))
            ++falseBlocks;
    CHECK(falseBlocks == 2u);
    CHECK(countNamedAllocas(*F, "morok.stateop.shadow") == 1u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stateOpaquePredicatesFunction is deterministic for a fixed seed") {
    LLVMContext ctx;
    auto M1 = parse(ctx, kFlattened);
    auto M2 = parse(ctx, kFlattened);
    Function *F1 = M1->getFunction("flat");
    Function *F2 = M2->getFunction("flat");
    REQUIRE(F1);
    REQUIRE(F2);

    // Two independent engines seeded identically must drive identical output.
    auto engine1 = morok::core::Xoshiro256pp::fromSeed(0xABCDEF01u);
    morok::ir::IRRandom rng1(engine1);
    auto engine2 = morok::core::Xoshiro256pp::fromSeed(0xABCDEF01u);
    morok::ir::IRRandom rng2(engine2);

    const morok::passes::StateOpParams params{/*probability=*/100u,
                                              /*max_blocks=*/8u,
                                              /*max_terms=*/4u};
    CHECK(morok::passes::stateOpaquePredicatesFunction(*F1, params, rng1));
    CHECK(morok::passes::stateOpaquePredicatesFunction(*F2, params, rng2));

    std::string text1;
    std::string text2;
    raw_string_ostream os1(text1);
    raw_string_ostream os2(text2);
    M1->print(os1, nullptr);
    M2->print(os2, nullptr);
    os1.flush();
    os2.flush();
    CHECK(text1 == text2);
    CHECK_FALSE(verifyModule(*M1));
    CHECK_FALSE(verifyModule(*M2));
}

TEST_CASE("stateOpaquePredicatesFunction builds an equality predicate over a "
          "2xi32 shadow") {
    LLVMContext ctx;
    auto M = parse(ctx, kFlattened);
    Function *F = M->getFunction("flat");
    REQUIRE(F);

    auto rng = makeRng();
    REQUIRE(morok::passes::stateOpaquePredicatesFunction(
        *F, {/*probability=*/100u, /*max_blocks=*/8u, /*max_terms=*/4u}, rng));

    // The guard reduces to an ICMP_EQ producing an i1.
    auto *Pred =
        dyn_cast_or_null<ICmpInst>(findNamedInstruction(*F, "morok.stateop.pred"));
    REQUIRE(Pred);
    CHECK(Pred->getPredicate() == ICmpInst::ICMP_EQ);
    CHECK(Pred->getType()->isIntegerTy(1));

    // The cancellation shadow is a two-element i32 array.
    AllocaInst *Shadow = nullptr;
    for (Instruction &I : F->getEntryBlock())
        if (auto *AI = dyn_cast<AllocaInst>(&I))
            if (AI->getName().starts_with("morok.stateop.shadow")) {
                Shadow = AI;
                break;
            }
    REQUIRE(Shadow);
    auto *ArrTy = dyn_cast<ArrayType>(Shadow->getAllocatedType());
    REQUIRE(ArrTy);
    CHECK(ArrTy->getNumElements() == 2u);
    CHECK(ArrTy->getElementType()->isIntegerTy(32));
    CHECK_FALSE(verifyModule(*M));
}
