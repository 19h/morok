// SPDX-License-Identifier: MIT
//
// Tests for CoherentDecoys — opaque-guarded dead alternate return arms whose
// bodies compute type-correct values from real inputs (coherent, not junk).

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/CoherentDecoys.hpp"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"

using namespace llvm;
using namespace morok::test;

namespace {

// Single wide-integer return with several computed live values available as
// decoy terms.  i64 return width sidesteps the target's small-integer skip, so
// the pass fires identically on every host/triple in CI.
const char *kIntReturn = R"ir(
define i64 @compute(i64 %a, i64 %b) {
entry:
  %s = add i64 %a, %b
  %m = mul i64 %s, %b
  %x = xor i64 %m, %a
  ret i64 %x
}
)ir";

// Four eligible i64 returns to exercise the max_blocks cap.
const char *kMultiReturn = R"ir(
define i64 @multiret(i64 %a, i64 %b, i64 %c) {
entry:
  %c0 = icmp slt i64 %a, %b
  br i1 %c0, label %p1, label %rest
p1:
  %r1 = add i64 %a, %c
  ret i64 %r1
rest:
  %c1 = icmp slt i64 %b, %c
  br i1 %c1, label %p2, label %more
p2:
  %r2 = mul i64 %b, %c
  ret i64 %r2
more:
  %c2 = icmp eq i64 %a, %c
  br i1 %c2, label %p3, label %p4
p3:
  %r3 = sub i64 %c, %a
  ret i64 %r3
p4:
  %r4 = xor i64 %a, %b
  ret i64 %r4
}
)ir";

// Floating-point return exercises the fp decoy builder (fadd/fmul/fsub).
const char *kFpReturn = R"ir(
define double @fcompute(double %a, double %b) {
entry:
  %s = fadd double %a, %b
  %m = fmul double %s, %b
  ret double %m
}
)ir";

const char *kDecl = R"ir(
declare i64 @ext(i64)
)ir";

// Void return has no computed value, so no arm is eligible.
const char *kVoid = R"ir(
define void @noret(i64 %a) {
entry:
  ret void
}
)ir";

// A morok-prefixed function must be skipped wholesale.
const char *kMorokName = R"ir(
define i64 @morok.helper(i64 %a) {
entry:
  %r = add i64 %a, 1
  ret i64 %r
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::size_t countDecoyAltBlocks(Function &F) {
    std::size_t n = 0;
    for (BasicBlock &BB : F)
        if (BB.getName().starts_with("morok.decoy.alt"))
            ++n;
    return n;
}

} // namespace

TEST_CASE("coherentDecoysFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kIntReturn);
    Function *F = M->getFunction("compute");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(0x1337);
    CHECK(morok::passes::coherentDecoysFunction(
        *F, {/*probability=*/100, /*max_blocks=*/4, /*depth=*/3}, rng));

    // One eligible return split into head + real + alt: block count grows.
    CHECK(F->size() > before);
    // Both private carrier globals are materialised on the first rewrite.
    CHECK(countGlobals(*M, "morok.decoy.") == 2);
    CHECK(M->getGlobalVariable("morok.decoy.opaque", true) != nullptr);
    CHECK(M->getGlobalVariable("morok.decoy.state", true) != nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("coherentDecoysFunction respects probability=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kIntReturn);
    Function *F = M->getFunction("compute");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(0x2001);
    CHECK_FALSE(morok::passes::coherentDecoysFunction(
        *F, {/*probability=*/0, /*max_blocks=*/4, /*depth=*/3}, rng));
    CHECK(F->size() == before);
    CHECK(countGlobals(*M, "morok.decoy.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("coherentDecoysFunction respects max_blocks=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kIntReturn);
    Function *F = M->getFunction("compute");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(0x2002);
    CHECK_FALSE(morok::passes::coherentDecoysFunction(
        *F, {/*probability=*/100, /*max_blocks=*/0, /*depth=*/3}, rng));
    CHECK(F->size() == before);
    CHECK(countGlobals(*M, "morok.decoy.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("coherentDecoysFunction is safe on declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, kDecl);
    Function *F = M->getFunction("ext");
    REQUIRE(F);

    auto rng = makeRng(0x2003);
    CHECK_FALSE(morok::passes::coherentDecoysFunction(
        *F, {/*probability=*/100, /*max_blocks=*/4, /*depth=*/3}, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("coherentDecoysFunction is a no-op on void returns") {
    LLVMContext ctx;
    auto M = parse(ctx, kVoid);
    Function *F = M->getFunction("noret");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(0x2004);
    // No return carries a computed value, so nothing is eligible.
    CHECK_FALSE(morok::passes::coherentDecoysFunction(
        *F, {/*probability=*/100, /*max_blocks=*/4, /*depth=*/3}, rng));
    CHECK(F->size() == before);
    CHECK(countGlobals(*M, "morok.decoy.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("coherentDecoysFunction skips morok-prefixed functions") {
    LLVMContext ctx;
    auto M = parse(ctx, kMorokName);
    Function *F = M->getFunction("morok.helper");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(0x2005);
    CHECK_FALSE(morok::passes::coherentDecoysFunction(
        *F, {/*probability=*/100, /*max_blocks=*/4, /*depth=*/3}, rng));
    CHECK(F->size() == before);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("coherentDecoysFunction caps decoy arms at max_blocks") {
    LLVMContext ctx;
    auto M = parse(ctx, kMultiReturn);
    Function *F = M->getFunction("multiret");
    REQUIRE(F);

    auto rng = makeRng(0x2006);
    // Four eligible returns, cap of two, guaranteed-fire probability.
    CHECK(morok::passes::coherentDecoysFunction(
        *F, {/*probability=*/100, /*max_blocks=*/2, /*depth=*/3}, rng));
    CHECK(countDecoyAltBlocks(*F) == 2);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("coherentDecoysFunction emits opaque guard and coherent alt arm") {
    LLVMContext ctx;
    auto M = parse(ctx, kIntReturn);
    Function *F = M->getFunction("compute");
    REQUIRE(F);

    auto rng = makeRng(0x2007);
    CHECK(morok::passes::coherentDecoysFunction(
        *F, {/*probability=*/100, /*max_blocks=*/4, /*depth=*/3}, rng));

    // The guard predicate is an equality over two volatile loads (always true
    // at runtime, not statically foldable).
    auto *pred = dyn_cast_or_null<ICmpInst>(
        findNamedInstruction(*F, "morok.decoy.pred"));
    REQUIRE(pred);
    CHECK(pred->getPredicate() == CmpInst::ICMP_EQ);

    auto *loadA =
        dyn_cast_or_null<LoadInst>(findNamedInstruction(*F, "morok.decoy.a"));
    REQUIRE(loadA);
    CHECK(loadA->isVolatile());

    // The alternate arm block and its coherent seed value exist.
    CHECK(countDecoyAltBlocks(*F) == 1);
    CHECK(findNamedInstruction(*F, "morok.decoy.alt.seed") != nullptr);

    // Executing the dead arm records nonzero hidden state via a volatile store.
    auto *stateLoad = dyn_cast_or_null<LoadInst>(
        findNamedInstruction(*F, "morok.decoy.state.load"));
    REQUIRE(stateLoad);
    CHECK(stateLoad->isVolatile());

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("coherentDecoysFunction handles floating-point returns") {
    LLVMContext ctx;
    auto M = parse(ctx, kFpReturn);
    Function *F = M->getFunction("fcompute");
    REQUIRE(F);
    const std::size_t before = F->size();
    const std::size_t fmulBefore =
        countOpcode(*M, static_cast<unsigned>(Instruction::FMul));

    auto rng = makeRng(0x2008);
    CHECK(morok::passes::coherentDecoysFunction(
        *F, {/*probability=*/100, /*max_blocks=*/4, /*depth=*/3}, rng));

    // The fp decoy builder mixes floating terms, so new FMuls appear.
    const std::size_t fmulAfter =
        countOpcode(*M, static_cast<unsigned>(Instruction::FMul));
    CHECK(fmulAfter > fmulBefore);
    CHECK(F->size() > before);
    CHECK(countDecoyAltBlocks(*F) == 1);
    CHECK(findNamedInstruction(*F, "morok.decoy.alt.seed") != nullptr);
    CHECK_FALSE(verifyModule(*M));
}
