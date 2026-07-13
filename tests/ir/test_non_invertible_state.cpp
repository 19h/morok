// SPDX-License-Identifier: MIT
//
// Tests for NonInvertibleState — non-invertible next-state flattening: a
// switch dispatcher whose cases hold keyed lossy-hash-encoded successor ids,
// with live program values folded through a volatile shadow channel.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/NonInvertibleState.hpp"

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

// A four-block function with a conditional branch and a join: enough distinct
// blocks (and live scalar terms) for the flattener to fire and mix terms.
const char *kBranchy = R"ir(
define i32 @branchy(i32 %a, i32 %b) {
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
  ret i32 %p
}
)ir";

// A loop: exercises a back-edge through the dispatcher.
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

// A single-block function: fewer than two blocks, so nothing to flatten.
const char *kSingleBlock = R"ir(
define i32 @trivial(i32 %x) {
entry:
  %r = add i32 %x, 1
  ret i32 %r
}
)ir";

const char *kDeclaration = R"ir(
declare i32 @external(i32)
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::size_t countVolatileStores(Function &F) {
    std::size_t n = 0;
    for (Instruction &I : instructions(F))
        if (auto *st = dyn_cast<StoreInst>(&I))
            if (st->isVolatile())
                ++n;
    return n;
}

std::string moduleText(Module &M) {
    std::string out;
    raw_string_ostream os(out);
    M.print(os, nullptr);
    os.flush();
    return out;
}

} // namespace

TEST_CASE("nonInvertibleStateFunction flattens a multi-block function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kBranchy);
    Function *F = M->getFunction("branchy");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(0x1337);
    CHECK(morok::passes::nonInvertibleStateFunction(*F, {}, rng));
    // The dispatcher adds blocks (dispatch/backedge/default) and rewrites edges.
    CHECK(F->size() > before);
    // A single switch dispatcher drives the flattened body.
    CHECK(countOpcode(*M, Instruction::Switch) >= 1);
    // The pass emits its keyed-state machinery under the "nistate." namespace.
    CHECK(countNamedInstructions(*F, "nistate.") > 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("nonInvertibleStateFunction flattens a loop and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kLoop);
    Function *F = M->getFunction("loop");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(0x2222);
    CHECK(morok::passes::nonInvertibleStateFunction(*F, {}, rng));
    CHECK(F->size() > before);
    CHECK(findNamedInstruction(*F, "nistate.next") != nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("nonInvertibleStateFunction leaves single-block functions unchanged") {
    LLVMContext ctx;
    auto M = parse(ctx, kSingleBlock);
    Function *F = M->getFunction("trivial");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(0x3333);
    // Fewer than two blocks: flattener declines, function untouched.
    CHECK_FALSE(morok::passes::nonInvertibleStateFunction(*F, {}, rng));
    CHECK(F->size() == before);
    CHECK(countNamedAllocas(*F, "nistate.shadow") == 0);
    CHECK(countNamedInstructions(*F, "nistate.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("nonInvertibleStateFunction is safe on declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, kDeclaration);
    Function *F = M->getFunction("external");
    REQUIRE(F);

    auto rng = makeRng(0x4444);
    // A declaration has no body: nothing to flatten, no crash.
    CHECK_FALSE(morok::passes::nonInvertibleStateFunction(*F, {}, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("nonInvertibleStateFunction emits the volatile shadow channel") {
    LLVMContext ctx;
    auto M = parse(ctx, kBranchy);
    Function *F = M->getFunction("branchy");
    REQUIRE(F);

    auto rng = makeRng(0x5555);
    REQUIRE(morok::passes::nonInvertibleStateFunction(*F, {}, rng));

    // Exactly one shadow slot array ([2 x i32]) is materialized and reused.
    CHECK(countNamedAllocas(*F, "nistate.shadow") == 1);
    // Live data is routed through volatile stores so the runtime value cancels.
    CHECK(countVolatileStores(*F) >= 2);
    // The cancelling XOR of the two shadow slots is present.
    CHECK(findNamedInstruction(*F, "nistate.cancel") != nullptr);
    // The current encoded state is reloaded per transition.
    auto *cur = dyn_cast_or_null<LoadInst>(
        findNamedInstruction(*F, "nistate.cur"));
    CHECK(cur != nullptr);
    // The token seed fuses the current state with the block id via XOR.
    auto *seed = dyn_cast_or_null<BinaryOperator>(
        findNamedInstruction(*F, "nistate.token.seed"));
    CHECK((seed != nullptr && seed->getOpcode() == Instruction::Xor));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("nonInvertibleStateFunction is deterministic for a fixed seed and input") {
    LLVMContext ctxA;
    LLVMContext ctxB;
    auto MA = parse(ctxA, kBranchy);
    auto MB = parse(ctxB, kBranchy);
    Function *FA = MA->getFunction("branchy");
    Function *FB = MB->getFunction("branchy");
    REQUIRE(FA);
    REQUIRE(FB);

    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xABCDEF);
    morok::ir::IRRandom rngA(engineA);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xABCDEF);
    morok::ir::IRRandom rngB(engineB);

    CHECK(morok::passes::nonInvertibleStateFunction(*FA, {}, rngA));
    CHECK(morok::passes::nonInvertibleStateFunction(*FB, {}, rngB));

    // Same fresh seed + same input => byte-identical IR.
    CHECK(moduleText(*MA) == moduleText(*MB));
    CHECK_FALSE(verifyModule(*MA));
    CHECK_FALSE(verifyModule(*MB));
}

TEST_CASE("nonInvertibleStateFunction scales the lossy hash with the rounds parameter") {
    LLVMContext ctx;
    auto MLo = parse(ctx, kBranchy);
    auto MHi = parse(ctx, kBranchy);
    Function *FLo = MLo->getFunction("branchy");
    Function *FHi = MHi->getFunction("branchy");
    REQUIRE(FLo);
    REQUIRE(FHi);

    auto rngLo = makeRng(0x6666);
    auto rngHi = makeRng(0x7777);
    REQUIRE(morok::passes::nonInvertibleStateFunction(
        *FLo, {/*max_terms=*/4, /*rounds=*/1}, rngLo));
    REQUIRE(morok::passes::nonInvertibleStateFunction(
        *FHi, {/*max_terms=*/4, /*rounds=*/6}, rngHi));

    // More hash rounds emit strictly more "nistate.hash." instructions; the
    // rewritten-block count is identical, so the difference is purely the rounds.
    const std::size_t hashLo = countNamedInstructions(*FLo, "nistate.hash.");
    const std::size_t hashHi = countNamedInstructions(*FHi, "nistate.hash.");
    CHECK(hashHi > hashLo);
    CHECK_FALSE(verifyModule(*MLo));
    CHECK_FALSE(verifyModule(*MHi));
}

TEST_CASE("nonInvertibleStateFunction gates term folding on max_terms") {
    LLVMContext ctx;
    auto MZero = parse(ctx, kBranchy);
    auto MFour = parse(ctx, kBranchy);
    Function *FZero = MZero->getFunction("branchy");
    Function *FFour = MFour->getFunction("branchy");
    REQUIRE(FZero);
    REQUIRE(FFour);

    auto rngZero = makeRng(0x8888);
    auto rngFour = makeRng(0x9999);
    // max_terms=0 still flattens, but no live values are folded into the token.
    REQUIRE(morok::passes::nonInvertibleStateFunction(
        *FZero, {/*max_terms=*/0, /*rounds=*/3}, rngZero));
    REQUIRE(morok::passes::nonInvertibleStateFunction(
        *FFour, {/*max_terms=*/4, /*rounds=*/3}, rngFour));

    // With max_terms=0 the fold loop never runs.
    CHECK(countNamedInstructions(*FZero, "nistate.token.fold") == 0);
    // The token seed is emitted regardless of max_terms.
    CHECK(findNamedInstruction(*FZero, "nistate.token.seed") != nullptr);
    // With a positive budget, live terms are folded in.
    CHECK(countNamedInstructions(*FFour, "nistate.token.fold") > 0);
    CHECK_FALSE(verifyModule(*MZero));
    CHECK_FALSE(verifyModule(*MFour));
}
