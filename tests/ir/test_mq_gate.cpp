// SPDX-License-Identifier: MIT
//
// Tests for MqGate — planted multivariate-quadratic (GF(2)) opaque gates.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/MqGate.hpp"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// A function with one input-derived conditional branch (icmp over arguments)
// plus a join with a PHI, so the rewrite has to fix up PHI predecessors.
const char *kCond = R"ir(
define i32 @cond(i32 %a, i32 %b) {
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

// Two independent input-derived conditional branches (entry and %b1), so the
// per-function gate cap can be exercised.
const char *kTwoBranches = R"ir(
define i32 @twobr(i32 %a, i32 %b) {
entry:
  %c0 = icmp slt i32 %a, %b
  br i1 %c0, label %b1, label %b2
b1:
  %c1 = icmp sgt i32 %a, 0
  br i1 %c1, label %j, label %b2
b2:
  br label %j
j:
  %p = phi i32 [ %a, %b1 ], [ %b, %b2 ]
  ret i32 %p
}
)ir";

// Conditional branch whose condition is derived only from constants: not
// input-derived, therefore ineligible for a gate.
const char *kConstCond = R"ir(
define i32 @constbr(i32 %a) {
entry:
  %c = icmp slt i32 1, 2
  br i1 %c, label %then, label %else
then:
  br label %join
else:
  br label %join
join:
  ret i32 %a
}
)ir";

const char *kDecl = R"ir(
declare i32 @external(i32)
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

// Full parameter set with a small variable/equation count to keep the emitted
// IR compact and stable.
morok::passes::MqGateParams smallParams(std::uint32_t maxGates = 2) {
    morok::passes::MqGateParams p;
    p.probability = 100;
    p.vars = 6;
    p.eqs = 4;
    p.density = 50;
    p.max_gates = maxGates;
    p.fold_diff = true;
    return p;
}

std::size_t countVolatileMemOps(Function &F) {
    std::size_t n = 0;
    for (Instruction &I : instructions(F)) {
        if (auto *SI = dyn_cast<StoreInst>(&I)) {
            if (SI->isVolatile())
                ++n;
        } else if (auto *LI = dyn_cast<LoadInst>(&I)) {
            if (LI->isVolatile())
                ++n;
        }
    }
    return n;
}

bool hasBlockNamed(Function &F, StringRef name) {
    for (BasicBlock &BB : F)
        if (BB.getName() == name)
            return true;
    return false;
}

std::string moduleText(Module &M) {
    std::string out;
    raw_string_ostream os(out);
    M.print(os, nullptr);
    os.flush();
    return out;
}

} // namespace

TEST_CASE("mqGateFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kCond);
    Function *F = M->getFunction("cond");
    REQUIRE(F);
    const std::size_t beforeBlocks = F->size();
    REQUIRE(countGlobals(*M, "morok.mq.sys") == 0);

    auto rng = makeRng(1);
    CHECK(morok::passes::mqGateFunction(*F, smallParams(), rng));
    // Rewrite inserts a fail block and a continuation block.
    CHECK(F->size() > beforeBlocks);
    // At least one packed MQ-system global was emitted.
    CHECK(countGlobals(*M, "morok.mq.sys") >= 1);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mqGateFunction respects probability=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kCond);
    Function *F = M->getFunction("cond");
    REQUIRE(F);
    const std::size_t beforeBlocks = F->size();

    auto p = smallParams();
    p.probability = 0;
    auto rng = makeRng(2);
    CHECK_FALSE(morok::passes::mqGateFunction(*F, p, rng));
    CHECK(F->size() == beforeBlocks);
    CHECK(countGlobals(*M, "morok.mq.sys") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mqGateFunction respects max_gates=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kCond);
    Function *F = M->getFunction("cond");
    REQUIRE(F);
    const std::size_t beforeBlocks = F->size();

    auto p = smallParams(/*maxGates=*/0);
    auto rng = makeRng(3);
    CHECK_FALSE(morok::passes::mqGateFunction(*F, p, rng));
    CHECK(F->size() == beforeBlocks);
    CHECK(countGlobals(*M, "morok.mq.sys") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mqGateFunction skips declarations and non-input-derived branches") {
    LLVMContext ctx;

    auto Mdecl = parse(ctx, kDecl);
    Function *Fdecl = Mdecl->getFunction("external");
    REQUIRE(Fdecl);
    auto rngDecl = makeRng(4);
    CHECK_FALSE(morok::passes::mqGateFunction(*Fdecl, smallParams(), rngDecl));
    CHECK_FALSE(verifyModule(*Mdecl));

    auto Mconst = parse(ctx, kConstCond);
    Function *Fconst = Mconst->getFunction("constbr");
    REQUIRE(Fconst);
    const std::size_t beforeBlocks = Fconst->size();
    auto rngConst = makeRng(5);
    // The only conditional branch is constant-derived, hence ineligible.
    CHECK_FALSE(morok::passes::mqGateFunction(*Fconst, smallParams(), rngConst));
    CHECK(Fconst->size() == beforeBlocks);
    CHECK(countGlobals(*Mconst, "morok.mq.sys") == 0);
    CHECK_FALSE(verifyModule(*Mconst));
}

TEST_CASE("mqGateFunction is deterministic for a fixed seed and input") {
    LLVMContext ctxA;
    LLVMContext ctxB;
    auto Ma = parse(ctxA, kCond);
    auto Mb = parse(ctxB, kCond);

    // Construct fresh engines directly so both runs start from identical state.
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0x2024u);
    morok::ir::IRRandom rngA(engineA);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0x2024u);
    morok::ir::IRRandom rngB(engineB);

    auto p = smallParams(/*maxGates=*/1);
    CHECK(morok::passes::mqGateFunction(*Ma->getFunction("cond"), p, rngA));
    CHECK(morok::passes::mqGateFunction(*Mb->getFunction("cond"), p, rngB));

    CHECK(moduleText(*Ma) == moduleText(*Mb));
    CHECK_FALSE(verifyModule(*Ma));
    CHECK_FALSE(verifyModule(*Mb));
}

TEST_CASE("mqGateFunction emits one scratch alloca sized to the var count") {
    LLVMContext ctx;
    auto M = parse(ctx, kCond);
    Function *F = M->getFunction("cond");
    REQUIRE(F);

    auto rng = makeRng(6);
    CHECK(morok::passes::mqGateFunction(*F, smallParams(), rng));

    // Exactly one reusable scratch buffer, an [vars x i8] array (vars=6).
    CHECK(countNamedAllocas(*F, "morok.mq.scratch") == 1);
    CHECK(maxStaticAllocaArrayBytes(*F, "morok.mq.scratch") ==
          static_cast<std::uint64_t>(6));
    // Input bits are rebased through volatile scratch cancellation: each of the
    // vars slots does one volatile store and two volatile loads.
    CHECK(countVolatileMemOps(*F) > 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mqGateFunction plants fail/cont blocks and named gate instructions") {
    LLVMContext ctx;
    auto M = parse(ctx, kCond);
    Function *F = M->getFunction("cond");
    REQUIRE(F);

    auto rng = makeRng(7);
    CHECK(morok::passes::mqGateFunction(*F, smallParams(/*maxGates=*/1), rng));

    CHECK(hasBlockNamed(*F, "morok.mq.fail"));
    CHECK(hasBlockNamed(*F, "morok.mq.cont"));
    // Per-form equality tests, the ANDed gate accumulator, and the planted bits.
    CHECK(countNamedInstructions(*F, "morok.mq.eq") > 0);
    CHECK(countNamedInstructions(*F, "morok.mq.gate") > 0);
    CHECK(countNamedInstructions(*F, "morok.mq.bit") > 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mqGateFunction honors the max_gates cap across branches") {
    LLVMContext ctx;

    auto Mone = parse(ctx, kTwoBranches);
    Function *Fone = Mone->getFunction("twobr");
    REQUIRE(Fone);
    auto rngOne = makeRng(8);
    CHECK(morok::passes::mqGateFunction(*Fone, smallParams(/*maxGates=*/1),
                                        rngOne));
    // Cap of one gate: exactly one MQ-system global despite two candidates.
    CHECK(countGlobals(*Mone, "morok.mq.sys") == 1);
    CHECK_FALSE(verifyModule(*Mone));

    auto Mtwo = parse(ctx, kTwoBranches);
    Function *Ftwo = Mtwo->getFunction("twobr");
    REQUIRE(Ftwo);
    auto rngTwo = makeRng(9);
    CHECK(morok::passes::mqGateFunction(*Ftwo, smallParams(/*maxGates=*/2),
                                        rngTwo));
    // Both eligible branches gated: two globals, but still a single shared
    // scratch alloca.
    CHECK(countGlobals(*Mtwo, "morok.mq.sys") == 2);
    CHECK(countNamedAllocas(*Ftwo, "morok.mq.scratch") == 1);
    CHECK_FALSE(verifyModule(*Mtwo));
}
