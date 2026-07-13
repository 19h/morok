// SPDX-License-Identifier: MIT
//
// Tests for ExternalOpaquePredicates — volatile-context-derived opaque
// predicates that guard selected blocks with an always-true branch built from
// an IPO-blocked helper plus a volatile decoy false-arm.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/ExternalOpaquePredicates.hpp"

#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// Single-block function with a real (non-terminator) split point.
const char *kArith = R"ir(
define i32 @arith(i32 %a, i32 %b) {
entry:
  %0 = add i32 %a, %b
  %1 = mul i32 %a, %b
  %2 = xor i32 %0, %1
  ret i32 %2
}
)ir";

// Four blocks, each with a guardable non-terminator instruction.
const char *kMulti = R"ir(
define i32 @multi(i32 %a, i32 %b) {
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
  %r = mul i32 %p, 2
  ret i32 %r
}
)ir";

// No guardable instruction: the only instruction is the terminator.
const char *kTrivial = R"ir(
define i32 @trivial(i32 %x) {
entry:
  ret i32 %x
}
)ir";

const char *kDecl = R"ir(
declare i32 @external(i32)
)ir";

// A morok.*-named (generated) function that is otherwise transformable.
const char *kGenerated = R"ir(
define i32 @"morok.gen"(i32 %x) {
entry:
  %r = add i32 %x, 7
  ret i32 %r
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::size_t countVolatileStores(Function &F) {
    std::size_t n = 0;
    for (Instruction &I : instructions(F))
        if (auto *SI = dyn_cast<StoreInst>(&I))
            if (SI->isVolatile())
                ++n;
    return n;
}

bool hasBlockWithPrefix(Function &F, StringRef prefix) {
    for (BasicBlock &BB : F)
        if (BB.getName().starts_with(prefix))
            return true;
    return false;
}

} // namespace

TEST_CASE("externalOpaquePredicatesFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(1);
    const bool changed = morok::passes::externalOpaquePredicatesFunction(
        *F, morok::passes::ExternalOpaqueParams{/*probability=*/100u,
                                                /*max_blocks=*/8u,
                                                /*decoy_stores=*/2u,
                                                /*include_generated=*/false},
        rng);
    CHECK(changed);
    CHECK(F->size() > before);
    CHECK_FALSE(verifyModule(*M));

    // Specific: the IPO-blocked helper and its two backing globals appear once.
    CHECK(countFunctions(*M, "morok.extop") == 1u);
    CHECK(countGlobals(*M, "morok.extop") == 2u);
    CHECK(M->getFunction("morok.extop.context") != nullptr);
    CHECK(M->getGlobalVariable("morok.extop.seed", true) != nullptr);
    CHECK(M->getGlobalVariable("morok.extop.scratch", true) != nullptr);
    // One transformed block => exactly two calls to the context helper.
    CHECK(countCallsTo(*F, "morok.extop.context") == 2u);
}

TEST_CASE("externalOpaquePredicatesFunction is a no-op at probability zero") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(2);
    const bool changed = morok::passes::externalOpaquePredicatesFunction(
        *F, morok::passes::ExternalOpaqueParams{/*probability=*/0u,
                                                /*max_blocks=*/8u,
                                                /*decoy_stores=*/2u,
                                                /*include_generated=*/false},
        rng);
    CHECK_FALSE(changed);
    CHECK(F->size() == before);
    // Nothing emitted at all.
    CHECK(countFunctions(*M, "morok.extop") == 0u);
    CHECK(countGlobals(*M, "morok.extop") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("externalOpaquePredicatesFunction is a no-op when max_blocks is zero") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(3);
    const bool changed = morok::passes::externalOpaquePredicatesFunction(
        *F, morok::passes::ExternalOpaqueParams{/*probability=*/100u,
                                                /*max_blocks=*/0u,
                                                /*decoy_stores=*/2u,
                                                /*include_generated=*/false},
        rng);
    CHECK_FALSE(changed);
    CHECK(F->size() == before);
    CHECK(countFunctions(*M, "morok.extop") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("externalOpaquePredicatesFunction skips declarations and trivial blocks") {
    LLVMContext ctx;

    auto MDecl = parse(ctx, kDecl);
    Function *Ext = MDecl->getFunction("external");
    REQUIRE(Ext);
    auto rngDecl = makeRng(4);
    CHECK_FALSE(morok::passes::externalOpaquePredicatesFunction(
        *Ext, morok::passes::ExternalOpaqueParams{100u, 8u, 2u, false}, rngDecl));
    CHECK_FALSE(verifyModule(*MDecl));

    // A single terminator-only block has no guardable split point.
    auto MTriv = parse(ctx, kTrivial);
    Function *Triv = MTriv->getFunction("trivial");
    REQUIRE(Triv);
    const std::size_t before = Triv->size();
    auto rngTriv = makeRng(5);
    CHECK_FALSE(morok::passes::externalOpaquePredicatesFunction(
        *Triv, morok::passes::ExternalOpaqueParams{100u, 8u, 2u, false},
        rngTriv));
    CHECK(Triv->size() == before);
    CHECK(countFunctions(*MTriv, "morok.extop") == 0u);
    CHECK_FALSE(verifyModule(*MTriv));
}

TEST_CASE("externalOpaquePredicatesFunction skips generated functions unless opted in") {
    LLVMContext ctx;

    // Default: morok.*-named functions are left untouched.
    auto MSkip = parse(ctx, kGenerated);
    Function *Gen = MSkip->getFunction("morok.gen");
    REQUIRE(Gen);
    const std::size_t before = Gen->size();
    auto rngSkip = makeRng(6);
    CHECK_FALSE(morok::passes::externalOpaquePredicatesFunction(
        *Gen,
        morok::passes::ExternalOpaqueParams{/*probability=*/100u, 8u, 2u,
                                            /*include_generated=*/false},
        rngSkip));
    CHECK(Gen->size() == before);
    CHECK_FALSE(verifyModule(*MSkip));

    // Opt in: the same function is now eligible and gets transformed.
    auto MTake = parse(ctx, kGenerated);
    Function *Gen2 = MTake->getFunction("morok.gen");
    REQUIRE(Gen2);
    auto rngTake = makeRng(7);
    CHECK(morok::passes::externalOpaquePredicatesFunction(
        *Gen2,
        morok::passes::ExternalOpaqueParams{/*probability=*/100u, 8u, 2u,
                                            /*include_generated=*/true},
        rngTake));
    CHECK(Gen2->size() > before);
    CHECK_FALSE(verifyModule(*MTake));
}

TEST_CASE("externalOpaquePredicatesFunction respects the max_blocks cap") {
    LLVMContext ctx;
    auto M = parse(ctx, kMulti);
    Function *F = M->getFunction("multi");
    REQUIRE(F);

    // Four transformable blocks, but the per-function cap is two.  Each guarded
    // block emits exactly two context calls, so we expect four total.
    auto rng = makeRng(8);
    const bool changed = morok::passes::externalOpaquePredicatesFunction(
        *F,
        morok::passes::ExternalOpaqueParams{/*probability=*/100u,
                                            /*max_blocks=*/2u,
                                            /*decoy_stores=*/2u,
                                            /*include_generated=*/false},
        rng);
    CHECK(changed);
    CHECK(countCallsTo(*F, "morok.extop.context") == 4u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("externalOpaquePredicatesFunction emits volatile decoy stores") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);

    // One transformed block with decoy_stores=4 => four volatile scratch writes.
    auto rng = makeRng(9);
    CHECK(morok::passes::externalOpaquePredicatesFunction(
        *F,
        morok::passes::ExternalOpaqueParams{/*probability=*/100u,
                                            /*max_blocks=*/8u,
                                            /*decoy_stores=*/4u,
                                            /*include_generated=*/false},
        rng));
    CHECK(countVolatileStores(*F) == 4u);
    CHECK(hasBlockWithPrefix(*F, "morok.extop.decoy"));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("externalOpaquePredicatesFunction clamps decoy stores to the maximum") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);

    // Way over the cap: clamped to kExternalOpaqueMaxDecoyStores (16).
    auto rng = makeRng(10);
    CHECK(morok::passes::externalOpaquePredicatesFunction(
        *F,
        morok::passes::ExternalOpaqueParams{/*probability=*/100u,
                                            /*max_blocks=*/8u,
                                            /*decoy_stores=*/100u,
                                            /*include_generated=*/false},
        rng));
    CHECK(countVolatileStores(*F) ==
          static_cast<std::size_t>(
              morok::passes::kExternalOpaqueMaxDecoyStores));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("externalOpaquePredicatesFunction builds an always-true predicate helper") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);

    auto rng = makeRng(11);
    CHECK(morok::passes::externalOpaquePredicatesFunction(
        *F,
        morok::passes::ExternalOpaqueParams{/*probability=*/100u,
                                            /*max_blocks=*/8u,
                                            /*decoy_stores=*/2u,
                                            /*include_generated=*/false},
        rng));

    // The context helper is internal, noinline and optnone so IPO/local folding
    // cannot collapse the twin calls.
    Function *Helper = M->getFunction("morok.extop.context");
    REQUIRE(Helper);
    CHECK(Helper->getLinkage() == GlobalValue::InternalLinkage);
    CHECK(Helper->hasFnAttribute(Attribute::NoInline));
    CHECK(Helper->hasFnAttribute(Attribute::OptimizeNone));

    // The predicate is an equality compare (diff == 0), always true at runtime.
    Instruction *Pred = findNamedInstruction(*F, "morok.extop.pred");
    REQUIRE(Pred);
    auto *Cmp = dyn_cast<ICmpInst>(Pred);
    REQUIRE(Cmp);
    CHECK(Cmp->getPredicate() == CmpInst::ICMP_EQ);
    CHECK(instructionHasConstantOperand(Cmp, 0));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("externalOpaquePredicatesFunction is deterministic for a fixed seed") {
    LLVMContext ctx;
    auto MA = parse(ctx, kMulti);
    auto MB = parse(ctx, kMulti);

    const morok::passes::ExternalOpaqueParams params{/*probability=*/100u,
                                                     /*max_blocks=*/8u,
                                                     /*decoy_stores=*/3u,
                                                     /*include_generated=*/false};

    // Two independent engines seeded identically must yield identical IR.
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xBEEF);
    morok::ir::IRRandom rngA(engineA);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xBEEF);
    morok::ir::IRRandom rngB(engineB);

    CHECK(morok::passes::externalOpaquePredicatesFunction(
        *MA->getFunction("multi"), params, rngA));
    CHECK(morok::passes::externalOpaquePredicatesFunction(
        *MB->getFunction("multi"), params, rngB));

    std::string textA;
    std::string textB;
    raw_string_ostream osA(textA);
    raw_string_ostream osB(textB);
    MA->print(osA, nullptr);
    MB->print(osB, nullptr);
    osA.flush();
    osB.flush();
    CHECK(textA == textB);
    CHECK_FALSE(verifyModule(*MA));
    CHECK_FALSE(verifyModule(*MB));
}
