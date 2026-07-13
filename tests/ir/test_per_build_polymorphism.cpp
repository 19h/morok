// SPDX-License-Identifier: MIT
//
// Tests for PerBuildPolymorphism — seed-driven final layout diversity:
// function/block reordering plus neutral volatile return anchors.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/PerBuildPolymorphism.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <string>
#include <vector>

using namespace llvm;
using namespace morok::test;

namespace {

// Three defined functions; @alpha carries non-entry blocks so block_order has
// something to permute, and every function has one eligible scalar return.
const char *kMultiFn = R"ir(
define i32 @alpha(i32 %x) {
entry:
  %c = icmp slt i32 %x, 5
  br i1 %c, label %lo, label %hi
lo:
  %a = add i32 %x, 2
  br label %merge
hi:
  %b = xor i32 %x, 3
  br label %merge
merge:
  %p = phi i32 [ %a, %lo ], [ %b, %hi ]
  ret i32 %p
}

define i64 @beta(i64 %y) {
entry:
  %m = mul i64 %y, 7
  ret i64 %m
}

define i32 @gamma(i32 %z) {
entry:
  %s = sub i32 %z, 4
  ret i32 %s
}
)ir";

// Single-block i32 function: a minimal, block-shuffle-immune anchor target.
const char *kSingleI32 = R"ir(
define i32 @only(i32 %x) {
entry:
  %y = add i32 %x, 8
  ret i32 %y
}
)ir";

// Declarations only: nothing the pass can legally touch.
const char *kDeclOnly = R"ir(
declare i32 @imported(i32)
declare void @sink()
)ir";

// Returns the pass never anchors: aggregate/pointer, void, and >64-bit integer.
const char *kIneligible = R"ir(
define ptr @ptr_ret(ptr %p) {
entry:
  ret ptr %p
}

define void @void_ret() {
entry:
  ret void
}

define i128 @wide_ret(i128 %w) {
entry:
  ret i128 %w
}
)ir";

// RNG idiom mandated by the harness: the engine is static so it outlives the
// returned adaptor, which only holds a reference.
morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337ULL) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::string moduleToString(Module &M) {
    std::string text;
    raw_string_ostream os(text);
    M.print(os, nullptr);
    return os.str();
}

std::vector<std::string> definedFunctionOrder(Module &M) {
    std::vector<std::string> names;
    for (Function &F : M)
        if (!F.isDeclaration())
            names.push_back(F.getName().str());
    return names;
}

} // namespace

TEST_CASE("perBuildPolymorphismModule grows the module and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kMultiFn);

    auto rng = makeRng(0xF00D1ULL);
    morok::passes::PerBuildPolymorphismParams p;
    p.function_order = true;
    p.block_order = true;
    p.anchor_probability = 100u;
    p.max_anchors = 16u;

    const std::size_t globalsBefore = countGlobals(*M, "morok.poly.");

    CHECK(morok::passes::perBuildPolymorphismModule(*M, p, rng));

    // Every eligible return (one per function) produced a private salt global.
    const std::size_t globalsAfter = countGlobals(*M, "morok.poly.salt");
    CHECK(globalsAfter == 3u);
    CHECK(globalsAfter > globalsBefore);
    // And the anchor arithmetic added named poly instructions.
    CHECK(countNamedInstructions(*M, "morok.poly.") > 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("perBuildPolymorphismModule leaves IR untouched when every knob is off") {
    LLVMContext ctx;
    auto M = parse(ctx, kMultiFn);

    const std::string before = moduleToString(*M);

    auto rng = makeRng(0xF00D2ULL);
    morok::passes::PerBuildPolymorphismParams p;
    p.function_order = false;
    p.block_order = false;
    p.anchor_probability = 0u;
    p.max_anchors = 0u;

    CHECK_FALSE(morok::passes::perBuildPolymorphismModule(*M, p, rng));
    CHECK(moduleToString(*M) == before);
    CHECK(countGlobals(*M, "morok.poly.") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("perBuildPolymorphismModule is safe on declaration-only modules") {
    LLVMContext ctx;
    auto M = parse(ctx, kDeclOnly);

    auto rng = makeRng(0xF00D3ULL);
    morok::passes::PerBuildPolymorphismParams p;
    p.function_order = true;
    p.block_order = true;
    p.anchor_probability = 100u;
    p.max_anchors = 16u;

    // No defined function to reorder and no eligible return to anchor.
    CHECK_FALSE(morok::passes::perBuildPolymorphismModule(*M, p, rng));
    CHECK(countGlobals(*M, "morok.poly.") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("perBuildPolymorphismModule refuses to re-run once poly globals exist") {
    LLVMContext ctx;
    auto M = parse(ctx, kMultiFn);

    morok::passes::PerBuildPolymorphismParams p;
    p.function_order = true;
    p.block_order = true;
    p.anchor_probability = 100u;
    p.max_anchors = 16u;

    auto rng1 = makeRng(0xF00D4ULL);
    CHECK(morok::passes::perBuildPolymorphismModule(*M, p, rng1));
    const std::size_t saltsAfterFirst = countGlobals(*M, "morok.poly.salt");
    CHECK(saltsAfterFirst == 3u);

    // hasExistingPoly() short-circuits the second invocation to a no-op.
    auto rng2 = makeRng(0xF00D5ULL);
    CHECK_FALSE(morok::passes::perBuildPolymorphismModule(*M, p, rng2));
    CHECK(countGlobals(*M, "morok.poly.salt") == saltsAfterFirst);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("perBuildPolymorphismModule emits identical text for identical seeds") {
    LLVMContext ctxA;
    LLVMContext ctxB;
    auto MA = parse(ctxA, kMultiFn);
    auto MB = parse(ctxB, kMultiFn);

    morok::passes::PerBuildPolymorphismParams p;
    p.function_order = true;
    p.block_order = true;
    p.anchor_probability = 100u;
    p.max_anchors = 16u;

    // Two independent engines seeded identically yield identical streams.
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xD1CEULL);
    morok::ir::IRRandom rngA(engineA);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xD1CEULL);
    morok::ir::IRRandom rngB(engineB);

    CHECK(morok::passes::perBuildPolymorphismModule(*MA, p, rngA));
    CHECK(morok::passes::perBuildPolymorphismModule(*MB, p, rngB));
    CHECK(moduleToString(*MA) == moduleToString(*MB));
    CHECK_FALSE(verifyModule(*MA));
    CHECK_FALSE(verifyModule(*MB));
}

TEST_CASE("perBuildPolymorphismModule emits divergent text for distinct seeds") {
    LLVMContext ctxA;
    LLVMContext ctxB;
    auto MA = parse(ctxA, kMultiFn);
    auto MB = parse(ctxB, kMultiFn);

    morok::passes::PerBuildPolymorphismParams p;
    p.function_order = true;
    p.block_order = true;
    p.anchor_probability = 100u;
    p.max_anchors = 16u;

    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xC0FFEEULL);
    morok::ir::IRRandom rngA(engineA);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xBADF00DULL);
    morok::ir::IRRandom rngB(engineB);

    CHECK(morok::passes::perBuildPolymorphismModule(*MA, p, rngA));
    CHECK(morok::passes::perBuildPolymorphismModule(*MB, p, rngB));
    // Distinct seeds drive distinct salt initializers, so the text differs.
    CHECK(moduleToString(*MA) != moduleToString(*MB));
    CHECK_FALSE(verifyModule(*MA));
    CHECK_FALSE(verifyModule(*MB));
}

TEST_CASE("perBuildPolymorphismModule wraps returns in volatile zeroing salt loads") {
    LLVMContext ctx;
    auto M = parse(ctx, kSingleI32);

    auto rng = makeRng(0xF00D6ULL);
    morok::passes::PerBuildPolymorphismParams p;
    p.function_order = false;
    p.block_order = false;
    p.anchor_probability = 100u;
    p.max_anchors = 16u;

    CHECK(morok::passes::perBuildPolymorphismModule(*M, p, rng));

    // Exactly one salt global, private and a non-constant i64.
    CHECK(countGlobals(*M, "morok.poly.salt") == 1u);
    GlobalVariable *salt = nullptr;
    for (GlobalVariable &G : M->globals())
        if (G.getName().starts_with("morok.poly.salt"))
            salt = &G;
    REQUIRE(salt != nullptr);
    CHECK(salt->hasPrivateLinkage());
    CHECK_FALSE(salt->isConstant());
    CHECK(salt->getValueType()->isIntegerTy(64));

    Function *only = M->getFunction("only");
    REQUIRE(only != nullptr);

    // The two salt reads are volatile loads.
    auto *loadA =
        dyn_cast_or_null<LoadInst>(findNamedInstruction(*only, "morok.poly.salt.a"));
    auto *loadB =
        dyn_cast_or_null<LoadInst>(findNamedInstruction(*only, "morok.poly.salt.b"));
    REQUIRE(loadA != nullptr);
    REQUIRE(loadB != nullptr);
    CHECK(loadA->isVolatile());
    CHECK(loadB->isVolatile());

    // salt ^ salt gives a semantic zero, then value ^ zero re-yields the value.
    auto *zero64 =
        dyn_cast_or_null<BinaryOperator>(findNamedInstruction(*only, "morok.poly.zero64"));
    REQUIRE(zero64 != nullptr);
    CHECK(zero64->getOpcode() == Instruction::Xor);
    auto *anchored =
        dyn_cast_or_null<BinaryOperator>(findNamedInstruction(*only, "morok.poly.value"));
    REQUIRE(anchored != nullptr);
    CHECK(anchored->getOpcode() == Instruction::Xor);
    CHECK(anchored->getType()->isIntegerTy(32));

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("perBuildPolymorphismModule leaves ineligible return types unanchored") {
    LLVMContext ctx;
    auto M = parse(ctx, kIneligible);

    auto rng = makeRng(0xF00D7ULL);
    morok::passes::PerBuildPolymorphismParams p;
    p.function_order = false;
    p.block_order = false;
    p.anchor_probability = 100u;
    p.max_anchors = 16u;

    // Pointer, void, and i128 returns are all ineligible: nothing to anchor.
    CHECK_FALSE(morok::passes::perBuildPolymorphismModule(*M, p, rng));
    CHECK(countGlobals(*M, "morok.poly.") == 0u);
    CHECK(countNamedInstructions(*M, "morok.poly.") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("perBuildPolymorphismModule permutes defined function order") {
    LLVMContext ctx;
    auto M = parse(ctx, kMultiFn);

    const std::vector<std::string> before = definedFunctionOrder(*M);
    REQUIRE(before.size() == 3u);

    auto rng = makeRng(0xF00D8ULL);
    morok::passes::PerBuildPolymorphismParams p;
    p.function_order = true;
    p.block_order = false;
    p.anchor_probability = 0u;
    p.max_anchors = 0u;

    // Only the function reorder is active; shuffleAndForceChange guarantees the
    // permutation of >=2 functions differs from the original.
    CHECK(morok::passes::perBuildPolymorphismModule(*M, p, rng));
    CHECK(definedFunctionOrder(*M) != before);
    CHECK(countGlobals(*M, "morok.poly.") == 0u);
    CHECK_FALSE(verifyModule(*M));
}
