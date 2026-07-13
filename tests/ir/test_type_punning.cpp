// SPDX-License-Identifier: MIT
//
// Tests for TypePunning — round-trips scalar SSA values through a volatile
// byte-array "union" and reloads them via a conflicting type view.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/TypePunning.hpp"

#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// Four integer instructions, all eligible (each has a next node, i32 store
// size is 4 bytes, well within the 1..128 byte window).
const char *kArith = R"ir(
define i32 @arith(i32 %a, i32 %b) {
entry:
  %0 = add i32 %a, %b
  %1 = mul i32 %a, %b
  %2 = xor i32 %0, %1
  %3 = sub i32 %2, %a
  ret i32 %3
}
)ir";

// A single floating-point scalar — punned only when include_floating is set.
const char *kFloat = R"ir(
define float @float_add(float %a, float %b) {
entry:
  %s = fadd float %a, %b
  ret float %s
}
)ir";

// Mixed integer + floating-point body; include_floating decides whether the
// float participates.
const char *kMixed = R"ir(
define i32 @mixed(i32 %a, float %b) {
entry:
  %i = add i32 %a, 7
  %f = fadd float %b, %b
  ret i32 %i
}
)ir";

// Non-byte-multiple integers (i1) exercise the covering-integer widen/trunc
// path rather than the bitcast path.
const char *kBoolChain = R"ir(
define i1 @cmp(i32 %a, i32 %b) {
entry:
  %c = icmp slt i32 %a, %b
  %d = xor i1 %c, true
  ret i1 %d
}
)ir";

const char *kEmpty = R"ir(
define void @empty() {
entry:
  ret void
}
)ir";

const char *kDecl = R"ir(
declare i32 @external(i32)
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::size_t totalInstructions(Function &F) {
    std::size_t n = 0;
    for (BasicBlock &BB : F)
        n += BB.size();
    return n;
}

} // namespace

TEST_CASE("typePunFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = totalInstructions(*F);

    auto rng = makeRng(0x1337);
    CHECK(morok::passes::typePunFunction(
        *F, {/*probability=*/100u, /*include_floating=*/true,
             /*max_targets=*/64u},
        rng));
    // The pass only inserts instructions into existing blocks (no new blocks).
    CHECK(totalInstructions(*F) > before);
    CHECK(countNamedAllocas(*F, "morok.pun") > 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("typePunFunction is a no-op at probability zero") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = totalInstructions(*F);

    auto rng = makeRng(0x2001);
    CHECK_FALSE(morok::passes::typePunFunction(
        *F, {/*probability=*/0u, /*include_floating=*/true,
             /*max_targets=*/64u},
        rng));
    CHECK(totalInstructions(*F) == before);
    CHECK(countNamedAllocas(*F, "morok.pun") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("typePunFunction skips declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, kDecl);
    Function *F = M->getFunction("external");
    REQUIRE(F);

    auto rng = makeRng(0x3002);
    CHECK_FALSE(morok::passes::typePunFunction(
        *F, {/*probability=*/100u, /*include_floating=*/true,
             /*max_targets=*/64u},
        rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("typePunFunction is safe on a function with no eligible values") {
    LLVMContext ctx;
    auto M = parse(ctx, kEmpty);
    Function *F = M->getFunction("empty");
    REQUIRE(F);

    auto rng = makeRng(0x4003);
    // Only a terminator lives here, so there is nothing to pun.
    CHECK_FALSE(morok::passes::typePunFunction(
        *F, {/*probability=*/100u, /*include_floating=*/true,
             /*max_targets=*/64u},
        rng));
    CHECK(countNamedAllocas(*F, "morok.pun") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("typePunFunction emits volatile pun buffers, views, and casts") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);

    auto rng = makeRng(0x5004);
    CHECK(morok::passes::typePunFunction(
        *F, {/*probability=*/100u, /*include_floating=*/true,
             /*max_targets=*/64u},
        rng));

    // All four integer values are punned: one buffer + view + value each.
    CHECK(countNamedAllocas(*F, "morok.pun") == 4);
    CHECK(countNamedInstructions(*F, "morok.pun.view") == 4);
    CHECK(countNamedInstructions(*F, "morok.pun.value") == 4);
    // The buffers are [4 x i8] byte unions.
    CHECK(maxStaticAllocaArrayBytes(*F, "morok.pun") == 4);

    // Every pun store and pun view load is volatile.
    std::size_t punStores = 0;
    std::size_t punLoads = 0;
    bool storesVolatile = true;
    bool loadsVolatile = true;
    for (Instruction &I : instructions(*F)) {
        if (auto *SI = dyn_cast<StoreInst>(&I)) {
            ++punStores;
            if (!SI->isVolatile())
                storesVolatile = false;
        }
        if (auto *LI = dyn_cast<LoadInst>(&I)) {
            if (!LI->getName().starts_with("morok.pun.view"))
                continue;
            ++punLoads;
            if (!LI->isVolatile())
                loadsVolatile = false;
        }
    }
    CHECK(punStores == 4);
    CHECK(punLoads == 4);
    CHECK(storesVolatile);
    CHECK(loadsVolatile);

    // Byte-multiple integers view memory through a <4 x i8> vector, then
    // bitcast back to i32.
    auto *view = dyn_cast_or_null<LoadInst>(
        findNamedInstruction(*F, "morok.pun.view"));
    REQUIRE(view);
    auto *viewVec = dyn_cast<FixedVectorType>(view->getType());
    REQUIRE(viewVec);
    CHECK(viewVec->getNumElements() == 4u);
    CHECK(viewVec->getElementType()->isIntegerTy(8));

    auto *value = findNamedInstruction(*F, "morok.pun.value");
    REQUIRE(value);
    CHECK(isa<BitCastInst>(value));
    CHECK(value->getType()->isIntegerTy(32));

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("typePunFunction honors the max_targets cap") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);

    auto rng = makeRng(0x6005);
    // Four values are eligible but the cap stops emission after two.
    CHECK(morok::passes::typePunFunction(
        *F, {/*probability=*/100u, /*include_floating=*/true,
             /*max_targets=*/2u},
        rng));
    CHECK(countNamedAllocas(*F, "morok.pun") == 2);
    CHECK(countNamedInstructions(*F, "morok.pun.value") == 2);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("typePunFunction round-trips floats through an integer view") {
    LLVMContext ctx;
    auto M = parse(ctx, kFloat);
    Function *F = M->getFunction("float_add");
    REQUIRE(F);

    auto rng = makeRng(0x7006);
    CHECK(morok::passes::typePunFunction(
        *F, {/*probability=*/100u, /*include_floating=*/true,
             /*max_targets=*/64u},
        rng));

    CHECK(countNamedAllocas(*F, "morok.pun") == 1);

    // Floats are viewed as an i32 integer, then bitcast back to float.
    auto *view = dyn_cast_or_null<LoadInst>(
        findNamedInstruction(*F, "morok.pun.view"));
    REQUIRE(view);
    CHECK(view->getType()->isIntegerTy(32));
    CHECK(view->isVolatile());

    auto *value = findNamedInstruction(*F, "morok.pun.value");
    REQUIRE(value);
    CHECK(isa<BitCastInst>(value));
    CHECK(value->getType()->isFloatTy());

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("typePunFunction gates floating-point scalars on include_floating") {
    LLVMContext ctx;
    auto Moff = parse(ctx, kMixed);
    auto Mon = parse(ctx, kMixed);
    Function *Foff = Moff->getFunction("mixed");
    Function *Fon = Mon->getFunction("mixed");
    REQUIRE(Foff);
    REQUIRE(Fon);

    auto rngOff = makeRng(0x8007);
    auto rngOn = makeRng(0x8008);

    // include_floating=false leaves the float alone: only the integer is punned.
    CHECK(morok::passes::typePunFunction(
        *Foff, {/*probability=*/100u, /*include_floating=*/false,
                /*max_targets=*/64u},
        rngOff));
    CHECK(countNamedAllocas(*Foff, "morok.pun") == 1);
    CHECK_FALSE(verifyModule(*Moff));

    // include_floating=true adds the float as a second target.
    CHECK(morok::passes::typePunFunction(
        *Fon, {/*probability=*/100u, /*include_floating=*/true,
               /*max_targets=*/64u},
        rngOn));
    CHECK(countNamedAllocas(*Fon, "morok.pun") == 2);
    CHECK_FALSE(verifyModule(*Mon));
}

TEST_CASE("typePunFunction covers sub-byte integers via widen and trunc") {
    LLVMContext ctx;
    auto M = parse(ctx, kBoolChain);
    Function *F = M->getFunction("cmp");
    REQUIRE(F);

    auto rng = makeRng(0x9009);
    CHECK(morok::passes::typePunFunction(
        *F, {/*probability=*/100u, /*include_floating=*/true,
             /*max_targets=*/64u},
        rng));

    // Two i1 values, each rounded up to a 1-byte covering buffer.
    CHECK(countNamedAllocas(*F, "morok.pun") == 2);
    CHECK(maxStaticAllocaArrayBytes(*F, "morok.pun") == 1);

    // Non-byte-multiple integers are widened before the store...
    CHECK(countNamedInstructions(*F, "morok.pun.widen") == 2);
    auto *widen = findNamedInstruction(*F, "morok.pun.widen");
    REQUIRE(widen);
    CHECK(isa<ZExtInst>(widen));

    // ...and truncated (not bitcast) back to the original width.
    auto *value = findNamedInstruction(*F, "morok.pun.value");
    REQUIRE(value);
    CHECK(isa<TruncInst>(value));
    CHECK(value->getType()->isIntegerTy(1));

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("typePunFunction is deterministic for a fixed seed and input") {
    LLVMContext ctxA;
    LLVMContext ctxB;
    auto MA = parse(ctxA, kArith);
    auto MB = parse(ctxB, kArith);

    // Independent engines from the same seed must yield identical output.
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xC0FFEE);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xC0FFEE);
    morok::ir::IRRandom rngA(engineA);
    morok::ir::IRRandom rngB(engineB);

    const morok::passes::TypePunParams params{
        /*probability=*/50u, /*include_floating=*/true, /*max_targets=*/64u};
    morok::passes::typePunFunction(*MA->getFunction("arith"), params, rngA);
    morok::passes::typePunFunction(*MB->getFunction("arith"), params, rngB);

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
