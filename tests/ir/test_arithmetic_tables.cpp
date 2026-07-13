// SPDX-License-Identifier: MIT
//
// Tests for ArithmeticTables — replaces narrow integer arithmetic, constant
// shifts and comparisons with encrypted lookup-table loads materialized by a
// tiny runtime decoder (morok::passes::tableArithmeticFunction).

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/ArithmeticTables.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// Six narrow (i8) binary operations with only variable operands.  At <=8 bits
// the pass uses the Pair8 index kind, so every op is eligible with no constant
// requirement — the reliable "fires" fixture.
const char *kNarrow = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i8 @narrow(i8 %a, i8 %b) {
entry:
  %0 = add i8 %a, %b
  %1 = mul i8 %0, %b
  %2 = xor i8 %1, %a
  %3 = and i8 %2, %b
  %4 = or  i8 %3, %a
  %5 = sub i8 %4, %b
  ret i8 %5
}
)ir";

// No eligible operations at all.
const char *kTrivial = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @trivial(i32 %x) {
entry:
  ret i32 %x
}
)ir";

// A declaration — nothing to transform.
const char *kDecl = R"ir(
declare i32 @external(i32)
)ir";

// Wide (i32) arithmetic: bit width > 16 is never eligible.
const char *kWide = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @wide(i32 %a, i32 %b) {
entry:
  %0 = add i32 %a, %b
  %1 = mul i32 %0, %b
  %2 = xor i32 %1, %a
  ret i32 %2
}
)ir";

// A function already living in the morok.* namespace — must be skipped.
const char *kMorokNamed = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i8 @"morok.helper"(i8 %a, i8 %b) {
entry:
  %0 = add i8 %a, %b
  %1 = mul i8 %0, %b
  ret i8 %1
}
)ir";

// A narrow icmp (i8 operands, i1 result) — eligible via the ICmp path.
const char *kCmp8 = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i1 @cmp8(i8 %a, i8 %b) {
entry:
  %c = icmp ult i8 %a, %b
  ret i1 %c
}
)ir";

// A single wide (i16) op with one constant operand — eligible via ConstRhs,
// exercising the 16-bit-element table path.
const char *kWideConst = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i16 @wideconst(i16 %a) {
entry:
  %0 = add i16 %a, 1234
  ret i16 %0
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::size_t instructionCount(Function &Fn) {
    std::size_t n = 0;
    for (BasicBlock &BB : Fn)
        n += BB.size();
    return n;
}

} // namespace

TEST_CASE("tableArithmeticFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kNarrow);
    Function *F = M->getFunction("narrow");
    REQUIRE(F);

    const std::size_t instsBefore = instructionCount(*F);
    REQUIRE(countGlobals(*M, "morok.tablearith") == 0);
    REQUIRE(countFunctions(*M, "morok.tablearith") == 0);

    auto rng = makeRng(0x1337);
    CHECK(morok::passes::tableArithmeticFunction(
        *F, {/*probability=*/100, /*max_tables=*/8}, rng));

    // The function body grew (each op became call+zext+shift+or+gep+load).
    CHECK(instructionCount(*F) > instsBefore);
    // Every rewritten op left morok.tablearith.* named instructions behind.
    CHECK(countNamedInstructions(*F, "morok.tablearith") > 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("tableArithmeticFunction emits one table/ready/ensure per rewrite") {
    LLVMContext ctx;
    auto M = parse(ctx, kNarrow);
    Function *F = M->getFunction("narrow");
    REQUIRE(F);

    auto rng = makeRng(0x2001);
    CHECK(morok::passes::tableArithmeticFunction(
        *F, {/*probability=*/100, /*max_tables=*/8}, rng));

    // All six eligible i8 ops fire (max_tables=8 does not clamp), and each
    // materializes its own private table, ready flag, internal ensure fn and
    // ensure call.
    CHECK(countGlobals(*M, "morok.tablearith.table") == 6);
    CHECK(countGlobals(*M, "morok.tablearith.ready") == 6);
    CHECK(countFunctions(*M, "morok.tablearith.ensure") == 6);
    CHECK(countCallsToPrefix(*F, "morok.tablearith.ensure") == 6);
    // Lazy decoders are registered as static constructors.
    CHECK(M->getGlobalVariable("llvm.global_ctors", true) != nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("tableArithmeticFunction is a no-op when disabled by params") {
    LLVMContext ctx;

    SUBCASE("probability zero") {
        auto M = parse(ctx, kNarrow);
        Function *F = M->getFunction("narrow");
        REQUIRE(F);
        const std::size_t binopsBefore = countBinops(*F);

        auto rng = makeRng(0x3003);
        CHECK_FALSE(morok::passes::tableArithmeticFunction(
            *F, {/*probability=*/0, /*max_tables=*/8}, rng));

        CHECK(countBinops(*F) == binopsBefore);
        CHECK(countGlobals(*M, "morok.tablearith") == 0);
        CHECK_FALSE(verifyModule(*M));
    }

    SUBCASE("max_tables zero") {
        auto M = parse(ctx, kNarrow);
        Function *F = M->getFunction("narrow");
        REQUIRE(F);

        auto rng = makeRng(0x4004);
        CHECK_FALSE(morok::passes::tableArithmeticFunction(
            *F, {/*probability=*/100, /*max_tables=*/0}, rng));

        CHECK(countGlobals(*M, "morok.tablearith") == 0);
        CHECK_FALSE(verifyModule(*M));
    }
}

TEST_CASE("tableArithmeticFunction skips declarations and morok.* functions") {
    LLVMContext ctx;
    auto Mdecl = parse(ctx, kDecl);
    Function *Ext = Mdecl->getFunction("external");
    REQUIRE(Ext);

    auto rngDecl = makeRng(0x5005);
    CHECK_FALSE(morok::passes::tableArithmeticFunction(
        *Ext, {/*probability=*/100, /*max_tables=*/8}, rngDecl));
    CHECK_FALSE(verifyModule(*Mdecl));

    auto Mnamed = parse(ctx, kMorokNamed);
    Function *Helper = Mnamed->getFunction("morok.helper");
    REQUIRE(Helper);

    auto rngNamed = makeRng(0x6006);
    // Name already in the morok.* namespace is refused to avoid recursion.
    CHECK_FALSE(morok::passes::tableArithmeticFunction(
        *Helper, {/*probability=*/100, /*max_tables=*/8}, rngNamed));
    CHECK(countGlobals(*Mnamed, "morok.tablearith") == 0);
    CHECK_FALSE(verifyModule(*Mnamed));
}

TEST_CASE("tableArithmeticFunction leaves wide (>16-bit) arithmetic untouched") {
    LLVMContext ctx;
    auto M = parse(ctx, kWide);
    Function *F = M->getFunction("wide");
    REQUIRE(F);
    const std::size_t binopsBefore = countBinops(*F);

    auto rng = makeRng(0x7007);
    CHECK_FALSE(morok::passes::tableArithmeticFunction(
        *F, {/*probability=*/100, /*max_tables=*/8}, rng));

    CHECK(countBinops(*F) == binopsBefore);
    CHECK(countGlobals(*M, "morok.tablearith") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("tableArithmeticFunction is safe on trivial single-block bodies") {
    LLVMContext ctx;
    auto M = parse(ctx, kTrivial);
    Function *F = M->getFunction("trivial");
    REQUIRE(F);

    auto rng = makeRng(0x8008);
    // No eligible ops => no change, no crash.
    CHECK_FALSE(morok::passes::tableArithmeticFunction(
        *F, {/*probability=*/100, /*max_tables=*/8}, rng));
    CHECK(countGlobals(*M, "morok.tablearith") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("tableArithmeticFunction lowers a narrow icmp to a table load") {
    LLVMContext ctx;
    auto M = parse(ctx, kCmp8);
    Function *F = M->getFunction("cmp8");
    REQUIRE(F);

    auto rng = makeRng(0x9009);
    CHECK(morok::passes::tableArithmeticFunction(
        *F, {/*probability=*/100, /*max_tables=*/8}, rng));

    // One comparison => one table, and the i1 result is a trunc of the load.
    CHECK(countGlobals(*M, "morok.tablearith.table") == 1);
    CHECK(findNamedInstruction(*F, "morok.tablearith.icmp") != nullptr);
    // The original icmp is gone from cmp8's body (the internal ensure decoder
    // has its own icmps, so this must stay function-local, not module-wide).
    std::size_t icmpsInF = 0;
    for (BasicBlock &BB : *F)
        for (Instruction &I : BB)
            if (isa<ICmpInst>(&I))
                ++icmpsInF;
    CHECK(icmpsInF == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("tableArithmeticFunction builds a 16-bit-element table for a wide "
          "op with a constant operand") {
    LLVMContext ctx;
    auto M = parse(ctx, kWideConst);
    Function *F = M->getFunction("wideconst");
    REQUIRE(F);

    auto rng = makeRng(0xA00A);
    CHECK(morok::passes::tableArithmeticFunction(
        *F, {/*probability=*/100, /*max_tables=*/8}, rng));

    CHECK(countGlobals(*M, "morok.tablearith.table") == 1);
    auto *Table = M->getGlobalVariable("morok.tablearith.table", true);
    REQUIRE(Table != nullptr);
    // The full 2^16 index space is materialized.
    auto *ArrTy = dyn_cast<ArrayType>(Table->getValueType());
    REQUIRE(ArrTy != nullptr);
    CHECK(ArrTy->getNumElements() == 65536);
    // 9..16-bit non-comparison ops use 16-bit table elements.
    auto *ElemTy = dyn_cast<IntegerType>(ArrTy->getElementType());
    REQUIRE(ElemTy != nullptr);
    CHECK(ElemTy->getBitWidth() == 16);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("tableArithmeticFunction honors the max_tables cap") {
    LLVMContext ctx;
    auto M = parse(ctx, kNarrow);
    Function *F = M->getFunction("narrow");
    REQUIRE(F);

    auto rng = makeRng(0xB00B);
    // Six ops are eligible, but the cap limits the rewrite to two tables.
    CHECK(morok::passes::tableArithmeticFunction(
        *F, {/*probability=*/100, /*max_tables=*/2}, rng));

    CHECK(countGlobals(*M, "morok.tablearith.table") == 2);
    CHECK(countFunctions(*M, "morok.tablearith.ensure") == 2);
    // Not everything was consumed: original arithmetic still remains.
    CHECK(countBinops(*F) > 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("tableArithmeticFunction is deterministic for a fixed seed") {
    LLVMContext ctxA;
    LLVMContext ctxB;
    auto MA = parse(ctxA, kNarrow);
    auto MB = parse(ctxB, kNarrow);
    REQUIRE(MA->getFunction("narrow"));
    REQUIRE(MB->getFunction("narrow"));

    // Two independent engines seeded identically must produce identical IR
    // (including the encrypted table bytes derived from the key schedule).
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xC0FFEE);
    morok::ir::IRRandom rngA(engineA);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xC0FFEE);
    morok::ir::IRRandom rngB(engineB);

    CHECK(morok::passes::tableArithmeticFunction(
        *MA->getFunction("narrow"), {/*probability=*/100, /*max_tables=*/8},
        rngA));
    CHECK(morok::passes::tableArithmeticFunction(
        *MB->getFunction("narrow"), {/*probability=*/100, /*max_tables=*/8},
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
    CHECK_FALSE(verifyModule(*MB));
}
