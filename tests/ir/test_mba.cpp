// SPDX-License-Identifier: MIT
//
// Tests for Mba — mixed boolean-arithmetic substitution of integer binops.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/Mba.hpp"

#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

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

const char *kSingleAdd = R"ir(
define i32 @just_add(i32 %a, i32 %b) {
entry:
  %r = add i32 %a, %b
  ret i32 %r
}
)ir";

const char *kSingleAnd = R"ir(
define i32 @just_and(i32 %a, i32 %b) {
entry:
  %r = and i32 %a, %b
  ret i32 %r
}
)ir";

const char *kConstShl = R"ir(
define i32 @const_shl(i32 %a) {
entry:
  %r = shl i32 %a, 3
  ret i32 %r
}
)ir";

const char *kVarShl = R"ir(
define i32 @var_shl(i32 %a, i32 %b) {
entry:
  %r = shl i32 %a, %b
  ret i32 %r
}
)ir";

const char *kFloat = R"ir(
define double @fp(double %a, double %b) {
entry:
  %r = fadd double %a, %b
  ret double %r
}
)ir";

const char *kDecl = R"ir(
declare i32 @external(i32)
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("mbaFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = countBinops(*F);

    auto rng = makeRng(0x1337);
    CHECK(morok::passes::mbaFunction(
        *F, morok::passes::MbaParams{
                .probability = 100, .layers = 2, .heuristic = true},
        rng));
    // Every eligible binop expands into a multi-instruction identity.
    CHECK(countBinops(*F) > before);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mbaFunction respects probability=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = countBinops(*F);

    auto rng = makeRng(0x2);
    // chance(0) is always false, so no target is ever rewritten.
    CHECK_FALSE(morok::passes::mbaFunction(
        *F, morok::passes::MbaParams{
                .probability = 0, .layers = 2, .heuristic = true},
        rng));
    CHECK(countBinops(*F) == before);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mbaFunction is safe on declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, kDecl);
    Function *F = M->getFunction("external");
    REQUIRE(F);

    auto rng = makeRng(0xAB);
    // A declaration has no basic blocks: nothing to rewrite, no crash.
    CHECK_FALSE(morok::passes::mbaFunction(
        *F, morok::passes::MbaParams{
                .probability = 100, .layers = 2, .heuristic = true},
        rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mbaFunction leaves a function with no integer binops unchanged") {
    LLVMContext ctx;
    auto M = parse(ctx, kFloat);
    Function *F = M->getFunction("fp");
    REQUIRE(F);
    const std::size_t before = countBinops(*F);

    auto rng = makeRng(0x99);
    // fadd is a BinaryOperator but not an integer type, so it is filtered out.
    CHECK_FALSE(morok::passes::mbaFunction(
        *F, morok::passes::MbaParams{
                .probability = 100, .layers = 2, .heuristic = true},
        rng));
    CHECK(countBinops(*F) == before);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mbaFunction is deterministic for a fixed seed") {
    LLVMContext ctxA;
    LLVMContext ctxB;
    auto MA = parse(ctxA, kArith);
    auto MB = parse(ctxB, kArith);
    Function *FA = MA->getFunction("arith");
    Function *FB = MB->getFunction("arith");
    REQUIRE(FA);
    REQUIRE(FB);

    // Two fresh engines seeded identically produce identical draw streams.
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xBEEF);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xBEEF);
    morok::ir::IRRandom rngA(engineA);
    morok::ir::IRRandom rngB(engineB);

    const morok::passes::MbaParams params{
        .probability = 100, .layers = 2, .heuristic = true};
    CHECK(morok::passes::mbaFunction(*FA, params, rngA));
    CHECK(morok::passes::mbaFunction(*FB, params, rngB));

    auto printModule = [](Module &Mod) {
        std::string text;
        raw_string_ostream os(text);
        Mod.print(os, nullptr);
        return text;
    };
    CHECK(printModule(*MA) == printModule(*MB));
    CHECK_FALSE(verifyModule(*MA));
    CHECK_FALSE(verifyModule(*MB));
}

TEST_CASE("mbaFunction rewrites add into an xor/and/shl identity") {
    LLVMContext ctx;
    auto M = parse(ctx, kSingleAdd);
    Function *F = M->getFunction("just_add");
    REQUIRE(F);

    auto rng = makeRng(0x10);
    CHECK(morok::passes::mbaFunction(
        *F, morok::passes::MbaParams{
                .probability = 100, .layers = 1, .heuristic = false},
        rng));
    // (a ^ b) + 2*(a & b): one xor, one and, one shl (the *2), one outer add.
    CHECK(countOpcode(*M, Instruction::Xor) == 1u);
    CHECK(countOpcode(*M, Instruction::And) == 1u);
    CHECK(countOpcode(*M, Instruction::Shl) == 1u);
    CHECK(countOpcode(*M, Instruction::Add) == 1u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mbaFunction eliminates the and opcode via De Morgan") {
    LLVMContext ctx;
    auto M = parse(ctx, kSingleAnd);
    Function *F = M->getFunction("just_and");
    REQUIRE(F);

    auto rng = makeRng(0x20);
    CHECK(morok::passes::mbaFunction(
        *F, morok::passes::MbaParams{
                .probability = 100, .layers = 1, .heuristic = false},
        rng));
    // ~((~a) | (~b)): three nots (xor -1) plus one or, and no and remains.
    CHECK(countOpcode(*M, Instruction::And) == 0u);
    CHECK(countOpcode(*M, Instruction::Or) == 1u);
    CHECK(countOpcode(*M, Instruction::Xor) == 3u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mbaFunction rewrites a constant shift-left into a multiply") {
    LLVMContext ctx;
    auto M = parse(ctx, kConstShl);
    Function *F = M->getFunction("const_shl");
    REQUIRE(F);

    auto rng = makeRng(0x30);
    CHECK(morok::passes::mbaFunction(
        *F, morok::passes::MbaParams{
                .probability = 100, .layers = 1, .heuristic = false},
        rng));
    // a << 3  ==  a * 8: the shift is gone, replaced by a constant multiply.
    CHECK(countOpcode(*M, Instruction::Shl) == 0u);
    CHECK(countOpcode(*M, Instruction::Mul) == 1u);

    Instruction *mulI = nullptr;
    for (Instruction &I : instructions(*F))
        if (I.getOpcode() == Instruction::Mul) {
            mulI = &I;
            break;
        }
    REQUIRE(mulI != nullptr);
    CHECK(instructionHasConstantOperand(mulI, 8));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mbaFunction leaves a variable shift amount unchanged") {
    LLVMContext ctx;
    auto M = parse(ctx, kVarShl);
    Function *F = M->getFunction("var_shl");
    REQUIRE(F);
    const std::size_t beforeShl = countOpcode(*M, Instruction::Shl);

    auto rng = makeRng(0x77);
    // Non-constant shift amount: emitMba returns null, so nothing is rewritten.
    CHECK_FALSE(morok::passes::mbaFunction(
        *F, morok::passes::MbaParams{
                .probability = 100, .layers = 1, .heuristic = false},
        rng));
    CHECK(countOpcode(*M, Instruction::Shl) == beforeShl);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mbaFunction clamps the layer count to at least one") {
    LLVMContext ctx;
    auto M = parse(ctx, kSingleAdd);
    Function *F = M->getFunction("just_add");
    REQUIRE(F);
    const std::size_t before = countBinops(*F);

    auto rng = makeRng(0x51);
    // layers = 0 is clamped to 1, so the single add is still rewritten.
    CHECK(morok::passes::mbaFunction(
        *F, morok::passes::MbaParams{
                .probability = 100, .layers = 0, .heuristic = false},
        rng));
    CHECK(countBinops(*F) > before);
    CHECK_FALSE(verifyModule(*M));
}
