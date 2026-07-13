// SPDX-License-Identifier: MIT
//
// Tests for Substitution — replaces integer binary operators with equivalent
// (larger) expression trees drawn from the verified identity catalog.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/Substitution.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// Every binary operator here is one of the handled integer opcodes
// (add/sub/and/or/xor/mul), so with probability=100 every one is rewritten.
const char *kArith = R"ir(
target triple = "x86_64-unknown-linux-gnu"
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

// A single add: useful to prove the rewrite introduces non-add operations for
// every catalog choice.
const char *kSingleAdd = R"ir(
define i32 @justadd(i32 %a, i32 %b) {
entry:
  %r = add i32 %a, %b
  ret i32 %r
}
)ir";

// A constant shift: the Shl path is RNG-free and lowers to `a * 2^k`.
const char *kConstShift = R"ir(
define i32 @shifter(i32 %a) {
entry:
  %r = shl i32 %a, 3
  ret i32 %r
}
)ir";

// No integer binary operators at all.
const char *kNoBinops = R"ir(
define i32 @passthrough(i32 %x) {
entry:
  ret i32 %x
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

// Print a module to text so two runs can be compared byte-for-byte.
std::string moduleText(Module &M) {
    std::string out;
    raw_string_ostream os(out);
    M.print(os, nullptr);
    os.flush();
    return out;
}

// First binary operator with the given opcode, or nullptr.
BinaryOperator *firstOpcode(Function &F, unsigned opcode) {
    for (Instruction &I : instructions(F))
        if (auto *bo = dyn_cast<BinaryOperator>(&I))
            if (bo->getOpcode() == opcode)
                return bo;
    return nullptr;
}

} // namespace

TEST_CASE("substituteFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = countBinops(*F);
    REQUIRE(before > 0);

    auto rng = makeRng(0x1001);
    CHECK(morok::passes::substituteFunction(*F, {/*prob=*/100, /*iters=*/1},
                                            rng));
    // Every catalog identity replaces one binop with at least two, so the
    // count strictly grows.
    CHECK(countBinops(*F) > before);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("substituteFunction is a no-op at probability 0") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = countBinops(*F);

    auto rng = makeRng(0x1002);
    // chance(0) is always false, so nothing is rewritten.
    CHECK_FALSE(morok::passes::substituteFunction(
        *F, {/*prob=*/0, /*iters=*/1}, rng));
    CHECK(countBinops(*F) == before);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("substituteFunction is safe on declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @external(i32)
)ir");
    Function *F = M->getFunction("external");
    REQUIRE(F);

    auto rng = makeRng(0x1003);
    // No basic blocks to walk: returns false, no crash.
    CHECK_FALSE(morok::passes::substituteFunction(
        *F, {/*prob=*/100, /*iters=*/2}, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("substituteFunction is safe on a binop-free function") {
    LLVMContext ctx;
    auto M = parse(ctx, kNoBinops);
    Function *F = M->getFunction("passthrough");
    REQUIRE(F);

    auto rng = makeRng(0x1004);
    // Nothing to collect: unchanged and reports no change.
    CHECK_FALSE(morok::passes::substituteFunction(
        *F, {/*prob=*/100, /*iters=*/3}, rng));
    CHECK(countBinops(*F) == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("substituteFunction is deterministic for a fixed seed") {
    LLVMContext ctxA;
    LLVMContext ctxB;
    auto MA = parse(ctxA, kArith);
    auto MB = parse(ctxB, kArith);

    // Fresh, independently-seeded engines so both runs see the identical PRNG
    // sequence (the shared static in makeRng cannot guarantee that).
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xBEEF);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xBEEF);
    morok::ir::IRRandom rngA(engineA);
    morok::ir::IRRandom rngB(engineB);

    CHECK(morok::passes::substituteFunction(*MA->getFunction("arith"),
                                            {/*prob=*/70, /*iters=*/2}, rngA));
    CHECK(morok::passes::substituteFunction(*MB->getFunction("arith"),
                                            {/*prob=*/70, /*iters=*/2}, rngB));

    CHECK(moduleText(*MA) == moduleText(*MB));
    CHECK_FALSE(verifyModule(*MA));
    CHECK_FALSE(verifyModule(*MB));
}

TEST_CASE("substituteFunction grows more with additional iterations") {
    LLVMContext ctx1;
    LLVMContext ctx3;
    auto M1 = parse(ctx1, kArith);
    auto M3 = parse(ctx3, kArith);

    // Same seed => iteration 1 is identical for both; the 3-iteration run then
    // keeps re-substituting its own output, so it must end up strictly larger.
    auto engine1 = morok::core::Xoshiro256pp::fromSeed(0xC0FFEE);
    auto engine3 = morok::core::Xoshiro256pp::fromSeed(0xC0FFEE);
    morok::ir::IRRandom rng1(engine1);
    morok::ir::IRRandom rng3(engine3);

    morok::passes::substituteFunction(*M1->getFunction("arith"),
                                      {/*prob=*/100, /*iters=*/1}, rng1);
    morok::passes::substituteFunction(*M3->getFunction("arith"),
                                      {/*prob=*/100, /*iters=*/3}, rng3);

    CHECK(countBinops(*M3->getFunction("arith")) >
          countBinops(*M1->getFunction("arith")));
    CHECK_FALSE(verifyModule(*M1));
    CHECK_FALSE(verifyModule(*M3));
}

TEST_CASE("substituteFunction clamps the iteration count") {
    LLVMContext ctxCap;
    LLVMContext ctxHuge;
    auto MCap = parse(ctxCap, kArith);
    auto MHuge = parse(ctxHuge, kArith);

    // iterations is clamped to a ceiling of 8; requesting 8 and 4000 must run
    // the exact same number of sweeps and, from identical engines, produce
    // identical text.
    auto engineCap = morok::core::Xoshiro256pp::fromSeed(0x5EED);
    auto engineHuge = morok::core::Xoshiro256pp::fromSeed(0x5EED);
    morok::ir::IRRandom rngCap(engineCap);
    morok::ir::IRRandom rngHuge(engineHuge);

    morok::passes::substituteFunction(*MCap->getFunction("arith"),
                                      {/*prob=*/100, /*iters=*/8}, rngCap);
    morok::passes::substituteFunction(*MHuge->getFunction("arith"),
                                      {/*prob=*/100, /*iters=*/4000}, rngHuge);

    CHECK(moduleText(*MCap) == moduleText(*MHuge));
    CHECK_FALSE(verifyModule(*MCap));
    CHECK_FALSE(verifyModule(*MHuge));
}

TEST_CASE("substituteFunction introduces non-add operations") {
    LLVMContext ctx;
    auto M = parse(ctx, kSingleAdd);
    Function *F = M->getFunction("justadd");
    REQUIRE(F);
    REQUIRE(countBinops(*F) == 1);

    auto rng = makeRng(0x1008);
    CHECK(morok::passes::substituteFunction(*F, {/*prob=*/100, /*iters=*/1},
                                            rng));
    // Every Add identity ((a&b)+(a|b), (a^b)+2*(a&b), a-(-b)) yields at least
    // one operator whose opcode is not Add, so the total binop count exceeds
    // the number of remaining adds.
    const std::size_t total = countBinops(*F);
    const std::size_t adds = countOpcode(*M, Instruction::Add);
    CHECK(total > adds);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("substituteFunction rewrites a constant shift into a multiply") {
    LLVMContext ctx;
    auto M = parse(ctx, kConstShift);
    Function *F = M->getFunction("shifter");
    REQUIRE(F);
    REQUIRE(countOpcode(*M, Instruction::Shl) == 1);

    // The Shl path consumes no randomness and lowers `shl a, 3` to `a * 8`,
    // with the constant surviving thanks to NoFolder.
    auto rng = makeRng(0x1009);
    CHECK(morok::passes::substituteFunction(*F, {/*prob=*/100, /*iters=*/1},
                                            rng));

    CHECK(countOpcode(*M, Instruction::Shl) == 0);
    BinaryOperator *mul = firstOpcode(*F, Instruction::Mul);
    REQUIRE(mul != nullptr);
    CHECK(instructionHasConstantOperand(mul, std::uint64_t{8}));
    CHECK_FALSE(verifyModule(*M));
}
