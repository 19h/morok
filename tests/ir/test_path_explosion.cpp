// SPDX-License-Identifier: MIT
//
// Tests for PathExplosion — anti-DSE opaque-guarded decoy path injection.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/PathExplosion.hpp"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// Multi-instruction single-block function: the entry block has a valid guard
// split point (first non-terminator instruction), so the pass fires on it.
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

// Four eligible blocks, each with a non-terminator instruction after any PHIs.
const char *kMultiBlock = R"ir(
target triple = "x86_64-unknown-linux-gnu"
define i32 @multi(i32 %a, i32 %b) {
entry:
  %c = icmp slt i32 %a, %b
  br i1 %c, label %b1, label %b2
b1:
  %x = add i32 %a, 1
  br label %join
b2:
  %y = sub i32 %b, 1
  br label %join
join:
  %z = phi i32 [ %x, %b1 ], [ %y, %b2 ]
  %w = mul i32 %z, 3
  ret i32 %w
}
)ir";

// Trivial single-block function whose only instruction is the terminator, so
// guardSplitPoint returns null and nothing is transformed.
const char *kTrivial = R"ir(
define i32 @trivial(i32 %x) {
entry:
  ret i32 %x
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::size_t countBlocksStartingWith(Function &F, StringRef prefix) {
    std::size_t n = 0;
    for (BasicBlock &BB : F)
        if (BB.getName().starts_with(prefix))
            ++n;
    return n;
}

std::string moduleToString(Module &M) {
    std::string text;
    raw_string_ostream os(text);
    M.print(os, nullptr);
    os.flush();
    return text;
}

} // namespace

TEST_CASE("pathExplosionFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t beforeBlocks = F->size();

    auto rng = makeRng(0x1001);
    CHECK(morok::passes::pathExplosionFunction(
        *F, {/*probability=*/100, /*max_blocks=*/4, /*max_iterations=*/16},
        rng));

    // Block count grew (SplitBlock + six decoy blocks per transform).
    CHECK(F->size() > beforeBlocks);
    // Exactly one opaque predicate global is materialised.
    CHECK(countGlobals(*M, "morok.path.opaque") == 1);
    // Module remains well-formed (verifyModule returns true on breakage).
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("pathExplosionFunction is a no-op at probability zero") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t beforeBlocks = F->size();

    auto rng = makeRng(0x1002);
    CHECK_FALSE(morok::passes::pathExplosionFunction(
        *F, {/*probability=*/0, /*max_blocks=*/4, /*max_iterations=*/16}, rng));

    CHECK(F->size() == beforeBlocks);
    CHECK(countGlobals(*M, "morok.path.opaque") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("pathExplosionFunction respects zero max_blocks and max_iterations") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t beforeBlocks = F->size();

    auto rngA = makeRng(0x1003);
    CHECK_FALSE(morok::passes::pathExplosionFunction(
        *F, {/*probability=*/100, /*max_blocks=*/0, /*max_iterations=*/16},
        rngA));

    auto rngB = makeRng(0x1004);
    CHECK_FALSE(morok::passes::pathExplosionFunction(
        *F, {/*probability=*/100, /*max_blocks=*/4, /*max_iterations=*/0},
        rngB));

    CHECK(F->size() == beforeBlocks);
    CHECK(countGlobals(*M, "morok.path.opaque") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("pathExplosionFunction skips declarations and morok functions") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @external(i32)
define i32 @morok.helper(i32 %x) {
entry:
  %r = add i32 %x, 1
  ret i32 %r
}
)ir");
    Function *Decl = M->getFunction("external");
    Function *Reserved = M->getFunction("morok.helper");
    REQUIRE(Decl);
    REQUIRE(Reserved);

    auto rngA = makeRng(0x1005);
    CHECK_FALSE(morok::passes::pathExplosionFunction(
        *Decl, {/*probability=*/100, /*max_blocks=*/4, /*max_iterations=*/16},
        rngA));

    auto rngB = makeRng(0x1006);
    // Names under the reserved "morok." prefix are skipped by name.
    CHECK_FALSE(morok::passes::pathExplosionFunction(
        *Reserved,
        {/*probability=*/100, /*max_blocks=*/4, /*max_iterations=*/16}, rngB));

    CHECK(countGlobals(*M, "morok.path.opaque") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("pathExplosionFunction is safe on a trivial single-block function") {
    LLVMContext ctx;
    auto M = parse(ctx, kTrivial);
    Function *F = M->getFunction("trivial");
    REQUIRE(F);
    const std::size_t beforeBlocks = F->size();

    auto rng = makeRng(0x1007);
    // The only instruction is the terminator, so there is no split point.
    CHECK_FALSE(morok::passes::pathExplosionFunction(
        *F, {/*probability=*/100, /*max_blocks=*/4, /*max_iterations=*/16},
        rng));

    CHECK(F->size() == beforeBlocks);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("pathExplosionFunction caps transformed blocks at max_blocks") {
    LLVMContext ctx;
    auto M1 = parse(ctx, kMultiBlock);
    auto M2 = parse(ctx, kMultiBlock);
    Function *F1 = M1->getFunction("multi");
    Function *F2 = M2->getFunction("multi");
    REQUIRE(F1);
    REQUIRE(F2);

    auto rng1 = makeRng(0x1008);
    CHECK(morok::passes::pathExplosionFunction(
        *F1, {/*probability=*/100, /*max_blocks=*/1, /*max_iterations=*/16},
        rng1));

    auto rng2 = makeRng(0x1009);
    CHECK(morok::passes::pathExplosionFunction(
        *F2, {/*probability=*/100, /*max_blocks=*/4, /*max_iterations=*/16},
        rng2));

    // Each transformed head produces exactly one indirectbr; the cap of 1
    // bounds it to a single transform even though four blocks are eligible.
    const std::size_t indirect1 = countOpcode(*M1, Instruction::IndirectBr);
    const std::size_t indirect4 = countOpcode(*M2, Instruction::IndirectBr);
    CHECK(indirect1 == 1);
    CHECK(indirect4 > indirect1);
    CHECK(indirect4 <= 4);

    // The scratch alloca is created once per function and reused across
    // transforms, so raising the cap must not multiply it.
    CHECK(countNamedAllocas(*F1, "morok.path.scratch") == 1);
    CHECK(countNamedAllocas(*F2, "morok.path.scratch") == 1);

    CHECK_FALSE(verifyModule(*M1));
    CHECK_FALSE(verifyModule(*M2));
}

TEST_CASE("pathExplosionFunction emits the decoy scaffold") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);

    auto rng = makeRng(0x100A);
    CHECK(morok::passes::pathExplosionFunction(
        *F, {/*probability=*/100, /*max_blocks=*/4, /*max_iterations=*/16},
        rng));

    // Opaque predicate global: private linkage, i32 payload.
    GlobalVariable *GV =
        M->getGlobalVariable("morok.path.opaque", /*AllowInternal=*/true);
    REQUIRE(GV != nullptr);
    CHECK(GV->hasPrivateLinkage());
    CHECK(GV->getValueType()->isIntegerTy(32));

    // Scratch is an [8 x i64] array, allocated once.
    CHECK(countNamedAllocas(*F, "morok.path.scratch") == 1);
    CHECK(maxStaticAllocaArrayElements(*F, "morok.path.scratch") == 8);

    // A single transform contributes an indirectbr, two loop PHIs, a volatile
    // store, and the named decoy blocks.
    CHECK(countOpcode(*M, Instruction::IndirectBr) == 1);
    CHECK(countPhis(*F) == 2);
    CHECK(countOpcode(*M, Instruction::Store) >= 1);
    CHECK(countBlocksStartingWith(*F, "morok.path.entry") == 1);
    CHECK(countBlocksStartingWith(*F, "morok.path.loop") == 1);
    CHECK(countBlocksStartingWith(*F, "morok.path.case") == 3);
    CHECK(countBlocksStartingWith(*F, "morok.path.exit") == 1);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("pathExplosionFunction clamps the decoy loop bound") {
    LLVMContext ctx;
    auto M1 = parse(ctx, kArith);
    auto M2 = parse(ctx, kArith);
    Function *F1 = M1->getFunction("arith");
    Function *F2 = M2->getFunction("arith");
    REQUIRE(F1);
    REQUIRE(F2);

    auto rng1 = makeRng(0x100B);
    CHECK(morok::passes::pathExplosionFunction(
        *F1, {/*probability=*/100, /*max_blocks=*/1, /*max_iterations=*/16},
        rng1));

    auto rng2 = makeRng(0x100C);
    // max_iterations above 64 is clamped to the [1, 64] modulo cap.
    CHECK(morok::passes::pathExplosionFunction(
        *F2, {/*probability=*/100, /*max_blocks=*/1, /*max_iterations=*/100},
        rng2));

    Instruction *Mod1 = findNamedInstruction(*F1, "morok.path.bound.mod");
    Instruction *Mod2 = findNamedInstruction(*F2, "morok.path.bound.mod");
    REQUIRE(Mod1 != nullptr);
    REQUIRE(Mod2 != nullptr);
    // The URem divisor equals clamp(max_iterations, 1, 64).
    CHECK(instructionHasConstantOperand(Mod1, 16));
    CHECK(instructionHasConstantOperand(Mod2, 64));

    CHECK_FALSE(verifyModule(*M1));
    CHECK_FALSE(verifyModule(*M2));
}

TEST_CASE("pathExplosionFunction is deterministic for a fixed seed") {
    LLVMContext ctx;
    auto MA = parse(ctx, kArith);
    auto MB = parse(ctx, kArith);
    Function *FA = MA->getFunction("arith");
    Function *FB = MB->getFunction("arith");
    REQUIRE(FA);
    REQUIRE(FB);

    // Two independent engines from the same seed yield identical IR.
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xC0FFEE);
    morok::ir::IRRandom rngA(engineA);
    CHECK(morok::passes::pathExplosionFunction(
        *FA, {/*probability=*/100, /*max_blocks=*/4, /*max_iterations=*/16},
        rngA));

    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xC0FFEE);
    morok::ir::IRRandom rngB(engineB);
    CHECK(morok::passes::pathExplosionFunction(
        *FB, {/*probability=*/100, /*max_blocks=*/4, /*max_iterations=*/16},
        rngB));

    CHECK(moduleToString(*MA) == moduleToString(*MB));
    CHECK_FALSE(verifyModule(*MA));
    CHECK_FALSE(verifyModule(*MB));
}
